//! mini-proxy: a minimal transparent proxy reusing the honk/dae kernel
//! datapath design — eBPF steers in the kernel, direct traffic never
//! reaches userspace, only proxy-bound flows enter this process.

mod bpf_raw;
mod config;
mod datapath;
mod dns;
mod hysteria2;
mod listener;
mod ns;
mod outbound;
mod relay;
mod rules;
mod socks5;

use anyhow::{Context, Result};
use clap::Parser;
use rules::{SharedRules, StaticMaps};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser)]
struct Args {
    /// Config file path (TOML).
    #[arg(short, long, default_value = "/etc/mini-proxy/config.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let raw =
        std::fs::read_to_string(&args.config).with_context(|| format!("read {}", args.config))?;
    let config: config::Config = toml::from_str(&raw).context("parse config")?;

    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("mini-proxy must run as root (TC, sk_lookup, netns, transparent sockets)");
    }

    // Resolve the hysteria2 server before any eBPF hook is attached, so the
    // lookup cannot loop through our own datapath.
    let hy2_server: Option<SocketAddr> = if config.general.outbound == "hysteria2" {
        Some(
            tokio::net::lookup_host(config.hysteria2.server.as_str())
                .await
                .with_context(|| format!("resolve hysteria2 server {}", config.hysteria2.server))?
                .next()
                .context("hysteria2 server: no address")?,
        )
    } else {
        None
    };

    // 1. Proxy namespace + veth bridge.
    ns::create_daens()?;
    datapath::setup_links(&config)?;

    // 2. eBPF: load, write globals, attach hooks, expose maps.
    let lan = match &config.general.lan_interface {
        Some(spec) => datapath::resolve_interface(spec)?,
        None => None,
    };
    let wan = match &config.general.wan_interface {
        Some(spec) => datapath::resolve_interface(spec)?,
        None => None,
    };
    let mut dp = datapath::load_and_attach(&config, lan.clone(), wan.clone())?;

    // 3. Routing: static surfaces now, domain surface via the DNS engine.
    // "list" rules import their ruleset files before the engines see them.
    let rules_list = config::expand_rules(&config)?;
    dp.maps
        .as_mut()
        .expect("maps")
        .populate_cidr_ports(&rules_list)?;
    let rules: SharedRules = Arc::new(Mutex::new(rules::Rules::new(
        &config.general.default_verdict,
        &rules_list,
    )?));
    let maps: Arc<Mutex<StaticMaps>> = Arc::new(Mutex::new(dp.take_maps()));
    datapath::install_control_marker(&dp)?;

    // 4. Transparent listeners inside daens, published to the sockmap.
    let listeners = listener::create(&mut dp, true).context("create transparent listeners")?;

    // 5. Outbound + engines.
    let outbound: Arc<outbound::Outbound> = match config.general.outbound.as_str() {
        "socks5" => {
            let server: SocketAddr = config
                .socks5
                .server
                .parse()
                .context("parse socks5 server")?;
            Arc::new(outbound::Outbound::Socks5(Arc::new(socks5::Socks5Client {
                server,
                username: config.socks5.username.clone(),
                password: config.socks5.password.clone(),
            })))
        }
        "hysteria2" => {
            let server = hy2_server.context("hysteria2 outbound selected")?;
            let hy2 = &config.hysteria2;
            Arc::new(outbound::Outbound::Hysteria2(Arc::new(
                hysteria2::Hysteria2Client::new(
                    server,
                    hy2.password.clone(),
                    hy2.sni.clone(),
                    hy2.insecure,
                    &hy2.up,
                    &hy2.down,
                )?,
            )))
        }
        other => anyhow::bail!("unknown outbound: {other}"),
    };
    let upstream: SocketAddr = config.dns.upstream.parse().context("parse dns upstream")?;
    let dns = Arc::new(dns::DnsEngine::new(upstream, rules.clone()));

    tracing::info!(?lan, ?wan, outbound = %config.general.outbound, "datapath up; relaying");

    // 6. Relay loops.
    let mut tcp_task = tokio::spawn(relay::run_tcp(listeners.tcp4, outbound.clone()));
    let mut udp_task = tokio::spawn(relay::run_udp(
        listeners.udp4,
        outbound.clone(),
        dns.clone(),
        maps.clone(),
    ));

    // 7. Run until a signal (or a relay crash), then tear everything down:
    // netlink-attached TC filters, the veth bridge and the proxy namespace
    // all outlive the process and must be removed explicitly.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut relay_result: Option<Result<()>> = None;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("interrupted; cleaning up");
        }
        _ = sigterm.recv() => {
            tracing::info!("terminated; cleaning up");
        }
        r = &mut tcp_task => {
            relay_result = Some(match r {
                Ok(v) => v,
                Err(e) => Err(anyhow::Error::new(e)),
            });
            tracing::warn!("tcp relay ended; cleaning up");
        }
        r = &mut udp_task => {
            relay_result = Some(match r {
                Ok(v) => v,
                Err(e) => Err(anyhow::Error::new(e)),
            });
            tracing::warn!("udp relay ended; cleaning up");
        }
    }
    tcp_task.abort();
    udp_task.abort();

    ns::cleanup(
        lan.as_ref().map(|(n, _)| n.as_str()),
        wan.as_ref().map(|(n, _)| n.as_str()),
        datapath::DAE0_HOST,
    );
    if let Some(r) = relay_result {
        r?;
    }
    Ok(())
}

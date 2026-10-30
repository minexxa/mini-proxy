//! mini-proxy: a minimal transparent proxy reusing the honk/dae kernel
//! datapath design — eBPF steers in the kernel, direct traffic never
//! reaches userspace, only proxy-bound flows enter this process.

mod bpf_raw;
mod config;
mod datapath;
mod dns;
mod listener;
mod ns;
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
    let raw = std::fs::read_to_string(&args.config)
        .with_context(|| format!("read {}", args.config))?;
    let config: config::Config = toml::from_str(&raw).context("parse config")?;

    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("mini-proxy must run as root (TC, sk_lookup, netns, transparent sockets)");
    }

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
    dp.maps.as_mut().expect("maps").populate_cidr_ports(&config)?;
    let rules: SharedRules = Arc::new(Mutex::new(rules::Rules::new(&config)?));
    let maps: Arc<Mutex<StaticMaps>> = Arc::new(Mutex::new(dp.take_maps()));
    datapath::install_control_marker(&dp)?;

    // 4. Transparent listeners inside daens, published to the sockmap.
    let listeners = listener::create(&mut dp, true).context("create transparent listeners")?;

    // 5. Outbound + engines.
    let server: SocketAddr = config.socks5.server.parse().context("parse socks5 server")?;
    let socks = Arc::new(socks5::Socks5Client {
        server,
        username: config.socks5.username.clone(),
        password: config.socks5.password.clone(),
    });
    let upstream: SocketAddr = config.dns.upstream.parse().context("parse dns upstream")?;
    let dns = Arc::new(dns::DnsEngine::new(upstream, rules.clone()));

    tracing::info!(?lan, ?wan, "datapath up; relaying");

    // 6. Relay loops.
    let tcp_task = tokio::spawn(relay::run_tcp(listeners.tcp4, socks.clone()));
    let udp_task = tokio::spawn(relay::run_udp(
        listeners.udp4,
        socks.clone(),
        dns.clone(),
        maps.clone(),
    ));
    let (tcp_res, udp_res) = tokio::join!(tcp_task, udp_task);
    tcp_res??;
    udp_res??;
    Ok(())
}

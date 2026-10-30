//! Configuration model (TOML). Deliberately a tiny subset of dae syntax:
//! ordered rule list + one outbound (SOCKS5 or Hysteria2) + one DNS upstream.

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub general: General,
    pub socks5: Socks5,
    #[serde(default)]
    pub hysteria2: Hysteria2,
    pub dns: Dns,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
pub struct General {
    /// LAN capture interface (gateway mode), e.g. "br-lan". Optional.
    pub lan_interface: Option<String>,
    /// WAN capture interface (host mode), e.g. "eth0". Optional.
    pub wan_interface: Option<String>,
    /// Skb mark steering traffic into the proxy namespace.
    pub tproxy_mark: Option<u32>,
    /// Verdict when no rule matches: "direct" | "proxy" | "block".
    #[serde(default = "default_verdict")]
    pub default_verdict: String,
    /// Outbound protocol: "socks5" | "hysteria2". Default socks5.
    #[serde(default = "default_outbound")]
    pub outbound: String,
}

fn default_outbound() -> String {
    "socks5".into()
}

fn default_verdict() -> String {
    "proxy".into()
}

#[derive(Debug, Deserialize)]
pub struct Socks5 {
    /// "host:port"
    pub server: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct Hysteria2 {
    /// "host:port" or "ip:port". Resolved via system DNS at startup.
    pub server: String,
    /// Auth credential (Hysteria-Auth header).
    #[serde(default)]
    pub password: String,
    /// TLS SNI; defaults to the server host.
    #[serde(default)]
    pub sni: String,
    /// Skip server certificate verification.
    #[serde(default)]
    pub insecure: bool,
    /// Local upload bandwidth ("100 Mbps", "80"); empty/"auto" = congestion control.
    #[serde(default)]
    pub up: String,
    /// Local download bandwidth; advertised to the server via Hysteria-CC-RX.
    #[serde(default)]
    pub down: String,
}

#[derive(Debug, Deserialize)]
pub struct Dns {
    /// Upstream resolver, queried directly (control-plane marked socket).
    pub upstream: String,
}

/// One routing rule; the list is evaluated in order and the first match on
/// its surface wins. Domain rules additionally drive the per-IP
/// DOMAIN_ROUTE map published by the DNS engine.
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    /// "cidr" | "domain" | "port" | "list" (list = ruleset file import)
    pub kind: String,
    /// CIDR ("10.0.0.0/8"), domain suffix ("cn", "example.com"), port (443),
    /// or a ruleset file path for kind="list".
    pub value: String,
    /// "direct" | "proxy" | "block"
    pub verdict: String,
}

/// Expand "list" rules (ruleset file import) into concrete cidr/domain rules.
/// Each file line holds one CIDR (contains '/') or one domain suffix; empty
/// lines and '#' comments are skipped, a "+." prefix is stripped.
pub fn expand_rules(config: &Config) -> Result<Vec<Rule>> {
    let mut out = Vec::new();
    for rule in &config.rules {
        if rule.kind != "list" {
            out.push(rule.clone());
            continue;
        }
        let text = std::fs::read_to_string(&rule.value)
            .with_context(|| format!("read ruleset {}", rule.value))?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let value = line.strip_prefix("+.").unwrap_or(line).to_string();
            if value.contains('/') {
                out.push(Rule {
                    kind: "cidr".into(),
                    value,
                    verdict: rule.verdict.clone(),
                });
            } else {
                out.push(Rule {
                    kind: "domain".into(),
                    value,
                    verdict: rule.verdict.clone(),
                });
            }
        }
        tracing::info!("imported ruleset {}", rule.value);
    }
    Ok(out)
}

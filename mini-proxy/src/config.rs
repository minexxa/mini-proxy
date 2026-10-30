//! Configuration model (TOML). Deliberately a tiny subset of dae syntax:
//! ordered rule list + one SOCKS5 outbound + one DNS upstream.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub general: General,
    pub socks5: Socks5,
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

#[derive(Debug, Deserialize)]
pub struct Dns {
    /// Upstream resolver, queried directly (control-plane marked socket).
    pub upstream: String,
}

/// One routing rule; the list is evaluated in order and the first match on
/// its surface wins. Domain rules additionally drive the per-IP
/// DOMAIN_ROUTE map published by the DNS engine.
#[derive(Debug, Deserialize)]
pub struct Rule {
    /// "cidr" | "domain" | "port"
    pub kind: String,
    /// CIDR ("10.0.0.0/8"), domain suffix ("cn", "example.com"), or port (443).
    pub value: String,
    /// "direct" | "proxy" | "block"
    pub verdict: String,
}

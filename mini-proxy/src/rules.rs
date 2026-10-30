//! Routing rules engine + map writers.
//!
//! eBPF only understands three concrete surfaces (CIDR LPM, ports, per-IP
//! domain verdicts). Domain *strings* are matched here, once per DNS answer,
//! and the resulting verdict is published into DOMAIN_ROUTE — the dae/dae
//! trick that lets the kernel route by domain without ever parsing DNS.

use anyhow::{Context, Result};
use aya::maps::lpm_trie::Key;
use aya::maps::{HashMap, MapData};
use mini_ebpf_common::{DomainRouteEntry, VERDICT_BLOCK, VERDICT_DIRECT, VERDICT_PROXY};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Direct,
    Proxy,
    Block,
}

impl Verdict {
    pub fn parse(s: &str) -> Result<Verdict> {
        match s {
            "direct" => Ok(Verdict::Direct),
            "proxy" => Ok(Verdict::Proxy),
            "block" => Ok(Verdict::Block),
            other => anyhow::bail!("unknown verdict: {other}"),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Verdict::Direct => VERDICT_DIRECT,
            Verdict::Proxy => VERDICT_PROXY,
            Verdict::Block => VERDICT_BLOCK,
        }
    }
}

pub struct Rules {
    pub default: Verdict,
    /// Ordered domain-suffix rules (matched bottom-up on labels).
    domain_rules: Vec<(Vec<String>, Verdict)>,
}

impl Rules {
    pub fn new(default_verdict: &str, rules: &[crate::config::Rule]) -> Result<Rules> {
        let mut domain_rules = Vec::new();
        for rule in rules {
            let verdict = Verdict::parse(&rule.verdict)?;
            match rule.kind.as_str() {
                "domain" => domain_rules.push((split_domain(&rule.value), verdict)),
                "cidr" | "port" => {}
                other => anyhow::bail!("unknown rule kind: {other}"),
            }
        }
        Ok(Rules {
            default: Verdict::parse(default_verdict)?,
            domain_rules,
        })
    }

    /// Longest-suffix match over the domain rule list.
    pub fn match_domain(&self, domain: &str) -> Verdict {
        let labels = split_domain(domain);
        let mut best: Option<(usize, Verdict)> = None;
        for (pattern, verdict) in &self.domain_rules {
            if pattern.len() > labels.len() {
                continue;
            }
            if pattern[..] == labels[labels.len() - pattern.len()..] && pattern.len() > 0 {
                if best.map(|(n, _)| pattern.len() > n).unwrap_or(true) {
                    best = Some((pattern.len(), *verdict));
                }
            }
        }
        best.map(|(_, v)| v).unwrap_or(self.default)
    }
}

fn split_domain(s: &str) -> Vec<String> {
    s.trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
        .map(|l| l.to_ascii_lowercase())
        .collect()
}

/// Static surfaces (CIDR / ports) written once at startup.
pub struct StaticMaps {
    pub domain_route: HashMap<MapData, [u8; 16], DomainRouteEntry>,
    pub port_route: HashMap<MapData, u16, u8>,
    pub cidr_v4: aya::maps::lpm_trie::LpmTrie<MapData, [u8; 4], u8>,
    pub cidr_v6: aya::maps::lpm_trie::LpmTrie<MapData, [u8; 16], u8>,
}

impl StaticMaps {
    pub fn populate_cidr_ports(&mut self, rules: &[crate::config::Rule]) -> Result<()> {
        for rule in rules {
            let verdict = Verdict::parse(&rule.verdict)?.to_u8();
            match rule.kind.as_str() {
                "cidr" => self.insert_cidr(&rule.value, verdict)?,
                "port" => {
                    let port: u16 = rule.value.parse().context("bad port in rule")?;
                    self.port_route.insert(port, verdict, 0)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn insert_cidr(&mut self, value: &str, verdict: u8) -> Result<()> {
        if let Ok((v4, plen)) = parse_v4_cidr(value) {
            self.cidr_v4
                .insert(&Key::new(plen as u32, v4.octets()), verdict, 0)?;
        } else if let Ok((v6, plen)) = parse_v6_cidr(value) {
            self.cidr_v6
                .insert(&Key::new(plen as u32, v6.octets()), verdict, 0)?;
        } else {
            anyhow::bail!("bad CIDR: {value}");
        }
        Ok(())
    }

    /// Publish one DNS-answered address with the verdict its domain resolves
    /// to. Called by the DNS engine for every A/AAAA record.
    pub fn publish_domain_ip(&mut self, ip: std::net::IpAddr, verdict: Verdict) -> Result<()> {
        let key = match ip {
            std::net::IpAddr::V4(v4) => {
                let mut k = [0u8; 16];
                k[10] = 0xff;
                k[11] = 0xff;
                k[12..16].copy_from_slice(&v4.octets());
                k
            }
            std::net::IpAddr::V6(v6) => v6.octets(),
        };
        let entry = DomainRouteEntry {
            verdict: verdict.to_u8(),
            _pad: [0; 7],
        };
        self.domain_route.insert(key, entry, 0)?;
        Ok(())
    }
}

pub fn parse_v4_cidr(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (addr, plen) = s
        .split_once('/')
        .with_context(|| format!("bad CIDR: {s}"))?;
    Ok((Ipv4Addr::from_str(addr)?, plen.parse()?))
}

pub fn parse_v6_cidr(s: &str) -> Result<(Ipv6Addr, u8)> {
    let (addr, plen) = s
        .split_once('/')
        .with_context(|| format!("bad CIDR: {s}"))?;
    Ok((Ipv6Addr::from_str(addr)?, plen.parse()?))
}

/// Shared handle handed to the DNS engine.
pub type SharedRules = Arc<tokio::sync::Mutex<Rules>>;

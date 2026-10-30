//! DNS engine: intercept UDP/53 flows, resolve through the configured
//! upstream on a control-plane socket, publish per-IP verdicts into
//! DOMAIN_ROUTE, and answer the client through a `daens` reply socket.

use crate::listener::create_reply_socket;
use crate::rules::{SharedRules, StaticMaps};
use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::os::fd::FromRawFd;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

pub struct DnsEngine {
    upstream: SocketAddr,
    rules: SharedRules,
    /// query cache: (qname, qtype) -> (response, expiry instant)
    cache: Mutex<std::collections::HashMap<(String, u16), (Vec<u8>, std::time::Instant)>>,
    /// Upstream socket, created lazily on the host namespace, marked.
    upstream_sock: tokio::sync::OnceCell<UdpSocket>,
}

impl DnsEngine {
    pub fn new(upstream: SocketAddr, rules: SharedRules) -> Self {
        DnsEngine {
            upstream,
            rules,
            cache: Mutex::new(Default::default()),
            upstream_sock: Default::default(),
        }
    }

    async fn upstream_socket(&self) -> Result<&UdpSocket> {
        self.upstream_sock
            .get_or_try_init(|| async {
                let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
                if fd < 0 {
                    anyhow::bail!("socket: {}", std::io::Error::last_os_error());
                }
                crate::datapath::mark_global_control(fd)?;
                unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
                let sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
                let sock = UdpSocket::from_std(sock)?;
                sock.connect(self.upstream).await?;
                Ok(sock)
            })
            .await
    }

    /// Handle one hijacked DNS flow. `payload` is the client's query,
    /// `client` its source, `orig` the original destination (DNS server).
    /// The reply socket is bound to `orig` inside `daens` so the answer
    /// looks like it came from the queried resolver.
    pub async fn handle_flow(
        &self,
        payload: &[u8],
        client: SocketAddr,
        orig: SocketAddr,
        maps: Arc<Mutex<crate::rules::StaticMaps>>,
    ) -> Result<()> {
        let qname = query_name(payload).unwrap_or_default();
        let qtype = query_type(payload).unwrap_or(0);

        // Resolve upstream and publish domain verdicts for every answer.
        let response = {
            let mut maps = maps.lock().await;
            self.resolve(payload, &qname, qtype, &mut maps).await?
        };

        // Answer through a transparent socket bound to the queried resolver.
        let reply_sock = create_reply_socket(orig)?;
        reply_sock.send_to(&response, client).await?;
        Ok(())
    }

    async fn resolve(
        &self,
        payload: &[u8],
        qname: &str,
        qtype: u16,
        maps: &mut StaticMaps,
    ) -> Result<Vec<u8>> {
        // 1. cache
        {
            let cache = self.cache.lock().await;
            if let Some((resp, expiry)) = cache.get(&(qname.to_string(), qtype)) {
                if *expiry > std::time::Instant::now() {
                    return Ok(resp.clone());
                }
            }
        }

        // 2. upstream query (control-plane marked, host namespace).
        let sock = self.upstream_socket().await?;
        sock.send(payload).await?;
        let mut buf = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            sock.recv_from(&mut buf),
        )
        .await
        .map_err(|_| anyhow!("DNS upstream timeout"))??;
        buf.truncate(n);

        // 3. publish verdicts: every A/AAAA answer for this qname routes by
        //    the domain rules matched against the qname.
        let verdict = self.rules.lock().await.match_domain(qname);
        for ip in answer_ips(&buf) {
            maps.publish_domain_ip(ip, verdict)?;
        }

        // 4. cache by the minimum answer TTL.
        let ttl = answer_min_ttl(&buf).unwrap_or(60);
        self.cache.lock().await.insert(
            (qname.to_string(), qtype),
            (buf.clone(), std::time::Instant::now() + std::time::Duration::from_secs(ttl)),
        );
        Ok(buf)
    }
}

fn query_name(msg: &[u8]) -> Option<String> {
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut pos = 12usize;
    let mut labels = Vec::new();
    loop {
        let len = *msg.get(pos)?;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return None; // compression in qname: unusual, bail
        }
        pos += 1;
        let label = msg.get(pos..pos + len as usize)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += len as usize;
    }
    Some(labels.join("."))
}

fn query_type(msg: &[u8]) -> Option<u16> {
    let mut pos = 12usize;
    loop {
        let len = *msg.get(pos)?;
        if len == 0 {
            return Some(u16::from_be_bytes([
                *msg.get(pos + 1)?,
                *msg.get(pos + 2)?,
            ]));
        }
        pos += 1 + len as usize;
    }
}

/// A/AAAA record addresses in the answer section.
fn answer_ips(msg: &[u8]) -> Vec<std::net::IpAddr> {
    let mut out = Vec::new();
    let Some(ancount) = msg.get(6..8).map(|b| u16::from_be_bytes([b[0], b[1]])) else {
        return out;
    };
    if ancount == 0 {
        return out;
    }
    // Skip the question section.
    let mut pos = 12usize;
    loop {
        let Some(len) = msg.get(pos).copied() else { return out };
        if len == 0 {
            pos += 1;
            break;
        }
        pos += 1 + len as usize;
    }
    pos += 4; // qtype + qclass

    for _ in 0..ancount {
        // name (possibly compressed)
        let Some(b) = msg.get(pos).copied() else { return out };
        pos += if b & 0xc0 != 0 { 2 } else { 1 + b as usize + 1 };
        let Some((rtype, rdlen)) = msg.get(pos..pos + 10).map(|b| {
            (u16::from_be_bytes([b[0], b[1]]), u16::from_be_bytes([b[8], b[9]]))
        }) else {
            return out;
        };
        let rdata = msg.get(pos + 10..pos + 10 + rdlen as usize).unwrap_or(&[]);
        match (rtype, rdata.len()) {
            (1, 4) => out.push(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            ))),
            (28, 16) => {
                out.push(std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(rdata).unwrap(),
                )));
            }
            _ => {}
        }
        pos += 10 + rdlen as usize;
    }
    out
}

fn answer_min_ttl(msg: &[u8]) -> Option<u64> {
    // Same walk as answer_ips but collecting TTLs; compact duplicate logic
    // is fine for a reference engine.
    let ancount = u16::from_be_bytes([*msg.get(6)?, *msg.get(7)?]);
    if ancount == 0 {
        return None;
    }
    let mut pos = 12usize;
    loop {
        let len = *msg.get(pos)?;
        if len == 0 {
            pos += 1;
            break;
        }
        pos += 1 + len as usize;
    }
    pos += 4;
    let mut min = u64::MAX;
    for _ in 0..ancount {
        let b = *msg.get(pos)?;
        pos += if b & 0xc0 != 0 { 2 } else { 1 + b as usize + 1 };
        let Some(hdr) = msg.get(pos..pos + 10) else { return None };
        let rdlen = u16::from_be_bytes([hdr[8], hdr[9]]);
        let ttl = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        min = min.min(ttl as u64);
        pos += 10 + rdlen as usize;
    }
    (min != u64::MAX).then_some(min)
}

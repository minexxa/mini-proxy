//! Transparent relay: consumes the `daens` listeners.
//!
//! TCP: accepted conns carry the original destination (IP_TRANSPARENT +
//! sk_lookup assignment); relay to the outbound (SOCKS5 / Hysteria2) over a
//! control-plane marked dial socket, copying both directions.
//!
//! UDP: each datagram carries its original destination via IP_RECVORIGDSTADDR.
//! Flows to port 53 are handed to the DNS engine; other flows go through the
//! outbound's UDP relay. Replies are sent from a per-flow socket bound to the
//! original destination inside `daens`, so the datapath's dae0_ingress
//! restores the captured framing and hands them back to the client.

use crate::listener::{create_reply_socket, orig_dst_tcp};
use crate::outbound::{BoxStream, Outbound, UdpUpstream};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

pub async fn run_tcp(listener: tokio::net::TcpListener, outbound: Arc<Outbound>) -> Result<()> {
    loop {
        let (conn, _client) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "tcp accept");
                continue;
            }
        };
        let outbound = outbound.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp(conn, outbound).await {
                tracing::debug!(error = %e, "tcp flow ended");
            }
        });
    }
}

async fn handle_tcp(conn: TcpStream, outbound: Arc<Outbound>) -> Result<()> {
    let orig = orig_dst_tcp(&conn)?;
    let upstream: BoxStream = outbound.connect_tcp(orig).await?;
    let (mut cr, mut cw) = conn.into_split();
    let (mut ur, mut uw) = tokio::io::split(upstream);
    let c2u = tokio::io::copy(&mut cr, &mut uw);
    let u2c = tokio::io::copy(&mut ur, &mut cw);
    tokio::select! {
        r = c2u => { r?; let _ = cw.shutdown().await; }
        r = u2c => { r?; let _ = uw.shutdown().await; }
    }
    Ok(())
}

struct UdpFlow {
    /// Outbound UDP relay channel.
    upstream: UdpUpstream,
    /// Reply socket bound to the original destination inside `daens`.
    reply: UdpSocket,
    client: SocketAddr,
}

pub async fn run_udp(
    sock: std::net::UdpSocket,
    outbound: Arc<Outbound>,
    dns: Arc<crate::dns::DnsEngine>,
    maps: Arc<Mutex<crate::rules::StaticMaps>>,
) -> Result<()> {
    // Dedicated blocking recv thread: the transparent socket is read with
    // recvmsg(RECVORIGDSTADDR), which has no tokio equivalent. Datagrams are
    // forwarded to the async dispatcher over a channel.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<UdpEvent>();
    std::thread::Builder::new().name("udp-recv".into()).spawn({
        use std::os::fd::AsRawFd;
        move || loop {
            let mut buf = vec![0u8; 65535];
            match unsafe { recv_orig_dst_blocking(sock.as_raw_fd(), &mut buf) } {
                Ok((n, client, orig)) => {
                    let payload = buf[..n].to_vec();
                    if tx
                        .send(UdpEvent {
                            payload,
                            client,
                            orig,
                        })
                        .is_err()
                    {
                        break; // dispatcher gone: shut down
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "udp recvmsg");
                }
            }
        }
    })?;

    let flows: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), Arc<UdpFlow>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    while let Some(ev) = rx.recv().await {
        let UdpEvent {
            payload,
            client,
            orig,
        } = ev;
        let key = (client, orig);

        if orig.port() == 53 {
            let dns = dns.clone();
            let maps = maps.clone();
            tokio::spawn(async move {
                if let Err(e) = dns.handle_flow(&payload, client, orig, maps).await {
                    tracing::warn!(error = %e, "dns flow");
                }
            });
            continue;
        }

        let flow = {
            let mut table = flows.lock().await;
            if let Some(f) = table.get(&key) {
                f.clone()
            } else {
                let flow = match create_udp_flow(&outbound, key).await {
                    Ok(f) => Arc::new(f),
                    Err(e) => {
                        tracing::warn!(error = %e, "udp flow setup");
                        continue;
                    }
                };
                table.insert(key, flow.clone());
                // One pump per flow: reads the SOCKS5 relay endpoint and
                // emits replies from the daens reply socket. Exits on idle.
                let pump_flow = flow.clone();
                let table_ref = flows.clone();
                tokio::spawn(async move {
                    let idle = pump_udp_replies(pump_flow).await;
                    table_ref.lock().await.remove(&key);
                    if let Err(e) = idle {
                        tracing::debug!(error = %e, "udp pump ended");
                    }
                });
                flow
            }
        };

        // Forward through the outbound relay channel.
        if let Err(e) = flow.upstream.send(&payload, orig).await {
            tracing::warn!(error = %e, "udp upstream send");
        }
    }
    Ok(())
}

async fn create_udp_flow(
    outbound: &Arc<Outbound>,
    key: (SocketAddr, SocketAddr),
) -> Result<UdpFlow> {
    let (client, _orig) = key;
    let upstream = outbound.udp_session().await?;
    let reply = create_reply_socket(_orig)?;
    Ok(UdpFlow {
        upstream,
        reply,
        client,
    })
}

async fn pump_udp_replies(flow: Arc<UdpFlow>) -> Result<()> {
    let mut buf = vec![0u8; 65535];
    loop {
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(300),
            flow.upstream.recv(&mut buf),
        )
        .await??;
        // Emit from the original-destination socket: src = orig, dst = client,
        // routed out of daens via dae0peer and restored by dae0_ingress.
        flow.reply.send_to(&buf[..n], flow.client).await?;
    }
}

struct UdpEvent {
    payload: Vec<u8>,
    client: SocketAddr,
    orig: SocketAddr,
}

/// recvmsg wrapper extracting IP_RECVORIGDSTADDR ancillary data. Runs on the
/// dedicated blocking recv thread; `fd` must be a blocking socket.
unsafe fn recv_orig_dst_blocking(
    fd: std::os::fd::RawFd,
    buf: &mut [u8],
) -> Result<(usize, SocketAddr, SocketAddr)> {
    // SAFETY: single-threaded FFI on the recv thread; buffers outlive the call.
    unsafe {
        let mut iovec = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut cmsg_buf = [0u8; 128];
        let mut from: libc::sockaddr_storage = std::mem::zeroed();
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iovec;
        msg.msg_iovlen = 1;
        msg.msg_name = &mut from as *mut _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_buf.len();

        let n = loop {
            let rc = libc::recvmsg(fd, &mut msg, 0);
            if rc >= 0 {
                break rc as usize;
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted
                || err.kind() == std::io::ErrorKind::WouldBlock
            {
                continue;
            }
            anyhow::bail!("recvmsg: {err}");
        };

        let client = sockaddr_to_addr(&from).context("client addr")?;
        let mut orig = None;
        let mut cpos = cmsg_buf.as_mut_ptr();
        let end = cmsg_buf
            .as_mut_ptr()
            .add(cmsg_buf.len() - msg.msg_controllen as usize);
        while cpos < end {
            let ch = cpos as *const libc::cmsghdr;
            let level = (*ch).cmsg_level;
            let ctype = (*ch).cmsg_type;
            if (level == libc::IPPROTO_IP && ctype == libc::IP_RECVORIGDSTADDR)
                || (level == libc::IPPROTO_IPV6 && ctype == libc::IPV6_RECVORIGDSTADDR)
            {
                let data =
                    cpos.add(std::mem::size_of::<libc::cmsghdr>()) as *const libc::sockaddr_storage;
                orig = sockaddr_to_addr(&*data);
                break;
            }
            cpos = cpos.add(cmsg_align((*ch).cmsg_len as usize));
        }
        let orig = orig.context("no orig dst ancillary")?;
        Ok((n, client, orig))
    }
}

/// CMSG_ALIGN is a libc macro, not a function — replicate it here.
fn cmsg_align(len: usize) -> usize {
    (len + std::mem::size_of::<usize>() - 1) & !(std::mem::size_of::<usize>() - 1)
}

fn sockaddr_to_addr(ss: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match ss.ss_family as libc::c_int {
        libc::AF_INET => {
            let a: &libc::sockaddr_in = unsafe { &*(ss as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
            Some(SocketAddr::new(ip.into(), u16::from_be(a.sin_port)))
        }
        libc::AF_INET6 => {
            let a: &libc::sockaddr_in6 = unsafe { &*(ss as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(a.sin6_addr.s6_addr);
            Some(SocketAddr::new(ip.into(), u16::from_be(a.sin6_port)))
        }
        _ => None,
    }
}

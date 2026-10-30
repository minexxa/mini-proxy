//! Transparent relay: consumes the `daens` listeners.
//!
//! TCP: accepted conns carry the original destination (IP_TRANSPARENT +
//! sk_lookup assignment); relay to the SOCKS5 server over a pre-marked
//! dial socket (CONNECT), copying both directions.
//!
//! UDP: each datagram carries its original destination via IP_RECVORIGDSTADDR.
//! Flows to port 53 are handed to the DNS engine; other flows use SOCKS5
//! UDP ASSOCIATE. Replies are sent from a per-flow socket bound to the
//! original destination inside `daens`, so the datapath's dae0_ingress
//! restores the captured framing and hands them back to the client.

use crate::listener::{create_reply_socket, orig_dst_tcp};
use crate::socks5::Socks5Client;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

pub async fn run_tcp(listener: tokio::net::TcpListener, socks: Arc<Socks5Client>) -> Result<()> {
    loop {
        let (conn, _client) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "tcp accept");
                continue;
            }
        };
        let socks = socks.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp(conn, socks).await {
                tracing::debug!(error = %e, "tcp flow ended");
            }
        });
    }
}

async fn handle_tcp(conn: TcpStream, socks: Arc<Socks5Client>) -> Result<()> {
    let orig = orig_dst_tcp(&conn)?;
    let mut upstream = socks.connect_tcp(orig).await?;
    let (mut cr, mut cw) = conn.into_split();
    let (mut ur, mut uw) = upstream.split();
    let c2u = tokio::io::copy(&mut cr, &mut uw);
    let u2c = tokio::io::copy(&mut ur, &mut cw);
    tokio::select! {
        r = c2u => { r?; let _ = cw.shutdown().await; }
        r = u2c => { r?; let _ = uw.shutdown().await; }
    }
    Ok(())
}

struct UdpFlow {
    /// SOCKS5 relay endpoint socket (control-plane marked, host ns).
    socks_udp: UdpSocket,
    /// ASSOCIATE control connection; dropped with the flow.
    _control: TcpStream,
    /// Reply socket bound to the original destination inside `daens`.
    reply: UdpSocket,
    client: SocketAddr,
}

pub async fn run_udp(
    listener: tokio::net::UdpSocket,
    socks: Arc<Socks5Client>,
    dns: Arc<crate::dns::DnsEngine>,
    maps: Arc<Mutex<crate::rules::StaticMaps>>,
) -> Result<()> {
    let flows: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), Arc<UdpFlow>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    loop {
        let buf = vec![0u8; 65535];
        let (buf, n, client, orig) = match recv_orig_dst(&listener, buf).await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "udp recvmsg");
                continue;
            }
        };
        let payload = buf[..n].to_vec();
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
                let flow = match create_udp_flow(&socks, key).await {
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

        // Wrap in the SOCKS5 UDP request header and forward.
        let mut pkt = vec![0u8, 0, 0];
        push_udp_addr(&mut pkt, orig);
        pkt.extend_from_slice(&payload);
        if let Err(e) = flow.socks_udp.send(&pkt).await {
            tracing::warn!(error = %e, "udp upstream send");
        }
    }
}

async fn create_udp_flow(
    socks: &Arc<Socks5Client>,
    key: (SocketAddr, SocketAddr),
) -> Result<UdpFlow> {
    let (client, orig) = key;
    let (control, socks_udp) = socks.associate_udp().await?;
    let reply = create_reply_socket(orig)?;
    Ok(UdpFlow {
        socks_udp,
        _control: control,
        reply,
        client,
    })
}

async fn pump_udp_replies(flow: Arc<UdpFlow>) -> Result<()> {
    let mut buf = vec![0u8; 65535];
    loop {
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(300),
            flow.socks_udp.recv(&mut buf),
        )
        .await??;
        if n < 4 {
            continue;
        }
        let (payload, _remote) = parse_udp_header(&buf[..n])?;
        // Emit from the original-destination socket: src = orig, dst = client,
        // routed out of daens via dae0peer and restored by dae0_ingress.
        flow.reply.send_to(payload, flow.client).await?;
    }
}

fn push_udp_addr(buf: &mut Vec<u8>, addr: SocketAddr) {
    match addr {
        SocketAddr::V4(a) => {
            buf.push(1);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            buf.push(4);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
    }
}

fn parse_udp_header(msg: &[u8]) -> Result<(&[u8], SocketAddr)> {
    if msg.len() < 4 {
        anyhow::bail!("short UDP relay packet");
    }
    let atyp = msg[3];
    let (addr, hdr_len) = match atyp {
        1 => {
            if msg.len() < 10 {
                anyhow::bail!("short v4 UDP header");
            }
            let ip = std::net::Ipv4Addr::new(msg[4], msg[5], msg[6], msg[7]);
            let port = u16::from_be_bytes([msg[8], msg[9]]);
            (SocketAddr::new(ip.into(), port), 10)
        }
        4 => {
            if msg.len() < 22 {
                anyhow::bail!("short v6 UDP header");
            }
            let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&msg[4..20]).unwrap());
            let port = u16::from_be_bytes([msg[20], msg[21]]);
            (SocketAddr::new(ip.into(), port), 22)
        }
        other => anyhow::bail!("UDP relay ATYP {other}"),
    };
    Ok((&msg[hdr_len..], addr))
}

/// recvmsg wrapper extracting IP_RECVORIGDSTADDR ancillary data. The buffer
/// is round-tripped through the blocking pool so the async caller stays
/// borrow-free.
async fn recv_orig_dst(
    sock: &UdpSocket,
    buf: Vec<u8>,
) -> Result<(Vec<u8>, usize, SocketAddr, SocketAddr)> {
    use std::os::fd::AsRawFd;
    let fd = sock.as_raw_fd();
    tokio::task::spawn_blocking(move || unsafe { recv_orig_dst_blocking(fd, buf) }).await?
}

unsafe fn recv_orig_dst_blocking(
    fd: std::os::fd::RawFd,
    mut buf: Vec<u8>,
) -> Result<(Vec<u8>, usize, SocketAddr, SocketAddr)> {
    // SAFETY: single-threaded FFI on the blocking pool; buffers outlive the call.
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
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        anyhow::bail!("recvmsg: {err}");
    };

    let client = sockaddr_to_addr(&from).context("client addr")?;
    let mut orig = None;
    let mut cpos = cmsg_buf.as_mut_ptr();
    let end = cmsg_buf.as_mut_ptr().add(cmsg_buf.len() - msg.msg_controllen as usize);
    while cpos < end {
        let ch = cpos as *const libc::cmsghdr;
        let level = (*ch).cmsg_level;
        let ctype = (*ch).cmsg_type;
        if (level == libc::IPPROTO_IP && ctype == libc::IP_RECVORIGDSTADDR)
            || (level == libc::IPPROTO_IPV6 && ctype == libc::IPV6_RECVORIGDSTADDR)
        {
            let data = cpos.add(std::mem::size_of::<libc::cmsghdr>())
                as *const libc::sockaddr_storage;
            orig = sockaddr_to_addr(&*data);
            break;
        }
        cpos = cpos.add(cmsg_align((*ch).cmsg_len as usize));
    }
    let orig = orig.context("no orig dst ancillary")?;
    Ok((buf, n, client, orig))
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

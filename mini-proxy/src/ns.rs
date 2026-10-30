//! Proxy namespace (`daens`) ownership, following honk's lifecycle:
//! a throwaway thread unshares a fresh network namespace and hands the ns
//! fd back to the process; every later entry uses setns(2) under a mutex.
//! A best-effort bind mount at /run/netns/<name> lets `ip -n` manage links.

use anyhow::{Context, Result};
use libc::{CLONE_NEWNET, MSG_CMSG_CLOEXEC};
use nix::sys::socket::{
    recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags, SockProtocol, UnixAddr,
};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Mutex, OnceLock};

static DAENS: OnceLock<OwnedFd> = OnceLock::new();
static ENTER_LOCK: Mutex<()> = Mutex::new(());

pub const NETNS_NAME: &str = "mini-proxy-daens";

/// A fresh fd referring to the proxy namespace (for aya `SkLookup::attach`).
pub fn daens_fd() -> Result<OwnedFd> {
    let ns = DAENS.get().context("daens not created")?;
    Ok(ns.try_clone()?)
}

/// Create the proxy namespace and retain its fd for the process lifetime.
pub fn create_daens() -> Result<()> {
    let (a, b) = nix::sys::socket::socketpair(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::Stream,
        None::<SockProtocol>,
        nix::sys::socket::SockFlag::empty(),
    )?;
    let a = a.as_raw_fd();
    let handle = std::thread::spawn(move || {
        // Isolate the unshare on a throwaway thread; the main process stays
        // in the host namespace.
        let rc = unsafe { libc::unshare(CLONE_NEWNET) };
        if rc != 0 {
            anyhow::bail!("unshare(CLONE_NEWNET): {}", std::io::Error::last_os_error());
        }
        let ns_path = std::path::Path::new("/proc/thread-self/ns/net");
        let fd = std::fs::File::open(ns_path).context("open thread-self ns/net")?;
        // Send the fd over SCM_RIGHTS. A payload byte is required: a
        // zero-length send on a stream socket is a no-op and the fd
        // would never be delivered.
        let fd = fd.as_raw_fd();
        sendmsg::<UnixAddr>(
            b.as_raw_fd(),
            &[std::io::IoSlice::new(&[1u8])],
            &[ControlMessage::ScmRights(&[fd])],
            MsgFlags::empty(),
            None,
        )?;
        anyhow::Ok(())
    });
    handle
        .join()
        .map_err(|_| anyhow::anyhow!("unshare thread panicked"))??;

    // Receive the fd.
    let mut buf = [0u8; 8];
    let mut iov = [std::io::IoSliceMut::new(&mut buf)];
    let msg = recvmsg::<UnixAddr>(
        a,
        &mut iov,
        None,
        MsgFlags::from_bits_truncate(MSG_CMSG_CLOEXEC),
    )
    .context("recvmsg scm_rights")?;
    let fd = match msg.cmsgs().context("cmsgs")?.next() {
        Some(ControlMessageOwned::ScmRights(fds)) => fds.first().copied(),
        _ => None,
    }
    .context("no fd received")?;

    let ns = unsafe { OwnedFd::from_raw_fd(fd) };
    DAENS.set(ns).ok().context("daens already created")?;

    // Best-effort bind mount for `ip -n` tooling; not required at runtime.
    let _ = bind_mount_netns();
    Ok(())
}

fn bind_mount_netns() -> Result<()> {
    let dir = std::path::Path::new("/run/netns");
    std::fs::create_dir_all(dir).ok();
    let target = dir.join(NETNS_NAME);
    if target.exists() {
        std::fs::remove_file(&target).ok();
    }
    std::fs::File::create(&target)?;
    let ns = DAENS.get().context("daens")?;
    let source = format!("/proc/self/fd/{}", ns.as_raw_fd());
    let src_c = std::ffi::CString::new(source)?;
    let tgt_c = std::ffi::CString::new(target.as_os_str().as_encoded_bytes())?;
    let rc = unsafe {
        libc::mount(
            src_c.as_ptr(),
            tgt_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        anyhow::bail!("bind mount netns failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

/// Run `f` inside `daens`, restoring the caller's namespace on all paths.
/// Never call this around an `.await` point: setns(2) is per-thread.
pub fn with_daens<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    let ns = DAENS.get().context("daens not created")?.as_raw_fd();
    let _guard = ENTER_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let saved = open_current_ns()?;
    let restore = |fd: &OwnedFd| {
        let rc = unsafe { libc::setns(fd.as_raw_fd(), CLONE_NEWNET) };
        rc == 0
    };
    let rc = unsafe { libc::setns(ns, CLONE_NEWNET) };
    if rc != 0 {
        anyhow::bail!("setns daens: {}", std::io::Error::last_os_error());
    }
    let out = f();
    if !restore(&saved) {
        tracing::error!("failed to restore host netns; aborting");
        std::process::abort();
    }
    out
}

fn open_current_ns() -> Result<OwnedFd> {
    let fd = std::fs::File::open("/proc/thread-self/ns/net").context("open current ns")?;
    Ok(fd.into())
}

/// Run an `ip`/`sysctl` command and require success.
pub fn run_cmd(args: &[&str]) -> Result<()> {
    tracing::debug!(cmd = %args.join(" "), "exec");
    let out = std::process::Command::new(args[0])
        .args(&args[1..])
        .output()
        .with_context(|| format!("spawn {}", args[0]))?;
    if !out.status.success() {
        anyhow::bail!(
            "`{}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// Run `ip -n daens ...` inside the proxy namespace.
pub fn run_ip_netns(args: &[&str]) -> Result<()> {
    let mut full: Vec<&str> = vec!["ip", "-n", NETNS_NAME];
    full.extend_from_slice(args);
    run_cmd(&full)
}

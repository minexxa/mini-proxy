//! Raw bpf(2) helpers for operations aya does not expose or that are simpler
//! at the syscall level: sk_storage marking of control-plane sockets.

use anyhow::Result;
use std::os::fd::{AsRawFd, RawFd};

const BPF_MAP_UPDATE_ELEM: i64 = 2;
const BPF_SK_STORAGE_GET_F_CREATE: u64 = 1;

/// Kernel contract for BPF_MAP_TYPE_SK_STORAGE updates: `key` points to an
/// int holding the map's value_size, and the target socket fd rides in the
/// upper 32 bits of `flags`.
pub fn mark_control_socket(sk_storage_map_fd: RawFd, sock_fd: RawFd) -> Result<()> {
    #[repr(C)]
    struct Attr {
        map_fd: u32,
        pad: u32,
        key: u64,
        value: u64,
        flags: u64,
    }
    let value_size: i32 = 4; // SK_IDENTITY stores u32
    let value: u32 = 1;
    let attr = Attr {
        map_fd: sk_storage_map_fd as u32,
        pad: 0,
        key: &value_size as *const i32 as u64,
        value: &value as *const u32 as u64,
        flags: ((sock_fd as u64) << 32) | BPF_SK_STORAGE_GET_F_CREATE,
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_UPDATE_ELEM,
            &attr as *const Attr,
            std::mem::size_of::<Attr>(),
        )
    };
    if rc < 0 {
        return Err(anyhow::anyhow!(
            "sk_storage update failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Set SO_MARK on a socket so egress skbs carry CONTROL_MARK.
pub fn set_socket_mark(fd: RawFd, mark: u32) -> Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(anyhow::anyhow!(
            "SO_MARK failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[allow(dead_code)]
pub fn fd_as_raw<F: AsRawFd>(f: &F) -> RawFd {
    f.as_raw_fd()
}

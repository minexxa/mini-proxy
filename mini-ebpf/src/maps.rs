//! eBPF map definitions. Contract shared with `mini-ebpf-common` and the
//! userspace writers in `mini-proxy`.
//!
//! Trimmed from honk's 40+ maps down to seven surfaces:
//! FLOW_TRACK (reply framing), DOMAIN_ROUTE (DNS-derived per-IP verdicts),
//! CIDR tries, PORT_ROUTE, LISTEN_SOCKETS, SK_IDENTITY (loop prevention).

use aya_ebpf::btf_maps::{HashMap, LruHashMap, SkStorage, SockMap};
use aya_ebpf::helpers::bpf_sk_storage_get;
use aya_ebpf::macros::{btf_map, map};
use aya_ebpf::maps::lpm_trie::LpmTrie;
use aya_ebpf::Global;
use mini_ebpf_common::{DomainRouteEntry, FlowKey, Param, TrackEntry, CONTROL_MARK};

#[unsafe(no_mangle)]
pub static PARAM: Global<Param> = Global::new(Param::DEFAULT);

/// Forward-direction flow -> captured framing, for reply restoration in
/// `dae0_ingress` (mirrors honk's REDIRECT_TRACK / CLIENT_REPLY_TRACK).
#[btf_map]
pub static FLOW_TRACK: LruHashMap<FlowKey, TrackEntry, 65536> = LruHashMap::new();

/// dst IP -> verdict, published by the userspace DNS engine whenever a DNS
/// answer resolves a domain that carries a routing decision
/// (mirrors dae's routing_map idea: eBPF never inspects domain strings).
#[btf_map]
pub static DOMAIN_ROUTE: LruHashMap<[u8; 16], DomainRouteEntry, 65536> = LruHashMap::new();

/// Destination port -> verdict.
#[btf_map]
pub static PORT_ROUTE: HashMap<u16, u8, 1024, 1> = HashMap::new();

/// CIDR -> verdict, longest prefix match. Legacy maps: LpmTrie is not yet a
/// BTF map in aya-ebpf. Key data is raw network-byte-order address bytes.
#[map]
pub static CIDR_V4: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(65536, 0);

#[map]
pub static CIDR_V6: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(65536, 0);

/// Transparent listeners published by userspace inside `daens`.
/// Keys: 0 = TCP IPv4, 1 = TCP IPv6, 2 = UDP IPv4, 3 = UDP IPv6.
pub const KEY_TCP4: u32 = 0;
pub const KEY_TCP6: u32 = 1;
pub const KEY_UDP4: u32 = 2;
pub const KEY_UDP6: u32 = 3;

#[btf_map]
pub static LISTEN_SOCKETS: SockMap<4> = SockMap::new();

/// Userspace marks every control-plane dial socket (SOCKS5, DNS upstream)
/// both with skb mark CONTROL_MARK (SO_MARK, reflected on egress) and with
/// this sk_storage flag; `wan_egress` passes marked sockets so the proxy
/// never captures its own outbound traffic (loop prevention).
#[btf_map]
pub static SK_IDENTITY: SkStorage<u32> = SkStorage::new();

#[inline(always)]
pub fn is_control_plane_socket(skb: *mut aya_ebpf_bindings::bindings::__sk_buff) -> bool {
    // Cheap check first: SO_MARK on the dial socket shows up as skb->mark.
    if unsafe { (*skb).mark } == CONTROL_MARK {
        return true;
    }
    let sk = unsafe { (*skb).__bindgen_anon_2.sk };
    if sk.is_null() {
        return false;
    }
    let map = (&raw const SK_IDENTITY).cast_mut().cast();
    !unsafe { bpf_sk_storage_get(map, sk.cast(), core::ptr::null_mut(), 0) }.is_null()
}

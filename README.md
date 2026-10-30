# mini-proxy

A minimal transparent proxy built on the honk/dae kernel datapath design:
eBPF steers traffic in the kernel, **direct traffic never reaches
userspace** — only flows the kernel verdicts as "proxy" enter this process,
which relays them to a SOCKS5 server.

Reuses honk's architecture (veth-pair proxy netns, TC hooks, sk_lookup,
DNS-derived per-IP domain routing) with a drastically trimmed map surface
(7 maps instead of 40+) and a small, single-binary userspace.

## Layout

```
mini-ebpf-common/   shared kernel<->userspace ABI (no_std)
mini-ebpf/          eBPF programs (aya-ebpf, standalone crate)
mini-proxy/         userspace: loader, netns, listeners, SOCKS5, DNS engine
```

### eBPF programs (4 + sk_lookup)

| Program              | Hook                      | Role |
|----------------------|---------------------------|------|
| `lan_ingress`        | TC ingress, LAN iface     | gateway capture |
| `wan_egress`         | TC egress, WAN iface      | host-originated capture |
| `dae0peer_ingress`   | TC ingress, dae0peer      | restore skb mark inside `daens` |
| `dae0_ingress`       | TC ingress, dae0          | restore reply framing, TX back |
| `sk_lookup`          | netns `daens`             | assign conns to transparent listeners |

### Maps

`FLOW_TRACK` (reply framing) · `DOMAIN_ROUTE` (per-IP verdicts from DNS) ·
`CIDR_V4/V6` (LPM) · `PORT_ROUTE` · `LISTEN_SOCKETS` (sockmap) ·
`SK_IDENTITY` (sk_storage loop-prevention) · `PARAM` (global config).

### Routing decision (kernel, first match wins)

1. DNS hijack — UDP dport 53 → userspace DNS engine
2. `DOMAIN_ROUTE` — per-IP verdict published by the DNS engine
3. CIDR longest-prefix match
4. Port table
5. `general.default_verdict`

`direct` → `TC_ACT_OK` (never touches userspace); `block` → dropped;
`proxy` → marked + recorded in `FLOW_TRACK` + redirected into the `daens`
proxy namespace, where sk_lookup hands the flow to the transparent
listeners in this process.

### Domain routing

eBPF never inspects domain strings. The DNS engine matches domain rules
against queried names, then publishes a verdict for **every IP** in the
answer into `DOMAIN_ROUTE`. Subsequent data packets to those IPs route by
domain — dae's trick, simplified.

### Loop prevention

Every outbound control-plane socket (SOCKS5 dial, DNS upstream) is marked
with `SO_MARK` (visible as `skb->mark`) *and* carries an sk_storage flag;
`wan_egress` passes sockets carrying either.

## Requirements

- Linux ≥ 6.6 (TCX/SchedClassifier attach; developed against honk's 6.12+ target)
- root privileges (TC, sk_lookup, netns, IP_TRANSPARENT)
- `iproute2` (`ip`, `tc`), and a SOCKS5 server that supports CONNECT +
  UDP ASSOCIATE

## Build

```sh
# 1. eBPF object (nightly, bpf-linker)
rustup component add rust-src
# bpf-linker must match your rustc nightly's bundled LLVM version
# (rustc -vV | grep llvm-version). Example for an LLVM-22 nightly on
# Ubuntu 24.04:
apt-get install -y llvm-22-dev libpolly-22-dev
LLVM_CONFIG_PATH=/usr/lib/llvm-22/bin/llvm-config \
RUSTFLAGS="-L /usr/lib/llvm-22/lib -C link-arg=-Wl,-rpath,/usr/lib/llvm-22/lib" \
  cargo install bpf-linker --version 0.11.1 --no-default-features --features llvm-22

cd mini-ebpf
cargo build --release -Zbuild-std=core --target bpfel-unknown-none

# 2. Userspace (stable)
cd ..
cargo build --release --features ebpf
# binary: target/release/mini-proxy
```

Note: bpf-linker's LLVM must match the rustc nightly's bundled LLVM —
older linkers (0.9.x) can't read LLVM 22 bitcode; 0.11.x needs a matching
system LLVM for the chosen feature.

## Run

```sh
sudo ./target/release/mini-proxy --config config.example.toml
```

Rules live in the TOML config (see `config.example.toml`): CIDR, port, and
domain-suffix rules with `direct`/`proxy`/`block` verdicts.

## What's intentionally missing (vs honk)

- No geoip/geosite databases, no logic/parameter expressions
- TCP only via SOCKS5 CONNECT; UDP via UDP ASSOCIATE (no QUIC-side tricks)
- Only plain UDP/53 DNS hijack (no DoH/DoT interception)
- Single SOCKS5 outbound, single DNS upstream
- No fragment reassembly routing (fragments fall through to
  address/port-less surfaces like dae)

## License

GPL-3.0-only. The eBPF side follows honk's design and this project
inherits that choice; see honk's licensing notes.

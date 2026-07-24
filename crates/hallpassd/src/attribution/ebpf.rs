//! eBPF-backed attribution: kernel programs (crates/hallpass-ebpf) record
//! the owning pid/uid of every outgoing TCP connect and UDP send in a
//! flow map keyed by tuple; a ring buffer streams process exec/exit
//! events so exe/cmdline can be snapshotted while the process is fresh.
//!
//! Compiled only with the `ebpf` feature, which requires a prior
//! `cargo xtask build-ebpf` to produce the embedded object. Any load or
//! attach failure (old kernel, missing CAP_BPF, no kprobe support) is a
//! warning and the constructor returns None: the chain then behaves
//! exactly as before, with procfs alone.

use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aya::maps::{HashMap as FlowMap, MapData, RingBuf};
use aya::programs::uprobe::UProbeScope;
use aya::programs::{KProbe, TracePoint, UProbe};
use aya::{Ebpf, EbpfLoader};
use lru::LruCache;
use hallpass_ebpf_common::{DnsEvent, ExecEvent, FlowKey, FlowVal, EVENT_EXEC, PROTO_TCP, PROTO_UDP};
use hallpass_types::{FlowTuple, Proto};

use crate::dns::{IpDomainCache, SnoopedResponse};

use super::btf::Btf;
use super::{procfs, Attributor, ProcInfo};

/// The object produced by `cargo xtask build-ebpf`.
static EBPF_OBJ: &[u8] = aya::include_bytes_aligned!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/bpfel-unknown-none/release/hallpass-ebpf"
));

/// pid -> details snapshotted at exec time. Exit events are the primary
/// eviction path, but they are lossy (the ring buffer drops under
/// pressure), so the LRU cap is the backstop against unbounded growth.
type ProcCache = Arc<Mutex<LruCache<u32, (Option<PathBuf>, Option<String>, Option<PathBuf>)>>>;

const PID_CACHE_CAP: usize = 4096;

pub struct EbpfAttributor {
    /// Keeps programs attached; dropping it detaches everything.
    _ebpf: Ebpf,
    sock_map: FlowMap<MapData, FlowKey, FlowVal>,
    cache: ProcCache,
    stop: Arc<AtomicBool>,
}

impl EbpfAttributor {
    /// Load and attach the eBPF programs. Returns None (with a warning)
    /// on any failure so the caller falls back to procfs attribution.
    /// `dns_cache`, when given, is fed resolved (name, address) pairs
    /// snooped from getaddrinfo via uprobes.
    pub fn new(dns_cache: Option<Arc<IpDomainCache>>) -> Option<EbpfAttributor> {
        match Self::load(dns_cache) {
            Ok(a) => {
                tracing::info!("eBPF attribution active");
                Some(a)
            }
            Err(e) => {
                tracing::warn!("eBPF attribution unavailable, using procfs fallback: {e}");
                None
            }
        }
    }

    fn load(dns_cache: Option<Arc<IpDomainCache>>) -> Result<EbpfAttributor, String> {
        // Patch kernel struct offsets resolved from BTF into the programs
        // before the verifier sees them; see resolve_offsets().
        let offs = resolve_offsets();
        let mut loader = EbpfLoader::new();
        for (name, value) in &offs {
            loader.override_global(name, value, true);
        }
        let mut ebpf = loader
            .load(EBPF_OBJ)
            .map_err(|e| format!("load object: {e}"))?;

        attach_kprobe(&mut ebpf, "tcp_connect_enter", &["tcp_v4_connect", "tcp_v6_connect"])?;
        attach_kprobe(&mut ebpf, "tcp_connect_ret", &["tcp_v4_connect", "tcp_v6_connect"])?;
        attach_kprobe(&mut ebpf, "udp_sendmsg", &["udp_sendmsg"])?;
        attach_kprobe(&mut ebpf, "udpv6_sendmsg", &["udpv6_sendmsg"])?;
        attach_tracepoint(&mut ebpf, "sched_process_exec")?;
        attach_tracepoint(&mut ebpf, "sched_process_exit")?;

        let sock_map = FlowMap::try_from(
            ebpf.take_map("SOCK_MAP")
                .ok_or("SOCK_MAP missing from object")?,
        )
        .map_err(|e| format!("SOCK_MAP: {e}"))?;
        let ring = RingBuf::try_from(
            ebpf.take_map("EVENTS").ok_or("EVENTS missing from object")?,
        )
        .map_err(|e| format!("EVENTS: {e}"))?;

        let cache: ProcCache = Arc::new(Mutex::new(LruCache::new(
            NonZeroUsize::new(PID_CACHE_CAP).expect("nonzero capacity"),
        )));
        let stop = Arc::new(AtomicBool::new(false));
        spawn_event_reader(ring, Arc::clone(&cache), Arc::clone(&stop));

        // getaddrinfo DNS snooping is best-effort on top of attribution:
        // statically linked or non-libc programs never hit the uprobe, and
        // the wire snooper still covers plaintext UDP 53.
        if let Some(dns) = dns_cache {
            match attach_getaddrinfo(&mut ebpf) {
                Ok(()) => {
                    let dns_ring = RingBuf::try_from(
                        ebpf.take_map("DNS_EVENTS")
                            .ok_or("DNS_EVENTS missing from object")?,
                    )
                    .map_err(|e| format!("DNS_EVENTS: {e}"))?;
                    spawn_dns_reader(dns_ring, dns, Arc::clone(&stop));
                    tracing::info!("getaddrinfo DNS snoop active");
                }
                Err(e) => {
                    tracing::warn!("getaddrinfo DNS snoop unavailable: {e}");
                }
            }
        }
        Ok(EbpfAttributor {
            _ebpf: ebpf,
            sock_map,
            cache,
            stop,
        })
    }

    fn details_for(&self, pid: u32) -> (Option<PathBuf>, Option<String>, Option<PathBuf>) {
        if let Some(d) = self.cache.lock().unwrap().get(&pid) {
            return d.clone();
        }
        // Not seen via the exec tracepoint (started before the daemon);
        // snapshot now and remember it. The exit event evicts it.
        let d = procfs::proc_snapshot(Path::new("/proc"), pid);
        self.cache.lock().unwrap().put(pid, d.clone());
        d
    }
}

impl Drop for EbpfAttributor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Attributor for EbpfAttributor {
    fn attribute(&self, tuple: &FlowTuple) -> Option<ProcInfo> {
        let val = self.sock_map.get(&flow_key(tuple), 0).ok()?;
        let (exe_path, cmdline, parent_exe) = self.details_for(val.pid);
        Some(ProcInfo {
            pid: Some(val.pid),
            uid: val.uid,
            exe_path,
            cmdline,
            parent_exe,
        })
    }
}

/// Kernel struct offsets for the eBPF programs, resolved from the running
/// kernel's BTF: per-kernel resolution instead of trusting one compiled-in
/// layout. Whatever resolves gets patched; any field that does not (BTF
/// missing entirely, or a single renamed/bitfield-ized member on a future
/// kernel) is left at the x86_64 default compiled into the object, with a
/// warning. A wrong default only costs eBPF lookup misses, which the
/// procfs attributor absorbs.
fn resolve_offsets() -> Vec<(&'static str, u32)> {
    let btf = match Btf::from_sys_fs() {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("kernel BTF unavailable, using compiled-in x86_64 offsets: {e}");
            return Vec::new();
        }
    };
    // The programs read fields off a `struct sock *`, so each sock_common
    // offset is `sock.__sk_common` (0 on every known kernel, but resolved
    // anyway) plus the field's offset within sock_common.
    let skc = btf.struct_field_offset("sock", "__sk_common");
    let sock_common = btf.struct_id("sock_common");
    let sc = |field| match (skc, sock_common) {
        (Some(base), Some(id)) => btf.field_offset(id, field).map(|o| base + o),
        _ => None,
    };
    let mut resolved = Vec::new();
    for (symbol, offset) in [
        ("OFF_SKC_DADDR", sc("skc_daddr")),
        ("OFF_SKC_RCV_SADDR", sc("skc_rcv_saddr")),
        ("OFF_SKC_DPORT", sc("skc_dport")),
        ("OFF_SKC_NUM", sc("skc_num")),
        ("OFF_SKC_FAMILY", sc("skc_family")),
        ("OFF_SKC_V6_DADDR", sc("skc_v6_daddr")),
        ("OFF_SKC_V6_RCV_SADDR", sc("skc_v6_rcv_saddr")),
        ("OFF_MSG_NAME", btf.struct_field_offset("msghdr", "msg_name")),
    ] {
        match offset {
            Some(o) => resolved.push((symbol, o)),
            None => tracing::warn!(symbol, "BTF offset unresolved; compiled-in x86_64 default applies"),
        }
    }
    resolved
}

/// FlowTuple -> map key, matching the byte-order convention of
/// hallpass-ebpf-common: address octets network order, ports host order.
fn flow_key(t: &FlowTuple) -> FlowKey {
    let proto = match t.proto {
        Proto::Tcp => PROTO_TCP,
        Proto::Udp => PROTO_UDP,
    };
    match (t.src.ip(), t.dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            FlowKey::v4(proto, s.octets(), t.src.port(), d.octets(), t.dst.port())
        }
        (s, d) => FlowKey::v6(proto, v6_octets(s), t.src.port(), v6_octets(d), t.dst.port()),
    }
}

fn v6_octets(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V6(v6) => v6.octets(),
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
    }
}

fn attach_kprobe(ebpf: &mut Ebpf, prog: &str, fns: &[&str]) -> Result<(), String> {
    let p: &mut KProbe = ebpf
        .program_mut(prog)
        .ok_or_else(|| format!("program {prog} missing"))?
        .try_into()
        .map_err(|e| format!("{prog}: {e}"))?;
    p.load().map_err(|e| format!("load {prog}: {e}"))?;
    for f in fns {
        p.attach(f, 0)
            .map_err(|e| format!("attach {prog} to {f}: {e}"))?;
    }
    Ok(())
}

/// Attach the getaddrinfo entry/return uprobes to the system libc, for
/// every process.
fn attach_getaddrinfo(ebpf: &mut Ebpf) -> Result<(), String> {
    for prog in ["getaddrinfo_enter", "getaddrinfo_ret"] {
        let p: &mut UProbe = ebpf
            .program_mut(prog)
            .ok_or_else(|| format!("program {prog} missing"))?
            .try_into()
            .map_err(|e| format!("{prog}: {e}"))?;
        p.load().map_err(|e| format!("load {prog}: {e}"))?;
        p.attach("getaddrinfo", "libc", UProbeScope::AllProcesses)
            .map_err(|e| format!("attach {prog}: {e}"))?;
    }
    Ok(())
}

fn attach_tracepoint(ebpf: &mut Ebpf, name: &str) -> Result<(), String> {
    let p: &mut TracePoint = ebpf
        .program_mut(name)
        .ok_or_else(|| format!("program {name} missing"))?
        .try_into()
        .map_err(|e| format!("{name}: {e}"))?;
    p.load().map_err(|e| format!("load {name}: {e}"))?;
    p.attach("sched", name)
        .map_err(|e| format!("attach {name}: {e}"))?;
    Ok(())
}

/// TTL for uprobe-snooped resolutions. The real DNS TTL is not visible at
/// the getaddrinfo layer; the cache clamps this into its supported range.
const UPROBE_DNS_TTL_SECS: u32 = 120;

/// Drain getaddrinfo events into the IP -> domain cache.
///
/// The eBPF side pins the queried name at call entry, so the (name, addr)
/// pair reflects one real resolution and cannot be split by a concurrent
/// buffer rewrite. The recorded mapping is still only as trustworthy as
/// what the process resolved: like the wire snooper (and like any
/// IP->domain cache), a process resolving a name it controls can map its
/// own name to any address, and the single-value-per-IP cache means the
/// last resolver of an address wins. Domain rules are therefore a
/// convenience over IP/exe rules, not a boundary against a local process
/// that is choosing its own DNS - which is why this feeds the same cache
/// the wire path does rather than a privileged one.
fn spawn_dns_reader(mut ring: RingBuf<MapData>, dns: Arc<IpDomainCache>, stop: Arc<AtomicBool>) {
    std::thread::Builder::new()
        .name("ebpf-dns".into())
        .spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                while let Some(item) = ring.next() {
                    let Some((ip, raw)) = DnsEvent::parse(&item) else {
                        continue;
                    };
                    let Some(name) = normalize_domain(raw) else {
                        continue;
                    };
                    tracing::debug!(domain = %name, %ip, "getaddrinfo resolution snooped");
                    dns.absorb(&SnoopedResponse {
                        id: 0,
                        query_name: name,
                        addrs: vec![(ip, UPROBE_DNS_TTL_SECS)],
                    });
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        })
        .expect("spawn ebpf-dns thread");
}

/// Lowercase, strip a trailing dot, and reject a name with control or
/// whitespace characters (log-injection and match-evasion guard) or an
/// implausible length. Matches the plaintext snooper's expectation that a
/// cached domain is the exact name a rule would carry.
fn normalize_domain(raw: &str) -> Option<String> {
    let trimmed = raw.strip_suffix('.').unwrap_or(raw);
    if trimmed.is_empty()
        || trimmed.len() > 253
        || trimmed.bytes().any(|b| b <= b' ' || b == 0x7f)
    {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

/// Drain exec/exit events into the pid cache. Exec events snapshot
/// /proc/pid/{exe,cmdline} while the process is fresh; exit events evict.
fn spawn_event_reader(mut ring: RingBuf<MapData>, cache: ProcCache, stop: Arc<AtomicBool>) {
    std::thread::Builder::new()
        .name("ebpf-events".into())
        .spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                while let Some(item) = ring.next() {
                    let Some(ev) = ExecEvent::from_bytes(&item) else {
                        continue;
                    };
                    if ev.kind == EVENT_EXEC {
                        let d = procfs::proc_snapshot(Path::new("/proc"), ev.pid);
                        cache.lock().unwrap().put(ev.pid, d);
                    } else {
                        cache.lock().unwrap().pop(&ev.pid);
                    }
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        })
        .expect("spawn ebpf-events thread");
}

#[cfg(test)]
mod tests {
    use super::normalize_domain;

    #[test]
    fn domain_normalization() {
        assert_eq!(normalize_domain("Example.COM").as_deref(), Some("example.com"));
        assert_eq!(normalize_domain("example.com.").as_deref(), Some("example.com"));
        assert_eq!(normalize_domain(""), None);
        assert_eq!(normalize_domain("."), None);
        // Control char / whitespace / injection guard.
        assert_eq!(normalize_domain("bad\nname.com"), None);
        assert_eq!(normalize_domain("has space.com"), None);
        assert_eq!(normalize_domain(&"a".repeat(254)), None);
    }
}

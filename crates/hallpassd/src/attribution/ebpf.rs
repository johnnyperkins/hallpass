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
use std::sync::{Arc, Mutex};

use aya::maps::{HashMap as FlowMap, MapData, RingBuf};
use aya::programs::uprobe::UProbeScope;
use aya::programs::{KProbe, TracePoint, UProbe};
use aya::{Ebpf, EbpfLoader};
use lru::LruCache;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::watch;
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
    /// Stop signal for the ring-buffer readers; the [`Drop`] impl sends on
    /// it, and dropping it alone would also wake them.
    stop: watch::Sender<bool>,
}

impl EbpfAttributor {
    /// Load and attach the eBPF programs. Returns None (with a warning)
    /// on any failure so the caller falls back to procfs attribution.
    /// `dns_cache`, when given, is fed resolved (name, address) pairs
    /// snooped from the libc resolver entry points via uprobes.
    ///
    /// Must be called from within a tokio runtime: the ring-buffer
    /// readers are spawned tasks driven by epoll readiness.
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
        let (stop, stop_rx) = watch::channel(false);
        spawn_event_reader(ring, Arc::clone(&cache), stop_rx.clone());

        // libc DNS snooping is best-effort on top of attribution:
        // statically linked or non-libc programs never hit the uprobes,
        // and the wire snooper still covers plaintext UDP 53.
        if let Some(dns) = dns_cache {
            match attach_dns_uprobes(&mut ebpf) {
                Ok(()) => {
                    let dns_ring = RingBuf::try_from(
                        ebpf.take_map("DNS_EVENTS")
                            .ok_or("DNS_EVENTS missing from object")?,
                    )
                    .map_err(|e| format!("DNS_EVENTS: {e}"))?;
                    spawn_dns_reader(dns_ring, dns, stop_rx);
                    tracing::info!("libc DNS snoop active (getaddrinfo, gethostbyname family)");
                }
                Err(e) => {
                    tracing::warn!("libc DNS snoop unavailable: {e}");
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
        let _ = self.stop.send(true);
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

/// Attach the DNS-snooping uprobes to the system libc, for every process.
///
/// `getaddrinfo` is the modern path and is required; the `gethostbyname`
/// family is best effort, since which of the legacy spellings a libc
/// exports (and whether they are stripped from a hardened build) varies,
/// and losing one legacy entry point is better than losing DNS snooping
/// entirely.
fn attach_dns_uprobes(ebpf: &mut Ebpf) -> Result<(), String> {
    attach_uprobe_pair(
        ebpf,
        ["getaddrinfo_enter", "getaddrinfo_ret"],
        &["getaddrinfo"],
    )?;
    for (progs, symbols) in [
        (
            ["gethostbyname_enter", "gethostbyname_ret"],
            &["gethostbyname", "gethostbyname2"][..],
        ),
        (
            ["gethostbyname_r_enter", "gethostbyname_r_ret"],
            &["gethostbyname_r"][..],
        ),
        (
            ["gethostbyname2_r_enter", "gethostbyname2_r_ret"],
            &["gethostbyname2_r"][..],
        ),
    ] {
        if let Err(e) = attach_uprobe_pair(ebpf, progs, symbols) {
            tracing::warn!("legacy resolver snoop unavailable: {e}");
        }
    }
    Ok(())
}

/// Load an entry/return program pair and attach both to every symbol in
/// `symbols`. Symbols missing from this libc are skipped; the pair fails
/// only when none of them resolved.
fn attach_uprobe_pair(
    ebpf: &mut Ebpf,
    progs: [&str; 2],
    symbols: &[&str],
) -> Result<(), String> {
    // Load both halves before attaching either. An entry probe attached
    // next to a return probe that failed to load would trap every call in
    // every process and stash scratch entries nothing ever consumes.
    for prog in progs {
        let p: &mut UProbe = ebpf
            .program_mut(prog)
            .ok_or_else(|| format!("program {prog} missing"))?
            .try_into()
            .map_err(|e| format!("{prog}: {e}"))?;
        p.load().map_err(|e| format!("load {prog}: {e}"))?;
    }
    for prog in progs {
        let p: &mut UProbe = ebpf
            .program_mut(prog)
            .ok_or_else(|| format!("program {prog} missing"))?
            .try_into()
            .map_err(|e| format!("{prog}: {e}"))?;
        let mut last_err = None;
        let mut attached = 0;
        for symbol in symbols {
            match p.attach(*symbol, "libc", UProbeScope::AllProcesses) {
                Ok(_) => attached += 1,
                Err(e) => last_err = Some(format!("{prog} -> {symbol}: {e}")),
            }
        }
        if attached == 0 {
            return Err(last_err.unwrap_or_else(|| format!("{prog}: no symbols given")));
        }
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
fn spawn_dns_reader(ring: RingBuf<MapData>, dns: Arc<IpDomainCache>, stop: StopRx) {
    spawn_ring_reader("ebpf-dns", ring, stop, move |item| {
        let Some((ip, raw)) = DnsEvent::parse(item) else {
            return;
        };
        let Some(name) = normalize_domain(raw) else {
            return;
        };
        tracing::debug!(domain = %name, %ip, "getaddrinfo resolution snooped");
        dns.absorb(&SnoopedResponse {
            id: 0,
            query_name: name,
            addrs: vec![(ip, UPROBE_DNS_TTL_SECS)],
        });
    });
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
fn spawn_event_reader(ring: RingBuf<MapData>, cache: ProcCache, stop: StopRx) {
    spawn_ring_reader("ebpf-events", ring, stop, move |item| {
        let Some(ev) = ExecEvent::from_bytes(item) else {
            return;
        };
        if ev.kind == EVENT_EXEC {
            let d = procfs::proc_snapshot(Path::new("/proc"), ev.pid);
            cache.lock().unwrap().put(ev.pid, d);
        } else {
            cache.lock().unwrap().pop(&ev.pid);
        }
    });
}

/// Shutdown signal for the ring-buffer readers. A watch channel rather
/// than a polled flag so a reader parked on the ring buffer wakes
/// immediately when the attributor is dropped.
type StopRx = watch::Receiver<bool>;

/// Drain `ring` into `handle`, driven by epoll readiness on the ring
/// buffer's fd.
///
/// Polling on a timer would delay every event by up to the poll interval,
/// which matters: a domain learned from the DNS ring buffer is only
/// useful if it lands before the connection that follows the resolution
/// is decided, and an exec snapshot is only fresh if it beats the process
/// to its first connect.
///
/// `handle` runs on a runtime worker rather than a dedicated thread, so
/// it must stay short. Both callers qualify: they do a handful of reads
/// from /proc (kernel-generated, no disk) and take an uncontended mutex.
/// Anything heavier belongs on a blocking task.
fn spawn_ring_reader(
    name: &'static str,
    ring: RingBuf<MapData>,
    mut stop: StopRx,
    mut handle: impl FnMut(&[u8]) + Send + 'static,
) {
    let mut ring = match AsyncFd::with_interest(ring, Interest::READABLE) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(reader = name, "cannot watch ring buffer: {e}");
            return;
        }
    };
    tokio::spawn(async move {
        loop {
            let mut guard = tokio::select! {
                _ = stop.changed() => return,
                readable = ring.readable_mut() => match readable {
                    Ok(g) => g,
                    Err(e) => {
                        tracing::error!(reader = name, "ring buffer readiness failed: {e}");
                        return;
                    }
                },
            };
            // Drain fully before clearing readiness: the kernel only
            // re-arms the notification once the buffer is emptied.
            let inner = guard.get_inner_mut();
            while let Some(item) = inner.next() {
                handle(&item);
            }
            guard.clear_ready();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The readers select on `stop.changed()`. If a fresh (or cloned)
    /// receiver reported a change straight away they would exit at
    /// startup, leaving attribution and DNS snooping silently dead, so
    /// pin the semantics rather than assuming them.
    #[tokio::test]
    async fn stop_signal_fires_only_on_shutdown() {
        let (stop, rx) = watch::channel(false);
        let mut readers = [rx.clone(), rx];
        for r in &mut readers {
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(50), r.changed())
                    .await
                    .is_err(),
                "receiver reported a change before shutdown"
            );
        }
        // Both the explicit signal and a dropped sender must wake them.
        stop.send(true).unwrap();
        assert!(readers[0].changed().await.is_ok());
        drop(stop);
        assert!(readers[1].changed().await.is_ok());
    }

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

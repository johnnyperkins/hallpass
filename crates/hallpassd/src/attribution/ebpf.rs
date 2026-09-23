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
use hallpass_ebpf_common::{
    DnsEvent, ExecEvent, FlowKey, FlowVal, EVENT_EXEC, PROTO_TCP, PROTO_UDP,
};
use hallpass_types::{FlowTuple, Proto};
use lru::LruCache;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::watch;

use crate::dns::{IpDomainCache, SnoopedResponse};

use super::btf::Btf;
use super::{procfs, Attributor, ExeId, ProcInfo};

/// The eBPF object, located by build.rs: an explicit `HALLPASS_EBPF_OBJ`,
/// a prebuilt object vendored in the crate, or whatever `cargo xtask
/// build-ebpf` produced, in that order.
static EBPF_OBJ: &[u8] = aya::include_bytes_aligned!(env!("HALLPASS_EBPF_OBJ"));

/// Details snapshotted at exec time, plus the starttime of the process
/// they were read from.
type ProcDetails = (Option<PathBuf>, Option<String>, Option<PathBuf>);

/// pid -> details snapshotted at exec time. Exit events are the primary
/// eviction path, but they are lossy (the ring buffer drops under
/// pressure), so the LRU cap is the backstop against unbounded growth
/// and the starttime check in [`EbpfAttributor::details_for`] is the
/// guard against a stale entry outliving its pid.
type ProcCache = Arc<Mutex<LruCache<u32, (ProcDetails, Option<u64>)>>>;

/// pid -> application identity, with the starttime it was read at.
///
/// Separate from [`ProcCache`] because it is filled at a different moment.
/// The details there are snapshotted by the exec tracepoint, which sees
/// every exec on the host; a cgroup is assigned to a process rather than
/// read out of its image, so reading it there would pay for every exec and
/// still be read too early. This one fills on first attribution instead,
/// which is the only time the answer is wanted, and the entry then serves
/// the rest of the flow.
type AppIdCache = Mutex<LruCache<u32, (Option<String>, u64)>>;

const PID_CACHE_CAP: usize = 4096;

/// How many pids the exec-race warning remembers before it repeats itself.
/// Small on purpose: it exists to collapse one process's retries into one
/// line, not to keep a history.
const RACED_LOG_CAP: usize = 256;

pub struct EbpfAttributor {
    /// Keeps programs attached; dropping it detaches everything.
    _ebpf: Ebpf,
    sock_map: FlowMap<MapData, FlowKey, FlowVal>,
    /// pid -> exec generation, the counter [`EbpfAttributor::exec_raced`]
    /// compares a flow's stamp against.
    exec_gen: FlowMap<MapData, u32, u64>,
    cache: ProcCache,
    /// Pids already warned about, so one evading process logs once rather
    /// than once per packet or once per retry.
    raced_seen: Mutex<LruCache<u32, ()>>,
    app_ids: AppIdCache,
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
                // The embedded object is located by build.rs and can be one
                // somebody vendored, so "your object is older than this
                // binary" is a real and otherwise baffling way to land here:
                // it reads exactly like a kernel that refuses eBPF, and the
                // host quietly loses the exec-race guard with it. The map
                // errors that say so are worth naming rather than passing
                // through as one more load failure.
                let stale = e.contains("EXEC_GEN") || e.contains("invalid value size");
                if stale {
                    tracing::warn!(
                        "eBPF attribution unavailable, using procfs fallback: {e}. This looks \
                         like an embedded object built before the daemon: rebuild it with \
                         `cargo xtask build-ebpf`, or replace the prebuilt one, and note that \
                         exe rules are only scoping conveniences until it loads"
                    );
                } else {
                    tracing::warn!("eBPF attribution unavailable, using procfs fallback: {e}");
                }
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

        attach_kprobe(
            &mut ebpf,
            "tcp_connect_enter",
            &["tcp_v4_connect", "tcp_v6_connect"],
        )?;
        attach_kprobe(
            &mut ebpf,
            "tcp_connect_ret",
            &["tcp_v4_connect", "tcp_v6_connect"],
        )?;
        attach_kprobe(&mut ebpf, "udp_sendmsg", &["udp_sendmsg"])?;
        attach_kprobe(&mut ebpf, "udpv6_sendmsg", &["udpv6_sendmsg"])?;
        attach_tracepoint(&mut ebpf, "sched_process_exec")?;
        attach_tracepoint(&mut ebpf, "sched_process_exit")?;

        let sock_map = FlowMap::try_from(
            ebpf.take_map("SOCK_MAP")
                .ok_or("SOCK_MAP missing from object")?,
        )
        .map_err(|e| format!("SOCK_MAP: {e}"))?;
        // Sizes are checked against the object's own map definitions here,
        // so a `FlowVal` that gained a field without the embedded object
        // being rebuilt fails to load loudly instead of reading a stamp
        // the kernel side never wrote.
        let exec_gen = FlowMap::try_from(
            ebpf.take_map("EXEC_GEN")
                .ok_or("EXEC_GEN missing from object")?,
        )
        .map_err(|e| format!("EXEC_GEN: {e}"))?;
        let ring = RingBuf::try_from(
            ebpf.take_map("EVENTS")
                .ok_or("EVENTS missing from object")?,
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
                    // Annotation loss only: the wire snooper still covers
                    // plaintext port 53; what goes missing is names resolved
                    // through a stub resolver or an encrypted upstream. The
                    // hint is earned: kprobes attaching while uprobes fail
                    // looks like a bug, but on several kernel lines the
                    // uprobe perf PMU demands CAP_SYS_ADMIN where the kprobe
                    // PMU accepts CAP_PERFMON (probe-confirmed on a live
                    // host), and the shipped unit deliberately refuses
                    // SYS_ADMIN; see etc/hallpassd.service.
                    tracing::warn!(
                        "libc DNS snoop unavailable: {e}; under a \
                         capability-restricted service this usually means \
                         attaching uprobes needs CAP_SYS_ADMIN on this \
                         kernel; wire DNS snooping still covers plaintext \
                         port 53"
                    );
                }
            }
        }
        Ok(EbpfAttributor {
            _ebpf: ebpf,
            sock_map,
            exec_gen,
            cache,
            raced_seen: Mutex::new(LruCache::new(
                NonZeroUsize::new(RACED_LOG_CAP).expect("nonzero capacity"),
            )),
            app_ids: Mutex::new(LruCache::new(
                NonZeroUsize::new(PID_CACHE_CAP).expect("nonzero capacity"),
            )),
            stop,
        })
    }

    /// Whether `pid` exec'd between recording this flow and now, which
    /// makes every after-the-fact read of its executable name the wrong
    /// binary.
    ///
    /// A socket descriptor survives `execve`, so a process can start a
    /// non-blocking `connect()` (or send a datagram), immediately exec
    /// something else, and be attributed to that instead - retrying until
    /// it wins the race. Neither the pid nor the start time can see it:
    /// both survive exec, so the pid-plus-starttime half of the guard in
    /// [`Self::details_for`] is the wrong instrument here. It guards pid
    /// reuse, a different problem. (The exe check that sits beside it is
    /// aimed at this one, but at a different vector: a *stale cache entry*
    /// rather than a stale flow stamp. Both are needed.)
    ///
    /// The kernel side stamps [`FlowVal::exec_gen`] at connect from a map
    /// its exec tracepoint replaces, so the comparison is between two facts
    /// the process cannot forge. Generations are timestamps rather than
    /// counts and are never zero, which is what makes every way the entry
    /// can be lost - LRU eviction, the exit handler, a reload - produce a
    /// disagreement rather than an accidental agreement; see `EXEC_GEN` in
    /// the kernel programs. Any inequality refuses: a refusal costs a
    /// prompt for a connection that would otherwise match an `exe` rule,
    /// and the alternative costs the rule.
    ///
    /// What this does not cover is a flow the kernel side never recorded,
    /// or lost from its own LRU. There is nothing to compare then, the
    /// whole source misses, and the chain falls through to procfs, which
    /// resolves the executable after the fact with no counter at all. That
    /// is the fallback working as designed - eBPF misses legitimate flows
    /// too - and it is why the README calls this a narrowing rather than a
    /// closure.
    fn exec_raced(&self, val: &FlowVal) -> bool {
        // A missing entry reads as 0, which the kernel side never stamps:
        // it claims a generation at connect for a process that has none, so
        // an absent entry here always disagrees.
        let now = self.exec_gen.get(&val.pid, 0).unwrap_or(0);
        if now == val.exec_gen {
            return false;
        }
        // Logged once per pid, not once per (pid, generation): the attack
        // this names is "retry until it wins the race", and every retry is
        // another exec and therefore another generation, so keying on the
        // pair would let an unprivileged process meter out a journal line
        // per attempt. A UDP flow, re-attributed per datagram, would do the
        // same at packet rate.
        if self.raced_seen.lock().unwrap().put(val.pid, ()).is_none() {
            tracing::warn!(
                pid = val.pid,
                uid = val.uid,
                at_connect = val.exec_gen,
                now,
                "process exec'd after connecting; refusing to name its executable, so \
                 exe rules cannot match this connection either way"
            );
        }
        true
    }

    /// Details for `pid`, with the start time they were read at and the
    /// identity of the executable they name. The caller needs both, so they
    /// are returned rather than read a second time.
    fn details_for(&self, pid: u32) -> (ProcDetails, Option<u64>, Option<ExeId>) {
        // Exit events are lossy and fork-without-exec emits no exec
        // event, so a cache hit may describe a previous occupant of
        // this pid; only serve it while the starttime still matches
        // the process the snapshot was taken from.
        let now_start = procfs::starttime_of(Path::new("/proc"), pid);
        // The start time cannot see an execve - that is the whole premise of
        // [`Self::exec_raced`] - so it cannot tell a cached snapshot apart
        // from the binary the process has since become either. The exe
        // symlink can, and this is the same check the chain's own cache
        // makes for the same reason (`super::cached_still_valid`).
        //
        // `exec_raced` does not cover this: it compares a *flow's* stamp
        // with the counter, and a flow opened after the exec carries the new
        // generation and agrees. What is stale is this cache, whose refresh
        // rides the exec ring buffer - an asynchronous reader that drops
        // under pressure and can simply lose the race to the verdict thread.
        // Without this check, a process holding an `exe` allow rule that
        // execs into something else keeps handing that rule to the new
        // image for as long as the stale entry lives.
        let (now_exe, now_id) = procfs::host_exe_id(Path::new("/proc"), pid).unzip();
        let now_id = now_id.flatten();
        if let Some((d, cached_start)) = self.cache.lock().unwrap().get(&pid) {
            if now_start.is_some() && *cached_start == now_start && d.0 == now_exe {
                return (d.clone(), now_start, now_id);
            }
        }
        // Not seen via the exec tracepoint (started before the daemon)
        // or stale; snapshot now and remember it.
        let d = procfs::proc_snapshot(Path::new("/proc"), pid);
        self.cache.lock().unwrap().put(pid, (d.clone(), now_start));
        // The identity describes the path read above; if the snapshot read a
        // different one, the process exec'd in between and it describes
        // neither for certain.
        let id = now_id.filter(|_| d.0 == now_exe);
        (d, now_start, id)
    }

    /// Application identity for `pid`, read once per process incarnation.
    ///
    /// Cached because this attributor's entries are never served from the
    /// chain's own cache: it reports no socket inode (see `attribute`), and
    /// [`super::cached_still_valid`] refuses an entry it cannot check
    /// against the flow, so the source runs again for every packet the
    /// kernel queues. A flow that stays `ct state new`, which is every
    /// one-way UDP flow, is queued per datagram, so an uncached /proc read
    /// here lands on the thread that decides every connection on the host.
    ///
    /// Guarded by the start time exactly as [`Self::details_for`] is: a
    /// recycled pid is a different process and must not inherit an identity.
    /// An entry is only stored when there is a start time to guard it with,
    /// since one without could never be served and would evict a usable
    /// entry to sit there unreadable.
    ///
    /// What is lost when the cache fills: the least recently used pid pays
    /// the /proc read again. What is lost by caching at all: a process whose
    /// launcher moves it into an application scope *after* it has already
    /// been judged keeps the identity it had at that moment for the rest of
    /// its life. That window is narrow (a launcher creates the scope around
    /// the process before handing it the network), and being wrong inside it
    /// costs a rule match and therefore a prompt, never a verdict.
    fn app_id_for(&self, pid: u32, starttime: Option<u64>) -> Option<String> {
        // Nothing to check a cached answer against: a pid whose stat cannot
        // be read is exiting or already gone, so read once and cache
        // nothing rather than store an entry no lookup can accept.
        let Some(starttime) = starttime else {
            return procfs::app_id_of(Path::new("/proc"), pid);
        };
        if let Some((cached, at)) = self.app_ids.lock().unwrap().get(&pid) {
            if *at == starttime {
                return cached.clone();
            }
        }
        let app_id = procfs::app_id_of(Path::new("/proc"), pid);
        self.app_ids
            .lock()
            .unwrap()
            .put(pid, (app_id.clone(), starttime));
        app_id
    }
}

impl Drop for EbpfAttributor {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

impl Attributor for EbpfAttributor {
    fn attribute(&self, tuple: &FlowTuple) -> Option<ProcInfo> {
        let key = flow_key(tuple);
        let val = self.sock_map.get(&key, 0).ok().or_else(|| {
            let wild = unbound_udp_key(tuple, key)?;
            self.sock_map.get(&wild, 0).ok()
        })?;
        // Read before the generation check, so a check that passes vouches
        // for the image this identity names: no exec landed between the
        // connect and the read.
        let ((exe_path, cmdline, parent_exe), starttime, exe_id) = self.details_for(val.pid);
        // Refused rather than reported when the process exec'd after it
        // connected: all three describe the image, and the image is exactly
        // what changed. `parent_exe` describes the launcher, which an exec
        // here does not touch, and is kept.
        let (exe_path, cmdline, exe_id) = match self.exec_raced(&val) {
            true => (None, None, None),
            false => (exe_path, cmdline, exe_id),
        };
        Some(ProcInfo {
            pid: Some(val.pid),
            uid: val.uid,
            exe_path,
            exe_id,
            cmdline,
            parent_exe,
            // Resolved here rather than snapshotted at exec like the
            // fields above: a cgroup is assigned to a process, not read out
            // of its image, so the current one is the true one, and this
            // keeps the read off the exec tracepoint, which sees every exec
            // on the host. Cached per process incarnation; see app_id_for.
            app_id: self.app_id_for(val.pid, starttime),
            starttime,
            // The kernel side records (pid, uid) against the flow tuple and
            // never sees the socket inode. Leaving it unset means the
            // attribution cache will not serve this entry without asking
            // again, which is the right trade here: the map is keyed by the
            // same tuple and the connect that reused the port has already
            // overwritten it, so one lookup is both cheaper than
            // revalidating and more current than the cached answer.
            socket_inode: None,
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
        (
            "OFF_MSG_NAME",
            btf.struct_field_offset("msghdr", "msg_name"),
        ),
    ] {
        match offset {
            Some(o) => resolved.push((symbol, o)),
            None => tracing::warn!(
                symbol,
                "BTF offset unresolved; compiled-in x86_64 default applies"
            ),
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
        (s, d) => FlowKey::v6(
            proto,
            v6_octets(s),
            t.src.port(),
            v6_octets(d),
            t.dst.port(),
        ),
    }
}

/// The key the kernel side records for a datagram sent from a UDP socket
/// with no local address, or `None` for anything else.
///
/// The kprobe runs at `udp_sendmsg` entry and reads the source address from
/// the socket, where an unbound or wildcard-bound socket holds 0.0.0.0 (or
/// `::`): the kernel picks the real one later, while routing the datagram.
/// So every `sendto()` on such a socket is recorded with a zero source and
/// never matched the packet's tuple. The miss fell through to procfs, which
/// resolves the owner after the fact with no exec generation to compare, so
/// "send, then exec an allowed binary" won the race the generation check
/// exists to refuse. TCP always has its source address by the time the
/// connect probe returns, and a connected UDP socket gets one at connect.
fn unbound_udp_key(tuple: &FlowTuple, mut key: FlowKey) -> Option<FlowKey> {
    if tuple.proto != Proto::Udp {
        return None;
    }
    key.saddr = [0u8; 16];
    Some(key)
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
fn attach_uprobe_pair(ebpf: &mut Ebpf, progs: [&str; 2], symbols: &[&str]) -> Result<(), String> {
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
        tracing::debug!(domain = %name, %ip, "libc resolver snooped a resolution");
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
    if trimmed.is_empty() || trimmed.len() > 253 || trimmed.bytes().any(|b| b <= b' ' || b == 0x7f)
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
            let start = procfs::starttime_of(Path::new("/proc"), ev.pid);
            cache.lock().unwrap().put(ev.pid, (d, start));
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
    fn unbound_udp_key_zeroes_only_the_source_address() {
        let udp = FlowTuple {
            proto: Proto::Udp,
            src: "10.0.0.5:40000".parse().unwrap(),
            dst: "10.0.0.9:53".parse().unwrap(),
        };
        let exact = flow_key(&udp);
        let wild = unbound_udp_key(&udp, exact).unwrap();
        assert_eq!(
            wild,
            FlowKey::v4(PROTO_UDP, [0; 4], 40000, [10, 0, 0, 9], 53),
            "what the kernel side records for a sendto() on an unbound socket"
        );
        let tcp = FlowTuple {
            proto: Proto::Tcp,
            ..udp
        };
        assert_eq!(unbound_udp_key(&tcp, flow_key(&tcp)), None);
    }

    #[test]
    fn domain_normalization() {
        assert_eq!(
            normalize_domain("Example.COM").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_domain("example.com.").as_deref(),
            Some("example.com")
        );
        assert_eq!(normalize_domain(""), None);
        assert_eq!(normalize_domain("."), None);
        // Control char / whitespace / injection guard.
        assert_eq!(normalize_domain("bad\nname.com"), None);
        assert_eq!(normalize_domain("has space.com"), None);
        assert_eq!(normalize_domain(&"a".repeat(254)), None);
    }
}

//! Map network flows to the local process that owns them.

#[cfg(any(test, feature = "ebpf"))]
pub mod btf;
pub mod cache;
#[cfg(feature = "ebpf")]
pub mod ebpf;
pub mod hash;
pub mod procfs;
pub mod sockdiag;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hallpass_types::{Connection, FlowTuple};

/// The file a process was running when it was attributed, as (device,
/// inode) of `/proc/<pid>/exe`.
///
/// Carried so the executable can be hashed later without hashing a
/// different one: the hash is read after attribution, and a process that
/// execs in between would otherwise have its new image hashed under the old
/// one's name. See [`hash::ExeHashCache::for_connection`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExeId {
    dev: u64,
    ino: u64,
}

impl ExeId {
    pub(crate) fn of(meta: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
        }
    }
}

/// Process metadata resolved for a flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    /// Process ID, when the socket inode could be traced to a process.
    pub pid: Option<u32>,
    /// Owning UID of the socket.
    pub uid: u32,
    /// Executable path from /proc/pid/exe.
    pub exe_path: Option<PathBuf>,
    /// The file `exe_path` named when it was read; `None` whenever
    /// `exe_path` is.
    pub exe_id: Option<ExeId>,
    /// Command line from /proc/pid/cmdline.
    pub cmdline: Option<String>,
    /// Executable path of the parent process, from /proc/ppid/exe.
    pub parent_exe: Option<PathBuf>,
    /// Packaged application from /proc/pid/cgroup, when the process runs
    /// under one; see [`hallpass_types::Connection::app_id`].
    pub app_id: Option<String>,
    /// Start time of `pid` from /proc/pid/stat. The kernel sets it at fork,
    /// so together with the pid it names one process incarnation and a
    /// recycled pid cannot pass for the one this was resolved from.
    pub starttime: Option<u64>,
    /// Socket inode this was resolved from, when the source knows it.
    /// Continued ownership of that inode is what makes a cached entry still
    /// true; see [`cached_still_valid`].
    pub socket_inode: Option<u64>,
}

/// A source of process attribution. Implementations are tried in order;
/// the first hit wins.
pub trait Attributor: Send + Sync {
    /// Resolve the process behind `tuple`, if this source can.
    fn attribute(&self, tuple: &FlowTuple) -> Option<ProcInfo>;

    /// Whether this source records every TCP connect as it happens, so that
    /// missing one is a fact worth noting rather than an ordinary miss.
    fn sees_every_connect(&self) -> bool {
        false
    }
}

/// Ordered chain of attributors behind a shared LRU cache.
pub struct AttributionChain {
    sources: Vec<Box<dyn Attributor>>,
    cache: cache::AttrCache,
    /// Root of the proc filesystem. A field rather than a constant so that
    /// [`cached_still_valid`], which decides whether one process's identity
    /// may be applied to another's connection, can be tested against a
    /// fixture instead of the running system.
    proc_root: PathBuf,
}

impl AttributionChain {
    /// Build a chain from ordered sources with the default cache sizing.
    pub fn new(sources: Vec<Box<dyn Attributor>>) -> Self {
        Self {
            sources,
            cache: cache::AttrCache::default(),
            proc_root: PathBuf::from("/proc"),
        }
    }

    /// A chain reading a fixture instead of the real `/proc`.
    #[cfg(test)]
    fn with_proc_root(sources: Vec<Box<dyn Attributor>>, proc_root: PathBuf) -> Self {
        Self {
            proc_root,
            ..Self::new(sources)
        }
    }

    /// Default chain: eBPF first when built with the `ebpf` feature and
    /// loadable on this system, then procfs. `dns_cache` receives
    /// getaddrinfo-snooped resolutions when the eBPF DNS uprobes attach
    /// (unused otherwise).
    ///
    /// With the `ebpf` feature this must be called from within a tokio
    /// runtime; see `ebpf::EbpfAttributor::new`.
    #[cfg_attr(not(feature = "ebpf"), allow(unused_variables))]
    pub fn default_chain(dns_cache: Option<Arc<crate::dns::IpDomainCache>>) -> Arc<Self> {
        let procfs: Box<dyn Attributor> = Box::new(procfs::ProcfsAttributor::with_sock_diag());
        #[cfg(feature = "ebpf")]
        if let Some(e) = ebpf::EbpfAttributor::new(dns_cache) {
            return Arc::new(Self::new(vec![Box::new(e), procfs]));
        }
        Arc::new(Self::new(vec![procfs]))
    }

    /// Resolve `tuple`, consulting the cache first. Misses (including
    /// negative results) are cached to avoid /proc scan storms.
    #[cfg(test)]
    pub fn attribute(&self, tuple: &FlowTuple) -> Option<ProcInfo> {
        self.resolve(tuple, false)
    }

    /// Resolve `tuple`, consulting the cache first, told whether the packet
    /// is a TCP SYN.
    ///
    /// A source that sees every connect is final for a SYN. It records the
    /// flow before the SYN reaches the daemon (probed: 0 misses in 4800
    /// parallel connects), so missing one means the record was lost, most
    /// likely flushed from its LRU, and a later source can only name the
    /// executable after the fact, which is exactly the exec-after-connect
    /// race the eBPF source's generation check exists to refuse. So a later
    /// source's answer keeps its uid, pid and launcher but not the image: no
    /// executable and no command line, as when that check fails. A refusal
    /// costs a prompt; a name from `/proc` could hand out another binary's
    /// allow rule.
    fn resolve(&self, tuple: &FlowTuple, syn: bool) -> Option<ProcInfo> {
        match self.cache.get(tuple) {
            Some(None) => return None,
            // Source ports are reused, so an entry outlives the flow it was
            // resolved from and serving it would hand one process's
            // identity, and its allow rules, to whatever owns the port now.
            // Every positive hit is checked before it is trusted.
            Some(Some(info)) if cached_still_valid(&self.proc_root, &info) => return Some(info),
            _ => {}
        }
        let mut witness_missed = false;
        let info = self.sources.iter().find_map(|s| {
            let found = s.attribute(tuple);
            witness_missed |= found.is_none() && s.sees_every_connect();
            found
        });
        let info = if syn && witness_missed {
            tracing::debug!(
                src = %tuple.src,
                dst = %tuple.dst,
                fallback = if info.is_some() { "procfs" } else { "none" },
                "eBPF missed a fresh TCP connect"
            );
            info.map(|i| ProcInfo {
                exe_path: None,
                exe_id: None,
                cmdline: None,
                ..i
            })
        } else {
            info
        };
        self.cache.put(*tuple, info.clone());
        info
    }

    /// Build a [`Connection`] for `tuple` with whatever attribution is
    /// available. The domain is left unset; DNS snooping fills it in later.
    ///
    /// Returned with the identity of the executable it names, which the wire
    /// type has no field for and hashing needs.
    pub fn connection(&self, tuple: FlowTuple, syn: bool) -> (Connection, Option<ExeId>) {
        // Fields move out of the attribution rather than being cloned: this
        // runs per packet. Assigned by name so a field added to either type
        // is one line here instead of a positional tuple to keep aligned.
        let mut conn = Connection {
            tuple,
            uid: None,
            pid: None,
            exe_path: None,
            cmdline: None,
            parent_exe: None,
            domain: None,
            // Interface is packet metadata; the queue loop fills it in.
            iface: None,
            app_id: None,
            // Needs the domain and the application identity below it, so the
            // queue loop stamps it once the connection is fully enriched.
            first_seen: None,
        };
        let mut exe_id = None;
        if let Some(i) = self.resolve(&tuple, syn) {
            conn.uid = Some(i.uid);
            conn.pid = i.pid;
            conn.exe_path = i.exe_path;
            exe_id = i.exe_id;
            conn.cmdline = i.cmdline;
            conn.parent_exe = i.parent_exe;
            conn.app_id = i.app_id;
        }
        (conn, exe_id)
    }
}

/// Executables of `pid`'s ancestors on the running system, nearest parent
/// first, at most `max` of them. Empty when the process is gone.
///
/// Not part of [`Attributor`] and not cached: it is read once per prompt
/// rather than per packet, and it is the one piece of process metadata that
/// is worth *less* the older it is. The per-flow attribution cache exists to
/// keep the verdict path off /proc; this deliberately goes there, at a rate
/// bounded by how fast an operator can be asked questions.
pub fn ancestry(pid: u32, max: usize) -> Vec<PathBuf> {
    procfs::ancestry_of(Path::new("/proc"), pid, max)
}

/// Whether a cached positive attribution still describes this flow.
///
/// Three things have to hold, and each rules out a different way the entry
/// can have gone wrong since it was made.
///
/// **The recorded process still holds the recorded socket inode.** This is
/// the one that matters. A source port only becomes free to reuse once the
/// socket behind it is closed, and the kernel hands out a fresh inode per
/// socket, so continued ownership of the inode is exactly the statement
/// "this is still the same flow". Without it, a process that reads a
/// victim's tuple out of the world-readable `/proc/net`, waits for that
/// socket to close and binds the same source port to the same destination
/// is judged as the victim for as long as the entry lives: its uid, exe,
/// cmdline and parent, and a hash-pinned rule matches too, because the hash
/// is taken from the victim's live binary. Checking that the process is
/// merely alive does not detect this at all, since the victim usually is.
///
/// **The start time is unchanged**, so a recycled pid cannot pass for the
/// process the entry was resolved from.
///
/// **The exe symlink reads the same**, which catches an exec in place:
/// execve keeps both the pid and the start time. A failed readlink counts
/// as None on both sides, matching how the entry was captured.
///
/// Checks run cheapest first, and an entry with no inode or no start time is
/// never served. That costs nothing worth having: the source that produces
/// entries without an inode is the eBPF one, whose map is keyed by this same
/// tuple and is overwritten by the connect that reused the port, so asking
/// it again is both cheaper than this function and more correct than the
/// cache. Procfs entries without a pid carry a uid alone, which is just as
/// wrong to reuse on a recycled port as the rest of it.
fn cached_still_valid(proc_root: &Path, info: &ProcInfo) -> bool {
    let (Some(pid), Some(inode)) = (info.pid, info.socket_inode) else {
        return false;
    };
    if info.starttime.is_none() || procfs::starttime_of(proc_root, pid) != info.starttime {
        return false;
    }
    // The same resolution the entry was made with, so a refused name stays
    // refused and a checked one is checked again, down to the file.
    let (exe, exe_id) = procfs::host_exe_id(proc_root, pid).unzip();
    if exe != info.exe_path || exe_id.flatten() != info.exe_id {
        return false;
    }
    procfs::pid_holds_inode(proc_root, pid, inode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A source that always answers the same thing and counts how often it
    /// was asked. The count is the point: these tests are about when the
    /// cache is allowed to answer instead.
    #[derive(Clone)]
    struct Fixed(Arc<(Option<ProcInfo>, AtomicUsize)>);

    impl Fixed {
        fn new(info: Option<ProcInfo>) -> Self {
            Self(Arc::new((info, AtomicUsize::new(0))))
        }
        fn calls(&self) -> usize {
            self.0 .1.load(Ordering::SeqCst)
        }
    }

    impl Attributor for Fixed {
        fn attribute(&self, _tuple: &FlowTuple) -> Option<ProcInfo> {
            self.0 .1.fetch_add(1, Ordering::SeqCst);
            self.0 .0.clone()
        }
    }

    /// A source that sees every connect and has lost this one.
    struct WitnessMiss;

    impl Attributor for WitnessMiss {
        fn attribute(&self, _tuple: &FlowTuple) -> Option<ProcInfo> {
            None
        }
        fn sees_every_connect(&self) -> bool {
            true
        }
    }

    /// When the source that sees every connect missed a SYN, the fallback's
    /// answer keeps who the process is but not which image it runs: that is
    /// what an exec after the connect would have changed.
    #[test]
    fn a_syn_the_witness_missed_carries_no_executable() {
        let fallback = Fixed::new(Some(ProcInfo {
            cmdline: Some("curl example.org".into()),
            parent_exe: Some(PathBuf::from("/usr/bin/bash")),
            ..info()
        }));
        let chain = AttributionChain::new(vec![Box::new(WitnessMiss), Box::new(fallback)]);
        let (conn, exe_id) = chain.connection(tuple(), true);
        assert_eq!(conn.uid, Some(1000));
        assert_eq!(conn.pid, Some(PID));
        assert_eq!(conn.exe_path, None);
        assert_eq!(exe_id, None);
        assert_eq!(conn.cmdline, None);
        assert_eq!(conn.parent_exe, Some(PathBuf::from("/usr/bin/bash")));

        // A mid-stream packet (not a SYN) keeps the fallback's full answer.
        let fallback = Fixed::new(Some(info()));
        let chain = AttributionChain::new(vec![Box::new(WitnessMiss), Box::new(fallback)]);
        let (conn, _) = chain.connection(tuple(), false);
        assert_eq!(conn.exe_path, Some(PathBuf::from(EXE)));
    }

    const PID: u32 = 4242;
    const INODE: u64 = 123_456;
    const EXE: &str = "/usr/bin/curl";

    fn tuple() -> FlowTuple {
        FlowTuple {
            proto: hallpass_types::Proto::Tcp,
            src: "10.0.0.1:1234".parse().unwrap(),
            dst: "10.0.0.2:80".parse().unwrap(),
        }
    }

    /// A `/proc` holding one process that owns one socket.
    fn fake_proc(tag: &str) -> crate::testutil::TestDir {
        let td = crate::testutil::TestDir::new(&format!("attr-{tag}"));
        let fd = td.path().join(PID.to_string()).join("fd");
        std::fs::create_dir_all(&fd).unwrap();
        std::os::unix::fs::symlink(format!("socket:[{INODE}]"), fd.join("3")).unwrap();
        std::os::unix::fs::symlink(EXE, td.path().join(PID.to_string()).join("exe")).unwrap();
        write_starttime(&td, 900);
        td
    }

    /// Rewrite the fixture's stat line. Field 22 is the start time; the
    /// nineteen before it are only there to be counted past.
    fn write_starttime(td: &crate::testutil::TestDir, starttime: u64) {
        std::fs::write(
            td.path().join(PID.to_string()).join("stat"),
            format!("{PID} (curl) S 1 {PID} {PID} 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {starttime}"),
        )
        .unwrap();
    }

    /// A chain over `source` alone, reading the fixture `/proc` in `td`.
    fn chain_over(td: &crate::testutil::TestDir, source: &Fixed) -> AttributionChain {
        AttributionChain::with_proc_root(vec![Box::new(source.clone())], td.path().to_path_buf())
    }

    fn info() -> ProcInfo {
        ProcInfo {
            pid: Some(PID),
            uid: 1000,
            exe_path: Some(PathBuf::from(EXE)),
            exe_id: None,
            cmdline: None,
            parent_exe: None,
            app_id: None,
            starttime: Some(900),
            socket_inode: Some(INODE),
        }
    }

    #[test]
    fn first_source_wins_and_result_is_cached() {
        let td = fake_proc("cached");
        let first = Fixed::new(Some(info()));
        let second = Fixed::new(None);
        let chain = AttributionChain::with_proc_root(
            vec![Box::new(first.clone()), Box::new(second.clone())],
            td.path().to_path_buf(),
        );
        assert_eq!(chain.attribute(&tuple()), Some(info()));
        assert_eq!(chain.attribute(&tuple()), Some(info()));
        assert_eq!(first.calls(), 1, "the second lookup came from cache");
        assert_eq!(second.calls(), 0, "the first source answered");
    }

    /// The attack the revalidation exists for. A local process reads a
    /// victim's flow out of the world-readable /proc/net, waits for the
    /// socket to close, and binds the same source port to the same
    /// destination. The tuple is the cache key, so the entry is still there,
    /// and the victim is still running its original binary, so liveness
    /// proves nothing. Serving it would hand the victim's uid, exe, cmdline,
    /// parent and hash-pinned rules to the connection.
    #[test]
    fn a_reused_source_port_is_not_judged_as_the_previous_owner() {
        let td = fake_proc("port-reuse");
        let source = Fixed::new(Some(info()));
        let chain = chain_over(&td, &source);
        assert_eq!(chain.attribute(&tuple()), Some(info()));

        // The victim closes the socket. It is still alive, still running the
        // same executable, and the port is now free for anyone.
        std::fs::remove_file(td.path().join(PID.to_string()).join("fd").join("3")).unwrap();

        assert_eq!(chain.attribute(&tuple()), Some(info()));
        assert_eq!(source.calls(), 2, "the cache answered for the new owner");
    }

    /// A pid that has been recycled is a different process wearing the same
    /// number. Start time is what tells them apart.
    #[test]
    fn a_recycled_pid_is_not_judged_as_the_process_that_left() {
        let td = fake_proc("pid-reuse");
        let source = Fixed::new(Some(info()));
        let chain = chain_over(&td, &source);
        assert_eq!(chain.attribute(&tuple()), Some(info()));
        write_starttime(&td, 901);
        assert_eq!(chain.attribute(&tuple()), Some(info()));
        assert_eq!(source.calls(), 2, "the cache answered for a new process");
    }

    /// execve keeps the pid and the start time, so the executable has to be
    /// checked too: the entry names a program, and the rules that matched it
    /// are about that program.
    #[test]
    fn an_exec_in_place_invalidates_the_entry() {
        let td = fake_proc("exec");
        let source = Fixed::new(Some(info()));
        let chain = chain_over(&td, &source);
        assert_eq!(chain.attribute(&tuple()), Some(info()));
        let exe = td.path().join(PID.to_string()).join("exe");
        std::fs::remove_file(&exe).unwrap();
        std::os::unix::fs::symlink("/tmp/other", &exe).unwrap();
        assert_eq!(chain.attribute(&tuple()), Some(info()));
        assert_eq!(source.calls(), 2, "the cache answered for a new program");
    }

    /// An entry with no socket inode cannot be checked against the flow, so
    /// it is never served. That is what eBPF-sourced entries look like, and
    /// asking that source again is one map lookup: cheaper than this check
    /// and more current than the cache.
    #[test]
    fn an_entry_with_nothing_to_check_against_is_never_served() {
        let td = fake_proc("no-inode");
        let mut i = info();
        i.socket_inode = None;
        let source = Fixed::new(Some(i.clone()));
        let chain = chain_over(&td, &source);
        assert_eq!(chain.attribute(&tuple()), Some(i.clone()));
        assert_eq!(chain.attribute(&tuple()), Some(i));
        assert_eq!(source.calls(), 2);
    }

    #[test]
    fn connection_from_unattributed_tuple() {
        let chain = AttributionChain::new(vec![Box::new(Fixed::new(None))]);
        let (conn, _) = chain.connection(tuple(), false);
        assert_eq!(conn.uid, None);
        assert_eq!(conn.exe_path, None);
        assert_eq!(conn.tuple, tuple());
    }
}

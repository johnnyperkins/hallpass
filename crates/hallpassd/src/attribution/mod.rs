//! Map network flows to the local process that owns them.

#[cfg(any(test, feature = "ebpf"))]
pub mod btf;
pub mod cache;
#[cfg(feature = "ebpf")]
pub mod ebpf;
pub mod hash;
pub mod procfs;
// Spike, measured but not yet consulted by the verdict path, so outside of
// tests nothing calls it; drop the allow when the chain adopts or the spike
// is thrown away. See docs/attribution-threading.md, recommendation 3.
#[allow(dead_code)]
pub mod sockdiag;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hallpass_types::{Connection, FlowTuple};

/// Process metadata resolved for a flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    /// Process ID, when the socket inode could be traced to a process.
    pub pid: Option<u32>,
    /// Owning UID of the socket.
    pub uid: u32,
    /// Executable path from /proc/pid/exe.
    pub exe_path: Option<PathBuf>,
    /// Command line from /proc/pid/cmdline.
    pub cmdline: Option<String>,
    /// Executable path of the parent process, from /proc/ppid/exe.
    pub parent_exe: Option<PathBuf>,
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
/// the first hit wins. An eBPF-based attributor will slot in here later.
pub trait Attributor: Send + Sync {
    /// Resolve the process behind `tuple`, if this source can.
    fn attribute(&self, tuple: &FlowTuple) -> Option<ProcInfo>;
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
        AttributionChain {
            sources,
            cache: cache::AttrCache::default(),
            proc_root: PathBuf::from("/proc"),
        }
    }

    /// A chain reading a fixture instead of the real `/proc`.
    #[cfg(test)]
    fn with_proc_root(sources: Vec<Box<dyn Attributor>>, proc_root: PathBuf) -> Self {
        AttributionChain {
            sources,
            cache: cache::AttrCache::default(),
            proc_root,
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
        let procfs: Box<dyn Attributor> = Box::new(procfs::ProcfsAttributor::default());
        #[cfg(feature = "ebpf")]
        if let Some(e) = ebpf::EbpfAttributor::new(dns_cache) {
            return Arc::new(Self::new(vec![Box::new(e), procfs]));
        }
        Arc::new(Self::new(vec![procfs]))
    }

    /// Resolve `tuple`, consulting the cache first. Misses (including
    /// negative results) are cached to avoid /proc scan storms.
    pub fn attribute(&self, tuple: &FlowTuple) -> Option<ProcInfo> {
        if let Some(cached) = self.cache.get(tuple) {
            match &cached {
                None => return None,
                // Source ports are reused, so an entry outlives the flow it
                // was resolved from and serving it would hand one process's
                // identity, and its allow rules, to whatever owns the port
                // now. Every positive hit is checked before it is trusted.
                Some(info) if cached_still_valid(&self.proc_root, info) => return cached,
                _ => {}
            }
        }
        let info = self.sources.iter().find_map(|s| s.attribute(tuple));
        self.cache.put(*tuple, info.clone());
        info
    }

    /// Build a [`Connection`] for `tuple` with whatever attribution is
    /// available. The domain is left unset; DNS snooping fills it in later.
    pub fn connection(&self, tuple: FlowTuple) -> Connection {
        let info = self.attribute(&tuple);
        let (uid, pid, exe_path, cmdline, parent_exe) = match info {
            Some(i) => (Some(i.uid), i.pid, i.exe_path, i.cmdline, i.parent_exe),
            None => (None, None, None, None, None),
        };
        Connection {
            tuple,
            uid,
            pid,
            exe_path,
            cmdline,
            parent_exe,
            domain: None,
            // Interface is packet metadata; the queue loop fills it in.
            iface: None,
        }
    }
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
    let exe = proc_root.join(pid.to_string()).join("exe");
    if std::fs::read_link(exe).ok() != info.exe_path {
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
        fn new(info: Option<ProcInfo>) -> Fixed {
            Fixed(Arc::new((info, AtomicUsize::new(0))))
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

    fn info() -> ProcInfo {
        ProcInfo {
            pid: Some(PID),
            uid: 1000,
            exe_path: Some(PathBuf::from(EXE)),
            cmdline: None,
            parent_exe: None,
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
        let chain = AttributionChain::with_proc_root(
            vec![Box::new(source.clone())],
            td.path().to_path_buf(),
        );
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
        let chain = AttributionChain::with_proc_root(
            vec![Box::new(source.clone())],
            td.path().to_path_buf(),
        );
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
        let chain = AttributionChain::with_proc_root(
            vec![Box::new(source.clone())],
            td.path().to_path_buf(),
        );
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
        let chain = AttributionChain::with_proc_root(
            vec![Box::new(source.clone())],
            td.path().to_path_buf(),
        );
        assert_eq!(chain.attribute(&tuple()), Some(i.clone()));
        assert_eq!(chain.attribute(&tuple()), Some(i));
        assert_eq!(source.calls(), 2);
    }

    #[test]
    fn connection_from_unattributed_tuple() {
        let chain = AttributionChain::new(vec![Box::new(Fixed::new(None))]);
        let conn = chain.connection(tuple());
        assert_eq!(conn.uid, None);
        assert_eq!(conn.exe_path, None);
        assert_eq!(conn.tuple, tuple());
    }
}

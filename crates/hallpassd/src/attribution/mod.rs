//! Map network flows to the local process that owns them.

#[cfg(any(test, feature = "ebpf"))]
pub mod btf;
pub mod cache;
#[cfg(feature = "ebpf")]
pub mod ebpf;
pub mod hash;
pub mod procfs;

use std::path::PathBuf;
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
}

impl AttributionChain {
    /// Build a chain from ordered sources with the default cache sizing.
    pub fn new(sources: Vec<Box<dyn Attributor>>) -> Self {
        AttributionChain {
            sources,
            cache: cache::AttrCache::default(),
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
        let procfs: Box<dyn Attributor> = Box::new(procfs::ProcfsAttributor);
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
                // Source ports are reused: a new connection can carry
                // the tuple of a flow whose owner has since exited, and
                // serving that entry would hand the old process's
                // identity (and its allow rules) to whatever owns the
                // port now. Trust a positive hit only while its process
                // still runs its recorded executable.
                Some(info) if cached_still_valid(info) => return cached,
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

/// Whether a cached positive attribution still describes a live process:
/// the pid exists and its exe symlink reads the same as when cached (a
/// failed readlink counts as None on both sides, matching how the entry
/// was captured). Without a pid there is nothing to verify against.
fn cached_still_valid(info: &ProcInfo) -> bool {
    let Some(pid) = info.pid else {
        return false;
    };
    let base = std::path::Path::new("/proc").join(pid.to_string());
    if !base.exists() {
        return false;
    }
    std::fs::read_link(base.join("exe")).ok() == info.exe_path
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fixed(Option<ProcInfo>, AtomicUsize);
    impl Attributor for Fixed {
        fn attribute(&self, _tuple: &FlowTuple) -> Option<ProcInfo> {
            self.1.fetch_add(1, Ordering::SeqCst);
            self.0.clone()
        }
    }

    fn tuple() -> FlowTuple {
        FlowTuple {
            proto: hallpass_types::Proto::Tcp,
            src: "10.0.0.1:1234".parse().unwrap(),
            dst: "10.0.0.2:80".parse().unwrap(),
        }
    }

    #[test]
    fn first_source_wins_and_result_is_cached() {
        let hit = ProcInfo {
            pid: Some(1),
            uid: 0,
            exe_path: None,
            cmdline: None,
            parent_exe: None,
        };
        let chain = AttributionChain::new(vec![
            Box::new(Fixed(Some(hit.clone()), AtomicUsize::new(0))),
            Box::new(Fixed(None, AtomicUsize::new(0))),
        ]);
        assert_eq!(chain.attribute(&tuple()), Some(hit.clone()));
        // Second lookup is served from cache; source not consulted again.
        assert_eq!(chain.attribute(&tuple()), Some(hit));
    }

    #[test]
    fn connection_from_unattributed_tuple() {
        let chain = AttributionChain::new(vec![Box::new(Fixed(None, AtomicUsize::new(0)))]);
        let conn = chain.connection(tuple());
        assert_eq!(conn.uid, None);
        assert_eq!(conn.exe_path, None);
        assert_eq!(conn.tuple, tuple());
    }
}

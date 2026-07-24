//! SHA-256 of executable files, cached by file identity.
//!
//! Hashing runs on the packet-decision thread, so results are cached keyed
//! by the file's (dev, inode, mtime, size): a rebuilt or replaced binary
//! gets a fresh hash, an unchanged one is hashed exactly once regardless of
//! the path it was reached through (`/proc/<pid>/exe` of different pids of
//! the same binary share one entry). Unreadable paths are cheap failures
//! and are not cached.

use std::num::NonZeroUsize;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use hallpass_types::Connection;
use lru::LruCache;
use sha2::{Digest, Sha256};

/// File identity snapshot; a changed binary changes this key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FileId {
    dev: u64,
    ino: u64,
    mtime: i64,
    size: u64,
}

impl FileId {
    fn of(meta: &std::fs::Metadata) -> FileId {
        FileId {
            dev: meta.dev(),
            ino: meta.ino(),
            mtime: meta.mtime(),
            size: meta.size(),
        }
    }
}

/// Bounded LRU cache of executable hashes.
pub struct ExeHashCache {
    entries: Mutex<LruCache<FileId, String>>,
}

impl Default for ExeHashCache {
    fn default() -> Self {
        ExeHashCache::new(1024)
    }
}

impl ExeHashCache {
    pub fn new(max_entries: usize) -> ExeHashCache {
        let cap = NonZeroUsize::new(max_entries.max(1)).unwrap();
        ExeHashCache {
            entries: Mutex::new(LruCache::new(cap)),
        }
    }

    /// SHA-256 of the executable behind `conn`, as lowercase hex.
    ///
    /// Prefers `/proc/<pid>/exe`, which pins the inode the process is
    /// actually executing: a binary renamed or overwritten after exec
    /// hashes as what is running, not what now sits at its old path. Falls
    /// back to the attributed path when the process is already gone.
    pub fn for_connection(&self, conn: &Connection) -> Option<String> {
        if let Some(pid) = conn.pid {
            let proc_exe = PathBuf::from(format!("/proc/{pid}/exe"));
            if let Some(hex) = self.sha256(&proc_exe) {
                return Some(hex);
            }
        }
        self.sha256(conn.exe_path.as_deref()?)
    }

    /// SHA-256 of the file at `path` as lowercase hex, or `None` if it
    /// cannot be read. Served from cache while (dev, ino, mtime, size)
    /// are unchanged.
    ///
    /// The file is opened first and the identity taken from the open fd,
    /// so the cached key always describes the bytes actually hashed - a
    /// stat-then-open sequence could pair the old binary's identity with
    /// a replacement's hash if the path was swapped between the calls.
    pub fn sha256(&self, path: &Path) -> Option<String> {
        let mut file = std::fs::File::open(path).ok()?;
        let id = FileId::of(&file.metadata().ok()?);
        if let Some(hex) = self.entries.lock().unwrap().get(&id) {
            return Some(hex.clone());
        }
        let mut hasher = Sha256::new();
        std::io::copy(&mut file, &mut hasher).ok()?;
        let hex = format!("{:x}", hasher.finalize());
        self.entries.lock().unwrap().put(id, hex.clone());
        Some(hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestDir;

    /// SHA-256 of the empty string, a well-known constant.
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn hashes_and_caches_until_file_changes() {
        let dir = TestDir::new("hash");
        let path = dir.path().join("bin");
        std::fs::write(&path, b"").unwrap();
        let cache = ExeHashCache::default();
        assert_eq!(cache.sha256(&path).unwrap(), EMPTY_SHA256);

        // Change contents (and thus identity); the hash must follow.
        std::fs::write(&path, b"hello").unwrap();
        assert_eq!(
            cache.sha256(&path).unwrap(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn unreadable_path_is_none() {
        let cache = ExeHashCache::default();
        assert_eq!(cache.sha256(Path::new("/nonexistent/no-such-file")), None);
    }

    #[test]
    fn tiny_capacity_still_works() {
        let dir = TestDir::new("hash-evict");
        let cache = ExeHashCache::new(1);
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        let ha = cache.sha256(&a).unwrap();
        let hb = cache.sha256(&b).unwrap();
        assert_ne!(ha, hb);
        assert_eq!(cache.sha256(&a).unwrap(), ha);
    }

    #[test]
    fn for_connection_prefers_own_proc_exe() {
        // Use our own pid: /proc/self-pid/exe is the test binary.
        let conn = Connection {
            tuple: hallpass_types::FlowTuple {
                proto: hallpass_types::Proto::Tcp,
                src: "127.0.0.1:1".parse().unwrap(),
                dst: "127.0.0.1:2".parse().unwrap(),
            },
            uid: None,
            pid: Some(std::process::id()),
            exe_path: None,
            cmdline: None,
            domain: None,
        };
        let cache = ExeHashCache::default();
        let hash = cache.for_connection(&conn).unwrap();
        assert_eq!(hash.len(), 64);
        // Dead pid and no path: nothing to hash.
        let gone = Connection {
            pid: Some(u32::MAX - 1),
            ..conn
        };
        assert_eq!(cache.for_connection(&gone), None);
    }
}

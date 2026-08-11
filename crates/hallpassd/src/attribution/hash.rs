//! SHA-256 of executable files, cached by file identity.
//!
//! Hashing runs on the packet-decision thread, so results are cached keyed
//! by the file's (dev, inode, mtime, ctime, size): a rebuilt, replaced or
//! rewritten binary gets a fresh hash, an unchanged one is hashed exactly
//! once regardless of the path it was reached through (`/proc/<pid>/exe` of
//! different pids of the same binary share one entry). Unreadable paths are
//! cheap failures and are not cached. See [`FileId`] for why ctime is in
//! that key and not just mtime.

use std::num::NonZeroUsize;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use hallpass_types::Connection;
use lru::LruCache;
use sha2::{Digest, Sha256};

/// File identity snapshot; a changed file changes this key. Shared with
/// the rule-list cache, which invalidates the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct FileId {
    dev: u64,
    ino: u64,
    mtime: i64,
    // Seconds-only mtime misses a same-size rewrite within one second;
    // nanoseconds close that window on filesystems that record them.
    mtime_nsec: i64,
    // Modification times are writable by the file's owner (utimensat), so
    // mtime and size alone are a key the attacker holds: rewrite the binary
    // in place at the same length, put the old mtime back, and the cache
    // keeps serving the pre-tamper hash for the life of the daemon. That
    // defeats exactly what exe_sha256 is bought for, and the victim only has
    // to run the program normally. ctime is the one field the owner cannot
    // set - utimensat bumps it too - and it moves on any write, chmod, or
    // rename. Probe-confirmed: after such a rewrite every other field here
    // was unchanged and ctime was the only one that moved.
    ctime: i64,
    ctime_nsec: i64,
    size: u64,
}

impl FileId {
    pub(crate) fn of(meta: &std::fs::Metadata) -> FileId {
        FileId {
            dev: meta.dev(),
            ino: meta.ino(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
            size: meta.size(),
        }
    }
}

/// Largest executable this will read.
///
/// The read runs on the verdict thread, where blocking is a stalled packet
/// for every other connection on the host, and the size of the file is
/// chosen by whoever exec'd it. 256 MiB is past any binary this is likely to
/// meet (the largest commonly shipped ones are well under 200 MiB) and is a
/// bounded fraction of a second to hash, once per distinct file.
///
/// Skipping costs the hash, which costs a match: a rule pinning
/// `exe_sha256` or listing a `hashes_file` does not match a binary this
/// large, and evaluation falls through to lower-priority rules or the prompt.
/// That is the behaviour [`hallpass_types::RuleMatch::exe_sha256`] already
/// documents for a binary that cannot be read, and it opens no new evasion:
/// padding a binary past the cap changes its bytes, and a padded binary has
/// a different hash, so it was never going to match a pinned rule anyway.
const MAX_HASHED_BYTES: u64 = 256 * 1024 * 1024;

/// Bounded LRU cache of executable hashes.
///
/// `None` records a file that was looked at and deliberately not hashed, so
/// an oversized binary is measured and refused once rather than on every
/// packet it sends.
pub struct ExeHashCache {
    entries: Mutex<LruCache<FileId, Option<String>>>,
    max_bytes: u64,
}

impl Default for ExeHashCache {
    fn default() -> Self {
        ExeHashCache::new(1024)
    }
}

impl ExeHashCache {
    pub fn new(max_entries: usize) -> ExeHashCache {
        ExeHashCache::with_max_bytes(max_entries, MAX_HASHED_BYTES)
    }

    /// Cache with an explicit size cap, so the refusal can be exercised
    /// without writing a quarter of a gigabyte to disk.
    pub fn with_max_bytes(max_entries: usize, max_bytes: u64) -> ExeHashCache {
        let cap = NonZeroUsize::new(max_entries.max(1)).unwrap();
        ExeHashCache {
            entries: Mutex::new(LruCache::new(cap)),
            max_bytes,
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
    /// cannot be read. Served from cache while (dev, ino, mtime, ctime,
    /// size) are unchanged.
    ///
    /// The file is opened first and the identity taken from the open fd,
    /// so the cached key always describes the bytes actually hashed - a
    /// stat-then-open sequence could pair the old binary's identity with
    /// a replacement's hash if the path was swapped between the calls.
    pub fn sha256(&self, path: &Path) -> Option<String> {
        let mut file = std::fs::File::open(path).ok()?;
        let meta = file.metadata().ok()?;
        let id = FileId::of(&meta);
        if let Some(cached) = self.entries.lock().unwrap().get(&id) {
            return cached.clone();
        }
        // Refused before a byte is read, and remembered as refused. Anything
        // without a length to check is refused with it: a regular file is
        // the only thing an executable can be, and it is the only thing
        // whose size means the read will end.
        if !meta.is_file() || meta.len() > self.max_bytes {
            tracing::warn!(
                bytes = meta.len(),
                regular = meta.is_file(),
                "not hashing an executable this large on the verdict thread; \
                 hash-pinned rules will not match it"
            );
            self.entries.lock().unwrap().put(id, None);
            return None;
        }
        let mut hasher = Sha256::new();
        // A read that fails part way is not cached: it is a transient
        // failure, not a decision about this file.
        std::io::copy(&mut file, &mut hasher).ok()?;
        let hex = format!("{:x}", hasher.finalize());
        self.entries.lock().unwrap().put(id, Some(hex.clone()));
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

    /// The tamper the cache key has to survive: rewrite the binary in place
    /// at the same length and put the old mtime back with utimensat, which
    /// any owner can do unprivileged. Every other stat field the key could
    /// use is unchanged by that, so before ctime joined the key the daemon
    /// served the pre-tamper hash for the rest of its life and a hash-pinned
    /// allow rule kept matching code nobody approved. The victim only has to
    /// run the program normally, so this is not covered by the documented
    /// exec-after-connect caveat.
    #[test]
    fn same_size_rewrite_with_restored_mtime_is_not_served_from_cache() {
        use std::io::{Seek, Write};

        let dir = TestDir::new("hash-tamper");
        let path = dir.path().join("bin");
        std::fs::write(&path, b"aaaaa").unwrap();
        let before = std::fs::metadata(&path).unwrap();
        let times = std::fs::FileTimes::new()
            .set_accessed(before.accessed().unwrap())
            .set_modified(before.modified().unwrap());

        let cache = ExeHashCache::default();
        let original = cache.sha256(&path).unwrap();

        // In place, same length, no truncation: the inode and size cannot
        // move. Then restore the timestamps the owner controls.
        let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(std::io::SeekFrom::Start(0)).unwrap();
        file.write_all(b"bbbbb").unwrap();
        file.set_times(times).unwrap();
        drop(file);

        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(after.len(), before.len(), "the rewrite kept the size");
        assert_eq!(after.mtime(), before.mtime(), "the rewrite restored mtime");
        assert_eq!(after.mtime_nsec(), before.mtime_nsec(), "including nanoseconds");

        assert_ne!(
            cache.sha256(&path).unwrap(),
            original,
            "a tampered binary must not keep serving its old hash"
        );
    }

    #[test]
    fn unreadable_path_is_none() {
        let cache = ExeHashCache::default();
        assert_eq!(cache.sha256(Path::new("/nonexistent/no-such-file")), None);
    }

    /// The read runs on the thread that decides every packet, and the size
    /// of the file is chosen by whoever exec'd it, so there is a point past
    /// which the daemon declines. Declining costs the match, not a verdict:
    /// a hash-pinned rule stops matching, exactly as it does for a binary it
    /// cannot read.
    #[test]
    fn an_oversized_executable_is_measured_and_refused() {
        let dir = TestDir::new("hash-cap");
        let path = dir.path().join("big");
        std::fs::write(&path, b"0123456789").unwrap();
        let cache = ExeHashCache::with_max_bytes(8, 4);
        assert_eq!(cache.sha256(&path), None);

        // Refused once and remembered, so a process sending at line rate
        // does not re-measure its own binary per packet.
        assert_eq!(cache.sha256(&path), None);
        assert_eq!(cache.entries.lock().unwrap().len(), 1);

        // Under the cap the same cache hashes normally.
        std::fs::write(&path, b"ab").unwrap();
        assert_eq!(cache.sha256(&path).unwrap().len(), 64);
    }

    /// Only a regular file has a length that makes the read finite. A
    /// directory, a fifo or a character device is refused on the same path.
    #[test]
    fn a_non_regular_file_is_never_read() {
        let dir = TestDir::new("hash-dir");
        let cache = ExeHashCache::default();
        assert_eq!(cache.sha256(dir.path()), None);
        assert_eq!(cache.sha256(Path::new("/dev/zero")), None);
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
            parent_exe: None,
            domain: None,
            iface: None,
            app_id: None,
            first_seen: None,
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

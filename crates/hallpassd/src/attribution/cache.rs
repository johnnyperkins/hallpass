//! LRU cache for flow attribution, with a short TTL on negative results
//! so a burst of packets from one unattributable flow does not trigger a
//! /proc rescan per packet.

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;
use hallpass_types::FlowTuple;

use super::ProcInfo;

const CAPACITY: usize = 4096;
const POSITIVE_TTL: Duration = Duration::from_secs(60);
const NEGATIVE_TTL: Duration = Duration::from_millis(1500);

struct Entry {
    info: Option<ProcInfo>,
    inserted: Instant,
}

/// Thread-safe LRU of tuple -> attribution result.
pub struct AttrCache {
    inner: Mutex<LruCache<FlowTuple, Entry>>,
    positive_ttl: Duration,
    negative_ttl: Duration,
}

impl Default for AttrCache {
    fn default() -> Self {
        Self::with_ttls(POSITIVE_TTL, NEGATIVE_TTL)
    }
}

impl AttrCache {
    /// Cache with explicit TTLs (tests use short ones).
    pub fn with_ttls(positive_ttl: Duration, negative_ttl: Duration) -> Self {
        AttrCache {
            inner: Mutex::new(LruCache::new(NonZeroUsize::new(CAPACITY).unwrap())),
            positive_ttl,
            negative_ttl,
        }
    }

    /// Outer `None` = cache miss; `Some(None)` = cached negative result.
    pub fn get(&self, tuple: &FlowTuple) -> Option<Option<ProcInfo>> {
        let mut cache = self.inner.lock().unwrap();
        let entry = cache.get(tuple)?;
        let ttl = if entry.info.is_some() {
            self.positive_ttl
        } else {
            self.negative_ttl
        };
        if entry.inserted.elapsed() >= ttl {
            cache.pop(tuple);
            return None;
        }
        Some(entry.info.clone())
    }

    /// Store a lookup result (positive or negative).
    pub fn put(&self, tuple: FlowTuple, info: Option<ProcInfo>) {
        self.inner.lock().unwrap().put(
            tuple,
            Entry {
                info,
                inserted: Instant::now(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(port: u16) -> FlowTuple {
        FlowTuple {
            proto: hallpass_types::Proto::Tcp,
            src: format!("127.0.0.1:{port}").parse().unwrap(),
            dst: "127.0.0.1:80".parse().unwrap(),
        }
    }

    fn info() -> ProcInfo {
        ProcInfo {
            pid: Some(42),
            uid: 1000,
            exe_path: Some("/usr/bin/curl".into()),
            cmdline: None,
            parent_exe: None,
            app_id: None,
            starttime: Some(1234),
            socket_inode: Some(99),
        }
    }

    #[test]
    fn positive_hit() {
        let c = AttrCache::default();
        c.put(tuple(1), Some(info()));
        assert_eq!(c.get(&tuple(1)), Some(Some(info())));
        assert_eq!(c.get(&tuple(2)), None);
    }

    #[test]
    fn negative_hit_and_expiry() {
        let c = AttrCache::with_ttls(Duration::from_secs(60), Duration::ZERO);
        c.put(tuple(1), None);
        // Zero TTL: the negative entry is already expired.
        assert_eq!(c.get(&tuple(1)), None);

        let c = AttrCache::default();
        c.put(tuple(1), None);
        assert_eq!(c.get(&tuple(1)), Some(None));
    }
}

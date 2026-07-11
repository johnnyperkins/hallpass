//! Lock-free daemon statistics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use sentinel_types::{Stats, Verdict};

/// Atomic counters snapshot into [`Stats`] for the IPC `Stats` reply.
pub struct Counters {
    start: Instant,
    connections_total: AtomicU64,
    allowed: AtomicU64,
    denied: AtomicU64,
    prompted: AtomicU64,
}

impl Default for Counters {
    fn default() -> Self {
        Counters {
            start: Instant::now(),
            connections_total: AtomicU64::new(0),
            allowed: AtomicU64::new(0),
            denied: AtomicU64::new(0),
            prompted: AtomicU64::new(0),
        }
    }
}

impl Counters {
    /// Count a decided connection.
    pub fn record_verdict(&self, verdict: Verdict) {
        self.connections_total.fetch_add(1, Ordering::Relaxed);
        match verdict {
            Verdict::Allow => &self.allowed,
            Verdict::Deny | Verdict::Reject => &self.denied,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    /// Count a connection that triggered an interactive prompt.
    pub fn record_prompted(&self) {
        self.prompted.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot for the IPC reply. `rules_loaded` comes from the rule store.
    pub fn snapshot(&self, rules_loaded: u32) -> Stats {
        Stats {
            connections_total: self.connections_total.load(Ordering::Relaxed),
            allowed: self.allowed.load(Ordering::Relaxed),
            denied: self.denied.load(Ordering::Relaxed),
            prompted: self.prompted.load(Ordering::Relaxed),
            rules_loaded,
            uptime_secs: self.start.elapsed().as_secs(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_by_verdict() {
        let c = Counters::default();
        c.record_verdict(Verdict::Allow);
        c.record_verdict(Verdict::Deny);
        c.record_verdict(Verdict::Reject);
        c.record_prompted();
        let s = c.snapshot(5);
        assert_eq!(s.connections_total, 3);
        assert_eq!(s.allowed, 1);
        assert_eq!(s.denied, 2);
        assert_eq!(s.prompted, 1);
        assert_eq!(s.rules_loaded, 5);
    }
}

//! Lock-free daemon statistics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use hallpass_types::{Stats, Verdict};

/// Atomic counters snapshot into [`Stats`] for the IPC `Stats` reply.
pub struct Counters {
    start: Instant,
    connections_total: AtomicU64,
    allowed: AtomicU64,
    denied: AtomicU64,
    prompted: AtomicU64,
    dns_spoof_rejected: AtomicU64,
    prompts_overflowed: AtomicU64,
    other_proto_total: AtomicU64,
    /// Snoop packets dropped because the DNS queue was full. Internal only:
    /// adding a field to the `Stats` wire type would bump the protocol, since
    /// postcard encodes structs positionally.
    dns_snoop_dropped: AtomicU64,
}

impl Default for Counters {
    fn default() -> Self {
        Counters {
            start: Instant::now(),
            connections_total: AtomicU64::new(0),
            allowed: AtomicU64::new(0),
            denied: AtomicU64::new(0),
            prompted: AtomicU64::new(0),
            dns_spoof_rejected: AtomicU64::new(0),
            prompts_overflowed: AtomicU64::new(0),
            other_proto_total: AtomicU64::new(0),
            dns_snoop_dropped: AtomicU64::new(0),
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

    /// Count a DNS response rejected as unsolicited/spoofed.
    pub fn record_dns_spoof_rejected(&self) {
        self.dns_spoof_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a connection resolved by default because the prompt table was
    /// full.
    pub fn record_prompt_overflow(&self) {
        self.prompts_overflowed.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a DNS snoop packet dropped because the queue was full.
    ///
    /// Costs a domain annotation, never a verdict: snoop packets are accepted
    /// immediately and no rule decision waits on this queue. Logged on the
    /// first drop and then at each power of ten, so a flood is visible without
    /// the log itself becoming the flood.
    pub fn record_dns_snoop_dropped(&self) {
        let n = self.dns_snoop_dropped.fetch_add(1, Ordering::Relaxed) + 1;
        if n.is_power_of_two() || n % 10_000 == 0 {
            tracing::warn!(dropped = n, "DNS snoop queue full, dropping observed DNS");
        }
    }

    /// Count a packet with a transport the rule engine does not model
    /// (SCTP, ICMP, ...) or that failed to parse.
    pub fn record_other_proto(&self) {
        self.other_proto_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot for the IPC reply. `rules_loaded` and `rules_skipped` come
    /// from the rule store.
    pub fn snapshot(&self, rules_loaded: u32, rules_skipped: u64) -> Stats {
        Stats {
            connections_total: self.connections_total.load(Ordering::Relaxed),
            allowed: self.allowed.load(Ordering::Relaxed),
            denied: self.denied.load(Ordering::Relaxed),
            prompted: self.prompted.load(Ordering::Relaxed),
            rules_loaded,
            uptime_secs: self.start.elapsed().as_secs(),
            dns_spoof_rejected: self.dns_spoof_rejected.load(Ordering::Relaxed),
            rules_skipped,
            prompts_overflowed: self.prompts_overflowed.load(Ordering::Relaxed),
            other_proto_total: self.other_proto_total.load(Ordering::Relaxed),
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
        c.record_dns_spoof_rejected();
        c.record_prompt_overflow();
        c.record_prompt_overflow();
        let s = c.snapshot(5, 4);
        assert_eq!(s.connections_total, 3);
        assert_eq!(s.allowed, 1);
        assert_eq!(s.denied, 2);
        assert_eq!(s.prompted, 1);
        assert_eq!(s.rules_loaded, 5);
        assert_eq!(s.dns_spoof_rejected, 1);
        assert_eq!(s.rules_skipped, 4);
        assert_eq!(s.prompts_overflowed, 2);
    }
}

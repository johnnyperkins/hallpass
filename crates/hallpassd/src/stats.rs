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
    /// Snoop packets dropped because the DNS queue was full.
    dns_snoop_dropped: AtomicU64,
    /// Deny/reject verdicts recorded but not applied, in observe mode.
    observed_only: AtomicU64,
    /// Connections resolved by the default verdict because nobody answered.
    prompts_unanswered: AtomicU64,
    /// Prompt handlers evicted from the slot for not answering.
    prompt_handlers_evicted: AtomicU64,
}

impl Default for Counters {
    fn default() -> Self {
        Counters::new()
    }
}

impl Counters {
    /// Fresh counters.
    pub fn new() -> Self {
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
            observed_only: AtomicU64::new(0),
            prompts_unanswered: AtomicU64::new(0),
            prompt_handlers_evicted: AtomicU64::new(0),
        }
    }

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

    /// Count a connection resolved by default because a hold limit was
    /// reached: the prompt table was full, this prompt's packet budget was
    /// full, or the daemon was already holding all the packets it will hold
    /// at once. One counter for all three because they are one outcome to an
    /// operator - a connection nobody was asked about - and the log line at
    /// each site says which limit it was.
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
        if n.is_power_of_two() || n.is_multiple_of(10_000) {
            tracing::warn!(dropped = n, "DNS snoop queue full, dropping observed DNS");
        }
    }

    /// Count a packet with a transport the rule engine does not model
    /// (SCTP, ICMP, ...) or that failed to parse.
    pub fn record_other_proto(&self) {
        self.other_proto_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a deny or reject that observe mode recorded without applying.
    ///
    /// This is the number an operator sizes a rollout by, so it counts every
    /// packet enforcement would have stopped, including the ones that carry
    /// no connection (ICMP, SCTP, unparsable) and are decided by
    /// `unhandled_proto_verdict` alone. Those appear in no event, so if they
    /// were left out of this counter too, a hardened profile's dead ping
    /// would be invisible until the day enforcement was switched on.
    pub fn record_observed_only(&self) {
        self.observed_only.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a connection the default verdict decided because nobody
    /// answered: no client held the prompt slot, the one that did let the
    /// prompt time out, or the daemon stopped enforcing while the prompt was
    /// open (observe mode never holds a packet, so the ones already held are
    /// released with the default).
    ///
    /// Separate from [`Counters::record_prompt_overflow`], which is the
    /// daemon's own limit rather than a missing operator, because the two
    /// call for different actions: raise `max_pending_prompts`, or find out
    /// what happened to the prompt handler.
    pub fn record_prompt_unanswered(&self) {
        self.prompts_unanswered.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a prompt handler evicted from the slot for not answering.
    pub fn record_prompt_handler_evicted(&self) {
        self.prompt_handlers_evicted.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot for the IPC reply. `rules_loaded` and `rules_skipped` come
    /// from the rule store, `prompt_handler_connected` from the prompt table,
    /// `enforcing` from the runtime settings (reported so a client cannot
    /// read `denied` as "blocked" when nothing was blocked).
    ///
    /// All four are passed in rather than mirrored into a counter here on
    /// purpose: they are facts owned elsewhere, and a copy kept in step by
    /// hand is a copy that eventually is not.
    pub fn snapshot(
        &self,
        rules_loaded: u32,
        rules_skipped: u64,
        prompt_handler_connected: bool,
        enforcing: bool,
    ) -> Stats {
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
            observed_only: self.observed_only.load(Ordering::Relaxed),
            dns_snoop_dropped: self.dns_snoop_dropped.load(Ordering::Relaxed),
            enforcing,
            prompt_handler_connected,
            prompts_unanswered: self.prompts_unanswered.load(Ordering::Relaxed),
            prompt_handlers_evicted: self.prompt_handlers_evicted.load(Ordering::Relaxed),
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
        c.record_prompt_unanswered();
        c.record_prompt_handler_evicted();
        let s = c.snapshot(5, 4, true, true);
        assert_eq!(s.connections_total, 3);
        assert_eq!(s.allowed, 1);
        assert_eq!(s.denied, 2);
        assert_eq!(s.prompted, 1);
        assert_eq!(s.rules_loaded, 5);
        assert_eq!(s.dns_spoof_rejected, 1);
        assert_eq!(s.rules_skipped, 4);
        assert_eq!(s.prompts_overflowed, 2);
        assert_eq!(s.observed_only, 0);
        assert_eq!(s.prompts_unanswered, 1);
        assert_eq!(s.prompt_handlers_evicted, 1);
        assert!(s.enforcing);
        assert!(s.prompt_handler_connected);
    }

    /// The prompt-handler flag is not a counter: it is passed in from the
    /// prompt table at snapshot time, so it cannot drift from the table.
    #[test]
    fn prompt_handler_flag_is_passed_through() {
        let c = Counters::default();
        assert!(!c.snapshot(0, 0, false, true).prompt_handler_connected);
        assert!(c.snapshot(0, 0, true, true).prompt_handler_connected);
    }

    /// Observe mode has to be visible in the snapshot: `denied` counts what
    /// policy decided, and without `enforcing` a client would render that as
    /// traffic it stopped.
    #[test]
    fn observe_mode_is_reported() {
        let c = Counters::default();
        c.record_verdict(Verdict::Deny);
        c.record_observed_only();
        c.record_dns_snoop_dropped();
        let s = c.snapshot(0, 0, true, false);
        assert!(!s.enforcing);
        assert_eq!(s.denied, 1);
        assert_eq!(s.observed_only, 1);
        assert_eq!(s.dns_snoop_dropped, 1);
    }
}

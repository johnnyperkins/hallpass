//! Lock-free daemon statistics, and the kernel's own nfqueue counters.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use hallpass_types::{Stats, Verdict};

/// One queue's counters as the kernel reports them in
/// `/proc/net/netfilter/nfnetlink_queue`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueCounters {
    /// Packets in the queue right now (`queue_total`).
    pub depth: u64,
    /// Packets discarded because the queue was full (`queue_dropped`).
    pub dropped: u64,
    /// Packets that failed delivery to userspace (`user_dropped`).
    pub user_dropped: u64,
}

/// The kernel's counters for both queues this daemon binds, for the stats
/// snapshot. `None` per queue when its row (or the whole file) is missing:
/// a number nobody counted must not be reported as zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueStats {
    /// The verdict queue. Drops here are packets policy never saw.
    pub verdict: Option<QueueCounters>,
    /// The DNS snoop queue. Drops here cost domain annotations.
    pub snoop: Option<QueueCounters>,
    /// Effective kernel fail-open flag per queue, from bind rather than
    /// /proc (the kernel does not report it there). Filled by the IPC
    /// handler from `nfqueue::BoundQueues`; the parser leaves them `None`.
    /// These make the counters above readable: a fail-open queue resolves
    /// overflow by reinjecting with accept, unjudged and counted nowhere,
    /// so its drop counters can only move while the flag is off.
    pub verdict_fail_open: Option<bool>,
    /// See [`QueueStats::verdict_fail_open`].
    pub snoop_fail_open: Option<bool>,
}

/// Read the kernel's counters for the verdict queue and its snoop queue.
///
/// Called from the IPC `Stats` handler, on demand and never on the packet
/// path: one small /proc read per status request. Any failure (file absent,
/// row absent, column unparsable) degrades to `None` rather than zero.
pub fn read_queue_stats(verdict_queue: u16) -> QueueStats {
    match std::fs::read_to_string("/proc/net/netfilter/nfnetlink_queue") {
        Ok(text) => parse_queue_stats(&text, verdict_queue),
        Err(_) => QueueStats::default(),
    }
}

/// Parse the seq_file: one row per bound queue, no header. The column order
/// is not a documented ABI; it was verified against a live read with the
/// daemon running (2026-08-06, both queues bound, portid matching the
/// daemon's pid):
///
/// ```text
/// queue_num portid queue_total copy_mode copy_range queue_dropped
/// user_dropped id_sequence 1
/// ```
fn parse_queue_stats(text: &str, verdict_queue: u16) -> QueueStats {
    let snoop_queue = crate::nft::snoop_queue(verdict_queue);
    let mut stats = QueueStats::default();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 7 {
            continue;
        }
        let (Ok(queue_num), Ok(depth), Ok(dropped), Ok(user_dropped)) = (
            cols[0].parse::<u16>(),
            cols[2].parse::<u64>(),
            cols[5].parse::<u64>(),
            cols[6].parse::<u64>(),
        ) else {
            continue;
        };
        let counters = QueueCounters {
            depth,
            dropped,
            user_dropped,
        };
        if queue_num == verdict_queue {
            stats.verdict = Some(counters);
        } else if queue_num == snoop_queue {
            stats.snoop = Some(counters);
        }
    }
    stats
}

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
    /// Times the nft watchdog found the table gone (repairs attempted).
    nft_flushes: AtomicU64,
    /// Unix ms of the most recent detection; 0 means never.
    nft_last_flush_ms: AtomicU64,
    /// Flows the conntrack accounting listener has tallied at teardown.
    flows_accounted: AtomicU64,
    /// Total bytes across those flows (both directions).
    flow_bytes: AtomicU64,
    /// Total packets across those flows (both directions).
    flow_packets: AtomicU64,
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
            nft_flushes: AtomicU64::new(0),
            nft_last_flush_ms: AtomicU64::new(0),
            flows_accounted: AtomicU64::new(0),
            flow_bytes: AtomicU64::new(0),
            flow_packets: AtomicU64::new(0),
        }
    }

    /// Fold one ended flow's totals into the accounting counters.
    pub fn record_flow(&self, bytes: u64, packets: u64) {
        self.flows_accounted.fetch_add(1, Ordering::Relaxed);
        self.flow_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.flow_packets.fetch_add(packets, Ordering::Relaxed);
    }

    /// Count the watchdog finding the nftables table gone.
    ///
    /// The timestamp goes first and the count publishes it (Release paired
    /// with the Acquire in [`Counters::snapshot`]): a snapshot that sees
    /// the incremented count is guaranteed to see the timestamp that came
    /// with it, so status can never pair a nonzero count with a stale
    /// time. `.max(1)` keeps a host whose clock reads the epoch (no RTC,
    /// NTP not yet synced) from storing 0, which is the never sentinel.
    pub fn record_nft_flush(&self) {
        self.nft_last_flush_ms
            .store(hallpass_types::unix_ms_now().max(1), Ordering::Relaxed);
        self.nft_flushes.fetch_add(1, Ordering::Release);
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
    /// read `denied` as "blocked" when nothing was blocked), `queues` from
    /// the kernel via [`read_queue_stats`].
    ///
    /// All of those are passed in rather than mirrored into a counter here
    /// on purpose: they are facts owned elsewhere, and a copy kept in step
    /// by hand is a copy that eventually is not.
    pub fn snapshot(
        &self,
        rules_loaded: u32,
        rules_skipped: u64,
        prompt_handler_connected: bool,
        enforcing: bool,
        queues: QueueStats,
    ) -> Stats {
        // Acquire pairs with record_nft_flush's Release; loaded once,
        // before the struct build, because the timestamp field is gated on
        // it below.
        let nft_flushes = self.nft_flushes.load(Ordering::Acquire);
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
            verdict_queue_dropped: queues.verdict.map(|q| q.dropped),
            verdict_queue_user_dropped: queues.verdict.map(|q| q.user_dropped),
            verdict_queue_depth: queues.verdict.map(|q| q.depth),
            snoop_queue_dropped: queues.snoop.map(|q| q.dropped),
            snoop_queue_user_dropped: queues.snoop.map(|q| q.user_dropped),
            snoop_queue_depth: queues.snoop.map(|q| q.depth),
            verdict_queue_fail_open: queues.verdict_fail_open,
            snoop_queue_fail_open: queues.snoop_fail_open,
            nft_flushes,
            // Gated on the count so the pair can never contradict itself
            // in either direction: a timestamp is reported exactly when at
            // least one flush is. (record_nft_flush stores a nonzero
            // timestamp before publishing the count, so the 0 arm is
            // belt-and-braces.)
            nft_last_flush_ms: match self.nft_last_flush_ms.load(Ordering::Relaxed) {
                _ if nft_flushes == 0 => None,
                0 => None,
                ms => Some(ms),
            },
            flows_accounted: self.flows_accounted.load(Ordering::Relaxed),
            flow_bytes: self.flow_bytes.load(Ordering::Relaxed),
            flow_packets: self.flow_packets.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A recorded flush publishes count and timestamp together, the
    /// timestamp is never the 0 sentinel, and a zero count reports no
    /// timestamp at all.
    #[test]
    fn nft_flush_count_and_timestamp_agree() {
        let c = Counters::default();
        let before = c.snapshot(0, 0, false, true, QueueStats::default());
        assert_eq!(before.nft_flushes, 0);
        assert_eq!(before.nft_last_flush_ms, None);

        c.record_nft_flush();
        let after = c.snapshot(0, 0, false, true, QueueStats::default());
        assert_eq!(after.nft_flushes, 1);
        let ms = after.nft_last_flush_ms.expect("a flush carries its time");
        assert!(ms >= 1);
    }

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
        let s = c.snapshot(5, 4, true, true, QueueStats::default());
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
        assert!(!c.snapshot(0, 0, false, true, QueueStats::default()).prompt_handler_connected);
        assert!(c.snapshot(0, 0, true, true, QueueStats::default()).prompt_handler_connected);
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
        let s = c.snapshot(0, 0, true, false, QueueStats::default());
        assert!(!s.enforcing);
        assert_eq!(s.denied, 1);
        assert_eq!(s.observed_only, 1);
        assert_eq!(s.dns_snoop_dropped, 1);
    }

    /// Verbatim from the live read that pinned the column order
    /// (2026-08-06, daemon pid 162691 bound to queues 0 and 1).
    const PROC_SAMPLE: &str = "    0 162691     0 2 65531     0     0     1278  1\n    1 162691     0 2 65531     0     0      707  1\n";

    /// A synthetic sample with every counter distinct, so a column swap in
    /// the parser cannot pass by symmetry (the live sample is mostly zeros).
    const PROC_DISTINCT: &str = "    0 162691    11 2 65531    22    33     1278  1\n    1 162691    44 2 65531    55    66      707  1\n";

    #[test]
    fn parses_the_live_sample() {
        let s = parse_queue_stats(PROC_SAMPLE, 0);
        assert_eq!(
            s.verdict,
            Some(QueueCounters {
                depth: 0,
                dropped: 0,
                user_dropped: 0
            })
        );
        assert_eq!(
            s.snoop,
            Some(QueueCounters {
                depth: 0,
                dropped: 0,
                user_dropped: 0
            })
        );
    }

    #[test]
    fn columns_map_to_the_right_counters() {
        let s = parse_queue_stats(PROC_DISTINCT, 0);
        assert_eq!(
            s.verdict,
            Some(QueueCounters {
                depth: 11,
                dropped: 22,
                user_dropped: 33
            })
        );
        assert_eq!(
            s.snoop,
            Some(QueueCounters {
                depth: 44,
                dropped: 55,
                user_dropped: 66
            })
        );
    }

    /// Rows for queues this daemon did not bind (another instance on a
    /// different queue number) must not be picked up as ours.
    #[test]
    fn foreign_queue_rows_are_ignored() {
        let s = parse_queue_stats(PROC_DISTINCT, 40);
        assert_eq!(s, QueueStats::default());
    }

    /// The fail-open flags ride through the snapshot untouched: they come
    /// from bind, not /proc, and the parser must leave them None.
    #[test]
    fn fail_open_flags_pass_through() {
        assert_eq!(parse_queue_stats(PROC_SAMPLE, 0).verdict_fail_open, None);
        let c = Counters::default();
        let s = c.snapshot(
            0,
            0,
            true,
            true,
            QueueStats {
                verdict_fail_open: Some(true),
                snoop_fail_open: Some(false),
                ..Default::default()
            },
        );
        assert_eq!(s.verdict_queue_fail_open, Some(true));
        assert_eq!(s.snoop_queue_fail_open, Some(false));
        // Counters stay independently None: the flag being known does not
        // invent numbers nobody read.
        assert_eq!(s.verdict_queue_dropped, None);
    }

    /// A missing row, an empty file, or a row that stops parsing must all
    /// degrade to None, never to zero: zero claims nothing was dropped.
    #[test]
    fn unparsable_input_degrades_to_none() {
        assert_eq!(parse_queue_stats("", 0), QueueStats::default());
        // Verdict row present, snoop row missing.
        let s = parse_queue_stats("    0 1 5 2 65531 6 7 8 1\n", 0);
        assert!(s.verdict.is_some());
        assert_eq!(s.snoop, None);
        // Truncated and non-numeric rows are skipped, not zeroed.
        assert_eq!(parse_queue_stats("    0 1 5\n", 0), QueueStats::default());
        assert_eq!(
            parse_queue_stats("    0 1 x 2 65531 y z 8 1\n", 0),
            QueueStats::default()
        );
    }
}

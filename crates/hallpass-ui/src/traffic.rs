//! Aggregation behind the Traffic tab: what this machine talks to, folded
//! from the decided-connection feed.
//!
//! Deliberately free of egui so it can be tested without a display, which is
//! the only way any of this gets exercised in CI. The tab itself is a thin
//! renderer over [`Aggregate`].

use std::collections::{HashMap, HashSet};

use hallpass_types::{sanitize_for_display, ConnEvent, Verdict};

/// Most distinct rows tracked at once.
///
/// Every key comes from traffic, so a process picking a fresh destination per
/// connection would otherwise grow this without bound. Past the cap new keys
/// are counted in [`Aggregate::overflow`] and reported in the tab rather than
/// silently dropped: a view that quietly stops counting is worse than one
/// that says it stopped.
const MAX_ROWS: usize = 2048;

/// Most distinct destinations remembered per row.
const MAX_PEERS_PER_ROW: usize = 128;

/// What each row counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GroupBy {
    /// Executable of the initiating process.
    #[default]
    Exe,
    /// Destination domain, falling back to the address when unknown.
    Domain,
    /// Name of the rule that decided the connection.
    Rule,
}

impl GroupBy {
    /// Label for the selector.
    pub fn label(self) -> &'static str {
        match self {
            GroupBy::Exe => "Application",
            GroupBy::Domain => "Domain",
            GroupBy::Rule => "Rule",
        }
    }
}

/// What the traffic table is ordered by.
///
/// The busiest row first is the right default and the wrong answer to
/// half the questions this tab is opened with: "what is being blocked
/// most" and "what talked to something last" are the other two, and both
/// are one click away only if the column headings sort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortBy {
    #[default]
    Total,
    Allowed,
    Blocked,
    WouldBlock,
    Peers,
    LastSeen,
    /// The grouping key itself, for finding a known name rather than
    /// ranking anything.
    Key,
}

/// One aggregated row, ready to render.
#[derive(Debug, Default, Clone)]
pub struct Row {
    /// Grouping key, already sanitized.
    pub key: String,
    /// Connections counted.
    pub total: u64,
    /// Connections allowed.
    pub allowed: u64,
    /// Deny or reject that was applied.
    pub blocked: u64,
    /// Deny or reject that observe mode recorded without applying.
    pub would_block: u64,
    /// Distinct destinations, capped at [`MAX_PEERS_PER_ROW`].
    pub peers: usize,
    /// Most recent event for this row, Unix milliseconds.
    pub last_ms: u64,
    peer_set: HashSet<String>,
}

/// Rows plus the totals the header needs.
#[derive(Debug, Default)]
pub struct Aggregate {
    rows: HashMap<String, Row>,
    /// Events whose key did not fit under [`MAX_ROWS`].
    pub overflow: u64,
    /// Connections counted, including those that overflowed.
    pub total: u64,
}

impl Aggregate {
    /// Rebuild from the whole feed. Called when the grouping changes or the
    /// feed is replaced; folding incrementally would need a second copy of
    /// the ring to stay consistent with it, and the feed is capped anyway.
    pub fn rebuild<'a>(
        events: impl Iterator<Item = &'a ConnEvent>,
        group_by: GroupBy,
    ) -> Aggregate {
        let mut agg = Aggregate::default();
        for ev in events {
            agg.add(ev, group_by);
        }
        agg
    }

    /// Fold one event in.
    pub fn add(&mut self, ev: &ConnEvent, group_by: GroupBy) {
        let key = sanitize_for_display(&raw_key(ev, group_by)).into_owned();
        self.total += 1;
        // Cap on insert only, so a flood of fresh keys cannot stop the rows
        // the operator is watching from updating.
        if !self.rows.contains_key(&key) && self.rows.len() >= MAX_ROWS {
            self.overflow += 1;
            return;
        }
        let row = self.rows.entry(key.clone()).or_insert_with(|| Row {
            key,
            ..Row::default()
        });
        row.total += 1;
        match (ev.verdict, ev.enforced) {
            (Verdict::Allow, _) => row.allowed += 1,
            (_, true) => row.blocked += 1,
            // An unenforced deny is never counted as blocked: the connection
            // went out, and showing it as stopped would be a lie.
            (_, false) => row.would_block += 1,
        }
        row.last_ms = row.last_ms.max(ev.unix_ms);
        if row.peer_set.len() < MAX_PEERS_PER_ROW {
            row.peer_set.insert(ev.conn.tuple.dst.ip().to_string());
        }
        row.peers = row.peer_set.len();
    }

    /// Rows ordered by `sort`, capped at `limit`.
    ///
    /// Ties always break by key ascending, whichever column is sorted and
    /// whichever way: this table is rebuilt from scratch every frame, and
    /// rows that swap places between redraws are unreadable on a live
    /// feed where most counts are equal.
    pub fn top(&self, limit: usize, sort: SortBy, descending: bool) -> Vec<Row> {
        let mut rows: Vec<Row> = self.rows.values().cloned().collect();
        rows.sort_by(|a, b| {
            let ordered = match sort {
                SortBy::Total => a.total.cmp(&b.total),
                SortBy::Allowed => a.allowed.cmp(&b.allowed),
                SortBy::Blocked => a.blocked.cmp(&b.blocked),
                SortBy::WouldBlock => a.would_block.cmp(&b.would_block),
                SortBy::Peers => a.peers.cmp(&b.peers),
                SortBy::LastSeen => a.last_ms.cmp(&b.last_ms),
                SortBy::Key => a.key.cmp(&b.key),
            };
            let ordered = if descending {
                ordered.reverse()
            } else {
                ordered
            };
            ordered.then_with(|| a.key.cmp(&b.key))
        });
        rows.truncate(limit);
        rows
    }

    /// Number of distinct rows tracked.
    pub fn len(&self) -> usize {
        self.rows.len()
    }
}

/// What happened in one slice of time, for the activity strip.
///
/// Split the same three ways the traffic rows are, and for the same
/// reason: "blocked" and "would have been blocked" are different facts
/// about the host, and a strip that merged them would draw an observing
/// machine exactly like an enforcing one.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Bucket {
    pub allowed: u64,
    pub blocked: u64,
    pub would_block: u64,
}

impl Bucket {
    pub fn total(self) -> u64 {
        self.allowed + self.blocked + self.would_block
    }
}

/// Fold events into `columns` equal slices spanning the feed's own time
/// range, oldest first.
///
/// The range comes from the events rather than from the clock: the feed is
/// capped, so on a busy host it covers the last few seconds and on a quiet
/// one the last few hours, and a strip pinned to a fixed window would be
/// empty in the second case and one solid column in the first.
pub fn buckets<'a>(events: impl Iterator<Item = &'a ConnEvent>, columns: usize) -> Vec<Bucket> {
    let stamped: Vec<(u64, Verdict, bool)> = events
        .map(|ev| (ev.unix_ms, ev.verdict, ev.enforced))
        .collect();
    if stamped.is_empty() || columns == 0 {
        return Vec::new();
    }
    let first = stamped.iter().map(|(ms, ..)| *ms).min().unwrap_or(0);
    let last = stamped.iter().map(|(ms, ..)| *ms).max().unwrap_or(0);
    let span = last.saturating_sub(first).max(1);
    let mut out = vec![Bucket::default(); columns];
    for (ms, verdict, enforced) in stamped {
        // The newest event lands in the last column rather than one past
        // it, which is what the saturating index below is for.
        let i = ((ms - first) as u128 * columns as u128 / span as u128) as usize;
        let slot = &mut out[i.min(columns - 1)];
        match (verdict, enforced) {
            (Verdict::Allow, _) => slot.allowed += 1,
            (_, true) => slot.blocked += 1,
            (_, false) => slot.would_block += 1,
        }
    }
    out
}

/// The grouping key, before sanitizing.
fn raw_key(ev: &ConnEvent, group_by: GroupBy) -> String {
    let c = &ev.conn;
    match group_by {
        // Keyed on the application when the connection names one, because
        // the column says Application and a packaged application's
        // executable path does not name it: two of them can run from one
        // path inside their sandboxes and would otherwise sum into one row.
        // The path stays alongside, since that is what a rule keys on.
        GroupBy::Exe => match (&c.exe_path, &c.app_id) {
            (Some(exe), Some(app)) => format!("{app} ({})", exe.display()),
            (Some(exe), None) => exe.display().to_string(),
            (None, Some(app)) => app.clone(),
            (None, None) => "unknown".to_string(),
        },
        // Falling back to the address keeps unresolved traffic visible.
        // Dropping it would hide exactly the connections that went around
        // the system resolver, which are the ones worth looking at.
        GroupBy::Domain => c
            .domain
            .clone()
            .unwrap_or_else(|| c.tuple.dst.ip().to_string()),
        GroupBy::Rule => ev.rule_name.clone().unwrap_or_else(|| "-".to_string()),
    }
}

/// Whether `ev` matches a free-text filter, checked against the executable
/// path, the domain and the rule name.
///
/// Matched against the raw metadata rather than its sanitized form: the
/// operator typed the substring they expect to find, and sanitizing first
/// would make a hostile name unmatchable by the very filter written to hunt
/// for it. Only the display path sanitizes.
pub fn matches_filter(ev: &ConnEvent, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let needle = needle.to_lowercase();
    let hay = |s: &str| s.to_lowercase().contains(&needle);
    ev.conn
        .exe_path
        .as_ref()
        .is_some_and(|p| hay(&p.display().to_string()))
        || ev.conn.domain.as_deref().is_some_and(hay)
        || ev.rule_name.as_deref().is_some_and(hay)
        || hay(&ev.conn.tuple.dst.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(exe: &str, dst: &str, verdict: Verdict, enforced: bool) -> ConnEvent {
        ConnEvent {
            conn: crate::testutil::conn(Some(exe), dst),
            verdict,
            rule_name: None,
            unix_ms: 1_720_000_000_000,
            enforced,
        }
    }

    #[test]
    fn counts_by_class_and_peer() {
        let events = [
            ev("/usr/bin/curl", "1.1.1.1:443", Verdict::Allow, true),
            ev("/usr/bin/curl", "1.1.1.2:443", Verdict::Deny, true),
            ev("/usr/bin/curl", "1.1.1.3:443", Verdict::Deny, false),
            ev("/usr/bin/wget", "1.1.1.1:80", Verdict::Allow, true),
        ];
        let agg = Aggregate::rebuild(events.iter(), GroupBy::Exe);
        let rows = agg.top(10, SortBy::Total, true);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].key, "/usr/bin/curl");
        assert_eq!((rows[0].total, rows[0].allowed), (3, 1));
        assert_eq!(rows[0].blocked, 1);
        assert_eq!(rows[0].would_block, 1);
        assert_eq!(rows[0].peers, 3);
    }

    #[test]
    fn grouping_keys() {
        let mut e = ev("/usr/bin/curl", "1.1.1.1:443", Verdict::Allow, true);
        assert_eq!(raw_key(&e, GroupBy::Exe), "/usr/bin/curl");
        assert_eq!(raw_key(&e, GroupBy::Rule), "-");
        // Unresolved traffic groups under its address rather than vanishing.
        assert_eq!(raw_key(&e, GroupBy::Domain), "1.1.1.1");
        e.conn.domain = Some("example.org".into());
        assert_eq!(raw_key(&e, GroupBy::Domain), "example.org");
    }

    /// Keys come from traffic, so a process cycling destinations must not be
    /// able to grow this without bound.
    #[test]
    fn rows_are_capped_and_overflow_counted() {
        let mut agg = Aggregate::default();
        for i in 0..(MAX_ROWS + 30) {
            agg.add(
                &ev(&format!("/bin/p{i}"), "1.1.1.1:443", Verdict::Allow, true),
                GroupBy::Exe,
            );
        }
        assert_eq!(agg.len(), MAX_ROWS);
        assert_eq!(agg.overflow, 30);
        // Totals still count everything, so the header does not under-report.
        assert_eq!(agg.total as usize, MAX_ROWS + 30);
    }

    /// The executable path is chosen by the process being reported on, and
    /// the row label is what the operator reads before writing a rule.
    #[test]
    fn hostile_keys_are_sanitized() {
        let mut agg = Aggregate::default();
        agg.add(
            &ev(
                "/tmp/evil\r\x1b[2K/usr/bin/firefox",
                "1.1.1.1:443",
                Verdict::Allow,
                true,
            ),
            GroupBy::Exe,
        );
        let rows = agg.top(1, SortBy::Total, true);
        assert!(!rows[0].key.contains('\x1b'), "{:?}", rows[0].key);
        assert!(!rows[0].key.contains('\r'), "{:?}", rows[0].key);
    }

    #[test]
    fn filter_matches_across_fields() {
        let mut e = ev("/usr/bin/curl", "93.184.216.34:443", Verdict::Allow, true);
        e.conn.domain = Some("example.org".into());
        e.rule_name = Some("allow-web".into());
        assert!(matches_filter(&e, ""), "empty filter keeps everything");
        assert!(matches_filter(&e, "curl"));
        assert!(
            matches_filter(&e, "EXAMPLE"),
            "filtering is case-insensitive"
        );
        assert!(matches_filter(&e, "allow-web"));
        assert!(matches_filter(&e, "93.184"));
        assert!(!matches_filter(&e, "firefox"));
    }

    /// Every column sorts, and a tie never reshuffles: the table is
    /// rebuilt from the feed every frame, so equal rows swapping places
    /// would make a live screen unreadable.
    #[test]
    fn rows_sort_by_any_column_and_break_ties_stably() {
        let mut agg = Aggregate::default();
        for (exe, verdict, enforced) in [
            ("/bin/b", Verdict::Deny, true),
            ("/bin/a", Verdict::Allow, true),
            ("/bin/c", Verdict::Deny, false),
        ] {
            agg.add(&ev(exe, "1.1.1.1:443", verdict, enforced), GroupBy::Exe);
        }
        let keys = |sort, desc| -> Vec<String> {
            agg.top(10, sort, desc).into_iter().map(|r| r.key).collect()
        };
        // One connection each: every count column is a three-way tie, and
        // the tiebreak has to be the key, both directions.
        assert_eq!(keys(SortBy::Total, true), ["/bin/a", "/bin/b", "/bin/c"]);
        assert_eq!(keys(SortBy::Total, false), ["/bin/a", "/bin/b", "/bin/c"]);
        assert_eq!(keys(SortBy::Blocked, true)[0], "/bin/b", "the applied deny");
        assert_eq!(
            keys(SortBy::WouldBlock, true)[0],
            "/bin/c",
            "the recorded but unapplied deny"
        );
        assert_eq!(keys(SortBy::Allowed, true)[0], "/bin/a");
        assert_eq!(keys(SortBy::Key, false), ["/bin/a", "/bin/b", "/bin/c"]);
        assert_eq!(keys(SortBy::Key, true), ["/bin/c", "/bin/b", "/bin/a"]);
    }

    /// The strip spans the feed's own range, oldest column first, and the
    /// newest event lands in the last column rather than one past the end.
    /// Off by one here is a panic on an index, not a cosmetic error.
    #[test]
    fn buckets_span_the_feed_and_keep_the_newest_in_range() {
        let at = |ms: u64, verdict: Verdict, enforced: bool| {
            let mut e = ev("/usr/bin/curl", "1.1.1.1:443", verdict, enforced);
            e.unix_ms = ms;
            e
        };
        let events = [
            at(1_000, Verdict::Allow, true),
            at(5_000, Verdict::Deny, true),
            at(9_000, Verdict::Deny, false),
            // Exactly on the range's end: the divisor is the span itself,
            // so this is the index that would overflow unclamped.
            at(9_000, Verdict::Allow, true),
        ];
        let out = buckets(events.iter(), 4);
        assert_eq!(out.len(), 4);
        assert_eq!(out[0].allowed, 1, "the oldest event opens the strip");
        assert_eq!(out[3].blocked + out[3].would_block + out[3].allowed, 2);
        assert_eq!(out.iter().map(|b| b.total()).sum::<u64>(), 4);
        // Each class stays its own: an unenforced deny is not a block.
        assert_eq!(out.iter().map(|b| b.would_block).sum::<u64>(), 1);
        assert_eq!(out.iter().map(|b| b.blocked).sum::<u64>(), 1);
    }

    /// A feed with nothing in it, and one whose events all share a
    /// millisecond: both are ordinary states, not division by zero.
    #[test]
    fn buckets_handle_an_empty_and_an_instant_feed() {
        assert!(buckets(std::iter::empty(), 8).is_empty());
        assert!(buckets(
            [ev("/bin/x", "1.1.1.1:443", Verdict::Allow, true)].iter(),
            0
        )
        .is_empty());
        let same = [
            ev("/bin/x", "1.1.1.1:443", Verdict::Allow, true),
            ev("/bin/x", "1.1.1.2:443", Verdict::Allow, true),
        ];
        let out = buckets(same.iter(), 5);
        assert_eq!(out.len(), 5);
        assert_eq!(out.iter().map(|b| b.total()).sum::<u64>(), 2);
    }
}

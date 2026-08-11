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
    pub fn rebuild<'a>(events: impl Iterator<Item = &'a ConnEvent>, group_by: GroupBy) -> Aggregate {
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

    /// Rows sorted by count, busiest first, capped at `limit`.
    pub fn top(&self, limit: usize) -> Vec<Row> {
        let mut rows: Vec<Row> = self.rows.values().cloned().collect();
        // Ties break by key so equal rows do not shuffle between redraws.
        rows.sort_by(|a, b| b.total.cmp(&a.total).then_with(|| a.key.cmp(&b.key)));
        rows.truncate(limit);
        rows
    }

    /// Number of distinct rows tracked.
    pub fn len(&self) -> usize {
        self.rows.len()
    }
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
    use hallpass_types::{Connection, FlowTuple, Proto};
    use std::path::PathBuf;

    fn ev(exe: &str, dst: &str, verdict: Verdict, enforced: bool) -> ConnEvent {
        ConnEvent {
            conn: Connection {
                tuple: FlowTuple {
                    proto: Proto::Tcp,
                    src: "10.0.0.1:40000".parse().unwrap(),
                    dst: dst.parse().unwrap(),
                },
                uid: Some(1000),
                pid: Some(1),
                exe_path: Some(PathBuf::from(exe)),
                cmdline: None,
                parent_exe: None,
                domain: None,
                iface: None,
                app_id: None,
                first_seen: None,
            },
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
        let rows = agg.top(10);
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
            agg.add(&ev(&format!("/bin/p{i}"), "1.1.1.1:443", Verdict::Allow, true), GroupBy::Exe);
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
            &ev("/tmp/evil\r\x1b[2K/usr/bin/firefox", "1.1.1.1:443", Verdict::Allow, true),
            GroupBy::Exe,
        );
        let rows = agg.top(1);
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
        assert!(matches_filter(&e, "EXAMPLE"), "filtering is case-insensitive");
        assert!(matches_filter(&e, "allow-web"));
        assert!(matches_filter(&e, "93.184"));
        assert!(!matches_filter(&e, "firefox"));
    }
}

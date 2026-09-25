//! `hallpass-cli top`: a live aggregate of what this machine is talking to.
//!
//! Everything here is folded client-side from the event stream, seeded with
//! the daemon's short history so a monitor opened after the traffic does not
//! look at an idle machine. The daemon keeps no aggregate of its own: the
//! interesting groupings differ per question, and doing it here keeps the
//! verdict path out of it entirely.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::Path;

use hallpass_types::{sanitize_for_display, ClientMsg, ConnEvent, DaemonMsg, Verdict};
use serde::Serialize;

use crate::args::{GroupBy, TopOpts};
use crate::client::{spawn_reader, CliError, Client};
use crate::fmt::{self, Cell, Output, Palette, Style};

/// Events requested from the daemon's history to seed the view.
const SEED_EVENTS: u32 = 1000;

/// Most distinct rows tracked at once.
///
/// Every key comes from traffic, and a process picking a fresh destination
/// per connection would otherwise grow this without bound. Past the cap new
/// keys are counted in `overflow` and named in a footer line rather than
/// silently dropped: a monitor that quietly stops counting is worse than one
/// that says it stopped.
const MAX_ROWS: usize = 4096;

/// Most distinct peers remembered per row, for the "peers" column.
const MAX_PEERS_PER_ROW: usize = 256;

/// One aggregated row.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Row {
    /// The grouping key, already sanitized for display.
    pub key: String,
    /// Connections counted.
    pub total: u64,
    /// Connections allowed.
    pub allowed: u64,
    /// Deny or reject that was actually applied.
    pub blocked: u64,
    /// Deny or reject that observe mode recorded without applying.
    pub would_block: u64,
    /// Distinct destinations seen, capped internally so a process cycling
    /// destinations cannot grow one row without bound.
    pub peers: usize,
    /// Most recent event for this row, as Unix milliseconds.
    pub last_ms: u64,
    #[serde(skip)]
    peer_set: HashSet<String>,
}

/// The whole view: rows plus the totals a header line needs.
#[derive(Debug, Default)]
pub struct Aggregate {
    rows: HashMap<String, Row>,
    /// Events whose key did not fit under [`MAX_ROWS`].
    overflow: u64,
    total: u64,
    allowed: u64,
    blocked: u64,
    would_block: u64,
    /// True once any event arrived unenforced, which means the daemon is
    /// evaluating policy without applying it.
    observing: bool,
}

impl Aggregate {
    /// Fold one event in.
    pub fn add(&mut self, ev: &ConnEvent, group_by: GroupBy) {
        let key = sanitize_for_display(&raw_key(ev, group_by)).into_owned();
        let class = classify(ev);
        self.total += 1;
        self.observing |= !ev.enforced;
        match class {
            Class::Allowed => self.allowed += 1,
            Class::Blocked => self.blocked += 1,
            Class::WouldBlock => self.would_block += 1,
        }
        // Cap on insert only: an existing row keeps counting whatever the
        // map size is, so a flood of fresh keys cannot stop the rows the
        // operator is actually watching from updating.
        if !self.rows.contains_key(&key) && self.rows.len() >= MAX_ROWS {
            self.overflow += 1;
            return;
        }
        let row = self.rows.entry(key.clone()).or_insert_with(|| Row {
            key,
            ..Row::default()
        });
        row.total += 1;
        match class {
            Class::Allowed => row.allowed += 1,
            Class::Blocked => row.blocked += 1,
            Class::WouldBlock => row.would_block += 1,
        }
        row.last_ms = row.last_ms.max(ev.unix_ms);
        if row.peer_set.len() < MAX_PEERS_PER_ROW {
            row.peer_set.insert(ev.conn.tuple.dst.ip().to_string());
        }
        row.peers = row.peer_set.len();
    }

    /// Rows sorted by count, most active first, capped at `limit`.
    pub fn top(&self, limit: usize) -> Vec<Row> {
        let mut rows: Vec<Row> = self.rows.values().cloned().collect();
        // Count descending, then key ascending so equal rows do not shuffle
        // between redraws and become unreadable.
        rows.sort_by(|a, b| b.total.cmp(&a.total).then_with(|| a.key.cmp(&b.key)));
        rows.truncate(limit);
        rows
    }
}

/// How one event counts against the blocked columns.
#[derive(Clone, Copy)]
enum Class {
    Allowed,
    Blocked,
    WouldBlock,
}

fn classify(ev: &ConnEvent) -> Class {
    match (ev.verdict, ev.enforced) {
        (Verdict::Allow, _) => Class::Allowed,
        (_, true) => Class::Blocked,
        (_, false) => Class::WouldBlock,
    }
}

/// The grouping key, before sanitizing.
fn raw_key(ev: &ConnEvent, group_by: GroupBy) -> String {
    let c = &ev.conn;
    match group_by {
        // Keyed on the application when the connection names one: two
        // packaged applications can run from one path inside their
        // sandboxes, and summing their rows together would report as one
        // program what policy treats as two. The path stays alongside,
        // since that is what a rule keys on.
        GroupBy::Exe => match (&c.exe_path, &c.app_id) {
            (Some(exe), Some(app)) => format!("{app} ({})", exe.display()),
            (Some(exe), None) => exe.display().to_string(),
            (None, Some(app)) => app.clone(),
            (None, None) => "?".to_string(),
        },
        // Falling back to the address keeps unresolved traffic visible.
        // Dropping it would hide exactly the connections that bypassed the
        // system resolver, which are the ones worth looking at.
        GroupBy::Domain => c
            .domain
            .clone()
            .unwrap_or_else(|| c.tuple.dst.ip().to_string()),
        GroupBy::Host => c.tuple.dst.ip().to_string(),
        GroupBy::Port => format!("{}/{}", c.tuple.dst.port(), c.tuple.proto),
        GroupBy::Rule => ev.rule_name.clone().unwrap_or_else(|| "-".to_string()),
    }
}

/// Render the view as a plain text block (no cursor movement).
pub fn render(agg: &Aggregate, opts: TopOpts, pal: Palette) -> String {
    let mut out = String::new();
    if agg.observing {
        let banner = "OBSERVE MODE: policy is evaluated but nothing is blocked";
        let _ = writeln!(out, "{}", pal.paint(Style::Warn, banner));
    }
    let _ = writeln!(
        out,
        "{} connections  {} allowed  {} blocked  {} would-block  (by {}, top {})",
        agg.total,
        agg.allowed,
        agg.blocked,
        agg.would_block,
        opts.group_by.as_str(),
        opts.top_n
    );

    let group = opts.group_by.as_str().to_uppercase();
    let header = [
        group.as_str(),
        "COUNT",
        "ALLOW",
        "BLOCK",
        "WOULD",
        "PEERS",
        "LAST",
    ];
    let rows: Vec<Vec<Cell>> = agg
        .top(opts.top_n)
        .into_iter()
        .map(|r| {
            let style = if r.would_block > 0 {
                Style::Would
            } else if r.blocked > 0 {
                Style::Deny
            } else {
                Style::Allow
            };
            vec![
                // Bounded like every path the CLI prints: the column is as
                // wide as its longest cell, so one process run from a deep
                // directory otherwise wrapped every row of the table.
                Cell::painted(fmt::path_display(Path::new(&r.key)), Some(style)),
                Cell::plain(r.total.to_string()),
                Cell::plain(r.allowed.to_string()),
                Cell::plain(r.blocked.to_string()),
                Cell::plain(r.would_block.to_string()),
                Cell::plain(r.peers.to_string()),
                Cell::plain(hallpass_types::format_ts(r.last_ms)),
            ]
        })
        .collect();
    out.push_str(&fmt::render_table(pal, &header, &rows));
    if agg.overflow > 0 {
        let _ = writeln!(
            out,
            "({} events not counted: more than {MAX_ROWS} distinct keys)",
            agg.overflow
        );
    }
    out
}

/// Run the live view until Ctrl-C.
pub async fn top(mut client: Client, opts: TopOpts, out: Output) -> Result<(), CliError> {
    let mut agg = Aggregate::default();

    // Seed from history. An older daemon answers Err; that costs the
    // backfill, not the command, so carry on with the live stream only.
    match client
        .request(ClientMsg::EventHistory { limit: SEED_EVENTS })
        .await
    {
        Ok(DaemonMsg::Events(events)) => {
            for ev in &events {
                agg.add(ev, opts.group_by);
            }
        }
        Ok(other) => return Err(CliError::unexpected(&other)),
        Err(CliError::Daemon(msg)) => {
            eprintln!("note: no event history from the daemon ({msg}); starting empty");
        }
        Err(e) => return Err(e),
    }

    client
        .send(ClientMsg::Subscribe {
            events: true,
            prompts: false,
        })
        .await?;

    // Reads on their own task: `read_msg` is not cancel-safe, and the ticker
    // below wins the select every interval, so a frame arriving across a
    // tick lost its first half and the stream came apart from there.
    let mut rx = spawn_reader(client.into_stream());

    let mut ticker =
        tokio::time::interval(std::time::Duration::from_secs(opts.interval_secs.max(1)));
    // The first tick fires immediately, which is what shows the seeded view
    // without waiting out an interval.
    loop {
        tokio::select! {
            msg = rx.recv() => match msg.ok_or_else(|| {
                CliError::Connect("daemon closed the connection".into())
            })?? {
                DaemonMsg::Event(ev) => agg.add(&ev, opts.group_by),
                DaemonMsg::Err { message } => return Err(CliError::Daemon(message)),
                _ => {}
            },
            _ = ticker.tick() => draw(&agg, opts, out)?,
            _ = tokio::signal::ctrl_c() => {
                if out.tty {
                    // Leave the terminal with the final view intact rather
                    // than half-erased.
                    println!();
                }
                return Ok(());
            }
        }
    }
}

fn draw(agg: &Aggregate, opts: TopOpts, out: Output) -> Result<(), CliError> {
    let mut stdout = std::io::stdout().lock();
    if out.json {
        let rows = agg.top(opts.top_n);
        let _ = writeln!(stdout, "{}", crate::json::to_json(&rows)?);
    } else if out.tty {
        // Cursor home plus erase-down: redrawing in place rather than
        // scrolling.
        let _ = write!(stdout, "\x1b[H\x1b[J{}", render(agg, opts, out.palette));
    } else {
        let _ = writeln!(stdout, "{}", render(agg, opts, out.palette));
    }
    let _ = stdout.flush();
    Ok(())
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
    fn groups_and_counts_by_class() {
        let mut agg = Aggregate::default();
        agg.add(
            &ev("/usr/bin/curl", "1.1.1.1:443", Verdict::Allow, true),
            GroupBy::Exe,
        );
        agg.add(
            &ev("/usr/bin/curl", "1.1.1.2:443", Verdict::Deny, true),
            GroupBy::Exe,
        );
        agg.add(
            &ev("/usr/bin/curl", "1.1.1.3:443", Verdict::Deny, false),
            GroupBy::Exe,
        );
        agg.add(
            &ev("/usr/bin/wget", "1.1.1.1:80", Verdict::Allow, true),
            GroupBy::Exe,
        );

        let rows = agg.top(10);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].key, "/usr/bin/curl");
        assert_eq!(rows[0].total, 3);
        assert_eq!(rows[0].allowed, 1);
        assert_eq!(rows[0].blocked, 1);
        // An unenforced deny is never counted as blocked: the connection
        // went out, and reporting it as stopped would be a lie.
        assert_eq!(rows[0].would_block, 1);
        assert_eq!(rows[0].peers, 3);
        assert!(agg.observing);
    }

    #[test]
    fn grouping_keys() {
        let mut e = ev("/usr/bin/curl", "1.1.1.1:443", Verdict::Allow, true);
        assert_eq!(raw_key(&e, GroupBy::Exe), "/usr/bin/curl");
        assert_eq!(raw_key(&e, GroupBy::Host), "1.1.1.1");
        assert_eq!(raw_key(&e, GroupBy::Port), "443/tcp");
        assert_eq!(raw_key(&e, GroupBy::Rule), "-");
        // Unresolved traffic groups under its address rather than vanishing.
        assert_eq!(raw_key(&e, GroupBy::Domain), "1.1.1.1");
        e.conn.domain = Some("example.org".into());
        assert_eq!(raw_key(&e, GroupBy::Domain), "example.org");
    }

    /// Keys come from traffic, so a process cycling destinations must not be
    /// able to grow this view without bound.
    #[test]
    fn row_count_is_capped_and_overflow_is_reported() {
        let mut agg = Aggregate::default();
        for i in 0..(MAX_ROWS + 25) {
            agg.add(
                &ev(&format!("/bin/p{i}"), "1.1.1.1:443", Verdict::Allow, true),
                GroupBy::Exe,
            );
        }
        assert_eq!(agg.rows.len(), MAX_ROWS);
        assert_eq!(agg.overflow, 25);
        // Every event is still counted in the totals, so the header does not
        // under-report what the machine did.
        assert_eq!(agg.total as usize, MAX_ROWS + 25);
        let out = render(&agg, TopOpts::default(), Palette::new(false));
        assert!(out.contains("not counted"), "{out}");
    }

    /// The executable path is chosen by the process being reported on. It
    /// must not be able to erase or rewrite the rows around it.
    #[test]
    fn hostile_keys_cannot_rewrite_the_screen() {
        let mut agg = Aggregate::default();
        agg.add(
            &ev(
                "/tmp/evil\r\x1b[A\x1b[2K/usr/bin/firefox",
                "1.1.1.1:443",
                Verdict::Allow,
                true,
            ),
            GroupBy::Exe,
        );
        let out = render(&agg, TopOpts::default(), Palette::new(false));
        assert!(
            !out.contains('\x1b'),
            "escape reached the terminal: {out:?}"
        );
        assert!(!out.contains('\r'), "CR reached the terminal: {out:?}");
        // Totals line, header, one row: nothing smuggled in extra lines.
        assert_eq!(out.lines().count(), 3, "{out:?}");
    }

    #[test]
    fn observe_banner_only_when_unenforced() {
        let mut agg = Aggregate::default();
        agg.add(
            &ev("/usr/bin/curl", "1.1.1.1:443", Verdict::Deny, true),
            GroupBy::Exe,
        );
        let out = render(&agg, TopOpts::default(), Palette::new(false));
        assert!(!out.contains("OBSERVE MODE"), "{out}");
        agg.add(
            &ev("/usr/bin/curl", "1.1.1.1:443", Verdict::Deny, false),
            GroupBy::Exe,
        );
        let out = render(&agg, TopOpts::default(), Palette::new(false));
        assert!(out.contains("OBSERVE MODE"), "{out}");
    }
}

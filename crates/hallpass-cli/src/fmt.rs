//! Output formatting: tables, event lines, timestamps, and the color palette.

use std::collections::HashMap;
use std::fmt::Write;

use hallpass_types::{
    format_ts, human_bytes, sanitize_for_display, ConnEvent, Connection, Explanation, FirstSeen,
    Lockdown, PromptScope, Rule, RuleHit, RuleTrace, RunSessionInfo, RuntimeConfig, Stats,
    TraceOutcome, Verdict,
};

use crate::args::ColorChoice;

/// Widest verdict label (`WOULD-REJECT`), so event lines stay in columns
/// whether or not the daemon is enforcing.
pub const VERDICT_WIDTH: usize = 12;

/// What a piece of text means, rather than what color it is.
///
/// Every ANSI sequence in the CLI comes from [`Palette::paint`], so the
/// palette is the only place that has to be reviewed when the output has to
/// stay readable on a given terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// An allowed connection.
    Allow,
    /// A connection that was dropped.
    Deny,
    /// A connection that was actively rejected.
    Reject,
    /// A verdict that was recorded but not applied (observe mode).
    Would,
    /// A heading or summary line.
    Header,
    /// Something the operator needs to notice.
    Warn,
}

impl Style {
    /// SGR parameters for this style.
    fn code(self) -> &'static str {
        match self {
            Style::Allow => "32",
            Style::Deny => "31",
            Style::Reject => "35",
            Style::Would => "33",
            Style::Header => "1",
            Style::Warn => "1;33",
        }
    }
}

/// Whether output is colorized, and the only source of ANSI color escapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    enabled: bool,
}

impl Palette {
    /// Palette that colors, or does not.
    pub fn new(enabled: bool) -> Palette {
        Palette { enabled }
    }

    /// Whether this palette emits escapes.
    pub fn enabled(self) -> bool {
        self.enabled
    }

    /// `text` in `style`, or unchanged when color is off.
    ///
    /// The reset is unconditional (`0m` rather than a per-attribute reset) so
    /// no style can leak into the next line if the terminal drops a sequence.
    pub fn paint(self, style: Style, text: &str) -> String {
        if !self.enabled {
            return text.to_string();
        }
        format!("\x1b[{}m{text}\x1b[0m", style.code())
    }
}

/// `text` painted in `style` and padded to `width` characters.
///
/// The padding is computed from the unpainted text: escape bytes take no space
/// on screen, so counting them would eat into the column and misalign every
/// column after it.
pub fn cell(pal: Palette, style: Style, text: &str, width: usize) -> String {
    let pad = width.saturating_sub(text.chars().count());
    pal.paint(style, text) + &" ".repeat(pad)
}

/// How output is rendered, resolved once at startup and passed down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Output {
    /// Emit machine-readable JSON instead of human tables.
    pub json: bool,
    /// Whether stdout is a terminal, which decides in-place redraws.
    pub tty: bool,
    /// The color palette for human output.
    pub palette: Palette,
}

impl Output {
    /// Resolve the output mode. `tty` is whether stdout is a terminal, and
    /// `no_color` whether `NO_COLOR` is set to a non-empty value.
    ///
    /// JSON is never colorized: the escapes would land inside string values
    /// and every consumer that parses them would carry them along.
    pub fn resolve(json: bool, color: ColorChoice, tty: bool, no_color: bool) -> Output {
        let colorize = !json
            && match color {
                ColorChoice::Always => true,
                ColorChoice::Never => false,
                ColorChoice::Auto => tty && !no_color,
            };
        Output {
            json,
            tty,
            palette: Palette::new(colorize),
        }
    }
}

/// Human-readable prompt scope.
pub fn scope_str(s: PromptScope) -> &'static str {
    match s {
        PromptScope::ThisPort => "this port",
        PromptScope::ThisHost => "this host",
        PromptScope::AppAnywhere => "app anywhere",
    }
}

/// Warning printed by [`format_stats`] and the `top` header when the daemon
/// is evaluating policy without applying it.
pub const OBSERVE_WARNING: &str = "OBSERVE MODE: nothing is being blocked";

/// Format daemon stats as an aligned key/value table.
///
/// `mode` leads the table, and observe mode also gets a trailing warning: a
/// reader who skims a healthy-looking row of counters would otherwise walk
/// away believing traffic is being filtered when none of it is.
pub fn format_stats(s: &Stats, pal: Palette) -> String {
    let prompt_handler = if s.prompt_handler_connected {
        "connected".to_string()
    } else {
        // Painted like observe mode, and for the same reason: with nobody
        // holding the slot every unmatched connection takes the default
        // verdict unasked, and the counters look no different when that is
        // what is happening.
        pal.paint(Style::Warn, "none (unmatched connections take the default)")
    };
    let lockdown = match &s.lockdown {
        // Painted like observe mode and for the mirror-image reason: a table
        // of counters looks the same whether this host is denying almost
        // everything or filtering normally.
        Some(l) => pal.paint(Style::Warn, &lockdown_summary(l)),
        None => "off".to_string(),
    };
    let rows = [
        ("mode", mode_cell(s.enforcing, pal)),
        ("connections", s.connections_total.to_string()),
        ("allowed", s.allowed.to_string()),
        ("denied", s.denied.to_string()),
        ("observed only", s.observed_only.to_string()),
        ("prompted", s.prompted.to_string()),
        ("prompt handler", prompt_handler),
        ("prompts unanswered", s.prompts_unanswered.to_string()),
        ("handlers evicted", s.prompt_handlers_evicted.to_string()),
        ("lockdown", lockdown),
        ("rules loaded", s.rules_loaded.to_string()),
        ("rules skipped", s.rules_skipped.to_string()),
        ("dns spoofed", s.dns_spoof_rejected.to_string()),
        ("dns snoop dropped", s.dns_snoop_dropped.to_string()),
        ("prompt overflows", s.prompts_overflowed.to_string()),
        ("other protocols", s.other_proto_total.to_string()),
        // The kernel's own counters, from /proc: packets on a full verdict
        // queue never reach the daemon, so no counter above sees them. They
        // count drops only; a fail-open queue lets overflow through unjudged
        // and uncounted, which the fail-open rows are there to reveal.
        // Verdict-queue drops are painted when nonzero, since they mean
        // packets dropped without policy running; the snoop queue only costs
        // domain annotations, so its rows stay plain like `dns snoop dropped`.
        (
            "verdict queue depth",
            queue_depth(s.verdict_queue_depth, s.verdict_queue_max_len),
        ),
        (
            "verdict queue dropped",
            warn_if_positive(pal, s.verdict_queue_dropped),
        ),
        (
            "verdict queue undelivered",
            warn_if_positive(pal, s.verdict_queue_user_dropped),
        ),
        // Plain even when "no": false is the intended state under a
        // fail-closed posture, and this table cannot see the posture.
        (
            "verdict queue fail-open",
            kernel_flag(s.verdict_queue_fail_open),
        ),
        ("snoop queue depth", kernel_count(s.snoop_queue_depth)),
        ("snoop queue dropped", kernel_count(s.snoop_queue_dropped)),
        (
            "snoop queue undelivered",
            kernel_count(s.snoop_queue_user_dropped),
        ),
        (
            "snoop queue fail-open",
            kernel_flag(s.snoop_queue_fail_open),
        ),
        // Painted when nonzero: every detected flush is a window in which
        // this host was unfiltered. The watchdog repairs each one; whether
        // a repair failed is in the journal.
        (
            "nft table flushes",
            warn_if_positive(pal, Some(s.nft_flushes)),
        ),
        // "-" for never, like a rule that never hit.
        (
            "nft last flush",
            s.nft_last_flush_ms
                .map_or_else(|| "-".to_string(), format_ts),
        ),
        // Volume from conntrack teardown accounting: zero everywhere when
        // flow_accounting is off, like any counter the host is not producing.
        ("flows accounted", s.flows_accounted.to_string()),
        (
            "flow bytes",
            format!("{} ({})", s.flow_bytes, human_bytes(s.flow_bytes)),
        ),
        ("flow packets", s.flow_packets.to_string()),
        ("uptime", format_uptime(s.uptime_secs)),
    ];
    let mut out = kv_table(&rows);
    // Kernel drops on the verdict queue answer "was the firewall consulted
    // for everything" with no, which a skimmed row of counters can miss.
    // Saturating: a stats reply is still socket input, and a rendering path
    // must not be able to panic on it.
    let missed = s
        .verdict_queue_dropped
        .unwrap_or(0)
        .saturating_add(s.verdict_queue_user_dropped.unwrap_or(0));
    if missed > 0 {
        let warning = format!("{missed} packets were dropped by the kernel before policy saw them");
        let _ = writeln!(out, "{}", pal.paint(Style::Warn, &warning));
    }
    if !s.enforcing {
        let _ = writeln!(out, "{}", pal.paint(Style::Warn, OBSERVE_WARNING));
        let _ = writeln!(
            out,
            "policy is evaluated and recorded, but every packet is let through"
        );
    }
    out
}

/// Render `rows` as `key  value` lines, keys padded to the longest.
///
/// Keys are ASCII literals, so bytes and characters agree; the value column
/// is last and never padded, so a painted value cannot misalign it.
fn kv_table(rows: &[(&str, String)]) -> String {
    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (k, v) in rows {
        let _ = writeln!(out, "{k:width$}  {v}");
    }
    out
}

/// The `mode` row of the stats and settings tables: plain while enforcing,
/// painted as a warning in observe mode.
fn mode_cell(enforcing: bool, pal: Palette) -> String {
    if enforcing {
        "enforcing".to_string()
    } else {
        pal.paint(Style::Warn, "observe (not enforcing)")
    }
}

/// The tags a lockdown posture pins, comma-separated, or `nothing`.
pub fn pinned_tags(tags: &[String]) -> String {
    if tags.is_empty() {
        "nothing".to_string()
    } else {
        tags.join(",")
    }
}

/// One-line description of a posture in force, as `status` and `lockdown`
/// print it: `ON since TS (pinned TAGS, N rule(s) suppressed)`.
pub fn lockdown_summary(l: &Lockdown) -> String {
    format!(
        "ON since {} (pinned {}, {} rule(s) suppressed)",
        format_ts(l.since_ms),
        pinned_tags(&l.tags),
        l.rules_suppressed
    )
}

/// Render a kernel-reported counter: the number, or "unavailable" when
/// nothing was read. Never zero for a missing value - zero is the claim
/// that nothing was missed.
fn kernel_count(n: Option<u64>) -> String {
    match n {
        Some(n) => n.to_string(),
        None => "unavailable".to_string(),
    }
}

/// [`kernel_count`], painted as a warning when positive: these counters
/// mean packets were dropped without policy running.
fn warn_if_positive(pal: Palette, n: Option<u64>) -> String {
    match n {
        Some(v) if v > 0 => pal.paint(Style::Warn, &v.to_string()),
        _ => kernel_count(n),
    }
}

/// Render the verdict queue's depth against the length in force, because a
/// depth alone has no scale: 900 is idle on one queue and overflowing on
/// another. Falls back to the bare count when no queue is bound, or when the
/// kernel refused the length and its own default is in force unreported.
fn queue_depth(depth: Option<u64>, max_len: Option<u32>) -> String {
    match (depth, max_len) {
        (Some(depth), Some(max_len)) => format!("{depth} / {max_len}"),
        _ => kernel_count(depth),
    }
}

/// Render a queue's effective fail-open flag, known at bind rather than
/// read from /proc; "unavailable" when no queue is bound.
fn kernel_flag(n: Option<bool>) -> String {
    match n {
        Some(true) => "yes".to_string(),
        Some(false) => "no".to_string(),
        None => "unavailable".to_string(),
    }
}

/// Format the runtime settings as an aligned key/value table.
///
/// Mode leads for the same reason it leads the stats table, and the trailing
/// note repeats what the GUI settings tab says: a change lasts until the
/// daemon restarts, and config.toml is where to make it permanent.
pub fn format_config(c: &RuntimeConfig, pal: Palette) -> String {
    let mut out = kv_table(&[
        ("mode", mode_cell(c.enforce, pal)),
        ("prompt timeout", format!("{}s", c.prompt_timeout_secs)),
        ("default action", c.default_verdict.as_str().to_string()),
    ]);
    if !c.enforce {
        let _ = writeln!(out, "{}", pal.paint(Style::Warn, OBSERVE_WARNING));
    }
    let _ = writeln!(
        out,
        "runtime only: changes last until the daemon restarts; config.toml is unchanged"
    );
    out
}

/// Format seconds as "1d 2h 3m 4s" (leading zero units omitted).
pub fn format_uptime(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    let mut parts = Vec::new();
    if d > 0 {
        parts.push(format!("{d}d"));
    }
    if h > 0 || !parts.is_empty() {
        parts.push(format!("{h}h"));
    }
    if m > 0 || !parts.is_empty() {
        parts.push(format!("{m}m"));
    }
    parts.push(format!("{s}s"));
    parts.join(" ")
}

/// One table cell: its text, and the style painting it, if any.
pub(crate) struct Cell {
    text: String,
    style: Option<Style>,
}

impl Cell {
    /// An unpainted cell.
    pub(crate) fn plain(text: String) -> Self {
        Self { text, style: None }
    }

    /// A cell painted in `style`, or unpainted for `None`.
    pub(crate) fn painted(text: String, style: Option<Style>) -> Self {
        Self { text, style }
    }
}

/// Render `rows` under `header` as space-padded columns.
///
/// Widths are character counts, not bytes: a multibyte name would otherwise
/// over-pad and misalign every column after it. Painted cells are padded on
/// their unpainted text for the same reason, and the last column is never
/// padded so no row ends in trailing whitespace.
pub(crate) fn render_table(pal: Palette, header: &[&str], rows: &[Vec<Cell>]) -> String {
    let mut widths: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.text.chars().count());
        }
    }
    let mut out = String::new();
    push_row(&mut out, pal, &widths, header.iter().map(|h| (*h, None)));
    for row in rows {
        let cells = row.iter().map(|c| (c.text.as_str(), c.style));
        push_row(&mut out, pal, &widths, cells);
    }
    out
}

/// One line of [`render_table`].
fn push_row<'a>(
    out: &mut String,
    pal: Palette,
    widths: &[usize],
    cells: impl Iterator<Item = (&'a str, Option<Style>)>,
) {
    let last = widths.len().saturating_sub(1);
    for (i, (text, style)) in cells.enumerate() {
        match style {
            Some(style) if i == last => out.push_str(&pal.paint(style, text)),
            Some(style) => {
                out.push_str(&cell(pal, style, text, widths[i]));
                out.push_str("  ");
            }
            None if i == last => out.push_str(text),
            None => {
                let _ = write!(out, "{text:w$}  ", w = widths[i]);
            }
        }
    }
    out.push('\n');
}

/// Format the live session grants as a table.
///
/// The label is a command basename the wrapper read off a path, so it is
/// sanitized like every other daemon-carried string before it is printed.
pub fn format_sessions(sessions: &[RunSessionInfo], pal: Palette) -> String {
    let mut out = String::new();
    if sessions.is_empty() {
        let _ = writeln!(out, "no session grants are open");
        return out;
    }
    let _ = writeln!(
        out,
        "{:<6} {:<8} {:<8} {:<10} {:<8} COMMAND",
        "ID", "PID", "UID", "AGE", "ALLOWED"
    );
    for s in sessions {
        let _ = writeln!(
            out,
            "{:<6} {:<8} {:<8} {:<10} {:<8} {}",
            s.id,
            s.root_pid,
            s.uid,
            format_uptime(s.age_secs),
            s.allowed,
            sanitize_for_display(&s.label)
        );
    }
    let _ = writeln!(
        out,
        "{}",
        pal.paint(
            Style::Warn,
            "while a grant is open, unmatched connections from its process tree are \
             allowed without a prompt"
        )
    );
    out
}

/// Format the rule list as an aligned table with a header row.
///
/// `hits`, from [`ClientMsg::RuleStats`](hallpass_types::ClientMsg::RuleStats),
/// adds the `HITS` and `LAST HIT` columns. A rule the daemon reported no
/// counter for reads `0` and `-` rather than a blank: the question those
/// columns answer is "which rules never match", and a gap where the answer
/// should be fails to answer it.
///
/// `lockdown`, the tags a posture pins, marks the rules it is stopping as
/// suppressed rather than enabled. That column is what an operator reads to
/// answer "what is in force", and under a posture a plain `yes` on a rule
/// that decides nothing is the wrong answer.
pub fn format_rules(
    rules: &[Rule],
    hits: Option<&[RuleHit]>,
    lockdown: Option<&[String]>,
) -> String {
    if rules.is_empty() {
        return "no rules\n".to_string();
    }
    let by_name = hits_by_name(hits.unwrap_or(&[]));

    // Only once some rule carries one: a column of empty cells costs width
    // on a table that already has seven of them, and tags are opt-in.
    let tagged = rules.iter().any(|r| !r.tags.is_empty());
    // "ENABLED" would be a lie for a rule a posture is stopping, which is
    // enabled and deciding nothing; "DECIDING" is the question this column
    // is actually being read for.
    let enabled_header = match lockdown {
        Some(_) => "DECIDING",
        None => "ENABLED",
    };
    let mut header: Vec<&str> = vec!["NAME", "ACTION", "DURATION", "PRIO", enabled_header];
    if tagged {
        header.push("TAGS");
    }
    if hits.is_some() {
        header.extend(["HITS", "LAST HIT"]);
    }
    header.push("MATCH");

    let rows: Vec<Vec<Cell>> = rules
        .iter()
        .map(|r| {
            let mut cells = vec![
                // Both of these carry attacker-influenced text: a generated
                // rule name embeds an executable stem, and the summary quotes
                // exe, domain and cmdline operands. This listing is what an
                // operator reads to audit policy, so a rule must not be able
                // to erase or rewrite the row it is displayed on.
                sanitize_for_display(&r.name).into_owned(),
                r.action.as_str().to_string(),
                r.duration.describe(),
                r.priority.to_string(),
                match (r.enabled, lockdown) {
                    (false, _) => "no".to_string(),
                    (true, Some(tags)) if !r.active_under_lockdown(tags) => "lockdown".to_string(),
                    (true, _) => "yes".to_string(),
                },
            ];
            if tagged {
                // Sanitized like the neighbouring cells: `valid_tag` should
                // make a hazardous tag impossible, but an audit listing is
                // exactly where relying on that would cost the most.
                cells.push(if r.tags.is_empty() {
                    "-".to_string()
                } else {
                    sanitize_for_display(&r.tags.join(",")).into_owned()
                });
            }
            if hits.is_some() {
                let hit = by_name.get(r.name.as_str());
                cells.push(hit.map_or(0, |h| h.hits).to_string());
                cells.push(
                    hit.and_then(|h| h.last_hit_ms)
                        .map_or_else(|| "-".to_string(), format_ts),
                );
            }
            cells.push(sanitize_for_display(&r.matcher.summary()).into_owned());
            cells.into_iter().map(Cell::plain).collect()
        })
        .collect();
    // No cell is painted, so the palette cannot reach the output.
    render_table(Palette::new(false), &header, &rows)
}

/// Hit counters keyed on the raw rule name, which is what the daemon
/// accounts against; the sanitized name is only ever the display copy.
pub(crate) fn hits_by_name(hits: &[RuleHit]) -> HashMap<&str, &RuleHit> {
    hits.iter().map(|h| (h.name.as_str(), h)).collect()
}

/// Longest path this prints before eliding the middle of it.
///
/// A path is bounded by PATH_MAX (4096) and a prompt can carry several, so
/// unbounded they wrap an 80-column terminal into hundreds of rows and push
/// the destination and the countdown off the top of it - an unanswerable
/// prompt anyone who can exec from a deep directory can construct. 200 is
/// the same bound the GUI prompt window applies to a path.
const PATH_DISPLAY_MAX: usize = 200;

/// Display string for a path read off the host.
///
/// Sanitized and bounded: every path the CLI shows was chosen by whoever
/// exec'd or created it, an unprivileged user can put control characters or
/// several kilobytes in one, and the operator reads these lines to decide.
///
/// Elides the middle rather than the tail. The head of a path says where it
/// lives and the tail names the binary, and both matter here; a plain
/// truncation would leave every deeply nested path reading as the same
/// prefix.
pub fn path_display(p: &std::path::Path) -> String {
    let text = sanitize_for_display(&p.display().to_string()).into_owned();
    let len = text.chars().count();
    if len <= PATH_DISPLAY_MAX {
        return text;
    }
    // Char boundaries: a path is arbitrary bytes and the sanitizer leaves
    // multi-byte characters intact.
    let keep = PATH_DISPLAY_MAX - 3;
    let head: String = text.chars().take(keep - keep / 2).collect();
    let tail: String = text.chars().skip(len - keep / 2).collect();
    format!("{head}...{tail}")
}

/// Longest command line `watch` prints: short enough that the whole line,
/// label and cut marker included, fits an 80-column terminal without
/// wrapping. A wrapped line starts its continuation at column 0, which is
/// where a forged `prompt #N: /usr/bin/...` header would have to begin.
const CMDLINE_DISPLAY_MAX: usize = 56;

/// Display string for a command line: sanitized, runs of whitespace
/// collapsed, and cut at 56 characters (`CMDLINE_DISPLAY_MAX`) with the
/// count of what was cut.
///
/// A process writes its own argv, up to the daemon's 4 KiB cap, and in a
/// prompt this line sits between the executable and the question. At full
/// length it scrolled the executable line off the screen, and spaces laid
/// out to the terminal width drew a convincing prompt header for another
/// program in its place. Collapsing the whitespace takes the layout away;
/// the cap and the count keep the line short and say that it was cut.
pub fn cmdline_display(cmdline: &str) -> String {
    // Collapsed before sanitizing, so tabs and newlines become the single
    // space they separate rather than a replacement character each.
    let joined = cmdline.split_whitespace().collect::<Vec<_>>().join(" ");
    let collapsed = sanitize_for_display(&joined).into_owned();
    let len = collapsed.chars().count();
    if len <= CMDLINE_DISPLAY_MAX {
        return collapsed;
    }
    let head: String = collapsed.chars().take(CMDLINE_DISPLAY_MAX).collect();
    format!("{head}... (+{})", len - CMDLINE_DISPLAY_MAX)
}

/// Display string for a connection's executable path, or "?" if unknown.
pub fn exe_display(conn: &Connection) -> String {
    conn.exe_path
        .as_deref()
        .map_or_else(|| "?".to_string(), path_display)
}

/// Display string for a connection destination: `domain:port` when the
/// domain is known, otherwise `ip:port`.
///
/// The domain comes from snooped DNS, so it is attacker-chosen too.
pub fn dst_display(conn: &Connection) -> String {
    match &conn.domain {
        Some(domain) => format!("{}:{}", sanitize_for_display(domain), conn.tuple.dst.port()),
        None => conn.tuple.dst.to_string(),
    }
}

/// Color role for a verdict, given whether it would actually be applied.
///
/// An unapplied deny is [`Style::Would`] rather than [`Style::Deny`]: the
/// color is the first thing read, and red for a connection that went out
/// anyway says the opposite of what happened.
pub fn verdict_style(verdict: Verdict, enforced: bool) -> Style {
    match (enforced, verdict) {
        (_, Verdict::Allow) => Style::Allow,
        (true, Verdict::Deny) => Style::Deny,
        (true, Verdict::Reject) => Style::Reject,
        (false, _) => Style::Would,
    }
}

/// Format one connection event line:
/// `TIMESTAMP VERDICT exe -> dst rule=NAME`.
///
/// The verdict comes from [`ConnEvent::verdict_label`], so an unenforced deny
/// reads `WOULD-DENY`. Printing `DENY` for a connection that in fact went out
/// tells the reader the opposite of what happened.
pub fn format_event(ev: &ConnEvent, pal: Palette) -> String {
    let rule = ev.rule_name.as_deref().unwrap_or("-");
    let label = ev.verdict_label().to_uppercase();
    let mut line = format!(
        "{} {} {} -> {} rule={}",
        format_ts(ev.unix_ms),
        cell(
            pal,
            verdict_style(ev.verdict, ev.enforced),
            &label,
            VERDICT_WIDTH
        ),
        exe_display(&ev.conn),
        dst_display(&ev.conn),
        sanitize_for_display(rule)
    );
    // Appended, and only when there is something to say. Every column before
    // this one is fixed, so a filter or a script reading the existing fields
    // by position keeps working, and a line without it is a line where
    // nothing was new (or where the daemon is not tracking, which
    // `--json`'s null distinguishes and a text line cannot).
    if let Some(tag) = ev.conn.first_seen.and_then(FirstSeen::tag) {
        line.push(' ');
        line.push_str(&pal.paint(Style::Warn, &format!("new={tag}")));
    }
    line
}

/// Most trace rows [`format_explanation`] renders; the rest are summarized by
/// a trailing line.
///
/// The daemon sends one entry per loaded rule and bounds how many it loads, so
/// this should never trigger. It is here because "should never" is a property
/// of the process on the other end of the socket, not of this one.
pub const MAX_TRACE_ROWS: usize = 200;

/// Note printed by [`format_explanation`] when the daemon is not enforcing.
pub const EXPLAIN_OBSERVE_NOTE: &str = "OBSERVE MODE: this verdict would be recorded, not applied";

/// Whether `t` is the rule that decided the verdict.
fn decided(t: &RuleTrace) -> bool {
    matches!(t.outcome, TraceOutcome::Matched)
}

/// Human-readable outcome for one traced rule.
///
/// `NoMatch` names the first operand that failed, which is the one to edit.
/// That name is daemon-supplied like everything else here, so it is sanitized
/// on the way out.
fn outcome_str(outcome: &TraceOutcome) -> String {
    match outcome {
        TraceOutcome::Matched => "matched".to_string(),
        TraceOutcome::Disabled => "disabled".to_string(),
        // Not "disabled": the rule is exactly as the operator left it, and
        // what stopped it is a posture they can lift.
        TraceOutcome::Suppressed => "suppressed by lockdown".to_string(),
        TraceOutcome::NoMatch { field } => {
            format!("no match ({})", sanitize_for_display(field))
        }
        TraceOutcome::NotReached => "not reached".to_string(),
    }
}

/// Format an explanation: the verdict first, then every rule in evaluation
/// order with why it did or did not decide.
///
/// The verdict line has to survive being read on its own, so both caveats are
/// spelled out there rather than left to be inferred from the trace.
/// `would_prompt` means no rule matched at all, and the verdict is only what
/// applies if the prompt goes unanswered; `enforced == false` means it would
/// be recorded and not applied. Either one makes a bare "ALLOW" the answer to
/// a question the operator did not ask.
pub fn format_explanation(exp: &Explanation, pal: Palette) -> String {
    let style = verdict_style(exp.verdict, exp.enforced);
    let verdict = pal.paint(style, &exp.verdict.as_str().to_uppercase());
    let mut out = String::new();
    if exp.would_prompt {
        let prompt = pal.paint(Style::Warn, "PROMPT");
        let _ = writeln!(out, "verdict: {prompt}  (no rule matched)");
        let _ = writeln!(
            out,
            "this connection would raise a prompt; the default if nobody \
             answers it is {verdict}"
        );
    } else {
        // Present whenever a rule decided, but the wire type allows None, and
        // a missing name must not read as a rule literally called "-".
        let rule = exp.rule_name.as_deref().unwrap_or("(unnamed)");
        let _ = writeln!(
            out,
            "verdict: {verdict}  rule={}",
            sanitize_for_display(rule)
        );
    }
    if !exp.enforced {
        let _ = writeln!(out, "{}", pal.paint(Style::Warn, EXPLAIN_OBSERVE_NOTE));
    }
    out.push('\n');

    if exp.trace.is_empty() {
        out.push_str("no rules loaded\n");
        return out;
    }
    let cap = exp.trace.len().min(MAX_TRACE_ROWS);
    let mut shown: Vec<&RuleTrace> = exp.trace[..cap].iter().collect();
    let mut hidden = exp.trace.len() - cap;
    // The deciding rule is what the command was run to find, so it is never
    // the row that falls off the end of the cap.
    if let Some(t) = exp.trace[cap..].iter().find(|t| decided(t)) {
        shown.push(t);
        hidden -= 1;
    }
    let rows: Vec<Vec<Cell>> = shown
        .iter()
        .map(|t| {
            // Only the deciding rule is painted: the rest of the trace is
            // context, and coloring all of it would bury the one row that
            // answers the question.
            let style = decided(t).then_some(style);
            [
                // A rule name embeds an executable stem, so it is as
                // attacker-influenced here as in the rule listing.
                sanitize_for_display(&t.name).into_owned(),
                t.priority.to_string(),
                outcome_str(&t.outcome),
            ]
            .into_iter()
            .map(|text| Cell::painted(text, style))
            .collect()
        })
        .collect();
    out.push_str(&render_table(pal, &["RULE", "PRIO", "OUTCOME"], &rows));
    if hidden > 0 {
        let _ = writeln!(out, "... {hidden} more rules not shown");
    }
    out
}

#[cfg(test)]
mod tests;

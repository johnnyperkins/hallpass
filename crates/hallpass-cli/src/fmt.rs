//! Output formatting: tables, event lines, timestamps, and the color palette.

use std::collections::HashMap;
use std::fmt::Write;

use hallpass_types::{
    format_ts, sanitize_for_display, ConnEvent, Connection, Explanation, PromptScope, Rule,
    RuleHit, RuleTrace, RuntimeConfig, Stats, TraceOutcome, Verdict,
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
    let mut out = pal.paint(style, text);
    for _ in 0..width.saturating_sub(text.chars().count()) {
        out.push(' ');
    }
    out
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
    let rows = [
        (
            "mode",
            if s.enforcing {
                "enforcing".to_string()
            } else {
                pal.paint(Style::Warn, "observe (not enforcing)")
            },
        ),
        ("connections", s.connections_total.to_string()),
        ("allowed", s.allowed.to_string()),
        ("denied", s.denied.to_string()),
        ("observed only", s.observed_only.to_string()),
        ("prompted", s.prompted.to_string()),
        (
            "prompt handler",
            if s.prompt_handler_connected {
                "connected".to_string()
            } else {
                // Painted like observe mode, and for the same reason: with
                // nobody holding the slot every unmatched connection takes
                // the default verdict unasked, and the counters above look
                // no different when that is what is happening.
                pal.paint(Style::Warn, "none (unmatched connections take the default)")
            },
        ),
        ("prompts unanswered", s.prompts_unanswered.to_string()),
        ("handlers evicted", s.prompt_handlers_evicted.to_string()),
        ("rules loaded", s.rules_loaded.to_string()),
        ("rules skipped", s.rules_skipped.to_string()),
        ("dns spoofed", s.dns_spoof_rejected.to_string()),
        ("dns snoop dropped", s.dns_snoop_dropped.to_string()),
        ("prompt overflows", s.prompts_overflowed.to_string()),
        ("other protocols", s.other_proto_total.to_string()),
        // The kernel's own counters, from /proc: packets on a full verdict
        // queue never reach the daemon, so no counter above sees them. The
        // counters count drops only - a fail-open queue resolves overflow
        // by letting packets through unjudged and counted nowhere, which
        // is what the fail-open rows are for reading them. Drop rows are
        // painted when nonzero because they mean packets were dropped
        // without policy running; the snoop queue's cost is only domain
        // annotations, so its rows stay plain like `dns snoop dropped`.
        ("verdict queue depth", kernel_count(s.verdict_queue_depth)),
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
        ("snoop queue fail-open", kernel_flag(s.snoop_queue_fail_open)),
        // Painted when nonzero: every detected flush is a window in which
        // this host was unfiltered. The watchdog repairs each one; whether
        // a repair failed is in the journal.
        ("nft table flushes", warn_if_positive(pal, Some(s.nft_flushes))),
        // "-" for never, like a rule that never hit.
        (
            "nft last flush",
            s.nft_last_flush_ms
                .map_or_else(|| "-".to_string(), format_ts),
        ),
        ("uptime", format_uptime(s.uptime_secs)),
    ];
    // Keys are ASCII literals, so bytes and characters agree here; the value
    // column is last and never padded, so a painted value cannot misalign it.
    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (k, v) in rows {
        let _ = writeln!(out, "{k:width$}  {v}");
    }
    // Kernel drops on the verdict queue answer "was the firewall consulted
    // for everything" with no, which a skimmed row of counters can miss.
    // Saturating: the daemon is trusted, but a stats reply is still socket
    // input and a rendering path must not be able to panic on it.
    let missed = s
        .verdict_queue_dropped
        .unwrap_or(0)
        .saturating_add(s.verdict_queue_user_dropped.unwrap_or(0));
    if missed > 0 {
        let _ = writeln!(
            out,
            "{}",
            pal.paint(
                Style::Warn,
                &format!("{missed} packets were dropped by the kernel before policy saw them"),
            )
        );
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
    let rows = [
        (
            "mode",
            if c.enforce {
                "enforcing".to_string()
            } else {
                pal.paint(Style::Warn, "observe (not enforcing)")
            },
        ),
        ("prompt timeout", format!("{}s", c.prompt_timeout_secs)),
        ("default action", c.default_verdict.as_str().to_string()),
    ];
    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (k, v) in rows {
        let _ = writeln!(out, "{k:width$}  {v}");
    }
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

/// One table row: its cells, and an optional style painting the whole row.
struct TableRow {
    cells: Vec<String>,
    /// Style for every cell, or None to leave the row unpainted.
    style: Option<Style>,
}

/// Render `rows` under `header` as space-padded columns.
///
/// Widths are character counts, not bytes: a multibyte name would otherwise
/// over-pad and misalign every column after it. Painted cells are padded on
/// their unpainted text for the same reason, and the last column is never
/// padded so no row ends in trailing whitespace.
fn render_table(pal: Palette, header: &[&str], rows: &[TableRow]) -> String {
    let mut widths: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row.cells.iter()) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let last = widths.len().saturating_sub(1);
    let mut out = String::new();
    for (i, h) in header.iter().enumerate() {
        if i == last {
            out.push_str(h);
        } else {
            let _ = write!(out, "{h:w$}  ", w = widths[i]);
        }
    }
    out.push('\n');
    for row in rows {
        for (i, text) in row.cells.iter().enumerate() {
            match row.style {
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
    out
}

/// Format the rule list as an aligned table with a header row.
pub fn format_rules(rules: &[Rule]) -> String {
    format_rule_table(rules, None)
}

/// Format the rule list with the `HITS` and `LAST HIT` columns from
/// [`ClientMsg::RuleStats`](hallpass_types::ClientMsg::RuleStats).
///
/// A rule the daemon reported no counter for reads `0` and `-` rather than a
/// blank: the question this table answers is "which rules never match", and a
/// gap where the answer should be is the one rendering that fails to answer it.
pub fn format_rules_with_hits(rules: &[Rule], hits: &[RuleHit]) -> String {
    format_rule_table(rules, Some(hits))
}

fn format_rule_table(rules: &[Rule], hits: Option<&[RuleHit]>) -> String {
    if rules.is_empty() {
        return "no rules\n".to_string();
    }
    // Keyed on the raw name, which is what the daemon accounts against; the
    // sanitized form is only ever the display copy.
    let by_name: HashMap<&str, &RuleHit> = hits
        .unwrap_or(&[])
        .iter()
        .map(|h| (h.name.as_str(), h))
        .collect();

    let mut header: Vec<&str> = vec!["NAME", "ACTION", "DURATION", "PRIO", "ENABLED"];
    if hits.is_some() {
        header.extend(["HITS", "LAST HIT"]);
    }
    header.push("MATCH");

    let rows: Vec<TableRow> = rules
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
                if r.enabled { "yes" } else { "no" }.to_string(),
            ];
            if hits.is_some() {
                let hit = by_name.get(r.name.as_str());
                cells.push(hit.map_or(0, |h| h.hits).to_string());
                cells.push(
                    hit.and_then(|h| h.last_hit_ms)
                        .map_or_else(|| "-".to_string(), format_ts),
                );
            }
            cells.push(sanitize_for_display(&r.matcher.summary()).into_owned());
            TableRow { cells, style: None }
        })
        .collect();
    // No row is painted, so the palette cannot reach the output.
    render_table(Palette::new(false), &header, &rows)
}

/// Display string for a connection's executable path, or "?" if unknown.
///
/// Sanitized: the path is chosen by the process being judged, and this string
/// is what the operator reads before allowing or denying it.
pub fn exe_display(conn: &Connection) -> String {
    conn.exe_path
        .as_ref()
        .map(|p| sanitize_for_display(&p.display().to_string()).into_owned())
        .unwrap_or_else(|| "?".to_string())
}

/// Display string for a connection destination: `domain:port` when the
/// domain is known, otherwise `ip:port`.
///
/// The domain comes from snooped DNS, so it is attacker-chosen too.
pub fn dst_display(conn: &Connection) -> String {
    match &conn.domain {
        Some(domain) => format!(
            "{}:{}",
            sanitize_for_display(domain),
            conn.tuple.dst.port()
        ),
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
    format!(
        "{} {} {} -> {} rule={}",
        format_ts(ev.unix_ms),
        cell(pal, verdict_style(ev.verdict, ev.enforced), &label, VERDICT_WIDTH),
        exe_display(&ev.conn),
        dst_display(&ev.conn),
        sanitize_for_display(rule)
    )
}

/// Most trace rows [`format_explanation`] renders; the rest are summarized by
/// a trailing line.
///
/// The daemon sends one entry per loaded rule and bounds how many it loads, so
/// this should never trigger. It is here because "should never" is a property
/// of the process on the other end of the socket, not of this one.
pub const MAX_TRACE_ROWS: usize = 200;

/// Note printed by [`format_explanation`] when the daemon is not enforcing.
pub const EXPLAIN_OBSERVE_NOTE: &str =
    "OBSERVE MODE: this verdict would be recorded, not applied";

/// Human-readable outcome for one traced rule.
///
/// `NoMatch` names the first operand that failed, which is the one to edit.
/// That name is daemon-supplied like everything else here, so it is sanitized
/// on the way out.
fn outcome_str(outcome: &TraceOutcome) -> String {
    match outcome {
        TraceOutcome::Matched => "matched".to_string(),
        TraceOutcome::Disabled => "disabled".to_string(),
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
    if hidden > 0 {
        if let Some(t) = exp.trace[cap..]
            .iter()
            .find(|t| matches!(t.outcome, TraceOutcome::Matched))
        {
            shown.push(t);
            hidden -= 1;
        }
    }
    let rows: Vec<TableRow> = shown
        .iter()
        .map(|t| TableRow {
            cells: vec![
                // A rule name embeds an executable stem, so it is as
                // attacker-influenced here as in the rule listing.
                sanitize_for_display(&t.name).into_owned(),
                t.priority.to_string(),
                outcome_str(&t.outcome),
            ],
            // Only the deciding rule is painted: the rest of the trace is
            // context, and coloring all of it would bury the one row that
            // answers the question.
            style: matches!(t.outcome, TraceOutcome::Matched).then_some(style),
        })
        .collect();
    out.push_str(&render_table(pal, &["RULE", "PRIO", "OUTCOME"], &rows));
    if hidden > 0 {
        let _ = writeln!(out, "... {hidden} more rules not shown");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hallpass_types::{Action, FlowTuple, Proto, RuleDuration, RuleMatch};
    use std::net::SocketAddr;
    use std::path::PathBuf;

    fn conn(domain: Option<&str>) -> Connection {
        Connection {
            tuple: FlowTuple {
                proto: Proto::Tcp,
                src: "127.0.0.1:50000".parse::<SocketAddr>().unwrap(),
                dst: "93.184.216.34:443".parse::<SocketAddr>().unwrap(),
            },
            uid: Some(1000),
            pid: Some(4242),
            exe_path: Some(PathBuf::from("/usr/bin/curl")),
            cmdline: Some("curl https://example.org".into()),
            parent_exe: None,
            domain: domain.map(String::from),
            iface: None,
        }
    }

    #[test]
    fn ts_formatting() {
        assert_eq!(format_ts(0), "1970-01-01 00:00:00");
        // 2024-07-03 09:46:40 UTC.
        assert_eq!(format_ts(1_720_000_000_000), "2024-07-03 09:46:40");
    }

    #[test]
    fn uptime_formatting() {
        assert_eq!(format_uptime(0), "0s");
        assert_eq!(format_uptime(59), "59s");
        assert_eq!(format_uptime(3661), "1h 1m 1s");
        assert_eq!(format_uptime(90_061), "1d 1h 1m 1s");
        assert_eq!(format_uptime(86_400), "1d 0h 0m 0s");
    }

    fn plain() -> Palette {
        Palette::new(false)
    }

    #[test]
    fn event_line_with_domain() {
        let ev = ConnEvent {
            conn: conn(Some("example.org")),
            verdict: Verdict::Allow,
            rule_name: Some("allow-curl".into()),
            unix_ms: 1_720_000_000_000,
            enforced: true,
        };
        assert_eq!(
            format_event(&ev, plain()),
            "2024-07-03 09:46:40 ALLOW        /usr/bin/curl -> example.org:443 \
             rule=allow-curl"
        );
    }

    #[test]
    fn event_line_without_domain_or_rule() {
        let mut c = conn(None);
        c.exe_path = None;
        let ev = ConnEvent {
            conn: c,
            verdict: Verdict::Reject,
            rule_name: None,
            unix_ms: 0,
            enforced: true,
        };
        assert_eq!(
            format_event(&ev, plain()),
            "1970-01-01 00:00:00 REJECT       ? -> 93.184.216.34:443 rule=-"
        );
    }

    /// An unenforced deny must read WOULD-DENY: the packet went out, and a
    /// reader shown DENY would conclude the opposite.
    #[test]
    fn observe_mode_event_lines_say_would() {
        let mk = |verdict, enforced| ConnEvent {
            conn: conn(Some("example.org")),
            verdict,
            rule_name: Some("r".into()),
            unix_ms: 0,
            enforced,
        };
        let cases = [
            (Verdict::Deny, false, "WOULD-DENY"),
            (Verdict::Reject, false, "WOULD-REJECT"),
            (Verdict::Deny, true, "DENY"),
            (Verdict::Reject, true, "REJECT"),
            (Verdict::Allow, false, "ALLOW"),
        ];
        for (verdict, enforced, want) in cases {
            let line = format_event(&mk(verdict, enforced), plain());
            let field = line.split_whitespace().nth(2).expect("verdict field");
            assert_eq!(field, want, "{line}");
        }
    }

    /// Color is opt-in, lands only on the verdict, and is padded on the
    /// unpainted text so the columns after it still line up.
    #[test]
    fn color_only_when_enabled_and_does_not_shift_columns() {
        let ev = ConnEvent {
            conn: conn(Some("example.org")),
            verdict: Verdict::Deny,
            rule_name: None,
            unix_ms: 0,
            enforced: true,
        };
        let bare = format_event(&ev, plain());
        assert!(!bare.contains('\x1b'));

        let painted = format_event(&ev, Palette::new(true));
        assert!(painted.contains("\x1b[31mDENY\x1b[0m"), "{painted:?}");
        // Same text once the escapes are removed: color adds nothing else.
        let stripped: String = painted.replace("\x1b[31m", "").replace("\x1b[0m", "");
        assert_eq!(stripped, bare);
    }

    #[test]
    fn color_choice_resolution() {
        let cases = [
            // (json, choice, tty, no_color, colorize)
            (false, ColorChoice::Auto, true, false, true),
            (false, ColorChoice::Auto, false, false, false),
            (false, ColorChoice::Auto, true, true, false),
            (false, ColorChoice::Always, false, true, true),
            (false, ColorChoice::Never, true, false, false),
            // JSON is never colorized, however loudly it was asked for.
            (true, ColorChoice::Always, true, false, false),
        ];
        for (json, choice, tty, no_color, want) in cases {
            let out = Output::resolve(json, choice, tty, no_color);
            assert_eq!(
                out.palette.enabled(),
                want,
                "json={json} choice={choice:?} tty={tty} no_color={no_color}"
            );
            assert_eq!(out.tty, tty);
            assert_eq!(out.json, json);
        }
    }

    fn stats(enforcing: bool) -> Stats {
        Stats {
            connections_total: 100,
            allowed: 80,
            denied: 15,
            prompted: 5,
            rules_loaded: 3,
            uptime_secs: 3600,
            dns_spoof_rejected: 7,
            rules_skipped: 2,
            prompts_overflowed: 1,
            other_proto_total: 0,
            observed_only: 4,
            dns_snoop_dropped: 6,
            enforcing,
            prompt_handler_connected: true,
            prompts_unanswered: 9,
            prompt_handlers_evicted: 2,
            verdict_queue_dropped: Some(0),
            verdict_queue_user_dropped: Some(0),
            verdict_queue_depth: Some(3),
            snoop_queue_dropped: Some(0),
            snoop_queue_user_dropped: Some(0),
            snoop_queue_depth: Some(0),
            verdict_queue_fail_open: Some(true),
            snoop_queue_fail_open: Some(true),
            nft_flushes: 0,
            nft_last_flush_ms: None,
        }
    }

    /// One stats-table row as [`format_stats`] pads it. The width is the
    /// longest key; keeping it here in one place is what lets the row
    /// assertions survive a new longest key.
    fn row(k: &str, v: &str) -> String {
        format!("{k:25}  {v}\n")
    }

    #[test]
    fn stats_table() {
        let out = format_stats(&stats(true), plain());
        assert!(out.contains(&row("mode", "enforcing")), "{out}");
        assert!(out.contains(&row("connections", "100")), "{out}");
        assert!(out.contains(&row("observed only", "4")), "{out}");
        assert!(out.contains(&row("rules loaded", "3")), "{out}");
        assert!(out.contains(&row("rules skipped", "2")), "{out}");
        assert!(out.contains(&row("dns spoofed", "7")), "{out}");
        assert!(out.contains(&row("dns snoop dropped", "6")), "{out}");
        assert!(out.contains(&row("prompt overflows", "1")), "{out}");
        assert!(out.contains(&row("nft table flushes", "0")), "{out}");
        assert!(out.contains(&row("nft last flush", "-")), "{out}");
        assert!(out.contains(&row("uptime", "1h 0m 0s")), "{out}");
        // No warning while enforcing.
        assert!(!out.contains("OBSERVE"), "{out}");
    }

    /// With no prompt handler the daemon asks nobody and applies the default
    /// verdict, and every other counter in this table looks the same as it
    /// does on a host whose operator is answering. The row has to say so.
    #[test]
    fn stats_table_reports_the_prompt_handler() {
        let out = format_stats(&stats(true), plain());
        assert!(out.contains(&row("prompt handler", "connected")), "{out}");
        assert!(out.contains(&row("prompts unanswered", "9")), "{out}");
        assert!(out.contains(&row("handlers evicted", "2")), "{out}");

        let mut s = stats(true);
        s.prompt_handler_connected = false;
        let out = format_stats(&s, plain());
        assert!(out.contains(&row("prompt handler", "none (unmatched connections take the default)")), "{out}");
    }

    /// A status table that looks healthy while nothing is filtered is the
    /// worst possible output, so observe mode says so twice: in the mode row
    /// and in a trailing line.
    #[test]
    fn stats_table_flags_observe_mode() {
        let out = format_stats(&stats(false), plain());
        assert!(out.contains(&row("mode", "observe (not enforcing)")), "{out}");
        assert!(out.contains(OBSERVE_WARNING), "{out}");
        assert!(out.contains("every packet is let through"), "{out}");
    }

    /// The kernel queue rows: numbers render as numbers, a healthy zero is
    /// unpainted, and nothing extra is claimed while nothing was dropped.
    /// A nonzero flush count renders painted, with its timestamp beside it.
    #[test]
    fn stats_table_flush_rows_when_flushed() {
        let s = Stats {
            nft_flushes: 2,
            nft_last_flush_ms: Some(1_720_000_000_000),
            ..stats(true)
        };
        let out = format_stats(&s, Palette::new(false));
        assert!(out.contains(&row("nft table flushes", "2")), "{out}");
        assert!(
            out.contains(&row("nft last flush", "2024-07-03 09:46:40")),
            "{out}"
        );
    }

    #[test]
    fn stats_table_kernel_queue_rows() {
        let out = format_stats(&stats(true), plain());
        assert!(out.contains(&row("verdict queue depth", "3")), "{out}");
        assert!(out.contains(&row("verdict queue dropped", "0")), "{out}");
        assert!(out.contains(&row("verdict queue undelivered", "0")), "{out}");
        assert!(out.contains(&row("verdict queue fail-open", "yes")), "{out}");
        assert!(out.contains(&row("snoop queue depth", "0")), "{out}");
        assert!(out.contains(&row("snoop queue dropped", "0")), "{out}");
        assert!(out.contains(&row("snoop queue undelivered", "0")), "{out}");
        assert!(out.contains(&row("snoop queue fail-open", "yes")), "{out}");
        assert!(!out.contains("dropped by the kernel"), "{out}");
    }

    /// The flag is rendered plainly either way: "no" is the intended state
    /// under a fail-closed posture, which this table cannot see.
    #[test]
    fn stats_table_fail_open_flag_renders_no() {
        let mut s = stats(true);
        s.verdict_queue_fail_open = Some(false);
        let out = format_stats(&s, plain());
        assert!(out.contains(&row("verdict queue fail-open", "no")), "{out}");
    }

    /// A missing counter reads "unavailable", never zero: zero claims the
    /// kernel dropped nothing, and nobody knows that.
    #[test]
    fn stats_table_missing_kernel_counters_are_not_zero() {
        let mut s = stats(true);
        s.verdict_queue_dropped = None;
        s.verdict_queue_user_dropped = None;
        s.verdict_queue_depth = None;
        s.verdict_queue_fail_open = None;
        let out = format_stats(&s, plain());
        assert!(out.contains(&row("verdict queue dropped", "unavailable")), "{out}");
        assert!(out.contains(&row("verdict queue depth", "unavailable")), "{out}");
        assert!(out.contains(&row("verdict queue fail-open", "unavailable")), "{out}");
        assert!(!out.contains("dropped by the kernel"), "{out}");
    }

    /// Kernel drops on the verdict queue are packets policy never saw, the
    /// one thing this table exists to make loud: painted in the row and
    /// summed in a trailing warning.
    #[test]
    fn stats_table_flags_verdict_queue_drops() {
        let mut s = stats(true);
        s.verdict_queue_dropped = Some(4);
        s.verdict_queue_user_dropped = Some(1);
        let out = format_stats(&s, plain());
        assert!(
            out.contains("5 packets were dropped by the kernel before policy saw them"),
            "{out}"
        );
        // Painted when color is on, and only the affected rows.
        let painted = format_stats(&s, Palette::new(true));
        assert!(painted.contains("\x1b[1;33m4\x1b[0m"), "{painted:?}");
        assert!(painted.contains("\x1b[1;33m1\x1b[0m"), "{painted:?}");
    }

    #[test]
    fn config_table() {
        let out = format_config(
            &RuntimeConfig {
                prompt_timeout_secs: 30,
                default_verdict: Verdict::Deny,
                enforce: true,
            },
            plain(),
        );
        assert!(out.contains("mode            enforcing\n"), "{out}");
        assert!(out.contains("prompt timeout  30s\n"), "{out}");
        assert!(out.contains("default action  deny\n"), "{out}");
        // The settings are runtime-only, and this output is where a headless
        // operator learns that; the GUI settings tab carries the same note.
        assert!(out.contains("runtime only"), "{out}");
        assert!(!out.contains("OBSERVE"), "{out}");
    }

    /// Same rule as the stats table: settings output that looks routine
    /// while nothing is filtered must say so.
    #[test]
    fn config_table_flags_observe_mode() {
        let out = format_config(
            &RuntimeConfig {
                prompt_timeout_secs: 30,
                default_verdict: Verdict::Allow,
                enforce: false,
            },
            plain(),
        );
        assert!(out.contains("mode            observe (not enforcing)\n"), "{out}");
        assert!(out.contains(OBSERVE_WARNING), "{out}");
    }

    /// The rule listing is what an operator reads to audit policy, and rule
    /// names carry an executable stem while summaries quote exe, domain and
    /// cmdline operands. A rule must not be able to erase or rewrite its row.
    #[test]
    fn rule_listing_cannot_rewrite_the_terminal() {
        let rules = vec![Rule {
            name: "evil\x1b[A\x1b[2K".into(),
            action: Action::Allow,
            duration: RuleDuration::Forever,
            priority: 100,
            enabled: true,
            matcher: RuleMatch {
                domain: Some("a\r\nb.example.org".into()),
                cmdline_contains: Some("x\x1b[2Ky".into()),
                ..Default::default()
            },
        }];
        let out = format_rules(&rules);
        assert!(!out.contains('\x1b'), "escape reached the terminal: {out:?}");
        assert!(!out.contains('\r'), "CR reached the terminal: {out:?}");
        // Header plus exactly one row: nothing smuggled in extra lines.
        assert_eq!(out.lines().count(), 2, "{out:?}");
    }

    /// Column widths are measured in characters; bytes would over-pad a
    /// multibyte name and misalign every column after it.
    #[test]
    fn multibyte_rule_name_keeps_columns_aligned() {
        let mk = |name: &str| Rule {
            name: name.into(),
            action: Action::Deny,
            duration: RuleDuration::Forever,
            priority: 1,
            enabled: true,
            matcher: RuleMatch {
                port: Some(25),
                ..Default::default()
            },
        };
        // Same character count, very different byte count.
        let out = format_rules(&[mk("日本語テスト"), mk("abcdef")]);
        let rows: Vec<&str> = out.lines().skip(1).collect();
        // Character offset, not the byte offset `find` returns: the point is
        // where the column appears on screen.
        let col = |line: &str| {
            let byte = line.find("deny").expect("action column");
            line[..byte].chars().count()
        };
        assert_eq!(
            col(rows[0]),
            col(rows[1]),
            "action column must line up:\n{out}"
        );
    }

    #[test]
    fn rules_table_alignment_and_summary() {
        let rules = vec![
            Rule {
                name: "a".into(),
                action: Action::Allow,
                duration: RuleDuration::Session,
                priority: 1,
                enabled: true,
                matcher: RuleMatch {
                    port: Some(443),
                    domain: Some("*.example.org".into()),
                    ..Default::default()
                },
            },
            Rule {
                name: "block-everything".into(),
                action: Action::Reject,
                duration: RuleDuration::Forever,
                priority: 0,
                enabled: false,
                matcher: RuleMatch::default(),
            },
        ];
        let out = format_rules(&rules);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("NAME              ACTION  DURATION"));
        assert!(lines[1].contains("port=443 domain=*.example.org"));
        assert!(lines[2].contains("(any)"));
        // NAME column aligned: ACTION starts at same offset in all lines.
        let col = lines[0].find("ACTION").unwrap();
        assert_eq!(&lines[1][col..col + 5], "allow");
        assert_eq!(&lines[2][col..col + 6], "reject");
    }

    #[test]
    fn empty_rules() {
        assert_eq!(format_rules(&[]), "no rules\n");
        assert_eq!(format_rules_with_hits(&[], &[]), "no rules\n");
    }

    fn counted(name: &str) -> Rule {
        Rule {
            name: name.into(),
            action: Action::Deny,
            duration: RuleDuration::Forever,
            priority: 1,
            enabled: true,
            matcher: RuleMatch {
                port: Some(25),
                ..Default::default()
            },
        }
    }

    /// The question this table answers is "which rules never match", so a rule
    /// the daemon reported nothing for has to say 0 and -, not go blank.
    #[test]
    fn rules_table_with_hits() {
        let rules = [counted("busy"), counted("idle"), counted("missing")];
        // "busy" has matched; "idle" is reported but has never matched, and
        // "missing" has no counter at all. The last two must read the same.
        let hits = [
            RuleHit {
                name: "busy".into(),
                hits: 7,
                last_hit_ms: Some(1_720_000_000_000),
            },
            RuleHit {
                name: "idle".into(),
                hits: 0,
                last_hit_ms: None,
            },
        ];
        let out = format_rules_with_hits(&rules, &hits);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 4, "{out}");
        assert!(lines[0].contains("HITS"), "{out}");
        assert!(lines[0].contains("LAST HIT"), "{out}");
        assert!(lines[1].contains("2024-07-03 09:46:40"), "{out}");

        let fields = |line: &str| -> Vec<String> {
            line.split_whitespace().map(str::to_string).collect()
        };
        assert_eq!(fields(lines[1])[5], "7");
        for row in [lines[2], lines[3]] {
            let f = fields(row);
            assert_eq!(f[5], "0", "{row}");
            assert_eq!(f[6], "-", "{row}");
        }
        // Plain `rules` is unchanged: no counters, no columns.
        assert!(!format_rules(&rules).contains("HITS"));
    }

    /// Counters are keyed on the raw name the daemon accounts against, while
    /// the table shows the sanitized copy. Keying on the display form would
    /// silently report zero hits for every rule with an odd character in it.
    #[test]
    fn hits_are_matched_on_the_raw_rule_name() {
        let out = format_rules_with_hits(
            &[counted("evil\x1b[2K")],
            &[RuleHit {
                name: "evil\x1b[2K".into(),
                hits: 3,
                last_hit_ms: None,
            }],
        );
        assert!(!out.contains('\x1b'), "{out:?}");
        assert_eq!(out.lines().nth(1).unwrap().split_whitespace().nth(5), Some("3"));
    }

    fn tr(name: &str, priority: u32, outcome: TraceOutcome) -> RuleTrace {
        RuleTrace {
            name: name.into(),
            priority,
            outcome,
        }
    }

    fn explanation() -> Explanation {
        Explanation {
            verdict: Verdict::Allow,
            rule_name: Some("allow-curl".into()),
            would_prompt: false,
            enforced: true,
            trace: vec![
                tr("allow-curl", 50, TraceOutcome::Matched),
                tr("catch-all", 1, TraceOutcome::NotReached),
                tr("turned-off", 60, TraceOutcome::Disabled),
                tr(
                    "wrong-port",
                    70,
                    TraceOutcome::NoMatch {
                        field: "port".into(),
                    },
                ),
            ],
        }
    }

    /// The verdict is the answer, so it comes first and on its own line; the
    /// trace below it says which operand to edit for every rule that missed.
    #[test]
    fn explanation_leads_with_the_verdict_then_the_trace() {
        let out = format_explanation(&explanation(), plain());
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "verdict: ALLOW  rule=allow-curl");
        assert_eq!(lines[1], "");
        assert!(lines[2].starts_with("RULE"), "{out}");
        assert!(lines[3].starts_with("allow-curl"), "{out}");
        assert!(lines[3].ends_with("matched"), "{out}");
        assert!(lines[4].ends_with("not reached"), "{out}");
        assert!(lines[5].ends_with("disabled"), "{out}");
        // Names the operand to change, not just "no".
        assert!(lines[6].ends_with("no match (port)"), "{out}");
        // Priority is shown so the evaluation order reads as deliberate.
        assert!(lines[6].contains("70"), "{out}");
        assert!(!out.contains("more rules not shown"), "{out}");
    }

    /// `would_prompt` means nothing matched, so the verdict is only what
    /// happens if the prompt is ignored. Printing it as the decision would
    /// answer a question the operator did not ask.
    #[test]
    fn explanation_says_when_it_would_prompt() {
        let mut exp = explanation();
        exp.would_prompt = true;
        exp.rule_name = None;
        exp.verdict = Verdict::Deny;
        exp.trace = vec![tr(
            "wrong-port",
            70,
            TraceOutcome::NoMatch {
                field: "port".into(),
            },
        )];
        let out = format_explanation(&exp, plain());
        assert!(out.starts_with("verdict: PROMPT  (no rule matched)\n"), "{out}");
        assert!(out.contains("would raise a prompt"), "{out}");
        assert!(out.contains("the default if nobody answers it is DENY"), "{out}");
    }

    /// Observe mode: the verdict would be recorded and the packet would go
    /// out anyway, which is the opposite of what "DENY" alone reads as.
    #[test]
    fn explanation_says_when_the_verdict_is_only_recorded() {
        let mut exp = explanation();
        exp.verdict = Verdict::Reject;
        exp.enforced = false;
        let out = format_explanation(&exp, plain());
        assert!(out.contains(EXPLAIN_OBSERVE_NOTE), "{out}");
        // And the color says the same thing as the words.
        assert_eq!(verdict_style(Verdict::Reject, false), Style::Would);
        assert_eq!(verdict_style(Verdict::Reject, true), Style::Reject);
    }

    #[test]
    fn explanation_without_rules() {
        let mut exp = explanation();
        exp.trace.clear();
        let out = format_explanation(&exp, plain());
        assert!(out.contains("no rules loaded"), "{out}");
    }

    /// A rule name embeds an executable stem, so the trace is one more place
    /// a process can try to talk to the operator. It must not be able to move
    /// the cursor, and it must not be able to forge a row of its own.
    #[test]
    fn explanation_trace_cannot_rewrite_the_terminal() {
        let exp = Explanation {
            verdict: Verdict::Deny,
            rule_name: Some("evil\x1b[2K".into()),
            would_prompt: false,
            enforced: true,
            trace: vec![
                tr("evil\x1b[A\x1b[2K", 100, TraceOutcome::Matched),
                tr(
                    "second\r\nallow-everything  0  matched",
                    1,
                    TraceOutcome::NoMatch {
                        field: "port\x1b[2K".into(),
                    },
                ),
            ],
        };
        let out = format_explanation(&exp, plain());
        assert!(!out.contains('\x1b'), "escape reached the terminal: {out:?}");
        assert!(!out.contains('\r'), "CR reached the terminal: {out:?}");
        // Verdict, blank, header, two rows: no smuggled extra line.
        assert_eq!(out.lines().count(), 5, "{out:?}");
    }

    /// The trace is one row per loaded rule, and the daemon bounds how many
    /// it loads - but that is a promise made on the other end of a socket.
    #[test]
    fn explanation_trace_is_capped_but_keeps_the_deciding_rule() {
        let total = MAX_TRACE_ROWS + 50;
        let mut exp = explanation();
        exp.trace = (0..total)
            .map(|i| {
                let outcome = if i == total - 1 {
                    TraceOutcome::Matched
                } else {
                    TraceOutcome::NoMatch {
                        field: "port".into(),
                    }
                };
                tr(&format!("r{i}"), 0, outcome)
            })
            .collect();
        exp.rule_name = Some(format!("r{}", total - 1));
        let out = format_explanation(&exp, plain());
        // Header plus the capped rows plus the deciding rule pulled in past
        // the cap; the count of what is left out stays exact.
        assert_eq!(out.lines().count(), 3 + MAX_TRACE_ROWS + 1 + 1, "{out}");
        assert!(out.contains(&format!("r{}", total - 1)), "{out}");
        assert!(out.contains("... 49 more rules not shown"), "{out}");
    }

    /// Color marks the answer: the verdict, and the one row that produced it.
    #[test]
    fn explanation_colors_only_the_verdict_and_the_deciding_rule() {
        let mut exp = explanation();
        exp.verdict = Verdict::Deny;
        let painted = format_explanation(&exp, Palette::new(true));
        assert!(painted.contains("\x1b[31mDENY\x1b[0m"), "{painted:?}");
        assert!(painted.contains("\x1b[31mallow-curl\x1b[0m"), "{painted:?}");
        assert!(!painted.contains("\x1b[31mcatch-all"), "{painted:?}");
        // Same text once the escapes are gone: color adds nothing else, and
        // padding is computed on the unpainted width so columns still line up.
        let stripped = painted.replace("\x1b[31m", "").replace("\x1b[0m", "");
        assert_eq!(stripped, format_explanation(&exp, plain()));
    }
}

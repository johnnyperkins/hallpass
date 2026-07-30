//! Output formatting: tables, event lines, timestamps, and the color palette.

use std::fmt::Write;

use hallpass_types::{
    format_ts, sanitize_for_display, ConnEvent, Connection, PromptScope, Rule, Stats, Verdict,
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
        ("rules loaded", s.rules_loaded.to_string()),
        ("rules skipped", s.rules_skipped.to_string()),
        ("dns spoofed", s.dns_spoof_rejected.to_string()),
        ("dns snoop dropped", s.dns_snoop_dropped.to_string()),
        ("prompt overflows", s.prompts_overflowed.to_string()),
        ("other protocols", s.other_proto_total.to_string()),
        ("uptime", format_uptime(s.uptime_secs)),
    ];
    // Keys are ASCII literals, so bytes and characters agree here; the value
    // column is last and never padded, so a painted value cannot misalign it.
    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (k, v) in rows {
        let _ = writeln!(out, "{k:width$}  {v}");
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

/// Format the rule list as an aligned table with a header row.
pub fn format_rules(rules: &[Rule]) -> String {
    if rules.is_empty() {
        return "no rules\n".to_string();
    }
    let header = ["NAME", "ACTION", "DURATION", "PRIO", "ENABLED", "MATCH"];
    let rows: Vec<[String; 6]> = rules
        .iter()
        .map(|r| {
            [
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
                sanitize_for_display(&r.matcher.summary()).into_owned(),
            ]
        })
        .collect();
    let mut widths: [usize; 6] = header.map(str::len);
    for row in &rows {
        for (w, cell) in widths.iter_mut().zip(row.iter()) {
            // Character count, not bytes: a multibyte name would otherwise
            // over-pad and misalign every following column.
            *w = (*w).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    let render = |out: &mut String, cells: [&str; 6]| {
        // Last column is not padded to avoid trailing whitespace.
        for (i, cell) in cells.iter().enumerate() {
            if i == 5 {
                out.push_str(cell);
            } else {
                let _ = write!(out, "{cell:w$}  ", w = widths[i]);
            }
        }
        out.push('\n');
    };
    render(&mut out, header);
    for row in &rows {
        let cells: [&str; 6] = [&row[0], &row[1], &row[2], &row[3], &row[4], &row[5]];
        render(&mut out, cells);
    }
    out
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

/// Color role for an event's verdict.
fn verdict_style(ev: &ConnEvent) -> Style {
    match (ev.enforced, ev.verdict) {
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
        cell(pal, verdict_style(ev), &label, VERDICT_WIDTH),
        exe_display(&ev.conn),
        dst_display(&ev.conn),
        sanitize_for_display(rule)
    )
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
        }
    }

    #[test]
    fn stats_table() {
        let out = format_stats(&stats(true), plain());
        assert!(out.contains("mode               enforcing\n"), "{out}");
        assert!(out.contains("connections        100\n"), "{out}");
        assert!(out.contains("observed only      4\n"), "{out}");
        assert!(out.contains("rules loaded       3\n"), "{out}");
        assert!(out.contains("rules skipped      2\n"), "{out}");
        assert!(out.contains("dns spoofed        7\n"), "{out}");
        assert!(out.contains("dns snoop dropped  6\n"), "{out}");
        assert!(out.contains("prompt overflows   1\n"), "{out}");
        assert!(out.contains("uptime             1h 0m 0s\n"), "{out}");
        // No warning while enforcing.
        assert!(!out.contains("OBSERVE"), "{out}");
    }

    /// A status table that looks healthy while nothing is filtered is the
    /// worst possible output, so observe mode says so twice: in the mode row
    /// and in a trailing line.
    #[test]
    fn stats_table_flags_observe_mode() {
        let out = format_stats(&stats(false), plain());
        assert!(out.contains("mode               observe (not enforcing)\n"), "{out}");
        assert!(out.contains(OBSERVE_WARNING), "{out}");
        assert!(out.contains("every packet is let through"), "{out}");
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
    }
}

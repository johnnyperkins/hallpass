//! Output formatting: tables, event lines, timestamps.

use std::fmt::Write;

use hallpass_types::{ConnEvent, Connection, PromptScope, Rule, Stats, Verdict};

/// Human-readable verdict name (uppercase, for event lines).
pub fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "ALLOW",
        Verdict::Deny => "DENY",
        Verdict::Reject => "REJECT",
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

/// Format daemon stats as an aligned key/value table.
pub fn format_stats(s: &Stats) -> String {
    let rows = [
        ("connections", s.connections_total.to_string()),
        ("allowed", s.allowed.to_string()),
        ("denied", s.denied.to_string()),
        ("prompted", s.prompted.to_string()),
        ("rules loaded", s.rules_loaded.to_string()),
        ("rules skipped", s.rules_skipped.to_string()),
        ("dns spoofed", s.dns_spoof_rejected.to_string()),
        ("prompt overflows", s.prompts_overflowed.to_string()),
        ("other protocols", s.other_proto_total.to_string()),
        ("uptime", format_uptime(s.uptime_secs)),
    ];
    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (k, v) in rows {
        let _ = writeln!(out, "{k:width$}  {v}");
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
                r.name.clone(),
                r.action.as_str().to_string(),
                r.duration.describe(),
                r.priority.to_string(),
                if r.enabled { "yes" } else { "no" }.to_string(),
                r.matcher.summary(),
            ]
        })
        .collect();
    let mut widths: [usize; 6] = header.map(str::len);
    for row in &rows {
        for (w, cell) in widths.iter_mut().zip(row.iter()) {
            *w = (*w).max(cell.len());
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
pub fn exe_display(conn: &Connection) -> String {
    conn.exe_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "?".to_string())
}

/// Display string for a connection destination: `domain:port` when the
/// domain is known, otherwise `ip:port`.
pub fn dst_display(conn: &Connection) -> String {
    match &conn.domain {
        Some(domain) => format!("{domain}:{}", conn.tuple.dst.port()),
        None => conn.tuple.dst.to_string(),
    }
}

/// Format one connection event line:
/// `TIMESTAMP VERDICT exe -> dst rule=NAME`.
pub fn format_event(ev: &ConnEvent) -> String {
    let rule = ev.rule_name.as_deref().unwrap_or("-");
    format!(
        "{} {:6} {} -> {} rule={}",
        format_ts(ev.unix_ms),
        verdict_str(ev.verdict),
        exe_display(&ev.conn),
        dst_display(&ev.conn),
        rule
    )
}

/// Format Unix milliseconds as `YYYY-MM-DD HH:MM:SS` (UTC).
pub fn format_ts(unix_ms: u64) -> String {
    let secs = (unix_ms / 1000) as i64;
    let days = secs.div_euclid(86400);
    let sod = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        sod / 3600,
        sod / 60 % 60,
        sod % 60
    )
}

/// Days-since-epoch to (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
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

    #[test]
    fn event_line_with_domain() {
        let ev = ConnEvent {
            conn: conn(Some("example.org")),
            verdict: Verdict::Allow,
            rule_name: Some("allow-curl".into()),
            unix_ms: 1_720_000_000_000,
        };
        assert_eq!(
            format_event(&ev),
            "2024-07-03 09:46:40 ALLOW  /usr/bin/curl -> example.org:443 rule=allow-curl"
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
        };
        assert_eq!(
            format_event(&ev),
            "1970-01-01 00:00:00 REJECT ? -> 93.184.216.34:443 rule=-"
        );
    }

    #[test]
    fn stats_table() {
        let s = Stats {
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
        };
        let out = format_stats(&s);
        assert!(out.contains("connections       100\n"));
        assert!(out.contains("rules loaded      3\n"));
        assert!(out.contains("rules skipped     2\n"));
        assert!(out.contains("dns spoofed       7\n"));
        assert!(out.contains("prompt overflows  1\n"));
        assert!(out.contains("uptime            1h 0m 0s\n"));
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

//! Machine-readable output for `--json`.
//!
//! The wire types already derive `Serialize`, so this module is mostly about
//! what has to happen *before* serializing: every daemon-supplied string is
//! sanitized first, exactly as on the human path.
//!
//! Two reasons that is not paranoia about a format that quotes its strings.
//! `serde_json` escapes a control byte (``) rather than dropping it, and
//! the usual consumer of these lines decodes them and prints them, so an
//! unsanitized cmdline still reaches a terminal intact, one hop later. And a
//! `PathBuf` that is not valid UTF-8 fails to serialize at all, which would
//! turn a process picking an odd exe path into a broken pipeline; sanitizing
//! through `Path::display` guarantees UTF-8 on the way in.

use std::path::PathBuf;

use hallpass_types::{sanitize_for_display, ConnEvent, Connection, Rule, RuleMatch, Stats};
use serde::Serialize;

use crate::client::CliError;

/// Serialize a value to one line of JSON.
///
/// Encoding these types cannot realistically fail (no non-string map keys, no
/// floats), but the error is mapped rather than unwrapped so a future field
/// cannot turn into a panic in a streaming loop.
pub fn to_json<T: Serialize>(value: &T) -> Result<String, CliError> {
    serde_json::to_string(value)
        .map_err(|e| CliError::Protocol(format!("cannot encode output as json: {e}")))
}

/// Daemon stats as one JSON object. [`Stats`] is all counters, so there is
/// nothing here to sanitize.
pub fn stats(s: &Stats) -> Result<String, CliError> {
    to_json(s)
}

/// The rule list as a JSON array.
pub fn rules(rules: &[Rule]) -> Result<String, CliError> {
    let clean: Vec<Rule> = rules.iter().map(sanitized_rule).collect();
    to_json(&clean)
}

/// One event as a JSON object, for the JSON Lines event stream.
///
/// Single-line by construction: `serde_json` never emits a bare newline, and
/// sanitizing has already replaced any newline inside a string value, so one
/// event cannot forge a second record.
pub fn event(ev: &ConnEvent) -> Result<String, CliError> {
    to_json(&sanitized_event(ev))
}

/// Sanitize a string field.
fn clean(s: &str) -> String {
    sanitize_for_display(s).into_owned()
}

/// Sanitize an optional string field.
fn clean_opt(s: &Option<String>) -> Option<String> {
    s.as_deref().map(clean)
}

/// Sanitize an optional path field, lossily decoding it on the way.
fn clean_path(p: &Option<PathBuf>) -> Option<PathBuf> {
    p.as_ref()
        .map(|p| PathBuf::from(clean(&p.display().to_string())))
}

/// Copy of `ev` with every daemon-supplied string sanitized.
///
/// Written out field by field rather than with `..ev.clone()`: a field added
/// to [`Connection`] upstream then fails to compile here, instead of silently
/// shipping one unsanitized value into every consumer.
pub fn sanitized_event(ev: &ConnEvent) -> ConnEvent {
    ConnEvent {
        conn: Connection {
            tuple: ev.conn.tuple,
            uid: ev.conn.uid,
            pid: ev.conn.pid,
            exe_path: clean_path(&ev.conn.exe_path),
            cmdline: clean_opt(&ev.conn.cmdline),
            parent_exe: clean_path(&ev.conn.parent_exe),
            domain: clean_opt(&ev.conn.domain),
            iface: clean_opt(&ev.conn.iface),
        },
        verdict: ev.verdict,
        rule_name: clean_opt(&ev.rule_name),
        unix_ms: ev.unix_ms,
        enforced: ev.enforced,
    }
}

/// Copy of `r` with every daemon-supplied string sanitized. Exhaustive for the
/// same reason as [`sanitized_event`]: a new operand must not slip through
/// unsanitized just because nobody remembered this file.
pub fn sanitized_rule(r: &Rule) -> Rule {
    let m = &r.matcher;
    Rule {
        name: clean(&r.name),
        action: r.action,
        duration: r.duration,
        priority: r.priority,
        enabled: r.enabled,
        matcher: RuleMatch {
            exe: clean_path(&m.exe),
            exe_glob: clean_opt(&m.exe_glob),
            exe_sha256: clean_opt(&m.exe_sha256),
            dest: clean_opt(&m.dest),
            port: m.port,
            port_range: m.port_range,
            domain: clean_opt(&m.domain),
            user: m.user,
            proto: m.proto,
            domains_file: clean_path(&m.domains_file),
            ips_file: clean_path(&m.ips_file),
            hashes_file: clean_path(&m.hashes_file),
            cmdline_contains: clean_opt(&m.cmdline_contains),
            parent_exe: clean_path(&m.parent_exe),
            src: clean_opt(&m.src),
            src_port: m.src_port,
            iface: clean_opt(&m.iface),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hallpass_types::{Action, FlowTuple, Proto, RuleDuration, Verdict};

    fn hostile_event() -> ConnEvent {
        ConnEvent {
            conn: Connection {
                tuple: FlowTuple {
                    proto: Proto::Tcp,
                    src: "127.0.0.1:50000".parse().unwrap(),
                    dst: "93.184.216.34:443".parse().unwrap(),
                },
                uid: Some(1000),
                pid: Some(7),
                exe_path: Some(PathBuf::from("/tmp/evil\r\x1b[A/usr/bin/firefox")),
                cmdline: Some("evil\n{\"verdict\":\"allow\"}".into()),
                parent_exe: None,
                domain: Some("bank.example\u{202e}moc.reknatta".into()),
                iface: Some("eth0\x1b[2K".into()),
            },
            verdict: Verdict::Deny,
            rule_name: Some("r\rule".into()),
            unix_ms: 1_720_000_000_123,
            enforced: false,
        }
    }

    /// JSON is not a safe harbour: the consumer decodes and prints these
    /// strings, and a newline inside one would forge a second JSON Lines
    /// record that a log reader would treat as a separate event.
    #[test]
    fn hostile_event_json_is_one_sanitized_line() {
        let line = event(&hostile_event()).expect("encode");
        assert_eq!(line.lines().count(), 1, "{line:?}");
        for bad in ['\x1b', '\r', '\n', '\u{202e}'] {
            assert!(!line.contains(bad), "{bad:?} survived: {line:?}");
        }
        // Escaped forms of the same bytes must not be there either: a
        // consumer that decodes  gets a live escape sequence.
        for bad in ["\\u001b", "\\r", "\\n", "\\u202e"] {
            assert!(!line.contains(bad), "{bad} survived: {line:?}");
        }
        // The readable part survives, and the observe-mode flag is present so
        // a consumer can tell a recorded deny from an applied one.
        assert!(line.contains("firefox"), "{line:?}");
        assert!(line.contains("\"enforced\":false"), "{line:?}");
        assert!(line.contains("\"verdict\":\"deny\""), "{line:?}");
    }

    #[test]
    fn hostile_rule_json_is_sanitized() {
        let rule = Rule {
            name: "evil\x1b[2K".into(),
            action: Action::Allow,
            duration: RuleDuration::Forever,
            priority: 3,
            enabled: true,
            matcher: RuleMatch {
                exe: Some(PathBuf::from("/bin/sh\r")),
                domain: Some("a\nb.example.org".into()),
                cmdline_contains: Some("x\x1b[2Ky".into()),
                port: Some(443),
                ..Default::default()
            },
        };
        let out = rules(&[rule]).expect("encode");
        assert_eq!(out.lines().count(), 1, "{out:?}");
        for bad in ["\\u001b", "\\r", "\\n"] {
            assert!(!out.contains(bad), "{bad} survived: {out:?}");
        }
        assert!(out.contains("\"port\":443"), "{out:?}");
        assert!(out.contains("\"priority\":3"), "{out:?}");
    }

    #[test]
    fn stats_json_carries_the_new_fields() {
        let s = Stats {
            connections_total: 9,
            observed_only: 4,
            dns_snoop_dropped: 2,
            enforcing: false,
            ..Default::default()
        };
        let out = stats(&s).expect("encode");
        assert!(out.contains("\"observed_only\":4"), "{out}");
        assert!(out.contains("\"dns_snoop_dropped\":2"), "{out}");
        assert!(out.contains("\"enforcing\":false"), "{out}");
    }

    /// A non-UTF-8 exe path must not break the pipeline: `PathBuf`'s
    /// serializer refuses one, so sanitizing has to decode it first.
    #[test]
    fn non_utf8_exe_path_still_serializes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let mut ev = hostile_event();
        ev.conn.exe_path = Some(PathBuf::from(OsString::from_vec(vec![
            b'/', b'x', 0xff, 0xfe, b'y',
        ])));
        let line = event(&ev).expect("encode");
        assert!(line.contains("\"pid\":7"), "{line:?}");
    }
}

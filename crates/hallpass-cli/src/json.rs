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

use hallpass_types::{
    sanitize_for_display, ConnEvent, Connection, Explanation, Rule, RuleHit, RuleMatch, RuleTrace,
    RunSessionInfo, RuntimeConfig, Stats, TraceOutcome,
};
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

/// The runtime settings as one JSON object, carrying the lockdown posture
/// alongside them.
///
/// The posture is in the same document rather than a second command,
/// because the settings reply reports what the operator *set* and the
/// posture is what overrides two of those values right now. A consumer that
/// read `enforce: false` here on a locked-down host and concluded the host
/// was not filtering would be wrong in the direction that matters, and
/// nothing in a settings-only document could have told it otherwise.
#[derive(Debug, Serialize)]
struct ConfigWithLockdown<'a> {
    #[serde(flatten)]
    config: &'a RuntimeConfig,
    /// Null when no posture is in force. While one is, the mode is enforce
    /// and the default verdict is deny whatever the fields above say.
    lockdown: &'a Option<hallpass_types::Lockdown>,
}

pub fn config(
    c: &RuntimeConfig,
    lockdown: &Option<hallpass_types::Lockdown>,
) -> Result<String, CliError> {
    to_json(&ConfigWithLockdown {
        config: c,
        lockdown,
    })
}

/// The live session grants as a JSON array. The label came from a client,
/// so it is sanitized like any other daemon-carried string.
pub fn sessions(sessions: &[RunSessionInfo]) -> Result<String, CliError> {
    let clean: Vec<RunSessionInfo> = sessions
        .iter()
        .map(|s| RunSessionInfo {
            label: sanitize_for_display(&s.label).into_owned(),
            ..s.clone()
        })
        .collect();
    to_json(&clean)
}

/// The rule list as a JSON array.
pub fn rules(rules: &[Rule]) -> Result<String, CliError> {
    let clean: Vec<Rule> = rules.iter().map(sanitized_rule).collect();
    to_json(&clean)
}

/// A rule with its hit counters, for `rules --stats --json`.
///
/// Flattened so a consumer sees one object per rule with two extra keys,
/// rather than having to reach through a wrapper for the fields it already
/// knows from plain `rules --json`.
#[derive(Debug, Serialize)]
struct RuleWithHits {
    #[serde(flatten)]
    rule: Rule,
    /// Connections this rule decided since the daemon started.
    hits: u64,
    /// When it last decided one, or None if never.
    last_hit_ms: Option<u64>,
}

/// The rule list as a JSON array, each rule carrying its hit counters.
///
/// A rule the daemon reported no counter for gets `0` and `null`, so every
/// element has the same shape whether or not the rule has ever matched.
pub fn rules_with_hits(rules: &[Rule], hits: &[RuleHit]) -> Result<String, CliError> {
    // Keyed on the raw name, which is what the daemon accounts against.
    let by_name: std::collections::HashMap<&str, &RuleHit> =
        hits.iter().map(|h| (h.name.as_str(), h)).collect();
    let clean: Vec<RuleWithHits> = rules
        .iter()
        .map(|r| {
            let hit = by_name.get(r.name.as_str());
            RuleWithHits {
                rule: sanitized_rule(r),
                hits: hit.map_or(0, |h| h.hits),
                last_hit_ms: hit.and_then(|h| h.last_hit_ms),
            }
        })
        .collect();
    to_json(&clean)
}

/// One explanation as a JSON object.
pub fn explanation(e: &Explanation) -> Result<String, CliError> {
    to_json(&sanitized_explanation(e))
}

/// Copy of `e` with every daemon-supplied string sanitized. The trace is not
/// truncated the way the human rendering is: a consumer that asked for the
/// whole evaluation would rather have it than a silently shortened list.
pub fn sanitized_explanation(e: &Explanation) -> Explanation {
    Explanation {
        verdict: e.verdict,
        rule_name: clean_opt(&e.rule_name),
        would_prompt: e.would_prompt,
        enforced: e.enforced,
        trace: e
            .trace
            .iter()
            .map(|t| RuleTrace {
                name: clean(&t.name),
                priority: t.priority,
                outcome: match &t.outcome {
                    // The field name is one of a fixed set today, but it
                    // arrives over a socket like every other string here.
                    TraceOutcome::NoMatch { field } => TraceOutcome::NoMatch {
                        field: clean(field),
                    },
                    other => other.clone(),
                },
            })
            .collect(),
    }
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
            app_id: clean_opt(&ev.conn.app_id),
            // Two bools; nothing here can carry an escape or a newline.
            first_seen: ev.conn.first_seen,
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
        // Sanitized like every other field, even though `valid_tag` should
        // make a hazardous tag impossible. This function's stated property is
        // that it has no exemptions, and an exemption resting on a validator
        // being correct is the argument it exists so nobody has to make.
        tags: r.tags.iter().map(|t| clean(t)).collect(),
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
            app_id: clean_opt(&m.app_id),
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
                app_id: None,
                first_seen: None,
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

    /// JSON is the one output that can tell "nothing was new" from "the
    /// daemon is not tracking", and a consumer alerting on first contact
    /// needs the difference: null is not `{"app":false,"dest":false}`.
    #[test]
    fn first_seen_survives_the_sanitizing_copy() {
        let mut ev = hostile_event();
        ev.conn.first_seen = Some(hallpass_types::FirstSeen {
            app: true,
            dest: false,
        });
        let line = event(&ev).expect("encode");
        assert!(
            line.contains(r#""first_seen":{"app":true,"dest":false}"#),
            "{line}"
        );

        ev.conn.first_seen = None;
        let line = event(&ev).expect("encode");
        assert!(line.contains(r#""first_seen":null"#), "{line}");
    }

    #[test]
    fn hostile_rule_json_is_sanitized() {
        let rule = Rule {
            name: "evil\x1b[2K".into(),
            action: Action::Allow,
            duration: RuleDuration::Forever,
            priority: 3,
            enabled: true,
            tags: Vec::new(),
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
            verdict_queue_dropped: Some(7),
            ..Default::default()
        };
        let out = stats(&s).expect("encode");
        assert!(out.contains("\"observed_only\":4"), "{out}");
        assert!(out.contains("\"dns_snoop_dropped\":2"), "{out}");
        assert!(out.contains("\"enforcing\":false"), "{out}");
        // A kernel counter nobody read is null, not 0: a JSON consumer must
        // be able to tell "nothing dropped" from "nothing known".
        assert!(out.contains("\"verdict_queue_dropped\":7"), "{out}");
        assert!(out.contains("\"snoop_queue_dropped\":null"), "{out}");
        assert!(out.contains("\"verdict_queue_fail_open\":null"), "{out}");
    }

    /// The counters ride alongside the rule's own fields, and a rule the
    /// daemon reported nothing for still gets both keys: a consumer should not
    /// have to tell "never matched" apart from "field absent".
    #[test]
    fn rules_with_hits_json_carries_the_counters() {
        let rule = |name: &str| Rule {
            name: name.into(),
            action: Action::Deny,
            duration: RuleDuration::Forever,
            priority: 1,
            enabled: true,
            tags: Vec::new(),
            matcher: RuleMatch::default(),
        };
        let out = rules_with_hits(
            &[rule("busy"), rule("never")],
            &[RuleHit {
                name: "busy".into(),
                hits: 12,
                last_hit_ms: Some(1_720_000_000_123),
            }],
        )
        .expect("encode");
        assert!(out.contains(r#""name":"busy""#), "{out}");
        assert!(out.contains(r#""hits":12"#), "{out}");
        assert!(out.contains(r#""last_hit_ms":1720000000123"#), "{out}");
        assert!(out.contains(r#""hits":0"#), "{out}");
        assert!(out.contains(r#""last_hit_ms":null"#), "{out}");
        // Flattened, not wrapped: the rule's own fields stay where a consumer
        // of plain `rules --json` already expects them.
        assert!(out.contains(r#""priority":1"#), "{out}");
        assert!(!out.contains(r#""rule":"#), "{out}");
    }

    /// The usual consumer of this decodes the strings and prints them, so a
    /// hostile rule name in a trace reaches a terminal one hop later.
    #[test]
    fn hostile_explanation_json_is_one_sanitized_line() {
        let exp = Explanation {
            verdict: Verdict::Deny,
            rule_name: Some("evil\x1b[2K".into()),
            would_prompt: false,
            enforced: false,
            trace: vec![
                RuleTrace {
                    name: "evil\x1b[2K".into(),
                    priority: 100,
                    outcome: TraceOutcome::Matched,
                },
                RuleTrace {
                    name: "second\r\nforged".into(),
                    priority: 0,
                    outcome: TraceOutcome::NoMatch {
                        field: "port\n".into(),
                    },
                },
            ],
        };
        let line = explanation(&exp).expect("encode");
        assert_eq!(line.lines().count(), 1, "{line:?}");
        for bad in ["\\u001b", "\\r", "\\n"] {
            assert!(!line.contains(bad), "{bad} survived: {line:?}");
        }
        assert!(line.contains(r#""would_prompt":false"#), "{line}");
        assert!(line.contains(r#""enforced":false"#), "{line}");
        assert!(line.contains(r#""verdict":"deny""#), "{line}");
        // The whole trace is there: a machine consumer asked for all of it.
        assert!(line.contains("\"priority\":100"), "{line}");
        assert!(line.contains("NoMatch"), "{line}");
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

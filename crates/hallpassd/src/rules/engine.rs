//! First-match-wins rule evaluation over a compiled, sorted rule set.

use hallpass_types::{Connection, Rule, RuleTrace, TraceOutcome, Verdict};

use super::model::CompiledRule;

/// Outcome of an explain evaluation: the deciding rule if any, plus why
/// every rule did or did not decide, in evaluation order.
pub struct ExplainResult {
    /// Name and verdict of the deciding rule; None when nothing matched.
    pub matched: Option<(String, Verdict)>,
    /// Per-rule trace in evaluation order (highest priority first).
    pub trace: Vec<RuleTrace>,
}

/// Immutable snapshot of compiled rules, ordered for evaluation:
/// higher priority first, ties broken by name for determinism.
pub struct RuleSet {
    rules: Vec<CompiledRule>,
    /// Whether any enabled rule pins an executable hash; precomputed so
    /// the per-packet check is free when the feature is unused.
    has_hash_rules: bool,
}

impl RuleSet {
    /// Compile `rules`, skipping (with a warning) any that fail validation.
    pub fn compile(rules: &[Rule]) -> RuleSet {
        let mut compiled: Vec<CompiledRule> = rules
            .iter()
            .filter_map(|r| match CompiledRule::compile(r) {
                Ok(c) => Some(c),
                Err(e) => {
                    tracing::warn!(rule = %r.name, "skipping invalid rule: {e}");
                    None
                }
            })
            .collect();
        compiled.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| a.name.cmp(&b.name))
        });
        let has_hash_rules = compiled.iter().any(|r| r.enabled && r.wants_exe_hash());
        RuleSet {
            rules: compiled,
            has_hash_rules,
        }
    }

    /// First enabled rule matching `conn`, with its verdict. `exe_sha256`
    /// is the connection executable's hash if it was computed; pass the
    /// result of gating on [`RuleSet::wants_exe_hash_for`].
    pub fn match_conn(
        &self,
        conn: &Connection,
        exe_sha256: Option<&str>,
    ) -> Option<(&CompiledRule, Verdict)> {
        self.rules
            .iter()
            .filter(|r| r.enabled)
            .find(|r| r.matches(conn, exe_sha256))
            .map(|r| (r, Verdict::from(r.action)))
    }

    /// Number of compiled rules (enabled or not).
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Evaluate `conn` exactly as [`RuleSet::match_conn`] does, recording
    /// why each rule did or did not decide.
    ///
    /// An explanation that disagrees with enforcement is worse than none, so
    /// this shares everything that can decide the outcome with `match_conn`:
    /// the same `rules` vector in the same order, the same `enabled` filter,
    /// and the same predicate, since [`CompiledRule::matches`] is defined as
    /// [`CompiledRule::first_failing_field`] returning None. The only thing
    /// added here is the reason, which cannot influence the verdict.
    ///
    /// Cost is one pass over the rules plus one allocation per rule for the
    /// trace, which is fine for an operator request and is why the packet
    /// path calls `match_conn` instead.
    pub fn explain(&self, conn: &Connection, exe_sha256: Option<&str>) -> ExplainResult {
        let mut matched: Option<(String, Verdict)> = None;
        let mut trace = Vec::with_capacity(self.rules.len());
        for rule in &self.rules {
            let outcome = if matched.is_some() {
                // First match wins, so these were never consulted. Reporting
                // them as non-matching would invite the operator to "fix" a
                // rule that nothing asked about.
                TraceOutcome::NotReached
            } else if !rule.enabled {
                TraceOutcome::Disabled
            } else {
                match rule.first_failing_field(conn, exe_sha256) {
                    Some(field) => TraceOutcome::NoMatch {
                        field: field.to_string(),
                    },
                    None => {
                        matched = Some((rule.name.clone(), Verdict::from(rule.action)));
                        TraceOutcome::Matched
                    }
                }
            };
            trace.push(RuleTrace {
                name: rule.name.clone(),
                priority: rule.priority,
                outcome,
            });
        }
        // Cheap insurance in tests and debug builds against a future edit
        // that splits the two walks apart again.
        debug_assert_eq!(
            matched.as_ref().map(|(name, verdict)| (name.as_str(), *verdict)),
            self.match_conn(conn, exe_sha256)
                .map(|(rule, verdict)| (rule.name.as_str(), verdict)),
            "explain disagreed with match_conn"
        );
        ExplainResult { matched, trace }
    }

    /// True when some enabled hash-pinning rule could apply to `conn`
    /// (its other criteria match), so hashing the executable can change
    /// the verdict. Keeps binary hashing off the packet path unless a
    /// hash rule is actually in play for this connection.
    pub fn wants_exe_hash_for(&self, conn: &Connection) -> bool {
        self.has_hash_rules
            && self
                .rules
                .iter()
                .any(|r| r.enabled && r.wants_exe_hash() && r.matches_ignoring_hash(conn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hallpass_types::{Action, FlowTuple, Proto, RuleDuration, RuleMatch};
    use std::path::PathBuf;

    fn conn(exe: &str, dst: &str, proto: Proto, domain: Option<&str>, uid: u32) -> Connection {
        Connection {
            tuple: FlowTuple {
                proto,
                src: "10.0.0.1:40000".parse().unwrap(),
                dst: dst.parse().unwrap(),
            },
            uid: Some(uid),
            pid: Some(1),
            exe_path: Some(PathBuf::from(exe)),
            cmdline: None,
            parent_exe: None,
            domain: domain.map(String::from),
            iface: None,
            app_id: None,
            first_seen: None,
        }
    }

    fn rule(name: &str, action: Action, priority: u32, enabled: bool, m: RuleMatch) -> Rule {
        Rule {
            name: name.into(),
            action,
            duration: RuleDuration::Session,
            priority,
            enabled,
            matcher: m,
        }
    }

    fn curl() -> Connection {
        conn(
            "/usr/bin/curl",
            "93.184.216.34:443",
            Proto::Tcp,
            Some("example.org"),
            1000,
        )
    }

    struct Case {
        name: &'static str,
        rules: Vec<Rule>,
        conn: Connection,
        expect: Option<(&'static str, Verdict)>,
    }

    /// The shared corpus: every case feeds both enforcement
    /// ([`table_driven_matching`]) and the explainer
    /// ([`explain_agrees_with_match_conn`]), so a case added for one is
    /// automatically checked against the other.
    fn cases() -> Vec<Case> {
        vec![
            Case {
                name: "higher priority wins",
                rules: vec![
                    rule("low-allow", Action::Allow, 1, true, RuleMatch::default()),
                    rule("high-deny", Action::Deny, 10, true, RuleMatch::default()),
                ],
                conn: curl(),
                expect: Some(("high-deny", Verdict::Deny)),
            },
            Case {
                name: "equal priority ties break by name",
                rules: vec![
                    rule("b-deny", Action::Deny, 5, true, RuleMatch::default()),
                    rule("a-allow", Action::Allow, 5, true, RuleMatch::default()),
                ],
                conn: curl(),
                expect: Some(("a-allow", Verdict::Allow)),
            },
            Case {
                name: "disabled rule skipped",
                rules: vec![
                    rule("off", Action::Deny, 10, false, RuleMatch::default()),
                    rule("on", Action::Allow, 1, true, RuleMatch::default()),
                ],
                conn: curl(),
                expect: Some(("on", Verdict::Allow)),
            },
            Case {
                name: "cidr match",
                rules: vec![rule(
                    "net",
                    Action::Deny,
                    0,
                    true,
                    RuleMatch {
                        dest: Some("93.184.0.0/16".into()),
                        ..Default::default()
                    },
                )],
                conn: curl(),
                expect: Some(("net", Verdict::Deny)),
            },
            Case {
                name: "cidr non-match",
                rules: vec![rule(
                    "net",
                    Action::Deny,
                    0,
                    true,
                    RuleMatch {
                        dest: Some("10.0.0.0/8".into()),
                        ..Default::default()
                    },
                )],
                conn: curl(),
                expect: None,
            },
            Case {
                name: "exe glob match",
                rules: vec![rule(
                    "glob",
                    Action::Allow,
                    0,
                    true,
                    RuleMatch {
                        exe_glob: Some("/usr/bin/*".into()),
                        ..Default::default()
                    },
                )],
                conn: curl(),
                expect: Some(("glob", Verdict::Allow)),
            },
            Case {
                name: "port range match",
                rules: vec![rule(
                    "range",
                    Action::Allow,
                    0,
                    true,
                    RuleMatch {
                        port_range: Some((400, 500)),
                        ..Default::default()
                    },
                )],
                conn: curl(),
                expect: Some(("range", Verdict::Allow)),
            },
            Case {
                name: "port range non-match",
                rules: vec![rule(
                    "range",
                    Action::Allow,
                    0,
                    true,
                    RuleMatch {
                        port_range: Some((1, 100)),
                        ..Default::default()
                    },
                )],
                conn: curl(),
                expect: None,
            },
            Case {
                name: "domain wildcard match",
                rules: vec![rule(
                    "dom",
                    Action::Deny,
                    0,
                    true,
                    RuleMatch {
                        domain: Some("*.example.org".into()),
                        ..Default::default()
                    },
                )],
                conn: conn(
                    "/usr/bin/curl",
                    "1.2.3.4:443",
                    Proto::Tcp,
                    Some("cdn.example.org"),
                    1000,
                ),
                expect: Some(("dom", Verdict::Deny)),
            },
            Case {
                name: "domain rule needs a domain on the connection",
                rules: vec![rule(
                    "dom",
                    Action::Deny,
                    0,
                    true,
                    RuleMatch {
                        domain: Some("*.example.org".into()),
                        ..Default::default()
                    },
                )],
                conn: conn("/usr/bin/curl", "1.2.3.4:443", Proto::Tcp, None, 1000),
                expect: None,
            },
            Case {
                name: "AND semantics: all criteria must hold",
                rules: vec![rule(
                    "and",
                    Action::Allow,
                    0,
                    true,
                    RuleMatch {
                        exe: Some("/usr/bin/curl".into()),
                        port: Some(443),
                        proto: Some(Proto::Udp), // mismatch
                        ..Default::default()
                    },
                )],
                conn: curl(),
                expect: None,
            },
            Case {
                name: "uid and proto match",
                rules: vec![rule(
                    "uid",
                    Action::Reject,
                    0,
                    true,
                    RuleMatch {
                        user: Some(1000),
                        proto: Some(Proto::Tcp),
                        ..Default::default()
                    },
                )],
                conn: curl(),
                expect: Some(("uid", Verdict::Reject)),
            },
            Case {
                name: "invalid rule skipped, valid one still applies",
                rules: vec![
                    rule(
                        "broken",
                        Action::Deny,
                        99,
                        true,
                        RuleMatch {
                            dest: Some("not-an-ip".into()),
                            ..Default::default()
                        },
                    ),
                    rule("ok", Action::Allow, 1, true, RuleMatch::default()),
                ],
                conn: curl(),
                expect: Some(("ok", Verdict::Allow)),
            },
            Case {
                name: "app id match",
                rules: vec![rule(
                    "app",
                    Action::Allow,
                    0,
                    true,
                    RuleMatch {
                        app_id: Some("flatpak:org.mozilla.firefox".into()),
                        ..Default::default()
                    },
                )],
                conn: Connection {
                    app_id: Some("flatpak:org.mozilla.firefox".into()),
                    ..curl()
                },
                expect: Some(("app", Verdict::Allow)),
            },
            Case {
                name: "app id rule needs an app id on the connection",
                rules: vec![rule(
                    "app",
                    Action::Allow,
                    0,
                    true,
                    RuleMatch {
                        app_id: Some("flatpak:org.mozilla.firefox".into()),
                        ..Default::default()
                    },
                )],
                conn: curl(),
                expect: None,
            },
            Case {
                name: "hash-pinned rule does not match without a hash",
                rules: vec![
                    rule(
                        "pinned",
                        Action::Allow,
                        10,
                        true,
                        RuleMatch {
                            exe_sha256: Some("ab".repeat(32)),
                            ..Default::default()
                        },
                    ),
                    rule("fallback", Action::Deny, 1, true, RuleMatch::default()),
                ],
                conn: curl(),
                expect: Some(("fallback", Verdict::Deny)),
            },
        ]
    }

    #[test]
    fn table_driven_matching() {
        for case in cases() {
            let set = RuleSet::compile(&case.rules);
            let got = set
                .match_conn(&case.conn, None)
                .map(|(r, v)| (r.name.clone(), v));
            let want = case.expect.map(|(n, v)| (n.to_string(), v));
            assert_eq!(got, want, "case: {}", case.name);
        }
    }

    /// The explainer must name the deciding rule the enforcement path would
    /// name, for every case in the shared corpus: priority order, the name
    /// tiebreak, disabled rules, and the invalid-rule skip. An explanation
    /// that disagrees with enforcement is worse than none.
    #[test]
    fn explain_agrees_with_match_conn() {
        for case in cases() {
            let set = RuleSet::compile(&case.rules);
            let enforced = set
                .match_conn(&case.conn, None)
                .map(|(r, v)| (r.name.clone(), v));
            let explained = set.explain(&case.conn, None);
            assert_eq!(explained.matched, enforced, "case: {}", case.name);

            // The trace must tell the same story as the verdict: one Matched
            // entry, and it is the deciding rule.
            let flagged: Vec<&str> = explained
                .trace
                .iter()
                .filter(|t| t.outcome == TraceOutcome::Matched)
                .map(|t| t.name.as_str())
                .collect();
            let want: Vec<&str> = enforced.iter().map(|(n, _)| n.as_str()).collect();
            assert_eq!(flagged, want, "case: {}", case.name);
            assert_eq!(
                explained.trace.len(),
                set.rule_count(),
                "every compiled rule is traced, case: {}",
                case.name
            );
        }
    }

    /// The trace distinguishes "did not match" from "was never consulted",
    /// and blames the operand the operator has to edit.
    #[test]
    fn explain_trace_outcomes() {
        struct TraceCase {
            name: &'static str,
            rules: Vec<Rule>,
            expect: Vec<(&'static str, u32, TraceOutcome)>,
        }
        let no_match = |field: &str| TraceOutcome::NoMatch {
            field: field.to_string(),
        };
        let cases = vec![
            TraceCase {
                name: "rules below the decision were not consulted",
                rules: vec![
                    rule("high", Action::Deny, 10, true, RuleMatch::default()),
                    rule("low", Action::Allow, 1, true, RuleMatch::default()),
                ],
                expect: vec![
                    ("high", 10, TraceOutcome::Matched),
                    ("low", 1, TraceOutcome::NotReached),
                ],
            },
            TraceCase {
                name: "a disabled rule is never evaluated",
                rules: vec![
                    rule("off", Action::Deny, 10, false, RuleMatch::default()),
                    rule("on", Action::Allow, 5, true, RuleMatch::default()),
                ],
                expect: vec![
                    ("off", 10, TraceOutcome::Disabled),
                    ("on", 5, TraceOutcome::Matched),
                ],
            },
            TraceCase {
                name: "the first failing operand is named",
                rules: vec![
                    rule(
                        "wrong-port",
                        Action::Deny,
                        10,
                        true,
                        RuleMatch {
                            port: Some(80),
                            ..Default::default()
                        },
                    ),
                    rule(
                        "wrong-exe",
                        Action::Deny,
                        9,
                        true,
                        RuleMatch {
                            exe: Some("/usr/bin/wget".into()),
                            port: Some(443),
                            ..Default::default()
                        },
                    ),
                    rule("catch-all", Action::Allow, 1, true, RuleMatch::default()),
                ],
                expect: vec![
                    ("wrong-port", 10, no_match("port")),
                    ("wrong-exe", 9, no_match("exe")),
                    ("catch-all", 1, TraceOutcome::Matched),
                ],
            },
            TraceCase {
                name: "nothing matches: every enabled rule reports a reason",
                rules: vec![
                    rule(
                        "dom",
                        Action::Deny,
                        10,
                        true,
                        RuleMatch {
                            domain: Some("*.example.com".into()),
                            ..Default::default()
                        },
                    ),
                    rule(
                        "sub",
                        Action::Deny,
                        5,
                        true,
                        RuleMatch {
                            src: Some("192.168.0.0/16".into()),
                            ..Default::default()
                        },
                    ),
                ],
                expect: vec![("dom", 10, no_match("domain")), ("sub", 5, no_match("src"))],
            },
        ];

        for case in cases {
            let set = RuleSet::compile(&case.rules);
            let got: Vec<(String, u32, TraceOutcome)> = set
                .explain(&curl(), None)
                .trace
                .into_iter()
                .map(|t| (t.name, t.priority, t.outcome))
                .collect();
            let want: Vec<(String, u32, TraceOutcome)> = case
                .expect
                .into_iter()
                .map(|(n, p, o)| (n.to_string(), p, o))
                .collect();
            assert_eq!(got, want, "case: {}", case.name);
        }
    }

    /// A hash-pinned rule is explained with the hash the caller supplies,
    /// exactly as the packet path would evaluate it.
    #[test]
    fn explain_uses_the_supplied_hash() {
        let rules = vec![rule(
            "pinned",
            Action::Allow,
            1,
            true,
            RuleMatch {
                exe_sha256: Some("ab".repeat(32)),
                ..Default::default()
            },
        )];
        let set = RuleSet::compile(&rules);
        let hash = "ab".repeat(32);
        assert_eq!(
            set.explain(&curl(), Some(&hash)).matched,
            Some(("pinned".to_string(), Verdict::Allow))
        );
        let other = "cd".repeat(32);
        let missed = set.explain(&curl(), Some(&other));
        assert_eq!(missed.matched, None);
        assert_eq!(
            missed.trace[0].outcome,
            TraceOutcome::NoMatch {
                field: "exe_sha256".to_string()
            }
        );
    }

    #[test]
    fn empty_set() {
        let set = RuleSet::compile(&[]);
        assert_eq!(set.rule_count(), 0);
        assert!(set.match_conn(&curl(), None).is_none());
        let explained = set.explain(&curl(), None);
        assert!(explained.matched.is_none());
        assert!(explained.trace.is_empty());
    }
}

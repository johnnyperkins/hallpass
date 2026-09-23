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
    /// Whether any deciding rule pins an executable hash; precomputed so
    /// the per-packet check is free when the feature is unused.
    has_hash_rules: bool,
    /// Whether a lockdown posture was in force when this was compiled.
    locked_down: bool,
}

impl RuleSet {
    /// Compile `rules` with no lockdown posture in force.
    pub fn compile(rules: &[Rule]) -> RuleSet {
        RuleSet::compile_with_lockdown(rules, None)
    }

    /// Compile `rules`, skipping (with a warning) any that fail validation.
    ///
    /// `lockdown` is the posture's pinned tags, if one is in force. The
    /// suppression is resolved here, once per rebuild, rather than consulted
    /// per packet: the packet path's filter stays one bool test, and the
    /// snapshot a connection is judged against carries its own answer about
    /// whether the posture was on, so a posture change mid-decision cannot
    /// split enrichment from matching.
    pub fn compile_with_lockdown(rules: &[Rule], lockdown: Option<&[String]>) -> RuleSet {
        let mut compiled: Vec<CompiledRule> = rules
            .iter()
            .filter_map(|r| match CompiledRule::compile(r) {
                Ok(mut c) => {
                    if let Some(tags) = lockdown {
                        c.suppressed = !r.active_under_lockdown(tags);
                    }
                    Some(c)
                }
                Err(e) => {
                    tracing::warn!(rule = %r.name, "skipping invalid rule: {e}");
                    None
                }
            })
            .collect();
        // Ties go to the stricter rule, then to the name. By name alone, two
        // prompt answers at the shared prompt priority were ordered by their
        // decimal ids as text, so an allow numbered 10 shadowed a deny
        // numbered 9 while an allow numbered 9 lost to a deny numbered 8.
        compiled.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| strictness(a.action).cmp(&strictness(b.action)))
                .then_with(|| a.name.cmp(&b.name))
        });
        let mut set = RuleSet {
            rules: compiled,
            has_hash_rules: false,
            locked_down: lockdown.is_some(),
        };
        let has_hash_rules = set.deciding_rules().any(CompiledRule::wants_exe_hash);
        set.has_hash_rules = has_hash_rules;
        set
    }

    /// The rules the operator and the posture currently let decide, in
    /// evaluation order.
    ///
    /// The one filter behind the `has_hash_rules` gate, [`RuleSet::match_conn`]
    /// and [`RuleSet::hash_pinning_candidates`], so the gate and the filters
    /// cannot drift into asking different questions.
    fn deciding_rules(&self) -> impl Iterator<Item = &CompiledRule> {
        self.rules.iter().filter(|r| r.deciding())
    }

    /// Whether a lockdown posture was in force when this set was compiled.
    ///
    /// Read from the snapshot the connection is being judged against, not
    /// from the posture itself, so the answer cannot change between deciding
    /// that no rule matched and deciding what to do about it.
    pub fn locked_down(&self) -> bool {
        self.locked_down
    }

    /// How many rules the posture is currently stopping from deciding.
    ///
    /// Enabled ones only: a rule the operator had already disabled decides
    /// nothing either way, and counting it would have a host with a drawer
    /// full of old disabled rules report a posture far wider than the one it
    /// actually applied.
    pub fn suppressed_count(&self) -> u32 {
        self.rules
            .iter()
            .filter(|r| r.enabled && r.suppressed)
            .count() as u32
    }

    /// First deciding rule matching `conn`, with its verdict. `exe_sha256`
    /// is the connection executable's hash if it was computed; pass the
    /// result of gating on [`RuleSet::wants_exe_hash_for`].
    pub fn match_conn(
        &self,
        conn: &Connection,
        exe_sha256: Option<&str>,
    ) -> Option<(&CompiledRule, Verdict)> {
        self.deciding_rules()
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
    /// the same `rules` vector in the same order, the same
    /// [`CompiledRule::deciding`] filter (told apart here as Disabled versus
    /// Suppressed, which cannot change who decides), and the same predicate,
    /// since [`CompiledRule::matches`] is defined as
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
            } else if rule.suppressed {
                // Distinct from Disabled on purpose: the rule is exactly as
                // the operator left it, and what stopped it is a posture
                // they can lift. Reporting it as disabled would send them
                // looking for an `enabled = false` that is not there.
                TraceOutcome::Suppressed
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
            matched
                .as_ref()
                .map(|(name, verdict)| (name.as_str(), *verdict)),
            self.match_conn(conn, exe_sha256)
                .map(|(rule, verdict)| (rule.name.as_str(), verdict)),
            "explain disagreed with match_conn"
        );
        ExplainResult { matched, trace }
    }

    /// True when some deciding hash-pinning rule could apply to `conn`
    /// (its other criteria match), so hashing the executable can change
    /// the verdict. Keeps binary hashing off the packet path unless a
    /// hash rule is actually in play for this connection.
    pub fn wants_exe_hash_for(&self, conn: &Connection) -> bool {
        self.hash_pinning_candidates(conn).next().is_some()
    }

    /// Names of deciding rules that `conn` satisfies in every field except
    /// the executable hash, which it has and which does not match, at most
    /// `max` of them in evaluation order.
    ///
    /// `exe_sha256` is the hash policy was actually evaluated against. With
    /// `None` this answers nothing, deliberately: the connection reached a
    /// prompt without a hash ever being computed (no rule pinned one, or the
    /// binary was too large or unreadable), and "no hash" is not a mismatch.
    /// Reporting one would put the loudest warning a prompt can show -
    /// "the binary asking is not the one your rule pins" - above a
    /// connection whose binary nobody ever looked at, and, when the fallback
    /// path did produce a hash for display, above the pinned hash itself.
    ///
    /// The comparison is [`CompiledRule::matches`], the predicate that
    /// declined this connection in the first place, so a named rule is
    /// always one that really did refuse this binary.
    ///
    /// Names rather than rules: this is read by a person on their way to look
    /// one up.
    pub fn hash_mismatch_rules(
        &self,
        conn: &Connection,
        exe_sha256: Option<&str>,
        max: usize,
    ) -> Vec<String> {
        let Some(hash) = exe_sha256 else {
            return Vec::new();
        };
        self.hash_pinning_candidates(conn)
            .filter(|r| !r.matches(conn, Some(hash)))
            .take(max)
            .map(|r| r.name.clone())
            .collect()
    }

    /// Deciding rules whose hash operand is the only thing standing between
    /// `conn` and their verdict, in evaluation order.
    ///
    /// One definition for two questions the packet path and the prompt path
    /// must not answer differently: "is a hash worth computing for this
    /// connection" and "which rules did the hash it produced miss". Written
    /// twice, a prompt could name rules the engine never consulted, or stay
    /// silent about the ones it did.
    ///
    /// [`CompiledRule::deciding`], not `enabled`, and for the same reason
    /// [`RuleSet::match_conn`] filters on it: a rule a lockdown posture
    /// suppresses decides nothing, so hashing a binary on its account is
    /// work the verdict cannot use, and naming it as a hash mismatch would
    /// point the operator at a rule that never looked at their binary. It is
    /// also what the `has_hash_rules` gate above is computed over, and the
    /// gate and the filter have to ask the same question.
    fn hash_pinning_candidates<'a>(
        &'a self,
        conn: &'a Connection,
    ) -> impl Iterator<Item = &'a CompiledRule> {
        // Precomputed at compile time, so a set with no hash-pinning rule in
        // it costs neither path a scan to find that out.
        self.has_hash_rules
            .then(|| {
                self.deciding_rules()
                    .filter(move |r| r.wants_exe_hash() && r.matches_ignoring_hash(conn))
            })
            .into_iter()
            .flatten()
    }
}

/// Order among rules of equal priority: a refusal before an allow.
fn strictness(action: hallpass_types::Action) -> u8 {
    match action {
        hallpass_types::Action::Reject => 0,
        hallpass_types::Action::Deny => 1,
        hallpass_types::Action::Allow => 2,
    }
}

#[cfg(test)]
mod tests {

    /// Equal priority: the refusal wins, whatever the names say.
    #[test]
    fn a_tie_goes_to_the_stricter_rule() {
        let rule = |name: &str, action| Rule {
            name: name.into(),
            action,
            duration: RuleDuration::Forever,
            priority: 50,
            enabled: true,
            tags: Vec::new(),
            matcher: RuleMatch::default(),
        };
        let set = RuleSet::compile(&[
            rule("prompt-curl-x-10", Action::Allow),
            rule("prompt-curl-x-9", Action::Deny),
        ]);
        let conn = conn("/usr/bin/curl", "1.1.1.1:443", Proto::Tcp, None, 1000);
        let (winner, verdict) = set.match_conn(&conn, None).unwrap();
        assert_eq!(winner.name, "prompt-curl-x-9");
        assert_eq!(verdict, Verdict::Deny);
    }
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
            tags: Vec::new(),
            matcher: m,
        }
    }

    /// An allow rule that pins `/usr/bin/curl` to the `"ab".repeat(32)`
    /// binary, the shape every hash-path test builds.
    fn pinned(name: &str, priority: u32, enabled: bool, tags: &[&str]) -> Rule {
        Rule {
            tags: tags.iter().map(|t| (*t).to_string()).collect(),
            ..rule(
                name,
                Action::Allow,
                priority,
                enabled,
                RuleMatch {
                    exe: Some(PathBuf::from("/usr/bin/curl")),
                    exe_sha256: Some("ab".repeat(32)),
                    ..Default::default()
                },
            )
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
                name: "equal priority ties go to the refusal",
                rules: vec![
                    rule("b-deny", Action::Deny, 5, true, RuleMatch::default()),
                    rule("a-allow", Action::Allow, 5, true, RuleMatch::default()),
                ],
                conn: curl(),
                expect: Some(("b-deny", Verdict::Deny)),
            },
            Case {
                name: "equal priority and action ties break by name",
                rules: vec![
                    rule("b-deny", Action::Deny, 5, true, RuleMatch::default()),
                    rule("a-deny", Action::Deny, 5, true, RuleMatch::default()),
                ],
                conn: curl(),
                expect: Some(("a-deny", Verdict::Deny)),
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

    /// What a prompt tells the operator when a hash-pinned rule was written
    /// for this program and the binary running now is not the one it pins.
    #[test]
    fn hash_mismatch_rules_names_the_rules_the_binary_missed() {
        let rules = vec![
            pinned("pin-high", 10, true, &[]),
            pinned("pin-low", 1, true, &[]),
            pinned("pin-off", 20, false, &[]),
            // Pins a hash but is not about this program at all.
            rule(
                "other-exe",
                Action::Allow,
                30,
                true,
                RuleMatch {
                    exe: Some(PathBuf::from("/usr/bin/wget")),
                    exe_sha256: Some("cd".repeat(32)),
                    ..Default::default()
                },
            ),
            // About this program, but decides without a hash, so it is not a
            // rule the operator is being asked to go and look at.
            rule(
                "no-hash",
                Action::Deny,
                40,
                true,
                RuleMatch {
                    exe: Some(PathBuf::from("/usr/bin/curl")),
                    ..Default::default()
                },
            ),
        ];
        let set = RuleSet::compile(&rules);
        let pinned_hash = "ab".repeat(32);
        let other_hash = "cd".repeat(32);

        assert_eq!(
            set.hash_mismatch_rules(&curl(), Some(&other_hash), 4),
            ["pin-high", "pin-low"],
            "only enabled hash-pinning rules that match this connection otherwise"
        );
        assert_eq!(
            set.hash_mismatch_rules(&curl(), Some(&other_hash), 1),
            ["pin-high"],
            "capped in evaluation order, so the rule that would have decided comes first"
        );

        // The whole point of the warning: it must not fire against a binary
        // that satisfies the rule. Such a connection would normally have been
        // decided rather than prompted, but a lower-priority deny can prompt
        // it anyway, and either way the sentence would be a lie.
        assert!(
            set.hash_mismatch_rules(&curl(), Some(&pinned_hash), 4)
                .is_empty(),
            "a binary that has the pinned hash mismatches nothing"
        );

        // No hash is not a mismatch. The connection reached a prompt without
        // one being computed (nothing pinned, or the binary was too large or
        // unreadable), and claiming tampering there is the loudest thing this
        // window can say about something nobody looked at.
        assert!(
            set.hash_mismatch_rules(&curl(), None, 4).is_empty(),
            "an uncomputed hash is not a failed comparison"
        );

        let wget = conn(
            "/usr/bin/wget",
            "93.184.216.34:443",
            Proto::Tcp,
            Some("example.org"),
            1000,
        );
        assert_eq!(
            set.hash_mismatch_rules(&wget, Some(&pinned_hash), 4),
            ["other-exe"],
            "the rule for this exe pins cd..cd, and this binary hashes to ab..ab"
        );
        assert!(set
            .hash_mismatch_rules(&wget, Some(&other_hash), 4)
            .is_empty());
    }

    /// A rule a lockdown posture suppresses decides nothing, so it must not
    /// pull a binary onto the hashing path or be named as a hash the
    /// operator's binary missed. Both questions read
    /// `hash_pinning_candidates`, and both used to filter on `enabled`
    /// alone while the `has_hash_rules` gate beside them already filtered
    /// on `deciding()` - so one deciding pin was enough to let every
    /// suppressed pin in the set back into the answer.
    #[test]
    fn a_suppressed_pin_neither_hashes_nor_is_named() {
        let other_hash = "cd".repeat(32);

        // Posture pins `keep`, so `drop-me` is suppressed while it is on.
        let rules = vec![
            pinned("keep", 10, true, &["keep"]),
            pinned("drop-me", 10, true, &[]),
        ];
        let posture = vec!["keep".to_string()];
        let set = RuleSet::compile_with_lockdown(&rules, Some(&posture));
        assert_eq!(set.suppressed_count(), 1);
        assert_eq!(
            set.hash_mismatch_rules(&curl(), Some(&other_hash), 4),
            ["keep"],
            "only the rule the posture still lets decide is named"
        );

        // With every pin suppressed there is nothing a hash can change, so
        // the packet path must not read the binary at all.
        let all_suppressed =
            RuleSet::compile_with_lockdown(&rules, Some(&["unrelated".to_string()]));
        assert_eq!(all_suppressed.suppressed_count(), 2);
        assert!(
            !all_suppressed.wants_exe_hash_for(&curl()),
            "a posture that suppresses every pin takes hashing off the packet path"
        );
        assert!(all_suppressed
            .hash_mismatch_rules(&curl(), Some(&other_hash), 4)
            .is_empty());

        // The same set with no posture in force answers for both rules.
        let unlocked = RuleSet::compile(&rules);
        assert_eq!(
            unlocked.hash_mismatch_rules(&curl(), Some(&other_hash), 4),
            ["drop-me", "keep"],
            "ties break by name, and nothing is suppressed"
        );
        assert!(unlocked.wants_exe_hash_for(&curl()));
    }

    /// A set with no hash-pinning rule in it has nothing to say about a
    /// hash, and must not pay a scan per prompt to find that out.
    #[test]
    fn hash_mismatch_rules_is_empty_without_hash_rules() {
        let rules = vec![rule(
            "plain",
            Action::Allow,
            10,
            true,
            RuleMatch {
                exe: Some(PathBuf::from("/usr/bin/curl")),
                ..Default::default()
            },
        )];
        let set = RuleSet::compile(&rules);
        let hash = "ab".repeat(32);
        assert!(set.hash_mismatch_rules(&curl(), Some(&hash), 4).is_empty());
        assert!(!set.wants_exe_hash_for(&curl()));
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

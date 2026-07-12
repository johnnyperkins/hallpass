//! First-match-wins rule evaluation over a compiled, sorted rule set.

use hallpass_types::{Connection, Rule, Verdict};

use super::model::CompiledRule;

/// Immutable snapshot of compiled rules, ordered for evaluation:
/// higher priority first, ties broken by name for determinism.
pub struct RuleSet {
    rules: Vec<CompiledRule>,
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
        RuleSet { rules: compiled }
    }

    /// First enabled rule matching `conn`, with its verdict.
    pub fn match_conn(&self, conn: &Connection) -> Option<(&CompiledRule, Verdict)> {
        self.rules
            .iter()
            .filter(|r| r.enabled)
            .find(|r| r.matches(conn))
            .map(|r| (r, Verdict::from(r.action)))
    }

    /// Number of compiled rules (enabled or not).
    pub fn rule_count(&self) -> usize {
        self.rules.len()
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
            domain: domain.map(String::from),
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

    #[test]
    fn table_driven_matching() {
        let cases = vec![
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
        ];

        for case in cases {
            let set = RuleSet::compile(&case.rules);
            let got = set
                .match_conn(&case.conn)
                .map(|(r, v)| (r.name.clone(), v));
            let want = case.expect.map(|(n, v)| (n.to_string(), v));
            assert_eq!(got, want, "case: {}", case.name);
        }
    }

    #[test]
    fn empty_set() {
        let set = RuleSet::compile(&[]);
        assert_eq!(set.rule_count(), 0);
        assert!(set.match_conn(&curl()).is_none());
    }
}

//! Compiled form of a rule: match fields pre-parsed for fast evaluation.

use std::path::PathBuf;

use globset::{Glob, GlobMatcher};
use ipnet::IpNet;
use hallpass_types::{Action, Connection, Proto, Rule};

/// Domain pattern from a rule's `domain` field.
#[derive(Debug, Clone)]
pub enum DomainPattern {
    /// Exact match, e.g. "example.org".
    Exact(String),
    /// "*.example.org": matches the suffix itself and any subdomain.
    Suffix(String),
}

impl DomainPattern {
    fn parse(raw: &str) -> DomainPattern {
        let lower = raw.to_ascii_lowercase();
        match lower.strip_prefix("*.") {
            Some(suffix) => DomainPattern::Suffix(suffix.to_string()),
            None => DomainPattern::Exact(lower),
        }
    }

    /// Case-insensitive match without allocating (per-packet path).
    fn matches(&self, domain: &str) -> bool {
        match self {
            DomainPattern::Exact(want) => domain.eq_ignore_ascii_case(want),
            DomainPattern::Suffix(suffix) => {
                if domain.eq_ignore_ascii_case(suffix) {
                    return true;
                }
                // Subdomain: "<head>.<suffix>" split at a char boundary.
                let Some(split) = domain.len().checked_sub(suffix.len()) else {
                    return false;
                };
                match (domain.get(..split), domain.get(split..)) {
                    (Some(head), Some(tail)) => {
                        head.ends_with('.') && tail.eq_ignore_ascii_case(suffix)
                    }
                    _ => false,
                }
            }
        }
    }
}

/// A rule with its match criteria pre-parsed. Invalid criteria are caught
/// at compile time so the hot path never parses strings.
pub struct CompiledRule {
    pub name: String,
    pub action: Action,
    pub priority: u32,
    pub enabled: bool,
    exe: Option<PathBuf>,
    exe_glob: Option<GlobMatcher>,
    /// Lowercase hex; validated at compile time.
    exe_sha256: Option<String>,
    dest: Option<IpNet>,
    port: Option<u16>,
    port_range: Option<(u16, u16)>,
    domain: Option<DomainPattern>,
    user: Option<u32>,
    proto: Option<Proto>,
    domains_file: Option<std::sync::Arc<super::lists::DomainSet>>,
    ips_file: Option<std::sync::Arc<super::lists::IpSet>>,
    hashes_file: Option<std::sync::Arc<super::lists::HashSet256>>,
    cmdline_contains: Option<String>,
    parent_exe: Option<PathBuf>,
    src: Option<IpNet>,
    src_port: Option<u16>,
    iface: Option<String>,
}

/// Parse an IP or CIDR match field (a bare address becomes a host net).
fn parse_net(field: &str, raw: &str) -> Result<IpNet, String> {
    raw.parse::<IpNet>()
        .or_else(|_| raw.parse::<std::net::IpAddr>().map(IpNet::from))
        .map_err(|e| format!("bad {field} {raw:?}: {e}"))
}

impl CompiledRule {
    /// Compile a rule, validating cidr/glob/range fields.
    pub fn compile(rule: &Rule) -> Result<CompiledRule, String> {
        let m = &rule.matcher;
        // A criteria-free matcher matches every connection. That is a valid
        // thing to want (a final catch-all), but it is never a thing to want
        // by accident, so say so at a level the operator will see.
        if *m == hallpass_types::RuleMatch::default() {
            tracing::warn!(
                rule = %rule.name,
                action = ?rule.action,
                priority = rule.priority,
                "rule has no match criteria and will match every connection"
            );
        }
        let dest = m.dest.as_deref().map(|s| parse_net("dest", s)).transpose()?;
        let src = m.src.as_deref().map(|s| parse_net("src", s)).transpose()?;
        let exe_glob = match &m.exe_glob {
            None => None,
            Some(g) => Some(
                Glob::new(g)
                    .map_err(|e| format!("bad exe_glob {g:?}: {e}"))?
                    .compile_matcher(),
            ),
        };
        if let Some((lo, hi)) = m.port_range {
            if lo > hi {
                return Err(format!("bad port_range {lo}-{hi}: start exceeds end"));
            }
        }
        let exe_sha256 = m
            .exe_sha256
            .as_deref()
            .map(super::lists::parse_sha256_hex)
            .transpose()
            .map_err(|e| format!("bad exe_sha256: {e}"))?;
        let domains_file = m
            .domains_file
            .as_deref()
            .map(super::lists::DomainSet::load)
            .transpose()?;
        let ips_file = m.ips_file.as_deref().map(super::lists::IpSet::load).transpose()?;
        let hashes_file = m
            .hashes_file
            .as_deref()
            .map(super::lists::HashSet256::load)
            .transpose()?;
        Ok(CompiledRule {
            name: rule.name.clone(),
            action: rule.action,
            priority: rule.priority,
            enabled: rule.enabled,
            exe: m.exe.clone(),
            exe_glob,
            exe_sha256,
            dest,
            port: m.port,
            port_range: m.port_range,
            domain: m.domain.as_deref().map(DomainPattern::parse),
            user: m.user,
            proto: m.proto,
            domains_file,
            ips_file,
            hashes_file,
            cmdline_contains: m.cmdline_contains.clone(),
            parent_exe: m.parent_exe.clone(),
            src,
            src_port: m.src_port,
            iface: m.iface.clone(),
        })
    }

    /// True when this rule matches on the executable hash. The packet path
    /// uses this (via [`RuleSet::wants_exe_hash_for`]) to hash a binary
    /// only when some hash-pinning rule could actually apply.
    ///
    /// [`RuleSet::wants_exe_hash_for`]: super::engine::RuleSet::wants_exe_hash_for
    pub fn wants_exe_hash(&self) -> bool {
        self.exe_sha256.is_some() || self.hashes_file.is_some()
    }

    /// True when every present criterion matches (AND semantics). A rule
    /// with no criteria matches everything. `exe_sha256` is the hash of
    /// the connection's executable, if it was computed (lowercase hex).
    ///
    /// Inlined so the packet path keeps the shape it had before the
    /// explainer shared this predicate: a discarded `&'static str`.
    #[inline]
    pub fn matches(&self, conn: &Connection, exe_sha256: Option<&str>) -> bool {
        self.first_failing_field(conn, exe_sha256).is_none()
    }

    /// The first criterion `conn` fails, named as the key the operator would
    /// edit in the rule file (`exe`, `port_range`, `hashes_file`, ...), or
    /// None when the rule matches.
    ///
    /// This is the only implementation of the match predicate: [`matches`]
    /// is defined as "nothing failed", so the policy explainer cannot blame
    /// a field that enforcement disagreed about. A `&'static str` keeps it
    /// allocation-free, so the packet path pays nothing for the detail.
    ///
    /// [`matches`]: CompiledRule::matches
    pub fn first_failing_field(
        &self,
        conn: &Connection,
        exe_sha256: Option<&str>,
    ) -> Option<&'static str> {
        if let Some(field) = self.first_failing_non_hash_field(conn) {
            return Some(field);
        }
        if let Some(want) = &self.exe_sha256 {
            // Hashes are produced lowercase on both sides; direct compare.
            match exe_sha256 {
                Some(have) if have == want.as_str() => {}
                _ => return Some("exe_sha256"),
            }
        }
        if let Some(hashes) = &self.hashes_file {
            match exe_sha256 {
                Some(have) if hashes.contains(have) => {}
                _ => return Some("hashes_file"),
            }
        }
        None
    }

    /// All criteria except the executable hash. Split out so the packet
    /// path can decide whether hashing is worth doing for a connection
    /// before paying for it.
    #[inline]
    pub fn matches_ignoring_hash(&self, conn: &Connection) -> bool {
        self.first_failing_non_hash_field(conn).is_none()
    }

    /// [`CompiledRule::first_failing_field`] without the hash criteria, which
    /// are the ones that need a hash the caller may not have computed yet.
    fn first_failing_non_hash_field(&self, conn: &Connection) -> Option<&'static str> {
        let dst = conn.tuple.dst;
        if let Some(exe) = &self.exe {
            if conn.exe_path.as_deref() != Some(exe) {
                return Some("exe");
            }
        }
        if let Some(glob) = &self.exe_glob {
            match &conn.exe_path {
                Some(path) if glob.is_match(path) => {}
                _ => return Some("exe_glob"),
            }
        }
        if let Some(net) = &self.dest {
            if !net.contains(&dst.ip()) {
                return Some("dest");
            }
        }
        if let Some(port) = self.port {
            if dst.port() != port {
                return Some("port");
            }
        }
        if let Some((lo, hi)) = self.port_range {
            if !(lo..=hi).contains(&dst.port()) {
                return Some("port_range");
            }
        }
        if let Some(pattern) = &self.domain {
            match &conn.domain {
                Some(d) if pattern.matches(d) => {}
                _ => return Some("domain"),
            }
        }
        if let Some(user) = self.user {
            if conn.uid != Some(user) {
                return Some("user");
            }
        }
        if let Some(proto) = self.proto {
            if conn.tuple.proto != proto {
                return Some("proto");
            }
        }
        if let Some(domains) = &self.domains_file {
            match &conn.domain {
                Some(d) if domains.contains(d) => {}
                _ => return Some("domains_file"),
            }
        }
        if let Some(ips) = &self.ips_file {
            if !ips.contains(&dst.ip()) {
                return Some("ips_file");
            }
        }
        if let Some(needle) = &self.cmdline_contains {
            match &conn.cmdline {
                Some(cmdline) if cmdline.contains(needle.as_str()) => {}
                _ => return Some("cmdline_contains"),
            }
        }
        if let Some(parent) = &self.parent_exe {
            if conn.parent_exe.as_deref() != Some(parent) {
                return Some("parent_exe");
            }
        }
        if let Some(net) = &self.src {
            if !net.contains(&conn.tuple.src.ip()) {
                return Some("src");
            }
        }
        if let Some(port) = self.src_port {
            if conn.tuple.src.port() != port {
                return Some("src_port");
            }
        }
        if let Some(iface) = &self.iface {
            match &conn.iface {
                Some(have) if have == iface => {}
                _ => return Some("iface"),
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hallpass_types::{RuleDuration, RuleMatch};

    fn rule_with(matcher: RuleMatch) -> Rule {
        Rule {
            name: "t".into(),
            action: Action::Allow,
            duration: RuleDuration::Session,
            priority: 0,
            enabled: true,
            matcher,
        }
    }

    #[test]
    fn bad_cidr_and_glob_rejected() {
        let r = rule_with(RuleMatch {
            dest: Some("300.1.2.3/8".into()),
            ..Default::default()
        });
        assert!(CompiledRule::compile(&r).is_err());
        let r = rule_with(RuleMatch {
            exe_glob: Some("/usr/[bin".into()),
            ..Default::default()
        });
        assert!(CompiledRule::compile(&r).is_err());
        let r = rule_with(RuleMatch {
            port_range: Some((2000, 1000)),
            ..Default::default()
        });
        assert!(CompiledRule::compile(&r).is_err());
    }

    #[test]
    fn exe_sha256_validation_and_matching() {
        // Bad lengths / non-hex rejected at compile time.
        for bad in ["short", &"g".repeat(64), &"a".repeat(63)] {
            let r = rule_with(RuleMatch {
                exe_sha256: Some(bad.to_string()),
                ..Default::default()
            });
            assert!(CompiledRule::compile(&r).is_err(), "accepted {bad:?}");
        }

        // Uppercase rule hash matches lowercase connection hash.
        let hash = "AB".repeat(32);
        let r = rule_with(RuleMatch {
            exe_sha256: Some(hash.clone()),
            ..Default::default()
        });
        let compiled = CompiledRule::compile(&r).unwrap();
        assert!(compiled.wants_exe_hash());
        let conn = Connection {
            tuple: hallpass_types::FlowTuple {
                proto: Proto::Tcp,
                src: "10.0.0.1:40000".parse().unwrap(),
                dst: "1.2.3.4:443".parse().unwrap(),
            },
            uid: None,
            pid: None,
            exe_path: None,
            cmdline: None,
            parent_exe: None,
            domain: None,
            iface: None,
        };
        assert!(compiled.matches(&conn, Some(&"ab".repeat(32))));
        // Wrong or missing hash: no match, but other criteria still do.
        assert!(!compiled.matches(&conn, Some(&"cd".repeat(32))));
        assert!(!compiled.matches(&conn, None));
        assert!(compiled.matches_ignoring_hash(&conn));
    }

    #[test]
    fn list_files_compile_and_match() {
        use crate::testutil::TestDir;
        let dir = TestDir::new("model-lists");
        let domains = dir.path().join("ads.list");
        std::fs::write(&domains, "0.0.0.0 ads.example.com\n").unwrap();
        let ips = dir.path().join("bad.list");
        std::fs::write(&ips, "10.0.0.0/8\n").unwrap();

        let conn = |domain: Option<&str>, dst: &str| Connection {
            tuple: hallpass_types::FlowTuple {
                proto: Proto::Tcp,
                src: "10.0.0.1:40000".parse().unwrap(),
                dst: dst.parse().unwrap(),
            },
            uid: None,
            pid: None,
            exe_path: None,
            cmdline: None,
            parent_exe: None,
            domain: domain.map(String::from),
            iface: None,
        };

        let r = rule_with(RuleMatch {
            domains_file: Some(domains),
            ..Default::default()
        });
        let compiled = CompiledRule::compile(&r).unwrap();
        assert!(compiled.matches(&conn(Some("ads.example.com"), "1.2.3.4:443"), None));
        assert!(!compiled.matches(&conn(Some("other.example.com"), "1.2.3.4:443"), None));
        assert!(!compiled.matches(&conn(None, "1.2.3.4:443"), None));

        let r = rule_with(RuleMatch {
            ips_file: Some(ips),
            ..Default::default()
        });
        let compiled = CompiledRule::compile(&r).unwrap();
        assert!(compiled.matches(&conn(None, "10.5.5.5:443"), None));
        assert!(!compiled.matches(&conn(None, "1.2.3.4:443"), None));

        // Missing list file: rule fails to compile (skipped with warning).
        let r = rule_with(RuleMatch {
            hashes_file: Some(dir.path().join("nope.sha256")),
            ..Default::default()
        });
        assert!(CompiledRule::compile(&r).is_err());

        // A hashes_file makes the rule want executable hashing.
        let hashes = dir.path().join("h.sha256");
        std::fs::write(&hashes, format!("{}\n", "ab".repeat(32))).unwrap();
        let r = rule_with(RuleMatch {
            hashes_file: Some(hashes),
            ..Default::default()
        });
        let compiled = CompiledRule::compile(&r).unwrap();
        assert!(compiled.wants_exe_hash());
        assert!(compiled.matches(&conn(None, "1.2.3.4:443"), Some(&"ab".repeat(32))));
        assert!(!compiled.matches(&conn(None, "1.2.3.4:443"), Some(&"cd".repeat(32))));
        assert!(!compiled.matches(&conn(None, "1.2.3.4:443"), None));
    }

    #[test]
    fn new_operand_matching() {
        let conn = Connection {
            tuple: hallpass_types::FlowTuple {
                proto: Proto::Tcp,
                src: "192.168.1.5:40000".parse().unwrap(),
                dst: "1.2.3.4:443".parse().unwrap(),
            },
            uid: Some(1000),
            pid: Some(1),
            exe_path: Some("/usr/bin/python3".into()),
            cmdline: Some("python3 /opt/backup.py --full".into()),
            parent_exe: Some("/usr/bin/bash".into()),
            domain: None,
            iface: Some("wg0".into()),
        };
        let check = |m: RuleMatch, expect: bool| {
            let compiled = CompiledRule::compile(&rule_with(m)).unwrap();
            assert_eq!(compiled.matches(&conn, None), expect);
        };

        check(RuleMatch { cmdline_contains: Some("backup.py".into()), ..Default::default() }, true);
        check(RuleMatch { cmdline_contains: Some("restore.py".into()), ..Default::default() }, false);
        check(RuleMatch { parent_exe: Some("/usr/bin/bash".into()), ..Default::default() }, true);
        check(RuleMatch { parent_exe: Some("/usr/bin/zsh".into()), ..Default::default() }, false);
        check(RuleMatch { src: Some("192.168.1.0/24".into()), ..Default::default() }, true);
        check(RuleMatch { src: Some("10.0.0.0/8".into()), ..Default::default() }, false);
        check(RuleMatch { src_port: Some(40000), ..Default::default() }, true);
        check(RuleMatch { src_port: Some(40001), ..Default::default() }, false);
        check(RuleMatch { iface: Some("wg0".into()), ..Default::default() }, true);
        check(RuleMatch { iface: Some("eth0".into()), ..Default::default() }, false);

        // Absent connection data never matches a present criterion.
        let mut bare = conn.clone();
        bare.cmdline = None;
        bare.parent_exe = None;
        bare.iface = None;
        let m = CompiledRule::compile(&rule_with(RuleMatch {
            cmdline_contains: Some("x".into()),
            ..Default::default()
        }))
        .unwrap();
        assert!(!m.matches(&bare, None));

        // Bad src rejected at compile time.
        assert!(CompiledRule::compile(&rule_with(RuleMatch {
            src: Some("not-an-ip".into()),
            ..Default::default()
        }))
        .is_err());
    }

    /// The reported field is the TOML key the operator has to edit, and it
    /// is the *first* failing one so the report is deterministic. A name
    /// that drifts from the key (an internal field name, say) sends the
    /// operator looking for something their rule file does not contain.
    #[test]
    fn first_failing_field_names_the_toml_key() {
        let conn = Connection {
            tuple: hallpass_types::FlowTuple {
                proto: Proto::Tcp,
                src: "192.168.1.5:40000".parse().unwrap(),
                dst: "1.2.3.4:443".parse().unwrap(),
            },
            uid: Some(1000),
            pid: Some(1),
            exe_path: Some("/usr/bin/curl".into()),
            cmdline: Some("curl https://example.org".into()),
            parent_exe: Some("/usr/bin/bash".into()),
            domain: Some("example.org".into()),
            iface: Some("wg0".into()),
        };

        struct Case {
            name: &'static str,
            matcher: RuleMatch,
            expect: Option<&'static str>,
        }
        let m = RuleMatch::default;
        let cases = vec![
            Case { name: "no criteria matches", matcher: m(), expect: None },
            Case {
                name: "exe",
                matcher: RuleMatch { exe: Some("/usr/bin/wget".into()), ..m() },
                expect: Some("exe"),
            },
            Case {
                name: "exe_glob",
                matcher: RuleMatch { exe_glob: Some("/opt/*".into()), ..m() },
                expect: Some("exe_glob"),
            },
            Case {
                name: "exe_sha256",
                matcher: RuleMatch { exe_sha256: Some("ab".repeat(32)), ..m() },
                expect: Some("exe_sha256"),
            },
            Case {
                name: "dest",
                matcher: RuleMatch { dest: Some("10.0.0.0/8".into()), ..m() },
                expect: Some("dest"),
            },
            Case {
                name: "port",
                matcher: RuleMatch { port: Some(80), ..m() },
                expect: Some("port"),
            },
            Case {
                name: "port_range",
                matcher: RuleMatch { port_range: Some((1, 100)), ..m() },
                expect: Some("port_range"),
            },
            Case {
                name: "domain",
                matcher: RuleMatch { domain: Some("*.example.com".into()), ..m() },
                expect: Some("domain"),
            },
            Case {
                name: "user",
                matcher: RuleMatch { user: Some(0), ..m() },
                expect: Some("user"),
            },
            Case {
                name: "proto",
                matcher: RuleMatch { proto: Some(Proto::Udp), ..m() },
                expect: Some("proto"),
            },
            Case {
                name: "cmdline_contains",
                matcher: RuleMatch { cmdline_contains: Some("wget".into()), ..m() },
                expect: Some("cmdline_contains"),
            },
            Case {
                name: "parent_exe",
                matcher: RuleMatch { parent_exe: Some("/usr/bin/zsh".into()), ..m() },
                expect: Some("parent_exe"),
            },
            Case {
                name: "src",
                matcher: RuleMatch { src: Some("10.0.0.0/8".into()), ..m() },
                expect: Some("src"),
            },
            Case {
                name: "src_port",
                matcher: RuleMatch { src_port: Some(1234), ..m() },
                expect: Some("src_port"),
            },
            Case {
                name: "iface",
                matcher: RuleMatch { iface: Some("eth0".into()), ..m() },
                expect: Some("iface"),
            },
            Case {
                name: "earliest failing operand wins over later ones",
                matcher: RuleMatch {
                    dest: Some("10.0.0.0/8".into()),
                    port: Some(80),
                    proto: Some(Proto::Udp),
                    ..m()
                },
                expect: Some("dest"),
            },
            Case {
                name: "a satisfied operand is not blamed",
                matcher: RuleMatch { port: Some(443), user: Some(0), ..m() },
                expect: Some("user"),
            },
        ];

        for case in cases {
            let compiled = CompiledRule::compile(&rule_with(case.matcher)).unwrap();
            let got = compiled.first_failing_field(&conn, None);
            assert_eq!(got, case.expect, "case: {}", case.name);
            // matches() is this method's is_none(), so they cannot disagree;
            // assert it anyway to catch a future re-split.
            assert_eq!(
                compiled.matches(&conn, None),
                case.expect.is_none(),
                "case: {}",
                case.name
            );
        }
    }

    /// The list-file operands are reported by their own keys, and a hash
    /// operand is only blamed once the non-hash criteria have passed.
    #[test]
    fn first_failing_field_for_list_operands() {
        use crate::testutil::TestDir;
        let dir = TestDir::new("model-fail-fields");
        let domains = dir.path().join("ads.list");
        std::fs::write(&domains, "ads.example.com\n").unwrap();
        let ips = dir.path().join("bad.list");
        std::fs::write(&ips, "10.0.0.0/8\n").unwrap();
        let hashes = dir.path().join("h.sha256");
        std::fs::write(&hashes, format!("{}\n", "ab".repeat(32))).unwrap();

        let conn = Connection {
            tuple: hallpass_types::FlowTuple {
                proto: Proto::Tcp,
                src: "10.0.0.1:40000".parse().unwrap(),
                dst: "1.2.3.4:443".parse().unwrap(),
            },
            uid: None,
            pid: None,
            exe_path: None,
            cmdline: None,
            parent_exe: None,
            domain: Some("example.org".into()),
            iface: None,
        };

        let compiled = CompiledRule::compile(&rule_with(RuleMatch {
            domains_file: Some(domains),
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(compiled.first_failing_field(&conn, None), Some("domains_file"));

        let compiled = CompiledRule::compile(&rule_with(RuleMatch {
            ips_file: Some(ips),
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(compiled.first_failing_field(&conn, None), Some("ips_file"));

        // port fails first, so the missing hash is not what the operator
        // is told to fix.
        let compiled = CompiledRule::compile(&rule_with(RuleMatch {
            port: Some(80),
            hashes_file: Some(hashes),
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(compiled.first_failing_field(&conn, None), Some("port"));
        let compiled = CompiledRule::compile(&rule_with(RuleMatch {
            port: Some(443),
            hashes_file: Some(dir.path().join("h.sha256")),
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(compiled.first_failing_field(&conn, None), Some("hashes_file"));
        assert_eq!(compiled.first_failing_field(&conn, Some(&"ab".repeat(32))), None);
    }

    #[test]
    fn plain_ip_dest_compiles_as_host_net() {
        let r = rule_with(RuleMatch {
            dest: Some("1.2.3.4".into()),
            ..Default::default()
        });
        assert!(CompiledRule::compile(&r).is_ok());
    }

    #[test]
    fn domain_pattern_semantics() {
        let exact = DomainPattern::parse("Example.org");
        assert!(exact.matches("example.org"));
        assert!(exact.matches("EXAMPLE.ORG"));
        assert!(!exact.matches("sub.example.org"));

        let wild = DomainPattern::parse("*.example.org");
        assert!(wild.matches("example.org"));
        assert!(wild.matches("a.example.org"));
        assert!(wild.matches("a.b.example.org"));
        assert!(!wild.matches("evilexample.org"));
        assert!(!wild.matches("example.org.evil.com"));
    }
}

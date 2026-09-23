//! Compiled form of a rule: match fields pre-parsed for fast evaluation.

use std::path::PathBuf;

use globset::GlobMatcher;
use hallpass_types::{Action, Connection, Proto, Rule};
use ipnet::IpNet;

/// Domain pattern from a rule's `domain` field.
#[derive(Debug, Clone)]
pub enum DomainPattern {
    /// Exact match, e.g. "example.org".
    Exact(String),
    /// "*.example.org": matches the suffix itself and any subdomain.
    Suffix(String),
}

impl DomainPattern {
    /// Parse a rule's `domain` operand, refusing anything no snooped name
    /// could ever equal.
    ///
    /// Snooped names are lowercase ASCII (IDNs arrive in their `xn--` form)
    /// with no trailing dot, so `example.org.`, `bücher.de`, `*example.org`
    /// or `*` compiled fine and then never matched. On an allow that costs a
    /// prompt; on a deny it is a block that silently is not there. Refused
    /// here, the rule is skipped with a warning naming it, or the IPC add
    /// fails with the reason. A trailing dot is the one spelling normalized
    /// rather than refused, since it names the same thing.
    fn parse(raw: &str) -> Result<DomainPattern, String> {
        let lower = raw.to_ascii_lowercase();
        let name = lower.strip_suffix('.').unwrap_or(&lower);
        let (suffix, body) = match name.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, name),
        };
        if !body.is_ascii() {
            return Err(format!(
                "{raw:?}: not ASCII; write an internationalized name in its xn-- form"
            ));
        }
        let valid_label = |l: &str| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        };
        if body.is_empty() || body.len() > 253 || !body.split('.').all(valid_label) {
            return Err(format!(
                "{raw:?}: expected a domain name, or \"*.\" followed by one"
            ));
        }
        Ok(match suffix {
            true => DomainPattern::Suffix(body.to_string()),
            false => DomainPattern::Exact(body.to_string()),
        })
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
    /// Set at compile time when a lockdown posture is in force and this is
    /// an allow rule carrying none of its pinned tags.
    ///
    /// Separate from `enabled` rather than folded into it, even though the
    /// packet path treats them the same: `enabled` is what the operator
    /// wrote and what a listing shows, and collapsing the two would have a
    /// posture silently rewrite policy that outlives it. `explain` reports
    /// the difference for the same reason.
    pub suppressed: bool,
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
    app_id: Option<String>,
}

/// Parse an IP or CIDR match field (a bare address becomes a host net).
fn parse_net(field: &str, raw: &str) -> Result<IpNet, String> {
    raw.parse::<IpNet>()
        .or_else(|_| raw.parse::<std::net::IpAddr>().map(IpNet::from))
        .map_err(|e| format!("bad {field} {raw:?}: {e}"))
}

impl CompiledRule {
    /// Compile a rule, validating cidr/glob/range fields.
    ///
    /// Also where the daemon's own rule-name prefixes are reserved, rather than in
    /// `RuleStore::add`: `add` is only the IPC and prompt path, and a rule
    /// file on disk reaches the ruleset through `load_dir`, which compiles
    /// but never calls `add`. A rule named after a live grant is exactly the
    /// ambiguity the reservation exists to remove - it would be
    /// indistinguishable from one in every event, listing and export - so
    /// the check belongs on the one path both entrances share.
    pub fn compile(rule: &Rule) -> Result<CompiledRule, String> {
        if let Some(prefix) = hallpass_types::RESERVED_RULE_PREFIXES
            .iter()
            .find(|p| rule.name.starts_with(**p))
        {
            return Err(format!(
                "rule names starting with `{prefix}` are reserved for decisions \
                 the daemon makes itself"
            ));
        }
        // Deliberately not where tags are validated, unlike every other
        // field here. Compiling is what decides whether a rule is enforced,
        // and a tag cannot change what a rule matches: refusing one would
        // mean an operator who mistyped a label on a deny rule silently
        // stops blocking the traffic that file exists to block. Rule files
        // have their tags normalized on the way in (`load_dir`), and the
        // interactive entrances refuse a bad list outright (`RuleStore::add`
        // and both clients), where the cost of being strict is an error
        // message rather than an unenforced rule.
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
        let dest = m
            .dest
            .as_deref()
            .map(|s| parse_net("dest", s))
            .transpose()?;
        let src = m.src.as_deref().map(|s| parse_net("src", s)).transpose()?;
        let exe_glob = match &m.exe_glob {
            None => None,
            // literal_separator, so `*` and `?` stop at a path separator the
            // way a shell's do. Off (the crate default) `/usr/bin/*` also
            // covered `/usr/bin/anything/deep/evil`, so a rule an operator
            // wrote for one directory silently carried every subtree under
            // it, and a binary dropped in a writable subdirectory of an
            // allowed tree inherited the verdict. A subtree is still
            // expressible, now on purpose: `/opt/app/**`.
            Some(g) => {
                // The one shape where the narrowing bites silently: a deny
                // written as `/opt/app/*` for a subtree now blocks only the
                // top level, and blocking less produces no visible failure.
                // Said here, at compile, because it reaches operators who
                // never read a release note.
                if g.ends_with("/*") {
                    tracing::info!(
                        rule = %rule.name,
                        glob = %g,
                        "exe_glob ending in /* matches one directory level; \
                         use /** for the whole subtree"
                    );
                }
                Some(
                    globset::GlobBuilder::new(g)
                        .literal_separator(true)
                        .build()
                        .map_err(|e| format!("bad exe_glob {g:?}: {e}"))?
                        .compile_matcher(),
                )
            }
        };
        if let Some((lo, hi)) = m.port_range {
            if lo > hi {
                return Err(format!("bad port_range {lo}-{hi}: start exceeds end"));
            }
        }
        if let Some(app) = &m.app_id {
            // Same gate the daemon applies to what it reads out of a cgroup,
            // so an operand that no connection could ever carry is a loud
            // skipped rule rather than a rule that lists fine and silently
            // never matches. `firefox` without a scheme is the likely typo.
            if !hallpass_types::valid_app_id(app) {
                return Err(format!(
                    "bad app_id {app:?}: expected {}, for example \"flatpak:org.mozilla.firefox\"",
                    hallpass_types::APP_ID_SCHEMES
                        .map(|s| format!("{s}:<name>"))
                        .join(" or ")
                ));
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
        let ips_file = m
            .ips_file
            .as_deref()
            .map(super::lists::IpSet::load)
            .transpose()?;
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
            // Never here: a posture is not a property of the rule, and this
            // function is called from paths that have no posture to consult.
            // `RuleSet::compile_with_lockdown` sets it.
            suppressed: false,
            exe: m.exe.clone(),
            exe_glob,
            exe_sha256,
            dest,
            port: m.port,
            port_range: m.port_range,
            domain: m
                .domain
                .as_deref()
                .map(DomainPattern::parse)
                .transpose()
                .map_err(|e| format!("bad domain {e}"))?,
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
            app_id: m.app_id.clone(),
        })
    }

    /// Whether this rule decides connections right now: the operator has it
    /// enabled and no lockdown posture is holding it back.
    ///
    /// One predicate for the packet path and the explainer, so a rule that
    /// enforcement skipped cannot be reported as evaluated.
    #[inline]
    pub fn deciding(&self) -> bool {
        self.enabled && !self.suppressed
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
        if let Some(app) = &self.app_id {
            // Exact, including the scheme prefix: a connection with no
            // application identity matches nothing here, the way a domain
            // rule needs a domain.
            if conn.app_id.as_deref() != Some(app.as_str()) {
                return Some("app_id");
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
        tagged_rule_with(Vec::new(), matcher)
    }

    fn tagged_rule_with(tags: Vec<String>, matcher: RuleMatch) -> Rule {
        Rule {
            name: "t".into(),
            action: Action::Allow,
            duration: RuleDuration::Session,
            priority: 0,
            enabled: true,
            tags,
            matcher,
        }
    }

    /// `*` covers one path level, `**` covers the subtree. Off (the crate
    /// default) an operator writing `/usr/bin/*` also allowed anything at
    /// any depth beneath it, so a binary dropped into a writable
    /// subdirectory of an allowed tree inherited that rule's verdict.
    #[test]
    fn exe_glob_star_does_not_cross_a_path_separator() {
        let matches = |pattern: &str, exe: &str| {
            let compiled = CompiledRule::compile(&rule_with(RuleMatch {
                exe_glob: Some(pattern.into()),
                ..Default::default()
            }))
            .expect("valid glob");
            let c = Connection {
                tuple: hallpass_types::FlowTuple {
                    proto: Proto::Tcp,
                    src: "10.0.0.1:40000".parse().unwrap(),
                    dst: "1.2.3.4:443".parse().unwrap(),
                },
                uid: None,
                pid: None,
                exe_path: Some(exe.into()),
                cmdline: None,
                parent_exe: None,
                domain: None,
                iface: None,
                app_id: None,
                first_seen: None,
            };
            compiled.matches(&c, None)
        };

        assert!(
            matches("/usr/bin/*", "/usr/bin/curl"),
            "one level still matches"
        );
        assert!(
            !matches("/usr/bin/*", "/usr/bin/nested/evil"),
            "* must not cross a separator"
        );
        assert!(
            !matches(
                "/usr/lib/firefox/*",
                "/usr/lib/firefox/plugins/writable/evil"
            ),
            "the README's own example must not carry a whole subtree"
        );
        assert!(
            matches("/opt/app/**", "/opt/app/deep/nested/bin"),
            "** is how a subtree is asked for"
        );
        assert!(
            !matches("/usr/bin/?", "/usr/bin//"),
            "? must not cross either"
        );
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
            app_id: None,
            first_seen: None,
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
        let domains = dir.write("ads.list", "0.0.0.0 ads.example.com\n");
        let ips = dir.write("bad.list", "10.0.0.0/8\n");

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
            app_id: None,
            first_seen: None,
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
        let hashes = dir.write("h.sha256", format!("{}\n", "ab".repeat(32)));
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
            app_id: Some("flatpak:org.mozilla.firefox".into()),
            first_seen: None,
        };
        let check = |m: RuleMatch, expect: bool| {
            let compiled = CompiledRule::compile(&rule_with(m)).unwrap();
            assert_eq!(compiled.matches(&conn, None), expect);
        };

        check(
            RuleMatch {
                cmdline_contains: Some("backup.py".into()),
                ..Default::default()
            },
            true,
        );
        check(
            RuleMatch {
                cmdline_contains: Some("restore.py".into()),
                ..Default::default()
            },
            false,
        );
        check(
            RuleMatch {
                parent_exe: Some("/usr/bin/bash".into()),
                ..Default::default()
            },
            true,
        );
        check(
            RuleMatch {
                parent_exe: Some("/usr/bin/zsh".into()),
                ..Default::default()
            },
            false,
        );
        check(
            RuleMatch {
                src: Some("192.168.1.0/24".into()),
                ..Default::default()
            },
            true,
        );
        check(
            RuleMatch {
                src: Some("10.0.0.0/8".into()),
                ..Default::default()
            },
            false,
        );
        check(
            RuleMatch {
                src_port: Some(40000),
                ..Default::default()
            },
            true,
        );
        check(
            RuleMatch {
                src_port: Some(40001),
                ..Default::default()
            },
            false,
        );
        check(
            RuleMatch {
                iface: Some("wg0".into()),
                ..Default::default()
            },
            true,
        );
        check(
            RuleMatch {
                iface: Some("eth0".into()),
                ..Default::default()
            },
            false,
        );
        check(
            RuleMatch {
                app_id: Some("flatpak:org.mozilla.firefox".into()),
                ..Default::default()
            },
            true,
        );
        // The scheme prefix is part of the value: the same application
        // packaged the other way is a different identity.
        check(
            RuleMatch {
                app_id: Some("snap:firefox".into()),
                ..Default::default()
            },
            false,
        );
        check(
            RuleMatch {
                app_id: Some("flatpak:org.mozilla".into()),
                ..Default::default()
            },
            false,
        );

        // Absent connection data never matches a present criterion.
        let mut bare = conn.clone();
        bare.cmdline = None;
        bare.parent_exe = None;
        bare.iface = None;
        bare.app_id = None;
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
            app_id: Some("snap:firefox".into()),
            first_seen: None,
        };

        struct Case {
            name: &'static str,
            matcher: RuleMatch,
            expect: Option<&'static str>,
        }
        let m = RuleMatch::default;
        let cases = vec![
            Case {
                name: "no criteria matches",
                matcher: m(),
                expect: None,
            },
            Case {
                name: "exe",
                matcher: RuleMatch {
                    exe: Some("/usr/bin/wget".into()),
                    ..m()
                },
                expect: Some("exe"),
            },
            Case {
                name: "exe_glob",
                matcher: RuleMatch {
                    exe_glob: Some("/opt/*".into()),
                    ..m()
                },
                expect: Some("exe_glob"),
            },
            Case {
                name: "exe_sha256",
                matcher: RuleMatch {
                    exe_sha256: Some("ab".repeat(32)),
                    ..m()
                },
                expect: Some("exe_sha256"),
            },
            Case {
                name: "dest",
                matcher: RuleMatch {
                    dest: Some("10.0.0.0/8".into()),
                    ..m()
                },
                expect: Some("dest"),
            },
            Case {
                name: "port",
                matcher: RuleMatch {
                    port: Some(80),
                    ..m()
                },
                expect: Some("port"),
            },
            Case {
                name: "port_range",
                matcher: RuleMatch {
                    port_range: Some((1, 100)),
                    ..m()
                },
                expect: Some("port_range"),
            },
            Case {
                name: "domain",
                matcher: RuleMatch {
                    domain: Some("*.example.com".into()),
                    ..m()
                },
                expect: Some("domain"),
            },
            Case {
                name: "user",
                matcher: RuleMatch {
                    user: Some(0),
                    ..m()
                },
                expect: Some("user"),
            },
            Case {
                name: "proto",
                matcher: RuleMatch {
                    proto: Some(Proto::Udp),
                    ..m()
                },
                expect: Some("proto"),
            },
            Case {
                name: "cmdline_contains",
                matcher: RuleMatch {
                    cmdline_contains: Some("wget".into()),
                    ..m()
                },
                expect: Some("cmdline_contains"),
            },
            Case {
                name: "parent_exe",
                matcher: RuleMatch {
                    parent_exe: Some("/usr/bin/zsh".into()),
                    ..m()
                },
                expect: Some("parent_exe"),
            },
            Case {
                name: "src",
                matcher: RuleMatch {
                    src: Some("10.0.0.0/8".into()),
                    ..m()
                },
                expect: Some("src"),
            },
            Case {
                name: "src_port",
                matcher: RuleMatch {
                    src_port: Some(1234),
                    ..m()
                },
                expect: Some("src_port"),
            },
            Case {
                name: "iface",
                matcher: RuleMatch {
                    iface: Some("eth0".into()),
                    ..m()
                },
                expect: Some("iface"),
            },
            Case {
                name: "app_id",
                matcher: RuleMatch {
                    app_id: Some("snap:chromium".into()),
                    ..m()
                },
                expect: Some("app_id"),
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
                matcher: RuleMatch {
                    port: Some(443),
                    user: Some(0),
                    ..m()
                },
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
        let domains = dir.write("ads.list", "ads.example.com\n");
        let ips = dir.write("bad.list", "10.0.0.0/8\n");
        let hashes = dir.write("h.sha256", format!("{}\n", "ab".repeat(32)));

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
            app_id: None,
            first_seen: None,
        };

        let compiled = CompiledRule::compile(&rule_with(RuleMatch {
            domains_file: Some(domains),
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(
            compiled.first_failing_field(&conn, None),
            Some("domains_file")
        );

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
        assert_eq!(
            compiled.first_failing_field(&conn, None),
            Some("hashes_file")
        );
        assert_eq!(
            compiled.first_failing_field(&conn, Some(&"ab".repeat(32))),
            None
        );
    }

    /// An app_id no connection could ever carry is refused at compile,
    /// like a bad hash or a bad CIDR: the rule is skipped with a warning
    /// instead of loading and matching nothing for a reason the operator
    /// cannot see.
    #[test]
    fn unwritable_app_id_is_rejected() {
        for bad in ["firefox", "docker:nginx", "flatpak:", "snap:Firefox"] {
            let r = rule_with(RuleMatch {
                app_id: Some(bad.into()),
                ..Default::default()
            });
            assert!(CompiledRule::compile(&r).is_err(), "accepted {bad:?}");
        }
        let r = rule_with(RuleMatch {
            app_id: Some("flatpak:org.mozilla.firefox".into()),
            ..Default::default()
        });
        assert!(CompiledRule::compile(&r).is_ok());
    }

    /// **A bad tag must never cost a rule its enforcement.** Compiling is
    /// what decides whether a rule is in the enforced set, and a tag cannot
    /// change what a rule matches, so refusing one here would mean a
    /// mistyped label on a deny rule silently passes the traffic that rule
    /// exists to stop. The strictness lives where a refusal is only an error
    /// message: `RuleStore::add` for the interactive path, and `load_dir`
    /// normalizes what is already on disk.
    #[test]
    fn a_malformed_tag_never_stops_a_rule_compiling() {
        let matcher = RuleMatch {
            port: Some(443),
            ..Default::default()
        };
        let one = |tag: &str| tagged_rule_with(vec![tag.to_string()], matcher.clone());
        for bad in ["Work", "work lab", "", "-", &"a".repeat(33)] {
            assert!(
                CompiledRule::compile(&one(bad)).is_ok(),
                "tag {bad:?} cost the rule its enforcement"
            );
        }
        let dup = tagged_rule_with(vec!["work".into(), "work".into()], matcher.clone());
        assert!(CompiledRule::compile(&dup).is_ok());
        let many: Vec<String> = (0..=hallpass_types::MAX_TAGS_PER_RULE)
            .map(|i| format!("t{i}"))
            .collect();
        assert!(CompiledRule::compile(&tagged_rule_with(many, matcher)).is_ok());
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
        let exact = DomainPattern::parse("Example.org").unwrap();
        assert!(exact.matches("example.org"));
        assert!(exact.matches("EXAMPLE.ORG"));
        assert!(!exact.matches("sub.example.org"));

        let wild = DomainPattern::parse("*.example.org").unwrap();
        assert!(wild.matches("example.org"));
        assert!(wild.matches("a.example.org"));
        assert!(wild.matches("a.b.example.org"));
        assert!(!wild.matches("evilexample.org"));
        assert!(!wild.matches("example.org.evil.com"));
    }

    /// A pattern no snooped name can equal is refused rather than compiled
    /// into a rule that never matches; a trailing dot is the same name.
    #[test]
    fn domain_patterns_that_could_never_match_are_refused() {
        let root = DomainPattern::parse("example.org.").unwrap();
        assert!(root.matches("example.org"));
        assert!(DomainPattern::parse("*.Example.ORG.")
            .unwrap()
            .matches("a.example.org"));
        assert!(DomainPattern::parse("_dmarc.example.org").is_ok());
        assert!(DomainPattern::parse("xn--bcher-kva.de").is_ok());
        for bad in [
            "bücher.de",
            "*",
            "*example.org",
            "exa*mple.org",
            "example..org",
            "example.org ",
            "",
            ".",
        ] {
            assert!(DomainPattern::parse(bad).is_err(), "{bad:?} was accepted");
        }
    }
}

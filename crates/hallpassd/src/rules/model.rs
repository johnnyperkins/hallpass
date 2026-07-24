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
}

impl CompiledRule {
    /// Compile a rule, validating cidr/glob/range fields.
    pub fn compile(rule: &Rule) -> Result<CompiledRule, String> {
        let m = &rule.matcher;
        let dest = match &m.dest {
            None => None,
            Some(s) => Some(
                s.parse::<IpNet>()
                    .or_else(|_| s.parse::<std::net::IpAddr>().map(IpNet::from))
                    .map_err(|e| format!("bad dest {s:?}: {e}"))?,
            ),
        };
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
    pub fn matches(&self, conn: &Connection, exe_sha256: Option<&str>) -> bool {
        if !self.matches_ignoring_hash(conn) {
            return false;
        }
        if let Some(want) = &self.exe_sha256 {
            // Hashes are produced lowercase on both sides; direct compare.
            match exe_sha256 {
                Some(have) if have == want.as_str() => {}
                _ => return false,
            }
        }
        if let Some(hashes) = &self.hashes_file {
            match exe_sha256 {
                Some(have) if hashes.contains(have) => {}
                _ => return false,
            }
        }
        true
    }

    /// All criteria except the executable hash. Split out so the packet
    /// path can decide whether hashing is worth doing for a connection
    /// before paying for it.
    pub fn matches_ignoring_hash(&self, conn: &Connection) -> bool {
        let dst = conn.tuple.dst;
        if let Some(exe) = &self.exe {
            if conn.exe_path.as_deref() != Some(exe) {
                return false;
            }
        }
        if let Some(glob) = &self.exe_glob {
            match &conn.exe_path {
                Some(path) if glob.is_match(path) => {}
                _ => return false,
            }
        }
        if let Some(net) = &self.dest {
            if !net.contains(&dst.ip()) {
                return false;
            }
        }
        if let Some(port) = self.port {
            if dst.port() != port {
                return false;
            }
        }
        if let Some((lo, hi)) = self.port_range {
            if !(lo..=hi).contains(&dst.port()) {
                return false;
            }
        }
        if let Some(pattern) = &self.domain {
            match &conn.domain {
                Some(d) if pattern.matches(d) => {}
                _ => return false,
            }
        }
        if let Some(user) = self.user {
            if conn.uid != Some(user) {
                return false;
            }
        }
        if let Some(proto) = self.proto {
            if conn.tuple.proto != proto {
                return false;
            }
        }
        if let Some(domains) = &self.domains_file {
            match &conn.domain {
                Some(d) if domains.contains(d) => {}
                _ => return false,
            }
        }
        if let Some(ips) = &self.ips_file {
            if !ips.contains(&dst.ip()) {
                return false;
            }
        }
        true
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
            domain: None,
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
            domain: domain.map(String::from),
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

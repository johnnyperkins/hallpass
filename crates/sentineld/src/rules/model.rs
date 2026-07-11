//! Compiled form of a rule: match fields pre-parsed for fast evaluation.

use std::path::PathBuf;

use globset::{Glob, GlobMatcher};
use ipnet::IpNet;
use sentinel_types::{Action, Connection, Proto, Rule};

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
    dest: Option<IpNet>,
    port: Option<u16>,
    port_range: Option<(u16, u16)>,
    domain: Option<DomainPattern>,
    user: Option<u32>,
    proto: Option<Proto>,
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
        Ok(CompiledRule {
            name: rule.name.clone(),
            action: rule.action,
            priority: rule.priority,
            enabled: rule.enabled,
            exe: m.exe.clone(),
            exe_glob,
            dest,
            port: m.port,
            port_range: m.port_range,
            domain: m.domain.as_deref().map(DomainPattern::parse),
            user: m.user,
            proto: m.proto,
        })
    }

    /// True when every present criterion matches (AND semantics). A rule
    /// with no criteria matches everything.
    pub fn matches(&self, conn: &Connection) -> bool {
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
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_types::{RuleDuration, RuleMatch};

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

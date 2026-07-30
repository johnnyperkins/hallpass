//! The TOML document `rules export` writes and `rules import` reads.
//!
//! One `[[rule]]` array of the daemon's own rule-file fields, so an exported
//! ruleset is something an operator can read, diff and check into version
//! control, and so a single entry can be lifted into `rules.d/` unchanged.
//!
//! Exported rules are sanitized first. The document is written to a terminal
//! and read back by a human, which is exactly the audience the rule listing
//! sanitizes for; a rule name that erases the line above it hides its
//! neighbour just as well in a diff as in a table.

use hallpass_types::Rule;
use serde::{Deserialize, Serialize};

use crate::client::CliError;
use crate::json::sanitized_rule;

/// The document as a whole.
///
/// `deny_unknown_fields` so a mistyped table name is an error rather than an
/// import that reports success and adds nothing: `[[rules]]` for `[[rule]]`
/// would otherwise parse as an empty ruleset.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    /// The rules, in the order the daemon listed them.
    #[serde(default)]
    rule: Vec<Rule>,
}

/// Render `rules` as one TOML document.
pub fn export(rules: &[Rule]) -> Result<String, CliError> {
    let doc = Document {
        rule: rules.iter().map(sanitized_rule).collect(),
    };
    // Sanitizing also decodes paths through `Path::display`, so a non-UTF-8
    // exe path cannot fail serialization here the way it would in `serde_json`.
    toml::to_string_pretty(&doc)
        .map_err(|e| CliError::Protocol(format!("cannot encode rules as toml: {e}")))
}

/// Parse a document written by [`export`].
pub fn import(text: &str) -> Result<Vec<Rule>, String> {
    let doc: Document = toml::from_str(text).map_err(|e| e.to_string())?;
    if doc.rule.is_empty() {
        return Err("no [[rule]] entries".to_string());
    }
    Ok(doc.rule)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hallpass_types::{Action, Proto, RuleDuration, RuleMatch};
    use std::path::PathBuf;

    /// A ruleset covering several matcher fields and every duration kind.
    fn sample() -> Vec<Rule> {
        vec![
            Rule {
                name: "allow-curl".into(),
                action: Action::Allow,
                duration: RuleDuration::Forever,
                priority: 50,
                enabled: true,
                matcher: RuleMatch {
                    exe: Some(PathBuf::from("/usr/bin/curl")),
                    exe_sha256: Some("ab".repeat(32)),
                    dest: Some("10.0.0.0/8".into()),
                    port: Some(443),
                    domain: Some("*.example.org".into()),
                    proto: Some(Proto::Tcp),
                    user: Some(1000),
                    ..Default::default()
                },
            },
            Rule {
                name: "temporary".into(),
                action: Action::Deny,
                duration: RuleDuration::Until {
                    deadline_ms: 4_102_444_800_000,
                },
                priority: 10,
                enabled: false,
                matcher: RuleMatch {
                    port_range: Some((1024, 65535)),
                    cmdline_contains: Some("--upload".into()),
                    parent_exe: Some(PathBuf::from("/bin/bash")),
                    src: Some("192.168.0.0/16".into()),
                    src_port: Some(9000),
                    iface: Some("wg0".into()),
                    domains_file: Some(PathBuf::from("/etc/hallpass/rules.d/ads.list")),
                    ..Default::default()
                },
            },
            Rule {
                name: "session-reject".into(),
                action: Action::Reject,
                duration: RuleDuration::Session,
                priority: 0,
                enabled: true,
                matcher: RuleMatch {
                    exe_glob: Some("/opt/*".into()),
                    ips_file: Some(PathBuf::from("/etc/hallpass/rules.d/bad.ips")),
                    hashes_file: Some(PathBuf::from("/etc/hallpass/rules.d/bad.hashes")),
                    ..Default::default()
                },
            },
        ]
    }

    /// The whole point of the pair: whatever `export` writes, `import` has to
    /// read back as the same rules, or a backup is not a backup.
    #[test]
    fn export_round_trips_through_import() {
        let rules = sample();
        let text = export(&rules).expect("export");
        assert_eq!(import(&text).expect("import"), rules);
    }

    /// The field names are the daemon's own, so an entry can be lifted into
    /// rules.d without translation.
    #[test]
    fn document_uses_the_daemon_rule_file_spelling() {
        let text = export(&sample()).expect("export");
        for want in [
            "[[rule]]",
            "name = \"allow-curl\"",
            "action = \"allow\"",
            "duration = \"forever\"",
            "priority = 50",
            "enabled = true",
            "[rule.match]",
            "port = 443",
            "domain = \"*.example.org\"",
            "cmdline_contains = \"--upload\"",
            "port_range = [",
        ] {
            assert!(text.contains(want), "missing {want:?} in:\n{text}");
        }
    }

    /// A single exported entry must parse as a rules.d file would have it,
    /// since that is how an operator restores one rule out of a backup.
    #[test]
    fn a_single_entry_parses_as_a_rule_file() {
        let text = export(&sample()[..1]).expect("export");
        let entry = text.trim_start_matches("[[rule]]\n").replace("[rule.", "[");
        let rule: Rule = toml::from_str(&entry).expect("parse as a rules.d file");
        assert_eq!(rule, sample()[0]);
    }

    /// The document is read by a human, so a rule name cannot smuggle an
    /// escape sequence into the file it is exported to.
    #[test]
    fn hostile_rule_name_is_sanitized_on_export() {
        let mut rules = sample();
        rules[0].name = "evil\x1b[2K\r\nname = \"forged\"".into();
        let text = export(&rules).expect("export");
        for bad in ['\x1b', '\r'] {
            assert!(!text.contains(bad), "{bad:?} survived:\n{text}");
        }
        // The forged assignment cannot become a line of its own either.
        assert!(!text.contains("\nname = \"forged\""), "{text}");
        assert_eq!(import(&text).expect("import").len(), rules.len());
    }

    #[test]
    fn import_rejects_junk() {
        // Mistyped table name: parses as valid TOML, means nothing here.
        let err = import("[[rules]]\nname = \"x\"\n").expect_err("unknown key");
        assert!(err.contains("rules"), "{err}");
        assert!(import("").expect_err("empty").contains("no [[rule]]"));
        assert!(import("not toml at all").is_err());
        // A rule missing a required field is an error, not a default.
        assert!(import("[[rule]]\nname = \"x\"\n").is_err());
    }
}

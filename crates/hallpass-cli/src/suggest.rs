//! `suggest`: fold the daemon's recorded decisions into a proposed ruleset.
//!
//! Observe mode answers "what would this policy break"; this answers the
//! question that comes next, "what rules do I write so it breaks nothing".
//! The daemon's recent decisions are grouped per executable and folded
//! into the narrowest rules that would keep that traffic flowing: one rule
//! per (executable, protocol, port, destination), where the destination is
//! the snooped domain when one was recorded and the literal address
//! otherwise. Domains sharing a suffix collapse into one wildcard rule
//! once there are enough of them to say the suffix, not the host, is the
//! pattern - except suffixes that are registries or shared hosting, which
//! never collapse.
//!
//! What folds: allowed connections, plus connections that went out
//! unjudged by any rule in observe mode (an unenforced default verdict
//! records the *absence* of a decision, which is exactly the gap this
//! command closes). A deny that a rule decided is respected either way,
//! and an enforced deny never went out at all.
//!
//! The output is the same TOML document shape `rules export` writes, so it
//! can be read, edited, diffed, and fed to `rules import` unchanged. It is
//! a proposal, not policy: every rule here allows traffic, the header says
//! to review it first, and nothing is sent to the daemon.

use std::collections::{BTreeMap, HashSet};

use hallpass_types::{format_ts, Action, ConnEvent, Proto, Rule, RuleDuration, RuleMatch, Verdict};

use crate::args::{Filters, SuggestOpts};
use crate::client::{CliError, Client};
use crate::fmt::Output;
use crate::{json, rules_file};

/// Distinct same-suffix domains at which per-host rules collapse into one
/// `*.suffix` wildcard: three hosts under one suffix say the suffix, not
/// the host, is the pattern; two may be a coincidence.
const WILDCARD_MIN: usize = 3;

/// Suffixes that never collapse into a wildcard, because the "domain" is a
/// registry or shared hosting and `*.suffix` would vouch for every tenant
/// of it - `*.co.uk` is not one operator's zone, and a cloud-bucket
/// wildcard is a standard exfiltration channel. Deliberately small and
/// incomplete: the operator's review is the real guard, this list only
/// keeps the obviously-wide proposals from ever reaching it.
const NEVER_COLLAPSE: &[&str] = &[
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.jp",
    "ne.jp",
    "co.in",
    "co.za",
    "com.br",
    "com.cn",
    "com.mx",
    "com.tr",
    "amazonaws.com",
    "cloudfront.net",
    "github.io",
    "githubusercontent.com",
    "herokuapp.com",
    "azurewebsites.net",
    "cloudflare.net",
    "fastly.net",
    "netlify.app",
    "vercel.app",
    "web.app",
    "firebaseapp.com",
];

/// Most rules a single run proposes. History is bounded, but a busy host
/// can still hold more distinct (exe, port, destination) triples than any
/// operator will review; past this the smallest groups are dropped and the
/// drop is reported, because a silently truncated proposal reads as
/// complete coverage.
const MAX_RULES: usize = 200;

/// What one proposed rule matched on, before it becomes a [`Rule`].
///
/// Ordered so the emitted document groups by executable, then port, then
/// destination: the shape an operator reviews one application at a time.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    exe: String,
    /// Packaged application the connections came from, when they carried
    /// one. Part of the key, not decoration: a sandboxed application's
    /// executable path is shared by every application of that packaging
    /// system, so folding on the path alone merges two applications into
    /// one proposed allow rule.
    app_id: Option<String>,
    proto: Proto,
    port: u16,
    target: Target,
}

/// A destination as a rule would match it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Target {
    /// Snooped domain, exact or (after collapsing) `*.suffix`.
    Domain(String),
    /// Literal destination address, used when no domain was recorded.
    Dest(String),
}

/// The outcome of folding history: the rules, and enough about the fold to
/// report its coverage honestly.
pub struct Proposal {
    pub rules: Vec<Rule>,
    /// Proposals dropped to the `MAX_RULES` cap; zero means complete.
    pub dropped: usize,
    /// Decisions that contributed to the rules.
    pub folded: usize,
    /// Unix-ms span of the contributing decisions, oldest and newest. The
    /// history ring is bounded, so this window is what the proposal
    /// actually covers - anything older is not represented.
    pub span_ms: Option<(u64, u64)>,
}

/// Whether a decision represents traffic an allow rule would have to
/// cover. See the module doc for why unenforced, rule-less denies count.
///
/// A connection a session grant allowed is not such traffic, and this is
/// the one exclusion that is about intent rather than about coverage: the
/// operator asked for that connection to be allowed *once*, for one command.
/// Folding it in would turn every `hallpass run` into a permanent rule
/// proposal, which is the ruleset pollution the wrapper exists to avoid.
fn needs_a_rule(ev: &ConnEvent) -> bool {
    // The same argument covers the loopback a lockdown posture exempts: that
    // allow is the posture's, granted for as long as it lasts, and folding
    // it into a permanent rule would outlive the reason for it.
    let daemons_own = ev.rule_name.as_deref().is_some_and(|n| {
        hallpass_types::RESERVED_RULE_PREFIXES
            .iter()
            .any(|p| n.starts_with(p))
    });
    !daemons_own && (ev.verdict == Verdict::Allow || (!ev.enforced && ev.rule_name.is_none()))
}

/// Fold `events` into proposed allow rules.
pub fn suggest(events: &[ConnEvent], filters: &Filters) -> Proposal {
    // Hit counts per key, so the cap keeps the busiest flows.
    let mut hits: BTreeMap<Key, u64> = BTreeMap::new();
    let mut folded = 0usize;
    let mut span_ms: Option<(u64, u64)> = None;
    for ev in events {
        if !needs_a_rule(ev) || !filters.matches(ev) {
            continue;
        }
        let Some(exe) = ev.conn.exe_path.as_ref() else {
            // Unattributed traffic cannot become an exe-scoped rule, and a
            // rule without an exe scope is the width the README warns about.
            continue;
        };
        folded += 1;
        span_ms = match span_ms {
            None => Some((ev.unix_ms, ev.unix_ms)),
            Some((lo, hi)) => Some((lo.min(ev.unix_ms), hi.max(ev.unix_ms))),
        };
        let target = match &ev.conn.domain {
            Some(d) => Target::Domain(d.clone()),
            None => Target::Dest(ev.conn.tuple.dst.ip().to_string()),
        };
        let key = Key {
            exe: exe.display().to_string(),
            app_id: ev.conn.app_id.clone(),
            proto: ev.conn.tuple.proto,
            port: ev.conn.tuple.dst.port(),
            target,
        };
        *hits.entry(key).or_insert(0) += 1;
    }

    let collapsed = collapse_wildcards(hits);
    let mut kept: Vec<(Key, u64)> = collapsed.into_iter().collect();
    let dropped = kept.len().saturating_sub(MAX_RULES);
    if dropped > 0 {
        // Keep the busiest keys, then restore review order.
        kept.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        kept.truncate(MAX_RULES);
        kept.sort_by(|a, b| a.0.cmp(&b.0));
    }

    let mut used_names = HashSet::new();
    let rules = kept
        .into_iter()
        .map(|(key, _)| {
            let name = unique_name(&key, &mut used_names);
            let Key {
                exe,
                app_id,
                proto,
                port,
                target,
            } = key;
            let (domain, dest) = match target {
                Target::Domain(d) => (Some(d), None),
                Target::Dest(ip) => (None, Some(ip)),
            };
            Rule {
                name,
                action: Action::Allow,
                duration: RuleDuration::Forever,
                priority: 0,
                enabled: true,
                tags: Vec::new(),
                matcher: RuleMatch {
                    exe: Some(exe.into()),
                    app_id,
                    domain,
                    dest,
                    port: Some(port),
                    proto: Some(proto),
                    ..Default::default()
                },
            }
        })
        .collect();
    Proposal {
        rules,
        dropped,
        folded,
        span_ms,
    }
}

/// Collapse per-host domain keys into `*.suffix` once [`WILDCARD_MIN`]
/// distinct hosts share a suffix (the last two labels). The apex domain
/// itself stays exact: `*.example.org` deliberately does not vouch for
/// `example.org`.
fn collapse_wildcards(hits: BTreeMap<Key, u64>) -> BTreeMap<Key, u64> {
    // Distinct hosts per group.
    let mut sizes: BTreeMap<Group, usize> = BTreeMap::new();
    for key in hits.keys() {
        if let Target::Domain(d) = &key.target {
            if let Some(suffix) = wildcard_suffix(d) {
                *sizes.entry(group_of(key, suffix)).or_insert(0) += 1;
            }
        }
    }
    // Rebuild, rewriting members of big-enough groups to the wildcard;
    // entry-and-add folds the rewritten hosts' counts together.
    let mut out = BTreeMap::new();
    for (mut key, count) in hits {
        if let Target::Domain(d) = &key.target {
            if let Some(suffix) = wildcard_suffix(d) {
                let group = group_of(&key, suffix.clone());
                if sizes.get(&group).copied().unwrap_or(0) >= WILDCARD_MIN {
                    key.target = Target::Domain(format!("*.{suffix}"));
                }
            }
        }
        *out.entry(key).or_insert(0) += count;
    }
    out
}

/// Everything except the host that decides whether a set of domains
/// collapses under one wildcard: the rule the collapse would produce, minus
/// its target.
type Group = (String, Option<String>, Proto, u16, String);

/// Build a [`Group`] from a key and the suffix its domain falls under.
///
/// One constructor, because both passes of [`collapse_wildcards`] have to
/// agree exactly. Built twice by hand, a field added to [`Key`] and applied
/// to only one of them leaves the counting pass coarser than the pass that
/// consults it, and members of two different groups then collapse onto one
/// wildcard rule: an allow covering traffic from an application nobody
/// reviewed.
fn group_of(key: &Key, suffix: String) -> Group {
    (
        key.exe.clone(),
        key.app_id.clone(),
        key.proto,
        key.port,
        suffix,
    )
}

/// The suffix a host would collapse under: its last two labels, only when
/// the host has more labels than that (an apex never collapses into its
/// own wildcard) and the suffix is not a registry or shared-hosting zone.
fn wildcard_suffix(domain: &str) -> Option<String> {
    let labels: Vec<&str> = domain.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() < 3 {
        return None;
    }
    let suffix = labels[labels.len() - 2..].join(".");
    if NEVER_COLLAPSE.contains(&suffix.as_str()) {
        return None;
    }
    Some(suffix)
}

/// A readable, unique, filesystem-safe rule name for one key.
fn unique_name(key: &Key, used: &mut HashSet<String>) -> String {
    // The application when there is one, because that is what the rule is
    // scoped to. Two applications sharing a sandbox executable path would
    // otherwise produce names differing only by the "-2" the collision
    // counter appends, and a reviewer reading the emitted document has
    // every reason to delete the second as an accidental duplicate.
    let exe_base = match &key.app_id {
        Some(app) => app.rsplit([':', '.']).next().unwrap_or("app"),
        None => key.exe.rsplit('/').next().unwrap_or("app"),
    };
    let target = match &key.target {
        Target::Domain(d) => d.as_str(),
        Target::Dest(ip) => ip.as_str(),
    };
    let mut base = format!("suggest-{exe_base}-{target}-{}", key.port)
        .chars()
        .map(|c| {
            // `-` maps to itself; spelled out so the allowed output
            // charset is readable in one place.
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    // Comfortably under the daemon's 256-byte name cap, leaving room for
    // the dedup suffix.
    base.truncate(200);
    let mut name = base.clone();
    let mut n = 1;
    while !used.insert(name.clone()) {
        n += 1;
        name = format!("{base}-{n}");
    }
    name
}

/// Header prepended to the human-readable document. Blank comment line at
/// the end so the first `[[rule]]` does not run into the prose.
const HEADER: &str = "\
# Proposed by `hallpass-cli suggest` from the daemon's recent decisions.
# Every rule below ALLOWS traffic - review before importing. Domain rules
# are a convenience, not a boundary against a process choosing its own
# DNS; tighten with dest/exe_sha256 where it matters. Import with:
#   hallpass-cli rules import <this file>
#
";

/// Run the command: fetch history, fold it, print the proposal.
pub async fn run(client: &mut Client, opts: SuggestOpts, out: Output) -> Result<(), CliError> {
    use hallpass_types::{ClientMsg, DaemonMsg};

    let events = match client
        .request(ClientMsg::EventHistory { limit: opts.last })
        .await?
    {
        DaemonMsg::Events(events) => events,
        other => return Err(CliError::unexpected(&other)),
    };
    let proposal = suggest(&events, &opts.filters);
    if proposal.rules.is_empty() {
        return Err(CliError::Input(
            "nothing in the daemon's history folds into a rule: no allowed or \
             observe-unmatched, attributed connections (run some traffic first, or \
             loosen --exe)"
                .into(),
        ));
    }
    if out.json {
        println!("{}", json::rules(&proposal.rules)?);
    } else {
        print!("{}{}", HEADER, rules_file::export(&proposal.rules)?);
    }
    // Coverage, on stderr so a piped proposal stays a clean document. The
    // history ring is bounded and this window is what was actually seen; a
    // reader must not mistake the proposal for everything the host does.
    if let Some((lo, hi)) = proposal.span_ms {
        eprintln!(
            "note: folded {} decisions between {} and {}; traffic outside the daemon's \
             bounded history is not represented",
            proposal.folded,
            format_ts(lo),
            format_ts(hi),
        );
    }
    if proposal.dropped > 0 {
        eprintln!(
            "note: {} smaller groups did not fit the {MAX_RULES}-rule cap; \
             narrow with --exe to see them",
            proposal.dropped
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hallpass_types::{Connection, FlowTuple};

    fn event(exe: Option<&str>, domain: Option<&str>, dst: &str, verdict: Verdict) -> ConnEvent {
        ConnEvent {
            conn: Connection {
                tuple: FlowTuple {
                    proto: Proto::Tcp,
                    src: "10.0.0.1:40000".parse().unwrap(),
                    dst: dst.parse().unwrap(),
                },
                uid: Some(1000),
                pid: None,
                exe_path: exe.map(Into::into),
                cmdline: None,
                parent_exe: None,
                domain: domain.map(Into::into),
                iface: None,
                app_id: None,
                first_seen: None,
            },
            verdict,
            rule_name: None,
            unix_ms: 1_720_000_000_000,
            enforced: true,
        }
    }

    /// A connection a session grant allowed was a one-off by construction,
    /// so folding it into a permanent rule proposal would turn every
    /// `hallpass run` into ruleset growth.
    #[test]
    fn session_grants_are_not_folded_into_proposals() {
        let mut granted = event(Some("/usr/bin/curl"), None, "1.1.1.1:443", Verdict::Allow);
        granted.rule_name = Some(format!("{}7", hallpass_types::RUN_SESSION_RULE_PREFIX));
        let proposal = suggest(&[granted.clone()], &Filters::default());
        assert!(proposal.rules.is_empty(), "a grant must not become a rule");
        assert_eq!(proposal.folded, 0);

        // The same connection decided any other way still folds, so this
        // excludes the grant rather than the traffic.
        let mut by_rule = granted;
        by_rule.rule_name = Some("allow-curl".into());
        assert_eq!(suggest(&[by_rule], &Filters::default()).rules.len(), 1);
    }

    fn exe_filter(sub: &str) -> Filters {
        Filters {
            exe: vec![sub.to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn folds_allowed_events_per_exe_and_destination() {
        let events = vec![
            event(
                Some("/usr/bin/curl"),
                Some("example.org"),
                "1.1.1.1:443",
                Verdict::Allow,
            ),
            // Repeat traffic folds into the same rule, not a second one.
            event(
                Some("/usr/bin/curl"),
                Some("example.org"),
                "1.1.1.1:443",
                Verdict::Allow,
            ),
            // No domain: the literal address is the match.
            event(Some("/usr/bin/curl"), None, "9.9.9.9:53", Verdict::Allow),
            // Denied traffic proposes nothing.
            event(Some("/usr/bin/nc"), None, "8.8.8.8:25", Verdict::Deny),
            // Unattributed traffic proposes nothing.
            event(None, None, "7.7.7.7:80", Verdict::Allow),
        ];
        let p = suggest(&events, &Filters::default());
        assert_eq!(p.dropped, 0);
        assert_eq!(p.folded, 3);
        assert_eq!(p.span_ms, Some((1_720_000_000_000, 1_720_000_000_000)));
        assert_eq!(p.rules.len(), 2);
        assert!(p.rules.iter().all(|r| r.action == Action::Allow));
        let domains: Vec<_> = p
            .rules
            .iter()
            .filter_map(|r| r.matcher.domain.clone())
            .collect();
        assert_eq!(domains, vec!["example.org"]);
        let dests: Vec<_> = p
            .rules
            .iter()
            .filter_map(|r| r.matcher.dest.clone())
            .collect();
        assert_eq!(dests, vec!["9.9.9.9"]);
        assert!(p.rules.iter().all(|r| r.matcher.exe.is_some()));
    }

    /// An unenforced deny with no rule name is observe mode's record of
    /// "no decision existed": exactly what the proposal must cover. A
    /// rule-driven deny stays excluded even unenforced.
    #[test]
    fn folds_observe_mode_gap_traffic() {
        let mut would_deny = event(
            Some("/usr/bin/curl"),
            Some("example.org"),
            "1.1.1.1:443",
            Verdict::Deny,
        );
        would_deny.enforced = false;
        let mut rule_deny = event(
            Some("/usr/bin/curl"),
            Some("blocked.example"),
            "2.2.2.2:443",
            Verdict::Deny,
        );
        rule_deny.enforced = false;
        rule_deny.rule_name = Some("block-it".into());
        let p = suggest(&[would_deny, rule_deny], &Filters::default());
        let domains: Vec<_> = p
            .rules
            .iter()
            .filter_map(|r| r.matcher.domain.clone())
            .collect();
        assert_eq!(domains, vec!["example.org"]);
    }

    #[test]
    fn collapses_enough_subdomains_into_a_wildcard() {
        let events = vec![
            event(
                Some("/usr/bin/ff"),
                Some("a.example.org"),
                "1.1.1.1:443",
                Verdict::Allow,
            ),
            event(
                Some("/usr/bin/ff"),
                Some("b.example.org"),
                "1.1.1.2:443",
                Verdict::Allow,
            ),
            event(
                Some("/usr/bin/ff"),
                Some("c.example.org"),
                "1.1.1.3:443",
                Verdict::Allow,
            ),
            // The apex stays exact even next to its own wildcard.
            event(
                Some("/usr/bin/ff"),
                Some("example.org"),
                "1.1.1.4:443",
                Verdict::Allow,
            ),
            // Two hosts under another suffix stay exact: below the threshold.
            event(
                Some("/usr/bin/ff"),
                Some("x.other.net"),
                "2.2.2.1:443",
                Verdict::Allow,
            ),
            event(
                Some("/usr/bin/ff"),
                Some("y.other.net"),
                "2.2.2.2:443",
                Verdict::Allow,
            ),
        ];
        let p = suggest(&events, &Filters::default());
        let mut domains: Vec<_> = p
            .rules
            .iter()
            .filter_map(|r| r.matcher.domain.clone())
            .collect();
        domains.sort();
        assert_eq!(
            domains,
            vec!["*.example.org", "example.org", "x.other.net", "y.other.net"]
        );
    }

    /// Two packaged applications can run from the same path inside their
    /// sandboxes, so folding on the executable alone would propose one allow
    /// rule covering both. They stay separate rules, each pinning its own
    /// application.
    #[test]
    fn packaged_applications_do_not_fold_together() {
        let app = |id: &str, domain: &str| {
            let mut ev = event(
                Some("/app/bin/browser"),
                Some(domain),
                "1.1.1.1:443",
                Verdict::Allow,
            );
            ev.conn.app_id = Some(id.to_string());
            ev
        };
        let p = suggest(
            &[
                app("flatpak:org.mozilla.firefox", "mozilla.example"),
                app("flatpak:com.example.Other", "other.example"),
            ],
            &Filters::default(),
        );
        let mut pairs: Vec<_> = p
            .rules
            .iter()
            .map(|r| (r.matcher.app_id.clone(), r.matcher.domain.clone()))
            .collect();
        pairs.sort();
        assert_eq!(
            pairs,
            vec![
                (
                    Some("flatpak:com.example.Other".into()),
                    Some("other.example".into())
                ),
                (
                    Some("flatpak:org.mozilla.firefox".into()),
                    Some("mozilla.example".into())
                ),
            ]
        );
        // And they are told apart by name, not by a collision counter: a
        // reviewer deleting an apparent duplicate would drop one
        // application's allow.
        let mut names: Vec<&str> = p.rules.iter().map(|r| r.name.as_str()).collect();
        names.sort();
        assert!(names[0].starts_with("suggest-firefox-"), "{names:?}");
        assert!(names[1].starts_with("suggest-other-"), "{names:?}");
        // A connection with no application identity proposes what it always
        // did: an exe rule with no app_id operand.
        let plain = suggest(
            &[event(
                Some("/usr/bin/curl"),
                Some("example.org"),
                "1.1.1.1:443",
                Verdict::Allow,
            )],
            &Filters::default(),
        );
        assert_eq!(plain.rules[0].matcher.app_id, None);
    }

    /// Registry and shared-hosting suffixes never collapse, however many
    /// hosts share them: `*.co.uk` would vouch for every tenant.
    #[test]
    fn never_collapses_registry_suffixes() {
        let events = vec![
            event(
                Some("/usr/bin/ff"),
                Some("a.co.uk"),
                "1.1.1.1:443",
                Verdict::Allow,
            ),
            event(
                Some("/usr/bin/ff"),
                Some("b.co.uk"),
                "1.1.1.2:443",
                Verdict::Allow,
            ),
            event(
                Some("/usr/bin/ff"),
                Some("c.co.uk"),
                "1.1.1.3:443",
                Verdict::Allow,
            ),
            event(
                Some("/usr/bin/ff"),
                Some("d.amazonaws.com"),
                "2.1.1.1:443",
                Verdict::Allow,
            ),
            event(
                Some("/usr/bin/ff"),
                Some("e.amazonaws.com"),
                "2.1.1.2:443",
                Verdict::Allow,
            ),
            event(
                Some("/usr/bin/ff"),
                Some("f.amazonaws.com"),
                "2.1.1.3:443",
                Verdict::Allow,
            ),
        ];
        let p = suggest(&events, &Filters::default());
        let domains: Vec<_> = p
            .rules
            .iter()
            .filter_map(|r| r.matcher.domain.clone())
            .collect();
        assert_eq!(p.rules.len(), 6);
        assert!(domains.iter().all(|d| !d.starts_with("*.")), "{domains:?}");
    }

    #[test]
    fn exe_filter_narrows_and_names_are_unique() {
        let events = vec![
            event(
                Some("/usr/bin/curl"),
                Some("example.org"),
                "1.1.1.1:443",
                Verdict::Allow,
            ),
            event(
                Some("/opt/other/curl"),
                Some("example.org"),
                "1.1.1.1:443",
                Verdict::Allow,
            ),
            event(
                Some("/usr/bin/wget"),
                Some("example.org"),
                "1.1.1.1:443",
                Verdict::Allow,
            ),
        ];
        let p = suggest(&events, &exe_filter("curl"));
        assert_eq!(p.rules.len(), 2);
        // Same basename, same destination: the names must still differ.
        assert_ne!(p.rules[0].name, p.rules[1].name);
        assert!(p.rules.iter().all(|r| r.name.starts_with("suggest-curl-")));
    }
}

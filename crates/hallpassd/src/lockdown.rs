//! The lockdown posture: a whole-host narrowing that is not a rule.
//!
//! While it is on, the only allow rules that decide connections are the ones
//! carrying a pinned tag; everything else no rule permits is denied without a
//! prompt, and the daemon enforces whatever mode it was in. Deny rules are
//! never suppressed - see [`hallpass_types::Rule::active_under_lockdown`].
//!
//! Three shapes were considered and only this one survived contact with the
//! failure directions:
//!
//! - **Not a mass toggle of `enabled`.** Rewriting every untagged rule's file
//!   means the way back is a snapshot of what each one was, taken before the
//!   write and read after it; a crash between the two leaves a half-locked
//!   host with no record of the other half, and an operator who disables a
//!   rule *during* a lockdown has that decision overwritten when it lifts.
//!   Here nothing on disk changes and lifting is one swap.
//! - **Not a rule.** A rule can be edited, reordered, deleted, or shadowed by
//!   a higher priority, and a posture that any group member can delete by
//!   name is not a posture.
//! - **Not runtime-only.** The daemon restarts on package upgrades, and a
//!   security posture that silently lifts when it does is the wrong failure
//!   direction. It is persisted, and re-read at startup.
//!
//! Two limits a posture does not overcome, both documented in docs/rules.md
//! rather than worked around here. Only `ct state new` is judged, so flows
//! already established when one engages keep running. And the verdict
//! queue's fail-open flag is fixed at bind (`nfqueue::want_fail_open`; the
//! flag cannot be re-issued on a live queue without discarding the packets
//! already on it), so on a host configured `queue_bypass = true` - the
//! shipped default - a kernel-side overflow still accepts packets the
//! posture would have denied. `status` and `doctor` both report that flag.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use hallpass_types::Lockdown;
use serde::{Deserialize, Serialize};

use crate::rules::store::RuleStore;

/// Format version of the posture file.
const POSTURE_VERSION: u32 = 1;

/// The posture as persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PostureFile {
    version: u32,
    /// Empty means no posture; the file is left in place rather than removed
    /// so "lockdown was lifted" and "the file was never written" are the
    /// same state to read back, and neither can be forged by deleting it.
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    since_ms: u64,
    /// True while a posture is on. Explicit rather than inferred from
    /// `tags`, because pinning no tags at all is a real (and maximal)
    /// posture: it denies everything no deny rule already caught.
    #[serde(default)]
    on: bool,
}

/// A posture in force: the tags it pins, and when it began.
#[derive(Debug, Clone)]
struct Active {
    tags: Vec<String>,
    since_ms: u64,
}

impl Active {
    /// This posture as a client sees it, given the ruleset now compiled.
    fn report(&self, store: &RuleStore) -> Lockdown {
        Lockdown {
            tags: self.tags.clone(),
            since_ms: self.since_ms,
            rules_suppressed: store.ruleset().suppressed_count(),
        }
    }
}

/// The posture in force, and where it is kept.
pub struct Posture {
    /// None when no posture is in force.
    active: Mutex<Option<Active>>,
    path: PathBuf,
}

impl Posture {
    /// Read the posture from `path`.
    ///
    /// Every failure is "no posture", loudly. The alternative - refusing to
    /// start, or assuming the strictest posture - turns a corrupt file into
    /// either a host with no firewall at all or a host that reaches nothing,
    /// with no operator present to judge which was meant. Unlike
    /// `queue_bypass`, the other place availability wins here, this one is
    /// visible: `status` and `doctor` both report the posture, so "not locked
    /// down" is never silent.
    pub fn load(path: &Path) -> Self {
        let posture = Self {
            active: Mutex::new(None),
            path: path.to_path_buf(),
        };
        let text = match read_trusted(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return posture,
            Err(e) => {
                tracing::error!(
                    path = %path.display(),
                    "cannot read the lockdown posture; starting without one: {e}"
                );
                return posture;
            }
        };
        let file: PostureFile = match toml::from_str(&text) {
            Ok(f) => f,
            Err(e) => {
                // `e.message()`, not `e`: the Display of a toml error quotes
                // the offending line, and this file is not the operator's.
                tracing::error!(
                    path = %path.display(),
                    span = ?e.span(),
                    "the lockdown posture is unreadable; starting without one: {}",
                    e.message()
                );
                return posture;
            }
        };
        if file.version != POSTURE_VERSION {
            tracing::error!(
                path = %path.display(),
                version = file.version,
                "the lockdown posture was written by a different version; \
                 starting without one"
            );
            return posture;
        }
        if !file.on {
            return posture;
        }
        // Normalized like a rule file's: an unusable tag pins nothing, and a
        // posture that silently keeps one would report a set it is not
        // actually keeping.
        let mut tags = file.tags;
        let dropped = hallpass_types::retain_valid_tags(&mut tags);
        if !dropped.is_empty() {
            tracing::error!(
                path = %path.display(),
                "the stored lockdown posture pinned unusable tags {dropped:?}; \
                 they pin nothing and the posture stays on without them"
            );
        }
        tracing::warn!(
            tags = ?tags,
            "lockdown is in force from the stored posture: only the allow rules \
             carrying these tags decide connections, everything else is denied"
        );
        *posture.active.lock().unwrap() = Some(Active {
            tags,
            since_ms: file.since_ms,
        });
        posture
    }

    /// The tags of the posture in force, if there is one.
    pub fn tags(&self) -> Option<Vec<String>> {
        self.active.lock().unwrap().as_ref().map(|a| a.tags.clone())
    }

    /// Whether a posture is in force.
    pub fn is_on(&self) -> bool {
        self.active.lock().unwrap().is_some()
    }

    /// The posture as a client sees it, given the ruleset now compiled.
    pub fn snapshot(&self, store: &RuleStore) -> Option<Lockdown> {
        let active = self.active.lock().unwrap().clone()?;
        Some(active.report(store))
    }

    /// Write `state` to disk. Synchronous, and its failure is the caller's:
    /// a posture that is in force but not recorded lifts silently at the
    /// next restart, which is exactly what persisting it is for, so the
    /// operator is told rather than left believing otherwise.
    ///
    /// Takes the state rather than reading it back, so the whole change can
    /// happen under one guard: two clients setting a posture at once must
    /// not be able to interleave into a file that says off while memory
    /// says on.
    fn save(&self, state: Option<&Active>) -> Result<(), String> {
        let file = PostureFile {
            version: POSTURE_VERSION,
            tags: state.map(|a| a.tags.clone()).unwrap_or_default(),
            since_ms: state.map_or(0, |a| a.since_ms),
            on: state.is_some(),
        };
        let text = toml::to_string(&file).map_err(|e| format!("serialize the posture: {e}"))?;
        // 0600, like the first-seen state: nothing but the daemon reads it.
        crate::rules::store::write_atomic(&self.path, text.as_bytes(), 0o600)
            .map_err(|e| format!("write {}: {e}", self.path.display()))
    }
}

/// The enabled rules that would still *permit* connections under a posture
/// pinned to `tags`.
///
/// Allows only. Deny rules survive every posture, so counting them would
/// have the emptiness guard pass on any host that has ever written one: an
/// operator who mistypes a tag on a host with a single `deny-tracker` rule
/// would get a silent blackout instead of the refusal `--force` exists to
/// make them override deliberately.
///
/// The daemon's own predicate, so what `lockdown on` refuses to engage over
/// cannot differ from what it then enforces.
pub fn still_permitting(store: &RuleStore, tags: &[String]) -> Vec<String> {
    store
        .list()
        .iter()
        .filter(|r| r.enabled && r.action == hallpass_types::Action::Allow)
        .filter(|r| r.active_under_lockdown(tags))
        .map(|r| r.name.clone())
        .collect()
}

/// Enter or leave the posture, persisting it and recompiling the ruleset.
///
/// One function rather than a setter per owner: the posture, the compiled
/// rule set and the runtime settings all have to move together, and any
/// order in which they do not is a window where the daemon denies traffic it
/// has not recorded a reason for, or records one it is not applying.
pub fn apply(
    posture: &Posture,
    store: &RuleStore,
    settings: &crate::config::RuntimeSettings,
    tags: Vec<String>,
    on: bool,
    force: bool,
) -> Result<Option<Lockdown>, String> {
    // One guard for the whole change. Two clients setting a posture at once
    // would otherwise interleave between the read, the write, the save and
    // the rebuild, and could leave the file saying one thing while memory
    // and the compiled rule set say another - which the next restart then
    // resolves in favour of a posture the host was never actually in.
    let mut active = posture.active.lock().unwrap();
    let next = if on {
        hallpass_types::validate_tags(&tags)?;
        // A posture that keeps nothing is a host that reaches nothing but
        // loopback. That is a real thing to want and `--force` expresses it;
        // without the flag it is far more often a tag that does not exist,
        // and finding that out from a host that has gone silent is the worst
        // possible way.
        if still_permitting(store, &tags).is_empty() && !force {
            return Err(format!(
                "no enabled allow rule survives a lockdown pinned to {tags:?}, so \
                 this would deny everything except loopback; re-run with --force \
                 if that is what you want"
            ));
        }
        // Re-pinning an existing posture keeps its start time: the
        // interesting question is how long this host has been locked down,
        // not when its tag list was last edited.
        let since_ms = active
            .as_ref()
            .map_or_else(hallpass_types::unix_ms_now, |a| a.since_ms);
        Some(Active { tags, since_ms })
    } else {
        None
    };

    // Persisted before anything starts enforcing it, and nothing is changed
    // at all if that fails: a posture in force but unrecorded lifts at the
    // next restart with nobody told, which is the failure persisting it
    // exists to prevent.
    if let Err(e) = posture.save(next.as_ref()) {
        return Err(format!("the posture was not changed: {e}"));
    }
    *active = next;

    settings.set_locked_down(active.is_some());
    store.rebuild_for_posture(active.as_ref().map(|a| a.tags.as_slice()));
    let state = active.as_ref().map(|a| a.report(store));
    drop(active);
    match &state {
        Some(state) => tracing::warn!(
            tags = ?state.tags,
            suppressed = state.rules_suppressed,
            "lockdown is on: only the allow rules carrying these tags decide \
             connections, everything else is denied without a prompt"
        ),
        None => tracing::warn!("lockdown is off: policy decides connections again"),
    }
    Ok(state)
}

/// Read the posture file, refusing a symlink at the path.
///
/// [`Links::Refuse`](crate::rules::store::Links::Refuse), like the
/// first-seen state and unlike the config: nothing about this file is
/// operator-authored, so a link planted where it reads would only ever aim a
/// root open somewhere the planter chose.
fn read_trusted(path: &Path) -> std::io::Result<String> {
    crate::rules::store::read_trusted(path, crate::rules::store::Links::Refuse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestDir;
    use hallpass_types::{Action, Rule, RuleDuration, RuleMatch};

    fn rule(name: &str, action: Action, tags: &[&str]) -> Rule {
        Rule {
            name: name.into(),
            action,
            duration: RuleDuration::Session,
            priority: 1,
            enabled: true,
            tags: tags.iter().map(|t| (*t).to_string()).collect(),
            matcher: RuleMatch {
                port: Some(443),
                ..Default::default()
            },
        }
    }

    struct Fixture {
        _dir: TestDir,
        posture: Posture,
        store: RuleStore,
        settings: crate::config::RuntimeSettings,
        path: PathBuf,
    }

    impl Fixture {
        /// [`apply`] against this fixture's posture, store and settings.
        fn apply(&self, tags: &[&str], on: bool, force: bool) -> Result<Option<Lockdown>, String> {
            let tags = tags.iter().map(|t| (*t).to_string()).collect();
            apply(&self.posture, &self.store, &self.settings, tags, on, force)
        }
    }

    fn fixture(tag: &str) -> Fixture {
        let dir = TestDir::new(&format!("lockdown-{tag}"));
        let path = dir.path().join("posture.toml");
        let store = RuleStore::new(dir.path().join("rules.d"));
        Fixture {
            posture: Posture::load(&path),
            store,
            settings: crate::config::RuntimeSettings::new(hallpass_types::RuntimeConfig {
                prompt_timeout_secs: 30,
                default_verdict: hallpass_types::Verdict::Allow,
                enforce: false,
            }),
            path,
            _dir: dir,
        }
    }

    /// **A posture never suppresses a deny.** It exists to permit less, and
    /// suppressing a block would permit more: an operator's deny on a
    /// tracker would come off exactly when the host was put into its most
    /// restrictive state.
    #[test]
    fn a_posture_suppresses_untagged_allows_only() {
        let f = fixture("suppress");
        f.store
            .add(rule("allow-work", Action::Allow, &["work"]))
            .unwrap();
        f.store
            .add(rule("allow-other", Action::Allow, &[]))
            .unwrap();
        f.store
            .add(rule("deny-tracker", Action::Deny, &[]))
            .unwrap();

        let state = f
            .apply(&["work"], true, false)
            .expect("a surviving rule means no force is needed")
            .expect("the posture is on");
        assert_eq!(state.tags, vec!["work".to_string()]);
        assert_eq!(state.rules_suppressed, 1, "only the untagged allow");
        assert!(f.store.ruleset().locked_down());

        // The guard counts what still *permits*: a deny survives every
        // posture, so counting denies would let a mistyped tag engage a
        // total blackout on any host that has ever written one.
        let kept = still_permitting(&f.store, &["work".to_string()]);
        assert_eq!(kept, vec!["allow-work".to_string()]);
    }

    /// The posture owns the mode and the default verdict while it is on, and
    /// hands both back exactly as they were when it lifts.
    #[test]
    fn a_posture_forces_enforcement_and_restores_it() {
        let f = fixture("settings");
        f.store
            .add(rule("allow-work", Action::Allow, &["work"]))
            .unwrap();
        assert!(!f.settings.enforcing(), "observe to begin with");
        assert_eq!(f.settings.default_verdict(), hallpass_types::Verdict::Allow);

        f.apply(&["work"], true, false).unwrap();
        assert!(
            f.settings.enforcing(),
            "a posture that records nothing is theatre"
        );
        assert_eq!(f.settings.default_verdict(), hallpass_types::Verdict::Deny);
        // `snapshot` reports what the operator set, not what the posture is
        // forcing: every client changes settings by reading it, editing one
        // field and writing the whole struct back, so reporting the
        // posture's values here would have a timeout change quietly persist
        // them - and lifting the posture would leave the host denying by
        // default forever with nothing that ever said so.
        assert!(
            !f.settings.snapshot().enforce,
            "the stored mode is the operator's"
        );
        assert_eq!(
            f.settings.snapshot().default_verdict,
            hallpass_types::Verdict::Allow
        );

        // And neither of the two the posture owns can be changed while it
        // is on, in either direction: a client told the change succeeded
        // would then watch the host keep doing something else.
        let mut want = f.settings.snapshot();
        want.enforce = true;
        assert!(f.settings.apply(&want).is_err());
        want = f.settings.snapshot();
        want.default_verdict = hallpass_types::Verdict::Reject;
        assert!(f.settings.apply(&want).is_err());
        // The one it does not own still moves.
        want = f.settings.snapshot();
        want.prompt_timeout_secs = 45;
        assert!(f.settings.apply(&want).is_ok());

        f.apply(&[], false, false).unwrap();
        assert!(!f.settings.enforcing(), "the operator's mode came back");
        assert_eq!(f.settings.default_verdict(), hallpass_types::Verdict::Allow);
        assert!(!f.store.ruleset().locked_down());
    }

    /// A posture is only a posture if it survives the restart that a package
    /// upgrade performs; otherwise it lifts silently with nobody told.
    #[test]
    fn a_posture_survives_a_restart() {
        let f = fixture("persist");
        f.store
            .add(rule("allow-work", Action::Allow, &["work"]))
            .unwrap();
        f.apply(&["work"], true, false).unwrap();
        let since = f.posture.snapshot(&f.store).unwrap().since_ms;

        let reloaded = Posture::load(&f.path);
        assert!(reloaded.is_on());
        assert_eq!(reloaded.tags(), Some(vec!["work".to_string()]));
        assert_eq!(
            reloaded.snapshot(&f.store).unwrap().since_ms,
            since,
            "how long this host has been locked down is the interesting fact"
        );

        // And lifting it is recorded too, rather than leaving a file that
        // would put the host back into lockdown at the next start.
        f.apply(&[], false, false).unwrap();
        assert!(!Posture::load(&f.path).is_on());
    }

    /// A tag that names nothing is far more often a typo than an intent, and
    /// finding that out from a host that has gone silent is the worst way.
    #[test]
    fn a_posture_that_keeps_nothing_needs_force() {
        let f = fixture("force");
        f.store
            .add(rule("allow-work", Action::Allow, &["work"]))
            .unwrap();

        let err = f
            .apply(&["wrok"], true, false)
            .expect_err("a posture keeping nothing must not engage quietly");
        assert!(err.contains("force"), "{err}");
        assert!(
            !f.posture.is_on(),
            "the refused posture must not be in force"
        );
        assert!(
            !f.settings.enforcing(),
            "a refused posture changed the mode"
        );

        // Deliberate is still expressible.
        f.apply(&["wrok"], true, true)
            .expect("--force says the operator means it");
        assert!(f.posture.is_on());
    }

    /// A file that cannot be read leaves the host unlocked and says so at
    /// error level. The alternative, assuming the strictest posture, turns a
    /// corrupt byte into a host that reaches nothing with no operator
    /// present to judge whether that was meant.
    #[test]
    fn an_unreadable_posture_starts_unlocked() {
        let dir = TestDir::new("lockdown-corrupt");
        let path = dir.path().join("posture.toml");
        std::fs::write(&path, "this is not toml {{{").unwrap();
        assert!(!Posture::load(&path).is_on());

        std::fs::write(&path, "version = 999\non = true\ntags = [\"work\"]\n").unwrap();
        assert!(
            !Posture::load(&path).is_on(),
            "a future version is not guessed at"
        );
    }

    /// An unusable tag pins nothing, so a posture that kept one would report
    /// a set it is not keeping.
    #[test]
    fn a_stored_posture_drops_unusable_tags() {
        let dir = TestDir::new("lockdown-badtag");
        let path = dir.write(
            "posture.toml",
            "version = 1\non = true\nsince_ms = 5\ntags = [\"Work\", \"work\"]\n",
        );
        let posture = Posture::load(&path);
        assert!(posture.is_on(), "the posture stays on without the bad tag");
        assert_eq!(posture.tags(), Some(vec!["work".to_string()]));
    }
}

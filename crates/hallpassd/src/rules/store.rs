//! Rule persistence and hot reload.
//!
//! Disk rules live as one TOML file per rule in the configured rules
//! directory; session rules live only in memory. Every mutation rebuilds
//! the compiled [`RuleSet`] and swaps it atomically, so the packet path
//! reads rules lock-free.

use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use notify::Watcher;
use hallpass_types::Rule;

use super::engine::RuleSet;
use super::model::CompiledRule;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Origin {
    Disk(PathBuf),
    Session,
}

struct Entry {
    rule: Rule,
    origin: Origin,
}

/// Owns all rules (disk and session) and the active compiled snapshot.
pub struct RuleStore {
    active: ArcSwap<RuleSet>,
    entries: Mutex<Vec<Entry>>,
    rules_dir: PathBuf,
    /// Cumulative count of disk rule files skipped across every load
    /// (bad permissions, unparsable, or duplicate name).
    rules_skipped: AtomicU64,
}

/// A rule (or list) file is trusted when owned by root (or by the daemon's
/// own euid, for non-root development runs) and not group/world-writable.
pub(crate) fn file_perms_ok(file_uid: u32, mode: u32, self_uid: u32) -> bool {
    (file_uid == 0 || file_uid == self_uid) && mode & 0o022 == 0
}

/// Effective UID via the st_uid of /proc/self; avoids a libc dependency.
pub(crate) fn effective_uid() -> Option<u32> {
    std::fs::metadata("/proc/self").map(|m| m.uid()).ok()
}

/// Confine a rule's match-list paths to `dir`.
///
/// Rules on disk are authored by root and may name any path. Rules arriving
/// over IPC are authored by any member of the `hallpass` group, whose granted
/// authority is managing rules and answering prompts, not reading root-only
/// files. Compiling a rule opens its list files as root, so an unconfined
/// path turned every root-readable, non-group-writable file (`/etc/shadow`,
/// `/proc/1/environ`) into something a group member could name and have the
/// daemon read.
///
/// Every rejection returns the same message: distinguishing "outside the
/// directory" from "does not exist" would leave a path-existence oracle.
fn list_paths_within(rule: &Rule, dir: &Path) -> Result<(), String> {
    let m = &rule.matcher;
    let fields = [
        ("domains_file", m.domains_file.as_deref()),
        ("ips_file", m.ips_file.as_deref()),
        ("hashes_file", m.hashes_file.as_deref()),
    ];
    if fields.iter().all(|(_, p)| p.is_none()) {
        return Ok(());
    }
    let canon_dir = dir
        .canonicalize()
        .map_err(|e| format!("cannot resolve rules dir {}: {e}", dir.display()))?;
    for (field, path) in fields {
        let Some(path) = path else { continue };
        let rejected = || format!("{field} must name a file in {}", canon_dir.display());
        // canonicalize resolves `..` and symlinks, so neither traversal nor a
        // link planted inside the directory escapes it.
        let canon = path.canonicalize().map_err(|_| rejected())?;
        if canon.parent() != Some(canon_dir.as_path()) {
            return Err(rejected());
        }
    }
    Ok(())
}

/// Turn a rule name into a safe file stem.
fn sanitize_filename(name: &str) -> String {
    let stem: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if stem.is_empty() || stem.chars().all(|c| c == '.') {
        "rule".to_string()
    } else {
        stem
    }
}

/// Result of scanning the rules directory: the accepted entries and how
/// many files were skipped (bad permissions, unparsable, or duplicate name).
struct LoadResult {
    entries: Vec<Entry>,
    skipped: u64,
}

fn load_dir(dir: &Path) -> LoadResult {
    let self_uid = effective_uid().unwrap_or(u32::MAX);
    let mut entries = Vec::new();
    let mut skipped = 0u64;
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), "cannot read rules dir: {e}");
            return LoadResult { entries, skipped };
        }
    };
    for item in read.flatten() {
        let path = item.path();
        if path.extension().is_none_or(|e| e != "toml") {
            continue;
        }
        // Reject symlinks before opening. `File::open` follows them, and
        // the fstat below would then describe the target, so a link is
        // the one way a rule could be loaded from outside this directory.
        // Checked off the directory entry, which does not follow.
        match item.file_type() {
            Ok(t) if t.is_symlink() => {
                tracing::warn!(file = %path.display(), "skipping symlinked rule file");
                skipped += 1;
                continue;
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(file = %path.display(), "cannot stat rule file: {e}");
                skipped += 1;
                continue;
            }
        }
        // Identity and content both come from this fd, as in lists.rs: no
        // window where the trust-checked file and the parsed bytes could
        // differ.
        let mut file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(file = %path.display(), "cannot open rule file: {e}");
                skipped += 1;
                continue;
            }
        };
        let meta = match file.metadata() {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(file = %path.display(), "cannot stat rule file: {e}");
                skipped += 1;
                continue;
            }
        };
        if !meta.is_file() {
            tracing::warn!(file = %path.display(), "skipping rule entry that is not a regular file");
            skipped += 1;
            continue;
        }
        if !file_perms_ok(meta.uid(), meta.mode(), self_uid) {
            tracing::warn!(
                file = %path.display(),
                uid = meta.uid(),
                mode = format!("{:o}", meta.mode() & 0o7777),
                "skipping rule file: must be owned by root and not group/world-writable"
            );
            skipped += 1;
            continue;
        }
        let mut text = String::new();
        let rule: Rule = match file
            .read_to_string(&mut text)
            .map_err(|e| e.to_string())
            .and_then(|_| toml::from_str(&text).map_err(|e| e.to_string()))
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(file = %path.display(), "skipping unparsable rule file: {e}");
                skipped += 1;
                continue;
            }
        };
        // The same validation add() applies: a rule that cannot compile
        // would otherwise sit inert in the set and crash clients that
        // render it (e.g. a malformed exe_sha256).
        if let Err(e) = CompiledRule::compile(&rule) {
            tracing::warn!(file = %path.display(), "skipping invalid rule file: {e}");
            skipped += 1;
            continue;
        }
        if entries.iter().any(|e: &Entry| e.rule.name == rule.name) {
            tracing::warn!(file = %path.display(), rule = %rule.name, "skipping duplicate rule name");
            skipped += 1;
            continue;
        }
        entries.push(Entry {
            rule,
            origin: Origin::Disk(path),
        });
    }
    LoadResult { entries, skipped }
}

impl RuleStore {
    /// Create a store, loading persisted rules from `rules_dir`.
    pub fn new(rules_dir: PathBuf) -> RuleStore {
        let loaded = load_dir(&rules_dir);
        tracing::info!(
            count = loaded.entries.len(),
            skipped = loaded.skipped,
            dir = %rules_dir.display(),
            "loaded disk rules"
        );
        let store = RuleStore {
            active: ArcSwap::from_pointee(RuleSet::compile(&[])),
            entries: Mutex::new(loaded.entries),
            rules_dir,
            rules_skipped: AtomicU64::new(loaded.skipped),
        };
        store.rebuild();
        store
    }

    /// Cumulative count of disk rule files skipped since startup.
    pub fn rules_skipped(&self) -> u64 {
        self.rules_skipped.load(Ordering::Relaxed)
    }

    /// Current compiled snapshot. The packet path takes one snapshot per
    /// packet so enrichment decisions and matching see the same rules.
    pub fn ruleset(&self) -> Arc<RuleSet> {
        self.active.load_full()
    }

    /// All rules, for `RuleList` replies.
    pub fn list(&self) -> Vec<Rule> {
        self.entries.lock().unwrap().iter().map(|e| e.rule.clone()).collect()
    }

    /// Add or replace a rule by name. Forever rules are persisted to disk.
    ///
    /// This is the entry point for rules that did not come from disk (IPC
    /// `RuleAdd` and prompt replies), so match-list paths are confined here.
    pub fn add(&self, rule: Rule) -> Result<(), String> {
        if rule.name.is_empty() {
            return Err("rule name must not be empty".into());
        }
        // Before compile: compiling opens the list files as root.
        list_paths_within(&rule, &self.rules_dir)?;
        CompiledRule::compile(&rule)?;
        // Persist while holding the entries lock: the directory watcher's
        // reload_disk() takes the same lock, so it cannot observe the new
        // file before this add lands in `entries`.
        let mut entries = self.entries.lock().unwrap();
        let origin = if rule.duration == hallpass_types::RuleDuration::Forever {
            Origin::Disk(self.persist(&rule, &entries)?)
        } else {
            Origin::Session
        };
        if let Some(pos) = entries.iter().position(|e| e.rule.name == rule.name) {
            let old = entries.remove(pos);
            // Replacing a disk rule with a session rule must not leave a
            // stale file that would resurrect the old rule on reload.
            if let Origin::Disk(old_path) = &old.origin {
                if !matches!(&origin, Origin::Disk(p) if p == old_path) {
                    let _ = std::fs::remove_file(old_path);
                }
            }
        }
        entries.push(Entry { rule, origin });
        drop(entries);
        self.rebuild();
        Ok(())
    }

    /// Delete a rule by name, removing its file if persisted.
    pub fn delete(&self, name: &str) -> Result<(), String> {
        let mut entries = self.entries.lock().unwrap();
        let pos = entries
            .iter()
            .position(|e| e.rule.name == name)
            .ok_or_else(|| format!("no such rule: {name}"))?;
        let old = entries.remove(pos);
        // Remove the file under the lock so a concurrent reload_disk()
        // cannot resurrect the rule from a file whose entry is gone.
        if let Origin::Disk(path) = &old.origin {
            if let Err(e) = std::fs::remove_file(path) {
                tracing::warn!(file = %path.display(), "failed to remove rule file: {e}");
            }
        }
        drop(entries);
        self.rebuild();
        Ok(())
    }

    /// Enable or disable a rule, updating its file if persisted.
    pub fn toggle(&self, name: &str, enabled: bool) -> Result<(), String> {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries
            .iter_mut()
            .find(|e| e.rule.name == name)
            .ok_or_else(|| format!("no such rule: {name}"))?;
        entry.rule.enabled = enabled;
        // Persist under the lock; see add() for the watcher race this
        // avoids. Write to the entry's own file: a hand-written rule can
        // live in a file whose name differs from the rule name, and a
        // name-derived path would orphan it (the stale file would revert
        // or resurrect the rule on the next reload).
        if let Origin::Disk(path) = entry.origin.clone() {
            let rule = entry.rule.clone();
            if let Err(e) = self.persist_to(&rule, &path) {
                entry.rule.enabled = !enabled;
                return Err(e);
            }
        }
        drop(entries);
        self.rebuild();
        Ok(())
    }

    /// Remove rules whose `Until` deadline has passed, deleting persisted
    /// files (hand-written `until` rules in rules.d). Returns whether
    /// anything was removed. Called by the expiry sweeper about once a
    /// second, which bounds how long an expired rule can keep matching.
    pub fn sweep_expired(&self) -> bool {
        let now = hallpass_types::unix_ms_now();
        let mut entries = self.entries.lock().unwrap();
        let before = entries.len();
        // File removal happens under the lock; see delete() for the
        // watcher race this avoids.
        entries.retain(|e| {
            if !e.rule.duration.expired(now) {
                return true;
            }
            tracing::info!(rule = %e.rule.name, "timed rule expired");
            if let Origin::Disk(path) = &e.origin {
                if let Err(err) = std::fs::remove_file(path) {
                    tracing::warn!(file = %path.display(), "failed to remove expired rule file: {err}");
                }
            }
            false
        });
        let changed = entries.len() != before;
        drop(entries);
        if changed {
            self.rebuild();
        }
        changed
    }

    /// Re-read disk rules (hot reload), keeping session rules.
    pub fn reload_disk(&self) {
        let fresh = load_dir(&self.rules_dir);
        self.rules_skipped.fetch_add(fresh.skipped, Ordering::Relaxed);
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|e| e.origin == Origin::Session);
        for f in fresh.entries {
            if !entries.iter().any(|e| e.rule.name == f.rule.name) {
                entries.push(f);
            }
        }
        drop(entries);
        self.rebuild();
        tracing::info!("rules reloaded from disk");
    }

    fn rebuild(&self) {
        let rules: Vec<Rule> = self.list();
        self.active.store(Arc::new(RuleSet::compile(&rules)));
    }

    fn persist(&self, rule: &Rule, entries: &[Entry]) -> Result<PathBuf, String> {
        std::fs::create_dir_all(&self.rules_dir)
            .map_err(|e| format!("create {}: {e}", self.rules_dir.display()))?;
        let path = self.unique_path(&rule.name, entries);
        self.persist_to(rule, &path)?;
        Ok(path)
    }

    /// A file path for `name` that no other rule's file occupies.
    /// Sanitizing collapses distinct names ("allow dns", "allow_dns",
    /// "allow/dns") onto one stem, and reusing a colliding path would
    /// silently overwrite the other rule's file.
    fn unique_path(&self, name: &str, entries: &[Entry]) -> PathBuf {
        let stem = sanitize_filename(name);
        let mine = |e: &Entry, p: &Path| {
            e.rule.name == name && matches!(&e.origin, Origin::Disk(d) if d == p)
        };
        let taken = |p: &PathBuf| {
            entries
                .iter()
                .any(|e| e.rule.name != name && matches!(&e.origin, Origin::Disk(d) if d == p))
                // A file nothing tracks (skipped as invalid, or another
                // rule's future name) is not ours to overwrite either.
                || (p.exists() && !entries.iter().any(|e| mine(e, p)))
        };
        let mut n = 1u32;
        loop {
            let path = if n == 1 {
                self.rules_dir.join(format!("{stem}.toml"))
            } else {
                self.rules_dir.join(format!("{stem}-{n}.toml"))
            };
            if !taken(&path) {
                return path;
            }
            n += 1;
        }
    }

    fn persist_to(&self, rule: &Rule, path: &Path) -> Result<(), String> {
        let text = toml::to_string_pretty(rule).map_err(|e| format!("serialize rule: {e}"))?;
        std::fs::write(path, text).map_err(|e| format!("write {}: {e}", path.display()))?;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
        Ok(())
    }
}

/// Periodically remove expired `Until` rules. One-second cadence: timed
/// rules overstay their deadline by at most about a second.
pub fn spawn_expiry_sweeper(store: Arc<RuleStore>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            store.sweep_expired();
        }
    });
}

/// Watch the rules directory and hot-reload on changes, debounced 200ms.
/// Returns an error if the watcher cannot be created; a missing directory
/// is tolerated (watch is skipped with a warning).
pub fn spawn_watcher(store: Arc<RuleStore>) -> notify::Result<()> {
    let dir = store.rules_dir.clone();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if res.is_ok() {
            let _ = tx.send(());
        }
    })?;
    if let Err(e) = watcher.watch(&dir, notify::RecursiveMode::NonRecursive) {
        tracing::warn!(dir = %dir.display(), "not watching rules dir: {e}");
        return Ok(());
    }
    tokio::spawn(async move {
        // Own the watcher so it lives as long as the task.
        let _watcher = watcher;
        while rx.recv().await.is_some() {
            tokio::time::sleep(Duration::from_millis(200)).await;
            while rx.try_recv().is_ok() {}
            store.reload_disk();
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestDir;
    use hallpass_types::{Action, RuleDuration, RuleMatch};

    fn rule(name: &str, duration: RuleDuration) -> Rule {
        Rule {
            name: name.into(),
            action: Action::Allow,
            duration,
            priority: 1,
            enabled: true,
            matcher: RuleMatch {
                port: Some(443),
                ..Default::default()
            },
        }
    }

    fn tmpdir(tag: &str) -> (TestDir, PathBuf) {
        let td = TestDir::new(&format!("store-{tag}"));
        let path = td.path().to_path_buf();
        (td, path)
    }

    fn rule_with_ips_file(path: &Path) -> Rule {
        let mut r = rule("listy", RuleDuration::Session);
        r.matcher.ips_file = Some(path.to_path_buf());
        r
    }

    /// A list path outside the rules directory is refused before anything
    /// opens it, so an IPC client cannot aim the root daemon at /etc/shadow.
    #[test]
    fn add_refuses_list_file_outside_rules_dir() {
        let (_td, dir) = tmpdir("outside-list");
        let outside = dir.join("elsewhere");
        std::fs::create_dir_all(&outside).unwrap();
        let list = outside.join("ips.list");
        std::fs::write(&list, "10.0.0.1\n").unwrap();

        let store = RuleStore::new(dir.join("rules.d"));
        std::fs::create_dir_all(dir.join("rules.d")).unwrap();
        let err = store.add(rule_with_ips_file(&list)).unwrap_err();
        assert!(err.contains("ips_file must name a file in"), "{err}");
    }

    /// The rejection for a nonexistent path is byte-identical to the one for
    /// a path outside the directory: no path-existence oracle.
    #[test]
    fn add_list_file_rejection_does_not_leak_existence() {
        let (_td, dir) = tmpdir("oracle-list");
        let rules_dir = dir.join("rules.d");
        std::fs::create_dir_all(&rules_dir).unwrap();
        let store = RuleStore::new(rules_dir);

        let real_but_outside = dir.join("real.list");
        std::fs::write(&real_but_outside, "10.0.0.1\n").unwrap();
        let missing = dir.join("definitely-absent.list");

        let a = store.add(rule_with_ips_file(&real_but_outside)).unwrap_err();
        let b = store.add(rule_with_ips_file(&missing)).unwrap_err();
        assert_eq!(a, b, "existing and missing paths must be indistinguishable");
    }

    /// A list file inside the rules directory still works.
    #[test]
    fn add_accepts_list_file_inside_rules_dir() {
        let (_td, dir) = tmpdir("inside-list");
        let rules_dir = dir.join("rules.d");
        std::fs::create_dir_all(&rules_dir).unwrap();
        let list = rules_dir.join("ips.list");
        std::fs::write(&list, "10.0.0.1\n").unwrap();

        let store = RuleStore::new(rules_dir);
        store.add(rule_with_ips_file(&list)).expect("in-dir list accepted");
    }

    #[test]
    fn perms_policy() {
        assert!(file_perms_ok(0, 0o100644, 1000));
        assert!(file_perms_ok(1000, 0o100600, 1000));
        assert!(!file_perms_ok(1001, 0o100644, 1000)); // wrong owner
        assert!(!file_perms_ok(0, 0o100664, 1000)); // group-writable
        assert!(!file_perms_ok(0, 0o100646, 1000)); // world-writable
    }

    /// A rule file reached through a symlink is not loaded. The mode of
    /// the link itself would pass no trust check, but the point is that
    /// the check and the read now see the same fd, so a link swapped in
    /// after the check cannot redirect what gets parsed.
    #[test]
    fn symlinked_rule_file_is_skipped() {
        let (_td, dir) = tmpdir("symlink");
        let outside = dir.join("real.txt");
        std::fs::write(
            &outside,
            "name = \"linked\"\naction = \"allow\"\nduration = \"forever\"\n\
             priority = 1\nenabled = true\n[match]\nport = 80\n",
        )
        .unwrap();
        let rules = dir.join("rules.d");
        std::fs::create_dir_all(&rules).unwrap();
        std::os::unix::fs::symlink(&outside, rules.join("linked.toml")).unwrap();

        let store = RuleStore::new(rules);
        assert!(
            store.list().is_empty(),
            "a symlinked rule file should not be loaded"
        );
    }

    #[test]
    fn filename_sanitization() {
        assert_eq!(sanitize_filename("allow-dns"), "allow-dns");
        assert_eq!(sanitize_filename("a/b c!"), "a_b_c_");
        assert_eq!(sanitize_filename(""), "rule");
        assert_eq!(sanitize_filename(".."), "rule");
    }

    #[test]
    fn forever_rule_persists_and_reloads() {
        let (_td, dir) = tmpdir("persist");
        let store = RuleStore::new(dir.clone());
        store.add(rule("keep-me", RuleDuration::Forever)).unwrap();
        assert!(dir.join("keep-me.toml").exists());

        // A fresh store sees the persisted rule.
        let store2 = RuleStore::new(dir.clone());
        let listed = store2.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0], rule("keep-me", RuleDuration::Forever));

    }

    #[test]
    fn session_rule_is_memory_only_and_survives_reload() {
        let (_td, dir) = tmpdir("session");
        let store = RuleStore::new(dir.clone());
        store.add(rule("ephemeral", RuleDuration::Session)).unwrap();
        assert!(std::fs::read_dir(&dir).unwrap().next().is_none());
        store.reload_disk();
        assert_eq!(store.list().len(), 1);
    }

    #[test]
    fn delete_and_toggle_update_disk() {
        let (_td, dir) = tmpdir("mutate");
        let store = RuleStore::new(dir.clone());
        store.add(rule("r1", RuleDuration::Forever)).unwrap();

        store.toggle("r1", false).unwrap();
        let on_disk: Rule =
            toml::from_str(&std::fs::read_to_string(dir.join("r1.toml")).unwrap()).unwrap();
        assert!(!on_disk.enabled);
        assert_eq!(store.ruleset().rule_count(), 1);

        store.delete("r1").unwrap();
        assert!(!dir.join("r1.toml").exists());
        assert!(store.list().is_empty());
        assert!(store.delete("r1").is_err());
        assert!(store.toggle("r1", true).is_err());
    }

    /// Toggling a hand-written rule whose file name differs from the
    /// rule name must update that file, not spawn a name-derived twin
    /// that reverts or resurrects the rule on reload.
    #[test]
    fn toggle_updates_the_original_disk_file() {
        let (_td, dir) = tmpdir("toggle-origin");
        let text = "name = \"block-x\"\naction = \"deny\"\nduration = \"forever\"\n\
                    priority = 1\nenabled = true\n[match]\nport = 25\n";
        std::fs::write(dir.join("00-block.toml"), text).unwrap();
        let store = RuleStore::new(dir.clone());
        store.toggle("block-x", false).unwrap();

        assert!(!dir.join("block-x.toml").exists(), "no name-derived twin");
        let on_disk: Rule =
            toml::from_str(&std::fs::read_to_string(dir.join("00-block.toml")).unwrap()).unwrap();
        assert!(!on_disk.enabled, "the original file carries the toggle");
        store.reload_disk();
        assert!(!store.list()[0].enabled, "reload does not revert the toggle");
    }

    /// Distinct rule names that sanitize to the same file stem must not
    /// share a file: the second persist would silently overwrite (and a
    /// later delete would remove) the first rule's backing file.
    #[test]
    fn colliding_sanitized_names_get_distinct_files() {
        let (_td, dir) = tmpdir("collide");
        let store = RuleStore::new(dir.clone());
        store.add(rule("allow dns", RuleDuration::Forever)).unwrap();
        store.add(rule("allow_dns", RuleDuration::Forever)).unwrap();

        let files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(files.len(), 2, "one file per rule: {files:?}");
        let store2 = RuleStore::new(dir);
        assert_eq!(store2.list().len(), 2, "both rules survive a restart");
    }

    /// An unparsable-but-valid-TOML rule (bad matcher) is skipped on
    /// load, like add() would have rejected it.
    #[test]
    fn invalid_disk_rule_is_skipped_on_load() {
        let (_td, dir) = tmpdir("invalid-disk");
        let text = "name = \"bad\"\naction = \"deny\"\nduration = \"forever\"\n\
                    priority = 1\nenabled = true\n[match]\ndest = \"not-an-ip\"\n";
        std::fs::write(dir.join("bad.toml"), text).unwrap();
        let store = RuleStore::new(dir);
        assert!(store.list().is_empty());
        assert_eq!(store.rules_skipped(), 1);
    }

    /// A misspelled match operand must fail the file, not silently drop the
    /// criterion. Dropping every criterion leaves a matcher that matches all
    /// connections, so `exe_path` for `exe` used to promote a narrow allow
    /// into an unconditional one at that rule's priority.
    #[test]
    fn misspelled_match_operand_skips_the_rule_file() {
        let (_td, dir) = tmpdir("typo-operand");
        let text = "name = \"typo\"\naction = \"allow\"\nduration = \"forever\"\n\
                    priority = 100\nenabled = true\n[match]\n\
                    exe_path = \"/usr/bin/curl\"\nprt = 443\n";
        std::fs::write(dir.join("typo.toml"), text).unwrap();
        let store = RuleStore::new(dir);
        assert!(
            store.list().is_empty(),
            "a rule with unknown match keys must not load: {:?}",
            store.list()
        );
        assert_eq!(store.rules_skipped(), 1);
    }

    /// An unknown key at the top level of a rule file is refused too.
    #[test]
    fn unknown_top_level_rule_key_skips_the_rule_file() {
        let (_td, dir) = tmpdir("typo-toplevel");
        let text = "name = \"t\"\naction = \"deny\"\nduration = \"forever\"\n\
                    priority = 1\nenabled = true\nprioritee = 9\n[match]\nport = 25\n";
        std::fs::write(dir.join("t.toml"), text).unwrap();
        let store = RuleStore::new(dir);
        assert!(store.list().is_empty());
        assert_eq!(store.rules_skipped(), 1);
    }

    #[test]
    fn replacing_disk_rule_with_session_rule_removes_file() {
        let (_td, dir) = tmpdir("replace");
        let store = RuleStore::new(dir.clone());
        store.add(rule("r1", RuleDuration::Forever)).unwrap();
        assert!(dir.join("r1.toml").exists());
        store.add(rule("r1", RuleDuration::Session)).unwrap();
        assert!(!dir.join("r1.toml").exists());
        assert_eq!(store.list().len(), 1);
    }

    #[test]
    fn sweep_removes_expired_until_rules() {
        let (_td, dir) = tmpdir("sweep");
        let store = RuleStore::new(dir.clone());
        let now = hallpass_types::unix_ms_now();
        let expired = rule(
            "expired",
            RuleDuration::Until {
                deadline_ms: now.saturating_sub(1),
            },
        );
        let live = rule(
            "live",
            RuleDuration::Until {
                deadline_ms: now + 60_000,
            },
        );
        store.add(expired).unwrap();
        store.add(live).unwrap();
        store.add(rule("forever", RuleDuration::Forever)).unwrap();
        assert_eq!(store.list().len(), 3);

        assert!(store.sweep_expired());
        let names: Vec<String> = store.list().into_iter().map(|r| r.name).collect();
        assert_eq!(names, vec!["live".to_string(), "forever".to_string()]);
        // Nothing left to expire; sweep is a no-op.
        assert!(!store.sweep_expired());
    }

    #[test]
    fn sweep_deletes_expired_disk_rule_file() {
        let (_td, dir) = tmpdir("sweep-disk");
        // Hand-written rules.d file with an already-passed deadline.
        let text = "name = \"stale\"\n\
                    action = \"deny\"\n\
                    priority = 1\n\
                    enabled = true\n\
                    [duration.until]\n\
                    deadline_ms = 1000\n\
                    [match]\n\
                    port = 25\n";
        std::fs::write(dir.join("stale.toml"), text).unwrap();
        let store = RuleStore::new(dir.clone());
        assert_eq!(store.list().len(), 1);
        assert!(store.sweep_expired());
        assert!(store.list().is_empty());
        assert!(!dir.join("stale.toml").exists(), "expired rule file should be deleted");
    }

    #[test]
    fn invalid_rule_rejected_on_add() {
        let (_td, dir) = tmpdir("invalid");
        let store = RuleStore::new(dir.clone());
        let mut bad = rule("bad", RuleDuration::Session);
        bad.matcher.dest = Some("not-an-ip".into());
        assert!(store.add(bad).is_err());
        let mut unnamed = rule("", RuleDuration::Session);
        unnamed.name = String::new();
        assert!(store.add(unnamed).is_err());
    }
}

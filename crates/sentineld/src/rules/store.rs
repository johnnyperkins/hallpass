//! Rule persistence and hot reload.
//!
//! Disk rules live as one TOML file per rule in the configured rules
//! directory; session rules live only in memory. Every mutation rebuilds
//! the compiled [`RuleSet`] and swaps it atomically, so the packet path
//! reads rules lock-free.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use notify::Watcher;
use sentinel_types::Rule;

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
}

/// A rule file is trusted when owned by root (or by the daemon's own euid,
/// for non-root development runs) and not group/world-writable.
fn file_perms_ok(file_uid: u32, mode: u32, self_uid: u32) -> bool {
    (file_uid == 0 || file_uid == self_uid) && mode & 0o022 == 0
}

/// Effective UID via the st_uid of /proc/self; avoids a libc dependency.
pub(crate) fn effective_uid() -> Option<u32> {
    std::fs::metadata("/proc/self").map(|m| m.uid()).ok()
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

fn load_dir(dir: &Path) -> Vec<Entry> {
    let self_uid = effective_uid().unwrap_or(u32::MAX);
    let mut entries = Vec::new();
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), "cannot read rules dir: {e}");
            return entries;
        }
    };
    for item in read.flatten() {
        let path = item.path();
        if path.extension().is_none_or(|e| e != "toml") {
            continue;
        }
        let meta = match item.metadata() {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(file = %path.display(), "cannot stat rule file: {e}");
                continue;
            }
        };
        if !file_perms_ok(meta.uid(), meta.mode(), self_uid) {
            tracing::warn!(
                file = %path.display(),
                uid = meta.uid(),
                mode = format!("{:o}", meta.mode() & 0o7777),
                "skipping rule file: must be owned by root and not group/world-writable"
            );
            continue;
        }
        let rule: Rule = match std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|t| toml::from_str(&t).map_err(|e| e.to_string()))
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(file = %path.display(), "skipping unparsable rule file: {e}");
                continue;
            }
        };
        if entries.iter().any(|e: &Entry| e.rule.name == rule.name) {
            tracing::warn!(file = %path.display(), rule = %rule.name, "skipping duplicate rule name");
            continue;
        }
        entries.push(Entry {
            rule,
            origin: Origin::Disk(path),
        });
    }
    entries
}

impl RuleStore {
    /// Create a store, loading persisted rules from `rules_dir`.
    pub fn new(rules_dir: PathBuf) -> RuleStore {
        let entries = load_dir(&rules_dir);
        tracing::info!(count = entries.len(), dir = %rules_dir.display(), "loaded disk rules");
        let store = RuleStore {
            active: ArcSwap::from_pointee(RuleSet::compile(&[])),
            entries: Mutex::new(entries),
            rules_dir,
        };
        store.rebuild();
        store
    }

    /// Current compiled snapshot. Callers that only need one lookup
    /// should prefer [`RuleStore::match_verdict`].
    pub fn ruleset(&self) -> Arc<RuleSet> {
        self.active.load_full()
    }

    /// Match one connection against the active snapshot. Uses the cheap
    /// `load()` guard instead of cloning the Arc; this is the per-packet
    /// path.
    pub fn match_verdict(
        &self,
        conn: &sentinel_types::Connection,
    ) -> Option<(String, sentinel_types::Verdict)> {
        self.active
            .load()
            .match_conn(conn)
            .map(|(rule, verdict)| (rule.name.clone(), verdict))
    }

    /// All rules, for `RuleList` replies.
    pub fn list(&self) -> Vec<Rule> {
        self.entries.lock().unwrap().iter().map(|e| e.rule.clone()).collect()
    }

    /// Add or replace a rule by name. Forever rules are persisted to disk.
    pub fn add(&self, rule: Rule) -> Result<(), String> {
        if rule.name.is_empty() {
            return Err("rule name must not be empty".into());
        }
        CompiledRule::compile(&rule)?;
        let origin = if rule.duration == sentinel_types::RuleDuration::Forever {
            Origin::Disk(self.persist(&rule)?)
        } else {
            Origin::Session
        };
        let mut entries = self.entries.lock().unwrap();
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
        drop(entries);
        if let Origin::Disk(path) = old.origin {
            if let Err(e) = std::fs::remove_file(&path) {
                tracing::warn!(file = %path.display(), "failed to remove rule file: {e}");
            }
        }
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
        let persist = match &entry.origin {
            Origin::Disk(_) => Some(entry.rule.clone()),
            Origin::Session => None,
        };
        drop(entries);
        if let Some(rule) = persist {
            self.persist(&rule)?;
        }
        self.rebuild();
        Ok(())
    }

    /// Re-read disk rules (hot reload), keeping session rules.
    pub fn reload_disk(&self) {
        let fresh = load_dir(&self.rules_dir);
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|e| e.origin == Origin::Session);
        for f in fresh {
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

    fn persist(&self, rule: &Rule) -> Result<PathBuf, String> {
        std::fs::create_dir_all(&self.rules_dir)
            .map_err(|e| format!("create {}: {e}", self.rules_dir.display()))?;
        let path = self
            .rules_dir
            .join(format!("{}.toml", sanitize_filename(&rule.name)));
        let text = toml::to_string_pretty(rule).map_err(|e| format!("serialize rule: {e}"))?;
        std::fs::write(&path, text).map_err(|e| format!("write {}: {e}", path.display()))?;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
        Ok(path)
    }
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
    use sentinel_types::{Action, RuleDuration, RuleMatch};

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

    #[test]
    fn perms_policy() {
        assert!(file_perms_ok(0, 0o100644, 1000));
        assert!(file_perms_ok(1000, 0o100600, 1000));
        assert!(!file_perms_ok(1001, 0o100644, 1000)); // wrong owner
        assert!(!file_perms_ok(0, 0o100664, 1000)); // group-writable
        assert!(!file_perms_ok(0, 0o100646, 1000)); // world-writable
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

use super::*;
use crate::testutil::TestDir;
use hallpass_types::{Action, RuleDuration, RuleMatch};
use std::os::unix::fs::PermissionsExt;

/// Every rule file `install.sh` puts in `/etc/hallpass/rules.d` has to
/// survive the same load path a daemon puts it through.
///
/// `load_dir` skips a file it cannot parse or compile and carries on
/// with a warning, which is right for an operator's own rules and
/// dangerous for these: the baseline exists so the daemons that run
/// before anyone can answer a prompt are not denied, so a typo in one
/// of them costs a booting host its DNS or its clock and says so only
/// in the journal. Nothing else reads these files before a release.
///
/// The rule *name* is checked too, because `load_dir` drops a second
/// file claiming a name it has already seen. Two baseline files that
/// disagree about which one loads is the same outage as a typo, and it
/// is the mistake copying an existing file to cover a new daemon makes.
///
/// Reads the directory rather than naming the files, so a baseline rule
/// added later is covered without anyone remembering this test.
#[test]
fn the_shipped_rule_files_parse_and_compile() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../etc/rules.d");
    let mut names: Vec<(String, String)> = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("etc/rules.d is missing") {
        let path = entry.expect("unreadable directory entry").path();
        if path.extension().is_none_or(|e| e != "toml") {
            continue;
        }
        let file = path.file_name().unwrap_or_default().to_string_lossy();
        let text = std::fs::read_to_string(&path).expect("unreadable rule file");
        let rule: Rule = toml::from_str(&text)
            .unwrap_or_else(|e| panic!("etc/rules.d/{file} does not parse: {e}"));
        CompiledRule::compile(&rule)
            .unwrap_or_else(|e| panic!("etc/rules.d/{file} does not compile: {e}"));
        if let Some((other, _)) = names.iter().find(|(_, n)| *n == rule.name) {
            panic!(
                "etc/rules.d/{file} and etc/rules.d/{other} both name a rule \
                 {:?}; load_dir would skip whichever it read second",
                rule.name
            );
        }
        names.push((file.into_owned(), rule.name));
    }
    assert!(
        !names.is_empty(),
        "no rule files found in {}",
        dir.display()
    );
}

fn rule(name: &str, duration: RuleDuration) -> Rule {
    Rule {
        name: name.into(),
        action: Action::Allow,
        duration,
        priority: 1,
        enabled: true,
        tags: Vec::new(),
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

/// A directory the trust checks accept, whatever the umask. Rule and
/// list files are refused unless they are not group/world-writable, and
/// `create_dir_all` alone inherits the umask; see
/// [`crate::testutil::trust_mode`].
fn trusted_dir(path: &Path) -> PathBuf {
    std::fs::create_dir_all(path).unwrap();
    crate::testutil::trust_mode(path);
    path.to_path_buf()
}

/// Write a rule or list file the loader will accept. See
/// [`crate::testutil::write_trusted`].
fn write(path: PathBuf, text: &str) -> PathBuf {
    crate::testutil::write_trusted(&path, text);
    path
}

fn rule_with_ips_file(path: &Path) -> Rule {
    let mut r = rule("listy", RuleDuration::Session);
    r.matcher.ips_file = Some(path.to_path_buf());
    r
}

/// **Unlinking a file needs write on the directory, not on the file.**
/// Every per-file check in this module is worth nothing if the directory
/// holding those files can be written by someone the daemon does not
/// trust: they cannot forge a rule (a file they create is theirs, and
/// `file_perms_ok` refuses it), but they can *delete* root's deny rules,
/// and `load_dir` reads a vanished file as an ordinary delete - nothing
/// skipped, nothing counted, the shrunken set applied as policy.
#[test]
fn a_writable_policy_directory_is_not_trusted() {
    let self_uid = 1000;
    // The shipped shape.
    assert!(dir_trust_ok(0, 0o755, self_uid), "root-owned 0755");
    // A non-root development run owns its own directory.
    assert!(dir_trust_ok(self_uid, 0o755, self_uid));

    // Group or world write is the delete power, whichever it is.
    assert!(!dir_trust_ok(0, 0o775, self_uid), "group-writable");
    assert!(!dir_trust_ok(0, 0o757, self_uid), "world-writable");
    // Owned by someone else entirely: they can replace it wholesale.
    assert!(!dir_trust_ok(1234, 0o755, self_uid));

    // The sticky bit takes the delete power back, so it is not a finding:
    // with `t` set a user may only unlink files they own, and files they
    // create are refused by `file_perms_ok` as before.
    assert!(dir_trust_ok(0, 0o1777, self_uid), "sticky");
}

/// The same check over a real directory, including the two answers that
/// are not failures: a directory that does not exist yet (no rule has
/// been persisted), and one at the shipped mode.
#[test]
fn check_policy_dir_accepts_absent_and_well_moded_directories() {
    use std::os::unix::fs::PermissionsExt;

    let (_td, dir) = tmpdir("policy-dir");
    let rules = trusted_dir(&dir.join("rules.d"));
    check_policy_dir(&rules).expect("0755 is the shipped mode");

    // Never created, because nothing has been persisted yet.
    check_policy_dir(&dir.join("never-made")).expect("absent is not untrusted");

    // A file where a directory belongs is a misconfiguration worth
    // naming rather than reading rules out of.
    let not_a_dir = write(dir.join("regular"), "");
    assert!(check_policy_dir(&not_a_dir).is_err());

    std::fs::set_permissions(&rules, std::fs::Permissions::from_mode(0o775)).unwrap();
    let err = check_policy_dir(&rules).expect_err("group-writable must be refused");
    // The message has to say what to do about it: this is read by an
    // operator in a journal, not by a developer at a backtrace.
    assert!(err.contains("delete or replace"), "{err}");
    assert!(err.contains("chmod 755"), "{err}");
}

/// The daemon must not create the state it refuses to start on. Plain
/// `create_dir_all` uses `0777 & ~umask`, so under the `umask 002` that
/// Debian and Ubuntu ship, a daemon run outside the unit would make its
/// own rules directory group-writable on the first persisted rule.
#[test]
fn persisting_creates_the_rules_directory_at_a_trusted_mode() {
    let (_td, dir) = tmpdir("persist-mkdir");
    let rules_dir = dir.join("made-on-demand");
    let store = RuleStore::new(rules_dir.clone());
    store
        .add(rule("keeper", RuleDuration::Forever))
        .expect("a forever rule is persisted, creating the directory");
    assert!(rules_dir.is_dir(), "the directory was created");
    check_policy_dir(&rules_dir).expect("and at a mode the daemon trusts");
}

/// A list path outside the rules directory is refused before anything
/// opens it, so an IPC client cannot aim the root daemon at /etc/shadow.
#[test]
fn add_refuses_list_file_outside_rules_dir() {
    let (_td, dir) = tmpdir("outside-list");
    let outside = trusted_dir(&dir.join("elsewhere"));
    let list = write(outside.join("ips.list"), "10.0.0.1\n");

    let store = RuleStore::new(dir.join("rules.d"));
    trusted_dir(&dir.join("rules.d"));
    let err = store.add(rule_with_ips_file(&list)).unwrap_err();
    assert!(err.contains("ips_file must name a file in"), "{err}");
}

/// The rejection for a nonexistent path is byte-identical to the one for
/// a path outside the directory: no path-existence oracle.
#[test]
fn add_list_file_rejection_does_not_leak_existence() {
    let (_td, dir) = tmpdir("oracle-list");
    let rules_dir = trusted_dir(&dir.join("rules.d"));
    let store = RuleStore::new(rules_dir);

    let real_but_outside = write(dir.join("real.list"), "10.0.0.1\n");
    let missing = dir.join("definitely-absent.list");

    let a = store
        .add(rule_with_ips_file(&real_but_outside))
        .unwrap_err();
    let b = store.add(rule_with_ips_file(&missing)).unwrap_err();
    assert_eq!(a, b, "existing and missing paths must be indistinguishable");
}

/// A list file inside the rules directory still works.
#[test]
fn add_accepts_list_file_inside_rules_dir() {
    let (_td, dir) = tmpdir("inside-list");
    let rules_dir = trusted_dir(&dir.join("rules.d"));
    let list = write(rules_dir.join("ips.list"), "10.0.0.1\n");

    let store = RuleStore::new(rules_dir);
    store
        .add(rule_with_ips_file(&list))
        .expect("in-dir list accepted");
}

/// A path that reaches the rules directory through a symlink the client
/// controls is stored as the file it resolved to, so repointing the link
/// afterwards changes nothing the daemon opens. Stored as sent, the next
/// rebuild followed the link to wherever it pointed by then, any
/// root-owned file on the host.
#[test]
fn add_stores_the_list_path_it_checked() {
    let (_td, dir) = tmpdir("list-link");
    let rules_dir = trusted_dir(&dir.join("rules.d"));
    let list = write(rules_dir.join("ips.list"), "10.0.0.1\n");
    let client = dir.join("client");
    std::fs::create_dir_all(&client).unwrap();
    let link = client.join("l");
    std::os::unix::fs::symlink(&list, &link).unwrap();

    let store = RuleStore::new(rules_dir);
    let mut r = rule_with_ips_file(&link);
    r.duration = RuleDuration::Forever;
    store
        .add(r)
        .expect("the link resolves inside the rules dir");

    let stored = store.list();
    let stored = stored.iter().find(|r| r.name == "listy").unwrap();
    assert_eq!(
        stored.matcher.ips_file.as_deref(),
        Some(list.canonicalize().unwrap().as_path()),
        "the rule keeps the resolved path, not the link"
    );
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
    let outside = write(
        dir.join("real.txt"),
        "name = \"linked\"\naction = \"allow\"\nduration = \"forever\"\n\
         priority = 1\nenabled = true\n[match]\nport = 80\n",
    );
    let rules = trusted_dir(&dir.join("rules.d"));
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
    write(dir.join("00-block.toml"), text);
    let store = RuleStore::new(dir.clone());
    store.toggle("block-x", false).unwrap();

    assert!(!dir.join("block-x.toml").exists(), "no name-derived twin");
    let on_disk: Rule =
        toml::from_str(&std::fs::read_to_string(dir.join("00-block.toml")).unwrap()).unwrap();
    assert!(!on_disk.enabled, "the original file carries the toggle");
    store.reload_disk();
    assert!(
        !store.list()[0].enabled,
        "reload does not revert the toggle"
    );
}

fn tagged(name: &str, tags: &[&str], duration: RuleDuration) -> Rule {
    let mut r = rule(name, duration);
    r.tags = tags.iter().map(|t| (*t).to_string()).collect();
    r
}

/// The bulk toggle reaches exactly the tagged rules, on disk and in
/// memory, and leaves everything else where it was.
#[test]
fn toggle_tag_changes_only_tagged_rules() {
    let (_td, dir) = tmpdir("toggle-tag");
    let store = RuleStore::new(dir.clone());
    store
        .add(tagged("w1", &["work", "vpn"], RuleDuration::Forever))
        .unwrap();
    store
        .add(tagged("w2", &["work"], RuleDuration::Session))
        .unwrap();
    store.add(rule("other", RuleDuration::Forever)).unwrap();

    let (changed, failed) = store.toggle_tag("work", false).unwrap();
    assert_eq!((changed, failed.len()), (2, 0));
    let by_name = |n: &str| store.list().into_iter().find(|r| r.name == n).unwrap();
    assert!(!by_name("w1").enabled);
    assert!(!by_name("w2").enabled, "a session rule toggles too");
    assert!(by_name("other").enabled, "an untagged rule is untouched");

    // The disk rule's file carries it, so a reload does not revert.
    let on_disk: Rule =
        toml::from_str(&std::fs::read_to_string(dir.join("w1.toml")).unwrap()).unwrap();
    assert!(!on_disk.enabled);
    assert_eq!(on_disk.tags, vec!["work".to_string(), "vpn".to_string()]);

    // Already in the requested state: nothing to change, and no error.
    let (changed, failed) = store.toggle_tag("work", false).unwrap();
    assert_eq!((changed, failed.len()), (0, 0));

    // A tag no rule carries is an error, not an empty success: it is a
    // typo, and a quiet zero reads as "your rules are disabled".
    assert!(store.toggle_tag("wrok", false).is_err());
}

/// **A mistyped label must not cost a rule its enforcement.** A tag
/// cannot change what a rule matches, so a rule file carrying an
/// unusable one loads and enforces exactly as written, with the tag
/// dropped. Refusing the file instead would mean `tags = ["Prod"]` on a
/// deny rule silently passes the traffic that rule exists to stop.
#[test]
fn a_rule_file_with_an_unusable_tag_still_enforces() {
    let (_td, dir) = tmpdir("bad-tag-file");
    let text = "name = \"deny-telemetry\"\naction = \"deny\"\nduration = \"forever\"\n\
                priority = 1\nenabled = true\ntags = [\"Prod\", \"work\", \"work\", \"-\"]\n\
                [match]\nport = 25\n";
    write(dir.join("00-deny.toml"), text);
    let store = RuleStore::new(dir.clone());
    let loaded = store.list();
    assert_eq!(loaded.len(), 1, "an unusable tag skipped the whole rule");
    assert_eq!(store.rules_skipped(), 0);
    assert!(loaded[0].enabled);
    // Only the usable one survives, and only once: nothing that got
    // through could have been named by a selector anyway.
    assert_eq!(loaded[0].tags, vec!["work".to_string()]);
    // And it is in the set it can be selected by.
    assert_eq!(store.toggle_tag("work", false).unwrap(), (1, Vec::new()));
}

/// The interactive path stays strict: there a refusal costs an error
/// message, not an unenforced rule, so the operator finds out before the
/// rule is in a set it does not belong to.
#[test]
fn add_refuses_an_unusable_tag() {
    let (_td, dir) = tmpdir("bad-tag-add");
    let store = RuleStore::new(dir);
    for bad in ["Work", "work lab", "-", &"a".repeat(33)] {
        let err = store
            .add(tagged("r", &[bad], RuleDuration::Session))
            .expect_err("accepted {bad:?}");
        assert!(err.contains("tag"), "{err}");
    }
    assert!(store
        .add(tagged("dup", &["work", "work"], RuleDuration::Session))
        .is_err());
    assert!(store.list().is_empty(), "a refused add left a rule behind");
    assert!(store
        .add(tagged("ok", &["work"], RuleDuration::Session))
        .is_ok());
}

/// The three claims [`RuleStore::set_enabled`] makes about a rule whose
/// file cannot be written: it keeps the state it had, the rest of the
/// selection still applies, and it is named back. Untested, a lost
/// revert would have `RuleList` reporting a rule disabled while its file
/// and the next reload bring it back enforcing.
#[test]
fn a_rule_whose_file_cannot_be_written_keeps_its_state() {
    let (_td, dir) = tmpdir("toggle-fail");
    let store = RuleStore::new(dir.clone());
    store
        .add(tagged("ok", &["work"], RuleDuration::Forever))
        .unwrap();
    store
        .add(tagged("stuck", &["work"], RuleDuration::Forever))
        .unwrap();

    // Unwritable in the one way `write_atomic` cannot work around: its
    // final rename lands on a directory. Read-only permissions would not
    // do it, since the rename replaces the file rather than opening it.
    let stuck = dir.join("stuck.toml");
    std::fs::remove_file(&stuck).unwrap();
    std::fs::create_dir(&stuck).unwrap();

    let (changed, failed) = store.toggle_tag("work", false).unwrap();
    assert_eq!(changed, 1, "the rest of the selection must still apply");
    assert_eq!(failed, vec!["stuck".to_string()], "the name is reported");
    let by_name = |n: &str| store.list().into_iter().find(|r| r.name == n).unwrap();
    assert!(!by_name("ok").enabled);
    assert!(
        by_name("stuck").enabled,
        "a rule that could not be written was reported as disabled while its \
         file still enables it"
    );
}

/// A rule file written before tags existed must keep loading, tags or
/// no tags. Without `serde(default)` on the field this scan skips every
/// rule an operator already had, and reports it only as warnings.
#[test]
fn a_rule_file_without_tags_still_loads() {
    let (_td, dir) = tmpdir("pre-tags");
    let text = "name = \"old\"\naction = \"deny\"\nduration = \"forever\"\n\
                priority = 1\nenabled = true\n[match]\nport = 25\n";
    write(dir.join("00-old.toml"), text);
    let store = RuleStore::new(dir.clone());
    let loaded = store.list();
    assert_eq!(loaded.len(), 1, "pre-tags rule file must load");
    assert!(loaded[0].tags.is_empty());
    assert_eq!(store.rules_skipped(), 0);
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
    write(dir.join("bad.toml"), text);
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
    write(dir.join("typo.toml"), text);
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
    write(dir.join("t.toml"), text);
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
    write(dir.join("stale.toml"), text);
    let store = RuleStore::new(dir.clone());
    assert_eq!(store.list().len(), 1);
    assert!(store.sweep_expired());
    assert!(store.list().is_empty());
    assert!(
        !dir.join("stale.toml").exists(),
        "expired rule file should be deleted"
    );
}

#[test]
fn hits_count_per_name_and_survive_reload() {
    let (_td, dir) = tmpdir("hits");
    let store = RuleStore::new(dir.clone());
    store.add(rule("a", RuleDuration::Forever)).unwrap();
    store.add(rule("b", RuleDuration::Forever)).unwrap();

    store.record_hit("a");
    store.record_hit("a");
    let hits = store.hits();
    assert_eq!(hits.len(), 2, "every loaded rule is reported");
    let a = hits.iter().find(|h| h.name == "a").unwrap();
    assert_eq!(a.hits, 2);
    assert!(a.last_hit_ms.is_some());
    // A rule that never fired reports zero rather than vanishing: that
    // is the interesting answer when auditing dead policy.
    let b = hits.iter().find(|h| h.name == "b").unwrap();
    assert_eq!(b.hits, 0);
    assert_eq!(b.last_hit_ms, None);

    // Editing rules on disk must not reset the accounting.
    store.reload_disk();
    assert_eq!(store.hits().iter().find(|h| h.name == "a").unwrap().hits, 2);

    // A name with no loaded rule is not reported: it would read as
    // policy that is not there.
    store.record_hit("ghost");
    assert!(store.hits().iter().all(|h| h.name != "ghost"));
}

/// The counter map outlives the rules it counts, so a client looping
/// add-then-delete with fresh names must not grow it without bound.
#[test]
fn hit_tracking_is_capped() {
    let (_td, dir) = tmpdir("hitcap");
    let store = RuleStore::new(dir.clone());
    for i in 0..(MAX_TRACKED_RULE_NAMES + 100) {
        store.record_hit(&format!("r{i}"));
    }
    let tracked = store.hits.read().unwrap().len();
    assert_eq!(tracked, MAX_TRACKED_RULE_NAMES);
}

/// A name is echoed back in every listing, hit report and explain trace,
/// so its length is multiplied by the rule count in one reply. Session
/// rules never reach the filesystem, so nothing else bounded this.
#[test]
fn overlong_rule_name_rejected() {
    let (_td, dir) = tmpdir("longname");
    let store = RuleStore::new(dir.clone());
    let mut r = rule("x", RuleDuration::Session);
    r.name = "n".repeat(MAX_RULE_NAME_BYTES + 1);
    let err = store.add(r).expect_err("overlong name must be refused");
    assert!(err.contains("must be at most"), "{err}");

    let mut ok = rule("x", RuleDuration::Session);
    ok.name = "n".repeat(MAX_RULE_NAME_BYTES);
    assert!(store.add(ok).is_ok(), "the limit itself is accepted");
}

/// A session grant reports itself through the rule-name field, so a
/// disk or IPC rule must not be able to answer to that name: an
/// operator reading events could not otherwise tell a permanent allow
/// from a grant that ends with a command.
#[test]
fn the_session_grant_prefix_is_reserved() {
    let (_td, dir) = tmpdir("reserved");
    let store = RuleStore::new(dir.clone());
    let mut r = rule("x", RuleDuration::Session);
    r.name = format!("{}42", hallpass_types::RUN_SESSION_RULE_PREFIX);
    let err = store
        .add(r)
        .expect_err("the reserved prefix must be refused");
    assert!(err.contains("reserved"), "{err}");

    // Only the prefix is reserved, not the word.
    let mut ok = rule("x", RuleDuration::Session);
    ok.name = "my-run-session:42".into();
    assert!(
        store.add(ok).is_ok(),
        "the prefix is only reserved at the start"
    );
}

/// The disk path never calls `add`, so a rule file is the way in that a
/// check living only in `add` would miss.
#[test]
fn a_rule_file_cannot_take_a_session_grants_name() {
    let (_td, dir) = tmpdir("reserved-disk");
    let mut r = rule("impostor", RuleDuration::Forever);
    r.name = format!("{}7", hallpass_types::RUN_SESSION_RULE_PREFIX);
    write(dir.join("impostor.toml"), &toml::to_string(&r).unwrap());

    let store = RuleStore::new(dir);
    assert!(
        store.list().is_empty(),
        "a disk rule named after a grant must be skipped, not loaded"
    );
    assert_eq!(store.rules_skipped(), 1, "and counted as skipped");
}

/// Counters for rules that are gone are never reported, so keeping them
/// only spends the cap. An interactive daemon generates a fresh rule name
/// per prompt, and past the cap every new rule would report zero hits
/// forever, which reads as dead policy an operator would then delete.
#[test]
fn hit_counters_for_deleted_rules_are_pruned() {
    let (_td, dir) = tmpdir("prunehits");
    let store = RuleStore::new(dir.clone());
    store.add(rule("keep", RuleDuration::Forever)).unwrap();
    store.add(rule("drop", RuleDuration::Forever)).unwrap();
    store.record_hit("keep");
    store.record_hit("drop");
    assert_eq!(store.hits.read().unwrap().len(), 2);

    store.delete("drop").unwrap();
    assert_eq!(
        store.hits.read().unwrap().len(),
        1,
        "the gone rule's counter goes too"
    );
    // The surviving rule keeps its history.
    assert_eq!(
        store.hits().iter().find(|h| h.name == "keep").unwrap().hits,
        1
    );
}

/// The store refuses to grow past [`MAX_RULES`], while replacing an
/// existing rule by name stays allowed at the cap.
#[test]
fn rule_count_capped_but_replacement_allowed() {
    let (_td, dir) = tmpdir("countcap");
    let store = RuleStore::new(dir.clone());
    // Filled directly rather than through MAX_RULES add() calls, each
    // of which rebuilds the whole set: under test is the cap check.
    {
        let mut entries = store.entries.lock().unwrap();
        for i in 0..MAX_RULES {
            entries.push(Entry {
                rule: rule(&format!("r{i}"), RuleDuration::Session),
                origin: Origin::Session,
            });
        }
    }
    let err = store
        .add(rule("one-too-many", RuleDuration::Session))
        .expect_err("the add past the cap must be refused");
    assert!(err.contains("full"), "{err}");
    store
        .add(rule("r7", RuleDuration::Session))
        .expect("replacement by name at the cap");
    assert_eq!(store.list().len(), MAX_RULES);
    // A delete makes room again.
    store.delete("r7").unwrap();
    store
        .add(rule("fits-now", RuleDuration::Session))
        .expect("add after a delete");
}

/// A rule whose matcher strings blow up its encoded size is refused:
/// the name cap alone does not protect the single-frame RuleList reply.
#[test]
fn oversized_rule_rejected_on_add() {
    let (_td, dir) = tmpdir("wiresize");
    let store = RuleStore::new(dir.clone());
    let mut big = rule("big", RuleDuration::Session);
    big.matcher.cmdline_contains = Some("x".repeat(MAX_RULE_WIRE_BYTES));
    let err = store.add(big).expect_err("oversized rule must be refused");
    assert!(err.contains("encodes to"), "{err}");
    assert!(store.list().is_empty());
}

/// The worst listing the caps allow, [`MAX_RULES`] rules each at
/// [`MAX_RULE_WIRE_BYTES`], must encode as one RuleList reply inside
/// the wire frame limit, with margin. This is the arithmetic the two
/// caps were chosen for; a future bump to either constant fails here
/// before it ships an unanswerable daemon.
#[test]
fn rule_list_frame_budget() {
    let worst = MAX_RULES * MAX_RULE_WIRE_BYTES;
    assert!(
        worst <= wire::MAX_FRAME_SIZE * 3 / 4,
        "{MAX_RULES} rules x {MAX_RULE_WIRE_BYTES} bytes = {worst} needs to stay \
         well inside the {} frame limit",
        wire::MAX_FRAME_SIZE
    );

    // And with real encoding, not just arithmetic: rules padded to the
    // per-rule cap, listed all at once, encode inside one frame.
    // encode() itself refuses payloads over the frame limit, so
    // surviving the expect is the entire check; asserting on the
    // returned length would re-test what encode already enforces.
    let mut rules = Vec::with_capacity(MAX_RULES);
    for i in 0..MAX_RULES {
        let mut r = rule(&format!("r{i}"), RuleDuration::Session);
        let base = wire::encode(&r).unwrap().len() - wire::FRAME_PREFIX_BYTES;
        // Padding leaves headroom for its own varint length bytes.
        r.matcher.cmdline_contains = Some("x".repeat(MAX_RULE_WIRE_BYTES - base - 8));
        let padded = wire::encode(&r).unwrap().len() - wire::FRAME_PREFIX_BYTES;
        assert!(padded <= MAX_RULE_WIRE_BYTES, "test rule overshot the cap");
        rules.push(r);
    }
    wire::encode(&hallpass_types::DaemonMsg::Rules(rules))
        .expect("a maximal RuleList reply must encode inside the frame limit");
}

/// Measurement harness, not a test: prints what the capped store costs
/// and always passes. Numbers are machine-relative; read them against
/// each other, not as absolutes. Run with:
/// `cargo test -p hallpassd --release rule_store_cost -- --ignored --nocapture`
#[test]
#[ignore = "measurement harness; run by hand with --nocapture"]
fn rule_store_cost() {
    use std::time::Instant;

    let mut typical = rule("allow curl to example.org:443", RuleDuration::Forever);
    typical.matcher.exe = Some("/usr/bin/curl".into());
    typical.matcher.domain = Some("example.org".into());
    let bytes = wire::encode(&typical).unwrap().len() - wire::FRAME_PREFIX_BYTES;
    println!("typical prompt rule: {bytes} wire bytes (cap {MAX_RULE_WIRE_BYTES})");

    let rules: Vec<Rule> = (0..MAX_RULES)
        .map(|i| {
            let mut r = rule(&format!("rule-{i}"), RuleDuration::Session);
            r.matcher.exe = Some(format!("/usr/bin/tool-{i}").into());
            r
        })
        .collect();

    let t = Instant::now();
    let set = RuleSet::compile(&rules);
    println!(
        "RuleSet::compile of {} rules: {:?} (paid per add and per reload, on a runtime worker)",
        set.rule_count(),
        t.elapsed()
    );

    let conn = hallpass_types::Connection {
        tuple: hallpass_types::FlowTuple {
            proto: hallpass_types::Proto::Tcp,
            src: "10.0.0.1:40000".parse().unwrap(),
            dst: "192.0.2.1:999".parse().unwrap(),
        },
        uid: Some(1000),
        pid: Some(1),
        exe_path: Some("/usr/bin/nothing-matches".into()),
        cmdline: None,
        parent_exe: None,
        domain: None,
        iface: None,
        app_id: None,
        first_seen: None,
    };
    let iterations = 1000u32;
    let t = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(set.match_conn(std::hint::black_box(&conn), None));
    }
    println!(
        "match_conn full miss over {MAX_RULES} rules: {:?} per packet (the verdict thread's share)",
        t.elapsed() / iterations
    );

    let (_td, dir) = tmpdir("cost");
    let store = RuleStore::new(dir);
    {
        let mut entries = store.entries.lock().unwrap();
        for r in rules.iter().take(MAX_RULES - 2) {
            entries.push(Entry {
                rule: r.clone(),
                origin: Origin::Session,
            });
        }
    }
    let t = Instant::now();
    store
        .add(rule("one-session", RuleDuration::Session))
        .unwrap();
    println!(
        "session add at occupancy {}: {:?}",
        MAX_RULES - 2,
        t.elapsed()
    );
    let t = Instant::now();
    store
        .add(rule("one-forever", RuleDuration::Forever))
        .unwrap();
    println!(
        "forever add at occupancy {}: {:?} (adds the rules.d write)",
        MAX_RULES - 1,
        t.elapsed()
    );
}

/// A reload whose directory scan fails must keep the last good rule
/// set. Dropping to whatever partially loaded would silently disable
/// rules root wrote, on nothing more than a transient error.
#[test]
fn failed_scan_does_not_shrink_ruleset() {
    if effective_uid() == Some(0) {
        return; // directory modes do not restrict root
    }
    let (_td, dir) = tmpdir("partial-scan");
    let store = RuleStore::new(dir.clone());
    store
        .add(rule("keep-on-disk", RuleDuration::Forever))
        .unwrap();
    assert_eq!(store.list().len(), 1);

    let mode = |m: u32| std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(m)).unwrap();
    mode(0o000);
    let applied = store.reload_disk();
    mode(0o755);
    assert!(!applied, "an incomplete scan must report itself for retry");
    assert_eq!(
        store.list().len(),
        1,
        "an unreadable rules dir must not drop loaded rules"
    );
    assert_eq!(store.ruleset().rule_count(), 1);
    assert_eq!(
        store.rules_skipped(),
        0,
        "an aborted reload must not count skips for files still enforced"
    );
    // Once the directory is scannable again the retry succeeds.
    assert!(store.reload_disk(), "a complete scan must report applied");
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

/// The reload path only ever opens for read, so the access-family
/// events it can generate about itself must not schedule a reload,
/// while every shape a writer produces must.
#[test]
fn read_side_events_are_not_reload_worthy() {
    use notify::event::{CreateKind, DataChange, ModifyKind, RemoveKind};
    // What a read-only directory scan emits.
    assert!(!reload_worthy(EventKind::Access(AccessKind::Open(
        AccessMode::Any
    ))));
    assert!(!reload_worthy(EventKind::Access(AccessKind::Close(
        AccessMode::Read
    ))));
    assert!(!reload_worthy(EventKind::Access(AccessKind::Any)));
    // What writers emit, including a mapped write's only trace.
    assert!(reload_worthy(EventKind::Access(AccessKind::Close(
        AccessMode::Write
    ))));
    assert!(reload_worthy(EventKind::Create(CreateKind::File)));
    assert!(reload_worthy(EventKind::Modify(ModifyKind::Data(
        DataChange::Any
    ))));
    assert!(reload_worthy(EventKind::Remove(RemoveKind::File)));
    // Unknown fails toward a spurious scan, never toward staleness.
    assert!(reload_worthy(EventKind::Any));
}

/// One write to the rules directory must produce one reload, not a
/// self-sustaining loop. The reload reads every file in the watched
/// directory and the inotify backend reports read events, so an
/// unfiltered watcher re-triggered itself at debounce cadence forever
/// (observed live as "rules reloaded from disk" every 200ms). Pinned
/// against the real watcher and the real reload: a second watcher on
/// the same directory sees the reload's own opens, so silence on it
/// after the reload has applied means the daemon watcher went quiet.
#[tokio::test]
async fn watcher_does_not_feed_itself() {
    let (_td, dir) = tmpdir("watch-quiesce");
    let store = Arc::new(RuleStore::new(dir.clone()));
    spawn_watcher(Arc::clone(&store)).unwrap();

    let (tx, rx) = std::sync::mpsc::channel();
    let mut observer = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(ev) = res {
            let _ = tx.send(ev.kind);
        }
    })
    .unwrap();
    observer
        .watch(&dir, notify::RecursiveMode::NonRecursive)
        .unwrap();

    // The legitimate write that starts the cycle.
    let text = toml::to_string(&rule("quiesce", RuleDuration::Forever)).unwrap();
    write(dir.join("quiesce.toml"), &text);

    // Wait for the debounced reload to apply rather than a fixed
    // interval, so a loaded machine cannot push the first reload's
    // reads into the silence window below.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !store.list().iter().any(|r| r.name == "quiesce") {
        assert!(std::time::Instant::now() < deadline, "reload never applied");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // Settle past one more debounce interval, drain what the reload
    // itself produced, then require silence: a self-feeding watcher
    // reloads again every 200ms, and each reload opens files here.
    tokio::time::sleep(Duration::from_millis(300)).await;
    while rx.try_recv().is_ok() {}
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut late = Vec::new();
    while let Ok(kind) = rx.try_recv() {
        late.push(kind);
    }
    assert!(late.is_empty(), "watcher fed itself: {late:?}");
}


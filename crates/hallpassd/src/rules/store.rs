//! Rule persistence and hot reload.
//!
//! Disk rules live as one TOML file per rule in the configured rules
//! directory; session rules live only in memory. Every mutation rebuilds
//! the compiled [`RuleSet`] and swaps it atomically, so the packet path
//! reads rules lock-free.

use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use arc_swap::ArcSwap;
use hallpass_types::{wire, Rule};
use notify::event::{AccessKind, AccessMode, EventKind};
use notify::Watcher;

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
    /// Cumulative count of disk rule files skipped across every applied
    /// load, whether refused deliberately (bad permissions, unparsable,
    /// duplicate name, symlink) or unreadable. Scans that were aborted as
    /// incomplete contribute nothing: their files are all still enforced.
    rules_skipped: AtomicU64,
    /// Per-rule-name hit accounting. Deliberately keyed by name and kept
    /// outside the entry list so a rules-directory reload does not reset
    /// it: an operator editing one rule file should not lose the answer to
    /// "is anything hitting this".
    hits: RwLock<HashMap<String, Hit>>,
    /// Bumped by every [`RuleStore::rebuild`], i.e. whenever the active
    /// ruleset may have changed. What the flow-kill sweeper watches; a
    /// watch channel rather than a notify so a subscriber that was busy
    /// during two changes still wakes once for the latest.
    changed: tokio::sync::watch::Sender<()>,
    /// Bumped, under the entries lock, by every mutation that writes a rule
    /// file. [`RuleStore::reload_disk`] reads it before scanning and again
    /// once it holds the lock, and abandons a scan that straddled a write.
    ///
    /// `load_dir` runs outside the lock deliberately (a directory of file
    /// reads is not something to hold the packet path's rule set behind), so
    /// a scan can be taken mid-write and describe a directory that never
    /// existed at any instant: some files carrying the new `enabled` and the
    /// rest the old. Applied, that snapshot re-enables rules the operator
    /// just disabled, after the CLI has already reported success. One
    /// bulk toggle's fsyncs are far wider than the watcher's debounce, so
    /// this is reachable rather than theoretical.
    mutations: AtomicU64,
    /// The lockdown posture's pinned tags, if one is in force.
    ///
    /// Held here because this is what compiles the rule set, and the packet
    /// path must read the posture and the rules from one snapshot. The
    /// authority on the posture is `lockdown::Posture`, which persists it
    /// and calls [`RuleStore::rebuild_for_posture`]; nothing else writes
    /// this.
    lockdown_tags: Mutex<Option<Vec<String>>>,
}

/// Hit accounting for one rule name.
struct Hit {
    count: AtomicU64,
    /// Unix milliseconds of the most recent hit.
    last_ms: AtomicU64,
}

/// Longest accepted rule name.
///
/// Names are echoed back in every rule listing, every hit report, every
/// explain trace and every event that a rule decided, so their length is
/// multiplied by the number of rules in a single reply. The wire codec
/// refuses frames over 1 MiB and a refused frame breaks the client's
/// connection instead of answering it, so an unbounded name let a
/// `hallpass`-group client make the daemon unanswerable to every client,
/// itself included. `Forever` rules were bounded incidentally by the
/// filesystem's name limit; `Session` rules are never written to disk and
/// had no bound at all.
pub const MAX_RULE_NAME_BYTES: usize = 256;

/// Most rule names tracked at once.
///
/// The map is keyed by name and outlives the rules themselves, so a client
/// looping add-then-delete with fresh names would otherwise grow it without
/// bound. Past the cap new names simply go uncounted: losing accounting for
/// a rule is a cosmetic failure, while refusing the rule or evicting a
/// live one would change enforcement, and this runs on the verdict path.
const MAX_TRACKED_RULE_NAMES: usize = 4096;

/// Most rules the store will hold at once, counting disk and session rules.
///
/// Any `hallpass`-group member can loop `RuleAdd` with distinct `Forever`
/// names, and without a count bound each add grows `rules.d` on disk,
/// recompiles a set one rule larger, and lengthens the O(n) match the
/// verdict thread runs per packet, forever. The bound fails toward an error
/// reply to the client whose add would exceed it, which costs that client a
/// rule and never costs a verdict: every rule already loaded keeps matching
/// exactly as before. On the prompt path the same refusal is logged and the
/// operator's verdict still applies to the held packets; only the remembered
/// rule is lost. Replacing an existing rule by name stays allowed at the cap
/// because it does not grow the set.
///
/// Disk rules are exempt at load time: they are authored by root, and
/// refusing to load the excess would silently change what root's own files
/// enforce, which is a verdict cost. A root operator who wants more than
/// the cap has written them by hand and owns the consequences; see the
/// frame-budget note on [`MAX_RULE_WIRE_BYTES`] for what those are.
pub const MAX_RULES: usize = 1024;

/// Largest postcard-encoded size of one rule accepted over IPC, in bytes.
///
/// `RuleList` answers with every rule in a single frame, and the codec
/// refuses frames over [`hallpass_types::wire::MAX_FRAME_SIZE`] on encode,
/// which breaks the connection instead of answering. The name cap alone
/// does not protect that reply: a matcher string (`cmdline_contains`, a
/// glob) can be pushed to nearly the 1 MiB inbound frame limit in a single
/// accepted rule, so a handful of such rules would make `RuleList`
/// unanswerable for every client from then on, and `Forever` rules reload
/// from disk across restarts. Bounding each rule's encoded size keeps the
/// worst full listing, [`MAX_RULES`] x this, at 768 KiB, comfortably
/// inside the frame (`rule_list_frame_budget` pins the arithmetic). The
/// bound fails toward an error reply to the client that sent the oversized
/// rule; hand-written disk rules bypass it on the same root-is-trusted
/// grounds as the count cap. On the prompt path, where the rule embeds the
/// connection's full executable path, an exe deep enough to push the
/// encoding past the bound means that prompt's decision is applied but not
/// remembered as a rule, with a warning each time; the verdict itself is
/// never affected.
pub const MAX_RULE_WIRE_BYTES: usize = 768;

/// A rule (or list) file is trusted when owned by root (or by the daemon's
/// own euid, for non-root development runs) and not group/world-writable.
pub(crate) fn file_perms_ok(file_uid: u32, mode: u32, self_uid: u32) -> bool {
    (file_uid == 0 || file_uid == self_uid) && mode & 0o022 == 0
}

/// Whether the *directory* holding policy files is as trustworthy as the
/// files in it are required to be.
///
/// [`file_perms_ok`] and the symlink refusal in [`load_dir`] both check
/// files, and every one of those checks silently assumes this. Unlinking a
/// file needs write permission on the **directory**, not on the file: on a
/// group-writable `rules.d`, any member of that group can delete root's deny
/// rules without ever touching a file the per-file checks would look at. It
/// is silent, too - `load_dir` classifies a vanished file as an ordinary
/// delete, so nothing is skipped, nothing is counted, and `reload_disk`
/// applies the shrunken set as authoritative policy.
///
/// The sticky bit is honoured because it takes exactly that power back: with
/// `t` set, a user may only unlink files they own, so a group-writable
/// sticky directory cannot lose root's rules. Files *created* there are owned
/// by whoever created them and are refused by [`file_perms_ok`] as before.
pub(crate) fn dir_trust_ok(dir_uid: u32, mode: u32, self_uid: u32) -> bool {
    if dir_uid != 0 && dir_uid != self_uid {
        return false;
    }
    mode & 0o022 == 0 || mode & 0o1000 != 0
}

/// How a directory the daemon trusts policy from failed its check, or `Ok`
/// when it is fine or simply absent.
///
/// Absent is not a failure: `rules_dir` is created on the first persisted
/// rule, and an operator who has written no rules yet has a directory that
/// does not exist rather than one that cannot be trusted.
pub fn check_policy_dir(path: &Path) -> Result<(), String> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("cannot stat {}: {e}", path.display())),
    };
    if !meta.is_dir() {
        return Err(format!("{} is not a directory", path.display()));
    }
    let self_uid = effective_uid().unwrap_or(u32::MAX);
    if dir_trust_ok(meta.uid(), meta.mode(), self_uid) {
        return Ok(());
    }
    Err(format!(
        "{} is uid {} mode {:04o}: anyone who can write this directory can \
         delete or replace the policy files in it, whatever those files' own \
         permissions say. Expected root-owned and not group/world-writable \
         (chown root {} && chmod 755 {})",
        path.display(),
        meta.uid(),
        meta.mode() & 0o7777,
        path.display(),
        path.display(),
    ))
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

/// `O_NOFOLLOW` on Linux. Spelled out rather than pulled from libc: this
/// crate takes no libc dependency (see [`effective_uid`]), and the value is
/// stable ABI on every Linux architecture.
const O_NOFOLLOW: i32 = 0o400_000;

/// `O_NONBLOCK` on Linux, spelled out for the same reason as [`O_NOFOLLOW`].
const O_NONBLOCK: i32 = 0o4_000;

/// Whether [`read_trusted`] may open a path that is a symbolic link.
///
/// Stated per call site rather than defaulted, because the two files the
/// daemon reads this way answer it differently and neither answer is
/// obviously right for the other. A path the operator named may legitimately
/// be a link (a config symlinked to `config.hardened.toml`, or into a
/// dotfile tree); a path the daemon writes itself never is, and following
/// one there would aim a root open at a file chosen by whoever planted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Links {
    /// Follow a symlink at the path.
    Follow,
    /// Refuse a symlink at the path (`O_NOFOLLOW`).
    Refuse,
}

/// Read a file only if it is as trustworthy as a rule file: owned by root
/// (or by the daemon's own euid) and not group- or world-writable.
///
/// Ownership and content come from the same descriptor, so the file that was
/// checked is the file that is read: a path checked by name and then opened
/// separately can be swapped in between. A `NotFound` error is passed
/// through unchanged, because callers distinguish it.
///
/// One implementation for every file the daemon trusts by ownership. Two
/// copies of this drifted on exactly the question [`Links`] now asks, and a
/// reader could not tell which position was deliberate.
pub(crate) fn read_trusted(path: &Path, links: Links) -> std::io::Result<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let mut opts = std::fs::OpenOptions::new();
    // O_NONBLOCK, and the regular-file check below, because these paths come
    // from a config file. Opening a FIFO blocks until a writer appears and
    // reading a character device may never end, so a mistyped or malicious
    // path would hang the daemon inside startup - alive, before the nftables
    // install, with the host unfiltered and nothing in the log to say why.
    // On a regular file the flag does nothing.
    opts.read(true).custom_flags(O_NONBLOCK);
    if links == Links::Refuse {
        opts.custom_flags(O_NONBLOCK | O_NOFOLLOW);
    }
    let mut file = opts.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::other("must be a regular file"));
    }
    let self_uid = effective_uid().unwrap_or(u32::MAX);
    if !file_perms_ok(meta.uid(), meta.mode(), self_uid) {
        return Err(std::io::Error::other(
            "must be owned by root and not group/world-writable",
        ));
    }
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(text)
}

/// Write `bytes` to `path` so that a reader sees either the old file or the
/// new one, never half of either.
///
/// Writing in place truncates first, so a crash or a full disk mid-write
/// leaves a partial file, which for a rule file means a rule that stops
/// applying and for the first-seen state means everything reads as new. The
/// temp file is dot-prefixed and not `.toml`, so a directory scan skips it
/// if it catches one mid-write, and the rename is atomic within the
/// directory.
///
/// `create_new` plus `O_NOFOLLOW` plus an explicit `mode`, not `fs::write`:
/// `fs::write` follows a symlink at the target and creates with
/// `0666 & ~umask`, so a planted link would aim a root write anywhere, and
/// under a permissive umask there is a window where the file about to become
/// live policy is world-writable.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let tmp = dir.join(format!(".{name}.tmp"));
    // A leftover from an interrupted write, so create_new below does not
    // refuse. Nothing else owns this name.
    let _ = std::fs::remove_file(&tmp);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(O_NOFOLLOW)
        .mode(mode)
        .open(&tmp)?;
    let written = file
        .write_all(bytes)
        // The bytes have to be on disk before the rename publishes them, or
        // a crash can leave the new name pointing at an empty file.
        .and_then(|()| file.sync_all());
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    drop(file);
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
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

/// Result of scanning the rules directory: the accepted entries, how many
/// files were skipped (every skip is logged at its site, whether refused
/// deliberately or unreadable), and whether the scan saw everything it
/// should have.
struct LoadResult {
    entries: Vec<Entry>,
    skipped: u64,
    /// False when the scan may have missed rules through no fault of their
    /// files: the directory failed to open or enumerate, or a file failed
    /// to open, stat, or read for a reason other than having been deleted.
    /// A deliberate skip (symlink, bad permissions, unparsable, duplicate)
    /// leaves this true: those files were seen and judged. A file the scan
    /// could not look at counts in `skipped` too, so the two categories
    /// overlap in the counter but not in this flag. The distinction matters
    /// because [`RuleStore::reload_disk`] replaces the loaded set with this
    /// one, and treating "could not look" as "looked and found nothing"
    /// turned a transient error into silently dropped policy.
    complete: bool,
}

fn load_dir(dir: &Path) -> LoadResult {
    let self_uid = effective_uid().unwrap_or(u32::MAX);
    let mut entries = Vec::new();
    let mut skipped = 0u64;
    let mut complete = true;
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), "cannot read rules dir: {e}");
            return LoadResult {
                entries,
                skipped,
                complete: false,
            };
        }
    };
    for item in read {
        let item = match item {
            Ok(i) => i,
            Err(e) => {
                // An enumeration error mid-scan: whatever entries the
                // iterator never yielded are simply absent, so the scan
                // cannot claim to be the whole directory.
                tracing::warn!(dir = %dir.display(), "error listing rules dir: {e}");
                complete = false;
                continue;
            }
        };
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
                // NotFound is a file deleted between the directory read and
                // this stat, which is an ordinary delete, not a blind spot.
                if e.kind() != std::io::ErrorKind::NotFound {
                    complete = false;
                }
                tracing::warn!(file = %path.display(), "cannot stat rule file: {e}");
                skipped += 1;
                continue;
            }
        }
        // Identity and content both come from this fd, as in lists.rs: no
        // window where the trust-checked file and the parsed bytes could
        // differ. O_NOFOLLOW makes the refusal above race-free: the
        // file_type() check reads the directory entry, so on its own a rename
        // between that check and this open could still substitute a link.
        let mut file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) => {
                // Same NotFound carve-out as the stat above. Anything else
                // (EACCES, EMFILE, EIO) is a file that exists but could not
                // be looked at, so the scan is not the whole story. ELOOP
                // from O_NOFOLLOW means a symlink raced in; that is the
                // refusal working, but the entry was seen as a non-link
                // moments ago, so conservatively treat it as incomplete too.
                if e.kind() != std::io::ErrorKind::NotFound {
                    complete = false;
                }
                tracing::warn!(file = %path.display(), "cannot open rule file: {e}");
                skipped += 1;
                continue;
            }
        };
        let meta = match file.metadata() {
            Ok(m) => m,
            Err(e) => {
                // fstat on an open fd; failure here is not a deletion.
                complete = false;
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
        if let Err(e) = file.read_to_string(&mut text) {
            // A read error on an open fd (EIO) is "could not look", not
            // "looked and judged": lumping it in with parse failures left
            // the scan claiming completeness through the exact transient
            // errors the completeness flag exists to catch.
            complete = false;
            tracing::warn!(file = %path.display(), "cannot read rule file: {e}");
            skipped += 1;
            continue;
        }
        let mut rule: Rule = match toml::from_str(&text) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(file = %path.display(), "skipping unparsable rule file: {e}");
                skipped += 1;
                continue;
            }
        };
        // Normalized, not refused: a tag is a label, and no selector could
        // ever have named a malformed one, so dropping it costs nothing that
        // worked. Skipping the rule instead would stop enforcing policy the
        // operator wrote over a mistyped label - on a deny rule, that means
        // passing exactly the traffic the file exists to stop.
        let dropped = hallpass_types::retain_valid_tags(&mut rule.tags);
        if !dropped.is_empty() {
            tracing::warn!(
                file = %path.display(),
                rule = %rule.name,
                "ignoring unusable tags {dropped:?}; the rule is still enforced. \
                 Tags are lowercase letters, digits, `-` and `_`, start with a \
                 letter or digit, and are unique"
            );
        }
        // The same validation add() applies, because both go through
        // `CompiledRule::compile`: a rule that cannot compile would
        // otherwise sit inert in the set and crash clients that render it
        // (e.g. a malformed exe_sha256), and a rule naming itself after a
        // session grant would be indistinguishable from one.
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
    LoadResult {
        entries,
        skipped,
        complete,
    }
}

impl RuleStore {
    /// Create a store, loading persisted rules from `rules_dir`.
    pub fn new(rules_dir: PathBuf) -> RuleStore {
        let loaded = load_dir(&rules_dir);
        // At startup there is no earlier good set to keep, so an incomplete
        // scan proceeds with what loaded, loudly. Refusing to start would
        // also take down the control channel and the prompt path over what
        // may be a transient error; the missing rules load when a later
        // scan completes (the watcher retries incomplete ones, when it is
        // running), and (unlike a silent reload shrink) the operator was
        // told.
        if !loaded.complete {
            tracing::error!(
                dir = %rules_dir.display(),
                count = loaded.entries.len(),
                "rules directory scan was incomplete; starting with a partial rule set"
            );
        }
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
            hits: RwLock::new(HashMap::new()),
            changed: tokio::sync::watch::channel(()).0,
            mutations: AtomicU64::new(0),
            lockdown_tags: Mutex::new(None),
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

    /// The loaded rules, recovering a poisoned lock. Poison here cannot
    /// reach a verdict - the packet path reads the ArcSwap snapshot - but
    /// propagating it would leave every later rule operation panicking in
    /// turn: policy frozen until restart over a panic that already
    /// happened. The entries are consistent at every await-free point a
    /// panic can interrupt, so recovering them is strictly better.
    fn lock_entries(&self) -> std::sync::MutexGuard<'_, Vec<Entry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// All rules, for `RuleList` replies.
    pub fn list(&self) -> Vec<Rule> {
        self.lock_entries().iter().map(|e| e.rule.clone()).collect()
    }

    /// Count one connection decided by the rule named `name`.
    ///
    /// Runs on the verdict thread for every decided packet, so the common
    /// path (a name already tracked) takes only a read lock and two relaxed
    /// atomics. The write lock is reached once per rule name, ever.
    pub fn record_hit(&self, name: &str) {
        let now = hallpass_types::unix_ms_now();
        {
            let map = self.hits.read().unwrap_or_else(|e| e.into_inner());
            if let Some(hit) = map.get(name) {
                hit.count.fetch_add(1, Ordering::Relaxed);
                hit.last_ms.store(now, Ordering::Relaxed);
                return;
            }
        }
        let mut map = self.hits.write().unwrap_or_else(|e| e.into_inner());
        // Re-check: another thread may have inserted between the two locks.
        if let Some(hit) = map.get(name) {
            hit.count.fetch_add(1, Ordering::Relaxed);
            hit.last_ms.store(now, Ordering::Relaxed);
            return;
        }
        if map.len() >= MAX_TRACKED_RULE_NAMES {
            return;
        }
        map.insert(
            name.to_string(),
            Hit {
                count: AtomicU64::new(1),
                last_ms: AtomicU64::new(now),
            },
        );
    }

    /// Hit counts for every currently loaded rule, in [`RuleStore::list`]
    /// order.
    ///
    /// Loaded rules only: a name that has hits but no longer exists would
    /// read as policy that is not there. Rules that never fired report zero
    /// rather than being omitted, since "this rule has never matched" is the
    /// interesting answer.
    pub fn hits(&self) -> Vec<hallpass_types::RuleHit> {
        let entries = self.lock_entries();
        let map = self.hits.read().unwrap_or_else(|e| e.into_inner());
        entries
            .iter()
            .map(|e| {
                let (hits, last) = map.get(&e.rule.name).map_or((0, 0), |h| {
                    (
                        h.count.load(Ordering::Relaxed),
                        h.last_ms.load(Ordering::Relaxed),
                    )
                });
                hallpass_types::RuleHit {
                    name: e.rule.name.clone(),
                    hits,
                    last_hit_ms: (last > 0).then_some(last),
                }
            })
            .collect()
    }

    /// Add or replace a rule by name. Forever rules are persisted to disk.
    ///
    /// This is the entry point for rules that did not come from disk (IPC
    /// `RuleAdd` and prompt replies), so match-list paths are confined here.
    pub fn add(&self, rule: Rule) -> Result<(), String> {
        if rule.name.is_empty() {
            return Err("rule name must not be empty".into());
        }
        if rule.name.len() > MAX_RULE_NAME_BYTES {
            return Err(format!(
                "rule name is {} bytes, must be at most {MAX_RULE_NAME_BYTES}",
                rule.name.len()
            ));
        }

        // Measured with the codec that will echo the rule back, so the size
        // being bounded is exactly the size RuleList pays; see
        // MAX_RULE_WIRE_BYTES for why the bound exists.
        let wire_bytes = wire::encode(&rule)
            .map_err(|e| format!("rule does not encode: {e}"))?
            .len()
            - wire::FRAME_PREFIX_BYTES;
        if wire_bytes > MAX_RULE_WIRE_BYTES {
            return Err(format!(
                "rule encodes to {wire_bytes} bytes, must be at most {MAX_RULE_WIRE_BYTES}"
            ));
        }
        // Strict here, where a refusal is an error message the caller reads,
        // rather than in `CompiledRule::compile`, where it would cost an
        // existing rule its enforcement (see the note there, and `load_dir`,
        // which normalizes instead).
        hallpass_types::validate_tags(&rule.tags)?;
        // Before compile: compiling opens the list files as root.
        list_paths_within(&rule, &self.rules_dir)?;
        CompiledRule::compile(&rule)?;
        // Persist while holding the entries lock: the directory watcher's
        // reload_disk() takes the same lock, so it cannot observe the new
        // file before this add lands in `entries`.
        let mut entries = self.lock_entries();
        // One lookup serves both the cap exemption and the replacement
        // below; persist() takes the entries as a shared slice, so nothing
        // between here and the remove() can shift the position.
        let existing = entries.iter().position(|e| e.rule.name == rule.name);
        // Checked under the lock so two racing adds cannot both squeeze in,
        // and before the persist so a refused add leaves no file behind.
        // Replacement by name is exempt: it does not grow the set. See
        // MAX_RULES for the failure direction.
        if existing.is_none() && entries.len() >= MAX_RULES {
            return Err(format!(
                "rule store is full ({MAX_RULES} rules); delete a rule first"
            ));
        }
        let origin = if rule.duration == hallpass_types::RuleDuration::Forever {
            Origin::Disk(self.persist(&rule, &entries)?)
        } else {
            Origin::Session
        };
        if let Some(pos) = existing {
            let old = entries.remove(pos);
            // Replacement by name is the API, but it is also how a rule an
            // operator approved earlier disappears, so it leaves a trace.
            tracing::info!(rule = %old.rule.name, "replacing an existing rule of the same name");
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
        let mut entries = self.lock_entries();
        let pos = entries
            .iter()
            .position(|e| e.rule.name == name)
            .ok_or_else(|| format!("no such rule: {name}"))?;
        let old = entries.remove(pos);
        // Remove the file under the lock so a concurrent reload_disk()
        // cannot resurrect the rule from a file whose entry is gone.
        if let Origin::Disk(path) = &old.origin {
            self.mutations.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = std::fs::remove_file(path) {
                tracing::warn!(file = %path.display(), "failed to remove rule file: {e}");
            }
        }
        drop(entries);
        self.rebuild();
        Ok(())
    }

    /// Set `enabled` on every rule `select` accepts, persisting each to its
    /// own file. Returns how many rules were selected, how many the change
    /// actually moved, and `(name, error)` for each whose file could not be
    /// written.
    ///
    /// The one mechanism behind [`RuleStore::toggle`] and
    /// [`RuleStore::toggle_tag`], which differ only in what they select and
    /// how they report. Written twice, the two verbs immediately disagreed
    /// about whether an already-correct rule is rewritten and whether a
    /// no-op change recompiles the ruleset.
    ///
    /// One lock and one rebuild for the whole selection: toggling name by
    /// name would recompile once per rule, so a packet arriving mid-sequence
    /// would be judged against half of the operator's intent, and half of
    /// "disable everything tagged `work`" is a policy nobody wrote.
    ///
    /// A rule whose file cannot be written keeps the state it had, and the
    /// rest of the selection still applies. The batch is deliberately not
    /// all-or-nothing: undoing the writes that already landed needs the same
    /// disk that just refused one.
    fn set_enabled(
        &self,
        enabled: bool,
        select: impl Fn(&Rule) -> bool,
    ) -> (usize, u32, Vec<(String, String)>) {
        let mut entries = self.lock_entries();
        let mut matched = 0usize;
        let mut changed = 0u32;
        let mut failed = Vec::new();
        for entry in entries.iter_mut().filter(|e| select(&e.rule)) {
            matched += 1;
            // Nothing to write, and nothing to recompile: `changed` counts
            // what actually moved.
            if entry.rule.enabled == enabled {
                continue;
            }
            entry.rule.enabled = enabled;
            // Persist under the lock; see add() for the watcher race this
            // avoids. Write to the entry's own file: a hand-written rule can
            // live in a file whose name differs from the rule name, and a
            // name-derived path would orphan it (the stale file would revert
            // or resurrect the rule on the next reload).
            if let Origin::Disk(path) = &entry.origin {
                if let Err(e) = self.persist_to(&entry.rule, path) {
                    tracing::warn!(rule = %entry.rule.name, "failed to persist toggle: {e}");
                    entry.rule.enabled = !enabled;
                    failed.push((entry.rule.name.clone(), e));
                    continue;
                }
            }
            changed += 1;
        }
        drop(entries);
        if changed > 0 {
            self.rebuild();
        }
        (matched, changed, failed)
    }

    /// Enable or disable a rule, updating its file if persisted.
    pub fn toggle(&self, name: &str, enabled: bool) -> Result<(), String> {
        let (matched, _, mut failed) = self.set_enabled(enabled, |r| r.name == name);
        if matched == 0 {
            return Err(format!("no such rule: {name}"));
        }
        // One rule selected, so at most one failure, and it is this call's
        // whole outcome rather than part of a batch.
        match failed.pop() {
            Some((_, e)) => Err(e),
            None => Ok(()),
        }
    }

    /// Enable or disable every rule carrying `tag`, as one change. Returns
    /// how many rules the change moved, and the names of any whose new state
    /// could not be written to disk.
    pub fn toggle_tag(&self, tag: &str, enabled: bool) -> Result<(u32, Vec<String>), String> {
        let (matched, changed, failed) = self.set_enabled(enabled, |r| r.has_tag(tag));
        // A tag no rule carries is nearly always a typo, and a quiet zero
        // reads as "done" - the wrong answer to give someone who believes
        // they just disabled their work rules.
        if matched == 0 {
            return Err(format!("no rule carries tag `{tag}`"));
        }
        Ok((changed, failed.into_iter().map(|(name, _)| name).collect()))
    }

    /// Remove rules whose `Until` deadline has passed, deleting persisted
    /// files (hand-written `until` rules in rules.d). Returns whether
    /// anything was removed. Called by the expiry sweeper about once a
    /// second, which bounds how long an expired rule can keep matching.
    pub fn sweep_expired(&self) -> bool {
        let now = hallpass_types::unix_ms_now();
        let mut entries = self.lock_entries();
        let before = entries.len();
        // File removal happens under the lock; see delete() for the
        // watcher race this avoids.
        entries.retain(|e| {
            if !e.rule.duration.expired(now) {
                return true;
            }
            tracing::info!(rule = %e.rule.name, "timed rule expired");
            if let Origin::Disk(path) = &e.origin {
                self.mutations.fetch_add(1, Ordering::Relaxed);
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

    /// Re-read disk rules (hot reload), keeping session rules. Returns
    /// whether a complete scan was applied; after `false` nothing changed
    /// and the caller should retry.
    pub fn reload_disk(&self) -> bool {
        let generation = self.mutations.load(Ordering::Relaxed);
        let fresh = load_dir(&self.rules_dir);
        // An incomplete scan fails toward staleness: the loaded set stays as
        // it is and this reload changes nothing, the skip counter included
        // (an aborted scan's skips would otherwise inflate it once per
        // retry, for files that are all still enforced). The alternative,
        // swapping in whatever partially loaded, silently disables rules
        // root wrote (a vanished deny keeps matching nothing while
        // everything reads as healthy) on nothing more than a transient
        // EMFILE or EIO. Stale policy is the last state root successfully
        // expressed; the watcher retries on a delay until a scan completes,
        // so the staleness lasts as long as the error does.
        if !fresh.complete {
            tracing::warn!(
                dir = %self.rules_dir.display(),
                "rules reload aborted: directory scan was incomplete; keeping current rules"
            );
            return false;
        }
        let mut entries = self.lock_entries();
        // Taken under the lock, so no further write can start before this
        // decision. A scan that straddled one describes a directory that
        // never existed at any instant - half a bulk toggle written, half
        // not - and applying it would re-enable rules the operator was told
        // were disabled. Same failure direction as an incomplete scan, same
        // answer: keep what is loaded and let the watcher retry.
        if self.mutations.load(Ordering::Relaxed) != generation {
            tracing::debug!("rules reload aborted: the rule files changed under the scan");
            return false;
        }
        self.rules_skipped
            .fetch_add(fresh.skipped, Ordering::Relaxed);
        entries.retain(|e| e.origin == Origin::Session);
        for f in fresh.entries {
            if !entries.iter().any(|e| e.rule.name == f.rule.name) {
                entries.push(f);
            }
        }
        drop(entries);
        self.rebuild();
        tracing::info!("rules reloaded from disk");
        true
    }

    /// Whether the lockdown posture currently stops `rule` from deciding.
    ///
    /// For the paths that hold a `Rule` rather than a compiled one - the
    /// prompt sweep in particular, which resolves live prompts with a rule a
    /// client just added and must not resolve one the packet path would skip.
    pub fn suppresses(&self, rule: &Rule) -> bool {
        match self.lockdown_tags.lock().unwrap().as_deref() {
            Some(tags) => !rule.active_under_lockdown(tags),
            None => false,
        }
    }

    /// Recompile under a new lockdown posture. `None` lifts it.
    ///
    /// Only `lockdown::apply` calls this: the posture on disk, the compiled
    /// set and the runtime settings have to move together.
    pub fn rebuild_for_posture(&self, tags: Option<&[String]>) {
        *self.lockdown_tags.lock().unwrap() = tags.map(|t| t.to_vec());
        self.rebuild();
    }

    pub(crate) fn rebuild(&self) {
        let rules: Vec<Rule> = self.list();
        self.prune_hits(&rules);
        let posture = self.lockdown_tags.lock().unwrap().clone();
        self.active.store(Arc::new(RuleSet::compile_with_lockdown(
            &rules,
            posture.as_deref(),
        )));
        // After the swap, so a woken subscriber always sees the new set.
        // send_replace, not send: this must not depend on a receiver being
        // subscribed yet, and the startup rebuild has none.
        self.changed.send_replace(());
    }

    /// A receiver that wakes whenever the active ruleset may have changed.
    pub fn change_signal(&self) -> tokio::sync::watch::Receiver<()> {
        self.changed.subscribe()
    }

    /// Drop hit counters for rules that are no longer loaded.
    ///
    /// The counter map deliberately outlives a reload so editing one rule
    /// file does not reset its history, but a name whose rule is gone is
    /// never reported again, so keeping it only spends the cap. Without
    /// this, an interactive daemon reaches the cap on prompt-generated
    /// names alone (each gets a fresh one), and past the cap every newly
    /// added rule reports zero hits forever, which reads as dead policy an
    /// operator would then delete.
    ///
    /// Called from `rebuild`, which already holds no lock: taking `hits`
    /// here and `entries` then `hits` in [`RuleStore::hits`] keeps one
    /// order everywhere.
    fn prune_hits(&self, rules: &[Rule]) {
        let live: std::collections::HashSet<&str> = rules.iter().map(|r| r.name.as_str()).collect();
        let mut map = self.hits.write().unwrap_or_else(|e| e.into_inner());
        map.retain(|name, _| live.contains(name.as_str()));
    }

    fn persist(&self, rule: &Rule, entries: &[Entry]) -> Result<PathBuf, String> {
        // An explicit mode, not plain `create_dir_all`: that creates with
        // `0777 & ~umask`, so a daemon started outside the shipped unit (which
        // sets `UMask=0077`) by a shell with the `umask 002` Debian and Ubuntu
        // default would create the rules directory group-writable - and a
        // group-writable rules directory is exactly what `dir_trust_ok`
        // exists to refuse. The daemon must not create the state it warns
        // about. Only applies when this call creates the directory; an
        // existing one keeps whatever the operator gave it.
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(&self.rules_dir)
            .or_else(|e| match self.rules_dir.is_dir() {
                true => Ok(()),
                false => Err(format!("create {}: {e}", self.rules_dir.display())),
            })?;
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

    /// Write a rule file so that it is either the old rule or the new one,
    /// never half of either. The atomicity and the mode are
    /// [`write_atomic`]'s; 0644 because a rule file is policy an operator
    /// reads, and `unique_path` has already refused to reuse a path this
    /// store does not own.
    fn persist_to(&self, rule: &Rule, path: &Path) -> Result<(), String> {
        // Before the write, not after: a scan that starts while this is in
        // flight must see a generation it cannot match later. See
        // `mutations`.
        self.mutations.fetch_add(1, Ordering::Relaxed);
        let text = toml::to_string_pretty(rule).map_err(|e| format!("serialize rule: {e}"))?;
        write_atomic(path, text.as_bytes(), 0o644)
            .map_err(|e| format!("write {}: {e}", path.display()))
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

/// How long to wait before retrying a reload whose directory scan came
/// back incomplete. Long enough that a transient EMFILE has usually
/// cleared, short enough that root's edit is not left unapplied for long;
/// a permanently unscannable directory warns at this cadence, which is the
/// operator's signal to go look.
const RELOAD_RETRY_DELAY: Duration = Duration::from_secs(5);

/// Whether a watcher event can reflect a change to the rules on disk.
///
/// The inotify backend reports read-side events too: opening a file for
/// reading arrives as `Access(Open)`. [`RuleStore::reload_disk`] opens
/// every rule and list file in the watched directory, so reloading on any
/// event let the watcher feed itself: one real write, then each reload's
/// own reads fired the next reload at debounce cadence, forever (observed
/// live as "rules reloaded from disk" every 200ms until restart). Only
/// `Access` events are dropped, and `Close(Write)` is kept out of the
/// drop: it is the one access-family event that implies a write (a file
/// modified through a mapping can close without any `Modify` event), and
/// the reload path opens read-only, so keeping it cannot re-arm the loop.
/// Everything unrecognized reloads: this filter fails toward a spurious
/// directory scan, never toward leaving root's edit unapplied.
fn reload_worthy(kind: &EventKind) -> bool {
    match kind {
        EventKind::Access(AccessKind::Close(AccessMode::Write)) => true,
        EventKind::Access(_) => false,
        _ => true,
    }
}

/// Watch the rules directory and hot-reload on changes, debounced 200ms.
/// Returns an error if the watcher cannot be created; a missing directory
/// is tolerated (watch is skipped with a warning).
pub fn spawn_watcher(store: Arc<RuleStore>) -> notify::Result<()> {
    let dir = store.rules_dir.clone();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if res.is_ok_and(|ev| reload_worthy(&ev.kind)) {
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
            // The directory event that got us here is consumed whether or
            // not the scan succeeds, so an incomplete scan is retried on a
            // timer rather than waiting for another write to the directory
            // that may never come: root's edit must not stay unapplied
            // because its own event raced a transient error.
            while !store.reload_disk() {
                tokio::time::sleep(RELOAD_RETRY_DELAY).await;
                while rx.try_recv().is_ok() {}
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
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

        let mode =
            |m: u32| std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(m)).unwrap();
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
        assert!(!reload_worthy(&EventKind::Access(AccessKind::Open(
            AccessMode::Any
        ))));
        assert!(!reload_worthy(&EventKind::Access(AccessKind::Close(
            AccessMode::Read
        ))));
        assert!(!reload_worthy(&EventKind::Access(AccessKind::Any)));
        // What writers emit, including a mapped write's only trace.
        assert!(reload_worthy(&EventKind::Access(AccessKind::Close(
            AccessMode::Write
        ))));
        assert!(reload_worthy(&EventKind::Create(CreateKind::File)));
        assert!(reload_worthy(&EventKind::Modify(ModifyKind::Data(
            DataChange::Any
        ))));
        assert!(reload_worthy(&EventKind::Remove(RemoveKind::File)));
        // Unknown fails toward a spurious scan, never toward staleness.
        assert!(reload_worthy(&EventKind::Any));
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
        let mut observer =
            notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
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
}

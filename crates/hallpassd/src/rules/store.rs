//! Rule persistence and hot reload.
//!
//! Disk rules live as one TOML file per rule in the configured rules
//! directory; session rules live only in memory. Every mutation rebuilds
//! the compiled [`RuleSet`] and swaps it atomically, so the packet path
//! reads rules lock-free.

use std::collections::{HashMap, HashSet};
use std::fs::DirEntry;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
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

impl Hit {
    /// Count one more hit, at `now_ms`.
    fn bump(&self, now_ms: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.last_ms.store(now_ms, Ordering::Relaxed);
    }
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
///
/// Each accepted path is replaced by the canonical one that was checked, and
/// that is what the rule is compiled and persisted with. Checking the
/// resolved path and keeping the one the client sent confined nothing: a
/// symlink in a directory the client owns passes while it points into the
/// rules directory, and every later rebuild reopens it wherever it points
/// by then.
fn confine_list_paths(rule: &mut Rule, dir: &Path) -> Result<(), String> {
    let m = &mut rule.matcher;
    let fields = [
        ("domains_file", &mut m.domains_file),
        ("ips_file", &mut m.ips_file),
        ("hashes_file", &mut m.hashes_file),
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
        *path = canon;
    }
    Ok(())
}

/// `O_NOFOLLOW` on Linux. Spelled out rather than pulled from libc: this
/// crate takes no libc dependency (see [`effective_uid`]), and the value is
/// stable ABI on every Linux architecture.
const O_NOFOLLOW: i32 = 0o400_000;

/// `O_NONBLOCK` on Linux, spelled out for the same reason as [`O_NOFOLLOW`].
pub(super) const O_NONBLOCK: i32 = 0o4_000;

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
    // O_NONBLOCK, and the regular-file check below, because these paths come
    // from a config file. Opening a FIFO blocks until a writer appears and
    // reading a character device may never end, so a mistyped or malicious
    // path would hang the daemon inside startup - alive, before the nftables
    // install, with the host unfiltered and nothing in the log to say why.
    // On a regular file the flag does nothing.
    let flags = match links {
        Links::Follow => O_NONBLOCK,
        Links::Refuse => O_NONBLOCK | O_NOFOLLOW,
    };
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)?;
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

/// `c` if it is safe in a rule file name, `_` otherwise: ASCII
/// alphanumerics plus `.`, `_` and `-`.
pub(crate) fn filename_char(c: char) -> char {
    if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
        c
    } else {
        '_'
    }
}

/// Turn a rule name into a safe file stem.
fn sanitize_filename(name: &str) -> String {
    let stem: String = name.chars().map(filename_char).collect();
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
    let mut entries: Vec<Entry> = Vec::new();
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
        let rule = match load_rule_file(&item, &path, self_uid) {
            Ok(rule) => rule,
            Err(skip) => {
                skipped += 1;
                if skip == Skipped::Unseen {
                    complete = false;
                }
                continue;
            }
        };
        if entries.iter().any(|e| e.rule.name == rule.name) {
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

/// Why [`load_rule_file`] produced no rule. The reason is logged either
/// way, and the file counts as skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Skipped {
    /// Seen and judged: a symlink, bad permissions, unparsable, invalid.
    /// Also a file deleted mid-scan, which is an ordinary delete.
    Refused,
    /// Exists but could not be looked at, so the scan is not the whole
    /// story; see [`LoadResult::complete`].
    Unseen,
}

impl Skipped {
    /// A failure to reach a file: `NotFound` is a file deleted between the
    /// directory read and this call, an ordinary delete rather than a blind
    /// spot; anything else (EACCES, EMFILE, EIO) is a file not looked at.
    fn reaching(e: &std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::NotFound {
            Self::Refused
        } else {
            Self::Unseen
        }
    }
}

/// Open, trust-check, read, parse and validate one rule file.
fn load_rule_file(item: &DirEntry, path: &Path, self_uid: u32) -> Result<Rule, Skipped> {
    // Reject symlinks before opening. `File::open` follows them, and the
    // fstat below would then describe the target, so a link is the one way
    // a rule could be loaded from outside this directory. Checked off the
    // directory entry, which does not follow.
    match item.file_type() {
        Ok(t) if t.is_symlink() => {
            tracing::warn!(file = %path.display(), "skipping symlinked rule file");
            return Err(Skipped::Refused);
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(file = %path.display(), "cannot stat rule file: {e}");
            return Err(Skipped::reaching(&e));
        }
    }
    // Identity and content both come from this fd, as in lists.rs: no window
    // where the trust-checked file and the parsed bytes could differ.
    // O_NOFOLLOW makes the refusal above race-free: the file_type() check
    // reads the directory entry, so on its own a rename between that check
    // and this open could still substitute a link. ELOOP from it means a
    // symlink raced in; that is the refusal working, but the entry was seen
    // as a non-link moments ago, so it conservatively counts as unseen.
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            tracing::warn!(file = %path.display(), "cannot open rule file: {e}");
            Skipped::reaching(&e)
        })?;
    // fstat on an open fd; failure here is not a deletion.
    let meta = file.metadata().map_err(|e| {
        tracing::warn!(file = %path.display(), "cannot stat rule file: {e}");
        Skipped::Unseen
    })?;
    if !meta.is_file() {
        tracing::warn!(file = %path.display(), "skipping rule entry that is not a regular file");
        return Err(Skipped::Refused);
    }
    if !file_perms_ok(meta.uid(), meta.mode(), self_uid) {
        tracing::warn!(
            file = %path.display(),
            uid = meta.uid(),
            mode = format!("{:o}", meta.mode() & 0o7777),
            "skipping rule file: must be owned by root and not group/world-writable"
        );
        return Err(Skipped::Refused);
    }
    let mut text = String::new();
    // A read error on an open fd (EIO) is "could not look", not "looked and
    // judged": lumping it in with parse failures left the scan claiming
    // completeness through the exact transient errors the flag exists for.
    file.read_to_string(&mut text).map_err(|e| {
        tracing::warn!(file = %path.display(), "cannot read rule file: {e}");
        Skipped::Unseen
    })?;
    let mut rule: Rule = toml::from_str(&text).map_err(|e| {
        tracing::warn!(file = %path.display(), "skipping unparsable rule file: {e}");
        Skipped::Refused
    })?;
    // Normalized, not refused: a tag is a label, and no selector could ever
    // have named a malformed one, so dropping it costs nothing that worked.
    // Skipping the rule instead would stop enforcing policy the operator
    // wrote over a mistyped label - on a deny rule, passing exactly the
    // traffic the file exists to stop.
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
    // `CompiledRule::compile`: a rule that cannot compile would otherwise
    // sit inert in the set and crash clients that render it (e.g. a
    // malformed exe_sha256), and a rule naming itself after a session grant
    // would be indistinguishable from one.
    if let Err(e) = CompiledRule::compile(&rule) {
        tracing::warn!(file = %path.display(), "skipping invalid rule file: {e}");
        return Err(Skipped::Refused);
    }
    Ok(rule)
}

impl RuleStore {
    /// Create a store, loading persisted rules from `rules_dir`.
    pub fn new(rules_dir: PathBuf) -> Self {
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
        let store = Self {
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
    fn lock_entries(&self) -> MutexGuard<'_, Vec<Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
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
        if let Some(hit) = self
            .hits
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(name)
        {
            hit.bump(now);
            return;
        }
        let mut map = self.hits.write().unwrap_or_else(PoisonError::into_inner);
        // Re-check: another thread may have inserted between the two locks.
        if let Some(hit) = map.get(name) {
            hit.bump(now);
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
        let map = self.hits.read().unwrap_or_else(PoisonError::into_inner);
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
    pub fn add(&self, mut rule: Rule) -> Result<(), String> {
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
        confine_list_paths(&mut rule, &self.rules_dir)?;
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
        self.lockdown_tags
            .lock()
            .unwrap()
            .as_deref()
            .is_some_and(|tags| !rule.active_under_lockdown(tags))
    }

    /// Recompile under a new lockdown posture. `None` lifts it.
    ///
    /// Only `lockdown::apply` calls this: the posture on disk, the compiled
    /// set and the runtime settings have to move together.
    pub fn rebuild_for_posture(&self, tags: Option<&[String]>) {
        *self.lockdown_tags.lock().unwrap() = tags.map(<[String]>::to_vec);
        self.rebuild();
    }

    fn rebuild(&self) {
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
        let live: HashSet<&str> = rules.iter().map(|r| r.name.as_str()).collect();
        let mut map = self.hits.write().unwrap_or_else(PoisonError::into_inner);
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
            .or_else(|e| {
                if self.rules_dir.is_dir() {
                    Ok(())
                } else {
                    Err(format!("create {}: {e}", self.rules_dir.display()))
                }
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
fn reload_worthy(kind: EventKind) -> bool {
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
        if res.is_ok_and(|ev| reload_worthy(ev.kind)) {
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
mod tests;

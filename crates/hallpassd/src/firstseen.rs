//! What the daemon has seen before, so a prompt can say what is new.
//!
//! Two facts per connection: has this application ever connected, and has it
//! ever reached this destination. Both are annotations. Nothing here decides
//! a verdict, and everything here is bounded and lossy on purpose, because
//! the alternative to forgetting is a file that grows with every domain a
//! host ever resolves.
//!
//! **What is lost when a bound is hit.** The maps are LRU and capped
//! ([`MAX_APPS`], [`MAX_DESTS`]), and a state file that cannot be read or
//! written costs everything across a restart: both lose the *record*, so the
//! connection reads as new a second time. An identity over
//! [`MAX_ACTOR_BYTES`], or a destination over [`MAX_DEST_BYTES`], is never
//! recorded and so reports new every time. Every one of those errs toward
//! saying too much: an operator seeing "NEW" on a familiar application has
//! been told something redundant, while the opposite failure would show a
//! first-ever connection as routine, which is the one thing this is for.
//!
//! That direction is a security property, not only an aesthetic one. The
//! only answer that renders identically to a familiar connection is `None`,
//! and `None` is reserved for a connection with no identity at all: if an
//! unrecordable identity returned it, any local user could suppress the
//! annotation on their own program by running it from a deep enough
//! directory.
//!
//! **Ownership.** The store lives on the verdict thread and is never shared,
//! so it adds no lock between that thread and the tokio side (the
//! architecture's one-lock promise; see `docs/ARCHITECTURE.md`). Persisting
//! is a snapshot handed to a writer task over a channel, at most every
//! [`FLUSH_INTERVAL`] and only when something changed, so no disk write ever
//! happens on the path a packet waits on.

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hallpass_types::{unix_ms_now, Connection, FirstSeen};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::UnboundedSender;

/// Applications remembered at once. Reached only on a host that has run
/// thousands of distinct executables; past it the least recently seen is
/// forgotten and reads as new again.
const MAX_APPS: usize = 512;

/// Destinations remembered at once, across all applications. Larger than
/// [`MAX_APPS`] because one application talks to many endpoints, and because
/// a destination reached by name costs two entries: the name, and the
/// address behind it (see [`Seen::observe_into`]).
const MAX_DESTS: usize = 4096;

/// Longest application identity recorded, in bytes.
///
/// No real identity comes close: this is an executable path plus at most
/// [`hallpass_types::MAX_APP_ID_NAME_BYTES`] of application name. Refusing
/// beats truncating, which would collapse two long paths sharing a prefix
/// onto one entry and hide a genuinely new application.
const MAX_ACTOR_BYTES: usize = 384;

/// Longest destination recorded, in bytes. A DNS name is at most 253, and an
/// address far less.
///
/// Budgeted separately from [`MAX_ACTOR_BYTES`] rather than sharing one bound
/// with it. Sharing meant a long application identity ate the destination's
/// room, so every destination that application reached came out over the
/// bound and was reported new on every single packet, with no path to
/// convergence: a bound on the whole key silently turned into a per-
/// application starvation.
const MAX_DEST_BYTES: usize = 256;

/// Longest composite key, which is what actually bounds the state file:
/// nothing longer is ever written down, so the file cannot exceed roughly
/// `(MAX_APPS + MAX_DESTS) * MAX_KEY_BYTES` however hostile the paths on
/// this host are.
const MAX_KEY_BYTES: usize = MAX_ACTOR_BYTES + 1 + MAX_DEST_BYTES;

/// How often a changed store is handed to the writer task.
///
/// A minute of unwritten history is what a hard power loss costs, and what
/// it costs is annotations. Shorter would write more often on a busy host
/// for nothing: this is not an audit log, and the file is rewritten whole.
const FLUSH_INTERVAL: Duration = Duration::from_secs(60);

/// Separator inside a composite key. A NUL cannot appear in a path (they are
/// NUL-terminated) or in an application identity (`valid_app_id` charset),
/// so joining on it is injective and splitting it back for the state file
/// cannot mix two components up.
const SEP: char = '\0';

/// Version stamp in the state file. A future format change reads this and
/// starts empty rather than misreading the old shape.
const STATE_VERSION: u32 = 1;

/// Identities the daemon has already seen, in memory.
///
/// Keys are internal: they are built from the executable path, the
/// application identity and the destination, none of which is ever rendered
/// from here. Only the two bools of [`FirstSeen`] leave this module, so the
/// hostile-string rules that govern the rest of the connection metadata
/// (`sanitize_for_display`) have nothing to act on.
pub struct Seen {
    // `Arc<str>` rather than `String`, for the snapshot: a flush copies every
    // key out of both maps, on the verdict thread, and with owned strings
    // that is thousands of allocations while a packet waits. Lookups are
    // unaffected (`Arc<str>: Borrow<str>`), and the clone a snapshot makes is
    // a refcount bump.
    apps: LruCache<Arc<str>, u64>,
    dests: LruCache<Arc<str>, u64>,
    /// Reused buffer the per-packet keys are built in.
    ///
    /// This runs on the verdict thread for every judged packet, and the
    /// steady state is a hit on both maps, so the steady state allocates
    /// nothing: the key is written into this buffer and looked up by `&str`,
    /// and only a miss (which is by definition rare after a host warms up)
    /// clones it to own the entry. The destination key extends the
    /// application key rather than being built separately, because it is
    /// exactly that key plus the destination.
    scratch: String,
    /// Whether anything has been recorded since the last snapshot.
    dirty: bool,
}

impl Seen {
    /// An empty store.
    pub fn new() -> Seen {
        Seen {
            apps: LruCache::new(NonZeroUsize::new(MAX_APPS).expect("nonzero")),
            dests: LruCache::new(NonZeroUsize::new(MAX_DESTS).expect("nonzero")),
            scratch: String::with_capacity(MAX_KEY_BYTES),
            dirty: false,
        }
    }

    /// Record `conn` and report what was new about it, or `None` when there
    /// is no identity to record it under.
    ///
    /// `None` is the unattributed case only: with neither an executable path
    /// nor an application identity there is nothing to be the same as next
    /// time, and answering `false` would claim a connection is familiar on
    /// the strength of knowing nothing about it. An identity that exists but
    /// is too long to store reports *new*, every time, rather than `None`:
    /// `None` renders identically to a routine connection everywhere, so
    /// returning it there would let any local user suppress the annotation by
    /// running from a deep enough directory.
    ///
    /// `now` is called only when something is recorded. The steady state
    /// here is two hits, and a clock read per packet to timestamp nothing is
    /// a syscall the verdict thread does not have to make - and it makes
    /// this one per *packet*, not per connection, since a one-way UDP flow
    /// never leaves `ct state new`.
    pub fn observe(&mut self, conn: &Connection, now: &dyn Fn() -> u64) -> Option<FirstSeen> {
        // Taken and put back so the maps and the buffer can be borrowed
        // mutably at once; the buffer survives every path out of here, which
        // is the point of having it.
        let mut key = std::mem::take(&mut self.scratch);
        let out = self.observe_into(&mut key, conn, now);
        key.clear();
        self.scratch = key;
        out
    }

    fn observe_into(
        &mut self,
        key: &mut String,
        conn: &Connection,
        now: &dyn Fn() -> u64,
    ) -> Option<FirstSeen> {
        key.clear();
        match write_actor_key(conn.app_id.as_deref(), conn.exe_path.as_deref(), key) {
            ActorKey::Written => {}
            // An identity exists, and is unrecordable. Nothing can be looked
            // up or stored, so the honest answer is that everything about
            // this connection is unfamiliar, said every time.
            ActorKey::TooLong => return Some(FirstSeen { app: true, dest: true }),
            ActorKey::None => return None,
        }
        let app = touch(&mut self.apps, key, now, &mut self.dirty);
        // A destination is only new if it was recorded; an over-long one is
        // not, and stays new. Deliberately not folded into the app arm: an
        // application whose *first* connection this is has a new destination
        // by definition, and reporting both is what lets a display say
        // "and", but the record still has to exist for the second one.
        let actor_len = key.len();
        let ip = conn.tuple.dst.ip();
        let dest = match &conn.domain {
            Some(domain) => {
                let new = write_dest(domain, key, actor_len)
                    .map(|()| touch(&mut self.dests, key, now, &mut self.dirty));
                // The address is recorded alongside the name, and its answer
                // is thrown away. A snooped name expires (the domain cache
                // clamps to a 30s TTL and then forgets), and every connection
                // decided after that carries no domain at all, so a
                // name-keyed record would miss and report a destination the
                // operator approved months ago as new - once per address, on
                // a CDN forever. Recording both means the address-keyed
                // lookup below finds it. Only the name decides what is
                // reported, so a genuinely new name is still loud even when
                // it resolves to an address this application already reached.
                if write_dest(&ip, key, actor_len).is_some() {
                    touch(&mut self.dests, key, now, &mut self.dirty);
                }
                new
            }
            None => write_dest(&ip, key, actor_len)
                .map(|()| touch(&mut self.dests, key, now, &mut self.dirty)),
        };
        Some(FirstSeen { app, dest: dest.unwrap_or(true) })
    }

    /// How many identities are held, as (applications, destinations).
    fn len(&self) -> (usize, usize) {
        (self.apps.len(), self.dests.len())
    }

    /// Both maps' keys and timestamps, oldest first so the file reads as a
    /// history and a load restores the same LRU order.
    ///
    /// Deliberately raw keys rather than the file's own shape: this runs on
    /// the verdict thread, and splitting a key into its components allocates
    /// three strings per entry. The writer task does that, off the packet
    /// path, from the pointers this hands over.
    fn snapshot(&self) -> Snapshot {
        // `iter()` is most-recent first; reverse so the oldest is written
        // first and re-inserting in file order rebuilds the same ordering.
        let copy = |(key, ms): (&Arc<str>, &u64)| (Arc::clone(key), *ms);
        Snapshot {
            apps: self.apps.iter().rev().map(copy).collect(),
            dests: self.dests.iter().rev().map(copy).collect(),
        }
    }
}

/// One flush: what both maps held, by shared pointer.
struct Snapshot {
    apps: Vec<(Arc<str>, u64)>,
    dests: Vec<(Arc<str>, u64)>,
}

impl Default for Seen {
    fn default() -> Seen {
        Seen::new()
    }
}

/// Look `key` up, recording it if it is absent. `true` means it was.
fn touch(
    map: &mut LruCache<Arc<str>, u64>,
    key: &str,
    now: &dyn Fn() -> u64,
    dirty: &mut bool,
) -> bool {
    // `get` rather than `contains`: it is what promotes the entry, and the
    // whole point of the LRU is that a daily application outlives a
    // one-off one when the cap is reached.
    if map.get(key).is_some() {
        return false;
    }
    // The only allocation on this path, and only ever on a miss.
    map.put(Arc::from(key), now());
    *dirty = true;
    true
}

/// What [`write_actor_key`] found. The two failures are different answers:
/// no identity cannot be tracked, an over-long one cannot be *stored*.
enum ActorKey {
    /// `key` now holds the identity.
    Written,
    /// An identity exists but is over [`MAX_ACTOR_BYTES`].
    TooLong,
    /// The connection was never attributed to anything.
    None,
}

/// Write an application identity into `key`: the same pair a rule generated
/// from a prompt reply is scoped to, so what the operator was told is new is
/// what their answer covers.
///
/// The one encoder of the key layout, used by the packet path with what a
/// connection carries and by [`Entry::key`] with what the state file
/// carries. Written once so the two directions cannot disagree about field
/// order, separators, or the length bound.
///
/// A packaged application is its own identity even when two of them run from
/// one sandbox path, and an application that turns up under a *different*
/// identity than before is new here, including one that chose that identity
/// itself: `app_id` is spoofable, and spoofing it produces an extra prompt
/// annotation rather than a suppressed one.
fn write_actor_key(app_id: Option<&str>, exe: Option<&Path>, key: &mut String) -> ActorKey {
    if app_id.is_none() && exe.is_none() {
        return ActorKey::None;
    }
    if let Some(app) = app_id {
        key.push_str(app);
    }
    key.push(SEP);
    if let Some(exe) = exe {
        // Lossy: a path is bytes, and this key has to be a string the state
        // file can hold. Two paths differing only in invalid UTF-8 collapse
        // onto one entry, which costs one annotation on a path no packaging
        // system produces.
        key.push_str(&exe.to_string_lossy());
    }
    if key.len() > MAX_ACTOR_BYTES {
        return ActorKey::TooLong;
    }
    ActorKey::Written
}

/// Replace whatever destination `key` carries with `dest`, keeping the
/// application key that occupies its first `actor_len` bytes. `None` when
/// the destination is over [`MAX_DEST_BYTES`], which leaves `key` holding a
/// truncated destination and so must be the caller's last use of it.
///
/// `dest` is the domain when one is known and the address otherwise, and it
/// is never the port. A browser opening 443 and then 80 on the same host is
/// one destination to an operator, and flagging the second would train them
/// to ignore the flag. Taking a name over an address means a host first
/// reached by address and later by name reads as new twice: the name really
/// is a fact the daemon did not have before, and it is the fact a domain
/// rule would be written against.
fn write_dest(dest: &dyn std::fmt::Display, key: &mut String, actor_len: usize) -> Option<()> {
    use std::fmt::Write as _;
    key.truncate(actor_len);
    key.push(SEP);
    // Formatted into the buffer rather than through `to_string`, which would
    // allocate a String per packet to then copy and drop.
    let _ = write!(key, "{dest}");
    (key.len() - actor_len - 1 <= MAX_DEST_BYTES).then_some(())
}

/// One remembered identity, as it appears in the state file.
///
/// Components are stored apart rather than as the joined key so the file can
/// be read (and edited, and deleted) by an operator who wants to know what
/// the daemon considers familiar. `first_ms` is there for the same reason
/// and for no other: nothing in the daemon reads it back, and "when did this
/// application first connect here" is the question an operator opening this
/// file has. Any retention policy later added to the caps would start from
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Entry {
    #[serde(skip_serializing_if = "Option::is_none")]
    app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dest: Option<String>,
    first_ms: u64,
}

impl Entry {
    /// Split a stored key back into its components, for the file.
    ///
    /// The inverse of [`write_actor_key`] plus [`write_dest`], and the
    /// only place that knows the layout in this direction.
    fn from_key(key: &str, first_ms: u64) -> Entry {
        let mut parts = key.split(SEP);
        let field = |p: Option<&str>| p.filter(|s| !s.is_empty()).map(str::to_string);
        Entry {
            app_id: field(parts.next()),
            exe: field(parts.next()),
            dest: field(parts.next()),
            first_ms,
        }
    }

    /// The in-memory key this entry restores to, or None when the file
    /// carries something no key could have produced.
    ///
    /// Built through the same encoder the packet path uses, so a file cannot
    /// restore a key shaped differently from the ones being recorded beside
    /// it, and the length bounds are the recording ones rather than a second
    /// copy of them.
    ///
    /// Nothing else is rejected, deliberately. An earlier version also
    /// refused a key containing a newline, on the theory that only a
    /// hand-edited file could hold one - but a Linux path may contain any
    /// byte except NUL, so the daemon writes such keys itself, and the guard
    /// silently dropped exactly those entries on every load. That
    /// application would have been reported new after every restart, for
    /// ever. Keys are never rendered anywhere (only the two bools of
    /// [`FirstSeen`] leave this module) and TOML escapes what it holds, so
    /// there was nothing for the guard to protect.
    fn key(&self) -> Option<String> {
        let mut key = String::with_capacity(MAX_KEY_BYTES);
        let exe = self.exe.as_deref().map(Path::new);
        match write_actor_key(self.app_id.as_deref(), exe, &mut key) {
            ActorKey::Written => {}
            ActorKey::TooLong | ActorKey::None => return None,
        }
        if let Some(dest) = &self.dest {
            let actor_len = key.len();
            write_dest(dest, &mut key, actor_len)?;
        }
        Some(key)
    }
}

/// The whole state file.
#[derive(Debug, Default, Serialize, Deserialize)]
struct StateFile {
    version: u32,
    #[serde(default)]
    app: Vec<Entry>,
    #[serde(default)]
    dest: Vec<Entry>,
}

impl From<Snapshot> for StateFile {
    /// Runs on the writer task, not the verdict thread: this is where the
    /// keys are split and copied into owned strings.
    fn from(snap: Snapshot) -> StateFile {
        let entries = |v: Vec<(Arc<str>, u64)>| {
            v.into_iter().map(|(key, ms)| Entry::from_key(&key, ms)).collect()
        };
        StateFile {
            version: STATE_VERSION,
            app: entries(snap.apps),
            dest: entries(snap.dests),
        }
    }
}

/// Read the state file at `path` into a store.
///
/// Every failure is a warning and an empty store, never a startup failure:
/// this file holds annotations, and refusing to start a firewall over one
/// would trade enforcement for a display detail. A missing file is the
/// normal first run and says so quietly.
///
/// Trusted like a rule file (root-owned, not group- or world-writable),
/// because that check is one line and the alternative is a file any user
/// could pre-seed to make their own new application read as familiar in the
/// prompt an operator is about to answer.
pub fn load(path: &Path) -> Seen {
    let mut seen = Seen::new();
    let text = match read_trusted(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!(path = %path.display(), "no first-seen state yet, starting empty");
            return seen;
        }
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                "cannot read the first-seen state, every application will read as new: {e}"
            );
            return seen;
        }
    };
    let state: StateFile = match toml::from_str(&text) {
        Ok(s) => s,
        Err(e) => {
            // `e.message()` rather than `e`: the Display of a toml error
            // quotes the offending line, and this path is a config setting.
            // Point it at a file the operator cannot read and the journal
            // would print a line of it, the same disclosure the list
            // parsers refuse by naming a line number instead of its text.
            tracing::warn!(
                path = %path.display(),
                span = ?e.span(),
                "first-seen state is unreadable, starting empty: {}",
                e.message()
            );
            return seen;
        }
    };
    if state.version != STATE_VERSION {
        tracing::warn!(
            path = %path.display(),
            version = state.version,
            "first-seen state was written by a different version, starting empty"
        );
        return seen;
    }
    // The caps apply to what a file can restore, not only to what a running
    // daemon records: doing it here means a file that grew by hand (an
    // operator merging two hosts', or restoring an old backup over a new
    // one) cannot make one load allocate more than the daemon's own bound.
    //
    // From the *end* of each list, because a snapshot writes oldest first.
    // Taking from the front kept the least recently seen entries and dropped
    // the most recent ones, so after an over-long file the applications the
    // host actually uses were the ones reported new while long-dead
    // executables stayed familiar - the exact inverse of what the LRU is for.
    let newest = |v: &[Entry], cap: usize| v.len().saturating_sub(cap);
    for e in &state.app[newest(&state.app, MAX_APPS)..] {
        if let Some(key) = e.key() {
            seen.apps.put(Arc::from(key), e.first_ms);
        }
    }
    for e in &state.dest[newest(&state.dest, MAX_DESTS)..] {
        if let Some(key) = e.key() {
            seen.dests.put(Arc::from(key), e.first_ms);
        }
    }
    let (apps, dests) = seen.len();
    tracing::info!(apps, dests, path = %path.display(), "first-seen state loaded");
    seen
}

/// Read the state file, refusing a symlink at the path.
///
/// [`Links::Refuse`](crate::rules::store::Links::Refuse), unlike the config:
/// this path is a setting too, so its default directory is not the only place
/// it can point, but nothing about this file is operator-authored: the daemon
/// writes it and only the daemon reads it. Following a link planted where it
/// reads would aim a root open at a file the planter cannot read, and the
/// ownership check passes for anything root owns. Refusing costs a warning
/// and an empty store.
fn read_trusted(path: &Path) -> std::io::Result<String> {
    crate::rules::store::read_trusted(path, crate::rules::store::Links::Refuse)
}

/// Write `state` to `path`, atomically and privately.
///
/// Mode 0600 rather than the rule store's 0644: this is a record of which
/// applications on this host talk to which destinations, and nothing but the
/// daemon needs to read it.
fn write_state(path: &Path, state: &StateFile) -> std::io::Result<()> {
    let text = toml::to_string(state)
        .map_err(|e| std::io::Error::other(format!("serialize first-seen state: {e}")))?;
    crate::rules::store::write_atomic(path, text.as_bytes(), 0o600)
}

/// The verdict thread's handle on first-seen tracking: the store itself,
/// plus the channel that carries snapshots to the writer task.
pub struct Tracker {
    seen: Seen,
    snapshots: UnboundedSender<Snapshot>,
    last_flush: Instant,
    /// Set by the writer task when a write fails, cleared when one succeeds.
    ///
    /// Without it a failed write was final: `flush` clears `dirty` before
    /// handing the snapshot over, so a full disk at minute five meant nothing
    /// was ever written again unless some later miss happened to re-dirty the
    /// store - and on a warmed-up host, none does. The whole run's record was
    /// then lost at restart with one warning in the journal to explain it.
    /// An atomic rather than a lock: the verdict thread reads it, and the
    /// architecture's one-lock promise is about locks, which this is not (the
    /// same reasoning `RuntimeSettings` is built on).
    write_failed: Arc<std::sync::atomic::AtomicBool>,
}

impl Tracker {
    /// Record `conn` and report what is new about it.
    pub fn observe(&mut self, conn: &Connection) -> Option<FirstSeen> {
        // The clock is read inside, and only when something is recorded.
        self.seen.observe(conn, &unix_ms_now)
    }

    /// Hand the writer task a snapshot if enough time has passed and there is
    /// anything to write. Cheap enough to call once per queue-loop iteration:
    /// on a quiet, written-out store it is two relaxed loads and a bool.
    pub fn maybe_flush(&mut self) {
        if !self.needs_write() || self.last_flush.elapsed() < FLUSH_INTERVAL {
            return;
        }
        self.flush();
    }

    /// Whether the file on disk is behind the store: something new was
    /// recorded, or the last attempt to write did not land. A snapshot is
    /// the whole state, so re-sending one after a failure is idempotent.
    fn needs_write(&self) -> bool {
        self.seen.dirty
            || self.write_failed.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Hand over a snapshot now. Called on the periodic path and once more
    /// when the queue loop ends, so a clean shutdown persists the run.
    fn flush(&mut self) {
        self.last_flush = Instant::now();
        // Cleared before the send: a failed send means the writer task is
        // gone, and retrying every iteration for the life of the process
        // would spend the verdict thread's time on a channel nobody reads.
        // A failed *write* is different, and `write_failed` carries that.
        self.seen.dirty = false;
        let _ = self.snapshots.send(self.seen.snapshot());
    }
}

impl Drop for Tracker {
    /// The queue loop ends by dropping its deps, and everything recorded
    /// since the last flush would go with them.
    fn drop(&mut self) {
        if self.needs_write() {
            self.flush();
        }
    }
}

/// Load `path` and start the task that writes it back.
///
/// Returns the verdict thread's [`Tracker`] and the writer's join handle, so
/// shutdown can await the final snapshot: the tracker is dropped when the
/// queue loop ends, which closes the channel, which ends the task after it
/// has drained what it was given.
pub fn start(path: PathBuf) -> (Tracker, tokio::task::JoinHandle<()>) {
    use std::sync::atomic::{AtomicBool, Ordering};

    let seen = load(&path);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Snapshot>();
    let write_failed = Arc::new(AtomicBool::new(false));
    let writer_failed = Arc::clone(&write_failed);
    let writer = tokio::spawn(async move {
        // Warn once per failure kind, not once per flush: an unwritable
        // state directory would otherwise fill the journal at flush cadence
        // for the life of the daemon, and the first line already says
        // everything the operator has to act on.
        let mut warned = false;
        while let Some(snapshot) = rx.recv().await {
            let path = path.clone();
            // spawn_blocking: this splits every key, serializes, writes and
            // fsyncs a file, and the runtime workers it would otherwise sit
            // on are the ones serving IPC.
            let result = tokio::task::spawn_blocking(move || {
                write_state(&path, &StateFile::from(snapshot))
            })
            .await;
            // The flag, not just the log line: the verdict thread cleared
            // `dirty` when it handed this over, so without it a write that
            // failed is one nothing ever retries.
            match result {
                Ok(Ok(())) => {
                    warned = false;
                    writer_failed.store(false, Ordering::Relaxed);
                }
                Ok(Err(e)) => {
                    writer_failed.store(true, Ordering::Relaxed);
                    if !warned {
                        warned = true;
                        tracing::warn!(
                            "cannot write the first-seen state, retrying every \
                             {}s until it succeeds: {e}",
                            FLUSH_INTERVAL.as_secs()
                        );
                    }
                }
                // The blocking pool is gone (shutdown) or the write panicked.
                Err(e) => {
                    writer_failed.store(true, Ordering::Relaxed);
                    tracing::warn!("first-seen state write did not run: {e}");
                }
            }
        }
    });
    (
        Tracker {
            seen,
            snapshots: tx,
            // Not `Instant::now() - FLUSH_INTERVAL`: the first flush should
            // not land in the middle of daemon startup, where it competes
            // with the rule load and the nftables install.
            last_flush: Instant::now(),
            write_failed,
        },
        writer,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestDir;
    use hallpass_types::{FlowTuple, Proto};
    use std::path::PathBuf;

    fn conn(exe: Option<&str>, app_id: Option<&str>, domain: Option<&str>, dst: &str) -> Connection {
        Connection {
            tuple: FlowTuple {
                proto: Proto::Tcp,
                src: "10.0.0.1:40000".parse().unwrap(),
                dst: dst.parse().unwrap(),
            },
            uid: Some(1000),
            pid: Some(7),
            exe_path: exe.map(PathBuf::from),
            cmdline: None,
            parent_exe: None,
            domain: domain.map(String::from),
            iface: None,
            app_id: app_id.map(String::from),
            first_seen: None,
        }
    }

    #[test]
    fn first_connection_is_new_and_the_second_is_not() {
        let mut seen = Seen::new();
        let c = conn(Some("/usr/bin/curl"), None, Some("example.org"), "1.1.1.1:443");
        assert_eq!(seen.observe(&c, &|| 1), Some(FirstSeen { app: true, dest: true }));
        assert_eq!(seen.observe(&c, &|| 2), Some(FirstSeen { app: false, dest: false }));
    }

    /// The point of splitting the two flags: a familiar application going
    /// somewhere it has never been is the interesting case, and it has to
    /// read differently from a routine connection.
    #[test]
    fn known_application_reaching_a_new_destination() {
        let mut seen = Seen::new();
        seen.observe(&conn(Some("/usr/bin/curl"), None, Some("a.example"), "1.1.1.1:443"), &|| 1);
        let second = conn(Some("/usr/bin/curl"), None, Some("b.example"), "1.1.1.1:443");
        let out = seen.observe(&second, &|| 2);
        assert_eq!(out, Some(FirstSeen { app: false, dest: true }));
    }

    /// Ports are not part of a destination: the same host on 80 after 443 is
    /// the same place, and flagging it would train an operator to ignore the
    /// flag.
    #[test]
    fn a_second_port_on_a_known_host_is_not_new() {
        let mut seen = Seen::new();
        seen.observe(&conn(Some("/usr/bin/curl"), None, None, "1.1.1.1:443"), &|| 1);
        let out = seen.observe(&conn(Some("/usr/bin/curl"), None, None, "1.1.1.1:80"), &|| 2);
        assert_eq!(out, Some(FirstSeen { app: false, dest: false }));
    }

    /// Two packaged applications can run from one sandbox path. They are
    /// different applications, and the identity a rule would pin is what
    /// tells them apart.
    #[test]
    fn packaged_applications_sharing_a_path_are_separate() {
        let mut seen = Seen::new();
        let a = conn(Some("/app/bin/x"), Some("flatpak:org.a.A"), None, "1.1.1.1:443");
        let b = conn(Some("/app/bin/x"), Some("flatpak:org.b.B"), None, "1.1.1.1:443");
        assert_eq!(seen.observe(&a, &|| 1), Some(FirstSeen { app: true, dest: true }));
        assert_eq!(seen.observe(&b, &|| 2), Some(FirstSeen { app: true, dest: true }));
        assert_eq!(seen.observe(&a, &|| 3), Some(FirstSeen { app: false, dest: false }));
    }

    /// Nothing to be the same as next time, so the honest answer is "not
    /// tracked" rather than "seen before".
    #[test]
    fn unattributed_connections_are_not_tracked() {
        let mut seen = Seen::new();
        assert_eq!(seen.observe(&conn(None, None, None, "1.1.1.1:443"), &|| 1), None);
    }

    /// An identity too long to record reports new every time rather than
    /// being truncated onto some other application's entry - and, crucially,
    /// rather than reporting `None`, which renders exactly like a familiar
    /// connection. Otherwise any local user could suppress the annotation by
    /// running from a deep enough directory.
    #[test]
    fn over_long_identities_report_new_rather_than_nothing() {
        let mut seen = Seen::new();
        let long = format!("/usr/bin/{}", "a".repeat(MAX_ACTOR_BYTES));
        let c = conn(Some(&long), None, None, "1.1.1.1:443");
        for _ in 0..3 {
            assert_eq!(seen.observe(&c, &|| 1), Some(FirstSeen { app: true, dest: true }));
        }
        assert_eq!(seen.len(), (0, 0), "nothing over the bound is stored");

        // A recordable application with an unrecordable destination keeps
        // the application half working.
        let domain = "d".repeat(MAX_DEST_BYTES + 1);
        let c = conn(Some("/usr/bin/curl"), None, Some(&domain), "1.1.1.1:443");
        assert_eq!(seen.observe(&c, &|| 1), Some(FirstSeen { app: true, dest: true }));
        assert_eq!(seen.observe(&c, &|| 2), Some(FirstSeen { app: false, dest: true }));
    }

    /// The destination gets its own byte budget. Sharing one bound with the
    /// application identity meant a long identity (a flatpak path with a
    /// commit hash in it) left no room for the destination, so every
    /// destination that application reached came out over the bound and was
    /// reported new on every packet, for ever.
    #[test]
    fn a_long_application_identity_does_not_starve_the_destination() {
        let mut seen = Seen::new();
        let exe = format!("/app/{}/bin/x", "a".repeat(MAX_ACTOR_BYTES - 20));
        let c = conn(Some(&exe), None, Some("cdn.example.org"), "1.1.1.1:443");
        assert_eq!(seen.observe(&c, &|| 1), Some(FirstSeen { app: true, dest: true }));
        assert_eq!(
            seen.observe(&c, &|| 2),
            Some(FirstSeen { app: false, dest: false }),
            "the destination must converge, not report new for ever"
        );
    }

    /// A snooped name expires from the domain cache, and connections decided
    /// after that carry no domain at all. Keying only on the name would then
    /// miss and re-flag a destination the operator approved long ago - once
    /// per address, and on a CDN for ever.
    #[test]
    fn a_destination_stays_familiar_after_its_domain_expires() {
        let mut seen = Seen::new();
        let named = conn(Some("/usr/bin/curl"), None, Some("cdn.example.org"), "1.1.1.1:443");
        assert_eq!(seen.observe(&named, &|| 1), Some(FirstSeen { app: true, dest: true }));

        let unnamed = conn(Some("/usr/bin/curl"), None, None, "1.1.1.1:443");
        assert_eq!(
            seen.observe(&unnamed, &|| 2),
            Some(FirstSeen { app: false, dest: false }),
            "the address behind a known name must be known too"
        );

        // A genuinely new name is still loud, even resolving to that address.
        let other = conn(Some("/usr/bin/curl"), None, Some("other.example"), "1.1.1.1:443");
        assert_eq!(seen.observe(&other, &|| 3), Some(FirstSeen { app: false, dest: true }));
    }

    #[test]
    fn the_least_recently_seen_is_forgotten_when_full() {
        let mut seen = Seen::new();
        for i in 0..MAX_APPS {
            seen.observe(&conn(Some(&format!("/usr/bin/p{i}")), None, None, "1.1.1.1:443"), &|| 1);
        }
        // Keep the first one warm, then overflow by one.
        let first = conn(Some("/usr/bin/p0"), None, None, "1.1.1.1:443");
        assert_eq!(seen.observe(&first, &|| 2).map(|f| f.app), Some(false));
        seen.observe(&conn(Some("/usr/bin/new"), None, None, "1.1.1.1:443"), &|| 3);
        assert_eq!(seen.len().0, MAX_APPS);
        // The touched entry survived; the one after it did not.
        assert_eq!(seen.observe(&first, &|| 4).map(|f| f.app), Some(false));
        let evicted = conn(Some("/usr/bin/p1"), None, None, "1.1.1.1:443");
        assert_eq!(seen.observe(&evicted, &|| 5).map(|f| f.app), Some(true));
    }

    #[test]
    fn state_survives_a_write_and_load() {
        let dir = TestDir::new("firstseen-roundtrip");
        let path = dir.path().join("seen.toml");
        let mut seen = Seen::new();
        let a = conn(Some("/usr/bin/curl"), None, Some("example.org"), "1.1.1.1:443");
        let b = conn(Some("/app/bin/x"), Some("snap:firefox"), None, "9.9.9.9:443");
        seen.observe(&a, &|| 1);
        seen.observe(&b, &|| 2);
        write_state(&path, &StateFile::from(seen.snapshot())).expect("write state");

        let mut loaded = load(&path);
        // Three destinations for two connections: the one reached by name
        // recorded its address as well, which is what keeps it familiar once
        // the name expires from the domain cache.
        assert_eq!(loaded.len(), (2, 3));
        assert_eq!(loaded.observe(&a, &|| 3), Some(FirstSeen { app: false, dest: false }));
        assert_eq!(loaded.observe(&b, &|| 4), Some(FirstSeen { app: false, dest: false }));
        // Something it never saw is still new after a reload.
        let c = conn(Some("/usr/bin/nc"), None, None, "1.1.1.1:443");
        assert_eq!(loaded.observe(&c, &|| 5), Some(FirstSeen { app: true, dest: true }));
    }

    /// A path may contain any byte but NUL, newlines included, so the daemon
    /// writes such keys itself. A load that refused them dropped exactly
    /// those entries every time, and that application was reported new after
    /// every restart, for ever.
    #[test]
    fn an_executable_path_with_a_newline_round_trips() {
        let dir = TestDir::new("firstseen-newline");
        let path = dir.path().join("seen.toml");
        let mut seen = Seen::new();
        let c = conn(Some("/tmp/a\nb/evil"), None, None, "1.1.1.1:443");
        assert_eq!(seen.observe(&c, &|| 1), Some(FirstSeen { app: true, dest: true }));
        write_state(&path, &StateFile::from(seen.snapshot())).expect("write state");

        let mut loaded = load(&path);
        assert_eq!(loaded.len(), (1, 1), "the entry survived the file");
        assert_eq!(loaded.observe(&c, &|| 2), Some(FirstSeen { app: false, dest: false }));
    }

    /// A file holding more than the caps keeps its *newest* entries. A
    /// snapshot writes oldest first, so taking from the front restored the
    /// least recently seen and dropped the rest: after an operator merged
    /// two hosts' files, the applications the host actually uses would be
    /// the ones reported new while long-dead ones stayed familiar.
    #[test]
    fn an_over_long_state_file_keeps_the_newest_entries() {
        let dir = TestDir::new("firstseen-overlong");
        let mut text = String::from("version = 1\n");
        for i in 0..MAX_APPS + 3 {
            text.push_str(&format!("[[app]]\nexe = \"/usr/bin/p{i}\"\nfirst_ms = {i}\n"));
        }
        let path = dir.write("seen.toml", text);

        let mut seen = load(&path);
        assert_eq!(seen.len().0, MAX_APPS);
        let newest = conn(Some(&format!("/usr/bin/p{}", MAX_APPS + 2)), None, None, "1.1.1.1:443");
        assert_eq!(seen.observe(&newest, &|| 1).map(|f| f.app), Some(false));
        let oldest = conn(Some("/usr/bin/p0"), None, None, "1.1.1.1:443");
        assert_eq!(seen.observe(&oldest, &|| 2).map(|f| f.app), Some(true));
    }

    /// The path is a config setting, and opening a FIFO blocks until a
    /// writer appears. This load happens before the nftables install, so a
    /// mistyped path that hung here would leave the daemon alive, silent,
    /// and the host unfiltered.
    #[test]
    fn a_fifo_at_the_state_path_does_not_hang_the_load() {
        let dir = TestDir::new("firstseen-fifo");
        let path = dir.path().join("seen.toml");
        let made = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !made {
            eprintln!("SKIP: mkfifo unavailable");
            return;
        }
        // Returns rather than blocking, and with nothing loaded.
        assert_eq!(load(&path).len(), (0, 0));
    }

    /// The file is a convenience, not a source of truth: anything wrong with
    /// it costs annotations and must never cost a start.
    #[test]
    fn a_broken_state_file_starts_empty() {
        let dir = TestDir::new("firstseen-broken");
        let path = dir.path().join("seen.toml");

        std::fs::write(&path, "this is not toml {{{").unwrap();
        assert_eq!(load(&path).len(), (0, 0));

        std::fs::write(&path, "version = 99\n").unwrap();
        assert_eq!(load(&path).len(), (0, 0));

        // A missing file is the normal first run.
        std::fs::remove_file(&path).unwrap();
        assert_eq!(load(&path).len(), (0, 0));
    }

    /// A file may not restore what the daemon would never write: an entry
    /// with no identity at all, or one past the length bound.
    #[test]
    fn hostile_entries_are_dropped_on_load() {
        let dir = TestDir::new("firstseen-hostile");
        let long = "a".repeat(MAX_KEY_BYTES * 2);
        let path = dir.write(
            "seen.toml",
            format!(
                "version = 1\n\
                 [[app]]\nfirst_ms = 1\n\
                 [[app]]\nexe = \"{long}\"\nfirst_ms = 1\n\
                 [[app]]\nexe = \"/usr/bin/curl\"\nfirst_ms = 1\n"
            ),
        );
        let seen = load(&path);
        assert_eq!(seen.len(), (1, 0));
    }

    /// The path is a config setting, so it can be pointed somewhere a
    /// planter controls. Reading must not follow a link, and a parse failure
    /// must not print the line it failed on: both would turn a root daemon
    /// into a reader of files the planter cannot open.
    #[test]
    fn reading_refuses_a_symlink_and_never_echoes_content() {
        let dir = TestDir::new("firstseen-link");
        let secret = "root:$6$SUPERSECRETHASH:19000:0:99999:7:::";
        let secret_path = dir.write("secret", secret);
        let path = dir.path().join("seen.toml");
        std::os::unix::fs::symlink(&secret_path, &path).unwrap();

        let err = read_trusted(&path).expect_err("a symlink must not be followed");
        assert!(!format!("{err}").contains("SUPERSECRETHASH"), "{err}");

        // And the error text for a real file that does not parse carries no
        // line of it either.
        std::fs::remove_file(&path).unwrap();
        crate::testutil::write_trusted(&path, secret);
        let text = read_trusted(&path).expect("a real file is read");
        let e = toml::from_str::<StateFile>(&text).expect_err("not toml");
        assert!(
            !e.message().contains("SUPERSECRETHASH"),
            "the message this logs quotes the file: {}",
            e.message()
        );
        assert_eq!(load(&path).len(), (0, 0));
    }

    /// Writing must not follow a symlink planted at the temp path, and must
    /// leave the previous state in place when it fails.
    #[test]
    fn a_planted_temp_symlink_is_refused() {
        let dir = TestDir::new("firstseen-symlink");
        let path = dir.path().join("seen.toml");
        let elsewhere = dir.path().join("elsewhere");
        std::os::unix::fs::symlink(&elsewhere, dir.path().join(".seen.toml.tmp")).unwrap();
        // The plant is removed by the writer before it creates its own temp
        // file, so this succeeds; what must not happen is a write landing on
        // the symlink target.
        write_state(&path, &StateFile::from(Seen::new().snapshot())).expect("write state");
        assert!(!elsewhere.exists(), "the write followed the planted link");
    }
}

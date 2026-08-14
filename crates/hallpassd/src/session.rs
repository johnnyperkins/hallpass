//! Session grants: a prompt suppressor scoped to one process tree.
//!
//! A session is opened by a client over its own IPC connection
//! (`hallpass run -- <cmd>`) and covers that client's descendants for as
//! long as the connection lives. A covered connection that no rule matched
//! is allowed instead of prompting, and reports itself through the existing
//! rule-name field as `run-session:<id>`.
//!
//! Three properties are worth stating outright, because they are what makes
//! this safe to have at all:
//!
//! - **Nothing is claimed.** The process a session is rooted at comes from
//!   the socket's peer credentials, so a client cannot open a session over
//!   someone else's process tree, and no verification step is needed.
//! - **A grant never overrides policy.** It is consulted only where a
//!   connection would otherwise raise a prompt, so an explicit deny still
//!   denies inside a session, and an explicit allow still names its own rule.
//! - **Every failure direction prompts.** No pid, no start time, a uid
//!   mismatch, a broken or too-deep chain, a session that has ended: all of
//!   them mean the connection is decided the way it would have been with no
//!   session at all. Nothing here can turn a prompt into an allow by
//!   accident, only by covering the process.
//!
//! Membership is process ancestry rather than a cgroup: see the roadmap
//! notes for why the cgroup design was rejected. The wrapper sets
//! `PR_SET_CHILD_SUBREAPER` before spawning, so a descendant that
//! double-forks reparents onto the wrapper instead of past it and stays
//! covered for exactly the session's lifetime.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use arc_swap::ArcSwap;
use hallpass_types::RunSessionInfo;

use crate::attribution::procfs::{covering_root, starttime_of};

/// Live sessions allowed at once, host-wide.
///
/// A bound rather than a resource limit: sessions are cheap, but the walk
/// below compares every hop against every root, so an unbounded registry
/// would put an unbounded loop on the packet path. What is lost when the
/// registry is full is a refusal to open one more session, never a verdict:
/// the wrapper reports the refusal and does not run the child.
const MAX_RUN_SESSIONS: usize = 64;

/// Live sessions allowed at once *per user*.
///
/// The host-wide bound alone is a denial of service between users: opening a
/// session needs nothing but a socket connection, so one member of the
/// `hallpass` group could hold all 64 and every other user's - including
/// root's - `hallpass run` would refuse to run its command. A per-user share
/// makes exhaustion self-inflicted. Well above any real use: a session is
/// one wrapped command, and eight concurrent ones per user is already a
/// strange desk.
const MAX_RUN_SESSIONS_PER_UID: usize = 8;

/// How far up the process tree a membership walk looks.
///
/// Deeper than the four hops a prompt renders as ancestry, because this is
/// asking a different question: build trees, test harnesses and shells nest,
/// and the answer has to hold for the whole tree rather than read well. A
/// legitimate process further from its session root than this loses its
/// coverage and prompts, which is the fail-safe direction.
const MAX_SESSION_WALK_DEPTH: usize = 32;

/// One live session grant.
#[derive(Debug)]
pub struct RunSession {
    /// Session id, as it appears in the `run-session:<id>` rule name.
    pub id: u64,
    /// The process the session is rooted at, as (pid, start time). The pair
    /// is one process incarnation: a recycled pid does not inherit a grant.
    pub root: (u32, u64),
    /// UID the session covers. A connection from another user is not
    /// covered even inside the tree, so `sudo` in a session still prompts.
    pub uid: u32,
    /// What the wrapper is running. Display only, never matched on.
    pub label: String,
    /// Connections this grant has allowed.
    allowed: AtomicU64,
    started: Instant,
}

impl RunSession {
    fn info(&self) -> RunSessionInfo {
        RunSessionInfo {
            id: self.id,
            uid: self.uid,
            root_pid: self.root.0,
            label: self.label.clone(),
            allowed: self.allowed.load(Ordering::Relaxed),
            age_secs: self.started.elapsed().as_secs(),
        }
    }
}

/// The live sessions, readable from the verdict thread without a lock.
///
/// Same shape as [`crate::rules::store::RuleStore`]'s active ruleset and for
/// the same reason: readers load a snapshot, and the mutex serializes the
/// rebuild-and-swap of the two writers (register, unregister), both of which
/// run on IPC tasks. The packet path never takes it, so the architecture's
/// one-lock promise still holds.
#[derive(Debug)]
pub struct SessionRegistry {
    active: ArcSwap<Vec<Arc<RunSession>>>,
    writers: Mutex<()>,
    next_id: AtomicU64,
}

impl Default for SessionRegistry {
    fn default() -> Self {
        SessionRegistry {
            active: ArcSwap::from_pointee(Vec::new()),
            writers: Mutex::new(()),
            next_id: AtomicU64::new(1),
        }
    }
}

impl SessionRegistry {
    /// Open a session rooted at `peer_pid`, covering `peer_uid`.
    ///
    /// Both arguments come from the socket's peer credentials. `peer_pid` of
    /// zero or absent means the peer is in a pid namespace this daemon
    /// cannot name a process in, and the session is refused rather than
    /// rooted at whatever pid 0 would walk into.
    pub fn register(&self, peer: PeerProcess, peer_uid: u32, label: String) -> Result<u64, String> {
        let Some(pid) = peer.pid.filter(|p| *p != 0) else {
            return Err(
                "the daemon cannot see this client's process id, so it cannot \
                        tell which processes the session would cover"
                    .into(),
            );
        };
        // The start time read when this connection was accepted, and the one
        // now. They must agree, and that is the whole defence against a
        // recycled pid: `SO_PEERCRED` is stamped once, when the socket is
        // connected, and the kernel never refreshes it. A client can connect,
        // fork so the child keeps the socket, let the parent exit, wait for
        // the pid to be reissued to an unrelated process of the same user,
        // and only then ask for a session - which would otherwise be rooted
        // at that stranger's process tree.
        //
        // Residual, and the reason this is a comparison rather than a proof:
        // the accept-time read happens just after the kernel stamped the
        // credentials, not atomically with it. Closing that microsecond
        // needs `SO_PEERPIDFD` (Linux 6.5+), which is worth doing the day
        // this daemon can require it.
        let Some(started) = peer.started else {
            return Err(format!(
                "could not read the start time of process {pid} when it connected"
            ));
        };
        if starttime_of(Path::new("/proc"), pid) != Some(started) {
            return Err(format!(
                "process {pid} is not the process that opened this connection"
            ));
        }
        if label.len() > crate::rules::store::MAX_RULE_NAME_BYTES {
            return Err(format!(
                "session label is {} bytes, must be at most {}",
                label.len(),
                crate::rules::store::MAX_RULE_NAME_BYTES
            ));
        }

        let _writing = self.writers.lock().unwrap_or_else(|e| e.into_inner());
        let current = self.active.load();
        if current.len() >= MAX_RUN_SESSIONS {
            return Err(format!(
                "{MAX_RUN_SESSIONS} sessions are already open host-wide, which is the limit"
            ));
        }
        if current.iter().filter(|s| s.uid == peer_uid).count() >= MAX_RUN_SESSIONS_PER_UID {
            return Err(format!(
                "this user already has {MAX_RUN_SESSIONS_PER_UID} sessions open, \
                 which is the per-user limit"
            ));
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let session = Arc::new(RunSession {
            id,
            root: (pid, started),
            uid: peer_uid,
            label,
            allowed: AtomicU64::new(0),
            started: Instant::now(),
        });
        let mut next = Vec::with_capacity(current.len() + 1);
        next.extend(current.iter().cloned());
        next.push(session.clone());
        self.active.store(Arc::new(next));
        tracing::info!(
            id,
            pid,
            uid = peer_uid,
            label = %hallpass_types::sanitize_for_display(&session.label),
            "session grant opened; unmatched connections from its process tree are allowed"
        );
        Ok(id)
    }

    /// Close a session. Silent when it is already gone.
    pub fn unregister(&self, id: u64) {
        let _writing = self.writers.lock().unwrap_or_else(|e| e.into_inner());
        let current = self.active.load();
        let Some(gone) = current.iter().find(|s| s.id == id).cloned() else {
            return;
        };
        let next: Vec<_> = current.iter().filter(|s| s.id != id).cloned().collect();
        self.active.store(Arc::new(next));
        tracing::info!(
            id,
            allowed = gone.allowed.load(Ordering::Relaxed),
            label = %hallpass_types::sanitize_for_display(&gone.label),
            "session grant closed; its process tree prompts again"
        );
    }

    /// Snapshot of the live sessions.
    ///
    /// A guard rather than an owned `Arc`: the packet path reads this per
    /// unmatched connection and does not keep it, so there is no reason to
    /// pay a refcount bump for it.
    pub fn snapshot(&self) -> arc_swap::Guard<Arc<Vec<Arc<RunSession>>>> {
        self.active.load()
    }

    /// The live sessions, for a client asking what is open.
    pub fn list(&self) -> Vec<RunSessionInfo> {
        self.active.load().iter().map(|s| s.info()).collect()
    }
}

/// Who is on the other end of a client connection, as the kernel reported it
/// when the connection was accepted.
///
/// The start time is read at accept rather than at register so it can be
/// compared later: it is what distinguishes the process that opened this
/// socket from a stranger that inherited its pid.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeerProcess {
    /// Peer pid from `SO_PEERCRED`, absent when the peer lives in a pid
    /// namespace this daemon cannot name a process in.
    pub pid: Option<u32>,
    /// That pid's start time, read immediately after the accept.
    pub started: Option<u64>,
}

impl PeerProcess {
    /// Read the peer's start time now, pinning the identity of the process
    /// on the other end of a freshly accepted connection.
    pub fn resolve(pid: Option<u32>) -> PeerProcess {
        PeerProcess {
            pid,
            started: pid
                .filter(|p| *p != 0)
                .and_then(|p| starttime_of(Path::new("/proc"), p)),
        }
    }
}

/// Id of the session covering `pid`, or `None` when nothing does.
///
/// `uid` is the connection's and must match the session's: a setuid step
/// inside a covered tree runs as another user, and a grant one user opened
/// must not decide for another.
///
/// **Deliberately not cached.** An earlier cut kept a per-pid LRU of the
/// answer, which is the obvious optimization and was wrong in three
/// directions at once, all of which cost a verdict rather than a display
/// string: a positive answer outlived the ancestry that justified it, so a
/// process that left the tree (a daemonizing descendant on a host where the
/// subreaper call failed) kept its grant; a negative answer computed for one
/// uid was returned for a later connection from the same pid under another;
/// and a walk that failed transiently - an intermediate parent exiting
/// between two `/proc` reads - was remembered as a permanent "not covered",
/// so a process that reparented onto the wrapper a millisecond later never
/// got another chance. Answers about a live process tree are not cacheable
/// facts. What bounds the cost instead is where this is asked from: only for
/// a connection that matched no rule, which is a connection that was
/// otherwise about to raise a dialog.
pub fn covering(
    sessions: &[Arc<RunSession>],
    proc_root: &Path,
    pid: u32,
    uid: Option<u32>,
) -> Option<u64> {
    let uid = uid?;
    // Only sessions this connection's user opened are worth walking for, so
    // a mismatched uid is a walk that never happens rather than one thrown
    // away afterwards.
    let mut roots = Vec::with_capacity(sessions.len());
    for s in sessions.iter().filter(|s| s.uid == uid) {
        roots.push(s.root);
    }
    if roots.is_empty() {
        return None;
    }
    let root = roots.get(covering_root(
        proc_root,
        pid,
        &roots,
        MAX_SESSION_WALK_DEPTH,
    )?)?;
    let session = sessions.iter().find(|s| s.uid == uid && s.root == *root)?;
    session.allowed.fetch_add(1, Ordering::Relaxed);
    Some(session.id)
}

/// The rule name a session grant reports itself under.
pub fn rule_name(id: u64) -> String {
    format!("{}{id}", hallpass_types::RUN_SESSION_RULE_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> SessionRegistry {
        SessionRegistry::default()
    }

    /// This test process, as the daemon would see it on the other end of a
    /// connection.
    fn peer() -> PeerProcess {
        PeerProcess::resolve(Some(std::process::id()))
    }

    #[test]
    fn a_session_is_rooted_at_the_calling_process() {
        let reg = registry();
        let me = std::process::id();
        let id = reg.register(peer(), 1000, "curl".into()).expect("register");
        let live = reg.snapshot();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].id, id);
        assert_eq!(live[0].root.0, me);
        assert_eq!(live[0].uid, 1000);

        reg.unregister(id);
        assert!(reg.snapshot().is_empty());
        // Closing twice is what a client task does when it already ended
        // the session explicitly; it must not disturb the others.
        reg.unregister(id);
        assert!(reg.snapshot().is_empty());
    }

    #[test]
    fn a_peer_the_daemon_cannot_name_is_refused() {
        let reg = registry();
        assert!(reg
            .register(PeerProcess::default(), 1000, "curl".into())
            .is_err());
        assert!(reg
            .register(PeerProcess::resolve(Some(0)), 1000, "curl".into())
            .is_err());
        assert!(reg.snapshot().is_empty());
    }

    #[test]
    fn an_oversized_label_is_refused() {
        let reg = registry();
        let label = "x".repeat(crate::rules::store::MAX_RULE_NAME_BYTES + 1);
        assert!(reg.register(peer(), 1000, label).is_err());
        assert!(reg.snapshot().is_empty());
    }

    /// The host-wide bound holds even when no single user is over its own
    /// share, which is the only way to reach it now.
    #[test]
    fn the_registry_is_bounded() {
        let reg = registry();
        let mut uid = 1000;
        while reg.snapshot().len() < MAX_RUN_SESSIONS {
            for _ in 0..MAX_RUN_SESSIONS_PER_UID {
                reg.register(peer(), uid, "curl".into()).expect("register");
            }
            uid += 1;
        }
        let err = reg
            .register(peer(), uid, "curl".into())
            .expect_err("the host-wide limit must be enforced");
        assert!(err.contains("host-wide"), "{err}");
        assert_eq!(reg.snapshot().len(), MAX_RUN_SESSIONS);
    }

    #[test]
    fn ids_are_not_reused_after_a_session_ends() {
        let reg = registry();
        let first = reg.register(peer(), 1000, "a".into()).expect("register");
        reg.unregister(first);
        let second = reg.register(peer(), 1000, "b".into()).expect("register");
        assert_ne!(
            first, second,
            "a closed session's id must not be handed out again"
        );
    }

    #[test]
    fn listing_reports_what_is_open() {
        let reg = registry();
        let me = std::process::id();
        let id = reg.register(peer(), 1000, "curl".into()).expect("register");
        let listed = reg.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, id);
        assert_eq!(listed[0].root_pid, me);
        assert_eq!(listed[0].label, "curl");
        assert_eq!(listed[0].allowed, 0);
    }

    #[test]
    fn rule_name_carries_the_reserved_prefix() {
        assert_eq!(rule_name(7), "run-session:7");
        assert!(rule_name(7).starts_with(hallpass_types::RUN_SESSION_RULE_PREFIX));
    }

    /// Coverage answers for the session's own user only, and asks nothing
    /// of /proc when no session could match.
    #[test]
    fn coverage_needs_a_session_and_a_matching_user() {
        let reg = registry();
        let me = std::process::id();
        let proc_root = Path::new("/proc");

        assert_eq!(covering(&[], proc_root, me, Some(1000)), None);

        let uid = crate::testutil::own_uid();
        let id = reg.register(peer(), uid, "curl".into()).expect("register");
        let live = reg.snapshot();

        assert_eq!(
            covering(&live, proc_root, me, Some(uid)),
            Some(id),
            "the session's own root process is covered"
        );
        assert_eq!(
            covering(&live, proc_root, me, Some(uid.wrapping_add(1))),
            None,
            "another user's connection inside the tree is not covered"
        );
        assert_eq!(
            covering(&live, proc_root, me, None),
            None,
            "an unattributed connection is not covered"
        );
        assert_eq!(
            reg.list()[0].allowed,
            1,
            "only the covered connection is counted against the grant"
        );
    }

    /// One user cannot spend the whole registry.
    #[test]
    fn one_user_cannot_exhaust_the_registry() {
        let reg = registry();
        let uid = crate::testutil::own_uid();
        for _ in 0..MAX_RUN_SESSIONS_PER_UID {
            reg.register(peer(), uid, "curl".into()).expect("register");
        }
        let err = reg
            .register(peer(), uid, "curl".into())
            .expect_err("the per-user limit must be enforced");
        assert!(err.contains("per-user limit"), "{err}");
        // Another user is unaffected, which is the point of the split.
        reg.register(peer(), uid.wrapping_add(1), "curl".into())
            .expect("another user still gets a session");
    }

    /// A pid the connection did not come from cannot be made a session root.
    #[test]
    fn a_root_that_is_not_the_connecting_process_is_refused() {
        let reg = registry();
        let stale = PeerProcess {
            pid: Some(std::process::id()),
            // Whatever this process's start time is, it is not this.
            started: Some(1),
        };
        let err = reg
            .register(stale, 1000, "curl".into())
            .expect_err("a mismatched start time must be refused");
        assert!(
            err.contains("not the process that opened this connection"),
            "{err}"
        );
        assert!(reg.snapshot().is_empty());
    }
}

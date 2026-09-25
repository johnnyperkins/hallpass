//! Pending interactive prompts.
//!
//! The queue thread holds undecided packets and forwards (sequence, conn)
//! pairs here. This table coalesces them per application and destination
//! (see [`Key`]), asks the registered prompt-handler client, and pushes the
//! resulting verdict back to the queue thread over the verdict channel.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hallpass_types::{
    unix_ms_now, Connection, DaemonMsg, PromptContext, PromptScope, Proto, Rule, RuleDuration,
    RuleMatch, Verdict, MAX_HASH_MISMATCH_RULES, MAX_PROMPT_ANCESTORS,
};
use tokio::sync::mpsc::{Sender, UnboundedSender};

use crate::config::RuntimeSettings;
use crate::events::EventBus;
use crate::rules::model::CompiledRule;
use crate::rules::store::{filename_char, RuleStore};
use crate::stats::Counters;

/// Priority given to rules created from prompt replies.
const PROMPT_RULE_PRIORITY: u32 = 50;

/// Coalescing key: (uid, exe, app id, proto, dst ip, dst port). The protocol
/// is part of it because a TCP and a UDP flow to the same ip:port (e.g. HTTPS
/// and QUIC) are different requests; one prompt must not answer both. The
/// application is part of it for the same reason the generated rule pins it
/// ([`rule_from_reply`]): a sandboxed application's executable path is
/// shared by every application of that packaging system, so exe alone would
/// let one dialog answer for two of them. The user is part of it because
/// the dialog shows the first connection's uid and command line: another
/// user's connection from the same binary joined it unseen and was released
/// by an answer given about someone else's, `Once` included.
type Key = (
    Option<u32>,
    Option<PathBuf>,
    Option<String>,
    Proto,
    IpAddr,
    u16,
);

/// The key `conn` coalesces under.
fn coalescing_key(conn: &Connection) -> Key {
    (
        conn.uid,
        conn.exe_path.clone(),
        conn.app_id.clone(),
        conn.tuple.proto,
        conn.tuple.dst.ip(),
        conn.tuple.dst.port(),
    )
}

struct Pending {
    key: Key,
    conn: Connection,
    /// Queue-thread sequence numbers of all packets awaiting this prompt.
    packets: Vec<u64>,
    /// Absolute deadline sent with the request, kept for re-delivery.
    deadline_ms: u64,
    /// What the operator is shown beyond the connection. Kept for
    /// re-delivery, like the connection and the deadline beside it.
    context: PromptContext,
}

impl Pending {
    /// The request for this prompt.
    ///
    /// One constructor for both senders, the creation path and the
    /// re-delivery sweep in [`PromptTable::set_handler`], so the two cannot
    /// describe one prompt differently. It has to hold because both clients
    /// ignore a repeat request for an id they already hold: whichever
    /// request arrives first is the one the operator answers.
    fn request(&self, id: u64) -> DaemonMsg {
        DaemonMsg::PromptRequest {
            id,
            conn: self.conn.clone(),
            deadline_ms: self.deadline_ms,
            context: self.context.clone(),
        }
    }
}

/// Most packets one prompt will hold while it waits for an answer.
///
/// Coalescing is what makes this necessary: every connection attempt with
/// the same [`Key`] joins one prompt, so a process
/// looping connect() adds a held packet per attempt to a single popup the
/// operator sees once. Each of those pins a kernel queue slot until the
/// prompt resolves. The queue thread caps the total
/// ([`crate::nfqueue`]'s `MAX_HELD_PACKETS`); this caps one flow's share of
/// it, so a loud connector cannot starve every other prompt on the host.
///
/// Generous next to a real application's retry behaviour (a TCP SYN is
/// retransmitted about six times), and the failure past it costs the extra
/// packets the default verdict, never the prompt: the operator is still
/// asked, and their answer still governs the flow from then on.
const MAX_PACKETS_PER_PROMPT: usize = 32;

/// Most packets one executable will hold across all of its prompts.
///
/// The per-prompt budget alone is a per-destination budget: eight
/// ip:port pairs at 32 packets each is the queue thread's whole global
/// budget, spent by one process with a couple of hundred connect() calls,
/// and past that no connection on the host gets a prompt at all until they
/// drain. This is a quarter of the global budget, so it takes four
/// misbehaving executables rather than one to reach that state, and a
/// well-behaved application never comes close: it is 64 packets in flight
/// to unanswered prompts at once.
///
/// Computed by walking the pending prompts rather than kept as a running
/// count, deliberately. The table is capped at `max_pending_prompts`, so the
/// walk is short, and a counter maintained across the five paths that add or
/// remove packets is a class of bug this does not need.
const MAX_PACKETS_PER_EXE: usize = 64;

/// Consecutive timed-out prompts before the handler slot is taken back.
///
/// Not one: a prompt can time out with a perfectly healthy handler on the
/// other end, because the operator was not at the keyboard. Three in a row is
/// the point where "nobody is reading this" is the better explanation, and
/// the cost of being wrong about that is one round trip (see
/// [`DaemonMsg::PromptHandlerRevoked`]), not a lost prompt.
const MAX_UNANSWERED_EXPIRIES: u32 = 3;

/// The client holding the prompt-handler slot.
struct Handler {
    /// Outbound channel of the client. Bounded: a stalled client drops
    /// messages instead of growing memory; the prompt timeout then applies
    /// the default verdict.
    tx: Sender<DaemonMsg>,
    /// Prompts that have timed out since this handler last answered one.
    unanswered: u32,
}

#[derive(Default)]
struct Inner {
    by_id: HashMap<u64, Pending>,
    by_key: HashMap<Key, u64>,
    /// The sole prompt-handler client, if one is connected.
    handler: Option<Handler>,
}

impl Inner {
    /// The handler, unless its client has gone away.
    fn live_handler(&self) -> Option<&Handler> {
        self.handler.as_ref().filter(|h| !h.tx.is_closed())
    }

    /// The handler's channel, for telling it about prompts after the lock
    /// is released.
    fn handler_tx(&self) -> Option<Sender<DaemonMsg>> {
        self.handler.as_ref().map(|h| h.tx.clone())
    }

    /// Whether `tx` is the channel holding the handler slot.
    fn is_handler(&self, tx: &Sender<DaemonMsg>) -> bool {
        self.handler.as_ref().is_some_and(|h| h.tx.same_channel(tx))
    }

    /// Take prompt `id` out of both indexes.
    fn remove(&mut self, id: u64) -> Option<Pending> {
        let pending = self.by_id.remove(&id)?;
        self.by_key.remove(&pending.key);
        Some(pending)
    }

    /// Whether one more packet for `conn` (coalescing under `key`) would
    /// exceed either held-packet budget: [`MAX_PACKETS_PER_PROMPT`] for its
    /// prompt, [`MAX_PACKETS_PER_EXE`] for its application.
    ///
    /// The application is the same (exe, app id) pair the coalescing key
    /// carries, not the executable alone. Two packaged applications can run
    /// from one sandbox path, and summing their held packets would let two
    /// of them fill this budget and send the third's first packet down the
    /// over-budget path, which never raises a prompt at all.
    fn over_budget(&self, key: &Key, conn: &Connection) -> bool {
        let app_held: usize = self
            .by_id
            .values()
            .filter(|p| p.conn.exe_path == conn.exe_path && p.conn.app_id == conn.app_id)
            .map(|p| p.packets.len())
            .sum();
        app_held >= MAX_PACKETS_PER_EXE
            || self
                .by_key
                .get(key)
                .and_then(|id| self.by_id.get(id))
                .is_some_and(|p| p.packets.len() >= MAX_PACKETS_PER_PROMPT)
    }
}

/// Table of prompts awaiting a client decision.
pub struct PromptTable {
    inner: Mutex<Inner>,
    /// Monotonic prompt ID. A u64 cannot realistically wrap, so collisions
    /// with a live prompt are ignored by design; do not make it wrapping.
    next_id: AtomicU64,
    verdict_tx: UnboundedSender<(u64, Verdict)>,
    events: Arc<EventBus>,
    stats: Arc<Counters>,
    store: Arc<RuleStore>,
    /// Prompt timeout and default verdict, changeable over IPC. The
    /// timeout is read when a prompt is created (deadline and timer arm
    /// together, so they cannot disagree); the verdict is read when a
    /// decision is actually applied.
    settings: Arc<RuntimeSettings>,
    max_pending: usize,
    /// Mirror of `inner.handler` being occupied, readable without the lock.
    ///
    /// Exists for one caller: the nfqueue verdict thread, which hashes a
    /// binary for every connection on its way to a prompt so the operator can
    /// pin the bytes they were shown. With no handler connected there is no
    /// operator and `handle_new` resolves with the default verdict instead, so
    /// that whole-binary read buys nothing - and a headless host, or a desktop
    /// before login, sits in that state permanently.
    ///
    /// An atomic rather than [`PromptTable::has_handler`] because the caller is
    /// the thread whose stalls are every other connection's stalls, and it
    /// should not queue behind the prompt path's mutex to ask. Kept in step by
    /// hand at the three sites that change the slot, which is a shape that
    /// drifts, so `the_handler_flag_tracks_the_slot` asserts the two agree
    /// across every transition.
    handler_present: Arc<AtomicBool>,
    /// Distinguishes this daemon run in the names of rules generated from
    /// prompt replies. Prompt ids restart at 1 every run while `Forever`
    /// rules persist, so `prompt-<exe>-<id>` alone collided across restarts,
    /// and [`RuleStore::add`] replaces by name: the first curl prompt after
    /// a restart silently overwrote the rule an operator approved for curl
    /// before it, file and all.
    run_tag: String,
}

impl PromptTable {
    pub fn new(
        verdict_tx: UnboundedSender<(u64, Verdict)>,
        events: Arc<EventBus>,
        stats: Arc<Counters>,
        store: Arc<RuleStore>,
        settings: Arc<RuntimeSettings>,
        max_pending: usize,
    ) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            next_id: AtomicU64::new(1),
            verdict_tx,
            events,
            stats,
            store,
            settings,
            max_pending,
            handler_present: Arc::new(AtomicBool::new(false)),
            // Milliseconds and the pid, hex. Seconds alone were not enough:
            // `Restart=on-failure` restarts within the same second by
            // default, and a crash loop is exactly when prompt ids restart
            // at 1 while the old run's rules are still on disk.
            run_tag: format!("{:x}-{:x}", unix_ms_now(), std::process::id()),
        }
    }

    /// Verdict applied to a connection no rule matched and no client
    /// answered in time. Also what an explain request reports for a
    /// connection that would raise a prompt.
    pub fn default_verdict(&self) -> Verdict {
        self.settings.default_verdict()
    }

    /// Whether a client currently holds the prompt-handler slot.
    ///
    /// Reported in the stats snapshot because nothing else says so: with no
    /// handler, every connection no rule matches is resolved with the default
    /// verdict and no operator is ever asked.
    pub fn has_handler(&self) -> bool {
        self.inner.lock().unwrap().live_handler().is_some()
    }

    /// The lock-free view of the handler slot, for the nfqueue verdict
    /// thread. See [`PromptTable::handler_present`].
    pub fn handler_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.handler_present)
    }

    /// Claim the prompt-handler slot. Returns false if already claimed.
    pub fn set_handler(&self, tx: Sender<DaemonMsg>) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if inner.live_handler().is_some() {
            return false;
        }
        // Re-deliver everything still pending: requests are otherwise sent
        // only at creation, so prompts opened before this handler connected
        // (or while the previous one was dying) would sit invisible until
        // their timeout applies the default verdict.
        for (&id, p) in &inner.by_id {
            let _ = tx.try_send(p.request(id));
        }
        inner.handler = Some(Handler { tx, unanswered: 0 });
        self.handler_present.store(true, Ordering::Relaxed);
        true
    }

    /// Release the handler slot if `tx` currently holds it.
    pub fn clear_handler(&self, tx: &Sender<DaemonMsg>) {
        let mut inner = self.inner.lock().unwrap();
        if inner.is_handler(tx) {
            inner.handler = None;
            self.handler_present.store(false, Ordering::Relaxed);
        }
    }

    /// Handle an unmatched connection holding packet `seq` on the queue
    /// thread. Either coalesces into an existing prompt, opens a new one,
    /// or resolves immediately with the default verdict (no handler
    /// connected, or the pending table is full).
    pub fn handle_new(self: &Arc<Self>, conn: Connection, seq: u64, exe_sha256: Option<String>) {
        // The queue thread does not hand over packets while observing, but
        // it reads the mode per packet and this runs on a different task, so
        // a toggle can land between the two: without this check a packet
        // already in flight opens a fresh prompt after
        // `resolve_pending_for_observe` has drained the table, and is then
        // held for the full timeout under a mode that promises to hold
        // nothing.
        if !self.settings.enforcing() {
            self.stats.record_prompt_unanswered();
            self.finish_default(conn, vec![seq]);
            return;
        }
        let key = coalescing_key(&conn);
        // Before the lock, and therefore also for packets that turn out to
        // coalesce into a prompt that already exists. That waste is bounded
        // by MAX_PACKETS_PER_PROMPT and every piece of it is cheap (see
        // `build_context`); holding the table lock across an ancestry walk
        // would instead put a /proc read in front of every prompt reply and
        // every handler reconnect.
        let context = self.build_context(&conn, exe_sha256);
        let mut inner = self.inner.lock().unwrap();

        // Both budgets, before either path below can take a slot.
        if inner.over_budget(&key, &conn) {
            drop(inner);
            // No event: this flow either has a prompt already or is about to
            // be represented by one, and that prompt's decision is what the
            // record should carry. Counted like any other connection
            // resolved without being asked about, and released now so the
            // kernel gets its queue slot back rather than at the deadline.
            self.stats.record_prompt_overflow();
            tracing::debug!("prompt packet budget full, applying default verdict");
            let _ = self.verdict_tx.send((seq, self.settings.default_verdict()));
            return;
        }

        if let Some(&id) = inner.by_key.get(&key) {
            if let Some(pending) = inner.by_id.get_mut(&id) {
                pending.packets.push(seq);
                return;
            }
        }

        let Some(handler) = inner.live_handler().map(|h| h.tx.clone()) else {
            drop(inner);
            tracing::debug!("no prompt handler connected, applying default verdict");
            // Nobody was asked, so this is one more decision made by nobody.
            // The counter is the only trace: with no handler there is no
            // prompt, and an event that records the default verdict looks
            // exactly like a rule having chosen it.
            self.stats.record_prompt_unanswered();
            self.finish_default(conn, vec![seq]);
            return;
        };
        if inner.by_id.len() >= self.max_pending {
            drop(inner);
            tracing::warn!("pending prompt table full, applying default verdict");
            self.stats.record_prompt_overflow();
            self.finish_default(conn, vec![seq]);
            return;
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        // One read serves both the deadline and the timer below, so a
        // concurrent settings change cannot arm a timer that disagrees
        // with the deadline the client was told.
        let timeout = Duration::from_secs(self.settings.prompt_timeout_secs());
        let deadline_ms = unix_ms_now() + timeout.as_millis() as u64;
        inner.by_key.insert(key.clone(), id);
        inner.by_id.insert(
            id,
            Pending {
                key,
                conn: conn.clone(),
                packets: vec![seq],
                deadline_ms,
                context,
            },
        );
        let request = inner.by_id[&id].request(id);
        drop(inner);

        self.stats.record_prompted();
        // try_send: never block the dispatcher on a stalled client. A
        // dropped request is resolved by the timeout below.
        if handler.try_send(request).is_err() {
            tracing::warn!(id, "prompt handler not accepting requests");
        }

        let table = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            table.expire(id);
        });
    }

    /// Everything a prompt shows beyond the connection itself.
    ///
    /// Runs inline on the prompt dispatcher, before the table lock, and does
    /// no disk IO at all: a prompt request must leave with the packet, not
    /// after an unbounded read. Built on a blocking worker and sent
    /// afterwards, a prompt could expire before it was ever sent (and be
    /// charged to a healthy handler by `strike_handler`), `max_pending`
    /// stopped bounding the work in flight, delivery order stopped matching
    /// prompt-id order, and a request could arrive after the `PromptExpired`
    /// for its own id.
    ///
    /// So `exe_sha256` is the value the verdict thread already computed while
    /// deciding this packet, passed in rather than re-read. It is present
    /// exactly when a hash-pinning rule could have applied, which is the case
    /// this feature exists for, and it is the same value the engine compared,
    /// so the mismatch list below cannot disagree with the decision that
    /// raised the prompt.
    ///
    /// What is left reads only procfs and memory: an ancestry walk of at most
    /// [`MAX_PROMPT_ANCESTORS`] hops, one bounded scan of the history ring,
    /// and one rule-set scan. The queue thread already does /proc reads per
    /// packet, so this is well inside the daemon's existing tolerance, and it
    /// is paid once per unmatched connection rather than per packet.
    ///
    /// The rule snapshot is taken here rather than reused from the packet
    /// path, so a rule added between the two shows up. That is the same drift
    /// `resolve_covered_by` exists for and it errs the readable way: what the
    /// prompt says about rules describes the rules as they are while it is on
    /// screen.
    fn build_context(&self, conn: &Connection, exe_sha256: Option<String>) -> PromptContext {
        PromptContext {
            ancestors: conn
                .pid
                .map(|pid| crate::attribution::ancestry(pid, MAX_PROMPT_ANCESTORS))
                .unwrap_or_default(),
            hash_mismatch_rules: self.store.ruleset().hash_mismatch_rules(
                conn,
                exe_sha256.as_deref(),
                MAX_HASH_MISMATCH_RULES,
            ),
            exe_sha256,
            recent_denials: self
                .events
                .denials_for(conn.exe_path.as_deref(), conn.app_id.as_deref()),
        }
    }

    /// Apply a client's decision to a pending prompt.
    ///
    /// `tx` is the replying client's outbound channel, and it must be the one
    /// registered as the prompt handler: prompt ids are a monotonic counter
    /// from 1, so without that check any connected client could guess an id
    /// and answer a prompt never sent to it, including racing the GUI to
    /// allow what the operator was about to deny.
    pub fn reply(
        &self,
        tx: &Sender<DaemonMsg>,
        id: u64,
        verdict: Verdict,
        duration: RuleDuration,
        scope: PromptScope,
        pin_exe: bool,
    ) -> Result<(), String> {
        let pending = self.take_as_handler(tx, id)?;

        // A posture engaged after this prompt was raised. `decide` stops
        // raising new ones, but the ones already on screen outlive it by up
        // to `prompt_timeout_secs`, and answering one Allow would put a
        // connection through the posture from the keyboard - the exact thing
        // suppressing prompts exists to prevent. The rule such an answer
        // would write carries no pinned tag, so it would be suppressed the
        // moment it was created; nothing is written, and the operator is
        // told through the journal why their answer did not take.
        if self.settings.locked_down() && verdict == Verdict::Allow {
            tracing::warn!(
                id,
                "an allow answered while the host is in lockdown; the posture \
                 decides and the connection is denied"
            );
            self.finish(
                pending.conn,
                pending.packets,
                Verdict::Deny,
                Some(hallpass_types::LOCKDOWN_DENIED_RULE.to_string()),
            );
            return Ok(());
        }

        // The hash the operator was shown, and only that one. Pinning is
        // meaningless on a deny (which should keep matching however the binary
        // changes) and the packet path already computes this for every
        // connection that reaches a prompt, so `None` here means the binary
        // could not be read or was past the size cap.
        let wants_pin = pin_exe && verdict == Verdict::Allow;
        let pin = if wants_pin {
            pending.context.exe_sha256.as_deref()
        } else {
            None
        };
        // Not for `Once`: this branch is about a rule that will not be
        // written, and with `Once` there was never going to be one, so the
        // warning would fire when nothing is wrong. Reachable, not a
        // backstop: the GUI hides the pin checkbox for `Once` without
        // clearing it, so ticking Pin under Forever and then switching to
        // Once sends exactly this combination.
        if wants_pin && duration != RuleDuration::Once && pin.is_none() {
            // No rule at all, rather than the unpinned one that would
            // otherwise be written. The operator asked to remember a set of
            // bytes; remembering a path instead is broader than what they
            // answered, and it would look identical in every listing. The
            // verdict below still applies to the held packets, so this costs
            // the memory of the decision and nothing else - the connection is
            // asked about again, which is the visible failure.
            tracing::warn!(
                id,
                "prompt reply asked to pin the executable but this prompt carries \
                 no hash (unreadable or past the size cap); applying the verdict \
                 without creating a rule"
            );
            self.finish(pending.conn, pending.packets, verdict, None);
            return Ok(());
        }

        let added = if duration == RuleDuration::Once {
            None
        } else {
            self.remember(id, &pending.conn, verdict, duration, scope, pin)
        };
        let rule_name = added.as_ref().map(|r| r.name.clone());
        self.finish(pending.conn, pending.packets, verdict, rule_name);
        // The new rule may cover other prompts already on screen: the same
        // app talking to its other endpoints. Resolve those now rather than
        // leaving a stack of popups whose answer is already decided (and
        // whose eventual timeout would apply the default verdict, possibly
        // the opposite one).
        if let Some(rule) = added {
            self.resolve_covered_by(&rule);
        }
        Ok(())
    }

    /// Write the rule a reply asks to be remembered, returning it when it
    /// was added. A refusal is logged and costs only the memory of the
    /// decision; the verdict still applies to the held packets.
    fn remember(
        &self,
        id: u64,
        conn: &Connection,
        verdict: Verdict,
        duration: RuleDuration,
        scope: PromptScope,
        pin: Option<&str>,
    ) -> Option<Rule> {
        let Some(rule) = rule_from_reply(&self.run_tag, id, conn, verdict, duration, scope, pin)
        else {
            tracing::warn!(
                "prompt reply for connection without executable path; \
                 applying verdict without creating a rule"
            );
            return None;
        };
        if let Err(e) = self.store.add(rule.clone()) {
            tracing::warn!("failed to add rule from prompt reply: {e}");
            return None;
        }
        Some(rule)
    }

    /// Resolve every pending prompt whose connection `rule` now matches,
    /// with the rule's own action. The handler is told each prompt is
    /// gone via `PromptExpired`, the same message it already handles for
    /// timeouts, so open popups close without a new message kind. Also
    /// called by the IPC server when a client adds a rule directly, for
    /// the same reason replies sweep: an already-open prompt the new
    /// rule covers must not fall through to the timeout default.
    pub fn resolve_covered_by(&self, rule: &Rule) {
        // The packet path evaluates enabled rules only, so a disabled one
        // must not decide anything here either: a client may add a rule with
        // `enabled = false`, and sweeping with it resolved live prompts with
        // a verdict no packet would ever have been given.
        if !rule.enabled {
            return;
        }
        // Same argument for a rule a lockdown posture suppresses. Rule adds
        // are not refused while a posture is on, so an untagged allow can
        // arrive at any moment; sweeping with it would resolve live prompts
        // with Allow and release their held packets, while the packet path
        // denies the identical connection as `lockdown:denied`.
        if self.store.suppresses(rule) {
            tracing::info!(
                rule = %rule.name,
                "not sweeping prompts with a rule the lockdown posture suppresses"
            );
            return;
        }
        let compiled = match CompiledRule::compile(rule) {
            Ok(c) => c,
            Err(e) => {
                // The store accepted the rule, so this cannot happen; if
                // it somehow does, the uncovered prompts just stay open.
                tracing::warn!("cannot compile prompt rule for sweeping: {e}");
                return;
            }
        };
        let verdict = Verdict::from(rule.action);
        let mut inner = self.inner.lock().unwrap();
        // Each prompt's own hash, not `None`: `first_failing_field` fails a
        // pinned rule whenever no hash is supplied, so sweeping with `None`
        // let a pinned rule cover nothing, and the siblings of a prompt just
        // answered "allow, pinned" sat open until the timeout applied
        // `default_verdict`. The hash was computed on the prompt path and
        // rides in each prompt's `PromptContext`.
        let covered: Vec<u64> = inner
            .by_id
            .iter()
            .filter(|(_, p)| compiled.matches(&p.conn, p.context.exe_sha256.as_deref()))
            .map(|(&id, _)| id)
            .collect();
        let resolved: Vec<(u64, Pending)> = covered
            .into_iter()
            .filter_map(|id| inner.remove(id).map(|p| (id, p)))
            .collect();
        let handler = inner.handler_tx();
        drop(inner);

        for (id, pending) in resolved {
            tracing::info!(id, rule = %rule.name, "prompt covered by new rule");
            self.finish(
                pending.conn,
                pending.packets,
                verdict,
                Some(rule.name.clone()),
            );
            if let Some(h) = &handler {
                let _ = h.try_send(DaemonMsg::PromptExpired { id });
            }
        }
    }

    /// Resolve every pending prompt because the daemon has stopped
    /// enforcing.
    ///
    /// Observe mode never holds a packet for a prompt, but prompts opened
    /// while enforcing outlive the toggle, and their packets stay held until
    /// somebody answers or the deadline passes - up to an hour at the
    /// maximum timeout. That contradicts what the toggle promises: observe
    /// mode is supposed to stop changing what reaches the wire from the
    /// moment it is turned on, and a held packet is delayed even though it
    /// will eventually be accepted. The verdict recorded is the configured
    /// default, which is what an observe-mode unmatched connection records
    /// anyway; the packets themselves are accepted, since the queue thread
    /// reads the mode when it hands them back.
    pub fn resolve_pending_for_observe(&self) {
        let mut inner = self.inner.lock().unwrap();
        let pending: Vec<(u64, Pending)> = inner.by_id.drain().collect();
        inner.by_key.clear();
        let handler = inner.handler_tx();
        drop(inner);

        if pending.is_empty() {
            return;
        }
        tracing::info!(
            count = pending.len(),
            "observe mode: releasing prompts opened while enforcing"
        );
        for (id, p) in pending {
            self.stats.record_prompt_unanswered();
            self.finish_default(p.conn, p.packets);
            if let Some(h) = &handler {
                let _ = h.try_send(DaemonMsg::PromptExpired { id });
            }
        }
    }

    /// Timeout path: apply the default verdict and notify the handler.
    fn expire(&self, id: u64) {
        let Some(pending) = self.take(id) else {
            return; // already answered
        };
        tracing::info!(id, "prompt timed out, applying default verdict");
        self.stats.record_prompt_unanswered();
        self.finish_default(pending.conn, pending.packets);
        self.strike_handler(id);
    }

    /// Tell the handler the prompt is gone, and count it against the
    /// handler's liveness.
    ///
    /// A client holding the slot and never answering is not a hypothetical:
    /// the slot goes to whoever asks first, so any process that may talk to
    /// the daemon can take it and stay silent, and then every unmatched
    /// connection is decided by the timeout default while the real interface
    /// is told the slot is occupied. Enough consecutive timeouts and the slot
    /// is released, so a client that is actually there can have it.
    ///
    /// Which way it fails: towards releasing a slot that was fine. The daemon
    /// cannot tell a client that is ignoring prompts from one whose operator
    /// walked away, so this deliberately punishes neither. A live client is
    /// told it lost the slot and claims it again on the next round trip; a
    /// client that is not reading its socket never sees the message and stays
    /// out. The one thing this is not is a boundary against a hostile client,
    /// which can hold the slot by re-claiming it, or simply write an allow
    /// rule instead: anything permitted to speak to this socket is already
    /// trusted with policy. What it does buy is that the state is now visible
    /// (`prompt_handlers_evicted`, `prompts_unanswered`) rather than silent.
    fn strike_handler(&self, expired_id: u64) {
        let mut inner = self.inner.lock().unwrap();
        // Taken out to be looked at and put back unless it is out of
        // strikes, so "still the handler" and "evicted" stay one decision
        // made under one lock.
        let Some(mut handler) = inner.handler.take() else {
            return;
        };
        let _ = handler
            .tx
            .try_send(DaemonMsg::PromptExpired { id: expired_id });
        handler.unanswered += 1;
        if handler.unanswered < MAX_UNANSWERED_EXPIRIES {
            inner.handler = Some(handler);
            return;
        }
        // Out of strikes: the slot stays empty, so the flag has to follow it
        // before the lock goes. Set under the lock for the same reason the
        // take-and-put-back above is one decision: a reader must never see
        // the slot empty and the flag still claiming an operator.
        self.handler_present.store(false, Ordering::Relaxed);
        drop(inner);

        self.stats.record_prompt_handler_evicted();
        tracing::warn!(
            unanswered = handler.unanswered,
            "prompt handler let every prompt time out, releasing the slot; \
             unmatched connections take the default verdict until a client claims it"
        );
        // Best effort by nature: the client this exists to remove is the one
        // not draining its channel, and it will not receive this either.
        let _ = handler.tx.try_send(DaemonMsg::PromptHandlerRevoked);
    }

    fn take(&self, id: u64) -> Option<Pending> {
        self.inner.lock().unwrap().remove(id)
    }

    /// Take a prompt only for the client currently holding the handler slot.
    ///
    /// The handler check and the removal share one lock acquisition, so a
    /// client cannot pass the check and then have the slot change under it.
    fn take_as_handler(&self, tx: &Sender<DaemonMsg>, id: u64) -> Result<Pending, String> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.is_handler(tx) {
            return Err("not the registered prompt handler".to_string());
        }
        let pending = inner
            .remove(id)
            .ok_or_else(|| format!("unknown or expired prompt id {id}"))?;
        // Deciding one prompt clears the liveness strikes: they count
        // consecutive timeouts, so a handler that is answering is never
        // evicted for prompts its operator missed earlier in the day.
        if let Some(h) = inner.handler.as_mut() {
            h.unanswered = 0;
        }
        Ok(pending)
    }

    /// Release all held packets with `verdict` and emit one event for the
    /// decision. Stats count the decision once, not per coalesced packet,
    /// matching the single `record_prompted` for the prompt.
    fn finish(&self, conn: Connection, packets: Vec<u64>, verdict: Verdict, rule: Option<String>) {
        for seq in packets {
            let _ = self.verdict_tx.send((seq, verdict));
        }
        self.stats.record_verdict(verdict);
        // Count the hit here too, not only on the packet path. A rule that
        // mostly resolves prompts already on screen (the sweep in
        // `resolve_covered_by`) would otherwise read as dead policy in
        // `rules --stats`, which is the exact question those counts answer.
        if let Some(name) = &rule {
            self.store.record_hit(name);
        }
        // The mode is read here, when the decision is committed, like the
        // packet path does: the stamp then matches the mode the released
        // packets are handed back under (the queue thread re-reads at
        // hand-back, so a toggle in between can still straddle, but never
        // by more than the one packet already in flight).
        self.events
            .emit(conn, verdict, rule, self.settings.enforcing());
    }

    /// Resolve packets with the configured default verdict (no handler,
    /// table overflow, or prompt timeout). Read here, at decision time,
    /// so a prompt outliving a settings change resolves with the
    /// operator's latest choice rather than the one it was created under.
    fn finish_default(&self, conn: Connection, packets: Vec<u64>) {
        self.finish(conn, packets, self.settings.default_verdict(), None);
    }
}

/// Longest executable stem carried into a generated rule name.
const MAX_RULE_STEM_CHARS: usize = 40;

/// Reduce an executable stem to characters that are safe in a rule name.
///
/// Conservative on purpose: alphanumerics plus `.`, `_` and `-`, which is the
/// same set [`crate::rules::store`] already accepts in a rule filename, so a
/// generated name never needs rewriting to become one. Everything else becomes
/// `_` rather than being dropped, so two different executables cannot collapse
/// to the same rule name.
fn sanitize_rule_stem(raw: &str) -> String {
    raw.chars()
        .take(MAX_RULE_STEM_CHARS)
        .map(filename_char)
        .collect()
}

/// Build the rule a prompt reply asks for. `None` when the connection has
/// no attributed executable (a rule would then match far too broadly).
///
/// `run_tag` makes the generated name unique across daemon restarts; see
/// [`PromptTable::run_tag`].
fn rule_from_reply(
    run_tag: &str,
    id: u64,
    conn: &Connection,
    verdict: Verdict,
    duration: RuleDuration,
    scope: PromptScope,
    pin_sha256: Option<&str>,
) -> Option<Rule> {
    let exe = conn.exe_path.clone()?;
    // The stem becomes part of the rule's persisted name, which the CLI and
    // GUI both list back to the operator when auditing policy. A filename may
    // contain any byte but '/' and NUL, so a process can pick one carrying an
    // escape sequence and have it replayed into that listing. Keep the name to
    // characters that cannot reshape output, and cap it so one rule cannot
    // dominate the display.
    let stem = exe
        .file_stem()
        .map(|s| sanitize_rule_stem(&s.to_string_lossy()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "app".to_string());
    let dst = conn.tuple.dst;
    let mut matcher = RuleMatch {
        exe: Some(exe),
        ..Default::default()
    };
    // Pinned on an allow, never on a deny, because the operand only ever
    // narrows and narrowing runs opposite ways for the two.
    //
    // On an allow it has to be pinned. A sandboxed application's executable
    // path resolves inside its sandbox, so `/app/bin/firefox` is a path
    // every application of that packaging system could present, and an
    // exe-only allow generated from one of their prompts would answer for
    // all of them. If that application is later launched somewhere no
    // recognized scope is created, the allow stops matching and prompts
    // again: the safe direction for a rule the operator has not seen since.
    //
    // On a deny that same silence is the wrong direction. The identity is
    // absent for reasons that have nothing to do with the operator - a
    // launcher that makes no per-app scope, a session with no user manager,
    // a unit name this daemon does not parse - and a deny that quietly stops
    // matching resolves the connection with `default_verdict` instead, which
    // an operator is free to set to allow and which says nothing about this
    // application either way. A deny stays exe-only and therefore covers
    // every application sharing that sandbox path, which is the direction a
    // block should err in.
    //
    // The user follows the same rule for the same reasons. The operator
    // answered about one user's process; an allow that also covered every
    // other account running that binary is a grant nobody was shown, and a
    // deny that stopped at one account would leave the rest to the default.
    //
    // And the hash: the operator approved these bytes rather than this name.
    // An exe path is not an identity: an allow granted to something under a
    // home directory or a build tree keeps matching after anything else is
    // written there. A pinned deny, like an app-scoped one, would stop
    // matching when the binary was updated - a block with an expiry date the
    // operator did not ask for. `reply` already drops the flag on a deny;
    // this is the layer that keeps a future caller from reintroducing it.
    if verdict == Verdict::Allow {
        matcher.app_id = conn.app_id.clone();
        matcher.user = conn.uid;
        matcher.exe_sha256 = pin_sha256.map(str::to_string);
    }
    match scope {
        // With the protocol: a port number means nothing without one, and the
        // prompt was about one (the coalescing key already keeps TCP and UDP
        // apart). Without it an answer about HTTPS on 443 also allowed QUIC
        // on 443, for good, and resolved a pending UDP prompt with it.
        PromptScope::ThisPort => {
            matcher.dest = Some(dst.ip().to_string());
            matcher.port = Some(dst.port());
            matcher.proto = Some(conn.tuple.proto);
        }
        PromptScope::ThisHost => {
            matcher.dest = Some(dst.ip().to_string());
        }
        PromptScope::AppAnywhere => {}
    }
    Some(Rule {
        name: format!("prompt-{stem}-{run_tag}-{id}"),
        action: verdict.into(),
        duration,
        priority: PROMPT_RULE_PRIORITY,
        enabled: true,
        // Untagged, and not a default worth inventing: a tag is a set an
        // operator chose to put a rule in, and answering one dialog is not
        // choosing. A rule that arrived here can be tagged afterwards by
        // saving it again under the same name.
        tags: Vec::new(),
        matcher,
    })
}

#[cfg(test)]
mod tests;

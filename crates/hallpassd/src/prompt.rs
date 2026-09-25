//! Pending interactive prompts.
//!
//! The queue thread holds undecided packets and forwards (sequence, conn)
//! pairs here. This table coalesces them per (exe, dst ip, dst port) key,
//! asks the registered prompt-handler client, and pushes the resulting
//! verdict back to the queue thread over the verdict channel.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hallpass_types::{
    Connection, DaemonMsg, PromptContext, PromptScope, Proto, Rule, RuleDuration, RuleMatch,
    Verdict, MAX_HASH_MISMATCH_RULES, MAX_PROMPT_ANCESTORS,
};
use tokio::sync::mpsc::{Sender, UnboundedSender};

use hallpass_types::unix_ms_now;

use crate::events::EventBus;
use crate::rules::store::RuleStore;
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
/// the same (exe, proto, dst ip, dst port) joins one prompt, so a process
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
/// count, deliberately. The table is capped at `max_pending_prompts` (64 by
/// default) so the walk is short, and a counter maintained across the five
/// paths that add or remove packets is a class of bug this does not need.
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
    settings: Arc<crate::config::RuntimeSettings>,
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
        settings: Arc<crate::config::RuntimeSettings>,
        max_pending: usize,
    ) -> PromptTable {
        PromptTable {
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
        let inner = self.inner.lock().unwrap();
        inner.handler.as_ref().is_some_and(|h| !h.tx.is_closed())
    }

    /// The lock-free view of the handler slot, for the nfqueue verdict
    /// thread. See [`PromptTable::handler_present`].
    pub fn handler_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.handler_present)
    }

    /// Claim the prompt-handler slot. Returns false if already claimed.
    pub fn set_handler(&self, tx: Sender<DaemonMsg>) -> bool {
        let mut inner = self.inner.lock().unwrap();
        match &inner.handler {
            Some(h) if !h.tx.is_closed() => false,
            _ => {
                // Re-deliver everything still pending: requests are
                // otherwise sent only at creation, so prompts opened
                // before this handler connected (or while the previous
                // one was dying) would sit invisible until their
                // timeout applies the default verdict.
                //
                for (&id, p) in inner.by_id.iter() {
                    let _ = tx.try_send(p.request(id));
                }
                inner.handler = Some(Handler { tx, unanswered: 0 });
                self.handler_present.store(true, Ordering::Relaxed);
                true
            }
        }
    }

    /// Release the handler slot if `tx` currently holds it.
    pub fn clear_handler(&self, tx: &Sender<DaemonMsg>) {
        let mut inner = self.inner.lock().unwrap();
        if inner
            .handler
            .as_ref()
            .is_some_and(|h| h.tx.same_channel(tx))
        {
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
        let key: Key = (
            conn.uid,
            conn.exe_path.clone(),
            conn.app_id.clone(),
            conn.tuple.proto,
            conn.tuple.dst.ip(),
            conn.tuple.dst.port(),
        );
        // Before the lock, and therefore also for packets that turn out to
        // coalesce into a prompt that already exists. That waste is bounded
        // by MAX_PACKETS_PER_PROMPT and every piece of it is cheap (see
        // `build_context`); holding the table lock across an ancestry walk
        // would instead put a /proc read in front of every prompt reply and
        // every handler reconnect.
        let context = self.build_context(&conn, exe_sha256);
        let mut inner = self.inner.lock().unwrap();

        // Both budgets, before either path can take a slot: one caps what a
        // single destination holds, the other what one application holds
        // across all of its destinations.
        //
        // Keyed on the same (exe, app id) pair the coalescing key carries,
        // not on the executable alone. Two packaged applications can run
        // from one sandbox path, and the coalescing key already tells them
        // apart; summing their held packets together would let two of them
        // fill this budget and send the third's first packet down the
        // over-budget path, which resolves with the default verdict and
        // never raises a prompt at all - the one thing the per-prompt cap
        // above promises it will not do.
        let exe_held: usize = inner
            .by_id
            .values()
            .filter(|p| p.conn.exe_path == conn.exe_path && p.conn.app_id == conn.app_id)
            .map(|p| p.packets.len())
            .sum();
        let over_budget = exe_held >= MAX_PACKETS_PER_EXE
            || inner
                .by_key
                .get(&key)
                .and_then(|id| inner.by_id.get(id))
                .is_some_and(|p| p.packets.len() >= MAX_PACKETS_PER_PROMPT);
        if over_budget {
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

        let handler = match &inner.handler {
            Some(h) if !h.tx.is_closed() => h.tx.clone(),
            _ => {
                drop(inner);
                tracing::debug!("no prompt handler connected, applying default verdict");
                // Nobody was asked, so this is one more decision made by
                // nobody. The counter is the only trace: with no handler
                // there is no prompt, and an event that records the default
                // verdict looks exactly like a rule having chosen it.
                self.stats.record_prompt_unanswered();
                self.finish_default(conn, vec![seq]);
                return;
            }
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
    /// no disk IO at all. That is the whole design constraint. An earlier cut
    /// built this on a blocking worker and sent the request afterwards, which
    /// bought a freshly read executable hash and cost four defects: a prompt
    /// whose build outran its deadline expired without ever being sent (and
    /// `strike_handler` charged that to the handler, evicting a healthy GUI
    /// after three), `expire` freed the table slot while the build ran on so
    /// `max_pending` stopped bounding the work in flight, delivery order
    /// stopped matching prompt-id order, and a request could arrive after the
    /// `PromptExpired` for its own id. A prompt request must leave with the
    /// packet, not after an unbounded read.
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
    /// registered as the prompt handler. Only one client holds that slot, and
    /// `set_handler` refuses to hand it over while the current holder is live,
    /// but nothing checked it here: prompt ids are a monotonic counter from 1,
    /// so any connected client could guess an id and answer a prompt that was
    /// never sent to it, including racing the GUI to allow what the operator
    /// was about to deny.
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
        let pin = match pin_exe && verdict == Verdict::Allow {
            true => pending.context.exe_sha256.as_deref(),
            false => None,
        };
        // `duration` is part of the condition because this branch is about a
        // rule that will not be written: with `Once` there was never going to
        // be one, so the warning would tell an operator their answer was not
        // remembered when nothing about it asked to be, and a security line
        // that fires when nothing is wrong is the one people learn to skip.
        //
        // Live code, not a backstop. The GUI's `PromptState::pin_exe` is
        // sticky and its `reply` gates only on the verdict, while the duration
        // check lives in the render path - which *hides* the checkbox without
        // clearing the field. So ticking Pin under Forever and then switching
        // the combo to Once sends exactly this combination.
        if pin_exe && verdict == Verdict::Allow && duration != RuleDuration::Once && pin.is_none() {
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

        let mut rule_name = None;
        let mut added_rule = None;
        if duration != RuleDuration::Once {
            match rule_from_reply(
                &self.run_tag,
                id,
                &pending.conn,
                verdict,
                duration,
                scope,
                pin,
            ) {
                Some(rule) => {
                    rule_name = Some(rule.name.clone());
                    if let Err(e) = self.store.add(rule.clone()) {
                        tracing::warn!("failed to add rule from prompt reply: {e}");
                        rule_name = None;
                    } else {
                        added_rule = Some(rule);
                    }
                }
                None => {
                    tracing::warn!(
                        "prompt reply for connection without executable path; \
                         applying verdict without creating a rule"
                    );
                }
            }
        }
        self.finish(pending.conn, pending.packets, verdict, rule_name);
        // The new rule may cover other prompts already on screen: the
        // same app talking to its other endpoints. Resolve those now
        // rather than leaving a stack of popups whose answer is already
        // decided (and whose eventual timeout would apply the default
        // verdict, possibly the opposite one).
        if let Some(rule) = added_rule {
            self.resolve_covered_by(&rule);
        }
        Ok(())
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
        let compiled = match crate::rules::model::CompiledRule::compile(rule) {
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
        // Each prompt's own hash, not `None`. A pinned rule carries
        // `exe_sha256`, and `first_failing_field` reports that criterion as
        // failing whenever the caller supplies no hash - so passing `None`
        // here meant a pinned rule swept nothing at all, and the sibling
        // prompts an operator had just answered "allow, forever, this app
        // anywhere, pinned" sat open until the timeout resolved them with
        // `default_verdict`, possibly the opposite one. Nothing is computed
        // for this: the value was hashed on the prompt path and `Pending`
        // has carried it in its `PromptContext` ever since.
        let covered: Vec<u64> = inner
            .by_id
            .iter()
            .filter(|(_, p)| compiled.matches(&p.conn, p.context.exe_sha256.as_deref()))
            .map(|(&id, _)| id)
            .collect();
        let mut resolved = Vec::new();
        for id in covered {
            if let Some(pending) = inner.by_id.remove(&id) {
                inner.by_key.remove(&pending.key);
                resolved.push((id, pending));
            }
        }
        let handler = inner.handler.as_ref().map(|h| h.tx.clone());
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
        let handler = inner.handler.as_ref().map(|h| h.tx.clone());
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
        let mut inner = self.inner.lock().unwrap();
        let pending = inner.by_id.remove(&id)?;
        inner.by_key.remove(&pending.key);
        Some(pending)
    }

    /// Take a prompt only for the client currently holding the handler slot.
    ///
    /// The handler check and the removal share one lock acquisition, so a
    /// client cannot pass the check and then have the slot change under it.
    fn take_as_handler(&self, tx: &Sender<DaemonMsg>, id: u64) -> Result<Pending, String> {
        let mut inner = self.inner.lock().unwrap();
        if !inner
            .handler
            .as_ref()
            .is_some_and(|h| h.tx.same_channel(tx))
        {
            return Err("not the registered prompt handler".to_string());
        }
        let pending = inner
            .by_id
            .remove(&id)
            .ok_or_else(|| format!("unknown or expired prompt id {id}"))?;
        inner.by_key.remove(&pending.key);
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
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
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
    if verdict == Verdict::Allow {
        matcher.app_id = conn.app_id.clone();
        matcher.user = conn.uid;
    }
    // The operator approved these bytes rather than this name. An exe path is
    // not an identity: an allow granted to something under a home directory or
    // a build tree keeps matching after anything else is written there, and a
    // remembered allow must not widen on its own.
    //
    // Guarded on the verdict for the same reason `app_id` is, one layer up.
    // Pinning narrows, and a deny that stops matching because the binary was
    // updated falls through to `default_verdict`, which an operator is free to
    // set to allow and which was never a judgement about this binary - so a
    // pinned deny is a block with an expiry date the operator did not ask for.
    // `reply` already drops the flag on a deny; this is the layer that makes a
    // future caller unable to reintroduce it.
    if verdict == Verdict::Allow {
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
mod tests {
    use super::*;
    use hallpass_types::{FlowTuple, Proto};
    use tokio::sync::mpsc;

    struct Harness {
        table: Arc<PromptTable>,
        verdict_rx: mpsc::UnboundedReceiver<(u64, Verdict)>,
        store: Arc<RuleStore>,
        stats: Arc<Counters>,
        settings: Arc<crate::config::RuntimeSettings>,
        events: Arc<EventBus>,
        _dir: crate::testutil::TestDir,
    }

    impl Harness {
        /// The stats snapshot a client would read, with the table's own
        /// handler state in it.
        fn snapshot(&self) -> hallpass_types::Stats {
            self.stats.snapshot(
                0,
                0,
                self.table.has_handler(),
                true,
                None,
                Default::default(),
            )
        }
    }

    fn harness(tag: &str, max_pending: usize, default: Verdict) -> Harness {
        let dir = crate::testutil::TestDir::new(&format!("prompt-{tag}"));
        let store = Arc::new(RuleStore::new(dir.path().to_path_buf()));
        let (verdict_tx, verdict_rx) = mpsc::unbounded_channel();
        let stats = Arc::new(Counters::default());
        let settings = Arc::new(crate::config::RuntimeSettings::new(
            crate::testutil::runtime_config(5, default),
        ));
        let events = Arc::new(EventBus::default());
        let table = Arc::new(PromptTable::new(
            verdict_tx,
            Arc::clone(&events),
            Arc::clone(&stats),
            Arc::clone(&store),
            Arc::clone(&settings),
            max_pending,
        ));
        Harness {
            table,
            verdict_rx,
            store,
            stats,
            settings,
            events,
            _dir: dir,
        }
    }

    fn conn(exe: &str, dst: &str) -> Connection {
        Connection {
            tuple: FlowTuple {
                proto: Proto::Tcp,
                src: "10.0.0.1:40000".parse().unwrap(),
                dst: dst.parse().unwrap(),
            },
            uid: Some(1000),
            pid: Some(1),
            exe_path: Some(PathBuf::from(exe)),
            cmdline: None,
            parent_exe: None,
            domain: None,
            iface: None,
            app_id: None,
            first_seen: None,
        }
    }

    #[tokio::test]
    async fn no_handler_applies_default_immediately() {
        let mut h = harness("nohandler", 4, Verdict::Deny);
        h.table.handle_new(conn("/bin/a", "1.1.1.1:443"), 7, None);
        assert_eq!(h.verdict_rx.recv().await, Some((7, Verdict::Deny)));
        // Nobody was asked, and the event this emits is indistinguishable
        // from a rule having chosen the same verdict. The counters are the
        // only place that difference exists.
        let s = h.snapshot();
        assert!(!s.prompt_handler_connected);
        assert_eq!(s.prompts_unanswered, 1);
    }

    /// A client can claim the prompt slot and never answer, which sends every
    /// unmatched connection to the timeout default while the real interface
    /// is told the slot is taken. Enough consecutive timeouts and the slot is
    /// released for somebody who will use it.
    #[tokio::test(start_paused = true)]
    async fn a_handler_that_never_answers_loses_the_slot() {
        let mut h = harness("evict", 8, Verdict::Allow);
        let (tx, mut prompt_rx) = mpsc::channel(64);
        assert!(h.table.set_handler(tx.clone()));

        for seq in 1..=u64::from(MAX_UNANSWERED_EXPIRIES) {
            h.table
                .handle_new(conn("/bin/a", &format!("1.1.1.{seq}:443")), seq, None);
            tokio::time::advance(Duration::from_secs(6)).await;
            assert_eq!(h.verdict_rx.recv().await, Some((seq, Verdict::Allow)));
        }

        let s = h.snapshot();
        assert!(!s.prompt_handler_connected, "slot released");
        assert_eq!(s.prompt_handlers_evicted, 1);
        assert_eq!(s.prompts_unanswered, u64::from(MAX_UNANSWERED_EXPIRIES));

        // The evicted client is told, so one that is merely idle reclaims
        // the slot instead of going quiet for the rest of the session.
        let mut revoked = 0;
        while let Ok(msg) = prompt_rx.try_recv() {
            if matches!(msg, DaemonMsg::PromptHandlerRevoked) {
                revoked += 1;
            }
        }
        assert_eq!(revoked, 1, "told exactly once");

        // And the slot is really free, for the evicted client or any other.
        let (other, _other_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(other));
    }

    /// **A prompt already on screen cannot be answered through a posture.**
    /// `decide` stops raising new ones the moment a lockdown engages, but
    /// the ones already open outlive it by up to the prompt timeout, and an
    /// Allow answered on one of those would put a connection through the
    /// posture from the keyboard.
    #[tokio::test]
    async fn an_allow_answered_under_lockdown_is_denied() {
        let mut h = harness("lockdown-reply", 8, Verdict::Allow);
        let (tx, mut prompt_rx) = mpsc::channel(64);
        assert!(h.table.set_handler(tx.clone()));
        h.table
            .handle_new(conn("/bin/curl", "1.1.1.1:443"), 1, None);
        let DaemonMsg::PromptRequest { id, .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };

        h.settings.set_locked_down(true);
        h.table
            .reply(
                &tx,
                id,
                Verdict::Allow,
                RuleDuration::Forever,
                PromptScope::ThisPort,
                false,
            )
            .expect("the reply is accepted, the answer is not");
        assert_eq!(h.verdict_rx.recv().await, Some((1, Verdict::Deny)));
        // And no rule is written: it would carry no pinned tag, so it would
        // be suppressed the instant it existed, leaving an allow rule in the
        // listing that permits nothing.
        assert!(
            h.store.list().is_empty(),
            "an answer wrote policy through the posture"
        );
    }

    /// A rule the posture suppresses must not sweep live prompts either.
    /// Rule adds are not refused under a posture, so an untagged allow can
    /// arrive at any moment; sweeping with it would resolve prompts with
    /// Allow and release their held packets while the packet path denies the
    /// identical connection.
    #[tokio::test]
    async fn a_suppressed_rule_does_not_sweep_prompts() {
        let mut h = harness("lockdown-sweep", 8, Verdict::Deny);
        let (tx, mut prompt_rx) = mpsc::channel(64);
        assert!(h.table.set_handler(tx.clone()));
        h.table
            .handle_new(conn("/bin/curl", "1.1.1.1:443"), 1, None);
        let DaemonMsg::PromptRequest { .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };

        h.settings.set_locked_down(true);
        h.store.rebuild_for_posture(Some(&["core".to_string()]));
        let untagged = Rule {
            name: "allow-curl".into(),
            action: hallpass_types::Action::Allow,
            duration: RuleDuration::Session,
            priority: 1,
            enabled: true,
            tags: Vec::new(),
            matcher: hallpass_types::RuleMatch {
                port: Some(443),
                ..Default::default()
            },
        };
        h.store
            .add(untagged.clone())
            .expect("adds are not refused under a posture");
        h.table.resolve_covered_by(&untagged);
        assert!(
            h.verdict_rx.try_recv().is_err(),
            "a suppressed rule resolved a live prompt with its own verdict"
        );

        // And once the posture lifts, the same rule sweeps as it always has.
        h.settings.set_locked_down(false);
        h.store.rebuild_for_posture(None);
        h.table.resolve_covered_by(&untagged);
        assert_eq!(h.verdict_rx.recv().await, Some((1, Verdict::Allow)));
    }

    /// The lock-free flag and the slot it mirrors are two representations of
    /// one fact, kept in step by hand at three sites, so this walks every
    /// transition and asserts they never disagree.
    ///
    /// A drifted-true flag costs the verdict thread a whole-binary hash on a
    /// host where nobody will ever see it, which is the waste the flag exists
    /// to remove. A drifted-false flag is worse: the prompt carries no hash,
    /// so both clients hide the pin control and the operator silently loses
    /// the feature on a host that has a handler.
    #[tokio::test(start_paused = true)]
    async fn the_handler_flag_tracks_the_slot() {
        let h = harness("handler-flag", 8, Verdict::Allow);
        let flag = h.table.handler_flag();
        let check = |what: &str| {
            assert_eq!(
                flag.load(Ordering::Relaxed),
                h.table.has_handler(),
                "the flag and the slot disagreed {what}"
            );
        };
        check("before any handler");

        let (tx, _rx) = mpsc::channel(64);
        assert!(h.table.set_handler(tx.clone()));
        check("after a handler claimed the slot");

        // A second claim is refused, so nothing moves.
        let (other, _other_rx) = mpsc::channel(64);
        assert!(!h.table.set_handler(other));
        check("after a refused second claim");

        h.table.clear_handler(&tx);
        check("after the handler released the slot");

        // Releasing a channel that does not hold the slot must not clear it.
        let (tx2, _rx2) = mpsc::channel(64);
        assert!(h.table.set_handler(tx2.clone()));
        h.table.clear_handler(&tx);
        check("after a stranger tried to release the slot");
        h.table.clear_handler(&tx2);
        check("after the real holder released it");
    }

    /// The eviction path is the third site, and the one that empties the slot
    /// without anybody asking it to.
    #[tokio::test(start_paused = true)]
    async fn eviction_clears_the_handler_flag() {
        let mut h = harness("handler-flag-evict", 8, Verdict::Allow);
        let flag = h.table.handler_flag();
        let (tx, _rx) = mpsc::channel(64);
        assert!(h.table.set_handler(tx));
        assert!(flag.load(Ordering::Relaxed));

        // Let every prompt time out until the handler is struck out.
        for seq in 1..=MAX_UNANSWERED_EXPIRIES as u64 {
            h.table
                .handle_new(conn("/bin/a", &format!("1.1.1.{seq}:443")), seq, None);
            tokio::time::advance(Duration::from_secs(6)).await;
            assert_eq!(h.verdict_rx.recv().await, Some((seq, Verdict::Allow)));
        }

        assert!(!h.table.has_handler(), "the handler should be evicted");
        assert!(
            !flag.load(Ordering::Relaxed),
            "eviction emptied the slot but left the flag claiming an operator"
        );
    }

    /// The strikes count consecutive timeouts, so a handler that is deciding
    /// prompts is never evicted for the ones its operator was away for.
    #[tokio::test(start_paused = true)]
    async fn answering_one_prompt_clears_the_strikes() {
        let mut h = harness("evict-reset", 8, Verdict::Allow);
        let (tx, mut prompt_rx) = mpsc::channel(64);
        assert!(h.table.set_handler(tx.clone()));

        let mut seq = 0;
        // One short of eviction, twice over, with an answer in between.
        for _ in 0..2 {
            for _ in 0..MAX_UNANSWERED_EXPIRIES - 1 {
                seq += 1;
                h.table
                    .handle_new(conn("/bin/a", &format!("1.1.1.{seq}:443")), seq, None);
                tokio::time::advance(Duration::from_secs(6)).await;
                assert_eq!(h.verdict_rx.recv().await, Some((seq, Verdict::Allow)));
            }
            // Drain the requests and expiries of the timed-out prompts, so
            // the next message is the one for the prompt answered below.
            while prompt_rx.try_recv().is_ok() {}
            seq += 1;
            h.table
                .handle_new(conn("/bin/a", &format!("1.1.1.{seq}:443")), seq, None);
            let DaemonMsg::PromptRequest { id, .. } = prompt_rx.recv().await.unwrap() else {
                panic!("expected PromptRequest");
            };
            h.table
                .reply(
                    &tx,
                    id,
                    Verdict::Deny,
                    RuleDuration::Once,
                    PromptScope::ThisPort,
                    false,
                )
                .expect("the handler answers");
            assert_eq!(h.verdict_rx.recv().await, Some((seq, Verdict::Deny)));
        }

        let s = h.snapshot();
        assert!(s.prompt_handler_connected, "still the handler");
        assert_eq!(s.prompt_handlers_evicted, 0);
    }

    /// A filename may hold any byte but '/' and NUL, and the stem lands in a
    /// persisted rule name that both clients list back when auditing policy.
    /// An escape sequence there would rewrite that listing.
    #[test]
    fn rule_names_from_hostile_exe_stems_are_inert() {
        let hostile = "/tmp/x\x1b[2K\rprompt-firefox-1";
        let mut c = conn(hostile, "1.1.1.1:443");
        c.exe_path = Some(PathBuf::from(hostile));
        let rule = rule_from_reply(
            "abc",
            7,
            &c,
            Verdict::Deny,
            RuleDuration::Forever,
            PromptScope::ThisPort,
            None,
        )
        .expect("a rule is generated");
        assert!(!rule.name.contains('\x1b'), "{:?}", rule.name);
        assert!(!rule.name.contains('\r'), "{:?}", rule.name);
        assert!(
            rule.name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-')),
            "{:?}",
            rule.name
        );
        // The exe criterion keeps the real path: only the name is reduced.
        assert_eq!(rule.matcher.exe, Some(PathBuf::from(hostile)));
    }

    /// A port answer names its protocol, and an allow names the user it was
    /// given for; a deny keeps covering every account.
    #[test]
    fn answered_rules_carry_the_protocol_and_an_allow_the_user() {
        let c = conn("/usr/bin/curl", "1.1.1.1:443");
        let rule = |verdict, scope| {
            rule_from_reply("abc", 1, &c, verdict, RuleDuration::Forever, scope, None).unwrap()
        };
        let allow = rule(Verdict::Allow, PromptScope::ThisPort);
        assert_eq!(allow.matcher.proto, Some(Proto::Tcp));
        assert_eq!(allow.matcher.user, Some(1000));
        let deny = rule(Verdict::Deny, PromptScope::ThisPort);
        assert_eq!(deny.matcher.proto, Some(Proto::Tcp));
        assert_eq!(deny.matcher.user, None);
        // No port, no protocol: the host answer covers both.
        assert_eq!(
            rule(Verdict::Allow, PromptScope::ThisHost).matcher.proto,
            None
        );
    }

    /// **A path is not an identity.** An allow the operator granted to
    /// something they can write themselves - a home directory, a build tree -
    /// keeps matching after anything else is written to that path, which is
    /// the one direction a remembered allow must never drift in. Pinning is
    /// the operator saying they approved these bytes, not this name.
    #[test]
    fn a_pinned_allow_carries_the_hash_the_operator_was_shown() {
        let c = conn("/home/u/.local/bin/tool", "1.1.1.1:443");
        let hash = "ab".repeat(32);
        let rule = rule_from_reply(
            "abc",
            7,
            &c,
            Verdict::Allow,
            RuleDuration::Forever,
            PromptScope::ThisPort,
            Some(&hash),
        )
        .expect("a rule is generated");
        assert_eq!(rule.matcher.exe_sha256.as_deref(), Some(hash.as_str()));
        // The path is still there: the pin narrows the rule, it does not
        // replace what it was already keyed on.
        assert_eq!(
            rule.matcher.exe,
            Some(PathBuf::from("/home/u/.local/bin/tool"))
        );

        // Unpinned is the old shape exactly, so an operator who did not ask
        // for this gets the rule they always got.
        let plain = rule_from_reply(
            "abc",
            7,
            &c,
            Verdict::Allow,
            RuleDuration::Forever,
            PromptScope::ThisPort,
            None,
        )
        .expect("a rule is generated");
        assert_eq!(plain.matcher.exe_sha256, None);
    }

    /// Pinning is refused rather than downgraded. The rule an unpinned write
    /// would produce is broader than what the operator answered and looks
    /// identical in every listing, so the reply applies its verdict to the
    /// held packets and remembers nothing - the connection is asked about
    /// again, which is the visible failure.
    #[tokio::test]
    async fn a_pin_request_with_no_hash_creates_no_rule_at_all() {
        let mut h = harness("pin-no-hash", 8, Verdict::Deny);
        let (tx, mut rx) = mpsc::channel(8);
        assert!(h.table.set_handler(tx.clone()));

        // No hash on the prompt: the binary was unreadable or past the cap.
        h.table
            .handle_new(conn("/usr/bin/curl", "1.1.1.1:443"), 1, None);
        let id = match rx.recv().await.expect("a prompt request") {
            DaemonMsg::PromptRequest { id, context, .. } => {
                assert_eq!(context.exe_sha256, None, "the fixture has no hash");
                id
            }
            other => panic!("expected a prompt request, got {other:?}"),
        };

        h.table
            .reply(
                &tx,
                id,
                Verdict::Allow,
                RuleDuration::Forever,
                PromptScope::ThisPort,
                true,
            )
            .expect("the reply is accepted");

        // The verdict still reached the held packet: refusing to remember a
        // decision must not refuse to apply it.
        assert_eq!(h.verdict_rx.recv().await, Some((1, Verdict::Allow)));
        assert!(
            h.store.list().is_empty(),
            "an unpinnable pin request must not fall back to an unpinned rule"
        );
    }

    /// Pinning narrows, and narrowing runs the wrong way for a deny: a deny
    /// that stops matching because the binary was updated resolves the
    /// connection with `default_verdict`, which an operator is free to set to
    /// allow. So the flag is dropped rather than honoured, the same way
    /// `app_id` already is.
    #[test]
    fn a_deny_is_never_pinned() {
        let c = conn("/usr/bin/curl", "1.1.1.1:443");
        for verdict in [Verdict::Deny, Verdict::Reject] {
            let rule = rule_from_reply(
                "abc",
                7,
                &c,
                verdict,
                RuleDuration::Forever,
                PromptScope::ThisPort,
                Some(&"ab".repeat(32)),
            )
            .expect("a rule is generated");
            // `reply` filters the flag before it reaches here; this asserts
            // the same thing one layer down, so a future caller that forgets
            // cannot quietly produce a self-expiring block.
            //
            // The hash is the assertion that matters. Asserting only on `exe`
            // passed vacuously - `rule_from_reply` sets it for every
            // `ThisPort` rule whether or not the pin was honoured - so this
            // test would have stayed green with the guard missing, which is
            // the one state it exists to catch.
            assert_eq!(
                rule.matcher.exe_sha256, None,
                "{verdict:?} must not be pinned to bytes that can be replaced"
            );
            assert_eq!(
                rule.matcher.exe,
                Some(PathBuf::from("/usr/bin/curl")),
                "{verdict:?} stays keyed on the path"
            );
        }
    }

    /// An allow answered for a sandboxed application names the application,
    /// not only the path inside its sandbox: that path is shared by every
    /// application of the same packaging system, so an exe-only allow would
    /// answer for all of them at once.
    ///
    /// A deny must not be pinned the same way. The operand only narrows, and
    /// a deny that stops matching because the application turned up without
    /// a recognized cgroup scope is resolved by `default_verdict`, which an
    /// operator is free to set to allow: the operator's block would silently
    /// stop applying.
    #[test]
    fn only_an_allow_pins_the_application() {
        let mut c = conn("/app/bin/firefox", "1.1.1.1:443");
        c.app_id = Some("flatpak:org.mozilla.firefox".into());
        let generated = |verdict| {
            rule_from_reply(
                "abc",
                7,
                &c,
                verdict,
                RuleDuration::Forever,
                PromptScope::AppAnywhere,
                None,
            )
            .expect("a rule is generated")
        };

        let allow = generated(Verdict::Allow);
        assert_eq!(allow.matcher.exe, Some(PathBuf::from("/app/bin/firefox")));
        assert_eq!(
            allow.matcher.app_id.as_deref(),
            Some("flatpak:org.mozilla.firefox")
        );

        for verdict in [Verdict::Deny, Verdict::Reject] {
            let rule = generated(verdict);
            assert_eq!(
                rule.matcher.app_id, None,
                "{verdict:?} must not be narrowed"
            );
            assert_eq!(rule.matcher.exe, Some(PathBuf::from("/app/bin/firefox")));
        }

        // Nothing changes for a connection with no application identity.
        let plain = conn("/usr/bin/curl", "1.1.1.1:443");
        let rule = rule_from_reply(
            "abc",
            8,
            &plain,
            Verdict::Allow,
            RuleDuration::Forever,
            PromptScope::AppAnywhere,
            None,
        )
        .expect("a rule is generated");
        assert_eq!(rule.matcher.app_id, None);
    }

    /// Two executables differing only in stripped characters must not collapse
    /// onto one rule name, or answering for one would silently cover the other.
    #[test]
    fn distinct_hostile_stems_do_not_collide() {
        let a = sanitize_rule_stem("ev\x1bil");
        let b = sanitize_rule_stem("ev\ril");
        assert_eq!(a, b, "same shape maps the same way");
        assert_ne!(sanitize_rule_stem("evil"), a, "dropped chars would collide");
    }

    /// The request carries what the operator reads to decide, not just the
    /// connection. Built off the dispatcher, so this is also the proof that
    /// the deferred send arrives at all.
    #[tokio::test]
    async fn the_request_carries_the_prompt_context() {
        let h = harness("context", 4, Verdict::Deny);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx));

        // Two earlier refusals for this application, and one for another, so
        // the count has to be per identity rather than a total.
        let mut denied = conn("/bin/a", "9.9.9.9:443");
        denied.app_id = Some("snap:thing".into());
        h.events.emit(denied.clone(), Verdict::Deny, None, true);
        h.events.emit(denied.clone(), Verdict::Reject, None, true);
        h.events
            .emit(conn("/bin/other", "9.9.9.9:443"), Verdict::Deny, None, true);

        let mut asked = conn("/bin/a", "1.1.1.1:443");
        asked.app_id = Some("snap:thing".into());
        h.table.handle_new(asked, 1, None);

        let DaemonMsg::PromptRequest { context, .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };
        assert_eq!(context.recent_denials, 2);
        // No rule in this store pins a hash, so there is nothing to warn
        // about, and the exe of a fixture connection does not exist to hash.
        assert!(context.hash_mismatch_rules.is_empty());
        assert_eq!(context.exe_sha256, None);
    }

    /// A prompt is on its way to the handler before `handle_new` returns,
    /// and in prompt-id order.
    ///
    /// Both were true by construction until the request was briefly built
    /// and sent from a task of its own. That cost four defects at once, and
    /// this is the property that rules them all out: nothing may sit between
    /// entering a prompt in the table and offering it to the handler. If it
    /// does, the expiry timer armed alongside it can fire first - applying
    /// the default verdict to a connection nobody was shown, and charging
    /// the silence to a handler that was never asked, until three of them
    /// evict it - and the order the operator is walked through prompts stops
    /// matching the order the packets arrived in.
    #[tokio::test]
    async fn requests_are_sent_before_handle_new_returns_and_in_order() {
        let h = harness("sync-delivery", 8, Verdict::Deny);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx));

        for seq in 1..=4u64 {
            h.table
                .handle_new(conn("/bin/a", &format!("1.1.1.{seq}:443")), seq, None);
            // try_recv, not recv().await: nothing may be awaited for the
            // request to exist.
            let msg = prompt_rx
                .try_recv()
                .expect("the request is sent synchronously");
            let DaemonMsg::PromptRequest { id, .. } = msg else {
                panic!("expected PromptRequest");
            };
            assert_eq!(id, seq, "prompt ids reach the handler in creation order");
        }
    }

    /// Prompt ids are a monotonic counter from 1, so they are trivially
    /// guessable. Only the client holding the handler slot may answer, or any
    /// other connected client could race the GUI and allow what the operator
    /// was about to deny.
    #[tokio::test]
    async fn only_the_registered_handler_may_reply() {
        let mut h = harness("reply-authz", 4, Verdict::Deny);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx.clone()));
        // A second client connects but does not hold the slot.
        let (other, _other_rx) = mpsc::channel(16);
        assert!(!h.table.set_handler(other.clone()), "slot is exclusive");

        h.table.handle_new(conn("/bin/a", "1.1.1.1:443"), 1, None);
        let DaemonMsg::PromptRequest { id, .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };

        let err = h
            .table
            .reply(
                &other,
                id,
                Verdict::Allow,
                RuleDuration::Once,
                PromptScope::ThisPort,
                false,
            )
            .expect_err("a non-handler must not answer");
        assert!(err.contains("prompt handler"), "{err}");
        // The prompt is untouched: no verdict released, still answerable.
        assert!(h.verdict_rx.try_recv().is_err());

        h.table
            .reply(
                &tx,
                id,
                Verdict::Deny,
                RuleDuration::Once,
                PromptScope::ThisPort,
                false,
            )
            .expect("the handler may answer");
        assert_eq!(h.verdict_rx.recv().await, Some((1, Verdict::Deny)));
    }

    #[tokio::test]
    async fn reply_resolves_all_coalesced_packets() {
        let mut h = harness("coalesce", 4, Verdict::Allow);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx.clone()));
        assert!(!h.table.set_handler(tx.clone()), "slot is exclusive");

        // Same key twice: one prompt, two held packets.
        h.table.handle_new(conn("/bin/a", "1.1.1.1:443"), 1, None);
        h.table.handle_new(conn("/bin/a", "1.1.1.1:443"), 2, None);
        let DaemonMsg::PromptRequest { id, .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };
        assert!(prompt_rx.try_recv().is_err(), "second packet coalesced");

        h.table
            .reply(
                &tx,
                id,
                Verdict::Deny,
                RuleDuration::Once,
                PromptScope::ThisPort,
                false,
            )
            .unwrap();
        assert_eq!(h.verdict_rx.recv().await, Some((1, Verdict::Deny)));
        assert_eq!(h.verdict_rx.recv().await, Some((2, Verdict::Deny)));
        // Once: no rule created.
        assert!(h.store.list().is_empty());
        assert!(h
            .table
            .reply(
                &tx,
                id,
                Verdict::Allow,
                RuleDuration::Once,
                PromptScope::ThisPort,
                false
            )
            .is_err());
    }

    #[tokio::test]
    async fn udp_once_covers_the_flow_without_a_rule() {
        // conntrack marks only the first datagram of a UDP flow `ct state
        // new`, so a single verdict reaches the queue and covers the whole
        // flow. `Once` reuses that: the held datagram is released with the
        // verdict and no persistent rule is created, so a genuinely new
        // flow prompts again.
        let mut h = harness("udp-once", 4, Verdict::Deny);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx.clone()));
        let mut c = conn("/usr/bin/dig", "9.9.9.9:53");
        c.tuple.proto = Proto::Udp;
        h.table.handle_new(c, 1, None);
        let DaemonMsg::PromptRequest { id, .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };
        h.table
            .reply(
                &tx,
                id,
                Verdict::Allow,
                RuleDuration::Once,
                PromptScope::ThisHost,
                false,
            )
            .unwrap();
        assert_eq!(h.verdict_rx.recv().await, Some((1, Verdict::Allow)));
        assert!(
            h.store.list().is_empty(),
            "Once creates no rule for UDP either"
        );
    }

    /// An app-wide (or host-wide) answer resolves the other prompts the
    /// same app already has open, with the same verdict; unrelated apps'
    /// prompts stay.
    #[tokio::test]
    async fn broad_reply_resolves_other_prompts_it_covers() {
        let mut h = harness("sweep", 8, Verdict::Deny);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx.clone()));

        // One app, three endpoints; another app, one endpoint.
        h.table
            .handle_new(conn("/usr/bin/chrome", "1.1.1.1:443"), 1, None);
        h.table
            .handle_new(conn("/usr/bin/chrome", "2.2.2.2:443"), 2, None);
        h.table
            .handle_new(conn("/usr/bin/chrome", "3.3.3.3:80"), 3, None);
        h.table
            .handle_new(conn("/bin/other", "4.4.4.4:443"), 4, None);
        let DaemonMsg::PromptRequest { id: first, .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };
        for _ in 0..3 {
            let _ = prompt_rx.recv().await.unwrap();
        }

        // Allow the app anywhere: every chrome prompt resolves allow.
        h.table
            .reply(
                &tx,
                first,
                Verdict::Allow,
                RuleDuration::Session,
                PromptScope::AppAnywhere,
                false,
            )
            .unwrap();
        let mut released = std::collections::HashMap::new();
        for _ in 0..3 {
            let (seq, v) = h.verdict_rx.recv().await.unwrap();
            released.insert(seq, v);
        }
        assert_eq!(
            released,
            [
                (1, Verdict::Allow),
                (2, Verdict::Allow),
                (3, Verdict::Allow)
            ]
            .into(),
            "all three chrome endpoints released with the replied verdict"
        );

        // The two covered prompts are announced gone so popups close.
        let mut expired = 0;
        while let Ok(msg) = prompt_rx.try_recv() {
            if matches!(msg, DaemonMsg::PromptExpired { .. }) {
                expired += 1;
            }
        }
        assert_eq!(expired, 2, "both covered prompts expired to the handler");

        // The unrelated app's prompt is untouched and still answerable.
        assert!(h.verdict_rx.try_recv().is_err());
        let other_id = first + 3;
        h.table
            .reply(
                &tx,
                other_id,
                Verdict::Deny,
                RuleDuration::Once,
                PromptScope::ThisPort,
                false,
            )
            .unwrap();
        assert_eq!(h.verdict_rx.recv().await, Some((4, Verdict::Deny)));
    }

    /// A port-scoped answer must not touch the app's prompts for other
    /// destinations.
    #[tokio::test]
    async fn narrow_reply_leaves_other_prompts_open() {
        let mut h = harness("narrow", 8, Verdict::Deny);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx.clone()));
        h.table
            .handle_new(conn("/usr/bin/chrome", "1.1.1.1:443"), 1, None);
        h.table
            .handle_new(conn("/usr/bin/chrome", "2.2.2.2:443"), 2, None);
        let DaemonMsg::PromptRequest { id: first, .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };
        let _ = prompt_rx.recv().await.unwrap();

        h.table
            .reply(
                &tx,
                first,
                Verdict::Allow,
                RuleDuration::Session,
                PromptScope::ThisPort,
                false,
            )
            .unwrap();
        assert_eq!(h.verdict_rx.recv().await, Some((1, Verdict::Allow)));
        // The second endpoint's prompt is still pending: no verdict, no
        // expiry announcement.
        assert!(h.verdict_rx.try_recv().is_err());
        assert!(prompt_rx.try_recv().is_err());
    }

    /// TCP and UDP flows to the same ip:port are different requests
    /// (HTTPS vs QUIC); one prompt must not answer both.
    #[tokio::test]
    async fn different_protocols_prompt_separately() {
        let mut h = harness("proto", 4, Verdict::Allow);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx.clone()));
        h.table.handle_new(conn("/bin/a", "1.1.1.1:443"), 1, None);
        let mut udp = conn("/bin/a", "1.1.1.1:443");
        udp.tuple.proto = Proto::Udp;
        h.table.handle_new(udp, 2, None);

        let DaemonMsg::PromptRequest { id: tcp_id, .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };
        let DaemonMsg::PromptRequest { id: udp_id, .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected a second PromptRequest for the UDP flow");
        };
        assert_ne!(tcp_id, udp_id);

        h.table
            .reply(
                &tx,
                tcp_id,
                Verdict::Deny,
                RuleDuration::Once,
                PromptScope::ThisPort,
                false,
            )
            .unwrap();
        assert_eq!(h.verdict_rx.recv().await, Some((1, Verdict::Deny)));
        // The UDP prompt is untouched and still answerable.
        assert!(h.verdict_rx.try_recv().is_err());
        h.table
            .reply(
                &tx,
                udp_id,
                Verdict::Allow,
                RuleDuration::Once,
                PromptScope::ThisPort,
                false,
            )
            .unwrap();
        assert_eq!(h.verdict_rx.recv().await, Some((2, Verdict::Allow)));
    }

    /// A handler claiming the slot receives the prompts that were opened
    /// while the previous handler was connected (or dying), instead of
    /// them silently timing out to the default verdict.
    #[tokio::test]
    async fn new_handler_receives_pending_prompts() {
        let mut h = harness("redeliver", 4, Verdict::Allow);
        let (tx1, mut rx1) = mpsc::channel(16);
        assert!(h.table.set_handler(tx1));
        h.table.handle_new(conn("/bin/a", "1.1.1.1:443"), 1, None);
        let DaemonMsg::PromptRequest { id, .. } = rx1.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };

        // The handler dies without answering; a new one takes the slot.
        drop(rx1);
        let (tx2, mut rx2) = mpsc::channel(16);
        assert!(h.table.set_handler(tx2.clone()));
        let DaemonMsg::PromptRequest {
            id: redelivered, ..
        } = rx2.recv().await.unwrap()
        else {
            panic!("expected the pending prompt to be re-delivered");
        };
        assert_eq!(redelivered, id);

        // The new handler owns the slot now, so it is the one that may answer.
        h.table
            .reply(
                &tx2,
                id,
                Verdict::Deny,
                RuleDuration::Once,
                PromptScope::ThisPort,
                false,
            )
            .unwrap();
        assert_eq!(h.verdict_rx.recv().await, Some((1, Verdict::Deny)));
    }

    #[tokio::test]
    async fn overflow_applies_default() {
        let mut h = harness("overflow", 1, Verdict::Deny);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx.clone()));
        h.table.handle_new(conn("/bin/a", "1.1.1.1:443"), 1, None);
        let _ = prompt_rx.recv().await.unwrap();
        // Different key while table is full.
        h.table.handle_new(conn("/bin/b", "2.2.2.2:80"), 2, None);
        assert_eq!(h.verdict_rx.recv().await, Some((2, Verdict::Deny)));
    }

    /// One flow cannot hold packets without limit. Coalescing means a
    /// process looping connect() to one endpoint adds a packet per attempt
    /// to a single prompt, and each held packet pins a kernel queue slot, so
    /// past the budget the extras take the default verdict immediately while
    /// the prompt itself stays open and answerable.
    #[tokio::test]
    async fn one_prompt_holds_a_bounded_number_of_packets() {
        let mut h = harness("packetcap", 4, Verdict::Deny);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx.clone()));

        for seq in 0..MAX_PACKETS_PER_PROMPT as u64 {
            h.table.handle_new(conn("/bin/a", "1.1.1.1:443"), seq, None);
        }
        let DaemonMsg::PromptRequest { id, .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };
        assert!(
            h.verdict_rx.try_recv().is_err(),
            "packets inside the budget stay held for the operator"
        );

        // One past the budget: released now, and counted as a connection
        // nobody was asked about.
        h.table.handle_new(conn("/bin/a", "1.1.1.1:443"), 999, None);
        assert_eq!(h.verdict_rx.recv().await, Some((999, Verdict::Deny)));
        assert_eq!(h.snapshot().prompts_overflowed, 1);

        // The prompt is untouched: still one popup, still answerable, and
        // its answer still governs every packet it did hold.
        h.table
            .reply(
                &tx,
                id,
                Verdict::Allow,
                RuleDuration::Once,
                PromptScope::ThisPort,
                false,
            )
            .expect("the prompt survives the packet budget");
        assert_eq!(h.verdict_rx.recv().await, Some((0, Verdict::Allow)));
    }

    /// The per-prompt budget is per destination, so without a second budget
    /// one process spreading connections over a handful of ip:port pairs
    /// still holds every packet the queue thread will hold, and then nothing
    /// on the host gets a prompt until they drain.
    #[tokio::test]
    async fn one_executable_holds_a_bounded_number_of_packets_across_destinations() {
        // Room for more prompts than this test opens, so the pending-table
        // cap cannot be what resolves them.
        let mut h = harness("exebudget", MAX_PACKETS_PER_EXE * 2, Verdict::Deny);
        let (tx, _prompt_rx) = mpsc::channel(256);
        assert!(h.table.set_handler(tx.clone()));

        // Spread over destinations so the per-prompt budget never applies:
        // MAX_PACKETS_PER_EXE packets, none of them a repeat.
        let mut seq = 0u64;
        for port in 0..(MAX_PACKETS_PER_EXE as u16) {
            h.table.handle_new(
                conn("/bin/loud", &format!("1.1.1.1:{}", 1000 + port)),
                seq,
                None,
            );
            seq += 1;
        }
        assert!(
            h.verdict_rx.try_recv().is_err(),
            "packets inside the budget stay held"
        );

        // One more from the same executable, to a fresh destination: over
        // budget, released immediately rather than holding another slot.
        h.table
            .handle_new(conn("/bin/loud", "1.1.1.1:9999"), seq, None);
        assert_eq!(h.verdict_rx.recv().await, Some((seq, Verdict::Deny)));
        assert_eq!(h.snapshot().prompts_overflowed, 1);

        // A different executable is unaffected: this is a per-exe share, not
        // a global stop.
        seq += 1;
        h.table
            .handle_new(conn("/bin/quiet", "2.2.2.2:443"), seq, None);
        assert!(
            h.verdict_rx.try_recv().is_err(),
            "one loud executable must not deny everyone else a prompt"
        );
    }

    /// The share is per application, and two packaged applications can run
    /// from one path inside their sandboxes. Summing their held packets
    /// together would let one of them spend the other's budget, and the
    /// over-budget path does not merely drop packets - it resolves them with
    /// the default verdict without ever raising a prompt, so the second
    /// application would be decided without anyone being asked.
    #[tokio::test]
    async fn applications_sharing_a_sandbox_path_do_not_share_a_budget() {
        let mut h = harness("appbudget", MAX_PACKETS_PER_EXE * 4, Verdict::Deny);
        let (tx, _prompt_rx) = mpsc::channel(256);
        assert!(h.table.set_handler(tx.clone()));

        let from = |app: &str, port: u16| {
            let mut c = conn("/app/bin/electron", &format!("1.1.1.1:{port}"));
            c.app_id = Some(app.to_string());
            c
        };

        // The first application spends its whole share.
        let mut seq = 0u64;
        for port in 0..(MAX_PACKETS_PER_EXE as u16) {
            h.table
                .handle_new(from("flatpak:com.example.First", 1000 + port), seq, None);
            seq += 1;
        }
        h.table
            .handle_new(from("flatpak:com.example.First", 9999), seq, None);
        assert_eq!(h.verdict_rx.recv().await, Some((seq, Verdict::Deny)));

        // The second is still asked about, though it runs from the same path.
        seq += 1;
        h.table
            .handle_new(from("flatpak:com.example.Second", 443), seq, None);
        assert!(
            h.verdict_rx.try_recv().is_err(),
            "a second application must not inherit the first's spent budget"
        );
    }

    /// Turning enforcement off must not leave packets held behind a prompt
    /// nobody is going to answer: the operator was told nothing is being
    /// blocked, and a packet held to its deadline is delayed by up to an
    /// hour.
    #[tokio::test]
    async fn switching_to_observe_releases_prompts_opened_while_enforcing() {
        let mut h = harness("observe-release", 8, Verdict::Allow);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx.clone()));
        h.table.handle_new(conn("/bin/a", "1.1.1.1:443"), 11, None);
        let DaemonMsg::PromptRequest { id, .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };

        h.table.resolve_pending_for_observe();

        assert_eq!(h.verdict_rx.recv().await, Some((11, Verdict::Allow)));
        assert_eq!(
            prompt_rx.recv().await,
            Some(DaemonMsg::PromptExpired { id })
        );
        // The prompt is gone from the table, so a late answer is refused
        // rather than resolving a flow that was already released.
        assert!(h
            .table
            .reply(
                &tx,
                id,
                Verdict::Deny,
                RuleDuration::Once,
                PromptScope::ThisPort,
                false
            )
            .is_err());
    }

    /// The sweep must apply the same enabled filter the packet path does. A
    /// client can add a disabled rule, and sweeping with it resolved live
    /// prompts with a verdict no packet would ever have been given.
    #[tokio::test]
    async fn a_disabled_rule_does_not_resolve_prompts() {
        let mut h = harness("disabled-sweep", 8, Verdict::Deny);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx.clone()));
        h.table.handle_new(conn("/bin/a", "1.1.1.1:443"), 21, None);
        let _ = prompt_rx.recv().await.unwrap();

        let mut rule = Rule {
            name: "off-allow".into(),
            action: hallpass_types::Action::Allow,
            duration: RuleDuration::Session,
            priority: 1,
            enabled: false,
            tags: Vec::new(),
            matcher: RuleMatch {
                exe: Some(PathBuf::from("/bin/a")),
                ..Default::default()
            },
        };
        h.table.resolve_covered_by(&rule);
        assert!(
            h.verdict_rx.try_recv().is_err(),
            "a disabled rule must not decide a prompt"
        );

        // Enabled, the same rule sweeps it.
        rule.enabled = true;
        h.table.resolve_covered_by(&rule);
        assert_eq!(h.verdict_rx.recv().await, Some((21, Verdict::Allow)));
    }

    /// Answering one of several pending prompts from one program with a
    /// remembered rule settles the others that rule covers, through the
    /// reply path itself: each is decided with the answer and its handler
    /// told it is gone. Checked for both verdicts, since an allow rule
    /// carries the user and the application identity and a deny does not,
    /// and for every scope, which decides how many of the siblings the
    /// answer reaches.
    #[tokio::test]
    async fn a_remembered_answer_settles_the_sibling_prompts_it_covers() {
        for (verdict, scope, covered) in [
            (Verdict::Deny, PromptScope::AppAnywhere, vec![2, 3, 4]),
            (Verdict::Allow, PromptScope::AppAnywhere, vec![2, 3, 4]),
            (Verdict::Deny, PromptScope::ThisHost, vec![2]),
            (Verdict::Allow, PromptScope::ThisPort, vec![]),
        ] {
            let mut h = harness("siblings", 8, Verdict::Allow);
            let (tx, mut prompt_rx) = mpsc::channel(16);
            assert!(h.table.set_handler(tx.clone()));
            let mut ids = Vec::new();
            // Same program: the first two share an address on different
            // ports, the rest go elsewhere. A different program's prompt
            // is never covered.
            for (seq, dst) in [
                (1, "1.1.1.1:443"),
                (2, "1.1.1.1:80"),
                (3, "2.2.2.2:443"),
                (4, "3.3.3.3:53"),
            ] {
                h.table.handle_new(conn("/usr/bin/curl", dst), seq, None);
                let DaemonMsg::PromptRequest { id, .. } = prompt_rx.recv().await.unwrap() else {
                    panic!("expected PromptRequest");
                };
                ids.push(id);
            }
            h.table
                .handle_new(conn("/usr/bin/wget", "1.1.1.1:443"), 9, None);
            let _ = prompt_rx.recv().await.unwrap();

            h.table
                .reply(&tx, ids[0], verdict, RuleDuration::Session, scope, false)
                .unwrap();

            let mut decided = vec![h.verdict_rx.recv().await.unwrap()];
            while let Ok(v) = h.verdict_rx.try_recv() {
                decided.push(v);
            }
            let mut want: Vec<(u64, Verdict)> = vec![(1, verdict)];
            want.extend(covered.iter().map(|seq| (*seq, verdict)));
            decided.sort_unstable_by_key(|(seq, _)| *seq);
            assert_eq!(decided, want, "{verdict:?} {scope:?}");

            let mut gone = Vec::new();
            while let Ok(msg) = prompt_rx.try_recv() {
                if let DaemonMsg::PromptExpired { id } = msg {
                    gone.push(id);
                }
            }
            let want_gone: Vec<u64> = covered.iter().map(|seq| ids[*seq as usize - 1]).collect();
            gone.sort_unstable();
            assert_eq!(
                gone, want_gone,
                "{verdict:?} {scope:?}: the handler is told"
            );
        }
    }

    /// A pinned rule must sweep the prompts it covers.
    ///
    /// `first_failing_field` reports `exe_sha256` as the failing criterion
    /// whenever the rule pins a hash and the caller supplies none, so sweeping
    /// with `None` made every pinned rule cover nothing at all. The visible
    /// failure: an operator answers one of a stack of prompts for the same
    /// application with "allow, forever, this app anywhere, pinned", the rule
    /// is written, and the siblings sit open until the timeout resolves them
    /// with `default_verdict` - here the opposite verdict to the one just
    /// given.
    #[tokio::test]
    async fn a_pinned_rule_sweeps_the_prompts_it_covers() {
        let hash = "ab".repeat(32);
        let mut h = harness("pinned-sweep", 8, Verdict::Deny);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx.clone()));
        h.table
            .handle_new(conn("/bin/a", "1.1.1.1:443"), 31, Some(hash.clone()));
        let _ = prompt_rx.recv().await.unwrap();

        let rule = Rule {
            name: "pinned-allow".into(),
            action: hallpass_types::Action::Allow,
            duration: RuleDuration::Forever,
            priority: 1,
            enabled: true,
            tags: Vec::new(),
            matcher: RuleMatch {
                exe: Some(PathBuf::from("/bin/a")),
                exe_sha256: Some(hash),
                ..Default::default()
            },
        };
        h.table.resolve_covered_by(&rule);
        assert_eq!(h.verdict_rx.recv().await, Some((31, Verdict::Allow)));
    }

    /// The other direction, so the fix above cannot be read as "ignore the
    /// hash when sweeping": pinning still narrows. A prompt for a different
    /// set of bytes at the same path is not covered by the pinned rule and
    /// must stay open to be answered on its own.
    #[tokio::test]
    async fn a_pinned_rule_does_not_sweep_a_different_binary() {
        let mut h = harness("pinned-sweep-narrow", 8, Verdict::Deny);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx.clone()));
        h.table
            .handle_new(conn("/bin/a", "1.1.1.1:443"), 32, Some("cd".repeat(32)));
        let _ = prompt_rx.recv().await.unwrap();

        let rule = Rule {
            name: "pinned-allow".into(),
            action: hallpass_types::Action::Allow,
            duration: RuleDuration::Forever,
            priority: 1,
            enabled: true,
            tags: Vec::new(),
            matcher: RuleMatch {
                exe: Some(PathBuf::from("/bin/a")),
                exe_sha256: Some("ab".repeat(32)),
                ..Default::default()
            },
        };
        h.table.resolve_covered_by(&rule);
        assert!(
            h.verdict_rx.try_recv().is_err(),
            "a pin is a narrowing, so bytes it does not name stay unanswered"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_applies_default_and_notifies() {
        let mut h = harness("timeout", 4, Verdict::Deny);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx.clone()));
        h.table.handle_new(conn("/bin/a", "1.1.1.1:443"), 9, None);
        let DaemonMsg::PromptRequest { id, .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };
        tokio::time::advance(Duration::from_secs(6)).await;
        assert_eq!(h.verdict_rx.recv().await, Some((9, Verdict::Deny)));
        assert_eq!(
            prompt_rx.recv().await,
            Some(DaemonMsg::PromptExpired { id })
        );
    }

    /// A runtime settings change: the new timeout arms prompts created
    /// after it (armed prompts keep their deadline), and the default
    /// verdict is read when a decision is applied, so a prompt that
    /// outlives the change resolves with the operator's latest choice.
    #[tokio::test(start_paused = true)]
    async fn settings_changes_apply_to_new_prompts_and_pending_defaults() {
        let mut h = harness("settings", 8, Verdict::Allow);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx.clone()));

        // Armed under timeout=5s.
        h.table.handle_new(conn("/bin/a", "1.1.1.1:443"), 1, None);
        let DaemonMsg::PromptRequest {
            deadline_ms: first_deadline,
            ..
        } = prompt_rx.recv().await.unwrap()
        else {
            panic!("expected PromptRequest");
        };

        h.settings
            .apply(&crate::testutil::runtime_config(60, Verdict::Deny))
            .expect("valid settings");

        // A prompt created after the change carries the longer deadline.
        h.table.handle_new(conn("/bin/b", "2.2.2.2:443"), 2, None);
        let DaemonMsg::PromptRequest {
            deadline_ms: second_deadline,
            ..
        } = prompt_rx.recv().await.unwrap()
        else {
            panic!("expected PromptRequest");
        };
        assert!(
            second_deadline >= first_deadline + 50_000,
            "new timeout did not reach new prompts: {first_deadline} vs {second_deadline}"
        );

        // The first prompt still expires on its original 5s timer, and the
        // default it resolves with is the one in force now: deny.
        tokio::time::advance(Duration::from_secs(6)).await;
        assert_eq!(h.verdict_rx.recv().await, Some((1, Verdict::Deny)));

        // Out-of-range sets are refused and change nothing.
        let err = h
            .settings
            .apply(&crate::testutil::runtime_config(0, Verdict::Allow))
            .expect_err("zero timeout must be refused");
        assert!(err.contains("at least 1"), "{err}");
        assert_eq!(h.settings.snapshot().prompt_timeout_secs, 60);
        assert_eq!(h.settings.snapshot().default_verdict, Verdict::Deny);
    }

    #[tokio::test]
    async fn reply_with_duration_creates_scoped_rule() {
        let mut h = harness("rule", 4, Verdict::Allow);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx.clone()));
        h.table
            .handle_new(conn("/usr/bin/curl", "9.9.9.9:853"), 1, None);
        let DaemonMsg::PromptRequest { id, .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };
        h.table
            .reply(
                &tx,
                id,
                Verdict::Allow,
                RuleDuration::Session,
                PromptScope::ThisHost,
                false,
            )
            .unwrap();
        assert_eq!(h.verdict_rx.recv().await, Some((1, Verdict::Allow)));

        let rules = h.store.list();
        assert_eq!(rules.len(), 1);
        let r = &rules[0];
        assert_eq!(
            r.matcher.exe.as_deref(),
            Some(std::path::Path::new("/usr/bin/curl"))
        );
        assert_eq!(r.matcher.dest.as_deref(), Some("9.9.9.9"));
        assert_eq!(r.matcher.port, None, "ThisHost scope has no port");
        assert_eq!(r.duration, RuleDuration::Session);
    }

    #[test]
    fn scope_matchers() {
        let c = conn("/usr/bin/curl", "9.9.9.9:853");
        let r = rule_from_reply(
            "abc",
            1,
            &c,
            Verdict::Deny,
            RuleDuration::Session,
            PromptScope::ThisPort,
            None,
        )
        .unwrap();
        assert_eq!(r.matcher.dest.as_deref(), Some("9.9.9.9"));
        assert_eq!(r.matcher.port, Some(853));
        assert_eq!(r.action, hallpass_types::Action::Deny);

        let r = rule_from_reply(
            "abc",
            2,
            &c,
            Verdict::Allow,
            RuleDuration::Forever,
            PromptScope::AppAnywhere,
            None,
        )
        .unwrap();
        assert_eq!(r.matcher.dest, None);
        assert_eq!(r.matcher.port, None);
        assert!(r.matcher.exe.is_some());

        let mut anon = c.clone();
        anon.exe_path = None;
        assert!(rule_from_reply(
            "abc",
            3,
            &anon,
            Verdict::Allow,
            RuleDuration::Session,
            PromptScope::AppAnywhere,
            None
        )
        .is_none());
    }
}

use super::*;
use hallpass_types::{FlowTuple, Proto};
use tokio::sync::mpsc;

struct Harness {
    table: Arc<PromptTable>,
    verdict_rx: mpsc::UnboundedReceiver<(u64, Verdict)>,
    store: Arc<RuleStore>,
    stats: Arc<Counters>,
    settings: Arc<RuntimeSettings>,
    events: Arc<EventBus>,
    _dir: crate::testutil::TestDir,
}

impl Harness {
    /// Answer prompt `id` as the handler holding `tx`, without pinning.
    fn answer(
        &self,
        tx: &mpsc::Sender<DaemonMsg>,
        id: u64,
        verdict: Verdict,
        duration: RuleDuration,
        scope: PromptScope,
    ) -> Result<(), String> {
        self.table.reply(tx, id, verdict, duration, scope, false)
    }

    /// The stats snapshot a client would read, with the table's own
    /// handler state in it.
    fn snapshot(&self) -> hallpass_types::Stats {
        self.stats.snapshot(
            0,
            0,
            self.table.has_handler(),
            true,
            None,
            crate::stats::QueueStats::default(),
        )
    }
}

fn harness(tag: &str, max_pending: usize, default: Verdict) -> Harness {
    let dir = crate::testutil::TestDir::new(&format!("prompt-{tag}"));
    let store = Arc::new(RuleStore::new(dir.path().to_path_buf()));
    let (verdict_tx, verdict_rx) = mpsc::unbounded_channel();
    let stats = Arc::new(Counters::default());
    let settings = Arc::new(RuntimeSettings::new(crate::testutil::runtime_config(
        5, default,
    )));
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

/// An enabled, untagged session allow rule over `matcher`.
fn allow_rule(name: &str, matcher: RuleMatch) -> Rule {
    Rule {
        name: name.into(),
        action: hallpass_types::Action::Allow,
        duration: RuleDuration::Session,
        priority: 1,
        enabled: true,
        tags: Vec::new(),
        matcher,
    }
}

/// The id of the next message on `rx`, which must be a prompt request.
async fn next_prompt_id(rx: &mut mpsc::Receiver<DaemonMsg>) -> u64 {
    match rx.recv().await {
        Some(DaemonMsg::PromptRequest { id, .. }) => id,
        other => panic!("expected a prompt request, got {other:?}"),
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
    let id = next_prompt_id(&mut prompt_rx).await;

    h.settings.set_locked_down(true);
    h.answer(
        &tx,
        id,
        Verdict::Allow,
        RuleDuration::Forever,
        PromptScope::ThisPort,
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
    next_prompt_id(&mut prompt_rx).await;

    h.settings.set_locked_down(true);
    h.store.rebuild_for_posture(Some(&["core".to_string()]));
    let untagged = allow_rule(
        "allow-curl",
        RuleMatch {
            port: Some(443),
            ..Default::default()
        },
    );
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
    for seq in 1..=u64::from(MAX_UNANSWERED_EXPIRIES) {
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
        let id = next_prompt_id(&mut prompt_rx).await;
        h.answer(
            &tx,
            id,
            Verdict::Deny,
            RuleDuration::Once,
            PromptScope::ThisPort,
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
    let id = next_prompt_id(&mut prompt_rx).await;

    let err = h
        .answer(
            &other,
            id,
            Verdict::Allow,
            RuleDuration::Once,
            PromptScope::ThisPort,
        )
        .expect_err("a non-handler must not answer");
    assert!(err.contains("prompt handler"), "{err}");
    // The prompt is untouched: no verdict released, still answerable.
    assert!(h.verdict_rx.try_recv().is_err());

    h.answer(
        &tx,
        id,
        Verdict::Deny,
        RuleDuration::Once,
        PromptScope::ThisPort,
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
    let id = next_prompt_id(&mut prompt_rx).await;
    assert!(prompt_rx.try_recv().is_err(), "second packet coalesced");

    h.answer(
        &tx,
        id,
        Verdict::Deny,
        RuleDuration::Once,
        PromptScope::ThisPort,
    )
    .unwrap();
    assert_eq!(h.verdict_rx.recv().await, Some((1, Verdict::Deny)));
    assert_eq!(h.verdict_rx.recv().await, Some((2, Verdict::Deny)));
    // Once: no rule created.
    assert!(h.store.list().is_empty());
    assert!(h
        .answer(
            &tx,
            id,
            Verdict::Allow,
            RuleDuration::Once,
            PromptScope::ThisPort
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
    let id = next_prompt_id(&mut prompt_rx).await;
    h.answer(
        &tx,
        id,
        Verdict::Allow,
        RuleDuration::Once,
        PromptScope::ThisHost,
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
    let first = next_prompt_id(&mut prompt_rx).await;
    for _ in 0..3 {
        let _ = prompt_rx.recv().await.unwrap();
    }

    // Allow the app anywhere: every chrome prompt resolves allow.
    h.answer(
        &tx,
        first,
        Verdict::Allow,
        RuleDuration::Session,
        PromptScope::AppAnywhere,
    )
    .unwrap();
    let mut released = HashMap::new();
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
    h.answer(
        &tx,
        other_id,
        Verdict::Deny,
        RuleDuration::Once,
        PromptScope::ThisPort,
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
    let first = next_prompt_id(&mut prompt_rx).await;
    let _ = prompt_rx.recv().await.unwrap();

    h.answer(
        &tx,
        first,
        Verdict::Allow,
        RuleDuration::Session,
        PromptScope::ThisPort,
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

    let tcp_id = next_prompt_id(&mut prompt_rx).await;
    let udp_id = next_prompt_id(&mut prompt_rx).await;
    assert_ne!(tcp_id, udp_id);

    h.answer(
        &tx,
        tcp_id,
        Verdict::Deny,
        RuleDuration::Once,
        PromptScope::ThisPort,
    )
    .unwrap();
    assert_eq!(h.verdict_rx.recv().await, Some((1, Verdict::Deny)));
    // The UDP prompt is untouched and still answerable.
    assert!(h.verdict_rx.try_recv().is_err());
    h.answer(
        &tx,
        udp_id,
        Verdict::Allow,
        RuleDuration::Once,
        PromptScope::ThisPort,
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
    let id = next_prompt_id(&mut rx1).await;

    // The handler dies without answering; a new one takes the slot.
    drop(rx1);
    let (tx2, mut rx2) = mpsc::channel(16);
    assert!(h.table.set_handler(tx2.clone()));
    let redelivered = next_prompt_id(&mut rx2).await;
    assert_eq!(redelivered, id);

    // The new handler owns the slot now, so it is the one that may answer.
    h.answer(
        &tx2,
        id,
        Verdict::Deny,
        RuleDuration::Once,
        PromptScope::ThisPort,
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
    let id = next_prompt_id(&mut prompt_rx).await;
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
    h.answer(
        &tx,
        id,
        Verdict::Allow,
        RuleDuration::Once,
        PromptScope::ThisPort,
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
    let id = next_prompt_id(&mut prompt_rx).await;

    h.table.resolve_pending_for_observe();

    assert_eq!(h.verdict_rx.recv().await, Some((11, Verdict::Allow)));
    assert_eq!(
        prompt_rx.recv().await,
        Some(DaemonMsg::PromptExpired { id })
    );
    // The prompt is gone from the table, so a late answer is refused
    // rather than resolving a flow that was already released.
    assert!(h
        .answer(
            &tx,
            id,
            Verdict::Deny,
            RuleDuration::Once,
            PromptScope::ThisPort
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
        enabled: false,
        ..allow_rule(
            "off-allow",
            RuleMatch {
                exe: Some(PathBuf::from("/bin/a")),
                ..Default::default()
            },
        )
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
            let id = next_prompt_id(&mut prompt_rx).await;
            ids.push(id);
        }
        h.table
            .handle_new(conn("/usr/bin/wget", "1.1.1.1:443"), 9, None);
        let _ = prompt_rx.recv().await.unwrap();

        h.answer(&tx, ids[0], verdict, RuleDuration::Session, scope)
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

    let rule = allow_rule(
        "pinned-allow",
        RuleMatch {
            exe: Some(PathBuf::from("/bin/a")),
            exe_sha256: Some(hash),
            ..Default::default()
        },
    );
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

    let rule = allow_rule(
        "pinned-allow",
        RuleMatch {
            exe: Some(PathBuf::from("/bin/a")),
            exe_sha256: Some("ab".repeat(32)),
            ..Default::default()
        },
    );
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
    let id = next_prompt_id(&mut prompt_rx).await;
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
    let id = next_prompt_id(&mut prompt_rx).await;
    h.answer(
        &tx,
        id,
        Verdict::Allow,
        RuleDuration::Session,
        PromptScope::ThisHost,
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

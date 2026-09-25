//! Headless state tests for [`HallpassApp`].
//!
//! Every GUI defect this branch produced was state logic that happened to
//! live behind a window: an edit applied before the daemon agreed to it, a
//! backfill appended twice, a claim about enforcement made before anything
//! had said so. None of them needed pixels to reproduce, only the app's two
//! channels, which is what these tests drive. No socket, no daemon, no
//! display, so they run in the ordinary workspace suite.

use std::time::Duration;

use hallpass_types::{Action, Connection, PromptScope, RuleDuration, RuleMatch};

use super::format::{format_uptime, grouped};
use super::prompt_agent::AGENT_GRACE;
use super::*;

/// An app plus the ends of its channel pair the network thread would own.
struct TestApp {
    app: HallpassApp,
    /// Where the network thread would deliver from.
    to_ui: std::sync::mpsc::Sender<UiEvent>,
    /// What the network thread would write to the daemon.
    from_ui: tokio::sync::mpsc::UnboundedReceiver<ClientMsg>,
}

impl TestApp {
    fn new() -> Self {
        let (to_daemon, from_ui) = tokio::sync::mpsc::unbounded_channel();
        let (to_ui, from_net) = std::sync::mpsc::channel();
        Self {
            app: HallpassApp::with_channels(to_daemon, from_net),
            to_ui,
            from_ui,
        }
    }

    /// Deliver one network event and let the app consume it, as a frame would.
    fn feed(&mut self, ev: UiEvent) {
        self.to_ui.send(ev).expect("the app holds the receiver");
        self.app.drain_net();
    }

    /// Deliver one message from the daemon.
    fn daemon(&mut self, msg: DaemonMsg) {
        self.feed(UiEvent::Daemon(msg));
    }

    /// Everything the app has sent since this was last called.
    fn sent(&mut self) -> Vec<ClientMsg> {
        drain(&mut self.from_ui)
    }

    /// Open the rule editor with a save already in flight, the state the
    /// window is in between clicking Save and the daemon answering.
    fn editor_awaiting_ack(&mut self) {
        let mut editor = RuleEditor::add();
        editor.mark_sent();
        self.app.editor = Some(editor);
        self.app.send(ClientMsg::RuleAdd(rule("pending", true)));
        self.sent();
    }
}

/// Everything queued on the app's outgoing channel, in send order. Shared
/// with the widget tests, which hold the receiver directly.
pub(super) fn drain(
    from_ui: &mut tokio::sync::mpsc::UnboundedReceiver<ClientMsg>,
) -> Vec<ClientMsg> {
    let mut out = Vec::new();
    while let Ok(msg) = from_ui.try_recv() {
        out.push(msg);
    }
    out
}

pub(super) fn conn(exe: &str, dst: &str) -> Connection {
    crate::testutil::conn(Some(exe), dst)
}

fn event(exe: &str, dst: &str, unix_ms: u64) -> ConnEvent {
    ConnEvent {
        conn: conn(exe, dst),
        verdict: Verdict::Allow,
        rule_name: None,
        unix_ms,
        enforced: true,
    }
}

fn rule(name: &str, enabled: bool) -> Rule {
    Rule {
        name: name.to_string(),
        action: Action::Deny,
        duration: RuleDuration::Forever,
        priority: 10,
        enabled,
        tags: Vec::new(),
        matcher: RuleMatch {
            port: Some(443),
            ..RuleMatch::default()
        },
    }
}

fn stats(enforcing: bool) -> Stats {
    Stats {
        enforcing,
        ..Stats::default()
    }
}

fn err(message: &str) -> DaemonMsg {
    DaemonMsg::Err {
        message: message.to_string(),
    }
}

fn prompt_request(id: u64, exe: &str) -> DaemonMsg {
    DaemonMsg::PromptRequest {
        id,
        conn: conn(exe, "93.184.216.34:443"),
        deadline_ms: hallpass_types::unix_ms_now() + 30_000,
        context: hallpass_types::PromptContext::default(),
    }
}

pub(super) fn runtime_config(secs: u64, verdict: Verdict) -> hallpass_types::RuntimeConfig {
    hallpass_types::RuntimeConfig {
        prompt_timeout_secs: secs,
        default_verdict: verdict,
        enforce: true,
    }
}

// ---- rule changes are the daemon's to make (662ea63) ---------------------

/// A refused toggle leaves the rule enforced, so the screen has to go back
/// to the daemon rather than keep the change it displayed. The list is only
/// ever what the daemon last reported: it changes when the refetch lands and
/// at no other time.
///
/// (That the checkbox itself does not edit the row is a property of the
/// rules tab, tested where it lives; see the widget tests.)
#[test]
fn a_refused_toggle_sends_the_screen_back_to_the_daemon() {
    let mut t = TestApp::new();
    t.daemon(DaemonMsg::Rules(vec![rule("block-telemetry", true)]));
    t.app.send(ClientMsg::RuleToggle {
        name: "block-telemetry".to_string(),
        enabled: false,
    });
    t.sent();

    t.daemon(err("rules.d is read-only"));
    assert_eq!(t.sent(), vec![ClientMsg::RuleList]);
    assert!(
        t.app.rules[0].enabled,
        "a refused toggle changed the screen"
    );
}

/// An accepted toggle refetches too: nothing on this side can tell the two
/// outcomes apart, so both ask.
#[test]
fn an_accepted_toggle_refetches_rather_than_guessing() {
    let mut t = TestApp::new();
    t.daemon(DaemonMsg::Rules(vec![rule("block-telemetry", true)]));
    t.app.send(ClientMsg::RuleToggle {
        name: "block-telemetry".to_string(),
        enabled: false,
    });
    t.sent();

    t.daemon(DaemonMsg::Ok);
    assert_eq!(t.sent(), vec![ClientMsg::RuleList]);
    assert!(
        t.app.rules[0].enabled,
        "the row changes when the refetch lands, not before"
    );

    t.daemon(DaemonMsg::Rules(vec![rule("block-telemetry", false)]));
    assert!(!t.app.rules[0].enabled);
}

/// Same for a delete: dropping the row on a refusal would hide a rule that
/// still exists and is still enforced.
#[test]
fn a_refused_delete_leaves_the_rule_on_screen() {
    let mut t = TestApp::new();
    t.daemon(DaemonMsg::Rules(vec![rule("block-telemetry", true)]));
    t.app.send(ClientMsg::RuleDelete {
        name: "block-telemetry".to_string(),
    });
    t.sent();

    t.daemon(err("no such rule"));
    assert_eq!(t.sent(), vec![ClientMsg::RuleList]);
    assert_eq!(t.app.rules.len(), 1, "a refused delete emptied the screen");
}

/// Toggles and deletes must not share an ack kind with anything else:
/// the FIFO is how a reply is matched to its request, so a miscategorized
/// request reconciles the wrong thing.
#[test]
fn ack_kinds_are_distinct_per_request() {
    let toggle = ClientMsg::RuleToggle {
        name: "r".into(),
        enabled: false,
    };
    let delete = ClientMsg::RuleDelete { name: "r".into() };
    assert_eq!(ack_kind(&toggle), Some(AckKind::RuleToggle));
    // The bulk toggle is answered with `RulesToggled`, but a refusal is the
    // same `Err` as everyone else's: left out of the FIFO, an unknown tag
    // would pop somebody else's slot and reconcile the wrong request.
    assert_eq!(
        ack_kind(&ClientMsg::RuleToggleTag {
            tag: "work".into(),
            enabled: false
        }),
        Some(AckKind::RuleToggle)
    );
    assert_eq!(ack_kind(&delete), Some(AckKind::RuleDelete));
    assert_eq!(
        ack_kind(&ClientMsg::ConfigSet(runtime_config(30, Verdict::Deny))),
        Some(AckKind::ConfigSet)
    );
    assert_eq!(
        ack_kind(&ClientMsg::Subscribe {
            events: true,
            prompts: true
        }),
        Some(AckKind::Other)
    );
    assert_eq!(
        ack_kind(&ClientMsg::PromptReply {
            id: 1,
            verdict: Verdict::Deny,
            duration: RuleDuration::Once,
            scope: PromptScope::ThisPort,
            pin_exe: false,
        }),
        Some(AckKind::Other)
    );
    // Requests answered with data, not an ack, must not enter the FIFO
    // at all or every later reply is matched to the wrong request.
    assert_eq!(ack_kind(&ClientMsg::RuleList), None);
    assert_eq!(ack_kind(&ClientMsg::Stats), None);
    assert_eq!(ack_kind(&ClientMsg::EventHistory { limit: 10 }), None);
    assert_eq!(ack_kind(&ClientMsg::RuleStats), None);
    assert_eq!(ack_kind(&ClientMsg::ConfigGet), None);
}

// ---- the ack FIFO --------------------------------------------------------

/// The editor holds everything typed into it, so it closes only when the
/// daemon has actually taken the rule.
#[test]
fn a_saved_rule_closes_the_form_only_on_ok() {
    let mut t = TestApp::new();
    t.editor_awaiting_ack();
    t.daemon(DaemonMsg::Ok);
    assert!(t.app.editor.is_none(), "an accepted save closes the form");
    assert!(t.app.last_error.is_none());
}

/// A rejected save keeps the form and routes the daemon's complaint into
/// it, rather than to the status bar where the retry is not.
#[test]
fn a_rejected_save_keeps_the_form_open() {
    let mut t = TestApp::new();
    t.editor_awaiting_ack();
    t.daemon(err("dest: invalid CIDR"));
    let editor = t
        .app
        .editor
        .as_ref()
        .expect("the form survives a rejection");
    assert!(!editor.awaiting_ack(), "the form is editable again");
    assert!(
        t.app.last_error.is_none(),
        "the message belongs in the form, not the status bar"
    );
    assert!(t.sent().is_empty(), "a save reconciles through the editor");
}

/// The ack matrix, crossed with Ok and with Err. Only toggles and deletes
/// refetch the rule list; with no form waiting, every Err here is the
/// status bar's. The two tests above cover where a save's ack goes when a
/// form is waiting for it, and the settings tests below cover ConfigSet,
/// whose ack reconciles against the settings instead.
#[test]
fn every_ack_kind_crossed_with_ok_and_err() {
    let refetch = [
        (
            ClientMsg::RuleToggle {
                name: "r".to_string(),
                enabled: true,
            },
            true,
        ),
        (
            ClientMsg::RuleDelete {
                name: "r".to_string(),
            },
            true,
        ),
        (ClientMsg::RuleAdd(rule("r", true)), false),
        (
            ClientMsg::Subscribe {
                events: true,
                prompts: true,
            },
            false,
        ),
    ];
    for (request, expected) in refetch {
        for outcome in [DaemonMsg::Ok, err("no")] {
            let mut t = TestApp::new();
            t.app.send(request.clone());
            t.sent();
            let is_err = matches!(outcome, DaemonMsg::Err { .. });
            t.daemon(outcome);
            let refetched = t.sent() == vec![ClientMsg::RuleList];
            assert_eq!(
                refetched, expected,
                "{request:?} refetch after err={is_err}"
            );
            assert!(
                t.app.pending_ack_kinds().is_empty(),
                "{request:?} left an ack in the FIFO"
            );
            // Without an editor waiting, an Err is the status bar's.
            assert_eq!(t.app.last_error.is_some(), is_err, "{request:?}");
        }
    }
}

/// The bulk toggle's reply takes its slot in the FIFO and reconciles the
/// screen, and the rules it could not write are said out loud - the refetch
/// that follows would otherwise show them enabled with nothing said why.
#[test]
fn a_bulk_toggle_reply_reconciles_and_reports_failures() {
    let mut t = TestApp::new();
    t.app.send(ClientMsg::RuleToggleTag {
        tag: "work".into(),
        enabled: false,
    });
    t.sent();
    assert_eq!(t.app.pending_ack_kinds(), vec![AckKind::RuleToggle]);

    t.daemon(DaemonMsg::RulesToggled {
        changed: 2,
        failed: Vec::new(),
    });
    assert_eq!(
        t.sent(),
        vec![ClientMsg::RuleList],
        "the screen is refetched"
    );
    assert!(t.app.pending_ack_kinds().is_empty(), "the slot is freed");
    assert!(t.app.last_error.is_none(), "a clean batch raises no error");
    // The count is always reported: the daemon acts on its own live tag
    // set, so a batch can be wider than the table the operator judged it
    // from, and the refetch alone says nothing about how much moved.
    assert_eq!(t.app.rules_notice.as_deref(), Some("2 rule(s) changed"));

    t.app.send(ClientMsg::RuleToggleTag {
        tag: "work".into(),
        enabled: false,
    });
    t.sent();
    t.daemon(DaemonMsg::RulesToggled {
        changed: 1,
        failed: vec!["stuck".into()],
    });
    assert_eq!(t.sent(), vec![ClientMsg::RuleList]);
    let shown = t.app.last_error.clone().expect("failures are surfaced");
    assert!(shown.contains("stuck"), "{shown}");

    // And the banner is cleared by a batch that succeeds. Left standing, it
    // keeps naming a rule as still enforcing after the retry that fixed it,
    // and the next real failure cannot be told from the stale one.
    t.app.send(ClientMsg::RuleToggleTag {
        tag: "work".into(),
        enabled: false,
    });
    t.sent();
    t.daemon(DaemonMsg::RulesToggled {
        changed: 1,
        failed: Vec::new(),
    });
    assert!(
        t.app.last_error.is_none(),
        "a fixed failure kept its banner"
    );
}

/// A refused bulk toggle is an ordinary `Err`, so it must consume exactly
/// its own slot: the alternative is the next reply reconciling this one's
/// request and this one's error being blamed on a rule save.
#[test]
fn a_refused_bulk_toggle_consumes_one_slot() {
    let mut t = TestApp::new();
    t.app.send(ClientMsg::RuleToggleTag {
        tag: "wrok".into(),
        enabled: false,
    });
    t.editor_awaiting_ack();
    assert_eq!(
        t.app.pending_ack_kinds(),
        vec![AckKind::RuleToggle, AckKind::RuleSave]
    );

    t.daemon(err("no rule carries tag `wrok`"));
    assert_eq!(t.sent(), vec![ClientMsg::RuleList], "the toggle's ack");
    assert!(t.app.editor.is_some(), "the save is still in flight");
    assert_eq!(t.app.pending_ack_kinds(), vec![AckKind::RuleSave]);
}

/// Replies arrive in request order on the one IPC stream, so the FIFO is
/// the only thing that says which request an Ok belongs to. Answer them out
/// of order and a save's ack would close a form the daemon never took.
#[test]
fn acks_are_matched_to_requests_in_send_order() {
    let mut t = TestApp::new();
    t.app.send(ClientMsg::RuleToggle {
        name: "first".to_string(),
        enabled: false,
    });
    t.editor_awaiting_ack();
    assert_eq!(
        t.app.pending_ack_kinds(),
        vec![AckKind::RuleToggle, AckKind::RuleSave]
    );

    t.daemon(DaemonMsg::Ok);
    assert_eq!(t.sent(), vec![ClientMsg::RuleList], "the toggle's ack");
    assert!(t.app.editor.is_some(), "the save is still in flight");

    t.daemon(DaemonMsg::Ok);
    assert!(t.app.editor.is_none(), "the save's ack");
    assert!(t.sent().is_empty(), "a save does not refetch here");
}

/// An unsolicited Ok or Err (a daemon bug, or a reply to a request this
/// client did not make) must not pop an ack that belongs to something else,
/// and must not be mistaken for a rule change.
#[test]
fn an_ack_with_an_empty_queue_reconciles_nothing() {
    let mut t = TestApp::new();
    t.daemon(DaemonMsg::Ok);
    assert!(t.sent().is_empty());
    t.daemon(err("unexpected"));
    assert!(t.sent().is_empty());
    assert_eq!(t.app.last_error.as_deref(), Some("unexpected"));
}

/// A message the network thread dropped will never be acked, so its slot in
/// the FIFO has to go with it or every later reply answers the wrong
/// request.
#[test]
fn a_dropped_message_keeps_the_queue_aligned() {
    let mut t = TestApp::new();
    t.app.send(ClientMsg::RuleToggle {
        name: "gone".to_string(),
        enabled: false,
    });
    t.sent();
    assert_eq!(t.app.pending_ack_kinds().len(), 1);

    t.feed(UiEvent::SendFailed {
        msg: ClientMsg::RuleToggle {
            name: "gone".to_string(),
            enabled: false,
        },
    });
    assert!(
        t.app.pending_ack_kinds().is_empty(),
        "the dead ack was left queued"
    );
    assert!(
        t.app
            .last_error
            .as_deref()
            .is_some_and(|e| e.contains("rule toggle")),
        "a lost rule change must be visible: {:?}",
        t.app.last_error
    );

    // The next ack answers the next request, not the dropped one.
    t.app.send(ClientMsg::Subscribe {
        events: true,
        prompts: true,
    });
    t.sent();
    t.daemon(DaemonMsg::Ok);
    assert!(t.sent().is_empty(), "an Other ack refetched the rule list");
}

/// A bulk toggle dropped on reconnect is a whole set still enforcing, so it
/// is named as one - and its slot has to leave the FIFO with it. The
/// message must also be in net.rs's reported-drop list, or nothing emits
/// this event and the slot is orphaned for the rest of the session.
#[test]
fn a_dropped_bulk_toggle_names_the_set_and_keeps_the_queue_aligned() {
    let msg = ClientMsg::RuleToggleTag {
        tag: "work".to_string(),
        enabled: false,
    };
    assert!(
        crate::net::reports_send_failure(&msg),
        "net.rs drops this without telling anyone"
    );

    let mut t = TestApp::new();
    t.app.send(msg.clone());
    t.sent();
    assert_eq!(t.app.pending_ack_kinds().len(), 1);

    t.feed(UiEvent::SendFailed { msg });
    assert!(
        t.app.pending_ack_kinds().is_empty(),
        "the dead ack was left queued"
    );
    let shown = t
        .app
        .last_error
        .clone()
        .expect("a lost bulk toggle is visible");
    assert!(shown.contains("work"), "the set is named: {shown}");
}

/// A settings change that never reached the daemon is not in force, and
/// the form will snap back on the next Config reply; the loss has to be
/// named, and its dead ack has to leave the FIFO.
#[test]
fn a_dropped_settings_change_is_reported_and_keeps_the_queue_aligned() {
    let mut t = TestApp::new();
    t.app
        .send(ClientMsg::ConfigSet(runtime_config(30, Verdict::Deny)));
    t.sent();
    t.feed(UiEvent::SendFailed {
        msg: ClientMsg::ConfigSet(runtime_config(30, Verdict::Deny)),
    });
    assert!(
        t.app.pending_ack_kinds().is_empty(),
        "the dead ack was left queued"
    );
    assert!(
        t.app
            .last_error
            .as_deref()
            .is_some_and(|e| e.contains("settings change")),
        "{:?}",
        t.app.last_error
    );
}

/// Everything in flight dies with the connection: acks that will never
/// arrive, and a save whose answer is gone. The form keeps what was typed.
#[test]
fn a_lost_connection_clears_what_cannot_survive_it() {
    let mut t = TestApp::new();
    t.editor_awaiting_ack();

    t.feed(UiEvent::Disconnected {
        retry_in: Duration::from_secs(1),
        denied: false,
    });
    assert!(t.app.pending_ack_kinds().is_empty());
    let editor = t.app.editor.as_ref().expect("the form survives");
    assert!(!editor.awaiting_ack(), "nothing is coming to answer it");
}

/// Subscribe has to be sent before the history request, or events decided
/// between the two are in neither and vanish. Rules and stats prime the
/// views the window opens on. Never the prompt slot: that is the agent's,
/// and a window claiming it would take prompts away from it.
#[test]
fn connecting_subscribes_before_asking_for_history() {
    let mut t = TestApp::new();
    t.feed(UiEvent::Connected);
    assert_eq!(
        t.sent(),
        vec![
            ClientMsg::Subscribe {
                events: true,
                prompts: false,
            },
            ClientMsg::RuleList,
            ClientMsg::Stats,
            ClientMsg::ConfigGet,
            ClientMsg::EventHistory {
                limit: EVENT_HISTORY_LIMIT,
            },
        ]
    );
    // Only Subscribe is acked; the other three are answered with data.
    assert_eq!(t.app.pending_ack_kinds(), vec![AckKind::Other]);
}

/// Prompt traffic reaching this window (a daemon that sent it anyway, or a
/// mistake on either side) is left alone: the window never answers,
/// reclaims or reports on a slot it does not hold.
#[test]
fn prompt_messages_are_left_to_the_agent() {
    let mut t = TestApp::new();
    t.feed(UiEvent::Connected);
    t.sent();
    t.daemon(prompt_request(1, "/usr/bin/curl"));
    t.daemon(DaemonMsg::PromptExpired { id: 1 });
    t.daemon(DaemonMsg::PromptHandlerRevoked);
    assert!(t.sent().is_empty());
    assert!(t.app.last_error.is_none());
}

// ---- the event feed (5c2c1a8) --------------------------------------------

/// Every reconnect asks for history again, and a daemon that did not
/// restart still holds everything this client already has. Appending it a
/// second time duplicated rows in the feed and inflated every count in the
/// traffic view, which rebuilds from this ring each frame.
#[test]
fn a_replayed_history_is_not_counted_twice() {
    let mut t = TestApp::new();
    let history = vec![
        event("/usr/bin/curl", "1.1.1.1:443", 1_000),
        event("/usr/bin/curl", "1.1.1.2:443", 2_000),
        event("/usr/bin/wget", "1.1.1.3:80", 3_000),
    ];
    t.daemon(DaemonMsg::Events(history.clone()));
    assert_eq!(t.app.events.len(), 3);

    t.daemon(DaemonMsg::Events(history));
    assert_eq!(t.app.events.len(), 3, "the backfill was appended twice");
    let agg = traffic::Aggregate::rebuild(t.app.filtered(), traffic::GroupBy::Exe);
    assert_eq!(agg.total, 3, "the traffic view double-counted the replay");
}

/// The live stream and the backfill overlap by design: the subscription is
/// sent first so nothing is lost in between, which means the history reply
/// can contain what already arrived live.
#[test]
fn a_live_event_is_not_re_added_by_the_backfill() {
    let mut t = TestApp::new();
    let live = event("/usr/bin/curl", "1.1.1.1:443", 1_000);
    let later = event("/usr/bin/curl", "1.1.1.2:443", 2_000);
    t.daemon(DaemonMsg::Event(live.clone()));
    t.daemon(DaemonMsg::Events(vec![live, later]));
    assert_eq!(t.app.events.len(), 2);
}

/// The other order: the daemon writes the history reply ahead of pushed
/// events already queued for this client, so an event the backfill holds
/// can arrive live after it. It is shown once.
#[test]
fn a_live_event_the_backfill_already_held_is_not_added_again() {
    let mut t = TestApp::new();
    let first = event("/usr/bin/curl", "1.1.1.1:443", 1_000);
    let queued = event("/usr/bin/curl", "1.1.1.2:443", 2_000);
    t.daemon(DaemonMsg::Events(vec![first, queued.clone()]));
    t.daemon(DaemonMsg::Event(queued.clone()));
    assert_eq!(
        t.app.events.len(),
        2,
        "the queued live copy was added again"
    );
    // Only once: a later decision on the same key is a new one.
    t.daemon(DaemonMsg::Event(queued));
    assert_eq!(t.app.events.len(), 3);
}

/// Replay detection must not swallow genuinely distinct decisions. Identity
/// is the decision itself: when it happened, which flow, and what was
/// decided.
#[test]
fn distinct_decisions_are_not_mistaken_for_replays() {
    let base = event("/usr/bin/curl", "1.1.1.1:443", 1_000);
    let mut later = base.clone();
    later.unix_ms = 1_001;
    let mut denied = base.clone();
    denied.verdict = Verdict::Deny;
    let mut other_flow = base.clone();
    other_flow.conn.tuple.src = "10.0.0.1:40001".parse().expect("source address");

    let mut t = TestApp::new();
    t.daemon(DaemonMsg::Events(vec![base, later, denied, other_flow]));
    assert_eq!(t.app.events.len(), 4);
}

/// Events are attacker-feedable at line rate, so the feed is capped and the
/// oldest goes rather than the window growing.
#[test]
fn the_feed_evicts_the_oldest_event() {
    let mut t = TestApp::new();
    let overflow = 50;
    let mut ev = event("/usr/bin/curl", "1.1.1.1:443", 0);
    for i in 0..(MAX_EVENTS + overflow) as u64 {
        ev.unix_ms = 1_000 + i;
        t.daemon(DaemonMsg::Event(ev.clone()));
    }
    assert_eq!(t.app.events.len(), MAX_EVENTS);
    assert_eq!(
        t.app.events.front().expect("a full feed").unix_ms,
        1_000 + overflow as u64,
        "the surviving window is the newest one"
    );
    assert_eq!(
        t.app.events.back().expect("a full feed").unix_ms,
        1_000 + (MAX_EVENTS + overflow - 1) as u64
    );
}

/// The feed and the traffic view fold the same filtered iterator, so a row
/// count and the rows themselves cannot disagree. The filter is checked
/// against every field the operator can see.
#[test]
fn the_filter_selects_across_exe_domain_rule_and_destination() {
    let mut t = TestApp::new();
    let mut by_domain = event("/usr/bin/firefox", "93.184.216.34:443", 2_000);
    by_domain.conn.domain = Some("example.org".to_string());
    let mut by_rule = event("/usr/bin/wget", "10.0.0.9:80", 3_000);
    by_rule.rule_name = Some("allow-web".to_string());
    t.daemon(DaemonMsg::Events(vec![
        event("/usr/bin/curl", "1.1.1.1:443", 1_000),
        by_domain,
        by_rule,
    ]));

    assert_eq!(
        t.app.filtered().count(),
        3,
        "an empty filter keeps everything"
    );
    for (needle, expected) in [
        ("curl", 1),
        ("EXAMPLE.ORG", 1),
        ("allow-web", 1),
        ("10.0.0.9", 1),
        ("/usr/bin/", 3),
        ("nothing-matches-this", 0),
    ] {
        t.app.filter = needle.to_string();
        assert_eq!(t.app.filtered().count(), expected, "filter {needle:?}");
        let agg = traffic::Aggregate::rebuild(t.app.filtered(), traffic::GroupBy::Exe);
        assert_eq!(
            agg.total as usize, expected,
            "the traffic view disagreed with the feed on {needle:?}"
        );
    }
}

/// The outcome lens narrows the same iterator the text filter does, and
/// composes with it: the feed and the traffic view have to agree on what
/// is on screen whichever of the two is doing the narrowing.
///
/// "Blocked" is deny and reject whether or not enforcement applied them.
/// In observe mode the interesting rows are precisely the decisions that
/// were recorded and let through anyway, and a lens that hid them would
/// answer "show me what is being stopped" with an empty screen on the one
/// host where the question is urgent.
#[test]
fn the_lens_narrows_by_outcome_and_composes_with_the_filter() {
    let mut t = TestApp::new();
    let decided = |exe: &str, verdict: Verdict, enforced: bool, ms: u64| ConnEvent {
        verdict,
        enforced,
        ..event(exe, "1.1.1.1:443", ms)
    };
    t.daemon(DaemonMsg::Events(vec![
        decided("/usr/bin/curl", Verdict::Allow, true, 1_000),
        decided("/usr/bin/curl", Verdict::Deny, true, 2_000),
        decided("/usr/bin/wget", Verdict::Reject, false, 3_000),
    ]));

    for (lens, expected) in [(Lens::All, 3), (Lens::Allowed, 1), (Lens::Blocked, 2)] {
        t.app.lens = lens;
        assert_eq!(t.app.filtered().count(), expected, "lens {lens:?}");
        let agg = traffic::Aggregate::rebuild(t.app.filtered(), traffic::GroupBy::Exe);
        assert_eq!(
            agg.total as usize, expected,
            "the traffic view disagreed with the feed under {lens:?}"
        );
    }

    // Both narrowings apply, not the last one set.
    t.app.lens = Lens::Blocked;
    t.app.filter = "wget".to_string();
    assert_eq!(t.app.filtered().count(), 1);
}

// ---- what the window claims about enforcement (5c2c1a8) ------------------

/// The banner is the only signal an operator gets that nothing is being
/// blocked, so it must never be shown on a guess. Before the first stats
/// reply there is nothing to report, and a daemon that cannot be reached
/// has reported nothing either.
#[test]
fn observe_mode_is_not_announced_before_the_daemon_says_so() {
    let mut t = TestApp::new();
    assert!(
        !t.app.observe_banner(),
        "announced observe mode with no answer from the daemon"
    );

    t.feed(UiEvent::Disconnected {
        retry_in: Duration::from_secs(1),
        denied: false,
    });
    assert!(
        !t.app.observe_banner(),
        "announced observe mode on a daemon it never reached"
    );

    // A reply only ever arrives on a live connection, so the connect comes
    // first here as it does on the wire.
    t.feed(UiEvent::Connected);
    t.daemon(DaemonMsg::Stats(stats(true)));
    assert!(!t.app.observe_banner(), "the daemon is enforcing");

    t.daemon(DaemonMsg::Stats(stats(false)));
    assert!(
        t.app.observe_banner(),
        "the daemon said it is not enforcing"
    );

    // And it goes away again with the connection it was said on, rather than
    // describing a daemon this window can no longer reach.
    t.feed(UiEvent::Disconnected {
        retry_in: Duration::from_secs(1),
        denied: false,
    });
    assert!(
        !t.app.observe_banner(),
        "kept announcing observe mode after losing the daemon that said it"
    );
}

/// The corner mark and window icon must never claim enforcement the window
/// cannot vouch for: before the first stats reply nothing has been said,
/// and a window that has lost the socket does not know whether what it
/// last saw still holds.
#[test]
fn the_mark_never_claims_enforcement_it_cannot_vouch_for() {
    let mut t = TestApp::new();
    assert_eq!(
        t.app.tray_state(),
        TrayState::Unknown,
        "claimed a state with no answer from the daemon"
    );

    t.feed(UiEvent::Connected);
    assert_eq!(
        t.app.tray_state(),
        TrayState::Unknown,
        "connected is not the same as having been told"
    );

    t.daemon(DaemonMsg::Stats(stats(true)));
    assert_eq!(t.app.tray_state(), TrayState::Enforcing);

    t.daemon(DaemonMsg::Stats(stats(false)));
    assert_eq!(t.app.tray_state(), TrayState::Observing);

    // The mode it last saw is not evidence about a daemon it can no longer
    // reach: the posture may have changed, or the daemon may be gone.
    t.feed(UiEvent::Disconnected {
        retry_in: Duration::from_secs(1),
        denied: false,
    });
    assert_eq!(
        t.app.tray_state(),
        TrayState::Unknown,
        "vouched for a daemon it cannot reach"
    );
}

/// A reconnect must not restore the dead daemon's claim.
///
/// `enforcing` and `stats` deliberately survive a disconnect so the tabs keep
/// rendering the last known numbers, which is right for a display and wrong
/// for a claim. Gating on `ConnStatus` alone stopped covering them the
/// instant the socket came back, so the window re-asserted the previous
/// daemon's mode before the new one had said anything - and a daemon that
/// restarts into observe mode, or one that accepts the connection then wedges
/// before answering, would be drawn as enforcing for as long as that lasted.
#[test]
fn a_reconnect_does_not_restore_the_previous_daemons_mode() {
    let mut t = TestApp::new();
    t.feed(UiEvent::Connected);
    t.daemon(DaemonMsg::Stats(stats(true)));
    assert_eq!(t.app.tray_state(), TrayState::Enforcing);

    t.feed(UiEvent::Disconnected {
        retry_in: Duration::from_secs(1),
        denied: false,
    });
    assert_eq!(t.app.tray_state(), TrayState::Unknown);

    // Connected again, and nothing has answered yet.
    t.feed(UiEvent::Connected);
    assert_eq!(
        t.app.tray_state(),
        TrayState::Unknown,
        "claimed the dead daemon's mode the moment the socket came back"
    );

    // This daemon came up in observe mode, and that is what is shown.
    t.daemon(DaemonMsg::Stats(stats(false)));
    assert_eq!(t.app.tray_state(), TrayState::Observing);
}

/// The banners sit behind the same gate as the tray, so a posture that was
/// lifted while the window was away cannot come back with the connection.
#[test]
fn a_stale_posture_does_not_survive_a_reconnect() {
    let mut t = TestApp::new();
    t.feed(UiEvent::Connected);

    let mut locked = stats(true);
    locked.lockdown = Some(hallpass_types::Lockdown {
        tags: vec!["prod".into()],
        since_ms: hallpass_types::unix_ms_now(),
        rules_suppressed: 3,
    });
    t.daemon(DaemonMsg::Stats(locked));
    assert!(t.app.lockdown_banner().is_some());

    t.feed(UiEvent::Disconnected {
        retry_in: Duration::from_secs(1),
        denied: false,
    });
    t.feed(UiEvent::Connected);
    assert!(
        t.app.lockdown_banner().is_none(),
        "a posture from the previous daemon came back with the connection"
    );
    assert_eq!(t.app.tray_state(), TrayState::Unknown);
}

/// The same ordering the banners use, for the same reason: a posture
/// overrides the stored mode, so a locked-down host with a stored observe
/// mode is locked down. Drawing it as "nothing is being blocked" would be
/// the exact inversion of what that host is doing.
#[test]
fn a_posture_outranks_the_stored_mode_in_the_tray() {
    let mut t = TestApp::new();
    t.feed(UiEvent::Connected);

    let mut locked = stats(false);
    locked.lockdown = Some(hallpass_types::Lockdown {
        tags: vec!["prod".into()],
        since_ms: hallpass_types::unix_ms_now(),
        rules_suppressed: 3,
    });
    t.daemon(DaemonMsg::Stats(locked));

    assert_eq!(t.app.tray_state(), TrayState::Lockdown);
    assert!(
        !t.app.observe_banner(),
        "the tray and the banner must not disagree about the same host"
    );
}

/// The window takes no prompts, so it is the one place that must say when
/// nobody does: only when this daemon has answered, only when it would
/// prompt at all, and never once the slot is held.
#[test]
fn the_window_says_when_nobody_takes_prompts() {
    let mut t = TestApp::new();
    let mut unhandled = stats(true);
    unhandled.prompt_handler_connected = false;
    t.daemon(DaemonMsg::Stats(unhandled.clone()));
    assert!(t.app.no_handler_banner().is_none(), "not connected yet");

    t.feed(UiEvent::Connected);
    t.daemon(DaemonMsg::Stats(unhandled.clone()));
    let text = t.app.no_handler_banner().expect("nobody takes prompts");
    assert!(text.contains("default verdict"), "{text}");

    let mut observing = unhandled.clone();
    observing.enforcing = false;
    t.daemon(DaemonMsg::Stats(observing));
    assert!(
        t.app.no_handler_banner().is_none(),
        "observe mode never prompts"
    );

    let mut locked = unhandled.clone();
    locked.lockdown = Some(hallpass_types::Lockdown {
        tags: vec!["prod".into()],
        since_ms: hallpass_types::unix_ms_now(),
        rules_suppressed: 3,
    });
    t.daemon(DaemonMsg::Stats(locked));
    assert!(
        t.app.no_handler_banner().is_none(),
        "a posture denies without prompting"
    );

    t.daemon(DaemonMsg::Stats(unhandled.clone()));
    t.feed(UiEvent::Disconnected {
        retry_in: Duration::from_secs(1),
        denied: false,
    });
    t.feed(UiEvent::Connected);
    assert!(
        t.app.no_handler_banner().is_none(),
        "the previous daemon's slot says nothing about this one's"
    );

    let mut handled = unhandled;
    handled.prompt_handler_connected = true;
    t.daemon(DaemonMsg::Stats(handled));
    assert!(t.app.no_handler_banner().is_none());
}

/// An agent this window started that exits while nobody holds the slot
/// says so beside the button, rather than the button silently coming back.
#[test]
fn an_agent_that_exits_without_the_slot_says_so() {
    let mut t = TestApp::new();
    t.feed(UiEvent::Connected);
    t.daemon(DaemonMsg::Stats(stats(true)));
    assert!(t.app.no_handler_banner().is_some());

    let mut child = std::process::Command::new("false")
        .spawn()
        .expect("spawn false");
    child.wait().expect("wait for false");
    t.app.agent = Some((child, std::time::Instant::now()));
    t.app.reap_agent();

    assert!(t.app.agent.is_none(), "the button comes back");
    let note = t.app.agent_error.as_deref().expect("the exit is reported");
    assert!(note.contains("stopped"), "{note}");
}

/// Opening the window with nobody taking prompts starts the agent, once
/// per retry period, and not while the daemon has not answered or someone
/// already holds the slot.
#[test]
fn the_window_starts_the_agent_when_nobody_takes_prompts() {
    let mut t = TestApp::new();
    assert!(!t.app.wants_agent(), "nothing known yet");
    t.feed(UiEvent::Connected);
    let mut handled = stats(true);
    handled.prompt_handler_connected = true;
    t.daemon(DaemonMsg::Stats(handled));
    assert!(!t.app.wants_agent(), "the slot is held");

    t.daemon(DaemonMsg::Stats(stats(true)));
    assert!(
        !t.app.wants_agent(),
        "the slot was held when the window opened: a free one now is a Quit, or \
         an agent reconnecting, not the window's to fill"
    );

    let mut t = TestApp::new();
    t.feed(UiEvent::Connected);
    t.daemon(DaemonMsg::Stats(stats(true)));
    assert!(t.app.wants_agent(), "nobody took prompts when it opened");
    t.app.agent_started = Some(std::time::Instant::now());
    assert!(!t.app.wants_agent(), "not again within the retry period");
}

/// An agent quit from its tray stays quit while the window is open.
#[test]
fn a_quit_agent_is_not_started_again() {
    let mut t = TestApp::new();
    t.feed(UiEvent::Connected);
    t.daemon(DaemonMsg::Stats(stats(true)));
    let mut child = std::process::Command::new("true")
        .spawn()
        .expect("spawn true");
    child.wait().expect("wait for true");
    t.app.agent = Some((child, std::time::Instant::now()));
    t.app.reap_agent();
    t.app.agent_started = None;
    assert!(!t.app.wants_agent());
}

/// An agent stopped with a signal meant to stop it (an upgrade replacing
/// it, `kill`) is not a crash: restarting it would run this window's own,
/// possibly older, image against the one that replaced it.
#[test]
fn a_stopped_agent_is_not_started_again() {
    let mut t = TestApp::new();
    t.feed(UiEvent::Connected);
    t.daemon(DaemonMsg::Stats(stats(true)));
    let mut child = std::process::Command::new("sh")
        .args(["-c", "kill -TERM $$"])
        .spawn()
        .expect("spawn sh");
    child.wait().expect("wait for sh");
    t.app.agent = Some((child, std::time::Instant::now()));
    t.app.reap_agent();
    assert!(!t.app.wants_agent());
    let note = t.app.agent_error.as_deref().expect("the exit is reported");
    assert!(note.contains("stopped"), "{note}");
}

/// How long the slot has been free is a fact about one daemon: a reconnect
/// starts the count again, so an agent reconnecting too gets its grace.
#[test]
fn a_reconnect_restarts_the_free_slot_count() {
    let mut t = TestApp::new();
    t.feed(UiEvent::Connected);
    t.daemon(DaemonMsg::Stats(stats(true)));
    assert!(t.app.slot_free_since.is_some());
    t.feed(UiEvent::Disconnected {
        retry_in: Duration::from_secs(1),
        denied: false,
    });
    t.feed(UiEvent::Connected);
    assert!(t.app.slot_free_since.is_none());
}

/// A window on the read-only socket starts no agent: one there could never
/// take the slot, and would outlive the window retrying for good. The
/// banner says why instead.
#[test]
fn a_window_on_the_read_only_socket_starts_no_agent() {
    let mut t = TestApp::new();
    t.app.socket = std::path::PathBuf::from("/run/hallpass/observe.sock");
    t.feed(UiEvent::Connected);
    t.daemon(DaemonMsg::Stats(stats(true)));
    assert!(t.app.no_handler_banner().is_some());
    assert!(!t.app.wants_agent());
}

/// An agent that found another running is not reported while the other may
/// still be taking the slot, and no second one is started meanwhile.
#[test]
fn an_agent_already_running_is_judged_after_the_grace() {
    let mut t = TestApp::new();
    t.feed(UiEvent::Connected);
    t.daemon(DaemonMsg::Stats(stats(true)));

    let mut child = std::process::Command::new("sh")
        .args(["-c", &format!("exit {}", crate::agent::ALREADY_RUNNING)])
        .spawn()
        .expect("spawn sh");
    child.wait().expect("wait for sh");
    t.app.agent = Some((child, std::time::Instant::now()));
    t.app.reap_agent();
    assert!(t.app.agent.is_some(), "held through the grace");
    assert!(t.app.agent_error.is_none(), "nothing said yet");
    assert!(!t.app.wants_agent(), "and no second one started");

    // Backdated, where the clock allows it (see `with_channels`).
    let Some(started) = std::time::Instant::now().checked_sub(AGENT_GRACE) else {
        return;
    };
    if let Some((_, at)) = t.app.agent.as_mut() {
        *at = started;
    }
    t.app.reap_agent();
    assert!(t.app.agent.is_none());
    let note = t.app.agent_error.as_deref().expect("the exit is reported");
    assert!(note.contains("already running"), "{note}");
}

/// A session that predates the account's group membership is told what to
/// do, since reconnecting forever will not fix it.
#[test]
fn a_refused_socket_is_remembered_until_a_connection_succeeds() {
    let mut t = TestApp::new();
    t.feed(UiEvent::Disconnected {
        retry_in: Duration::from_secs(1),
        denied: true,
    });
    assert!(t.app.denied);
    t.feed(UiEvent::Connected);
    assert!(!t.app.denied);
}

/// Opening a data tab refreshes what it shows, rather than rendering
/// whatever was current when the window last asked. The traffic tab reads
/// the enforcement flag for its wording, so it refreshes the stats too.
#[test]
fn opening_a_data_tab_refetches_it() {
    let mut t = TestApp::new();
    for (tab, expected) in [
        (Tab::Rules, vec![ClientMsg::RuleList]),
        (Tab::Traffic, vec![ClientMsg::Stats]),
        (Tab::Stats, vec![ClientMsg::Stats]),
        (Tab::Settings, vec![ClientMsg::ConfigGet]),
        (Tab::Events, vec![]),
    ] {
        t.app.select_tab(tab);
        assert_eq!(t.sent(), expected, "opening {tab:?}");
        t.app.select_tab(tab);
        assert!(t.sent().is_empty(), "reselecting {tab:?} refetched again");
    }
}

// ---- runtime settings ----------------------------------------------------

/// A Config reply is what fills the settings form, drafts included: the
/// form shows what the daemon holds, never a guess.
#[test]
fn a_config_reply_fills_the_settings_form() {
    let mut t = TestApp::new();
    assert!(
        t.app.daemon_config.is_none(),
        "no values before the daemon speaks"
    );
    t.daemon(DaemonMsg::Config(runtime_config(30, Verdict::Deny)));
    assert_eq!(t.app.daemon_config, Some(runtime_config(30, Verdict::Deny)));
    assert_eq!(t.app.settings_timeout, "30");
    assert_eq!(t.app.settings_verdict, Verdict::Deny);
}

/// An accepted settings change re-reads the settings, so the form settles
/// on what the daemon actually holds; a refused one does the same and puts
/// the daemon's complaint next to the Apply that retries it, not in the
/// status bar.
#[test]
fn a_settings_ack_reconciles_by_refetching() {
    for (outcome, expect_err) in [(DaemonMsg::Ok, false), (err("out of range"), true)] {
        let mut t = TestApp::new();
        t.app
            .send(ClientMsg::ConfigSet(runtime_config(30, Verdict::Deny)));
        t.sent();
        t.daemon(outcome);
        assert_eq!(t.sent(), vec![ClientMsg::ConfigGet], "err={expect_err}");
        assert_eq!(t.app.settings_error.is_some(), expect_err);
        assert!(
            t.app.last_error.is_none(),
            "a settings rejection belongs in the settings tab"
        );
        assert!(t.app.pending_ack_kinds().is_empty());
    }
}

// ---- replies this client does not ask for --------------------------------

/// Rule hits and explanations are answers to requests the window never
/// makes. Ignoring them keeps the connection alive; the alternative on an
/// unexpected reply is tearing down the stream the whole window runs on.
#[test]
fn unrequested_replies_are_ignored_rather_than_fatal() {
    let mut t = TestApp::new();
    t.daemon(DaemonMsg::RuleHits(Vec::new()));
    t.daemon(DaemonMsg::HelloAck { version: 3 });
    assert!(t.sent().is_empty());
    assert!(t.app.last_error.is_none());
    assert!(t.app.pending_ack_kinds().is_empty());
}

// ---- display helpers -----------------------------------------------------

#[test]
fn uptime_formatting() {
    assert_eq!(format_uptime(0), "0m");
    assert_eq!(format_uptime(3661), "1h 01m");
    assert_eq!(format_uptime(86400), "1d 0h 00m");
    assert_eq!(
        format_uptime(3 * 86400 + 4 * 3600 + 17 * 60 + 9),
        "3d 4h 17m"
    );
}

#[test]
fn grouped_counts() {
    assert_eq!(grouped(0), "0");
    assert_eq!(grouped(999), "999");
    assert_eq!(grouped(1000), "1,000");
    assert_eq!(grouped(3_900_112), "3,900,112");
    assert_eq!(grouped(u64::MAX), "18,446,744,073,709,551,615");
}

/// The word the rules table and the settings picker show for a verdict.
#[test]
fn labels() {
    assert_eq!(Verdict::Reject.as_str(), "reject");
}

/// An unenforced deny is amber, not red: nothing was stopped, and colouring
/// it like a block would say the opposite of what happened.
#[test]
fn an_unenforced_block_is_not_coloured_as_one() {
    let mut ev = event("/usr/bin/curl", "1.1.1.1:443", 1_000);
    ev.verdict = Verdict::Deny;
    ev.enforced = false;
    assert_eq!(event_color(&ev), REJECT_COLOR);
    ev.enforced = true;
    assert_eq!(event_color(&ev), DENY_COLOR);
    // Allow is allow either way: observe mode changes nothing about it.
    ev.verdict = Verdict::Allow;
    assert_eq!(event_color(&ev), ALLOW_COLOR);
    ev.enforced = false;
    assert_eq!(event_color(&ev), ALLOW_COLOR);
}

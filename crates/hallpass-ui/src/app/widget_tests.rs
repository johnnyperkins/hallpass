//! Tests of properties that need a real widget tree.
//!
//! Two kinds live here, and nothing else should. First, layout as a security
//! property: which button keyboard traversal reaches first in the prompt
//! window. Second, the paths that only exist because a widget was operated -
//! a window closed, a checkbox clicked, Quit pressed - where the thing worth
//! proving is that the operation reaches the state logic at all.
//!
//! `egui_kittest` reads the AccessKit tree, so none of this needs a GPU or a
//! display. Everything downstream of these entry points is cheaper to test as
//! state; see the sibling `tests` module.

use egui_kittest::kittest::{NodeT as _, Queryable as _};
use egui_kittest::Harness;

use super::tests::{conn, drain, runtime_config};
use super::*;

/// A prompt plus what its buttons answered, so a test can read the reply
/// back out from behind the harness.
struct PromptFixture {
    prompt: PromptState,
    answered: Vec<(u64, ClientMsg)>,
}

/// Fixed rather than wall clock: the countdown is display-only here, and a
/// real clock would make the progress bar (and so the frame) differ per run.
const NOW_MS: u64 = 1_700_000_000_000;

const EXE: &str = "/usr/bin/curl";

/// One prompt window's body, laid out on its own the way its viewport shows
/// it.
fn prompt_harness() -> Harness<'static, PromptFixture> {
    let state = PromptFixture {
        prompt: PromptState::new(1, conn(EXE, "93.184.216.34:443"), NOW_MS + 30_000, NOW_MS),
        answered: Vec::new(),
    };
    Harness::builder()
        .with_size(egui::vec2(440.0, 330.0))
        .build_ui_state(
            |ui, state: &mut PromptFixture| {
                prompt_ui(ui, &mut state.prompt, NOW_MS, &[], &mut state.answered);
            },
            state,
        )
}

/// An app holding `count` prompts from one application, plus the receiver
/// the network thread would read.
fn app_with_prompts(count: u64) -> (HallpassApp, tokio::sync::mpsc::UnboundedReceiver<ClientMsg>) {
    let (to_daemon, from_ui) = tokio::sync::mpsc::unbounded_channel();
    let (_to_ui, from_net) = std::sync::mpsc::channel();
    let app = HallpassApp::with_channels(to_daemon, from_net);
    // Real deadlines: the window drops prompts the daemon has already timed
    // out, and it reads the clock to do it.
    let now = hallpass_types::unix_ms_now();
    app.prompts.lock().unwrap().pending = (1..=count)
        .map(|id| PromptState::new(id, conn(EXE, &format!("1.1.1.{id}:443")), now + 30_000, now))
        .collect();
    (app, from_ui)
}

/// The buttons must survive the worst content the window can carry: a
/// path at its display cap, a command line at its cap, the full pending
/// list, and the App-anywhere warning, all inside the fixed 440x330
/// viewport. Every one of those strings is chosen by the process being
/// judged, so "the info pushed Allow and Deny off the window" is an
/// unanswerable prompt an adversary can construct; the actions are pinned
/// to a bottom panel and the info scrolls, and this clicks Deny through
/// exactly that worst case to prove it stays reachable.
#[test]
fn buttons_survive_worst_case_content() {
    let mut state = PromptFixture {
        prompt: PromptState::new(
            1,
            conn(&format!("/very/long/{}/curl", "x".repeat(180)), "93.184.216.34:443"),
            NOW_MS + 30_000,
            NOW_MS,
        ),
        answered: Vec::new(),
    };
    state.prompt.conn.cmdline = Some(format!("curl {}", "a".repeat(200)));
    state.prompt.scope = PromptScope::AppAnywhere; // adds the warning label
    let rest: Vec<String> = (0..9).map(|i| format!("tcp 10.0.0.{i}:443")).collect();
    let mut harness = Harness::builder()
        .with_size(egui::vec2(440.0, 330.0))
        .build_ui_state(
            move |ui, state: &mut PromptFixture| {
                prompt_ui(ui, &mut state.prompt, NOW_MS, &rest, &mut state.answered);
            },
            state,
        );
    harness.get_by_label("Deny").click();
    harness.run();
    let expected = harness.state().prompt.reply(Verdict::Deny);
    assert_eq!(
        harness.state().answered,
        vec![(1, expected)],
        "Deny was not clickable under worst-case content"
    );
}

/// Deny has to be what keyboard traversal reaches first.
///
/// This window steals focus from whatever the operator was doing, and the
/// answer given without reading it has to be the recoverable one: a wrong
/// deny costs a retry, a wrong allow costs the connection the prompt existed
/// to stop. Widget order is traversal order in egui, so this is a property
/// of the laid-out tree and nothing else.
#[test]
fn deny_leads_keyboard_traversal() {
    let mut harness = prompt_harness();
    let mut reached = Vec::new();
    for _ in 0..8 {
        harness.key_press(egui::Key::Tab);
        harness.run();
        for label in ["Deny", "Allow"] {
            if harness.get_by_label(label).accesskit_node().is_focused() {
                reached.push(label);
            }
        }
        // Traversal wraps, so stop once both have been seen or the order
        // gets recorded twice.
        if reached.len() == 2 {
            break;
        }
    }
    assert_eq!(
        reached.first().copied(),
        Some("Deny"),
        "tab order reached {reached:?}"
    );
    assert!(
        reached.contains(&"Allow"),
        "traversal must still reach Allow: {reached:?}"
    );
}

/// The reorder above moves the buttons past each other, so the wiring is
/// worth pinning: each button answers with its own verdict, carrying the
/// duration and scope the operator picked.
#[test]
fn each_button_answers_with_its_own_verdict() {
    for (label, verdict) in [("Deny", Verdict::Deny), ("Allow", Verdict::Allow)] {
        let mut harness = prompt_harness();
        harness.get_by_label(label).click();
        harness.run();
        let expected = harness.state().prompt.reply(verdict);
        assert_eq!(
            harness.state().answered,
            vec![(1, expected)],
            "{label} answered with the wrong verdict"
        );
    }
}

/// Closing the window reaches the dismissal, and reaches it for every prompt
/// the window covers rather than only the one on show. What dismissal means
/// is `dismiss_prompts`, tested as state.
#[test]
fn closing_the_window_dismisses_every_prompt_it_covers() {
    let (app, mut from_ui) = app_with_prompts(3);
    let mut harness = Harness::builder()
        .with_size(egui::vec2(600.0, 500.0))
        .build_ui_state(|ui, app: &mut HallpassApp| app.prompt_windows(ui.ctx()), app);
    // One window, really on screen, for all three: the front prompt names
    // the application and the other two are listed as pending.
    harness.get_by_label(EXE);
    harness.get_by_label_contains("2 more request(s) pending");

    // Under a test backend egui embeds child viewports in the root one, so
    // the close arrives on the root's info; a single group keeps that
    // faithful to one window being closed.
    harness
        .input_mut()
        .viewports
        .entry(egui::ViewportId::ROOT)
        .or_default()
        .events
        .push(egui::ViewportEvent::Close);
    harness.step();

    assert_eq!(
        drain(&mut from_ui),
        (1..=3).map(prompt::close_reply).collect::<Vec<_>>(),
        "a closed window left prompts for the daemon's default verdict"
    );
    assert!(harness.state().prompt_ids().is_empty());
}

/// Quitting abandons every prompt on screen, so it answers them for the same
/// reason closing one window does. Best effort by nature - the process may
/// exit before the network thread writes the replies - but the queue must
/// hold them, or the one certain outcome is the daemon's default verdict.
#[test]
fn quitting_denies_the_prompts_left_on_screen() {
    let (app, mut from_ui) = app_with_prompts(2);
    let mut harness = Harness::builder()
        .with_size(egui::vec2(820.0, 520.0))
        .build_ui_state(|ui, app: &mut HallpassApp| app.main_window(ui), app);

    harness.get_by_label("Quit").click();
    harness.run();

    assert_eq!(
        drain(&mut from_ui),
        (1..=2).map(prompt::close_reply).collect::<Vec<_>>(),
        "quitting left prompts to the daemon's default verdict"
    );
    assert!(harness.state().prompt_ids().is_empty());
}

/// Apply in the settings tab sends the edited values to the daemon and
/// edits nothing locally: the displayed settings change when the daemon's
/// answer to the refetch lands, the same contract the rules tab keeps.
#[test]
fn settings_apply_asks_the_daemon_instead_of_editing_the_form() {
    let (mut app, mut from_ui) = app_with_prompts(0);
    app.tab = Tab::Settings;
    app.daemon_config = Some(runtime_config(15, Verdict::Allow));
    app.settings_timeout = "45".to_string();
    app.settings_verdict = Verdict::Deny;
    let mut harness = Harness::builder()
        .with_size(egui::vec2(820.0, 520.0))
        .build_ui_state(|ui, app: &mut HallpassApp| app.main_window(ui), app);

    harness.get_by_label("Apply").click();
    harness.run();

    assert_eq!(
        drain(&mut from_ui),
        vec![ClientMsg::ConfigSet(runtime_config(45, Verdict::Deny))]
    );
    assert_eq!(
        harness.state().daemon_config.map(|c| c.prompt_timeout_secs),
        Some(15),
        "the displayed settings change when the daemon's answer lands, not before"
    );
}

/// The rule editor's Save button stays reachable on a viewport far too
/// short for the full form: the window caps itself to the screen and the
/// form body scrolls, with Save pinned below the scroll area. Clicking
/// Save through that layout must still reach the form logic (here: the
/// empty-name parse error keeps the editor open and nothing is sent).
#[test]
fn editor_save_stays_reachable_on_a_short_viewport() {
    let (mut app, mut from_ui) = app_with_prompts(0);
    app.editor = Some(RuleEditor::add());
    let mut harness = Harness::builder()
        .with_size(egui::vec2(600.0, 240.0))
        .build_ui_state(|ui, app: &mut HallpassApp| app.editor_window(ui.ctx()), app);

    harness.get_by_label("Save").click();
    harness.run();

    assert!(
        harness.state().editor.is_some(),
        "the empty form was rejected client-side, so the editor stays open"
    );
    assert!(
        drain(&mut from_ui).is_empty(),
        "an invalid form must not reach the daemon"
    );
}

/// The main window's close button quits like Quit does: the prompts still
/// on screen are denied-once rather than abandoned to the daemon's timeout,
/// and the close is not cancelled. (It used to hide the window instead; the
/// user experienced that as the close button not working.)
#[test]
fn closing_the_main_window_quits_and_answers_open_prompts() {
    let (app, mut from_ui) = app_with_prompts(2);
    let mut harness = Harness::builder()
        .with_size(egui::vec2(820.0, 520.0))
        .build_ui_state(|ui, app: &mut HallpassApp| app.main_window(ui), app);

    harness
        .input_mut()
        .viewports
        .entry(egui::ViewportId::ROOT)
        .or_default()
        .events
        .push(egui::ViewportEvent::Close);
    harness.step();

    assert_eq!(
        drain(&mut from_ui),
        (1..=2).map(prompt::close_reply).collect::<Vec<_>>(),
        "closing the window left prompts to the daemon's default verdict"
    );
    assert!(harness.state().prompt_ids().is_empty());
}

/// The checkbox in the rules list asks the daemon; it does not edit the row.
/// A refused toggle would otherwise leave the operator believing a rule is
/// off while it is still enforced, which claims less enforcement than there
/// is. The row only changes when the daemon's answer to the refetch lands.
#[test]
fn toggling_a_rule_asks_the_daemon_instead_of_editing_the_row() {
    let (to_daemon, mut from_ui) = tokio::sync::mpsc::unbounded_channel();
    let (_to_ui, from_net) = std::sync::mpsc::channel();
    let mut app = HallpassApp::with_channels(to_daemon, from_net);
    app.tab = Tab::Rules;
    app.rules = vec![hallpass_types::Rule {
        name: "block-telemetry".to_string(),
        action: hallpass_types::Action::Deny,
        duration: RuleDuration::Forever,
        priority: 10,
        enabled: true,
        matcher: hallpass_types::RuleMatch {
            port: Some(443),
            ..Default::default()
        },
    }];
    let mut harness = Harness::builder()
        .with_size(egui::vec2(820.0, 520.0))
        .build_ui_state(|ui, app: &mut HallpassApp| app.main_window(ui), app);

    harness
        .get_by_role(egui::accesskit::Role::CheckBox)
        .click();
    harness.run();

    assert_eq!(
        drain(&mut from_ui),
        vec![ClientMsg::RuleToggle {
            name: "block-telemetry".to_string(),
            enabled: false,
        }]
    );
    assert!(
        harness.state().rules[0].enabled,
        "the row was edited before the daemon agreed to it"
    );
}

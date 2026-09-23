//! Tests of properties that need a real widget tree: the paths that only
//! exist because a widget was operated - a checkbox clicked, a heading
//! sorted, a form saved - where the thing worth proving is that the
//! operation reaches the state logic at all. The prompt window's layout
//! tests live beside it, in `prompt_view` and `prompt_window`.
//!
//! `egui_kittest` reads the AccessKit tree, so none of this needs a GPU or a
//! display. Everything downstream of these entry points is cheaper to test as
//! state; see the sibling `tests` module.

use egui_kittest::kittest::Queryable as _;
use egui_kittest::Harness;

use hallpass_types::RuleDuration;

use super::tests::{conn, drain, runtime_config};
use super::*;

const EXE: &str = "/usr/bin/curl";

/// An app plus the receiver the network thread would read.
fn app() -> (HallpassApp, tokio::sync::mpsc::UnboundedReceiver<ClientMsg>) {
    let (to_daemon, from_ui) = tokio::sync::mpsc::unbounded_channel();
    let (_to_ui, from_net) = std::sync::mpsc::channel();
    (HallpassApp::with_channels(to_daemon, from_net), from_ui)
}

/// Apply in the settings tab sends the edited values to the daemon and
/// edits nothing locally: the displayed settings change when the daemon's
/// answer to the refetch lands, the same contract the rules tab keeps.
#[test]
fn settings_apply_asks_the_daemon_instead_of_editing_the_form() {
    let (mut app, mut from_ui) = app();
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

/// The tab-bar mode switch asks the daemon and edits nothing locally, the
/// same contract as Apply above: the switch position is whatever the daemon
/// last reported, and it moves when the refetched config lands. Everything
/// else in the config must ride along unchanged - a toggle that also reset
/// the timeout would be a settings edit nobody made.
#[test]
fn the_mode_toggle_asks_the_daemon_instead_of_flipping_the_switch() {
    let (mut app, mut from_ui) = app();
    let cfg = runtime_config(45, Verdict::Deny);
    app.daemon_config = Some(cfg);
    let mut harness = Harness::builder()
        .with_size(egui::vec2(820.0, 520.0))
        .build_ui_state(|ui, app: &mut HallpassApp| app.main_window(ui), app);

    harness.get_by_label("Enforce").click();
    harness.run();

    assert_eq!(
        drain(&mut from_ui),
        vec![ClientMsg::ConfigSet(hallpass_types::RuntimeConfig {
            enforce: false,
            ..cfg
        })]
    );
    assert_eq!(
        harness.state().daemon_config.map(|c| c.enforce),
        Some(true),
        "the switch moves when the daemon's answer lands, not before"
    );
}

/// The rule editor's Save button stays reachable on a viewport far too
/// short for the full form: the window caps itself to the screen and the
/// form body scrolls, with Save pinned below the scroll area. Clicking
/// Save through that layout must still reach the form logic (here: the
/// empty-name parse error keeps the editor open and nothing is sent).
#[test]
fn editor_save_stays_reachable_on_a_short_viewport() {
    let (mut app, mut from_ui) = app();
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
        tags: Vec::new(),
        matcher: hallpass_types::RuleMatch {
            port: Some(443),
            ..Default::default()
        },
    }];
    let mut harness = Harness::builder()
        .with_size(egui::vec2(820.0, 520.0))
        .build_ui_state(|ui, app: &mut HallpassApp| app.main_window(ui), app);

    harness.get_by_role(egui::accesskit::Role::CheckBox).click();
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

/// The bulk buttons act on the selected tag, not on what the table happens
/// to be showing, and like the per-row checkbox they ask rather than edit.
/// They also only exist under a chosen tag: an "enable all" whose scope is
/// whatever is on screen is the kind of button that disables a host.
#[test]
fn the_bulk_buttons_act_on_the_selected_tag() {
    let (to_daemon, mut from_ui) = tokio::sync::mpsc::unbounded_channel();
    let (_to_ui, from_net) = std::sync::mpsc::channel();
    let mut app = HallpassApp::with_channels(to_daemon, from_net);
    app.tab = Tab::Rules;
    let tagged = |name: &str, tags: &[&str]| hallpass_types::Rule {
        name: name.to_string(),
        action: hallpass_types::Action::Deny,
        duration: RuleDuration::Forever,
        priority: 10,
        enabled: true,
        tags: tags.iter().map(|t| (*t).to_string()).collect(),
        matcher: hallpass_types::RuleMatch {
            port: Some(443),
            ..Default::default()
        },
    };
    app.rules = vec![tagged("w", &["work"]), tagged("plain", &[])];
    let mut harness = Harness::builder()
        .with_size(egui::vec2(820.0, 520.0))
        .build_ui_state(|ui, app: &mut HallpassApp| app.main_window(ui), app);
    harness.run();

    // No tag chosen: nothing that could act on a set is on screen.
    assert!(
        harness.query_by_label("Disable all").is_none(),
        "a bulk button with no set selected"
    );

    harness.state_mut().rule_tag_filter = Some("work".to_string());
    harness.run();
    harness.get_by_label("Disable all").click();
    harness.run();

    assert_eq!(
        drain(&mut from_ui),
        vec![ClientMsg::RuleToggleTag {
            tag: "work".to_string(),
            enabled: false,
        }]
    );
    assert!(
        harness.state().rules.iter().all(|r| r.enabled),
        "the rows were edited before the daemon agreed to it"
    );
}

/// The traffic headings sort the table, and a second click on the column
/// already sorted reverses it. The rows themselves are rebuilt from the
/// feed every frame, so what a click changes is this state and nothing
/// else.
#[test]
fn the_traffic_headings_sort_and_reverse() {
    let (to_daemon, mut from_ui) = tokio::sync::mpsc::unbounded_channel();
    let (_to_ui, from_net) = std::sync::mpsc::channel();
    let mut app = HallpassApp::with_channels(to_daemon, from_net);
    app.tab = Tab::Traffic;
    app.events.push_back(hallpass_types::ConnEvent {
        conn: conn(EXE, "93.184.216.34:443"),
        verdict: Verdict::Deny,
        rule_name: None,
        unix_ms: hallpass_types::unix_ms_now(),
        enforced: true,
    });
    let mut harness = Harness::builder()
        .with_size(egui::vec2(1040.0, 520.0))
        .build_ui_state(|ui, app: &mut HallpassApp| app.main_window(ui), app);

    assert_eq!(
        harness.state().traffic_sort,
        (crate::traffic::SortBy::Total, true),
        "busiest first is the default"
    );
    harness.get_by_label("BLOCKED").click();
    harness.run();
    assert_eq!(
        harness.state().traffic_sort,
        (crate::traffic::SortBy::Blocked, true),
        "a new column starts at the end that answers the question"
    );
    harness.get_by_label("BLOCKED").click();
    harness.run();
    assert_eq!(
        harness.state().traffic_sort,
        (crate::traffic::SortBy::Blocked, false),
        "the same column again reverses"
    );
    assert!(
        drain(&mut from_ui).is_empty(),
        "sorting is a local view change and asks the daemon nothing"
    );
}

/// A filter naming a tag no rule carries any more (its last rule was
/// deleted or retagged) must fall back to the whole list: an empty table
/// with no way back to it reads as a ruleset that lost its rules.
#[test]
fn a_filter_whose_tag_stopped_existing_resets() {
    let (to_daemon, mut from_ui) = tokio::sync::mpsc::unbounded_channel();
    let (_to_ui, from_net) = std::sync::mpsc::channel();
    let mut app = HallpassApp::with_channels(to_daemon, from_net);
    app.tab = Tab::Rules;
    app.rules = vec![hallpass_types::Rule {
        name: "w".to_string(),
        action: hallpass_types::Action::Deny,
        duration: RuleDuration::Forever,
        priority: 10,
        enabled: true,
        tags: vec!["work".to_string()],
        matcher: hallpass_types::RuleMatch {
            port: Some(443),
            ..Default::default()
        },
    }];
    app.rule_tag_filter = Some("gone".to_string());
    let mut harness = Harness::builder()
        .with_size(egui::vec2(820.0, 520.0))
        .build_ui_state(|ui, app: &mut HallpassApp| app.main_window(ui), app);
    harness.run();

    assert_eq!(harness.state().rule_tag_filter, None);
    assert!(
        drain(&mut from_ui).is_empty(),
        "resetting a filter asks nothing"
    );
}

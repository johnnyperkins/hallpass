//! What a prompt window draws: the connection being judged and the controls
//! that answer it.
//!
//! Rendering only. Which prompts a window holds, and where its answers go,
//! belong to whoever owns the window; this takes one prompt and reports
//! what its buttons answered.

use eframe::egui::{self, RichText};
use hallpass_types::{ClientMsg, PromptScope, RuleDuration, Verdict};

use crate::prompt::{self, PromptState};
use crate::theme::{self, Tone, ALLOW_COLOR, DENY_COLOR, MUTED, REJECT_COLOR, TEXT};

/// How many of the other pending prompts the list under the front one
/// names; the rest are counted. A prompt past this is not on screen.
pub(crate) const REST_SHOWN: usize = 5;

/// Body of a prompt window: the app's oldest pending prompt, plus
/// its other pending destinations (`rest`), which a host- or app-wide
/// answer will cover in the same stroke.
///
/// Split into a bottom action panel and a scrolling info body, in that
/// order, because the window is a fixed 440x330 and every info line
/// (path, command line, resolved names) is text the judged process
/// chose: stacked in one column, enough of it pushed Allow and Deny out
/// of the window, an unanswerable prompt an adversary can construct.
/// The panel is laid out first so the actions own their space no matter
/// how much the body wants, and the body scrolls inside what is left.
///
/// Returns this pass's answer, if a button gave one.
#[must_use = "a dropped answer is a click that never reaches the daemon"]
pub(crate) fn prompt_ui(
    ui: &mut egui::Ui,
    p: &mut PromptState,
    now_ms: u64,
    rest: &[String],
) -> Option<ClientMsg> {
    theme::ensure_installed(ui.ctx());
    // First pass with this prompt in front: restart the visible countdown
    // from now. Its deadline is unchanged (see PromptState::fronted_ms), so
    // this cannot delay the default verdict; it only stops a prompt that
    // queued behind another from surfacing with its bar already part-drained.
    // Stamped here rather than by whoever owns the window, because this view
    // is what reads it: a window that forgot would leave Allow disarmed for
    // good.
    if p.fronted_ms.is_none() {
        p.fronted_ms = Some(now_ms);
    }
    // Salted by prompt id like the details grid: two apps prompting at
    // once means two of these windows live in one pass, and their panels
    // must not collide on one id.
    let answer = egui::Panel::bottom(egui::Id::new(("prompt-actions", p.id)))
        .frame(
            egui::Frame::new()
                .fill(theme::SURFACE)
                .inner_margin(egui::Margin::symmetric(10, 8)),
        )
        .show_separator_line(false)
        .show(ui, |ui| prompt_actions_ui(ui, p, now_ms))
        .inner;
    egui::CentralPanel::default()
        .frame(
            egui::Frame::new()
                .fill(theme::BG)
                .inner_margin(egui::Margin::symmetric(10, 8)),
        )
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    prompt_info_ui(ui, p, rest);
                });
        });
    answer
}

/// The scrolling half: everything the operator reads to decide.
fn prompt_info_ui(ui: &mut egui::Ui, p: &PromptState, rest: &[String]) {
    let conn = &p.conn;
    // Read once and used by both the badge and the details row below, so
    // "the badge and the row always say the same thing" is structural rather
    // than two call sites a later edit could split.
    let whats_new = conn.first_seen.and_then(|f| f.describe());

    // The header band. Its colour is the prompt's own risk, read off the
    // same facts the body states in words: a first sighting, a history of
    // refusals, or a binary that no longer matches the rule pinned to it.
    // A routine prompt gets the neutral accent, so the loud ones are loud
    // by contrast rather than by everything shouting.
    let risk = prompt_tone(p);
    theme::band(ui, risk.color(), |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            ui.label(
                RichText::new(prompt::exe_name(conn))
                    .strong()
                    .size(18.0)
                    .color(TEXT),
            );
            ui.label(RichText::new("wants to connect").color(MUTED));
            theme::ghost_pill(ui, &conn.tuple.proto.to_string());
            // In the title line rather than the details grid below,
            // because it changes what the question is: a first-ever
            // connection from a program is the one an operator reads
            // the rest of this window for. Absent when nothing is new
            // *and* when the daemon is not tracking, which is why
            // there is no "seen before" badge to pair with it: it
            // would be a claim the daemon may have no basis for.
            if let Some(what) = whats_new {
                theme::pill(ui, "NEW", REJECT_COLOR).on_hover_text(what);
            }
        });
        if let Some(exe) = &conn.exe_path {
            // Full path, sanitized: this is the line the operator
            // checks to see which binary is actually asking.
            ui.label(
                RichText::new(prompt::path_text(exe))
                    .small()
                    .monospace()
                    .color(MUTED),
            );
        }
    });
    if let Some(cmdline) = &conn.cmdline {
        ui.add_space(4.0);
        ui.label(
            RichText::new(prompt::truncate(cmdline, 100))
                .small()
                .color(MUTED),
        );
    }
    // Its own banner rather than a line of text: it says a rule was
    // written for this program and the binary running now is not the one
    // that rule pins, which changes what the whole window is about. The
    // sentence itself is the shared one, so this window and `hallpass-cli
    // watch` cannot end up saying different things about the same fact.
    if let Some(what) = p.context.hash_mismatch_describe() {
        ui.add_space(4.0);
        ui.label(
            RichText::new(format!("Warning: {}", prompt::sentence_text(&what)))
                .strong()
                .color(DENY_COLOR),
        );
    }
    ui.add_space(6.0);

    egui::Grid::new(("prompt_details", p.id))
        .num_columns(2)
        .striped(false)
        .spacing([10.0, 4.0])
        .show(ui, |ui| {
            ui.label(RichText::new("Destination").color(MUTED));
            ui.label(theme::num(prompt::format_dest(conn)));
            ui.end_row();
            ui.label(RichText::new("User / process").color(MUTED));
            ui.label(theme::num(format!(
                "uid {} / pid {}",
                opt_num(conn.uid),
                opt_num(conn.pid)
            )));
            ui.end_row();
            // Only for a packaged application, which is where the executable
            // path above says little: it resolves inside the sandbox, so it
            // names neither a file on this host nor the application uniquely.
            if let Some(app) = &conn.app_id {
                ui.label(RichText::new("Application").color(MUTED));
                ui.label(theme::num(prompt::ui_text(app)));
                ui.end_row();
            }
            // With the identity rows rather than the history ones below:
            // "what started this" is the question an operator meeting an
            // unfamiliar program asks straight after "what is it". Stacked
            // nearest parent first, one per line, because a chain joined
            // into one cell wraps into an unreadable run in a 440px window.
            if !p.context.ancestors.is_empty() {
                ui.label(RichText::new("Started by").color(MUTED));
                ui.vertical(|ui| {
                    for exe in &p.context.ancestors {
                        ui.label(
                            RichText::new(prompt::path_text(exe))
                                .small()
                                .monospace()
                                .color(TEXT),
                        );
                    }
                });
                ui.end_row();
            }
            // The badge above says something is new; this says what, since
            // the two cases lead to different answers. A hover tooltip is
            // not enough on its own: the keyboard path to the buttons never
            // passes through it.
            if let Some(what) = whats_new {
                ui.label(RichText::new("First seen").color(MUTED));
                ui.colored_label(REJECT_COLOR, what);
                ui.end_row();
            }
            // Beside the first-seen row, because the two are the halves of
            // one question and can disagree loudly: a familiar application
            // that has been refused ten times is a different prompt from a
            // first sighting. Absent rather than a zero, which the shared
            // sentence decides for both clients.
            if let Some(what) = p.context.denials_describe() {
                ui.label(RichText::new("Denied lately").color(MUTED));
                ui.colored_label(DENY_COLOR, what);
                ui.end_row();
            }
        });
    // Below the grid and full width: 64 hex digits do not fit beside a
    // label column, and this is the one line here meant to be read
    // character by character (or copied into an `exe_sha256` rule).
    if let Some(hash) = &p.context.exe_sha256 {
        ui.add_space(6.0);
        ui.label(RichText::new("Executable SHA-256").small().color(MUTED));
        ui.label(
            RichText::new(prompt::truncate(hash, 64))
                .small()
                .monospace()
                .color(TEXT)
                .background_color(theme::SURFACE),
        );
    }
    if !rest.is_empty() {
        ui.add_space(6.0);
        theme::card(ui, "", |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                RichText::new(format!(
                    "{} more request(s) pending from this app:",
                    rest.len()
                ))
                .small()
                .color(TEXT),
            );
            // A handful is informative; a browser's full endpoint list is not.
            for dest in rest.iter().take(REST_SHOWN) {
                ui.label(RichText::new(dest).small().monospace().color(MUTED));
            }
            if rest.len() > REST_SHOWN {
                ui.label(
                    RichText::new(format!("...and {} more", rest.len() - REST_SHOWN))
                        .small()
                        .color(MUTED),
                );
            }
            ui.label(
                RichText::new(
                    "Answering \"This host\" or \"App anywhere\" also settles the covered ones.",
                )
                .small()
                .color(MUTED),
            );
        });
    }
}

/// How loudly this prompt should present itself.
///
/// Read off the facts the body already states, so the colour of the band
/// can never disagree with the words under it: a binary that no longer
/// matches the rule pinned to it is the strongest thing this window says,
/// a first sighting or a recent history of refusals is the next, and
/// everything else is an ordinary question.
fn prompt_tone(p: &PromptState) -> Tone {
    if p.context.hash_mismatch_describe().is_some() {
        return Tone::Bad;
    }
    let new_here = p.conn.first_seen.and_then(|f| f.describe()).is_some();
    if new_here || p.context.denials_describe().is_some() {
        return Tone::Warn;
    }
    Tone::Info
}

/// The pinned half: the pickers, the warning the scope picker earns, the
/// verdict buttons, and the countdown. The warning lives here rather than
/// in the scrolling body because it must be on screen at the moment the
/// scope it warns about is selected.
fn prompt_actions_ui(ui: &mut egui::Ui, p: &mut PromptState, now_ms: u64) -> Option<ClientMsg> {
    let mut answer = None;
    ui.horizontal(|ui| {
        ui.label(RichText::new("For").small().color(MUTED));
        for d in [
            RuleDuration::Once,
            RuleDuration::Session,
            RuleDuration::Forever,
        ] {
            // Segmented rather than a drop-down: both pickers are two
            // clicks deep in a window that answers itself on a timer, and
            // what they are set to has to be readable without opening
            // anything.
            if theme::chip(ui, p.duration == d, duration_label(d)).clicked() {
                p.duration = d;
            }
        }
        // Only when the daemon computed a hash for this prompt: it pins the
        // value shown here and nothing else, so a prompt without one has
        // nothing to pin and a reply asking anyway would create no rule at
        // all. Hidden rather than disabled - a permanently greyed control on
        // a firewall dialog reads as something broken.
        //
        // Not offered for Once either, which creates no rule to pin, and the
        // reply drops the flag on a deny (a deny keyed on the path should keep
        // blocking whatever is written there).
        if p.can_pin() && p.duration != RuleDuration::Once {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.checkbox(&mut p.pin_exe, "Pin binary").on_hover_text(
                    "Allow only this exact executable: the rule stops matching if the \
                     file at that path is replaced. Worth it for anything you can write \
                     yourself, since a path is not an identity. The rule will need \
                     answering again after the program updates.",
                );
            });
        }
    });
    ui.horizontal(|ui| {
        ui.label(RichText::new("To").small().color(MUTED));
        for sc in [
            PromptScope::ThisPort,
            PromptScope::ThisHost,
            PromptScope::AppAnywhere,
        ] {
            if theme::chip(ui, p.scope == sc, scope_label(sc)).clicked() {
                p.scope = sc;
            }
        }
    });
    ui.add_space(4.0);

    // Attribution is advisory (procfs races, eBPF offset guesses, cache
    // TTLs), and an "App anywhere" allow rule is only as strong as the exe
    // match: any process that execs the same binary inherits it. Warn before
    // the reply widens a rule to every destination.
    //
    // The text has to hold for whichever button is pressed, and the two
    // rules differ: an allow for a packaged application is pinned to its
    // identity, a deny deliberately is not (see `rule_from_reply`). So the
    // shared sentence states the widest of the two, and the second line
    // says where the allow is narrower. Stating only the allow's scope
    // would understate what Deny does, and Deny is the button that leads
    // keyboard traversal.
    //
    // Both names are cut short here, and only here: this panel is the one
    // part of the window that does not scroll, so text the judged process
    // chose (a file name runs to 255 bytes, an application id to 104) could
    // otherwise grow it past the viewport and take the buttons below it with
    // them. The body above states both in full.
    if p.scope == PromptScope::AppAnywhere {
        ui.colored_label(
            REJECT_COLOR,
            format!(
                "\u{26a0} \"App anywhere\" lets any process running {} reach any destination.",
                prompt::truncate(&prompt::exe_name(&p.conn), PINNED_NAME_MAX)
            ),
        );
        if let Some(app) = &p.conn.app_id {
            ui.colored_label(
                REJECT_COLOR,
                format!(
                    "Allow is scoped to {}; Deny is not, and covers every application \
                     running from that path.",
                    prompt::truncate(app, PINNED_NAME_MAX)
                ),
            );
        }
        ui.add_space(4.0);
    }

    ui.horizontal(|ui| {
        let width = (ui.available_width() - ui.spacing().item_spacing.x) / 2.0;
        // Deny is added first, so it leads keyboard traversal: egui hands
        // focus out in the order widgets are added. This window interrupts
        // whatever the operator was doing, and the answer given without
        // reading it has to be the recoverable one - a wrong deny costs a
        // retry, a wrong allow costs the connection the prompt existed to
        // stop.
        if ui
            .add(theme::verdict_button("Deny", DENY_COLOR).min_size(egui::vec2(width, 32.0)))
            .clicked()
        {
            answer = Some(p.reply(Verdict::Deny));
        }
        // Disabled until armed; see `PromptState::allow_armed`.
        let armed = p.allow_armed(now_ms);
        if ui
            .add_enabled(
                armed,
                theme::verdict_button("Allow", ALLOW_COLOR).min_size(egui::vec2(width, 32.0)),
            )
            .clicked()
        {
            // Never over a Deny from the same pass: both can fire at once (an
            // assistive-technology client clicks any node it names), and the
            // answer that stands has to be the recoverable one.
            answer.get_or_insert_with(|| p.reply(Verdict::Allow));
        }
        if !armed {
            // For the moment it arms, not a full arm period from now: a
            // pass drawn part way through (a pointer move) would otherwise
            // push the repaint that enables Allow back each time.
            let wait = p
                .allow_arms_at()
                .map_or(prompt::ALLOW_ARM_MS, |at| at.saturating_sub(now_ms));
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(wait));
        }
    });
    ui.add_space(4.0);

    let frac = p.remaining_fraction(now_ms);
    theme::countdown(
        ui,
        frac,
        &format!("{}s until default verdict", p.remaining_secs(now_ms)),
    );
    answer
}

fn duration_label(d: RuleDuration) -> &'static str {
    match d {
        RuleDuration::Once => "Once",
        RuleDuration::Session => "Session",
        RuleDuration::Forever => "Forever",
        RuleDuration::Until { .. } => "Timed",
    }
}

fn scope_label(s: PromptScope) -> &'static str {
    match s {
        PromptScope::ThisPort => "This port",
        PromptScope::ThisHost => "This host",
        PromptScope::AppAnywhere => "App anywhere",
    }
}

fn opt_num(n: Option<u32>) -> String {
    n.map_or_else(|| "?".to_string(), |v| v.to_string())
}

/// Bound for a name the judged process chose, quoted inside the pinned
/// action panel. Short enough that both warnings together cannot crowd the
/// verdict buttons out of the viewport; the scrolling body carries the
/// names in full.
const PINNED_NAME_MAX: usize = 40;

#[cfg(test)]
mod tests {
    //! Layout as a security property: the verdict buttons stay reachable
    //! whatever the judged process put in the body, Deny leads keyboard
    //! traversal, and Allow does not answer a prompt nobody has read yet.

    use std::path::PathBuf;

    use egui_kittest::kittest::{NodeT as _, Queryable as _};
    use egui_kittest::Harness;
    use hallpass_types::{Connection, PromptContext};

    use super::*;

    fn conn(exe: &str, dst: &str) -> Connection {
        crate::testutil::conn(Some(exe), dst)
    }

    /// A prompt plus what its buttons answered, so a test can read the reply
    /// back out from behind the harness.
    struct PromptFixture {
        prompt: PromptState,
        answered: Vec<ClientMsg>,
    }

    /// Fixed rather than wall clock: the countdown is display-only here, and a
    /// real clock would make the progress bar (and so the frame) differ per run.
    const NOW_MS: u64 = 1_700_000_000_000;

    const EXE: &str = "/usr/bin/curl";

    /// A fully populated prompt context: ancestry, hash, a hash-mismatch
    /// warning and a denial count all present at once.
    ///
    /// The default for every fixture here on purpose. This module exists to hold
    /// the layout property that the viewport is a fixed 440x330 and the verdict
    /// buttons must stay reachable no matter how much the scrolling body wants,
    /// so the fixtures carry the largest body the daemon can produce rather than
    /// the smallest.
    /// Sized from the daemon's own caps rather than a hand-picked number, so
    /// "the largest body" stays true if a cap moves.
    fn ctx() -> PromptContext {
        PromptContext {
            ancestors: (0..hallpass_types::MAX_PROMPT_ANCESTORS)
                .map(|i| PathBuf::from(format!("/usr/lib/ancestor-{i}/launcher")))
                .collect(),
            exe_sha256: Some("ab".repeat(32)),
            hash_mismatch_rules: (0..hallpass_types::MAX_HASH_MISMATCH_RULES)
                .map(|i| format!("pinned-rule-{i}"))
                .collect(),
            recent_denials: 7,
        }
    }

    /// One prompt window's body, laid out on its own the way its viewport shows
    /// it, in front long enough for Allow to answer.
    fn prompt_harness() -> Harness<'static, PromptFixture> {
        prompt_harness_fronted(NOW_MS - crate::prompt::ALLOW_ARM_MS)
    }

    /// [`prompt_harness`], with the prompt at the front of its window since
    /// `fronted_ms`.
    fn prompt_harness_fronted(fronted_ms: u64) -> Harness<'static, PromptFixture> {
        let mut prompt = PromptState::new(
            1,
            conn(EXE, "93.184.216.34:443"),
            NOW_MS + 30_000,
            NOW_MS,
            ctx(),
        );
        prompt.fronted_ms = Some(fronted_ms);
        let state = PromptFixture {
            prompt,
            answered: Vec::new(),
        };
        Harness::builder()
            .with_size(egui::vec2(440.0, 330.0))
            .build_ui_state(
                |ui, state: &mut PromptFixture| {
                    state
                        .answered
                        .extend(prompt_ui(ui, &mut state.prompt, NOW_MS, &[]));
                },
                state,
            )
    }

    /// The buttons must survive the worst content the window can carry: a
    /// path at its display cap, a file name at the filesystem's, a command line
    /// at its cap, an application id at its cap, the full pending list, and the
    /// App-anywhere warning, all inside the fixed 440x330 viewport. Every one of
    /// those strings is chosen by the process being judged, so "the info pushed
    /// Allow and Deny off the window" is an unanswerable prompt an adversary can
    /// construct; the actions are pinned to a bottom panel and the info scrolls,
    /// and this clicks Deny through exactly that worst case to prove it stays
    /// reachable.
    ///
    /// The file name and application id are the two that also reach the pinned
    /// panel, through the App-anywhere warning, so they are sized to wrap as
    /// many lines as they can: wide glyphs, with break points.
    #[test]
    fn buttons_survive_worst_case_content() {
        // NAME_MAX: the longest file name the kernel will hand the daemon.
        let file_name = "WWWW ".repeat(51);
        let mut state = PromptFixture {
            prompt: PromptState::new(
                1,
                conn(
                    &format!("/very/long/{}/{file_name}", "x".repeat(180)),
                    "93.184.216.34:443",
                ),
                NOW_MS + 30_000,
                NOW_MS,
                ctx(),
            ),
            answered: Vec::new(),
        };
        state.prompt.conn.cmdline = Some(format!("curl {}", "a".repeat(200)));
        state.prompt.conn.app_id = Some(format!(
            "flatpak:{}",
            "WWW.".repeat(hallpass_types::MAX_APP_ID_NAME_BYTES / 4)
        ));
        state.prompt.scope = PromptScope::AppAnywhere; // adds the warning label
        let rest: Vec<String> = (0..9).map(|i| format!("tcp 10.0.0.{i}:443")).collect();
        let mut harness = Harness::builder()
            .with_size(egui::vec2(440.0, 330.0))
            .build_ui_state(
                move |ui, state: &mut PromptFixture| {
                    state
                        .answered
                        .extend(prompt_ui(ui, &mut state.prompt, NOW_MS, &rest));
                },
                state,
            );
        // Settled first: the panel sizes itself from the frame before, so the
        // first pass alone would not show where the buttons end up.
        harness.run();
        harness.get_by_label("Deny").click();
        harness.run();
        let expected = harness.state().prompt.reply(Verdict::Deny);
        assert_eq!(
            harness.state().answered,
            vec![expected],
            "Deny was not clickable under worst-case content"
        );
    }

    /// A prompt for something never seen here has to say so where the operator
    /// is already looking, and a routine one must not.
    ///
    /// A property of the laid-out tree rather than of the state: the flag is on
    /// the connection either way, and what this proves is that it reaches the
    /// window at all. The badge is deliberately not the only carrier - keyboard
    /// traversal never passes through it, so the details grid states it in words
    /// too, and both are asserted here.
    #[test]
    fn a_new_application_is_announced_in_the_prompt_window() {
        let mut fixture = PromptFixture {
            prompt: PromptState::new(
                1,
                conn(EXE, "93.184.216.34:443"),
                NOW_MS + 30_000,
                NOW_MS,
                ctx(),
            ),
            answered: Vec::new(),
        };
        fixture.prompt.conn.first_seen = Some(hallpass_types::FirstSeen {
            app: true,
            dest: true,
        });
        let mut harness = Harness::builder()
            .with_size(egui::vec2(440.0, 330.0))
            .build_ui_state(
                |ui, state: &mut PromptFixture| {
                    state
                        .answered
                        .extend(prompt_ui(ui, &mut state.prompt, NOW_MS, &[]));
                },
                fixture,
            );
        harness.get_by_label("NEW");
        harness.get_by_label("this application has not connected before");

        // Nothing new, and tracking off, both render as an ordinary prompt: a
        // window that said "seen before" would be making a claim the daemon may
        // have no basis for.
        for quiet in [
            Some(hallpass_types::FirstSeen {
                app: false,
                dest: false,
            }),
            None,
        ] {
            harness.state_mut().prompt.conn.first_seen = quiet;
            harness.run();
            assert!(
                harness.query_by_label("NEW").is_none(),
                "an unremarkable connection was announced as new ({quiet:?})"
            );
        }
    }

    /// The context the daemon builds has to reach the window, and the loudest
    /// part of it has to be where the operator is already looking.
    ///
    /// A hash-mismatch is the strongest thing this window ever says: a rule was
    /// written for this program and the binary asking now is not the one it
    /// pins. It sits above the separator with the identity lines rather than in
    /// the details grid, because it changes what the whole prompt is about.
    #[test]
    fn the_prompt_window_carries_the_daemon_context() {
        let mut harness = prompt_harness();
        let context = ctx();
        // The sentences are the shared ones, so asserting the rendered label
        // against them also pins this window and `hallpass-cli watch` to saying
        // the same thing.
        harness.get_by_label(&format!(
            "Warning: {}",
            context.hash_mismatch_describe().unwrap()
        ));
        harness.get_by_label(&context.denials_describe().unwrap());
        harness.get_by_label("/usr/lib/ancestor-2/launcher");
        harness.get_by_label(&"ab".repeat(32));

        // An empty context renders an ordinary prompt. Zero denials in
        // particular say nothing rather than "never denied": the daemon's
        // history is bounded and lost on restart, so it does not know that.
        harness.state_mut().prompt.context = PromptContext::default();
        harness.run();
        for absent in ["Started by", "Executable SHA-256", "Denied lately"] {
            assert!(
                harness.query_by_label(absent).is_none(),
                "an empty context still rendered {absent:?}"
            );
        }
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
        // Enough presses to walk the whole panel: the pickers are segmented
        // controls, so each option is its own focus stop, and the two verdict
        // buttons are the last widgets added. The property is the order the
        // two are reached in, not how many stops precede them.
        for _ in 0..16 {
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
                vec![expected],
                "{label} answered with the wrong verdict"
            );
        }
    }

    /// Both buttons fired in one pass answer Deny. A pointer cannot do it,
    /// but an assistive-technology client can click any node it names, as
    /// many as it likes per frame.
    #[test]
    fn deny_stands_when_both_buttons_fire_in_one_pass() {
        let mut harness = prompt_harness();
        for label in ["Deny", "Allow"] {
            let (target_node, target_tree) = harness.get_by_label(label).accesskit_node().locate();
            harness
                .input_mut()
                .events
                .push(egui::Event::AccessKitActionRequest(
                    egui::accesskit::ActionRequest {
                        target_node,
                        target_tree,
                        action: egui::accesskit::Action::Click,
                        data: None,
                    },
                ));
        }
        harness.step();
        let expected = harness.state().prompt.reply(Verdict::Deny);
        assert_eq!(harness.state().answered, vec![expected]);
    }

    /// A prompt that has only just come to the front does not take an Allow:
    /// the click was aimed at whatever sat there a moment ago.
    #[test]
    fn allow_does_not_answer_a_prompt_that_just_surfaced() {
        let mut harness = prompt_harness_fronted(NOW_MS);
        harness.get_by_label("Allow").click();
        harness.run();
        assert!(
            harness.state().answered.is_empty(),
            "an unread prompt was allowed"
        );
        harness.get_by_label("Deny").click();
        harness.run();
        assert_eq!(
            harness.state().answered.len(),
            1,
            "Deny still answers at once"
        );
    }

    #[test]
    fn labels() {
        assert_eq!(duration_label(RuleDuration::Session), "Session");
        assert_eq!(scope_label(PromptScope::AppAnywhere), "App anywhere");
    }
}

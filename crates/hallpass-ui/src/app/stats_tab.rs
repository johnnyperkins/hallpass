//! The Stats tab: four headline numbers, then the counters that only
//! matter when they are not zero.
//!
//! Ordered by what an operator came here to find out. The tiles answer
//! "is this thing working and what is it doing"; the cards below answer
//! "why is it not", and each one is a group that fails together - the
//! prompt path, the kernel queues, the integrity watchdog, the volume
//! accounting. A flat list of eighteen rows made the two kinds
//! indistinguishable.
//!
//! Every sum here saturates, as everywhere a stats reply is rendered: a
//! figure off the socket must not be able to panic the window.

use eframe::egui::{self, RichText};
use hallpass_types::{ClientMsg, Stats};

use super::chrome::empty_state;
use super::format::{compact, format_uptime, grouped, percent_of};
use super::{HallpassApp, NARROW};
use crate::theme::{self, Tone, ALLOW_COLOR, DENY_COLOR, MUTED, REJECT_COLOR, TEXT};

impl HallpassApp {
    pub(super) fn stats_tab(&mut self, ui: &mut egui::Ui) {
        let Some(s) = &self.stats else {
            empty_state(
                ui,
                "Waiting for the daemon",
                "Counters appear as soon as it answers.",
            );
            return;
        };
        let refresh = egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                // Two rows of two when four would be too narrow to read,
                // and the cards below stacked for the same reason.
                let narrow = ui.available_width() < NARROW;
                headline_tiles(ui, s, narrow);
                ui.add_space(8.0);
                theme::ratio_bar(
                    ui,
                    egui::vec2(ui.available_width(), 10.0),
                    &[(s.allowed, ALLOW_COLOR), (s.denied, DENY_COLOR)],
                )
                .on_hover_text(format!(
                    "{} allowed, {} denied or rejected since the daemon started",
                    s.allowed, s.denied
                ));
                ui.add_space(10.0);
                card_pair(
                    ui,
                    narrow,
                    |ui| prompting_card(ui, s),
                    |ui| volume_card(ui, s),
                );
                ui.add_space(8.0);
                let mut refresh = false;
                card_pair(
                    ui,
                    narrow,
                    |ui| kernel_queues_card(ui, s),
                    |ui| refresh = integrity_card(ui, s),
                );
                refresh
            })
            .inner;
        if refresh {
            self.send(ClientMsg::Stats);
        }
    }
}

/// Two cards side by side, or the right one under the left when there is
/// only room for one column.
fn card_pair(
    ui: &mut egui::Ui,
    narrow: bool,
    left: impl FnOnce(&mut egui::Ui),
    right: impl FnOnce(&mut egui::Ui),
) {
    ui.columns(if narrow { 1 } else { 2 }, |cols| {
        let last = cols.len() - 1;
        left(&mut cols[0]);
        right(&mut cols[last]);
    });
}

/// The four numbers the tab leads with, four across or two by two.
fn headline_tiles(ui: &mut egui::Ui, s: &Stats, narrow: bool) {
    let per_row = if narrow { 2 } else { 4 };
    // Less each tile's margins and stroke, which the frame adds outside the
    // width it is given.
    let tile_w =
        ((ui.available_width() - (per_row - 1) as f32 * 8.0) / per_row as f32 - 28.0).max(90.0);
    let tiles = [
        (
            "CONNECTIONS",
            compact(s.connections_total),
            TEXT,
            format!("up {}", format_uptime(s.uptime_secs)),
        ),
        (
            "ALLOWED",
            compact(s.allowed),
            ALLOW_COLOR,
            percent_of(s.allowed, s.connections_total),
        ),
        (
            "DENIED / REJECTED",
            compact(s.denied),
            DENY_COLOR,
            percent_of(s.denied, s.connections_total),
        ),
        (
            "PROMPTED",
            compact(s.prompted),
            REJECT_COLOR,
            format!("{} unanswered", s.prompts_unanswered),
        ),
    ];
    for row in tiles.chunks(per_row) {
        ui.horizontal(|ui| {
            for (label, value, color, sub) in row {
                theme::stat_tile(ui, tile_w, label, value, *color, sub);
            }
        });
    }
}

/// Whether anyone is being asked at all, and how often nobody answered.
/// Without this card an agent that is not running, or has quietly lost the
/// prompt slot, looks exactly like a quiet machine.
fn prompting_card(ui: &mut egui::Ui, s: &Stats) {
    theme::card(ui, "PROMPTING", |ui| {
        theme::stat_row(ui, "Prompt handler", |ui| {
            if s.prompt_handler_connected {
                theme::pill(ui, "connected", ALLOW_COLOR);
            } else {
                theme::pill(ui, "none - connections take the default", DENY_COLOR);
            }
        });
        for (key, n) in [
            ("Unanswered prompts", s.prompts_unanswered),
            ("Prompt overflows", s.prompts_overflowed),
            ("Handlers evicted", s.prompt_handlers_evicted),
            ("Rules loaded", u64::from(s.rules_loaded)),
        ] {
            number_row(ui, key, grouped(n));
        }
    });
}

/// Volume from conntrack teardown accounting; zeros when flow_accounting
/// is off, like any counter the host is not producing.
fn volume_card(ui: &mut egui::Ui, s: &Stats) {
    theme::card(ui, "VOLUME", |ui| {
        number_row(ui, "Flows accounted", grouped(s.flows_accounted));
        number_row(ui, "Flow bytes", hallpass_types::human_bytes(s.flow_bytes));
        number_row(ui, "Flow packets", grouped(s.flow_packets));
        number_row(ui, "Daemon uptime", format_uptime(s.uptime_secs));
    });
}

/// What the kernel's queues dropped or are holding, which no verdict
/// counter above can show.
fn kernel_queues_card(ui: &mut egui::Ui, s: &Stats) {
    theme::card(ui, "KERNEL QUEUES", |ui| {
        // A packet dropped from a full verdict queue never reached the
        // daemon, so no counter above moved for it. Painted when nonzero
        // because packets were dropped without policy running;
        // "unavailable" (never 0) when nothing was read. Drops only: a
        // working fail-open queue passes its overflow through unjudged and
        // uncounted, which is what the fail-open row is for reading this
        // one.
        let missed = s
            .verdict_queue_dropped
            .zip(s.verdict_queue_user_dropped)
            .map(|(dropped, undelivered)| dropped.saturating_add(undelivered));
        theme::stat_row(ui, "Verdict queue drops", |ui| match missed {
            Some(0) => {
                ui.label(theme::num("0"));
            }
            Some(n) => {
                theme::pill(
                    ui,
                    &format!("{n} dropped before policy saw them"),
                    DENY_COLOR,
                );
            }
            None => {
                ui.label(unavailable());
            }
        });
        // Plain even when "no": that is the intended state under a
        // fail-closed posture, which this panel cannot see.
        theme::stat_row(ui, "Verdict queue fail-open", |ui| {
            ui.label(match s.verdict_queue_fail_open {
                Some(true) => theme::num("yes"),
                Some(false) => theme::num("no"),
                None => unavailable(),
            });
        });
        // Depth against the length the daemon set at bind, because a depth
        // only reads as pressure against its ceiling. No ceiling means the
        // kernel refused the request and kept its own, which the daemon
        // logged and this panel will not guess at.
        theme::stat_row(ui, "Verdict queue depth", |ui| {
            match (s.verdict_queue_depth, s.verdict_queue_max_len) {
                (Some(n), Some(max)) => {
                    // Right to left: the bar sits at the edge, the count
                    // just inside it.
                    theme::ratio_bar(
                        ui,
                        egui::vec2(60.0, 6.0),
                        &[
                            (n, REJECT_COLOR),
                            (u64::from(max).saturating_sub(n), theme::HAIRLINE),
                        ],
                    );
                    ui.label(theme::num(format!("{n} of {max}")));
                }
                (Some(n), None) => {
                    ui.label(theme::num(n.to_string()));
                }
                (None, _) => {
                    ui.label(unavailable());
                }
            }
        });
        // Domain annotations, not verdicts, so never painted; the userspace
        // half of the same loss is dns_snoop_dropped.
        theme::stat_row(ui, "Snoop queue drops", |ui| {
            ui.label(
                match s.snoop_queue_dropped.zip(s.snoop_queue_user_dropped) {
                    Some((dropped, undelivered)) => {
                        theme::num(grouped(dropped.saturating_add(undelivered)))
                    }
                    None => unavailable(),
                },
            );
        });
    });
}

/// Every detected flush is a window in which the host was unfiltered. The
/// watchdog repairs each one; a failed repair is in the journal, so this
/// card claims detection, not success. Returns whether Refresh was
/// clicked.
fn integrity_card(ui: &mut egui::Ui, s: &Stats) -> bool {
    theme::card(ui, "RULESET INTEGRITY", |ui| {
        if s.nft_flushes == 0 {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                theme::pill(ui, "intact", ALLOW_COLOR);
                ui.label(RichText::new("nothing has flushed the nftables ruleset").color(MUTED));
            });
        } else {
            let last = s
                .nft_last_flush_ms
                .map_or_else(|| "unknown".into(), hallpass_types::format_ts);
            theme::banner(
                ui,
                Tone::Bad,
                theme::WARNING_SIGN,
                &format!("{} flush(es) detected", s.nft_flushes),
                &format!("something flushed the nftables ruleset, last {last}"),
            );
        }
        ui.add_space(10.0);
        theme::ghost_button(ui, "Refresh counters", theme::ACCENT, true).clicked()
    })
}

/// A detail row whose value is one number.
fn number_row(ui: &mut egui::Ui, key: &str, value: String) {
    theme::stat_row(ui, key, |ui| {
        ui.label(theme::num(value));
    });
}

/// A counter the daemon could not read, which is not the same as zero.
fn unavailable() -> RichText {
    theme::num_muted("unavailable")
}

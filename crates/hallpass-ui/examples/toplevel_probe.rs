//! Live probe: main-toplevel visibility semantics under the current session.
//!
//! Settles, with eyes on the screen plus the terminal log:
//!   1. does `ViewportCommand::Visible(false)` hide the MAIN toplevel
//!      (the recorded no-op probe was on child viewports)?
//!   2. does `Visible(true)` bring it back?
//!   3. does `Minimized(true)` / `Minimized(false)` work on the main window?
//!   4. while minimized: does a child viewport (prompt popup stand-in)
//!      surface, and does `RequestUserAttention` show anything?
//!   5. do repaint requests from a background thread (net-event stand-in)
//!      still produce frames while hidden/minimized?
//!
//! Run under the session compositor, then again forced onto XWayland:
//!   cargo run -p hallpass-ui --example toplevel_probe
//!   env -u WAYLAND_DISPLAY cargo run -p hallpass-ui --example toplevel_probe
//!
//! Fully automated (~40s); just watch. A ticker thread hard-exits at 50s
//! in case the window ends up unmappable and the frame loop never runs.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use eframe::egui;

static START: OnceLock<Instant> = OnceLock::new();
static POPUP_FRAMES: AtomicU32 = AtomicU32::new(0);

fn elapsed() -> f32 {
    START.get().map_or(0.0, |s| s.elapsed().as_secs_f32())
}

fn log(msg: &str) {
    println!("[{:6.2}s] {msg}", elapsed());
}

/// (end_second, name, what the operator should see)
const PHASES: &[(f32, &str, &str)] = &[
    (4.0, "baseline", "window visible, painting normally"),
    (10.0, "Visible(false)", "window should VANISH (no taskbar entry)"),
    (
        18.0,
        "popup while hidden",
        "small POPUP should appear + attention hint while main window stays hidden",
    ),
    (
        24.0,
        "Visible(true)",
        "main window should REAPPEAR and take focus, popup closes",
    ),
    (
        30.0,
        "Minimized(true)",
        "window should MINIMIZE (known trap: frame loop may stall here)",
    ),
    (
        36.0,
        "Minimized(false)",
        "window should RESTORE, if the loop still runs at all",
    ),
    (38.0, "summary", "printing results, then closing"),
];

struct Probe {
    phase: usize,
    frames: Vec<u32>,
    popup_open: bool,
    last_flags: (Option<bool>, Option<bool>),
}

impl Probe {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        START.set(Instant::now()).ok();
        let ctx = cc.egui_ctx.clone();
        // Net-event stand-in: an out-of-band wakeup source that keeps
        // requesting repaints no matter what the window state is. If
        // frames stall in a phase anyway, the compositor or backend is
        // refusing to paint, not the app failing to wake.
        std::thread::spawn(move || {
            let mut ticks = 0u32;
            loop {
                std::thread::sleep(std::time::Duration::from_millis(500));
                ticks += 1;
                ctx.request_repaint();
                if ticks.is_multiple_of(4) {
                    log("ticker alive, repaint requested");
                }
                if elapsed() > 50.0 {
                    log("backstop: frame loop never finished, hard exit");
                    std::process::exit(0);
                }
            }
        });
        log("probe start");
        log(&format!(
            "WAYLAND_DISPLAY={:?} DISPLAY={:?}",
            std::env::var("WAYLAND_DISPLAY").ok(),
            std::env::var("DISPLAY").ok()
        ));
        Self {
            phase: 0,
            frames: vec![0; PHASES.len()],
            popup_open: false,
            last_flags: (None, None),
        }
    }

    fn enter(&mut self, phase: usize, ctx: &egui::Context) {
        let (_, name, expect) = PHASES[phase];
        // Frame counts print at each boundary, not only in a final summary,
        // so a stalled phase still leaves its evidence behind when the
        // backstop kills the process.
        log(&format!(
            "leaving phase {} with {} frames; popup frames so far: {}",
            phase - 1,
            self.frames[phase - 1],
            POPUP_FRAMES.load(Ordering::Relaxed)
        ));
        log(&format!("enter phase {phase}: {name} - expect: {expect}"));
        match phase {
            1 => ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false)),
            2 => {
                self.popup_open = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
                    egui::UserAttentionType::Critical,
                ));
            }
            3 => {
                self.popup_open = false;
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            }
            4 => ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true)),
            5 => {
                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            }
            6 => {
                log("---- summary ----");
                for (i, (_, name, _)) in PHASES.iter().enumerate() {
                    log(&format!("frames in phase {i} ({name}): {}", self.frames[i]));
                }
                log(&format!(
                    "popup frames total: {}",
                    POPUP_FRAMES.load(Ordering::Relaxed)
                ));
                log("closing");
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            _ => {}
        }
    }
}

impl eframe::App for Probe {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let ctx = &ctx;
        let now = elapsed();
        let target = PHASES
            .iter()
            .position(|(end, _, _)| now < *end)
            .unwrap_or(PHASES.len() - 1);
        // Walk every phase boundary even if frames stalled across one, so
        // the command sequence stays coherent; the stall shows up as a
        // zero frame count for the skipped phase.
        while self.phase < target {
            let next = self.phase + 1;
            self.enter(next, ctx);
            self.phase = next;
        }

        self.frames[self.phase] += 1;
        if self.frames[self.phase] <= 3 {
            log(&format!("frame in phase {} ({})", self.phase, PHASES[self.phase].1));
        }

        let flags = ctx.input(|i| (i.viewport().minimized, i.viewport().focused));
        if flags != self.last_flags {
            log(&format!(
                "viewport flags changed: minimized={:?} focused={:?}",
                flags.0, flags.1
            ));
            self.last_flags = flags;
        }

        if self.popup_open {
            ctx.show_viewport_deferred(
                egui::ViewportId::from_hash_of("probe_popup"),
                egui::ViewportBuilder::default()
                    .with_title("probe popup")
                    .with_inner_size([260.0, 120.0]),
                |ui, _class| {
                    let n = POPUP_FRAMES.fetch_add(1, Ordering::Relaxed);
                    if n < 3 {
                        log(&format!("popup frame {n}"));
                    }
                    egui::CentralPanel::default().show(ui, |ui| {
                        ui.heading("popup while minimized");
                        ui.label("if you can read this, popups survive a parked main window");
                    });
                },
            );
        }

        let (_, name, expect) = PHASES[self.phase];
        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading(format!("phase {}: {name}", self.phase));
            ui.label(expect);
            ui.monospace(format!("t = {now:.1}s"));
        });
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("hallpass toplevel probe")
            .with_inner_size([460.0, 220.0]),
        ..Default::default()
    };
    eframe::run_native(
        "hallpass toplevel probe",
        options,
        Box::new(|cc| Ok(Box::new(Probe::new(cc)))),
    )
}

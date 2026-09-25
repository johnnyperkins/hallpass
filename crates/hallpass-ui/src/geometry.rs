//! The management window's size, kept across launches.
//!
//! A size the operator chose is a statement about their screen, and the
//! window opening at its default every time undoes it. Only the size and
//! whether the window was maximized: Wayland does not let a client place
//! itself, so a saved position would work on one backend and be ignored on
//! the other. The prompt windows keep their fixed size and are not saved.
//!
//! Written by hand rather than through eframe's persistence feature, which
//! opens a data directory for every process that runs a window (each
//! prompt window included), stores egui's own memory alongside, and brings
//! in a serialization format for a file holding two numbers.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use eframe::egui;

/// The default size, for a first launch or a file that cannot be read.
pub const DEFAULT: egui::Vec2 = egui::vec2(1000.0, 640.0);

/// The smallest size the window allows, and so the smallest restored.
pub const MIN: egui::Vec2 = egui::vec2(480.0, 320.0);

/// Larger than any screen: a file claiming more is corrupt, not a size.
const MAX_SIDE: f32 = 16_384.0;

/// How long a size has to hold before it is written, so a drag-resize
/// writes once when it ends rather than on every frame of it.
const SETTLE: Duration = Duration::from_secs(1);

/// What is saved: the window's size in points, and whether it was
/// maximized. The size is the one it returns to when un-maximized.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Geometry {
    pub size: egui::Vec2,
    pub maximized: bool,
}

impl Default for Geometry {
    fn default() -> Self {
        Self {
            size: DEFAULT,
            maximized: false,
        }
    }
}

impl Geometry {
    /// `1040 660`, with ` maximized` after it when it was.
    fn to_line(self) -> String {
        format!(
            "{} {}{}\n",
            self.size.x.round(),
            self.size.y.round(),
            if self.maximized { " maximized" } else { "" }
        )
    }

    /// The saved line, or `None` for anything else. Sizes are clamped to
    /// what the window allows, so a file from a larger screen still opens
    /// a window this one can show the edges of.
    fn from_line(line: &str) -> Option<Self> {
        let mut words = line.split_whitespace();
        let mut side = || {
            words
                .next()?
                .parse::<f32>()
                .ok()
                .filter(|v| v.is_finite() && *v > 0.0 && *v <= MAX_SIDE)
        };
        let size = egui::vec2(side()?, side()?).max(MIN);
        let maximized = match words.next() {
            None => false,
            Some("maximized") => true,
            Some(_) => return None,
        };
        Some(Self { size, maximized })
    }
}

/// Where the size is kept: `$XDG_STATE_HOME/hallpass/window`, falling back
/// to `~/.local/state` as the base directory spec says. Window size is
/// state the program keeps, not configuration anyone edits.
fn path() -> Option<PathBuf> {
    let set = |name| std::env::var_os(name).filter(|v| !v.is_empty());
    let base = match set("XDG_STATE_HOME") {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(set("HOME")?).join(".local/state"),
    };
    Some(base.join("hallpass").join("window"))
}

/// The saved geometry, or the default.
pub fn load() -> Geometry {
    path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|text| Geometry::from_line(&text))
        .unwrap_or_default()
}

/// Write through a temporary file, so a crash mid-write leaves the old
/// size rather than half a line.
fn save_to(path: &Path, geometry: Geometry) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, geometry.to_line())?;
    std::fs::rename(&tmp, path)
}

/// Follows the window's size frame by frame and writes it once it settles.
///
/// Written on change rather than at exit: a window closed by a signal or
/// by its session ending never gets an exit to write on.
#[derive(Debug)]
pub struct Tracker {
    saved: Geometry,
    seen: Geometry,
    since: Instant,
}

impl Tracker {
    /// Starting from what was loaded, so an unchanged window writes nothing.
    pub fn new(loaded: Geometry) -> Self {
        Self {
            saved: loaded,
            seen: loaded,
            since: Instant::now(),
        }
    }

    /// Note this frame's size, and write it once it has held for
    /// [`SETTLE`].
    pub fn observe(&mut self, ctx: &egui::Context) {
        let (inner, maximized, fullscreen) = ctx.input(|i| {
            let v = i.viewport();
            (
                v.inner_rect,
                v.maximized.unwrap_or(false),
                v.fullscreen.unwrap_or(false),
            )
        });
        let Some(inner) = inner else {
            return;
        };
        // Maximized or fullscreen, the size is the screen's; keep the one
        // the window goes back to.
        let size = if maximized || fullscreen {
            self.seen.size
        } else {
            inner.size()
        };
        let now = Geometry { size, maximized };
        if !close(now, self.seen) {
            self.seen = now;
            self.since = Instant::now();
            // One more frame once it has settled, or a resize that ends
            // with the pointer still would never be written.
            ctx.request_repaint_after(SETTLE);
        }
        if !close(self.seen, self.saved) && self.since.elapsed() >= SETTLE {
            self.saved = self.seen;
            if let Some(path) = path() {
                if let Err(e) = save_to(&path, self.saved) {
                    tracing::debug!("not keeping the window size: {e}");
                }
            }
        }
    }
}

/// Equal to the point: sizes arrive as floats from the platform and are
/// saved rounded.
fn close(a: Geometry, b: Geometry) -> bool {
    a.maximized == b.maximized && (a.size - b.size).abs().max_elem() < 1.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_saved_line_reads_back() {
        for g in [
            Geometry {
                size: egui::vec2(1040.0, 660.0),
                maximized: false,
            },
            Geometry {
                size: egui::vec2(1280.0, 800.0),
                maximized: true,
            },
        ] {
            assert_eq!(Geometry::from_line(&g.to_line()), Some(g));
        }
    }

    /// A file that says anything else is ignored rather than trusted: the
    /// window then opens at its default, which is always showable.
    #[test]
    fn anything_else_is_ignored() {
        for line in [
            "",
            "1040",
            "wide tall",
            "1040 660 minimized",
            "-5 600",
            "NaN 600",
            "inf 600",
            "99999 600",
        ] {
            assert_eq!(Geometry::from_line(line), None, "{line:?}");
        }
    }

    /// Smaller than the window allows is raised to its minimum, not refused.
    #[test]
    fn a_tiny_size_is_raised_to_the_minimum() {
        assert_eq!(Geometry::from_line("100 50").map(|g| g.size), Some(MIN));
    }

    #[test]
    fn saving_creates_the_directory_and_replaces_the_file() {
        let dir = std::env::temp_dir().join(format!("hallpass-geometry-{}", std::process::id()));
        let path = dir.join("hallpass").join("window");
        for g in [
            Geometry::default(),
            Geometry {
                size: egui::vec2(1200.0, 700.0),
                maximized: true,
            },
        ] {
            save_to(&path, g).expect("saving");
            let text = std::fs::read_to_string(&path).expect("reading back");
            assert_eq!(Geometry::from_line(&text), Some(g));
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}

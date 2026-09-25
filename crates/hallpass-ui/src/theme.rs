//! The window's visual language: one palette, one style, and the small
//! painted parts every tab shares.
//!
//! Kept in one place because this is a status surface before it is a
//! control surface: the operator reads a colour before they read a word,
//! so "green means the packet went out" has to be the same green in the
//! feed, in the traffic bars, in the stats tiles and on the prompt. A tab
//! picking its own shade of red is a bug in the same way a wrong number
//! is.
//!
//! The palette is dark and fixed rather than following the desktop theme.
//! Every colour here is chosen against [`BG`] for contrast, and the three
//! verdict colours have to stay apart from each other at a glance in a
//! table of small text; re-deriving that against an arbitrary system
//! background is not something this window can promise.

use eframe::egui::{self, Color32, CornerRadius, Margin, Response, RichText, Stroke, Ui, Vec2};

// ---- palette -------------------------------------------------------------

/// Window background: the darkest surface, everything else sits on it.
pub const BG: Color32 = Color32::from_rgb(0x0e, 0x11, 0x17);
/// Panel background (the tab bar and the status bar).
pub const SURFACE: Color32 = Color32::from_rgb(0x14, 0x18, 0x21);
/// Raised surface: cards, tiles, the prompt's header band.
pub const SURFACE_RAISED: Color32 = Color32::from_rgb(0x1a, 0x1f, 0x2b);
/// One step above that, for controls at rest.
pub const SURFACE_CONTROL: Color32 = Color32::from_rgb(0x22, 0x29, 0x37);
/// Sunk below the window: the track a picker's options sit in.
pub const WELL: Color32 = Color32::from_rgb(0x0a, 0x0d, 0x13);
/// Borders and separators. Visible, never loud.
pub const HAIRLINE: Color32 = Color32::from_rgb(0x2a, 0x32, 0x42);
/// Body text.
pub const TEXT: Color32 = Color32::from_rgb(0xdd, 0xe3, 0xf0);
/// Secondary text: labels, units, anything read second.
pub const MUTED: Color32 = Color32::from_rgb(0x8b, 0x97, 0xad);

/// Brand accent: selection, focus, the active tab, the daemon link.
pub const ACCENT: Color32 = Color32::from_rgb(0x4d, 0xa3, 0xff);
/// Green accent for Allow: the connection went out.
pub const ALLOW_COLOR: Color32 = Color32::from_rgb(0x3f, 0xc9, 0x6c);
/// Red accent for Deny: the connection was stopped.
pub const DENY_COLOR: Color32 = Color32::from_rgb(0xf2, 0x5f, 0x5a);
/// Amber accent for Reject, and for everything that was decided but not
/// applied (observe mode's would-block, an expiring prompt, a posture).
pub const REJECT_COLOR: Color32 = Color32::from_rgb(0xe8, 0xa8, 0x2e);

/// Rounding shared by cards, banners and tiles.
const CARD_RADIUS: u8 = 10;
/// Rounding for controls: buttons, fields, chips.
const CONTROL_RADIUS: u8 = 7;

/// How opaque a colour's own tint is when it becomes a background.
///
/// One constant rather than a number per call site: a pill, a banner and a
/// selected tab are the same idea at three sizes, and they have to keep
/// reading as the same idea.
const TINT: f32 = 0.16;

/// The tone a banner, pill or tile is speaking in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// Neutral, brand-coloured: a fact.
    Info,
    /// Something is working: allowed, connected, enforcing.
    Good,
    /// Something is deliberately off, or about to matter.
    Warn,
    /// Something is blocked, failed, or lost.
    Bad,
}

impl Tone {
    pub fn color(self) -> Color32 {
        match self {
            Tone::Info => ACCENT,
            Tone::Good => ALLOW_COLOR,
            Tone::Warn => REJECT_COLOR,
            Tone::Bad => DENY_COLOR,
        }
    }
}

/// `color` as a background: its own hue, dimmed onto the dark surface.
pub fn tint(color: Color32) -> Color32 {
    BG.lerp_to_gamma(color, TINT)
}

/// The same wash at half strength, for a whole panel rather than a chip.
/// At full strength a large area of tinted red or amber turns muddy and
/// stops reading as its own colour.
pub fn tint_soft(color: Color32) -> Color32 {
    BG.lerp_to_gamma(color, TINT / 2.0)
}

/// A panel that takes the colour of what it is about, with the colour
/// itself carried by an edge rather than by the whole fill.
pub fn band<R>(ui: &mut Ui, color: Color32, add: impl FnOnce(&mut Ui) -> R) -> R {
    let frame = egui::Frame::new()
        .fill(tint_soft(color))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.35)))
        .corner_radius(CornerRadius::same(CARD_RADIUS - 2))
        .inner_margin(Margin {
            left: 12,
            right: 10,
            top: 7,
            bottom: 7,
        });
    let out = frame.show(ui, |ui| {
        ui.set_width(ui.available_width());
        add(ui)
    });
    let rect = out.response.rect;
    ui.painter().rect_filled(
        egui::Rect::from_min_size(rect.min, Vec2::new(3.0, rect.height())),
        CornerRadius {
            nw: CARD_RADIUS - 2,
            sw: CARD_RADIUS - 2,
            ne: 0,
            se: 0,
        },
        color,
    );
    out.inner
}

// ---- style ---------------------------------------------------------------

/// Install the palette on `ctx`, once per context.
///
/// Called from every entry point that can be the first one on a frame (the
/// management window, a prompt window, the rule editor) rather than only at
/// startup: tests drive each of those directly, and a screen that came up
/// unstyled would be a different layout from the one shipped - which is
/// exactly what the prompt window's fixed size makes load-bearing.
pub fn ensure_installed(ctx: &egui::Context) {
    let id = egui::Id::new("hallpass-theme");
    if ctx.data(|d| d.get_temp::<bool>(id)).unwrap_or(false) {
        return;
    }
    ctx.data_mut(|d| d.insert_temp(id, true));
    install(ctx);
}

/// The weight bold text is set in, on the variable interface face. egui's
/// `strong` only brightens the colour; this is what makes a title a title.
pub const SEMIBOLD: f32 = 600.0;

/// Put Inter in front of egui's own proportional fonts.
///
/// egui's default face is a light weight that reads thin at the sizes a
/// dense table uses, and has one weight only. Inter is drawn for small
/// text on screens and is variable, so titles can be set heavier without
/// a second file. The defaults stay behind it, for the glyphs the bundled
/// subset leaves out (anything past Latin, and the symbols the banners
/// use).
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "inter".to_owned(),
        std::sync::Arc::new(egui::FontData::from_static(include_bytes!(
            "../assets/fonts/InterUI.ttf"
        ))),
    );
    if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
        family.insert(0, "inter".to_owned());
    }
    ctx.set_fonts(fonts);
}

fn install(ctx: &egui::Context) {
    use egui::{FontFamily::Monospace, FontFamily::Proportional, FontId, TextStyle};

    install_fonts(ctx);

    let mut style = (*ctx.style_of(egui::Theme::Dark)).clone();

    style.text_styles = [
        (TextStyle::Heading, FontId::new(19.0, Proportional)),
        (TextStyle::Body, FontId::new(13.5, Proportional)),
        (TextStyle::Button, FontId::new(13.5, Proportional)),
        (TextStyle::Small, FontId::new(11.0, Proportional)),
        (TextStyle::Monospace, FontId::new(12.5, Monospace)),
    ]
    .into();

    let spacing = &mut style.spacing;
    spacing.item_spacing = Vec2::new(8.0, 6.0);
    spacing.button_padding = Vec2::new(10.0, 4.0);
    spacing.interact_size.y = 26.0;
    spacing.window_margin = Margin::same(12);
    spacing.menu_margin = Margin::same(6);
    spacing.indent = 18.0;
    spacing.scroll.bar_width = 9.0;
    spacing.scroll.floating = false;

    let v = &mut style.visuals;
    v.dark_mode = true;
    v.panel_fill = BG;
    v.window_fill = SURFACE;
    v.window_stroke = Stroke::new(1.0, HAIRLINE);
    v.window_corner_radius = CornerRadius::same(CARD_RADIUS + 2);
    v.window_shadow = egui::epaint::Shadow {
        offset: [0, 10],
        blur: 32,
        spread: 0,
        color: Color32::from_black_alpha(140),
    };
    v.popup_shadow = egui::epaint::Shadow {
        offset: [0, 6],
        blur: 18,
        spread: 0,
        color: Color32::from_black_alpha(120),
    };
    v.menu_corner_radius = CornerRadius::same(CONTROL_RADIUS);
    v.extreme_bg_color = WELL;
    v.faint_bg_color = Color32::from_rgb(0x15, 0x1a, 0x24);
    v.code_bg_color = Color32::from_rgb(0x18, 0x1e, 0x29);
    v.hyperlink_color = ACCENT;
    v.warn_fg_color = REJECT_COLOR;
    v.error_fg_color = DENY_COLOR;
    v.selection.bg_fill = ACCENT.gamma_multiply(0.35);
    v.selection.stroke = Stroke::new(1.0, TEXT);
    v.striped = true;
    v.slider_trailing_fill = true;
    // The one thing a hover must always do here is say "this is live":
    // rows are dense and the pointer is often the only thing telling an
    // operator which one they are about to act on.
    v.widgets.noninteractive = egui::style::WidgetVisuals {
        bg_fill: SURFACE,
        weak_bg_fill: SURFACE,
        bg_stroke: Stroke::new(1.0, HAIRLINE),
        fg_stroke: Stroke::new(1.0, TEXT),
        corner_radius: CornerRadius::same(CONTROL_RADIUS),
        expansion: 0.0,
    };
    v.widgets.inactive = egui::style::WidgetVisuals {
        bg_fill: SURFACE_CONTROL,
        weak_bg_fill: SURFACE_CONTROL,
        bg_stroke: Stroke::new(1.0, HAIRLINE),
        fg_stroke: Stroke::new(1.0, Color32::from_rgb(0xc5, 0xcd, 0xdd)),
        corner_radius: CornerRadius::same(CONTROL_RADIUS),
        expansion: 0.0,
    };
    v.widgets.hovered = egui::style::WidgetVisuals {
        bg_fill: Color32::from_rgb(0x2c, 0x35, 0x46),
        weak_bg_fill: Color32::from_rgb(0x2c, 0x35, 0x46),
        bg_stroke: Stroke::new(1.0, ACCENT.gamma_multiply(0.55)),
        fg_stroke: Stroke::new(1.0, TEXT),
        corner_radius: CornerRadius::same(CONTROL_RADIUS),
        expansion: 1.0,
    };
    v.widgets.active = egui::style::WidgetVisuals {
        bg_fill: Color32::from_rgb(0x35, 0x40, 0x55),
        weak_bg_fill: Color32::from_rgb(0x35, 0x40, 0x55),
        bg_stroke: Stroke::new(1.0, ACCENT),
        fg_stroke: Stroke::new(1.0, Color32::WHITE),
        corner_radius: CornerRadius::same(CONTROL_RADIUS),
        expansion: 0.0,
    };
    v.widgets.open = egui::style::WidgetVisuals {
        bg_fill: SURFACE_CONTROL,
        weak_bg_fill: SURFACE_CONTROL,
        bg_stroke: Stroke::new(1.0, ACCENT.gamma_multiply(0.7)),
        fg_stroke: Stroke::new(1.0, TEXT),
        corner_radius: CornerRadius::same(CONTROL_RADIUS),
        expansion: 0.0,
    };

    // Both themes, then dark: a desktop set to light must not hand this
    // window a light background with a palette calibrated against a dark
    // one, which is the one way these colours stop being readable.
    ctx.set_style_of(egui::Theme::Dark, style.clone());
    ctx.set_style_of(egui::Theme::Light, style);
    ctx.set_theme(egui::ThemePreference::Dark);
}

/// The frame a card is drawn in: a raised surface with a hairline.
pub fn card_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(SURFACE_RAISED)
        .stroke(Stroke::new(1.0, HAIRLINE))
        .corner_radius(CornerRadius::same(CARD_RADIUS))
        .inner_margin(Margin::symmetric(12, 10))
}

/// A titled card. The title is the small muted line every panel here
/// starts with, so sections are told apart by position rather than by
/// separators stacked down the page.
pub fn card<R>(ui: &mut Ui, title: &str, add: impl FnOnce(&mut Ui) -> R) -> R {
    card_frame()
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            // Left-aligned rather than inheriting the caller's layout: a
            // card dropped into a justified column would otherwise
            // stretch every button inside it to the card's full width.
            ui.vertical(|ui| {
                if !title.is_empty() {
                    ui.label(
                        egui::RichText::new(title)
                            .small()
                            .color(MUTED)
                            .strong()
                            .variation("wght", SEMIBOLD)
                            .line_height(Some(16.0)),
                    );
                    ui.add_space(2.0);
                }
                add(ui)
            })
            .inner
        })
        .inner
}

// ---- small painted parts -------------------------------------------------

/// A filled chip: a short word in its own colour, on a dim wash of it.
///
/// Carries an accessible label, because in the tables a pill is the only
/// thing saying what happened to a connection.
pub fn pill(ui: &mut Ui, text: &str, color: Color32) -> Response {
    pill_sized(ui, text, color, egui::TextStyle::Small.resolve(ui.style()))
}

fn pill_sized(ui: &mut Ui, text: &str, color: Color32, font: egui::FontId) -> Response {
    let galley = ui.painter().layout_no_wrap(text.to_owned(), font, color);
    let pad = Vec2::new(7.0, 2.0);
    let (rect, response) = ui.allocate_exact_size(galley.size() + pad * 2.0, egui::Sense::hover());
    if ui.is_rect_visible(rect) {
        ui.painter()
            .rect_filled(rect, CornerRadius::same(CONTROL_RADIUS - 2), tint(color));
        ui.painter().galley(rect.min + pad, galley, color);
    }
    let label = text.to_owned();
    response
        .widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Label, true, label.clone()));
    response
}

/// A pill with no fill: for things that are true but unremarkable (a tag,
/// a protocol), where a wash of colour would compete with the verdicts.
pub fn ghost_pill(ui: &mut Ui, text: &str) -> Response {
    let font = egui::TextStyle::Small.resolve(ui.style());
    let galley = ui.painter().layout_no_wrap(text.to_owned(), font, MUTED);
    let pad = Vec2::new(6.0, 2.0);
    let (rect, response) = ui.allocate_exact_size(galley.size() + pad * 2.0, egui::Sense::hover());
    if ui.is_rect_visible(rect) {
        ui.painter().rect(
            rect,
            CornerRadius::same(CONTROL_RADIUS - 2),
            Color32::TRANSPARENT,
            Stroke::new(1.0, HAIRLINE),
            egui::StrokeKind::Inside,
        );
        ui.painter().galley(rect.min + pad, galley, MUTED);
    }
    let label = text.to_owned();
    response
        .widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Label, true, label.clone()));
    response
}

/// A full-width notice with a coloured edge: the whole-host facts (a
/// posture, observe mode, a lost connection) that have to be readable
/// from across the room and from whatever tab is open.
pub fn banner(ui: &mut Ui, tone: Tone, glyph: &str, title: &str, body: &str) {
    let color = tone.color();
    let frame = egui::Frame::new()
        .fill(tint(color))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.45)))
        .corner_radius(CornerRadius::same(CARD_RADIUS))
        .inner_margin(Margin {
            // Extra on the left: the coloured edge painted below sits
            // inside the frame, so the text starts clear of it.
            left: 14,
            right: 12,
            top: 8,
            bottom: 8,
        });
    let rect = frame
        .show(ui, |ui| {
            // Edge to edge: a whole-host notice that hugs its own words
            // reads as one more card, not as the state of the window.
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                ui.label(
                    egui::RichText::new(glyph)
                        .color(color)
                        .strong()
                        .variation("wght", SEMIBOLD),
                );
                ui.label(
                    egui::RichText::new(title)
                        .color(color)
                        .strong()
                        .variation("wght", SEMIBOLD),
                );
                if !body.is_empty() {
                    ui.label(egui::RichText::new(body).color(TEXT));
                }
            });
        })
        .response
        .rect;
    // The edge, painted over the frame that was just drawn: a rounded
    // rect cannot carry one thick side on its own.
    ui.painter().rect_filled(
        egui::Rect::from_min_size(rect.min, Vec2::new(3.0, rect.height())),
        CornerRadius {
            nw: CARD_RADIUS,
            sw: CARD_RADIUS,
            ne: 0,
            se: 0,
        },
        color,
    );
}

/// A status dot with a soft halo: the daemon link, where the colour is
/// the whole message and the words beside it are the detail.
///
/// Deliberately still. An animated dot would have to ask for a repaint
/// every frame forever, which is a busy CPU on an idle desktop for a fact
/// that is already on screen in two other ways.
pub fn status_dot(ui: &mut Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(10.0), egui::Sense::hover());
    let c = rect.center();
    ui.painter()
        .circle_filled(c, 5.0, color.gamma_multiply(0.25));
    ui.painter().circle_filled(c, 3.0, color);
}

/// A horizontal bar split into coloured segments, sized to `size`.
///
/// The traffic table's whole point is proportion - this application is
/// mostly allowed, that one is mostly blocked - and four numbers in four
/// columns do not carry it. Segments under a pixel are widened to one, so
/// a single blocked connection in ten thousand still shows.
pub fn ratio_bar(ui: &mut Ui, size: Vec2, segments: &[(u64, Color32)]) -> Response {
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::hover());
    if !ui.is_rect_visible(rect) {
        return response;
    }
    let radius = CornerRadius::same((size.y / 2.0) as u8);
    ui.painter()
        .rect_filled(rect, radius, Color32::from_rgb(0x1e, 0x24, 0x30));
    let total: u64 = segments.iter().map(|(n, _)| *n).sum();
    if total == 0 {
        return response;
    }
    let mut x = rect.left();
    for (n, color) in segments {
        if *n == 0 {
            continue;
        }
        let w = (rect.width() * (*n as f32 / total as f32)).max(1.5);
        let seg = egui::Rect::from_min_max(
            egui::pos2(x, rect.top()),
            egui::pos2((x + w).min(rect.right()), rect.bottom()),
        );
        ui.painter().rect_filled(seg, radius, *color);
        x += w;
    }
    response
}

/// The activity strip: one stacked column per time slice, newest at the
/// right.
///
/// A thousand rows of feed say what happened; this says when, and whether
/// the denies are a steady trickle or the last ten seconds. Scaled to its
/// own busiest column, so an idle machine still shows its shape. Hovering
/// a column lights it and names its counts, so a spike can be read as
/// numbers without leaving the feed.
pub fn activity_strip(
    ui: &mut Ui,
    height: f32,
    buckets: &[crate::traffic::Bucket],
    describe: impl Fn(usize) -> String,
) -> Response {
    let width = ui.available_width();
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, height), egui::Sense::hover());
    if !ui.is_rect_visible(rect) || buckets.is_empty() {
        return response;
    }
    let painter = ui.painter();
    painter.rect_filled(rect, CornerRadius::same(CARD_RADIUS - 2), WELL);
    let inner = rect.shrink2(Vec2::new(8.0, 6.0));
    // Quarter lines, so a column's height reads against something.
    for f in [0.25, 0.5, 0.75] {
        painter.hline(
            inner.x_range(),
            inner.bottom() - inner.height() * f,
            Stroke::new(1.0, HAIRLINE.gamma_multiply(0.35)),
        );
    }
    let peak = buckets.iter().map(|b| b.total()).max().unwrap_or(0).max(1) as f32;
    let step = inner.width() / buckets.len() as f32;
    let bar_w = (step - 2.0).clamp(1.0, 10.0);
    let hovered = response
        .hover_pos()
        .filter(|p| inner.x_range().contains(p.x))
        .map(|p| (((p.x - inner.left()) / step) as usize).min(buckets.len() - 1));
    if let Some(i) = hovered {
        let x = inner.left() + step * i as f32;
        painter.rect_filled(
            egui::Rect::from_x_y_ranges(x..=x + step, rect.y_range()),
            CornerRadius::same(2),
            SURFACE_CONTROL.gamma_multiply(0.7),
        );
    }
    for (i, b) in buckets.iter().enumerate() {
        if b.total() == 0 {
            continue;
        }
        // The rest dim while one column is under the pointer, so the one
        // being read stands out of the shape it belongs to.
        let dim = if hovered.is_some_and(|h| h != i) {
            0.55
        } else {
            1.0
        };
        let x = inner.left() + step * i as f32 + (step - bar_w) / 2.0;
        let mut y = inner.bottom();
        // Stacked blocked-first from the bottom, so the red base line is
        // continuous across columns and readable as one shape.
        for (n, color) in [
            (b.blocked, DENY_COLOR),
            (b.would_block, REJECT_COLOR),
            (b.allowed, ALLOW_COLOR),
        ] {
            if n == 0 {
                continue;
            }
            let h = (inner.height() * (n as f32 / peak)).max(1.5);
            let seg = egui::Rect::from_min_max(
                egui::pos2(x, (y - h).max(inner.top())),
                egui::pos2(x + bar_w, y),
            );
            painter.rect_filled(seg, CornerRadius::same(2), color.gamma_multiply(dim));
            y -= h + 0.5;
        }
    }
    // Baseline, so an empty stretch still reads as time rather than as a
    // gap in the widget.
    painter.hline(
        inner.x_range(),
        inner.bottom() + 1.0,
        Stroke::new(1.0, HAIRLINE),
    );
    match hovered {
        Some(i) => response.on_hover_ui_at_pointer(|ui| {
            let b = buckets[i];
            ui.label(RichText::new(describe(i)).small().color(MUTED));
            for (n, what, color) in [
                (b.allowed, "allowed", ALLOW_COLOR),
                (b.blocked, "blocked", DENY_COLOR),
                (b.would_block, "not enforced", REJECT_COLOR),
            ] {
                if n > 0 || what != "not enforced" {
                    ui.horizontal(|ui| {
                        status_dot(ui, color);
                        ui.label(num(n.to_string()));
                        ui.label(RichText::new(what).color(MUTED));
                    });
                }
            }
        }),
        None => response,
    }
}

/// A headline number in a card: what the Stats tab leads with.
///
/// Washed faintly in its own colour, with a short bar of it along the top
/// edge, so the four tiles are told apart by colour before their labels
/// are read.
pub fn stat_tile(ui: &mut Ui, width: f32, label: &str, value: &str, color: Color32, sub: &str) {
    let rect = card_frame()
        .fill(SURFACE_RAISED.lerp_to_gamma(color, 0.05))
        .inner_margin(Margin {
            left: 14,
            right: 12,
            top: 12,
            bottom: 10,
        })
        .show(ui, |ui| {
            ui.set_width(width);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.label(
                    RichText::new(label)
                        .small()
                        .color(MUTED)
                        .strong()
                        .variation("wght", SEMIBOLD),
                );
                ui.label(
                    RichText::new(value)
                        .color(color)
                        .font(egui::FontId::proportional(28.0)),
                );
                ui.label(RichText::new(sub).small().color(MUTED));
            });
        })
        .response
        .rect;
    ui.painter().rect_filled(
        egui::Rect::from_min_size(rect.min + Vec2::new(14.0, 1.0), Vec2::new(28.0, 2.0)),
        CornerRadius::same(1),
        color,
    );
}

/// A switch. Reads as on or off from across the room, which a tick in a
/// box does not, and the mode of a firewall is the one thing in this
/// window worth that.
///
/// Announced to accessibility as the checkbox it replaces, so the label is
/// still what reaches a screen reader (and the widget tests).
pub fn switch(ui: &mut Ui, on: &mut bool, label: &str) -> Response {
    switch_impl(ui, on, label, true)
}

/// The same switch with no words beside it, for a table column whose
/// heading already says what it switches. `label` still names it to a
/// screen reader.
pub fn switch_bare(ui: &mut Ui, on: &mut bool, label: &str) -> Response {
    switch_impl(ui, on, label, false)
}

fn switch_impl(ui: &mut Ui, on: &mut bool, label: &str, visible_label: bool) -> Response {
    let font = egui::TextStyle::Body.resolve(ui.style());
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_owned(), font, Color32::PLACEHOLDER);
    let track = Vec2::new(32.0, 17.0);
    let size = if visible_label {
        Vec2::new(
            track.x + 7.0 + galley.size().x,
            track.y.max(galley.size().y),
        )
    } else {
        track
    };
    let (rect, mut response) = ui.allocate_exact_size(size, egui::Sense::click());
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    let enabled = ui.is_enabled();
    let is_on = *on;
    let text = label.to_owned();
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::Checkbox, enabled, is_on, text.clone())
    });

    if ui.is_rect_visible(rect) {
        let how_on = ui.ctx().animate_bool_responsive(response.id, *on);
        let track_rect = egui::Rect::from_min_size(
            egui::pos2(rect.left(), rect.center().y - track.y / 2.0),
            track,
        );
        let off_fill = SURFACE_CONTROL;
        let on_fill = if enabled {
            ALLOW_COLOR.gamma_multiply(0.9)
        } else {
            ALLOW_COLOR.gamma_multiply(0.4)
        };
        let fill = off_fill.lerp_to_gamma(on_fill, how_on);
        ui.painter().rect(
            track_rect,
            CornerRadius::same((track.y / 2.0) as u8),
            fill,
            Stroke::new(1.0, if response.hovered() { ACCENT } else { HAIRLINE }),
            egui::StrokeKind::Inside,
        );
        let knob_x = egui::lerp(
            (track_rect.left() + track.y / 2.0)..=(track_rect.right() - track.y / 2.0),
            how_on,
        );
        let knob = egui::pos2(knob_x, track_rect.center().y);
        ui.painter().circle_filled(
            knob + Vec2::new(0.0, 1.0),
            track.y / 2.0 - 2.0,
            Color32::from_black_alpha(70),
        );
        ui.painter().circle_filled(
            knob,
            track.y / 2.0 - 2.5,
            if enabled { Color32::WHITE } else { MUTED },
        );
        if response.has_focus() {
            focus_ring(ui, track_rect, (track.y / 2.0) as u8);
        }
        if !visible_label {
            return response;
        }
        let text_color = if enabled { TEXT } else { MUTED };
        let galley = ui.painter().layout_no_wrap(
            label.to_owned(),
            egui::TextStyle::Body.resolve(ui.style()),
            text_color,
        );
        ui.painter().galley(
            egui::pos2(
                track_rect.right() + 7.0,
                rect.center().y - galley.size().y / 2.0,
            ),
            galley,
            text_color,
        );
    }
    response
}

/// How a [`segmented`] control is drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Segments {
    /// The window's tab bar: full height, floating on the header.
    Tabs,
    /// A filter or a picker: shorter, and sunk into a track so its options
    /// read as one control with one answer.
    Picker,
}

/// How long the selection takes to slide from one option to the next.
/// Long enough to be seen travelling, short enough that a quick second
/// click never waits on the first.
const SLIDE_SECS: f64 = 0.2;

/// Where a segmented control's indicator is, and where it was heading.
///
/// Kept relative to the control, so a window resize or a scroll moves the
/// indicator with its options instead of animating it across the screen.
#[derive(Debug, Clone, Copy)]
struct Slide {
    to: usize,
    start: f64,
    from: egui::Rect,
    from_color: Color32,
    shown: egui::Rect,
    shown_color: Color32,
}

/// A row of options with one highlight that slides to whichever is picked.
/// Returns the option clicked this pass, if any.
///
/// One moving indicator rather than a fill per option: the eye follows the
/// motion from the old choice to the new one, so a click that landed on the
/// wrong option is noticed at once. Each option carries its own colour, so
/// a picker whose options are verdicts says which one is set in the same
/// language the rest of the window uses, and the indicator changes colour
/// on its way across.
///
/// Every option is its own focus stop and is announced as a selectable
/// label, the same as the separate buttons this replaces.
pub fn segmented(
    ui: &mut Ui,
    id_salt: impl std::hash::Hash + std::fmt::Debug,
    items: &[(&str, Color32)],
    selected: usize,
    kind: Segments,
) -> Option<usize> {
    let (height, pad_x, inset, gap, radius) = match kind {
        Segments::Tabs => (28.0, 11.0, 0.0, 4.0, CONTROL_RADIUS),
        Segments::Picker => (22.0, 9.0, 2.0, 1.0, CONTROL_RADIUS - 1),
    };
    let id = ui.make_persistent_id(("segmented", id_salt));
    let font = egui::TextStyle::Button.resolve(ui.style());
    let galleys: Vec<_> = items
        .iter()
        .map(|(text, _)| {
            ui.painter()
                .layout_no_wrap((*text).to_owned(), font.clone(), Color32::PLACEHOLDER)
        })
        .collect();
    let widths: Vec<f32> = galleys.iter().map(|g| g.size().x + pad_x * 2.0).collect();
    let total =
        widths.iter().sum::<f32>() + gap * items.len().saturating_sub(1) as f32 + inset * 2.0;
    let (outer, _) =
        ui.allocate_exact_size(Vec2::new(total, height + inset * 2.0), egui::Sense::hover());

    let mut rects = Vec::with_capacity(items.len());
    let mut x = outer.left() + inset;
    for w in &widths {
        rects.push(egui::Rect::from_min_size(
            egui::pos2(x, outer.top() + inset),
            Vec2::new(*w, height),
        ));
        x += w + gap;
    }

    let enabled = ui.is_enabled();
    let mut clicked = None;
    let mut responses = Vec::with_capacity(items.len());
    for (i, rect) in rects.iter().enumerate() {
        let response = ui.interact(*rect, id.with(i), egui::Sense::click());
        let label = items[i].0.to_owned();
        let is_selected = i == selected;
        response.widget_info(|| {
            egui::WidgetInfo::selected(
                egui::WidgetType::SelectableLabel,
                enabled,
                is_selected,
                label.clone(),
            )
        });
        if response.clicked() {
            clicked = Some(i);
        }
        responses.push(response);
    }
    if !ui.is_rect_visible(outer) || items.is_empty() {
        return clicked;
    }

    let selected = selected.min(items.len() - 1);
    let target = rects[selected].translate(-outer.min.to_vec2());
    let target_color = items[selected].1;
    let now = ui.input(|i| i.time);
    let animate = ui.style().animation_time > 0.0;
    let mut slide = ui
        .data(|d| d.get_temp::<Slide>(id))
        .filter(|_| animate)
        .unwrap_or(Slide {
            to: selected,
            start: f64::NEG_INFINITY,
            from: target,
            from_color: target_color,
            shown: target,
            shown_color: target_color,
        });
    if slide.to != selected {
        slide = Slide {
            to: selected,
            start: now,
            from: slide.shown,
            from_color: slide.shown_color,
            ..slide
        };
    }
    let t = ((now - slide.start) / SLIDE_SECS).clamp(0.0, 1.0) as f32;
    let eased = 1.0 - (1.0 - t).powi(3);
    slide.shown = egui::Rect::from_min_max(
        slide.from.min.lerp(target.min, eased),
        slide.from.max.lerp(target.max, eased),
    );
    slide.shown_color = slide.from_color.lerp_to_gamma(target_color, eased);
    ui.data_mut(|d| d.insert_temp(id, slide));
    if t < 1.0 {
        ui.ctx().request_repaint();
    }

    let painter = ui.painter();
    if kind == Segments::Picker {
        painter.rect(
            outer,
            CornerRadius::same(radius + inset as u8),
            WELL,
            Stroke::new(1.0, HAIRLINE),
            egui::StrokeKind::Inside,
        );
    }
    for (i, response) in responses.iter().enumerate() {
        if i != selected && response.hovered() {
            painter.rect_filled(
                rects[i],
                CornerRadius::same(radius),
                SURFACE_CONTROL.gamma_multiply(0.6),
            );
        }
    }
    let indicator = slide.shown.translate(outer.min.to_vec2());
    let color = slide.shown_color;
    match kind {
        Segments::Tabs => {
            painter.rect_filled(indicator, CornerRadius::same(radius), tint(color));
            // The underline is what makes the selection legible at a
            // glance across the room, where the wash alone is faint.
            let w = indicator.width() * 0.5;
            let y = indicator.bottom() - 3.0;
            painter.line_segment(
                [
                    egui::pos2(indicator.center().x - w / 2.0, y),
                    egui::pos2(indicator.center().x + w / 2.0, y),
                ],
                Stroke::new(2.0, color),
            );
        }
        Segments::Picker => {
            painter.rect(
                indicator,
                CornerRadius::same(radius),
                SURFACE_CONTROL.lerp_to_gamma(color, 0.22),
                Stroke::new(1.0, color.gamma_multiply(0.55)),
                egui::StrokeKind::Inside,
            );
        }
    }
    for (i, (galley, response)) in galleys.into_iter().zip(&responses).enumerate() {
        let text = if i == selected {
            TEXT
        } else if response.hovered() {
            TEXT.gamma_multiply(0.9)
        } else {
            MUTED
        };
        let text = if enabled {
            text
        } else {
            text.gamma_multiply(0.5)
        };
        let nudge = if kind == Segments::Tabs { -1.0 } else { 0.0 };
        painter.galley(
            rects[i].center() - galley.size() / 2.0 + Vec2::new(0.0, nudge),
            galley,
            text,
        );
        if response.has_focus() {
            focus_ring(ui, rects[i], radius);
        }
    }
    clicked
}

/// The keyboard focus outline every painted control here draws, so a
/// Tab press is visible whichever control it lands on.
fn focus_ring(ui: &Ui, rect: egui::Rect, radius: u8) {
    ui.painter().rect_stroke(
        rect.expand(1.5),
        CornerRadius::same(radius + 1),
        Stroke::new(1.5, ACCENT),
        egui::StrokeKind::Outside,
    );
}

/// A button that is text until the pointer reaches it: for actions
/// repeated down every row of a table, where a column of framed buttons
/// is louder than the data beside it.
///
/// `hot` lights the text at rest, for a row the pointer is already on.
pub fn ghost_button(ui: &mut Ui, text: &str, color: Color32, hot: bool) -> Response {
    let font = egui::TextStyle::Button.resolve(ui.style());
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_owned(), font, Color32::PLACEHOLDER);
    let pad = Vec2::new(8.0, 3.0);
    let (rect, response) = ui.allocate_exact_size(galley.size() + pad * 2.0, egui::Sense::click());
    let label = text.to_owned();
    response
        .widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, label.clone()));
    if ui.is_rect_visible(rect) {
        let how_hot = ui
            .ctx()
            .animate_bool_responsive(response.id, response.hovered());
        if how_hot > 0.0 {
            ui.painter().rect(
                rect,
                CornerRadius::same(CONTROL_RADIUS - 1),
                Color32::TRANSPARENT.lerp_to_gamma(tint(color), how_hot),
                Stroke::new(1.0, color.gamma_multiply(0.45 * how_hot)),
                egui::StrokeKind::Inside,
            );
        }
        let rest = if hot {
            color.gamma_multiply(0.85)
        } else {
            MUTED.gamma_multiply(0.8)
        };
        let text = rest.lerp_to_gamma(color, how_hot);
        ui.painter().galley(rect.min + pad, galley, text);
        if response.has_focus() {
            focus_ring(ui, rect, CONTROL_RADIUS - 1);
        }
    }
    response
}

/// The one button on a screen that does what the screen is for.
pub fn primary_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(
        RichText::new(text)
            .color(Color32::WHITE)
            .strong()
            .variation("wght", SEMIBOLD),
    )
    .fill(ACCENT.gamma_multiply(0.85))
    .stroke(Stroke::new(1.0, ACCENT))
    .corner_radius(CornerRadius::same(CONTROL_RADIUS))
    .min_size(Vec2::new(84.0, 28.0))
}

/// The search field: a magnifier inside it, and a clear control once
/// there is something to clear.
///
/// Both painted into the field's own margins rather than placed beside it,
/// so the whole thing is one target and lines up with the pickers next to
/// it at their height.
pub fn search_field(
    ui: &mut Ui,
    text: &mut String,
    id: egui::Id,
    hint: &str,
    width: f32,
) -> Response {
    let response = ui.add(
        egui::TextEdit::singleline(text)
            .id(id)
            .hint_text(hint)
            .desired_width(width)
            .min_size(Vec2::new(0.0, 26.0))
            .vertical_align(egui::Align::Center)
            .margin(Margin {
                left: 28,
                right: 24,
                top: 3,
                bottom: 3,
            }),
    );
    let rect = response.rect;
    let focused = response.has_focus();
    let glass = if focused { ACCENT } else { MUTED };
    let c = egui::pos2(rect.left() + 14.0, rect.center().y - 1.0);
    let painter = ui.painter();
    painter.circle_stroke(c, 4.5, Stroke::new(1.5, glass));
    painter.line_segment(
        [c + Vec2::splat(3.3), c + Vec2::splat(7.0)],
        Stroke::new(1.8, glass),
    );
    if !text.is_empty() {
        let hit = egui::Rect::from_center_size(
            egui::pos2(rect.right() - 13.0, rect.center().y),
            Vec2::splat(18.0),
        );
        let clear = ui.interact(hit, id.with("clear"), egui::Sense::click());
        clear.widget_info(|| {
            egui::WidgetInfo::labeled(egui::WidgetType::Button, true, "Clear filter")
        });
        let color = if clear.hovered() { TEXT } else { MUTED };
        if clear.hovered() {
            ui.painter()
                .circle_filled(hit.center(), 8.0, SURFACE_CONTROL);
        }
        let (c, r) = (hit.center(), 3.5);
        for (a, b) in [
            (Vec2::new(-r, -r), Vec2::new(r, r)),
            (Vec2::new(-r, r), Vec2::new(r, -r)),
        ] {
            ui.painter()
                .line_segment([c + a, c + b], Stroke::new(1.5, color));
        }
        if clear.clicked() {
            text.clear();
        }
    }
    response
}

/// A sortable column heading: the title, plus an arrow when this is the
/// column the table is ordered by.
///
/// Painted rather than a plain label so the whole cell is the hit target:
/// these headings are small text, and a click that misses by two pixels
/// on a live table reads as the sort not working.
pub fn sort_header(ui: &mut Ui, title: &str, direction: Option<bool>) -> Response {
    let text = title.to_uppercase();
    let font = egui::TextStyle::Small.resolve(ui.style());
    let galley = ui
        .painter()
        .layout_no_wrap(text.clone(), font.clone(), Color32::PLACEHOLDER);
    // Room for the marker whether or not this column carries it, so the
    // headings do not shift sideways when the sort moves.
    let size = Vec2::new(
        galley.size().x + 16.0,
        galley.size().y.max(ui.available_height()),
    );
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
    let label = text.clone();
    response
        .widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, label.clone()));
    if ui.is_rect_visible(rect) {
        let color = match (direction.is_some(), response.hovered()) {
            (_, true) => TEXT,
            (true, _) => ACCENT,
            (false, _) => MUTED,
        };
        let galley = ui.painter().layout_no_wrap(text, font, color);
        let text_left = rect.left() + 2.0;
        ui.painter().galley(
            egui::pos2(text_left, rect.center().y - galley.size().y / 2.0),
            galley.clone(),
            color,
        );
        // Painted rather than written: the bundled fonts have no
        // dependable triangle, and a heading that renders as a hollow box
        // is worse than no marker at all.
        if let Some(descending) = direction {
            let x = text_left + galley.size().x + 5.0;
            let y = rect.center().y;
            let (a, b, tip) = if descending {
                (
                    egui::pos2(x, y - 2.0),
                    egui::pos2(x + 7.0, y - 2.0),
                    egui::pos2(x + 3.5, y + 2.5),
                )
            } else {
                (
                    egui::pos2(x, y + 2.0),
                    egui::pos2(x + 7.0, y + 2.0),
                    egui::pos2(x + 3.5, y - 2.5),
                )
            };
            ui.painter().add(egui::epaint::PathShape::convex_polygon(
                vec![a, b, tip],
                color,
                Stroke::NONE,
            ));
        }
    }
    response
}

/// A verdict button for the prompt window: big, filled, and unmistakably
/// the thing to press.
pub fn verdict_button(text: &str, color: Color32) -> egui::Button<'static> {
    egui::Button::new(
        egui::RichText::new(text)
            .color(Color32::WHITE)
            .strong()
            .variation("wght", SEMIBOLD)
            .size(14.5),
    )
    .fill(color)
    .stroke(Stroke::new(1.0, color.gamma_multiply(1.3)))
    .corner_radius(CornerRadius::same(CONTROL_RADIUS + 1))
    .min_size(Vec2::new(118.0, 34.0))
}

/// The countdown under a prompt: a bar that drains and warms as the
/// default verdict approaches.
///
/// The colour is the point. A prompt at twenty seconds and one at two are
/// the same widget with the same words, and the second one is about to
/// decide itself.
pub fn countdown(ui: &mut Ui, fraction: f32, text: &str) {
    let color = if fraction > 0.5 {
        ALLOW_COLOR
    } else if fraction > 0.2 {
        REJECT_COLOR
    } else {
        DENY_COLOR
    };
    let height = 17.0;
    let (rect, _) = ui.allocate_exact_size(
        Vec2::new(ui.available_width(), height),
        egui::Sense::hover(),
    );
    if !ui.is_rect_visible(rect) {
        return;
    }
    let radius = CornerRadius::same((height / 2.0) as u8);
    ui.painter().rect_filled(rect, radius, SURFACE);
    let filled = egui::Rect::from_min_size(
        rect.min,
        Vec2::new((rect.width() * fraction.clamp(0.0, 1.0)).max(2.0), height),
    );
    ui.painter()
        .rect_filled(filled, radius, color.gamma_multiply(0.55));
    ui.painter().rect(
        rect,
        radius,
        Color32::TRANSPARENT,
        Stroke::new(1.0, color.gamma_multiply(0.5)),
        egui::StrokeKind::Inside,
    );
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        text,
        egui::TextStyle::Small.resolve(ui.style()),
        TEXT,
    );
}

/// The brand mark: a shield in the colour of whatever the host is doing.
///
/// The icon is the status, for the same reason the tray icon is: this
/// window is often glanced at rather than read, and the top-left corner is
/// where a glance lands first.
pub fn brand(ui: &mut Ui, color: Color32) -> Response {
    mark(ui, 20.0, color)
}

/// The mark at any size: the corner brand, and the large quiet one an empty
/// tab is drawn around.
pub fn mark(ui: &mut Ui, width: f32, color: Color32) -> Response {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(width, width * 1.1), egui::Sense::hover());
    if !ui.is_rect_visible(rect) {
        return response;
    }
    let (outline, bolt) = shield(rect.shrink(1.0));
    ui.painter().add(egui::epaint::PathShape::convex_polygon(
        outline,
        tint(color),
        Stroke::new((width / 14.0).max(1.4), color),
    ));
    ui.painter().add(egui::epaint::PathShape::convex_polygon(
        bolt,
        color,
        Stroke::NONE,
    ));
    response
}

/// The mark's geometry: the shield, and the bolt through it.
///
/// One definition, used by the painted mark and by the rasterized window
/// icon, so the thing in the corner and the thing in the taskbar are the
/// same drawing rather than two that drifted.
fn shield(r: egui::Rect) -> (Vec<egui::Pos2>, Vec<egui::Pos2>) {
    let (l, right, top, bottom) = (r.left(), r.right(), r.top(), r.bottom());
    let (w, h) = (r.width(), r.height());
    let shoulder = top + h * 0.55;
    // Flat shoulders, tapering to a point.
    let outline = vec![
        egui::pos2(l, top + h * 0.09),
        egui::pos2(right, top + h * 0.09),
        egui::pos2(right, shoulder),
        egui::pos2(r.center().x, bottom),
        egui::pos2(l, shoulder),
    ];
    // A bolt, so the mark reads at 16 pixels as well as it does at 64.
    let bolt = vec![
        egui::pos2(l + w * 0.55, top + h * 0.18),
        egui::pos2(l + w * 0.30, top + h * 0.52),
        egui::pos2(l + w * 0.47, top + h * 0.52),
        egui::pos2(l + w * 0.40, top + h * 0.86),
        egui::pos2(l + w * 0.70, top + h * 0.44),
        egui::pos2(l + w * 0.52, top + h * 0.44),
    ];
    (outline, bolt)
}

/// The window icon: the mark again, rasterized, in the colour of whatever
/// the host is doing.
///
/// Painted rather than shipped as a file so the taskbar entry can carry
/// the state the same way the corner mark and the tray icon do, and so
/// there is one drawing to keep in step instead of three.
pub fn icon(color: Color32) -> egui::IconData {
    const SIZE: u32 = 64;
    // Its own dark ground rather than the window's: this lands on a
    // taskbar of unknown colour, and a shield that borrows the desktop's
    // background is a shield-shaped hole.
    let ground = Color32::from_rgb(0x10, 0x16, 0x20);
    let rect = egui::Rect::from_min_size(
        egui::pos2(3.0, 2.0),
        Vec2::new(SIZE as f32 - 6.0, SIZE as f32 - 4.0),
    );
    let (outline, bolt) = shield(rect);
    let inner: Vec<egui::Pos2> = shrink_towards(&outline, 0.88);
    let mut rgba = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    for y in 0..SIZE {
        for x in 0..SIZE {
            // Three by three samples per pixel: the shield is all
            // diagonals, and at this size a hard edge looks broken.
            let (mut body, mut edge, mut spark) = (0.0f32, 0.0f32, 0.0f32);
            for sy in 0..3 {
                for sx in 0..3 {
                    let p = egui::pos2(
                        x as f32 + (sx as f32 + 0.5) / 3.0,
                        y as f32 + (sy as f32 + 0.5) / 3.0,
                    );
                    if contains(&bolt, p) {
                        spark += 1.0;
                    } else if contains(&inner, p) {
                        body += 1.0;
                    } else if contains(&outline, p) {
                        edge += 1.0;
                    }
                }
            }
            let coverage = (body + edge + spark) / 9.0;
            let pixel = if coverage == 0.0 {
                Color32::TRANSPARENT
            } else {
                // Mixed by which part won the pixel, so an edge sample
                // next to a body sample blends instead of stepping.
                let mix = |a: Color32, b: Color32, t: f32| a.lerp_to_gamma(b, t);
                let lit = spark + edge;
                mix(
                    ground,
                    color,
                    if coverage > 0.0 {
                        lit / (lit + body).max(1.0)
                    } else {
                        0.0
                    },
                )
            };
            let [r, g, b, _] = pixel.to_array();
            rgba.extend_from_slice(&[r, g, b, (coverage * 255.0) as u8]);
        }
    }
    egui::IconData {
        rgba,
        width: SIZE,
        height: SIZE,
    }
}

/// A polygon pulled towards its own centre, for the icon's inner fill.
fn shrink_towards(points: &[egui::Pos2], factor: f32) -> Vec<egui::Pos2> {
    let n = points.len() as f32;
    let cx = points.iter().map(|p| p.x).sum::<f32>() / n;
    let cy = points.iter().map(|p| p.y).sum::<f32>() / n;
    points
        .iter()
        .map(|p| egui::pos2(cx + (p.x - cx) * factor, cy + (p.y - cy) * factor))
        .collect()
}

/// Ray casting, because the bolt is not convex.
fn contains(poly: &[egui::Pos2], p: egui::Pos2) -> bool {
    let mut inside = false;
    let mut j = poly.len() - 1;
    for i in 0..poly.len() {
        let (a, b) = (poly[i], poly[j]);
        if (a.y > p.y) != (b.y > p.y) && p.x < (b.x - a.x) * (p.y - a.y) / (b.y - a.y) + a.x {
            inside = !inside;
        }
        j = i;
    }
    inside
}

/// The wordmark: spaced capitals, because this is a title and not a
/// sentence.
pub fn wordmark(ui: &mut Ui) {
    ui.label(
        egui::RichText::new("H A L L P A S S")
            .color(TEXT)
            .strong()
            .variation("wght", SEMIBOLD)
            .size(13.0),
    );
}

/// A key/value line in the detail cards: the key at the left, the value
/// pinned to the right edge, and a hairline between it and the line above.
///
/// Right-aligned rather than in a grid column, so the values of every
/// line in a card share one edge and a card twice as wide as its content
/// reads as a list rather than as two lumps with a gap between them.
pub fn stat_row(ui: &mut Ui, key: &str, value: impl FnOnce(&mut Ui)) {
    let width = ui.available_width();
    let rect = ui
        .allocate_ui_with_layout(
            Vec2::new(width, 26.0),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.set_min_size(Vec2::new(width, 26.0));
                ui.label(RichText::new(key).color(MUTED));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), value);
            },
        )
        .response
        .rect;
    ui.painter().hline(
        rect.x_range(),
        rect.top() - ui.spacing().item_spacing.y / 2.0,
        Stroke::new(1.0, HAIRLINE.gamma_multiply(0.6)),
    );
}

/// The mono style every number here is written in, so columns of digits
/// line up and a count never re-flows as it grows.
pub fn num(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text.into()).monospace().color(TEXT)
}

/// The same, dimmed: numbers that are context rather than the answer.
pub fn num_muted(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text.into()).monospace().color(MUTED)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three verdict colours have to stay apart from each other and
    /// from the background: they are the whole readout in a table of
    /// eleven-point text, and two of them are the difference between a
    /// connection that went out and one that did not.
    #[test]
    fn verdict_colors_are_distinct_and_legible() {
        let luma = |c: Color32| {
            0.2126 * f32::from(c.r()) + 0.7152 * f32::from(c.g()) + 0.0722 * f32::from(c.b())
        };
        for c in [ALLOW_COLOR, DENY_COLOR, REJECT_COLOR, TEXT, MUTED, ACCENT] {
            assert!(
                luma(c) - luma(BG) > 60.0,
                "{c:?} is too close to the background to read"
            );
        }
        for (a, b) in [
            (ALLOW_COLOR, DENY_COLOR),
            (ALLOW_COLOR, REJECT_COLOR),
            (DENY_COLOR, REJECT_COLOR),
        ] {
            let d = (f32::from(a.r()) - f32::from(b.r())).abs()
                + (f32::from(a.g()) - f32::from(b.g())).abs()
                + (f32::from(a.b()) - f32::from(b.b())).abs();
            assert!(d > 120.0, "{a:?} and {b:?} are too close to tell apart");
        }
    }

    /// The window icon has to be a shield on a transparent field, not a
    /// square: it lands on a taskbar whose colour this window does not
    /// know, and a full-bleed opaque icon is the one way that looks
    /// broken. Checked at the corners (outside the shield) and at the
    /// centre (inside it).
    #[test]
    fn the_window_icon_is_a_shield_on_transparency() {
        let icon = icon(ALLOW_COLOR);
        let (w, h) = (icon.width as usize, icon.height as usize);
        assert_eq!(icon.rgba.len(), w * h * 4);
        let alpha_at = |x: usize, y: usize| icon.rgba[(y * w + x) * 4 + 3];
        for (x, y) in [(0, 0), (w - 1, 0), (0, h - 1), (w - 1, h - 1)] {
            assert_eq!(alpha_at(x, y), 0, "the corner at {x},{y} is not clear");
        }
        assert_eq!(alpha_at(w / 2, h / 3), 255, "the shield has a hole in it");
    }

    /// Installing is idempotent and does not depend on being first: the
    /// prompt windows, the editor and the management window each call it on
    /// whatever frame they happen to open on.
    #[test]
    fn installing_twice_is_the_same_as_once() {
        let ctx = egui::Context::default();
        let _ = ctx.run_ui(Default::default(), |ui| {
            let ctx = ui.ctx();
            ensure_installed(ctx);
            let first = ctx.style_of(egui::Theme::Dark).visuals.panel_fill;
            ensure_installed(ctx);
            assert_eq!(first, ctx.style_of(egui::Theme::Dark).visuals.panel_fill);
            assert_eq!(first, BG);
        });
    }
}

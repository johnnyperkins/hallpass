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

use eframe::egui::{self, Color32, CornerRadius, Margin, Response, Stroke, Ui, Vec2};

// ---- palette -------------------------------------------------------------

/// Window background: the darkest surface, everything else sits on it.
pub const BG: Color32 = Color32::from_rgb(0x0e, 0x11, 0x17);
/// Panel background (the tab bar and the status bar).
pub const SURFACE: Color32 = Color32::from_rgb(0x14, 0x18, 0x21);
/// Raised surface: cards, tiles, the prompt's header band.
pub const SURFACE_RAISED: Color32 = Color32::from_rgb(0x1a, 0x1f, 0x2b);
/// One step above that, for controls at rest.
pub const SURFACE_CONTROL: Color32 = Color32::from_rgb(0x22, 0x29, 0x37);
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
/// main window, a prompt popup, the rule editor) rather than only at
/// startup: popups render from their own viewport callbacks, tests drive
/// each of those directly, and a screen that came up unstyled would be a
/// different layout from the one shipped - which is exactly what the
/// prompt window's fixed size makes load-bearing.
pub fn ensure_installed(ctx: &egui::Context) {
    let id = egui::Id::new("hallpass-theme");
    if ctx.data(|d| d.get_temp::<bool>(id)).unwrap_or(false) {
        return;
    }
    ctx.data_mut(|d| d.insert_temp(id, true));
    install(ctx);
}

fn install(ctx: &egui::Context) {
    use egui::{FontFamily::Monospace, FontFamily::Proportional, FontId, TextStyle};

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
    v.extreme_bg_color = Color32::from_rgb(0x0a, 0x0d, 0x13);
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
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                ui.label(egui::RichText::new(glyph).color(color).strong());
                ui.label(egui::RichText::new(title).color(color).strong());
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
/// own busiest column, so an idle machine still shows its shape.
pub fn activity_strip(ui: &mut Ui, height: f32, buckets: &[crate::traffic::Bucket]) -> Response {
    let width = ui.available_width();
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, height), egui::Sense::hover());
    if !ui.is_rect_visible(rect) || buckets.is_empty() {
        return response;
    }
    ui.painter()
        .rect_filled(rect, CornerRadius::same(CARD_RADIUS - 2), SURFACE);
    let peak = buckets.iter().map(|b| b.total()).max().unwrap_or(0).max(1) as f32;
    let inner = rect.shrink2(Vec2::new(6.0, 5.0));
    let step = inner.width() / buckets.len() as f32;
    let bar_w = (step - 2.0).clamp(1.0, 9.0);
    for (i, b) in buckets.iter().enumerate() {
        if b.total() == 0 {
            continue;
        }
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
            ui.painter().rect_filled(seg, CornerRadius::same(2), color);
            y -= h + 0.5;
        }
    }
    // Baseline, so an empty stretch still reads as time rather than as a
    // gap in the widget.
    ui.painter().line_segment(
        [
            egui::pos2(inner.left(), inner.bottom() + 1.0),
            egui::pos2(inner.right(), inner.bottom() + 1.0),
        ],
        Stroke::new(1.0, HAIRLINE),
    );
    response
}

/// A headline number in a card: what the Stats tab leads with.
pub fn stat_tile(ui: &mut Ui, width: f32, label: &str, value: &str, color: Color32, sub: &str) {
    card_frame().show(ui, |ui| {
        ui.set_width(width);
        ui.vertical(|ui| {
            ui.label(egui::RichText::new(label).small().color(MUTED).strong());
            ui.label(
                egui::RichText::new(value)
                    .color(color)
                    .font(egui::FontId::proportional(24.0)),
            );
            ui.label(egui::RichText::new(sub).small().color(MUTED));
        });
    });
}

/// A switch. Reads as on or off from across the room, which a tick in a
/// box does not, and the mode of a firewall is the one thing in this
/// window worth that.
///
/// Announced to accessibility as the checkbox it replaces, so the label is
/// still what reaches a screen reader (and the widget tests).
pub fn switch(ui: &mut Ui, on: &mut bool, label: &str) -> Response {
    let font = egui::TextStyle::Body.resolve(ui.style());
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_owned(), font, Color32::PLACEHOLDER);
    let track = Vec2::new(32.0, 17.0);
    let size = Vec2::new(
        track.x + 7.0 + galley.size().x,
        track.y.max(galley.size().y),
    );
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
        ui.painter().circle_filled(
            egui::pos2(knob_x, track_rect.center().y),
            track.y / 2.0 - 2.5,
            if enabled { Color32::WHITE } else { MUTED },
        );
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

/// The tab-bar button: a pill that fills in when its tab is the one on
/// screen, and lights its own underline on the way.
pub fn tab(ui: &mut Ui, selected: bool, text: &str) -> Response {
    tab_sized(ui, selected, text, 28.0, ACCENT)
}

/// The same control at the height a dense panel can afford. The prompt
/// window is a fixed 440x330 and every point the pickers take is a point
/// the process description does not get.
pub fn chip(ui: &mut Ui, selected: bool, text: &str) -> Response {
    tab_sized(ui, selected, text, 22.0, ACCENT)
}

/// A chip that lights up in a colour of its own when picked.
///
/// For the pickers whose options are verdicts: the choice is the colour
/// everywhere else in this window, so the control that sets it says so in
/// the same language instead of explaining itself in a second widget.
pub fn chip_colored(ui: &mut Ui, selected: bool, text: &str, accent: Color32) -> Response {
    tab_sized(ui, selected, text, 22.0, accent)
}

fn tab_sized(ui: &mut Ui, selected: bool, text: &str, height: f32, accent: Color32) -> Response {
    let font = egui::TextStyle::Button.resolve(ui.style());
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_owned(), font, Color32::PLACEHOLDER);
    let size = Vec2::new(galley.size().x + height * 0.8, height);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
    let label = text.to_owned();
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::SelectableLabel,
            true,
            selected,
            label.clone(),
        )
    });
    if ui.is_rect_visible(rect) {
        let how_on = ui.ctx().animate_bool_responsive(response.id, selected);
        let hovered = response.hovered() && !selected;
        let fill = if hovered {
            SURFACE_CONTROL.gamma_multiply(0.7)
        } else {
            Color32::TRANSPARENT
        };
        let fill = fill.lerp_to_gamma(tint(accent), how_on);
        ui.painter()
            .rect_filled(rect, CornerRadius::same(CONTROL_RADIUS), fill);
        // The underline is what makes the selection legible when several
        // tabs are tinted mid-animation.
        if how_on > 0.01 {
            let w = rect.width() * 0.55 * how_on;
            let y = rect.bottom() - 3.0;
            ui.painter().line_segment(
                [
                    egui::pos2(rect.center().x - w / 2.0, y),
                    egui::pos2(rect.center().x + w / 2.0, y),
                ],
                Stroke::new(2.0, accent),
            );
        }
        let color = if selected {
            TEXT
        } else if hovered {
            TEXT.gamma_multiply(0.9)
        } else {
            MUTED
        };
        let galley = ui.painter().layout_no_wrap(
            text.to_owned(),
            egui::TextStyle::Button.resolve(ui.style()),
            color,
        );
        ui.painter().galley(
            rect.center() - galley.size() / 2.0 + Vec2::new(0.0, -1.0),
            galley,
            color,
        );
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
    let size = Vec2::new(20.0, 22.0);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::hover());
    if !ui.is_rect_visible(rect) {
        return response;
    }
    let r = rect.shrink(1.0);
    let top = r.top();
    let bottom = r.bottom();
    let (l, right) = (r.left(), r.right());
    let shoulder = top + r.height() * 0.55;
    // A shield: flat shoulders, tapering to a point.
    let outline = vec![
        egui::pos2(l, top + 2.0),
        egui::pos2(right, top + 2.0),
        egui::pos2(right, shoulder),
        egui::pos2(r.center().x, bottom),
        egui::pos2(l, shoulder),
    ];
    ui.painter().add(egui::epaint::PathShape::convex_polygon(
        outline,
        tint(color),
        Stroke::new(1.4, color),
    ));
    // A bolt through it, in the background colour, so the mark reads at
    // 16 pixels as well as it does here.
    let w = r.width();
    let h = r.height();
    let bolt = vec![
        egui::pos2(l + w * 0.55, top + h * 0.18),
        egui::pos2(l + w * 0.30, top + h * 0.52),
        egui::pos2(l + w * 0.47, top + h * 0.52),
        egui::pos2(l + w * 0.40, top + h * 0.86),
        egui::pos2(l + w * 0.70, top + h * 0.44),
        egui::pos2(l + w * 0.52, top + h * 0.44),
    ];
    ui.painter().add(egui::epaint::PathShape::convex_polygon(
        bolt,
        color,
        Stroke::NONE,
    ));
    response
}

/// The wordmark: spaced capitals, because this is a title and not a
/// sentence.
pub fn wordmark(ui: &mut Ui) {
    ui.label(
        egui::RichText::new("H A L L P A S S")
            .color(TEXT)
            .strong()
            .size(13.0),
    );
}

/// A key/value line in the dense detail panels: muted key, plain value.
pub fn kv(ui: &mut Ui, key: &str, value: impl Into<egui::WidgetText>) {
    ui.label(egui::RichText::new(key).color(MUTED));
    ui.label(value);
    ui.end_row();
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

    /// Installing is idempotent and does not depend on being first: the
    /// popups, the editor and the main window each call it on whatever
    /// frame they happen to open on.
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

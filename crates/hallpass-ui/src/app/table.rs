//! The parts every data table shares, so the tabs cannot drift apart: the
//! heights, the style, the widths fitted to the window, and the cells.

use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};

use crate::columns::{self, Col};
use crate::theme;

/// (header, row) heights for the data tables. Rows hold buttons and
/// checkboxes as well as text, so they are sized to the interact height:
/// the table lays every virtual row out at exactly this height, and the
/// declared and rendered heights agreeing is what keeps stick-to-bottom
/// from bouncing.
pub(super) fn table_heights(ui: &egui::Ui) -> (f32, f32) {
    let text = ui.text_style_height(&egui::TextStyle::Body);
    (text + 6.0, ui.spacing().interact_size.y.max(text) + 2.0)
}

/// The style every data table shares. The cells stay at each call site,
/// where they are load-bearing; the widths come from [`fit_table`].
///
/// Sensed for hover, which egui_extras turns into a highlight across the
/// whole row: these rows are dense and several columns wide, and the
/// pointer is the only thing saying which one a click is about to act on.
///
/// Also draws the rule under the header row. Not resizable by hand: the
/// widths are refitted to the window every frame, and a width dragged by
/// hand was stored by the table and kept through every resize after it,
/// which is how a narrowed window lost its right-hand columns.
pub(super) fn data_table<'a>(
    ui: &'a mut egui::Ui,
    salt: &'static str,
    header_h: f32,
    fitted: &Fitted,
) -> TableBuilder<'a> {
    let area = ui.available_rect_before_wrap();
    let y = area.top() + header_h + ui.spacing().item_spacing.y / 2.0;
    let right = area.left() + fitted.width.max(area.width());
    theme::hairline(ui, area.left()..=right, y);
    let mut table = TableBuilder::new(ui)
        .id_salt(salt)
        .striped(true)
        .resizable(false)
        .sense(egui::Sense::hover())
        .auto_shrink([false, false])
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center));
    for width in fitted.widths.iter().flatten() {
        table = table.column(Column::exact(*width).clip(true));
    }
    table
}

/// A table's columns fitted to the room it has.
pub(super) struct Fitted {
    /// Each column's width, `None` where it was dropped.
    pub(super) widths: Vec<Option<f32>>,
    /// The width the shown columns take, gaps included.
    width: f32,
    /// Wider than the room: the table scrolls sideways.
    overflow: bool,
}

/// Fit `cols` to the width left in `ui`, less the scroll bar the table's
/// body keeps room for.
pub(super) fn fit_table(ui: &egui::Ui, cols: &[Col]) -> Fitted {
    let gap = ui.spacing().item_spacing.x;
    let avail = ui.available_width() - ui.spacing().scroll.allocated_width();
    let widths = columns::fit(avail, gap, cols);
    let shown: Vec<f32> = widths.iter().flatten().copied().collect();
    let width = shown.iter().sum::<f32>() + gap * shown.len().saturating_sub(1) as f32;
    Fitted {
        overflow: width > avail + 0.5,
        width,
        widths,
    }
}

/// Lay a table out, scrolling sideways when even its narrowest fit is
/// wider than the window: past the columns that can be dropped, a column
/// cut off at the edge is worse than one scrolled to.
pub(super) fn table_area(
    ui: &mut egui::Ui,
    fitted: &Fitted,
    salt: &str,
    add: impl FnOnce(&mut egui::Ui),
) {
    if !fitted.overflow {
        add(ui);
        return;
    }
    egui::ScrollArea::horizontal()
        .id_salt(("table-scroll", salt))
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_width(fitted.width + ui.spacing().scroll.allocated_width());
            add(ui);
        });
}

/// A table row, header or body, that skips the cells of dropped columns,
/// so each call site writes every cell and says nothing about which are
/// on screen.
pub(super) struct Cells<'r, 'a, 'b> {
    row: &'r mut egui_extras::TableRow<'a, 'b>,
    widths: &'r [Option<f32>],
    next: usize,
}

impl<'r, 'a, 'b> Cells<'r, 'a, 'b> {
    pub(super) fn new(row: &'r mut egui_extras::TableRow<'a, 'b>, fitted: &'r Fitted) -> Self {
        Self {
            row,
            widths: &fitted.widths,
            next: 0,
        }
    }

    pub(super) fn col(&mut self, add: impl FnOnce(&mut egui::Ui)) {
        if self.widths.get(self.next).is_some_and(Option::is_some) {
            self.row.col(add);
        }
        self.next += 1;
    }

    /// A header row of plain column titles.
    pub(super) fn titles(&mut self, titles: &[&str]) {
        for title in titles {
            self.col(|ui| {
                ui.label(column_title(title));
            });
        }
    }
}

/// Where a table's rows are, so a row's action can light up while the
/// pointer is anywhere on that row rather than only on the button.
#[derive(Clone, Copy)]
pub(super) struct RowHover {
    rows: egui::Rect,
    pointer: Option<egui::Pos2>,
}

impl RowHover {
    /// Taken just before the table is laid out, where its rows will be.
    pub(super) fn new(ui: &egui::Ui) -> Self {
        Self {
            rows: ui.available_rect_before_wrap(),
            pointer: ui.ctx().pointer_hover_pos(),
        }
    }

    /// Whether the pointer is on the row `cell` belongs to.
    pub(super) fn on_row(self, cell: &egui::Ui) -> bool {
        self.pointer
            .is_some_and(|p| self.rows.contains(p) && cell.max_rect().y_range().contains(p.y))
    }
}

/// A table's column heading: small, muted, and out of the way of the data.
pub(super) fn column_title(title: &str) -> RichText {
    theme::caption(title.to_uppercase())
}

/// A count in a table cell, dimmed when it is zero.
///
/// A column of bright zeros reads as activity from across the room, which
/// is exactly backwards: the whole point of these columns is that a
/// nonzero blocked count should catch the eye.
pub(super) fn count_text(n: u64, color: Color32) -> RichText {
    if n == 0 {
        theme::num_muted("0")
    } else {
        theme::num(n.to_string()).color(color)
    }
}

//! Column widths for the data tables, fitted to the window every frame.
//!
//! The tables used to start each column at a fixed width and hand whatever
//! was left to one of them. A narrow window then pushed the right-hand
//! columns out of view (on the rules tab, Edit and Delete with them), and
//! a wide one poured all its spare width into a single column of short
//! names. Here every column states how narrow it can go, how wide it wants
//! to be and how much of any spare width it should take, and the columns
//! that matter least are dropped, in a stated order, before a column that
//! matters is squeezed below the width it can still be read at.

/// How one column of a data table sizes itself.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Col {
    /// Narrowest it may be drawn at; below this it is dropped instead.
    pub min: f32,
    /// What it gets before any column grows past its own ideal.
    pub ideal: f32,
    /// Widest it grows to, however much room is spare.
    pub max: f32,
    /// Its share of the width left once every column has its ideal.
    pub grow: f32,
    /// When it is dropped on a narrow window: never at 0, otherwise the
    /// highest goes first.
    pub drop: u8,
}

impl Col {
    /// A column that stays at one width.
    pub const fn fixed(width: f32) -> Self {
        Self {
            min: width,
            ideal: width,
            max: width,
            grow: 0.0,
            drop: 0,
        }
    }

    /// A column that can give up width down to `min`, and take spare width
    /// in proportion to `grow`.
    pub const fn flex(min: f32, ideal: f32, grow: f32) -> Self {
        Self {
            min,
            ideal,
            max: f32::INFINITY,
            grow,
            drop: 0,
        }
    }

    /// The same, growing no wider than `max`.
    pub const fn up_to(self, max: f32) -> Self {
        Self { max, ..self }
    }

    /// The same, dropped when the window is too narrow; higher goes first.
    pub const fn dropped(self, order: u8) -> Self {
        Self {
            drop: order,
            ..self
        }
    }
}

/// Fit `cols` into `avail` points with `gap` between neighbours. `None`
/// for a dropped column.
///
/// Dropping comes first, until every column left fits at its minimum or
/// none can be dropped; the sum can then still exceed `avail`, and the
/// caller scrolls. Then each column grows from its minimum towards its
/// ideal, all by the same fraction of the way, and past that the spare
/// width is shared by `grow` among the columns under their `max`. What no
/// column can take goes to the last one that grows at all, so the table
/// always spans the width it was given.
pub fn fit(avail: f32, gap: f32, cols: &[Col]) -> Vec<Option<f32>> {
    let mut shown: Vec<bool> = vec![true; cols.len()];
    let needed = |shown: &[bool]| {
        let n = shown.iter().filter(|s| **s).count();
        let mins: f32 = cols
            .iter()
            .zip(shown)
            .filter(|(_, s)| **s)
            .map(|(c, _)| c.min)
            .sum();
        mins + gap * n.saturating_sub(1) as f32
    };
    while needed(&shown) > avail {
        // Highest order first; the rightmost of equals, which is the one
        // read last.
        let Some(victim) = cols
            .iter()
            .enumerate()
            .filter(|(i, c)| shown[*i] && c.drop > 0)
            .max_by_key(|(i, c)| (c.drop, *i))
            .map(|(i, _)| i)
        else {
            break;
        };
        shown[victim] = false;
    }

    let visible: Vec<usize> = (0..cols.len()).filter(|i| shown[*i]).collect();
    let mut widths: Vec<f32> = cols.iter().map(|c| c.min).collect();
    let mut room = avail - needed(&shown);
    if room > 0.0 {
        let want: f32 = visible.iter().map(|i| cols[*i].ideal - cols[*i].min).sum();
        let share = if want > 0.0 {
            (room / want).min(1.0)
        } else {
            0.0
        };
        for i in &visible {
            widths[*i] += (cols[*i].ideal - cols[*i].min) * share;
        }
        room -= want * share;
    }
    // Spare width by weight, again for whoever is still under their cap
    // after a round in which somebody reached theirs.
    while room > 0.5 {
        let open: Vec<usize> = visible
            .iter()
            .copied()
            .filter(|i| cols[*i].grow > 0.0 && widths[*i] < cols[*i].max)
            .collect();
        let weight: f32 = open.iter().map(|i| cols[*i].grow).sum();
        if open.is_empty() || weight <= 0.0 {
            break;
        }
        let mut given = 0.0;
        for i in &open {
            let take = (room * cols[*i].grow / weight).min(cols[*i].max - widths[*i]);
            widths[*i] += take;
            given += take;
        }
        room -= given;
        if given <= 0.0 {
            break;
        }
    }
    if room > 0.5 {
        if let Some(last) = visible.iter().rev().find(|i| cols[**i].grow > 0.0) {
            widths[*last] += room;
        }
    }
    (0..cols.len())
        .map(|i| shown[i].then_some(widths[i]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const GAP: f32 = 8.0;

    fn total(widths: &[Option<f32>]) -> f32 {
        let shown: Vec<f32> = widths.iter().flatten().copied().collect();
        shown.iter().sum::<f32>() + GAP * shown.len().saturating_sub(1) as f32
    }

    fn table() -> [Col; 4] {
        [
            Col::fixed(60.0),
            Col::flex(100.0, 200.0, 1.0).up_to(260.0),
            Col::flex(120.0, 240.0, 2.0),
            Col::flex(80.0, 120.0, 1.0).dropped(1),
        ]
    }

    /// Every width the window is given is used: a table that stops short
    /// of the panel leaves its row stripes and its row actions hanging.
    #[test]
    fn the_table_spans_whatever_it_is_given() {
        for avail in [400.0, 500.0, 700.0, 1000.0, 2000.0] {
            let w = fit(avail, GAP, &table());
            assert!((total(&w) - avail).abs() < 1.0, "{avail}: {w:?}");
        }
    }

    /// Short of room, the columns marked droppable go before anything is
    /// squeezed under its minimum, and the rest are never dropped.
    #[test]
    fn a_narrow_window_drops_before_it_squeezes() {
        let w = fit(330.0, GAP, &table());
        assert_eq!(w[3], None, "the droppable column goes first");
        assert!(w.iter().take(3).all(Option::is_some));
        for (col, width) in table().iter().zip(&w) {
            if let Some(width) = width {
                assert!(*width >= col.min, "{w:?}");
            }
        }
    }

    /// Too narrow even without the droppable columns: nothing more is
    /// dropped and every column keeps its minimum, for the caller to
    /// scroll rather than to draw unreadable.
    #[test]
    fn past_dropping_the_columns_keep_their_minimum() {
        let w = fit(100.0, GAP, &table());
        assert_eq!(w, vec![Some(60.0), Some(100.0), Some(120.0), None]);
    }

    /// A wide window shares its spare width by weight and respects caps,
    /// rather than handing all of it to one column.
    #[test]
    fn spare_width_is_shared_by_weight_up_to_each_cap() {
        let w = fit(1000.0, GAP, &table());
        assert_eq!(w[0], Some(60.0), "a fixed column stays fixed");
        assert_eq!(w[1], Some(260.0), "capped");
        let (b, c) = (w[2].unwrap(), w[3].unwrap());
        assert!(c > 120.0 && b > c, "{w:?}");
    }

    /// Between minimum and ideal every column moves by the same fraction,
    /// so no one column is starved while another sits at its ideal.
    #[test]
    fn below_ideal_every_column_gives_up_the_same_share() {
        let cols = [Col::flex(100.0, 200.0, 1.0), Col::flex(50.0, 250.0, 1.0)];
        let w = fit(100.0 + 50.0 + GAP + 150.0, GAP, &cols);
        assert_eq!(w, vec![Some(150.0), Some(150.0)]);
    }
}

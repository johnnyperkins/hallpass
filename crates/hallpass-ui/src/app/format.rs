//! Numbers and times, written the way the tabs show them.

/// A long count, shortened: 18402 becomes 18.4k.
///
/// Only in the headline tiles, where the number is read as a magnitude and
/// the exact digits are one card lower. Nothing that has to be exact (a
/// queue depth, a drop count) goes through here.
pub(super) fn compact(n: u64) -> String {
    match n {
        0..=9_999 => n.to_string(),
        10_000..=999_999 => format!("{:.1}k", n as f64 / 1_000.0),
        _ => format!("{:.1}M", n as f64 / 1_000_000.0),
    }
}

/// An exact count with thousands separated, for the detail cards: 3900112
/// becomes 3,900,112, which is read as "about four million" at a glance.
pub(super) fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// `n` as a share of `total`, for the line under a headline number.
pub(super) fn percent_of(n: u64, total: u64) -> String {
    if total == 0 {
        return "no traffic yet".to_string();
    }
    format!("{:.1}% of all connections", n as f64 * 100.0 / total as f64)
}

/// A duration in seconds as the coarsest unit that still says something.
pub(super) fn format_span(secs: u64) -> String {
    match secs {
        0 => "moment".to_string(),
        1..=90 => format!("{secs}s"),
        91..=5_400 => format!("{}m", secs / 60),
        _ => format!("{}h", secs / 3600),
    }
}

/// Local wall-clock "HH:MM:SS" for an event timestamp.
pub(super) fn format_time(unix_ms: u64) -> String {
    use chrono::TimeZone;
    match chrono::Local.timestamp_millis_opt(unix_ms as i64) {
        chrono::LocalResult::Single(t) => t.format("%H:%M:%S").to_string(),
        _ => "-".to_string(),
    }
}

/// Uptime to the minute, in days once it runs to days.
///
/// No seconds: the figure is refreshed with the stats poll, every few
/// seconds, and a seconds digit that jumps by three at a time looks broken
/// rather than live.
pub(super) fn format_uptime(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, (secs % 86_400) / 3600, (secs % 3600) / 60);
    match (d, h) {
        (0, 0) => format!("{m}m"),
        (0, _) => format!("{h}h {m:02}m"),
        _ => format!("{d}d {h}h {m:02}m"),
    }
}

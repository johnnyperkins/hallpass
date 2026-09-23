//! State and pure helpers for prompt popup windows.

use hallpass_types::{
    sanitize_for_display, ClientMsg, Connection, PromptContext, PromptScope, RuleDuration, Verdict,
};

/// State of one pending prompt popup (one immediate viewport each).
pub struct PromptState {
    /// Prompt ID; echoed back in the reply.
    pub id: u64,
    /// The connection awaiting a decision.
    pub conn: Connection,
    /// Deadline as Unix milliseconds.
    pub deadline_ms: u64,
    /// Unix milliseconds when the prompt was received.
    pub received_ms: u64,
    /// Unix milliseconds when this prompt first became the front of its
    /// popup window, stamped by the popup's render pass.
    ///
    /// The progress bar drains from here rather than from `received_ms`: a
    /// prompt that queued behind another in the same window would otherwise
    /// appear already part-elapsed the moment it surfaces. The deadline
    /// itself is untouched - the daemon armed it at creation and holding
    /// packets longer is not this side's call - so the bar restarting only
    /// changes what "full" means, never when the default verdict lands.
    pub fronted_ms: Option<u64>,
    /// Selected rule duration.
    pub duration: RuleDuration,
    /// Selected rule scope.
    pub scope: PromptScope,
    /// Whether the operator asked to pin the rule to this exact binary.
    /// Only offered when [`PromptState::can_pin`], and only sent on an allow.
    pub pin_exe: bool,
    /// What the daemon found out about the process beyond the connection
    /// itself. Best effort and possibly empty; see [`PromptContext`].
    pub context: PromptContext,
}

impl PromptState {
    /// Create popup state with the spec defaults (Session / This port).
    pub fn new(
        id: u64,
        conn: Connection,
        deadline_ms: u64,
        received_ms: u64,
        context: PromptContext,
    ) -> Self {
        Self {
            id,
            conn,
            deadline_ms,
            received_ms,
            fronted_ms: None,
            duration: RuleDuration::Session,
            scope: PromptScope::ThisPort,
            // Off unless the operator ticks it, and offered at all only when
            // this prompt carries a hash (`can_pin`). Defaulting it on would
            // make the common answer create a rule that stops matching the
            // next time the program is updated, which reads as the firewall
            // breaking rather than as the pin working.
            pin_exe: false,
            context,
        }
    }

    /// Where the visible countdown starts: the moment this prompt reached
    /// the front of its window, or its arrival until it has.
    fn countdown_start(&self) -> u64 {
        self.fronted_ms.unwrap_or(self.received_ms)
    }

    /// Whether pinning the executable is on offer for this prompt.
    ///
    /// Needs a hash: the daemon pins the value it showed here and nothing
    /// else, so a prompt whose binary it could not read (or that was past the
    /// size cap) has nothing to pin, and a reply asking anyway creates no rule
    /// at all. Hiding the control is what keeps that a backstop rather than a
    /// way to lose a rule the operator thought they wrote.
    pub fn can_pin(&self) -> bool {
        self.context.exe_sha256.is_some()
    }

    /// Whether Allow answers yet at `now_ms`: only once this prompt has been
    /// at the front of its window for [`ALLOW_ARM_MS`].
    ///
    /// A popup comes to the front with focus, and when one prompt is
    /// answered the next takes its place in the same spot, so a click or a
    /// keypress meant for something else, or the second half of a
    /// double-click, landed on a connection nobody had read. Deny is not
    /// held back: answered unread, it costs a retry.
    pub fn allow_armed(&self, now_ms: u64) -> bool {
        self.allow_arms_at().is_some_and(|at| now_ms >= at)
    }

    /// Unix milliseconds at which Allow arms, or `None` while this prompt
    /// has not reached the front; see [`PromptState::allow_armed`].
    pub fn allow_arms_at(&self) -> Option<u64> {
        self.fronted_ms
            .map(|fronted| fronted.saturating_add(ALLOW_ARM_MS))
    }

    /// Build the reply message for the given verdict.
    pub fn reply(&self, verdict: Verdict) -> ClientMsg {
        ClientMsg::PromptReply {
            id: self.id,
            verdict,
            duration: self.duration,
            scope: self.scope,
            // Only an allow narrows by being pinned. A deny keyed on the path
            // should keep blocking whatever is written there, so the flag is
            // dropped rather than sent and ignored. Nor on Once, which writes
            // no rule: the checkbox is hidden then but keeps its state.
            pin_exe: self.pin_exe
                && verdict == Verdict::Allow
                && self.duration != RuleDuration::Once
                && self.can_pin(),
        }
    }

    /// Remaining fraction of the countdown in `[0.0, 1.0]` at `now_ms`.
    /// 1.0 = just surfaced, 0.0 = deadline reached.
    pub fn remaining_fraction(&self, now_ms: u64) -> f32 {
        remaining_fraction(self.countdown_start(), self.deadline_ms, now_ms)
    }

    /// Whole seconds left until the deadline at `now_ms`.
    pub fn remaining_secs(&self, now_ms: u64) -> u64 {
        self.deadline_ms.saturating_sub(now_ms) / 1000
    }
}

/// How long a prompt has to be at the front before Allow answers; see
/// [`PromptState::allow_armed`]. Long enough to outlast a reflex, short
/// enough not to be noticed by someone reading.
pub const ALLOW_ARM_MS: u64 = 700;

/// The reply a closed prompt window sends for prompt `id`.
///
/// Deny, once, this port. Closing the window is a decision about the
/// connection on screen and about nothing else, so it deliberately ignores
/// the duration and scope pickers: inheriting them would let a dismissed
/// window write a permanent, app-wide rule the operator never confirmed.
/// [`RuleDuration::Once`] creates no rule at all; it only settles the
/// packets the daemon is holding.
pub fn close_reply(id: u64) -> ClientMsg {
    ClientMsg::PromptReply {
        id,
        verdict: Verdict::Deny,
        duration: RuleDuration::Once,
        scope: PromptScope::ThisPort,
        pin_exe: false,
    }
}

/// Remaining fraction of a countdown in `[0.0, 1.0]`.
fn remaining_fraction(start_ms: u64, deadline_ms: u64, now_ms: u64) -> f32 {
    let total = deadline_ms.saturating_sub(start_ms);
    if total == 0 {
        return 0.0;
    }
    let left = deadline_ms.saturating_sub(now_ms);
    (left as f32 / total as f32).clamp(0.0, 1.0)
}

/// Format a destination as "domain (ip):port" when the domain is known,
/// otherwise "ip:port".
///
/// The domain is bounded and sanitized like every other untrusted field: this
/// is the row the operator judges, and the prompt viewport is not resizable,
/// so an unbounded or multi-line value here pushes the allow and deny buttons
/// out of view. The literal address is always shown alongside, so a name that
/// had to be shortened cannot hide where the connection actually goes.
pub fn format_dest(conn: &Connection) -> String {
    let dst = conn.tuple.dst;
    match &conn.domain {
        Some(domain) => format!("{} ({}):{}", truncate(domain, 80), dst.ip(), dst.port()),
        None => dst.to_string(),
    }
}

/// Bound for a path shown in full: long enough that a real path is never
/// cut, short enough that one chosen to be long cannot fill the window.
const PATH_MAX: usize = 200;

/// A path read off the host, bounded and sanitized for a full-width label.
pub fn path_text(p: &std::path::Path) -> String {
    truncate(&p.display().to_string(), PATH_MAX)
}

/// Bound for a sentence the daemon composed from several bounded parts.
///
/// [`UI_TEXT_MAX`] is sized for one label-sized value; a sentence that names
/// up to `MAX_HASH_MISMATCH_RULES` operator-chosen rules is several of them,
/// and cutting it there truncates the rule names the operator is being told
/// to go and open, which is the only thing that sentence is for. This is
/// generous enough to hold the longest one the daemon can build, and the
/// prompt body scrolls.
const SENTENCE_MAX: usize = 700;

/// A daemon-composed sentence, bounded and sanitized for a wrapping label.
pub fn sentence_text(s: &str) -> String {
    truncate(s, SENTENCE_MAX)
}

/// Executable file name for display; falls back to "unknown".
pub fn exe_name(conn: &Connection) -> String {
    conn.exe_path
        .as_deref()
        .and_then(|p| p.file_name())
        .map(|n| sanitize_for_display(&n.to_string_lossy()).into_owned())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Default bound for a daemon-supplied string used as a label or title.
const UI_TEXT_MAX: usize = 120;

/// Make a daemon-supplied string safe to use as a label or a window title.
///
/// egui does not interpret ANSI, so the risk here is not terminal spoofing but
/// layout: an unbounded or multi-line value expands its cell and distorts the
/// view an operator is reading, and zero-width or bidi characters let two
/// different rules render identically in the list used to audit policy.
pub fn ui_text(s: &str) -> String {
    truncate(s, UI_TEXT_MAX)
}

/// Truncate a string for single-line display, appending "..." when cut.
///
/// Also sanitizes: every field routed through here (command line, executable
/// path, resolved domain) is chosen by the process being judged, and the
/// operator reads it to decide. Bidi overrides and zero-width characters
/// would otherwise reshape a label without changing its length, and the
/// truncation itself counts characters, so hazards must go before the cut.
pub fn truncate(s: &str, max_chars: usize) -> String {
    let s = sanitize_for_display(s);
    let s = s.as_ref();
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max_chars.saturating_sub(3)).collect();
        format!("{cut}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hallpass_types::{FlowTuple, Proto};
    use std::net::SocketAddr;
    use std::path::PathBuf;

    fn conn(domain: Option<&str>, exe: Option<&str>) -> Connection {
        Connection {
            tuple: FlowTuple {
                proto: Proto::Tcp,
                src: "10.0.0.2:50000".parse::<SocketAddr>().unwrap(),
                dst: "93.184.216.34:443".parse::<SocketAddr>().unwrap(),
            },
            uid: Some(1000),
            pid: Some(4242),
            exe_path: exe.map(PathBuf::from),
            cmdline: Some("curl https://example.org".into()),
            parent_exe: None,
            domain: domain.map(String::from),
            iface: None,
            app_id: None,
            first_seen: None,
        }
    }

    #[test]
    fn allow_arms_only_after_the_prompt_has_been_in_front() {
        let mut p = PromptState::new(1, conn(None, None), 60_000, 1_000, Default::default());
        assert!(!p.allow_armed(50_000), "never fronted, never armed");
        assert_eq!(p.allow_arms_at(), None);
        p.fronted_ms = Some(2_000);
        assert_eq!(p.allow_arms_at(), Some(2_000 + ALLOW_ARM_MS));
        assert!(!p.allow_armed(2_000));
        assert!(!p.allow_armed(2_000 + ALLOW_ARM_MS - 1));
        assert!(p.allow_armed(2_000 + ALLOW_ARM_MS));
    }

    #[test]
    fn a_once_reply_never_pins() {
        let mut p = PromptState::new(
            1,
            conn(None, Some("/usr/bin/curl")),
            60_000,
            0,
            Default::default(),
        );
        p.context.exe_sha256 = Some("ab".repeat(32));
        p.pin_exe = true;
        p.duration = RuleDuration::Forever;
        assert!(matches!(
            p.reply(Verdict::Allow),
            ClientMsg::PromptReply { pin_exe: true, .. }
        ));
        p.duration = RuleDuration::Once;
        assert!(matches!(
            p.reply(Verdict::Allow),
            ClientMsg::PromptReply { pin_exe: false, .. }
        ));
    }

    /// Giving up a prompt denies, and denies once: it settles the connection
    /// on screen without writing policy for any future one. Pinned as a
    /// literal because every field is a decision - a wider scope or a lasting
    /// duration would make dismissing a window an act of policy.
    #[test]
    fn a_dismissed_prompt_is_denied_for_this_connection_only() {
        assert_eq!(
            close_reply(7),
            ClientMsg::PromptReply {
                id: 7,
                verdict: Verdict::Deny,
                duration: RuleDuration::Once,
                scope: PromptScope::ThisPort,
                pin_exe: false,
            }
        );
    }

    #[test]
    fn countdown_fraction_bounds() {
        // 10s window starting at t=1000ms.
        assert_eq!(remaining_fraction(1000, 11000, 1000), 1.0);
        assert_eq!(remaining_fraction(1000, 11000, 6000), 0.5);
        assert_eq!(remaining_fraction(1000, 11000, 11000), 0.0);
        // Past the deadline clamps at 0, before the start clamps at 1.
        assert_eq!(remaining_fraction(1000, 11000, 99999), 0.0);
        assert_eq!(remaining_fraction(1000, 11000, 0), 1.0);
        // Degenerate zero-length window.
        assert_eq!(remaining_fraction(5000, 5000, 5000), 0.0);
        // Deadline before start (daemon clock skew) must not panic.
        assert_eq!(remaining_fraction(9000, 5000, 7000), 0.0);
    }

    /// A prompt that queued behind another starts its bar full when it
    /// surfaces, draining over the time it actually has left; the seconds
    /// text and the deadline are untouched.
    #[test]
    fn countdown_restarts_when_the_prompt_reaches_the_front() {
        // Received at t=0 with a 30s deadline, surfaced at t=20s.
        let mut p = PromptState::new(1, conn(None, None), 30_000, 0, PromptContext::default());
        assert!((p.remaining_fraction(20_000) - 1.0 / 3.0).abs() < 1e-6);
        p.fronted_ms = Some(20_000);
        assert_eq!(p.remaining_fraction(20_000), 1.0, "bar restarts full");
        assert_eq!(
            p.remaining_fraction(25_000),
            0.5,
            "drains over what is left"
        );
        assert_eq!(p.remaining_fraction(30_000), 0.0, "deadline unchanged");
        assert_eq!(p.remaining_secs(20_000), 10, "seconds stay honest");
    }

    #[test]
    fn remaining_secs_saturates() {
        let p = PromptState::new(1, conn(None, None), 10_000, 4_000, PromptContext::default());
        assert_eq!(p.remaining_secs(4_000), 6);
        assert_eq!(p.remaining_secs(9_400), 0);
        assert_eq!(p.remaining_secs(20_000), 0);
    }

    #[test]
    fn dest_with_domain() {
        assert_eq!(
            format_dest(&conn(Some("example.org"), None)),
            "example.org (93.184.216.34):443"
        );
    }

    #[test]
    fn dest_without_domain() {
        assert_eq!(format_dest(&conn(None, None)), "93.184.216.34:443");
    }

    #[test]
    fn exe_name_and_fallback() {
        assert_eq!(exe_name(&conn(None, Some("/usr/bin/curl"))), "curl");
        assert_eq!(exe_name(&conn(None, None)), "unknown");
    }

    #[test]
    fn prompt_reply_uses_selected_options() {
        let mut p = PromptState::new(7, conn(None, None), 10_000, 0, PromptContext::default());
        // Defaults per spec: Session / This port.
        assert_eq!(p.duration, RuleDuration::Session);
        assert_eq!(p.scope, PromptScope::ThisPort);
        p.duration = RuleDuration::Forever;
        p.scope = PromptScope::AppAnywhere;
        assert_eq!(
            p.reply(Verdict::Allow),
            ClientMsg::PromptReply {
                id: 7,
                verdict: Verdict::Allow,
                duration: RuleDuration::Forever,
                scope: PromptScope::AppAnywhere,
                pin_exe: false,
            }
        );
    }

    #[test]
    fn truncate_behaviour() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("abcdefghij", 10), "abcdefghij");
        assert_eq!(truncate("abcdefghijk", 10), "abcdefg...");
    }
}

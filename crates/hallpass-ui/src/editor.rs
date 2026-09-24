//! The rule add/edit form.
//!
//! Every field is edited as text (empty means "not set") and parsed into
//! a [`Rule`] on save. Client-side parsing exists for immediate feedback
//! only; the daemon revalidates through the same compilation path as
//! every other rule source and its error comes back over IPC, so nothing
//! here is a trust boundary.

use eframe::egui::{self, ComboBox, TextEdit};
use hallpass_types::{Action, Connection, Proto, Rule, RuleDuration, RuleMatch};

/// Duration choice in the form; `Timed` carries its timespan text.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DurationChoice {
    Session,
    Forever,
    Timed,
}

impl DurationChoice {
    fn label(self) -> &'static str {
        match self {
            DurationChoice::Session => "Session",
            DurationChoice::Forever => "Forever",
            DurationChoice::Timed => "Timed",
        }
    }
}

/// State of the editor window. `Some` means the window is open.
pub struct RuleEditor {
    /// Empty for a new rule; the loaded name when editing. Editing keeps
    /// the name field disabled, since saving under a changed name would
    /// add a second rule rather than rename (adds replace by name).
    editing: Option<String>,
    name: String,
    action: Action,
    duration: DurationChoice,
    timespan: String,
    priority: String,
    enabled: bool,
    /// Comma-separated tags, parsed on save. Not a match criterion.
    tags: String,
    // Match criteria, blank = unset.
    exe: String,
    exe_glob: String,
    exe_sha256: String,
    dest: String,
    port: String,
    port_range: String,
    domain: String,
    user: String,
    proto: Option<Proto>,
    domains_file: String,
    ips_file: String,
    hashes_file: String,
    cmdline_contains: String,
    parent_exe: String,
    src: String,
    src_port: String,
    iface: String,
    app_id: String,
    /// Parse error from the last save attempt.
    error: Option<String>,
    /// A save was sent and the daemon has not answered yet. The window
    /// stays open until the ack: the daemon validates more than the form
    /// does (CIDR syntax, globs, hash format), and closing on send would
    /// destroy everything typed when the daemon rejects the rule.
    awaiting: bool,
}

/// Parse the tags field: separated by commas or whitespace, in whichever
/// combination the operator typed.
///
/// Validated here so the form says what is wrong next to the field, but the
/// daemon checks the same thing on the way in - this is feedback, not a gate.
fn parse_tags(text: &str) -> Result<Vec<String>, String> {
    let mut tags: Vec<String> = Vec::new();
    for tag in text.split([',', ' ', '\t']).filter(|t| !t.is_empty()) {
        // Bailing inside the loop rather than checking the length after it:
        // a pasted field is unbounded, and the check that would catch it is
        // otherwise reached only after allocating every entry in it.
        if tags.len() == hallpass_types::MAX_TAGS_PER_RULE {
            return Err(format!(
                "at most {} tags per rule",
                hallpass_types::MAX_TAGS_PER_RULE
            ));
        }
        tags.push(tag.to_string());
    }
    hallpass_types::validate_tags(&tags)?;
    Ok(tags)
}

impl RuleEditor {
    /// An empty form for a new rule.
    pub fn add() -> Self {
        RuleEditor {
            editing: None,
            name: String::new(),
            action: Action::Deny,
            duration: DurationChoice::Forever,
            timespan: "1h".to_string(),
            priority: "10".to_string(),
            enabled: true,
            tags: String::new(),
            exe: String::new(),
            exe_glob: String::new(),
            exe_sha256: String::new(),
            dest: String::new(),
            port: String::new(),
            port_range: String::new(),
            domain: String::new(),
            user: String::new(),
            proto: None,
            domains_file: String::new(),
            ips_file: String::new(),
            hashes_file: String::new(),
            cmdline_contains: String::new(),
            parent_exe: String::new(),
            src: String::new(),
            src_port: String::new(),
            iface: String::new(),
            app_id: String::new(),
            error: None,
            awaiting: false,
        }
    }

    /// A form pre-filled from a connection that already happened.
    ///
    /// Writing a rule by hand from a row in the traffic view means retyping
    /// an executable path and an address the operator is looking at, which is
    /// where the typos come from. The action deliberately stays at the `add`
    /// default (deny) rather than mirroring whatever the connection got: this
    /// opens from a row the operator picked out, and the safe reading of that
    /// is "I want to stop this", not "make what just happened permanent".
    ///
    /// The name is a suggestion, not a decision; it is sanitized because the
    /// process chose its own executable path, and it lands in a field the
    /// operator edits and then reads back.
    pub fn from_connection(conn: &Connection) -> Self {
        let mut e = Self::add();
        let exe = conn
            .exe_path
            .as_ref()
            .map(|p| hallpass_types::sanitize_for_display(&p.display().to_string()).into_owned())
            .unwrap_or_default();
        let stem = conn
            .exe_path
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| hallpass_types::sanitize_for_display(&n.to_string_lossy()).into_owned())
            .unwrap_or_else(|| "connection".to_string());
        e.name = format!("{stem}-{}", conn.tuple.dst.port());
        e.exe = exe;
        // Carried for the same reason the daemon pins it on a rule made
        // from a prompt reply: a sandboxed application's executable path is
        // shared by every application of that packaging system, so exe
        // alone would write a rule that answers for all of them.
        if let Some(app) = &conn.app_id {
            e.app_id = hallpass_types::sanitize_for_display(app).into_owned();
        }
        e.port = conn.tuple.dst.port().to_string();
        e.proto = Some(conn.tuple.proto);
        // Prefer the domain over the address: an address is one of however
        // many a name resolves to today, so a rule pinned to it silently
        // stops covering the thing the operator meant.
        match &conn.domain {
            Some(domain) => e.domain = hallpass_types::sanitize_for_display(domain).into_owned(),
            None => e.dest = conn.tuple.dst.ip().to_string(),
        }
        e
    }

    /// A form pre-filled from an existing rule.
    pub fn edit(rule: &Rule) -> Self {
        let m = &rule.matcher;
        let path = |p: &Option<std::path::PathBuf>| {
            p.as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        };
        let text = |s: &Option<String>| s.clone().unwrap_or_default();
        let num = |n: Option<u16>| n.map(|n| n.to_string()).unwrap_or_default();
        let mut e = Self::add();
        e.editing = Some(rule.name.clone());
        e.name = rule.name.clone();
        e.action = rule.action;
        e.enabled = rule.enabled;
        e.duration = match rule.duration {
            RuleDuration::Session | RuleDuration::Once => DurationChoice::Session,
            RuleDuration::Forever => DurationChoice::Forever,
            RuleDuration::Until { .. } => DurationChoice::Timed,
        };
        // A deadline cannot round-trip into a "from now" timespan, so
        // prefill the time actually remaining: saving without touching
        // the field then approximately preserves the deadline instead of
        // silently re-arming the rule for a default hour.
        if let RuleDuration::Until { deadline_ms } = rule.duration {
            let left_secs = deadline_ms
                .saturating_sub(hallpass_types::unix_ms_now())
                .div_ceil(1000)
                .max(1);
            e.timespan = format!("{left_secs}s");
        }
        e.priority = rule.priority.to_string();
        e.tags = rule.tags.join(", ");
        e.exe = path(&m.exe);
        e.exe_glob = text(&m.exe_glob);
        e.exe_sha256 = text(&m.exe_sha256);
        e.dest = text(&m.dest);
        e.port = num(m.port);
        e.port_range = m
            .port_range
            .map(|(a, b)| format!("{a}-{b}"))
            .unwrap_or_default();
        e.domain = text(&m.domain);
        e.user = m.user.map(|u| u.to_string()).unwrap_or_default();
        e.proto = m.proto;
        e.domains_file = path(&m.domains_file);
        e.ips_file = path(&m.ips_file);
        e.hashes_file = path(&m.hashes_file);
        e.cmdline_contains = text(&m.cmdline_contains);
        e.parent_exe = path(&m.parent_exe);
        e.src = text(&m.src);
        e.src_port = num(m.src_port);
        e.iface = text(&m.iface);
        e.app_id = text(&m.app_id);
        e
    }

    /// Build the rule from the form. `Err` is a message for the user.
    fn to_rule(&self) -> Result<Rule, String> {
        let name = self.name.trim().to_string();
        if name.is_empty() {
            return Err("name must not be empty".into());
        }
        let priority: u32 = self
            .priority
            .trim()
            .parse()
            .map_err(|_| "priority must be a number".to_string())?;
        let duration = match self.duration {
            DurationChoice::Session => RuleDuration::Session,
            DurationChoice::Forever => RuleDuration::Forever,
            DurationChoice::Timed => RuleDuration::until_after(self.timespan.trim())
                .ok_or("timespan must be like 30s, 5m, 2h, or 1d")?,
        };

        let opt = |s: &str| {
            let t = s.trim();
            (!t.is_empty()).then(|| t.to_string())
        };
        let opt_path = |s: &str| opt(s).map(std::path::PathBuf::from);
        let opt_u16 = |s: &str, what: &str| -> Result<Option<u16>, String> {
            opt(s)
                .map(|t| {
                    t.parse()
                        .map_err(|_| format!("{what} must be a port number"))
                })
                .transpose()
        };

        let port_range = match opt(&self.port_range) {
            None => None,
            Some(t) => {
                let (a, b) = t
                    .split_once('-')
                    .ok_or("port range must be like 6000-6100")?;
                Some((
                    a.trim()
                        .parse()
                        .map_err(|_| "bad port range start".to_string())?,
                    b.trim()
                        .parse()
                        .map_err(|_| "bad port range end".to_string())?,
                ))
            }
        };

        let matcher = RuleMatch {
            exe: opt_path(&self.exe),
            exe_glob: opt(&self.exe_glob),
            exe_sha256: opt(&self.exe_sha256),
            dest: opt(&self.dest),
            port: opt_u16(&self.port, "port")?,
            port_range,
            domain: opt(&self.domain),
            user: opt(&self.user)
                .map(|t| {
                    t.parse()
                        .map_err(|_| "user must be a numeric uid".to_string())
                })
                .transpose()?,
            proto: self.proto,
            domains_file: opt_path(&self.domains_file),
            ips_file: opt_path(&self.ips_file),
            hashes_file: opt_path(&self.hashes_file),
            cmdline_contains: opt(&self.cmdline_contains),
            parent_exe: opt_path(&self.parent_exe),
            src: opt(&self.src),
            src_port: opt_u16(&self.src_port, "src_port")?,
            iface: opt(&self.iface),
            app_id: opt(&self.app_id),
        };
        if matcher == RuleMatch::default() {
            return Err("set at least one match criterion, or the rule matches everything".into());
        }
        Ok(Rule {
            name,
            action: self.action,
            duration,
            priority,
            enabled: self.enabled,
            tags: parse_tags(&self.tags)?,
            matcher,
        })
    }

    /// Render the editor window. Returns `(keep_open, rule_to_send)`.
    /// A returned rule does not close the window; the app closes it when
    /// the daemon acks; see [`RuleEditor::ack_err`] and
    /// [`RuleEditor::ack_lost`] for the paths that keep it open.
    pub fn window(&mut self, ctx: &egui::Context) -> (bool, Option<Rule>) {
        crate::theme::ensure_installed(ctx);
        let mut open = true;
        let mut saved = None;
        let title = match &self.editing {
            Some(name) => format!("Edit rule: {}", crate::prompt::ui_text(name)),
            None => "Add rule".to_string(),
        };
        // The form is two dozen rows, so on a short viewport the window
        // used to grow past the screen and put the title bar and Save out
        // of reach (same defect class as the prompt-button overflow). Cap
        // the window to the viewport; the form body scrolls inside it and
        // the error line and Save stay pinned below the scroll area, so
        // the button that retries a rejection is always next to it.
        let max_height = (ctx.content_rect().height() - 48.0).max(160.0);
        egui::Window::new(title)
            .id(egui::Id::new("rule-editor"))
            .open(&mut open)
            .collapsible(false)
            .default_width(420.0)
            .max_height(max_height)
            .show(ctx, |ui| {
                self.form(ui, &mut saved);
            });
        if saved.is_some() {
            self.awaiting = true;
        }
        (open, saved)
    }

    /// Put the form into the state a returned rule leaves it in.
    ///
    /// Test-only: `awaiting` is private, and the state between clicking Save
    /// and the daemon answering is where the reconciliation logic lives, so
    /// a headless test has to be able to reach it without a widget tree.
    #[cfg(test)]
    pub(crate) fn mark_sent(&mut self) {
        self.awaiting = true;
    }

    /// Whether a save is in flight, i.e. the next daemon Ok/Err answers it.
    pub fn awaiting_ack(&self) -> bool {
        self.awaiting
    }

    /// The daemon rejected the save: show its message, allow another try.
    pub fn ack_err(&mut self, message: &str) {
        self.awaiting = false;
        self.error = Some(format!(
            "daemon rejected the rule: {}",
            crate::prompt::ui_text(message)
        ));
    }

    /// The save never reached the daemon (connection lost): re-enable
    /// the form so it can be retried without losing what was typed.
    pub fn ack_lost(&mut self, message: &str) {
        self.awaiting = false;
        self.error = Some(message.to_string());
    }

    fn form(&mut self, ui: &mut egui::Ui, saved: &mut Option<Rule>) {
        // Room kept under the scroll area for what must stay visible: the
        // error line (two wrapped lines at its 120-char cap) and the Save
        // row. Everything above scrolls when the window hits its cap.
        let pinned = 96.0;
        let body_height = (ui.available_height() - pinned).max(120.0);
        egui::ScrollArea::vertical()
            .auto_shrink([false, true])
            .max_height(body_height)
            .show(ui, |ui| {
                self.form_fields(ui);
            });
        if let Some(err) = &self.error {
            // Bounded to its share of the pinned space: an error wrapping
            // past two lines on a narrow window scrolls here instead of
            // pushing Save below the window's height cap, which is the
            // exact overflow this layout exists to prevent.
            egui::ScrollArea::vertical()
                .id_salt("rule-editor-error")
                .max_height(40.0)
                .show(ui, |ui| {
                    crate::theme::banner(ui, crate::theme::Tone::Bad, "\u{26a0}", err, "");
                });
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !self.awaiting,
                    egui::Button::new(
                        egui::RichText::new("Save")
                            .color(egui::Color32::WHITE)
                            .strong(),
                    )
                    .fill(crate::theme::ACCENT.gamma_multiply(0.85))
                    .min_size(egui::vec2(90.0, 28.0)),
                )
                .clicked()
            {
                match self.to_rule() {
                    Ok(rule) => {
                        self.error = None;
                        *saved = Some(rule);
                    }
                    Err(e) => self.error = Some(e),
                }
            }
            if self.awaiting {
                ui.label(egui::RichText::new("Saving...").color(crate::theme::MUTED));
            }
        });
    }

    /// The scrolling half of the form: every editable field.
    fn form_fields(&mut self, ui: &mut egui::Ui) {
        egui::Grid::new("rule-editor-grid")
            .num_columns(2)
            .spacing([8.0, 4.0])
            .show(ui, |ui| {
                field_label(ui, "Name");
                ui.add_enabled(
                    self.editing.is_none(),
                    TextEdit::singleline(&mut self.name).hint_text("required"),
                );
                ui.end_row();

                field_label(ui, "Action");
                ui.horizontal(|ui| {
                    for a in [Action::Allow, Action::Deny, Action::Reject] {
                        if crate::theme::chip_colored(
                            ui,
                            self.action == a,
                            a.as_str(),
                            action_color(a),
                        )
                        .clicked()
                        {
                            self.action = a;
                        }
                    }
                });
                ui.end_row();

                field_label(ui, "Duration");
                ui.horizontal(|ui| {
                    ComboBox::from_id_salt("editor-duration")
                        .selected_text(self.duration.label())
                        .show_ui(ui, |ui| {
                            for d in [
                                DurationChoice::Session,
                                DurationChoice::Forever,
                                DurationChoice::Timed,
                            ] {
                                ui.selectable_value(&mut self.duration, d, d.label());
                            }
                        });
                    if self.duration == DurationChoice::Timed {
                        ui.add(
                            TextEdit::singleline(&mut self.timespan)
                                .desired_width(60.0)
                                .hint_text("1h"),
                        );
                        ui.label("from now");
                    }
                });
                ui.end_row();

                field_label(ui, "Priority");
                ui.add(TextEdit::singleline(&mut self.priority).desired_width(60.0));
                ui.end_row();

                field_label(ui, "Enabled");
                ui.checkbox(&mut self.enabled, "");
                ui.end_row();

                // Above the separator, with the rest of the rule's own
                // properties: a tag selects the rule, it does not select
                // connections, and putting it under "Match criteria" would
                // read as an operand that narrows what the rule catches.
                field_label(ui, "Tags");
                ui.add(
                    TextEdit::singleline(&mut self.tags)
                        .hint_text("work, vpn")
                        .desired_width(200.0),
                );
                ui.end_row();
            });

        ui.add_space(8.0);
        ui.label(
            egui::RichText::new("MATCH CRITERIA")
                .small()
                .strong()
                .color(crate::theme::MUTED),
        );
        ui.label(
            egui::RichText::new("All set fields must match; leave blank to ignore.")
                .small()
                .color(crate::theme::MUTED),
        );
        ui.add_space(4.0);

        egui::Grid::new("rule-editor-match")
            .num_columns(2)
            .spacing([8.0, 4.0])
            .show(ui, |ui| {
                for (label, field, hint) in [
                    ("Executable", &mut self.exe, "/usr/bin/curl"),
                    ("Exe glob", &mut self.exe_glob, "/usr/bin/*"),
                    ("Exe SHA-256", &mut self.exe_sha256, "64 hex digits"),
                    ("Destination", &mut self.dest, "1.2.3.4 or 10.0.0.0/8"),
                    ("Port", &mut self.port, "443"),
                    ("Port range", &mut self.port_range, "6000-6100"),
                    ("Domain", &mut self.domain, "example.org or *.example.org"),
                    ("User (uid)", &mut self.user, "1000"),
                ] {
                    field_label(ui, label);
                    ui.add(TextEdit::singleline(field).hint_text(hint));
                    ui.end_row();
                }

                field_label(ui, "Protocol");
                ComboBox::from_id_salt("editor-proto")
                    .selected_text(proto_label(self.proto))
                    .show_ui(ui, |ui| {
                        for p in [None, Some(Proto::Tcp), Some(Proto::Udp)] {
                            ui.selectable_value(&mut self.proto, p, proto_label(p));
                        }
                    });
                ui.end_row();

                for (label, field, hint) in [
                    (
                        "Domains file",
                        &mut self.domains_file,
                        "/etc/hallpass/rules.d/ads.list",
                    ),
                    ("IPs file", &mut self.ips_file, "one IP/CIDR per line"),
                    ("Hashes file", &mut self.hashes_file, "one SHA-256 per line"),
                    (
                        "Cmdline contains",
                        &mut self.cmdline_contains,
                        "substring of argv",
                    ),
                    ("Parent exe", &mut self.parent_exe, "/usr/bin/bash"),
                    ("Source", &mut self.src, "IP or CIDR"),
                    ("Source port", &mut self.src_port, ""),
                    ("Interface", &mut self.iface, "wg0"),
                    ("App id", &mut self.app_id, "flatpak:org.mozilla.firefox"),
                ] {
                    field_label(ui, label);
                    ui.add(TextEdit::singleline(field).hint_text(hint));
                    ui.end_row();
                }
            });

        // Said where the operator can still act on it, because this form is
        // prefilled from a connection with the action defaulting to deny.
        // An app id only narrows, and a block that narrows can stop applying
        // for a reason that has nothing to do with policy: the application
        // turns up without a recognized cgroup scope, the operand does not
        // match, and the connection falls through to the default verdict.
        // The daemon refuses to generate this shape at all (see
        // `rule_from_reply`); here the operator may want it, so it is a
        // warning rather than a rule.
        if self.action != Action::Allow && !self.app_id.trim().is_empty() {
            ui.colored_label(
                crate::theme::REJECT_COLOR,
                "\u{26a0} An app id narrows this rule. A deny carrying one stops applying \
                 whenever the application runs outside its packaging scope; leave it blank \
                 to block the executable however it is launched.",
            );
        }

        if self.editing.is_some() && self.duration == DurationChoice::Timed {
            ui.label(
                egui::RichText::new("Saving a timed rule restarts its clock from now.")
                    .small()
                    .color(crate::theme::MUTED),
            );
        }
    }
}

/// A form label: muted, so the eye lands on the values rather than on the
/// two dozen field names beside them.
fn field_label(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).color(crate::theme::MUTED));
}

/// The verdict palette, for the action picker's own chip.
fn action_color(action: Action) -> egui::Color32 {
    match action {
        Action::Allow => crate::theme::ALLOW_COLOR,
        Action::Deny => crate::theme::DENY_COLOR,
        Action::Reject => crate::theme::REJECT_COLOR,
    }
}

fn proto_label(p: Option<Proto>) -> String {
    p.map_or_else(|| "any".to_string(), |p| p.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filled() -> RuleEditor {
        let mut e = RuleEditor::add();
        e.name = "test".into();
        e.port = "443".into();
        e
    }

    fn conn(exe: Option<&str>, domain: Option<&str>) -> Connection {
        Connection {
            pid: Some(1),
            domain: domain.map(String::from),
            ..crate::testutil::conn(exe, "93.184.216.34:443")
        }
    }

    #[test]
    fn prefill_from_connection_prefers_the_domain() {
        let e = RuleEditor::from_connection(&conn(Some("/usr/bin/curl"), Some("example.org")));
        assert_eq!(e.name, "curl-443");
        assert_eq!(e.exe, "/usr/bin/curl");
        assert_eq!(e.port, "443");
        assert_eq!(e.proto, Some(Proto::Tcp));
        // An address is one of however many a name resolves to, so a rule
        // pinned to it would quietly stop covering what was meant.
        assert_eq!(e.domain, "example.org");
        assert_eq!(e.dest, "");
        // Deny, not whatever the connection got: the operator picked this
        // row out, and the safe reading of that is "stop this".
        assert_eq!(e.action, Action::Deny);

        // Without a resolved name the address is all there is.
        let e = RuleEditor::from_connection(&conn(Some("/usr/bin/curl"), None));
        assert_eq!(e.dest, "93.184.216.34");
        assert_eq!(e.domain, "");
    }

    /// The process chose its own executable path, and the prefilled name is
    /// a field the operator reads back before saving.
    #[test]
    fn prefill_sanitizes_hostile_paths() {
        let e = RuleEditor::from_connection(&conn(
            Some("/tmp/evil\r\x1b[2K/usr/bin/firefox"),
            Some("bank.example\u{202e}moc.reknatta"),
        ));
        for field in [&e.name, &e.exe, &e.domain] {
            assert!(!field.contains('\x1b'), "{field:?}");
            assert!(!field.contains('\r'), "{field:?}");
            assert!(!field.contains('\u{202e}'), "{field:?}");
        }
    }

    #[test]
    fn minimal_rule_builds() {
        let rule = filled().to_rule().expect("minimal rule");
        assert_eq!(rule.name, "test");
        assert_eq!(rule.matcher.port, Some(443));
        assert_eq!(rule.duration, RuleDuration::Forever);
        assert!(rule.enabled);
    }

    #[test]
    fn empty_match_is_rejected() {
        let mut e = RuleEditor::add();
        e.name = "everything".into();
        let err = e.to_rule().unwrap_err();
        assert!(err.contains("at least one match criterion"), "{err}");
    }

    #[test]
    fn parse_errors_name_the_field() {
        let mut e = filled();
        e.port = "http".into();
        assert!(e.to_rule().unwrap_err().contains("port"));

        let mut e = filled();
        e.port_range = "80".into();
        assert!(e.to_rule().unwrap_err().contains("port range"));

        let mut e = filled();
        e.user = "alice".into();
        assert!(e.to_rule().unwrap_err().contains("uid"));

        let mut e = filled();
        e.duration = DurationChoice::Timed;
        e.timespan = "soon".into();
        assert!(e.to_rule().unwrap_err().contains("timespan"));
    }

    #[test]
    fn timed_duration_lands_in_the_future() {
        let mut e = filled();
        e.duration = DurationChoice::Timed;
        e.timespan = "5m".into();
        let rule = e.to_rule().expect("timed rule");
        match rule.duration {
            RuleDuration::Until { deadline_ms } => {
                assert!(deadline_ms > hallpass_types::unix_ms_now());
            }
            other => panic!("expected Until, got {other:?}"),
        }
    }

    #[test]
    fn edit_round_trips_the_matcher() {
        let rule = Rule {
            name: "rt".into(),
            action: Action::Reject,
            duration: RuleDuration::Forever,
            priority: 42,
            enabled: true,
            // Tagged, because saving is an add by the same name: an editor
            // that dropped tags would quietly remove a rule from every set
            // it belonged to.
            tags: vec!["work".into(), "vpn".into()],
            matcher: RuleMatch {
                exe: Some("/usr/bin/curl".into()),
                dest: Some("10.0.0.0/8".into()),
                port_range: Some((6000, 6100)),
                proto: Some(Proto::Udp),
                iface: Some("wg0".into()),
                user: Some(1000),
                ..Default::default()
            },
        };
        let back = RuleEditor::edit(&rule).to_rule().expect("round trip");
        assert_eq!(back, rule);
    }

    #[test]
    fn tags_field_accepts_commas_and_spaces_and_refuses_the_rest() {
        assert_eq!(parse_tags(""), Ok(Vec::new()));
        assert_eq!(
            parse_tags("work, vpn home-lab"),
            Ok(vec!["work".to_string(), "vpn".into(), "home-lab".into()])
        );
        assert!(parse_tags("Work").is_err(), "case is refused, not folded");
        assert!(parse_tags("work, work").is_err(), "a repeat is a typo");
        let many = (0..=hallpass_types::MAX_TAGS_PER_RULE)
            .map(|i| format!("t{i}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_tags(&many).is_err());
    }

    /// Editing a disabled rule must not re-enable it: the enabled flag
    /// rides through the form like every other field.
    #[test]
    fn editing_a_disabled_rule_keeps_it_disabled() {
        let rule = Rule {
            name: "off".into(),
            action: Action::Allow,
            duration: RuleDuration::Forever,
            priority: 1,
            enabled: false,
            tags: Vec::new(),
            matcher: RuleMatch {
                port: Some(80),
                ..Default::default()
            },
        };
        let back = RuleEditor::edit(&rule).to_rule().expect("round trip");
        assert!(!back.enabled);
        assert_eq!(back, rule);
    }

    #[test]
    fn editing_a_timed_rule_prefills_the_remaining_time() {
        let rule = Rule {
            name: "timed".into(),
            action: Action::Deny,
            duration: RuleDuration::Until {
                deadline_ms: hallpass_types::unix_ms_now() + 90_000,
            },
            priority: 1,
            enabled: true,
            tags: Vec::new(),
            matcher: RuleMatch {
                port: Some(80),
                ..Default::default()
            },
        };
        let e = RuleEditor::edit(&rule);
        // ~90 seconds left; the prefill is that remainder, not a default.
        let secs: u64 = e
            .timespan
            .strip_suffix('s')
            .expect("prefill in seconds")
            .parse()
            .expect("numeric");
        assert!((85..=91).contains(&secs), "prefill was {secs}s");
    }

    #[test]
    fn whitespace_only_fields_are_unset() {
        let mut e = filled();
        e.domain = "  ".into();
        e.iface = " ".into();
        let rule = e.to_rule().unwrap();
        assert_eq!(rule.matcher.domain, None);
        assert_eq!(rule.matcher.iface, None);
    }
}

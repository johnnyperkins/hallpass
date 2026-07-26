//! The rule add/edit form.
//!
//! Every field is edited as text (empty means "not set") and parsed into
//! a [`Rule`] on save. Client-side parsing exists for immediate feedback
//! only; the daemon revalidates through the same compilation path as
//! every other rule source and its error comes back over IPC, so nothing
//! here is a trust boundary.

use eframe::egui::{self, ComboBox, TextEdit};
use hallpass_types::{Action, Proto, Rule, RuleDuration, RuleMatch};

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
    /// Parse error from the last save attempt.
    error: Option<String>,
    /// A save was sent and the daemon has not answered yet. The window
    /// stays open until the ack: the daemon validates more than the form
    /// does (CIDR syntax, globs, hash format), and closing on send would
    /// destroy everything typed when the daemon rejects the rule.
    awaiting: bool,
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
            error: None,
            awaiting: false,
        }
    }

    /// A form pre-filled from an existing rule.
    pub fn edit(rule: &Rule) -> Self {
        let m = &rule.matcher;
        let path = |p: &Option<std::path::PathBuf>| {
            p.as_ref().map(|p| p.display().to_string()).unwrap_or_default()
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
                .map(|t| t.parse().map_err(|_| format!("{what} must be a port number")))
                .transpose()
        };

        let port_range = match opt(&self.port_range) {
            None => None,
            Some(t) => {
                let (a, b) = t
                    .split_once('-')
                    .ok_or("port range must be like 6000-6100")?;
                Some((
                    a.trim().parse().map_err(|_| "bad port range start".to_string())?,
                    b.trim().parse().map_err(|_| "bad port range end".to_string())?,
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
                .map(|t| t.parse().map_err(|_| "user must be a numeric uid".to_string()))
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
            matcher,
        })
    }

    /// Render the editor window. Returns `(keep_open, rule_to_send)`.
    /// A returned rule does not close the window; the app closes it when
    /// the daemon acks via [`RuleEditor::ack_ok`].
    pub fn window(&mut self, ctx: &egui::Context) -> (bool, Option<Rule>) {
        let mut open = true;
        let mut saved = None;
        let title = match &self.editing {
            Some(name) => format!("Edit rule: {name}"),
            None => "Add rule".to_string(),
        };
        egui::Window::new(title)
            .id(egui::Id::new("rule-editor"))
            .open(&mut open)
            .collapsible(false)
            .default_width(420.0)
            .show(ctx, |ui| {
                self.form(ui, &mut saved);
            });
        if saved.is_some() {
            self.awaiting = true;
        }
        (open, saved)
    }

    /// Whether a save is in flight, i.e. the next daemon Ok/Err answers it.
    pub fn awaiting_ack(&self) -> bool {
        self.awaiting
    }

    /// The daemon rejected the save: show its message, allow another try.
    pub fn ack_err(&mut self, message: &str) {
        self.awaiting = false;
        self.error = Some(format!("daemon rejected the rule: {message}"));
    }

    /// The save never reached the daemon (connection lost): re-enable
    /// the form so it can be retried without losing what was typed.
    pub fn ack_lost(&mut self, message: &str) {
        self.awaiting = false;
        self.error = Some(message.to_string());
    }

    fn form(&mut self, ui: &mut egui::Ui, saved: &mut Option<Rule>) {
        egui::Grid::new("rule-editor-grid")
            .num_columns(2)
            .spacing([8.0, 4.0])
            .show(ui, |ui| {
                ui.label("Name");
                ui.add_enabled(
                    self.editing.is_none(),
                    TextEdit::singleline(&mut self.name).hint_text("required"),
                );
                ui.end_row();

                ui.label("Action");
                ComboBox::from_id_salt("editor-action")
                    .selected_text(self.action.as_str())
                    .show_ui(ui, |ui| {
                        for a in [Action::Allow, Action::Deny, Action::Reject] {
                            ui.selectable_value(&mut self.action, a, a.as_str());
                        }
                    });
                ui.end_row();

                ui.label("Duration");
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

                ui.label("Priority");
                ui.add(TextEdit::singleline(&mut self.priority).desired_width(60.0));
                ui.end_row();

                ui.label("Enabled");
                ui.checkbox(&mut self.enabled, "");
                ui.end_row();
            });

        ui.separator();
        ui.label("Match criteria (all set fields must match; leave blank to ignore):");

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
                    ui.label(label);
                    ui.add(TextEdit::singleline(field).hint_text(hint));
                    ui.end_row();
                }

                ui.label("Protocol");
                ComboBox::from_id_salt("editor-proto")
                    .selected_text(proto_label(self.proto))
                    .show_ui(ui, |ui| {
                        for p in [None, Some(Proto::Tcp), Some(Proto::Udp)] {
                            ui.selectable_value(&mut self.proto, p, proto_label(p));
                        }
                    });
                ui.end_row();

                for (label, field, hint) in [
                    ("Domains file", &mut self.domains_file, "/etc/hallpass/rules.d/ads.list"),
                    ("IPs file", &mut self.ips_file, "one IP/CIDR per line"),
                    ("Hashes file", &mut self.hashes_file, "one SHA-256 per line"),
                    ("Cmdline contains", &mut self.cmdline_contains, "substring of argv"),
                    ("Parent exe", &mut self.parent_exe, "/usr/bin/bash"),
                    ("Source", &mut self.src, "IP or CIDR"),
                    ("Source port", &mut self.src_port, ""),
                    ("Interface", &mut self.iface, "wg0"),
                ] {
                    ui.label(label);
                    ui.add(TextEdit::singleline(field).hint_text(hint));
                    ui.end_row();
                }
            });

        if self.editing.is_some() && self.duration == DurationChoice::Timed {
            ui.label("Saving a timed rule restarts its clock from now.");
        }
        if let Some(err) = &self.error {
            ui.colored_label(crate::app::DENY_COLOR, err);
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!self.awaiting, egui::Button::new("Save"))
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
                ui.label("Saving...");
            }
        });
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

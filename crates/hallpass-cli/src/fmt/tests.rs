use super::*;
use hallpass_types::{Action, FirstSeen, FlowTuple, Proto, RuleDuration, RuleMatch};
use std::net::SocketAddr;
use std::path::PathBuf;

#[test]
fn cmdline_display_is_bounded_and_keeps_no_layout() {
    assert_eq!(cmdline_display("curl  -s\t https://x"), "curl -s https://x");
    let padded = format!(
        "x{}prompt #9: /usr/bin/firefox{}",
        " ".repeat(300),
        "y".repeat(4000)
    );
    let shown = cmdline_display(&padded);
    assert!(!shown.contains("  "), "whitespace layout survived: {shown}");
    // The whole `watch` line, label included, stays inside 80 columns.
    assert!("  cmdline: ".len() + shown.chars().count() <= 80, "{shown}");
    assert!(shown.ends_with(')'), "{shown}");
}

fn conn(domain: Option<&str>) -> Connection {
    Connection {
        tuple: FlowTuple {
            proto: Proto::Tcp,
            src: "127.0.0.1:50000".parse::<SocketAddr>().unwrap(),
            dst: "93.184.216.34:443".parse::<SocketAddr>().unwrap(),
        },
        uid: Some(1000),
        pid: Some(4242),
        exe_path: Some(PathBuf::from("/usr/bin/curl")),
        cmdline: Some("curl https://example.org".into()),
        parent_exe: None,
        domain: domain.map(String::from),
        iface: None,
        app_id: None,
        first_seen: None,
    }
}

#[test]
fn ts_formatting() {
    assert_eq!(format_ts(0), "1970-01-01 00:00:00");
    // 2024-07-03 09:46:40 UTC.
    assert_eq!(format_ts(1_720_000_000_000), "2024-07-03 09:46:40");
}

#[test]
fn uptime_formatting() {
    assert_eq!(format_uptime(0), "0s");
    assert_eq!(format_uptime(59), "59s");
    assert_eq!(format_uptime(3661), "1h 1m 1s");
    assert_eq!(format_uptime(90_061), "1d 1h 1m 1s");
    assert_eq!(format_uptime(86_400), "1d 0h 0m 0s");
}

fn plain() -> Palette {
    Palette::new(false)
}

#[test]
fn event_line_with_domain() {
    let ev = ConnEvent {
        conn: conn(Some("example.org")),
        verdict: Verdict::Allow,
        rule_name: Some("allow-curl".into()),
        unix_ms: 1_720_000_000_000,
        enforced: true,
    };
    assert_eq!(
        format_event(&ev, plain()),
        "2024-07-03 09:46:40 ALLOW        /usr/bin/curl -> example.org:443 \
         rule=allow-curl"
    );
}

/// The marker is appended, so every existing field keeps its position,
/// and it is absent both when nothing is new and when the daemon is not
/// tracking: a text line cannot say "unknown", and claiming "seen
/// before" for a feature that is off would be a lie about policy.
#[test]
fn event_line_marks_what_is_new() {
    let mk = |first_seen| {
        let mut c = conn(Some("example.org"));
        c.first_seen = first_seen;
        format_event(
            &ConnEvent {
                conn: c,
                verdict: Verdict::Allow,
                rule_name: Some("allow-curl".into()),
                unix_ms: 1_720_000_000_000,
                enforced: true,
            },
            plain(),
        )
    };
    assert!(mk(Some(FirstSeen {
        app: true,
        dest: true
    }))
    .ends_with(" new=app,dest"));
    assert!(mk(Some(FirstSeen {
        app: false,
        dest: true
    }))
    .ends_with(" new=dest"));
    assert!(mk(Some(FirstSeen {
        app: true,
        dest: false
    }))
    .ends_with(" new=app"));
    for quiet in [
        Some(FirstSeen {
            app: false,
            dest: false,
        }),
        None,
    ] {
        let line = mk(quiet);
        assert!(!line.contains("new="), "{line}");
        assert!(line.ends_with("rule=allow-curl"), "{line}");
    }
}

#[test]
fn event_line_without_domain_or_rule() {
    let mut c = conn(None);
    c.exe_path = None;
    let ev = ConnEvent {
        conn: c,
        verdict: Verdict::Reject,
        rule_name: None,
        unix_ms: 0,
        enforced: true,
    };
    assert_eq!(
        format_event(&ev, plain()),
        "1970-01-01 00:00:00 REJECT       ? -> 93.184.216.34:443 rule=-"
    );
}

/// An unenforced deny must read WOULD-DENY: the packet went out, and a
/// reader shown DENY would conclude the opposite.
#[test]
fn observe_mode_event_lines_say_would() {
    let mk = |verdict, enforced| ConnEvent {
        conn: conn(Some("example.org")),
        verdict,
        rule_name: Some("r".into()),
        unix_ms: 0,
        enforced,
    };
    let cases = [
        (Verdict::Deny, false, "WOULD-DENY"),
        (Verdict::Reject, false, "WOULD-REJECT"),
        (Verdict::Deny, true, "DENY"),
        (Verdict::Reject, true, "REJECT"),
        (Verdict::Allow, false, "ALLOW"),
    ];
    for (verdict, enforced, want) in cases {
        let line = format_event(&mk(verdict, enforced), plain());
        let field = line.split_whitespace().nth(2).expect("verdict field");
        assert_eq!(field, want, "{line}");
    }
}

/// Color is opt-in, lands only on the verdict, and is padded on the
/// unpainted text so the columns after it still line up.
#[test]
fn color_only_when_enabled_and_does_not_shift_columns() {
    let ev = ConnEvent {
        conn: conn(Some("example.org")),
        verdict: Verdict::Deny,
        rule_name: None,
        unix_ms: 0,
        enforced: true,
    };
    let bare = format_event(&ev, plain());
    assert!(!bare.contains('\x1b'));

    let painted = format_event(&ev, Palette::new(true));
    assert!(painted.contains("\x1b[31mDENY\x1b[0m"), "{painted:?}");
    // Same text once the escapes are removed: color adds nothing else.
    let stripped: String = painted.replace("\x1b[31m", "").replace("\x1b[0m", "");
    assert_eq!(stripped, bare);
}

#[test]
fn color_choice_resolution() {
    let cases = [
        // (json, choice, tty, no_color, colorize)
        (false, ColorChoice::Auto, true, false, true),
        (false, ColorChoice::Auto, false, false, false),
        (false, ColorChoice::Auto, true, true, false),
        (false, ColorChoice::Always, false, true, true),
        (false, ColorChoice::Never, true, false, false),
        // JSON is never colorized, however loudly it was asked for.
        (true, ColorChoice::Always, true, false, false),
    ];
    for (json, choice, tty, no_color, want) in cases {
        let out = Output::resolve(json, choice, tty, no_color);
        assert_eq!(
            out.palette.enabled(),
            want,
            "json={json} choice={choice:?} tty={tty} no_color={no_color}"
        );
        assert_eq!(out.tty, tty);
        assert_eq!(out.json, json);
    }
}

fn stats(enforcing: bool) -> Stats {
    Stats {
        connections_total: 100,
        allowed: 80,
        denied: 15,
        prompted: 5,
        rules_loaded: 3,
        lockdown: None,
        uptime_secs: 3600,
        dns_spoof_rejected: 7,
        rules_skipped: 2,
        prompts_overflowed: 1,
        other_proto_total: 0,
        observed_only: 4,
        dns_snoop_dropped: 6,
        enforcing,
        prompt_handler_connected: true,
        prompts_unanswered: 9,
        prompt_handlers_evicted: 2,
        verdict_queue_dropped: Some(0),
        verdict_queue_user_dropped: Some(0),
        verdict_queue_depth: Some(3),
        snoop_queue_dropped: Some(0),
        snoop_queue_user_dropped: Some(0),
        snoop_queue_depth: Some(0),
        verdict_queue_fail_open: Some(true),
        snoop_queue_fail_open: Some(true),
        verdict_queue_max_len: Some(4096),
        nft_flushes: 0,
        nft_last_flush_ms: None,
        flows_accounted: 0,
        flow_bytes: 0,
        flow_packets: 0,
    }
}

/// One stats-table row as [`format_stats`] pads it. The width is the
/// longest key; keeping it here in one place is what lets the row
/// assertions survive a new longest key.
fn row(k: &str, v: &str) -> String {
    format!("{k:25}  {v}\n")
}

#[test]
fn stats_table() {
    let out = format_stats(&stats(true), plain());
    assert!(out.contains(&row("mode", "enforcing")), "{out}");
    assert!(out.contains(&row("connections", "100")), "{out}");
    assert!(out.contains(&row("observed only", "4")), "{out}");
    assert!(out.contains(&row("rules loaded", "3")), "{out}");
    assert!(out.contains(&row("rules skipped", "2")), "{out}");
    assert!(out.contains(&row("dns spoofed", "7")), "{out}");
    assert!(out.contains(&row("dns snoop dropped", "6")), "{out}");
    assert!(out.contains(&row("prompt overflows", "1")), "{out}");
    assert!(out.contains(&row("nft table flushes", "0")), "{out}");
    assert!(out.contains(&row("nft last flush", "-")), "{out}");
    assert!(out.contains(&row("uptime", "1h 0m 0s")), "{out}");
    // No warning while enforcing.
    assert!(!out.contains("OBSERVE"), "{out}");
}

/// With no prompt handler the daemon asks nobody and applies the default
/// verdict, and every other counter in this table looks the same as it
/// does on a host whose operator is answering. The row has to say so.
#[test]
fn stats_table_reports_the_prompt_handler() {
    let out = format_stats(&stats(true), plain());
    assert!(out.contains(&row("prompt handler", "connected")), "{out}");
    assert!(out.contains(&row("prompts unanswered", "9")), "{out}");
    assert!(out.contains(&row("handlers evicted", "2")), "{out}");

    let mut s = stats(true);
    s.prompt_handler_connected = false;
    let out = format_stats(&s, plain());
    assert!(
        out.contains(&row(
            "prompt handler",
            "none (unmatched connections take the default)"
        )),
        "{out}"
    );
}

/// A status table that looks healthy while nothing is filtered is the
/// worst possible output, so observe mode says so twice: in the mode row
/// and in a trailing line.
#[test]
fn stats_table_flags_observe_mode() {
    let out = format_stats(&stats(false), plain());
    assert!(
        out.contains(&row("mode", "observe (not enforcing)")),
        "{out}"
    );
    assert!(out.contains(OBSERVE_WARNING), "{out}");
    assert!(out.contains("every packet is let through"), "{out}");
}

/// The kernel queue rows: numbers render as numbers, a healthy zero is
/// unpainted, and nothing extra is claimed while nothing was dropped.
/// A nonzero flush count renders painted, with its timestamp beside it.
#[test]
fn stats_table_flush_rows_when_flushed() {
    let s = Stats {
        nft_flushes: 2,
        nft_last_flush_ms: Some(1_720_000_000_000),
        ..stats(true)
    };
    let out = format_stats(&s, Palette::new(false));
    assert!(out.contains(&row("nft table flushes", "2")), "{out}");
    assert!(
        out.contains(&row("nft last flush", "2024-07-03 09:46:40")),
        "{out}"
    );
}

#[test]
fn stats_table_shows_flow_accounting_rows() {
    let s = Stats {
        flows_accounted: 41,
        flow_bytes: 9_000_000,
        flow_packets: 7_200,
        ..stats(true)
    };
    let out = format_stats(&s, Palette::new(false));
    assert!(out.contains(&row("flows accounted", "41")), "{out}");
    assert!(
        out.contains(&row("flow bytes", "9000000 (8.6 MiB)")),
        "{out}"
    );
    assert!(out.contains(&row("flow packets", "7200")), "{out}");
}

#[test]
fn stats_table_kernel_queue_rows() {
    let out = format_stats(&stats(true), plain());
    // Against the length in force, since a depth alone has no scale.
    assert!(
        out.contains(&row("verdict queue depth", "3 / 4096")),
        "{out}"
    );
    assert!(out.contains(&row("verdict queue dropped", "0")), "{out}");
    assert!(
        out.contains(&row("verdict queue undelivered", "0")),
        "{out}"
    );
    assert!(
        out.contains(&row("verdict queue fail-open", "yes")),
        "{out}"
    );
    assert!(out.contains(&row("snoop queue depth", "0")), "{out}");
    assert!(out.contains(&row("snoop queue dropped", "0")), "{out}");
    assert!(out.contains(&row("snoop queue undelivered", "0")), "{out}");
    assert!(out.contains(&row("snoop queue fail-open", "yes")), "{out}");
    assert!(!out.contains("dropped by the kernel"), "{out}");
}

/// A kernel that refused the queue length leaves its own default in
/// force and nothing to report it, so the depth is shown bare rather
/// than against a limit this daemon did not set.
#[test]
fn stats_table_depth_without_a_known_limit() {
    let mut s = stats(true);
    s.verdict_queue_max_len = None;
    let out = format_stats(&s, plain());
    assert!(out.contains(&row("verdict queue depth", "3")), "{out}");
}

/// The flag is rendered plainly either way: "no" is the intended state
/// under a fail-closed posture, which this table cannot see.
#[test]
fn stats_table_fail_open_flag_renders_no() {
    let mut s = stats(true);
    s.verdict_queue_fail_open = Some(false);
    let out = format_stats(&s, plain());
    assert!(out.contains(&row("verdict queue fail-open", "no")), "{out}");
}

/// A missing counter reads "unavailable", never zero: zero claims the
/// kernel dropped nothing, and nobody knows that.
#[test]
fn stats_table_missing_kernel_counters_are_not_zero() {
    let mut s = stats(true);
    s.verdict_queue_dropped = None;
    s.verdict_queue_user_dropped = None;
    s.verdict_queue_depth = None;
    s.verdict_queue_fail_open = None;
    let out = format_stats(&s, plain());
    assert!(
        out.contains(&row("verdict queue dropped", "unavailable")),
        "{out}"
    );
    assert!(
        out.contains(&row("verdict queue depth", "unavailable")),
        "{out}"
    );
    assert!(
        out.contains(&row("verdict queue fail-open", "unavailable")),
        "{out}"
    );
    assert!(!out.contains("dropped by the kernel"), "{out}");
}

/// Kernel drops on the verdict queue are packets policy never saw, the
/// one thing this table exists to make loud: painted in the row and
/// summed in a trailing warning.
#[test]
fn stats_table_flags_verdict_queue_drops() {
    let mut s = stats(true);
    s.verdict_queue_dropped = Some(4);
    s.verdict_queue_user_dropped = Some(1);
    let out = format_stats(&s, plain());
    assert!(
        out.contains("5 packets were dropped by the kernel before policy saw them"),
        "{out}"
    );
    // Painted when color is on, and only the affected rows.
    let painted = format_stats(&s, Palette::new(true));
    assert!(painted.contains("\x1b[1;33m4\x1b[0m"), "{painted:?}");
    assert!(painted.contains("\x1b[1;33m1\x1b[0m"), "{painted:?}");
}

#[test]
fn config_table() {
    let out = format_config(
        &RuntimeConfig {
            prompt_timeout_secs: 30,
            default_verdict: Verdict::Deny,
            enforce: true,
        },
        plain(),
    );
    assert!(out.contains("mode            enforcing\n"), "{out}");
    assert!(out.contains("prompt timeout  30s\n"), "{out}");
    assert!(out.contains("default action  deny\n"), "{out}");
    // The settings are runtime-only, and this output is where a headless
    // operator learns that; the GUI settings tab carries the same note.
    assert!(out.contains("runtime only"), "{out}");
    assert!(!out.contains("OBSERVE"), "{out}");
}

/// Same rule as the stats table: settings output that looks routine
/// while nothing is filtered must say so.
#[test]
fn config_table_flags_observe_mode() {
    let out = format_config(
        &RuntimeConfig {
            prompt_timeout_secs: 30,
            default_verdict: Verdict::Allow,
            enforce: false,
        },
        plain(),
    );
    assert!(
        out.contains("mode            observe (not enforcing)\n"),
        "{out}"
    );
    assert!(out.contains(OBSERVE_WARNING), "{out}");
}

/// The rule listing is what an operator reads to audit policy, and rule
/// names carry an executable stem while summaries quote exe, domain and
/// cmdline operands. A rule must not be able to erase or rewrite its row.
#[test]
fn rule_listing_cannot_rewrite_the_terminal() {
    let rules = vec![Rule {
        name: "evil\x1b[A\x1b[2K".into(),
        action: Action::Allow,
        duration: RuleDuration::Forever,
        priority: 100,
        enabled: true,
        tags: Vec::new(),
        matcher: RuleMatch {
            domain: Some("a\r\nb.example.org".into()),
            cmdline_contains: Some("x\x1b[2Ky".into()),
            ..Default::default()
        },
    }];
    let out = format_rules(&rules, None, None);
    assert!(
        !out.contains('\x1b'),
        "escape reached the terminal: {out:?}"
    );
    assert!(!out.contains('\r'), "CR reached the terminal: {out:?}");
    // Header plus exactly one row: nothing smuggled in extra lines.
    assert_eq!(out.lines().count(), 2, "{out:?}");
}

/// Column widths are measured in characters; bytes would over-pad a
/// multibyte name and misalign every column after it.
#[test]
fn multibyte_rule_name_keeps_columns_aligned() {
    let mk = |name: &str| Rule {
        name: name.into(),
        action: Action::Deny,
        duration: RuleDuration::Forever,
        priority: 1,
        enabled: true,
        tags: Vec::new(),
        matcher: RuleMatch {
            port: Some(25),
            ..Default::default()
        },
    };
    // Same character count, very different byte count.
    let out = format_rules(&[mk("日本語テスト"), mk("abcdef")], None, None);
    let rows: Vec<&str> = out.lines().skip(1).collect();
    // Character offset, not the byte offset `find` returns: the point is
    // where the column appears on screen.
    let col = |line: &str| {
        let byte = line.find("deny").expect("action column");
        line[..byte].chars().count()
    };
    assert_eq!(
        col(rows[0]),
        col(rows[1]),
        "action column must line up:\n{out}"
    );
}

#[test]
fn rules_table_alignment_and_summary() {
    let rules = vec![
        Rule {
            name: "a".into(),
            action: Action::Allow,
            duration: RuleDuration::Session,
            priority: 1,
            enabled: true,
            tags: Vec::new(),
            matcher: RuleMatch {
                port: Some(443),
                domain: Some("*.example.org".into()),
                ..Default::default()
            },
        },
        Rule {
            name: "block-everything".into(),
            action: Action::Reject,
            duration: RuleDuration::Forever,
            priority: 0,
            enabled: false,
            tags: Vec::new(),
            matcher: RuleMatch::default(),
        },
    ];
    let out = format_rules(&rules, None, None);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].starts_with("NAME              ACTION  DURATION"));
    assert!(lines[1].contains("port=443 domain=*.example.org"));
    assert!(lines[2].contains("(any)"));
    // NAME column aligned: ACTION starts at same offset in all lines.
    let col = lines[0].find("ACTION").unwrap();
    assert_eq!(&lines[1][col..col + 5], "allow");
    assert_eq!(&lines[2][col..col + 6], "reject");
}

#[test]
fn empty_rules() {
    assert_eq!(format_rules(&[], None, None), "no rules\n");
    assert_eq!(format_rules(&[], Some(&[]), None), "no rules\n");
}

#[test]
fn tags_column_appears_only_when_a_rule_has_tags() {
    let mut rules = vec![counted("a"), counted("b")];
    assert!(!format_rules(&rules, None, None).contains("TAGS"));

    rules[1].tags = vec!["work".into(), "vpn".into()];
    let out = format_rules(&rules, None, None);
    assert!(out.contains("TAGS"), "{out}");
    let lines: Vec<&str> = out.lines().collect();
    assert!(
        lines[1].contains(" -  "),
        "untagged rule reads as a dash:\n{out}"
    );
    assert!(lines[2].contains("work,vpn"), "{out}");
}

fn counted(name: &str) -> Rule {
    Rule {
        name: name.into(),
        action: Action::Deny,
        duration: RuleDuration::Forever,
        priority: 1,
        enabled: true,
        tags: Vec::new(),
        matcher: RuleMatch {
            port: Some(25),
            ..Default::default()
        },
    }
}

/// The question this table answers is "which rules never match", so a rule
/// the daemon reported nothing for has to say 0 and -, not go blank.
#[test]
fn rules_table_with_hits() {
    let rules = [counted("busy"), counted("idle"), counted("missing")];
    // "busy" has matched; "idle" is reported but has never matched, and
    // "missing" has no counter at all. The last two must read the same.
    let hits = [
        RuleHit {
            name: "busy".into(),
            hits: 7,
            last_hit_ms: Some(1_720_000_000_000),
        },
        RuleHit {
            name: "idle".into(),
            hits: 0,
            last_hit_ms: None,
        },
    ];
    let out = format_rules(&rules, Some(&hits), None);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 4, "{out}");
    assert!(lines[0].contains("HITS"), "{out}");
    assert!(lines[0].contains("LAST HIT"), "{out}");
    assert!(lines[1].contains("2024-07-03 09:46:40"), "{out}");

    let fields =
        |line: &str| -> Vec<String> { line.split_whitespace().map(str::to_string).collect() };
    assert_eq!(fields(lines[1])[5], "7");
    for row in [lines[2], lines[3]] {
        let f = fields(row);
        assert_eq!(f[5], "0", "{row}");
        assert_eq!(f[6], "-", "{row}");
    }
    // Plain `rules` is unchanged: no counters, no columns.
    assert!(!format_rules(&rules, None, None).contains("HITS"));
}

/// Counters are keyed on the raw name the daemon accounts against, while
/// the table shows the sanitized copy. Keying on the display form would
/// silently report zero hits for every rule with an odd character in it.
#[test]
fn hits_are_matched_on_the_raw_rule_name() {
    let out = format_rules(
        &[counted("evil\x1b[2K")],
        Some(&[RuleHit {
            name: "evil\x1b[2K".into(),
            hits: 3,
            last_hit_ms: None,
        }]),
        None,
    );
    assert!(!out.contains('\x1b'), "{out:?}");
    assert_eq!(
        out.lines().nth(1).unwrap().split_whitespace().nth(5),
        Some("3")
    );
}

fn tr(name: &str, priority: u32, outcome: TraceOutcome) -> RuleTrace {
    RuleTrace {
        name: name.into(),
        priority,
        outcome,
    }
}

fn explanation() -> Explanation {
    Explanation {
        verdict: Verdict::Allow,
        rule_name: Some("allow-curl".into()),
        would_prompt: false,
        enforced: true,
        trace: vec![
            tr("allow-curl", 50, TraceOutcome::Matched),
            tr("catch-all", 1, TraceOutcome::NotReached),
            tr("turned-off", 60, TraceOutcome::Disabled),
            tr(
                "wrong-port",
                70,
                TraceOutcome::NoMatch {
                    field: "port".into(),
                },
            ),
        ],
    }
}

/// The verdict is the answer, so it comes first and on its own line; the
/// trace below it says which operand to edit for every rule that missed.
#[test]
fn explanation_leads_with_the_verdict_then_the_trace() {
    let out = format_explanation(&explanation(), plain());
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "verdict: ALLOW  rule=allow-curl");
    assert_eq!(lines[1], "");
    assert!(lines[2].starts_with("RULE"), "{out}");
    assert!(lines[3].starts_with("allow-curl"), "{out}");
    assert!(lines[3].ends_with("matched"), "{out}");
    assert!(lines[4].ends_with("not reached"), "{out}");
    assert!(lines[5].ends_with("disabled"), "{out}");
    // Names the operand to change, not just "no".
    assert!(lines[6].ends_with("no match (port)"), "{out}");
    // Priority is shown so the evaluation order reads as deliberate.
    assert!(lines[6].contains("70"), "{out}");
    assert!(!out.contains("more rules not shown"), "{out}");
}

/// `would_prompt` means nothing matched, so the verdict is only what
/// happens if the prompt is ignored. Printing it as the decision would
/// answer a question the operator did not ask.
#[test]
fn explanation_says_when_it_would_prompt() {
    let mut exp = explanation();
    exp.would_prompt = true;
    exp.rule_name = None;
    exp.verdict = Verdict::Deny;
    exp.trace = vec![tr(
        "wrong-port",
        70,
        TraceOutcome::NoMatch {
            field: "port".into(),
        },
    )];
    let out = format_explanation(&exp, plain());
    assert!(
        out.starts_with("verdict: PROMPT  (no rule matched)\n"),
        "{out}"
    );
    assert!(out.contains("would raise a prompt"), "{out}");
    assert!(
        out.contains("the default if nobody answers it is DENY"),
        "{out}"
    );
}

/// Observe mode: the verdict would be recorded and the packet would go
/// out anyway, which is the opposite of what "DENY" alone reads as.
#[test]
fn explanation_says_when_the_verdict_is_only_recorded() {
    let mut exp = explanation();
    exp.verdict = Verdict::Reject;
    exp.enforced = false;
    let out = format_explanation(&exp, plain());
    assert!(out.contains(EXPLAIN_OBSERVE_NOTE), "{out}");
    // And the color says the same thing as the words.
    assert_eq!(verdict_style(Verdict::Reject, false), Style::Would);
    assert_eq!(verdict_style(Verdict::Reject, true), Style::Reject);
}

#[test]
fn explanation_without_rules() {
    let mut exp = explanation();
    exp.trace.clear();
    let out = format_explanation(&exp, plain());
    assert!(out.contains("no rules loaded"), "{out}");
}

/// A rule name embeds an executable stem, so the trace is one more place
/// a process can try to talk to the operator. It must not be able to move
/// the cursor, and it must not be able to forge a row of its own.
#[test]
fn explanation_trace_cannot_rewrite_the_terminal() {
    let exp = Explanation {
        verdict: Verdict::Deny,
        rule_name: Some("evil\x1b[2K".into()),
        would_prompt: false,
        enforced: true,
        trace: vec![
            tr("evil\x1b[A\x1b[2K", 100, TraceOutcome::Matched),
            tr(
                "second\r\nallow-everything  0  matched",
                1,
                TraceOutcome::NoMatch {
                    field: "port\x1b[2K".into(),
                },
            ),
        ],
    };
    let out = format_explanation(&exp, plain());
    assert!(
        !out.contains('\x1b'),
        "escape reached the terminal: {out:?}"
    );
    assert!(!out.contains('\r'), "CR reached the terminal: {out:?}");
    // Verdict, blank, header, two rows: no smuggled extra line.
    assert_eq!(out.lines().count(), 5, "{out:?}");
}

/// The trace is one row per loaded rule, and the daemon bounds how many
/// it loads - but that is a promise made on the other end of a socket.
#[test]
fn explanation_trace_is_capped_but_keeps_the_deciding_rule() {
    let total = MAX_TRACE_ROWS + 50;
    let mut exp = explanation();
    exp.trace = (0..total)
        .map(|i| {
            let outcome = if i == total - 1 {
                TraceOutcome::Matched
            } else {
                TraceOutcome::NoMatch {
                    field: "port".into(),
                }
            };
            tr(&format!("r{i}"), 0, outcome)
        })
        .collect();
    exp.rule_name = Some(format!("r{}", total - 1));
    let out = format_explanation(&exp, plain());
    // Header plus the capped rows plus the deciding rule pulled in past
    // the cap; the count of what is left out stays exact.
    assert_eq!(out.lines().count(), 3 + MAX_TRACE_ROWS + 1 + 1, "{out}");
    assert!(out.contains(&format!("r{}", total - 1)), "{out}");
    assert!(out.contains("... 49 more rules not shown"), "{out}");
}

/// Color marks the answer: the verdict, and the one row that produced it.
#[test]
fn explanation_colors_only_the_verdict_and_the_deciding_rule() {
    let mut exp = explanation();
    exp.verdict = Verdict::Deny;
    let painted = format_explanation(&exp, Palette::new(true));
    assert!(painted.contains("\x1b[31mDENY\x1b[0m"), "{painted:?}");
    assert!(painted.contains("\x1b[31mallow-curl\x1b[0m"), "{painted:?}");
    assert!(!painted.contains("\x1b[31mcatch-all"), "{painted:?}");
    // Same text once the escapes are gone: color adds nothing else, and
    // padding is computed on the unpainted width so columns still line up.
    let stripped = painted.replace("\x1b[31m", "").replace("\x1b[0m", "");
    assert_eq!(stripped, format_explanation(&exp, plain()));
}

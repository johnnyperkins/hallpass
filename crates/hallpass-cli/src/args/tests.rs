use super::*;
use hallpass_types::{Connection, FlowTuple};

fn parse_ok(args: &[&str]) -> Cli {
    let argv: Vec<String> = args.iter().map(ToString::to_string).collect();
    match parse(&argv).unwrap() {
        Parsed::Cli(cli) => cli,
        Parsed::Help => panic!("unexpected help"),
    }
}

fn parse_err(args: &[&str]) -> String {
    let argv: Vec<String> = args.iter().map(ToString::to_string).collect();
    parse(&argv).unwrap_err()
}

/// The wrapped command's own flags belong to it, not to this CLI.
#[test]
fn run_takes_its_command_verbatim() {
    assert_eq!(
        parse_ok(&["run", "--", "curl", "--json", "https://example.org"]).cmd,
        Cmd::Run {
            argv: vec!["curl".into(), "--json".into(), "https://example.org".into()]
        },
        "flags after the command are the command's, including ones this CLI has"
    );
    assert_eq!(
        parse_ok(&["run", "curl"]).cmd,
        Cmd::Run {
            argv: vec!["curl".into()]
        },
        "the separator is conventional, not required"
    );
    // Global options still work, as long as they precede `run`.
    let cli = parse_ok(&["--socket", "/tmp/s.sock", "run", "--", "curl"]);
    assert_eq!(cli.socket, std::path::PathBuf::from("/tmp/s.sock"));
    assert_eq!(
        cli.cmd,
        Cmd::Run {
            argv: vec!["curl".into()]
        }
    );

    assert!(parse_err(&["run"]).contains("needs a command"));
    // `run --help` is a question about `run`, not a program to execute.
    assert_eq!(
        parse(&["run".to_string(), "--help".to_string()]).unwrap(),
        Parsed::Help
    );
    assert_eq!(
        parse_ok(&["run", "--", "--help"]).cmd,
        Cmd::Run {
            argv: vec!["--help".into()]
        },
        "after the separator it is the wrapped command's argument"
    );
    assert_eq!(
        parse_ok(&["run", "curl", "--help"]).cmd,
        Cmd::Run {
            argv: vec!["curl".into(), "--help".into()]
        },
        "and later in the line it is always the command's"
    );
    // `run` is only a command in command position; elsewhere it is
    // whatever the option it follows says it is.
    assert_eq!(
        parse_ok(&["explain", "--dest", "1.1.1.1", "--port", "443", "--exe", "run"]).cmd,
        Cmd::Explain(ExplainRequest {
            conn: Connection {
                tuple: FlowTuple {
                    proto: Proto::Tcp,
                    src: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    dst: "1.1.1.1:443".parse().unwrap(),
                },
                uid: None,
                pid: None,
                exe_path: Some("run".into()),
                cmdline: None,
                parent_exe: None,
                domain: None,
                iface: None,
                app_id: None,
                first_seen: None,
            },
            exe_sha256: None,
        }),
        "an option value that happens to be `run` stays that option's value"
    );
    assert!(parse_err(&["run", "--"]).contains("needs a command"));
    assert_eq!(parse_ok(&["sessions"]).cmd, Cmd::Sessions);
    parse_err(&["sessions", "extra"]);
}

#[test]
fn simple_commands() {
    assert_eq!(parse_ok(&["status"]).cmd, Cmd::Status);
    assert_eq!(parse_ok(&["doctor"]).cmd, Cmd::Doctor);
    parse_err(&["doctor", "extra"]);
    assert_eq!(parse_ok(&["watch"]).cmd, Cmd::Watch);
    assert_eq!(
        parse_ok(&["rules"]).cmd,
        Cmd::RulesList {
            stats: false,
            tag: None
        }
    );
    assert_eq!(
        parse_ok(&["events"]).cmd,
        Cmd::Events(EventsOpts {
            last: None,
            follow: true,
            filters: Filters::default(),
        })
    );
    assert_eq!(parse_ok(&["top"]).cmd, Cmd::Top(TopOpts::default()));
}

#[test]
fn global_output_flags() {
    let cli = parse_ok(&["status"]);
    assert!(!cli.json);
    assert_eq!(cli.color, ColorChoice::Auto);
    // Accepted on either side of the command, like --socket.
    let cli = parse_ok(&["--json", "top", "--color", "never"]);
    assert!(cli.json);
    assert_eq!(cli.color, ColorChoice::Never);
    assert_eq!(
        parse_ok(&["status", "--color", "always"]).color,
        ColorChoice::Always
    );
    assert!(parse_err(&["status", "--color", "maybe"]).contains("invalid --color"));
    assert!(parse_err(&["status", "--color"]).contains("requires a value"));
}

#[test]
fn config_commands() {
    assert_eq!(parse_ok(&["config"]).cmd, Cmd::ConfigShow);
    assert_eq!(
        parse_ok(&["config", "set", "--timeout", "60", "--default", "deny"]).cmd,
        Cmd::ConfigSet(ConfigSetOpts {
            timeout_secs: Some(60),
            default_verdict: Some(Verdict::Deny),
            enforce: None,
        })
    );
    assert!(parse_err(&["config", "nope"]).contains("unknown config subcommand"));
    assert!(parse_err(&["config", "set"]).contains("nothing to change"));
    assert!(parse_err(&["config", "set", "--timeout", "x"]).contains("invalid --timeout"));
    assert!(parse_err(&["config", "set", "--default", "maybe"]).contains("invalid --default"));
    assert!(parse_err(&["config", "set", "--observe", "--enforce"]).contains("at most one"));
}

/// `--observe` alone is refused: it stops enforcement host-wide, and in
/// a script one mistyped flag should not be able to do that silently.
/// `--enforce` needs no confirmation; turning the firewall on is the
/// safe direction.
#[test]
fn observe_requires_yes() {
    assert!(parse_err(&["config", "set", "--observe"]).contains("--yes"));
    assert_eq!(
        parse_ok(&["config", "set", "--observe", "--yes"]).cmd,
        Cmd::ConfigSet(ConfigSetOpts {
            timeout_secs: None,
            default_verdict: None,
            enforce: Some(false),
        })
    );
    assert_eq!(
        parse_ok(&["config", "set", "--enforce"]).cmd,
        Cmd::ConfigSet(ConfigSetOpts {
            enforce: Some(true),
            ..ConfigSetOpts::default()
        })
    );
}

#[test]
fn events_flags() {
    let Cmd::Events(opts) = parse_ok(&[
        "events",
        "--last",
        "50",
        "--no-follow",
        "--exe",
        "curl",
        "--exe",
        "wget",
        "--domain",
        "example.org",
        "--verdict",
        "blocked",
    ])
    .cmd
    else {
        panic!("expected Events");
    };
    assert_eq!(opts.last, Some(50));
    assert!(!opts.follow);
    assert_eq!(
        opts.filters.exe,
        vec!["curl".to_string(), "wget".to_string()]
    );
    assert_eq!(opts.filters.domain, vec!["example.org".to_string()]);
    assert_eq!(opts.filters.verdict, vec![Verdict::Deny, Verdict::Reject]);
}

/// `--last` is clamped rather than rejected, so an absurd value still
/// bounds what the daemon has to encode and the CLI has to hold.
#[test]
fn events_last_is_clamped() {
    let Cmd::Events(opts) = parse_ok(&["events", "--last", "99999999"]).cmd else {
        panic!("expected Events");
    };
    assert_eq!(opts.last, Some(MAX_HISTORY));
    assert!(parse_err(&["events", "--last", "0"]).contains("at least 1"));
    assert!(parse_err(&["events", "--last", "x"]).contains("invalid --last"));
    assert!(parse_err(&["events", "--no-follow"]).contains("--last"));
    assert!(parse_err(&["events", "--verdict", "maybe"]).contains("invalid --verdict"));
    assert!(parse_err(&["events", "--nope", "1"]).contains("unknown flag"));
}

#[test]
fn top_flags_and_clamps() {
    let cases: [(&[&str], TopOpts); 4] = [
        (
            &[
                "top",
                "--group-by",
                "domain",
                "--interval",
                "5",
                "--top",
                "3",
            ],
            TopOpts {
                group_by: GroupBy::Domain,
                interval_secs: 5,
                top_n: 3,
            },
        ),
        // Interval floor: 0 would be a redraw loop with no sleep.
        (
            &["top", "--interval", "0"],
            TopOpts {
                interval_secs: MIN_INTERVAL_SECS,
                ..TopOpts::default()
            },
        ),
        (
            &["top", "--top", "99999"],
            TopOpts {
                top_n: MAX_TOP_ROWS,
                ..TopOpts::default()
            },
        ),
        (
            &["top", "--top", "0"],
            TopOpts {
                top_n: 1,
                ..TopOpts::default()
            },
        ),
    ];
    for (argv, want) in cases {
        assert_eq!(parse_ok(argv).cmd, Cmd::Top(want), "{argv:?}");
    }
    for group in ["exe", "domain", "host", "port", "rule"] {
        let Cmd::Top(opts) = parse_ok(&["top", "--group-by", group]).cmd else {
            panic!("expected Top");
        };
        assert_eq!(opts.group_by.as_str(), group);
    }
    assert!(parse_err(&["top", "--group-by", "pid"]).contains("invalid --group-by"));
    assert!(parse_err(&["top", "--interval", "soon"]).contains("invalid --interval"));
    assert!(parse_err(&["top", "--top"]).contains("requires a value"));
}

#[test]
fn filter_matching() {
    let ev = |exe: Option<&str>, domain: Option<&str>, verdict| ConnEvent {
        conn: Connection {
            tuple: FlowTuple {
                proto: Proto::Tcp,
                src: "127.0.0.1:1".parse().unwrap(),
                dst: "93.184.216.34:443".parse().unwrap(),
            },
            uid: None,
            pid: None,
            exe_path: exe.map(PathBuf::from),
            cmdline: None,
            parent_exe: None,
            domain: domain.map(String::from),
            iface: None,
            app_id: None,
            first_seen: None,
        },
        verdict,
        rule_name: None,
        unix_ms: 0,
        enforced: true,
    };
    let curl = ev(Some("/usr/bin/curl"), Some("example.org"), Verdict::Allow);
    let nc = ev(Some("/usr/bin/nc"), None, Verdict::Deny);

    // Empty filters keep everything.
    assert!(Filters::default().matches(&curl));

    let exe_only = Filters {
        exe: vec!["curl".into()],
        ..Default::default()
    };
    assert!(exe_only.matches(&curl));
    assert!(!exe_only.matches(&nc));

    // Repeated terms of one kind are OR-ed.
    let either = Filters {
        exe: vec!["curl".into(), "/nc".into()],
        ..Default::default()
    };
    assert!(either.matches(&curl));
    assert!(either.matches(&nc));

    // Kinds are AND-ed, and a missing domain never matches a domain term.
    let both = Filters {
        exe: vec!["curl".into()],
        domain: vec!["example.org".into()],
        ..Default::default()
    };
    assert!(both.matches(&curl));
    assert!(!both.matches(&nc));

    let denied = Filters {
        verdict: vec![Verdict::Deny, Verdict::Reject],
        ..Default::default()
    };
    assert!(!denied.matches(&curl));
    assert!(denied.matches(&nc));

    // An unenforced deny is still a deny for filtering: the operator
    // asking for denies wants to see what observe mode would have blocked.
    let mut would = nc.clone();
    would.enforced = false;
    assert!(denied.matches(&would));

    // An unknown executable is not silently kept by an --exe filter.
    assert!(!exe_only.matches(&ev(None, None, Verdict::Allow)));
}

#[test]
fn socket_override() {
    let cli = parse_ok(&["--socket", "/tmp/x.sock", "status"]);
    assert_eq!(cli.socket, PathBuf::from("/tmp/x.sock"));
    // Also accepted after the command.
    let cli = parse_ok(&["status", "--socket", "/tmp/y.sock"]);
    assert_eq!(cli.socket, PathBuf::from("/tmp/y.sock"));
    assert_eq!(cli.cmd, Cmd::Status);
}

#[test]
fn help_flag() {
    let argv = vec!["--help".to_string()];
    assert_eq!(parse(&argv).unwrap(), Parsed::Help);
}

#[test]
fn rules_rm_and_toggle() {
    assert_eq!(
        parse_ok(&["rules", "rm", "foo"]).cmd,
        Cmd::RulesRm { name: "foo".into() }
    );
    assert_eq!(
        parse_ok(&["rules", "toggle", "foo", "on"]).cmd,
        Cmd::RulesToggle {
            name: "foo".into(),
            enabled: true
        }
    );
    assert_eq!(
        parse_ok(&["rules", "toggle", "foo", "off"]).cmd,
        Cmd::RulesToggle {
            name: "foo".into(),
            enabled: false
        }
    );
    assert!(parse_err(&["rules", "toggle", "foo", "maybe"]).contains("on"));
}

#[test]
fn rules_tag_selectors() {
    assert_eq!(
        parse_ok(&["rules", "--tag", "work"]).cmd,
        Cmd::RulesList {
            stats: false,
            tag: Some("work".into())
        }
    );
    assert_eq!(
        parse_ok(&["rules", "--tag", "work", "--stats"]).cmd,
        Cmd::RulesList {
            stats: true,
            tag: Some("work".into())
        }
    );
    assert_eq!(
        parse_ok(&["rules", "toggle", "--tag", "work", "off"]).cmd,
        Cmd::RulesToggleTag {
            tag: "work".into(),
            enabled: false
        }
    );
    // A selector that could never name a rule is refused here rather
    // than sent and reported as an empty set.
    assert!(parse_err(&["rules", "--tag", "Work"]).contains("bad tag"));
    assert!(parse_err(&["rules", "toggle", "--tag", "Work", "off"]).contains("bad tag"));
    assert!(parse_err(&["rules", "--tag"]).contains("requires a value"));
    // `--tag off` is two arguments, which is the shape of `NAME on|off`:
    // it must not read as toggling a rule literally named `--tag`.
    assert!(parse_err(&["rules", "toggle", "--tag", "off"]).contains("--tag TAG"));
    // Only `--tag` is reserved. `rules add --name --legacy-allow` and a
    // hand-written rules.d file both create names like this, and `rules
    // rm` still takes them, so refusing them here would leave deletion
    // as the only way to stop such a rule enforcing.
    assert_eq!(
        parse_ok(&["rules", "toggle", "--legacy-allow", "off"]).cmd,
        Cmd::RulesToggle {
            name: "--legacy-allow".into(),
            enabled: false
        }
    );
    // A tag cannot begin with a dash, so a flag after `--tag` is refused
    // rather than swallowed as the selector - which would have listed an
    // empty set and exited 0 for `rules --tag --stats`.
    assert!(parse_err(&["rules", "--tag", "--stats"]).contains("bad tag"));
    // And a second `--tag` is an error, not an overwrite: printing only
    // the last one's rules reads as the first set being gone.
    assert!(parse_err(&["rules", "--tag", "work", "--tag", "vpn"]).contains("only be given once"));
}

/// An add replaces any rule of the same name outright, so the flag that
/// keeps a disabled rule disabled has to exist: re-adding is how tags
/// are changed, and without it that silently re-enables the rule.
#[test]
fn rules_add_enabled_flag() {
    let base = [
        "rules", "add", "--name", "r", "--action", "deny", "--port", "443",
    ];
    let rule_of = |extra: &[&str]| {
        let mut argv: Vec<&str> = base.to_vec();
        argv.extend_from_slice(extra);
        match parse_ok(&argv).cmd {
            Cmd::RulesAdd { rule, .. } => rule,
            other => panic!("expected RulesAdd, got {other:?}"),
        }
    };
    assert!(rule_of(&[]).enabled, "an add still defaults to enabled");
    assert!(!rule_of(&["--enabled", "false"]).enabled);
    assert!(rule_of(&["--enabled", "true"]).enabled);

    let mut argv: Vec<&str> = base.to_vec();
    argv.extend_from_slice(&["--enabled", "maybe"]);
    assert!(parse_err(&argv).contains("expected true or false"));
}

#[test]
fn lockdown_parsing() {
    assert_eq!(parse_ok(&["lockdown"]).cmd, Cmd::LockdownShow);
    assert_eq!(
        parse_ok(&["lockdown", "on", "--tag", "core", "--tag", "vpn"]).cmd,
        Cmd::LockdownSet {
            tags: vec!["core".into(), "vpn".into(), "system".into()],
            on: true,
            force: false
        }
    );
    assert_eq!(
        parse_ok(&["lockdown", "on", "--force", "--no-system"]).cmd,
        Cmd::LockdownSet {
            tags: Vec::new(),
            on: true,
            force: true
        }
    );
    // Named explicitly, it is not pinned twice.
    assert_eq!(
        parse_ok(&["lockdown", "on", "--tag", "system"]).cmd,
        Cmd::LockdownSet {
            tags: vec!["system".into()],
            on: true,
            force: false
        }
    );
    assert_eq!(
        parse_ok(&["lockdown", "off"]).cmd,
        Cmd::LockdownSet {
            tags: Vec::new(),
            on: false,
            force: false
        }
    );
    // Lifting takes no options: `lockdown off --tag work` would read as
    // "unpin this one", which is not a thing this has.
    assert!(parse_err(&["lockdown", "off", "--tag", "work"]).contains("no options"));
    assert!(parse_err(&["lockdown", "off", "--no-system"]).contains("no options"));
    assert!(parse_err(&["lockdown", "maybe"]).contains("on"));
    assert!(parse_err(&["lockdown", "on", "--tag", "Core"]).contains("bad tag"));
    assert!(parse_err(&["lockdown", "on", "--tag"]).contains("requires a value"));
}

#[test]
fn rules_add_tags() {
    let cli = parse_ok(&[
        "rules", "add", "--name", "r", "--action", "deny", "--port", "443", "--tag", "work",
        "--tag", "vpn",
    ]);
    let Cmd::RulesAdd { rule, .. } = cli.cmd else {
        panic!("expected RulesAdd");
    };
    assert_eq!(rule.tags, vec!["work".to_string(), "vpn".to_string()]);

    let base = [
        "rules", "add", "--name", "r", "--action", "deny", "--port", "443",
    ];
    let with = |extra: &[&str]| {
        let mut argv: Vec<&str> = base.to_vec();
        argv.extend_from_slice(extra);
        parse_err(&argv)
    };
    assert!(with(&["--tag", "Work"]).contains("bad tag"));
    assert!(with(&["--tag", "work", "--tag", "work"]).contains("duplicate tag"));
    // The count cap is the check this parser used to be missing, so a
    // rule the daemon would refuse was only refused after a round trip.
    let many: Vec<String> = (0..=hallpass_types::MAX_TAGS_PER_RULE)
        .flat_map(|i| ["--tag".to_string(), format!("t{i}")])
        .collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    assert!(with(&many).contains("at most"));
}

#[test]
fn rules_list_stats_export_import() {
    assert_eq!(
        parse_ok(&["rules", "--stats"]).cmd,
        Cmd::RulesList {
            stats: true,
            tag: None
        }
    );
    assert_eq!(parse_ok(&["rules", "export"]).cmd, Cmd::RulesExport);
    assert_eq!(
        parse_ok(&["rules", "import", "/tmp/r.toml"]).cmd,
        Cmd::RulesImport {
            path: PathBuf::from("/tmp/r.toml"),
            replace: false
        }
    );
    assert_eq!(
        parse_ok(&["rules", "import", "--replace", "/tmp/r.toml"]).cmd,
        Cmd::RulesImport {
            path: PathBuf::from("/tmp/r.toml"),
            replace: true
        }
    );
    assert!(parse_err(&["rules", "import"]).contains("rules import [--replace] PATH"));
    assert!(parse_err(&["rules", "import", "a", "b"]).contains("rules import [--replace] PATH"));
    let Cmd::RulesAdd { replace, .. } = parse_ok(&[
        "rules",
        "add",
        "--name",
        "r",
        "--action",
        "deny",
        "--replace",
    ])
    .cmd
    else {
        panic!("not an add");
    };
    assert!(replace);
    assert!(parse_err(&["rules", "export", "now"]).contains("rules export"));
    assert!(parse_err(&["rules", "--stats", "x"]).contains("unknown flag"));
}

#[test]
fn explain_full() {
    let hash = "ab".repeat(32);
    let Cmd::Explain(req) = parse_ok(&[
        "explain",
        "--exe",
        "/usr/bin/curl",
        "--cmdline",
        "curl https://example.org",
        "--parent-exe",
        "/bin/bash",
        "--dest",
        "93.184.216.34",
        "--port",
        "443",
        "--proto",
        "udp",
        "--domain",
        "example.org",
        "--user",
        "1000",
        "--src",
        "10.0.0.5",
        "--src-port",
        "51000",
        "--iface",
        "wg0",
        "--app-id",
        "flatpak:org.mozilla.firefox",
        "--exe-sha256",
        &hash,
    ])
    .cmd
    else {
        panic!("expected Explain");
    };
    let conn = &req.conn;
    assert_eq!(conn.tuple.proto, Proto::Udp);
    assert_eq!(conn.tuple.dst, "93.184.216.34:443".parse().unwrap());
    assert_eq!(conn.tuple.src, "10.0.0.5:51000".parse().unwrap());
    assert_eq!(conn.exe_path, Some(PathBuf::from("/usr/bin/curl")));
    assert_eq!(conn.cmdline.as_deref(), Some("curl https://example.org"));
    assert_eq!(conn.parent_exe, Some(PathBuf::from("/bin/bash")));
    assert_eq!(conn.domain.as_deref(), Some("example.org"));
    assert_eq!(conn.uid, Some(1000));
    assert_eq!(conn.iface.as_deref(), Some("wg0"));
    assert_eq!(conn.app_id.as_deref(), Some("flatpak:org.mozilla.firefox"));
    // A value no connection could carry is named as the error it is,
    // not passed through to an explanation that matches nothing.
    for bad in ["firefox", "snap:Firefox", "docker:nginx"] {
        let err = parse_err(&[
            "explain", "--dest", "1.2.3.4", "--port", "1", "--app-id", bad,
        ]);
        assert!(err.contains("invalid --app-id"), "{bad}: {err}");
    }
    // The hash rides beside the connection: it is what the daemon should
    // use for hash operands, not a property of the flow.
    assert_eq!(req.exe_sha256.as_deref(), Some(hash.as_str()));
    // Nothing here describes a real process, so no pid is invented.
    assert_eq!(conn.pid, None);
}

/// Only the destination is required, and the source defaults to the
/// unspecified address of the destination's own family.
#[test]
fn explain_defaults() {
    let cases = [
        ("93.184.216.34", "0.0.0.0:0"),
        ("2606:4700::1111", "[::]:0"),
    ];
    for (dest, want_src) in cases {
        let Cmd::Explain(req) = parse_ok(&["explain", "--dest", dest, "--port", "53"]).cmd else {
            panic!("expected Explain");
        };
        assert_eq!(req.conn.tuple.src, want_src.parse().unwrap(), "{dest}");
        assert_eq!(req.conn.tuple.proto, Proto::Tcp);
        assert_eq!(req.conn.tuple.dst.port(), 53);
        assert_eq!(req.conn.exe_path, None);
        assert_eq!(req.exe_sha256, None);
    }
}

#[test]
fn explain_bad_values() {
    let cases: [(&[&str], &str); 8] = [
        (&["explain", "--port", "443"], "--dest is required"),
        (&["explain", "--dest", "1.2.3.4"], "--port is required"),
        // A block has no single address to send to; explain describes one
        // connection, not a range.
        (
            &["explain", "--dest", "10.0.0.0/8", "--port", "1"],
            "invalid --dest",
        ),
        (
            &["explain", "--dest", "example.org", "--port", "1"],
            "invalid --dest",
        ),
        (
            &["explain", "--dest", "1.2.3.4", "--port", "99999"],
            "invalid port",
        ),
        (
            &[
                "explain", "--dest", "1.2.3.4", "--port", "1", "--proto", "icmp",
            ],
            "invalid proto",
        ),
        (
            &[
                "explain",
                "--dest",
                "1.2.3.4",
                "--port",
                "1",
                "--exe-sha256",
                "beef",
            ],
            "64 hex digits",
        ),
        (&["explain", "--dest"], "requires a value"),
    ];
    for (argv, want) in cases {
        let err = parse_err(argv);
        assert!(err.contains(want), "{argv:?}: {err}");
    }
    assert!(parse_err(&["explain", "--pid", "1"]).contains("unknown flag"));
}

#[test]
fn rules_add_full() {
    let cli = parse_ok(&[
        "rules",
        "add",
        "--name",
        "curl-https",
        "--action",
        "allow",
        "--exe",
        "/usr/bin/curl",
        "--exe-glob",
        "/usr/bin/*",
        "--dest",
        "10.0.0.0/8",
        "--port",
        "443",
        "--domain",
        "*.example.org",
        "--user",
        "1000",
        "--proto",
        "tcp",
        "--duration",
        "session",
        "--priority",
        "7",
    ]);
    let Cmd::RulesAdd { rule, .. } = cli.cmd else {
        panic!("expected RulesAdd");
    };
    assert_eq!(rule.name, "curl-https");
    assert_eq!(rule.action, Action::Allow);
    assert_eq!(rule.duration, RuleDuration::Session);
    assert_eq!(rule.priority, 7);
    assert!(rule.enabled);
    assert_eq!(rule.matcher.exe, Some(PathBuf::from("/usr/bin/curl")));
    assert_eq!(rule.matcher.exe_glob.as_deref(), Some("/usr/bin/*"));
    assert_eq!(rule.matcher.dest.as_deref(), Some("10.0.0.0/8"));
    assert_eq!(rule.matcher.port, Some(443));
    assert_eq!(rule.matcher.domain.as_deref(), Some("*.example.org"));
    assert_eq!(rule.matcher.user, Some(1000));
    assert_eq!(rule.matcher.proto, Some(Proto::Tcp));
}

#[test]
fn rules_add_timed_duration() {
    let timed = parse_ok(&[
        "rules",
        "add",
        "--name",
        "t",
        "--action",
        "allow",
        "--duration",
        "5m",
    ]);
    let Cmd::RulesAdd { rule, .. } = timed.cmd else {
        panic!("expected RulesAdd")
    };
    let RuleDuration::Until { deadline_ms } = rule.duration else {
        panic!("expected Until, got {:?}", rule.duration)
    };
    let now = hallpass_types::unix_ms_now();
    assert!(deadline_ms > now + 290_000 && deadline_ms <= now + 300_000);
    assert!(parse_err(&[
        "rules",
        "add",
        "--name",
        "t",
        "--action",
        "allow",
        "--duration",
        "5w"
    ])
    .contains("invalid duration"));
}

#[test]
fn rules_add_defaults() {
    let cli = parse_ok(&["rules", "add", "--name", "n", "--action", "deny"]);
    let Cmd::RulesAdd { rule, .. } = cli.cmd else {
        panic!("expected RulesAdd");
    };
    assert_eq!(rule.action, Action::Deny);
    assert_eq!(rule.duration, RuleDuration::Forever);
    assert_eq!(rule.priority, 0);
    assert_eq!(rule.matcher, RuleMatch::default());
}

#[test]
fn rules_add_missing_required() {
    assert!(parse_err(&["rules", "add", "--action", "allow"]).contains("--name"));
    assert!(parse_err(&["rules", "add", "--name", "n"]).contains("--action"));
}

#[test]
fn rules_add_bad_values() {
    assert!(
        parse_err(&["rules", "add", "--name", "n", "--action", "drop"]).contains("invalid action")
    );
    assert!(
        parse_err(&["rules", "add", "--name", "n", "--action", "deny", "--port", "70000"])
            .contains("invalid port")
    );
    assert!(
        parse_err(&["rules", "add", "--name", "n", "--action", "deny", "--proto", "icmp"])
            .contains("invalid proto")
    );
    assert!(parse_err(&[
        "rules",
        "add",
        "--name",
        "n",
        "--action",
        "deny",
        "--duration",
        "once"
    ])
    .contains("invalid duration"));
}

#[test]
fn dest_validation() {
    assert!(validate_net("1.2.3.4").is_ok());
    assert!(validate_net("10.0.0.0/8").is_ok());
    assert!(validate_net("2606:4700::1111").is_ok());
    assert!(validate_net("2606:4700::/32").is_ok());
    assert!(validate_net("example.org").is_err());
    assert!(validate_net("10.0.0.0/33").is_err());
    assert!(validate_net("2606:4700::/129").is_err());
}

#[test]
fn unknown_command() {
    assert!(parse_err(&["frobnicate"]).contains("unknown command"));
    assert!(parse_err(&[]).contains("no command"));
    assert!(parse_err(&["status", "extra"]).contains("unexpected arguments"));
}

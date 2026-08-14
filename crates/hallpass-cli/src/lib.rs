//! Hallpass CLI - client library for the hallpass application firewall.
//!
//! The binary in `main.rs` is a thin wrapper around [`run()`]. Everything is
//! kept in the library so integration tests can drive commands against a
//! mock daemon.

#![deny(unsafe_code)]

pub mod args;
pub mod client;
pub mod doctor;
pub mod fmt;
pub mod json;
pub mod rules_file;
pub mod run;
pub mod suggest;
pub mod top;
pub mod watch;

use std::io::IsTerminal;
use std::path::Path;

use hallpass_types::{
    sanitize_for_display, ClientMsg, ConnEvent, DaemonMsg, ExplainRequest, RuntimeConfig,
};

use crate::args::{Cmd, ConfigSetOpts, EventsOpts};
use crate::client::{CliError, Client};
use crate::fmt::Output;

/// Exit code for success.
pub const EXIT_OK: i32 = 0;
/// Exit code for a daemon-reported error (or usage error).
pub const EXIT_ERR: i32 = 1;
/// Exit code for a connection failure.
pub const EXIT_CONN: i32 = 2;

/// Run the CLI with the given arguments (excluding `argv[0]`).
///
/// Returns the process exit code.
pub async fn run(argv: &[String]) -> i32 {
    let cli = match args::parse(argv) {
        Ok(args::Parsed::Cli(cli)) => cli,
        Ok(args::Parsed::Help) => {
            println!("{}", args::USAGE);
            return EXIT_OK;
        }
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("{}", args::USAGE);
            return EXIT_ERR;
        }
    };

    // Resolved once, here, so no command decides for itself whether to
    // colorize: a stray escape in a piped stream is a bug the operator only
    // notices in the file they saved.
    let out = Output::resolve(
        cli.json,
        cli.color,
        std::io::stdout().is_terminal(),
        std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()),
    );

    // Doctor owns its own connection attempt: a dead daemon is a finding
    // for it to report, not a reason the command cannot run.
    if cli.cmd == Cmd::Doctor {
        return doctor::run(&cli.socket, out).await;
    }

    // Like doctor, `run` owns its exit code rather than reporting success
    // or failure: it exits with the wrapped command's status, and it owns
    // its connection because a daemon it cannot reach means the command is
    // not run at all.
    if let Cmd::Run { argv } = &cli.cmd {
        return run::run(&cli.socket, argv).await;
    }

    let mut client = match Client::connect(&cli.socket).await {
        Ok(c) => c,
        Err(e) => return report(e),
    };

    let result = match cli.cmd {
        Cmd::Doctor => unreachable!("dispatched before connecting"),
        Cmd::Run { .. } => unreachable!("dispatched before connecting"),
        Cmd::Status => status(&mut client, out).await,
        Cmd::Sessions => run::sessions(&mut client, out).await,
        Cmd::LockdownShow => lockdown_show(&mut client, out).await,
        Cmd::LockdownSet { tags, on, force } => {
            lockdown_set(&mut client, tags, on, force, out).await
        }
        Cmd::ConfigShow => config_show(&mut client, out).await,
        Cmd::ConfigSet(opts) => config_set(&mut client, opts, out).await,
        Cmd::RulesList { stats, tag } => rules_list(&mut client, stats, tag, out).await,
        Cmd::RulesAdd(rule) => expect_ok(&mut client, ClientMsg::RuleAdd(rule)).await,
        Cmd::RulesRm { name } => expect_ok(&mut client, ClientMsg::RuleDelete { name }).await,
        Cmd::RulesToggle { name, enabled } => {
            expect_ok(&mut client, ClientMsg::RuleToggle { name, enabled }).await
        }
        Cmd::RulesToggleTag { tag, enabled } => rules_toggle_tag(&mut client, tag, enabled).await,
        Cmd::RulesExport => rules_export(&mut client).await,
        Cmd::RulesImport { path } => rules_import(&mut client, &path).await,
        Cmd::Suggest(opts) => suggest::run(&mut client, opts, out).await,
        Cmd::Events(opts) => events(client, opts, out).await,
        Cmd::Top(opts) => top::top(client, opts, out.json, out.palette).await,
        Cmd::Watch => watch::watch(client).await,
        Cmd::Explain(req) => explain(&mut client, req, out).await,
    };

    match result {
        Ok(()) => EXIT_OK,
        Err(e) => report(e),
    }
}

fn report(e: CliError) -> i32 {
    eprintln!("error: {e}");
    e.exit_code()
}

async fn status(client: &mut Client, out: Output) -> Result<(), CliError> {
    match client.request(ClientMsg::Stats).await? {
        DaemonMsg::Stats(stats) => {
            if out.json {
                println!("{}", json::stats(&stats)?);
            } else {
                print!("{}", fmt::format_stats(&stats, out.palette));
            }
            Ok(())
        }
        other => Err(CliError::unexpected(&other)),
    }
}

async fn config_show(client: &mut Client, out: Output) -> Result<(), CliError> {
    let cfg = match client.request(ClientMsg::ConfigGet).await? {
        DaemonMsg::Config(cfg) => cfg,
        other => return Err(CliError::unexpected(&other)),
    };
    // Always asked for, in both output modes. `ConfigGet` reports what the
    // operator set, not what a lockdown posture is forcing, so that a
    // client's read-modify-write cannot persist the posture's values as the
    // operator's own - which makes this the only thing that says the two
    // fields it owns are not the ones in force. A script reading
    // `enforce: false` on a locked-down host would otherwise record it as
    // not filtering.
    let lockdown = match client.request(ClientMsg::LockdownGet).await? {
        DaemonMsg::LockdownState(state) => state,
        other => return Err(CliError::unexpected(&other)),
    };
    print_config(&cfg, &lockdown, out)?;
    if let (false, Some(l)) = (out.json, &lockdown) {
        println!(
            "note: lockdown is on (pinned {}), so the mode is enforce and \
             the default verdict is deny until it is lifted",
            if l.tags.is_empty() {
                "nothing".to_string()
            } else {
                l.tags.join(",")
            }
        );
    }
    Ok(())
}

/// Change the runtime settings, carrying the unnamed ones forward.
///
/// `ConfigSet` carries the whole struct, so a partial update is a
/// read-modify-write, the same shape the GUI settings tab uses. Two clients
/// changing settings at once can clobber each other; last write wins (the
/// usage text says so), and what is printed afterwards is refetched rather
/// than echoed, so it is what the daemon actually holds.
async fn config_set(client: &mut Client, opts: ConfigSetOpts, out: Output) -> Result<(), CliError> {
    let current = match client.request(ClientMsg::ConfigGet).await? {
        DaemonMsg::Config(cfg) => cfg,
        other => return Err(CliError::unexpected(&other)),
    };
    let new = RuntimeConfig {
        prompt_timeout_secs: opts.timeout_secs.unwrap_or(current.prompt_timeout_secs),
        default_verdict: opts.default_verdict.unwrap_or(current.default_verdict),
        enforce: opts.enforce.unwrap_or(current.enforce),
    };
    match client.request(ClientMsg::ConfigSet(new)).await? {
        DaemonMsg::Ok => {}
        other => return Err(CliError::unexpected(&other)),
    }
    let refetched = match client.request(ClientMsg::ConfigGet).await? {
        DaemonMsg::Config(cfg) => cfg,
        other => return Err(CliError::unexpected(&other)),
    };
    let lockdown = match client.request(ClientMsg::LockdownGet).await? {
        DaemonMsg::LockdownState(state) => state,
        other => return Err(CliError::unexpected(&other)),
    };
    print_config(&refetched, &lockdown, out)
}

fn print_config(
    cfg: &RuntimeConfig,
    lockdown: &Option<hallpass_types::Lockdown>,
    out: Output,
) -> Result<(), CliError> {
    if out.json {
        println!("{}", json::config(cfg, lockdown)?);
    } else {
        print!("{}", fmt::format_config(cfg, out.palette));
    }
    Ok(())
}

async fn rules_list(
    client: &mut Client,
    stats: bool,
    tag: Option<String>,
    out: Output,
) -> Result<(), CliError> {
    let mut rules = match client.request(ClientMsg::RuleList).await? {
        DaemonMsg::Rules(rules) => rules,
        other => return Err(CliError::unexpected(&other)),
    };
    // Filtered here rather than by the daemon: `RuleList` answers with the
    // whole set, and a listing filter is a display concern that no other
    // client has to agree with. The predicate is the daemon's, so a listing
    // and a bulk toggle cannot disagree about what a set contains.
    if let Some(tag) = &tag {
        rules.retain(|r| r.has_tag(tag));
        // Before the counters are fetched: an empty listing has nothing to
        // count, and asking anyway costs a whole round trip thrown away.
        //
        // An error rather than an empty listing, in both output modes, and
        // worded exactly as `rules toggle --tag` words it. A tag no rule
        // carries is nearly always a typo, and the two entrances must not
        // disagree about that: `--json rules --tag wrok` printing `[]` and
        // exiting 0 tells a script "this set is empty, nothing to review"
        // about a set it never actually queried, while the same typo
        // through the toggle fails loudly.
        if rules.is_empty() {
            return Err(CliError::Input(format!("no rule carries tag `{tag}`")));
        }
    }
    // Two requests rather than one: the counters are the daemon's runtime
    // accounting and are deliberately not part of a rule. An error here is
    // not degraded into a plain listing - the counts are what was asked for.
    let hits = if stats {
        match client.request(ClientMsg::RuleStats).await? {
            DaemonMsg::RuleHits(hits) => Some(hits),
            other => return Err(CliError::unexpected(&other)),
        }
    } else {
        None
    };
    // A posture changes what this table means: an enabled allow it
    // suppresses decides nothing, and the column an operator reads to answer
    // "what is in force" would otherwise say `yes` for every one of them.
    // Asked for only on the human path; the JSON carries the tags on each
    // rule, so a consumer can apply the same predicate itself.
    let lockdown = match out.json {
        true => None,
        false => match client.request(ClientMsg::LockdownGet).await? {
            DaemonMsg::LockdownState(state) => state,
            other => return Err(CliError::unexpected(&other)),
        },
    };
    match (&hits, out.json, &lockdown) {
        (Some(hits), true, _) => println!("{}", json::rules_with_hits(&rules, hits)?),
        (Some(hits), false, Some(l)) => print!(
            "{}",
            fmt::format_rules_with_hits_under_lockdown(&rules, hits, &l.tags)
        ),
        (Some(hits), false, None) => print!("{}", fmt::format_rules_with_hits(&rules, hits)),
        (None, true, _) => println!("{}", json::rules(&rules)?),
        (None, false, Some(l)) => {
            print!("{}", fmt::format_rules_under_lockdown(&rules, &l.tags))
        }
        (None, false, None) => print!("{}", fmt::format_rules(&rules)),
    }
    Ok(())
}

/// Report the lockdown posture.
async fn lockdown_show(client: &mut Client, out: Output) -> Result<(), CliError> {
    let state = match client.request(ClientMsg::LockdownGet).await? {
        DaemonMsg::LockdownState(state) => state,
        other => return Err(CliError::unexpected(&other)),
    };
    print_lockdown(client, &state, out).await
}

/// Enter or leave the lockdown posture.
///
/// Entering prints what the posture keeps, because "which rules still decide
/// connections" is the question an operator has immediately after running
/// this and the only way to answer it otherwise is to reason about tags by
/// hand across the whole ruleset.
async fn lockdown_set(
    client: &mut Client,
    tags: Vec<String>,
    on: bool,
    force: bool,
    out: Output,
) -> Result<(), CliError> {
    let state = match client
        .request(ClientMsg::LockdownSet { tags, on, force })
        .await?
    {
        DaemonMsg::LockdownState(state) => state,
        other => return Err(CliError::unexpected(&other)),
    };
    print_lockdown(client, &state, out).await
}

/// Render a posture, and under it the rules that still decide connections.
async fn print_lockdown(
    client: &mut Client,
    state: &Option<hallpass_types::Lockdown>,
    out: Output,
) -> Result<(), CliError> {
    if out.json {
        println!("{}", json::to_json(state)?);
        return Ok(());
    }
    let Some(state) = state else {
        println!("lockdown is off");
        return Ok(());
    };
    println!(
        "lockdown is ON since {} (pinned {}, {} rule(s) suppressed)",
        hallpass_types::format_ts(state.since_ms),
        if state.tags.is_empty() {
            "nothing".to_string()
        } else {
            state.tags.join(",")
        },
        state.rules_suppressed
    );
    // The kept set is computed from the rule list with the daemon's own
    // predicate, so this cannot describe a set other than the one enforcing.
    let rules = match client.request(ClientMsg::RuleList).await? {
        DaemonMsg::Rules(rules) => rules,
        other => return Err(CliError::unexpected(&other)),
    };
    let kept: Vec<&hallpass_types::Rule> = rules
        .iter()
        .filter(|r| r.enabled && r.active_under_lockdown(&state.tags))
        .collect();
    // Split by action rather than listed together: every deny survives every
    // posture, so a combined list reads as though the host can still reach
    // things when the only survivors are blocks.
    let permitting: Vec<&&hallpass_types::Rule> = kept
        .iter()
        .filter(|r| r.action == hallpass_types::Action::Allow)
        .collect();
    match permitting.is_empty() {
        true => println!("nothing still permits connections: only loopback is reachable"),
        false => {
            println!("still permitting:");
            for rule in &permitting {
                println!("  {}", sanitize_for_display(&rule.name));
            }
        }
    }
    let blocking = kept.len() - permitting.len();
    if blocking > 0 {
        println!("{blocking} deny rule(s) still apply: a posture never suppresses one");
    }
    // Said whenever the posture cannot resolve names, because a pinned rule
    // written against a domain silently stops matching when it cannot: the
    // daemon annotates a connection with a domain only when it saw the
    // lookup, and under lockdown the lookup itself is what gets denied.
    // Allows only. A deny rule on port 53 survives the posture like every
    // other deny, and counting it as "something covers DNS" would silence
    // this warning on exactly the hosts that block plaintext DNS.
    let resolves = kept
        .iter()
        .filter(|r| r.action == hallpass_types::Action::Allow)
        .any(|r| {
            r.matcher.port == Some(53)
                || r.matcher
                    .port_range
                    .is_some_and(|(lo, hi)| lo <= 53 && 53 <= hi)
        });
    if !resolves {
        let pinned_domains = rules.iter().any(|r| {
            r.enabled && r.active_under_lockdown(&state.tags) && r.matcher.domain.is_some()
        });
        println!(
            "warning: nothing pinned covers DNS, so this host cannot resolve names{}",
            if pinned_domains {
                " - and the rules pinned by domain will stop matching, since a \
                 connection only carries a domain when the daemon saw its lookup"
            } else {
                ""
            }
        );
    }
    Ok(())
}

/// Enable or disable every rule carrying a tag.
///
/// Exits non-zero when any rule's new state could not be written: the change
/// the operator asked for is not the change the daemon made, and a bulk
/// operation that reports success while part of it did not happen is how a
/// disabled-everything posture ends up with a rule still enforcing.
async fn rules_toggle_tag(client: &mut Client, tag: String, enabled: bool) -> Result<(), CliError> {
    let (changed, failed) = match client
        .request(ClientMsg::RuleToggleTag {
            tag: tag.clone(),
            enabled,
        })
        .await?
    {
        DaemonMsg::RulesToggled { changed, failed } => (changed, failed),
        other => return Err(CliError::unexpected(&other)),
    };
    let state = if enabled { "enabled" } else { "disabled" };
    if changed == 0 && failed.is_empty() {
        println!("no change: every rule tagged `{tag}` was already {state}");
    } else {
        let noun = if changed == 1 { "rule" } else { "rules" };
        println!("{changed} {noun} tagged `{tag}` {state}");
    }
    if failed.is_empty() {
        return Ok(());
    }
    Err(CliError::Daemon(format!(
        "{} could not be written and kept their previous state: {}",
        failed.len(),
        failed.join(", ")
    )))
}

/// Write the whole ruleset to stdout as one TOML document.
///
/// Always TOML, never JSON: this output exists to be saved, diffed and fed
/// back to `rules import`, and `--json` already covers the "pipe it into a
/// program" case through `rules --json`.
async fn rules_export(client: &mut Client) -> Result<(), CliError> {
    match client.request(ClientMsg::RuleList).await? {
        DaemonMsg::Rules(rules) => {
            print!("{}", rules_file::export(&rules)?);
            Ok(())
        }
        other => Err(CliError::unexpected(&other)),
    }
}

/// Add every rule in `path`, one request each.
///
/// A rejected rule does not stop the import. Half a ruleset plus a list of
/// exactly which entries the daemon refused is something an operator can act
/// on; aborting on the first failure leaves them re-running the whole file to
/// discover the next problem. Only a broken connection stops it, because
/// after that there is nobody left to ask.
async fn rules_import(client: &mut Client, path: &Path) -> Result<(), CliError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| CliError::Input(format!("cannot read {}: {e}", path.display())))?;
    let rules = rules_file::import(&text)
        .map_err(|e| CliError::Input(format!("cannot parse {}: {e}", path.display())))?;

    let total = rules.len();
    let mut failed = 0usize;
    for rule in rules {
        // The document was not necessarily written on this machine, and this
        // name is about to be printed either way.
        let name = sanitize_for_display(&rule.name).into_owned();
        match client.request(ClientMsg::RuleAdd(rule)).await {
            Ok(DaemonMsg::Ok) => println!("added {name}"),
            Ok(other) => return Err(CliError::unexpected(&other)),
            Err(e @ CliError::Daemon(_)) => {
                failed += 1;
                eprintln!("error: rule '{name}': {e}");
            }
            Err(e) => return Err(e),
        }
    }
    println!("imported {} of {total} rules", total - failed);
    if failed > 0 {
        return Err(CliError::Input(format!("{failed} of {total} rules failed")));
    }
    Ok(())
}

/// Ask what policy would do with a hypothetical connection.
async fn explain(client: &mut Client, req: ExplainRequest, out: Output) -> Result<(), CliError> {
    match client.request(ClientMsg::Explain(req)).await? {
        DaemonMsg::Explanation(exp) => {
            if out.json {
                println!("{}", json::explanation(&exp)?);
            } else {
                print!("{}", fmt::format_explanation(&exp, out.palette));
            }
            Ok(())
        }
        other => Err(CliError::unexpected(&other)),
    }
}

async fn expect_ok(client: &mut Client, msg: ClientMsg) -> Result<(), CliError> {
    match client.request(msg).await? {
        DaemonMsg::Ok => {
            println!("ok");
            Ok(())
        }
        other => Err(CliError::unexpected(&other)),
    }
}

/// Replay past connections, then stream new ones until Ctrl-C.
async fn events(mut client: Client, opts: EventsOpts, out: Output) -> Result<(), CliError> {
    if let Some(last) = opts.last {
        // An older daemon has no history to give. That costs the replay, not
        // the command, so say so and carry on with the live stream.
        match client
            .request(ClientMsg::EventHistory { limit: last })
            .await
        {
            Ok(DaemonMsg::Events(events)) => {
                for ev in events.iter().filter(|ev| opts.filters.matches(ev)) {
                    print_event(ev, out)?;
                }
            }
            Ok(other) => return Err(CliError::unexpected(&other)),
            Err(CliError::Daemon(msg)) => {
                eprintln!("note: no event history from the daemon ({msg})");
            }
            Err(e) => return Err(e),
        }
        if !opts.follow {
            return Ok(());
        }
    }

    client
        .send(ClientMsg::Subscribe {
            events: true,
            prompts: false,
        })
        .await?;
    // recv (read_msg) is not cancel-safe, but here the only competing branch
    // is ctrl_c, which exits the process - a dropped mid-frame read is fine.
    loop {
        tokio::select! {
            msg = client.recv() => match msg? {
                DaemonMsg::Event(ev) => {
                    if opts.filters.matches(&ev) {
                        print_event(&ev, out)?;
                    }
                }
                DaemonMsg::Err { message } => return Err(CliError::Daemon(message)),
                // Ignore anything else (e.g. an Ok acknowledging Subscribe).
                _ => {}
            },
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
    }
}

fn print_event(ev: &ConnEvent, out: Output) -> Result<(), CliError> {
    if out.json {
        println!("{}", json::event(ev)?);
    } else {
        println!("{}", fmt::format_event(ev, out.palette));
    }
    Ok(())
}

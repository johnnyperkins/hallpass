//! Hallpass CLI - client library for the hallpass application firewall.
//!
//! The binary in `main.rs` is a thin wrapper around [`run`]. Everything is
//! kept in the library so integration tests can drive commands against a
//! mock daemon.

#![deny(unsafe_code)]

pub mod args;
pub mod client;
pub mod fmt;
pub mod json;
pub mod rules_file;
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

    let mut client = match Client::connect(&cli.socket).await {
        Ok(c) => c,
        Err(e) => return report(e),
    };

    let result = match cli.cmd {
        Cmd::Status => status(&mut client, out).await,
        Cmd::ConfigShow => config_show(&mut client, out).await,
        Cmd::ConfigSet(opts) => config_set(&mut client, opts, out).await,
        Cmd::RulesList { stats } => rules_list(&mut client, stats, out).await,
        Cmd::RulesAdd(rule) => expect_ok(&mut client, ClientMsg::RuleAdd(rule)).await,
        Cmd::RulesRm { name } => expect_ok(&mut client, ClientMsg::RuleDelete { name }).await,
        Cmd::RulesToggle { name, enabled } => {
            expect_ok(&mut client, ClientMsg::RuleToggle { name, enabled }).await
        }
        Cmd::RulesExport => rules_export(&mut client).await,
        Cmd::RulesImport { path } => rules_import(&mut client, &path).await,
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
    match client.request(ClientMsg::ConfigGet).await? {
        DaemonMsg::Config(cfg) => print_config(&cfg, out),
        other => Err(CliError::unexpected(&other)),
    }
}

/// Change the runtime settings, carrying the unnamed ones forward.
///
/// `ConfigSet` carries the whole struct, so a partial update is a
/// read-modify-write, the same shape the GUI settings tab uses. Two clients
/// changing settings at once can clobber each other; last write wins (the
/// usage text says so), and what is printed afterwards is refetched rather
/// than echoed, so it is what the daemon actually holds.
async fn config_set(
    client: &mut Client,
    opts: ConfigSetOpts,
    out: Output,
) -> Result<(), CliError> {
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
    match client.request(ClientMsg::ConfigGet).await? {
        DaemonMsg::Config(cfg) => print_config(&cfg, out),
        other => Err(CliError::unexpected(&other)),
    }
}

fn print_config(cfg: &RuntimeConfig, out: Output) -> Result<(), CliError> {
    if out.json {
        println!("{}", json::config(cfg)?);
    } else {
        print!("{}", fmt::format_config(cfg, out.palette));
    }
    Ok(())
}

async fn rules_list(client: &mut Client, stats: bool, out: Output) -> Result<(), CliError> {
    let rules = match client.request(ClientMsg::RuleList).await? {
        DaemonMsg::Rules(rules) => rules,
        other => return Err(CliError::unexpected(&other)),
    };
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
    match (&hits, out.json) {
        (Some(hits), true) => println!("{}", json::rules_with_hits(&rules, hits)?),
        (Some(hits), false) => print!("{}", fmt::format_rules_with_hits(&rules, hits)),
        (None, true) => println!("{}", json::rules(&rules)?),
        (None, false) => print!("{}", fmt::format_rules(&rules)),
    }
    Ok(())
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
async fn explain(
    client: &mut Client,
    req: ExplainRequest,
    out: Output,
) -> Result<(), CliError> {
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
        match client.request(ClientMsg::EventHistory { limit: last }).await {
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

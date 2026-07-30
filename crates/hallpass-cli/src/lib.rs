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
pub mod top;
pub mod watch;

use std::io::IsTerminal;

use hallpass_types::{ClientMsg, ConnEvent, DaemonMsg};

use crate::args::{Cmd, EventsOpts};
use crate::client::{CliError, Client};
use crate::fmt::Output;

/// Exit code for success.
pub const EXIT_OK: i32 = 0;
/// Exit code for a daemon-reported error (or usage error).
pub const EXIT_ERR: i32 = 1;
/// Exit code for a connection failure.
pub const EXIT_CONN: i32 = 2;

/// Run the CLI with the given arguments (excluding argv[0]).
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
        Cmd::RulesList => rules_list(&mut client, out).await,
        Cmd::RulesAdd(rule) => expect_ok(&mut client, ClientMsg::RuleAdd(rule)).await,
        Cmd::RulesRm { name } => expect_ok(&mut client, ClientMsg::RuleDelete { name }).await,
        Cmd::RulesToggle { name, enabled } => {
            expect_ok(&mut client, ClientMsg::RuleToggle { name, enabled }).await
        }
        Cmd::Events(opts) => events(client, opts, out).await,
        Cmd::Top(opts) => top::top(client, opts, out.json, out.palette).await,
        Cmd::Watch => watch::watch(client).await,
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

async fn rules_list(client: &mut Client, out: Output) -> Result<(), CliError> {
    match client.request(ClientMsg::RuleList).await? {
        DaemonMsg::Rules(rules) => {
            if out.json {
                println!("{}", json::rules(&rules)?);
            } else {
                print!("{}", fmt::format_rules(&rules));
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

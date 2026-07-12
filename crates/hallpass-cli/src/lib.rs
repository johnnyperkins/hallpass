//! Hallpass CLI - client library for the hallpass application firewall.
//!
//! The binary in `main.rs` is a thin wrapper around [`run`]. Everything is
//! kept in the library so integration tests can drive commands against a
//! mock daemon.

#![deny(unsafe_code)]

pub mod args;
pub mod client;
pub mod fmt;
pub mod watch;

use hallpass_types::{ClientMsg, DaemonMsg};

use crate::args::Cmd;
use crate::client::{CliError, Client};

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

    let mut client = match Client::connect(&cli.socket).await {
        Ok(c) => c,
        Err(e) => return report(e),
    };

    let result = match cli.cmd {
        Cmd::Status => status(&mut client).await,
        Cmd::RulesList => rules_list(&mut client).await,
        Cmd::RulesAdd(rule) => expect_ok(&mut client, ClientMsg::RuleAdd(rule)).await,
        Cmd::RulesRm { name } => expect_ok(&mut client, ClientMsg::RuleDelete { name }).await,
        Cmd::RulesToggle { name, enabled } => {
            expect_ok(&mut client, ClientMsg::RuleToggle { name, enabled }).await
        }
        Cmd::Events => events(client).await,
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

async fn status(client: &mut Client) -> Result<(), CliError> {
    match client.request(ClientMsg::Stats).await? {
        DaemonMsg::Stats(stats) => {
            print!("{}", fmt::format_stats(&stats));
            Ok(())
        }
        other => Err(CliError::unexpected(&other)),
    }
}

async fn rules_list(client: &mut Client) -> Result<(), CliError> {
    match client.request(ClientMsg::RuleList).await? {
        DaemonMsg::Rules(rules) => {
            print!("{}", fmt::format_rules(&rules));
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

/// Stream connection events until Ctrl-C.
async fn events(mut client: Client) -> Result<(), CliError> {
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
                DaemonMsg::Event(ev) => println!("{}", fmt::format_event(&ev)),
                DaemonMsg::Err { message } => return Err(CliError::Daemon(message)),
                // Ignore anything else (e.g. an Ok acknowledging Subscribe).
                _ => {}
            },
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
    }
}

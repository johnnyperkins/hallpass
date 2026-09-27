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
    sanitize_for_display, Action, ClientMsg, ConnEvent, DaemonMsg, ExplainRequest, Lockdown, Rule,
    RuntimeConfig,
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
        // The protocol too: it is what has to match between this binary and
        // the daemon, and the version alone does not say which one it is.
        Ok(args::Parsed::Version) => {
            println!(
                "hallpass-cli {} (protocol v{})",
                env!("CARGO_PKG_VERSION"),
                hallpass_types::PROTOCOL_VERSION
            );
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
        Err(e) => return report(&e),
    };

    let result = match cli.cmd {
        Cmd::Doctor | Cmd::Run { .. } => unreachable!("dispatched before connecting"),
        Cmd::Status => status(&mut client, out).await,
        Cmd::Sessions => run::sessions(&mut client, out).await,
        Cmd::LockdownShow => lockdown_show(&mut client, out).await,
        Cmd::LockdownSet { tags, on, force } => {
            lockdown_set(&mut client, tags, on, force, out).await
        }
        Cmd::ConfigShow => config_show(&mut client, out).await,
        Cmd::ConfigSet(opts) => config_set(&mut client, opts, out).await,
        Cmd::RulesList { stats, tag } => rules_list(&mut client, stats, tag, out).await,
        Cmd::RulesAdd { rule, replace } => rules_add(&mut client, rule, replace).await,
        Cmd::RulesRm { name } => print_ok(&mut client, ClientMsg::RuleDelete { name }).await,
        Cmd::RulesToggle { name, enabled } => {
            print_ok(&mut client, ClientMsg::RuleToggle { name, enabled }).await
        }
        Cmd::RulesToggleTag { tag, enabled } => rules_toggle_tag(&mut client, tag, enabled).await,
        Cmd::RulesExport => rules_export(&mut client).await,
        Cmd::RulesImport { path, replace } => rules_import(&mut client, &path, replace).await,
        Cmd::Suggest(opts) => suggest::run(&mut client, opts, out).await,
        Cmd::Events(opts) => events(client, opts, out).await,
        Cmd::Top(opts) => top::top(client, opts, out).await,
        Cmd::Watch => watch::watch(client).await,
        Cmd::Explain(req) => explain(&mut client, req, out).await,
    };

    match result {
        Ok(()) => EXIT_OK,
        Err(e) => report(&e),
    }
}

fn report(e: &CliError) -> i32 {
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
    let cfg = client.config().await?;
    // Always asked for, in both output modes. `ConfigGet` reports what the
    // operator set, not what a lockdown posture is forcing, so that a
    // client's read-modify-write cannot persist the posture's values as the
    // operator's own. That makes this the only thing saying the two fields
    // the posture owns are not the ones in force: a script reading
    // `enforce: false` on a locked-down host would otherwise record it as
    // not filtering.
    let lockdown = client.lockdown().await?;
    print_config(&cfg, lockdown.as_ref(), out)?;
    if let (false, Some(l)) = (out.json, &lockdown) {
        println!(
            "note: lockdown is on (pinned {}), so the mode is enforce and \
             the default verdict is deny until it is lifted",
            fmt::pinned_tags(&l.tags)
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
    let current = client.config().await?;
    let new = RuntimeConfig {
        prompt_timeout_secs: opts.timeout_secs.unwrap_or(current.prompt_timeout_secs),
        default_verdict: opts.default_verdict.unwrap_or(current.default_verdict),
        enforce: opts.enforce.unwrap_or(current.enforce),
    };
    client.request_ok(ClientMsg::ConfigSet(new)).await?;
    let refetched = client.config().await?;
    let lockdown = client.lockdown().await?;
    print_config(&refetched, lockdown.as_ref(), out)
}

fn print_config(
    cfg: &RuntimeConfig,
    lockdown: Option<&Lockdown>,
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
    let mut rules = client.rules().await?;
    // Filtered here rather than by the daemon: `RuleList` answers with the
    // whole set, and a listing filter is a display concern no other client
    // has to agree with. The predicate is the daemon's, so a listing and a
    // bulk toggle cannot disagree about what a set contains.
    if let Some(tag) = &tag {
        rules.retain(|r| r.has_tag(tag));
        // Checked before the counters are fetched, which would be a round
        // trip thrown away. An error rather than an empty listing, in both
        // output modes, and worded exactly as `rules toggle --tag` words it:
        // a tag no rule carries is nearly always a typo, and `--json rules
        // --tag wrok` printing `[]` and exiting 0 would tell a script "this
        // set is empty" about a set it never queried, while the same typo
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
    if out.json {
        match &hits {
            Some(hits) => println!("{}", json::rules_with_hits(&rules, hits)?),
            None => println!("{}", json::rules(&rules)?),
        }
        return Ok(());
    }
    // A posture changes what this table means: an enabled allow it
    // suppresses decides nothing, and the column an operator reads to answer
    // "what is in force" would otherwise say `yes` for every one of them.
    // Asked for only on the human path; the JSON carries the tags on each
    // rule, so a consumer can apply the same predicate itself.
    let lockdown = client.lockdown().await?;
    print!(
        "{}",
        fmt::format_rules(
            &rules,
            hits.as_deref(),
            lockdown.as_ref().map(|l| l.tags.as_slice())
        )
    );
    Ok(())
}

/// Report the lockdown posture.
async fn lockdown_show(client: &mut Client, out: Output) -> Result<(), CliError> {
    let state = client.lockdown().await?;
    print_lockdown(client, state.as_ref(), out).await
}

/// Enter or leave the lockdown posture.
///
/// Entering prints what the posture keeps, because "which rules still decide
/// connections" is the question an operator has immediately after running
/// this, and otherwise the only way to answer it is to reason about tags by
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
    print_lockdown(client, state.as_ref(), out).await
}

/// Render a posture, and under it the rules that still decide connections.
async fn print_lockdown(
    client: &mut Client,
    state: Option<&Lockdown>,
    out: Output,
) -> Result<(), CliError> {
    if out.json {
        println!("{}", json::lockdown(state)?);
        return Ok(());
    }
    let Some(state) = state else {
        println!("lockdown is off");
        return Ok(());
    };
    println!("lockdown is {}", fmt::lockdown_summary(state));
    // The kept set is computed from the rule list with the daemon's own
    // predicate, so this cannot describe a set other than the one enforcing.
    let rules = client.rules().await?;
    let kept: Vec<&Rule> = rules
        .iter()
        .filter(|r| r.enabled && r.active_under_lockdown(&state.tags))
        .collect();
    // Split by action rather than listed together: every deny survives every
    // posture, so a combined list reads as though the host can still reach
    // things when the only survivors are blocks.
    let permitting: Vec<&Rule> = kept
        .iter()
        .copied()
        .filter(|r| r.action == Action::Allow)
        .collect();
    if permitting.is_empty() {
        println!("nothing still permits connections: only loopback is reachable");
    } else {
        println!("still permitting:");
        for rule in &permitting {
            println!("  {}", sanitize_for_display(&rule.name));
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
    // Allows only: a deny on port 53 survives the posture like every other
    // deny, and counting it as "something covers DNS" would silence this
    // warning on exactly the hosts that block plaintext DNS.
    if !permitting.iter().any(|r| covers_dns(r)) {
        let pinned_domains = kept.iter().any(|r| r.matcher.domain.is_some());
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

/// Whether `rule` matches destination port 53, alone or within a range.
fn covers_dns(rule: &Rule) -> bool {
    let m = &rule.matcher;
    m.port == Some(53) || m.port_range.is_some_and(|(lo, hi)| lo <= 53 && 53 <= hi)
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
    let rules = client.rules().await?;
    print!("{}", rules_file::export(&rules)?);
    Ok(())
}

/// Add every rule in `path`, one request each.
///
/// A rejected rule does not stop the import. Half a ruleset plus a list of
/// exactly which entries the daemon refused is something an operator can act
/// on; aborting on the first failure leaves them re-running the whole file to
/// discover the next problem. Only a broken connection stops it, because
/// after that there is nobody left to ask.
/// The names of the rules the daemon holds, for refusing an add that would
/// silently overwrite one.
async fn rule_names(client: &mut Client) -> Result<std::collections::HashSet<String>, CliError> {
    Ok(client.rules().await?.into_iter().map(|r| r.name).collect())
}

/// Why an add that would overwrite a rule is refused.
fn name_in_use(name: &str) -> String {
    format!(
        "a rule named '{}' exists; pass --replace to overwrite it (every field, \
         including enabled and tags, is replaced)",
        sanitize_for_display(name)
    )
}

/// `rules add`. The daemon replaces a rule of the same name outright, which
/// silently re-enables a disabled rule and drops its tags, so an add of a
/// name in use is refused unless `--replace` asked for exactly that. Checked
/// here rather than by the daemon, so it is a guard against a slip, not a
/// lock: two clients can still race.
async fn rules_add(client: &mut Client, rule: Rule, replace: bool) -> Result<(), CliError> {
    if !replace && rule_names(client).await?.contains(&rule.name) {
        return Err(CliError::Input(name_in_use(&rule.name)));
    }
    print_ok(client, ClientMsg::RuleAdd(rule)).await
}

async fn rules_import(client: &mut Client, path: &Path, replace: bool) -> Result<(), CliError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| CliError::Input(format!("cannot read {}: {e}", path.display())))?;
    let rules = rules_file::import(&text)
        .map_err(|e| CliError::Input(format!("cannot parse {}: {e}", path.display())))?;
    let existing = if replace {
        Default::default()
    } else {
        rule_names(client).await?
    };

    let total = rules.len();
    let mut failed = 0usize;
    for rule in rules {
        // The document was not necessarily written on this machine, and this
        // name is about to be printed either way.
        let name = sanitize_for_display(&rule.name).into_owned();
        if existing.contains(&rule.name) {
            failed += 1;
            eprintln!("error: rule '{name}': {}", name_in_use(&rule.name));
            continue;
        }
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

/// Send a request answered by a bare `Ok`, and say so.
async fn print_ok(client: &mut Client, msg: ClientMsg) -> Result<(), CliError> {
    client.request_ok(msg).await?;
    println!("ok");
    Ok(())
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

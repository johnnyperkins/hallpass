//! Workspace build tasks (cargo xtask).
//!
//! One entry point for every dev loop, so the commands a contributor runs
//! locally are the same ones CI enforces instead of a hand-copied
//! approximation of them. See CONTRIBUTING.md for what each task covers.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let task = std::env::args().nth(1);
    let result = match task.as_deref() {
        Some("check") => check(),
        Some("fmt") => fmt_check(),
        Some("test") => test_workspace(),
        Some("lint") => lint(),
        Some("doc") => doc(),
        Some("ci") => ci(),
        Some("build-ebpf") => build_ebpf(),
        Some("clippy-ebpf") => clippy_ebpf(),
        Some("build") => build_ebpf().and_then(|()| build_workspace()),
        Some("e2e") => test_e2e(std::env::args().any(|a| a == "--ebpf")),
        Some("dev") => dev(),
        Some("fuzz") => fuzz(&std::env::args().skip(2).collect::<Vec<_>>()),
        Some(other) => {
            eprintln!("unknown task: {other}");
            print_usage();
            return ExitCode::FAILURE;
        }
        None => {
            print_usage();
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

const USAGE: &str = "\
usage: cargo xtask <task>

verification (cheapest first):
  fmt           cargo fmt --check over the workspace and hallpass-ebpf
  check         cargo check over the workspace and the ebpf feature
  test          run the workspace unit/integration tests (no privileges)
  lint          clippy in both feature configurations, plus clippy-ebpf;
                the same lints CI fails on
  doc           cargo doc --no-deps with -D warnings (broken links fail)
  ci            everything CI runs that does not need root, failing at
                the first stage that breaks; cargo-deny if it is installed
  e2e [--ebpf]  run the hallpassd e2e tests (compiles as you, runs the
                test binary under sudo -E; will prompt for your password).
                --ebpf builds the object first and enables the feature, so
                the tests that skip without it actually run

builds:
  build-ebpf    build the hallpass-ebpf kernel programs
  clippy-ebpf   lint the hallpass-ebpf kernel programs (-D warnings)
  build         build-ebpf, then a release build of the whole workspace
                (with the ebpf feature); what install.sh runs

running:
  dev           run hallpassd unprivileged against a scratch config, for
                CLI/UI work; interception is off, IPC and rules work
  fuzz [TARGET] [SECS]
                fuzz one target, or every target in turn, for SECS each
                (default 60); needs cargo-fuzz. Crashes land in
                fuzz/artifacts/<target>/
";

fn print_usage() {
    eprint!("{USAGE}");
}

/// `cargo <args>` in the workspace root, run by the cargo that invoked
/// xtask. Cargo sets $CARGO to its own absolute path; fall back to plain
/// "cargo" if it is somehow unset.
fn cargo(args: &[&str]) -> Command {
    let bin = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut cmd = Command::new(bin);
    cmd.args(args).current_dir(workspace_root());
    cmd
}

/// `cargo <args>` in fuzz/, which is its own workspace on its own nightly
/// pin; the environment is cleared for the same reason as [`ebpf_cargo`].
fn fuzz_cargo(args: &[&str]) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.args(args)
        .current_dir(workspace_root().join("fuzz"))
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO");
    cmd
}

/// `cargo <args>` in crates/hallpass-ebpf, which is not a workspace member.
///
/// Target, build-std and the shared target dir come from the crate's own
/// .cargo/config.toml, nightly and rust-src from its rust-toolchain.toml.
/// cargo xtask runs under the workspace toolchain, so that is dropped from
/// the environment for the crate's own pin to take effect.
fn ebpf_cargo(args: &[&str]) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.args(args)
        .current_dir(workspace_root().join("crates/hallpass-ebpf"))
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO");
    cmd
}

fn workspace_root() -> PathBuf {
    // xtask lives at <root>/xtask; CARGO_MANIFEST_DIR is set at compile
    // time, which is fine because xtask is always built in-tree.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent dir")
        .to_path_buf()
}

/// Build crates/hallpass-ebpf for bpfel-unknown-none.
fn build_ebpf() -> Result<(), String> {
    if !have_binary("bpf-linker") {
        return Err(
            "bpf-linker not found in PATH; install it with: cargo install bpf-linker".to_string(),
        );
    }
    run(ebpf_cargo(&["build", "--release"]))
}

/// Lint crates/hallpass-ebpf, which no workspace command reaches.
///
/// It is deliberately not a workspace member, so `cargo clippy --workspace`
/// cannot see it, and `build-ebpf` only compiles it. That left the one crate
/// in the project containing `unsafe` (and running in the kernel) as the only
/// crate never linted.
fn clippy_ebpf() -> Result<(), String> {
    run(ebpf_cargo(&["clippy", "--release", "--", "-D", "warnings"]))
}

fn build_workspace() -> Result<(), String> {
    run(cargo(&[
        "build",
        "--release",
        "--workspace",
        "--features",
        "hallpassd/ebpf",
    ]))
}

/// Type-check everything without codegen: the fastest way to learn that a
/// change does not compile, including in the `ebpf` configuration, which the
/// plain workspace commands never enable.
fn check() -> Result<(), String> {
    run(cargo(&["check", "--workspace", "--all-targets"]))?;
    run(cargo(&[
        "check",
        "-p",
        "hallpassd",
        "--features",
        "ebpf,dev-fixtures",
    ]))
}

fn test_workspace() -> Result<(), String> {
    run(cargo(&["test", "--workspace"]))
}

/// The eBPF attribution unit tests are gated on the feature, so the plain
/// workspace test run never reaches them.
fn test_ebpf_feature() -> Result<(), String> {
    run(cargo(&["test", "-p", "hallpassd", "--features", "ebpf"]))
}

/// Every lint gate CI has, in one command.
///
/// Three invocations are needed rather than one: the workspace run cannot see
/// code behind a feature, and neither run can see crates/hallpass-ebpf at all
/// because it is not a workspace member. `dev-fixtures` rides along with
/// `ebpf` for the same reason `clippy-ebpf` exists: code nothing lints is
/// code that rots, and this is the feature that fabricates events.
fn lint() -> Result<(), String> {
    run(cargo(&[
        "clippy",
        "--workspace",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ]))?;
    run(cargo(&[
        "clippy",
        "-p",
        "hallpassd",
        "--all-targets",
        "--features",
        "ebpf,dev-fixtures",
        "--",
        "-D",
        "warnings",
    ]))?;
    clippy_ebpf()
}

/// Check formatting, workspace and eBPF crate alike.
///
/// Gated in CI rather than left to habit: a tree nothing checks drifts from
/// rustfmt's output until running the formatter once rewrites dozens of
/// files, which makes it a trap for the next person who runs it.
///
/// `hallpass-ebpf` is not a workspace member, so `--all` does not reach it -
/// the same gap [`clippy_ebpf`] exists to close.
fn fmt_check() -> Result<(), String> {
    run(cargo(&["fmt", "--all", "--check"]))?;
    run(ebpf_cargo(&["fmt", "--check"]))?;
    run(fuzz_cargo(&["fmt", "--check"]))
}

/// Run the fuzz targets in fuzz/: `[TARGET] [SECS]`.
///
/// Each run reads and grows `fuzz/corpus/<target>` (ignored by git) and also
/// reads the checked-in seeds in `fuzz/seeds/<target>`. A crash stops the run
/// and leaves its input in `fuzz/artifacts/<target>/`; replay it with
/// `cargo fuzz run -O <target> <file>` inside fuzz/.
fn fuzz(args: &[String]) -> Result<(), String> {
    if !Command::new("cargo")
        .args(["fuzz", "--version"])
        .output()
        .is_ok_and(|o| o.status.success())
    {
        return Err("cargo-fuzz not found; install it with: cargo install cargo-fuzz".into());
    }
    let (targets, secs) = match args {
        [] => (fuzz_targets()?, "60".to_string()),
        [t] if t.parse::<u64>().is_ok() => (fuzz_targets()?, t.clone()),
        [t] => (vec![t.clone()], "60".to_string()),
        [t, n] if n.parse::<u64>().is_ok() => (vec![t.clone()], n.clone()),
        _ => return Err("usage: cargo xtask fuzz [TARGET] [SECS]".into()),
    };
    let root = workspace_root().join("fuzz");
    for t in &targets {
        for dir in ["corpus", "seeds"] {
            std::fs::create_dir_all(root.join(dir).join(t))
                .map_err(|e| format!("create fuzz/{dir}/{t}: {e}"))?;
        }
        eprintln!("--- fuzz {t} for {secs}s");
        let (corpus, seeds) = (format!("corpus/{t}"), format!("seeds/{t}"));
        let max_time = format!("-max_total_time={secs}");
        run(fuzz_cargo(&[
            "fuzz",
            "run",
            "-O",
            t,
            &corpus,
            &seeds,
            "--",
            &max_time,
            "-timeout=5",
            "-rss_limit_mb=2048",
        ]))?;
    }
    Ok(())
}

/// The fuzz targets, as cargo-fuzz lists them.
fn fuzz_targets() -> Result<Vec<String>, String> {
    let out = fuzz_cargo(&["fuzz", "list"])
        .output()
        .map_err(|e| format!("cargo fuzz list: {e}"))?;
    if !out.status.success() {
        return Err("cargo fuzz list failed".into());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect())
}

/// Build the rustdoc, treating warnings as errors.
///
/// The project documents public items heavily and leans on intra-doc links to
/// keep the prose pointing at the right code. Without `-D warnings` a link that
/// stops resolving is a silent downgrade to plain text, so the convention rots
/// without anything failing.
fn doc() -> Result<(), String> {
    let mut cmd = cargo(&["doc", "--workspace", "--no-deps"]);
    cmd.env("RUSTDOCFLAGS", "-D warnings");
    run(cmd)
}

fn deny() -> Result<(), String> {
    run(cargo(&["deny", "check"]))
}

/// True if `name` can be spawned, i.e. it is on PATH and executable.
fn have_binary(name: &str) -> bool {
    Command::new(name).arg("--version").output().is_ok()
}

/// One stage of [`ci`]: a name for the failure message, and the task to run.
type Stage = (&'static str, fn() -> Result<(), String>);

/// Everything CI runs that does not need root, cheapest failure first.
///
/// The point is that a contributor can learn CI's answer before pushing.
/// Stages that need privileges (the e2e suite) are deliberately excluded, so
/// this task never asks for a password; run `cargo xtask e2e` separately.
fn ci() -> Result<(), String> {
    // fmt needs nothing built, so a badly formatted branch fails in a second.
    // build-ebpf comes next because every later stage that enables the
    // `ebpf` feature needs an object to embed, and without one the failure
    // surfaces from a build script deep inside a long compile.
    let stages: [Stage; 7] = [
        ("fmt", fmt_check),
        ("build-ebpf", build_ebpf),
        ("check", check),
        ("test", test_workspace),
        ("test (ebpf feature)", test_ebpf_feature),
        ("lint", lint),
        ("doc", doc),
    ];
    for (name, stage) in stages {
        eprintln!("--- xtask ci: {name}");
        stage().map_err(|e| format!("ci stage '{name}' failed: {e}"))?;
    }
    // cargo-deny is a separate install and not everyone has it; a missing
    // tool must not read as a passing supply-chain check.
    if have_binary("cargo-deny") {
        eprintln!("--- xtask ci: deny");
        deny().map_err(|e| format!("ci stage 'deny' failed: {e}"))?;
    } else {
        eprintln!("--- xtask ci: deny SKIPPED");
        eprintln!(
            "note: cargo-deny is not installed, so licences and advisories were not \
             checked here (CI still does). Install it with: cargo install --locked cargo-deny"
        );
    }
    eprintln!("--- xtask ci: all stages passed");
    Ok(())
}

/// Run the privileged hallpassd e2e tests. Compilation happens as the
/// current user (so target/ and the registry cache stay user-owned);
/// only the finished test binary runs under sudo, via cargo's per-target
/// `runner`. `cfg(all())` matches every host triple, so no triple is
/// hard-coded here.
///
/// `ebpf` builds the kernel programs first and enables the feature. Several
/// tests are gated on it and skip loudly without it - the libc-resolver
/// uprobes and the exec-after-connect race - so a run without this exercises
/// neither, and a suite that skips the tests for a feature reports the same
/// green as one that passed them.
fn test_e2e(ebpf: bool) -> Result<(), String> {
    if ebpf {
        build_ebpf()?;
    }
    let mut cmd = cargo(&["test", "-p", "hallpassd", "--test", "e2e"]);
    if ebpf {
        cmd.args(["--features", "ebpf"]);
    }
    cmd.args([
        "--config",
        "target.'cfg(all())'.runner=\"sudo -E\"",
        "--",
        "--ignored",
        "--test-threads=1",
    ]);
    run(cmd)
}

/// Escape a string for a TOML basic string (`"..."`).
///
/// Scratch paths come from `$XDG_RUNTIME_DIR` or the repo location, neither of
/// which the operator chose with TOML in mind, so a backslash or quote in
/// either would otherwise render a config the daemon rejects as malformed.
fn toml_escape(s: &str) -> String {
    // Backslashes first, so the ones escaping quotes are not doubled.
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Render the dev config that [`dev`] writes into `dir`.
///
/// Only the paths that must not point at the real installation are set;
/// everything else comes from the daemon's built-in defaults, which keeps this
/// from drifting as config fields are added.
fn dev_config(dir: &Path) -> String {
    let dir = toml_escape(&dir.display().to_string());
    format!(
        "# Generated by `cargo xtask dev`. Scratch only: edit freely, it is\n\
         # rewritten on every run and lives outside /etc.\n\
         #\n\
         # Every path is redirected so a dev daemon cannot touch the socket,\n\
         # the rule files, or the first-seen state of an installed one. Every\n\
         # other setting is the daemon's built-in default.\n\
         socket_path = \"{dir}/hallpass.sock\"\n\
         rules_dir = \"{dir}/rules.d\"\n\
         first_seen_state = \"{dir}/seen.toml\"\n\
         lockdown_state = \"{dir}/posture.toml\"\n"
    )
}

/// The starter policy `dev` writes into an empty scratch `rules.d`.
///
/// The synthetic connections are decided by whatever is loaded, so against an
/// empty directory every one of them falls to `default_verdict` and the feed
/// is a wall of identical allows with no rule names. These give the cast
/// something to be decided by: an allow, a deny at higher priority that wins
/// over it, a reject, and two connections nothing matches. There is nothing
/// special about them - edit, disable, delete, or add from a client, and the
/// next connection follows.
const DEV_RULES: &[(&str, &str)] = &[
    (
        "allow-web",
        "name = \"allow-web\"\n\
         action = \"allow\"\n\
         duration = \"forever\"\n\
         priority = 10\n\
         enabled = true\n\
         \n\
         [match]\n\
         port = 443\n\
         proto = \"tcp\"\n",
    ),
    (
        "block-telemetry",
        "name = \"block-telemetry\"\n\
         action = \"deny\"\n\
         duration = \"forever\"\n\
         priority = 100\n\
         enabled = true\n\
         \n\
         [match]\n\
         domain = \"telemetry.example.com\"\n",
    ),
    (
        "allow-updates",
        "name = \"allow-updates\"\n\
         action = \"allow\"\n\
         duration = \"forever\"\n\
         priority = 10\n\
         enabled = true\n\
         \n\
         [match]\n\
         port = 80\n\
         proto = \"tcp\"\n",
    ),
    (
        "block-unknown-binaries",
        "name = \"block-unknown-binaries\"\n\
         action = \"reject\"\n\
         duration = \"forever\"\n\
         priority = 100\n\
         enabled = true\n\
         \n\
         [match]\n\
         exe_glob = \"/tmp/*\"\n",
    ),
];

/// Write the starter policy, unless the scratch directory already has rules.
///
/// Guarded on the directory being empty of rules rather than on each file
/// being absent, so a rule deleted while working on something stays deleted
/// across runs. Emptying the directory is how to ask for the starter set
/// back.
fn seed_dev_rules(dir: &Path) -> Result<(), String> {
    let has_rules = std::fs::read_dir(dir)
        .map_err(|e| format!("failed to read {}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .any(|e| e.path().extension().is_some_and(|x| x == "toml"));
    if has_rules {
        return Ok(());
    }
    for (stem, body) in DEV_RULES {
        let path = dir.join(format!("{stem}.toml"));
        std::fs::write(&path, body)
            .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
        // The daemon skips a rule file that is group- or world-writable, and
        // a permissive umask would produce one. A skipped starter rule would
        // show up only as a count in `status`.
        set_mode(&path, 0o600)?;
    }
    Ok(())
}

/// Where the dev scratch dir goes.
///
/// `$XDG_RUNTIME_DIR` is preferred: it is already 0700 and user-owned, it is
/// on tmpfs, and it is short, which matters because `sun_path` caps a unix
/// socket path at 107 bytes. `target/dev` is the fallback, and is covered by
/// the existing `target/` ignore rule.
fn dev_dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(base) if !base.is_empty() => PathBuf::from(base).join("hallpass-dev"),
        _ => workspace_root().join("target/dev"),
    }
}

/// Run the daemon locally, as the invoking user, for client development.
///
/// Binding an nfqueue needs CAP_NET_ADMIN, so unprivileged the bind fails and
/// the daemon logs that it is continuing without interception: no nftables
/// table is installed and no packet is judged. What does work is everything a
/// client talks to - the IPC server, the rule store and its directory watcher,
/// the prompt table, events, and stats - which is the whole surface
/// hallpass-cli and hallpass-ui are written against. So the CLI and UI can be
/// developed and driven end to end without root and without touching the
/// installed daemon's socket or /etc/hallpass.
fn dev() -> Result<(), String> {
    use std::os::unix::process::CommandExt;

    let dir = dev_dir();
    let rules_dir = dir.join("rules.d");
    std::fs::create_dir_all(&rules_dir)
        .map_err(|e| format!("failed to create {}: {e}", rules_dir.display()))?;
    seed_dev_rules(&rules_dir)?;

    let cfg_path = dir.join("config.toml");
    std::fs::write(&cfg_path, dev_config(&dir))
        .map_err(|e| format!("failed to write {}: {e}", cfg_path.display()))?;
    // The daemon refuses a config that is group- or world-writable, and a
    // permissive umask would otherwise produce one. Setting the mode
    // explicitly means `cargo xtask dev` does not depend on the caller's
    // umask to start at all.
    set_mode(&cfg_path, 0o600)?;

    let socket = dir.join("hallpass.sock");
    // The dev-fixtures feature feeds synthetic connections into the event
    // bus. Without root there is no interception, so every event-driven
    // view renders an empty machine and the whole observability surface is
    // undevelopable. It is a non-default feature precisely so a shipped
    // binary cannot be talked into fabricating events.
    run(cargo(&[
        "build",
        "-p",
        "hallpassd",
        "--features",
        "dev-fixtures",
    ]))?;

    let socket = socket.display();
    eprintln!();
    eprintln!("dev daemon config: {}", cfg_path.display());
    eprintln!("dev daemon socket: {socket}");
    eprintln!();
    eprintln!("interception is OFF for this run: binding an nfqueue needs root, so");
    eprintln!("no nftables table is installed and no traffic is filtered. IPC, rule");
    eprintln!("management, prompts, events, and stats all work, which is what the");
    eprintln!("CLI and the UI are written against.");
    eprintln!();
    eprintln!("the events and traffic views are fed by SYNTHETIC connections, since");
    eprintln!("with no interception there is nothing real to show. They are built in");
    eprintln!("under the dev-fixtures feature and cannot exist in a release binary.");
    eprintln!();
    eprintln!("the connections are invented; the verdicts are not. Each one runs through");
    eprintln!("the loaded ruleset the way a real packet does, so editing a rule changes");
    eprintln!("what the next one is decided by, and hit counts move. A starter policy is");
    eprintln!("written to the rules dir when it is empty:");
    eprintln!("  {}", rules_dir.display());
    eprintln!();
    eprintln!("in another terminal:");
    eprintln!("  cargo run -q -p hallpass-cli -- --socket {socket} status");
    eprintln!("  cargo run -q -p hallpass-cli -- --socket {socket} rules");
    eprintln!("  cargo run -q -p hallpass-cli -- --socket {socket} top");
    eprintln!("  cargo run -q -p hallpass-ui  -- --socket {socket}");
    eprintln!("  cargo run -q -p hallpass-ui  -- agent --socket {socket}");
    eprintln!();
    eprintln!("the window takes no prompts; the agent does, and exits at once if an");
    eprintln!("installed agent is already running for this user.");
    eprintln!();
    eprintln!("Ctrl-C stops the daemon.");
    eprintln!();

    // exec rather than spawn: the daemon should own the terminal and the
    // signals, with no xtask process in between to swallow Ctrl-C.
    let err = Command::new(workspace_root().join("target/debug/hallpassd"))
        .arg("--config")
        .arg(&cfg_path)
        .arg("--synthetic-events")
        .current_dir(workspace_root())
        .exec();
    Err(format!("failed to exec hallpassd: {err}"))
}

fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("failed to chmod {} to {mode:o}: {e}", path.display()))
}

fn run(mut cmd: Command) -> Result<(), String> {
    let status = cmd
        .status()
        .map_err(|e| format!("failed to spawn {:?}: {e}", cmd.get_program()))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{:?} exited with {status}", cmd.get_program()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_config_redirects_every_path_into_the_scratch_dir() {
        let cfg = dev_config(Path::new("/run/user/1000/hallpass-dev"));
        assert!(cfg.contains("socket_path = \"/run/user/1000/hallpass-dev/hallpass.sock\"\n"));
        assert!(cfg.contains("rules_dir = \"/run/user/1000/hallpass-dev/rules.d\"\n"));
        assert!(cfg.contains("first_seen_state = \"/run/user/1000/hallpass-dev/seen.toml\"\n"));
    }

    /// The daemon rejects an unknown key outright (`deny_unknown_fields`), so
    /// the rendered config must stay limited to keys that exist.
    #[test]
    fn dev_config_sets_only_path_keys() {
        let cfg = dev_config(Path::new("/tmp/x"));
        let keys: Vec<&str> = cfg
            .lines()
            .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
            .map(|l| l.split('=').next().unwrap_or("").trim())
            .collect();
        assert_eq!(
            keys,
            vec![
                "socket_path",
                "rules_dir",
                "first_seen_state",
                "lockdown_state"
            ]
        );
    }

    /// Nothing under /etc: a dev run must not be able to write, or point the
    /// daemon at, the real installation.
    #[test]
    fn dev_config_never_references_etc() {
        assert!(!dev_config(Path::new("/tmp/x")).contains("/etc/"));
        assert!(!dev_dir().starts_with("/etc"));
    }

    #[test]
    fn dev_dir_prefers_xdg_runtime_dir() {
        // Not using set_var: tests share a process, and the fallback is
        // covered by the assertion below regardless of the ambient value.
        match std::env::var_os("XDG_RUNTIME_DIR") {
            Some(base) if !base.is_empty() => {
                assert_eq!(dev_dir(), PathBuf::from(base).join("hallpass-dev"));
            }
            _ => assert_eq!(dev_dir(), workspace_root().join("target/dev")),
        }
    }

    /// Parsed through the daemon's own type, which is `deny_unknown_fields`:
    /// a starter rule with a key the daemon does not know is skipped at load
    /// with nothing but a counter to say so, and the dev loop then looks
    /// broken for a reason nobody can see.
    #[test]
    fn the_starter_rules_are_rules_the_daemon_accepts() {
        for (stem, body) in DEV_RULES {
            let rule: hallpass_types::Rule = toml::from_str(body)
                .unwrap_or_else(|e| panic!("{stem}.toml does not parse as a rule: {e}"));
            assert_eq!(&rule.name, stem, "file name and rule name must agree");
            assert!(rule.enabled, "{stem} would load disabled");
            assert_ne!(
                rule.matcher,
                hallpass_types::RuleMatch::default(),
                "{stem} matches every connection"
            );
        }
    }

    /// The deny has to outrank the allow it overlaps, or the telemetry
    /// connection is allowed by the port rule and the starter policy
    /// demonstrates nothing.
    #[test]
    fn the_starter_policy_lets_the_block_win() {
        let by_name = |want: &str| -> hallpass_types::Rule {
            let (_, body) = DEV_RULES
                .iter()
                .find(|(stem, _)| *stem == want)
                .expect("rule present");
            toml::from_str(body).expect("parses")
        };
        let block = by_name("block-telemetry");
        let allow = by_name("allow-web");
        assert!(
            block.priority > allow.priority,
            "higher priority is evaluated first"
        );
        assert_eq!(block.action, hallpass_types::Action::Deny);
        assert_eq!(allow.matcher.port, Some(443));
    }

    /// Re-running `dev` must not undo an edit. The seed is written only into
    /// a directory with no rules in it.
    #[test]
    fn seeding_leaves_an_existing_rules_dir_alone() {
        let dir = std::env::temp_dir().join(format!("hallpass-xtask-seed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        seed_dev_rules(&dir).unwrap();
        let seeded = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(seeded, DEV_RULES.len());

        std::fs::write(dir.join("allow-web.toml"), "edited").unwrap();
        seed_dev_rules(&dir).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("allow-web.toml")).unwrap(),
            "edited",
            "a second run overwrote an edited rule"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn toml_escape_handles_quotes_and_backslashes() {
        assert_eq!(toml_escape("/tmp/plain"), "/tmp/plain");
        assert_eq!(toml_escape("/tmp/a\"b"), "/tmp/a\\\"b");
        assert_eq!(toml_escape("/tmp/a\\b"), "/tmp/a\\\\b");
    }

    /// A path with a quote in it must still render as parseable TOML rather
    /// than terminating the string early.
    #[test]
    fn dev_config_escapes_an_awkward_path() {
        let cfg = dev_config(Path::new("/tmp/we\"ird"));
        assert!(cfg.contains("socket_path = \"/tmp/we\\\"ird/hallpass.sock\""));
    }
}

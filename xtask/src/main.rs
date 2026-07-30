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
        Some("test") => test_workspace(),
        Some("lint") => lint(),
        Some("doc") => doc(),
        Some("ci") => ci(),
        Some("build-ebpf") => build_ebpf(),
        Some("clippy-ebpf") => clippy_ebpf(),
        Some("build") => build_ebpf().and_then(|()| build_workspace()),
        Some("e2e") => test_e2e(),
        Some("dev") => dev(),
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

fn print_usage() {
    eprintln!("usage: cargo xtask <task>");
    eprintln!();
    eprintln!("verification (cheapest first):");
    eprintln!("  check         cargo check over the workspace and the ebpf feature");
    eprintln!("  test          run the workspace unit/integration tests (no privileges)");
    eprintln!("  lint          clippy in both feature configurations, plus clippy-ebpf;");
    eprintln!("                the same lints CI fails on");
    eprintln!("  doc           cargo doc --no-deps with -D warnings (broken links fail)");
    eprintln!("  ci            everything CI runs that does not need root, failing at");
    eprintln!("                the first stage that breaks; cargo-deny if it is installed");
    eprintln!("  e2e           run the hallpassd e2e tests (compiles as you, runs the");
    eprintln!("                test binary under sudo -E; will prompt for your password)");
    eprintln!();
    eprintln!("builds:");
    eprintln!("  build-ebpf    build the hallpass-ebpf kernel programs");
    eprintln!("  clippy-ebpf   lint the hallpass-ebpf kernel programs (-D warnings)");
    eprintln!("  build         build-ebpf, then a release build of the whole workspace");
    eprintln!("                (with the ebpf feature); what install.sh runs");
    eprintln!();
    eprintln!("running:");
    eprintln!("  dev           run hallpassd unprivileged against a scratch config, for");
    eprintln!("                CLI/UI work; interception is off, IPC and rules work");
}

/// The cargo binary that invoked xtask. Cargo sets $CARGO to its own
/// absolute path; fall back to plain "cargo" if it is somehow unset.
fn cargo() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string())
}

fn workspace_root() -> PathBuf {
    // xtask lives at <root>/xtask; CARGO_MANIFEST_DIR is set at compile
    // time, which is fine because xtask is always built in-tree.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent dir")
        .to_path_buf()
}

/// Build crates/hallpass-ebpf for bpfel-unknown-none. Target, build-std,
/// and the shared target dir come from the crate's own .cargo/config.toml;
/// nightly + rust-src come from its rust-toolchain.toml.
fn build_ebpf() -> Result<(), String> {
    if Command::new("bpf-linker").arg("--version").output().is_err() {
        return Err("bpf-linker not found in PATH; install it with: cargo install bpf-linker"
            .to_string());
    }
    let dir = workspace_root().join("crates/hallpass-ebpf");
    run(Command::new("cargo")
        .args(["build", "--release"])
        .current_dir(dir)
        // cargo xtask runs under the workspace toolchain; drop that so
        // hallpass-ebpf's rust-toolchain.toml (nightly) takes effect.
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO"))
}

/// Lint crates/hallpass-ebpf, which no workspace command reaches.
///
/// It is deliberately not a workspace member, so `cargo clippy --workspace`
/// cannot see it, and `build-ebpf` only compiles it. That left the one crate
/// in the project containing `unsafe` (and running in the kernel) as the only
/// crate never linted. Same toolchain juggling as [`build_ebpf`].
fn clippy_ebpf() -> Result<(), String> {
    let dir = workspace_root().join("crates/hallpass-ebpf");
    run(Command::new("cargo")
        .args(["clippy", "--release", "--", "-D", "warnings"])
        .current_dir(dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO"))
}

fn build_workspace() -> Result<(), String> {
    run(Command::new(cargo())
        .args(["build", "--release", "--workspace", "--features", "hallpassd/ebpf"])
        .current_dir(workspace_root()))
}

/// Type-check everything without codegen: the fastest way to learn that a
/// change does not compile, including in the `ebpf` configuration, which the
/// plain workspace commands never enable.
fn check() -> Result<(), String> {
    run(Command::new(cargo())
        .args(["check", "--workspace", "--all-targets"])
        .current_dir(workspace_root()))?;
    run(Command::new(cargo())
        .args(["check", "-p", "hallpassd", "--features", "ebpf"])
        .current_dir(workspace_root()))
}

fn test_workspace() -> Result<(), String> {
    run(Command::new(cargo())
        .args(["test", "--workspace"])
        .current_dir(workspace_root()))
}

/// The eBPF attribution unit tests are gated on the feature, so the plain
/// workspace test run never reaches them.
fn test_ebpf_feature() -> Result<(), String> {
    run(Command::new(cargo())
        .args(["test", "-p", "hallpassd", "--features", "ebpf"])
        .current_dir(workspace_root()))
}

/// Every lint gate CI has, in one command.
///
/// Three invocations are needed rather than one: the workspace run cannot see
/// code behind the `ebpf` feature, and neither run can see crates/hallpass-ebpf
/// at all because it is not a workspace member.
fn lint() -> Result<(), String> {
    run(Command::new(cargo())
        .args(["clippy", "--workspace", "--all-targets", "--", "-D", "warnings"])
        .current_dir(workspace_root()))?;
    run(Command::new(cargo())
        .args([
            "clippy",
            "-p",
            "hallpassd",
            "--all-targets",
            "--features",
            "ebpf",
            "--",
            "-D",
            "warnings",
        ])
        .current_dir(workspace_root()))?;
    clippy_ebpf()
}

/// Build the rustdoc, treating warnings as errors.
///
/// The project documents public items heavily and leans on intra-doc links to
/// keep the prose pointing at the right code. Without `-D warnings` a link that
/// stops resolving is a silent downgrade to plain text, so the convention rots
/// without anything failing.
fn doc() -> Result<(), String> {
    run(Command::new(cargo())
        .args(["doc", "--workspace", "--no-deps"])
        .env("RUSTDOCFLAGS", "-D warnings")
        .current_dir(workspace_root()))
}

/// One stage of [`ci`]: a name for the failure message, and the task to run.
type Stage = (&'static str, fn() -> Result<(), String>);

fn deny() -> Result<(), String> {
    run(Command::new(cargo())
        .args(["deny", "check"])
        .current_dir(workspace_root()))
}

/// True if `name` can be spawned, i.e. it is on PATH and executable.
fn have_binary(name: &str) -> bool {
    Command::new(name).arg("--version").output().is_ok()
}

/// Everything CI runs that does not need root, cheapest failure first.
///
/// The point is that a contributor can learn CI's answer before pushing.
/// Stages that need privileges (the e2e suite) are deliberately excluded, so
/// this task never asks for a password; run `cargo xtask e2e` separately.
fn ci() -> Result<(), String> {
    // build-ebpf first, because every later stage that enables the `ebpf`
    // feature needs an object to embed, and without one the failure surfaces
    // from a build script deep inside a long compile rather than up front.
    let stages: [Stage; 6] = [
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
fn test_e2e() -> Result<(), String> {
    run(Command::new(cargo())
        .args([
            "test",
            "-p",
            "hallpassd",
            "--test",
            "e2e",
            "--config",
            "target.'cfg(all())'.runner=\"sudo -E\"",
            "--",
            "--ignored",
            "--test-threads=1",
        ])
        .current_dir(workspace_root()))
}

/// Escape a string for a TOML basic string (`"..."`).
///
/// Scratch paths come from `$XDG_RUNTIME_DIR` or the repo location, neither of
/// which the operator chose with TOML in mind, so a backslash or quote in
/// either would otherwise render a config the daemon rejects as malformed.
fn toml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    out
}

/// Render the dev config that [`dev`] writes into `dir`.
///
/// Only the two paths that must not point at the real installation are set;
/// everything else comes from the daemon's built-in defaults, which keeps this
/// from drifting as config fields are added.
fn dev_config(dir: &Path) -> String {
    let dir = toml_escape(&dir.display().to_string());
    format!(
        "# Generated by `cargo xtask dev`. Scratch only: edit freely, it is\n\
         # rewritten on every run and lives outside /etc.\n\
         #\n\
         # Both paths are redirected so a dev daemon cannot touch the socket\n\
         # or the rule files of an installed one. Every other setting is the\n\
         # daemon's built-in default.\n\
         socket_path = \"{dir}/hallpass.sock\"\n\
         rules_dir = \"{dir}/rules.d\"\n"
    )
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

    let cfg_path = dir.join("config.toml");
    std::fs::write(&cfg_path, dev_config(&dir))
        .map_err(|e| format!("failed to write {}: {e}", cfg_path.display()))?;
    // The daemon refuses a config that is group- or world-writable, and a
    // permissive umask would otherwise produce one. Setting the mode
    // explicitly means `cargo xtask dev` does not depend on the caller's
    // umask to start at all.
    set_mode(&cfg_path, 0o600)?;

    let socket = dir.join("hallpass.sock");
    run(Command::new(cargo())
        .args(["build", "-p", "hallpassd"])
        .current_dir(workspace_root()))?;

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
    eprintln!("in another terminal:");
    eprintln!("  cargo run -q -p hallpass-cli -- --socket {socket} status");
    eprintln!("  cargo run -q -p hallpass-cli -- --socket {socket} rules");
    eprintln!("  cargo run -q -p hallpass-cli -- --socket {socket} top");
    eprintln!("  cargo run -q -p hallpass-ui  -- --socket {socket}");
    eprintln!();
    eprintln!("Ctrl-C stops the daemon.");
    eprintln!();

    // exec rather than spawn: the daemon should own the terminal and the
    // signals, with no xtask process in between to swallow Ctrl-C.
    let err = Command::new(workspace_root().join("target/debug/hallpassd"))
        .arg("--config")
        .arg(&cfg_path)
        .current_dir(workspace_root())
        .exec();
    Err(format!("failed to exec hallpassd: {err}"))
}

fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("failed to chmod {} to {mode:o}: {e}", path.display()))
}

fn run(cmd: &mut Command) -> Result<(), String> {
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
    fn dev_config_redirects_both_paths_into_the_scratch_dir() {
        let cfg = dev_config(Path::new("/run/user/1000/hallpass-dev"));
        assert!(cfg.contains("socket_path = \"/run/user/1000/hallpass-dev/hallpass.sock\"\n"));
        assert!(cfg.contains("rules_dir = \"/run/user/1000/hallpass-dev/rules.d\"\n"));
    }

    /// The daemon rejects an unknown key outright (`deny_unknown_fields`), so
    /// the rendered config must stay limited to keys that exist.
    #[test]
    fn dev_config_sets_only_the_two_path_keys() {
        let cfg = dev_config(Path::new("/tmp/x"));
        let keys: Vec<&str> = cfg
            .lines()
            .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
            .map(|l| l.split('=').next().unwrap_or("").trim())
            .collect();
        assert_eq!(keys, vec!["socket_path", "rules_dir"]);
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

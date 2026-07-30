//! Workspace build tasks (cargo xtask).

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let task = std::env::args().nth(1);
    let result = match task.as_deref() {
        Some("build-ebpf") => build_ebpf(),
        Some("clippy-ebpf") => clippy_ebpf(),
        Some("build") => build_ebpf().and_then(|()| build_workspace()),
        Some("test") => test_workspace(),
        Some("e2e") => test_e2e(),
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
    eprintln!("tasks:");
    eprintln!("  build-ebpf    build the hallpass-ebpf kernel programs");
    eprintln!("  clippy-ebpf   lint the hallpass-ebpf kernel programs (-D warnings)");
    eprintln!("  build         build-ebpf, then a release build of the whole workspace");
    eprintln!("                (with the ebpf feature); what install.sh runs");
    eprintln!("  test          run the workspace unit/integration tests (no privileges)");
    eprintln!("  e2e           run the hallpassd e2e tests (compiles as you, runs the");
    eprintln!("                test binary under sudo -E; will prompt for your password)");
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
    run(Command::new("cargo")
        .args(["build", "--release", "--workspace", "--features", "hallpassd/ebpf"])
        .current_dir(workspace_root()))
}

fn test_workspace() -> Result<(), String> {
    run(Command::new(cargo())
        .args(["test", "--workspace"])
        .current_dir(workspace_root()))
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

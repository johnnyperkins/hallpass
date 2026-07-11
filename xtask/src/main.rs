//! Workspace build tasks (cargo xtask).

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let task = std::env::args().nth(1);
    let result = match task.as_deref() {
        Some("build-ebpf") => build_ebpf(),
        Some("build") => build_ebpf().and_then(|()| build_workspace()),
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
    eprintln!("  build-ebpf    build the sentinel-ebpf kernel programs");
    eprintln!("  build         build-ebpf, then the whole workspace (with the ebpf feature)");
}

fn workspace_root() -> PathBuf {
    // xtask lives at <root>/xtask; CARGO_MANIFEST_DIR is set at compile
    // time, which is fine because xtask is always built in-tree.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent dir")
        .to_path_buf()
}

/// Build crates/sentinel-ebpf for bpfel-unknown-none. Target, build-std,
/// and the shared target dir come from the crate's own .cargo/config.toml;
/// nightly + rust-src come from its rust-toolchain.toml.
fn build_ebpf() -> Result<(), String> {
    if Command::new("bpf-linker").arg("--version").output().is_err() {
        return Err("bpf-linker not found in PATH; install it with: cargo install bpf-linker"
            .to_string());
    }
    let dir = workspace_root().join("crates/sentinel-ebpf");
    run(Command::new("cargo")
        .args(["build", "--release"])
        .current_dir(dir)
        // cargo xtask runs under the workspace toolchain; drop that so
        // sentinel-ebpf's rust-toolchain.toml (nightly) takes effect.
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO"))
}

fn build_workspace() -> Result<(), String> {
    run(Command::new("cargo")
        .args(["build", "--workspace", "--features", "sentineld/ebpf"])
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

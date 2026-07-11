//! Workspace build tasks (cargo xtask).

use std::process::ExitCode;

fn main() -> ExitCode {
    let task = std::env::args().nth(1);
    match task.as_deref() {
        Some("build-ebpf") => {
            eprintln!("build-ebpf: not yet implemented (sentinel-ebpf crate pending)");
            ExitCode::FAILURE
        }
        Some(other) => {
            eprintln!("unknown task: {other}");
            print_usage();
            ExitCode::FAILURE
        }
        None => {
            print_usage();
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!("usage: cargo xtask <task>");
    eprintln!("tasks:");
    eprintln!("  build-ebpf    build the sentinel-ebpf kernel programs");
}

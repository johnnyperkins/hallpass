//! Locate the eBPF object the `ebpf` feature embeds.
//!
//! Building the object needs nightly plus bpf-linker, which is a lot to
//! ask of someone who just wants eBPF attribution. Resolving the path
//! here means a prebuilt object can be dropped in or pointed at instead,
//! and the crate itself builds on stable.
//!
//! Order: an explicit `HALLPASS_EBPF_OBJ`, then a prebuilt object
//! vendored next to the crate, then whatever `cargo xtask build-ebpf`
//! produced. Nothing is built here; a missing object is an error with
//! instructions rather than a surprise later.

use std::path::PathBuf;

const OBJ_NAME: &str = "hallpass-ebpf";
const OVERRIDE_VAR: &str = "HALLPASS_EBPF_OBJ";

fn main() {
    // Set by cargo-fuzz; gates the fuzz entry points (src/fuzz.rs).
    println!("cargo::rustc-check-cfg=cfg(fuzzing)");
    println!("cargo::rerun-if-env-changed={OVERRIDE_VAR}");
    println!("cargo::rerun-if-env-changed=CARGO_TARGET_DIR");
    // Only the ebpf feature embeds the object; without it there is
    // nothing to find and a missing object must not fail the build.
    if std::env::var_os("CARGO_FEATURE_EBPF").is_none() {
        return;
    }

    let manifest = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo"),
    );
    let workspace = manifest.join("..").join("..");
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| workspace.join("target"), PathBuf::from);
    let prebuilt = manifest.join("prebuilt").join(OBJ_NAME);
    let xtask_built = target_dir
        .join("bpfel-unknown-none")
        .join("release")
        .join(OBJ_NAME);

    let candidates = [
        std::env::var_os(OVERRIDE_VAR).map(PathBuf::from),
        Some(prebuilt.clone()),
        Some(xtask_built.clone()),
    ];

    for path in candidates.into_iter().flatten() {
        if path.is_file() {
            println!("cargo::rerun-if-changed={}", path.display());
            // A prebuilt object outranks the xtask one, so one dropped in
            // later must be noticed. Watching its path directly would not
            // do: cargo treats a missing path as always stale and would rerun
            // this script on every build. The crate directory holds it, and
            // is what cargo watches anyway when a script names nothing.
            if path == xtask_built {
                println!("cargo::rerun-if-changed={}", manifest.display());
            }
            println!("cargo::rustc-env={OVERRIDE_VAR}={}", path.display());
            return;
        }
    }

    panic!(
        "the `ebpf` feature needs a compiled eBPF object and none was found.\n\
         Build one with `cargo xtask build-ebpf` (needs nightly plus bpf-linker),\n\
         drop a prebuilt one at {}, or point {OVERRIDE_VAR} at it.",
        prebuilt.display()
    );
}

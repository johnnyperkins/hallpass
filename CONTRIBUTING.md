# Contributing

This is how to build hallpass, how to prove a change is correct, and what
review will ask about. `docs/ARCHITECTURE.md` covers the shape of the system
and the invariants that are not obvious from any one file; read it before
changing the daemon's startup path or the wire protocol.

## Building

Stable Rust is enough for the default build, which uses procfs attribution
only:

```sh
cargo build --release
```

`cargo xtask build` builds the eBPF object and then the whole workspace with
the `ebpf` feature, which is what `install.sh` runs.

**`cargo xtask build-ebpf` is the only place the eBPF build recipe lives.**
The kernel crate needs a different target (`bpfel-unknown-none`), a
`build-std` of `core`, a shared target directory, and a nightly toolchain
with `rust-src`. None of that is spelled out in the task: the target and
target directory come from `crates/hallpass-ebpf/.cargo/config.toml`, the
toolchain from `crates/hallpass-ebpf/rust-toolchain.toml`, which rustup
installs on first use. The task's own contribution is to clear
`RUSTUP_TOOLCHAIN` and `CARGO` from the environment, so the nested build
picks up the crate's toolchain instead of the one that invoked xtask. That
is the part that is easy to get wrong by hand, and it is why there is one
owner of the recipe rather than a documented incantation.

[bpf-linker](https://github.com/aya-rs/bpf-linker) must be on `PATH`
(`cargo install bpf-linker`; CI pins `--locked --version 0.10.4`).
`build-ebpf` checks for it up front rather than letting the failure surface
from inside a link step.

The `ebpf` feature does not build the object, it embeds one. `hallpassd`'s
build script looks for `HALLPASS_EBPF_OBJ`, then
`crates/hallpassd/prebuilt/hallpass-ebpf`, then
`target/bpfel-unknown-none/release/hallpass-ebpf`, and fails with those
instructions if there is none. So a prebuilt object can be dropped in and
the daemon still builds on stable.

## Verifying a change

`cargo xtask ci` runs everything CI runs that does not need root, cheapest
failure first, and never asks for a password. Each stage is also available on
its own.

| Task | Raw equivalent | What it is for |
| --- | --- | --- |
| `cargo xtask check` | `cargo check --workspace --all-targets` and `cargo check -p hallpassd --features ebpf` | Fastest answer to "does this compile", in both feature configurations |
| `cargo xtask test` | `cargo test --workspace` | The unprivileged suite |
| (part of `ci`) | `cargo test -p hallpassd --features ebpf` | The eBPF attribution unit tests |
| `cargo xtask lint` | three `cargo clippy` runs, see below | Every lint gate CI has |
| `cargo xtask clippy-ebpf` | `cargo clippy` inside `crates/hallpass-ebpf` | The kernel crate, which nothing else lints |
| `cargo xtask doc` | `cargo doc --workspace --no-deps` with `RUSTDOCFLAGS=-D warnings` | Broken intra-doc links |
| `cargo xtask build-ebpf` | see above | The kernel programs still compile |
| `cargo xtask e2e` | see below | The privileged end-to-end suite |
| (no task) | `cargo deny check` | Licences and advisories |

Three things about that matrix are worth stating explicitly, because each one
covers code the obvious command misses.

`cargo test -p hallpassd --features ebpf` is not redundant with
`cargo test --workspace`. The eBPF attribution module is `#[cfg(feature =
"ebpf")]`, so its unit tests do not exist in the plain workspace run and
never execute there. `cargo xtask ci` runs both, and CI has a separate job
for the feature build.

Clippy needs three invocations, not one. The workspace run cannot see code
behind the `ebpf` feature, and neither workspace run can see
`crates/hallpass-ebpf` at all, because it is deliberately not a workspace
member. That left the one crate in the project containing `unsafe` (the
workspace is `unsafe_code = "deny"`) and running in the kernel as the only
crate never linted, which is what `cargo xtask clippy-ebpf` exists to fix.

`cargo xtask doc` treats rustdoc warnings as errors on purpose. The doc
comments in this tree carry the security reasoning and lean on intra-doc
links to keep the prose pointing at the right code; a link that stops
resolving degrades silently to plain text, so without `-D warnings` the
convention rots with nothing failing.

There is no `cargo fmt` gate. The tree is hand-formatted.

`cargo deny check` is separate because cargo-deny is a separate install. The
`ci` task skips it with a loud note when it is missing rather than letting an
absent tool read as a passing supply-chain check.

### The end-to-end suite

The e2e tests run the real daemon inside a pair of network namespaces. Every
one is `#[ignore]`-gated because it needs root plus `ip`, `nft`, and `nc`
(`python3` as well for the DNS tests).

```sh
cargo xtask e2e
```

That compiles as your user and runs only the finished test binary under
`sudo -E`, through cargo's per-target `runner` setting. By hand, the same
split:

```sh
cargo test -p hallpassd --test e2e --no-run    # compile unprivileged
sudo -E ./target/debug/deps/e2e-<hash> --ignored --test-threads=1
```

**Never `sudo cargo`.** It builds as root and leaves root-owned files in
`target/`, which then break every later build as your user. If it happens,
`sudo chown -R $USER:$USER target` repairs it. (CI does use `sudo -E cargo
test`, because the runner is throwaway and cargo picks the test binary by a
hash that changes with every source edit. Locally the prebuild is what keeps
compilation unprivileged.)

`--test-threads=1` is required. The tests share fixed namespace names, so
two running at once fight over the same veth pair.

Add `--features ebpf` to include the libc-resolver uprobe test, which skips
itself without the feature.

The suite skips gracefully and passes when the environment cannot run it, so
a green run is not proof the tests ran. CI greps the output for the `SKIP
e2e` marker and fails the job if it appears.

## Running the daemon for CLI and GUI work

```sh
cargo xtask dev
```

This runs `hallpassd` as your own user against a generated scratch config in
`$XDG_RUNTIME_DIR/hallpass-dev` (or `target/dev`), with only the socket path
and rules directory redirected so a dev daemon cannot touch an installed
one's socket or `/etc/hallpass`.

Interception is off in that mode: binding an nfqueue needs `CAP_NET_ADMIN`,
so the bind fails, no nftables table is installed, and no packet is judged.
What does work is everything a client talks to, which is the IPC server, the
rule store and its directory watcher, the prompt table, events, and stats.
That is the entire surface `hallpass-cli` and `hallpass-ui` are written
against, so both can be developed and driven end to end without root. The
task prints the socket path and the commands to point a client at it.

## Commits

Small, conventional commits (`fix(dns,prompt): ...`, `harden(ipc): ...`,
`feat(cli): ...`). The subject says what changed; **the body explains why**,
including what went wrong without it. `git log` is the register to match:
several commit bodies in this tree are the only record of a bug's failure
mode, and they are worth more than the diff.

Two rules that apply everywhere, code and prose alike:

- **No em dashes.** Use `-` or reword.
- **Do not name competing products** in code comments, commit messages, or
  documentation.

Make two passes before committing, and keep them separate. The first is a
cleanup pass: dead code, duplicated logic, comments that no longer describe
the code. The second is a correctness and security pass over the same diff,
reading it as an attacker would. Both have caught real defects here, and
folding them into one pass reliably loses the second.

## What review looks for

Beyond the usual, three things get asked about every time in this codebase.

**Anything an attacker can feed must be bounded, and the bound must cost
something harmless.** The DNS snoop channel is bounded because the input
snoop rule queues any UDP packet with source port 53, so anything that can
reach this host can feed it at line rate. Per-client IPC queues are bounded
because a client that stops reading would otherwise grow daemon memory. The
event history is capped by count *and* by bytes, because command lines are
read from `/proc` uncapped and one long argv could push a reply past the 1
MiB frame limit, and a refused frame breaks the connection instead of
answering it. The rule-hit map is capped because it is keyed by name and
outlives the rules. The eBPF scratch maps are LRU because a missed return
probe leaks an entry. When you add a queue, a map, or a cache, say in a
comment what is lost when it fills, and make sure the answer is an event or
an annotation, never a verdict.

**Any daemon-supplied string rendered to a human goes through
`hallpass_types::sanitize_for_display`.** Connection metadata is chosen by
the process being judged: it rewrites its own argv, picks the path it runs
from, and can resolve a name it controls, and all of it is shown to the
operator who is about to allow or deny it. Rendered raw, a carriage return
or a cursor-movement escape overwrites the line being read. This applies to
JSON output too: `serde_json` escapes a control byte rather than dropping
it, so an unsanitized value still reaches a terminal one hop later.

**A new failure path must state which way it fails and why.** Every existing
one does, in a comment at the site: the nfqueue bind refuses to start under
`queue_bypass = false` and degrades to no-interception under `true`; the
panic hook tears the nftables table down in fail-open mode and deliberately
leaves it standing in fail-closed mode; a config file the operator named
explicitly is fatal when missing, while the default path may fall back. If a
new path can fail, the diff should say which posture it takes and what the
other choice would have cost.

One habit that follows from the last point: prefer a test that exercises the
real thing. The rendered nftables ruleset is piped through the actual `nft`
parser in a unit test, because substring assertions cannot catch a ruleset
`nft` refuses to parse, and one bad token means no table is installed and
nothing is filtered.

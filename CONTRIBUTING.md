# Contributing

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) before touching the daemon's
startup path or the wire protocol.

## Building

```sh
cargo build --release     # procfs attribution only, stable Rust
cargo xtask build         # eBPF object, then the workspace with the ebpf feature
```

`cargo xtask build-ebpf` is the one place the eBPF build recipe lives. The
target and target dir come from `crates/hallpass-ebpf/.cargo/config.toml` and
the nightly toolchain from its `rust-toolchain.toml`; the task clears
`RUSTUP_TOOLCHAIN` and `CARGO` so the nested build picks those up rather than
the toolchain that invoked xtask. It needs
[bpf-linker](https://github.com/aya-rs/bpf-linker) on `PATH`
(`cargo install bpf-linker`; CI pins `--locked --version 0.10.4`).

The `ebpf` feature embeds an object rather than building one, looking in
`HALLPASS_EBPF_OBJ`, `crates/hallpassd/prebuilt/hallpass-ebpf`, then
`target/bpfel-unknown-none/release/hallpass-ebpf`.

## Verifying a change

`cargo xtask ci` runs everything CI runs that needs no root, cheapest failure
first. Each stage also runs on its own:

| Task | Runs | Covers |
| --- | --- | --- |
| `cargo xtask fmt` | `cargo fmt --check`, workspace and `hallpass-ebpf` | Formatting (rustfmt defaults, no config) |
| `cargo xtask check` | `cargo check`, plain and with `ebpf,dev-fixtures` | Compiles in both feature sets |
| `cargo xtask test` | `cargo test --workspace` | The unprivileged suite |
| (in `ci`) | `cargo test -p hallpassd --features ebpf` | eBPF attribution tests, which are feature-gated |
| `cargo xtask lint` | clippy on the workspace, on `hallpassd` with features, and on `hallpass-ebpf` | Every lint gate CI has |
| `cargo xtask doc` | `cargo doc` with `-D warnings` | Broken intra-doc links |
| `cargo xtask e2e [--ebpf]` | see below | The privileged end-to-end suite |
| (no task) | `cargo deny check` | Licences and advisories; `ci` runs it if installed |

Why so many invocations: feature-gated code is invisible to a plain workspace
run, and `hallpass-ebpf` is invisible to every workspace command. Rustdoc
warnings are errors because a broken intra-doc link silently becomes plain
text, and the doc comments here carry the security reasoning.

**GUI tests** run headless. `HallpassApp::with_channels` gives a test both ends
of the app's channels: feed it `UiEvent`s, assert on the `ClientMsg`s it
sends. That is where most GUI tests belong, since the GUI bugs this project has
had were state logic, not drawing. Tests that need a real widget tree (keyboard
focus order, a button actually reaching the state logic) use `egui_kittest`,
which reads the AccessKit tree without a GPU. Snapshot testing is deliberately
off.

### Fuzzing

Every parser that reads bytes an attacker chooses has a fuzz target in
`fuzz/`: DNS messages, IP packets, netlink replies, `/proc` cgroup and
cmdline text, `/proc/net` lines, rule TOML, syslog export and the wire
protocol. The entry points and their oracles live in
`crates/hallpassd/src/fuzz.rs`, which the normal test run also exercises.

```sh
cargo install cargo-fuzz
cargo xtask fuzz              # every target, 60s each
cargo xtask fuzz dns 600      # one target, ten minutes
```

A crash stops the run and leaves its input in `fuzz/artifacts/<target>/`.
Replay it with `cargo fuzz run -O <target> <file>` inside `fuzz/`, fix it, and
turn it into a unit test beside the parser. Seeds worth keeping go in
`fuzz/seeds/<target>/`; the growing corpus in `fuzz/corpus/` is not committed.

The tree was reformatted wholesale once; skip that commit in blame with:

```sh
git config blame.ignoreRevsFile .git-blame-ignore-revs
```

### The end-to-end suite

The e2e tests run the real daemon in a pair of network namespaces. They need
root plus `ip`, `nft` and `nc` (and `python3` for DNS tests), so each is
`#[ignore]`d.

```sh
cargo xtask e2e           # compiles as you, runs only the test binary under sudo -E
cargo xtask e2e --ebpf    # also builds the object and runs the eBPF-gated tests
cargo xtask e2e --ebpf probe_ --nocapture   # just the probes, with their output
```

Tests named `probe_` measure rather than assert: each prints one `PROBE` line
for a question a design decision is waiting on.

By hand:

```sh
cargo test -p hallpassd --test e2e --no-run
sudo -E ./target/debug/deps/e2e-<hash> --ignored --test-threads=1
```

- **Never `sudo cargo`.** It leaves root-owned files in `target/` that break
  every later build (`sudo chown -R $USER:$USER target` repairs it). CI does
  it because its runner is throwaway.
- **`--test-threads=1` is required**: the tests share namespace names.
- **A green run may have skipped.** Tests pass when the environment cannot run
  them. CI fails the job if the output contains `SKIP e2e`, and under `--ebpf`
  an eBPF test that cannot load eBPF fails rather than skips.

## Running without root

```sh
cargo xtask dev
```

Runs `hallpassd` as you against a scratch config in
`$XDG_RUNTIME_DIR/hallpass-dev`, with its own socket and rules directory.
Interception is off (binding a queue needs `CAP_NET_ADMIN`), but the IPC
server, rule store, watcher, events and stats all work, which is everything the
CLI and GUI talk to. It prints the socket path and how to point clients at it.

It never raises prompts. For the prompt agent and windows use the stand-in
daemon, which raises a batch of prompts when the agent claims the slot and
prints every answer:

```sh
cargo run -p hallpass-ui --example demo_daemon    # prints its socket
cargo run -p hallpass-ui -- agent --socket <that socket>
```

The agent is one per user, so quit an installed one first.

## Commits

Small conventional commits (`fix(dns,prompt): ...`, `harden(ipc): ...`,
`feat(cli): ...`). The subject says what changed; the body briefly says why,
including what went wrong without it.

Everywhere, code and prose:

- **No em dashes.** Use `-` or reword.
- **Do not name other products** in code comments or commit messages.

Review your diff twice before committing: once for cleanliness (dead code,
duplication, stale comments), then separately as an attacker would read it.

## What review asks about

**Anything an attacker can feed must be bounded, and the bound must cost
something harmless.** The DNS snoop channel, per-client IPC queues, the event
history (by count and bytes, since one long argv could exceed the 1 MiB
frame), the rule-hit map, the eBPF scratch maps: all bounded. When you add a
queue, map or cache, say in a comment what is lost when it fills. The answer
must be an event or an annotation, never a verdict.

**Every daemon-supplied string shown to a human goes through
`hallpass_types::sanitize_for_display`.** The process being judged controls its
argv, its path and the names it resolves, and a carriage return or escape
sequence would rewrite the line the operator is reading. JSON output too:
`serde_json` escapes control bytes, it does not remove them.

**A new failure path states which way it fails and why**, in a comment at the
site, like every existing one: what posture it takes, and what the other
choice would cost.

**Prefer tests that exercise the real thing.** The rendered nftables ruleset is
checked by the real `nft` parser, because substring assertions cannot catch a
ruleset `nft` rejects, and a rejected ruleset means nothing is filtered.

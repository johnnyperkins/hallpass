# Hallpass

An interactive application firewall for Linux, written in Rust. Hallpass
catches every new outbound connection, works out which program made it, and
asks you (or your rules) whether it may go.

*"Hallpass" is a working title.*

- **Per-program rules** keyed on executable path, glob or SHA-256, packaged app
  id, user, destination, domain, port and more.
- **Prompts** in a desktop app or in the terminal, remembered once, for the
  session, or forever.
- **Observe mode** to see what a policy would break before it breaks anything,
  and `suggest` to turn what you saw into rules.
- **Built to fail safely:** deny by default, fail-closed if you want it,
  eBPF attribution that a process cannot trivially lie to.

## How it works

```
                     +---------------------------+
    outbound         |         hallpassd         |
    connection       |                           |
  ----------------->-|  nfqueue --> rules engine |--> verdict (allow/deny)
   nftables NFQUEUE  |     |            |        |
   (ct state new,    |     v            v        |
    bypass)          | attribution   prompt      |
                     | (eBPF/procfs) table       |
   DNS replies       |     ^            |        |
  ----------------->-|  dns snoop       |        |
   (udp sport 53)    +------------------|--------+
                                        | IPC: Unix socket,
                                        | postcard frames
                          +-------------+-------------+
                          |                           |
                    +-----------+              +-------------+
                    | hallpass- |              | hallpass-ui |
                    |    cli    |              |   (egui)    |
                    +-----------+              +-------------+
                     status, rules,             prompt agent and
                     events, watch              windows, management
```

nftables hands each new connection to the daemon through NFQUEUE. The daemon
attributes it to a process (eBPF when available, procfs otherwise), names the
destination from snooped DNS, and runs it through the rule engine. Anything no
rule matches becomes a prompt; your answer can be saved as a rule.

| Crate                  | What it is                                                         |
| ---------------------- | ------------------------------------------------------------------ |
| `hallpassd`            | The daemon: verdict loop, attribution, DNS snooping, rules, prompts, IPC |
| `hallpass-cli`         | Command line client: status, rules, events, `top`, `watch`, `doctor` |
| `hallpass-ui`          | egui desktop app: prompt agent, prompt windows, management window  |
| `hallpass-types`       | Shared types and the postcard wire protocol                        |
| `hallpass-ebpf`        | Kernel-side eBPF programs (not a workspace member, built by `xtask`) |
| `hallpass-ebpf-common` | `no_std` types shared by kernel and userspace                      |
| `xtask`                | Build, lint, test and dev tasks                                    |

## Install

```sh
./install.sh                          # eBPF attribution if the toolchain is present
HALLPASS_EBPF=1 ./install.sh          # require eBPF
HALLPASS_EBPF=0 ./install.sh          # procfs only, stable Rust
HALLPASS_POSTURE=desktop ./install.sh # fail open if the daemon crashes
```

The script builds as you, then uses `sudo` once to install the binaries,
config, baseline rules, systemd unit and desktop entries, add you to the
`hallpass` group, and start `hallpassd`. Log out and back in once after the
first install so the group takes effect. Never run it as `sudo ./install.sh`:
that runs cargo and every build script as root.

Things to know before you run it:

- **A fresh install is hardened.** Unmatched and unanswered connections are
  denied, and so is traffic when the daemon is dead (`queue_bypass = false`).
  `HALLPASS_POSTURE=desktop` keeps the deny default but lets traffic through a
  crashed daemon. An existing `config.toml` is never overwritten.
- **Baseline rules** (`20-system-*.toml`) keep the host's resolver, clock and
  DHCP working under a deny default. Check their paths match your system; see
  [the rules guide](docs/rules.md#baseline-rules).
- **The `hallpass` group is full control of the firewall.** Members can turn
  enforcement off, delete rules and answer prompts. For monitoring only, use
  the read-only `hallpass-observer` group; see
  [the security model](docs/security.md#who-can-do-what).

`./uninstall.sh` removes it again (`HALLPASS_PURGE=1` also deletes
`/etc/hallpass` and `/var/lib/hallpass`).

## First steps

The safe way to adopt a policy is to watch before you enforce:

```sh
hallpass-cli config set --observe --yes    # record verdicts, block nothing
hallpass-cli top                           # what is this machine talking to?
hallpass-cli suggest > proposed.toml       # proposed allow rules, for review
hallpass-cli rules import proposed.toml    # once you have read them
hallpass-cli config set --enforce
```

In observe mode a would-be block is recorded as `WOULD-DENY` and the
connection goes out anyway. `config set` lasts until the daemon restarts; set
`mode` in `/etc/hallpass/config.toml` to change the mode it starts in. The
GUI's **Enforce** switch does the same.

Day to day:

```sh
hallpass-cli status                        # daemon health and counters
hallpass-cli doctor                        # post-install and troubleshooting checks
hallpass-cli events --last 50              # recent decisions, then follow
hallpass-cli watch                         # answer prompts in the terminal
hallpass-cli rules --stats                 # rules with hit counts
hallpass-cli rules add --name block-smtp --action deny --port 25 --duration forever
hallpass-cli explain --exe /usr/bin/curl --dest 1.1.1.1 --port 443
hallpass-cli run -- ./build.sh             # allow one command and its children, once
hallpass-cli lockdown on --tag core        # only rules tagged `core` may allow
```

`man hallpass-cli` documents every command.

## The desktop app

`hallpass-ui` runs as three kinds of process from one binary:

- the **prompt agent**, started at login, which owns the tray icon and
  notifications and opens a prompt window per application with connections
  waiting;
- **prompt windows**: allow or deny, with scope and duration. Deny is the
  keyboard default, closing a window denies what it showed, and Allow only
  works once the prompt has been on screen for a moment;
- the **management window** (app menu or tray) for rules, live events,
  traffic, stats and settings. `Ctrl+1`..`Ctrl+5` switch tabs, `Ctrl+F`
  searches.

The windows run on native Wayland whenever it is available, because on X11 any
client can synthesize input into them. See
[the security model](docs/security.md#the-desktop-app).

## Documentation

- [docs/guide.md](docs/guide.md): configuration, observe mode, the CLI tools,
  syslog export, flow accounting.
- [docs/rules.md](docs/rules.md): the rule format, tags, lockdown and session
  grants.
- [docs/security.md](docs/security.md): what hallpass guarantees, how it is
  hardened, and its limits. Read this before relying on it.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how the daemon is put together,
  for anyone changing it.
- [CONTRIBUTING.md](CONTRIBUTING.md): building, testing, and review.

## Building from source

```sh
cargo build --release                 # procfs attribution, stable Rust
cargo install bpf-linker
cargo xtask build                     # eBPF programs + workspace with the ebpf feature
cargo xtask ci                        # every check CI runs that needs no root
```

eBPF attribution records the owning process in the kernel at `connect()`, so
it survives a process exiting before its first packet is inspected, and it
refuses to name a binary a process exec'd into after connecting. It needs a
nightly toolchain, which `crates/hallpass-ebpf/rust-toolchain.toml` pulls in.
The `ebpf` feature embeds a prebuilt object from `HALLPASS_EBPF_OBJ`,
`crates/hallpassd/prebuilt/hallpass-ebpf`, or
`target/bpfel-unknown-none/release/hallpass-ebpf`, in that order, so a
packaged object builds on stable. Struct offsets are read from the running
kernel's BTF at load time; without an object, or if the kernel rejects it,
the daemon falls back to procfs.

## License

GPL-3.0-only. The desktop app bundles the Inter typeface under the SIL Open
Font License 1.1; see [crates/hallpass-ui/assets/fonts](crates/hallpass-ui/assets/fonts).

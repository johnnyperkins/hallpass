# Sentinel

An interactive application firewall for Linux, written in Rust. Sentinel
intercepts new outbound connections, attributes them to the process that made
them, and asks you (or your rules) whether to allow them.

*"Sentinel" is a working title.*

## How it works

New connections are diverted to userspace with nftables NFQUEUE. The daemon
attributes each connection to a process (eBPF when available, procfs
otherwise), enriches it with the destination domain from snooped DNS replies,
and runs it through the rule engine. Unmatched connections trigger an
interactive prompt in the GUI (or `sentinel-cli watch`); the reply can be
persisted as a rule.

```
                     +---------------------------+
    outbound         |         sentineld         |
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
                    | sentinel- |              | sentinel-ui |
                    |    cli    |              |   (egui)    |
                    +-----------+              +-------------+
                     status, rules,             prompt popups,
                     events, watch              management window
```

## Components

| Crate                  | What it is                                                              |
| ---------------------- | ----------------------------------------------------------------------- |
| `sentineld`            | The daemon: nfqueue loop, rule engine, prompts, IPC server, attribution, DNS snooping |
| `sentinel-cli`         | Command line client: status, rule management, event stream, interactive watch |
| `sentinel-ui`          | egui desktop app: prompt popups and a management window                 |
| `sentinel-types`       | Shared types and the length-prefixed postcard wire protocol             |
| `sentinel-ebpf`        | Kernel-side eBPF programs (kprobes on `tcp_v4_connect` etc., exec/exit tracepoints); built separately, not a workspace member |
| `sentinel-ebpf-common` | `no_std` types shared between kernel and userspace                      |
| `xtask`                | Build tasks (`cargo xtask build-ebpf`)                                  |

## Building

Stable Rust is enough for the default build (procfs attribution only):

```sh
cargo build --release
```

Binaries land in `target/release/`: `sentineld`, `sentinel-cli`, `sentinel-ui`.

### eBPF attribution (optional)

The eBPF programs need a nightly toolchain (picked up automatically via
`crates/sentinel-ebpf/rust-toolchain.toml`, including `rust-src`) and
[bpf-linker](https://github.com/aya-rs/bpf-linker):

```sh
cargo install bpf-linker
cargo xtask build-ebpf                          # builds the kernel programs
cargo build --release --features ebpf -p sentineld
# or both steps at once:
cargo xtask build
```

At runtime the daemon loads the eBPF object if it was compiled in and the
kernel accepts it; otherwise it silently falls back to procfs attribution.

## Installing

```sh
install -Dm755 target/release/sentineld  /usr/bin/sentineld
install -Dm755 target/release/sentinel-cli /usr/bin/sentinel-cli
install -Dm755 target/release/sentinel-ui  /usr/bin/sentinel-ui
install -Dm644 etc/config.toml           /etc/sentinel/config.toml
install -Dm644 etc/rules.d/example-allow-dns.toml /etc/sentinel/rules.d/example-allow-dns.toml
install -Dm644 etc/sentineld.service     /etc/systemd/system/sentineld.service
install -Dm644 etc/sentinel-ui.desktop   /usr/share/applications/sentinel-ui.desktop

# Optional: members of the "sentinel" group may talk to the daemon socket.
groupadd -f sentinel && usermod -aG sentinel "$USER"

systemctl daemon-reload
systemctl enable --now sentineld
```

Configuration lives in `/etc/sentinel/config.toml` (default verdict, prompt
timeout, queue number, socket path, rules directory). Persistent rules are
TOML files in `/etc/sentinel/rules.d/`, one rule per file:

```toml
name = "allow-dns"
action = "allow"        # allow | deny | reject
duration = "forever"
priority = 100
enabled = true

[match]                 # all present fields must match (AND)
port = 53
proto = "udp"
# exe = "/usr/bin/curl"
# exe_glob = "/usr/lib/firefox/*"
# dest = "10.0.0.0/8"
# domain = "*.example.org"
# user = 1000
```

The directory is watched; edits apply without a restart.

## Usage

```sh
sentinel-cli status                        # daemon statistics
sentinel-cli rules                         # list rules
sentinel-cli rules add --name block-smtp --action deny --port 25 --duration forever
sentinel-cli rules rm block-smtp
sentinel-cli rules toggle allow-dns off
sentinel-cli events                        # stream connection events
sentinel-cli watch                         # answer prompts in the terminal
```

The GUI (`sentinel-ui`) connects to the same socket, pops up a dialog for each
unmatched connection (allow/deny, scope, duration), and offers a management
window for rules, live events, and statistics. Only one client at a time can
hold the prompt-handler role.

## Security model

- **Fail-open by design**: the NFQUEUE rules use the `bypass` flag, so if the
  daemon dies traffic flows unfiltered instead of bricking the network. On
  clean shutdown and on panic, the nftables table is removed. This is an
  availability-over-enforcement tradeoff; an attacker who can SIGKILL the
  daemon (root) can bypass it anyway.
- **IPC socket**: `/run/sentinel/sentinel.sock`, directory 0750, socket 0660
  root:sentinel. Only root and the `sentinel` group can manage rules or answer
  prompts. Peer UIDs are logged for every mutating request.
- **Rule files**: files in `rules.d` are ignored (with a warning) unless owned
  by root (or the daemon's own euid) and not group/other writable.
- **systemd hardening**: `ProtectSystem=strict`, `ProtectHome`,
  `NoNewPrivileges`, `MemoryDenyWriteExecute`, restricted address families,
  and a read-write allowlist limited to `/etc/sentinel` and `/run/sentinel`.
- **No unsafe code** in the userspace crates (`#![deny(unsafe_code)]`
  workspace-wide; the eBPF crate is the exception by nature).

## Limitations

- **DoT / DoH are invisible** to the DNS snooper: domain-based rules only see
  names resolved through plaintext UDP port 53. Encrypted DNS still works, but
  those connections match by IP/port/exe only.
- **Reject currently behaves like Drop**: the `reject` action drops the packet
  without sending TCP RST / ICMP unreachable yet.
- Only new connections (`ct state new`) are evaluated; established flows are
  never re-checked.
- eBPF struct offsets are tuned for x86_64 distro kernels; on mismatch the
  daemon falls back to procfs attribution automatically.

## Testing

```sh
cargo test --workspace                     # unit + integration tests
cargo clippy --all-targets -- -D warnings
```

End-to-end tests run the real daemon inside network namespaces and need root
plus `ip`, `nft`, and `nc`:

```sh
cargo test -p sentineld --test e2e --no-run   # just compile them
sudo -E cargo test -p sentineld --test e2e -- --ignored --test-threads=1
```

They cover rule enforcement (allow/deny), default verdicts, queue-bypass
fail-open after `kill -9`, and process attribution over the IPC socket. Tests
skip gracefully when not run as root.

License compliance is checked with [cargo-deny](https://github.com/EmbarkStudios/cargo-deny):

```sh
cargo deny check
```

## License

GPL-3.0-only.

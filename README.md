# Hallpass

An interactive application firewall for Linux, written in Rust. Hallpass
intercepts new outbound connections, attributes them to the process that made
them, and asks you (or your rules) whether to allow them.

*"Hallpass" is a working title.*

## How it works

New connections are diverted to userspace with nftables NFQUEUE. The daemon
attributes each connection to a process (eBPF when available, procfs
otherwise), enriches it with the destination domain from snooped DNS replies,
and runs it through the rule engine. Unmatched connections trigger an
interactive prompt in the GUI (or `hallpass-cli watch`); the reply can be
persisted as a rule.

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
                     status, rules,             prompt popups,
                     events, watch              management window
```

## Components

| Crate                  | What it is                                                              |
| ---------------------- | ----------------------------------------------------------------------- |
| `hallpassd`            | The daemon: nfqueue loop, rule engine, prompts, IPC server, attribution, DNS snooping |
| `hallpass-cli`         | Command line client: status, rule management, event stream, interactive watch |
| `hallpass-ui`          | egui desktop app: prompt popups and a management window                 |
| `hallpass-types`       | Shared types and the length-prefixed postcard wire protocol             |
| `hallpass-ebpf`        | Kernel-side eBPF programs (kprobes on `tcp_v4_connect` etc., exec/exit tracepoints); built separately, not a workspace member |
| `hallpass-ebpf-common` | `no_std` types shared between kernel and userspace                      |
| `xtask`                | Build tasks (`cargo xtask build-ebpf`)                                  |

## Building

Stable Rust is enough for the default build (procfs attribution only):

```sh
cargo build --release
```

Binaries land in `target/release/`: `hallpassd`, `hallpass-cli`, `hallpass-ui`.

### eBPF attribution (optional)

The eBPF programs need a nightly toolchain (picked up automatically via
`crates/hallpass-ebpf/rust-toolchain.toml`, including `rust-src`) and
[bpf-linker](https://github.com/aya-rs/bpf-linker):

```sh
cargo install bpf-linker
cargo xtask build-ebpf                          # builds the kernel programs
cargo build --release --features ebpf -p hallpassd
# or both steps at once:
cargo xtask build
```

At runtime the daemon loads the eBPF object if it was compiled in and the
kernel accepts it; otherwise it silently falls back to procfs attribution.

## Installing

```sh
install -Dm755 target/release/hallpassd  /usr/bin/hallpassd
install -Dm755 target/release/hallpass-cli /usr/bin/hallpass-cli
install -Dm755 target/release/hallpass-ui  /usr/bin/hallpass-ui
install -Dm644 etc/config.toml           /etc/hallpass/config.toml
install -Dm644 etc/rules.d/example-allow-dns.toml /etc/hallpass/rules.d/example-allow-dns.toml
install -Dm644 etc/hallpassd.service     /etc/systemd/system/hallpassd.service
install -Dm644 etc/hallpass-ui.desktop   /usr/share/applications/hallpass-ui.desktop

# Optional: members of the "hallpass" group may talk to the daemon socket.
groupadd -f hallpass && usermod -aG hallpass "$USER"

systemctl daemon-reload
systemctl enable --now hallpassd
```

Configuration lives in `/etc/hallpass/config.toml` (default verdict, prompt
timeout, queue number, socket path, rules directory). Persistent rules are
TOML files in `/etc/hallpass/rules.d/`, one rule per file:

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
hallpass-cli status                        # daemon statistics
hallpass-cli rules                         # list rules
hallpass-cli rules add --name block-smtp --action deny --port 25 --duration forever
hallpass-cli rules rm block-smtp
hallpass-cli rules toggle allow-dns off
hallpass-cli events                        # stream connection events
hallpass-cli watch                         # answer prompts in the terminal
```

The GUI (`hallpass-ui`) connects to the same socket, pops up a dialog for each
unmatched connection (allow/deny, scope, duration), and offers a management
window for rules, live events, and statistics. Only one client at a time can
hold the prompt-handler role.

## Security model

- **Fail-open by design**: the NFQUEUE rules use the `bypass` flag, so if the
  daemon dies traffic flows unfiltered instead of bricking the network. On
  clean shutdown and on panic, the nftables table is removed. This is an
  availability-over-enforcement tradeoff; an attacker who can SIGKILL the
  daemon (root) can bypass it anyway.
- **IPC socket**: `/run/hallpass/hallpass.sock`, directory 0750, socket 0660
  root:hallpass. Only root and the `hallpass` group can manage rules or answer
  prompts. Peer UIDs are logged for every mutating request. Per-client
  outbound queues are bounded; a client that stops reading loses events
  instead of growing daemon memory.
- **DNS snoop validation**: outbound queries are observed alongside replies,
  and a reply only enters the IP-domain cache when its source/destination
  addresses, transaction ID, and question name match a recorded query.
  Spoofed packets from source port 53 cannot poison domain rules.
- **Rule files**: files in `rules.d` are ignored (with a warning) unless owned
  by root (or the daemon's own euid) and not group/other writable.
- **systemd hardening**: `ProtectSystem=strict`, `ProtectHome`,
  `NoNewPrivileges`, `MemoryDenyWriteExecute`, restricted address families,
  and a read-write allowlist limited to `/etc/hallpass` and `/run/hallpass`.
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
cargo test -p hallpassd --test e2e --no-run   # just compile them
sudo -E cargo test -p hallpassd --test e2e -- --ignored --test-threads=1
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

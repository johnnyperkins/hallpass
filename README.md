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
| `hallpass-ebpf`        | Kernel-side eBPF programs (kprobes on `tcp_v4_connect` etc., exec/exit tracepoints, libc resolver uprobes); built separately, not a workspace member |
| `hallpass-ebpf-common` | `no_std` types shared between kernel and userspace                      |
| `xtask`                | Build tasks (`cargo xtask build-ebpf`)                                  |

## Building

Stable Rust is enough for the default build (procfs attribution only):

```sh
cargo build --release
```

Binaries land in `target/release/`: `hallpassd`, `hallpass-cli`, `hallpass-ui`.

### eBPF attribution (recommended)

eBPF attribution records the owning process at `connect()` time in the
kernel, so even processes that exit before the first packet is inspected
attribute correctly; procfs attribution races those and can come up empty.
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

Building the object is only needed if you do not already have one. The
`ebpf` feature embeds whichever object it finds first:

1. `HALLPASS_EBPF_OBJ`, if set, pointing at the object file.
2. `crates/hallpassd/prebuilt/hallpass-ebpf`, for a vendored or packaged
   object.
3. `target/bpfel-unknown-none/release/hallpass-ebpf`, what `cargo xtask
   build-ebpf` writes.

So a prebuilt object can be dropped in or pointed at, and the daemon
itself then builds on stable with no nightly and no bpf-linker. If none
of the three exists the build fails with these instructions rather than
an error from inside the embedding macro.

At load time the daemon resolves the kernel struct offsets the programs
read (`sock_common`, `msghdr`) from the running kernel's BTF
(`/sys/kernel/btf/vmlinux`) and patches them into the object, so the
programs are not tied to one kernel version or architecture layout.
Kernels without BTF fall back to compiled-in x86_64 offsets. At runtime
the daemon loads the eBPF object if it was compiled in and the kernel
accepts it; otherwise it silently falls back to procfs attribution, and
any flow eBPF cannot resolve is retried through procfs.

## Installing

One command builds, installs, and starts everything:

```sh
./install.sh                    # eBPF attribution when the toolchain is present
HALLPASS_EBPF=1 ./install.sh    # require eBPF (fail instead of falling back)
HALLPASS_EBPF=0 ./install.sh    # force the procfs-only build (stable Rust)
```

It builds the release binaries as your user, then uses `sudo` (prompting
once) to install them to `/usr/bin`, drop the config and example rule into
`/etc/hallpass` (an existing `config.toml` is never overwritten), install the
systemd unit and desktop entry, autostart the UI, add you to the `hallpass`
group, and `systemctl enable --now hallpassd`. Log out and back in once so the
group membership and UI autostart take effect.

Remove it again with `./uninstall.sh` (add `HALLPASS_PURGE=1` to also delete
`/etc/hallpass`).

<details><summary>Manual install (what the script does)</summary>

```sh
install -Dm755 target/release/hallpassd  /usr/bin/hallpassd
install -Dm755 target/release/hallpass-cli /usr/bin/hallpass-cli
install -Dm755 target/release/hallpass-ui  /usr/bin/hallpass-ui
install -Dm644 etc/config.toml           /etc/hallpass/config.toml
install -Dm644 etc/rules.d/example-allow-dns.toml /etc/hallpass/rules.d/example-allow-dns.toml  # ships disabled
install -Dm644 etc/hallpassd.service     /etc/systemd/system/hallpassd.service
install -Dm644 etc/hallpass-ui.desktop   /usr/share/applications/hallpass-ui.desktop

# Optional: members of the "hallpass" group may talk to the daemon socket.
groupadd -f hallpass && usermod -aG hallpass "$USER"

systemctl daemon-reload
systemctl enable --now hallpassd
```

</details>

Configuration lives in `/etc/hallpass/config.toml` (default verdict, prompt
timeout, queue number, socket path, rules directory).

Setting `mode = "observe"` there evaluates policy and records what it
decided without applying any of it. Nothing is blocked: a rule that would
deny is recorded as a deny and the connection goes out anyway, and unmatched
connections record `default_verdict` and never prompt, because answering a
dialog that changes nothing would be misleading. It exists because the honest
answer to "what will this policy break" cannot be read off the rule files; it
depends on what the host actually talks to. So the way to size a rollout is
to run in observe mode, watch `hallpass-cli top` and `hallpass-cli events`
for a while, and only then enforce. The GUI has an **Enforce** switch in its
tab bar that flips the mode at runtime - active filtering on, passive
watching off - lasting until the daemon restarts; the config file decides
the mode it starts in. The mode is visible in `hallpass-cli status`, in
every event as an unenforced verdict (a recorded block reads `WOULD-DENY`,
never `DENY`), on syslog export as `enforced="false"`, in a warning at
startup, and as a banner in the GUI. **It is not a security posture.** While
it is on, this host is not filtered.

Persistent rules are TOML files in `/etc/hallpass/rules.d/`, one rule per
file:

```toml
name = "allow-dns"
action = "allow"        # allow | deny | reject
duration = "forever"    # once | session | forever; the CLI also takes a
                        # timespan (30s, 5m, 2h, 1d) for a rule that expires
priority = 100
enabled = true

[match]                 # all present fields must match (AND)
port = 53
proto = "udp"
# exe = "/usr/bin/curl"
# exe_glob = "/usr/lib/firefox/*"   # one level; "/usr/lib/firefox/**" for the subtree
# exe_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
# dest = "10.0.0.0/8"
# domain = "*.example.org"
# user = 1000
# cmdline_contains = "backup.py"   # substring of the full command line
# parent_exe = "/usr/bin/bash"     # exact path of the parent process
# src = "192.168.1.0/24"
# src_port = 40000
# iface = "wg0"                    # outbound interface name
# domains_file = "/etc/hallpass/rules.d/ads.list"   # hosts format or one per line
# ips_file = "/etc/hallpass/rules.d/bad-ips.list"   # IPs/CIDRs, one per line
# hashes_file = "/etc/hallpass/rules.d/bad.sha256"  # exe SHA-256s, one per line
```

The directory is watched; edits apply without a restart. Unknown keys are
rejected: a file with a misspelled operand is skipped with a warning rather
than loaded with a wider match than you wrote.

The one rule the installer drops in, `example-allow-dns.toml`, ships with
`enabled = false`. Matching on port and protocol alone would let every local
process send arbitrary UDP to port 53 on any host, which is a standard
exfiltration channel, so scope it (with `dest` or `exe`) before enabling it.
Reinstalling never overwrites it, so your edits survive upgrades. **If you
installed before this changed, check that file:** the old copy shipped
`enabled = true` and an upgrade will not touch it.

Decided connections can also be exported to syslog (local socket or a
remote collector) for SIEM ingestion, as RFC 5424 structured data or JSON:

```toml
[syslog]
format = "rfc5424"        # rfc5424 | json
[syslog.target]
kind = "udp"              # or kind = "local" with an optional path
addr = "10.0.0.9:514"     # literal IP:port; hostnames are not resolved
```

Export runs as an ordinary event subscriber, so a stalled or unreachable
collector costs events, never verdicts. Values are escaped and capped, and
control characters are neutralized, so a process cannot forge log records
through its own command line. Export datagrams do not need a rule: the
daemon marks its own export socket and the ruleset accepts that mark from
root-owned sockets, so they never enter the verdict queue. Filtering them
would not just cost logs under a default-deny posture, it would feed the
daemon its own tail - an unanswered UDP flow stays `ct state new`, so each
exported event would be decided as a new connection and emit the event that
produces the next datagram.

## Usage

```sh
hallpass-cli status                        # daemon statistics
hallpass-cli rules                         # list rules
hallpass-cli rules add --name block-smtp --action deny --port 25 --duration forever
hallpass-cli rules rm block-smtp
hallpass-cli rules toggle allow-dns off
hallpass-cli events                        # stream connection events
hallpass-cli top                           # live aggregate of current activity
hallpass-cli watch                         # answer prompts in the terminal
hallpass-cli rules --stats                 # list rules with hit counts
hallpass-cli rules export > policy.toml    # the whole ruleset as one document
hallpass-cli rules import policy.toml      # add every rule in a document
hallpass-cli explain --exe /usr/bin/curl --dest 1.1.1.1 --port 443
```

`explain` asks what policy would do with a connection without sending a
packet. It answers with the verdict, then every rule in evaluation order and
why each one did or did not decide, naming the operand that failed rather
than only reporting that something did:

```
verdict: DENY  rule=block-telemetry

RULE               PRIO  OUTCOME
allow-curl-https    100  no match (domain)
block-telemetry      50  matched
deny-all              0  not reached
```

It evaluates through the same predicate the packet path uses, so an
explanation cannot disagree with enforcement. The connection is described
entirely by the flags, so it answers for the facts you state: nothing is
verified against `/proc`, and `--exe-sha256` has to be supplied if a
hash-pinning rule is in play, since the daemon will not hash a path a client
named for it.

`rules --stats` adds hit counts and a last-hit time to the listing, which is
how a rule that never matches anything becomes visible. Counts are per rule
name and survive a rules-directory reload, so editing one file keeps its
history; they reset when the daemon restarts, because this answers "is this
rule doing anything", not "what happened last month".

`rules export` writes the ruleset as one TOML document using the same field
names as the files in `rules.d`, so it can be read, diffed, and checked into
version control, and a single entry can be lifted into `rules.d` unchanged.
`rules import` offers every rule even after one is refused, reports each by
name, and exits non-zero if any failed.

`top` answers "what is this machine talking to" rather than "what happened
next": it folds the event stream into a live table, seeded from the daemon's
history so it is populated the moment it opens. What a row counts is chosen
with `--group-by`, one of `exe`, `domain`, `host`, `port`, or `rule`, since
the interesting grouping differs per question. Rows and per-row peer sets are
capped, and events that did not fit under the row cap are reported rather
than silently dropped.

`events` streams from the moment it starts, which makes a freshly opened
monitor look like an idle machine, so `--last N` replays the last N decided
connections first (`--no-follow` to print the replay and stop). `--exe`,
`--domain`, and `--verdict` filter the replay and the live stream alike;
repeating one ORs the terms, mixing kinds ANDs them.

Both accept the global `--json` (wire types, one object per line for
streams) and `--color auto|always|never` (`auto` colors only on a terminal
with `NO_COLOR` unset). A verdict the daemon recorded but did not apply,
which is what observe mode produces, renders as `WOULD-DENY`: the connection
went out, and printing `DENY` would say the opposite of what happened.

The GUI (`hallpass-ui`) connects to the same socket, pops up a dialog for each
unmatched connection (allow/deny, scope, duration), and offers a management
window for rules, live events, and statistics. Deny leads the dialog's
keyboard traversal, and closing a prompt window denies every connection it
covers rather than leaving them to the timeout: dismissing a decision is a
decision, and it is the one the operator can undo. The deny is `Once`, so it
writes no rule. Only one client at a time can hold the prompt-handler role.

## Security model

**The enforcement guarantee in one sentence: by default, hallpass only blocks
what a live, healthy daemon explicitly denies.** Everything below is a
consequence of that. Queue `bypass`, `default_verdict = "allow"`, and the
prompt-timeout default all fail open, so a dead, wedged, or unconfigured
daemon lets traffic through. For an enforce-by-default posture, start from
[`etc/config.hardened.toml`](etc/config.hardened.toml) (`default_verdict =
"deny"`, `queue_bypass = false`): unmatched connections are denied and
enforcement survives a dead or overloaded daemon. The residual gap is an
attacker with root, who can delete the nftables table outright.

- **Fail-open by default**: the NFQUEUE verdict rule uses the `bypass` flag,
  so if the daemon dies traffic flows unfiltered instead of bricking the
  network. On clean shutdown and on panic, the nftables table is removed.
  This is an availability-over-enforcement tradeoff; set
  `queue_bypass = false` to invert it and have new connections dropped
  whenever no live daemon is deciding them (daemon dead, queue full). In
  that mode a panic deliberately leaves the table up, so enforcement holds
  until the daemon restarts; clean shutdown still removes it. The
  DNS snoop queues always keep `bypass` - they are observe-only, and
  dropping DNS with the daemon gone would cost availability without adding
  enforcement.
- **IPC socket**: `/run/hallpass/hallpass.sock`, directory 0750, socket 0660
  root:hallpass. Only root and the `hallpass` group can manage rules or answer
  prompts. The socket is created inside a 0700 staging directory and moved
  into place once its mode and group are set, so it is never reachable at
  whatever mode the process umask would have produced. Peer UIDs are logged
  for every mutating request. Per-client outbound queues are bounded; a
  client that stops reading loses events instead of growing daemon memory.
- **No filtering without a control channel**: the socket is bound before
  any nftables rule is installed, and the daemon exits if it cannot be
  bound. A daemon that filtered traffic while unreachable would answer
  every prompt with the default verdict and give the operator no way to
  see it or change it; binding first means that failure costs nothing,
  because nothing has been installed yet.
- **No queueing without a listener**: the nfqueues are bound before the
  nftables rules that feed them are installed, so no packet is ever
  resolved by the queue's `bypass` flag alone (which would skip the
  default verdict and every rule). Packets arriving before the verdict
  loop starts buffer in the queue and are judged when it drains.
- **DNS snoop validation**: outbound queries are observed alongside replies,
  and a reply only enters the IP-domain cache when its source/destination
  addresses, transaction ID, and question name match a recorded query.
  Spoofed packets from source port 53 cannot poison domain rules.
- **Domain rules are a convenience, not a boundary against a local
  process choosing its own DNS.** Both snoopers record what was resolved;
  a process that controls a zone can point a name it owns at any address,
  and the cache keeps one domain per address, so the last resolver of an
  address wins. Scope security-relevant rules with `exe`/`exe_sha256` or
  IP/CIDR criteria rather than domain alone.
- **Rule files**: files in `rules.d` are ignored (with a warning) unless owned
  by root (or the daemon's own euid) and not group/other writable. Symlinks
  are skipped, and the ownership check and the parsed bytes come from the
  same file descriptor, so the file that was checked is the file that is
  read. The same policy and mechanism apply to match-list files.
- **systemd hardening**: `ProtectSystem=strict`, `ProtectHome`,
  `NoNewPrivileges`, `MemoryDenyWriteExecute`, `RestrictNamespaces`,
  `RestrictSUIDSGID`, `PrivateTmp`, `ProtectKernelTunables`/`Logs`/`Modules`,
  `UMask=0077`, restricted address families, and a read-write allowlist
  limited to `/etc/hallpass` and `/run/hallpass`. `StartLimitIntervalSec=0`
  so a crash loop never leaves a bypass-less queue with no daemon behind it.
  `ProtectProc` is deliberately unset, because attribution reads
  `/proc/<pid>/exe` for processes it does not own.
- **Reduced privilege**: although the daemon runs as root, its
  `CapabilityBoundingSet` is narrowed to the seven capabilities it actually
  uses (`NET_ADMIN`, `DAC_READ_SEARCH`, `SYS_PTRACE`, `CHOWN`, `BPF`,
  `PERFMON`, `SYS_RESOURCE`), and `SystemCallFilter` allows only
  `@system-service` plus `bpf` and `perf_event_open`. `SYS_PTRACE` is what
  passes the kernel's ptrace access check on `/proc/<pid>/exe` for other
  users' processes; the `ptrace` syscall itself stays outside the filter, so
  the grant is `/proc` visibility, not live attach. `CAP_SYS_ADMIN` is
  deliberately excluded, which costs annotation, never enforcement: on
  kernels older than 5.8, where `bpf()` requires it, eBPF attribution falls
  back to procfs and logs why; and on kernel lines whose uprobe perf PMU
  demands it (kprobes accept `CAP_PERFMON`), the libc-resolver DNS snoop is
  unavailable under the unit and logs why - the wire snooper still covers
  plaintext port 53, so the loss is names resolved through a stub resolver
  or an encrypted upstream. Both are restored per host by a
  `systemctl edit hallpassd` drop-in re-adding `CAP_SYS_ADMIN`; the unit
  file shows the exact lines.
- **Config file trust**: the config is read under the same ownership and
  permission policy as rule files. It sets `default_verdict`, `queue_bypass`,
  and the rules directory, so it is the most security-relevant file on disk.
  A `--config` path that does not exist is fatal rather than silently
  replaced by the (fail-open) built-in defaults.
- **No unsafe code** in the userspace crates (`#![deny(unsafe_code)]`
  workspace-wide; the eBPF crate is the exception by nature).

## Limitations

- **DoT / DoH are invisible to the wire snooper**: it only sees names
  resolved through plaintext UDP port 53. With the `ebpf` feature the
  daemon also snoops the libc resolver entry points (`getaddrinfo`, the
  `gethostbyname` family, and their reentrant `_r` variants) via uprobes,
  which catches
  resolutions through systemd-resolved's stub and encrypted upstreams as
  long as the process uses the system resolver. Statically linked
  programs, non-libc runtimes, and apps doing their own DoH still match
  by IP/port/exe only.
- Only new connections (`ct state new`) are evaluated; established flows are
  never re-checked.
- **A process can choose which executable it is attributed to.** Attribution
  resolves the executable from `/proc/<pid>/exe` after the connection is
  observed, and a socket descriptor survives `execve`. So a process can start
  a non-blocking `connect()` (or send a UDP datagram), immediately exec a
  different binary, and be attributed to that binary instead; it can retry
  until it wins the race. The eBPF path records the pid at connect time,
  which is more precise than the procfs scan, but the executable is still
  resolved afterwards, so it is affected too. Rules keyed on `exe`,
  `exe_glob`, or `exe_sha256` are therefore a scoping convenience against
  ordinary software, not a boundary against a process that is actively
  evading them. The same caveat already applies for a different reason to
  `cmdline_contains` and `parent_exe`, which a process controls outright.
- **Only the `output` and `input` hooks are filtered.** Traffic that is
  *forwarded* rather than locally generated, which is what containers, VMs,
  and other network namespaces bridged to the host produce, traverses the
  `forward` hook and is not seen at all. Hallpass polices what this host
  originates.
- Rules only model TCP and UDP. Other transports (SCTP, ICMP, ...) are not
  matched against rules; they are counted and resolved by the
  `unhandled_proto_verdict` policy (`allow` by default, `deny` in the
  hardened config).
- **UDP verdicts are per flow, not per datagram**: conntrack marks only the
  first datagram of a UDP flow as `ct state new`, so exactly one verdict
  reaches the queue and it covers the whole flow until the conntrack entry
  expires. A `Once` prompt reply therefore means "this flow" for UDP (as it
  means "this connection" for TCP): the held datagram is released with the
  verdict, no rule is persisted, and a genuinely new flow to the same
  destination prompts again.
- eBPF struct offsets are tuned for x86_64 distro kernels; on mismatch the
  daemon falls back to procfs attribution automatically.

## Testing

```sh
cargo test --workspace                     # unit + integration tests
cargo clippy --all-targets -- -D warnings
```

End-to-end tests run the real daemon inside network namespaces and need root
plus `ip`, `nft`, and `nc` (`python3` too for the DNS test):

```sh
cargo test -p hallpassd --test e2e --no-run   # just compile them
sudo -E cargo test -p hallpassd --test e2e -- --ignored --test-threads=1
```

They cover rule enforcement (allow/deny), default verdicts, queue-bypass
fail-open after `kill -9`, process attribution over the IPC socket, and the
DNS snoop path (a domain rule blocks a destination only after its name is
resolved through the snooped query and validated reply). Tests skip
gracefully when not run as root or when a needed tool is missing.

License compliance is checked with [cargo-deny](https://github.com/EmbarkStudios/cargo-deny):

```sh
cargo deny check
```

`cargo xtask ci` runs everything above that does not need root, cheapest
failure first. [CONTRIBUTING.md](CONTRIBUTING.md) has the full verification
matrix, what each part covers, and the dev loop for working on the clients
without privileges; [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) has the
startup ordering invariants and the debugging landmines.

## License

GPL-3.0-only.

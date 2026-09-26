# Security model

**In one sentence: a live daemon passes only what a rule allows or an operator
approves, and a dead one passes everything unless you configure it not to.**

Those are two separate settings, and they fail in opposite directions on
purpose.

- **Policy: `default_verdict = "deny"`.** A connection no rule matches and
  nobody answers is denied. That includes a host with no prompt client
  attached, the time between boot and login, a crashed GUI, and a full prompt
  table. An allow default made the firewall stop working silently in all of
  those, and one of them can be triggered by anything able to crash the
  prompt handler.
- **Liveness: `queue_bypass`.** With `true` (desktop posture), a dead daemon
  or an overflowing queue lets traffic through rather than cutting the host
  off, and the nftables table is removed on shutdown and on panic. With
  `false` (the hardened default the installer writes), those packets are
  dropped, a panic leaves the table in place, and the daemon refuses to start
  rather than run unenforced. Clean shutdown removes the table either way.

The remaining gap is root, which can delete the nftables table.

## What is judged

Only the first packet of a connection (`ct state new`) is judged, on the
`output` and `input` hooks. Everything that follows rides the conntrack entry.

- **Established flows are not re-checked**, except that a new deny rule cuts
  matching flows it can find ([rules.md](rules.md#deny-rules-and-established-flows)).
- **Forwarded traffic is not filtered at all.** Containers, VMs and bridged
  namespaces use the `forward` hook, which hallpass does not touch. Their
  packets have no local process to attribute, so every identity field in a
  rule would be meaningless for them, and queueing them under a deny default
  would black out every container on the host with no way to prompt. Filter
  forwarded traffic with an nftables chain of your own. `hallpass-cli doctor`
  warns on any host with forwarding enabled.
- **Only TCP and UDP are matched against rules.** Other transports are counted
  and decided by `unhandled_proto_verdict`. UDP-Lite is always denied, since
  its ports are a separate space and attribution would name the wrong
  program. Packets conntrack cannot classify (`invalid`, `untracked`) never
  reach a queue, so when `unhandled_proto_verdict` is not `allow` the table
  drops them outright; otherwise a process with `CAP_NET_RAW` could hold a
  whole conversation in them. IPv6 neighbour discovery and MLD are let
  through.
- **A UDP flow is judged once, answered or not.** An unanswered UDP flow
  stays `new` in conntrack, so each datagram reaches the daemon, which
  remembers the flow's first decision for 30 seconds (the kernel's timeout
  for an unreplied entry) and applies it to the rest. A `once` answer means
  "this flow" for UDP as for TCP. A flow that keeps sending is re-judged
  every 30 seconds, and a ruleset or mode change forgets every remembered
  verdict.
- **An allowed UDP flow can be borrowed.** Once a process closes its socket,
  another can bind the same local port and keep sending inside the allowed
  conntrack entry, or the verdict remembered for it. This matters most for
  broad allows such as port 53 to anywhere.

## Who can do what

The daemon serves two sockets. Which one a client connects to is the whole
authorization decision, made by the kernel at `connect()`.

| Socket | Group | Can |
| --- | --- | --- |
| `/run/hallpass/hallpass.sock` | `hallpass` | Everything: rules, config, mode, lockdown, prompts, session grants |
| `/run/hallpass/observe.sock` | `hallpass-observer` | Read only: stats, events, history, rules and hit counts, `explain`, config and lockdown state |

**`hallpass` membership is full control of the firewall**, the same as being
able to delete every rule. The installer adds the installing user. Mutating
requests are logged with the peer's uid and pid.

**Read-only is not harmless.** The event stream covers every process on the
host, root's included, with executable, command line, uid and destination. An
observer can see what everyone on the machine runs and talks to. The installer
creates the group empty.

Per-message group checks are not an option: `SO_PEERCRED` carries only the
peer's primary gid, never supplementary groups. Hence two sockets.

Each client's outbound queue is bounded, so a client that stops reading loses
events rather than growing daemon memory. The socket is created in a private
staging directory and moved into place once its mode and group are set.

## Startup and shutdown

- **No filtering without a control channel.** The IPC socket binds before any
  nftables rule is installed, and failing to bind is fatal. A firewall nobody
  can reach would answer every prompt with the default verdict, with no way
  to see or change it.
- **No queueing without a listener.** The queues are bound, and the verdict
  loop is draining them, before the rules that feed them are installed. A
  packet is never decided by the queue's bypass flag alone.
- **The table is watched.** `nft flush ruleset` (a firewalld restart, an
  nftables reload, container tooling) removes it without the daemon noticing
  anything but silence, so it is checked every ten seconds and reinstalled,
  loudly. Under `queue_bypass = false` a failed reinstall is fatal.

## Trust in files

- **Rule files** are ignored, with a warning, unless owned by root (or the
  daemon's user) and not writable by group or other. Symlinks are skipped. The
  ownership check and the read use the same file descriptor. List files get
  the same check; a list path sent over IPC must resolve inside `rules.d`.
- **Policy directories** (`/etc/hallpass`, `rules.d`) must be root-owned and not
  group- or world-writable, because deleting a file needs write permission on
  the directory, not the file: on a group-writable `rules.d`, any group member
  can delete root's deny rules and nothing looks wrong. The daemon logs an
  error, refuses to start under `queue_bypass = false`, and `doctor` reports
  it. A sticky directory is accepted.
- **The config file** gets the same checks as rule files. A `--config` path
  that does not exist is fatal rather than silently replaced by defaults.

## The daemon's privileges

The daemon runs as root under a systemd unit that takes most of that away:

- `CapabilityBoundingSet` is seven capabilities: `NET_ADMIN`,
  `DAC_READ_SEARCH`, `SYS_PTRACE`, `CHOWN`, `BPF`, `PERFMON`, `SYS_RESOURCE`.
- `SystemCallFilter` is `@system-service` plus `bpf` and `perf_event_open`,
  minus `process_vm_readv` and `process_vm_writev`.
- `ProtectSystem=strict`, `ProtectHome`, `NoNewPrivileges`,
  `MemoryDenyWriteExecute`, `RestrictNamespaces`, `RestrictSUIDSGID`,
  `PrivateTmp`, `ProtectKernelTunables`/`Logs`/`Modules`, `DevicePolicy=closed`,
  `UMask=0077`, restricted address families, and write access only to
  `/etc/hallpass`, `/run/hallpass` and `/var/lib/hallpass`.
- `StartLimitIntervalSec=0`, so a crash loop never leaves a fail-closed queue
  with nothing behind it.

`SYS_PTRACE` is needed to read `/proc/<pid>/exe` of other users' processes. It
is not harmless: the same kernel check lets a compromised daemon open other
processes' memory for writing, which no syscall filter can stop. `ProtectProc`
is unset for the same reason.

`CAP_SYS_ADMIN` is excluded. That costs annotation, never enforcement: on
kernels before 5.8 eBPF attribution falls back to procfs, and on kernels whose
uprobe PMU demands it, the libc resolver snoop is unavailable (plain port 53
snooping still works). A `systemctl edit hallpassd` drop-in restores both; the
unit file shows the lines.

Userspace crates are `#![deny(unsafe_code)]`. The eBPF crate is the exception.

## The desktop app

Every hallpass window runs on native Wayland whenever the session has it, even
with `DISPLAY` set. Under X11 and XWayland any X client can synthesize input
into another window, including a sandboxed app given the X11 socket but not the
hallpass socket, and that was shown to answer live prompts. Wayland clients
cannot reach each other's surfaces, and GNOME and KDE keep input injection
privileged. wlroots compositors such as Sway offer virtual keyboard and pointer
protocols to any client unless a sandbox filters them, so there a client can
still type into the focused window.

On an X11-only session the GUI runs and logs a warning. Every X client can
already inject into every window there, a terminal running sudo included.

Prompt windows talk to the agent over a socket pair it hands them at startup.
Nothing listens for answers, so only a window the agent started can answer.

## Session grants

`hallpass-cli run` opens a grant rooted at the wrapper process, identified from
the socket's peer credentials, so a client cannot open one over someone else's
processes. Membership is the connecting process's ancestry up to that root,
checked hop by hop against `(pid, start time)`, and the uid must match. Every
failure (no pid, wrong uid, an ancestry that cannot be walked, more than 32
hops, an ended session) falls back to a prompt. The wrapper is a child
subreaper, so a daemonizing descendant stays inside the tree. `run-session:`
and `lockdown:` are reserved rule-name prefixes, so no rule can impersonate a
grant or the posture in the event stream.

## Limits

These are the places where hallpass reports what a process tells it rather
than what is true, or where a determined local attacker has room.

**Domain rules trust DNS the process may control.** Replies only enter the
domain cache when they match a recorded query (addresses, transaction id and
name), so spoofed packets from port 53 cannot poison it. But a process chooses
what it resolves: it can ask its own server, or point libc at one
(`LOCALDOMAIN`, `RES_OPTIONS`, a search domain it controls), and have any name
answered with any address. The cache keeps one name per address, and the last
lookup wins for every process. Names containing control characters,
whitespace or non-ASCII bytes are refused outright. Scope security-relevant
rules with `exe`/`exe_sha256` or addresses, not domains alone.

**Encrypted DNS is invisible to the wire snooper**, which only sees plaintext
port 53. With the `ebpf` feature, uprobes on the libc resolver entry points
(`getaddrinfo`, `gethostbyname` and friends) catch lookups through
systemd-resolved's stub and encrypted upstreams. Static binaries, non-libc
runtimes and applications doing their own DoH still match only by address,
port and executable.

**A process can influence which executable it is attributed to.** Attribution
reads `/proc/<pid>/exe` after the connection is seen, and a socket survives
`execve`, so a process can start a non-blocking connect, exec a different
binary, and retry until it wins the race.

- With **eBPF**, the kernel stamps the process's exec generation into the flow
  record at connect time, and the daemon refuses to name an executable whose
  generation has moved. A process that wins the race gets no executable at all
  and falls to the prompt or default verdict, rather than inheriting another
  binary's allow rule. It can still dodge an `exe`-keyed *deny* this way. One
  gap remains: attribution falls back to procfs when the flow record is gone,
  and the record lives in a fixed-size LRU that a process can try to flush.
  (Evicting the generation instead does not help; generations are unique
  timestamps, so any loss reads as a mismatch.)
- With **procfs only**, nothing closes the race. `exe`, `exe_glob` and
  `exe_sha256` are then scoping conveniences rather than a boundary.
- `cmdline_contains` and `parent_exe` are controlled by the process outright.

**Executable paths are checked against the host's own filesystem.** The kernel
reports `/proc/<pid>/exe` inside the process's own mount namespace, so a user
able to create one could mount their own binary over
`/usr/sbin/NetworkManager` and inherit its rules. The daemon resolves the path
through PID 1's root and reports it only if it reaches the file actually
running. Sandboxed services pass, and so do paths under a top-level directory
the host does not have at all, such as a Flatpak's `/app`. A container's
binary on the host network does not, nor does a deleted executable outside
PID 1's namespace: those connections carry no executable until the process
restarts.

**`app_id` is a cgroup name, which users choose.** Anyone can start a command
under a scope named like a Flatpak (`systemd-run --user --scope
--unit=app-flatpak-org.mozilla.firefox-99.scope ...`). It scopes rules the way
`cmdline_contains` does, and is useful because a sandboxed app's executable
path identifies neither a host file nor the app.

**Prompt context describes; it does not attest.** The parent-process chain is
read from `/proc` after the fact, and every path in it was chosen by processes
the prompting one may control. The denial count only covers the daemon's
in-memory history. Each part is left out rather than guessed when it cannot be
established.

**NEW is an observation.** The first-seen record is capped and written at most
once a minute, so an entry can be forgotten and flagged again; it keys on the
same identity a rule does, which a process can influence. Those errors all flag
something familiar, the harmless direction. The absence of a flag is weaker: it
can also mean the daemon is not tracking (`first_seen: null` in `--json`).
Exactly one event per program and destination carries the flag, so an alert
built on syslog export can miss it if the collector drops that line.

**eBPF struct offsets** come from the kernel's BTF. Without BTF the daemon uses
compiled-in x86_64 offsets, and if those are wrong it falls back to procfs.

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
                     status, rules,             prompt agent and
                     events, watch              windows, management
```

## Components

| Crate                  | What it is                                                              |
| ---------------------- | ----------------------------------------------------------------------- |
| `hallpassd`            | The daemon: nfqueue loop, rule engine, prompts, IPC server, attribution, DNS snooping |
| `hallpass-cli`         | Command line client: status, rule management, event stream, interactive watch |
| `hallpass-ui`          | egui desktop app: a prompt agent, prompt windows and a management window |
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
kernel, so a process that exits before its first packet is inspected still
attributes correctly; procfs races those and can come up empty. The eBPF
programs need a nightly toolchain (picked up automatically from
`crates/hallpass-ebpf/rust-toolchain.toml`, including `rust-src`) and
[bpf-linker](https://github.com/aya-rs/bpf-linker):

```sh
cargo install bpf-linker
cargo xtask build-ebpf                          # builds the kernel programs
cargo build --release --features ebpf -p hallpassd
# or both steps at once:
cargo xtask build
```

The `ebpf` feature embeds an object; it does not build one. It takes the
first it finds:

1. `HALLPASS_EBPF_OBJ`, if set, pointing at the object file.
2. `crates/hallpassd/prebuilt/hallpass-ebpf`, for a vendored or packaged
   object.
3. `target/bpfel-unknown-none/release/hallpass-ebpf`, what `cargo xtask
   build-ebpf` writes.

So a prebuilt object can be dropped in or pointed at, and the daemon
then builds on stable with no nightly and no bpf-linker. With none of
the three the build fails with these instructions rather than an error
from inside the embedding macro.

At load time the daemon reads the kernel struct offsets the programs
need (`sock_common`, `msghdr`) from the running kernel's BTF
(`/sys/kernel/btf/vmlinux`) and patches them into the object, so the
programs are not tied to one kernel version or architecture layout.
Kernels without BTF fall back to compiled-in x86_64 offsets. If no
object was compiled in, or the kernel rejects it, attribution falls back
to procfs; so does any individual flow eBPF cannot resolve.

## Installing

One command builds, installs, and starts everything:

```sh
./install.sh                          # eBPF attribution when the toolchain is present
HALLPASS_EBPF=1 ./install.sh          # require eBPF (fail instead of falling back)
HALLPASS_EBPF=0 ./install.sh          # force the procfs-only build (stable Rust)
HALLPASS_POSTURE=desktop ./install.sh # fail-open-on-crash config instead of the hardened one
```

It builds the release binaries as your user, then uses `sudo` (prompting
once) to install them to `/usr/bin`, drop the config and example rule into
`/etc/hallpass` (an existing `config.toml` is never overwritten), install the
systemd unit and desktop entry, autostart the prompt agent, add you to the
`hallpass` group, and `systemctl enable --now hallpassd`. When your session
is already in the group (any install after the first) it also starts the
agent, replacing one from an older build, so prompts work at once. After the
first install, log out and back in once so the group membership takes
effect.

It installs, as root, the binaries it just built in your checkout, so it is
exactly as trustworthy as the account that ran the build: anything running as
you between the build and the password prompt could have replaced them. Run
it from an account you trust, and never as `sudo ./install.sh`, which would
also run cargo and every dependency's build script as root.

Two things it does that are worth reading before you run it:

- **A fresh install starts from `etc/config.hardened.toml`.** Unmatched and
  unanswered connections are denied, transports the rule engine does not model
  are denied, and `queue_bypass = false` keeps enforcement up when the daemon
  is dead or its queue is full. `HALLPASS_POSTURE=desktop` writes
  `etc/config.toml` instead, which denies unmatched and unanswered connections
  just the same and allows the other two - fine for a desktop where you are at
  the keyboard to answer prompts and would rather a crashed daemon not take the
  network with it, wrong for anything unattended. Either way an existing
  `config.toml` is left exactly as you edited it, and either way the
  `20-system-*.toml` baseline rules go into `/etc/hallpass/rules.d` so a denied
  default does not leave the host without DNS, a clock or an address.
- **The `hallpass` group is full control of the firewall**, and the script
  adds you to it. A member can set `enforce = false`, lift a lockdown posture,
  delete any rule, or take the prompt-handler slot and answer allow. Add only
  accounts you would trust with that.
- **For anything that only needs to watch, use `hallpass-observer`.** The
  daemon serves a second socket, `/run/hallpass/observe.sock`, `0660
  root:hallpass-observer`, carrying the same protocol and the same answers as
  the control socket and refusing everything that changes anything: stats, the
  event stream and history, the rule list and hit counts, `explain`, and the
  config and lockdown state are served; rule edits, `config set`, lockdown
  changes, prompt replies, session grants and the prompt-handler slot are
  refused with an error naming what was refused. The installer creates the
  group empty and adds nobody, because a monitoring account is a deployment
  decision; add one with `sudo usermod -aG hallpass-observer <user>` and point
  the client at it with `hallpass-cli --socket /run/hallpass/observe.sock`.

  Read-only is not the same as harmless, and this is the part worth knowing
  before adding an account: the event stream describes *every* process on this
  host, root's included, and each event carries the executable path, the
  command line, the uid and the destination. A member can watch what everyone
  else on the box is running and talking to. That is what a network monitor
  is, but it is a real grant and it is not implied by "read-only".

  Which socket a client reached is the whole authorization decision, and the
  kernel makes it at `connect()`. It is not per-message uid checking, and that
  is not an implementation shortcut: `SO_PEERCRED` carries the peer's *primary*
  gid and never its supplementary groups, so a daemon holding an accepted
  connection cannot tell whether the peer is in a group the normal way.

Remove it again with `./uninstall.sh` (add `HALLPASS_PURGE=1` to also delete
`/etc/hallpass` and `/var/lib/hallpass`).

<details><summary>Manual install (what the script does)</summary>

```sh
install -Dm755 target/release/hallpassd  /usr/bin/hallpassd
install -Dm755 target/release/hallpass-cli /usr/bin/hallpass-cli
install -Dm755 target/release/hallpass-ui  /usr/bin/hallpass-ui
install -Dm644 etc/config.toml           /etc/hallpass/config.toml
install -Dm644 etc/rules.d/example-allow-dns.toml /etc/hallpass/rules.d/example-allow-dns.toml  # ships disabled

# Not optional under either shipped config: both deny what no rule matches,
# so without these the host boots with no DNS, no clock and no address.
# Install only the ones whose binary this host has, and check each path
# against the one /proc/<pid>/exe reports - the daemon matches `exe`
# exactly, and where /usr/sbin is a symlink to /usr/bin the rule as shipped
# would match nothing. `readlink -f` on the path in the file gives the one
# to write. A host running chrony, ntpd, systemd-networkd or dhcpcd instead
# needs a rule of its own for it, on the same pattern.
install -Dm644 etc/rules.d/20-system-resolved.toml      /etc/hallpass/rules.d/20-system-resolved.toml
install -Dm644 etc/rules.d/20-system-timesyncd.toml     /etc/hallpass/rules.d/20-system-timesyncd.toml
install -Dm644 etc/rules.d/20-system-networkmanager.toml /etc/hallpass/rules.d/20-system-networkmanager.toml

install -Dm644 etc/hallpassd.service     /etc/systemd/system/hallpassd.service
install -Dm644 etc/hallpass-ui.desktop   /usr/share/applications/hallpass-ui.desktop
# The prompt agent, started at login. Without it nothing takes prompts: the
# app-menu entry above opens the management window, which does not.
install -Dm644 etc/hallpass-ui-autostart.desktop /etc/xdg/autostart/hallpass-ui.desktop

# Optional: members of the "hallpass" group control the daemon; members of
# "hallpass-observer" reach the read-only socket and can change nothing.
groupadd -f hallpass && usermod -aG hallpass "$USER"
groupadd -f hallpass-observer

systemctl daemon-reload
systemctl enable --now hallpassd
```

</details>

Configuration lives in `/etc/hallpass/config.toml` (default verdict, prompt
timeout, queue number, socket path, rules directory).

A deny rule applies to established flows, not only to the next
connection. On every ruleset change (and on an observe-to-enforce flip)
the daemon deletes the conntrack entries of flows the changed ruleset
explicitly denies, so each one's next packet is judged as a new
connection and the rule catches it there. Flows the ruleset leaves
unmatched are never touched (a rule edit cannot cause a prompt storm),
observe mode kills nothing, and every kill is logged with the rule
behind it.

Best effort by design. Candidates come from the recent-decision history
(the newest 1024 decisions, kept since daemon start), so a flow older
than that window, or predating the daemon, keeps running until it ends;
a rule matching only by executable hash cannot identify flows to kill;
and a flow whose peer keeps transmitting can re-establish its conntrack
entry from the unfiltered inbound side before its next outbound packet,
surviving the kill until it goes quiet. `kill_established = false`
restores next-connection-only behavior.

`mode = "observe"` evaluates policy and records each decision without
applying it. Nothing is blocked: a rule that would deny is recorded as a deny
and the connection goes out anyway, and unmatched connections record
`default_verdict` and never prompt, because a dialog that changes nothing
would mislead.

It exists because what a policy will break cannot be read off the rule
files; it depends on what the host actually talks to. So the way to size a
rollout is to run in observe mode, watch `hallpass-cli top` and `hallpass-cli
events` for a while, fold what you saw into a reviewable ruleset with
`hallpass-cli suggest` (one proposed allow rule per executable, protocol,
port and destination, wildcarded where enough hosts share a suffix; the
output is a `rules export`-shaped document for `rules import`), and only then
enforce.

The GUI's tab bar has an **Enforce** switch that flips the mode at runtime,
lasting until the daemon restarts; the config file decides the mode it starts
in. The mode is visible in `hallpass-cli status`, in every event as an
unenforced verdict (a recorded block reads `WOULD-DENY`, never `DENY`), on
syslog export as `enforced="false"`, in a warning at startup, and as a banner
in the GUI. **It is not a security posture.** While it is on, this host is
not filtered.

Persistent rules are TOML files in `/etc/hallpass/rules.d/`, one rule per
file:

```toml
name = "allow-dns"
action = "allow"        # allow | deny | reject
duration = "forever"    # once | session | forever; the CLI also takes a
                        # timespan (30s, 5m, 2h, 1d) for a rule that expires
priority = 100
enabled = true
tags = ["core"]         # optional labels for selecting this rule in bulk;
                        # lowercase letters, digits, "-" and "_", starting
                        # with a letter or digit

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
# app_id = "flatpak:org.mozilla.firefox"   # packaged app: flatpak:<id> or snap:<name>
# domains_file = "/etc/hallpass/rules.d/ads.list"   # hosts format or one per line
# ips_file = "/etc/hallpass/rules.d/bad-ips.list"   # IPs/CIDRs, one per line
# hashes_file = "/etc/hallpass/rules.d/bad.sha256"  # exe SHA-256s, one per line
```

The directory is watched; edits apply without a restart. Unknown keys are
rejected: a file with a misspelled operand is skipped with a warning rather
than loaded with a wider match than you wrote.

Tags label a rule; they never match a connection. `hallpass-cli rules --tag
work` lists the set, and `hallpass-cli rules toggle --tag work off` disables
all of it as one change, so no connection is ever judged against half of it.
A rule already in the requested state is left alone, and a tag no rule
carries is an error from both commands: a typo fails loudly rather than
reporting an empty set. Tags are set when the rule is written: `rules add
--tag work`, the `tags` key in the file, or the Tags field in the GUI editor.

Because a tag cannot change what a rule matches, an unusable one never costs
a rule its enforcement: a rules.d file whose `tags` are misspelled, repeated
or over the cap still loads and filters, with the bad entries dropped and
named in the journal. `rules add`, an IPC add and the GUI editor reject a bad
tag outright instead, because there the cost is an error message rather than
a rule that stopped filtering.

**Adding a rule under an existing name replaces it wholesale**, which is how
a rule's tags are changed from the CLI - and also means everything else must
be restated. In particular a rule that was toggled off comes back enabled
unless the add passes `--enabled false`, and a `rules import` of a document
exported before tags existed strips the tags off every rule it restores. The
GUI editor loads the whole rule first, so saving from it preserves both.

The GUI's Rules tab has the same three operations: a TAGS column, a tag
picker that narrows the table, and Enable all / Disable all buttons that act
on the picked tag. The buttons appear only once a tag is picked, because they
act on the set rather than on whatever the table is showing.

### Lockdown

`hallpass-cli lockdown on --tag core` narrows the whole host to one set of
rules. While it is on:

- only allow rules carrying a pinned tag decide connections;
- **deny rules are never suppressed**, tagged or not, because a posture
  exists to permit less and suppressing a block would permit more;
- everything no surviving rule permits is denied **without a prompt**, since
  a dialog would let anyone at the keyboard answer their way out of the
  posture, and the rule that answer writes would carry no pinned tag;
- the daemon enforces regardless of the mode it was in, and the default
  verdict is deny, both restored exactly as you had them when it lifts;
- **loopback is exempt.** It never leaves the host, so refusing it would cost
  the resolver stub and every local service and buy nothing. A deny rule that
  covers loopback still applies, since denies are not suppressed.

The posture is persisted (`/var/lib/hallpass/posture.toml`, 0600) and re-read
at startup, so a package upgrade's restart does not silently lift it. It is
reported by `hallpass-cli lockdown`, in `status`, in `doctor`, and as a
banner in the GUI. Any member of the socket group can lift it, exactly as any
of them can delete a deny rule; both transitions are logged with the peer's
uid and pid.

Three things to know before relying on it. **Only new connections are
judged**, so everything already established keeps running: lockdown is not a
kill switch for open flows. **The verdict queue's fail-open flag is fixed at
startup**, so on the shipped `queue_bypass = true` default a kernel-side
queue overflow still accepts packets the posture would have denied; the flag
cannot be changed on a live queue without losing the packets already on it,
and `status` and `doctor` both report it. And **a locked-down host usually
cannot resolve names**: unless something pinned covers DNS, the resolver's
own upstream query is denied like anything else, and `domain` rules then stop
matching, because a connection only carries a domain when the daemon saw its
lookup. `lockdown on` prints what survives and warns when nothing pinned
covers DNS; it refuses outright when *no* rule survives, unless you pass
`--force`.

The one rule the installer drops in, `example-allow-dns.toml`, ships with
`enabled = false`. Matching on port and protocol alone would let every local
process send arbitrary UDP to port 53 on any host, a standard exfiltration
channel, so scope it (with `dest` or `exe`) before enabling it. Reinstalling
never overwrites it, so your edits survive upgrades. **If you installed
before this changed, check that file:** the old copy shipped `enabled = true`
and an upgrade will not touch it.

With `flow_accounting = true` the daemon also records how much each
connection moved. It joins the conntrack destroy multicast group and, as
each flow ends, reads the bytes and packets the kernel counted for it
(needs `net.netfilter.nf_conntrack_acct=1` and
`net.netfilter.nf_conntrack_events=1`), logs a line naming the executable
the flow was attributed to and how much it sent and received, and folds
the totals into `hallpass-cli status` (`flows accounted`, `flow bytes`,
`flow packets`). The group carries every conntrack teardown on the host,
so only flows matching a connection still in the daemon's decision history
are counted: the totals are hallpass-governed traffic, not whole-host
volume, and a hallpass flow whose decision has aged out of that short
history is missed. Observe-only: it reads notifications the kernel sends
anyway and never affects a verdict.

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
would not only cost logs under a default-deny posture, it would feed the
daemon its own tail: an unanswered UDP flow stays `ct state new`, so each
exported event would be decided as a new connection and emit the event that
produces the next datagram.

That exemption only reaches the daemon's own socket. With `kind = "local"`
on a host whose syslog daemon forwards to a collector over UDP (rsyslog's
`*.* @host`), the forwarded datagrams come from rsyslog, are judged like any
other connection, and each decision is logged and forwarded again: the same
loop, one hop longer. Give that forwarding its own rule and it still runs,
since allowed events are exported too. Point `[syslog.target]` at the
collector directly instead, or filter hallpassd's messages out of what the
local syslog daemon forwards.

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
hallpass-cli suggest --exe firefox > proposed.toml   # propose rules from history
hallpass-cli run -- ./build.sh             # one-off grant for a command and its children
hallpass-cli sessions                      # grants open right now
```

`run` is for the command you are about to run once: while it runs,
connections from it and everything it spawns that no rule matches are
allowed instead of prompting, and the grant ends when it exits. It is the
alternative to a permanent allow rule for a build, an installer or a test
suite, and to answering forty prompts for one of them. Events allowed this way
name the grant (`run-session:7`) instead of a rule, so they show in `events`,
`top`, syslog and the GUI like any other decision, and `suggest` leaves them
out of the rules it proposes.

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
verified against `/proc`, and `--exe-sha256` must be supplied when a
hash-pinning rule is in play, since the daemon will not hash a path a client
named for it.

`rules --stats` adds hit counts and a last-hit time to the listing, which is
how a rule that never matches anything becomes visible. Counts are per rule
name and survive a rules-directory reload, so editing one file keeps its
history; they reset on daemon restart, because this answers "is this rule
doing anything", not "what happened last month".

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

Connections carry whether they are the first the daemon has seen from an
application, and the first that application has made to a destination. A
prompt shows a **NEW** badge and says which of the two it is, `events` marks
the line `new=app`, `new=dest` or `new=app,dest`, and syslog export carries a
`first_seen` field. It is an annotation, never a verdict: the record behind
it is bounded and lossy in one direction only, so a forgotten application
reads as new a second time rather than a familiar one going unflagged. The
record is a list of applications and the destinations they reached, in
`/var/lib/hallpass/seen.toml` (root-only, rewritten at most once a minute);
`first_seen = false` in the config turns it off and writes nothing.

A prompt also carries what the daemon can find out about the process beyond
the connection itself, which neither `events` nor export shows because only a
prompt has someone to inform: what launched it (its ancestors' executables,
nearest parent first), its executable's SHA-256, and how often decisions
still in the daemon's history said no to this same application. Loudest of
the four, when it appears: **the names of enabled rules this binary fails
only on the executable hash**. That is a rule written for this program at
this destination whose pinned hash the running binary does not have, exactly
what `exe_sha256` is bought to catch; without it the operator sees only an
unexplained prompt for something they had already made a rule about. Each
part is best effort and absent on its own: a process can exit between the
packet and the prompt, and the history is bounded and lost on restart, so a
count of zero means "nothing in what is still remembered", not "never". The
hash is computed while deciding the packet, so it is the value policy was
evaluated against; with no hash there is no mismatch to report, and the
warning stays silent rather than accusing a binary nobody hashed.

That hash is also what **"Pin binary"** writes. A rule generated from a
prompt is keyed on the executable's path, and a path is not an identity: an
allow granted to something under a home directory, a build tree, or anywhere
else you can write yourself keeps matching after anything at all is written
there. Ticking the box (or answering the pin question in `hallpass-cli
watch`) adds `exe_sha256` to the rule, so it stops matching the moment that
file is replaced and the connection is asked about again. It is offered only
on an allow - a deny should keep blocking whatever is put at that path - and
only when the prompt actually carries a hash. A reply asking to pin one that
does not creates no rule at all rather than the broader unpinned rule, which
would look identical in every listing.

The GUI (`hallpass-ui`) is three kinds of process from one binary. The
**prompt agent** (`hallpass-ui agent`, autostarted at login) draws nothing:
it holds the daemon's prompt-handler role, the tray icon and the desktop
notifications, and opens a **prompt window** for each application with
connections waiting (allow/deny, scope, duration). The **management window**
(`hallpass-ui`, from the app menu or the tray) is an ordinary client for
rules, live events, statistics and settings. It takes no prompts itself, but
opening it starts the agent when nobody holds the prompt-handler role, and
it shows a banner only when that cannot work, saying why (usually: log out
and back in so the `hallpass` group takes effect). Only one client at a time
can hold the role.

Deny leads a prompt window's keyboard traversal, and closing the window
denies every connection it was showing rather than leaving them to the
timeout: dismissing a decision is a decision, and it is the one the operator
can undo. The deny is `Once`, so it writes no rule. A prompt that arrived as
the window was being closed was never on screen, so it goes to a fresh window
instead. A prompt window that dies without answering denies what it held,
once. Allow only answers once a prompt has been at the front of its window
for a moment, so a click or keypress aimed at whatever was there before it
cannot approve it. At most eight prompt windows are open at once; prompts
for further applications wait for one to close, and one that times out
still waiting takes the default verdict like any unanswered prompt.
Quitting the agent denies the prompts on screen, as closing their windows
would, and leaves those still waiting to the same default at their
deadline, unless an agent started before then shows them.

Every hallpass window runs on native Wayland whenever the session has it,
even with `DISPLAY` set. Under XWayland any client of the X server can
synthesize input (XTest) into another X window, including a sandboxed
application given the X11 socket but not the hallpass socket, and that was
shown to answer live prompts. A Wayland client cannot reach another client's
surfaces, and GNOME and KDE keep input injection privileged. wlroots-based
compositors such as Sway offer their virtual keyboard and pointer to any
client unless a sandbox's security context filters them, and there a client
can still type into whichever window has focus. The cost is that nothing
hallpass draws can stay on top of other windows on Wayland, and whether a new
prompt window takes focus is the compositor's call (GNOME gives it): the
window asks for the operator's attention, and the notification is the
interrupt. On a session with X11 alone the GUI runs there and logs a
warning; every X client can already inject into every window on such a
session, a terminal running sudo included, and no single application
changes that. The prompt windows talk to the agent over a socket pair it
hands them at startup, so nothing listens for answers anywhere: only a
window the agent started can answer.

The management window reads as a status surface: the mark in its top-left
corner carries the same colour as the tray icon (green enforcing, amber
observing, red under a lockdown posture, grey until the daemon has said),
verdicts are colour-coded everywhere they appear, and the event feed carries
a strip of the last few minutes so a burst of denies is visible without
reading rows. `Ctrl+1` to `Ctrl+5` switch tabs, `Ctrl+F` jumps to the filter,
and the All/Allowed/Blocked lens beside it narrows the feed and the Traffic
tab by outcome - "Blocked" includes the decisions observe mode recorded
without applying, which are the ones worth looking at on an unenforced host.

## Security model

**The enforcement guarantee in one sentence: a live daemon passes only what a
rule allows or an operator approves, and a dead one passes everything.** Those
are two different axes and they fail in opposite directions deliberately.

`default_verdict = "deny"` is the policy axis. A connection no rule matches and
no operator answers is denied, and that covers more than an ignored prompt: a
host with no GUI and no `hallpass-cli watch` attached, the window between boot
and login, a handler that crashed, and both held-packet budgets. Anything
needing the network before a human can answer therefore needs a rule, which is
what the `20-system-*.toml` files in [`etc/rules.d`](etc/rules.d) are for.
Allowing in those states made the tool stop working silently, and one of them
is reachable by anything that can crash the handler.

Queue `bypass` is the liveness axis, and it still fails open: if the daemon
dies the kernel passes traffic rather than bricking the network. Set
`queue_bypass = false` to close that too, which is what
[`etc/config.hardened.toml`](etc/config.hardened.toml) does, along with denying
the protocols rules cannot model. The residual gap is an attacker with root,
who can delete the nftables table outright.

- **Fail-open when the daemon dies**: the NFQUEUE verdict rule uses the `bypass` flag,
  so if the daemon dies traffic flows unfiltered instead of bricking the
  network. On clean shutdown and on panic, the nftables table is removed.
  This is an availability-over-enforcement tradeoff; set
  `queue_bypass = false` to invert it and have new connections dropped
  whenever no live daemon is deciding them (daemon dead, queue full). In
  that mode a panic deliberately leaves the table up, so enforcement holds
  until the daemon restarts; clean shutdown still removes it. The DNS snoop
  queues always keep `bypass`: they are observe-only, and dropping DNS with
  the daemon gone would cost availability without adding enforcement.
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
  process choosing its own DNS.** Both snoopers record what was resolved,
  and a process chooses what it resolves: it can query a server of its own,
  or point its own libc at one (`LOCALDOMAIN`, `RES_OPTIONS` and a search
  domain it controls), and have *any* name, not only one it owns, answered
  with any address. The cache keeps one domain per address, so the last
  resolver of an address wins, for every process on the host. Scope
  security-relevant rules with `exe`/`exe_sha256` or IP/CIDR criteria
  rather than domain alone.
- **An allowed UDP flow can be borrowed.** Only a flow's first packet is
  judged; later packets that match its conntrack entry are not. UDP has no
  connection to close, so once a process closes its socket, another one can
  bind the same local port and keep sending to the same destination inside
  the entry the first one was allowed, refreshing it as it goes. Local
  ports are visible in `/proc/net/udp`. This is what judging new
  connections means, and it matters most for a broad allow such as a
  resolver's port 53 to anywhere.
- **Rule files**: files in `rules.d` are ignored (with a warning) unless owned
  by root (or the daemon's own euid) and not group/other writable. Symlinks
  are skipped, and the ownership check and the parsed bytes come from the
  same file descriptor, so the file that was checked is the file that is
  read. Match-list files get the same ownership check on the same
  descriptor, but a root-written rule may reach its list through a symlink;
  a list path sent over IPC must resolve into `rules.d` and is stored
  resolved, so a client cannot re-aim it later.
- **Policy directories**: the daemon checks that `/etc/hallpass` and the
  rules directory are root-owned and not group/world-writable, warns at error
  level when they are not, and refuses to start under `queue_bypass = false`.
  The per-file checks above are worth nothing without it: unlinking a file
  needs write permission on the *directory*, not on the file, so on a
  group-writable `rules.d` any member of that group can delete root's deny
  rules without ever touching a file those checks would look at - and a
  vanished rule file is an ordinary delete, so nothing is skipped, nothing is
  counted, and the shrunken set is applied as policy. A sticky directory is
  accepted, because `t` takes exactly that power back. `hallpass-cli doctor`
  reports the same check as `policy-dirs`.
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
  `@system-service` plus `bpf` and `perf_event_open`, minus
  `process_vm_readv` and `process_vm_writev`. `SYS_PTRACE` is what passes
  the kernel's ptrace access check on `/proc/<pid>/exe` for other users'
  processes. The `ptrace` syscall stays outside the filter, but the same
  check also opens `/proc/<pid>/mem` for writing, which no filter can
  refuse, so a compromised daemon can still write into other processes:
  the capability is needed, and it is not harmless. `DevicePolicy=closed`
  keeps raw disks out of reach and `LimitNOFILE` gives attribution room to
  keep opening `/proc`. `CAP_SYS_ADMIN` is
  deliberately excluded, which costs annotation, never enforcement: on
  kernels older than 5.8, where `bpf()` requires it, eBPF attribution falls
  back to procfs and logs why; and on kernel lines whose uprobe perf PMU
  demands it (kprobes accept `CAP_PERFMON`), the libc-resolver DNS snoop is
  unavailable under the unit and logs why. The wire snooper still covers
  plaintext port 53 there, so the loss is names resolved through a stub
  resolver or an encrypted upstream. Both are restored per host by a
  `systemctl edit hallpassd` drop-in re-adding `CAP_SYS_ADMIN`; the unit
  file shows the exact lines.
- **Config file trust**: the config is read under the same ownership and
  permission policy as rule files. It sets `default_verdict`, `queue_bypass`,
  and the rules directory, so it is the most security-relevant file on disk.
  A `--config` path that does not exist is fatal rather than silently
  replaced by the built-in defaults, which deny unmatched connections and so
  would enforce a policy naming none of the rules the operator meant to load.
- **Session grants (`hallpass-cli run`) cover a process tree, one user, and
  only what would have prompted.** The daemon roots the grant at the wrapper
  process using the IPC socket's peer credentials, so a client cannot open
  one over someone else's processes, and membership is the connecting
  process's `(pid, start time)`-guarded ancestry up to that root. What this
  means in practice:
  - **An explicit rule always wins.** The grant is consulted only where a
    connection would otherwise raise a prompt, so a deny rule still denies
    inside a session.
  - **Same user only.** A `sudo` step inside a session runs as another user
    and prompts as usual.
  - **Anything the session spawns is covered**, including a descendant that
    daemonizes: the wrapper sets `PR_SET_CHILD_SUBREAPER`, so an orphan
    reparents onto it rather than past it. That is the grant's definition,
    not a gap - if you would not trust the command's children, do not wrap
    it. What a session cannot do is widen itself: every failure direction
    (no pid, uid mismatch, an ancestry chain that cannot be walked, a depth
    past 32 hops, a session that has ended) resolves to a prompt.
  - **The grant ends with the wrapper**, because the daemon ties it to the
    IPC connection - `kill -9` on the wrapper ends it too. Connections
    *already established* under a grant survive it, since only `ct state
    new` is judged.
  - **`run-session:` is a reserved rule-name prefix**, refused when a rule
    is compiled - which covers both the control socket and rule files on
    disk - so a rule cannot impersonate a grant in the event stream.
  - **Sessions are capped per user** (8) as well as host-wide (64), so one
    member of the `hallpass` group cannot hold every slot and stop everyone
    else's `run` from starting.
  - **A grant-allowed connection still counts as a sighting** for
    first-seen highlighting, exactly as an allow *rule* would: the event it
    emits carries the `first_seen` flag, so a later prompt for the same
    application will not repeat it. If you want a program's first contact to
    reach a prompt, do not introduce it inside a session.
- **No unsafe code** in the userspace crates (`#![deny(unsafe_code)]`
  workspace-wide; the eBPF crate is the exception by nature).

## Limitations

- **DoT / DoH are invisible to the wire snooper**: it only sees names
  resolved through plaintext UDP port 53. With the `ebpf` feature the daemon
  also snoops the libc resolver entry points (`getaddrinfo`, the
  `gethostbyname` family, and their reentrant `_r` variants) via uprobes,
  which catches resolutions through systemd-resolved's stub and encrypted
  upstreams as long as the process uses the system resolver. Statically
  linked programs, non-libc runtimes, and apps doing their own DoH still
  match by IP/port/exe only.
- Only new connections (`ct state new`) are evaluated; established flows are
  never re-checked.
- **"NEW" is an observation, not a claim about the past.** The first-seen
  record is capped, so an application or destination that falls out of it is
  reported new again; it is written at most once a minute, so a hard power
  loss forgets the last minute of it; and it keys on the same identity a rule
  would (executable plus `app_id`), which a process can influence for the same
  reason it can influence that rule. Every one of those errs toward flagging
  something familiar, the harmless direction. The absence of a flag is the
  weaker signal: it can also mean the daemon is not tracking, which
  `--json`'s `first_seen: null` distinguishes and a text line does not.
  Resolver queries are deliberately not annotated, since a new program's DNS
  lookup would otherwise spend its first sighting on a packet nobody judges.
  And because the record is written as it is reported, exactly one event per
  application and destination ever carries the field: syslog export is an
  ordinary event subscriber, so a lagging or unreachable collector can lose
  that line, and an alert built on it will miss that first contact.
- **Prompt context describes, it does not attest.** The ancestry a prompt
  shows is read from `/proc` after the fact, so a process reparented to init
  the moment its parent exited has no launcher left to name, and every path
  in the chain was chosen by a process this one may control: "what started
  this" is worth reading and is no more a claim than `cmdline` is. The
  executable hash carries the caveat below about which executable a process
  is attributed to. The denial count is bounded by the daemon's in-memory
  history and lost on restart. Each part is absent rather than approximated
  when it cannot be established, so a prompt showing none of them means the
  daemon could not find out more, not a clean bill of health.
- **A process can choose which executable it is attributed to; the eBPF
  attributor narrows this rather than closing it.** Attribution resolves the
  executable from
  `/proc/<pid>/exe` after the connection is observed, and a socket descriptor
  survives `execve`. So a process can start a non-blocking `connect()` (or
  send a UDP datagram), immediately exec a different binary, and be
  attributed to that binary instead; it can retry until it wins the race.

  With the `ebpf` feature the kernel side stamps the process's exec
  generation into the flow record at connect, and the daemon refuses to name
  an executable whose generation has moved since. A masquerade that wins the
  ordinary race therefore does not inherit the other binary's allow rule: the
  connection carries no executable at all and is decided by the prompt or the
  default verdict instead. What it still costs is the honest name - an `exe`
  rule that *would* have matched the program that really connected does not
  match either, so a deny rule keyed on `exe` can still be stepped out of,
  and a connection that would have been quietly allowed now asks. Both
  failures are visible; neither hands out an identity.

  One way around it remains, and it needs more of the attacker than the plain
  race: attribution falls back to procfs whenever the eBPF flow record is
  missing, and that record lives in a fixed-size LRU, so a process that can
  evict it puts its connection back on the path that has no generation to
  compare. Evicting the *generation* is not a second way in - generations are
  unique timestamps and never zero, so an entry that is lost and recreated
  cannot land back on a value an earlier connect already stamped, and every
  loss reads as a disagreement.

  On the procfs path nothing closes this at all, because resolving `/proc`
  after the fact is what that path is. Rules keyed on `exe`, `exe_glob`, or
  `exe_sha256` are therefore a boundary only as strong as the attributor
  underneath them, and a scoping convenience without eBPF. The same caveat
  applies for a different reason to `cmdline_contains` and `parent_exe`,
  which a process controls outright.
- **An executable path is only reported when it names the host's file.** The
  kernel spells `/proc/<pid>/exe` inside the process's own mount namespace,
  so a user who can create one could mount their own binary over
  `/usr/sbin/NetworkManager` and inherit its rules. The daemon resolves the
  path through PID 1's root and reports it only when that reaches the inode
  being run. Sandboxed services pass, since their namespaces narrow the
  host's view without replacing its files. So does a path under a top-level
  directory the host does not have at all, such as a Flatpak's `/app`: no
  host rule can name it, and it is exactly as trustworthy as the `app_id`
  beside it (see below). A process on the host's network whose executable is
  a file inside a container does not, and neither does
  a deleted executable in any namespace but PID 1's (a sandboxed service
  still running a binary a package upgrade replaced): those connections
  carry no executable, so `exe` rules cannot match them and they prompt or
  take the default verdict until the process restarts.
- **`app_id` names a cgroup, and a user names their own cgroups.** The
  packaged-application identity comes from `/proc/<pid>/cgroup`, which is
  whatever the launcher called the scope it started the process in. Any
  unprivileged user can start a command under a scope of their choosing
  (`systemd-run --user --scope --unit=app-flatpak-org.mozilla.firefox-99.scope
  ...`), so `app_id` scopes rules the way `cmdline_contains` does and is not a
  boundary. It is worth having because a sandboxed application's executable
  path resolves inside its sandbox: it names neither a file on this host nor
  the application uniquely, which is what left those connections hard to
  scope at all.
- **Only the `output` and `input` hooks are filtered, so a container host is
  unfiltered for everything inside it.** Traffic this machine *forwards*
  rather than originates - which is what containers, VMs, and other network
  namespaces bridged to the host produce - traverses the `forward` hook,
  reaches no verdict queue, and is not matched against any rule. Not a
  weakened check: those packets are never seen. A Docker host running
  hallpass polices the daemon and the CLI on the host itself and nothing in
  any container.

  This is a scope decision rather than an unfinished one, and the reason is
  attribution. Every attributor here resolves a *local process* - `/proc/<pid>`,
  socket inodes, the eBPF connect kprobes - and a forwarded packet has no
  local process at all, so every `exe`, `exe_glob`, `exe_sha256`, `app_id`,
  `cmdline_contains` and `user` operand is inapplicable to it. What is left is
  tuple matching, which is a different product with a rule model of its own,
  and it cannot ship on by default either: a `forward` base chain feeding the
  verdict queue under the shipped `default_verdict = "deny"` would
  black out every container on the host, with no prompt possible because
  there is no process to name in one. Filter forwarded traffic with an
  nftables `forward` chain of your own; hallpass will not fight you for it.

  `hallpass-cli doctor` reports `forwarding` as a warning on any host that has
  it enabled, naming the interfaces and this host's bridges, so the limitation
  is delivered to the operators it applies to instead of waiting to be read
  here. It reads the whole `conf/<iface>/forwarding` tree rather than
  `net.ipv4.ip_forward` alone, because the global knob is only an alias for
  `conf/all` and the kernel consults the arrival interface's own.
- Rules only model TCP and UDP. UDP-Lite, which any process can use in place
  of UDP, is always denied: it cannot be judged as UDP, because its ports are
  a separate space and attribution would name whichever program holds the
  same UDP port. Other transports (SCTP, ICMP, ...) are not matched against
  rules; they are counted and resolved by the
  `unhandled_proto_verdict` policy (`allow` by default, `deny` in the
  hardened config). Packets conntrack cannot place (`invalid`, `untracked`)
  are never new connections and never reach the daemon; when that policy is
  not `allow` and the daemon starts enforcing, the table drops them
  outright, since a process with `CAP_NET_RAW` can otherwise carry a whole
  conversation in them. IPv6 neighbour discovery and MLD, which conntrack
  leaves untracked by design, are let through.
- **UDP verdicts are per flow once the peer answers.** A UDP flow stays
  `ct state new` until a reply is seen, so every datagram of an unanswered
  flow reaches the queue and is decided (and logged) on its own; from the
  first reply on, the flow is established and its verdict covers the rest
  of it until the conntrack entry expires. A `Once` prompt reply therefore
  means "this flow" for an answered UDP flow (as it means "this connection"
  for TCP): the held datagram is released with the verdict, no rule is
  persisted, and a genuinely new flow to the same destination prompts
  again. A peer that never answers is asked about again per datagram.
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

GPL-3.0-only. The desktop UI bundles the Inter typeface, under the SIL Open
Font License 1.1; see [crates/hallpass-ui/assets/fonts](crates/hallpass-ui/assets/fonts).

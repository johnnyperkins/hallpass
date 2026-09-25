# Changelog

What an upgrade changes on a running host; commit bodies carry the reasoning.

## Unreleased

The wire protocol is now v17. Daemon, CLI and UI must be upgraded and
restarted together; a version mismatch is refused at connect.

### Added

- **Read-only socket.** `/run/hallpass/observe.sock` (`0660
  root:hallpass-observer`) serves stats, events, history, rules and hit
  counts, `explain`, and config and lockdown state, and refuses every change.
  Use it with `hallpass-cli --socket /run/hallpass/observe.sock`. Members still
  see every process's executable, command line, uid and destination.
  Upgrade: reinstall the unit (`/run/hallpass` moves from 0750 to 0751; the old
  unit leaves the socket unreachable), then add accounts with `sudo usermod
  -aG hallpass-observer <user>`. `install.sh` now ends with `systemctl restart
  hallpassd`, so re-running it over a live install actually loads the new
  binaries.
- **Pin a prompt answer to the binary (wire v17).** "Pin binary" in the GUI,
  or the pin question in `hallpass-cli watch`, adds the executable's SHA-256 to
  the rule, so it stops matching once the file is replaced. Offered only on an
  allow and only when the prompt shows a hash.
- **Policy directory ownership check.** `/etc/hallpass` and the rules
  directory must be root-owned and not group/world writable (sticky
  directories are accepted). A failure is logged at error level, is fatal under
  `queue_bypass = false`, and shows in `hallpass-cli doctor` as `policy-dirs`.
- **Exec-after-connect guard (`ebpf` feature).** A process that execs after
  starting a connection gets no executable instead of the new binary's
  identity, so it prompts or takes the default verdict. Attribution that falls
  back to procfs is not covered. Upgrade: rebuild the eBPF object; an old one
  fails to load.
- **Verdict queue length set to 4096 (wire v16).** Previously the kernel
  default of 1024. `status`, `doctor` and the GUI show the length beside the
  live depth; if the kernel refuses, the daemon logs it and keeps the default.
- **`hallpass-cli lockdown on --tag core` (wire v15).** While on, only allow
  rules with a pinned tag decide, everything else is denied without a prompt,
  and the daemon enforces whatever its mode. Deny rules and loopback are
  unaffected, and only new connections are judged. The posture persists in
  `/var/lib/hallpass/posture.toml` across restarts; lifting it restores every
  rule as it was. `lockdown on` warns when nothing covers DNS and refuses when
  no rule survives, unless given `--force`.
- **Rule tags (wire v14).** `tags = ["work"]` in a rule, `rules add --tag`,
  `hallpass-cli rules --tag work`, and `rules toggle --tag work off` to flip a
  set in one change. The GUI Rules tab gets a TAGS column, a tag picker and
  Enable all / Disable all. Tags never match connections. Upgrade: files this
  version writes carry `tags = []`, which an older daemon refuses, so remove
  those lines before downgrading. Re-adding a rule restates it wholesale (pass
  `--enabled`), and importing a pre-tags export drops tags.
- **`hallpass-cli run -- <cmd>` (wire v13).** Unmatched connections from the
  command and its children are allowed until it exits, including on `kill -9`.
  Explicit rules still decide, coverage is limited to the opening user, and
  allowed connections show `run-session:<id>`. `hallpass-cli sessions` lists
  open grants, and `suggest` ignores their traffic.
- **Richer prompts (wire v12).** Prompts in the GUI and `hallpass-cli watch`
  show the process's ancestors, its executable's SHA-256, how many recent
  decisions denied the same application, and any enabled rule it fails only on
  `exe_sha256`. Each field is best effort, and none of it appears in `events`,
  `--json` or syslog.
- **First-seen flags (wire v11).** Connections carry whether the application,
  and the application-to-destination pair, is new to the daemon's record: a
  NEW badge in the GUI, a line in `watch`, `new=app,dest` in `events`, and a
  `first_seen` field in `--json` and syslog. On by default, stored in
  `/var/lib/hallpass/seen.toml`; `first_seen = false` turns it off. Upgrade:
  re-run `install.sh` so the unit gets its `StateDirectory`, or the record is
  kept in memory only.
- **Flatpak and Snap application identity (wire v10).** Connections carry
  `flatpak:<id>` or `snap:<name>` from the process's cgroup, and rules gain an
  `app_id` operand (`rules add --app-id`, `explain --app-id`, GUI editor).
  Allows written from prompts, traffic rows or `suggest` pin it. It is not a
  boundary; pair it with `exe` or `exe_sha256`.
- **Flow accounting (wire v9).** With `flow_accounting = true`, each ended flow
  is logged with its executable and bytes, and `status` and the GUI show
  totals for hallpass-governed traffic. Needs
  `net.netfilter.nf_conntrack_acct=1` and `nf_conntrack_events=1`. Off by
  default; never affects a verdict.
- **`hallpass-cli suggest`.** Proposes narrow allow rules from recent allowed,
  attributed traffic as a `rules export` document for review and `rules
  import`. Applies nothing; `--exe` narrows to one application, capped at 200
  rules.
- **Table flush count in `status` (wire v8).** `nft_flushes` and the time of
  the last one appear in `status`, the GUI and a `doctor` warning. It counts
  detections, not successful repairs.
- **Deny rules reach established flows (`kill_established`).** On a ruleset
  change or observe-to-enforce flip, the daemon deletes conntrack entries of
  recent flows the new ruleset denies, so their next packet is judged again.
  Best effort: only the newest 1024 decisions are candidates, and hash-pinned
  rules cannot select flows. Opt out with `kill_established = false`.
- **`hallpass-cli doctor`.** Checks daemon reachability and wire version,
  queues and drop counters, observe mode, a missing prompt handler, socket
  permissions, group membership, the nftables chain (root only), kernel BTF,
  and host forwarding (routed traffic is not filtered). Exits non-zero when a
  check fails.
- **Kernel queue counters in `status` (wire v7).** Drops, delivery failures and
  depth for the verdict and DNS snoop queues, plus each queue's fail-open flag.
  On a fail-open queue a nonzero drop count means the flag did not take. An
  unreadable counter shows `unavailable`.
- **`hallpass-cli config`.** Shows and sets `prompt_timeout_secs`,
  `default_verdict` and enforce/observe mode at runtime (`config set --timeout
  N --default deny --observe|--enforce`). Changes last until restart;
  `--observe` requires `--yes`.
- **Tray icon.** The prompt agent shows a StatusNotifierItem icon (stock GNOME
  needs the AppIndicator extension) that distinguishes enforcing, lockdown,
  observe mode and waiting for the daemon. Quit denies on-screen prompts once
  and releases the prompt-handler slot. The management window is one per user
  and socket.

### Changed

- **Unmatched connections are denied by default.** `default_verdict` now ships
  and defaults to `"deny"`, which also applies with no prompt handler attached,
  before login, and when a held-packet budget is spent. `queue_bypass` still
  ships `true`. Upgrade: a config that omits `default_verdict` flips to deny;
  one that states `"allow"` keeps it.
- **Baseline rules for boot-time daemons.** `20-system-resolved.toml`,
  `20-system-timesyncd.toml`, `20-system-timesyncd-dns.toml` and
  `20-system-networkmanager.toml` ship enabled at priority 20, each scoped to
  its binary, so a deny default still boots with DNS, time and an address.
  `install.sh` installs each only when its binary exists, with the path
  canonicalized, and keeps local edits or deletions across reinstalls.
- **LLMNR is denied by default.** `20-deny-llmnr.toml` blocks port 5355 for
  any executable. Delete it if you rely on LLMNR, or set `LLMNR=no` in
  `/etc/systemd/resolved.conf`. mDNS (5353) is not covered and will prompt.
- **`install.sh` writes the hardened config on a fresh install** (deny
  default, unmodelled transports denied, `queue_bypass = false`).
  `HALLPASS_POSTURE=desktop ./install.sh` keeps the permissive config. An
  existing `/etc/hallpass/config.toml` is never replaced.
- **Prompts wait 30 seconds by default, up from 15.** The hardened profile
  stays at 10. Upgrade: an existing config keeps its `prompt_timeout_secs`.
- **The desktop profile holds 128 pending prompts, up from 64.** Past the cap a
  connection takes the default verdict without a prompt.
- **The GUI is a windowless agent plus separate windows, on native Wayland.**
  `hallpass-ui agent` (autostarted) holds prompts, tray and notifications and
  opens one prompt window per application; `hallpass-ui` opens the management
  window. On Wayland, prompt windows cannot stay on top. Upgrade: `--hidden` is
  gone, so a `~/.config/autostart` copy that passes it starts nothing.
  `install.sh` replaces the autostart entry and restarts a running UI when the
  installing session is in `hallpass`.
- **GUI redesign.** Colour verdict chips, an activity strip, per-row
  allowed/blocked bars, headline stats, and a state-coloured mark and window
  icon. Prompts get segmented pickers, a colour countdown, and `Esc` to deny
  once. New keys: `Ctrl+1`-`Ctrl+5` for tabs, `Ctrl+F` for the filter; an
  All/Allowed/Blocked lens and sortable traffic columns. Always dark.
- **Executable paths are checked against the host's file.** A process whose
  `/proc/<pid>/exe` path holds a different file on the host (private mount
  namespace, host-network container) gets no executable. A sandboxed service
  running a deleted (upgraded) binary loses its `exe` rules until restarted.
- **UDP-Lite is always denied**, whatever `unhandled_proto_verdict` says.
- **When enforcing with `unhandled_proto_verdict` other than `allow`, the
  table drops `invalid` and `untracked` packets** (IPv6 neighbour discovery and
  MLD excepted). Decided at startup.
- **A rule `domain` no name can equal is refused**: Unicode (use `xn--`), `*`,
  `*example.org`, empty labels. A trailing dot is ignored.
- **Equal-priority rules order reject and deny before allow**, then by name.
- **Prompt-written rules carry the protocol for a port answer, and the uid on
  an allow**, so another account's connections no longer share them.
- **GUI Allow works only after the prompt has been in front for 700ms**; Deny
  is immediate. `hallpass-cli watch` ignores input within 700ms of a new
  prompt.
- **IPC sockets hold at most 64 connections, 16 per uid**, and close one that
  sends no Hello within 10 seconds.
- **The unit sets `DevicePolicy=closed` and `LimitNOFILE=16384` and refuses
  `process_vm_readv`/`process_vm_writev`.** Upgrade: reinstall the unit.
- **`rules export` names any rule it altered for display**, on stderr and in a
  header comment.
- **The installer and docs state what `hallpass` group membership grants**:
  disabling enforcement, lifting lockdown, deleting rules, taking the prompt
  slot. See [docs/security.md](docs/security.md).
- **`exe_glob` wildcards no longer cross `/`.** `*` and `?` stop at a path
  separator; use `**` for a subtree. Upgrade: `/opt/vendor/*` now matches one
  level only, which silently narrows deny rules; change such patterns to
  `/opt/vendor/**`. Audit with:

  ```sh
  hallpass-cli --json rules | \
    jq '.[] | select(.match.exe_glob) | {name, action, glob: .match.exe_glob}'
  ```

  The daemon logs a hint for any glob ending in `/*`.

### Fixed

- **Concurrent rule changes could leave a stale ruleset enforced.** Two
  overlapping rebuilds could store the older one last, so a just-added deny
  was missing, or a just-deleted rule still applied, until the next change.
- **A lost sock_diag reply could stall every verdict.** Lookups now time out
  after 50ms and fall back to reading `/proc/net`.
- **Connections could pass unjudged when the queue socket buffer filled.** The
  snoop queue now has its own socket, and only replies to this host's DNS
  queries are snooped.
- **A burst of refused verdicts stopped the daemon**, leaving a fail-open host
  unfiltered.
- **The exec-race guard missed UDP from unbound sockets and hash-only rules.**
- **A hash could be taken of a file the process was not running.**
- **A list path added over IPC could be re-aimed through a symlink**, and a
  FIFO no longer hangs startup.
- **A denied DNS query still armed the snoop tracker.** One answer caches at
  most 32 addresses, and a numeric name no longer overwrites a cached domain.
- **A dead prompt path allowed every unmatched connection, and held packets
  were accepted at exit**; both now take `default_verdict`.
- **The table was replaced in two steps**, leaving a gap with no filtering.
- **A client that stopped reading replies could pin hundreds of megabytes** in
  the daemon.
- **Syslog export escaped only C0 controls**; all display hazards are now
  neutralized and field caps count bytes.
- **The GUI and `hallpass-cli top` could lose their place in the stream**,
  emptying the prompt slot.
- **`hallpass-cli watch` printed a process's whole command line.**
- **`max_pending_prompts` above 512 is rejected at config load.** Larger
  values silently lost prompts on handler reconnect. Upgrade: a config setting
  it higher now fails validation at startup.
- **Growing a binary during hashing could stall packet decisions.** The read
  is now capped.
- **Executables were hashed for connections that never prompt**, such as in
  observe mode; the hash is now computed only when a prompt is raised.
- **RUSTSEC-2026-0257** (`webbrowser` argument injection) in the GUI's
  dependencies.

# Rules

Every new connection is checked against the rules, highest priority first, and
the first match decides. A connection nothing matches becomes a prompt, or
takes `default_verdict` when nobody answers.

## The rule file

Persistent rules live in `/etc/hallpass/rules.d/`, one TOML file per rule:

```toml
name = "allow-dns"
action = "allow"        # allow | deny | reject
duration = "forever"    # once | session | forever
priority = 100          # higher is checked first
enabled = true
tags = ["core"]         # optional labels, see below

[match]                 # every field present must match
port = 53
proto = "udp"
```

The directory is watched, so edits apply without a restart. Unknown keys are
an error: a file with a misspelled field is skipped with a warning rather than
loaded with a wider match than you meant.

**Ordering.** Higher `priority` wins. At equal priority a deny or reject is
checked before an allow, then rules go by name. Prompt answers are written at
priority 50 and the shipped baseline rules at 20, so anything you answer
overrides the baseline.

**Actions.** `deny` drops the packet; `reject` answers with a TCP reset or ICMP
unreachable so the program fails fast instead of timing out.

**Durations.** `once` decides one connection and is never stored. `session`
lasts until the daemon restarts. `forever` is written to `rules.d`. The CLI also
takes a timespan (`30s`, `5m`, `2h`, `1d`) for a rule that expires.

### Match fields

| Field | Matches |
| --- | --- |
| `exe` | Exact executable path |
| `exe_glob` | Glob on the executable path. `*` and `?` stop at `/`; use `**` for a subtree |
| `exe_sha256` | SHA-256 of the executable file |
| `hashes_file` | Any SHA-256 listed in a file, one per line |
| `parent_exe` | Exact executable path of the parent process |
| `cmdline_contains` | Substring of the full command line |
| `app_id` | Packaged app: `flatpak:org.mozilla.firefox`, `snap:firefox` |
| `user` | UID of the process |
| `dest` | Destination IP or CIDR |
| `ips_file` | Any IP or CIDR listed in a file, one per line |
| `domain` | Destination domain, exact or `*.example.org` |
| `domains_file` | Any domain listed in a file, hosts format or one per line |
| `port`, `port_range` | Destination port, or an inclusive `[low, high]` |
| `proto` | `tcp` or `udp` |
| `src`, `src_port` | Source IP/CIDR and port |
| `iface` | Outbound interface name, e.g. `wg0` |

List files are reloaded with the directory, so keep them inside `rules.d`
(any extension but `.toml`).

Not every field is equally trustworthy. `cmdline_contains`, `parent_exe` and
`app_id` are chosen by the process itself, `domain` depends on DNS the
process may control, and even `exe` is only as strong as the attributor behind
it. Scope allow rules with `exe` or `exe_sha256` plus a destination where it
matters. [security.md](security.md#limits) has the details.

A rule that pins `exe_sha256` does not match when the hash cannot be computed
(the process is gone, the binary is unreadable), so a hash-pinned deny cannot
vouch for connections it cannot verify. Pair it with a default-deny posture.

## Managing rules

```sh
hallpass-cli rules                          # list
hallpass-cli rules --stats                  # with hit counts and last hit
hallpass-cli rules add --name block-smtp --action deny --port 25 --duration forever
hallpass-cli rules rm block-smtp
hallpass-cli rules toggle block-smtp off
hallpass-cli rules export > policy.toml     # the whole ruleset, rules.d field names
hallpass-cli rules import policy.toml       # add each rule; non-zero exit if any failed
```

**Adding a rule under an existing name replaces it entirely.** Everything must
be restated: a disabled rule comes back enabled unless you pass
`--enabled false`, and tags you leave out are dropped. The GUI editor loads the
whole rule first, so saving from it keeps both.

Hit counts are per rule name, survive a reload, and reset when the daemon
restarts. A rule that never counts anything is a rule worth questioning.

### Asking what policy would do

`explain` evaluates a connection you describe, without sending anything, and
shows why each rule did or did not decide it:

```
$ hallpass-cli explain --exe /usr/bin/curl --dest 1.1.1.1 --port 443
verdict: DENY  rule=block-telemetry

RULE               PRIO  OUTCOME
allow-curl-https    100  no match (domain)
block-telemetry      50  matched
deny-all              0  not reached
```

It runs the same matcher the packet path uses, so it cannot disagree with
enforcement. It only knows what you tell it: nothing is checked against
`/proc`, and a hash-pinned rule needs `--exe-sha256`.

### Proposing rules from traffic

`hallpass-cli suggest` folds recent decisions into one allow rule per
executable, protocol, port and destination, wildcarding a domain where enough
hosts share a suffix. The output is a `rules export` document: read it, trim
it, then `rules import` it. Filter with `--exe` and `--domain`. Connections
allowed by a session grant are left out.

## Prompts

A prompt shows the program, its destination, and what else the daemon could
find out: the chain of parent processes, the executable's SHA-256, how often
this program was recently denied, and a **NEW** badge the first time the
program, or the program reaching this destination, has been seen.

It also warns loudly when an enabled rule for this program and destination
fails only on the executable hash. That is the binary having changed since you
pinned it.

Answering creates a rule unless you choose `once`. **Pin binary** (or the pin
question in `hallpass-cli watch`) adds `exe_sha256`, so the rule stops
matching the moment the file is replaced. A rule keyed on a path alone keeps
matching whatever is written there later, which matters for anything under a
home directory or a build tree. Pinning is offered only on an allow, and only
when the daemon has a hash.

## Deny rules and established flows

A new deny rule also cuts connections that are already open. When the ruleset
changes, the daemon deletes the conntrack entries of recent flows the new rules
deny, so their next packet is judged as a new connection. Flows the change
leaves unmatched are never touched, so a rule edit cannot cause a prompt storm.

This is best effort. Only the newest 1024 decisions are candidates, a rule
matching only on the executable hash cannot identify flows, and a peer that
keeps sending can re-create the entry from the inbound side until it goes
quiet. Set `kill_established = false` to apply deny rules to new connections
only.

## Tags

Tags label rules for bulk operations. They never affect matching.

```sh
hallpass-cli rules add --name work-vpn ... --tag work
hallpass-cli rules --tag work               # list the set
hallpass-cli rules toggle --tag work off    # disable all of it, as one change
```

A tag is lowercase letters, digits, `-` and `_`, starting with a letter or
digit. A tag no rule carries is an error, so a typo fails loudly. The GUI's
Rules tab has a tag picker and Enable all / Disable all buttons for the
picked tag.

A bad tag in a `rules.d` file is dropped with a warning and the rule still
loads, because a typo in a label should never cost a deny rule its
enforcement. The CLI, IPC and GUI refuse a bad tag outright instead.

## Lockdown

`hallpass-cli lockdown on --tag core` narrows the host to the allow rules
carrying a pinned tag. While it is on:

- only allow rules with a pinned tag can allow;
- **deny rules always apply**, tagged or not;
- everything else is denied **without a prompt**, since a prompt would let
  anyone at the keyboard answer their way out;
- the daemon enforces and the default verdict is deny, whatever they were set
  to; both come back when the posture lifts;
- loopback traffic is exempt.

The posture survives restarts (`/var/lib/hallpass/posture.toml`) and shows in
`status`, `doctor`, `lockdown` and the GUI. `lockdown off` lifts it.

Before relying on it:

- **Open connections keep running.** Only new connections are judged.
- **DNS usually stops working** unless a pinned rule covers the resolver, and
  `domain` rules then stop matching. `lockdown on` warns about this, and
  refuses outright when no rule would survive unless you pass `--force`.
- **A full kernel queue drops** while the posture is on, even under
  `queue_bypass = true`: a flood cannot carry traffic through it unjudged.

## Session grants

```sh
hallpass-cli run -- ./build.sh
hallpass-cli sessions                       # grants open right now
```

While the command runs, connections from it and everything it spawns that no
rule matches are allowed instead of prompting. The grant ends when the command
exits, including on `kill -9`. It is the alternative to a permanent allow rule
for a build, an installer or a test suite.

- **Rules still win.** A grant only answers what would otherwise prompt, so
  deny rules still deny.
- **Same user only.** A `sudo` step inside the session prompts as usual.
- **Everything spawned is covered,** including daemonized descendants. Do not
  wrap a command whose children you would not trust.
- **Lockdown wins over grants.**
- Grants are capped at 8 per user and 64 per host. Events allowed by a grant
  name it (`run-session:7`) in place of a rule.
- A grant-allowed connection counts as the program's first sighting, so its
  **NEW** badge will not show on a later prompt.

## Baseline rules

Both shipped configs deny what no rule matches, so the host's own services need
rules before anyone logs in. The installer puts these in `rules.d`:

| File | Allows |
| --- | --- |
| `20-system-resolved.toml` | systemd-resolved's upstream DNS |
| `20-system-timesyncd.toml`, `20-system-timesyncd-dns.toml` | systemd-timesyncd's NTP and lookups |
| `20-system-networkmanager.toml` | NetworkManager's address configuration and connectivity check |
| `20-deny-llmnr.toml` | Denies LLMNR (port 5355), which resolves bare hostnames by asking the whole link |

Check each `exe` against what `readlink -f /proc/<pid>/exe` reports on your
host: the match is exact, and where `/usr/sbin` is a symlink to `/usr/bin` a
shipped path can match nothing. A host running chrony, ntpd,
systemd-networkd or dhcpcd needs its own rule on the same pattern.

The installer offers each shipped rule once. A rule you edit or delete stays
that way across reinstalls; the record is `/var/lib/hallpass/offered-rules`,
and a purge (`HALLPASS_PURGE=1 ./uninstall.sh`) resets it. A baseline rule
skipped because its binary was missing is offered again on the next install.

`example-allow-dns.toml` ships **disabled**. Port 53 to anywhere lets every
process on the host send arbitrary UDP to any server, a classic exfiltration
channel. Scope it with `dest` or `exe` before enabling it. (Installs from
before this change shipped it enabled, and upgrades do not touch it.)

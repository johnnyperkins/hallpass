# Changelog

Operator-facing changes. Commit bodies carry the full reasoning; this file
carries what an upgrade changes on a running host.

## Unreleased

### Added

- **Kernel queue counters in `status` (wire protocol v7).** The daemon's
  own counters cannot see a packet the kernel resolves because an nfqueue
  is full: it never reaches userspace, so no event and no daemon counter
  moves for it. `status` now reports the kernel's per-queue counters
  (drops, delivery failures, current depth) for the verdict and DNS snoop
  queues, read from `/proc/net/netfilter/nfnetlink_queue` on request,
  plus each queue's effective fail-open flag, known at bind. The flag is
  how the counters read: the kernel counts only what it drops, and a
  queue whose fail-open flag is on resolves overflow by passing packets
  through unjudged and counted nowhere, with the queue depth as the only
  pressure signal. So on a fail-open host the drop counters staying at
  zero is health, and a nonzero there means the fail-open flag did not
  take at bind and traffic is being dropped. A counter that cannot be
  read shows `unavailable`, never zero. The protocol bump means daemon,
  CLI and UI must be upgraded together; a version mismatch is refused at
  connect.
- **`hallpass-cli config`.** The runtime settings (`prompt_timeout_secs`,
  `default_verdict`, enforce/observe mode) previously had a GUI surface
  only; on a headless host they could not be changed at all without
  editing config.toml and restarting. `hallpass-cli config` shows them,
  `hallpass-cli config set --timeout N --default deny --observe|--enforce`
  changes them at runtime. Changes last until the daemon restarts;
  config.toml stays the operator's file. `--observe` disables enforcement
  host-wide and therefore requires `--yes`.

- **Tray icon and close-to-tray for the UI.** hallpass-ui now shows a
  status icon (StatusNotifierItem; on stock GNOME this needs the
  AppIndicator extension, which Ubuntu ships enabled). Closing the main
  window parks it behind the icon instead of quitting, so prompts keep
  appearing while the window is out of the way; the icon's menu (or a
  click on it) brings the window back. Quit - the status-bar button or
  the tray menu item - still denies open prompts once, releases the
  prompt-handler slot, and exits. The installed autostart entry now
  launches `hallpass-ui --hidden`, so login gets a prompt surface with no
  window in the way; the app-menu entry still opens the window. On a
  session where the icon cannot exist (no StatusNotifier host, or no X11
  display), closing the window quits exactly as before - the window is
  never parked somewhere it cannot be recovered from.

### Changed

- **The UI prefers the X11 backend (XWayland on Wayland sessions).**
  Close-to-tray needs to hide the window, keep painting prompts while
  hidden, and re-show on demand; the Wayland backend can do none of that
  (hide is a no-op there, and a minimized window stops receiving frames
  entirely). One consequence exists on every backend and predates this
  change: while the main window is manually minimized, prompt popups
  cannot appear until it is restored - desktop notifications still fire.
  Sessions with no X11 display keep the previous behavior throughout:
  visible window at start, close quits.
- **`exe_glob` wildcards no longer cross `/`.** `*` and `?` stop at a path
  separator, the way a shell's do, and a subtree is written `**`. Existing
  patterns narrow: `exe_glob = "/opt/vendor/*"`, which previously covered
  the entire subtree at any depth, now matches only that one directory
  level. For an allow rule the narrowing is loud, since a binary that
  matched yesterday starts prompting. For a deny rule it is silent and it
  is the dangerous half: a deny written for a subtree now blocks only the
  top level, and nothing on the host says so. Wherever a subtree was
  meant, add a second star: `/opt/vendor/*` becomes `/opt/vendor/**`.
  Audit the loaded ruleset with:

  ```sh
  hallpass-cli --json rules | \
    jq '.[] | select(.match.exe_glob) | {name, action, glob: .match.exe_glob}'
  ```

  The daemon also logs a hint at rule load when a glob ends in `/*`, the
  one shape where the narrowing bites silently.

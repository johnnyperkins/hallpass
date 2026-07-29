#!/bin/sh
# Hallpass one-command installer.
#
#   ./install.sh                   # build + install + enable
#   HALLPASS_EBPF=1 ./install.sh   # require eBPF attribution (fail if toolchain missing)
#   HALLPASS_EBPF=0 ./install.sh   # force the procfs-only build
#
# eBPF attribution is recommended and built by default when the toolchain
# (nightly Rust + bpf-linker) is available; otherwise the build falls back
# to procfs-only attribution with a note.
#
# The build runs as the invoking user (so target/ stays user-owned); only
# the system install steps use sudo, which will prompt for your password.
set -eu

root=$(CDPATH= cd "$(dirname "$0")" && pwd)
cd "$root"

# `cargo xtask build` (eBPF object, then the workspace with the ebpf
# feature) is the single owner of the eBPF build recipe, and doubles as
# the capability probe: rustup auto-installs the nightly pinned by
# crates/hallpass-ebpf/rust-toolchain.toml, and xtask reports a missing
# bpf-linker with install instructions. No toolchain knowledge here.
echo ">> Building release binaries..."
case ${HALLPASS_EBPF:-auto} in
auto)
	if ! cargo xtask build; then
		echo ">> eBPF build failed (see above); building procfs-only."
		echo "   eBPF attribution is recommended; fix the build and re-run,"
		echo "   or silence this fallback with HALLPASS_EBPF=0."
		cargo build --release
	fi
	;;
1)
	cargo xtask build # fail the install if the eBPF build fails
	;;
0)
	echo ">> HALLPASS_EBPF=0: procfs-only build."
	cargo build --release
	;;
*)
	echo "HALLPASS_EBPF must be 1, 0, or unset; got '${HALLPASS_EBPF}'" >&2
	exit 1
	;;
esac

# Pick the login user even when the script itself is later re-run under sudo.
target_user=${SUDO_USER:-$(id -un)}

echo ">> Installing (sudo)..."
sudo sh -eu <<INSTALL
install -Dm755 target/release/hallpassd   /usr/bin/hallpassd
install -Dm755 target/release/hallpass-cli /usr/bin/hallpass-cli
install -Dm755 target/release/hallpass-ui  /usr/bin/hallpass-ui

# Config and example rule: never clobber admin-edited policy. The example
# rule is guarded like the config, so editing it (or deleting it outright)
# survives a reinstall instead of being silently restored.
install -d /etc/hallpass /etc/hallpass/rules.d
[ -f /etc/hallpass/config.toml ] || install -m644 etc/config.toml /etc/hallpass/config.toml
[ -e /etc/hallpass/rules.d/example-allow-dns.toml ] \
  || install -m644 etc/rules.d/example-allow-dns.toml /etc/hallpass/rules.d/example-allow-dns.toml

# systemd unit and desktop entries.
install -Dm644 etc/hallpassd.service   /etc/systemd/system/hallpassd.service
install -Dm644 etc/hallpass-ui.desktop /usr/share/applications/hallpass-ui.desktop
# Autostart the UI so prompts appear without launching anything by hand.
install -Dm644 etc/hallpass-ui.desktop /etc/xdg/autostart/hallpass-ui.desktop

# Let the installing user manage the daemon without sudo.
groupadd -f hallpass
usermod -aG hallpass "$target_user"

systemctl daemon-reload
systemctl enable --now hallpassd
INSTALL

echo
echo ">> Done. hallpassd is running."
echo "   - Log out and back in once so '$target_user' picks up the 'hallpass' group."
echo "   - The Hallpass UI autostarts on next login and pops up connection prompts."
echo "   - Terminal client: hallpass-cli status | rules | events | watch"

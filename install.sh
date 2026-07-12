#!/bin/sh
# Hallpass one-command installer.
#
#   ./install.sh              # build (procfs attribution) + install + enable
#   HALLPASS_EBPF=1 ./install.sh   # also build the eBPF attribution programs
#
# The build runs as the invoking user (so target/ stays user-owned); only
# the system install steps use sudo, which will prompt for your password.
set -eu

root=$(CDPATH= cd "$(dirname "$0")" && pwd)
cd "$root"

echo ">> Building release binaries..."
if [ "${HALLPASS_EBPF:-0}" = "1" ]; then
	# eBPF path: needs nightly + bpf-linker; builds kernel programs then the
	# daemon with the ebpf feature.
	cargo xtask build
	cargo build --release --features ebpf -p hallpassd
else
	cargo build --release
fi

# Pick the login user even when the script itself is later re-run under sudo.
target_user=${SUDO_USER:-$(id -un)}

echo ">> Installing (sudo)..."
sudo sh -eu <<INSTALL
install -Dm755 target/release/hallpassd   /usr/bin/hallpassd
install -Dm755 target/release/hallpass-cli /usr/bin/hallpass-cli
install -Dm755 target/release/hallpass-ui  /usr/bin/hallpass-ui

# Config and example rule: never clobber an existing admin-edited config.
install -d /etc/hallpass /etc/hallpass/rules.d
[ -f /etc/hallpass/config.toml ] || install -m644 etc/config.toml /etc/hallpass/config.toml
install -Dm644 etc/rules.d/example-allow-dns.toml /etc/hallpass/rules.d/example-allow-dns.toml

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

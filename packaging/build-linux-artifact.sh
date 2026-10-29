#!/usr/bin/env bash
# Run with GNU tar inside Debian 12; the payload is installer media, not an install.
set -euo pipefail
binary=$(realpath "${1:?binary}")
version=${2:?version}
epoch=${3:?tag commit timestamp}
out=$(realpath -m "${4:?output directory}")
[[ $version =~ ^0\.19\.1-sudo\.[1-9][0-9]*$ ]]
[[ $epoch =~ ^[0-9]+$ ]]
root=$(git rev-parse --show-toplevel)
name="sudo-secretspec-$version-x86_64-unknown-linux-gnu"
mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
media="$work/$name"
install -Dm755 "$binary" "$media/libexec/sudo-secretspec"
install -Dm644 "$root/sudo-secretspec/AI-GUIDANCE.md" "$media/share/sudo-secretspec/AI-GUIDANCE.md"
install -Dm644 "$root/sudo-secretspec/sudo-secretspec-retired.toml" "$media/share/sudo-secretspec/sudo-secretspec-retired.toml"
install -Dm644 "$root/skills/sudo-secretspec/SKILL.md" "$media/share/sudo-secretspec/skills/sudo-secretspec/SKILL.md"
install -m644 "$root/README.downstream.md" "$media/README.md"
install -m644 "$root/LICENSE" "$media/LICENSE"
cat > "$media/INSTALL.txt" <<'INSTALL'
sudo-secretspec for x86_64 Linux (glibc 2.36 or newer).
Requires sudo and system SQLite: apt install sudo libsqlite3-0
Supports Debian 12/13 and Ubuntu 24.04 or newer; not Ubuntu 22.04.
NixOS must use services.sudo-secretspec instead of this installer.

Extract the tarball anywhere, review its contents, then run from its root:
  sudo ./libexec/sudo-secretspec install --declarations /path/secretspec.toml
Use an ordinary operator account with interactive sudo permission.
No passwordless sudo is needed to bootstrap. The installer creates the public
client at /usr/bin/sudo-secretspec and the protected broker at
/usr/libexec/sudo-secretspec.
After installation:
  sudo-secretspec doctor
Review README.md and share/sudo-secretspec/AI-GUIDANCE.md before using secrets.
INSTALL
chmod 644 "$media/INSTALL.txt"
# gzip -n removes the compressor's wall clock and source-name fields.
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
  --mode='u+rwX,go+rX,go-w' --format=ustar -C "$work" -cf "$work/media.tar" "$name"
gzip -n -c "$work/media.tar" > "$out/$name.tar.gz"
(cd "$out"; sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")

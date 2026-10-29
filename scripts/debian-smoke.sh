#!/usr/bin/env bash
# Destructive integration proof: ONLY run as root in a disposable Debian container.
set -euo pipefail
[[ $(id -u) == 0 ]] || { echo 'requires root in a disposable Debian container' >&2; exit 1; }
[[ -f /.dockerenv || -f /run/.containerenv ]] || { echo 'requires a disposable container' >&2; exit 1; }
[[ ! -e /etc/sudo-secretspec.toml && ! -e /var/lib/sudo-secretspec ]]
[[ ! -e /run/current-system && ! -L /run/current-system ]]
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
binary=$(realpath "${1:-target/release/sudo-secretspec}")
root=$(git rev-parse --show-toplevel)
work=$(mktemp -d /opt/sudo-secretspec-smoke.XXXXXX)
trap 'rm -f /run/current-system; rm -rf "$work"' EXIT
ok() { printf 'PASS: %s\n' "$*"; }
meta() {
  local actual
  actual=$(stat -c '%a %U:%G' "$1")
  [[ $actual == "$2" ]] || { echo "FAIL: $1: $actual (expected $2)" >&2; exit 1; }
  ok "$1 mode and ownership: $actual"
}
absent() { [[ ! -e $1 && ! -L $1 ]]; ok "$1 absent"; }
useradd --create-home --shell /bin/bash --groups sudo opuser
ok 'ordinary operator account created with password-required sudo'
media="$work/media"
install -Dm755 "$binary" "$media/libexec/sudo-secretspec"
install -Dm644 "$root/sudo-secretspec/AI-GUIDANCE.md" "$media/share/sudo-secretspec/AI-GUIDANCE.md"
install -Dm644 "$root/sudo-secretspec/sudo-secretspec-retired.toml" "$media/share/sudo-secretspec/sudo-secretspec-retired.toml"
install -Dm644 "$root/skills/sudo-secretspec/SKILL.md" "$media/share/sudo-secretspec/skills/sudo-secretspec/SKILL.md"
cat > "$work/secretspec.toml" <<'TOML'
[project]
name = "debian-installer-smoke"
revision = "1.0"
[profiles.default]
SMOKE_OPTIONAL = { description = "No real secret used by installer smoke", required = false }
TOML
chmod 644 "$work/secretspec.toml"
bootstrap="$media/libexec/sudo-secretspec"
install_boundary() {
  SUDO_USER=opuser "$bootstrap" install --declarations "$work/secretspec.toml" --non-interactive
}
install_boundary > "$work/first-install.log"
cat "$work/first-install.log"
ok 'fresh install with SUDO_USER=opuser'
entry=$(getent passwd sudo-secretspec)
IFS=: read -r _ _ service_uid service_gid _ _ service_shell <<< "$entry"
[[ $service_uid -gt 0 && $service_uid -lt 1000 ]]
[[ $service_gid -gt 0 && $service_gid -lt 1000 ]]
[[ $service_shell == */nologin || $service_shell == */false ]]
getent group sudo-secretspec
[[ $(getent group sudo-secretspec | cut -d: -f3) == "$service_gid" ]]
ok 'service system user/group exist with a non-login shell'
meta /var/lib/sudo-secretspec '700 sudo-secretspec:sudo-secretspec'
meta /etc/sudo-secretspec.toml '444 root:root'
meta /usr/libexec/sudo-secretspec '755 root:root'
meta /usr/local/bin/sudo-secretspec '755 root:root'
[[ $(stat -c '%d:%i' /usr/libexec/sudo-secretspec) != $(stat -c '%d:%i' /usr/local/bin/sudo-secretspec) ]]
cmp /usr/libexec/sudo-secretspec /usr/local/bin/sudo-secretspec
sha256sum /usr/libexec/sudo-secretspec /usr/local/bin/sudo-secretspec
ok 'client and broker are separate files with identical hashes'
meta /etc/sudoers.d/sudo-secretspec '440 root:root'
visudo -c
ok 'combined sudoers accepted by visudo'
policy=/etc/sudoers.d/sudo-secretspec
! grep -E '^ALL[[:space:]].*NOPASSWD|NOPASSWD:.*[[:space:]](install|uninstall|rollback|doctor)([[:space:]]|$)' "$policy"
[[ $(grep -c 'NOPASSWD:' "$policy") == 11 ]]
for verb in source-add source-set source-delete source-undeclare source-get source-check source-export source-template-check source-schema source-restore; do
  grep -Fx "opuser ALL=(sudo-secretspec) NOPASSWD: /usr/libexec/sudo-secretspec __broker $verb --*" "$policy"
done
grep -Fx 'opuser ALL=(sudo-secretspec) NOPASSWD: /usr/libexec/sudo-secretspec __broker audit-verify' "$policy"
! grep 'NOPASSWD:' "$policy" | grep -v '^opuser ALL=(sudo-secretspec) NOPASSWD: /usr/libexec/sudo-secretspec __broker '
grep -F 'secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' "$policy"
grep -Fx 'Defaults!/usr/local/bin/sudo-secretspec timestamp_timeout=0' "$policy"
ok 'only the eleven broker verbs are granted NOPASSWD; Debian PATH and client timeout are pinned'
su opuser -c 'sudo -n -l' > "$work/sudo-list.txt"
cat "$work/sudo-list.txt"
grep -F '/usr/libexec/sudo-secretspec __broker source-get --*' "$work/sudo-list.txt"
grep -F '/usr/libexec/sudo-secretspec __broker audit-verify' "$work/sudo-list.txt"
ok 'operator can list the mediated broker grants without a password'
if su opuser -c 'sudo -n /usr/local/bin/sudo-secretspec install --declarations x' > "$work/denied.txt" 2>&1; then
  echo 'FAIL: install unexpectedly allowed without authentication' >&2; exit 1
fi
cat "$work/denied.txt"
grep -Ei 'password.*required|password is required' "$work/denied.txt"
ok 'public-client install requires interactive authentication'
/usr/local/bin/sudo-secretspec doctor
ok 'doctor accepts the Debian layout'
# A first installation has no prior artifacts. Reinstall to produce a real,
# restorable snapshot; timestamp-based snapshot names require a distinct second.
sleep 1
install_boundary > "$work/upgrade.log"
cat "$work/upgrade.log"
snapshot=$(awk -F= '/^rollback_snapshot=/{print substr($0,index($0,"=")+1)}' "$work/upgrade.log")
[[ $snapshot == /usr/libexec/sudo-secretspec-rollback-* && -d $snapshot ]]
ls -la "$snapshot"
/usr/local/bin/sudo-secretspec rollback "$snapshot"
/usr/local/bin/sudo-secretspec doctor
ok 'upgrade snapshot listed, restored and accepted by doctor'
/usr/local/bin/sudo-secretspec uninstall --non-interactive
for path in /etc/sudo-secretspec.toml /etc/sudoers.d/sudo-secretspec /usr/libexec/sudo-secretspec /usr/local/bin/sudo-secretspec; do absent "$path"; done
getent passwd sudo-secretspec >/dev/null
getent group sudo-secretspec >/dev/null
meta /var/lib/sudo-secretspec '700 sudo-secretspec:sudo-secretspec'
ok 'default uninstall retains the service identity and vault'
SUDO_USER=opuser "$bootstrap" install --adopt-existing --vault /var/lib/sudo-secretspec --declarations "$work/secretspec.toml" --non-interactive
/usr/local/bin/sudo-secretspec uninstall --purge-vault --remove-service-user --non-interactive
absent /var/lib/sudo-secretspec
! getent passwd sudo-secretspec
! getent group sudo-secretspec
ok 'explicit purge removes vault and service identity'
ln -s /nonexistent /run/current-system
set +e
install_boundary > "$work/nixos.txt" 2>&1
status=$?
set -e
cat "$work/nixos.txt"
[[ $status == 2 ]]
grep -F 'services.sudo-secretspec' "$work/nixos.txt"
absent /etc/sudo-secretspec.toml
ok 'dangling NixOS system marker refuses install with exit 2 before mutation'
rm /run/current-system
install_boundary
/usr/local/bin/sudo-secretspec doctor
ok 'ordinary Debian installation works again after removing the NixOS marker'
/usr/local/bin/sudo-secretspec uninstall --purge-vault --remove-service-user --non-interactive
visudo -c
ok 'final cleanup complete; Debian installer smoke passed'

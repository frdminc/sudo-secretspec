# NixOS VM test for the declared sudo-secretspec boundary.
#
# Boots a minimal NixOS machine with the module enabled and an operator user
# `dann` (deliberately NOT in `wheel`, so the module's sudoers policy is the
# only thing granting him anything), then asserts the boundary:
#
#   * exactly the ten mediated broker verbs and `audit-verify` are NOPASSWD —
#     11 grant lines, each naming the broker once;
#   * no blanket `NOPASSWD: ALL` grant sneaks in;
#   * the broker's `Defaults!` line is exactly as emitted (env_reset, HOME
#     pinned, /run/current-system secure_path, umask 0077, always_set_home);
#   * the authenticated commands (`source-restore-force`, `source-destroy`) and
#     the macOS-only diagnostic (`doctor`) are NOT NOPASSWD — sudo demands a
#     password for them;
#   * the Linux policy carries no macOS `timestamp_timeout=0` client line.
#
# The runtime assertions run as the operator, never as root: root is exempt from
# the NOPASSWD restriction, so `sudo -n -u <svc> ...` from root would always
# exec the broker regardless of grant. `sudo -u dann sudo -n ...` drops to the
# operator first, where `-n` (non-interactive) succeeds iff the verb is granted
# and otherwise fails with "a password is required".
#
# A granted verb is exercised with a real `--*` argument (`--client vmtest`,
# what the public client appends): the grant is `<broker> __broker <verb> --*`,
# so a bare `<verb>` with no argument does not match the glob. `audit-verify`
# is granted exactly (no glob) and takes no argument. `source-restore --all`
# matches the `--*` glob, so sudo does NOT prompt — but the broker must refuse
# the mass restore itself (exit 2); with `declarations = null` the broker bails
# at manifest load before that guard, so here we assert only "no password
# demanded + non-zero exit", the exact refusal being a Rust unit test.
#
# This is a `nixosTest`: it needs a hypervisor (QEMU), so it only runs on Linux
# and only in CI (Forgejo/Hyades), not on a macOS dev box. The module's
# import-from-derivation (the `print-sudoers` runCommand) also requires
# `allow-import-from-derivation = true` when evaluating the flake.
{
  pkgs,
  self,
}: pkgs.nixosTest {
  name = "sudo-secretspec";

  nodes.machine = {
    imports = [ self.nixosModules.default ];

    services.sudo-secretspec = {
      enable = true;
      operator = "dann";
      # No declarations: the vault/manager is out of scope for this test, which
      # is only about the sudoers boundary. The broker never actually runs a
      # credential operation here.
      declarations = null;
    };

    users.users.dann = {
      isNormalUser = true;
      description = "operator (test)";
    };
  };

  testScript =
    { nodes, ... }:
    ''
      # The broker store path is interpolated by Nix into this line as a Python
      # string literal (not a Nix `let` binding), so the f-strings below can use
      # it. A Nix `let` value would never reach the Python script: `{broker}`
      # here is Python syntax, not `${broker}` Nix interpolation.
      broker = "${nodes.machine.config.services.sudo-secretspec.package}/libexec/sudo-secretspec"

      start_all()
      machine.wait_for_unit("multi-user.target")

      # ---- the emitted policy, verbatim ------------------------------------
      # `security.sudo.extraConfig` lands in /etc/sudoers, appended LAST (after
      # the `%wheel` extraRules block in /etc/sudoers.d), so our NOPASSWD grants
      # win on last-match-wins.
      sudoers = machine.succeed("cat /etc/sudoers")

      broker_lines = [l for l in sudoers.splitlines() if "__broker" in l]
      assert len(broker_lines) == 11, f"expected 11 broker grant lines, got {len(broker_lines)}\n{sudoers}"
      assert all("NOPASSWD:" in l for l in broker_lines), f"broker grants must all be NOPASSWD:\n{sudoers}"
      assert not any("NOPASSWD: ALL" in l for l in broker_lines), f"no blanket grant may exist:\n{sudoers}"

      # The exact broker Defaults! line: env_reset, HOME pinned, the
      # /run/current-system secure_path, umask 0077, always_set_home.
      expected_defaults = f'Defaults!{broker} env_reset,env_keep-="HOME",secure_path=/run/current-system/sw/bin:/run/wrappers/bin,umask=0077,always_set_home'
      assert expected_defaults in sudoers, f"missing/incorrect broker Defaults! line:\n{sudoers}"

      # No macOS-only client line, no doctor grant.
      assert "timestamp_timeout=0" not in sudoers, "Linux policy must not set timestamp_timeout=0"
      assert " doctor" not in sudoers, "Linux policy must not grant doctor"

      # ---- runtime: each mediated verb is NOPASSWD with a --* argument ------
      for verb in [
          "source-add", "source-set", "source-delete", "source-undeclare",
          "source-get", "source-check", "source-export", "source-template-check",
          "source-schema", "source-restore",
      ]:
          out = machine.execute(
              f"sudo -u dann sudo -n -u sudo-secretspec {broker} __broker {verb} --client vmtest 2>&1"
          )
          assert "a password is required" not in out[1], f"{verb} demanded a password:\n{out[1]}"

      # audit-verify is granted exactly (no glob) and takes no argument.
      out = machine.execute(
          f"sudo -u dann sudo -n -u sudo-secretspec {broker} __broker audit-verify 2>&1"
      )
      assert "a password is required" not in out[1], f"audit-verify demanded a password:\n{out[1]}"

      # source-restore --all matches the `--*` glob (sudo does NOT prompt), but
      # the broker refuses the mass restore (exit 2).
      out = machine.execute(
          f"sudo -u dann sudo -n -u sudo-secretspec {broker} __broker source-restore --all --to 1 --client vmtest 2>&1"
      )
      assert "a password is required" not in out[1], f"source-restore --all demanded a password:\n{out[1]}"
      assert out[0] != 0, f"source-restore --all unexpectedly succeeded:\n{out[1]}"

      # ---- runtime: authenticated + diagnostic verbs are NOT NOPASSWD -------
      for forbidden in ["source-restore-force --all", "source-destroy --all", "doctor"]:
          out = machine.execute(
              f"sudo -u dann sudo -n -u sudo-secretspec {broker} __broker {forbidden} 2>&1"
          )
          assert "a password is required" in out[1], f"{forbidden} was not password-gated:\n{out[1]}"
    '';
}

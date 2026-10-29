# NixOS VM test for the declared sudo-secretspec boundary.
#
# Boots a minimal NixOS machine with the module enabled and an operator user
# `dann` (deliberately NOT in `wheel`, so the module's sudoers policy is the
# only thing granting him anything), then asserts the boundary:
#
#   * exactly the ten mediated broker verbs and `audit-verify` are NOPASSWD;
#   * the authenticated commands (`source-restore-force`, `source-destroy`) and
#     the macOS-only diagnostic (`doctor`) are NOT NOPASSWD;
#   * the Linux policy carries no macOS `timestamp_timeout=0` client line.
#
# The runtime assertions run as the operator, never as root: root is exempt from
# the NOPASSWD restriction, so `sudo -n -u <svc> ...` from root would always
# exec the broker regardless of grant. `sudo -u dann sudo -n ...` drops to the
# operator first, where `-n` (non-interactive) succeeds iff the verb is granted
# and otherwise fails with "a password is required".
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
    let
      broker = "${nodes.machine.config.services.sudo-secretspec.package}/libexec/sudo-secretspec";
    in
    ''
      start_all()
      machine.wait_for_unit("multi-user.target")

      # ---- the exact grant set, via sudo's own view of the policy ---------
      listing = machine.succeed("sudo -U dann -l")
      granted = [
        "source-add", "source-set", "source-delete", "source-undeclare",
        "source-get", "source-check", "source-export", "source-template-check",
        "source-schema", "source-restore", "audit-verify",
      ]
      for verb in granted:
          assert f"__broker {verb}" in listing, f"missing NOPASSWD grant: {verb}\n{listing}"

      # ---- the authenticated + diagnostic commands are NOT NOPASSWD --------
      for forbidden in ["source-restore-force", "source-destroy", "doctor"]:
          assert f"__broker {forbidden}" not in listing, f"unexpected grant: {forbidden}\n{listing}"

      # ---- the Linux policy omits the macOS-only client line ---------------
      sudoers = machine.succeed("cat /etc/sudoers")
      assert "timestamp_timeout=0" not in sudoers, "Linux policy must not set timestamp_timeout=0"
      assert " doctor" not in sudoers, "Linux policy must not grant doctor"

      # ---- runtime: a mediated verb runs without a password prompt ---------
      # The broker may still exit non-zero (no manifest); what matters is sudo
      # did not demand a password.
      out = machine.execute(
          "sudo -u dann sudo -n -u sudo-secretspec "
          f"{broker} __broker source-schema 2>&1"
      )
      assert "a password is required" not in out[1], f"mediated verb demanded a password:\n{out[1]}"

      # ---- runtime: authenticated + diagnostic verbs are refused by sudo ---
      for forbidden in ["source-restore-force --all", "source-destroy --all", "doctor"]:
          machine.fail(
              "sudo -u dann sudo -n -u sudo-secretspec "
              f"{broker} __broker {forbidden} 2>&1"
          )
    '';
}

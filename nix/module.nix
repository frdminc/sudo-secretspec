# NixOS module for the sudo-secretspec privilege boundary.
#
# The boundary is `sudo` + a NOPASSWD sudoers rule; there is no daemon. This
# module is the declarative equivalent of what `sudo-secretspec install` does
# on macOS (`install.rs`): service account, protected config, vault directory,
# sudoers policy. The imperative `install`/`uninstall`/`rollback`/`doctor`
# commands refuse on Linux and point here.
#
# `doctor` — and its drift/layout checks — is a macOS-only diagnostic. Its
# checks are macOS-shaped (a real `/bin/ls`, a `sudoers.d` `#include` line,
# root-owned `/etc/static`, Homebrew paths) and have no NixOS equivalent, so
# the Linux binary refuses it via `platform::lifecycle_refusal`. The declared
# boundary has no drift checker instead: the broker is an immutable store path
# (not a mutable `/run` symlink), and `systemd.tmpfiles` re-asserts the vault
# owner/mode and the config file owner/mode on every activation, so the
# equivalent guarantee is "a rebuild is the only way anything changes".
self:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.sudo-secretspec;
  inherit (lib) mkOption mkEnableOption mkIf types;

  # Single source of truth: the paths compiled into the package.
  #
  # `broker` is the `libexec/` copy in the store — a distinct regular file from
  # the public client at `bin/`, so `main`'s canonical-path identity check can
  # tell the NOPASSWD broker apart from the operator's client. The flake bakes
  # `platform::BROKER_PATH` to exactly this store path (`SUDO_SECRETSPEC_BROKER_PATH`
  # in package.nix), so `broker` here and the path `print-sudoers` emits agree.
  broker = "${cfg.package}/libexec/sudo-secretspec";
  configPath = cfg.package.passthru.configPath;

  # The sudoers policy is emitted by the same binary that enforces it, through
  # the hidden `print-sudoers` subcommand (`install.rs::linux_sudoers_text`).
  # Import-from-derivation means the module's sudoers text and the compiled-in
  # broker path can never drift apart: when the package changes, the text is
  # regenerated from the new binary. `OPERATOR`/`SERVICE_USER` reach the command
  # as derivation env, never through shell interpolation, so a hostile operator
  # or service-user string cannot break out of the builder command.
  sudoersText = pkgs.runCommand "sudo-secretspec-sudoers"
    {
      OPERATOR = cfg.operator;
      SERVICE_USER = cfg.serviceUser;
    }
    ''"${cfg.package}/bin/sudo-secretspec" print-sudoers \
        --operator "$OPERATOR" --service-user "$SERVICE_USER" > "$out"'';

  identity = "[a-z_][a-z0-9_-]{0,30}"; # config.rs `valid_service_identity` (Linux)
  tomlFormat = pkgs.formats.toml { };

  # Keys are exactly `config.rs`'s `Config` (`deny_unknown_fields`). `engine`
  # and `audit_helper` are required by the parser; on a single-binary install
  # both name the privileged binary.
  configFile = tomlFormat.generate "sudo-secretspec.toml" (
    {
      engine = broker;
      audit_helper = broker;
      vault = cfg.vault;
      vault_realpath = cfg.vault;
      service_user = cfg.serviceUser;
      service_group = cfg.serviceGroup;
      profile = cfg.profile;
    }
    // lib.optionalAttrs (cfg.declarations != null) { declarations = "${cfg.declarations}"; }
  );
  manifest = "${cfg.vault}/secretspec.toml";
in
{
  options.services.sudo-secretspec = {
    enable = mkEnableOption "the sudo-secretspec privilege boundary (sudo + sudoers, no daemon)";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.sudo-secretspec;
      defaultText = lib.literalExpression "sudo-secretspec.packages.\${system}.sudo-secretspec";
      description = ''
        The companion build. It must be compiled with the Linux path overrides
        (the flake's package is); the broker and config paths are read from it.
      '';
    };

    operator = mkOption {
      type = types.str;
      default = "dann";
      description = "User granted the NOPASSWD rules for the unattended broker verbs.";
    };

    serviceUser = mkOption {
      type = types.str;
      default = "sudo-secretspec";
      description = "System user that owns the vault and runs the broker.";
    };

    serviceGroup = mkOption {
      type = types.str;
      default = "sudo-secretspec";
      description = "Primary group of the service user.";
    };

    vault = mkOption {
      type = types.str;
      default = "/var/lib/sudo-secretspec";
      description = ''
        Vault directory. Must be a direct child of `/var/lib`: the broker
        refuses any other location (`config.rs`).
      '';
    };

    profile = mkOption {
      type = types.str;
      default = "default";
      description = "Manifest profile the broker resolves secrets from.";
    };

    declarations = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        Tracked declarations file (a `secretspec.toml`). It is recorded in the
        protected config for `template-check`, and copied into the vault as
        `secretspec.toml` if the vault has none yet. The runtime manifest is
        never overwritten afterwards: `add`/`undeclare` edit it in place.
        When null the manifest must be provided by hand; the broker refuses
        to run without one.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = config.security.sudo.enable;
        message = "services.sudo-secretspec needs security.sudo.enable (the boundary is sudo).";
      }
      {
        assertion = lib.hasPrefix "/etc/" configPath;
        message = "sudo-secretspec: the package's config path (${configPath}) must live under /etc.";
      }
      {
        assertion = builtins.dirOf cfg.vault == "/var/lib" && cfg.vault != "/var/lib";
        message = "services.sudo-secretspec.vault must be a direct child of /var/lib.";
      }
      {
        assertion =
          builtins.match identity cfg.serviceUser != null
          && builtins.match identity cfg.serviceGroup != null
          && cfg.serviceUser != "root"
          && cfg.serviceGroup != "root";
        message = "services.sudo-secretspec: serviceUser/serviceGroup must match ${identity} and not be root.";
      }
      {
        assertion = builtins.match "[A-Za-z][A-Za-z0-9_-]{0,63}" cfg.profile != null;
        message = "services.sudo-secretspec.profile must be a plain profile name (letters, digits, `_`, `-`).";
      }
      {
        assertion = cfg.operator != "root";
        message = "services.sudo-secretspec.operator must be a non-root user.";
      }
    ];

    users.groups.${cfg.serviceGroup} = { };
    users.users.${cfg.serviceUser} = {
      isSystemUser = true;
      group = cfg.serviceGroup;
      description = "sudo-secretspec broker";
      home = "/var/empty";
      shell = "${pkgs.shadow}/bin/nologin";
    };

    environment.systemPackages = [ cfg.package ];

    # Root-owned, mode 0444, a real file (a `mode` other than "symlink" makes
    # the etc builder copy rather than link): the broker reads it as the
    # service user and it is the boundary's control plane.
    environment.etc.${lib.removePrefix "/etc/" configPath} = {
      source = configFile;
      mode = "0444";
      user = "root";
      group = "root";
    };

    systemd.tmpfiles.rules = [
      # `d` re-asserts owner and mode on an existing directory every run; the
      # broker refuses anything but 0700 owned by the service user.
      "d ${cfg.vault} 0700 ${cfg.serviceUser} ${cfg.serviceGroup} -"
    ]
    ++ lib.optionals (cfg.declarations != null) [
      # Seed only: `C` never overwrites, and `add`/`undeclare` mutate this file.
      "C ${manifest} 0600 ${cfg.serviceUser} ${cfg.serviceGroup} - ${cfg.declarations}"
      # The broker requires exactly 0600, service-user owned.
      "z ${manifest} 0600 ${cfg.serviceUser} ${cfg.serviceGroup} -"
    ];

    # The whole policy — the `Defaults!` line *and* the operator's NOPASSWD
    # grant lines — comes from `sudoersText`, the IFD derivation that runs the
    # binary's own `print-sudoers`. `extraConfig` is appended by NixOS after the
    # stock `%wheel` rule, and sudoers is last-match-wins, so the NOPASSWD
    # grants take effect over `%wheel`'s password prompt. There is no
    # `timestamp_timeout=0` line and no `doctor` grant on Linux: the former has
    # no client path to attach to, the latter refuses on Linux.
    security.sudo.extraConfig = builtins.readFile sudoersText;
  };
}

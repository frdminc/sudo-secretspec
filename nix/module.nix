# NixOS module for the sudo-secretspec privilege boundary.
#
# The boundary is `sudo` + a NOPASSWD sudoers rule; there is no daemon. This
# module is the declarative equivalent of what `sudo-secretspec install` does
# on macOS (`install.rs`): service account, protected config, vault directory,
# sudoers policy. The imperative `install`/`uninstall`/`rollback`/`doctor`
# commands refuse on Linux and point here.
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
  broker = cfg.package.passthru.brokerPath;
  configPath = cfg.package.passthru.configPath;
  brokerTarget = "${cfg.package}/libexec/sudo-secretspec";

  # Same verbs, same `--*` argument glob as `install.rs`'s `sudoers_text()`.
  # `source-restore-force` and `source-destroy` are deliberately absent: with
  # no line they fall through to the operator's ordinary password-prompted
  # sudo, which is what makes them "authenticated" operations.
  globbedVerbs = [
    "source-add"
    "source-set"
    "source-delete"
    "source-undeclare"
    "source-get"
    "source-check"
    "source-export"
    "source-template-check"
    "source-schema"
    "source-restore"
  ];
  nopasswd = command: {
    inherit command;
    options = [ "NOPASSWD" ];
  };

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
      # Parent is root-owned and non-writable, so nobody can swap the symlink.
      "d ${builtins.dirOf broker} 0755 root root -"
      # Stable name for sudoers; `L+` re-points it on every rebuild. The target
      # is the `libexec/` copy, whose canonical path equals the broker's own
      # `current_exe()` and differs from the public client's (see package.nix).
      "L+ ${broker} - - - - ${brokerTarget}"
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

    # `install.rs` also sets `timestamp_timeout=0` on the *client* path. That
    # only guards the client's own `sudo client install|uninstall|rollback`,
    # which do not exist on Linux, so there is nothing to attach it to.
    security.sudo.extraConfig = ''
      Defaults!${broker} env_reset,env_keep-="HOME",secure_path=/run/current-system/sw/bin:/run/wrappers/bin,umask=0077,always_set_home
    '';

    # After the stock `%wheel` rule: sudoers is last-match-wins, so the
    # NOPASSWD lines must come later to take effect.
    security.sudo.extraRules = lib.mkAfter [
      {
        users = [ cfg.operator ];
        runAs = cfg.serviceUser;
        commands =
          map (verb: nopasswd "${broker} __broker ${verb} --*") globbedVerbs
          ++ [ (nopasswd "${broker} __broker audit-verify") ];
      }
    ];
  };
}

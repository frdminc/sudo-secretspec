# sudo-secretspec-cli, built from this workspace.
#
# Build helper: nixpkgs' `rustPlatform.buildRustPackage` with `cargoLock`.
# Cargo.lock has no git dependencies, so no `outputHashes` are needed, and the
# flake keeps a single input (nixpkgs) rather than adding crane/naersk, which
# would each be one more pinned input guarding a privilege boundary.
#
# On Linux the three platform paths are baked into the binary at compile time
# (see `sudo-secretspec-cli/src/platform.rs`); on macOS the defaults apply
# untouched, so a Nix-built macOS binary behaves exactly like the Homebrew one.
{
  lib,
  stdenv,
  rustPlatform,
  pkg-config,
  sqlite,
  # NixOS has no /usr/bin/sudo: the setuid wrapper lives in /run/wrappers/bin.
  sudoPath ? "/run/wrappers/bin/sudo",
  # Root-owned 0444 file written by the NixOS module.
  configPath ? "/etc/sudo-secretspec.toml",
}:

rustPlatform.buildRustPackage {
  pname = "sudo-secretspec";
  version = (builtins.fromTOML (builtins.readFile ../Cargo.toml)).workspace.package.version;

  src = lib.cleanSourceWith {
    src = ../.;
    filter =
      path: type:
      lib.cleanSourceFilter path type
      && !(builtins.elem (baseNameOf path) [
        "target"
        "node_modules"
        ".devenv"
        ".direnv"
      ]);
  };

  cargoLock.lockFile = ../Cargo.lock;

  # The workspace has seven members; only the companion is wanted here.
  cargoBuildFlags = [
    "--package"
    "sudo-secretspec-cli"
  ];

  # The suite is macOS-shaped (macOS paths, a real `sudo`, service accounts)
  # and needs a host it can mutate; it runs in CI, not in the Nix sandbox.
  doCheck = false;

  nativeBuildInputs = [ pkg-config ];
  # The companion links the system SQLite (see FORK-AI.md: not `bundled`).
  buildInputs = [ sqlite ];

  env = lib.optionalAttrs stdenv.hostPlatform.isLinux {
    SUDO_SECRETSPEC_SUDO = sudoPath;
    # The broker path is the store path of the `libexec/` copy, baked at build
    # time. There is deliberately no `/run` symlink: a sudoers rule on a
    # mutable symlink could be repointed, whereas the store path is immutable.
    SUDO_SECRETSPEC_BROKER_PATH = "${builtins.placeholder "out"}/libexec/sudo-secretspec";
    SUDO_SECRETSPEC_CONFIG_PATH = configPath;
  };

  # The public client and the privileged broker must be DIFFERENT paths.
  # `main` refuses everything but `__broker`/`doctor` when
  # canonicalize(current_exe()) == canonicalize(BROKER_PATH), so that the
  # NOPASSWD path cannot serve `install`/`rollback`. If the broker path were
  # `bin/sudo-secretspec`, the operator's own client would resolve to the same
  # store path and refuse every command. A second copy under `libexec/` keeps
  # the two identities apart without changing that check.
  postInstall = ''
    install -D -m755 "$out/bin/sudo-secretspec" "$out/libexec/sudo-secretspec"
  '';

  passthru = { inherit sudoPath configPath; };

  meta = {
    description = "Privilege-separated SecretSpec companion (sudo + sudoers boundary)";
    mainProgram = "sudo-secretspec";
    platforms = lib.platforms.unix;
  };
}

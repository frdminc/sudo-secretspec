{
  description = "sudo-secretspec: privilege-separated SecretSpec companion (NixOS module + package)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        sudo-secretspec = pkgs.callPackage ./nix/package.nix { };
        default = sudo-secretspec;
      });

      nixosModules.default = import ./nix/module.nix self;
      nixosModules.sudo-secretspec = self.nixosModules.default;

      # The VM test boots a NixOS machine and drives sudo, so it is Linux-only
      # (needs QEMU) and runs in CI, not on a macOS dev box. Evaluating it also
      # forces the module's import-from-derivation, so CI must set
      # `allow-import-from-derivation = true`.
      checks = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (system: {
        sudo-secretspec-vm = import ./nix/test.nix {
          pkgs = nixpkgs.legacyPackages.${system};
          inherit self;
        };
      });
    };
}

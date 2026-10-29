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
    };
}

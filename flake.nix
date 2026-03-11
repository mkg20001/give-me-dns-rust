{
  description = "Temporary DNS names for IPv6 addresses";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default self.overlays.default ];
        };
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        };
      in
      {
        packages = {
          give-me-dns = pkgs.give-me-dns;
          default = pkgs.give-me-dns;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            cargo-watch
            pkg-config
            perl
          ];
        };
      }
    ) // {
      overlays.default = final: prev: {
        give-me-dns = prev.callPackage ./. { };
      };

      nixosModules = {
        give-me-dns = import ./module.nix;
      };
    };
}

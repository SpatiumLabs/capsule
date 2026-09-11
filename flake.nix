{
  description = "Development shell for Capsule";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      systems = [
        "aarch64-linux"
        "x86_64-linux"
        "aarch64-darwin"
      ];

      forAllSystems =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f {
            inherit system;
            pkgs = import nixpkgs {
              inherit system;
              overlays = [ rust-overlay.overlays.default ];
              config = {
                allowUnfree = true;
              };
            };
          }
        );
    in
    let
      devShellSet = forAllSystems (
        { system, pkgs }:
        let
          rustToolchain = pkgs.rust-bin.stable."1.98.1".default.override {
            extensions = [
              "rust-src"
              "rust-analyzer"
              "clippy"
              "rustfmt"
            ];
          };

          linuxOnly =
            pkgs: with pkgs; [
              mold
              lld
            ];
          darwinOnly = pkgs: with pkgs; [ libiconv ];

          commonInputs = [
            # Rust toolchain
            rustToolchain

            # Build tools
            pkgs.cargo-watch

            # Linker and compiler
            pkgs.clang

            # Native dependencies
            pkgs.pkg-config
            pkgs.openssl
            pkgs.protobuf
            pkgs.cmake
            pkgs.gnumake

            # Database (for sqlx)
            pkgs.postgresql

            # Infrastructure
            pkgs.docker-client

            # Utilities
            pkgs.jq
            pkgs.curl
            pkgs.openssh
            pkgs.git
            pkgs.opencode
          ];
        in
        pkgs.mkShell {
          name = "capsule";

          buildInputs =
            commonInputs
            ++ (if (system == "x86_64-linux" || system == "aarch64-linux") then linuxOnly pkgs else [ ])
            ++ (if system == "aarch64-darwin" then darwinOnly pkgs else [ ]);

          shellHook = ''
            echo "Capsule dev shell loaded"
            echo "Rust $(rustc --version)"
            echo "Run 'cargo setup' to install cargo tools"
          '';
        }
      );
    in
    {
      devShells = devShellSet;
      devShell = devShellSet;
    };
}

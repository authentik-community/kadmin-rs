{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    rust-overlay.url = "github:oxalica/rust-overlay";
    futils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
    futils,
  } @ inputs: let
    inherit (nixpkgs) lib;
    inherit (futils.lib) eachDefaultSystem defaultSystems;

    nixpkgsFor = lib.genAttrs defaultSystems (system:
      import nixpkgs {
        inherit system;
        overlays = [
          rust-overlay.overlays.default
        ];
      });
  in
    eachDefaultSystem (system: let
      pkgs = nixpkgsFor.${system};
    in {
      devShell = pkgs.mkShell {
        buildInputs = with pkgs; [
          (lib.hiPrio rust-bin.nightly.latest.rustfmt)
          (rust-bin.fromRustupToolchainFile ./rust-toolchain.toml)
          sccache

          poetry
          python3Full

          clang
          glibc
          krb5.out
          krb5.dev
          heimdal.dev
          libclang
          openssl
          pkg-config

          cargo-msrv
          cargo-release
          cargo-workspaces
          git
          just
          valgrind
        ];

        RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
        RUST_BACKTRACE = 1;
        RUSTC_WRAPPER = "sccache";
        LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";

        KADMIN_MIT_INCLUDES = "${pkgs.krb5.dev}/include";
        KADMIN_HEIMDAL_INCLUDES = "${pkgs.heimdal.dev}/include";
      };
    });
}

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
      devShell =
        pkgs.mkShell
        {
          buildInputs = with pkgs; [
            (lib.hiPrio rust-bin.nightly.latest.rustfmt)
            (rust-bin.fromRustupToolchainFile ./rust-toolchain.toml)
            sccache

            poetry
            python3Full

            clang
            glibc
            # krb5.out
            # krb5.dev
            # heimdal.dev
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
          KADMIN_MIT_KRB5_CONFIG = "${pkgs.krb5.dev}/bin/krb5-config";
          KADMIN_HEIMDAL_KRB5_CONFIG = "${pkgs.heimdal.dev}/bin/krb5-config";
          SYSTEM_DEPS_KRB5_NO_PKG_CONFIG = "true";
          SYSTEM_DEPS_KRB5_SEARCH_NATIVE = "${pkgs.krb5.lib}/lib";
          SYSTEM_DEPS_KRB5_LIB = "krb5";
          SYSTEM_DEPS_KADM5CLNT_NO_PKG_CONFIG = "true";
          SYSTEM_DEPS_KADM5CLNT_SEARCH_NATIVE = "${pkgs.krb5.lib}/lib";
          SYSTEM_DEPS_KADM5CLNT_LIB = "kadm5clnt_mit";
          SYSTEM_DEPS_KADM5CLNT_INCLUDE = "${pkgs.krb5.dev}/include";
        };
    });
}

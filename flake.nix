{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    rust-overlay.url = "github:oxalica/rust-overlay";
    futils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self
    , nixpkgs
    , rust-overlay
    , futils
    ,
    } @ inputs:
    let
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
    eachDefaultSystem
      (system:
      let
        pkgs = nixpkgsFor.${system};
      in
      {
        devShell =
          pkgs.mkShell
            {
              buildInputs = with pkgs; [
                (lib.hiPrio rust-bin.nightly.latest.rustfmt)
                (rust-bin.fromRustupToolchainFile ./rust-toolchain.toml)
                sccache

                python314
                uv

                clang
                glibc
                krb5.out
                krb5.dev
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
              UV_NO_BINARY_PACKAGE = "maturin ruff";

              KADMIN_MIT_CLIENT_INCLUDES = "${pkgs.krb5.dev}/include";
              KADMIN_MIT_SERVER_INCLUDES = "${pkgs.krb5.dev}/include";
              KADMIN_HEIMDAL_CLIENT_INCLUDES = "${pkgs.heimdal.dev}/include";
              KADMIN_HEIMDAL_SERVER_INCLUDES = "${pkgs.heimdal.dev}/include";
              KADMIN_MIT_CLIENT_KRB5_CONFIG = "${pkgs.krb5.dev}/bin/krb5-config";
              KADMIN_MIT_SERVER_KRB5_CONFIG = "${pkgs.krb5.dev}/bin/krb5-config";
              KADMIN_HEIMDAL_CLIENT_KRB5_CONFIG = "${pkgs.heimdal.dev}/bin/krb5-config";
              KADMIN_HEIMDAL_SERVER_KRB5_CONFIG = "${pkgs.heimdal.dev}/bin/krb5-config";

              K5TEST_MIT_KDB5_UTIL = "${pkgs.krb5}/bin/kdb5_util";
              K5TEST_MIT_KRB5KDC = "${pkgs.krb5}/bin/krb5kdc";
              K5TEST_MIT_KADMIN = "${pkgs.krb5}/bin/kadmin";
              K5TEST_MIT_KADMIN_LOCAL = "${pkgs.krb5}/bin/kadmin.local";
              K5TEST_MIT_KADMIND = "${pkgs.krb5}/bin/kadmind";
              K5TEST_MIT_KPROP = "${pkgs.krb5}/bin/kprop";
              K5TEST_MIT_KINIT = "${pkgs.krb5}/bin/kinit";
              K5TEST_MIT_KLIST = "${pkgs.krb5}/bin/klist";

              K5TEST_HEIMDAL_KDC = "${pkgs.heimdal}/libexec/kdc";
              K5TEST_HEIMDAL_KADMIN = "${pkgs.heimdal}/bin/kadmin";
              K5TEST_HEIMDAL_KADMIND = "${pkgs.heimdal}/libexec/kadmind";
              K5TEST_HEIMDAL_KINIT = "${pkgs.heimdal}/bin/kinit";
              K5TEST_HEIMDAL_KLIST = "${pkgs.heimdal}/bin/klist";
              K5TEST_HEIMDAL_KTUTIL = "${pkgs.heimdal}/bin/ktutil";
            };
      });
}

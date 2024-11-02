use std::{env, path::PathBuf};

use pkg_config::probe_library;

fn main() {
    let mut libraries = vec![
        probe_library("krb5").expect("Unable to find library 'krb5'."),
        probe_library("kdb").expect("Unable to find library 'kdb5'."),
    ];
    if cfg!(feature = "client") {
        libraries.push(probe_library("kadm-client").expect("Unable to find library 'kadm5clnt'."));
    }
    if cfg!(feature = "server") {
        libraries.push(probe_library("kadm-server").expect("Unable to find library 'kadm5srv'."));
    }

    for lib in libraries {
        for lib in lib.libs {
            println!("cargo:rustc-lib-lib={}", lib);
        }
    }

    let bindings = bindgen::builder()
        .header("src/wrapper.h")
        .allowlist_type("(_|)kadm5.*")
        .allowlist_function("kadm5.*")
        .allowlist_var("KADM5_.*")
        .allowlist_var("KRB5_NT_SRV_HST")
        .allowlist_var("KRB5_OK")
        .allowlist_function("krb5_init_context")
        .allowlist_function("krb5_free_context")
        .allowlist_function("krb5_get_error_message")
        .allowlist_function("krb5_free_error_message")
        .allowlist_function("krb5_parse_name")
        .allowlist_function("krb5_sname_to_principal")
        .allowlist_function("krb5_free_principal")
        .allowlist_function("krb5_unparse_name")
        .allowlist_function("krb5_free_unparsed_name")
        .allowlist_function("krb5_cc_get_principal")
        .allowlist_function("krb5_cc_default")
        .allowlist_function("krb5_cc_resolve")
        .allowlist_function("krb5_cc_close")
        .allowlist_function("krb5_get_default_realm")
        .allowlist_function("krb5_free_default_realm")
        .clang_arg("-fparse-all-comments")
        .derive_default(true)
        .generate_cstr(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

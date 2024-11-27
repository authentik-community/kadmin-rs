use std::{env, path::PathBuf};

fn main() {
    let deps = system_deps::Config::new().probe().unwrap();

    let mut builder = bindgen::builder()
        .header("src/wrapper.h")
        .allowlist_type("(_|)kadm5.*")
        .allowlist_function("kadm5.*")
        .allowlist_var("KADM5_.*")
        // Principal attributes
        .allowlist_var("KRB5_KDB_DISALLOW_POSTDATED")
        .allowlist_var("KRB5_KDB_DISALLOW_FORWARDABLE")
        .allowlist_var("KRB5_KDB_DISALLOW_TGT_BASED")
        .allowlist_var("KRB5_KDB_DISALLOW_RENEWABLE")
        .allowlist_var("KRB5_KDB_DISALLOW_PROXIABLE")
        .allowlist_var("KRB5_KDB_DISALLOW_DUP_SKEY")
        .allowlist_var("KRB5_KDB_DISALLOW_ALL_TIX")
        .allowlist_var("KRB5_KDB_REQUIRES_PRE_AUTH")
        .allowlist_var("KRB5_KDB_REQUIRES_HW_AUTH")
        .allowlist_var("KRB5_KDB_REQUIRES_PWCHANGE")
        .allowlist_var("KRB5_KDB_DISALLOW_SVR")
        .allowlist_var("KRB5_KDB_PWCHANGE_SERVICE")
        .allowlist_var("KRB5_KDB_SUPPORT_DESMD5")
        .allowlist_var("KRB5_KDB_NEW_PRINC")
        .allowlist_var("KRB5_KDB_OK_AS_DELEGATE")
        .allowlist_var("KRB5_KDB_OK_TO_AUTH_AS_DELEGATE")
        .allowlist_var("KRB5_KDB_NO_AUTH_DATA_REQUIRED")
        .allowlist_var("KRB5_KDB_LOCKDOWN_KEYS")
        // Other utilites
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
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    for include_path in deps.all_include_paths() {
        builder = builder.clang_arg(format!("-I{}", include_path.display()));
    }

    let bindings = builder.generate().expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

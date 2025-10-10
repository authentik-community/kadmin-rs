//! kadmin build script

// build.rs
use std::{
    env,
    fs::read_to_string,
    path::{Path, PathBuf},
    process::Command,
};

use strum::IntoEnumIterator;

#[derive(Debug, Clone)]
struct Kadm5Config {
    #[allow(dead_code)]
    variant: Kadm5Variant,
    include_paths: Vec<PathBuf>,
}

impl Kadm5Config {
    fn name(&self) -> &'static str {
        self.variant.name()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, strum::EnumIter)]
enum Kadm5Variant {
    Mit,
    Heimdal,
}

impl Kadm5Variant {
    fn name(&self) -> &'static str {
        match self {
            Kadm5Variant::Mit => "mit",
            Kadm5Variant::Heimdal => "heimdal",
        }
    }

    fn cargo_callbacks() {
        for variant in Self::iter() {
            println!("cargo:rustc-check-cfg=cfg({})", variant.name());
            println!(
                "cargo:rerun-if-env-changed={}",
                variant.includes_override_env_var()
            );
            println!(
                "cargo:rerun-if-env-changed={}",
                variant.bin_override_env_var()
            );
        }
    }

    fn includes_override_env_var(&self) -> &'static str {
        match self {
            Self::Mit => "KADMIN_MIT_INCLUDES",
            Self::Heimdal => "KADMIN_HEIMDAL_INCLUDES",
        }
    }

    fn bin_override_env_var(&self) -> &'static str {
        match self {
            Self::Mit => "KADMIN_MIT_KRB5_CONFIG",
            Self::Heimdal => "KADMIN_HEIMDAL_KRB5_CONFIG",
        }
    }
}

fn generate_bindings(config: &Kadm5Config, out_path: &Path) {
    let mut builder = bindgen::Builder::default()
        .header("src/wrapper.h")
        .allowlist_type("(_|)kadm5.*")
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
        .allowlist_var("ENCTYPE_.*")
        .allowlist_var("KRB5_KDB_SALTTYPE_.*")
        .allowlist_var("KRB5_TL_LAST_ADMIN_UNLOCK")
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
        .allowlist_function("krb5_string_to_enctype")
        .allowlist_function("krb5_string_to_salttype")
        .allowlist_function("krb5_enctype_to_string")
        .allowlist_function("krb5_salttype_to_string")
        .clang_arg("-fparse-all-comments")
        .derive_default(true)
        .generate_cstr(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    for include_path in &config.include_paths {
        builder = builder.clang_arg(format!("-I{}", include_path.display()));
    }

    let bindings = builder.generate().unwrap();

    bindings
        .write_to_file(out_path.join(format!("bindings_{}.rs", config.name())))
        .unwrap();
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    Kadm5Variant::cargo_callbacks();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    let mut found_any = false;

    if let Some(config) = find_kadm5(Kadm5Variant::Mit) {
        println!("cargo:rustc-cfg={}", config.name());
        generate_bindings(&config, &out_path);
        found_any = true;
    }

    if let Some(config) = find_kadm5(Kadm5Variant::Heimdal) {
        println!("cargo:rustc-cfg={}", config.name());
        generate_bindings(&config, &out_path);
        found_any = true;
    }

    if !found_any {
        panic!("Could not find MIT Kerberos or Heimdal kadm5 libraries.");
    }
}

fn find_kadm5(variant: Kadm5Variant) -> Option<Kadm5Config> {
    if let Some(config) = try_includes_override(variant) {
        return Some(config);
    }

    if let Some(config) = try_krb5_config(variant) {
        return Some(config);
    }

    if let Some(config) = try_pkg_config(variant) {
        return Some(config);
    }

    None
}

fn try_includes_override(variant: Kadm5Variant) -> Option<Kadm5Config> {
    if let Ok(includes_override) = env::var(variant.includes_override_env_var()) {
        return Some(Kadm5Config {
            variant,
            include_paths: includes_override
                .split_whitespace()
                .map(PathBuf::from)
                .collect(),
        });
    }
    None
}

fn try_krb5_config(variant: Kadm5Variant) -> Option<Kadm5Config> {
    if let Ok(bin_override) = env::var(variant.bin_override_env_var()) {
        if let Some(config) = probe_krb5_config(&bin_override, variant) {
            return Some(config);
        }
    }

    let bins = match variant {
        Kadm5Variant::Mit => vec!["krb5-config.mit", "krb5-config"],
        Kadm5Variant::Heimdal => vec!["krb5-config.heimdal", "krb5-config"],
    };

    for bin in bins {
        if let Some(bin) = probe_krb5_config(bin, variant) {
            return Some(bin);
        }
    }

    None
}

fn probe_krb5_config(bin: &str, variant: Kadm5Variant) -> Option<Kadm5Config> {
    let output = Command::new(bin)
        .arg("--cflags")
        .arg("kadm-client")
        .output()
        .or_else(|_| {
            Command::new(bin)
                .arg("--cflags")
                .arg("kadm-server")
                .output()
        })
        .or_else(|_| Command::new(bin).arg("--cflags").output())
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let cflags = String::from_utf8_lossy(&output.stdout);
    let include_paths: Vec<PathBuf> = cflags
        .split_whitespace()
        .filter_map(|flag| {
            if flag.starts_with("-I") {
                Some(PathBuf::from(&flag[2..]))
            } else {
                None
            }
        })
        .collect();

    if include_paths.is_empty() {
        return None;
    }

    // Search include paths for the header
    for include_path in &include_paths {
        let header_path = include_path.join("kadm5/admin.h");
        if header_path.exists() && verify_header_variant(&header_path, variant) {
            return Some(Kadm5Config {
                variant,
                include_paths: include_paths.clone(),
            });
        }
    }

    None
}

fn try_pkg_config(variant: Kadm5Variant) -> Option<Kadm5Config> {
    let pkg_names = match variant {
        Kadm5Variant::Mit => vec![
            "mit-krb5/kadm-client",
            "mit-krb5/kadm-server",
            "kadm-client",
            "kadm-server",
        ],
        Kadm5Variant::Heimdal => vec![
            "heimdal-kadm-server",
            "heimdal-kadm-client",
            "kadm-server",
            "kadm-client",
            "heimdal-kadm5",
        ],
    };

    for pkg_name in pkg_names {
        if let Ok(lib) = pkg_config::Config::new().probe(pkg_name) {
            if let Some(config) = probe_from_pkg_config(lib, variant) {
                return Some(config);
            }
        }
    }

    None
}

fn probe_from_pkg_config(lib: pkg_config::Library, variant: Kadm5Variant) -> Option<Kadm5Config> {
    for include_path in &lib.include_paths {
        let header_path = include_path.join("kadm5/admin.h");
        if header_path.exists() && verify_header_variant(&header_path, variant) {
            return Some(Kadm5Config {
                variant,
                include_paths: lib.include_paths.clone(),
            });
        }
    }

    None
}

fn verify_header_variant(path: &Path, variant: Kadm5Variant) -> bool {
    if let Ok(content) = read_to_string(path) {
        match variant {
            Kadm5Variant::Mit => content.contains("kiprop"),
            Kadm5Variant::Heimdal => !content.contains("kiprop"),
        }
    } else {
        false
    }
}

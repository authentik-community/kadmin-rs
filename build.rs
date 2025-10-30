//! kadmin build script

// build.rs
use std::{
    collections::HashSet,
    env,
    fs::{read_to_string, write},
    path::{Path, PathBuf},
    process::Command,
};

use quote::quote;
use strum::IntoEnumIterator;

#[derive(Debug, Clone, Copy, PartialEq, strum::EnumIter)]
enum KAdm5Variant {
    #[cfg(feature = "mit_client")]
    MitClient,
    #[cfg(feature = "mit_server")]
    MitServer,
    #[cfg(feature = "heimdal_client")]
    HeimdalClient,
    #[cfg(feature = "heimdal_server")]
    HeimdalServer,
}

impl KAdm5Variant {
    fn name(&self) -> &'static str {
        match self {
            #[cfg(feature = "mit_client")]
            Self::MitClient => "mit_client",
            #[cfg(feature = "mit_server")]
            Self::MitServer => "mit_server",
            #[cfg(feature = "heimdal_client")]
            Self::HeimdalClient => "heimdal_client",
            #[cfg(feature = "heimdal_server")]
            Self::HeimdalServer => "heimdal_server",
        }
    }

    fn is_mit(&self) -> bool {
        match self {
            #[cfg(feature = "mit_client")]
            Self::MitClient => true,
            #[cfg(feature = "mit_server")]
            Self::MitServer => true,
            #[cfg(feature = "heimdal_client")]
            Self::HeimdalClient => false,
            #[cfg(feature = "heimdal_server")]
            Self::HeimdalServer => false,
        }
    }

    fn is_heimdal(&self) -> bool {
        match self {
            #[cfg(feature = "mit_client")]
            Self::MitClient => false,
            #[cfg(feature = "mit_server")]
            Self::MitServer => false,
            #[cfg(feature = "heimdal_client")]
            Self::HeimdalClient => true,
            #[cfg(feature = "heimdal_server")]
            Self::HeimdalServer => true,
        }
    }

    fn is_server(&self) -> bool {
        match self {
            #[cfg(feature = "mit_client")]
            Self::MitClient => false,
            #[cfg(feature = "mit_server")]
            Self::MitServer => true,
            #[cfg(feature = "heimdal_client")]
            Self::HeimdalClient => false,
            #[cfg(feature = "heimdal_server")]
            Self::HeimdalServer => true,
        }
    }

    fn cargo_callbacks() {
        // Those are hardcoded because we need to handle them even if disabled
        println!("cargo:rustc-check-cfg=cfg(mit_client)");
        println!("cargo:rustc-check-cfg=cfg(mit_server)");
        println!("cargo:rustc-check-cfg=cfg(heimdal_client)");
        println!("cargo:rustc-check-cfg=cfg(heimdal_server)");
        for variant in Self::iter() {
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

    fn includes_override_env_var(&self) -> String {
        format!("KADMIN_{}_INCLUDES", self.name().to_uppercase())
    }

    fn bins(&self) -> Vec<&'static str> {
        match self {
            #[cfg(feature = "mit_client")]
            Self::MitClient => vec![
                "krb5-config.mit",
                "/opt/homebrew/opt/krb5/bin/krb5-config",
                "krb5-config",
            ],
            #[cfg(feature = "mit_server")]
            Self::MitServer => vec![
                "krb5-config.mit",
                "/opt/homebrew/opt/krb5/bin/krb5-config",
                "krb5-config",
            ],
            #[cfg(feature = "heimdal_client")]
            Self::HeimdalClient => {
                vec![
                    "krb5-config.heimdal",
                    "heimdal-krb5-config",
                    "/opt/homebrew/opt/heimdal/bin/krb5-config",
                    "krb5-config",
                ]
            }
            #[cfg(feature = "heimdal_server")]
            Self::HeimdalServer => {
                vec![
                    "krb5-config.heimdal",
                    "heimdal-krb5-config",
                    "/opt/homebrew/opt/heimdal/bin/krb5-config",
                    "krb5-config",
                ]
            }
        }
    }

    fn bin_lib(&self) -> &'static str {
        match self {
            #[cfg(feature = "mit_client")]
            Self::MitClient => "kadm-client",
            #[cfg(feature = "mit_server")]
            Self::MitServer => "kadm-server",
            #[cfg(feature = "heimdal_client")]
            Self::HeimdalClient => "kadm-client",
            #[cfg(feature = "heimdal_server")]
            Self::HeimdalServer => "kadm-server",
        }
    }

    fn bin_override_env_var(&self) -> String {
        format!("KADMIN_{}_KRB5_CONFIG", self.name().to_uppercase())
    }

    fn pkg_config_names(&self) -> Vec<&'static str> {
        match self {
            #[cfg(feature = "mit_client")]
            Self::MitClient => vec!["mit-krb5/kadm-client", "kadm-client"],
            #[cfg(feature = "mit_server")]
            Self::MitServer => vec!["mit-krb5/kadm-server", "kadm-server"],
            #[cfg(feature = "heimdal_client")]
            Self::HeimdalClient => vec!["heimdal-kadm-client", "kadm-client", "heimdal-kadm5"],
            #[cfg(feature = "heimdal_server")]
            Self::HeimdalServer => vec!["heimdal-kadm-server", "kadm-server", "heimdal-kadm5"],
        }
    }

    fn verify_lib_name(&self, lib: &str) -> bool {
        if !lib.contains("kadm5") {
            return false;
        }

        match self {
            #[cfg(feature = "mit_client")]
            Self::MitClient => lib.contains("clnt"),
            #[cfg(feature = "mit_server")]
            Self::MitServer => lib.contains("srv"),
            #[cfg(feature = "heimdal_client")]
            Self::HeimdalClient => lib.contains("clnt"),
            #[cfg(feature = "heimdal_server")]
            Self::HeimdalServer => lib.contains("srv"),
        }
    }

    fn verify_header_variant(&self, path: &Path) -> bool {
        if let Ok(content) = read_to_string(path) {
            match self {
                #[cfg(feature = "mit_client")]
                Self::MitClient => content.contains("kiprop"),
                #[cfg(feature = "mit_server")]
                Self::MitServer => content.contains("kiprop"),
                #[cfg(feature = "heimdal_client")]
                Self::HeimdalClient => !content.contains("kiprop"),
                #[cfg(feature = "heimdal_server")]
                Self::HeimdalServer => !content.contains("kiprop"),
            }
        } else {
            false
        }
    }
}

#[derive(Debug, Clone)]
struct KAdm5Config {
    variant: KAdm5Variant,
    include_paths: HashSet<PathBuf>,
    library_paths: HashSet<PathBuf>,
    libraries: HashSet<String>,
}

impl KAdm5Config {
    fn name(&self) -> &'static str {
        self.variant.name()
    }

    fn outputs(&self) {
        println!(
            "cargo::rustc-env=KADMIN_BUILD_{}_LIBRARY_PATHS={}",
            self.name().to_uppercase(),
            self.library_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<String>>()
                .join(" ")
        );
        println!(
            "cargo::rustc-env=KADMIN_BUILD_{}_LIBRARIES={}",
            self.name().to_uppercase(),
            self.libraries
                .iter()
                .cloned()
                .collect::<Vec<String>>()
                .join(" ")
        );
    }

    fn extend(&mut self, other: &Self) {
        self.library_paths.extend(other.library_paths.clone());
        self.libraries.extend(other.libraries.clone());
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    KAdm5Variant::cargo_callbacks();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    let mut found_any = false;

    #[cfg(feature = "mit_client")]
    if let Some(config) = find_kadm5(KAdm5Variant::MitClient) {
        println!("cargo:rustc-cfg={}", config.name());
        println!(
            "cargo::warning=Found MIT Kerberos kadm5-client. Includes: {:?}. Links: {:?}. \
             Libraries: {:?}",
            config.include_paths, config.library_paths, config.libraries,
        );
        generate_bindings(&config, &out_path);
        found_any = true;
    }
    #[cfg(feature = "mit_server")]
    if let Some(config) = find_kadm5(KAdm5Variant::MitServer) {
        println!("cargo:rustc-cfg={}", config.name());
        println!(
            "cargo::warning=Found MIT Kerberos kadm5-server. Includes: {:?}. Links: {:?}. \
             Libraries: {:?}",
            config.include_paths, config.library_paths, config.libraries,
        );
        generate_bindings(&config, &out_path);
        found_any = true;
    }

    #[cfg(feature = "heimdal_client")]
    if let Some(config) = find_kadm5(KAdm5Variant::HeimdalClient) {
        println!("cargo:rustc-cfg={}", config.name());
        println!(
            "cargo::warning=Found Heimdal Kerberos kadm5-client. Includes: {:?}. Links: {:?}. \
             Libraries: {:?}",
            config.include_paths, config.library_paths, config.libraries,
        );
        generate_bindings(&config, &out_path);
        found_any = true;
    }

    #[cfg(feature = "heimdal_server")]
    if let Some(config) = find_kadm5(KAdm5Variant::HeimdalServer) {
        println!("cargo:rustc-cfg={}", config.name());
        println!(
            "cargo::warning=Found Heimdal Kerberos kadm5-server. Includes: {:?}. Links: {:?}. \
             Libraries: {:?}",
            config.include_paths, config.library_paths, config.libraries,
        );
        generate_bindings(&config, &out_path);
        found_any = true;
    }

    if !found_any {
        panic!("Could not find MIT Kerberos or Heimdal kadm5 libraries.");
    }
}

fn find_kadm5(variant: KAdm5Variant) -> Option<KAdm5Config> {
    let mut config = None;
    if let Some(c) = try_overrides(variant) {
        config = Some(c);
    }

    if let Some(c) = try_krb5_config(variant) {
        if let Some(config) = config.as_mut() {
            config.extend(&c);
        } else {
            config = Some(c);
        }
    }

    if let Some(c) = try_pkg_config(variant) {
        if let Some(config) = config.as_mut() {
            config.extend(&c);
        } else {
            config = Some(c);
        }
    }

    config
}

fn try_overrides(variant: KAdm5Variant) -> Option<KAdm5Config> {
    if let Ok(includes_override) = env::var(variant.includes_override_env_var()) {
        return Some(KAdm5Config {
            variant,
            include_paths: includes_override
                .split_whitespace()
                .map(PathBuf::from)
                .collect(),
            library_paths: HashSet::new(),
            libraries: HashSet::new(),
        });
    }
    None
}

fn try_krb5_config(variant: KAdm5Variant) -> Option<KAdm5Config> {
    let mut config: Option<KAdm5Config> = None;
    let libs = vec![Some(variant.bin_lib()), None];

    if let Ok(bin_override) = env::var(variant.bin_override_env_var()) {
        for lib in libs.clone() {
            if let Some(c) = probe_krb5_config(&bin_override, lib, variant) {
                if let Some(config) = config.as_mut() {
                    config.extend(&c);
                } else {
                    config = Some(c);
                }
            }
        }
    }

    for bin in variant.bins() {
        for lib in libs.clone() {
            if let Some(c) = probe_krb5_config(bin, lib, variant) {
                if let Some(config) = config.as_mut() {
                    config.extend(&c);
                } else {
                    config = Some(c);
                }
            }
        }
    }

    config
}

fn probe_krb5_config(bin: &str, lib: Option<&str>, variant: KAdm5Variant) -> Option<KAdm5Config> {
    let mut args = vec!["--cflags", "--libs"];
    if let Some(lib) = lib {
        args.push(lib);
    }
    let output = Command::new(bin).args(args).output().ok()?;

    if !output.status.success() {
        return None;
    }

    let output = String::from_utf8_lossy(&output.stdout);
    let include_paths: HashSet<PathBuf> = output
        .split_whitespace()
        .filter_map(|flag| flag.strip_prefix("-I").map(|flag| PathBuf::from(&flag)))
        .collect();
    let library_paths: HashSet<PathBuf> = output
        .split_whitespace()
        .filter_map(|flag| flag.strip_prefix("-L").map(|flag| PathBuf::from(&flag)))
        .collect();
    let libraries: HashSet<String> = output
        .split_whitespace()
        .filter_map(|flag| flag.strip_prefix("-l"))
        .filter(|lib| variant.verify_lib_name(lib))
        .map(|lib| lib.to_owned())
        .collect();

    if include_paths.is_empty() {
        return None;
    }

    // Search include paths for the header
    for include_path in &include_paths {
        let header_path = include_path.join("kadm5/admin.h");
        if header_path.exists() && variant.verify_header_variant(&header_path) {
            return Some(KAdm5Config {
                variant,
                include_paths,
                library_paths,
                libraries,
            });
        }
    }

    None
}

fn try_pkg_config(variant: KAdm5Variant) -> Option<KAdm5Config> {
    let mut config: Option<KAdm5Config> = None;

    for pkg_name in variant.pkg_config_names() {
        if let Ok(lib) = pkg_config::Config::new().probe(pkg_name) {
            if let Some(c) = probe_from_pkg_config(lib, variant) {
                if let Some(config) = config.as_mut() {
                    config.extend(&c);
                } else {
                    config = Some(c);
                }
            }
        }
    }

    config
}

fn probe_from_pkg_config(lib: pkg_config::Library, variant: KAdm5Variant) -> Option<KAdm5Config> {
    for include_path in &lib.include_paths {
        let header_path = include_path.join("kadm5/admin.h");
        if header_path.exists() && variant.verify_header_variant(&header_path) {
            return Some(KAdm5Config {
                variant,
                include_paths: HashSet::from_iter(lib.include_paths.iter().cloned()),
                library_paths: HashSet::from_iter(lib.link_paths.iter().cloned()),
                libraries: lib
                    .libs
                    .into_iter()
                    .filter(|lib| lib.contains("kadm5"))
                    .collect(),
            });
        }
    }

    None
}

fn generate_bindings(config: &KAdm5Config, out_path: &Path) {
    config.outputs();

    let mut builder = bindgen::builder()
        .clang_arg(format!("-DKADMIN_RS_{}", config.name().to_uppercase()))
        .header("src/wrapper.h")
        .allowlist_type("(_|)kadm5.*")
        .allowlist_type("krb5_key_salt_tuple")
        .allowlist_type("krb5_enctype")
        .allowlist_var("KADM5_.*")
        .allowlist_var("KRB5_TL_.*")
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
        .allowlist_function("kadm5_chpass_principal")
        .allowlist_function("kadm5_create_principal")
        .allowlist_function("kadm5_delete_principal")
        .allowlist_function("kadm5_destroy")
        .allowlist_function("kadm5_flush")
        .allowlist_function("kadm5_free_name_list")
        .allowlist_function("kadm5_free_principal_ent")
        .allowlist_function("kadm5_free_strings")
        .allowlist_function("kadm5_get_principal")
        .allowlist_function("kadm5_get_principals")
        .allowlist_function("kadm5_get_privs")
        .allowlist_function("kadm5_get_strings")
        .allowlist_function("kadm5_init_krb5_context")
        .allowlist_function("kadm5_init_with_creds")
        .allowlist_function("kadm5_init_with_creds_ctx")
        .allowlist_function("kadm5_init_with_password")
        .allowlist_function("kadm5_init_with_password_ctx")
        .allowlist_function("kadm5_init_with_skey")
        .allowlist_function("kadm5_init_with_skey_ctx")
        .allowlist_function("kadm5_modify_principal")
        .allowlist_function("kadm5_randkey_principal")
        .allowlist_function("kadm5_rename_principal")
        .allowlist_function("kadm5_set_string")
        .allowlist_function("krb5_cc_close")
        .allowlist_function("krb5_cc_default")
        .allowlist_function("krb5_cc_get_principal")
        .allowlist_function("krb5_cc_resolve")
        .allowlist_function("krb5_enctype_to_string")
        .allowlist_function("krb5_free_context")
        .allowlist_function("krb5_free_default_realm")
        .allowlist_function("krb5_free_error_message")
        .allowlist_function("krb5_free_principal")
        .allowlist_function("krb5_free_unparsed_name")
        .allowlist_function("krb5_get_default_realm")
        .allowlist_function("krb5_get_error_message")
        .allowlist_function("krb5_init_context")
        .allowlist_function("krb5_parse_name")
        .allowlist_function("krb5_salttype_to_string")
        .allowlist_function("krb5_sname_to_principal")
        .allowlist_function("krb5_string_to_enctype")
        .allowlist_function("krb5_string_to_salttype")
        .allowlist_function("krb5_unparse_name")
        .clang_arg("-fparse-all-comments")
        .derive_default(true)
        .generate_cstr(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    if config.variant.is_mit() || config.variant.is_heimdal() && config.variant.is_server() {
        builder = builder
            .allowlist_function("kadm5_chpass_principal_3")
            .allowlist_function("kadm5_create_policy")
            .allowlist_function("kadm5_create_principal_3")
            .allowlist_function("kadm5_delete_policy")
            .allowlist_function("kadm5_free_policy_ent")
            .allowlist_function("kadm5_get_policies")
            .allowlist_function("kadm5_get_policy")
            .allowlist_function("kadm5_modify_policy")
            .allowlist_function("kadm5_randkey_principal_3");
    }

    for include_path in &config.include_paths {
        builder = builder.clang_arg(format!("-I{}", include_path.display()));
    }

    let bindings = builder.generate().unwrap();
    let bindings_path = out_path.join(format!("bindings_{}.rs", config.name()));

    bindings.write_to_file(&bindings_path).unwrap();

    patch_heimdal_error_code(&bindings_path);
    transform_bindings_functions_to_dlopen_wrapper(&bindings_path);
    #[cfg(feature = "python")]
    extract_constants_to_python_wrapper(config, &bindings_path, out_path);
}

// Latest versions of heimdal are putting errors in an enum, which is good, but breaks
// compatibility with older versions. Also, this simplifies the code a bit since we don't have to
// differentiate between MIT and Heimdal as much.
fn patch_heimdal_error_code(bindings_path: &Path) {
    let content = read_to_string(bindings_path).unwrap();
    let content = content.replace("kadm5_error_number_", "");
    write(bindings_path, content).unwrap();
}

fn transform_bindings_functions_to_dlopen_wrapper(bindings_path: &Path) {
    let content = read_to_string(bindings_path).unwrap();

    let syntax_tree = syn::parse_file(&content).unwrap();

    let mut bindings = Vec::new();
    let mut function_fields = Vec::new();

    for item in syntax_tree.items {
        match item {
            syn::Item::ForeignMod(foreign_mod) => {
                for foreign_item in foreign_mod.items {
                    if let syn::ForeignItem::Fn(func) = foreign_item {
                        let name = &func.sig.ident;
                        let inputs = &func.sig.inputs;
                        let output = &func.sig.output;

                        function_fields.push(quote! {
                            #name: unsafe extern "C" fn(#inputs) #output
                        });
                    }
                }
            }
            _ => bindings.push(item),
        }
    }

    let bindings_tokens = quote! {
        #(#bindings)*

        use dlopen2::wrapper::WrapperApi;

        #[derive(WrapperApi)]
        pub struct Api {
            #(#function_fields,)*
        }
    };

    let bindings_syntax = syn::parse2(bindings_tokens).unwrap();
    let bindings_output = prettyplease::unparse(&bindings_syntax);
    write(bindings_path, bindings_output).unwrap();
}

#[cfg(feature = "python")]
fn extract_constants_to_python_wrapper(
    config: &KAdm5Config,
    bindings_path: &Path,
    out_path: &Path,
) {
    let content = read_to_string(bindings_path).unwrap();

    let syntax_tree = syn::parse_file(&content).unwrap();

    let variant_name = config.name();
    let sys_module = quote::format_ident!("{}", config.name());

    let mut consts = Vec::new();
    for item in syntax_tree.items {
        if let syn::Item::Const(const_item) = item {
            if const_item.ident == "_" {
                continue;
            }
            if let syn::Type::Reference(syn::TypeReference { elem, .. }) = &*const_item.ty {
                if let syn::Type::Path(syn::TypePath { path, .. }) = &**elem {
                    if let Some(segment) = path.segments.last() {
                        if segment.ident == "CStr" {
                            continue;
                        }
                    }
                }
            }
            consts.push(const_item.ident.clone());
        }
    }

    let add_statements: Vec<_> = consts
        .iter()
        .map(|name| {
            let name_str = name.to_string();
            quote! {
                m.add(#name_str, crate::sys::#sys_module::#name)?;
            }
        })
        .collect();

    let python_wrapper_tokens = quote! {
        use pyo3::prelude::*;

        pub(super) fn init(parent: &Bound<'_, PyModule>) -> PyResult<()> {
            let m = PyModule::new(parent.py(), #variant_name)?;
            #(#add_statements)*
            parent.add_submodule(&m)?;
            Ok(())
        }
    };

    let python_wrapper_syntax = syn::parse2(python_wrapper_tokens).unwrap();
    let python_wrapper_output = prettyplease::unparse(&python_wrapper_syntax);
    let python_wrapper_path = out_path.join(format!("python_bindings_{}.rs", config.name()));
    write(python_wrapper_path, python_wrapper_output).unwrap();
}

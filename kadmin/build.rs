//! kadmin build script
#[cfg(feature = "java")]
use std::{env, path::Path};

#[cfg(feature = "java")]
use flapigen::{Generator, JavaConfig, LanguageConfig};

#[cfg(feature = "java")]
fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let in_src = Path::new("src").join("java.rs.in");
    let out_src = Path::new(&out_dir).join("java.rs");
    let java_cfg = JavaConfig::new(Path::new("..").join("java").join("rust"), "rust".into());
    let gen = Generator::new(LanguageConfig::JavaConfig(java_cfg))
        .remove_not_generated_files_from_output_directory(true)
        .rustfmt_bindings(true);
    gen.expand("kadmin", &in_src, &out_src);
    println!("cargo:rerun-if-changed={}", in_src.display());
}

#[cfg(not(feature = "java"))]
fn main() {}

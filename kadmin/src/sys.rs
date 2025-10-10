#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_qualifications)]
#![allow(clippy::exhaustive_structs)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::ptr_offset_with_cast)]
#![allow(clippy::semicolon_if_nothing_returned)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::unseparated_literal_suffix)]
#![allow(clippy::useless_transmute)]
#![allow(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::unescaped_backticks)]

#[cfg(mit)]
pub mod mit {
    pub fn library_paths() -> Vec<&'static str> {
        env!("KADMIN_BUILD_MIT_LIBRARY_PATHS")
            .split_whitespace()
            .collect()
    }

    pub fn libraries() -> Vec<&'static str> {
        env!("KADMIN_BUILD_MIT_LIBRARIES")
            .split_whitespace()
            .collect()
    }

    include!(concat!(env!("OUT_DIR"), "/bindings_mit.rs"));
}

#[cfg(heimdal)]
pub mod heimdal {
    pub fn library_paths() -> Vec<&'static str> {
        env!("KADMIN_BUILD_HEIMDAL_LIBRARY_PATHS")
            .split_whitespace()
            .collect()
    }

    pub fn libraries() -> Vec<&'static str> {
        env!("KADMIN_BUILD_HEIMDAL_LIBRARIES")
            .split_whitespace()
            .collect()
    }

    include!(concat!(env!("OUT_DIR"), "/bindings_heimdal.rs"));
}

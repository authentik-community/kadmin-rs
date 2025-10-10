#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::exhaustive_structs)]
#![allow(clippy::unseparated_literal_suffix)]
#![allow(clippy::unreadable_literal)]

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

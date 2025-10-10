#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(missing_docs)]

#[cfg(mit)]
pub mod mit {
    include!(concat!(env!("OUT_DIR"), "/bindings_mit.rs"));
}

#[cfg(heimdal)]
pub mod heimdal {
    include!(concat!(env!("OUT_DIR"), "/bindings_heimdal.rs"));
}

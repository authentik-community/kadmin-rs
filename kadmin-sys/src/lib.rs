#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[cfg(all(feature = "client", feature = "server"))]
compile_error!("Feature \"client\" and feature \"server\" cannot be enabled at the same time.");

#[cfg(all(not(feature = "client"), not(feature = "server")))]
compile_error!("Exactly one of feature \"client\" or feature \"server\" must be selected.");

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

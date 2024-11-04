//! # Raw bindings to libkadm5
//!
//! This crate providers raw bindings to libkadm5.
//!
//! These bindings are generated by [bindgen](https://docs.rs/bindgen) by including `kadm5/admin.h`. The types provided
//! are filtered to only import required symbols for kadm5. In the future, this crate may also allow for more symbols
//! that may be useful, such as error types.
//!
//! This crate links against libkrb5 plus the required kadm5 library depending on the feature
//! selected (see below).
//!
//! By default, those include headers and libraries are found using pkg-config. You can override this behavior with the
//! following environment variables (which must be paths to directories containing the required libraries and header
//! files):
//!
//! - `SYSTEM_DEPS_KRB5_SEARCH_NATIVE`
//! - `SYSTEM_DEPS_KRB5_INCLUDE`
//! - `SYSTEM_DEPS_KADM5CLNT_SEARCH_NATIVE`
//! - `SYSTEM_DEPS_KADM5CLNT_INCLUDE`
//! - `SYSTEM_DEPS_KADM5SRV_SEARCH_NATIVE`
//! - `SYSTEM_DEPS_KADM5SRV_INCLUDE`
//!
//! You can read more about this in the [system-deps documentation](https://docs.rs/system-deps).
//!
//! # Features
//!
//! This crate offers two features, client and server. You must choose one of them depending on how your application is
//! going to interact with the KDC. By default, none are enabled and the crate will not compile.
//!
//! - `client`: links against `kadm5clnt`. Use this is you plan to remotely access the KDC, using kadmind's GSS-API RPC
//!   interface, like the CLI tool `kadmin` does.
//! - `server`: links against `kadm5srv`. Use this is you plan to directly edit the KDB from the machine where the KDC
//!   is running, like the CLI tool `kadmin.local` does.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[cfg(all(feature = "client", feature = "server", not(docsrs)))]
compile_error!("Feature \"client\" and feature \"server\" cannot be enabled at the same time.");

#[cfg(all(not(feature = "client"), not(feature = "server"), not(docsrs)))]
compile_error!("Exactly one of feature \"client\" or feature \"server\" must be selected.");

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

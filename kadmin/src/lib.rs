//! Rust bindings to libkadm5
//!
//! This is a safe, idiomatic Rust interface to libkadm5. This crate offers two features, `client` and `local`. They are similar to how kadmin-sys behaves. You should only enable one of them.
//! 
//! With the `client` feature:
//! 
//! ```no_run
//! use kadmin::{KAdmin, KAdminImpl};
//! 
//! # #[cfg(feature = "client")]
//! # fn example() {
//! let princ = "user/admin@EXAMPLE.ORG";
//! let password = "vErYsEcUrE";
//! 
//! let kadmin = KAdmin::builder().with_password(&princ, &password).unwrap();
//! 
//! dbg!("{}", kadmin.list_principals("*").unwrap());
//! # }
//! ```
//! 
//! With the `local` feature:
//! 
//! ```no_run
//! use kadmin::{KAdmin, KAdminImpl};
//! 
//! # #[cfg(feature = "local")]
//! # fn example() {
//! let princ = "user/admin@EXAMPLE.ORG";
//! let password = "vErYsEcUrE";
//! 
//! let kadmin = KAdmin::builder().with_local().unwrap();
//! 
//! dbg!("{}", kadmin.list_principals("*").unwrap());
//! # }
//! ```
//! 
//! # About thread safety
//! 
//! As far as I can tell, libkadm5 APIs are **not** thread safe. As such, the types provided by this crate are neither `Send` nor `Sync`. You _must not_ use those with threads. You can either create a `KAdmin` instance per thread, or use the `kadmin::sync::KAdmin` interface that spawns a thread and sends the various commands to it. The API is not exactly the same as the non-thread-safe one, but should be close enough that switching between one or the other is easy enough.

#[cfg(all(feature = "client", feature = "local", not(docsrs)))]
compile_error!("Feature \"client\" and feature \"local\" cannot be enabled at the same time.");

#[cfg(all(not(feature = "client"), not(feature = "local"), not(docsrs)))]
compile_error!("Exactly one of feature \"client\" or feature \"local\" must be selected.");

pub mod context;
pub use context::KAdminContext;

pub mod db_args;
pub use db_args::KAdminDbArgs;

pub mod error;
pub use error::Error;

pub mod kadmin;
pub use kadmin::{KAdmin, KAdminImpl};

pub mod params;
pub use params::KAdminParams;

pub mod principal;
pub use principal::Principal;

mod strconv;

pub mod sync;

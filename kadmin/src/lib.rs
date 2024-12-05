//! Rust bindings to libkadm5
//!
//! This is a safe, idiomatic Rust interface to libkadm5. This crate offers two features, `client`
//! and `local`. They are similar to how kadmin-sys behaves. You should only enable one of them.
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
//! dbg!("{}", kadmin.list_principals(None).unwrap());
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
//! let kadmin = KAdmin::builder().with_local().unwrap();
//!
//! dbg!("{}", kadmin.list_principals(None).unwrap());
//! # }
//! ```
//!
//! # About thread safety
//!
//! As far as I can tell, libkadm5 APIs are **not** thread safe. As such, the types provided by this
//! crate are neither `Send` nor `Sync`. You _must not_ use those with threads. You can either
//! create a `KAdmin` instance per thread, or use the `kadmin::sync::KAdmin` interface that spawns a
//! thread and sends the various commands to it. The API is not exactly the same as the
//! non-thread-safe one, but should be close enough that switching between one or the other is
//! easy enough.

#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(all(feature = "client", feature = "local", not(doc)))]
compile_error!("Feature \"client\" and feature \"local\" cannot be enabled at the same time.");

#[cfg(all(not(feature = "client"), not(feature = "local"), not(doc)))]
compile_error!("Exactly one of feature \"client\" or feature \"local\" must be selected.");

mod conv;

pub mod error;
pub use error::Error;

pub mod context;
pub use context::Context;

pub mod params;
pub use params::Params;

pub mod db_args;
pub use db_args::DbArgs;

pub mod tl_data;
pub use tl_data::{TlData, TlDataEntry};

pub mod keysalt;
pub use keysalt::{EncryptionType, KeySalt, KeySalts, SaltType};

pub mod kadmin;
pub use kadmin::{KAdmin, KAdminApiVersion, KAdminImpl};

pub mod sync;

pub mod policy;
pub use policy::Policy;

pub mod principal;
pub use principal::{Principal, PrincipalAttributes};

#[cfg(feature = "python")]
mod python;

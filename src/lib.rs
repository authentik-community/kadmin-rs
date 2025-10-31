//! Rust bindings to libkadm5
//!
//! This is a safe, idiomatic Rust interface to libkadm5.
//!
//! This library does not link against libkadm5, but instead loads it at runtime to be able to
//! support multiple variants.
//!
//! It provides four features, all enabled by default, for the supported variants of libkadm5:
//!
//! - `mit_client`
//! - `mit_server`
//! - `heimdal_client`
//! - `heimdal_server`
//!
//! For remote operations:
//!
//! ```no_run
//! use kadmin::{KAdm5Variant, KAdmin, KAdminImpl};
//!
//! let princ = "user/admin@EXAMPLE.ORG";
//! let password = "vErYsEcUrE";
//!
//! let kadmin = KAdmin::builder(KAdm5Variant::MitClient)
//!     .with_password(&princ, &password)
//!     .unwrap();
//!
//! dbg!("{}", kadmin.list_principals(None).unwrap());
//! ```
//!
//! For local operations:
//!
//! ```no_run
//! use kadmin::{KAdm5Variant, KAdmin, KAdminImpl};
//!
//! let kadmin = KAdmin::builder(KAdm5Variant::MitServer)
//!     .with_local()
//!     .unwrap();
//!
//! dbg!("{}", kadmin.list_principals(None).unwrap());
//! ```
//!
//! # About compilation
//!
//! During compilation, all the enabled variants will be discovered and bindings will be generated
//! from the discovered variants. If a variant cannot be discovered, it will not be available for
//! use. The following environment variables are available to override that discovery process:
//!
//! To override the directories in which the `kadm5/admin.h` header will be searched for:
//!
//! - `KADMIN_MIT_CLIENT_INCLUDES`
//! - `KADMIN_MIT_SERVER_INCLUDES`
//! - `KADMIN_HEIMDAL_CLIENT_INCLUDES`
//! - `KADMIN_HEIMDAL_SERVER_INCLUDES`
//!
//! To override the path to the `krb5-config` binary:
//!
//! - `KADM5_MIT_CLIENT_KRB5_CONFIG`
//! - `KADM5_MIT_SERVER_KRB5_CONFIG`
//! - `KADM5_HEIMDAL_CLIENT_KRB5_CONFIG`
//! - `KADM5_HEIMDAL_SERVER_KRB5_CONFIG`
//!
//! Library paths will also be looked for, and forwarded so that at runtime, the library can be
//! loaded. If it cannot find any, it will try to load a generic library from the system library
//! paths. You can override the path the library is loaded from with [`sys::Library::from_path`].
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

#[cfg(any(mit_client, mit_server, heimdal_server))]
pub mod policy;
#[cfg(any(mit_client, mit_server, heimdal_server))]
pub use policy::Policy;

pub mod principal;
pub use principal::Principal;

pub mod sys;
pub use sys::KAdm5Variant;

#[cfg(feature = "python")]
mod python;

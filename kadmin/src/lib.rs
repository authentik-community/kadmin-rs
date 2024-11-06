#[cfg(all(feature = "client", feature = "local"))]
compile_error!("Feature \"client\" and feature \"local\" cannot be enabled at the same time.");

#[cfg(all(not(feature = "client"), not(feature = "local")))]
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

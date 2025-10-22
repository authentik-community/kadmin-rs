//! Bindings to various kadm5 libraries

use std::ffi::OsStr;

use dlopen2::wrapper::{Container, WrapperApi};
#[cfg(feature = "python")]
use pyo3::prelude::*;

use crate::error::Result;

/// kadm5 library variant
///
/// Represent a kadm5 library to use. This struct will determine which C library kadmin will link
/// against. The list of currently supported options consist of the enum variants.
///
/// Depending on how kadmin was compiled, not all variants may be supported on your system. Refer
/// to the crate's documentation on how to compile for all possible options.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[allow(clippy::exhaustive_enums)]
#[repr(u32)]
#[cfg_attr(feature = "python", pyclass(eq, eq_int))]
pub enum KAdm5Variant {
    #[cfg(mit_client)]
    /// MIT krb5 client-side
    MitClient,
    #[cfg(mit_server)]
    /// MIT krb5 server-side
    MitServer,
    #[cfg(heimdal_client)]
    /// Heimdal client-side
    HeimdalClient,
    #[cfg(heimdal_server)]
    /// Heimdal server-side
    HeimdalServer,
}

impl KAdm5Variant {
    /// Check if this [`KAdm5Variant`] is for MIT krb5
    pub fn is_mit(&self) -> bool {
        match self {
            #[cfg(mit_client)]
            Self::MitClient => true,
            #[cfg(mit_server)]
            Self::MitServer => true,
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    /// Check if this [`KAdm5Variant`] is for Heimdal
    pub fn is_heimdal(&self) -> bool {
        match self {
            #[cfg(heimdal_client)]
            Self::HeimdalClient => true,
            #[cfg(heimdal_server)]
            Self::HeimdalServer => true,
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    /// Check if this [`KAdm5Variant`] is for client-side usage
    pub fn is_client(&self) -> bool {
        match self {
            #[cfg(mit_client)]
            Self::MitClient => true,
            #[cfg(heimdal_client)]
            Self::HeimdalClient => true,
            _ => false,
        }
    }

    /// Check if this [`KAdm5Variant`] is for server-side usage
    pub fn is_server(&self) -> bool {
        match self {
            #[cfg(mit_server)]
            Self::MitServer => true,
            #[cfg(heimdal_server)]
            Self::HeimdalServer => true,
            _ => false,
        }
    }
}

/// Bindings to a kadm5 library
#[allow(clippy::exhaustive_enums)]
pub enum Library {
    /// Bindings for the MIT krb5 client-side library
    #[cfg(mit_client)]
    MitClient(Container<mit_client::Api>),
    /// Bindings for the MIT krb5 server-side library
    #[cfg(mit_server)]
    MitServer(Container<mit_server::Api>),
    /// Bindings for the Heimdal client-side library
    #[cfg(heimdal_client)]
    HeimdalClient(Container<heimdal_client::Api>),
    /// Bindings for the Heimdal server-side library
    #[cfg(heimdal_server)]
    HeimdalServer(Container<heimdal_server::Api>),
}

impl Library {
    /// Which [`KAdm5Variant`] this library implements
    pub fn variant(&self) -> KAdm5Variant {
        match self {
            #[cfg(mit_client)]
            Self::MitClient(_) => KAdm5Variant::MitClient,
            #[cfg(mit_server)]
            Self::MitServer(_) => KAdm5Variant::MitServer,
            #[cfg(heimdal_client)]
            Self::HeimdalClient(_) => KAdm5Variant::HeimdalClient,
            #[cfg(heimdal_server)]
            Self::HeimdalServer(_) => KAdm5Variant::HeimdalServer,
        }
    }

    /// Check if this [`Library`] is for MIT krb5
    pub fn is_mit(&self) -> bool {
        match self {
            #[cfg(mit_client)]
            Self::MitClient(_) => true,
            #[cfg(mit_server)]
            Self::MitServer(_) => true,
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    /// Check if this [`Library`] is for Heimdal
    pub fn is_heimdal(&self) -> bool {
        match self {
            #[cfg(heimdal_client)]
            Self::HeimdalClient(_) => true,
            #[cfg(heimdal_server)]
            Self::HeimdalServer(_) => true,
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    /// Check if this [`Library`] is for client-side usage
    pub fn is_client(&self) -> bool {
        match self {
            #[cfg(mit_client)]
            Self::MitClient(_) => true,
            #[cfg(heimdal_client)]
            Self::HeimdalClient(_) => true,
            _ => false,
        }
    }

    /// Check if this [`Library`] is for server-side usage
    pub fn is_server(&self) -> bool {
        match self {
            #[cfg(mit_server)]
            Self::MitServer(_) => true,
            #[cfg(heimdal_server)]
            Self::HeimdalServer(_) => true,
            _ => false,
        }
    }

    fn find_library<T: WrapperApi>(
        library_paths: Vec<&'static str>,
        libraries: Vec<&'static str>,
    ) -> Option<Container<T>> {
        for path in library_paths {
            for library in libraries.iter() {
                let full_path = format!("{}/lib{}.so", path, library);
                let load = unsafe { Container::load(&full_path) };
                dbg!(&full_path);
                if let Err(e) = &load {
                    dbg!(e);
                }
                if let Ok(cont) = load {
                    return Some(cont);
                }
            }
        }
        None
    }

    /// Create a new [`Library`] instance from a [`KAdm5Variant`]
    pub fn from_variant(variant: KAdm5Variant) -> Result<Self> {
        Ok(match variant {
            #[cfg(mit_client)]
            KAdm5Variant::MitClient => {
                if let Some(cont) =
                    Self::find_library(mit_client::library_paths(), mit_client::libraries())
                {
                    Library::MitClient(cont)
                } else {
                    Library::MitClient(unsafe { Container::load("libkadm5clnt_mit.so") }?)
                }
            }
            #[cfg(mit_server)]
            KAdm5Variant::MitServer => {
                if let Some(cont) =
                    Self::find_library(mit_server::library_paths(), mit_server::libraries())
                {
                    Library::MitServer(cont)
                } else {
                    Library::MitServer(unsafe { Container::load("libkadm5srv_mit.so") }?)
                }
            }
            #[cfg(heimdal_client)]
            KAdm5Variant::HeimdalClient => {
                if let Some(cont) =
                    Self::find_library(heimdal_client::library_paths(), heimdal_client::libraries())
                {
                    Library::HeimdalClient(cont)
                } else {
                    Library::HeimdalClient(unsafe { Container::load("libkadm5clnt.so") }?)
                }
            }
            #[cfg(heimdal_server)]
            KAdm5Variant::HeimdalServer => {
                if let Some(cont) =
                    Self::find_library(heimdal_server::library_paths(), heimdal_server::libraries())
                {
                    Library::HeimdalServer(cont)
                } else {
                    Library::HeimdalServer(unsafe { Container::load("libkadm5srv.so") }?)
                }
            }
        })
    }

    /// Create a new [`Library`] instance from a [`KAdm5Variant`] and a custom library path
    pub fn from_path<S: AsRef<OsStr>>(variant: KAdm5Variant, path: S) -> Result<Self> {
        Ok(match variant {
            #[cfg(mit_client)]
            KAdm5Variant::MitClient => Library::MitClient(unsafe { Container::load(path) }?),
            #[cfg(mit_server)]
            KAdm5Variant::MitServer => Library::MitServer(unsafe { Container::load(path) }?),
            #[cfg(heimdal_client)]
            KAdm5Variant::HeimdalClient => {
                Library::HeimdalClient(unsafe { Container::load(path) }?)
            }
            #[cfg(heimdal_server)]
            KAdm5Variant::HeimdalServer => {
                Library::HeimdalServer(unsafe { Container::load(path) }?)
            }
        })
    }
}

/// MIT kadm5-client bindings
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
#[allow(clippy::exhaustive_structs)]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::unreadable_literal)]
#[allow(clippy::unseparated_literal_suffix)]
#[cfg(mit_client)]
pub mod mit_client {
    pub fn library_paths() -> Vec<&'static str> {
        env!("KADMIN_BUILD_MIT_CLIENT_LIBRARY_PATHS")
            .split_whitespace()
            .collect()
    }

    pub fn libraries() -> Vec<&'static str> {
        env!("KADMIN_BUILD_MIT_CLIENT_LIBRARIES")
            .split_whitespace()
            .collect()
    }

    include!(concat!(env!("OUT_DIR"), "/bindings_mit_client.rs"));
}

/// MIT kadm5-server bindings
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
#[allow(clippy::exhaustive_structs)]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::unreadable_literal)]
#[allow(clippy::unseparated_literal_suffix)]
#[cfg(mit_server)]
pub mod mit_server {
    pub fn library_paths() -> Vec<&'static str> {
        env!("KADMIN_BUILD_MIT_SERVER_LIBRARY_PATHS")
            .split_whitespace()
            .collect()
    }

    pub fn libraries() -> Vec<&'static str> {
        env!("KADMIN_BUILD_MIT_SERVER_LIBRARIES")
            .split_whitespace()
            .collect()
    }

    include!(concat!(env!("OUT_DIR"), "/bindings_mit_server.rs"));
}

/// Heimdal kadm5-client bindings
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[allow(unused_qualifications)]
#[allow(clippy::exhaustive_structs)]
#[allow(clippy::missing_safety_doc)]
#[allow(clippy::ptr_offset_with_cast)]
#[allow(clippy::semicolon_if_nothing_returned)]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::unreadable_literal)]
#[allow(clippy::unseparated_literal_suffix)]
#[allow(clippy::useless_transmute)]
#[cfg(heimdal_client)]
pub mod heimdal_client {
    pub fn library_paths() -> Vec<&'static str> {
        env!("KADMIN_BUILD_HEIMDAL_CLIENT_LIBRARY_PATHS")
            .split_whitespace()
            .collect()
    }

    pub fn libraries() -> Vec<&'static str> {
        env!("KADMIN_BUILD_HEIMDAL_CLIENT_LIBRARIES")
            .split_whitespace()
            .collect()
    }

    include!(concat!(env!("OUT_DIR"), "/bindings_heimdal_client.rs"));
}

/// Heimdal kadm5-server bindings
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[allow(unused_qualifications)]
#[allow(clippy::exhaustive_structs)]
#[allow(clippy::missing_safety_doc)]
#[allow(clippy::ptr_offset_with_cast)]
#[allow(clippy::semicolon_if_nothing_returned)]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::unreadable_literal)]
#[allow(clippy::unseparated_literal_suffix)]
#[allow(clippy::useless_transmute)]
#[cfg(heimdal_server)]
pub mod heimdal_server {
    pub fn library_paths() -> Vec<&'static str> {
        env!("KADMIN_BUILD_HEIMDAL_SERVER_LIBRARY_PATHS")
            .split_whitespace()
            .collect()
    }

    pub fn libraries() -> Vec<&'static str> {
        env!("KADMIN_BUILD_HEIMDAL_SERVER_LIBRARIES")
            .split_whitespace()
            .collect()
    }

    include!(concat!(env!("OUT_DIR"), "/bindings_heimdal_server.rs"));
}

macro_rules! library_match {
    ($expr:expr; |$cont:ident, $lib:ident| $code:expr) => {
        library_match!(
            $expr;
            mit_client => |$cont, $lib| $code,
            mit_server => |$cont, $lib| $code,
            heimdal_client => |$cont, $lib| $code,
            heimdal_server => |$cont, $lib| $code
        )
    };

    ($expr:expr; $($($libname:ident),+ => |$cont:ident, $lib:ident| $code:expr),+) => {
        match $expr {
            $(
                $(
                    #[cfg($libname)]
                    library_match!(@variant $libname, $cont) => {
                        macro_rules! $lib {
                            ($ty:ident) => { crate::sys::$libname::$ty };
                        }
                        $code
                    }
                )+
            )+
        }
    };

    (@variant mit_client, $cont:ident) => {
        crate::sys::Library::MitClient($cont)
    };
    (@variant mit_server, $cont:ident) => {
        crate::sys::Library::MitServer($cont)
    };
    (@variant heimdal_client, $cont:ident) => {
        crate::sys::Library::HeimdalClient($cont)
    };
    (@variant heimdal_server, $cont:ident) => {
        crate::sys::Library::HeimdalServer($cont)
    };
}
pub(crate) use library_match;

macro_rules! cfg_match {
    (|$lib:ident| $code:expr) => {
        cfg_match!(
            mit_client => |$lib| $code,
            mit_server => |$lib| $code,
            heimdal_client => |$lib| $code,
            heimdal_server => |$lib| $code
        )
    };

    ($($($libname:ident),+ => |$lib:ident| $code:expr),+) => {
        $(
            $(
                #[cfg($libname)]
                {
                    macro_rules! $lib {
                        ($ty:ident) => { crate::sys::$libname::$ty };
                    }
                    $code
                };
            )+
        )+
    };
}
pub(crate) use cfg_match;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(mit_client)]
    #[test]
    fn library_load_mit_client() -> Result<()> {
        Library::from_variant(KAdm5Variant::MitClient)?;
        Ok(())
    }

    #[cfg(mit_server)]
    #[test]
    fn library_load_mit_server() -> Result<()> {
        Library::from_variant(KAdm5Variant::MitServer)?;
        Ok(())
    }

    #[cfg(heimdal_client)]
    #[test]
    fn library_load_heimdal_client() -> Result<()> {
        Library::from_variant(KAdm5Variant::HeimdalClient)?;
        Ok(())
    }

    #[cfg(heimdal_server)]
    #[test]
    fn library_load_heimdal_server() -> Result<()> {
        Library::from_variant(KAdm5Variant::HeimdalServer)?;
        Ok(())
    }
}

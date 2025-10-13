//! Bindings to various kadm5 libraries

use std::ffi::OsStr;

use dlopen2::wrapper::{Container, WrapperApi};

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
    #[cfg(mit)]
    /// MIT krb5 client-side
    MitClient,
    #[cfg(mit)]
    /// MIT krb5 server-side
    MitServer,
    #[cfg(heimdal)]
    /// Heimdal client-side
    HeimdalClient,
    #[cfg(heimdal)]
    /// Heimdal server-side
    HeimdalServer,
}

/// Bindings to a kadm5 library
#[allow(clippy::exhaustive_enums)]
pub enum Library {
    /// Bindings for the MIT krb5 client-side library
    #[cfg(mit)]
    MitClient(Container<mit::Api>),
    /// Bindings for the MIT krb5 server-side library
    #[cfg(mit)]
    MitServer(Container<mit::Api>),
    /// Bindings for the Heimdal client-side library
    #[cfg(heimdal)]
    HeimdalClient(Container<heimdal::Api>),
    /// Bindings for the Heimdal server-side library
    #[cfg(heimdal)]
    HeimdalServer(Container<heimdal::Api>),
}

impl Library {
    /// Check if this [`Library`] is for MIT krb5
    pub fn is_mit(&self) -> bool {
        match self {
            #[cfg(mit)]
            Self::MitClient(_) | Self::MitServer(_) => true,
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    /// Check if this [`Library`] is for Heimdal
    pub fn is_heimdal(&self) -> bool {
        match self {
            #[cfg(heimdal)]
            Self::HeimdalClient(_) | Self::HeimdalServer(_) => true,
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    fn find_library<T: WrapperApi>(
        library_paths: Vec<&'static str>,
        libraries: Vec<&'static str>,
        contains: &'static str,
    ) -> Option<Container<T>> {
        for path in library_paths {
            for library in libraries.iter().filter(|lib| lib.contains(contains)) {
                let full_path = format!("{}/lib{}.so", path, library);
                let load = unsafe { Container::load(&full_path) };
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
            #[cfg(mit)]
            KAdm5Variant::MitClient => {
                if let Some(cont) =
                    Self::find_library(mit::library_paths(), mit::libraries(), "clnt")
                {
                    Library::MitClient(cont)
                } else {
                    Library::MitClient(unsafe { Container::load("libkadm5clnt_mit.so") }?)
                }
            }
            #[cfg(mit)]
            KAdm5Variant::MitServer => {
                if let Some(cont) =
                    Self::find_library(mit::library_paths(), mit::libraries(), "srv")
                {
                    Library::MitServer(cont)
                } else {
                    Library::MitServer(unsafe { Container::load("libkadm5srv_mit.so") }?)
                }
            }
            #[cfg(heimdal)]
            KAdm5Variant::HeimdalClient => {
                if let Some(cont) =
                    Self::find_library(heimdal::library_paths(), heimdal::libraries(), "clnt")
                {
                    Library::HeimdalClient(cont)
                } else {
                    Library::HeimdalClient(unsafe { Container::load("libkadm5clnt.so") }?)
                }
            }
            #[cfg(heimdal)]
            KAdm5Variant::HeimdalServer => {
                if let Some(cont) =
                    Self::find_library(heimdal::library_paths(), heimdal::libraries(), "srv")
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
            #[cfg(mit)]
            KAdm5Variant::MitClient => Library::MitClient(unsafe { Container::load(path) }?),
            #[cfg(mit)]
            KAdm5Variant::MitServer => Library::MitServer(unsafe { Container::load(path) }?),
            #[cfg(heimdal)]
            KAdm5Variant::HeimdalClient => {
                Library::HeimdalClient(unsafe { Container::load(path) }?)
            }
            #[cfg(heimdal)]
            KAdm5Variant::HeimdalServer => {
                Library::HeimdalServer(unsafe { Container::load(path) }?)
            }
        })
    }

    /// Create a new [`Library`] instance from a [`KAdm5Variant`] and symbols from the program
    /// itself.
    pub fn from_self(variant: KAdm5Variant) -> Result<Self> {
        Ok(match variant {
            #[cfg(mit)]
            KAdm5Variant::MitClient => Library::MitClient(unsafe { Container::load_self() }?),
            #[cfg(mit)]
            KAdm5Variant::MitServer => Library::MitServer(unsafe { Container::load_self() }?),
            #[cfg(heimdal)]
            KAdm5Variant::HeimdalClient => {
                Library::HeimdalClient(unsafe { Container::load_self() }?)
            }
            #[cfg(heimdal)]
            KAdm5Variant::HeimdalServer => {
                Library::HeimdalServer(unsafe { Container::load_self() }?)
            }
        })
    }
}

/// MIT krb5 bindings
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
#[allow(clippy::exhaustive_structs)]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::unreadable_literal)]
#[allow(clippy::unseparated_literal_suffix)]
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

/// Heimdal bindings
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(mit)]
    #[test]
    fn library_load_mit_client() -> Result<()> {
        Library::from_variant(KAdm5Variant::MitClient)?;
        Ok(())
    }

    #[cfg(mit)]
    #[test]
    fn library_load_mit_server() -> Result<()> {
        Library::from_variant(KAdm5Variant::MitServer)?;
        Ok(())
    }

    #[cfg(heimdal)]
    #[test]
    fn library_load_heimdal_client() -> Result<()> {
        Library::from_variant(KAdm5Variant::HeimdalClient)?;
        Ok(())
    }

    #[cfg(heimdal)]
    #[test]
    fn library_load_heimdal_server() -> Result<()> {
        Library::from_variant(KAdm5Variant::HeimdalServer)?;
        Ok(())
    }
}

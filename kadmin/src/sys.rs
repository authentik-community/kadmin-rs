//! Bindings to various kadm5 libraries

use dlopen2::wrapper::Container;

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
    /// MIT krb5 client-side
    MitClient,
    /// MIT krb5 server-side
    MitServer,
    /// Heimdal client-side
    HeimdalClient,
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
    /// Create a new [`Library`] instance from a [`KAdm5Variant`]
    pub fn from_variant(_variant: KAdm5Variant) -> Result<Self> {
        todo!()
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

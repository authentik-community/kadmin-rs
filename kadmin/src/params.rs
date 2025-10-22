//! Define [`Params`] to pass to kadm5
use std::{
    ffi::{CString, c_void},
    ptr::null_mut,
};

#[cfg(feature = "python")]
use pyo3::prelude::*;

use crate::{
    context::Context,
    error::Result,
    sys::{self, cfg_match, library_match},
};

/// kadm5 config options
///
/// ```
/// let params = kadmin::Params::new().realm("EXAMPLE.ORG");
/// ```
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "python", pyclass)]
pub struct Params {
    #[cfg(mit_client)]
    /// Mask for which values are set
    mask_mit_client: i64,
    #[cfg(mit_server)]
    /// Mask for which values are set
    mask_mit_server: i64,
    #[cfg(heimdal_client)]
    /// Mask for which values are set
    mask_heimdal_client: i64,
    #[cfg(heimdal_server)]
    /// Mask for which values are set
    mask_heimdal_server: i64,

    /// Default database realm
    realm: Option<String>,
    /// kadmind port to connect to
    kadmind_port: i32,
    #[cfg(any(mit_client, mit_server))]
    /// kpasswd port to connect to
    kpasswd_port: i32,
    /// Admin server which kadmin should contact
    admin_server: Option<String>,
    /// Name of the KDC database
    dbname: Option<String>,
    /// Location of the access control list file
    acl_file: Option<String>,
    #[cfg(any(mit_client, mit_server))]
    /// Location of the dictionary file containing strings that are not allowed as passwords
    dict_file: Option<String>,
    /// Location where the master key has been stored
    stash_file: Option<String>,
}

macro_rules! set_mask {
    ($self:ident, $mask:ident) => {
        cfg_match!(
            mit_client => |lib| $self.mask_mit_client |= lib!($mask) as i64,
            mit_server => |lib| $self.mask_mit_server |= lib!($mask) as i64,
            heimdal_client => |lib| $self.mask_heimdal_client |= lib!($mask) as i64,
            heimdal_server => |lib| $self.mask_heimdal_server |= lib!($mask) as i64
        )
    };

    ($self:ident; $($libname:ident),+ => $mask:ident) => {
        cfg_match!(
            $(
                $libname => |lib| set_mask!(@attr $self, $libname) |= lib!($mask) as i64
            ),+
        )
    };

    (@attr $self:ident, mit_client) => {
        $self.mask_mit_client
    };
    (@attr $self:ident, mit_server) => {
        $self.mask_mit_server
    };
    (@attr $self:ident, heimdal_client) => {
        $self.mask_heimdal_client
    };
    (@attr $self:ident, heimdal_server) => {
        $self.mask_heimdal_server
    };
}

impl Params {
    /// Create new [`Params`] instance
    pub fn new() -> Self {
        Default::default()
    }

    /// Set the default database realm
    pub fn realm(mut self, realm: &str) -> Self {
        self.realm = Some(realm.to_owned());
        set_mask!(self, KADM5_CONFIG_REALM);
        self
    }

    /// Set the kadmind port to connect to
    pub fn kadmind_port(mut self, port: i32) -> Self {
        self.kadmind_port = port;
        set_mask!(self, KADM5_CONFIG_KADMIND_PORT);
        self
    }

    #[cfg(any(mit_client, mit_server))]
    /// Set the kpasswd port to connect to
    ///
    /// No-op for non-MIT variants
    pub fn kpasswd_port(mut self, port: i32) -> Self {
        self.kpasswd_port = port;
        set_mask!(self; mit_client, mit_server => KADM5_CONFIG_KPASSWD_PORT);
        self
    }

    /// Set the admin server which kadmin should contact
    pub fn admin_server(mut self, admin_server: &str) -> Self {
        self.admin_server = Some(admin_server.to_owned());
        set_mask!(self, KADM5_CONFIG_ADMIN_SERVER);
        self
    }

    /// Set the name of the KDC database
    pub fn dbname(mut self, dbname: &str) -> Self {
        self.dbname = Some(dbname.to_owned());
        set_mask!(self, KADM5_CONFIG_DBNAME);
        self
    }

    /// Set the location of the access control list file
    pub fn acl_file(mut self, acl_file: &str) -> Self {
        self.acl_file = Some(acl_file.to_owned());
        set_mask!(self, KADM5_CONFIG_ACL_FILE);
        self
    }

    #[cfg(any(mit_client, mit_server))]
    /// Set the location of the access control list file
    ///
    /// No-op for non-MIT variants
    pub fn dict_file(mut self, dict_file: &str) -> Self {
        self.dict_file = Some(dict_file.to_owned());
        set_mask!(self; mit_client, mit_server => KADM5_CONFIG_DICT_FILE);
        self
    }

    /// Set the location of the access control list file
    pub fn stash_file(mut self, stash_file: &str) -> Self {
        self.stash_file = Some(stash_file.to_owned());
        set_mask!(self, KADM5_CONFIG_STASH_FILE);
        self
    }
}

pub(crate) struct ParamsGuard<'a> {
    pub(crate) raw: *mut c_void,
    context: &'a Context,

    realm: Option<CString>,
    admin_server: Option<CString>,
    dbname: Option<CString>,
    acl_file: Option<CString>,
    #[cfg(any(mit_client, mit_server))]
    dict_file: Option<CString>,
    stash_file: Option<CString>,
}

impl<'a> ParamsGuard<'a> {
    pub(crate) fn build(context: &'a Context, params: &Params) -> Result<Self> {
        let realm = params
            .realm
            .as_ref()
            .map(|s| CString::new(s.as_str()))
            .transpose()?;
        let admin_server = params
            .admin_server
            .as_ref()
            .map(|s| CString::new(s.as_str()))
            .transpose()?;
        let dbname = params
            .dbname
            .as_ref()
            .map(|s| CString::new(s.as_str()))
            .transpose()?;
        let acl_file = params
            .acl_file
            .as_ref()
            .map(|s| CString::new(s.as_str()))
            .transpose()?;
        #[cfg(any(mit_client, mit_server))]
        let dict_file = params
            .dict_file
            .as_ref()
            .map(|s| CString::new(s.as_str()))
            .transpose()?;
        let stash_file = params
            .stash_file
            .as_ref()
            .map(|s| CString::new(s.as_str()))
            .transpose()?;

        let mut guard = Self {
            raw: null_mut(),
            context,
            realm,
            admin_server,
            dbname,
            acl_file,
            #[cfg(any(mit_client, mit_server))]
            dict_file,
            stash_file,
        };

        let mask = library_match!(
            &context.library;
            mit_client => |_cont, _lib| params.mask_mit_client,
            mit_server => |_cont, _lib| params.mask_mit_server,
            heimdal_client => |_cont, _lib| params.mask_heimdal_client,
            heimdal_server => |_cont, _lib| params.mask_heimdal_server
        );

        library_match!(
            &context.library;
            mit_client, mit_server => |_cont, lib| {
                let mut raw: lib!(kadm5_config_params) = Default::default();

                raw.mask = mask;
                raw.realm = if let Some(realm) = &guard.realm {
                    realm.as_ptr().cast_mut()
                } else {
                    null_mut()
                };
                raw.kadmind_port = params.kadmind_port;
                raw.kpasswd_port = params.kpasswd_port;
                raw.admin_server = if let Some(admin_server) = &guard.admin_server {
                    admin_server.as_ptr().cast_mut()
                } else {
                    null_mut()
                };
                raw.dbname =  if let Some(dbname) = &guard.dbname {
                    dbname.as_ptr().cast_mut()
                } else {
                    null_mut()
                };
                raw.acl_file = if let Some(acl_file) = &guard.acl_file {
                    acl_file.as_ptr().cast_mut()
                } else {
                    null_mut()
                };
                raw.dict_file = if let Some(dict_file) = &guard.dict_file {
                    dict_file.as_ptr().cast_mut()
                } else {
                    null_mut()
                };
                raw.stash_file = if let Some(stash_file) = &guard.stash_file {
                    stash_file.as_ptr().cast_mut()
                } else {
                    null_mut()
                };

                let raw = Box::new(raw);
                guard.raw = Box::into_raw(raw) as *mut c_void;
            },
            heimdal_client, heimdal_server => |_cont, lib| {
                let mut raw: lib!(kadm5_config_params) = Default::default();

                raw.mask = mask as u32;
                raw.realm = if let Some(realm) = &guard.realm {
                    realm.as_ptr().cast_mut()
                } else {
                    null_mut()
                };
                raw.kadmind_port = params.kadmind_port;
                raw.admin_server = if let Some(admin_server) = &guard.admin_server {
                    admin_server.as_ptr().cast_mut()
                } else {
                    null_mut()
                };
                raw.dbname = if let Some(dbname) = &guard.dbname {
                    dbname.as_ptr().cast_mut()
                } else {
                    null_mut()
                };
                raw.acl_file = if let Some(acl_file) = &guard.acl_file {
                    acl_file.as_ptr().cast_mut()
                } else {
                    null_mut()
                };
                raw.stash_file = if let Some(stash_file) = &guard.stash_file {
                    stash_file.as_ptr().cast_mut()
                } else {
                    null_mut()
                };

                let raw = Box::new(raw);
                guard.raw = Box::into_raw(raw) as *mut c_void;
            }
        );

        Ok(guard)
    }
}

impl Drop for ParamsGuard<'_> {
    fn drop(&mut self) {
        if self.raw.is_null() {
            return;
        }
        library_match!(&self.context.library; |_cont, lib| {
            let raw: Box<lib!(kadm5_config_params)> = unsafe { Box::from_raw(self.raw as *mut lib!(kadm5_config_params)) };
            drop(raw);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(mit_client)]
    #[test]
    fn build_empty_mit() {
        let params = Params::new();
        assert_eq!(params.mask_mit_client, 0);
    }

    #[cfg(heimdal_client)]
    #[test]
    fn build_empty_heimdal() {
        let params = Params::new();
        assert_eq!(params.mask_heimdal_client, 0);
    }

    #[cfg(mit_client)]
    #[test]
    fn build_realm_mit() {
        let params = Params::new().realm("EXAMPLE.ORG");
        assert_eq!(params.mask_mit_client, 1);
    }

    #[cfg(heimdal_client)]
    #[test]
    fn build_realm_heimdal() {
        let params = Params::new().realm("EXAMPLE.ORG");
        assert_eq!(params.mask_heimdal_client, 1);
    }

    #[cfg(mit_client)]
    #[test]
    fn build_all_mit_client() {
        let params = Params::new()
            .realm("EXAMPLE.ORG")
            .admin_server("kdc.example.org")
            .kadmind_port(750)
            .kpasswd_port(465);
        assert_eq!(params.mask_mit_client, 0x94001);
    }

    #[cfg(mit_server)]
    #[test]
    fn build_all_mit_server() {
        let params = Params::new()
            .realm("EXAMPLE.ORG")
            .admin_server("kdc.example.org")
            .kadmind_port(750)
            .kpasswd_port(465);
        assert_eq!(params.mask_mit_server, 0x94001);
    }

    #[cfg(heimdal_client)]
    #[test]
    fn build_all_heimdal_client() {
        let params = Params::new()
            .realm("EXAMPLE.ORG")
            .admin_server("kdc.example.org")
            .kadmind_port(750);
        assert_eq!(params.mask_heimdal_client, 0xd);
    }

    #[cfg(heimdal_server)]
    #[test]
    fn build_all_heimdal_server() {
        let params = Params::new()
            .realm("EXAMPLE.ORG")
            .admin_server("kdc.example.org")
            .kadmind_port(750);
        assert_eq!(params.mask_heimdal_server, 0xd);
    }
}

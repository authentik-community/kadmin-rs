//! Define [`Params`] to pass to kadm5
use std::{ffi::CString, ptr::null_mut};

#[cfg(feature = "python")]
use pyo3::prelude::*;

use crate::{error::Result, sys};

/// kadm5 config options
///
/// ```
/// let params = kadmin::Params::new().realm("EXAMPLE.ORG");
/// ```
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "python", pyclass)]
pub struct Params {
    #[cfg(mit)]
    /// Mask for which values are set
    mask_mit: i64,
    #[cfg(heimdal)]
    /// Mask for which values are set
    mask_heimdal: i64,

    /// Default database realm
    realm: Option<String>,
    /// kadmind port to connect to
    kadmind_port: i32,
    #[cfg(mit)]
    /// kpasswd port to connect to
    kpasswd_port: i32,
    /// Admin server which kadmin should contact
    admin_server: Option<String>,
    /// Name of the KDC database
    dbname: Option<String>,
    /// Location of the access control list file
    acl_file: Option<String>,
    #[cfg(mit)]
    /// Location of the dictionary file containing strings that are not allowed as passwords
    dict_file: Option<String>,
    /// Location where the master key has been stored
    stash_file: Option<String>,
}

impl Params {
    /// Create new [`Params`] instance
    pub fn new() -> Self {
        Default::default()
    }

    /// Set the default database realm
    pub fn realm(mut self, realm: &str) -> Self {
        self.realm = Some(realm.to_owned());
        #[cfg(mit)]
        {
            self.mask_mit |= sys::mit::KADM5_CONFIG_REALM as i64;
        }
        #[cfg(heimdal)]
        {
            self.mask_heimdal |= sys::heimdal::KADM5_CONFIG_REALM as i64;
        }
        self
    }

    /// Set the kadmind port to connect to
    pub fn kadmind_port(mut self, port: i32) -> Self {
        self.kadmind_port = port;
        #[cfg(mit)]
        {
            self.mask_mit |= sys::mit::KADM5_CONFIG_KADMIND_PORT as i64;
        }
        #[cfg(heimdal)]
        {
            self.mask_heimdal |= sys::heimdal::KADM5_CONFIG_KADMIND_PORT as i64;
        }
        self
    }

    #[cfg(mit)]
    /// Set the kpasswd port to connect to
    ///
    /// No-op for non-MIT variants
    pub fn kpasswd_port(mut self, port: i32) -> Self {
        self.kpasswd_port = port;
        #[cfg(mit)]
        {
            self.mask_mit |= sys::mit::KADM5_CONFIG_KPASSWD_PORT as i64;
        }
        self
    }

    /// Set the admin server which kadmin should contact
    pub fn admin_server(mut self, admin_server: &str) -> Self {
        self.admin_server = Some(admin_server.to_owned());
        #[cfg(mit)]
        {
            self.mask_mit |= sys::mit::KADM5_CONFIG_ADMIN_SERVER as i64;
        }
        #[cfg(heimdal)]
        {
            self.mask_heimdal |= sys::heimdal::KADM5_CONFIG_ADMIN_SERVER as i64;
        }
        self
    }

    /// Set the name of the KDC database
    pub fn dbname(mut self, dbname: &str) -> Self {
        self.dbname = Some(dbname.to_owned());
        #[cfg(mit)]
        {
            self.mask_mit |= sys::mit::KADM5_CONFIG_DBNAME as i64;
        }
        #[cfg(heimdal)]
        {
            self.mask_heimdal |= sys::heimdal::KADM5_CONFIG_DBNAME as i64;
        }
        self
    }

    /// Set the location of the access control list file
    pub fn acl_file(mut self, acl_file: &str) -> Self {
        self.acl_file = Some(acl_file.to_owned());
        #[cfg(mit)]
        {
            self.mask_mit |= sys::mit::KADM5_CONFIG_ACL_FILE as i64;
        }
        #[cfg(heimdal)]
        {
            self.mask_heimdal |= sys::heimdal::KADM5_CONFIG_ACL_FILE as i64;
        }
        self
    }

    #[cfg(mit)]
    /// Set the location of the access control list file
    ///
    /// No-op for non-MIT variants
    pub fn dict_file(mut self, dict_file: &str) -> Self {
        self.dict_file = Some(dict_file.to_owned());
        #[cfg(mit)]
        {
            self.mask_mit |= sys::mit::KADM5_CONFIG_DICT_FILE as i64;
        }
        self
    }

    /// Set the location of the access control list file
    pub fn stash_file(mut self, stash_file: &str) -> Self {
        self.stash_file = Some(stash_file.to_owned());
        #[cfg(mit)]
        {
            self.mask_mit |= sys::mit::KADM5_CONFIG_STASH_FILE as i64;
        }
        #[cfg(heimdal)]
        {
            self.mask_heimdal |= sys::heimdal::KADM5_CONFIG_STASH_FILE as i64;
        }
        self
    }
}

#[derive(Debug, Default)]
pub(crate) struct ParamsGuard {
    #[cfg(mit)]
    pub(crate) params_mit: Option<sys::mit::kadm5_config_params>,
    #[cfg(heimdal)]
    pub(crate) params_heimdal: Option<sys::heimdal::kadm5_config_params>,

    realm: Option<CString>,
    admin_server: Option<CString>,
    dbname: Option<CString>,
    acl_file: Option<CString>,
    #[cfg(mit)]
    dict_file: Option<CString>,
    stash_file: Option<CString>,
}

impl ParamsGuard {
    fn build_base(params: &Params) -> Result<Self> {
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
        #[cfg(mit)]
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

        Ok(Self {
            realm,
            admin_server,
            dbname,
            acl_file,
            #[cfg(mit)]
            dict_file,
            stash_file,
            ..Default::default()
        })
    }

    #[cfg(mit)]
    pub(crate) fn build_mit(params: &Params) -> Result<Self> {
        let mut guard = Self::build_base(params)?;
        let params_mit = sys::mit::kadm5_config_params {
            mask: params.mask_mit,

            realm: if let Some(realm) = &guard.realm {
                realm.as_ptr().cast_mut()
            } else {
                null_mut()
            },
            kadmind_port: params.kadmind_port,
            kpasswd_port: params.kpasswd_port,

            admin_server: if let Some(admin_server) = &guard.admin_server {
                admin_server.as_ptr().cast_mut()
            } else {
                null_mut()
            },

            dbname: if let Some(dbname) = &guard.dbname {
                dbname.as_ptr().cast_mut()
            } else {
                null_mut()
            },
            acl_file: if let Some(acl_file) = &guard.acl_file {
                acl_file.as_ptr().cast_mut()
            } else {
                null_mut()
            },
            dict_file: if let Some(dict_file) = &guard.dict_file {
                dict_file.as_ptr().cast_mut()
            } else {
                null_mut()
            },
            mkey_from_kbd: 0,
            stash_file: if let Some(stash_file) = &guard.stash_file {
                stash_file.as_ptr().cast_mut()
            } else {
                null_mut()
            },
            mkey_name: null_mut(),
            enctype: 0,
            max_life: 0,
            max_rlife: 0,
            expiration: 0,
            flags: 0,
            keysalts: null_mut(),
            num_keysalts: 0,
            kvno: 0,
            iprop_enabled: 0,
            iprop_ulogsize: 0,
            iprop_poll_time: 0,
            iprop_logfile: null_mut(),
            iprop_port: 0,
            iprop_resync_timeout: 0,
            kadmind_listen: null_mut(),
            kpasswd_listen: null_mut(),
            iprop_listen: null_mut(),
        };
        guard.params_mit = Some(params_mit);
        Ok(guard)
    }

    #[cfg(heimdal)]
    pub(crate) fn build_heimdal(params: &Params) -> Result<Self> {
        let mut guard = Self::build_base(params)?;
        let params_heimdal = sys::heimdal::kadm5_config_params {
            mask: params.mask_heimdal as u32,

            realm: if let Some(realm) = &guard.realm {
                realm.as_ptr().cast_mut()
            } else {
                null_mut()
            },
            kadmind_port: params.kadmind_port,

            admin_server: if let Some(admin_server) = &guard.admin_server {
                admin_server.as_ptr().cast_mut()
            } else {
                null_mut()
            },
            readonly_admin_server: null_mut(),
            readonly_kadmind_port: 0,

            dbname: if let Some(dbname) = &guard.dbname {
                dbname.as_ptr().cast_mut()
            } else {
                null_mut()
            },
            acl_file: if let Some(acl_file) = &guard.acl_file {
                acl_file.as_ptr().cast_mut()
            } else {
                null_mut()
            },
            stash_file: if let Some(stash_file) = &guard.stash_file {
                stash_file.as_ptr().cast_mut()
            } else {
                null_mut()
            },
        };
        guard.params_heimdal = Some(params_heimdal);
        Ok(guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(mit)]
    #[test]
    fn build_empty_mit() {
        let params = Params::new();
        assert_eq!(params.mask_mit, 0);
    }

    #[cfg(heimdal)]
    #[test]
    fn build_empty_heimdal() {
        let params = Params::new();
        assert_eq!(params.mask_heimdal, 0);
    }

    #[cfg(mit)]
    #[test]
    fn build_realm_mit() {
        let params = Params::new().realm("EXAMPLE.ORG");
        assert_eq!(params.mask_mit, 1);
    }

    #[cfg(heimdal)]
    #[test]
    fn build_realm_heimdal() {
        let params = Params::new().realm("EXAMPLE.ORG");
        assert_eq!(params.mask_heimdal, 1);
    }

    #[cfg(mit)]
    #[test]
    fn build_all_mit() {
        let params = Params::new()
            .realm("EXAMPLE.ORG")
            .admin_server("kdc.example.org")
            .kadmind_port(750)
            .kpasswd_port(465);
        assert_eq!(params.mask_mit, 0x94001);
    }

    #[cfg(heimdal)]
    #[test]
    fn build_all_heimdal() {
        let params = Params::new()
            .realm("EXAMPLE.ORG")
            .admin_server("kdc.example.org")
            .kadmind_port(750);
        assert_eq!(params.mask_heimdal, 0xd);
    }
}

//! Define [`Params`] to pass to kadm5

use std::{ffi::CString, ptr::null_mut};

use kadmin_sys::*;

use crate::error::Result;
#[cfg(feature = "python")]
use pyo3::prelude::*;

/// kadm5 config options
///
/// ```
/// let params = kadmin::Params::builder()
///     .realm("EXAMPLE.ORG")
///     .build()
///     .unwrap();
/// ```
#[derive(Debug)]
#[cfg_attr(feature = "python", pyclass)]
pub struct Params {
    /// Params for kadm5
    ///
    /// Additional fields to store transient strings so the pointer stored in
    /// [`kadm5_config_params`]
    /// doesn't become invalid while this struct lives.
    pub(crate) params: kadm5_config_params,

    /// Store [`CString`] that is in `params`
    _realm: Option<CString>,
    /// Store [`CString`] that is in `params`
    _admin_server: Option<CString>,
    /// Store [`CString`] that is in `params`
    _dbname: Option<CString>,
    /// Store [`CString`] that is in `params`
    _acl_file: Option<CString>,
    /// Store [`CString`] that is in `params`
    _dict_file: Option<CString>,
    /// Store [`CString`] that is in `params`
    _stash_file: Option<CString>,
}

// Pointees are contained in the struct itself
unsafe impl Send for Params {}
unsafe impl Sync for Params {}

impl Clone for Params {
    fn clone(&self) -> Self {
        let _realm = self._realm.clone();
        let _admin_server = self._admin_server.clone();
        let _dbname = self._dbname.clone();
        let _acl_file = self._acl_file.clone();
        let _dict_file = self._dict_file.clone();
        let _stash_file = self._stash_file.clone();
        Self {
            params: kadm5_config_params {
                mask: self.params.mask,
                realm: if let Some(realm) = &_realm {
                    realm.as_ptr().cast_mut()
                } else {
                    null_mut()
                },
                kadmind_port: self.params.kadmind_port,
                kpasswd_port: self.params.kpasswd_port,

                admin_server: if let Some(admin_server) = &_admin_server {
                    admin_server.as_ptr().cast_mut()
                } else {
                    null_mut()
                },

                dbname: if let Some(dbname) = &_dbname {
                    dbname.as_ptr().cast_mut()
                } else {
                    null_mut()
                },
                acl_file: if let Some(acl_file) = &_acl_file {
                    acl_file.as_ptr().cast_mut()
                } else {
                    null_mut()
                },
                dict_file: if let Some(dict_file) = &_dict_file {
                    dict_file.as_ptr().cast_mut()
                } else {
                    null_mut()
                },
                mkey_from_kbd: 0,
                stash_file: if let Some(stash_file) = &_stash_file {
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
            },
            _realm,
            _admin_server,
            _dbname,
            _acl_file,
            _dict_file,
            _stash_file,
        }
    }
}

impl Params {
    /// Construct a new [`ParamsBuilder`]
    pub fn builder() -> ParamsBuilder {
        ParamsBuilder::default()
    }
}

impl Default for Params {
    /// Construct an empty [`Params`]
    fn default() -> Self {
        Self::builder().build().unwrap()
    }
}

/// [`Params`] builder
#[derive(Clone, Debug, Default)]
pub struct ParamsBuilder {
    /// Mask for which values are set
    mask: i64,

    /// Default database realm
    realm: Option<String>,
    /// kadmind port to connect to
    kadmind_port: i32,
    /// kpasswd port to connect to
    kpasswd_port: i32,
    /// Admin server which kadmin should contact
    admin_server: Option<String>,
    /// Name of the KDC database
    dbname: Option<String>,
    /// Location of the access control list file
    acl_file: Option<String>,
    /// Location of the dictionary file containing strings that are not allowed as passwords
    dict_file: Option<String>,
    /// Location where the master key has been stored
    stash_file: Option<String>,
}

impl ParamsBuilder {
    /// Set the default database realm
    pub fn realm(mut self, realm: &str) -> Self {
        self.realm = Some(realm.to_owned());
        self.mask |= KADM5_CONFIG_REALM as i64;
        self
    }

    /// Set the kadmind port to connect to
    pub fn kadmind_port(mut self, port: i32) -> Self {
        self.kadmind_port = port;
        self.mask |= KADM5_CONFIG_KADMIND_PORT as i64;
        self
    }

    /// Set the kpasswd port to connect to
    pub fn kpasswd_port(mut self, port: i32) -> Self {
        self.kpasswd_port = port;
        self.mask |= KADM5_CONFIG_KPASSWD_PORT as i64;
        self
    }

    /// Set the admin server which kadmin should contact
    pub fn admin_server(mut self, admin_server: &str) -> Self {
        self.admin_server = Some(admin_server.to_owned());
        self.mask |= KADM5_CONFIG_ADMIN_SERVER as i64;
        self
    }

    /// Set the name of the KDC database
    pub fn dbname(mut self, dbname: &str) -> Self {
        self.dbname = Some(dbname.to_owned());
        self.mask |= KADM5_CONFIG_DBNAME as i64;
        self
    }

    /// Set the location of the access control list file
    pub fn acl_file(mut self, acl_file: &str) -> Self {
        self.acl_file = Some(acl_file.to_owned());
        self.mask |= KADM5_CONFIG_ACL_FILE as i64;
        self
    }

    /// Set the location of the dictionary file containing strings that are not allowed as passwords
    pub fn dict_file(mut self, dict_file: &str) -> Self {
        self.dict_file = Some(dict_file.to_owned());
        self.mask |= KADM5_CONFIG_DICT_FILE as i64;
        self
    }

    /// Set the location where the master key has been stored
    pub fn stash_file(mut self, stash_file: &str) -> Self {
        self.stash_file = Some(stash_file.to_owned());
        self.mask |= KADM5_CONFIG_STASH_FILE as i64;
        self
    }

    /// Construct [`Params`] from the provided options
    pub fn build(self) -> Result<Params> {
        let _realm = self.realm.map(CString::new).transpose()?;
        let _admin_server = self.admin_server.map(CString::new).transpose()?;
        let _dbname = self.dbname.map(CString::new).transpose()?;
        let _acl_file = self.acl_file.map(CString::new).transpose()?;
        let _dict_file = self.dict_file.map(CString::new).transpose()?;
        let _stash_file = self.stash_file.map(CString::new).transpose()?;

        let params = kadm5_config_params {
            mask: self.mask,
            realm: if let Some(realm) = &_realm {
                realm.as_ptr().cast_mut()
            } else {
                null_mut()
            },
            kadmind_port: self.kadmind_port,
            kpasswd_port: self.kpasswd_port,

            admin_server: if let Some(admin_server) = &_admin_server {
                admin_server.as_ptr().cast_mut()
            } else {
                null_mut()
            },

            dbname: if let Some(dbname) = &_dbname {
                dbname.as_ptr().cast_mut()
            } else {
                null_mut()
            },
            acl_file: if let Some(acl_file) = &_acl_file {
                acl_file.as_ptr().cast_mut()
            } else {
                null_mut()
            },
            dict_file: if let Some(dict_file) = &_dict_file {
                dict_file.as_ptr().cast_mut()
            } else {
                null_mut()
            },
            mkey_from_kbd: 0,
            stash_file: if let Some(stash_file) = &_stash_file {
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

        Ok(Params {
            params,
            _realm,
            _admin_server,
            _dbname,
            _acl_file,
            _dict_file,
            _stash_file,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use super::*;

    #[test]
    fn build_empty() {
        let params = Params::builder().build().unwrap();

        assert_eq!(params.params.mask, 0);
    }

    #[test]
    fn build_realm() {
        let params = Params::builder().realm("EXAMPLE.ORG").build().unwrap();

        assert_eq!(params.params.mask, 1);
        assert_eq!(
            unsafe { CStr::from_ptr(params.params.realm).to_owned() },
            CString::new("EXAMPLE.ORG").unwrap()
        );
    }

    #[test]
    fn build_all() {
        let params = Params::builder()
            .realm("EXAMPLE.ORG")
            .admin_server("kdc.example.org")
            .kadmind_port(750)
            .kpasswd_port(465)
            .build()
            .unwrap();

        assert_eq!(params.params.mask, 0x94001);
        assert_eq!(
            unsafe { CStr::from_ptr(params.params.realm).to_owned() },
            CString::new("EXAMPLE.ORG").unwrap()
        );
        assert_eq!(
            unsafe { CStr::from_ptr(params.params.realm).to_owned() },
            CString::new("EXAMPLE.ORG").unwrap()
        );
        assert_eq!(params.params.kadmind_port, 750);
        assert_eq!(params.params.kpasswd_port, 465);
    }
}

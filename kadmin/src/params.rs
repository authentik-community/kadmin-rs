//! Define [`Params`] to pass to kadm5

use std::{
    ffi::{CString, c_int, c_long},
    ptr::null_mut,
};

#[cfg(feature = "python")]
use pyo3::prelude::*;

use crate::{
    error::Result,
    sys::{self, KAdm5Variant},
};

#[cfg(mit)]
#[derive(Debug)]
pub(crate) struct ParamsMit {
    /// Params for kadm5
    ///
    /// Additional fields to store transient strings so the pointer stored in
    /// [`kadm5_config_params`]
    /// doesn't become invalid while this struct lives.
    pub(crate) params: sys::mit::kadm5_config_params,

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
#[cfg(mit)]
unsafe impl Send for ParamsMit {}
#[cfg(mit)]
unsafe impl Sync for ParamsMit {}

#[cfg(mit)]
impl Clone for ParamsMit {
    fn clone(&self) -> Self {
        let _realm = self._realm.clone();
        let _admin_server = self._admin_server.clone();
        let _dbname = self._dbname.clone();
        let _acl_file = self._acl_file.clone();
        let _dict_file = self._dict_file.clone();
        let _stash_file = self._stash_file.clone();
        Self {
            params: sys::mit::kadm5_config_params {
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

#[cfg(heimdal)]
#[derive(Debug)]
pub(crate) struct ParamsHeimdal {
    /// Params for kadm5
    ///
    /// Additional fields to store transient strings so the pointer stored in
    /// [`kadm5_config_params`]
    /// doesn't become invalid while this struct lives.
    pub(crate) params: sys::heimdal::kadm5_config_params,

    /// Store [`CString`] that is in `params`
    _realm: Option<CString>,
    /// Store [`CString`] that is in `params`
    _admin_server: Option<CString>,
    /// Store [`CString`] that is in `params`
    _dbname: Option<CString>,
    /// Store [`CString`] that is in `params`
    _acl_file: Option<CString>,
    /// Store [`CString`] that is in `params`
    _stash_file: Option<CString>,
}

// Pointees are contained in the struct itself
#[cfg(heimdal)]
unsafe impl Send for ParamsHeimdal {}
#[cfg(heimdal)]
unsafe impl Sync for ParamsHeimdal {}

#[cfg(heimdal)]
impl Clone for ParamsHeimdal {
    fn clone(&self) -> Self {
        let _realm = self._realm.clone();
        let _admin_server = self._admin_server.clone();
        let _dbname = self._dbname.clone();
        let _acl_file = self._acl_file.clone();
        let _stash_file = self._stash_file.clone();
        Self {
            params: sys::heimdal::kadm5_config_params {
                mask: self.params.mask,
                realm: if let Some(realm) = &_realm {
                    realm.as_ptr().cast_mut()
                } else {
                    null_mut()
                },
                kadmind_port: self.params.kadmind_port,

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
                stash_file: if let Some(stash_file) = &_stash_file {
                    stash_file.as_ptr().cast_mut()
                } else {
                    null_mut()
                },
                readonly_admin_server: null_mut(),
                readonly_kadmind_port: 0,
            },
            _realm,
            _admin_server,
            _dbname,
            _acl_file,
            _stash_file,
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "python", pyclass)]
pub(crate) enum ParamsInner {
    #[cfg(mit)]
    Mit(ParamsMit),
    #[cfg(heimdal)]
    Heimdal(ParamsHeimdal),
}

/// kadm5 config options
///
/// ```
/// let params = kadmin::Params::builder()
///     .realm("EXAMPLE.ORG")
///     .build()
///     .unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct Params {
    inner: ParamsInner,
}

impl Params {
    /// Construct a new [`ParamsBuilder`]
    pub fn builder(variant: KAdm5Variant) -> ParamsBuilder {
        ParamsBuilder::new(variant)
    }
}

/// [`Params`] builder
#[derive(Clone, Debug)]
pub struct ParamsBuilder {
    variant: KAdm5Variant,

    /// Mask for which values are set
    mask: i32,

    /// Default database realm
    realm: Option<String>,
    /// kadmind port to connect to
    kadmind_port: c_int,
    #[cfg(mit)]
    /// kpasswd port to connect to
    kpasswd_port: c_int,
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

impl ParamsBuilder {
    pub fn new(variant: KAdm5Variant) -> Self {
        Self {
            variant,
            mask: 0,
            realm: None,
            kadmind_port: 0,
            #[cfg(mit)]
            kpasswd_port: 0,
            admin_server: None,
            dbname: None,
            acl_file: None,
            #[cfg(mit)]
            dict_file: None,
            stash_file: None,
        }
    }

    /// Set the default database realm
    pub fn realm(mut self, realm: &str) -> Self {
        self.realm = Some(realm.to_owned());
        self.mask |= match self.variant {
            #[cfg(mit)]
            KAdm5Variant::MitClient | KAdm5Variant::MitServer => sys::mit::KADM5_CONFIG_REALM,
            #[cfg(heimdal)]
            KAdm5Variant::HeimdalClient | KAdm5Variant::HeimdalServer => {
                sys::heimdal::KADM5_CONFIG_REALM
            }
        } as i32;
        self
    }

    /// Set the kadmind port to connect to
    pub fn kadmind_port(mut self, port: c_int) -> Self {
        self.kadmind_port = port;
        self.mask |= match self.variant {
            #[cfg(mit)]
            KAdm5Variant::MitClient | KAdm5Variant::MitServer => {
                sys::mit::KADM5_CONFIG_KADMIND_PORT
            }
            #[cfg(heimdal)]
            KAdm5Variant::HeimdalClient | KAdm5Variant::HeimdalServer => {
                sys::heimdal::KADM5_CONFIG_KADMIND_PORT
            }
        } as i32;
        self
    }

    #[cfg(mit)]
    /// Set the kpasswd port to connect to
    ///
    /// No-op for heimdal
    pub fn kpasswd_port(mut self, port: c_int) -> Self {
        #[cfg(heimdal)]
        if self.variant == KAdm5Variant::HeimdalClient
            || self.variant == KAdm5Variant::HeimdalServer
        {
            return self;
        }
        self.kpasswd_port = port;
        self.mask |= sys::mit::KADM5_CONFIG_KPASSWD_PORT as i32;
        self
    }

    /// Set the admin server which kadmin should contact
    pub fn admin_server(mut self, admin_server: &str) -> Self {
        self.admin_server = Some(admin_server.to_owned());
        self.mask |= match self.variant {
            #[cfg(mit)]
            KAdm5Variant::MitClient | KAdm5Variant::MitServer => {
                sys::mit::KADM5_CONFIG_ADMIN_SERVER
            }
            #[cfg(heimdal)]
            KAdm5Variant::HeimdalClient | KAdm5Variant::HeimdalServer => {
                sys::heimdal::KADM5_CONFIG_ADMIN_SERVER
            }
        } as i32;
        self
    }

    /// Set the name of the KDC database
    pub fn dbname(mut self, dbname: &str) -> Self {
        self.dbname = Some(dbname.to_owned());
        self.mask |= match self.variant {
            #[cfg(mit)]
            KAdm5Variant::MitClient | KAdm5Variant::MitServer => sys::mit::KADM5_CONFIG_DBNAME,
            #[cfg(heimdal)]
            KAdm5Variant::HeimdalClient | KAdm5Variant::HeimdalServer => {
                sys::heimdal::KADM5_CONFIG_DBNAME
            }
        } as i32;
        self
    }

    /// Set the location of the access control list file
    pub fn acl_file(mut self, acl_file: &str) -> Self {
        self.acl_file = Some(acl_file.to_owned());
        self.mask |= match self.variant {
            #[cfg(mit)]
            KAdm5Variant::MitClient | KAdm5Variant::MitServer => sys::mit::KADM5_CONFIG_ACL_FILE,
            #[cfg(heimdal)]
            KAdm5Variant::HeimdalClient | KAdm5Variant::HeimdalServer => {
                sys::heimdal::KADM5_CONFIG_ACL_FILE
            }
        } as i32;
        self
    }

    #[cfg(mit)]
    /// Set the location of the dictionary file containing strings that are not allowed as passwords
    ///
    /// No-op for Heimdal
    pub fn dict_file(mut self, dict_file: &str) -> Self {
        #[cfg(heimdal)]
        if self.variant == KAdm5Variant::HeimdalClient
            || self.variant == KAdm5Variant::HeimdalServer
        {
            return self;
        }
        self.dict_file = Some(dict_file.to_owned());
        self.mask |= sys::mit::KADM5_CONFIG_DICT_FILE as i32;
        self
    }

    /// Set the location where the master key has been stored
    pub fn stash_file(mut self, stash_file: &str) -> Self {
        self.stash_file = Some(stash_file.to_owned());
        self.mask |= match self.variant {
            #[cfg(mit)]
            KAdm5Variant::MitClient | KAdm5Variant::MitServer => sys::mit::KADM5_CONFIG_STASH_FILE,
            #[cfg(heimdal)]
            KAdm5Variant::HeimdalClient | KAdm5Variant::HeimdalServer => {
                sys::heimdal::KADM5_CONFIG_STASH_FILE
            }
        } as i32;
        self
    }

    #[cfg(mit)]
    /// Construct [`Params`] from the provided options for an MIT [`crate::sys::Library`]
    fn build_mit(self) -> Result<ParamsInner> {
        let _realm = self.realm.map(CString::new).transpose()?;
        let _admin_server = self.admin_server.map(CString::new).transpose()?;
        let _dbname = self.dbname.map(CString::new).transpose()?;
        let _acl_file = self.acl_file.map(CString::new).transpose()?;
        let _dict_file = self.dict_file.map(CString::new).transpose()?;
        let _stash_file = self.stash_file.map(CString::new).transpose()?;

        let params = sys::mit::kadm5_config_params {
            mask: self.mask as c_long,
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

        Ok(ParamsInner::Mit(ParamsMit {
            params,
            _realm,
            _admin_server,
            _dbname,
            _acl_file,
            _dict_file,
            _stash_file,
        }))
    }

    #[cfg(heimdal)]
    /// Construct [`Params`] from the provided options for an Heimdal [`crate::sys::Library`]
    fn build_heimdal(self) -> Result<ParamsInner> {
        let _realm = self.realm.map(CString::new).transpose()?;
        let _admin_server = self.admin_server.map(CString::new).transpose()?;
        let _dbname = self.dbname.map(CString::new).transpose()?;
        let _acl_file = self.acl_file.map(CString::new).transpose()?;
        let _stash_file = self.stash_file.map(CString::new).transpose()?;

        let params = sys::heimdal::kadm5_config_params {
            mask: self.mask as u32,
            realm: if let Some(realm) = &_realm {
                realm.as_ptr().cast_mut()
            } else {
                null_mut()
            },
            kadmind_port: self.kadmind_port,

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
            stash_file: if let Some(stash_file) = &_stash_file {
                stash_file.as_ptr().cast_mut()
            } else {
                null_mut()
            },
            readonly_admin_server: null_mut(),
            readonly_kadmind_port: 0,
        };

        Ok(ParamsInner::Heimdal(ParamsHeimdal {
            params,
            _realm,
            _admin_server,
            _dbname,
            _acl_file,
            _stash_file,
        }))
    }

    /// Construct [`Params`] from the provided options for an MIT [`crate::sys::Library`]
    pub fn build(self) -> Result<Params> {
        Ok(Params {
            inner: match self.variant {
                #[cfg(mit)]
                KAdm5Variant::MitClient | KAdm5Variant::MitServer => self.build_mit()?,
                #[cfg(heimdal)]
                KAdm5Variant::HeimdalClient | KAdm5Variant::HeimdalServer => {
                    self.build_heimdal()?
                }
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use super::*;

    #[cfg(mit)]
    #[test]
    fn build_empty_mit() {
        let params = Params::builder(KAdm5Variant::MitClient).build().unwrap();

        match params.inner {
            ParamsInner::Mit(p) => assert_eq!(p.params.mask, 0),
            _ => unreachable!(),
        };
    }

    #[cfg(heimdal)]
    #[test]
    fn build_empty_heimdal() {
        let params = Params::builder(KAdm5Variant::HeimdalClient)
            .build()
            .unwrap();

        match params.inner {
            ParamsInner::Heimdal(p) => assert_eq!(p.params.mask, 0),
            _ => unreachable!(),
        };
    }

    #[cfg(mit)]
    #[test]
    fn build_realm_mit() {
        let params = Params::builder(KAdm5Variant::MitClient)
            .realm("EXAMPLE.ORG")
            .build()
            .unwrap();

        match params.inner {
            ParamsInner::Mit(p) => {
                assert_eq!(p.params.mask, 1);
                assert_eq!(
                    unsafe { CStr::from_ptr(p.params.realm).to_owned() },
                    CString::new("EXAMPLE.ORG").unwrap()
                );
            }
            _ => unreachable!(),
        };
    }

    #[cfg(heimdal)]
    #[test]
    fn build_realm_heimdal() {
        let params = Params::builder(KAdm5Variant::HeimdalClient)
            .realm("EXAMPLE.ORG")
            .build()
            .unwrap();

        match params.inner {
            ParamsInner::Heimdal(p) => {
                assert_eq!(p.params.mask, 1);
                assert_eq!(
                    unsafe { CStr::from_ptr(p.params.realm).to_owned() },
                    CString::new("EXAMPLE.ORG").unwrap()
                );
            }
            _ => unreachable!(),
        };
    }

    #[cfg(mit)]
    #[test]
    fn build_all_mit() {
        let params = Params::builder(KAdm5Variant::MitClient)
            .realm("EXAMPLE.ORG")
            .admin_server("kdc.example.org")
            .kadmind_port(750)
            .kpasswd_port(465)
            .build()
            .unwrap();

        match params.inner {
            ParamsInner::Mit(p) => {
                assert_eq!(p.params.mask, 0x94001);
                assert_eq!(
                    unsafe { CStr::from_ptr(p.params.realm).to_owned() },
                    CString::new("EXAMPLE.ORG").unwrap()
                );
                assert_eq!(
                    unsafe { CStr::from_ptr(p.params.realm).to_owned() },
                    CString::new("EXAMPLE.ORG").unwrap()
                );
                assert_eq!(p.params.kadmind_port, 750);
                assert_eq!(p.params.kpasswd_port, 465);
            }
            _ => unreachable!(),
        };
    }

    #[cfg(heimdal)]
    #[test]
    fn build_all_heimdal() {
        let params = Params::builder(KAdm5Variant::HeimdalClient)
            .realm("EXAMPLE.ORG")
            .admin_server("kdc.example.org")
            .kadmind_port(750)
            .build()
            .unwrap();

        match params.inner {
            ParamsInner::Heimdal(p) => {
                assert_eq!(p.params.mask, 0xd);
                assert_eq!(
                    unsafe { CStr::from_ptr(p.params.realm).to_owned() },
                    CString::new("EXAMPLE.ORG").unwrap()
                );
                assert_eq!(
                    unsafe { CStr::from_ptr(p.params.realm).to_owned() },
                    CString::new("EXAMPLE.ORG").unwrap()
                );
                assert_eq!(p.params.kadmind_port, 750);
            }
            _ => unreachable!(),
        };
    }
}

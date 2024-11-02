use std::{ffi::CString, ptr::null_mut};

use kadmin_sys::*;

use crate::error::Result;

#[derive(Debug)]
pub struct KAdminParams {
    pub(crate) params: kadm5_config_params,

    // Additional fields to store transient strings so the pointer stored in kadm5_config_params
    // doesn't become invalid while this struct lives.
    _strings: Vec<Option<CString>>,
}

impl KAdminParams {
    pub fn builder() -> KAdminParamsBuilder {
        KAdminParamsBuilder::default()
    }
}

impl Default for KAdminParams {
    fn default() -> Self {
        Self::builder().build().unwrap()
    }
}

#[derive(Clone, Debug, Default)]
pub struct KAdminParamsBuilder {
    mask: i64,

    realm: Option<String>,
    kadmind_port: i32,
    kpasswd_port: i32,
    admin_server: Option<String>,
    dbname: Option<String>,
    acl_file: Option<String>,
    dict_file: Option<String>,
    stash_file: Option<String>,
}

impl KAdminParamsBuilder {
    pub fn realm(mut self, realm: &str) -> Self {
        self.realm = Some(realm.to_owned());
        self.mask |= KADM5_CONFIG_REALM as i64;
        self
    }

    pub fn kadmind_port(mut self, port: i32) -> Self {
        self.kadmind_port = port;
        self.mask |= KADM5_CONFIG_KADMIND_PORT as i64;
        self
    }

    pub fn kpasswd_port(mut self, port: i32) -> Self {
        self.kpasswd_port = port;
        self.mask |= KADM5_CONFIG_KPASSWD_PORT as i64;
        self
    }

    pub fn admin_server(mut self, admin_server: &str) -> Self {
        self.admin_server = Some(admin_server.to_owned());
        self.mask |= KADM5_CONFIG_ADMIN_SERVER as i64;
        self
    }

    pub fn dbname(mut self, dbname: &str) -> Self {
        self.dbname = Some(dbname.to_owned());
        self.mask |= KADM5_CONFIG_DBNAME as i64;
        self
    }

    pub fn acl_file(mut self, acl_file: &str) -> Self {
        self.acl_file = Some(acl_file.to_owned());
        self.mask |= KADM5_CONFIG_ACL_FILE as i64;
        self
    }

    pub fn dict_file(mut self, dict_file: &str) -> Self {
        self.dict_file = Some(dict_file.to_owned());
        self.mask |= KADM5_CONFIG_DICT_FILE as i64;
        self
    }

    pub fn stash_file(mut self, stash_file: &str) -> Self {
        self.stash_file = Some(stash_file.to_owned());
        self.mask |= KADM5_CONFIG_STASH_FILE as i64;
        self
    }

    pub fn build(self) -> Result<KAdminParams> {
        let realm = self.realm.map(CString::new).transpose()?;
        let admin_server = self.admin_server.map(CString::new).transpose()?;
        let dbname = self.dbname.map(CString::new).transpose()?;
        let acl_file = self.acl_file.map(CString::new).transpose()?;
        let dict_file = self.dict_file.map(CString::new).transpose()?;
        let stash_file = self.stash_file.map(CString::new).transpose()?;

        let params = kadm5_config_params {
            mask: self.mask,
            realm: if let Some(realm) = &realm {
                realm.as_ptr().cast_mut()
            } else {
                null_mut()
            },
            kadmind_port: self.kadmind_port,
            kpasswd_port: self.kpasswd_port,

            admin_server: if let Some(admin_server) = &admin_server {
                admin_server.as_ptr().cast_mut()
            } else {
                null_mut()
            },

            dbname: if let Some(dbname) = &dbname {
                dbname.as_ptr().cast_mut()
            } else {
                null_mut()
            },
            acl_file: if let Some(acl_file) = &acl_file {
                acl_file.as_ptr().cast_mut()
            } else {
                null_mut()
            },
            dict_file: if let Some(dict_file) = &dict_file {
                dict_file.as_ptr().cast_mut()
            } else {
                null_mut()
            },
            mkey_from_kbd: 0,
            stash_file: if let Some(stash_file) = &stash_file {
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

        Ok(KAdminParams {
            params,
            _strings: vec![realm, admin_server, dbname, acl_file, dict_file, stash_file],
        })
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use super::*;

    #[test]
    fn build_empty() {
        let params = KAdminParams::builder().build().unwrap();

        assert_eq!(params.params.mask, 0);
    }

    #[test]
    fn build_realm() {
        let params = KAdminParams::builder().realm("EXAMPLE.ORG").build().unwrap();

        assert_eq!(params.params.mask, 1);
        assert_eq!(
            unsafe { CStr::from_ptr(params.params.realm).to_owned() },
            CString::new("EXAMPLE.ORG").unwrap()
        );
    }

    #[test]
    fn build_all() {
        let params = KAdminParams::builder()
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

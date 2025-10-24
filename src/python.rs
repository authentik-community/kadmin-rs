//! Python bindings to libkadm5

use std::{
    collections::{HashMap, HashSet},
    ffi::c_int,
};

use pyo3::{
    prelude::*,
    types::{PyDict, PyString, PyTuple},
};

#[cfg(any(mit_client, mit_server, heimdal_server))]
use crate::policy::Policy;
use crate::{
    db_args::DbArgs,
    error::Result,
    kadmin::{KAdminApiVersion, KAdminImpl},
    keysalt::{EncryptionType, KeySalt, KeySalts, SaltType},
    params::Params,
    principal::{Principal, PrincipalBuilderKey},
    sync::{KAdmin, KAdminBuilder},
    sys::KAdm5Variant,
    tl_data::{TlData, TlDataEntry},
};

#[pymodule(name = "_lib", gil_used = false)]
fn init(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<KAdminApiVersion>()?;
    m.add_class::<KAdm5Variant>()?;
    m.add_class::<Params>()?;
    m.add_class::<DbArgs>()?;
    m.add_class::<TlDataEntry>()?;
    m.add_class::<TlData>()?;
    m.add_class::<EncryptionType>()?;
    m.add_class::<SaltType>()?;
    m.add_class::<KeySalt>()?;
    m.add_class::<KeySalts>()?;
    m.add_class::<KAdmin>()?;
    m.add_class::<PyPrincipalBuilderKey>()?;
    m.add_class::<Principal>()?;
    #[cfg(any(mit_client, mit_server, heimdal_server))]
    m.add_class::<Policy>()?;
    exceptions::init(m)?;
    Ok(())
}

#[pymethods]
impl Params {
    #[new]
    #[pyo3(signature = (
        realm=None,
        kadmind_port=None,
        kpasswd_port=None,
        admin_server=None,
        dbname=None,
        acl_file=None,
        dict_file=None,
        stash_file=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn py_new(
        realm: Option<&str>,
        kadmind_port: Option<c_int>,
        kpasswd_port: Option<c_int>,
        admin_server: Option<&str>,
        dbname: Option<&str>,
        acl_file: Option<&str>,
        dict_file: Option<&str>,
        stash_file: Option<&str>,
    ) -> Self {
        let mut params = Params::new();
        if let Some(realm) = realm {
            params = params.realm(realm);
        }
        if let Some(kadmind_port) = kadmind_port {
            params = params.kadmind_port(kadmind_port);
        }
        #[cfg(any(mit_client, mit_server))]
        if let Some(kpasswd_port) = kpasswd_port {
            params = params.kpasswd_port(kpasswd_port);
        }
        if let Some(admin_server) = admin_server {
            params = params.admin_server(admin_server);
        }
        if let Some(dbname) = dbname {
            params = params.dbname(dbname);
        }
        if let Some(acl_file) = acl_file {
            params = params.acl_file(acl_file);
        }
        #[cfg(any(mit_client, mit_server))]
        if let Some(dict_file) = dict_file {
            params = params.dict_file(dict_file);
        }
        if let Some(stash_file) = stash_file {
            params = params.stash_file(stash_file);
        }
        params
    }
}

#[pymethods]
impl DbArgs {
    #[new]
    #[pyo3(signature = (*args, **kwargs))]
    fn py_new(args: &Bound<'_, PyTuple>, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
        let mut builder = DbArgs::builder();
        for arg in args.iter() {
            let arg = if !arg.is_instance_of::<PyString>() {
                arg.str()?
            } else {
                arg.extract()?
            };
            builder = builder.arg(arg.to_str()?, None);
        }
        if let Some(kwargs) = kwargs {
            for (name, value) in kwargs.iter() {
                let name = if !name.is_instance_of::<PyString>() {
                    name.str()?
                } else {
                    name.extract()?
                };
                builder = if !value.is_none() {
                    let value = value.str()?;
                    builder.arg(name.to_str()?, Some(value.to_str()?))
                } else {
                    builder.arg(name.to_str()?, None)
                };
            }
        }
        Ok(builder.build()?)
    }
}

#[pymethods]
impl EncryptionType {
    #[new]
    fn py_new(enctype: i32) -> Self {
        enctype.into()
    }
}

#[pymethods]
impl SaltType {
    #[new]
    #[pyo3(signature = (salttype = None))]
    fn py_new(salttype: Option<i32>) -> Self {
        match salttype {
            None => Default::default(),
            Some(salttype) => salttype.into(),
        }
    }
}

#[pymethods]
impl KeySalt {
    #[new]
    #[pyo3(signature = (enctype, salttype = None))]
    fn py_new(enctype: EncryptionType, salttype: Option<SaltType>) -> Self {
        Self {
            enctype,
            salttype: salttype.unwrap_or_default(),
        }
    }
}

#[pymethods]
impl KeySalts {
    #[new]
    fn py_new(keysalts: HashSet<KeySalt>) -> Self {
        Self { keysalts }
    }
}

#[pymethods]
impl TlDataEntry {
    #[new]
    fn py_new(data_type: i16, contents: Vec<u8>) -> Self {
        Self {
            data_type,
            contents,
        }
    }
}

#[pymethods]
impl TlData {
    #[new]
    fn py_new(entries: Vec<TlDataEntry>) -> Self {
        Self { entries }
    }
}

impl KAdmin {
    fn py_get_builder(
        variant: KAdm5Variant,
        params: Option<Params>,
        db_args: Option<DbArgs>,
        api_version: Option<KAdminApiVersion>,
    ) -> KAdminBuilder {
        let mut builder = KAdminBuilder::new(variant);
        if let Some(params) = params {
            builder = builder.params(params);
        }
        if let Some(db_args) = db_args {
            builder = builder.db_args(db_args);
        }
        if let Some(api_version) = api_version {
            builder = builder.api_version(api_version);
        }
        builder
    }
}

#[pymethods]
impl KAdmin {
    #[pyo3(name = "add_principal", signature = (name, **kwargs))]
    fn py_add_principal(
        &self,
        name: &str,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Principal> {
        let mut builder = Principal::builder(name);
        if let Some(kwargs) = kwargs {
            if let Some(expire_time) = kwargs.get_item("expire_time")? {
                builder = builder.expire_time(expire_time.extract()?);
            }
            if let Some(password_expiration) = kwargs.get_item("password_expiration")? {
                builder = builder.password_expiration(password_expiration.extract()?);
            }
            if let Some(max_life) = kwargs.get_item("max_life")? {
                builder = builder.max_life(max_life.extract()?);
            }
            if let Some(attributes) = kwargs.get_item("attributes")? {
                builder = builder.attributes(attributes.extract()?);
            }
            if let Some(policy) = kwargs.get_item("policy")? {
                builder = builder.policy(policy.extract::<Option<String>>()?.as_deref());
            }
            if let Some(aux_attributes) = kwargs.get_item("aux_attributes")? {
                builder = builder.aux_attributes(aux_attributes.extract()?);
            }
            if let Some(max_renewable_life) = kwargs.get_item("max_renewable_life")? {
                builder = builder.max_renewable_life(max_renewable_life.extract()?);
            }
            if let Some(fail_auth_count) = kwargs.get_item("fail_auth_count")? {
                builder = builder.fail_auth_count(fail_auth_count.extract()?);
            }
            if let Some(tl_data) = kwargs.get_item("tl_data")? {
                builder = builder.tl_data(tl_data.extract()?);
            }
            #[cfg(any(mit_client, mit_server))]
            if let Some(db_args) = kwargs.get_item("db_args")? {
                builder = builder.db_args(db_args.extract()?);
            }
            if let Some(kvno) = kwargs.get_item("kvno")? {
                builder = builder.kvno(kvno.extract()?);
            }
            if let Some(key) = kwargs.get_item("key")? {
                let key = key.extract::<PyPrincipalBuilderKey>()?;
                builder = builder.key(&key.into());
            }
            #[cfg(any(mit_client, mit_server, heimdal_server))]
            if let Some(keysalts) = kwargs.get_item("keysalts")? {
                builder = builder.keysalts(&keysalts.extract()?);
            }
        }
        Ok(builder.create(self)?)
    }

    #[pyo3(name = "rename_principal")]
    fn py_rename_principal(&self, old_name: &str, new_name: &str) -> Result<()> {
        self.rename_principal(old_name, new_name)
    }

    #[pyo3(name = "delete_principal")]
    fn py_delete_principal(&self, name: &str) -> Result<()> {
        self.delete_principal(name)
    }

    #[pyo3(name = "get_principal")]
    fn py_get_principal(&self, name: &str) -> Result<Option<Principal>> {
        self.get_principal(name)
    }

    #[pyo3(name = "principal_exists")]
    fn py_principal_exists(&self, name: &str) -> Result<bool> {
        self.principal_exists(name)
    }

    #[pyo3(name = "principal_change_password", signature = (name, password, keepold = None, keysalts = None))]
    fn py_principal_change_password(
        &self,
        name: &str,
        password: &str,
        keepold: Option<bool>,
        keysalts: Option<&KeySalts>,
    ) -> Result<()> {
        self.principal_change_password(
            name,
            password,
            #[cfg(any(mit_client, mit_server, heimdal_server))]
            keepold,
            #[cfg(any(mit_client, mit_server, heimdal_server))]
            keysalts,
        )
    }

    #[pyo3(name = "principal_randkey", signature = (name, keepold = None, keysalts = None))]
    fn py_principal_randkey(
        &self,
        name: &str,
        keepold: Option<bool>,
        keysalts: Option<&KeySalts>,
    ) -> Result<()> {
        self.principal_randkey(name, keepold, keysalts)
    }

    #[cfg(any(mit_client, mit_server))]
    #[pyo3(name = "principal_get_strings")]
    fn py_principal_get_strings(&self, name: &str) -> Result<HashMap<String, String>> {
        self.principal_get_strings(name)
    }

    #[cfg(any(mit_client, mit_server))]
    #[pyo3(name = "principal_set_string", signature = (name, key, value))]
    fn py_principal_set_string(&self, name: &str, key: &str, value: Option<&str>) -> Result<()> {
        self.principal_set_string(name, key, value)
    }

    #[pyo3(name = "list_principals", signature = (query=None))]
    fn py_list_principals(&self, query: Option<&str>) -> Result<Vec<String>> {
        self.list_principals(query)
    }

    #[cfg(any(mit_client, mit_server, heimdal_server))]
    #[pyo3(name = "add_policy", signature = (name, **kwargs))]
    fn py_add_policy(&self, name: &str, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Policy> {
        let mut builder = Policy::builder(name);
        if let Some(kwargs) = kwargs {
            if let Some(password_min_life) = kwargs.get_item("password_min_life")? {
                builder = builder.password_min_life(password_min_life.extract()?);
            }
            if let Some(password_max_life) = kwargs.get_item("password_max_life")? {
                builder = builder.password_max_life(password_max_life.extract()?);
            }
            if let Some(password_min_length) = kwargs.get_item("password_min_length")? {
                builder = builder.password_min_length(password_min_length.extract()?);
            }
            if let Some(password_min_classes) = kwargs.get_item("password_min_classes")? {
                builder = builder.password_min_classes(password_min_classes.extract()?);
            }
            if let Some(password_history_num) = kwargs.get_item("password_history_num")? {
                builder = builder.password_history_num(password_history_num.extract()?);
            }
            #[cfg(any(mit_client, mit_server))]
            if let Some(password_max_fail) = kwargs.get_item("password_max_fail")? {
                builder = builder.password_max_fail(password_max_fail.extract()?);
            }
            #[cfg(any(mit_client, mit_server))]
            if let Some(password_failcount_interval) =
                kwargs.get_item("password_failcount_interval")?
            {
                builder =
                    builder.password_failcount_interval(password_failcount_interval.extract()?);
            }
            #[cfg(any(mit_client, mit_server))]
            if let Some(password_lockout_duration) = kwargs.get_item("password_lockout_duration")? {
                builder = builder.password_lockout_duration(password_lockout_duration.extract()?);
            }
            #[cfg(any(mit_client, mit_server))]
            if let Some(attributes) = kwargs.get_item("attributes")? {
                builder = builder.attributes(attributes.extract()?);
            }
            #[cfg(any(mit_client, mit_server))]
            if let Some(max_life) = kwargs.get_item("max_life")? {
                builder = builder.max_life(max_life.extract()?);
            }
            #[cfg(any(mit_client, mit_server))]
            if let Some(max_renewable_life) = kwargs.get_item("max_renewable_life")? {
                builder = builder.max_renewable_life(max_renewable_life.extract()?);
            }
            #[cfg(any(mit_client, mit_server))]
            if let Some(allowed_keysalts) = kwargs.get_item("allowed_keysalts")? {
                builder = builder.allowed_keysalts(allowed_keysalts.extract()?);
            }
            #[cfg(any(mit_client, mit_server))]
            if let Some(tl_data) = kwargs.get_item("tl_data")? {
                builder = builder.tl_data(tl_data.extract()?);
            }
        }
        Ok(builder.create(self)?)
    }

    #[cfg(any(mit_client, mit_server, heimdal_server))]
    #[pyo3(name = "delete_policy")]
    fn py_delete_policy(&self, name: &str) -> Result<()> {
        self.delete_policy(name)
    }

    #[cfg(any(mit_client, mit_server, heimdal_server))]
    #[pyo3(name = "get_policy")]
    fn py_get_policy(&self, name: &str) -> Result<Option<Policy>> {
        self.get_policy(name)
    }

    #[cfg(any(mit_client, mit_server, heimdal_server))]
    #[pyo3(name = "policy_exists")]
    fn py_policy_exists(&self, name: &str) -> Result<bool> {
        self.policy_exists(name)
    }

    #[cfg(any(mit_client, mit_server, heimdal_server))]
    #[pyo3(name = "list_policies", signature = (query=None))]
    fn py_list_policies(&self, query: Option<&str>) -> Result<Vec<String>> {
        self.list_policies(query)
    }

    #[pyo3(name = "get_privileges")]
    fn py_get_privileges(&self) -> Result<i64> {
        self.get_privileges()
    }

    #[staticmethod]
    #[pyo3(name = "with_password", signature = (variant, client_name, password, params=None, db_args=None, api_version=None))]
    fn py_with_password(
        variant: KAdm5Variant,
        client_name: &str,
        password: &str,
        params: Option<Params>,
        db_args: Option<DbArgs>,
        api_version: Option<KAdminApiVersion>,
    ) -> Result<Self> {
        Self::py_get_builder(variant, params, db_args, api_version)
            .with_password(client_name, password)
    }

    #[staticmethod]
    #[pyo3(name = "with_keytab", signature = (variant, client_name=None, keytab=None, params=None, db_args=None, api_version=None))]
    fn py_with_keytab(
        variant: KAdm5Variant,
        client_name: Option<&str>,
        keytab: Option<&str>,
        params: Option<Params>,
        db_args: Option<DbArgs>,
        api_version: Option<KAdminApiVersion>,
    ) -> Result<Self> {
        Self::py_get_builder(variant, params, db_args, api_version).with_keytab(client_name, keytab)
    }

    #[staticmethod]
    #[pyo3(name = "with_ccache", signature = (variant, client_name=None, ccache_name=None, params=None, db_args=None, api_version=None))]
    fn py_with_ccache(
        variant: KAdm5Variant,
        client_name: Option<&str>,
        ccache_name: Option<&str>,
        params: Option<Params>,
        db_args: Option<DbArgs>,
        api_version: Option<KAdminApiVersion>,
    ) -> Result<Self> {
        Self::py_get_builder(variant, params, db_args, api_version)
            .with_ccache(client_name, ccache_name)
    }

    #[staticmethod]
    #[pyo3(name = "with_anonymous", signature = (variant, client_name, params=None, db_args=None, api_version=None))]
    fn py_with_anonymous(
        variant: KAdm5Variant,
        client_name: &str,
        params: Option<Params>,
        db_args: Option<DbArgs>,
        api_version: Option<KAdminApiVersion>,
    ) -> Result<Self> {
        Self::py_get_builder(variant, params, db_args, api_version).with_anonymous(client_name)
    }

    #[cfg(any(mit_server, heimdal_server))]
    #[staticmethod]
    #[pyo3(name = "with_local", signature = (variant, params=None, db_args=None, api_version=None))]
    fn py_with_local(
        variant: KAdm5Variant,
        params: Option<Params>,
        db_args: Option<DbArgs>,
        api_version: Option<KAdminApiVersion>,
    ) -> Result<Self> {
        Self::py_get_builder(variant, params, db_args, api_version).with_local()
    }
}

#[pymethods]
impl Principal {
    #[pyo3(name = "modify", signature = (kadmin, **kwargs))]
    fn py_modify(&self, kadmin: &KAdmin, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
        if let Some(kwargs) = kwargs {
            let mut modifier = self.modifier();
            if let Some(expire_time) = kwargs.get_item("expire_time")? {
                modifier = modifier.expire_time(expire_time.extract()?);
            }
            if let Some(password_expiration) = kwargs.get_item("password_expiration")? {
                modifier = modifier.password_expiration(password_expiration.extract()?);
            }
            if let Some(max_life) = kwargs.get_item("max_life")? {
                modifier = modifier.max_life(max_life.extract()?);
            }
            if let Some(attributes) = kwargs.get_item("attributes")? {
                modifier = modifier.attributes(attributes.extract()?);
            }
            if let Some(policy) = kwargs.get_item("policy")? {
                modifier = modifier.policy(policy.extract::<Option<String>>()?.as_deref());
            }
            if let Some(aux_attributes) = kwargs.get_item("aux_attributes")? {
                modifier = modifier.aux_attributes(aux_attributes.extract()?);
            }
            if let Some(max_renewable_life) = kwargs.get_item("max_renewable_life")? {
                modifier = modifier.max_renewable_life(max_renewable_life.extract()?);
            }
            if let Some(fail_auth_count) = kwargs.get_item("fail_auth_count")? {
                modifier = modifier.fail_auth_count(fail_auth_count.extract()?);
            }
            if let Some(tl_data) = kwargs.get_item("tl_data")? {
                modifier = modifier.tl_data(tl_data.extract()?);
            }
            #[cfg(any(mit_client, mit_server))]
            if let Some(db_args) = kwargs.get_item("db_args")? {
                modifier = modifier.db_args(db_args.extract()?);
            }
            Ok(modifier.modify(kadmin)?)
        } else {
            Ok(self.clone())
        }
    }

    #[pyo3(name = "delete")]
    fn py_delete(&self, kadmin: &KAdmin) -> Result<()> {
        self.delete(kadmin)
    }

    #[pyo3(name = "change_password", signature = (kadmin, password, keepold = None, keysalts = None))]
    fn py_change_password(
        &self,
        kadmin: &KAdmin,
        password: &str,
        keepold: Option<bool>,
        keysalts: Option<&KeySalts>,
    ) -> Result<()> {
        self.change_password(
            kadmin,
            password,
            #[cfg(any(mit_client, mit_server, heimdal_server))]
            keepold,
            #[cfg(any(mit_client, mit_server, heimdal_server))]
            keysalts,
        )
    }

    #[pyo3(name = "randkey", signature = (kadmin, keepold = None, keysalts = None))]
    fn py_randkey(
        &self,
        kadmin: &KAdmin,
        keepold: Option<bool>,
        keysalts: Option<&KeySalts>,
    ) -> Result<()> {
        self.randkey(kadmin, keepold, keysalts)
    }

    #[pyo3(name = "unlock")]
    fn py_unlock(&self, kadmin: &KAdmin) -> Result<()> {
        self.unlock(kadmin)
    }

    #[cfg(any(mit_client, mit_server))]
    #[pyo3(name = "get_strings")]
    fn py_get_strings(&self, kadmin: &KAdmin) -> Result<HashMap<String, String>> {
        self.get_strings(kadmin)
    }

    #[cfg(any(mit_client, mit_server))]
    #[pyo3(name = "set_string", signature = (kadmin, key, value))]
    fn py_set_string(&self, kadmin: &KAdmin, key: &str, value: Option<&str>) -> Result<()> {
        self.set_string(kadmin, key, value)
    }
}

// Copy of PrincipalBuilderKey due to pyo3 limitations
// See https://pyo3.rs/v0.23.3/class.html?highlight=enum#complex-enums
#[pyclass(name = "NewPrincipalKey")]
#[derive(Clone, Debug, PartialEq)]
enum PyPrincipalBuilderKey {
    Password(String),
    NoKey(),
    RandKey(),
    ServerRandKey(),
    OldStyleRandKey(),
}

impl From<PyPrincipalBuilderKey> for PrincipalBuilderKey {
    fn from(key: PyPrincipalBuilderKey) -> Self {
        match key {
            PyPrincipalBuilderKey::Password(s) => Self::Password(s.clone()),
            PyPrincipalBuilderKey::NoKey() => Self::NoKey,
            PyPrincipalBuilderKey::RandKey() => Self::RandKey,
            PyPrincipalBuilderKey::ServerRandKey() => Self::ServerRandKey,
            PyPrincipalBuilderKey::OldStyleRandKey() => Self::OldStyleRandKey,
        }
    }
}

#[cfg(any(mit_client, mit_server, heimdal_server))]
#[pymethods]
impl Policy {
    #[pyo3(name = "modify", signature = (kadmin, **kwargs))]
    fn py_modify(&self, kadmin: &KAdmin, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
        if let Some(kwargs) = kwargs {
            let mut modifier = self.modifier();
            if let Some(password_min_life) = kwargs.get_item("password_min_life")? {
                modifier = modifier.password_min_life(password_min_life.extract()?);
            }
            if let Some(password_max_life) = kwargs.get_item("password_max_life")? {
                modifier = modifier.password_max_life(password_max_life.extract()?);
            }
            if let Some(password_min_length) = kwargs.get_item("password_min_length")? {
                modifier = modifier.password_min_length(password_min_length.extract()?);
            }
            if let Some(password_min_classes) = kwargs.get_item("password_min_classes")? {
                modifier = modifier.password_min_classes(password_min_classes.extract()?);
            }
            if let Some(password_history_num) = kwargs.get_item("password_history_num")? {
                modifier = modifier.password_history_num(password_history_num.extract()?);
            }
            #[cfg(any(mit_client, mit_server))]
            if let Some(password_max_fail) = kwargs.get_item("password_max_fail")? {
                modifier = modifier.password_max_fail(password_max_fail.extract()?);
            }
            #[cfg(any(mit_client, mit_server))]
            if let Some(password_failcount_interval) =
                kwargs.get_item("password_failcount_interval")?
            {
                modifier =
                    modifier.password_failcount_interval(password_failcount_interval.extract()?);
            }
            #[cfg(any(mit_client, mit_server))]
            if let Some(password_lockout_duration) = kwargs.get_item("password_lockout_duration")? {
                modifier = modifier.password_lockout_duration(password_lockout_duration.extract()?);
            }
            #[cfg(any(mit_client, mit_server))]
            if let Some(attributes) = kwargs.get_item("attributes")? {
                modifier = modifier.attributes(attributes.extract()?);
            }
            #[cfg(any(mit_client, mit_server))]
            if let Some(max_life) = kwargs.get_item("max_life")? {
                modifier = modifier.max_life(max_life.extract()?);
            }
            #[cfg(any(mit_client, mit_server))]
            if let Some(max_renewable_life) = kwargs.get_item("max_renewable_life")? {
                modifier = modifier.max_renewable_life(max_renewable_life.extract()?);
            }
            #[cfg(any(mit_client, mit_server))]
            if let Some(allowed_keysalts) = kwargs.get_item("allowed_keysalts")? {
                modifier = modifier.allowed_keysalts(allowed_keysalts.extract()?);
            }
            #[cfg(any(mit_client, mit_server))]
            if let Some(tl_data) = kwargs.get_item("tl_data")? {
                modifier = modifier.tl_data(tl_data.extract()?);
            }
            Ok(modifier.modify(kadmin)?)
        } else {
            Ok(self.clone())
        }
    }

    #[pyo3(name = "delete")]
    fn py_delete(&self, kadmin: &KAdmin) -> Result<()> {
        self.delete(kadmin)
    }
}

/// python-kadmin-rs exceptions
mod exceptions {
    use indoc::indoc;
    use pyo3::{create_exception, exceptions::PyException, intern, prelude::*};

    use crate::error::Error;

    pub(super) fn init(parent: &Bound<'_, PyModule>) -> PyResult<()> {
        let m = PyModule::new(parent.py(), "exceptions")?;
        m.add("PyKAdminException", m.py().get_type::<PyKAdminException>())?;
        m.add("KAdminException", m.py().get_type::<KAdminException>())?;
        m.add("KerberosException", m.py().get_type::<KerberosException>())?;
        m.add(
            "EncryptionTypeConversion",
            m.py().get_type::<EncryptionTypeConversion>(),
        )?;
        m.add(
            "SaltTypeConversion",
            m.py().get_type::<SaltTypeConversion>(),
        )?;
        m.add("KerberosException", m.py().get_type::<KerberosException>())?;
        m.add(
            "NullPointerDereference",
            m.py().get_type::<NullPointerDereference>(),
        )?;
        m.add("CStringConversion", m.py().get_type::<CStringConversion>())?;
        m.add(
            "CStringImportFromVec",
            m.py().get_type::<CStringImportFromVec>(),
        )?;
        m.add("StringConversion", m.py().get_type::<StringConversion>())?;
        m.add("ThreadSendError", m.py().get_type::<ThreadSendError>())?;
        m.add("ThreadRecvError", m.py().get_type::<ThreadRecvError>())?;
        m.add(
            "TimestampConversion",
            m.py().get_type::<TimestampConversion>(),
        )?;
        m.add(
            "DateTimeConversion",
            m.py().get_type::<DateTimeConversion>(),
        )?;
        m.add(
            "DurationConversion",
            m.py().get_type::<DurationConversion>(),
        )?;
        m.add("LockError", m.py().get_type::<LockError>())?;
        m.add("LibraryLoadError", m.py().get_type::<LibraryLoadError>())?;
        m.add("LibraryMismatch", m.py().get_type::<LibraryMismatch>())?;
        parent.add_submodule(&m)?;
        Ok(())
    }

    create_exception!(
        exceptions,
        PyKAdminException,
        PyException,
        "Top-level exception"
    );
    create_exception!(
        exceptions,
        KAdminException,
        PyKAdminException,
        indoc! {"
            kadm5 error

            :ivar code: kadm5 error code
            :ivar origin_message: kadm5 error message
            "}
    );
    create_exception!(
        exceptions,
        KerberosException,
        PyKAdminException,
        indoc! {"
            Kerberos error

            :ivar code: Kerberos error code
            :ivar origin_message: Kerberos error message
            "}
    );
    create_exception!(
        exceptions,
        EncryptionTypeConversion,
        PyKAdminException,
        "Failed to convert to encryption type"
    );
    create_exception!(
        exceptions,
        SaltTypeConversion,
        PyKAdminException,
        "Failed to convert to salt type"
    );
    create_exception!(
        exceptions,
        NullPointerDereference,
        PyKAdminException,
        "Pointer was NULL when converting a `*c_char` to a `String`"
    );
    create_exception!(
        exceptions,
        CStringConversion,
        PyKAdminException,
        "Couldn't convert a `CString` to a `String`"
    );
    create_exception!(
        exceptions,
        CStringImportFromVec,
        PyKAdminException,
        "Couldn't import a `Vec<u8>` `CString`"
    );
    create_exception!(
        exceptions,
        StringConversion,
        PyKAdminException,
        "Couldn't convert a `CString` to a `String`, because an interior nul byte was found"
    );
    create_exception!(
        exceptions,
        ThreadSendError,
        PyKAdminException,
        "Failed to send an operation to the sync executor"
    );
    create_exception!(
        exceptions,
        ThreadRecvError,
        PyKAdminException,
        "Failed to receive the result from an operatior from the sync executor"
    );
    create_exception!(
        exceptions,
        TimestampConversion,
        PyKAdminException,
        "Failed to convert a `krb5_timestamp` to a `chrono::DateTime`"
    );
    create_exception!(
        exceptions,
        DateTimeConversion,
        PyKAdminException,
        "Failed to convert a `chrono::DateTime` to a `krb5_timestamp`"
    );
    create_exception!(
        exceptions,
        DurationConversion,
        PyKAdminException,
        "Failed to convert a `Duration` to a `krb5_deltat`"
    );
    create_exception!(
        exceptions,
        LockError,
        PyKAdminException,
        "Failed to acquire the kadmin initialisation lock"
    );
    create_exception!(
        exceptions,
        LibraryLoadError,
        PyKAdminException,
        "Failed to load the kadm5 library"
    );
    create_exception!(
        exceptions,
        LibraryMismatch,
        PyKAdminException,
        "The library is not compatible with the current operation"
    );

    impl From<Error> for PyErr {
        fn from(error: Error) -> Self {
            let (exc, extras) = match &error {
                Error::Kerberos { code, message } => (
                    KerberosException::new_err(error.to_string()),
                    Some((*code as i64, message)),
                ),
                Error::KAdmin { code, message } => (
                    KAdminException::new_err(error.to_string()),
                    Some((*code, message)),
                ),
                Error::EncryptionTypeConversion => {
                    (EncryptionTypeConversion::new_err(error.to_string()), None)
                }
                Error::SaltTypeConversion => (SaltTypeConversion::new_err(error.to_string()), None),
                Error::NullPointerDereference => {
                    (NullPointerDereference::new_err(error.to_string()), None)
                }
                Error::CStringConversion(_) => {
                    (CStringConversion::new_err(error.to_string()), None)
                }
                Error::CStringImportFromVec(_) => {
                    (CStringImportFromVec::new_err(error.to_string()), None)
                }
                Error::StringConversion(_) => (StringConversion::new_err(error.to_string()), None),
                Error::ThreadSendError => (ThreadSendError::new_err(error.to_string()), None),
                Error::ThreadRecvError(_) => (ThreadRecvError::new_err(error.to_string()), None),
                Error::TimestampConversion => {
                    (TimestampConversion::new_err(error.to_string()), None)
                }
                Error::DateTimeConversion(_) => {
                    (DateTimeConversion::new_err(error.to_string()), None)
                }
                Error::DurationConversion(_) => {
                    (DurationConversion::new_err(error.to_string()), None)
                }
                Error::LockError => (LockError::new_err(error.to_string()), None),
                Error::LibraryLoadError(_) => (LibraryLoadError::new_err(error.to_string()), None),
                Error::LibraryMismatch(_) => (LibraryMismatch::new_err(error.to_string()), None),
            };

            Python::attach(|py| {
                if let Some((code, message)) = extras {
                    let bound_exc = exc.value(py);
                    if let Err(err) = bound_exc.setattr(intern!(py, "code"), code) {
                        return err;
                    }
                    if let Err(err) = bound_exc.setattr(intern!(py, "origin_message"), message) {
                        return err;
                    }
                }

                exc
            })
        }
    }
}

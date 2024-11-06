use pyo3::prelude::*;

#[pymodule(name = "_lib")]
mod pykadmin {
    use std::{ops::Deref, sync::Arc};

    use kadmin::{
        db_args::KAdminDbArgsBuilder,
        kadmin::KAdminImpl,
        params::KAdminParamsBuilder,
        principal::Principal as KPrincipal,
        sync::{KAdmin as KKAdmin, KAdminBuilder},
    };
    use pyo3::{
        prelude::*,
        types::{PyDict, PyString},
    };

    type Result<T> = std::result::Result<T, exceptions::PyKAdminError>;

    #[pymodule_init]
    fn init(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add("__version__", env!("CARGO_PKG_VERSION"))?;
        Ok(())
    }

    #[pyclass]
    #[derive(Clone)]
    struct Params(KAdminParamsBuilder);

    #[pymethods]
    impl Params {
        #[new]
        #[pyo3(signature = (realm=None, kadmind_port=None, kpasswd_port=None, admin_server=None, dbname=None, acl_file=None, dict_file=None, stash_file=None))]
        #[allow(clippy::too_many_arguments)]
        fn new(
            realm: Option<&str>,
            kadmind_port: Option<i32>,
            kpasswd_port: Option<i32>,
            admin_server: Option<&str>,
            dbname: Option<&str>,
            acl_file: Option<&str>,
            dict_file: Option<&str>,
            stash_file: Option<&str>,
        ) -> Self {
            let mut builder = KAdminParamsBuilder::default();
            if let Some(realm) = realm {
                builder = builder.realm(realm);
            }
            if let Some(kadmind_port) = kadmind_port {
                builder = builder.kadmind_port(kadmind_port);
            }
            if let Some(kpasswd_port) = kpasswd_port {
                builder = builder.kpasswd_port(kpasswd_port);
            }
            if let Some(admin_server) = admin_server {
                builder = builder.admin_server(admin_server);
            }
            if let Some(dbname) = dbname {
                builder = builder.dbname(dbname);
            }
            if let Some(acl_file) = acl_file {
                builder = builder.acl_file(acl_file);
            }
            if let Some(dict_file) = dict_file {
                builder = builder.dict_file(dict_file);
            }
            if let Some(stash_file) = stash_file {
                builder = builder.stash_file(stash_file);
            }
            Self(builder)
        }
    }

    #[pyclass]
    #[derive(Clone)]
    struct DbArgs(KAdminDbArgsBuilder);

    #[pymethods]
    impl DbArgs {
        #[new]
        #[pyo3(signature = (**kwargs))]
        fn new(kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
            let mut builder = KAdminDbArgsBuilder::default();
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
            Ok(Self(builder))
        }
    }

    #[pyclass]
    struct KAdmin(Arc<KKAdmin>);

    impl KAdmin {
        fn get_builder(params: Option<Params>, db_args: Option<DbArgs>) -> KAdminBuilder {
            let mut builder = KAdminBuilder::default();
            if let Some(params) = params {
                builder = builder.params_builder(params.0);
            }
            if let Some(db_args) = db_args {
                builder = builder.db_args_builder(db_args.0);
            }
            builder
        }
    }

    #[pymethods]
    impl KAdmin {
        fn add_principal(&self) {
            unimplemented!();
        }

        fn delete_principal(&self) {
            unimplemented!();
        }

        fn modify_principal(&self) {
            unimplemented!();
        }

        fn rename_principal(&self) {
            unimplemented!();
        }

        fn get_principal(&self, name: &str) -> Result<Option<Principal>> {
            Ok(self.0.get_principal(name)?.map(|p| Principal {
                inner: p,
                kadmin: Arc::clone(&self.0),
            }))
        }

        fn principal_exists(&self, name: &str) -> Result<bool> {
            Ok(self.0.principal_exists(name)?)
        }

        fn list_principals(&self, query: &str) -> Result<Vec<String>> {
            Ok(self.0.list_principals(query)?)
        }

        fn add_policy(&self) {
            unimplemented!();
        }

        fn modify_policy(&self) {
            unimplemented!();
        }

        fn delete_policy(&self) {
            unimplemented!();
        }

        fn get_policy(&self) {
            unimplemented!();
        }

        fn list_policies(&self, query: &str) -> Result<Vec<String>> {
            Ok(self.0.list_policies(query)?)
        }

        fn get_privs(&self) {
            unimplemented!();
        }

        #[cfg(feature = "client")]
        #[staticmethod]
        #[pyo3(signature = (client_name, password, params=None, db_args=None))]
        fn with_password(
            client_name: &str,
            password: &str,
            params: Option<Params>,
            db_args: Option<DbArgs>,
        ) -> Result<Self> {
            Ok(Self(Arc::new(
                Self::get_builder(params, db_args).with_password(client_name, password)?,
            )))
        }

        #[cfg(feature = "client")]
        #[staticmethod]
        #[pyo3(signature = (client_name=None, keytab=None, params=None, db_args=None))]
        fn with_keytab(
            client_name: Option<&str>,
            keytab: Option<&str>,
            params: Option<Params>,
            db_args: Option<DbArgs>,
        ) -> Result<Self> {
            Ok(Self(Arc::new(
                Self::get_builder(params, db_args).with_keytab(client_name, keytab)?,
            )))
        }

        #[cfg(feature = "client")]
        #[staticmethod]
        #[pyo3(signature = (client_name=None, ccache_name=None, params=None, db_args=None))]
        fn with_ccache(
            client_name: Option<&str>,
            ccache_name: Option<&str>,
            params: Option<Params>,
            db_args: Option<DbArgs>,
        ) -> Result<Self> {
            Ok(Self(Arc::new(
                Self::get_builder(params, db_args).with_ccache(client_name, ccache_name)?,
            )))
        }

        #[cfg(feature = "client")]
        #[staticmethod]
        #[pyo3(signature = (client_name, params=None, db_args=None))]
        fn with_anonymous(client_name: &str, params: Option<Params>, db_args: Option<DbArgs>) -> Result<Self> {
            Ok(Self(Arc::new(
                Self::get_builder(params, db_args).with_anonymous(client_name)?,
            )))
        }

        #[cfg(feature = "local")]
        #[staticmethod]
        #[pyo3(signature = (params=None, db_args=None))]
        fn with_local(params: Option<Params>, db_args: Option<DbArgs>) -> Result<Self> {
            Ok(Self(Arc::new(Self::get_builder(params, db_args).with_local()?)))
        }
    }

    #[pyclass]
    struct Principal {
        inner: KPrincipal,
        kadmin: Arc<KKAdmin>,
    }

    #[pymethods]
    impl Principal {
        fn change_password(&self, password: &str) -> Result<()> {
            Ok(self.inner.change_password(self.kadmin.deref(), password)?)
        }
    }

    #[pymodule]
    mod exceptions {
        use kadmin::Error;
        use pyo3::{create_exception, exceptions::PyException, intern, prelude::*};

        #[pymodule_init]
        fn init(m: &Bound<'_, PyModule>) -> PyResult<()> {
            m.add("PyKAdminException", m.py().get_type_bound::<PyKAdminException>())?;
            m.add("KAdminException", m.py().get_type_bound::<KAdminException>())?;
            m.add("KerberosException", m.py().get_type_bound::<KerberosException>())?;
            m.add(
                "NullPointerDereference",
                m.py().get_type_bound::<NullPointerDereference>(),
            )?;
            m.add("CStringConversion", m.py().get_type_bound::<CStringConversion>())?;
            m.add("CStringImportFromVec", m.py().get_type_bound::<CStringImportFromVec>())?;
            m.add("StringConversion", m.py().get_type_bound::<StringConversion>())?;
            m.add("TimestampConversion", m.py().get_type_bound::<TimestampConversion>())?;
            Ok(())
        }

        create_exception!(exceptions, PyKAdminException, PyException);
        create_exception!(exceptions, KAdminException, PyKAdminException);
        create_exception!(exceptions, KerberosException, PyKAdminException);
        create_exception!(exceptions, NullPointerDereference, PyKAdminException);
        create_exception!(exceptions, CStringConversion, PyKAdminException);
        create_exception!(exceptions, CStringImportFromVec, PyKAdminException);
        create_exception!(exceptions, StringConversion, PyKAdminException);
        create_exception!(exceptions, ThreadSendError, PyKAdminException);
        create_exception!(exceptions, ThreadRecvError, PyKAdminException);
        create_exception!(exceptions, TimestampConversion, PyKAdminException);

        pub(crate) struct PyKAdminError(Error);

        impl From<Error> for PyKAdminError {
            fn from(error: Error) -> Self {
                Self(error)
            }
        }

        impl From<PyKAdminError> for PyErr {
            fn from(error: PyKAdminError) -> Self {
                Python::with_gil(|py| {
                    let error = error.0;
                    let (exc, extras) = match &error {
                        Error::Kerberos { code, message } => (
                            KerberosException::new_err(error.to_string()),
                            Some((*code as i64, message)),
                        ),
                        Error::KAdmin { code, message } => {
                            (KAdminException::new_err(error.to_string()), Some((*code, message)))
                        }
                        Error::NullPointerDereference => (NullPointerDereference::new_err(error.to_string()), None),
                        Error::CStringConversion(_) => (CStringConversion::new_err(error.to_string()), None),
                        Error::CStringImportFromVec(_) => (CStringImportFromVec::new_err(error.to_string()), None),
                        Error::StringConversion(_) => (StringConversion::new_err(error.to_string()), None),
                        Error::ThreadSendError => (ThreadSendError::new_err(error.to_string()), None),
                        Error::ThreadRecvError(_) => (ThreadRecvError::new_err(error.to_string()), None),
                        Error::TimestampConversion => (TimestampConversion::new_err(error.to_string()), None),
                        _ => (PyKAdminException::new_err("Unknown error: {}"), None),
                    };

                    if let Some((code, message)) = extras {
                        let bound_exc = exc.value_bound(py);
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
}

//! Python bindings to libkadm5

use pyo3::prelude::*;

/// Python bindings to libkadm5
///
/// This is a Python interface to libkadm5. It provides two Python modules: `kadmin` for remote
/// operations, and `kadmin_local` for local operations.
///
/// With `kadmin`:
///
/// ```python
/// import kadmin
///
/// princ = "user/admin@EXAMPLE.ORG"
/// password = "vErYsEcUrE"
/// kadm = kadmin.KAdmin.with_password(princ, password)
/// print(kadm.list_principals())
/// ```
///
/// With `kadmin_local`:
///
/// ```python
/// import kadmin
///
/// kadm = kadmin.KAdmin.with_local()
/// print(kadm.list_principals())
/// ```
#[pymodule(name = "_lib")]
pub mod pykadmin {
    use std::{ops::Deref, sync::Arc};

    use kadmin::{
        db_args::DbArgsBuilder,
        kadmin::KAdminImpl,
        params::ParamsBuilder,
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

    /// kadm5 config options
    ///
    /// :param realm: Default realm database
    /// :type realm: str, optional
    /// :param kadmind_port: kadmind port to connect to
    /// :type kadmind_port: int, optional
    /// :param kpasswd_port: kpasswd port to connect to
    /// :type kpasswd_port: int, optional
    /// :param admin_server: Admin server which kadmin should contact
    /// :type admin_server: str, optional
    /// :param dbname: Name of the KDC database
    /// :type dbname: str, optional
    /// :param acl_file: Location of the access control list file
    /// :type acl_file: str, optional
    /// :param dict_file: Location of the dictionary file containing strings that are not allowed as
    ///     passwords
    /// :type dict_file: str, optional
    /// :param stash_file: Location where the master key has been stored
    /// :type stash_file: str, optional
    ///
    /// .. code-block:: python
    ///
    ///    params = Params(realm="EXAMPLE.ORG")
    #[pyclass]
    #[derive(Clone)]
    pub struct Params(ParamsBuilder);

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
            let mut builder = ParamsBuilder::default();
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

    /// Database specific arguments
    ///
    /// See `man kadmin(1)` for a list of supported arguments
    ///
    /// :param \**kwargs: Database arguments
    /// :type \**kwargs: dict[str, str | None]
    ///
    /// .. code-block:: python
    ///
    ///    db_args = DbArgs(host="ldap.example.org")
    #[pyclass]
    #[derive(Clone)]
    pub struct DbArgs(DbArgsBuilder);

    #[pymethods]
    impl DbArgs {
        #[new]
        #[pyo3(signature = (**kwargs))]
        fn new(kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
            let mut builder = DbArgsBuilder::default();
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

    /// Interface to kadm5
    ///
    /// This class has no constructor. Instead, use the `with_` methods
    #[pyclass]
    pub struct KAdmin(Arc<KKAdmin>);

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
        /// Not implemented
        fn add_principal(&self) {
            unimplemented!();
        }

        /// Not implemented
        fn delete_principal(&self) {
            unimplemented!();
        }

        /// Not implemented
        fn modify_principal(&self) {
            unimplemented!();
        }

        /// Not implemented
        fn rename_principal(&self) {
            unimplemented!();
        }

        /// Retrieve a principal
        ///
        /// :param name: principal name to retrieve
        /// :type name: str
        /// :return: Principal if found, None otherwise
        /// :rtype: Principal, optional
        pub fn get_principal(&self, name: &str) -> Result<Option<Principal>> {
            Ok(self.0.get_principal(name)?.map(|p| Principal {
                inner: p,
                kadmin: Arc::clone(&self.0),
            }))
        }

        /// Check if a principal exists
        ///
        /// :param name: principal name to check for
        /// :type name: str
        /// :return: `True` if the principal exists, `False` otherwise
        /// :rtype: bool
        fn principal_exists(&self, name: &str) -> Result<bool> {
            Ok(self.0.principal_exists(name)?)
        }

        /// List principals
        ///
        /// :param query: a shell-style glob expression that can contain the wild-card characters
        ///     `?`, `*`, and `[]`. All principal names matching the expression are retuned. If
        ///     the expression does not contain an `@` character, an `@` character followed by
        ///     the local realm is appended to the expression. If no query is provided, all
        ///     principals are returned.
        /// :type query: str, optional
        /// :return: the list of principal names matching the query
        /// :rtype: list[str]
        #[pyo3(signature = (query=None))]
        pub fn list_principals(&self, query: Option<&str>) -> Result<Vec<String>> {
            Ok(self.0.list_principals(query)?)
        }

        /// Not implemented
        fn add_policy(&self) {
            unimplemented!();
        }

        /// Not implemented
        fn modify_policy(&self) {
            unimplemented!();
        }

        /// Not implemented
        fn delete_policy(&self) {
            unimplemented!();
        }

        /// Not implemented
        fn get_policy(&self) {
            unimplemented!();
        }

        /// List policies
        ///
        /// :param query: a shell-style glob expression that can contain the wild-card characters
        ///     `?`, `*`, and `[]`. All policy names matching the expression are returned.
        ///     If no query is provided, all existing policy names are returned.
        /// :type query: str, optional
        /// :return: the list of policy names matching the query
        /// :rtype: list[str]
        #[pyo3(signature = (query=None))]
        pub fn list_policies(&self, query: Option<&str>) -> Result<Vec<String>> {
            Ok(self.0.list_policies(query)?)
        }

        /// Construct a KAdmin object using a password
        ///
        /// :param client_name: client name, usually a principal name
        /// :type client_name: str
        /// :param password: password to authenticate with
        /// :type password: str
        /// :param params: additional kadm5 config options
        /// :type params: Params, optional
        /// :param db_args: additional database specific arguments
        /// :type db_args: DbArgs, optional
        /// :return: an initialized KAdmin object
        /// :rtype: KAdmin
        ///
        /// .. code-block:: python
        ///
        ///    kadm = KAdmin.with_password("user@EXAMPLE.ORG", "vErYsEcUrE")
        #[cfg(feature = "client")]
        #[staticmethod]
        #[pyo3(signature = (client_name, password, params=None, db_args=None))]
        pub fn with_password(
            client_name: &str,
            password: &str,
            params: Option<Params>,
            db_args: Option<DbArgs>,
        ) -> Result<Self> {
            Ok(Self(Arc::new(
                Self::get_builder(params, db_args).with_password(client_name, password)?,
            )))
        }

        /// Construct a KAdmin object using a keytab
        ///
        /// :param client_name: client name, usually a principal name. If not provided,
        ///     `host/hostname` will be used
        /// :type client_name: str, optional
        /// :param keytab: path to the keytab to use. If not provided, the default keytab will be
        ///     used
        /// :type keytab: str, optional
        /// :param params: additional kadm5 config options
        /// :type params: Params, optional
        /// :param db_args: additional database specific arguments
        /// :type db_args: DbArgs, optional
        /// :return: an initialized KAdmin object
        /// :rtype: KAdmin
        #[cfg(feature = "client")]
        #[staticmethod]
        #[pyo3(signature = (client_name=None, keytab=None, params=None, db_args=None))]
        pub fn with_keytab(
            client_name: Option<&str>,
            keytab: Option<&str>,
            params: Option<Params>,
            db_args: Option<DbArgs>,
        ) -> Result<Self> {
            Ok(Self(Arc::new(
                Self::get_builder(params, db_args).with_keytab(client_name, keytab)?,
            )))
        }

        /// Construct a KAdmin object using a credentials cache
        ///
        /// :param client_name: client name, usually a principal name. If not provided, the default
        ///     principal from the credentials cache will be used
        /// :type client_name: str, optional
        /// :param ccache_name: credentials cache name. If not provided, the default credentials
        ///     cache will be used
        /// :type ccache_name: str, optional
        /// :param params: additional kadm5 config options
        /// :type params: Params, optional
        /// :param db_args: additional database specific arguments
        /// :type db_args: DbArgs, optional
        /// :return: an initialized KAdmin object
        /// :rtype: KAdmin
        #[cfg(feature = "client")]
        #[staticmethod]
        #[pyo3(signature = (client_name=None, ccache_name=None, params=None, db_args=None))]
        pub fn with_ccache(
            client_name: Option<&str>,
            ccache_name: Option<&str>,
            params: Option<Params>,
            db_args: Option<DbArgs>,
        ) -> Result<Self> {
            Ok(Self(Arc::new(
                Self::get_builder(params, db_args).with_ccache(client_name, ccache_name)?,
            )))
        }

        /// Not implemented
        #[cfg(feature = "client")]
        #[staticmethod]
        #[pyo3(signature = (client_name, params=None, db_args=None))]
        pub fn with_anonymous(
            client_name: &str,
            params: Option<Params>,
            db_args: Option<DbArgs>,
        ) -> Result<Self> {
            Ok(Self(Arc::new(
                Self::get_builder(params, db_args).with_anonymous(client_name)?,
            )))
        }

        /// Construct a KAdmin object for local database manipulation.
        ///
        /// :param params: additional kadm5 config options
        /// :type params: Params, optional
        /// :param db_args: additional database specific arguments
        /// :type db_args: DbArgs, optional
        /// :return: an initialized KAdmin object
        /// :rtype: KAdmin
        #[cfg(feature = "local")]
        #[staticmethod]
        #[pyo3(signature = (params=None, db_args=None))]
        pub fn with_local(params: Option<Params>, db_args: Option<DbArgs>) -> Result<Self> {
            Ok(Self(Arc::new(
                Self::get_builder(params, db_args).with_local()?,
            )))
        }
    }

    /// A kadm5 principal
    #[pyclass]
    pub struct Principal {
        inner: KPrincipal,
        kadmin: Arc<KKAdmin>,
    }

    #[pymethods]
    impl Principal {
        /// Change the password of the principal
        ///
        /// :param password: the new password
        /// :type password: str
        pub fn change_password(&self, password: &str) -> Result<()> {
            Ok(self.inner.change_password(self.kadmin.deref(), password)?)
        }
    }

    /// python-kadmin-rs exceptions
    #[pymodule]
    pub mod exceptions {
        use indoc::indoc;
        use kadmin::Error;
        use pyo3::{create_exception, exceptions::PyException, intern, prelude::*};

        #[pymodule_init]
        fn init(m: &Bound<'_, PyModule>) -> PyResult<()> {
            m.add(
                "PyKAdminException",
                m.py().get_type_bound::<PyKAdminException>(),
            )?;
            m.add(
                "KAdminException",
                m.py().get_type_bound::<KAdminException>(),
            )?;
            m.add(
                "KerberosException",
                m.py().get_type_bound::<KerberosException>(),
            )?;
            m.add(
                "NullPointerDereference",
                m.py().get_type_bound::<NullPointerDereference>(),
            )?;
            m.add(
                "CStringConversion",
                m.py().get_type_bound::<CStringConversion>(),
            )?;
            m.add(
                "CStringImportFromVec",
                m.py().get_type_bound::<CStringImportFromVec>(),
            )?;
            m.add(
                "StringConversion",
                m.py().get_type_bound::<StringConversion>(),
            )?;
            m.add(
                "ThreadSendError",
                m.py().get_type_bound::<ThreadSendError>(),
            )?;
            m.add(
                "ThreadRecvError",
                m.py().get_type_bound::<ThreadRecvError>(),
            )?;
            m.add(
                "TimestampConversion",
                m.py().get_type_bound::<TimestampConversion>(),
            )?;
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

        /// Wrapper around [`kadmin::Error`] for type conversion to [`PyErr`]
        pub struct PyKAdminError(Error);

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
                        Error::KAdmin { code, message } => (
                            KAdminException::new_err(error.to_string()),
                            Some((*code, message)),
                        ),
                        Error::NullPointerDereference => {
                            (NullPointerDereference::new_err(error.to_string()), None)
                        }
                        Error::CStringConversion(_) => {
                            (CStringConversion::new_err(error.to_string()), None)
                        }
                        Error::CStringImportFromVec(_) => {
                            (CStringImportFromVec::new_err(error.to_string()), None)
                        }
                        Error::StringConversion(_) => {
                            (StringConversion::new_err(error.to_string()), None)
                        }
                        Error::ThreadSendError => {
                            (ThreadSendError::new_err(error.to_string()), None)
                        }
                        Error::ThreadRecvError(_) => {
                            (ThreadRecvError::new_err(error.to_string()), None)
                        }
                        Error::TimestampConversion => {
                            (TimestampConversion::new_err(error.to_string()), None)
                        }
                        _ => (PyKAdminException::new_err("Unknown error: {}"), None),
                    };

                    if let Some((code, message)) = extras {
                        let bound_exc = exc.value_bound(py);
                        if let Err(err) = bound_exc.setattr(intern!(py, "code"), code) {
                            return err;
                        }
                        if let Err(err) = bound_exc.setattr(intern!(py, "origin_message"), message)
                        {
                            return err;
                        }
                    }

                    exc
                })
            }
        }
    }
}

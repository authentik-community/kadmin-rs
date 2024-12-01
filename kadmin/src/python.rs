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
    use std::time::Duration;

    use pyo3::{
        prelude::*,
        types::{PyDict, PyString},
    };

    use crate::{
        db_args::DbArgsBuilder,
        kadmin::KAdminImpl,
        params::ParamsBuilder,
        policy::Policy as KPolicy,
        principal::Principal as KPrincipal,
        sync::{KAdmin as KKAdmin, KAdminBuilder},
        tl_data::{TlData, TlDataEntry},
    };

    type Result<T> = std::result::Result<T, exceptions::PyKAdminError>;

    #[pymodule_init]
    fn init(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add("__version__", env!("CARGO_PKG_VERSION"))?;
        m.add_class::<TlDataEntry>()?;
        m.add_class::<TlData>()?;
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
    #[derive(Clone, Debug)]
    pub struct KAdmin(KKAdmin);

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
                kadmin: self.clone(),
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

        /// Create a policy
        ///
        /// :param name: the name of the policy to create
        /// :type name: str
        /// :param kwargs: Extra args for the creation. The name of those arguments must match the
        ///     attributes name of the `Policy` class that have a setter. Same goes for their
        ///     types.
        /// :return: the newly created Policy
        /// :rtype: Policy
        #[pyo3(signature = (name, **kwargs))]
        pub fn add_policy(
            &self,
            name: &str,
            kwargs: Option<&Bound<'_, PyDict>>,
        ) -> PyResult<Policy> {
            let mut builder = KPolicy::builder(name);
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
                if let Some(password_max_fail) = kwargs.get_item("password_max_fail")? {
                    builder = builder.password_max_fail(password_max_fail.extract()?);
                }
                if let Some(password_failcount_interval) =
                    kwargs.get_item("password_failcount_interval")?
                {
                    builder =
                        builder.password_failcount_interval(password_failcount_interval.extract()?);
                }
                if let Some(password_lockout_duration) =
                    kwargs.get_item("password_lockout_duration")?
                {
                    builder =
                        builder.password_lockout_duration(password_lockout_duration.extract()?);
                }
                if let Some(attributes) = kwargs.get_item("attributes")? {
                    builder = builder.attributes(attributes.extract()?);
                }
                if let Some(max_life) = kwargs.get_item("max_life")? {
                    builder = builder.max_life(max_life.extract()?);
                }
                if let Some(max_renewable_life) = kwargs.get_item("max_renewable_life")? {
                    builder = builder.max_renewable_life(max_renewable_life.extract()?);
                }
                if let Some(tl_data) = kwargs.get_item("tl_data")? {
                    builder = builder.tl_data(tl_data.extract::<TlData>()?.into());
                }
            }
            Ok(Policy {
                inner: builder
                    .create(&self.0)
                    .map_err(|e| PyErr::from(exceptions::PyKAdminError(e)))?,
                kadmin: self.clone(),
            })
        }

        /// Delete a policy
        ///
        /// `Policy.delete` is also available
        ///
        /// :param name: name of the policy to delete
        /// :type name: str
        fn delete_policy(&self, name: &str) -> Result<()> {
            Ok(self.0.delete_policy(name)?)
        }

        /// Retrieve a policy
        ///
        /// :param name: policy name to retrieve
        /// :type name: str
        /// :return: Policy if found, None otherwise
        /// :rtype: Policy, optional
        fn get_policy(&self, name: &str) -> Result<Option<Policy>> {
            Ok(self.0.get_policy(name)?.map(|p| Policy {
                inner: p,
                kadmin: self.clone(),
            }))
        }

        /// Check if a policy exists
        ///
        /// :param name: policy name to check for
        /// :type name: str
        /// :return: `True` if the policy exists, `False` otherwise
        /// :rtype: bool
        fn policy_exists(&self, name: &str) -> Result<bool> {
            Ok(self.0.policy_exists(name)?)
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
            Ok(Self(
                Self::get_builder(params, db_args).with_password(client_name, password)?,
            ))
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
            Ok(Self(
                Self::get_builder(params, db_args).with_keytab(client_name, keytab)?,
            ))
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
            Ok(Self(
                Self::get_builder(params, db_args).with_ccache(client_name, ccache_name)?,
            ))
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
            Ok(Self(
                Self::get_builder(params, db_args).with_anonymous(client_name)?,
            ))
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
            Ok(Self(Self::get_builder(params, db_args).with_local()?))
        }
    }

    /// A kadm5 principal
    #[pyclass]
    pub struct Principal {
        inner: KPrincipal,
        kadmin: KAdmin,
    }

    #[pymethods]
    impl Principal {
        /// Change the password of the principal
        ///
        /// :param password: the new password
        /// :type password: str
        pub fn change_password(&self, password: &str) -> Result<()> {
            Ok(self.inner.change_password(&self.kadmin.0, password)?)
        }
    }

    /// A kadm5 policy
    ///
    /// This class has no constructor. Instead, use `KAdmin.add_policy`
    ///
    /// Setters in this class use the `Policy.modify` method, which makes a call to the kadmin
    /// server. If you need to make changes to multiple attributes, it is recommended to use the
    /// modify method directly to avoid unnecessary operations
    #[pyclass]
    #[derive(Clone)]
    pub struct Policy {
        inner: KPolicy,
        kadmin: KAdmin,
    }

    #[pymethods]
    impl Policy {
        /// Change this policy
        ///
        /// Check each property documentation for accepted types and documentation. Each parameter
        /// has the same name and type as specified in the properties.
        ///
        /// :return: a new Policy object with the modifications made to it. The old object is still
        ///     available, but will not be up-to-date
        /// :rtype: Policy
        #[pyo3(signature = (**kwargs))]
        pub fn modify(&self, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
            if let Some(kwargs) = kwargs {
                let mut modifier = self.inner.modifier();
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
                if let Some(password_max_fail) = kwargs.get_item("password_max_fail")? {
                    modifier = modifier.password_max_fail(password_max_fail.extract()?);
                }
                if let Some(password_failcount_interval) =
                    kwargs.get_item("password_failcount_interval")?
                {
                    modifier = modifier
                        .password_failcount_interval(password_failcount_interval.extract()?);
                }
                if let Some(password_lockout_duration) =
                    kwargs.get_item("password_lockout_duration")?
                {
                    modifier =
                        modifier.password_lockout_duration(password_lockout_duration.extract()?);
                }
                if let Some(attributes) = kwargs.get_item("attributes")? {
                    modifier = modifier.attributes(attributes.extract()?);
                }
                if let Some(max_life) = kwargs.get_item("max_life")? {
                    modifier = modifier.max_life(max_life.extract()?);
                }
                if let Some(max_renewable_life) = kwargs.get_item("max_renewable_life")? {
                    modifier = modifier.max_renewable_life(max_renewable_life.extract()?);
                }
                if let Some(tl_data) = kwargs.get_item("tl_data")? {
                    modifier = modifier.tl_data(tl_data.extract::<TlData>()?.into());
                }
                Ok(Self {
                    inner: modifier
                        .modify(&self.kadmin.0)
                        .map_err(|e| PyErr::from(exceptions::PyKAdminError(e)))?,
                    kadmin: self.kadmin.clone(),
                })
            } else {
                Ok(self.clone())
            }
        }

        /// Delete this policy
        ///
        /// The object will still be available, but shouldn’t be used for modifying, as the policy
        /// may not exist anymore
        pub fn delete(&self) -> Result<()> {
            Ok(self.inner.delete(&self.kadmin.0)?)
        }

        /// The policy name
        ///
        /// :getter: Get the policy name
        /// :type: str
        #[getter]
        pub fn name(&self) -> &str {
            self.inner.name()
        }

        /// Minimum lifetime of a password
        ///
        /// :getter: Get the minimum lifetime of a password
        /// :setter: Set the minimum lifetime of a password. Pass `None` to clear it
        /// :type: datetime.timedelta, optional
        #[getter]
        pub fn get_password_min_life(&self) -> Option<Duration> {
            self.inner.password_min_life()
        }

        /// Ignored
        #[setter]
        pub fn set_password_min_life(&mut self, password_min_life: Option<Duration>) -> Result<()> {
            let policy = self
                .inner
                .modifier()
                .password_min_life(password_min_life)
                .modify(&self.kadmin.0)?;
            let _ = std::mem::replace(&mut self.inner, policy);
            Ok(())
        }

        /// Maximum lifetime of a password
        ///
        /// :getter: Get the maximum lifetime of a password
        /// :setter: Set the maximum lifetime of a password. Pass `None` to clear it
        /// :type: datetime.timedelta, optional
        #[getter]
        pub fn get_password_max_life(&self) -> Option<Duration> {
            self.inner.password_max_life()
        }

        /// Ignored
        #[setter]
        pub fn set_password_max_life(&mut self, password_max_life: Option<Duration>) -> Result<()> {
            let policy = self
                .inner
                .modifier()
                .password_max_life(password_max_life)
                .modify(&self.kadmin.0)?;
            let _ = std::mem::replace(&mut self.inner, policy);
            Ok(())
        }

        /// Minimum length of a password
        ///
        /// :getter: Get the minimum length of a password
        /// :setter: Set the minimum length of a password
        /// :type: int
        #[getter]
        pub fn get_password_min_length(&self) -> i64 {
            self.inner.password_min_length()
        }

        /// Ignored
        #[setter]
        pub fn set_password_min_length(&mut self, password_min_length: i64) -> Result<()> {
            let policy = self
                .inner
                .modifier()
                .password_min_length(password_min_length)
                .modify(&self.kadmin.0)?;
            let _ = std::mem::replace(&mut self.inner, policy);
            Ok(())
        }

        /// Minimum number of character classes required in a password
        ///
        /// The five character classes are lower case, upper case, numbers, punctuation, and
        /// whitespace/unprintable characters
        ///
        /// :getter: Get the minimum number of character classes required in a password
        /// :setter: Set the minimum number of character classes required in a password
        /// :type: int
        #[getter]
        pub fn get_password_min_classes(&self) -> i64 {
            self.inner.password_min_classes()
        }

        /// Ignored
        #[setter]
        pub fn set_password_min_classes(&mut self, password_min_classes: i64) -> Result<()> {
            let policy = self
                .inner
                .modifier()
                .password_min_classes(password_min_classes)
                .modify(&self.kadmin.0)?;
            let _ = std::mem::replace(&mut self.inner, policy);
            Ok(())
        }

        /// Number of past keys kept for a principal
        ///
        /// May be ignored if used with other database modules such as the MIT krb5 LDAP KDC
        /// database module
        ///
        /// :getter: Get the number of past keys kept for a principal
        /// :setter: Set the number of past keys kept for a principal
        /// :type: int
        #[getter]
        pub fn get_password_history_num(&self) -> i64 {
            self.inner.password_history_num()
        }

        /// Ignored
        #[setter]
        pub fn set_password_history_num(&mut self, password_history_num: i64) -> Result<()> {
            let policy = self
                .inner
                .modifier()
                .password_history_num(password_history_num)
                .modify(&self.kadmin.0)?;
            let _ = std::mem::replace(&mut self.inner, policy);
            Ok(())
        }

        /// How many principals use this policy
        ///
        /// Not filled for at least MIT krb5
        ///
        /// :getter: Get how many principals use this policy
        /// :type: int
        #[getter]
        pub fn get_policy_refcnt(&self) -> i64 {
            self.inner.policy_refcnt()
        }

        /// Number of authentication failures before the principal is locked
        ///
        /// Authentication failures are only tracked for principals which require preauthentication.
        /// The counter of failed attempts resets to 0 after a successful attempt to authenticate
        ///
        /// :getter: Get the number of authentication failures before the principal is locked
        /// :setter: Set the number of authentication failures before the principal is locked. A
        ///     value of 0 disables lock-out
        /// :type: int
        #[getter]
        pub fn get_password_max_fail(&self) -> u32 {
            self.inner.password_max_fail()
        }

        /// Ignored
        #[setter]
        pub fn set_password_max_fail(&mut self, password_max_fail: u32) -> Result<()> {
            let policy = self
                .inner
                .modifier()
                .password_max_fail(password_max_fail)
                .modify(&self.kadmin.0)?;
            let _ = std::mem::replace(&mut self.inner, policy);
            Ok(())
        }

        /// Allowable time between authentication failures
        ///
        /// If an authentication failure happens after this duration has elapsed since the previous
        /// failure, the number of authentication failures is reset to 1
        ///
        /// :getter: Get the allowable time between authentication failures
        /// :setter: Set the allowable time between authentication failures. Pass `None` to clear
        ///     it, which means forever
        /// :type: datetime.timedelta, optional
        #[getter]
        pub fn get_password_failcount_interval(&self) -> Option<Duration> {
            self.inner.password_failcount_interval()
        }

        /// Ignored
        #[setter]
        pub fn set_password_failcount_interval(
            &mut self,
            password_failcount_interval: Option<Duration>,
        ) -> Result<()> {
            let policy = self
                .inner
                .modifier()
                .password_failcount_interval(password_failcount_interval)
                .modify(&self.kadmin.0)?;
            let _ = std::mem::replace(&mut self.inner, policy);
            Ok(())
        }

        /// Duration for which the principal is locked from authenticating if too many
        /// authentication failures occur without the specified failure count interval elapsing
        ///
        /// :getter: Get the lockout duration
        /// :setter: Set the lockout duration. Pass `None` to clear it, which means the principal
        ///    remains locked out until it is administratively unlocked
        /// :type: datetime.timedelta, optional
        #[getter]
        pub fn get_password_lockout_duration(&self) -> Option<Duration> {
            self.inner.password_lockout_duration()
        }

        /// Ignored
        #[setter]
        pub fn set_password_lockout_duration(
            &mut self,
            password_lockout_duration: Option<Duration>,
        ) -> Result<()> {
            let policy = self
                .inner
                .modifier()
                .password_lockout_duration(password_lockout_duration)
                .modify(&self.kadmin.0)?;
            let _ = std::mem::replace(&mut self.inner, policy);
            Ok(())
        }

        /// Policy attributes
        ///
        /// :getter: Get the policy attributes
        /// :setter: Set the policy attributes
        /// :type: int
        #[getter]
        pub fn get_attributes(&self) -> i32 {
            self.inner.attributes()
        }

        /// Ignored
        #[setter]
        pub fn set_attributes(&mut self, attributes: i32) -> Result<()> {
            let policy = self
                .inner
                .modifier()
                .attributes(attributes)
                .modify(&self.kadmin.0)?;
            let _ = std::mem::replace(&mut self.inner, policy);
            Ok(())
        }

        /// Maximum ticket life
        ///
        /// :getter: Get the maximum ticket life
        /// :setter: Set the maximum ticket life. Pass `None` to clear it
        /// :type: datetime.timedelta, optional
        #[getter]
        pub fn get_max_life(&self) -> Option<Duration> {
            self.inner.max_life()
        }

        /// Ignored
        #[setter]
        pub fn set_max_life(&mut self, max_life: Option<Duration>) -> Result<()> {
            let policy = self
                .inner
                .modifier()
                .max_life(max_life)
                .modify(&self.kadmin.0)?;
            let _ = std::mem::replace(&mut self.inner, policy);
            Ok(())
        }

        /// Maximum renewable ticket life
        ///
        /// :getter: Get the maximum renewable ticket life
        /// :setter: Set the maximum renewable ticket life. Pass `None` to clear it
        /// :type: datetime.timedelta, optional
        #[getter]
        pub fn get_max_renewable_life(&self) -> Option<Duration> {
            self.inner.max_renewable_life()
        }

        /// Ignored
        #[setter]
        pub fn set_max_renewable_life(
            &mut self,
            max_renewable_life: Option<Duration>,
        ) -> Result<()> {
            let policy = self
                .inner
                .modifier()
                .max_renewable_life(max_renewable_life)
                .modify(&self.kadmin.0)?;
            let _ = std::mem::replace(&mut self.inner, policy);
            Ok(())
        }

        /// Policy TL-data
        ///
        /// :getter: Get the TL-data
        /// :setter: Set the TL-data. Completely overrides existing TL-data, make sure to re-use
        ///     the old ones
        /// :type: TlData
        #[getter]
        pub fn get_tl_data(&self) -> TlData {
            (*self.inner.tl_data()).clone().into()
        }

        /// Ignored
        #[setter]
        pub fn set_tl_data(&mut self, tl_data: TlData) -> Result<()> {
            let policy = self
                .inner
                .modifier()
                .tl_data(tl_data.into())
                .modify(&self.kadmin.0)?;
            let _ = std::mem::replace(&mut self.inner, policy);
            Ok(())
        }
    }

    /// python-kadmin-rs exceptions
    #[pymodule]
    pub mod exceptions {
        use indoc::indoc;
        use pyo3::{create_exception, exceptions::PyException, intern, prelude::*};

        use crate::error::Error;

        #[pymodule_init]
        fn init(m: &Bound<'_, PyModule>) -> PyResult<()> {
            m.add("PyKAdminException", m.py().get_type::<PyKAdminException>())?;
            m.add("KAdminException", m.py().get_type::<KAdminException>())?;
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
            Ok(())
        }

        create_exception!(
            exceptions,
            PyKAdminException,
            PyException,
            "Top-level exception"
        );
        create_exception!(exceptions, KAdminException, PyKAdminException, indoc! {"
            kadm5 error

            :ivar code: kadm5 error code
            :ivar origin_message: kadm5 error message
            "});
        create_exception!(exceptions, KerberosException, PyKAdminException, indoc! {"
            Kerberos error

            :ivar code: Kerberos error code
            :ivar origin_message: Kerberos error message
            "});
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

        /// Wrapper around [`kadmin::Error`] for type conversion to [`PyErr`]
        #[allow(clippy::exhaustive_structs)]
        pub struct PyKAdminError(pub Error);

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
                        Error::DateTimeConversion(_) => {
                            (DateTimeConversion::new_err(error.to_string()), None)
                        }
                        Error::DurationConversion(_) => {
                            (DurationConversion::new_err(error.to_string()), None)
                        }
                    };

                    if let Some((code, message)) = extras {
                        let bound_exc = exc.value(py);
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

//! Thread-safe [`KAdmin`] interface to kadm5
//!
//! This is a thread-safe wrapper over [`crate::kadmin::KAdmin`]. It accomplishes this by spawning
//! a separate thread with a non-sync [`crate::kadmin::KAdmin`] instance, and sending operations
//! and results over a [`channel`].
//!
//! The APIs between this wrapper and the underlying [`crate::kadmin::KAdmin`] are the same, and
//! wrapped and the [`KAdminImpl`] trait.
use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    panic::resume_unwind,
    sync::{
        Arc,
        mpsc::{Sender, channel},
    },
    thread::{JoinHandle, spawn},
};

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(mit)]
use crate::policy::{Policy, PolicyBuilder, PolicyModifier};
use crate::{
    db_args::DbArgs,
    error::Result,
    kadmin::{KAdminApiVersion, KAdminImpl, KAdminPrivileges},
    keysalt::KeySalts,
    params::Params,
    principal::{Principal, PrincipalBuilder, PrincipalModifier},
    sys::{KAdm5Variant, Library},
};

/// Operations from [`KAdminImpl`]
enum KAdminOperation {
    /// See [`KAdminImpl::add_principal`]
    AddPrincipal(PrincipalBuilder, Sender<Result<()>>),
    /// See [`KAdminImpl::modify_principal`]
    ModifyPrincipal(PrincipalModifier, Sender<Result<()>>),
    /// See [`KAdminImpl::rename_principal`]
    RenamePrincipal(String, String, Sender<Result<()>>),
    /// See [`KAdminImpl::delete_principal`]
    DeletePrincipal(String, Sender<Result<()>>),
    /// See [`KAdminImpl::get_principal`]
    GetPrincipal(String, Sender<Result<Option<Principal>>>),
    /// See [`KAdminImpl::principal_change_password`]
    PrincipalChangePassword(
        String,
        String,
        Option<bool>,
        Option<KeySalts>,
        Sender<Result<()>>,
    ),
    /// See [`KAdminImpl::principal_randkey`]
    PrincipalRandkey(String, Option<bool>, Option<KeySalts>, Sender<Result<()>>),
    #[cfg(mit)]
    /// See [`KAdminImpl::principal_get_strings`]
    PrincipalGetStrings(String, Sender<Result<HashMap<String, String>>>),
    #[cfg(mit)]
    /// See [`KAdminImpl::principal_set_string`]
    PrincipalSetString(String, String, Option<String>, Sender<Result<()>>),
    /// See [`KAdminImpl::list_principals`]
    ListPrincipals(Option<String>, Sender<Result<Vec<String>>>),
    #[cfg(mit)]
    /// See [`KAdminImpl::add_policy`]
    AddPolicy(PolicyBuilder, Sender<Result<()>>),
    #[cfg(mit)]
    /// See [`KAdminImpl::modify_policy`]
    ModifyPolicy(PolicyModifier, Sender<Result<()>>),
    #[cfg(mit)]
    /// See [`KAdminImpl::delete_policy`]
    DeletePolicy(String, Sender<Result<()>>),
    #[cfg(mit)]
    /// See [`KAdminImpl::get_policy`]
    GetPolicy(String, Sender<Result<Option<Policy>>>),
    #[cfg(mit)]
    /// See [`KAdminImpl::list_policies`]
    ListPolicies(Option<String>, Sender<Result<Vec<String>>>),
    /// See [`KAdminImpl::get_privileges`]
    GetPrivileges(Sender<Result<KAdminPrivileges>>),
    /// Stop the kadmin thread
    Exit,
}

impl KAdminOperation {
    fn handle(&self, kadmin: &crate::kadmin::KAdmin) {
        match self {
            Self::Exit => (),
            Self::AddPrincipal(builder, sender) => {
                let _ = sender.send(kadmin.add_principal(builder));
            }
            Self::ModifyPrincipal(modifier, sender) => {
                let _ = sender.send(kadmin.modify_principal(modifier));
            }
            Self::RenamePrincipal(old_name, new_name, sender) => {
                let _ = sender.send(kadmin.rename_principal(old_name, new_name));
            }
            Self::DeletePrincipal(name, sender) => {
                let _ = sender.send(kadmin.delete_principal(name));
            }
            Self::GetPrincipal(name, sender) => {
                let _ = sender.send(kadmin.get_principal(name));
            }
            Self::PrincipalChangePassword(name, password, keepold, keysalts, sender) => {
                let _ = sender.send(kadmin.principal_change_password(
                    name,
                    password,
                    *keepold,
                    keysalts.as_ref(),
                ));
            }
            Self::PrincipalRandkey(name, keepold, keysalts, sender) => {
                let _ = sender.send(kadmin.principal_randkey(name, *keepold, keysalts.as_ref()));
            }
            #[cfg(mit)]
            Self::PrincipalGetStrings(name, sender) => {
                let _ = sender.send(kadmin.principal_get_strings(name));
            }
            #[cfg(mit)]
            Self::PrincipalSetString(name, key, value, sender) => {
                let _ = sender.send(kadmin.principal_set_string(name, key, value.as_deref()));
            }
            Self::ListPrincipals(query, sender) => {
                let _ = sender.send(kadmin.list_principals(query.as_deref()));
            }
            #[cfg(mit)]
            Self::AddPolicy(builder, sender) => {
                let _ = sender.send(kadmin.add_policy(builder));
            }
            #[cfg(mit)]
            Self::ModifyPolicy(modifier, sender) => {
                let _ = sender.send(kadmin.modify_policy(modifier));
            }
            #[cfg(mit)]
            Self::DeletePolicy(name, sender) => {
                let _ = sender.send(kadmin.delete_policy(name));
            }
            #[cfg(mit)]
            Self::GetPolicy(name, sender) => {
                let _ = sender.send(kadmin.get_policy(name));
            }
            #[cfg(mit)]
            Self::ListPolicies(query, sender) => {
                let _ = sender.send(kadmin.list_policies(query.as_deref()));
            }
            Self::GetPrivileges(sender) => {
                let _ = sender.send(kadmin.get_privileges());
            }
        }
    }
}

/// Inner attributes to be wrapped in an [`Arc`]
#[derive(Debug)]
struct InnerKAdmin {
    op_sender: Sender<KAdminOperation>,
    join_handle: Option<JoinHandle<()>>,
}

impl Drop for InnerKAdmin {
    fn drop(&mut self) {
        // Thread might have already exited, so we don't care about the result of this
        let _ = self.op_sender.send(KAdminOperation::Exit);
        if let Some(join_handle) = self.join_handle.take() {
            if let Err(e) = join_handle.join() {
                resume_unwind(e);
            }
        }
    }
}

/// Thread-safe interface to kadm5
///
/// This is a thread-safe wrapper over [`crate::kadmin::KAdmin`].
#[derive(Clone, Debug)]
#[cfg_attr(feature = "python", pyclass)]
pub struct KAdmin {
    variant: KAdm5Variant,
    inner: Arc<InnerKAdmin>,
}

impl KAdmin {
    /// Construct a new [`KAdminBuilder`]
    pub fn builder(variant: KAdm5Variant) -> KAdminBuilder {
        KAdminBuilder::new(variant)
    }
}

impl KAdminImpl for KAdmin {
    fn variant(&self) -> KAdm5Variant {
        self.variant
    }

    fn add_principal(&self, builder: &PrincipalBuilder) -> Result<()> {
        let (sender, receiver) = channel();
        self.inner
            .op_sender
            .send(KAdminOperation::AddPrincipal(builder.clone(), sender))?;
        receiver.recv()?
    }

    fn modify_principal(&self, modifier: &PrincipalModifier) -> Result<()> {
        let (sender, receiver) = channel();
        self.inner
            .op_sender
            .send(KAdminOperation::ModifyPrincipal(modifier.clone(), sender))?;
        receiver.recv()?
    }

    fn rename_principal(&self, old_name: &str, new_name: &str) -> Result<()> {
        let (sender, receiver) = channel();
        self.inner.op_sender.send(KAdminOperation::RenamePrincipal(
            old_name.to_owned(),
            new_name.to_owned(),
            sender,
        ))?;
        receiver.recv()?
    }

    fn delete_principal(&self, name: &str) -> Result<()> {
        let (sender, receiver) = channel();
        self.inner
            .op_sender
            .send(KAdminOperation::DeletePrincipal(name.to_owned(), sender))?;
        receiver.recv()?
    }

    fn get_principal(&self, name: &str) -> Result<Option<Principal>> {
        let (sender, receiver) = channel();
        self.inner
            .op_sender
            .send(KAdminOperation::GetPrincipal(name.to_owned(), sender))?;
        receiver.recv()?
    }

    fn principal_change_password(
        &self,
        name: &str,
        password: &str,
        keepold: Option<bool>,
        keysalts: Option<&KeySalts>,
    ) -> Result<()> {
        let (sender, receiver) = channel();
        self.inner
            .op_sender
            .send(KAdminOperation::PrincipalChangePassword(
                name.to_owned(),
                password.to_owned(),
                keepold,
                keysalts.cloned(),
                sender,
            ))?;
        receiver.recv()?
    }

    fn principal_randkey(
        &self,
        name: &str,
        keepold: Option<bool>,
        keysalts: Option<&KeySalts>,
    ) -> Result<()> {
        let (sender, receiver) = channel();
        self.inner
            .op_sender
            .send(KAdminOperation::PrincipalRandkey(
                name.to_owned(),
                keepold,
                keysalts.cloned(),
                sender,
            ))?;
        receiver.recv()?
    }

    #[cfg(mit)]
    fn principal_get_strings(&self, name: &str) -> Result<HashMap<String, String>> {
        let (sender, receiver) = channel();
        self.inner
            .op_sender
            .send(KAdminOperation::PrincipalGetStrings(
                name.to_owned(),
                sender,
            ))?;
        receiver.recv()?
    }

    #[cfg(mit)]
    fn principal_set_string(&self, name: &str, key: &str, value: Option<&str>) -> Result<()> {
        let (sender, receiver) = channel();
        self.inner
            .op_sender
            .send(KAdminOperation::PrincipalSetString(
                name.to_owned(),
                key.to_owned(),
                value.map(String::from),
                sender,
            ))?;
        receiver.recv()?
    }

    fn list_principals(&self, query: Option<&str>) -> Result<Vec<String>> {
        let (sender, receiver) = channel();
        self.inner.op_sender.send(KAdminOperation::ListPrincipals(
            query.map(String::from),
            sender,
        ))?;
        receiver.recv()?
    }

    #[cfg(mit)]
    fn add_policy(&self, builder: &PolicyBuilder) -> Result<()> {
        let (sender, receiver) = channel();
        self.inner
            .op_sender
            .send(KAdminOperation::AddPolicy(builder.clone(), sender))?;
        receiver.recv()?
    }

    #[cfg(mit)]
    fn modify_policy(&self, modifier: &PolicyModifier) -> Result<()> {
        let (sender, receiver) = channel();
        self.inner
            .op_sender
            .send(KAdminOperation::ModifyPolicy(modifier.clone(), sender))?;
        receiver.recv()?
    }

    #[cfg(mit)]
    fn delete_policy(&self, name: &str) -> Result<()> {
        let (sender, receiver) = channel();
        self.inner
            .op_sender
            .send(KAdminOperation::DeletePolicy(name.to_owned(), sender))?;
        receiver.recv()?
    }

    #[cfg(mit)]
    fn get_policy(&self, name: &str) -> Result<Option<Policy>> {
        let (sender, receiver) = channel();
        self.inner
            .op_sender
            .send(KAdminOperation::GetPolicy(name.to_owned(), sender))?;
        receiver.recv()?
    }

    #[cfg(mit)]
    fn list_policies(&self, query: Option<&str>) -> Result<Vec<String>> {
        let (sender, receiver) = channel();
        self.inner.op_sender.send(KAdminOperation::ListPolicies(
            query.map(String::from),
            sender,
        ))?;
        receiver.recv()?
    }

    fn get_privileges(&self) -> Result<KAdminPrivileges> {
        let (sender, receiver) = channel();
        self.inner
            .op_sender
            .send(KAdminOperation::GetPrivileges(sender))?;
        receiver.recv()?
    }
}

/// [`KAdmin`] builder
#[derive(Debug)]
pub struct KAdminBuilder {
    variant: KAdm5Variant,
    library_path: Option<OsString>,
    params: Option<Params>,
    db_args: Option<DbArgs>,
    api_version: KAdminApiVersion,
}

impl KAdminBuilder {
    /// Create a new [`KAdminBuilder`] instance
    pub fn new(variant: KAdm5Variant) -> Self {
        Self {
            variant,
            library_path: None,
            params: None,
            db_args: None,
            api_version: Default::default(),
        }
    }

    /// Provide additional [`Params`][`crate::params::Params`] to this
    /// [`KAdmin`] instance
    pub fn params(mut self, params: Params) -> Self {
        self.params = Some(params);
        self
    }

    /// Provide additional [`DbArgs`][`crate::db_args::DbArgs`] to this
    /// [`KAdmin`] instance
    pub fn db_args(mut self, db_args: DbArgs) -> Self {
        self.db_args = Some(db_args);
        self
    }

    /// Set the kadm5 API version to use. See [`KAdminApiVersion`] for details
    pub fn api_version(mut self, api_version: KAdminApiVersion) -> Self {
        self.api_version = api_version;
        self
    }

    /// Set the path from where to load the kadm5 library
    pub fn library_path<S: AsRef<OsStr>>(mut self, library_path: S) -> Self {
        self.library_path = Some(library_path.as_ref().to_os_string());
        self
    }

    /// Construct a [`crate::kadmin::KAdminBuilder`] object that isn't initialized yet from the
    /// builder inputs
    fn get_builder(self) -> Result<crate::kadmin::KAdminBuilder> {
        let mut builder = crate::kadmin::KAdmin::builder(self.variant);
        if let Some(params) = self.params {
            builder = builder.params(params);
        }
        if let Some(db_args) = self.db_args {
            builder = builder.db_args(db_args);
        }
        if let Some(library_path) = self.library_path {
            let library = Library::from_path(self.variant, &library_path)?;
            builder = builder.library(library);
        }
        builder = builder.api_version(self.api_version);
        Ok(builder)
    }

    /// Build a [`crate::kadmin::KAdmin`] instance with a custom function
    fn build<F>(self, kadmin_build: F) -> Result<KAdmin>
    where F: FnOnce(crate::kadmin::KAdminBuilder) -> Result<crate::kadmin::KAdmin> + Send + 'static
    {
        let variant = self.variant;
        let (op_sender, op_receiver) = channel();
        let (start_sender, start_receiver) = channel();

        let join_handle = spawn(move || {
            let builder = match self.get_builder() {
                Ok(builder) => builder,
                Err(e) => {
                    let _ = start_sender.send(Err(e));
                    return;
                }
            };
            let kadmin = match kadmin_build(builder) {
                Ok(kadmin) => {
                    let _ = start_sender.send(Ok(()));
                    kadmin
                }
                Err(e) => {
                    let _ = start_sender.send(Err(e));
                    return;
                }
            };
            while let Ok(op) = op_receiver.recv() {
                match op {
                    KAdminOperation::Exit => break,
                    _ => op.handle(&kadmin),
                };
            }
        });

        match start_receiver.recv()? {
            Ok(_) => Ok(KAdmin {
                variant,
                inner: Arc::new(InnerKAdmin {
                    op_sender,
                    join_handle: Some(join_handle),
                }),
            }),
            Err(e) => match join_handle.join() {
                Ok(_) => Err(e),
                Err(e) => resume_unwind(e),
            },
        }
    }

    /// Construct a [`KAdmin`] object from this builder using a client name (usually a principal
    /// name) and a password
    pub fn with_password(self, client_name: &str, password: &str) -> Result<KAdmin> {
        let client_name = client_name.to_owned();
        let password = password.to_owned();

        self.build(move |builder| builder.with_password(&client_name, &password))
    }

    /// Construct a [`KAdmin`] object from this builder using an optional client name (usually a
    /// principal name) and an optional keytab
    ///
    /// If no client name is provided, `host/hostname` will be used
    ///
    /// If no keytab is provided, the default keytab will be used
    pub fn with_keytab(self, client_name: Option<&str>, keytab: Option<&str>) -> Result<KAdmin> {
        let client_name = client_name.map(String::from);
        let keytab = keytab.map(String::from);

        self.build(move |builder| builder.with_keytab(client_name.as_deref(), keytab.as_deref()))
    }

    /// Construct a [`KAdmin`] object from this builder using an optional client name (usually a
    /// principal name) and an optional credentials cache name
    ///
    /// If no client name is provided, the default principal from the credentials cache will be
    /// used
    ///
    /// If no credentials cache name is provided, the default credentials cache will be used
    pub fn with_ccache(
        self,
        client_name: Option<&str>,
        ccache_name: Option<&str>,
    ) -> Result<KAdmin> {
        let client_name = client_name.map(String::from);
        let ccache_name = ccache_name.map(String::from);

        self.build(move |builder| {
            builder.with_ccache(client_name.as_deref(), ccache_name.as_deref())
        })
    }

    /// Not implemented
    pub fn with_anonymous(self, client_name: &str) -> Result<KAdmin> {
        let client_name = client_name.to_owned();

        self.build(move |builder| builder.with_anonymous(&client_name))
    }

    /// Construct a [`KAdmin`] object from this builder for local database manipulation.
    pub fn with_local(self) -> Result<KAdmin> {
        self.build(move |builder| builder.with_local())
    }
}

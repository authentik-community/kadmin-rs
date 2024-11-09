//! Thread-safe [`KAdmin`] interface to kadm5
//!
//! This is a thread-safe wrapper over [`crate::kadmin::KAdmin`]. It accomplishes this by spawning
//! a separate thread with a non-sync [`crate::kadmin::KAdmin`] instance, and sending operations
//! and results over a [`channel`].
//!
//! The APIs between this wrapper and the underlying [`crate::kadmin::KAdmin`] are the same, and
//! wrapped and the [`KAdminImpl`] trait, apart for the builder. The builder in this wrapper does
//! not allow using a custom [`Context`][`crate::context::Context`], and takes [`ParamsBuilder`]
//! and [`DbArgsBuilder`] instead of [`Params`][`crate::params::Params`] and
//! [`DbArgs`][`crate::db_args::DbArgs`].
use std::{
    panic::resume_unwind,
    sync::mpsc::{Sender, channel},
    thread::{JoinHandle, spawn},
};

use crate::{
    db_args::DbArgsBuilder, error::Result, kadmin::KAdminImpl, params::ParamsBuilder,
    principal::Principal,
};

/// Operations from [`KAdminImpl`]
enum KAdminOperation {
    /// See [`KAdminImpl::get_principal`]
    GetPrincipal(String, Sender<Result<Option<Principal>>>),
    /// See [`KAdminImpl::principal_change_password`]
    PrincipalChangePassword(String, String, Sender<Result<()>>),
    /// See [`KAdminImpl::list_principals`]
    ListPrincipals(Option<String>, Sender<Result<Vec<String>>>),
    /// See [`KAdminImpl::list_policies`]
    ListPolicies(Option<String>, Sender<Result<Vec<String>>>),
    /// Stop the kadmin thread
    Exit,
}

impl KAdminOperation {
    fn handle(&self, kadmin: &crate::kadmin::KAdmin) {
        match self {
            Self::Exit => (),
            Self::GetPrincipal(name, sender) => {
                let _ = sender.send(kadmin.get_principal(name));
            }
            Self::PrincipalChangePassword(name, password, sender) => {
                let _ = sender.send(kadmin.principal_change_password(name, password));
            }
            Self::ListPrincipals(query, sender) => {
                let _ = sender.send(kadmin.list_principals(query.as_deref()));
            }
            Self::ListPolicies(query, sender) => {
                let _ = sender.send(kadmin.list_policies(query.as_deref()));
            }
        }
    }
}

/// Thread-safe interface to kadm5
///
/// This is a thread-safe wrapper over [`crate::kadmin::KAdmin`].
pub struct KAdmin {
    op_sender: Sender<KAdminOperation>,
    join_handle: Option<JoinHandle<()>>,
}

impl KAdmin {
    /// Construct a new [`KAdminBuilder`]
    pub fn builder() -> KAdminBuilder {
        KAdminBuilder::default()
    }
}

impl KAdminImpl for KAdmin {
    fn get_principal(&self, name: &str) -> Result<Option<Principal>> {
        let (sender, receiver) = channel();
        self.op_sender
            .send(KAdminOperation::GetPrincipal(name.to_owned(), sender))?;
        receiver.recv()?
    }

    fn principal_change_password(&self, name: &str, password: &str) -> Result<()> {
        let (sender, receiver) = channel();
        self.op_sender
            .send(KAdminOperation::PrincipalChangePassword(
                name.to_owned(),
                password.to_owned(),
                sender,
            ))?;
        receiver.recv()?
    }

    fn list_principals(&self, query: Option<&str>) -> Result<Vec<String>> {
        let (sender, receiver) = channel();
        self.op_sender.send(KAdminOperation::ListPrincipals(
            query.map(String::from),
            sender,
        ))?;
        receiver.recv()?
    }

    fn list_policies(&self, query: Option<&str>) -> Result<Vec<String>> {
        let (sender, receiver) = channel();
        self.op_sender.send(KAdminOperation::ListPolicies(
            query.map(String::from),
            sender,
        ))?;
        receiver.recv()?
    }
}

impl Drop for KAdmin {
    fn drop(&mut self) {
        // Thread might have already exited, so we don't care about the result of this.
        let _ = self.op_sender.send(KAdminOperation::Exit);
        if let Some(join_handle) = self.join_handle.take() {
            if let Err(e) = join_handle.join() {
                resume_unwind(e);
            }
        }
    }
}

/// [`KAdmin`] builder
#[derive(Debug, Default)]
pub struct KAdminBuilder {
    params_builder: Option<ParamsBuilder>,
    db_args_builder: Option<DbArgsBuilder>,
}

impl KAdminBuilder {
    /// Provide additional [`Params`][`crate::params::Params`] through [`ParamsBuilder`] to this
    /// [`KAdmin`] instance
    pub fn params_builder(mut self, params_builder: ParamsBuilder) -> Self {
        self.params_builder = Some(params_builder);
        self
    }

    /// Provide additional [`DbArgs`][`crate::db_args::DbArgs`] through [`DbArgsBuilder`] to this
    /// [`KAdmin`] instance
    pub fn db_args_builder(mut self, db_args_builder: DbArgsBuilder) -> Self {
        self.db_args_builder = Some(db_args_builder);
        self
    }

    /// Construct a [`crate::kadmin::KAdminBuilder`] object that isn't initialized yet from the
    /// builder inputs
    fn get_builder(self) -> Result<crate::kadmin::KAdminBuilder> {
        let mut builder = crate::kadmin::KAdmin::builder();
        if let Some(params_builder) = self.params_builder {
            builder = builder.params(params_builder.build()?);
        }
        if let Some(db_args_builder) = self.db_args_builder {
            builder = builder.db_args(db_args_builder.build()?);
        }
        Ok(builder)
    }

    /// Build a [`crate::kadmin::KAdmin`] instance with a custom function
    fn build<F>(self, kadmin_build: F) -> Result<KAdmin>
    where F: FnOnce(crate::kadmin::KAdminBuilder) -> Result<crate::kadmin::KAdmin> + Send + 'static
    {
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
                op_sender,
                join_handle: Some(join_handle),
            }),
            Err(e) => match join_handle.join() {
                Ok(_) => Err(e),
                Err(e) => resume_unwind(e),
            },
        }
    }

    /// Construct a [`KAdmin`] object from this builder using a client name (usually a principal
    /// name) and a password
    #[cfg(any(feature = "client", doc))]
    #[cfg_attr(docsrs, doc(cfg(feature = "client")))]
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
    #[cfg(any(feature = "client", doc))]
    #[cfg_attr(docsrs, doc(cfg(feature = "client")))]
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
    #[cfg(any(feature = "client", doc))]
    #[cfg_attr(docsrs, doc(cfg(feature = "client")))]
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
    #[cfg(any(feature = "client", doc))]
    #[cfg_attr(docsrs, doc(cfg(feature = "client")))]
    pub fn with_anonymous(self, client_name: &str) -> Result<KAdmin> {
        let client_name = client_name.to_owned();

        self.build(move |builder| builder.with_anonymous(&client_name))
    }

    /// Construct a [`KAdmin`] object from this builder for local database manipulation.
    #[cfg(any(feature = "local", doc))]
    #[cfg_attr(docsrs, doc(cfg(feature = "local")))]
    pub fn with_local(self) -> Result<KAdmin> {
        self.build(move |builder| builder.with_local())
    }
}

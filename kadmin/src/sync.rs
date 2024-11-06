use std::{
    panic::resume_unwind,
    sync::mpsc::{Sender, channel},
    thread::{JoinHandle, spawn},
};

use crate::{
    db_args::KAdminDbArgsBuilder, error::Result, kadmin::KAdminImpl, params::KAdminParamsBuilder, principal::Principal,
};

enum KAdminOperation {
    GetPrincipal(String, Sender<Result<Option<Principal>>>),
    PrincipalChangePassword(String, String, Sender<Result<()>>),
    ListPrincipals(String, Sender<Result<Vec<String>>>),
    ListPolicies(String, Sender<Result<Vec<String>>>),
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
                let _ = sender.send(kadmin.list_principals(query));
            }
            Self::ListPolicies(query, sender) => {
                let _ = sender.send(kadmin.list_policies(query));
            }
        }
    }
}

pub struct KAdmin {
    op_sender: Sender<KAdminOperation>,
    join_handle: Option<JoinHandle<()>>,
}

impl KAdmin {
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
        self.op_sender.send(KAdminOperation::PrincipalChangePassword(
            name.to_owned(),
            password.to_owned(),
            sender,
        ))?;
        receiver.recv()?
    }

    fn list_principals(&self, query: &str) -> Result<Vec<String>> {
        let (sender, receiver) = channel();
        self.op_sender
            .send(KAdminOperation::ListPrincipals(query.to_owned(), sender))?;
        receiver.recv()?
    }

    fn list_policies(&self, query: &str) -> Result<Vec<String>> {
        let (sender, receiver) = channel();
        self.op_sender
            .send(KAdminOperation::ListPolicies(query.to_owned(), sender))?;
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

#[derive(Debug, Default)]
pub struct KAdminBuilder {
    params_builder: Option<KAdminParamsBuilder>,
    db_args_builder: Option<KAdminDbArgsBuilder>,
}

impl KAdminBuilder {
    pub fn params_builder(mut self, params_builder: KAdminParamsBuilder) -> Self {
        self.params_builder = Some(params_builder);
        self
    }

    pub fn db_args_builder(mut self, db_args_builder: KAdminDbArgsBuilder) -> Self {
        self.db_args_builder = Some(db_args_builder);
        self
    }

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

    fn build<F>(self, kadmin_build: F) -> Result<KAdmin>
    where F: FnOnce(crate::kadmin::KAdminBuilder) -> Result<crate::kadmin::KAdmin> + Send + 'static {
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

    #[cfg(feature = "client")]
    pub fn with_password(self, client_name: &str, password: &str) -> Result<KAdmin> {
        let client_name = client_name.to_owned();
        let password = password.to_owned();

        self.build(move |builder| builder.with_password(&client_name, &password))
    }

    #[cfg(feature = "client")]
    pub fn with_keytab(self, client_name: Option<&str>, keytab: Option<&str>) -> Result<KAdmin> {
        let client_name = client_name.map(String::from);
        let keytab = keytab.map(String::from);

        self.build(move |builder| builder.with_keytab(client_name.as_deref(), keytab.as_deref()))
    }

    #[cfg(feature = "client")]
    pub fn with_ccache(self, client_name: Option<&str>, ccache_name: Option<&str>) -> Result<KAdmin> {
        let client_name = client_name.map(String::from);
        let ccache_name = ccache_name.map(String::from);

        self.build(move |builder| builder.with_ccache(client_name.as_deref(), ccache_name.as_deref()))
    }

    #[cfg(feature = "client")]
    pub fn with_anonymous(self, client_name: &str) -> Result<KAdmin> {
        let client_name = client_name.to_owned();

        self.build(move |builder| builder.with_anonymous(&client_name))
    }

    #[cfg(any(feature = "local", docsrs))]
    pub fn with_local(self) -> Result<KAdmin> {
        self.build(move |builder| builder.with_local())
    }
}

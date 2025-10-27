//! Utility to run a krb5 KDC
use std::{ffi::CStr, process::Command, thread::sleep, time::Duration};

use anyhow::Result;
use pyo3::ffi::c_str;
#[allow(unused_imports)]
use pyo3::{prelude::*, types::PyDict};

#[allow(dead_code)]
const K5REALM_INIT: &CStr = c_str!(
    r#"
import os
from copy import deepcopy
from k5test import realm

realm = realm.K5Realm(start_kadmind=True)
realm.http_princ = f"HTTP/testserver@{realm.realm}"
realm.http_keytab = os.path.join(realm.tmpdir, "http_keytab")
realm.addprinc(realm.http_princ)
realm.extract_keytab(realm.http_princ, realm.http_keytab)

saved_env = deepcopy(os.environ)
for k, v in realm.env.items():
    os.environ[k] = v
"#
);

const RESTORE_ENV: &CStr = c_str!(
    r#"
import os
from copy import deepcopy

def restore_env(saved_env):
    for k in deepcopy(os.environ):
        if k in saved_env:
            os.environ[k] = saved_env[k]
        else:
            del os.environ[k]
"#
);

pub(crate) struct K5Test {
    realm: Py<PyAny>,
    saved_env: Py<PyAny>,
}

impl K5Test {
    #[allow(dead_code)]
    pub(crate) fn new() -> Result<Self> {
        let (realm, saved_env) = Python::attach(|py| {
            let module = PyModule::from_code(py, K5REALM_INIT, c_str!(""), c_str!(""))?;
            let realm = module.getattr("realm")?;
            let saved_env = module.getattr("saved_env")?;
            Ok::<(Py<PyAny>, Py<PyAny>), PyErr>((realm.into(), saved_env.into()))
        })?;

        Ok(Self { realm, saved_env })
    }

    #[allow(dead_code)]
    pub(crate) fn realm_name(&self) -> Result<String> {
        Python::attach(|py| {
            let realm = self.realm.bind(py);
            let realm_name: String = realm.getattr("realm")?.extract()?;
            Ok(realm_name)
        })
    }

    #[allow(dead_code)]
    pub(crate) fn tmpdir(&self) -> Result<String> {
        Python::attach(|py| {
            let realm = self.realm.bind(py);
            let tmpdir: String = realm.getattr("tmpdir")?.extract()?;
            Ok(tmpdir)
        })
    }

    #[allow(dead_code)]
    pub(crate) fn user_princ(&self) -> Result<String> {
        Python::attach(|py| {
            let realm = self.realm.bind(py);
            let user_princ: String = realm.getattr("user_princ")?.extract()?;
            Ok(user_princ)
        })
    }

    #[allow(dead_code)]
    pub(crate) fn admin_princ(&self) -> Result<String> {
        Python::attach(|py| {
            let realm = self.realm.bind(py);
            let admin_princ: String = realm.getattr("admin_princ")?.extract()?;
            Ok(admin_princ)
        })
    }

    #[allow(dead_code)]
    pub(crate) fn kadmin_ccache(&self) -> Result<String> {
        Python::attach(|py| {
            let realm = self.realm.bind(py);
            let kadmin_ccache: String = realm.getattr("kadmin_ccache")?.extract()?;
            Ok(kadmin_ccache)
        })
    }

    #[allow(dead_code)]
    pub(crate) fn password(&self, name: &str) -> Result<String> {
        Python::attach(|py| {
            let realm = self.realm.bind(py);
            let password: String = realm.call_method1("password", (name,))?.extract()?;
            Ok(password)
        })
    }

    #[allow(dead_code)]
    pub(crate) fn kinit(&self, name: &str, password: &str) -> Result<()> {
        Python::attach(|py| {
            let realm = self.realm.bind(py);
            realm.call_method1("kinit", (name, password))?;
            Ok(())
        })
    }

    #[allow(dead_code)]
    pub(crate) fn prep_kadmin(&self) -> Result<()> {
        Python::attach(|py| {
            let realm = self.realm.bind(py);
            realm.call_method0("prep_kadmin")?;
            Ok(())
        })
    }
}

impl Drop for K5Test {
    fn drop(&mut self) {
        Python::attach(|py| {
            let realm = self.realm.bind(py);
            let saved_env = self.saved_env.bind(py);

            realm.call_method0("stop")?;

            let module = PyModule::from_code(py, RESTORE_ENV, c_str!(""), c_str!(""))?;
            let restore_env = module.getattr("restore_env")?;
            restore_env.call1((saved_env,))?;

            Ok::<(), PyErr>(())
        })
        .unwrap();
        Command::new("pkill").arg("krb5kdc").output().unwrap();
        Command::new("pkill").arg("kadmind").output().unwrap();
    }
}

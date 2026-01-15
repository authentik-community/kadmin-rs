//! Utility to run a krb5 KDC
use std::{ffi::CStr, process::Command};

use anyhow::Result;
use kadmin::KAdm5Variant;
use pyo3::ffi::c_str;
#[allow(unused_imports)]
use pyo3::{prelude::*, types::PyDict};

#[allow(dead_code)]
const K5REALM_MIT_INIT: &CStr = c_str!(
    r#"
import logging
import os
import shutil
from copy import deepcopy
from k5test import realm

logging.basicConfig(level=logging.DEBUG)

def _discover_path(name, default, paths):
    if name in paths:
        return paths[name]
    path = shutil.which(name)
    if path is not None:
        return path
    else:
        return default
realm._discover_path = _discover_path

saved_env = deepcopy(os.environ)

realm_paths = {}
for name in ("kdb5_util", "krb5kdc", "kadmin", "kadmin.local", "kadmind", "kprop", "kinit", "klist"):
    path = os.environ.get("K5TEST_MIT_" + name.upper().replace(".", "_"))
    if path is not None:
        realm_paths[name] = path

realm = realm.MITRealm(start_kadmind=True, **realm_paths)
realm.http_princ = f"HTTP/testserver@{realm.realm}"
realm.http_keytab = os.path.join(realm.tmpdir, "http_keytab")
realm.addprinc(realm.http_princ)
realm.extract_keytab(realm.http_princ, realm.http_keytab)

for k, v in realm.env.items():
    os.environ[k] = v
"#
);

#[allow(dead_code)]
const K5REALM_HEIMDAL_INIT: &CStr = c_str!(
    r#"
import logging
import os
import shutil
from copy import deepcopy
from k5test import realm

logging.basicConfig(level=logging.DEBUG)

saved_env = deepcopy(os.environ)

def _discover_path(name, default, paths):
    if name in paths:
        return paths[name]
    path = shutil.which(name)
    if path is not None:
        return path
    else:
        return default
realm._discover_path = _discover_path

realm.HeimdalRealm.hostname = None
realm.HeimdalRealm.hostname = "localhost"

def start_kadmind(self, env=None):
    if self._kadmind_proc:
        raise Exception("kadmind already started")
    if env is None:
        env = self.env
    config_file = f"--config-file={env['KRB5_CONFIG']}"
    port = "--ports=%s" % (self.portbase + 1)
    args = [self.kadmind, config_file, port]
    self._kadmind_proc = self._start_daemon(args)
realm.HeimdalRealm.start_kadmind = start_kadmind

def prep_kadmin(self, princname=None, pw=None, flags=None):
    if princname is None:
        princname = self.admin_princ
        pw = self.password("admin")
    return self.kinit(
        princname,
        pw,
        flags=["-S", "kadmin/admin", "-c", self.kadmin_ccache] + (flags or [])
    )
realm.HeimdalRealm.prep_kadmin = prep_kadmin

realm_paths = {}
for name in ("kdc", "kadmin", "kadmind", "kinit", "klist", "ktutil"):
    path = os.environ.get("K5TEST_HEIMDAL_" + name.upper().replace(".", "_"))
    if path is not None:
        realm_paths[name] = path

realm = realm.HeimdalRealm(start_kadmind=True, **realm_paths)
realm.http_princ = f"HTTP/testserver@{realm.realm}"
realm.http_keytab = os.path.join(realm.tmpdir, "http_keytab")
realm.addprinc(realm.http_princ)
realm.extract_keytab(realm.http_princ, realm.http_keytab)

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
    pub(crate) fn new(variant: KAdm5Variant) -> Result<Self> {
        let (realm, saved_env) = Python::attach(|py| {
            let module = match variant {
                #[cfg(mit_client)]
                KAdm5Variant::MitClient => {
                    PyModule::from_code(py, K5REALM_MIT_INIT, c_str!(""), c_str!(""))?
                }
                #[cfg(mit_server)]
                KAdm5Variant::MitServer => {
                    PyModule::from_code(py, K5REALM_MIT_INIT, c_str!(""), c_str!(""))?
                }
                #[cfg(heimdal_client)]
                KAdm5Variant::HeimdalClient => {
                    PyModule::from_code(py, K5REALM_HEIMDAL_INIT, c_str!(""), c_str!(""))?
                }
                #[cfg(heimdal_server)]
                KAdm5Variant::HeimdalServer => {
                    PyModule::from_code(py, K5REALM_HEIMDAL_INIT, c_str!(""), c_str!(""))?
                }
            };
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
        Command::new("pkill").arg("kdc").output().unwrap();
        Command::new("pkill").arg("kadmind").output().unwrap();
    }
}

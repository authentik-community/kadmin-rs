#[cfg(feature = "client")]
use std::{ffi::CStr, mem::MaybeUninit};
use std::{
    ffi::CString,
    os::raw::{c_char, c_void},
    ptr::null_mut,
    sync::Mutex,
};

use kadmin_sys::*;

use crate::{
    context::KAdminContext,
    db_args::KAdminDbArgs,
    error::{Result, kadm5_ret_t_escape_hatch, krb5_error_code_escape_hatch},
    params::KAdminParams,
    principal::Principal,
    strconv::c_string_to_string,
};

static KADMIN_INIT_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug)]
pub struct KAdmin {
    pub(crate) context: KAdminContext,
    pub(crate) server_handle: *mut c_void,
}

pub trait KAdminImpl {
    // ank, addprinc, add_principal
    fn add_principal() {
        unimplemented!();
    }

    // delprinc, delete_principal
    fn delete_principal() {
        unimplemented!();
    }

    // modify_principal, modprinc
    fn modify_principal() {
        unimplemented!();
    }

    // rename_principal, renprinc
    fn rename_principal() {
        unimplemented!();
    }

    // get_principal, getprinc
    fn get_principal(&self, name: &str) -> Result<Option<Principal>>;

    fn principal_exists(&self, name: &str) -> Result<bool> {
        Ok(self.get_principal(name)?.is_some())
    }

    // change_password, cpw
    fn principal_change_password(&self, name: &str, password: &str) -> Result<()>;

    // list_principals, listprincs, get_principals, getprincs
    fn list_principals(&self, query: &str) -> Result<Vec<String>>;

    // add_policy, addpol
    fn add_policy() {
        unimplemented!();
    }

    // modify_policy, modpol
    fn modify_policy() {
        unimplemented!();
    }

    // delete_policy, delpol
    fn delete_policy() {
        unimplemented!();
    }

    // get_policy, getpol
    fn get_policy() {
        unimplemented!();
    }

    // list_policies, listpols, get_policies, getpols
    fn list_policies(&self, query: &str) -> Result<Vec<String>>;

    // get_privs, getprivs
    fn get_privs() {
        unimplemented!();
    }
}

impl KAdmin {
    pub fn builder() -> KAdminBuilder {
        KAdminBuilder::default()
    }
}

impl KAdminImpl for KAdmin {
    fn get_principal(&self, name: &str) -> Result<Option<Principal>> {
        let mut temp_princ = null_mut();
        let name = CString::new(name)?;
        let code = unsafe { krb5_parse_name(self.context.context, name.as_ptr().cast_mut(), &mut temp_princ) };
        krb5_error_code_escape_hatch(&self.context, code)?;
        let mut principal_ent = _kadm5_principal_ent_t::default();
        let code = unsafe {
            kadm5_get_principal(
                self.server_handle,
                temp_princ,
                &mut principal_ent,
                (KADM5_PRINCIPAL_NORMAL_MASK | KADM5_KEY_DATA) as i64,
            )
        };
        unsafe {
            krb5_free_principal(self.context.context, temp_princ);
        }
        if code == KADM5_UNK_PRINC as i64 {
            return Ok(None);
        }
        kadm5_ret_t_escape_hatch(code)?;
        let principal = Principal::from_raw(self, &principal_ent)?;
        let code = unsafe { kadm5_free_principal_ent(self.server_handle, &mut principal_ent) };
        kadm5_ret_t_escape_hatch(code)?;
        Ok(Some(principal))
    }

    fn principal_change_password(&self, name: &str, password: &str) -> Result<()> {
        let mut temp_princ = null_mut();
        let name = CString::new(name)?;
        let password = CString::new(password)?;
        let code = unsafe { krb5_parse_name(self.context.context, name.as_ptr().cast_mut(), &mut temp_princ) };
        krb5_error_code_escape_hatch(&self.context, code)?;
        let code = unsafe { kadm5_chpass_principal(self.server_handle, temp_princ, password.as_ptr().cast_mut()) };
        unsafe {
            krb5_free_principal(self.context.context, temp_princ);
        }
        kadm5_ret_t_escape_hatch(code)?;
        Ok(())
    }

    fn list_principals(&self, query: &str) -> Result<Vec<String>> {
        let query = CString::new(query)?;
        let mut count = 0;
        let mut princs: *mut *mut c_char = null_mut();
        let code =
            unsafe { kadm5_get_principals(self.server_handle, query.as_ptr().cast_mut(), &mut princs, &mut count) };
        kadm5_ret_t_escape_hatch(code)?;
        let mut result = Vec::with_capacity(count as usize);
        for raw in unsafe { std::slice::from_raw_parts(princs, count as usize) }.iter() {
            result.push(c_string_to_string(*raw)?);
        }
        unsafe {
            kadm5_free_name_list(self.server_handle, princs, count);
        }
        Ok(result)
    }

    fn list_policies(&self, query: &str) -> Result<Vec<String>> {
        let query = CString::new(query)?;
        let mut count = 0;
        let mut policies: *mut *mut c_char = null_mut();
        let code =
            unsafe { kadm5_get_policies(self.server_handle, query.as_ptr().cast_mut(), &mut policies, &mut count) };
        kadm5_ret_t_escape_hatch(code)?;
        let mut result = Vec::with_capacity(count as usize);
        for raw in unsafe { std::slice::from_raw_parts(policies, count as usize) }.iter() {
            result.push(c_string_to_string(*raw)?);
        }
        unsafe {
            kadm5_free_name_list(self.server_handle, policies, count);
        }
        Ok(result)
    }
}

impl Drop for KAdmin {
    fn drop(&mut self) {
        let _guard = KADMIN_INIT_LOCK
            .lock()
            .expect("Failed to lock kadmin for de-initialization.");
        unsafe {
            kadm5_flush(self.server_handle);
            kadm5_destroy(self.server_handle);
        }
    }
}

#[derive(Debug, Default)]
pub struct KAdminBuilder {
    context: Option<Result<KAdminContext>>,
    params: Option<KAdminParams>,
    db_args: Option<KAdminDbArgs>,
}

impl KAdminBuilder {
    pub fn context(mut self, context: KAdminContext) -> Self {
        self.context = Some(Ok(context));
        self
    }

    pub fn params(mut self, params: KAdminParams) -> Self {
        self.params = Some(params);
        self
    }

    pub fn db_args(mut self, db_args: KAdminDbArgs) -> Self {
        self.db_args = Some(db_args);
        self
    }

    fn get_kadmin(self) -> Result<(KAdmin, KAdminParams, KAdminDbArgs)> {
        let params = self.params.unwrap_or_default();
        let db_args = self.db_args.unwrap_or_default();
        let context = self.context.unwrap_or(KAdminContext::new())?;
        let kadmin = KAdmin {
            context,
            server_handle: null_mut(),
        };
        Ok((kadmin, params, db_args))
    }

    #[cfg(feature = "client")]
    pub fn with_password(self, client_name: &str, password: &str) -> Result<KAdmin> {
        let _guard = KADMIN_INIT_LOCK.lock().expect("Failed to lock context initialization.");

        let (mut kadmin, params, db_args) = self.get_kadmin()?;

        let client_name = CString::new(client_name)?;
        let password = CString::new(password)?;
        let service_name = KADM5_ADMIN_SERVICE.to_owned();

        let mut params = params;

        let code = unsafe {
            kadm5_init_with_password(
                kadmin.context.context,
                client_name.as_ptr().cast_mut(),
                password.as_ptr().cast_mut(),
                service_name.as_ptr().cast_mut(),
                &mut params.params,
                KADM5_STRUCT_VERSION,
                KADM5_API_VERSION_2,
                db_args.db_args,
                &mut kadmin.server_handle,
            )
        };

        kadm5_ret_t_escape_hatch(code)?;

        Ok(kadmin)
    }

    #[cfg(feature = "client")]
    pub fn with_keytab(self, client_name: Option<&str>, keytab: Option<&str>) -> Result<KAdmin> {
        let _guard = KADMIN_INIT_LOCK.lock().expect("Failed to lock context initialization.");

        let (mut kadmin, params, db_args) = self.get_kadmin()?;

        let client_name = if let Some(client_name) = client_name {
            CString::new(client_name)?
        } else {
            let mut princ_ptr: MaybeUninit<krb5_principal> = MaybeUninit::zeroed();
            let code = unsafe {
                krb5_sname_to_principal(
                    kadmin.context.context,
                    null_mut(),
                    CString::new("host")?.as_ptr().cast_mut(),
                    KRB5_NT_SRV_HST as i32,
                    princ_ptr.as_mut_ptr(),
                )
            };
            krb5_error_code_escape_hatch(&kadmin.context, code)?;
            let princ = unsafe { princ_ptr.assume_init() };
            let mut raw_client_name: *mut c_char = null_mut();
            let code = unsafe { krb5_unparse_name(kadmin.context.context, princ, &mut raw_client_name) };
            krb5_error_code_escape_hatch(&kadmin.context, code)?;
            unsafe {
                krb5_free_principal(kadmin.context.context, princ);
            }
            let client_name = unsafe { CStr::from_ptr(raw_client_name) }.to_owned();
            unsafe {
                krb5_free_unparsed_name(kadmin.context.context, raw_client_name);
            }
            client_name
        };
        let keytab = if let Some(keytab) = keytab {
            CString::new(keytab)?
        } else {
            CString::new("/etc/krb5.keytab")?
        };
        let service_name = KADM5_ADMIN_SERVICE.to_owned();

        let mut params = params;

        let code = unsafe {
            kadm5_init_with_skey(
                kadmin.context.context,
                client_name.as_ptr().cast_mut(),
                keytab.as_ptr().cast_mut(),
                service_name.as_ptr().cast_mut(),
                &mut params.params,
                KADM5_STRUCT_VERSION,
                KADM5_API_VERSION_2,
                db_args.db_args,
                &mut kadmin.server_handle,
            )
        };

        kadm5_ret_t_escape_hatch(code)?;

        Ok(kadmin)
    }

    #[cfg(feature = "client")]
    pub fn with_ccache(self, client_name: Option<&str>, ccache_name: Option<&str>) -> Result<KAdmin> {
        let _guard = KADMIN_INIT_LOCK.lock().expect("Failed to lock context initialization.");

        let (mut kadmin, params, db_args) = self.get_kadmin()?;

        let ccache = {
            let mut ccache: MaybeUninit<krb5_ccache> = MaybeUninit::zeroed();
            let code = if let Some(ccache_name) = ccache_name {
                let ccache_name = CString::new(ccache_name)?;
                unsafe {
                    krb5_cc_resolve(
                        kadmin.context.context,
                        ccache_name.as_ptr().cast_mut(),
                        ccache.as_mut_ptr(),
                    )
                }
            } else {
                unsafe { krb5_cc_default(kadmin.context.context, ccache.as_mut_ptr()) }
            };
            krb5_error_code_escape_hatch(&kadmin.context, code)?;
            unsafe { ccache.assume_init() }
        };

        let client_name = if let Some(client_name) = client_name {
            CString::new(client_name)?
        } else {
            let mut princ_ptr: MaybeUninit<krb5_principal> = MaybeUninit::zeroed();
            let code = unsafe { krb5_cc_get_principal(kadmin.context.context, ccache, princ_ptr.as_mut_ptr()) };
            krb5_error_code_escape_hatch(&kadmin.context, code)?;
            let princ = unsafe { princ_ptr.assume_init() };
            let mut raw_client_name: *mut c_char = null_mut();
            let code = unsafe { krb5_unparse_name(kadmin.context.context, princ, &mut raw_client_name) };
            krb5_error_code_escape_hatch(&kadmin.context, code)?;
            unsafe {
                krb5_free_principal(kadmin.context.context, princ);
            }
            let client_name = unsafe { CStr::from_ptr(raw_client_name) }.to_owned();
            unsafe {
                krb5_free_unparsed_name(kadmin.context.context, raw_client_name);
            }
            client_name
        };
        let service_name = KADM5_ADMIN_SERVICE.to_owned();

        let mut params = params;

        let code = unsafe {
            kadm5_init_with_creds(
                kadmin.context.context,
                client_name.as_ptr().cast_mut(),
                ccache,
                service_name.as_ptr().cast_mut(),
                &mut params.params,
                KADM5_STRUCT_VERSION,
                KADM5_API_VERSION_2,
                db_args.db_args,
                &mut kadmin.server_handle,
            )
        };

        unsafe {
            krb5_cc_close(kadmin.context.context, ccache);
        }

        kadm5_ret_t_escape_hatch(code)?;

        Ok(kadmin)
    }

    #[cfg(feature = "client")]
    pub fn with_anonymous(self, _client_name: &str) -> Result<KAdmin> {
        let _guard = KADMIN_INIT_LOCK.lock().expect("Failed to lock context initialization.");

        let (mut _kadmin, _params, _db_args) = self.get_kadmin()?;

        unimplemented!();
    }

    #[cfg(any(feature = "local", docsrs))]
    pub fn with_local(self) -> Result<KAdmin> {
        let _guard = KADMIN_INIT_LOCK.lock().expect("Failed to lock context initialization.");

        let (mut kadmin, params, db_args) = self.get_kadmin()?;

        let client_name = if let Some(default_realm) = &kadmin.context.default_realm {
            let mut concat = CString::new("root/admin@")?.into_bytes();
            concat.extend_from_slice(default_realm.to_bytes_with_nul());
            CString::from_vec_with_nul(concat)?
        } else {
            CString::new("root/admin")?
        };
        let service_name = KADM5_ADMIN_SERVICE.to_owned();

        let mut params = params;

        let code = unsafe {
            kadm5_init_with_creds(
                kadmin.context.context,
                client_name.as_ptr().cast_mut(),
                null_mut(),
                service_name.as_ptr().cast_mut(),
                &mut params.params,
                KADM5_STRUCT_VERSION,
                KADM5_API_VERSION_2,
                db_args.db_args,
                &mut kadmin.server_handle,
            )
        };

        kadm5_ret_t_escape_hatch(code)?;

        Ok(kadmin)
    }
}

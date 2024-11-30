//! [`KAdmin`] interface to kadm5

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
    context::Context,
    conv::{c_string_to_string, dt_to_ts, dur_to_delta},
    db_args::DbArgs,
    error::{Result, kadm5_ret_t_escape_hatch, krb5_error_code_escape_hatch},
    params::Params,
    principal::{Principal, PrincipalBuilder, PrincipalBuilderKey},
};

/// Lock acquired when creating or dropping a [`KAdmin`] instance
static KADMIN_INIT_LOCK: Mutex<()> = Mutex::new(());

/// Interface to kadm5
///
/// This interface is not thread safe. Consider creating one per thread where needed, or using the
/// [`sync::KAdmin`][`crate::sync::KAdmin`] interface that is thread safe.
#[derive(Debug)]
pub struct KAdmin {
    /// Kerberos context
    pub(crate) context: Context,
    /// Server handle for kadm5
    pub(crate) server_handle: *mut c_void,
}

/// Common methods for `KAdmin` implementations
pub trait KAdminImpl {
    /// Create a principal. Not yet implemented
    #[doc(alias("ank", "addprinc"))]
    fn add_principal(&self, _builder: &PrincipalBuilder) -> Result<()> {
        unimplemented!();
    }

    /// Delete a principal. Not yet implemented
    #[doc(alias = "delprinc")]
    fn delete_principal() {
        unimplemented!();
    }

    /// Modify a principal. Not yet implemented
    #[doc(alias = "modprinc")]
    fn modify_principal() {
        unimplemented!();
    }

    /// Rename a principal. Not yet implemented
    #[doc(alias = "renprinc")]
    fn rename_principal() {
        unimplemented!();
    }

    /// Retrieve a principal
    ///
    /// ```no_run
    /// # use crate::kadmin::{KAdmin, KAdminImpl};
    /// # #[cfg(feature = "client")]
    /// # fn example() {
    /// let kadm = kadmin::KAdmin::builder().with_ccache(None, None).unwrap();
    /// let princname = String::from("user@EXAMPLE.ORG");
    /// let principal = kadm.get_principal(&princname).unwrap();
    /// assert!(principal.is_some());
    /// # }
    /// ```
    #[doc(alias = "getprinc")]
    fn get_principal(&self, name: &str) -> Result<Option<Principal>>;

    /// Check if a principal exists
    ///
    /// ```no_run
    /// # use crate::kadmin::{KAdmin, KAdminImpl};
    /// # #[cfg(feature = "client")]
    /// # fn example() {
    /// let kadm = kadmin::KAdmin::builder().with_ccache(None, None).unwrap();
    /// let princname = String::from("user@EXAMPLE.ORG");
    /// assert!(kadm.principal_exists(&princname).unwrap());
    /// # }
    /// ```
    fn principal_exists(&self, name: &str) -> Result<bool> {
        Ok(self.get_principal(name)?.is_some())
    }

    /// Change a principal password
    ///
    /// Don't use this method directly. Instead, use [`Principal::change_password`]
    #[doc(alias = "cpw")]
    fn principal_change_password(&self, name: &str, password: &str) -> Result<()>;

    /// List principals
    ///
    /// `query` is a shell-style glob expression that can contain the wild-card characters `?`, `*`,
    /// and `[]`. All principal names matching the expression are retuned. If the expression
    /// does not contain an `@` character, an `@` character followed by the local realm is
    /// appended to the expression. If no query is provided, all principals are returned.
    ///
    /// ```no_run
    /// # use crate::kadmin::{KAdmin, KAdminImpl};
    /// # #[cfg(feature = "client")]
    /// # fn example() {
    /// let kadm = kadmin::KAdmin::builder().with_ccache(None, None).unwrap();
    /// for princ in kadm.list_principals(None).unwrap() {
    ///     println!("{princ}");
    /// }
    /// # }
    /// ```
    #[doc(alias("listprincs", "get_principals", "getprincs"))]
    fn list_principals(&self, query: Option<&str>) -> Result<Vec<String>>;

    /// Add a policy. Not yet implemented
    #[doc(alias = "addpol")]
    fn add_policy() {
        unimplemented!();
    }

    /// Modify a policy. Not yet implemented
    #[doc(alias = "modpol")]
    fn modify_policy() {
        unimplemented!();
    }

    /// Delete a policy. Not yet implemented
    #[doc(alias = "delpol")]
    fn delete_policy() {
        unimplemented!();
    }

    /// Retrieve a policy. Not yet implemented
    #[doc(alias = "getpol")]
    fn get_policy() {
        unimplemented!();
    }

    /// List policies
    ///
    /// `query` is a shell-style glob expression that can contain the wild-card characters `?`, `*`,
    /// and `[]`. All policy names matching the expression are returned. If no query is provided,
    /// all existing policy names are returned.
    ///
    /// ```no_run
    /// # use crate::kadmin::{KAdmin, KAdminImpl};
    /// # #[cfg(feature = "client")]
    /// # fn example() {
    /// let kadm = kadmin::KAdmin::builder().with_ccache(None, None).unwrap();
    /// for princ in kadm.list_principals(None).unwrap() {
    ///     println!("{princ}");
    /// }
    /// # }
    /// ```
    #[doc(alias("listpols", "get_policies", "getpols"))]
    fn list_policies(&self, query: Option<&str>) -> Result<Vec<String>>;
}

impl KAdmin {
    /// Construct a new [`KAdminBuilder`]
    pub fn builder() -> KAdminBuilder {
        KAdminBuilder::default()
    }
}

impl KAdminImpl for KAdmin {
    fn add_principal(&self, builder: &PrincipalBuilder) -> Result<()> {
        let mut entry = _kadm5_principal_ent_t::default();
        let mut mask = builder.mask;

        let name = CString::new(builder.name.clone())?;
        let code = unsafe {
            krb5_parse_name(self.context.context, name.as_ptr().cast_mut(), &mut entry.principal)
        };
        krb5_error_code_escape_hatch(&self.context, code)?;

        if let Some(expire_time) = builder.expire_time {
            entry.princ_expire_time = dt_to_ts(expire_time)?;
        }
        if let Some(password_expiration) = builder.password_expiration {
            entry.pw_expiration = dt_to_ts(password_expiration)?;
        }
        if let Some(max_life) = builder.max_life {
            entry.max_life = dur_to_delta(max_life)?;
        }
        if let Some(attributes) = builder.attributes {
            entry.attributes = attributes.bits();
        }
        // TODO: policy
        if let Some(max_renewable_life) = builder.max_renewable_life {
            entry.max_renewable_life = dur_to_delta(max_renewable_life)?;
        }

        let prepare_dummy_pass = || {
            let mut dummy_pass = String::with_capacity(256);
            dummy_pass.push_str("6F a[");
            for i in dummy_pass.len()..=256 {
                dummy_pass.push((b'a' + ((i % 26) as u8)) as char);
            }
            CString::new(dummy_pass)
        };

        let pass = match &builder.key {
            PrincipalBuilderKey::Password(key) => Some(CString::new(key.clone())?),
            PrincipalBuilderKey::NoKey => {
                mask |= KADM5_KEY_DATA as i64;
                None
            },
            PrincipalBuilderKey::RandKey => None,
            PrincipalBuilderKey::ServerRandKey => None,
            PrincipalBuilderKey::OldStyleRandKey => Some(prepare_dummy_pass()?),
        };
        let raw_pass = if let Some(pass) = pass {
            pass.as_ptr().cast_mut()
        } else { null_mut() };

        let code = unsafe {
            kadm5_create_principal(self.server_handle, &mut entry, mask, raw_pass)
        };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(())
    }

    fn get_principal(&self, name: &str) -> Result<Option<Principal>> {
        let mut temp_princ = null_mut();
        let name = CString::new(name)?;
        let code = unsafe {
            krb5_parse_name(
                self.context.context,
                name.as_ptr().cast_mut(),
                &mut temp_princ,
            )
        };
        krb5_error_code_escape_hatch(&self.context, code)?;
        let mut principal_ent = _kadm5_principal_ent_t::default();
        let code = unsafe {
            kadm5_get_principal(
                self.server_handle,
                temp_princ,
                &mut principal_ent,
                KADM5_PRINCIPAL_NORMAL_MASK as i64,
            )
        };
        unsafe {
            krb5_free_principal(self.context.context, temp_princ);
        }
        if code == KADM5_UNK_PRINC as i64 {
            return Ok(None);
        }
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        let principal = Principal::from_raw(self, &principal_ent)?;
        let code = unsafe { kadm5_free_principal_ent(self.server_handle, &mut principal_ent) };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(Some(principal))
    }

    fn principal_change_password(&self, name: &str, password: &str) -> Result<()> {
        let mut temp_princ = null_mut();
        let name = CString::new(name)?;
        let password = CString::new(password)?;
        let code = unsafe {
            krb5_parse_name(
                self.context.context,
                name.as_ptr().cast_mut(),
                &mut temp_princ,
            )
        };
        krb5_error_code_escape_hatch(&self.context, code)?;
        let code = unsafe {
            kadm5_chpass_principal(self.server_handle, temp_princ, password.as_ptr().cast_mut())
        };
        unsafe {
            krb5_free_principal(self.context.context, temp_princ);
        }
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(())
    }

    fn list_principals(&self, query: Option<&str>) -> Result<Vec<String>> {
        let query = CString::new(query.unwrap_or("*"))?;
        let mut count = 0;
        let mut princs: *mut *mut c_char = null_mut();
        let code = unsafe {
            kadm5_get_principals(
                self.server_handle,
                query.as_ptr().cast_mut(),
                &mut princs,
                &mut count,
            )
        };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        let mut result = Vec::with_capacity(count as usize);
        for raw in unsafe { std::slice::from_raw_parts(princs, count as usize) }.iter() {
            result.push(c_string_to_string(*raw)?);
        }
        unsafe {
            kadm5_free_name_list(self.server_handle, princs, count);
        }
        Ok(result)
    }

    fn list_policies(&self, query: Option<&str>) -> Result<Vec<String>> {
        let query = CString::new(query.unwrap_or("*"))?;
        let mut count = 0;
        let mut policies: *mut *mut c_char = null_mut();
        let code = unsafe {
            kadm5_get_policies(
                self.server_handle,
                query.as_ptr().cast_mut(),
                &mut policies,
                &mut count,
            )
        };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
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

/// [`KAdmin`] builder
#[derive(Debug, Default)]
pub struct KAdminBuilder {
    context: Option<Context>,
    params: Option<Params>,
    db_args: Option<DbArgs>,
}

impl KAdminBuilder {
    /// Set the [`Context`] to use for this [`KAdmin`] instance
    pub fn context(mut self, context: Context) -> Self {
        self.context = Some(context);
        self
    }

    /// Provide additional [`Params`] to this [`KAdmin`] instance
    pub fn params(mut self, params: Params) -> Self {
        self.params = Some(params);
        self
    }

    /// Provide additional [`DbArgs`] to this [`KAdmin`] instance
    pub fn db_args(mut self, db_args: DbArgs) -> Self {
        self.db_args = Some(db_args);
        self
    }

    /// Construct a [`KAdmin`] object that isn't initialized yet from the builder inputs
    fn get_kadmin(self) -> Result<(KAdmin, Params, DbArgs)> {
        let params = self.params.unwrap_or_default();
        let db_args = self.db_args.unwrap_or_default();
        let context = self.context.unwrap_or(Context::new()?);
        let kadmin = KAdmin {
            context,
            server_handle: null_mut(),
        };
        Ok((kadmin, params, db_args))
    }

    /// Construct a [`KAdmin`] object from this builder using a client name (usually a principal
    /// name) and a password
    #[cfg(any(feature = "client", doc))]
    #[cfg_attr(docsrs, doc(cfg(feature = "client")))]
    pub fn with_password(self, client_name: &str, password: &str) -> Result<KAdmin> {
        let _guard = KADMIN_INIT_LOCK
            .lock()
            .expect("Failed to lock context initialization.");

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

        drop(_guard);

        kadm5_ret_t_escape_hatch(&kadmin.context, code)?;

        Ok(kadmin)
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
        let _guard = KADMIN_INIT_LOCK
            .lock()
            .expect("Failed to lock context initialization.");

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
            let code =
                unsafe { krb5_unparse_name(kadmin.context.context, princ, &mut raw_client_name) };
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

        drop(_guard);

        kadm5_ret_t_escape_hatch(&kadmin.context, code)?;

        Ok(kadmin)
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
        let _guard = KADMIN_INIT_LOCK
            .lock()
            .expect("Failed to lock context initialization.");

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
            let code = unsafe {
                krb5_cc_get_principal(kadmin.context.context, ccache, princ_ptr.as_mut_ptr())
            };
            krb5_error_code_escape_hatch(&kadmin.context, code)?;
            let princ = unsafe { princ_ptr.assume_init() };
            let mut raw_client_name: *mut c_char = null_mut();
            let code =
                unsafe { krb5_unparse_name(kadmin.context.context, princ, &mut raw_client_name) };
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

        drop(_guard);

        kadm5_ret_t_escape_hatch(&kadmin.context, code)?;

        Ok(kadmin)
    }

    /// Not implemented
    #[cfg(any(feature = "client", doc))]
    #[cfg_attr(docsrs, doc(cfg(feature = "client")))]
    pub fn with_anonymous(self, _client_name: &str) -> Result<KAdmin> {
        let _guard = KADMIN_INIT_LOCK
            .lock()
            .expect("Failed to lock context initialization.");

        let (mut _kadmin, _params, _db_args) = self.get_kadmin()?;

        unimplemented!();
    }

    /// Construct a [`KAdmin`] object from this builder for local database manipulation.
    #[cfg(any(feature = "local", doc))]
    #[cfg_attr(docsrs, doc(cfg(feature = "local")))]
    pub fn with_local(self) -> Result<KAdmin> {
        let _guard = KADMIN_INIT_LOCK
            .lock()
            .expect("Failed to lock context initialization.");

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

        drop(_guard);

        kadm5_ret_t_escape_hatch(&kadmin.context, code)?;

        Ok(kadmin)
    }
}

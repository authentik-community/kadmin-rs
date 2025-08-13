//! [`KAdmin`] interface to kadm5

use std::{
    collections::HashMap,
    ffi::{CString, c_int},
    os::raw::{c_char, c_long, c_void},
    ptr::{null, null_mut},
    sync::Mutex,
};
#[cfg(feature = "client")]
use std::{ffi::CStr, mem::MaybeUninit};

use bitflags::bitflags;
use kadmin_sys::*;
use libc::EINVAL;
#[cfg(feature = "python")]
use pyo3::prelude::*;

use crate::{
    KeyData,
    context::Context,
    conv::{c_string_to_string, parse_name},
    db_args::DbArgs,
    error::{Result, kadm5_ret_t_escape_hatch, krb5_error_code_escape_hatch},
    keysalt::KeySalts,
    params::Params,
    policy::{Policy, PolicyBuilder, PolicyModifier},
    principal::{Principal, PrincipalBuilder, PrincipalBuilderKey, PrincipalModifier},
};

/// Lock acquired when creating or dropping a [`KAdmin`] instance
static KADMIN_INIT_LOCK: Mutex<()> = Mutex::new(());

/// kadm5 API version
///
/// MIT krb5 supports up to version 4. Heimdal supports up to version 2.
///
/// This changes which fields will be available in the [`Policy`] and [`Principal`] structs. If the
/// version is too low, some fields may not be populated. We try our best to document those in the
/// fields documentation themselves.
///
/// If no version is provided during the KAdmin initialization, it defaults to the most
/// conservative one, currently version 2.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[allow(clippy::exhaustive_enums)]
#[repr(u32)]
#[cfg_attr(feature = "python", pyclass(eq, eq_int))]
pub enum KAdminApiVersion {
    /// Version 2
    Version2 = KADM5_API_VERSION_2,
    /// Version 3
    Version3 = KADM5_API_VERSION_3,
    /// Version 4
    Version4 = KADM5_API_VERSION_4,
}

impl From<KAdminApiVersion> for krb5_ui_4 {
    fn from(api_version: KAdminApiVersion) -> Self {
        api_version as Self
    }
}

impl Default for KAdminApiVersion {
    fn default() -> Self {
        Self::Version2
    }
}

/// KAdmin privileges
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
#[cfg_attr(feature = "python", pyclass(eq))]
pub struct KAdminPrivileges(c_long);

bitflags! {
    impl KAdminPrivileges: c_long {
        /// Inquire privilege
        const Inquire = KADM5_PRIV_GET as c_long;
        /// Add privilege
        const Add = KADM5_PRIV_ADD as c_long;
        /// Modify privilege
        const Modify = KADM5_PRIV_MODIFY as c_long;
        /// Delete privilege
        const Delete = KADM5_PRIV_DELETE as c_long;

        const _ = !0;
    }
}

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
    /// Create a principal
    ///
    /// Don't use this method directly. Instead, use a [`PrincipalBuilder`], via
    /// [`Principal::builder`]
    #[doc(alias("ank", "addprinc"))]
    fn add_principal(&self, builder: &PrincipalBuilder) -> Result<()>;

    /// Modify a principal
    ///
    /// Don't use this method directly. Instead, use a [`PrincipalModifier`], via
    /// [`Principal::modifier`]
    #[doc(alias = "modprinc")]
    fn modify_principal(&self, modifier: &PrincipalModifier) -> Result<()>;

    /// Rename a principal
    ///
    /// ```no_run
    /// # use crate::kadmin::{KAdmin, KAdminImpl};
    /// # #[cfg(feature = "client")]
    /// # fn example() {
    /// let kadm = kadmin::KAdmin::builder().with_ccache(None, None).unwrap();
    /// kadm.rename_principal("old@EXAMPLE.ORG", "new@EXAMPLE.ORG")
    ///     .unwrap();
    /// # }
    /// ```
    #[doc(alias = "renprinc")]
    fn rename_principal(&self, old_name: &str, new_name: &str) -> Result<()>;

    /// Delete a principal
    ///
    /// [`Principal::delete`] is also available
    #[doc(alias = "delprinc")]
    fn delete_principal(&self, name: &str) -> Result<()>;

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
    /// * `keepold`: Keeps the existing keys in the database. This flag is usually not necessary
    ///   except perhaps for krbtgt principals. Defaults to false
    /// * `keysalts`: Uses the specified keysalt list for setting the keys of the principal
    ///
    /// Don't use this method directly. Instead, prefer [`Principal::change_password`]
    #[doc(alias = "cpw")]
    fn principal_change_password(
        &self,
        name: &str,
        password: &str,
        keepold: Option<bool>,
        keysalts: Option<&KeySalts>,
    ) -> Result<()>;

    /// Sets the key of the principal to a random value
    ///
    /// * `keepold`: Keeps the existing keys in the database. This flag is usually not necessary
    ///   except perhaps for krbtgt principals. Defaults to false
    /// * `keysalts`: Uses the specified keysalt list for setting the keys of the principal
    ///
    /// [`Principal::randkey`] is also available
    // TODO: add returning newly created keys
    #[doc(alias = "randkey")]
    fn principal_randkey(
        &self,
        name: &str,
        keepold: Option<bool>,
        keysalts: Option<&KeySalts>,
    ) -> Result<()>;

    /// Retrieve string attributes on a principal
    ///
    /// [`Principal::get_strings`] is also available
    fn principal_get_strings(&self, name: &str) -> Result<HashMap<String, String>>;

    /// Set string attribute on a principal
    ///
    /// Set `value` to None to remove the string
    ///
    /// [`Principal::set_string`] is also available
    fn principal_set_string(&self, name: &str, key: &str, value: Option<&str>) -> Result<()>;

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

    /// Add a policy
    ///
    /// Don't use this method directly. Instead, use a [`PolicyBuilder`], via [`Policy::builder`]
    #[doc(alias = "addpol")]
    fn add_policy(&self, builder: &PolicyBuilder) -> Result<()>;

    /// Modify a policy
    ///
    /// Don't use this method directly. Instead, use a [`PolicyModifier`], via [`Policy::modifier`]
    #[doc(alias = "modpol")]
    fn modify_policy(&self, modifier: &PolicyModifier) -> Result<()>;

    /// Delete a policy
    ///
    /// [`Policy::delete`] is also available
    #[doc(alias = "delpol")]
    fn delete_policy(&self, name: &str) -> Result<()>;

    /// Retrieve a policy
    ///
    /// ```no_run
    /// # use crate::kadmin::{KAdmin, KAdminImpl};
    /// # #[cfg(feature = "client")]
    /// # fn example() {
    /// let kadm = kadmin::KAdmin::builder().with_ccache(None, None).unwrap();
    /// let polname = String::from("mypol");
    /// let policy = kadm.get_policy(&polname).unwrap();
    /// assert!(policy.is_some());
    /// # }
    /// ```
    #[doc(alias = "getpol")]
    fn get_policy(&self, name: &str) -> Result<Option<Policy>>;

    /// Check if a policy exists
    ///
    /// ```no_run
    /// # use crate::kadmin::{KAdmin, KAdminImpl};
    /// # #[cfg(feature = "client")]
    /// # fn example() {
    /// let kadm = kadmin::KAdmin::builder().with_ccache(None, None).unwrap();
    /// let polname = String::from("mypol");
    /// assert!(kadm.policy_exists(&polname).unwrap());
    /// # }
    /// ```
    fn policy_exists(&self, name: &str) -> Result<bool> {
        Ok(self.get_policy(name)?.is_some())
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

    /// Get current privileges
    fn get_privileges(&self) -> Result<KAdminPrivileges>;
}

impl KAdmin {
    /// Construct a new [`KAdminBuilder`]
    pub fn builder() -> KAdminBuilder {
        KAdminBuilder::default()
    }

    /// TODO
    pub fn principal_get_keys(&self, name: &str) -> Result<()> {
        let princ = parse_name(&self.context, name)?;
        let mut key_data = null_mut();
        let mut n_key_data = 0;
        let code = unsafe {
            kadm5_get_principal_keys(
                self.server_handle,
                princ.raw,
                1,
                &mut key_data,
                &mut n_key_data,
            )
        };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        // TODO: check null
        unsafe { dbg!(key_data) };
        unsafe { dbg!(*key_data) };
        let kd = KeyData::from_raw(n_key_data, key_data)?;
        dbg!(kd);
        Ok(())
    }
}

impl KAdminImpl for KAdmin {
    fn add_principal(&self, builder: &PrincipalBuilder) -> Result<()> {
        let mut entry = builder.make_entry(&self.context)?;
        let mut mask = builder.mask;
        if let Some(kvno) = builder.kvno {
            entry.raw.kvno = kvno;
        }

        if let Some(policy) = &builder.policy {
            if policy.is_none() {
                mask &= !(KADM5_POLICY_CLR as c_long);
            }
        }

        let prepare_dummy_pass = || {
            let mut dummy_pass = String::with_capacity(256);
            dummy_pass.push_str("6F a[");
            for i in dummy_pass.len()..=256 {
                dummy_pass.push((b'a' + ((i % 26) as u8)) as char);
            }
            CString::new(dummy_pass)
        };

        let mut old_style_randkey = false;

        let pass = match &builder.key {
            PrincipalBuilderKey::Password(key) => Some(CString::new(key.clone())?),
            PrincipalBuilderKey::NoKey => {
                mask |= KADM5_KEY_DATA as c_long;
                None
            }
            PrincipalBuilderKey::RandKey => None,
            PrincipalBuilderKey::ServerRandKey => None,
            PrincipalBuilderKey::OldStyleRandKey => Some(prepare_dummy_pass()?),
        };
        let raw_pass = if let Some(pass) = pass {
            pass.as_ptr().cast_mut()
        } else {
            null_mut()
        };

        if builder.key == PrincipalBuilderKey::OldStyleRandKey {
            entry.raw.attributes |= KRB5_KDB_DISALLOW_ALL_TIX as krb5_flags;
            mask |= KADM5_ATTRIBUTES as c_long;
            old_style_randkey = true;
        }

        let mut keysalts = builder.keysalts.as_ref().map(|ks| ks.to_raw());
        let (n_ks_tuple, ks_tuple) = if let Some(ref mut keysalts) = keysalts {
            (keysalts.len() as c_int, keysalts.as_mut_ptr())
        } else {
            (0, null_mut())
        };

        mask |= KADM5_PRINCIPAL as c_long;
        let code = if keysalts.is_none() {
            unsafe { kadm5_create_principal(self.server_handle, &mut entry.raw, mask, raw_pass) }
        } else {
            unsafe {
                kadm5_create_principal_3(
                    self.server_handle,
                    &mut entry.raw,
                    mask,
                    n_ks_tuple,
                    ks_tuple,
                    raw_pass,
                )
            }
        };
        let code = if code == EINVAL as kadm5_ret_t && builder.key == PrincipalBuilderKey::RandKey {
            let pass = prepare_dummy_pass()?;
            let raw_pass = pass.as_ptr().cast_mut();
            // The server doesn't support randkey creation. Create the principal with a dummy
            // password and disallow tickets.
            entry.raw.attributes |= KRB5_KDB_DISALLOW_ALL_TIX as krb5_flags;
            mask |= KADM5_ATTRIBUTES as c_long;
            old_style_randkey = true;
            if keysalts.is_none() {
                unsafe {
                    kadm5_create_principal(self.server_handle, &mut entry.raw, mask, raw_pass)
                }
            } else {
                unsafe {
                    kadm5_create_principal_3(
                        self.server_handle,
                        &mut entry.raw,
                        mask,
                        n_ks_tuple,
                        ks_tuple,
                        raw_pass,
                    )
                }
            }
        } else {
            code
        };
        kadm5_ret_t_escape_hatch(&self.context, code)?;

        if old_style_randkey {
            self.principal_randkey(&builder.name, None, builder.keysalts.as_ref())?;
            entry.raw.attributes &= !(KRB5_KDB_DISALLOW_ALL_TIX as krb5_flags);
            mask = KADM5_ATTRIBUTES as c_long;
            let code = unsafe { kadm5_modify_principal(self.server_handle, &mut entry.raw, mask) };
            kadm5_ret_t_escape_hatch(&self.context, code)?;
        }

        Ok(())
    }

    fn modify_principal(&self, modifier: &PrincipalModifier) -> Result<()> {
        let mut entry = modifier.make_entry(&self.context)?;
        let code =
            unsafe { kadm5_modify_principal(self.server_handle, &mut entry.raw, modifier.mask) };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(())
    }

    fn rename_principal(&self, old_name: &str, new_name: &str) -> Result<()> {
        let old_princ = parse_name(&self.context, old_name)?;
        let new_princ = parse_name(&self.context, new_name)?;
        let code =
            unsafe { kadm5_rename_principal(self.server_handle, old_princ.raw, new_princ.raw) };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(())
    }

    fn delete_principal(&self, name: &str) -> Result<()> {
        let princ = parse_name(&self.context, name)?;
        let code = unsafe { kadm5_delete_principal(self.server_handle, princ.raw) };
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
        let mut canon = null_mut();
        let code = unsafe { krb5_unparse_name(self.context.context, temp_princ, &mut canon) };
        krb5_error_code_escape_hatch(&self.context, code)?;
        let mut principal_ent = _kadm5_principal_ent_t::default();
        let code = unsafe {
            kadm5_get_principal(
                self.server_handle,
                temp_princ,
                &mut principal_ent,
                (KADM5_PRINCIPAL_NORMAL_MASK | KADM5_KEY_DATA | KADM5_TL_DATA) as c_long,
            )
        };
        unsafe {
            krb5_free_principal(self.context.context, temp_princ);
        }
        if code == KADM5_UNK_PRINC as kadm5_ret_t {
            return Ok(None);
        }
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        let principal = Principal::from_raw(self, &principal_ent)?;
        let code = unsafe { kadm5_free_principal_ent(self.server_handle, &mut principal_ent) };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(Some(principal))
    }

    fn principal_change_password(
        &self,
        name: &str,
        password: &str,
        keepold: Option<bool>,
        keysalts: Option<&KeySalts>,
    ) -> Result<()> {
        let password = CString::new(password)?;
        let princ = parse_name(&self.context, name)?;

        let keepold = keepold.unwrap_or(false);
        let mut keysalts = keysalts.map(|ks| ks.to_raw());
        let (n_ks_tuple, ks_tuple) = if let Some(ref mut keysalts) = keysalts {
            (keysalts.len() as c_int, keysalts.as_mut_ptr())
        } else {
            (0, null_mut())
        };

        let code = if keepold || keysalts.is_some() {
            unsafe {
                kadm5_chpass_principal_3(
                    self.server_handle,
                    princ.raw,
                    keepold as krb5_boolean,
                    n_ks_tuple,
                    ks_tuple,
                    password.as_ptr().cast_mut(),
                )
            }
        } else {
            unsafe {
                kadm5_chpass_principal(self.server_handle, princ.raw, password.as_ptr().cast_mut())
            }
        };
        kadm5_ret_t_escape_hatch(&self.context, code)?;

        Ok(())
    }

    fn principal_randkey(
        &self,
        name: &str,
        keepold: Option<bool>,
        keysalts: Option<&KeySalts>,
    ) -> Result<()> {
        let princ = parse_name(&self.context, name)?;
        let keepold = keepold.unwrap_or(false);

        let mut keysalts = keysalts.map(|ks| ks.to_raw());
        let (n_ks_tuple, ks_tuple) = if let Some(ref mut keysalts) = keysalts {
            (keysalts.len() as c_int, keysalts.as_mut_ptr())
        } else {
            (0, null_mut())
        };

        let code = unsafe {
            kadm5_randkey_principal_3(
                self.server_handle,
                princ.raw,
                keepold as krb5_boolean,
                n_ks_tuple,
                ks_tuple,
                null_mut(),
                null_mut(),
            )
        };

        let code = if code == KADM5_RPC_ERROR as kadm5_ret_t && !keepold && keysalts.is_none() {
            unsafe {
                kadm5_randkey_principal(self.server_handle, princ.raw, null_mut(), null_mut())
            }
        } else {
            code
        };

        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(())
    }

    fn principal_get_strings(&self, name: &str) -> Result<HashMap<String, String>> {
        let princ = parse_name(&self.context, name)?;

        let mut count = 0;
        let mut raw_strings = null_mut();

        let code = unsafe {
            kadm5_get_strings(self.server_handle, princ.raw, &mut raw_strings, &mut count)
        };
        kadm5_ret_t_escape_hatch(&self.context, code)?;

        let mut strings = HashMap::with_capacity(count as usize);

        if raw_strings.is_null() {
            return Ok(strings);
        }

        for raw in unsafe { std::slice::from_raw_parts(raw_strings, count as usize) }.iter() {
            strings.insert(c_string_to_string(raw.key)?, c_string_to_string(raw.value)?);
        }

        unsafe {
            kadm5_free_strings(self.server_handle, raw_strings, count);
        }

        Ok(strings)
    }

    fn principal_set_string(&self, name: &str, key: &str, value: Option<&str>) -> Result<()> {
        let princ = parse_name(&self.context, name)?;
        let key = CString::new(key)?;
        let value = value.map(CString::new).transpose()?;

        let code = unsafe {
            kadm5_set_string(
                self.server_handle,
                princ.raw,
                key.as_ptr(),
                if let Some(value) = &value {
                    value.as_ptr()
                } else {
                    null()
                },
            )
        };
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
        if count == 0 {
            return Ok(result);
        }
        for raw in unsafe { std::slice::from_raw_parts(princs, count as usize) }.iter() {
            result.push(c_string_to_string(*raw)?);
        }
        unsafe {
            kadm5_free_name_list(self.server_handle, princs, count);
        }
        Ok(result)
    }

    fn add_policy(&self, builder: &PolicyBuilder) -> Result<()> {
        let mut entry = builder.make_entry()?;
        let mask = builder.mask | KADM5_POLICY as c_long;
        let code = unsafe { kadm5_create_policy(self.server_handle, &mut entry.raw, mask) };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(())
    }

    fn modify_policy(&self, modifier: &PolicyModifier) -> Result<()> {
        let mut entry = modifier.make_entry()?;
        let code =
            unsafe { kadm5_modify_policy(self.server_handle, &mut entry.raw, modifier.mask) };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(())
    }

    fn delete_policy(&self, name: &str) -> Result<()> {
        let name = CString::new(name)?;
        let code = unsafe { kadm5_delete_policy(self.server_handle, name.as_ptr().cast_mut()) };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(())
    }

    fn get_policy(&self, name: &str) -> Result<Option<Policy>> {
        let name = CString::new(name)?;
        let mut policy_ent = _kadm5_policy_ent_t::default();
        let code = unsafe {
            kadm5_get_policy(
                self.server_handle,
                name.as_ptr().cast_mut(),
                &mut policy_ent,
            )
        };
        if code == KADM5_UNK_POLICY as kadm5_ret_t {
            return Ok(None);
        }
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        let policy = Policy::from_raw(&policy_ent)?;
        let code = unsafe { kadm5_free_policy_ent(self.server_handle, &mut policy_ent) };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(Some(policy))
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
        if count == 0 {
            return Ok(result);
        }
        for raw in unsafe { std::slice::from_raw_parts(policies, count as usize) }.iter() {
            result.push(c_string_to_string(*raw)?);
        }
        unsafe {
            kadm5_free_name_list(self.server_handle, policies, count);
        }
        Ok(result)
    }

    fn get_privileges(&self) -> Result<KAdminPrivileges> {
        let mut privs = 0;
        let code = unsafe { kadm5_get_privs(self.server_handle, &mut privs) };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(KAdminPrivileges::from_bits_retain(privs))
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
    api_version: KAdminApiVersion,
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

    /// Set the kadm5 API version to use. See [`KAdminApiVersion`] for details
    pub fn api_version(mut self, api_version: KAdminApiVersion) -> Self {
        self.api_version = api_version;
        self
    }

    /// Construct a [`KAdmin`] object that isn't initialized yet from the builder inputs
    fn get_kadmin(self) -> Result<(KAdmin, Params, DbArgs, KAdminApiVersion)> {
        let params = self.params.unwrap_or_default();
        let db_args = self.db_args.unwrap_or_default();
        let context = self.context.unwrap_or(Context::new()?);
        let api_version = self.api_version;
        let kadmin = KAdmin {
            context,
            server_handle: null_mut(),
        };
        Ok((kadmin, params, db_args, api_version))
    }

    /// Construct a [`KAdmin`] object from this builder using a client name (usually a principal
    /// name) and a password
    #[cfg(any(feature = "client", doc))]
    #[cfg_attr(docsrs, doc(cfg(feature = "client")))]
    pub fn with_password(self, client_name: &str, password: &str) -> Result<KAdmin> {
        let _guard = KADMIN_INIT_LOCK
            .lock()
            .expect("Failed to lock context initialization.");

        let (mut kadmin, params, db_args, api_version) = self.get_kadmin()?;

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
                api_version.into(),
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

        let (mut kadmin, params, db_args, api_version) = self.get_kadmin()?;

        let client_name = if let Some(client_name) = client_name {
            CString::new(client_name)?
        } else {
            let mut princ_ptr: MaybeUninit<krb5_principal> = MaybeUninit::zeroed();
            let code = unsafe {
                krb5_sname_to_principal(
                    kadmin.context.context,
                    null_mut(),
                    CString::new("host")?.as_ptr().cast_mut(),
                    KRB5_NT_SRV_HST as krb5_int32,
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
                api_version.into(),
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

        let (mut kadmin, params, db_args, api_version) = self.get_kadmin()?;

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
                api_version.into(),
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

        let (mut _kadmin, _params, _db_args, _api_version) = self.get_kadmin()?;

        unimplemented!();
    }

    /// Construct a [`KAdmin`] object from this builder for local database manipulation.
    #[cfg(any(feature = "local", doc))]
    #[cfg_attr(docsrs, doc(cfg(feature = "local")))]
    pub fn with_local(self) -> Result<KAdmin> {
        let _guard = KADMIN_INIT_LOCK
            .lock()
            .expect("Failed to lock context initialization.");

        let (mut kadmin, params, db_args, api_version) = self.get_kadmin()?;

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
                api_version.into(),
                db_args.db_args,
                &mut kadmin.server_handle,
            )
        };

        drop(_guard);

        kadm5_ret_t_escape_hatch(&kadmin.context, code)?;

        Ok(kadmin)
    }
}

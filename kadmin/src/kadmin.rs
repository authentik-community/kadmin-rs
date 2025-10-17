//! [`KAdmin`] interface to kadm5

use std::{
    collections::HashMap,
    ffi::{CString, c_void},
    mem::MaybeUninit,
    ptr::{null, null_mut},
    sync::Mutex,
};

use bitflags::bitflags;
use libc::EINVAL;
#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(heimdal)]
use crate::conv::unparse_name_heimdal;
#[cfg(heimdal)]
use crate::sys::heimdal::{
    KADM5_PRIV_ADD, KADM5_PRIV_CPW, KADM5_PRIV_DELETE, KADM5_PRIV_GET, KADM5_PRIV_GET_KEYS,
    KADM5_PRIV_LIST, KADM5_PRIV_MODIFY,
};
#[cfg(all(mit, not(heimdal)))]
use crate::sys::mit::{KADM5_PRIV_ADD, KADM5_PRIV_DELETE, KADM5_PRIV_GET, KADM5_PRIV_MODIFY};
use crate::{
    context::Context,
    conv::{c_string_to_string, parse_name},
    db_args::DbArgs,
    error::{Error, Result, kadm5_ret_t_escape_hatch, krb5_error_code_escape_hatch},
    keysalt::KeySalts,
    params::{Params, ParamsGuard},
    principal::{Principal, PrincipalBuilder, PrincipalBuilderKey, PrincipalModifier},
    sys::{self, KAdm5Variant, Library},
};
#[cfg(mit)]
use crate::{
    conv::unparse_name_mit,
    policy::{Policy, PolicyBuilder, PolicyModifier},
};

/// Lock acquired when creating or dropping a [`KAdmin`] instance
pub static KADMIN_INIT_LOCK: Mutex<()> = Mutex::new(());

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
#[cfg_attr(feature = "python", pyclass(eq, eq_int))]
pub enum KAdminApiVersion {
    /// Version 2
    Version2,
    /// Version 3, only usable with MIT kadm5
    #[cfg(mit)]
    Version3,
    /// Version 4, only usable with MIT kadm5
    #[cfg(mit)]
    Version4,
}

impl Default for KAdminApiVersion {
    fn default() -> Self {
        Self::Version2
    }
}

impl KAdminApiVersion {
    fn to_raw(self, variant: KAdm5Variant) -> Result<u32> {
        match self {
            Self::Version2 => match variant {
                #[cfg(mit)]
                KAdm5Variant::MitClient | KAdm5Variant::MitServer => {
                    Ok(sys::mit::KADM5_API_VERSION_2)
                }
                #[cfg(heimdal)]
                KAdm5Variant::HeimdalClient | KAdm5Variant::HeimdalServer => {
                    Ok(sys::heimdal::KADM5_API_VERSION_2)
                }
            },
            #[cfg(mit)]
            Self::Version3 => match variant {
                #[cfg(mit)]
                KAdm5Variant::MitClient | KAdm5Variant::MitServer => {
                    Ok(sys::mit::KADM5_API_VERSION_2)
                }
                _ => Err(Error::LibraryMismatch(
                    "Version 3 is only available for MIT kadm5",
                )),
            },
            #[cfg(mit)]
            Self::Version4 => match variant {
                #[cfg(mit)]
                KAdm5Variant::MitClient | KAdm5Variant::MitServer => {
                    Ok(sys::mit::KADM5_API_VERSION_2)
                }
                _ => Err(Error::LibraryMismatch(
                    "Version 3 is only available for MIT kadm5",
                )),
            },
        }
    }
}

/// KAdmin privileges
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
#[cfg_attr(feature = "python", pyclass(eq))]
pub struct KAdminPrivileges(i64);

bitflags! {
    impl KAdminPrivileges: i64 {
        /// Inquire privilege
        const Inquire = KADM5_PRIV_GET as i64;
        /// Add privilege
        const Add = KADM5_PRIV_ADD as i64;
        /// Modify privilege
        const Modify = KADM5_PRIV_MODIFY as i64;
        /// Delete privilege
        const Delete = KADM5_PRIV_DELETE as i64;
        #[cfg(heimdal)]
        /// List privilege
        const List = KADM5_PRIV_LIST as i64;
        #[cfg(heimdal)]
        /// Change password privilege
        const ChangePassword = KADM5_PRIV_CPW as i64;
        #[cfg(heimdal)]
        /// Get keys privilege
        const GetKeys = KADM5_PRIV_GET_KEYS as i64;

        const _ = !0;
    }
}

/// Interface to kadm5
///
/// This interface is not thread safe. Consider creating one per thread where needed, or using the
/// [`sync::KAdmin`][`crate::sync::KAdmin`] interface that is thread safe.
pub struct KAdmin {
    /// Kerberos context
    pub(crate) context: Context,
    /// Server handle for kadm5
    pub(crate) server_handle: *mut c_void,
}

/// Common methods for `KAdmin` implementations
pub trait KAdminImpl {
    /// Retrieve the kadm5 variant used
    fn variant(&self) -> KAdm5Variant;

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

    #[cfg(mit)]
    /// Retrieve string attributes on a principal
    ///
    /// [`Principal::get_strings`] is also available
    fn principal_get_strings(&self, name: &str) -> Result<HashMap<String, String>>;

    #[cfg(mit)]
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
    /// # fn example() {
    /// let kadm = kadmin::KAdmin::builder().with_ccache(None, None).unwrap();
    /// for princ in kadm.list_principals(None).unwrap() {
    ///     println!("{princ}");
    /// }
    /// # }
    /// ```
    #[doc(alias("listprincs", "get_principals", "getprincs"))]
    fn list_principals(&self, query: Option<&str>) -> Result<Vec<String>>;

    #[cfg(mit)]
    /// Add a policy
    ///
    /// Don't use this method directly. Instead, use a [`PolicyBuilder`], via [`Policy::builder`]
    #[doc(alias = "addpol")]
    fn add_policy(&self, builder: &PolicyBuilder) -> Result<()>;

    #[cfg(mit)]
    /// Modify a policy
    ///
    /// Don't use this method directly. Instead, use a [`PolicyModifier`], via
    /// [`Policy::modifier`] #[doc(alias = "modpol")]
    fn modify_policy(&self, modifier: &PolicyModifier) -> Result<()>;

    #[cfg(mit)]
    /// Delete a policy
    ///
    /// [`Policy::delete`] is also available
    #[doc(alias = "delpol")]
    fn delete_policy(&self, name: &str) -> Result<()>;

    #[cfg(mit)]
    /// Retrieve a policy
    ///
    /// ```no_run
    /// # use crate::kadmin::{KAdmin, KAdminImpl};
    /// # fn example() {
    /// let kadm = kadmin::KAdmin::builder().with_ccache(None, None).unwrap();
    /// let polname = String::from("mypol");
    /// let policy = kadm.get_policy(&polname).unwrap();
    /// assert!(policy.is_some());
    /// # }
    /// ```
    #[doc(alias = "getpol")]
    fn get_policy(&self, name: &str) -> Result<Option<Policy>>;

    #[cfg(mit)]
    /// Check if a policy exists
    ///
    /// ```no_run
    /// # use crate::kadmin::{KAdmin, KAdminImpl};
    /// # fn example() {
    /// let kadm = kadmin::KAdmin::builder().with_ccache(None, None).unwrap();
    /// let polname = String::from("mypol");
    /// assert!(kadm.policy_exists(&polname).unwrap());
    /// # }
    /// ```
    fn policy_exists(&self, name: &str) -> Result<bool> {
        Ok(self.get_policy(name)?.is_some())
    }

    #[cfg(mit)]
    /// List policies
    ///
    /// `query` is a shell-style glob expression that can contain the wild-card characters `?`, `*`,
    /// and `[]`. All policy names matching the expression are returned. If no query is provided,
    /// all existing policy names are returned.
    ///
    /// ```no_run
    /// # use crate::kadmin::{KAdmin, KAdminImpl};
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
    pub fn builder(variant: KAdm5Variant) -> KAdminBuilder {
        KAdminBuilder::new(variant)
    }
}

impl KAdminImpl for KAdmin {
    fn variant(&self) -> KAdm5Variant {
        self.context.library.variant()
    }

    fn add_principal(&self, builder: &PrincipalBuilder) -> Result<()> {
        #[cfg(mit)]
        let mut mask_mit = builder.mask_mit;
        #[cfg(heimdal)]
        let mut mask_heimdal = builder.mask_heimdal;

        if let Some(policy) = &builder.policy {
            if policy.is_none() {
                match &self.context.library {
                    #[cfg(mit)]
                    Library::MitClient(_) | Library::MitServer(_) => {
                        mask_mit &= !(sys::mit::KADM5_POLICY_CLR as i64);
                    }
                    #[cfg(heimdal)]
                    Library::HeimdalClient(_) | Library::HeimdalServer(_) => {
                        mask_heimdal &= !sys::heimdal::KADM5_POLICY_CLR;
                    }
                };
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
                match &self.context.library {
                    #[cfg(mit)]
                    Library::MitClient(_) | Library::MitServer(_) => {
                        mask_mit &= !(sys::mit::KADM5_KEY_DATA as i64);
                    }
                    #[cfg(heimdal)]
                    Library::HeimdalClient(_) | Library::HeimdalServer(_) => {
                        mask_heimdal &= !sys::heimdal::KADM5_KEY_DATA;
                    }
                };
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

        match &self.context.library {
            #[cfg(mit)]
            Library::MitClient(cont) | Library::MitServer(cont) => {
                let mut entry = builder.make_entry_mit(&self.context)?;
                if let Some(kvno) = builder.kvno {
                    entry.raw.kvno = kvno;
                }

                if builder.key == PrincipalBuilderKey::OldStyleRandKey {
                    entry.raw.attributes |= sys::mit::KRB5_KDB_DISALLOW_ALL_TIX as i32;
                    mask_mit |= sys::mit::KADM5_ATTRIBUTES as i64;
                    old_style_randkey = true;
                }

                let mut keysalts = builder.keysalts.as_ref().map(|ks| ks.to_raw_mit());
                let (n_ks_tuple, ks_tuple) = if let Some(ref mut keysalts) = keysalts {
                    (keysalts.len() as i32, keysalts.as_mut_ptr())
                } else {
                    (0, null_mut())
                };

                mask_mit |= sys::mit::KADM5_PRINCIPAL as i64;
                let code = if keysalts.is_none() {
                    unsafe {
                        cont.kadm5_create_principal(
                            self.server_handle,
                            &mut entry.raw,
                            mask_mit,
                            raw_pass,
                        )
                    }
                } else {
                    unsafe {
                        cont.kadm5_create_principal_3(
                            self.server_handle,
                            &mut entry.raw,
                            mask_mit,
                            n_ks_tuple,
                            ks_tuple,
                            raw_pass,
                        )
                    }
                };
                let code = if code == EINVAL as i64 && builder.key == PrincipalBuilderKey::RandKey {
                    let pass = prepare_dummy_pass()?;
                    let raw_pass = pass.as_ptr().cast_mut();
                    // The server doesn't support randkey creation. Create the principal with a
                    // dummy password and disallow tickets.
                    entry.raw.attributes |= sys::mit::KRB5_KDB_DISALLOW_ALL_TIX as i32;
                    mask_mit |= sys::mit::KADM5_ATTRIBUTES as i64;
                    old_style_randkey = true;
                    if keysalts.is_none() {
                        unsafe {
                            cont.kadm5_create_principal(
                                self.server_handle,
                                &mut entry.raw,
                                mask_mit,
                                raw_pass,
                            )
                        }
                    } else {
                        unsafe {
                            cont.kadm5_create_principal_3(
                                self.server_handle,
                                &mut entry.raw,
                                mask_mit,
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
                    entry.raw.attributes &= !(sys::mit::KRB5_KDB_DISALLOW_ALL_TIX as i32);
                    mask_mit = sys::mit::KADM5_ATTRIBUTES.into();
                    let code = unsafe {
                        cont.kadm5_modify_principal(self.server_handle, &mut entry.raw, mask_mit)
                    };
                    kadm5_ret_t_escape_hatch(&self.context, code)?;
                }
            }
            #[cfg(heimdal)]
            Library::HeimdalClient(cont) | Library::HeimdalServer(cont) => {
                let mut entry = builder.make_entry_heimdal(&self.context)?;
                if let Some(kvno) = builder.kvno {
                    entry.raw.kvno = kvno as i32;
                }

                if builder.key == PrincipalBuilderKey::OldStyleRandKey {
                    entry.raw.attributes |= sys::heimdal::KRB5_KDB_DISALLOW_ALL_TIX;
                    mask_heimdal |= sys::heimdal::KADM5_ATTRIBUTES;
                    old_style_randkey = true;
                }

                let mut keysalts = builder.keysalts.as_ref().map(|ks| ks.to_raw_heimdal());
                let (n_ks_tuple, ks_tuple) = if let Some(ref mut keysalts) = keysalts {
                    (keysalts.len() as i32, keysalts.as_mut_ptr())
                } else {
                    (0, null_mut())
                };

                mask_heimdal |= sys::heimdal::KADM5_PRINCIPAL;
                let code = if keysalts.is_none() {
                    unsafe {
                        cont.kadm5_create_principal(
                            self.server_handle,
                            &mut entry.raw,
                            mask_heimdal,
                            raw_pass,
                        )
                    }
                } else {
                    unsafe {
                        cont.kadm5_create_principal_3(
                            self.server_handle,
                            &mut entry.raw,
                            mask_heimdal,
                            n_ks_tuple,
                            ks_tuple,
                            raw_pass,
                        )
                    }
                };
                let code = if code == EINVAL && builder.key == PrincipalBuilderKey::RandKey {
                    let pass = prepare_dummy_pass()?;
                    let raw_pass = pass.as_ptr().cast_mut();
                    // The server doesn't support randkey creation. Create the principal with a
                    // dummy password and disallow tickets.
                    entry.raw.attributes |= sys::heimdal::KRB5_KDB_DISALLOW_ALL_TIX;
                    mask_heimdal |= sys::heimdal::KADM5_ATTRIBUTES;
                    old_style_randkey = true;
                    if keysalts.is_none() {
                        unsafe {
                            cont.kadm5_create_principal(
                                self.server_handle,
                                &mut entry.raw,
                                mask_heimdal,
                                raw_pass,
                            )
                        }
                    } else {
                        unsafe {
                            cont.kadm5_create_principal_3(
                                self.server_handle,
                                &mut entry.raw,
                                mask_heimdal,
                                n_ks_tuple,
                                ks_tuple,
                                raw_pass,
                            )
                        }
                    }
                } else {
                    code
                };
                kadm5_ret_t_escape_hatch(&self.context, code.into())?;

                if old_style_randkey {
                    self.principal_randkey(&builder.name, None, builder.keysalts.as_ref())?;
                    entry.raw.attributes &= !sys::heimdal::KRB5_KDB_DISALLOW_ALL_TIX;
                    mask_heimdal = sys::heimdal::KADM5_ATTRIBUTES.into();
                    let code = unsafe {
                        cont.kadm5_modify_principal(
                            self.server_handle,
                            &mut entry.raw,
                            mask_heimdal,
                        )
                    };
                    kadm5_ret_t_escape_hatch(&self.context, code.into())?;
                }
            }
        };

        Ok(())
    }

    fn modify_principal(&self, modifier: &PrincipalModifier) -> Result<()> {
        let code = match &self.context.library {
            #[cfg(mit)]
            Library::MitClient(cont) | Library::MitServer(cont) => {
                let mut entry = modifier.make_entry_mit(&self.context)?;
                unsafe {
                    cont.kadm5_modify_principal(
                        self.server_handle,
                        &mut entry.raw,
                        modifier.mask_mit,
                    )
                }
            }
            #[cfg(heimdal)]
            Library::HeimdalClient(cont) | Library::HeimdalServer(cont) => {
                let mut entry = modifier.make_entry_heimdal(&self.context)?;
                unsafe {
                    cont.kadm5_modify_principal(
                        self.server_handle,
                        &mut entry.raw,
                        modifier.mask_heimdal,
                    )
                }
                .into()
            }
        };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(())
    }

    fn rename_principal(&self, old_name: &str, new_name: &str) -> Result<()> {
        let old_princ = parse_name(&self.context, old_name)?;
        let new_princ = parse_name(&self.context, new_name)?;
        let code = match &self.context.library {
            #[cfg(mit)]
            Library::MitClient(cont) | Library::MitServer(cont) => unsafe {
                cont.kadm5_rename_principal(
                    self.server_handle,
                    old_princ.raw as sys::mit::krb5_principal,
                    new_princ.raw as sys::mit::krb5_principal,
                )
            },
            #[cfg(heimdal)]
            Library::HeimdalClient(cont) | Library::HeimdalServer(cont) => (unsafe {
                cont.kadm5_rename_principal(
                    self.server_handle,
                    old_princ.raw as sys::heimdal::krb5_principal,
                    new_princ.raw as sys::heimdal::krb5_principal,
                )
            })
            .into(),
        };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(())
    }

    fn delete_principal(&self, name: &str) -> Result<()> {
        let princ = parse_name(&self.context, name)?;
        let code = match &self.context.library {
            #[cfg(mit)]
            Library::MitClient(cont) | Library::MitServer(cont) => unsafe {
                cont.kadm5_delete_principal(
                    self.server_handle,
                    princ.raw as sys::mit::krb5_principal,
                )
            },
            #[cfg(heimdal)]
            Library::HeimdalClient(cont) | Library::HeimdalServer(cont) => (unsafe {
                cont.kadm5_delete_principal(
                    self.server_handle,
                    princ.raw as sys::heimdal::krb5_principal,
                )
            })
            .into(),
        };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(())
    }

    fn get_principal(&self, name: &str) -> Result<Option<Principal>> {
        let principal = match &self.context.library {
            #[cfg(mit)]
            Library::MitClient(cont) | Library::MitServer(cont) => {
                let mut temp_princ = null_mut();
                let name = CString::new(name)?;
                let code = unsafe {
                    cont.krb5_parse_name(
                        self.context.context as sys::mit::krb5_context,
                        name.as_ptr().cast_mut(),
                        &mut temp_princ,
                    )
                };
                krb5_error_code_escape_hatch(&self.context, code.into())?;
                let mut canon = null_mut();
                let code = unsafe {
                    cont.krb5_unparse_name(
                        self.context.context as sys::mit::krb5_context,
                        temp_princ,
                        &mut canon,
                    )
                };
                krb5_error_code_escape_hatch(&self.context, code.into())?;
                let mut principal_ent = sys::mit::_kadm5_principal_ent_t::default();
                let code = unsafe {
                    cont.kadm5_get_principal(
                        self.server_handle,
                        temp_princ,
                        &mut principal_ent,
                        (sys::mit::KADM5_PRINCIPAL_NORMAL_MASK
                            | sys::mit::KADM5_KEY_DATA
                            | sys::mit::KADM5_TL_DATA) as i64,
                    )
                };
                unsafe {
                    cont.krb5_free_principal(
                        self.context.context as sys::mit::krb5_context,
                        temp_princ,
                    );
                }
                if code == sys::mit::KADM5_UNK_PRINC as i64 {
                    return Ok(None);
                }
                kadm5_ret_t_escape_hatch(&self.context, code)?;
                let principal = Principal::from_raw_mit(self, &principal_ent)?;
                let code = unsafe {
                    cont.kadm5_free_principal_ent(self.server_handle, &mut principal_ent)
                };
                kadm5_ret_t_escape_hatch(&self.context, code)?;
                principal
            }
            #[cfg(heimdal)]
            Library::HeimdalClient(cont) | Library::HeimdalServer(cont) => {
                let mut temp_princ = null_mut();
                let name = CString::new(name)?;
                let code = unsafe {
                    cont.krb5_parse_name(
                        self.context.context as sys::heimdal::krb5_context,
                        name.as_ptr().cast_mut(),
                        &mut temp_princ,
                    )
                };
                krb5_error_code_escape_hatch(&self.context, code.into())?;
                let mut canon = null_mut();
                let code = unsafe {
                    cont.krb5_unparse_name(
                        self.context.context as sys::heimdal::krb5_context,
                        temp_princ,
                        &mut canon,
                    )
                };
                krb5_error_code_escape_hatch(&self.context, code.into())?;
                let mut principal_ent = sys::heimdal::_kadm5_principal_ent_t::default();
                let code = unsafe {
                    cont.kadm5_get_principal(
                        self.server_handle,
                        temp_princ,
                        &mut principal_ent,
                        sys::heimdal::KADM5_PRINCIPAL_NORMAL_MASK as u32
                            | sys::heimdal::KADM5_TL_DATA,
                    )
                };
                unsafe {
                    cont.krb5_free_principal(
                        self.context.context as sys::heimdal::krb5_context,
                        temp_princ,
                    );
                }
                // TODO: fix this
                // if code == sys::heimdal::KADM5_UNK_PRINC.into() {
                //     return Ok(None);
                // }
                kadm5_ret_t_escape_hatch(&self.context, code.into())?;
                let principal = Principal::from_raw_heimdal(self, &principal_ent)?;
                unsafe { cont.kadm5_free_principal_ent(self.server_handle, &mut principal_ent) };
                principal
            }
        };
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

        let code = if keepold || keysalts.is_some() {
            match &self.context.library {
                #[cfg(mit)]
                Library::MitClient(cont) | Library::MitServer(cont) => {
                    let mut keysalts = keysalts.map(|ks| ks.to_raw_mit());
                    let (n_ks_tuple, ks_tuple) = if let Some(ref mut keysalts) = keysalts {
                        (keysalts.len() as i32, keysalts.as_mut_ptr())
                    } else {
                        (0, null_mut())
                    };
                    unsafe {
                        cont.kadm5_chpass_principal_3(
                            self.server_handle,
                            princ.raw as sys::mit::krb5_principal,
                            keepold.into(),
                            n_ks_tuple,
                            ks_tuple,
                            password.as_ptr().cast_mut(),
                        )
                    }
                }
                #[cfg(heimdal)]
                Library::HeimdalClient(cont) | Library::HeimdalServer(cont) => {
                    let mut keysalts = keysalts.map(|ks| ks.to_raw_heimdal());
                    let (n_ks_tuple, ks_tuple) = if let Some(ref mut keysalts) = keysalts {
                        (keysalts.len() as i32, keysalts.as_mut_ptr())
                    } else {
                        (0, null_mut())
                    };
                    unsafe {
                        cont.kadm5_chpass_principal_3(
                            self.server_handle,
                            princ.raw as sys::heimdal::krb5_principal,
                            keepold.into(),
                            n_ks_tuple,
                            ks_tuple,
                            password.as_ptr().cast_mut(),
                        )
                    }
                    .into()
                }
            }
        } else {
            match &self.context.library {
                #[cfg(mit)]
                Library::MitClient(cont) | Library::MitServer(cont) => unsafe {
                    cont.kadm5_chpass_principal(
                        self.server_handle,
                        princ.raw as sys::mit::krb5_principal,
                        password.as_ptr().cast_mut(),
                    )
                },
                #[cfg(heimdal)]
                Library::HeimdalClient(cont) | Library::HeimdalServer(cont) => unsafe {
                    cont.kadm5_chpass_principal(
                        self.server_handle,
                        princ.raw as sys::heimdal::krb5_principal,
                        password.as_ptr().cast_mut(),
                    )
                }
                .into(),
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

        let code = match &self.context.library {
            #[cfg(mit)]
            Library::MitClient(cont) | Library::MitServer(cont) => {
                let mut keysalts = keysalts.map(|ks| ks.to_raw_mit());
                let (n_ks_tuple, ks_tuple) = if let Some(ref mut keysalts) = keysalts {
                    (keysalts.len() as i32, keysalts.as_mut_ptr())
                } else {
                    (0, null_mut())
                };
                unsafe {
                    cont.kadm5_randkey_principal_3(
                        self.server_handle,
                        princ.raw as sys::mit::krb5_principal,
                        keepold.into(),
                        n_ks_tuple,
                        ks_tuple,
                        null_mut(),
                        null_mut(),
                    )
                }
            }
            #[cfg(heimdal)]
            Library::HeimdalClient(cont) | Library::HeimdalServer(cont) => {
                let mut keysalts = keysalts.map(|ks| ks.to_raw_heimdal());
                let (n_ks_tuple, ks_tuple) = if let Some(ref mut keysalts) = keysalts {
                    (keysalts.len() as i32, keysalts.as_mut_ptr())
                } else {
                    (0, null_mut())
                };
                unsafe {
                    cont.kadm5_randkey_principal_3(
                        self.server_handle,
                        princ.raw as sys::heimdal::krb5_principal,
                        keepold.into(),
                        n_ks_tuple,
                        ks_tuple,
                        null_mut(),
                        null_mut(),
                    )
                }
                .into()
            }
        };

        let rpc_error = match &self.context.library {
            #[cfg(mit)]
            Library::MitClient(_) | Library::MitServer(_) => sys::mit::KADM5_RPC_ERROR,
            #[cfg(heimdal)]
            // Library::HeimdalClient(_) | Library::HeimdalServer(_) =>
            // sys::heimdal::KADM5_RPC_ERROR, TODO: fix this
            Library::HeimdalClient(_) | Library::HeimdalServer(_) => 42,
        };

        let code = if code == rpc_error as i64 && !keepold && keysalts.is_none() {
            match &self.context.library {
                #[cfg(mit)]
                Library::MitClient(cont) | Library::MitServer(cont) => unsafe {
                    cont.kadm5_randkey_principal(
                        self.server_handle,
                        princ.raw as sys::mit::krb5_principal,
                        null_mut(),
                        null_mut(),
                    )
                },
                #[cfg(heimdal)]
                Library::HeimdalClient(cont) | Library::HeimdalServer(cont) => unsafe {
                    cont.kadm5_randkey_principal(
                        self.server_handle,
                        princ.raw as sys::heimdal::krb5_principal,
                        null_mut(),
                        null_mut(),
                    )
                }
                .into(),
            }
        } else {
            code
        };

        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(())
    }

    #[cfg(mit)]
    fn principal_get_strings(&self, name: &str) -> Result<HashMap<String, String>> {
        if !self.context.library.is_mit() {
            return Err(Error::LibraryMismatch(
                "Principal strings are only available on MIT libraries.",
            ));
        }
        let princ = parse_name(&self.context, name)?;

        let mut count = 0;
        let mut raw_strings = null_mut();

        let code = match &self.context.library {
            Library::MitClient(cont) | Library::MitServer(cont) => unsafe {
                cont.kadm5_get_strings(
                    self.server_handle,
                    princ.raw as sys::mit::krb5_principal,
                    &mut raw_strings,
                    &mut count,
                )
            },
            _ => unreachable!(),
        };
        kadm5_ret_t_escape_hatch(&self.context, code)?;

        let mut strings = HashMap::with_capacity(count as usize);

        if raw_strings.is_null() {
            return Ok(strings);
        }

        for raw in unsafe { std::slice::from_raw_parts(raw_strings, count as usize) }.iter() {
            strings.insert(c_string_to_string(raw.key)?, c_string_to_string(raw.value)?);
        }

        match &self.context.library {
            Library::MitClient(cont) | Library::MitServer(cont) => unsafe {
                cont.kadm5_free_strings(self.server_handle, raw_strings, count)
            },
            _ => unreachable!(),
        };

        Ok(strings)
    }

    #[cfg(mit)]
    fn principal_set_string(&self, name: &str, key: &str, value: Option<&str>) -> Result<()> {
        if !self.context.library.is_mit() {
            return Err(Error::LibraryMismatch(
                "Principal strings are only available on MIT libraries.",
            ));
        }

        let princ = parse_name(&self.context, name)?;
        let key = CString::new(key)?;
        let value = value.map(CString::new).transpose()?;

        let code = match &self.context.library {
            Library::MitClient(cont) | Library::MitServer(cont) => unsafe {
                cont.kadm5_set_string(
                    self.server_handle,
                    princ.raw as sys::mit::krb5_principal,
                    key.as_ptr(),
                    if let Some(value) = &value {
                        value.as_ptr()
                    } else {
                        null()
                    },
                )
            },
            _ => unreachable!(),
        };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(())
    }

    fn list_principals(&self, query: Option<&str>) -> Result<Vec<String>> {
        let query = CString::new(query.unwrap_or("*"))?;
        let mut count = 0;
        let mut princs: *mut *mut i8 = null_mut();
        let code = match &self.context.library {
            #[cfg(mit)]
            Library::MitClient(cont) | Library::MitServer(cont) => unsafe {
                cont.kadm5_get_principals(
                    self.server_handle,
                    query.as_ptr().cast_mut(),
                    &mut princs,
                    &mut count,
                )
            },
            #[cfg(heimdal)]
            Library::HeimdalClient(cont) | Library::HeimdalServer(cont) => (unsafe {
                cont.kadm5_get_principals(
                    self.server_handle,
                    query.as_ptr().cast_mut(),
                    &mut princs,
                    &mut count,
                )
            })
            .into(),
        };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        let mut result = Vec::with_capacity(count as usize);
        if count == 0 {
            return Ok(result);
        }
        for raw in unsafe { std::slice::from_raw_parts(princs, count as usize) }.iter() {
            result.push(c_string_to_string(*raw)?);
        }
        match &self.context.library {
            #[cfg(mit)]
            Library::MitClient(cont) | Library::MitServer(cont) => unsafe {
                cont.kadm5_free_name_list(self.server_handle, princs, count);
            },
            #[cfg(heimdal)]
            Library::HeimdalClient(cont) | Library::HeimdalServer(cont) => unsafe {
                cont.kadm5_free_name_list(self.server_handle, princs, &mut count);
            },
        };
        Ok(result)
    }

    #[cfg(mit)]
    fn add_policy(&self, builder: &PolicyBuilder) -> Result<()> {
        if !self.context.library.is_mit() {
            return Err(Error::LibraryMismatch(
                "Policy operations are only available for MIT kadm5",
            ));
        }

        let mut entry = builder.make_entry(&self.context)?;
        let mask = builder.mask | sys::mit::KADM5_POLICY as i64;
        let code = match &self.context.library {
            Library::MitClient(cont) | Library::MitServer(cont) => unsafe {
                cont.kadm5_create_policy(self.server_handle, &mut entry.raw, mask)
            },
            _ => unreachable!(),
        };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(())
    }

    #[cfg(mit)]
    fn modify_policy(&self, modifier: &PolicyModifier) -> Result<()> {
        if !self.context.library.is_mit() {
            return Err(Error::LibraryMismatch(
                "Policy operations are only available for MIT kadm5",
            ));
        }

        let mut entry = modifier.make_entry(&self.context)?;
        let code = match &self.context.library {
            Library::MitClient(cont) | Library::MitServer(cont) => unsafe {
                cont.kadm5_modify_policy(self.server_handle, &mut entry.raw, modifier.mask)
            },
            _ => unreachable!(),
        };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(())
    }

    #[cfg(mit)]
    fn delete_policy(&self, name: &str) -> Result<()> {
        if !self.context.library.is_mit() {
            return Err(Error::LibraryMismatch(
                "Policy operations are only available for MIT kadm5",
            ));
        }

        let name = CString::new(name)?;
        let code = match &self.context.library {
            Library::MitClient(cont) | Library::MitServer(cont) => unsafe {
                cont.kadm5_delete_policy(self.server_handle, name.as_ptr().cast_mut())
            },
            _ => unreachable!(),
        };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(())
    }

    #[cfg(mit)]
    fn get_policy(&self, name: &str) -> Result<Option<Policy>> {
        if !self.context.library.is_mit() {
            return Err(Error::LibraryMismatch(
                "Policy operations are only available for MIT kadm5",
            ));
        }

        let name = CString::new(name)?;
        let mut policy_ent = sys::mit::_kadm5_policy_ent_t::default();
        let code = match &self.context.library {
            Library::MitClient(cont) | Library::MitServer(cont) => unsafe {
                cont.kadm5_get_policy(
                    self.server_handle,
                    name.as_ptr().cast_mut(),
                    &mut policy_ent,
                )
            },
            _ => unreachable!(),
        };
        if code == sys::mit::KADM5_UNK_POLICY as i64 {
            return Ok(None);
        }
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        let policy = Policy::from_raw(&self.context, &policy_ent)?;
        match &self.context.library {
            Library::MitClient(cont) | Library::MitServer(cont) => unsafe {
                cont.kadm5_free_policy_ent(self.server_handle, &mut policy_ent)
            },
            _ => unreachable!(),
        };
        Ok(Some(policy))
    }

    #[cfg(mit)]
    fn list_policies(&self, query: Option<&str>) -> Result<Vec<String>> {
        if !self.context.library.is_mit() {
            return Err(Error::LibraryMismatch(
                "Policy operations are only available for MIT kadm5",
            ));
        }

        let query = CString::new(query.unwrap_or("*"))?;
        let mut count = 0;
        let mut policies: *mut *mut i8 = null_mut();
        let code = match &self.context.library {
            Library::MitClient(cont) | Library::MitServer(cont) => unsafe {
                cont.kadm5_get_policies(
                    self.server_handle,
                    query.as_ptr().cast_mut(),
                    &mut policies,
                    &mut count,
                )
            },
            _ => unreachable!(),
        };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        let mut result = Vec::with_capacity(count as usize);
        if count == 0 {
            return Ok(result);
        }
        for raw in unsafe { std::slice::from_raw_parts(policies, count as usize) }.iter() {
            result.push(c_string_to_string(*raw)?);
        }
        match &self.context.library {
            Library::MitClient(cont) | Library::MitServer(cont) => unsafe {
                cont.kadm5_free_name_list(self.server_handle, policies, count);
            },
            _ => unreachable!(),
        };
        Ok(result)
    }

    fn get_privileges(&self) -> Result<KAdminPrivileges> {
        let (privs, code) = match &self.context.library {
            #[cfg(mit)]
            Library::MitClient(cont) | Library::MitServer(cont) => {
                let mut privs = 0;
                let code = unsafe { cont.kadm5_get_privs(self.server_handle, &mut privs) };
                (privs, code)
            }
            #[cfg(heimdal)]
            Library::HeimdalClient(cont) | Library::HeimdalServer(cont) => {
                let mut privs = 0;
                let code = unsafe { cont.kadm5_get_privs(self.server_handle, &mut privs) };
                (privs.into(), code.into())
            }
        };
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(KAdminPrivileges::from_bits_retain(privs))
    }
}

impl Drop for KAdmin {
    fn drop(&mut self) {
        if self.server_handle.is_null() {
            return;
        }
        if let Ok(_guard) = KADMIN_INIT_LOCK.lock() {
            match &self.context.library {
                #[cfg(mit)]
                Library::MitClient(cont) | Library::MitServer(cont) => unsafe {
                    cont.kadm5_flush(self.server_handle);
                    cont.kadm5_destroy(self.server_handle);
                },
                #[cfg(heimdal)]
                Library::HeimdalClient(cont) | Library::HeimdalServer(cont) => unsafe {
                    cont.kadm5_flush(self.server_handle);
                    cont.kadm5_destroy(self.server_handle);
                },
            };
        }
    }
}

/// [`KAdmin`] builder
pub struct KAdminBuilder {
    variant: KAdm5Variant,
    library: Option<Library>,
    context: Option<Context>,

    params: Option<Params>,
    db_args: Option<DbArgs>,
    /// kadm5 API version
    api_version: KAdminApiVersion,
}

impl KAdminBuilder {
    /// Create a new [`KAdminBuilder`] instance
    pub fn new(variant: KAdm5Variant) -> Self {
        Self {
            variant,
            library: None,
            context: None,

            params: None,
            db_args: None,
            api_version: Default::default(),
        }
    }

    /// Set the [`Library`] to use for this [`KAdmin`] instance
    pub fn library(mut self, library: Library) -> Self {
        self.library = Some(library);
        self
    }

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
    fn get_kadmin(self) -> Result<(KAdmin, ParamsGuard, DbArgs, u32, CString, u32)> {
        if self.library.is_some() && self.context.is_some() {
            return Err(Error::LibraryMismatch(
                "Both library and context cannot be set at the same time",
            ));
        }
        if let Some(library) = &self.library {
            if library.variant() != self.variant {
                return Err(Error::LibraryMismatch(
                    "Library variant and builder variant don't match",
                ));
            }
        }
        if let Some(context) = &self.context {
            if context.library.variant() != self.variant {
                return Err(Error::LibraryMismatch(
                    "Context variant and builder variant don't match",
                ));
            }
        }
        let params = self.params.unwrap_or_default();
        let db_args = self.db_args.unwrap_or_default();
        let api_version = self.api_version;

        let context = self.context.unwrap_or(Context::new(
            self.library.unwrap_or(Library::from_variant(self.variant)?),
        )?);

        let kadmin = KAdmin {
            context,
            server_handle: null_mut(),
        };

        let api_version = api_version.to_raw(kadmin.context.library.variant())?;

        let params_guard = match &kadmin.context.library {
            #[cfg(mit)]
            Library::MitClient(_) | Library::MitServer(_) => ParamsGuard::build_mit(&params)?,
            #[cfg(heimdal)]
            Library::HeimdalClient(_) | Library::HeimdalServer(_) => {
                ParamsGuard::build_heimdal(&params)?
            }
        };

        let service_name = match &kadmin.context.library {
            #[cfg(mit)]
            Library::MitClient(_) | Library::MitServer(_) => sys::mit::KADM5_ADMIN_SERVICE,
            #[cfg(heimdal)]
            Library::HeimdalClient(_) | Library::HeimdalServer(_) => {
                sys::heimdal::KADM5_ADMIN_SERVICE
            }
        }
        .to_owned();
        let struct_version = match &kadmin.context.library {
            #[cfg(mit)]
            Library::MitClient(_) | Library::MitServer(_) => sys::mit::KADM5_STRUCT_VERSION,
            #[cfg(heimdal)]
            Library::HeimdalClient(_) | Library::HeimdalServer(_) => {
                sys::heimdal::KADM5_STRUCT_VERSION
            }
        };

        Ok((
            kadmin,
            params_guard,
            db_args,
            api_version,
            service_name,
            struct_version,
        ))
    }

    /// Construct a [`KAdmin`] object from this builder using a client name (usually a principal
    /// name) and a password
    ///
    /// Can only be used with client-side libraries.
    pub fn with_password(self, client_name: &str, password: &str) -> Result<KAdmin> {
        let _guard = KADMIN_INIT_LOCK.lock().map_err(|_| Error::LockError)?;

        let (mut kadmin, params, db_args, api_version, service_name, struct_version) =
            self.get_kadmin()?;

        if !kadmin.context.library.is_client() {
            return Err(Error::LibraryMismatch(
                "with_password can only be used with client-side libraries",
            ));
        }

        let client_name = CString::new(client_name)?;
        let password = CString::new(password)?;

        let code = match &kadmin.context.library {
            #[cfg(mit)]
            Library::MitClient(cont) => unsafe {
                cont.kadm5_init_with_password(
                    kadmin.context.context as sys::mit::krb5_context,
                    client_name.as_ptr().cast_mut(),
                    password.as_ptr().cast_mut(),
                    service_name.as_ptr().cast_mut(),
                    &mut params.params_mit.unwrap(),
                    struct_version,
                    api_version,
                    db_args.db_args,
                    &mut kadmin.server_handle,
                )
            },
            #[cfg(heimdal)]
            Library::HeimdalClient(cont) => (unsafe {
                cont.kadm5_init_with_password_ctx(
                    kadmin.context.context as sys::heimdal::krb5_context,
                    client_name.as_ptr().cast_mut(),
                    password.as_ptr().cast_mut(),
                    service_name.as_ptr().cast_mut(),
                    &mut params.params_heimdal.unwrap(),
                    struct_version.into(),
                    api_version.into(),
                    &mut kadmin.server_handle,
                )
            })
            .into(),
            _ => unreachable!(),
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
    pub fn with_keytab(self, client_name: Option<&str>, keytab: Option<&str>) -> Result<KAdmin> {
        let _guard = KADMIN_INIT_LOCK.lock().map_err(|_| Error::LockError)?;

        let (mut kadmin, params, db_args, api_version, service_name, struct_version) =
            self.get_kadmin()?;

        if !kadmin.context.library.is_client() {
            return Err(Error::LibraryMismatch(
                "with_keytab can only be used with client-side libraries",
            ));
        }

        let client_name = if let Some(client_name) = client_name {
            CString::new(client_name)?
        } else {
            match &kadmin.context.library {
                #[cfg(mit)]
                Library::MitClient(cont) | Library::MitServer(cont) => {
                    let mut princ_ptr: MaybeUninit<sys::mit::krb5_principal> =
                        MaybeUninit::zeroed();
                    let code = unsafe {
                        cont.krb5_sname_to_principal(
                            kadmin.context.context as sys::mit::krb5_context,
                            null_mut(),
                            CString::new("host")?.as_ptr().cast_mut(),
                            sys::mit::KRB5_NT_SRV_HST as i32,
                            princ_ptr.as_mut_ptr(),
                        )
                    };
                    krb5_error_code_escape_hatch(&kadmin.context, code.into())?;
                    let princ = unsafe { princ_ptr.assume_init() };
                    let princ_name = unparse_name_mit(&kadmin.context, princ);
                    unsafe {
                        cont.krb5_free_principal(
                            kadmin.context.context as sys::mit::krb5_context,
                            princ,
                        );
                    }
                    CString::new(princ_name?.unwrap())?
                }
                #[cfg(heimdal)]
                Library::HeimdalClient(cont) | Library::HeimdalServer(cont) => {
                    let mut princ_ptr: MaybeUninit<sys::heimdal::krb5_principal> =
                        MaybeUninit::zeroed();
                    let code = unsafe {
                        cont.krb5_sname_to_principal(
                            kadmin.context.context as sys::heimdal::krb5_context,
                            null_mut(),
                            CString::new("host")?.as_ptr().cast_mut(),
                            sys::heimdal::NAME_TYPE_KRB5_NT_SRV_HST,
                            princ_ptr.as_mut_ptr(),
                        )
                    };
                    krb5_error_code_escape_hatch(&kadmin.context, code.into())?;
                    let princ = unsafe { princ_ptr.assume_init() };
                    let princ_name = unparse_name_heimdal(&kadmin.context, princ);
                    unsafe {
                        cont.krb5_free_principal(
                            kadmin.context.context as sys::heimdal::krb5_context,
                            princ,
                        );
                    }
                    CString::new(princ_name?.unwrap())?
                }
            }
        };
        let keytab = if let Some(keytab) = keytab {
            CString::new(keytab)?
        } else {
            CString::new("/etc/krb5.keytab")?
        };

        let code = match &kadmin.context.library {
            #[cfg(mit)]
            Library::MitClient(cont) => unsafe {
                cont.kadm5_init_with_skey(
                    kadmin.context.context as sys::mit::krb5_context,
                    client_name.as_ptr().cast_mut(),
                    keytab.as_ptr().cast_mut(),
                    service_name.as_ptr().cast_mut(),
                    &mut params.params_mit.unwrap(),
                    struct_version,
                    api_version,
                    db_args.db_args,
                    &mut kadmin.server_handle,
                )
            },
            #[cfg(heimdal)]
            Library::HeimdalClient(cont) => (unsafe {
                cont.kadm5_init_with_skey_ctx(
                    kadmin.context.context as sys::heimdal::krb5_context,
                    client_name.as_ptr().cast_mut(),
                    keytab.as_ptr().cast_mut(),
                    service_name.as_ptr().cast_mut(),
                    &mut params.params_heimdal.unwrap(),
                    struct_version.into(),
                    api_version.into(),
                    &mut kadmin.server_handle,
                )
            })
            .into(),
            _ => unreachable!(),
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
    pub fn with_ccache(
        self,
        client_name: Option<&str>,
        ccache_name: Option<&str>,
    ) -> Result<KAdmin> {
        let _guard = KADMIN_INIT_LOCK.lock().map_err(|_| Error::LockError)?;

        let (mut kadmin, params, db_args, api_version, service_name, struct_version) =
            self.get_kadmin()?;

        if !kadmin.context.library.is_client() {
            return Err(Error::LibraryMismatch(
                "with_ccache can only be used with client-side libraries",
            ));
        }

        let code = match &kadmin.context.library {
            #[cfg(mit)]
            Library::MitClient(cont) => {
                let ccache = {
                    let mut ccache: MaybeUninit<sys::mit::krb5_ccache> = MaybeUninit::zeroed();
                    let code = if let Some(ccache_name) = ccache_name {
                        let ccache_name = CString::new(ccache_name)?;
                        unsafe {
                            cont.krb5_cc_resolve(
                                kadmin.context.context as sys::mit::krb5_context,
                                ccache_name.as_ptr().cast_mut(),
                                ccache.as_mut_ptr(),
                            )
                        }
                    } else {
                        unsafe {
                            cont.krb5_cc_default(
                                kadmin.context.context as sys::mit::krb5_context,
                                ccache.as_mut_ptr(),
                            )
                        }
                    };
                    krb5_error_code_escape_hatch(&kadmin.context, code.into())?;
                    unsafe { ccache.assume_init() }
                };

                let client_name = if let Some(client_name) = client_name {
                    CString::new(client_name)?
                } else {
                    let mut princ_ptr: MaybeUninit<sys::mit::krb5_principal> =
                        MaybeUninit::zeroed();
                    let code = unsafe {
                        cont.krb5_cc_get_principal(
                            kadmin.context.context as sys::mit::krb5_context,
                            ccache,
                            princ_ptr.as_mut_ptr(),
                        )
                    };
                    krb5_error_code_escape_hatch(&kadmin.context, code.into())?;
                    let princ = unsafe { princ_ptr.assume_init() };
                    let princ_name = unparse_name_mit(&kadmin.context, princ);
                    unsafe {
                        cont.krb5_free_principal(
                            kadmin.context.context as sys::mit::krb5_context,
                            princ,
                        );
                    }
                    CString::new(princ_name?.unwrap())?
                };

                let code = unsafe {
                    cont.kadm5_init_with_creds(
                        kadmin.context.context as sys::mit::krb5_context,
                        client_name.as_ptr().cast_mut(),
                        ccache,
                        service_name.as_ptr().cast_mut(),
                        &mut params.params_mit.unwrap(),
                        struct_version,
                        api_version,
                        db_args.db_args,
                        &mut kadmin.server_handle,
                    )
                };

                unsafe {
                    cont.krb5_cc_close(kadmin.context.context as sys::mit::krb5_context, ccache);
                }

                code
            }
            #[cfg(heimdal)]
            Library::HeimdalClient(cont) => {
                let ccache = {
                    let mut ccache: MaybeUninit<sys::heimdal::krb5_ccache> = MaybeUninit::zeroed();
                    let code = if let Some(ccache_name) = ccache_name {
                        let ccache_name = CString::new(ccache_name)?;
                        unsafe {
                            cont.krb5_cc_resolve(
                                kadmin.context.context as sys::heimdal::krb5_context,
                                ccache_name.as_ptr().cast_mut(),
                                ccache.as_mut_ptr(),
                            )
                        }
                    } else {
                        unsafe {
                            cont.krb5_cc_default(
                                kadmin.context.context as sys::heimdal::krb5_context,
                                ccache.as_mut_ptr(),
                            )
                        }
                    };
                    krb5_error_code_escape_hatch(&kadmin.context, code.into())?;
                    unsafe { ccache.assume_init() }
                };

                let client_name = if let Some(client_name) = client_name {
                    CString::new(client_name)?
                } else {
                    let mut princ_ptr: MaybeUninit<sys::heimdal::krb5_principal> =
                        MaybeUninit::zeroed();
                    let code = unsafe {
                        cont.krb5_cc_get_principal(
                            kadmin.context.context as sys::heimdal::krb5_context,
                            ccache,
                            princ_ptr.as_mut_ptr(),
                        )
                    };
                    krb5_error_code_escape_hatch(&kadmin.context, code.into())?;
                    let princ = unsafe { princ_ptr.assume_init() };
                    let princ_name = unparse_name_heimdal(&kadmin.context, princ);
                    unsafe {
                        cont.krb5_free_principal(
                            kadmin.context.context as sys::heimdal::krb5_context,
                            princ,
                        );
                    }
                    CString::new(princ_name?.unwrap())?
                };

                let code = unsafe {
                    cont.kadm5_init_with_creds_ctx(
                        kadmin.context.context as sys::heimdal::krb5_context,
                        client_name.as_ptr().cast_mut(),
                        ccache,
                        service_name.as_ptr().cast_mut(),
                        &mut params.params_heimdal.unwrap(),
                        struct_version.into(),
                        api_version.into(),
                        &mut kadmin.server_handle,
                    )
                };

                unsafe {
                    cont.krb5_cc_close(
                        kadmin.context.context as sys::heimdal::krb5_context,
                        ccache,
                    );
                }

                code.into()
            }
            _ => unreachable!(),
        };

        drop(_guard);

        kadm5_ret_t_escape_hatch(&kadmin.context, code)?;

        Ok(kadmin)
    }

    /// Not implemented
    pub fn with_anonymous(self, _client_name: &str) -> Result<KAdmin> {
        let _guard = KADMIN_INIT_LOCK.lock().map_err(|_| Error::LockError)?;

        let (mut _kadmin, _params, _db_args, _api_version, _service_name, _struct_version) =
            self.get_kadmin()?;

        unimplemented!();
    }

    /// Construct a [`KAdmin`] object from this builder for local database manipulation.
    pub fn with_local(self) -> Result<KAdmin> {
        let _guard = KADMIN_INIT_LOCK.lock().map_err(|_| Error::LockError)?;

        let (mut kadmin, params, db_args, api_version, service_name, struct_version) =
            self.get_kadmin()?;

        if !kadmin.context.library.is_server() {
            return Err(Error::LibraryMismatch(
                "with_local can only be used with server-side libraries",
            ));
        }

        let client_name = if let Some(default_realm) = &kadmin.context.default_realm {
            let mut concat = CString::new("root/admin@")?.into_bytes();
            concat.extend_from_slice(default_realm.to_bytes_with_nul());
            CString::from_vec_with_nul(concat)?
        } else {
            CString::new("root/admin")?
        };

        let code = match &kadmin.context.library {
            #[cfg(mit)]
            Library::MitServer(cont) => unsafe {
                cont.kadm5_init_with_creds(
                    kadmin.context.context as sys::mit::krb5_context,
                    client_name.as_ptr().cast_mut(),
                    null_mut(),
                    service_name.as_ptr().cast_mut(),
                    &mut params.params_mit.unwrap(),
                    struct_version,
                    api_version,
                    db_args.db_args,
                    &mut kadmin.server_handle,
                )
            },
            #[cfg(heimdal)]
            Library::HeimdalServer(cont) => unsafe {
                cont.kadm5_init_with_creds_ctx(
                    kadmin.context.context as sys::heimdal::krb5_context,
                    client_name.as_ptr().cast_mut(),
                    null_mut(),
                    service_name.as_ptr().cast_mut(),
                    &mut params.params_heimdal.unwrap(),
                    struct_version.into(),
                    api_version.into(),
                    &mut kadmin.server_handle,
                )
            }
            .into(),
            _ => unreachable!(),
        };

        drop(_guard);

        kadm5_ret_t_escape_hatch(&kadmin.context, code)?;

        Ok(kadmin)
    }
}

#[cfg(test)]
mod tests_sys {
    use crate::sys;

    #[cfg(all(mit, heimdal))]
    #[test]
    fn test_kadmin_privileges_are_same() {
        assert_eq!(sys::mit::KADM5_PRIV_GET, sys::heimdal::KADM5_PRIV_GET);
        assert_eq!(sys::mit::KADM5_PRIV_ADD, sys::heimdal::KADM5_PRIV_ADD);
        assert_eq!(sys::mit::KADM5_PRIV_MODIFY, sys::heimdal::KADM5_PRIV_MODIFY);
        assert_eq!(sys::mit::KADM5_PRIV_DELETE, sys::heimdal::KADM5_PRIV_DELETE);
    }
}

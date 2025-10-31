//! [`KAdmin`] interface to kadm5

use std::{
    collections::HashMap,
    ffi::{CString, c_char, c_void},
    mem::MaybeUninit,
    ptr::{self, null, null_mut},
    sync::Mutex,
};

use libc::EINVAL;
#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(any(mit_client, mit_server, heimdal_server))]
use crate::policy::{Policy, PolicyBuilder, PolicyModifier};
use crate::{
    context::Context,
    conv::{c_string_to_string, parse_name, unparse_name},
    db_args::DbArgs,
    error::{Error, Result, kadm5_ret_t_escape_hatch, krb5_error_code_escape_hatch},
    keysalt::KeySalts,
    params::{Params, ParamsRaw},
    principal::{Principal, PrincipalBuilder, PrincipalBuilderKey, PrincipalModifier},
    sys::{self, KAdm5Variant, Library, library_match},
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
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
#[allow(clippy::exhaustive_enums)]
#[cfg_attr(feature = "python", pyclass(eq, eq_int))]
pub enum KAdminApiVersion {
    /// Version 2
    #[default]
    Version2,
    /// Version 3, only usable with MIT kadm5
    #[cfg(any(mit_client, mit_server))]
    Version3,
    /// Version 4, only usable with MIT kadm5
    #[cfg(any(mit_client, mit_server))]
    Version4,
}

impl KAdminApiVersion {
    fn to_raw(self, variant: KAdm5Variant) -> Result<u32> {
        match self {
            Self::Version2 => match variant {
                #[cfg(mit_client)]
                KAdm5Variant::MitClient => Ok(sys::mit_client::KADM5_API_VERSION_2),
                #[cfg(mit_server)]
                KAdm5Variant::MitServer => Ok(sys::mit_server::KADM5_API_VERSION_2),
                #[cfg(heimdal_client)]
                KAdm5Variant::HeimdalClient => Ok(sys::heimdal_client::KADM5_API_VERSION_2),
                #[cfg(heimdal_server)]
                KAdm5Variant::HeimdalServer => Ok(sys::heimdal_server::KADM5_API_VERSION_2),
            },
            #[cfg(any(mit_client, mit_server))]
            Self::Version3 => match variant {
                #[cfg(mit_client)]
                KAdm5Variant::MitClient => Ok(sys::mit_client::KADM5_API_VERSION_3),
                #[cfg(mit_server)]
                KAdm5Variant::MitServer => Ok(sys::mit_server::KADM5_API_VERSION_3),
                _ => Err(Error::LibraryMismatch(
                    "Version 3 is only available for MIT kadm5",
                )),
            },
            #[cfg(any(mit_client, mit_server))]
            Self::Version4 => match variant {
                #[cfg(mit_client)]
                KAdm5Variant::MitClient => Ok(sys::mit_client::KADM5_API_VERSION_4),
                #[cfg(mit_server)]
                KAdm5Variant::MitServer => Ok(sys::mit_server::KADM5_API_VERSION_4),
                _ => Err(Error::LibraryMismatch(
                    "Version 4 is only available for MIT kadm5",
                )),
            },
        }
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
    /// # use crate::kadmin::{KAdmin, KAdminImpl, KAdm5Variant};
    /// # let kadmin = KAdmin::builder(KAdm5Variant::MitClient)
    /// #     .with_ccache(None, None)
    /// #     .unwrap();
    /// kadmin
    ///     .rename_principal("old@EXAMPLE.ORG", "new@EXAMPLE.ORG")
    ///     .unwrap();
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
    /// # use crate::kadmin::{KAdmin, KAdminImpl, KAdm5Variant};
    /// # let kadmin = KAdmin::builder(KAdm5Variant::MitClient)
    /// #     .with_ccache(None, None)
    /// #     .unwrap();
    /// let princname = String::from("user@EXAMPLE.ORG");
    /// let principal = kadmin.get_principal(&princname).unwrap();
    /// assert!(principal.is_some());
    /// ```
    #[doc(alias = "getprinc")]
    fn get_principal(&self, name: &str) -> Result<Option<Principal>>;

    /// Check if a principal exists
    ///
    /// ```no_run
    /// # use crate::kadmin::{KAdmin, KAdminImpl, KAdm5Variant};
    /// # let kadmin = KAdmin::builder(KAdm5Variant::MitClient)
    /// #     .with_ccache(None, None)
    /// #     .unwrap();
    /// let princname = String::from("user@EXAMPLE.ORG");
    /// assert!(kadmin.principal_exists(&princname).unwrap());
    /// ```
    fn principal_exists(&self, name: &str) -> Result<bool> {
        Ok(self.get_principal(name)?.is_some())
    }

    /// Change a principal password
    ///
    /// * `keepold`: Keeps the existing keys in the database. This flag is usually not necessary
    ///   except perhaps for krbtgt principals. Defaults to false. With Heimdal client, this option
    ///   is silently ignored.
    /// * `keysalts`: Uses the specified keysalt list for setting the keys of the principal. With
    ///   Heimdal client, this option is silently ignored.
    ///
    /// Don't use this method directly. Instead, prefer [`Principal::change_password`]
    #[doc(alias = "cpw")]
    fn principal_change_password(
        &self,
        name: &str,
        password: &str,
        #[cfg(any(mit_client, mit_server, heimdal_server))] keepold: Option<bool>,
        #[cfg(any(mit_client, mit_server, heimdal_server))] keysalts: Option<&KeySalts>,
    ) -> Result<()>;

    /// Sets the key of the principal to a random value
    ///
    /// * `keepold`: Keeps the existing keys in the database. This flag is usually not necessary
    ///   except perhaps for krbtgt principals. Defaults to false. With Heimdal client, this option
    ///   is silently ignored.
    /// * `keysalts`: Uses the specified keysalt list for setting the keys of the principal. With
    ///   Heimdal client, this option is silently ignored.
    ///
    /// [`Principal::randkey`] is also available
    // TODO: add returning newly created keys
    #[doc(alias = "randkey")]
    fn principal_randkey(
        &self,
        name: &str,
        #[cfg(any(mit_client, mit_server, heimdal_server))] keepold: Option<bool>,
        #[cfg(any(mit_client, mit_server, heimdal_server))] keysalts: Option<&KeySalts>,
    ) -> Result<()>;

    #[cfg(any(mit_client, mit_server))]
    /// Retrieve string attributes on a principal
    ///
    /// [`Principal::get_strings`] is also available
    ///
    /// Only available for MIT variants
    fn principal_get_strings(&self, name: &str) -> Result<HashMap<String, String>>;

    #[cfg(any(mit_client, mit_server))]
    /// Set string attribute on a principal
    ///
    /// Set `value` to None to remove the string
    ///
    /// [`Principal::set_string`] is also available
    ///
    /// Only available for MIT variants
    fn principal_set_string(&self, name: &str, key: &str, value: Option<&str>) -> Result<()>;

    /// List principals
    ///
    /// `query` is a shell-style glob expression that can contain the wild-card characters `?`, `*`,
    /// and `[]`. All principal names matching the expression are retuned. If the expression ///
    /// does not contain an `@` character, an `@` character followed by the local realm is appended
    /// to the expression. If no query is provided, all principals are returned.
    /// ```no_run
    /// # use crate::kadmin::{KAdmin, KAdminImpl, KAdm5Variant};
    /// # let kadmin = KAdmin::builder(KAdm5Variant::MitClient)
    /// #     .with_ccache(None, None)
    /// #     .unwrap();
    /// for princ in kadmin.list_principals(None).unwrap() {
    ///     println!("{princ}");
    /// }
    /// ```
    #[doc(alias("listprincs", "get_principals", "getprincs"))]
    fn list_principals(&self, query: Option<&str>) -> Result<Vec<String>>;

    #[cfg(any(mit_client, mit_server, heimdal_server))]
    /// Add a policy
    ///
    /// Don't use this method directly. Instead, use a [`PolicyBuilder`], via [`Policy::builder`]
    ///
    /// Only available for MIT and Heimdal server-side libraries.
    #[doc(alias = "addpol")]
    fn add_policy(&self, builder: &PolicyBuilder) -> Result<()>;

    #[cfg(any(mit_client, mit_server, heimdal_server))]
    /// Modify a policy
    ///
    /// Don't use this method directly. Instead, use a [`PolicyModifier`], via
    /// [`Policy::modifier`] #[doc(alias = "modpol")]
    ///
    /// Only available for MIT and Heimdal server-side libraries.
    fn modify_policy(&self, modifier: &PolicyModifier) -> Result<()>;

    #[cfg(any(mit_client, mit_server, heimdal_server))]
    /// Delete a policy
    ///
    /// [`Policy::delete`] is also available
    ///
    /// Only available for MIT and Heimdal server-side libraries.
    #[doc(alias = "delpol")]
    fn delete_policy(&self, name: &str) -> Result<()>;

    #[cfg(any(mit_client, mit_server, heimdal_server))]
    /// Retrieve a policy
    ///
    /// ```no_run
    /// # use crate::kadmin::{KAdmin, KAdminImpl, KAdm5Variant};
    /// # let kadmin = KAdmin::builder(KAdm5Variant::MitClient)
    /// #   .with_ccache(None, None)
    /// #   .unwrap();
    /// let polname = String::from("mypol");
    /// let policy = kadmin.get_policy(&polname).unwrap();
    /// assert!(policy.is_some());
    /// ```
    ///
    /// Only available for MIT and Heimdal server-side libraries.
    #[doc(alias = "getpol")]
    fn get_policy(&self, name: &str) -> Result<Option<Policy>>;

    #[cfg(any(mit_client, mit_server, heimdal_server))]
    /// Check if a policy exists
    ///
    /// ```no_run
    /// # use crate::kadmin::{KAdmin, KAdminImpl, KAdm5Variant};
    /// # let kadmin = KAdmin::builder(KAdm5Variant::MitClient)
    /// #     .with_ccache(None, None)
    /// #     .unwrap();
    /// let polname = String::from("mypol");
    /// assert!(kadmin.policy_exists(&polname).unwrap());
    /// ```
    ///
    /// Only available for MIT and Heimdal server-side libraries.
    fn policy_exists(&self, name: &str) -> Result<bool> {
        Ok(self.get_policy(name)?.is_some())
    }

    #[cfg(any(mit_client, mit_server, heimdal_server))]
    /// List policies
    ///
    /// `query` is a shell-style glob expression that can contain the wild-card characters `?`, `*`,
    /// and `[]`. All policy names matching the expression are returned. If no query is provided,
    /// all existing policy names are returned.
    ///
    /// ```no_run
    /// # use crate::kadmin::{KAdmin, KAdminImpl, KAdm5Variant};
    /// # let kadmin = KAdmin::builder(KAdm5Variant::MitClient)
    /// #     .with_ccache(None, None)
    /// #     .unwrap();
    /// for pol in kadmin.list_policies(None).unwrap() {
    ///     println!("{pol}");
    /// }
    /// ```
    ///
    /// Only available for MIT and Heimdal server-side libraries.
    #[doc(alias("listpols", "get_policies", "getpols"))]
    fn list_policies(&self, query: Option<&str>) -> Result<Vec<String>>;

    /// Get current privileges
    fn get_privileges(&self) -> Result<i64>;
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
        let prepare_dummy_pass = || {
            let mut dummy_pass = String::with_capacity(256);
            dummy_pass.push_str("6F a[");
            for i in dummy_pass.len()..=256 {
                dummy_pass.push((b'a' + ((i % 26) as u8)) as char);
            }
            CString::new(dummy_pass)
        };

        let (entry, mut mask) = builder.make_entry(&self.context)?;

        let mut old_style_randkey = false;

        let (_pass, raw_pass) = library_match!(&self.context.library; |_cont, lib| {
            if let Some(policy) = &builder.policy {
                if policy.is_none() {
                    mask &= !(lib!(KADM5_POLICY_CLR) as i64);
                }
            }

            let pass = match &builder.key {
                PrincipalBuilderKey::Password(key) => Some(CString::new(key.clone())?),
                PrincipalBuilderKey::NoKey => {
                    mask |= lib!(KADM5_KEY_DATA) as i64;
                    None
                },
                PrincipalBuilderKey::RandKey => None,
                PrincipalBuilderKey::ServerRandKey => None,
                PrincipalBuilderKey::OldStyleRandKey => {
                    mask |= lib!(KADM5_ATTRIBUTES) as i64;
                    old_style_randkey = true;
                    Some(prepare_dummy_pass()?)
                }
            };
            let raw_pass = if let Some(pass) = &pass {
                pass.as_ptr().cast_mut()
            } else { null_mut() };

            mask |= lib!(KADM5_PRINCIPAL) as i64;

            (pass, raw_pass)
        });

        macro_rules! prepare_keysalts {
            () => {{
                let mut keysalts: Option<Vec<lib!(krb5_key_salt_tuple)>> =
                    builder.keysalts.as_ref().map(|ks| ks.into());
                let (n_ks_tuple, ks_tuple) = if let Some(ref mut keysalts) = keysalts {
                    (keysalts.len(), keysalts.as_mut_ptr())
                } else {
                    (0, null_mut())
                };
                (keysalts, n_ks_tuple, ks_tuple)
            }};
        }

        let code = library_match!(
            &self.context.library;
            mit_client, mit_server, heimdal_server => |cont, lib| {
                let (keysalts, n_ks_tuple, ks_tuple) = prepare_keysalts!();
                if keysalts.is_none() {
                    unsafe {
                        cont.kadm5_create_principal(
                            self.server_handle,
                            entry.raw as *mut lib!(_kadm5_principal_ent_t),
                            (mask as u32).into(),
                            raw_pass
                        ).into()
                    }
                } else {
                    unsafe {
                        cont.kadm5_create_principal_3(
                            self.server_handle,
                            entry.raw as *mut lib!(_kadm5_principal_ent_t),
                            (mask as u32).into(),
                            n_ks_tuple as i32,
                            ks_tuple,
                            raw_pass,
                        ).into()
                    }
                }
            },
            heimdal_client => |cont, lib| unsafe {
                cont.kadm5_create_principal(
                    self.server_handle,
                    entry.raw as *mut lib!(_kadm5_principal_ent_t),
                    mask as u32,
                    raw_pass,
                ).into()
            }
        );
        let code = if code == EINVAL as i64 && builder.key == PrincipalBuilderKey::RandKey {
            // The server doesn't support randkey creation. Create the principal with a dummy
            // password and disallow tickets.
            let pass = prepare_dummy_pass()?;
            let raw_pass = pass.as_ptr().cast_mut();
            library_match!(&self.context.library; |_cont, lib| {
                let raw_entry = entry.raw as *mut lib!(_kadm5_principal_ent_t);
                unsafe { *raw_entry }.attributes |= lib!(KRB5_KDB_DISALLOW_ALL_TIX) as lib!(krb5_flags);
                mask |= lib!(KADM5_ATTRIBUTES) as i64;
                old_style_randkey = true;
            });
            library_match!(
                &self.context.library;
                mit_client, mit_server, heimdal_server => |cont, lib| {
                    let (keysalts, n_ks_tuple, ks_tuple) = prepare_keysalts!();
                    if keysalts.is_none() {
                        unsafe {
                            cont.kadm5_create_principal(
                                self.server_handle,
                                entry.raw as *mut lib!(_kadm5_principal_ent_t),
                                (mask as u32).into(),
                                raw_pass
                            ).into()
                        }
                    } else {
                        unsafe {
                            cont.kadm5_create_principal_3(
                                self.server_handle,
                                entry.raw as *mut lib!(_kadm5_principal_ent_t),
                                (mask as u32).into(),
                                n_ks_tuple as i32,
                                ks_tuple,
                                raw_pass,
                            ).into()
                        }
                    }
                },
                heimdal_client => |cont, lib| unsafe {
                    cont.kadm5_create_principal(
                        self.server_handle,
                        entry.raw as *mut lib!(_kadm5_principal_ent_t),
                        mask as u32,
                        raw_pass,
                    ).into()
                }
            )
        } else {
            code
        };
        kadm5_ret_t_escape_hatch(&self.context, code)?;

        if old_style_randkey {
            library_match!(&self.context.library; |cont, lib| {
                self.principal_randkey(
                    &builder.name,
                    #[cfg(any(mit_client, mit_server, heimdal_server))]
                    None,
                    #[cfg(any(mit_client, mit_server, heimdal_server))]
                    None,
                )?;
                let raw_entry = entry.raw as *mut lib!(_kadm5_principal_ent_t);
                unsafe { *raw_entry }.attributes &= !lib!(KRB5_KDB_DISALLOW_ALL_TIX) as lib!(krb5_flags);
                mask = lib!(KADM5_ATTRIBUTES) as i64;
                let code = unsafe {
                    cont.kadm5_modify_principal(
                        self.server_handle,
                        raw_entry,
                        (mask as u32).into(),
                    ).into()
                };
                kadm5_ret_t_escape_hatch(&self.context, code)?;
            });
        }

        Ok(())
    }

    fn modify_principal(&self, modifier: &PrincipalModifier) -> Result<()> {
        library_match!(&self.context.library; |cont, lib| {
            let (entry, mask) = modifier.make_entry(&self.context)?;
            let code = unsafe {
                cont.kadm5_modify_principal(
                    self.server_handle,
                    entry.raw as *mut lib!(_kadm5_principal_ent_t),
                    (mask as u32).into(),
                ).into()
            };
            kadm5_ret_t_escape_hatch(&self.context, code)?;
            Ok(())
        })
    }

    fn rename_principal(&self, old_name: &str, new_name: &str) -> Result<()> {
        let old_princ = parse_name(&self.context, old_name)?;
        let new_princ = parse_name(&self.context, new_name)?;
        let code = library_match!(&self.context.library; |cont, lib| unsafe {
            cont.kadm5_rename_principal(
                self.server_handle,
                old_princ.raw as lib!(krb5_principal),
                new_princ.raw as lib!(krb5_principal),
            ).into()
        });
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(())
    }

    fn delete_principal(&self, name: &str) -> Result<()> {
        let princ = parse_name(&self.context, name)?;
        let code = library_match!(&self.context.library; |cont, lib| unsafe {
            cont.kadm5_delete_principal(
                self.server_handle,
                princ.raw as lib!(krb5_principal),
            ).into()
        });
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(())
    }

    fn get_principal(&self, name: &str) -> Result<Option<Principal>> {
        library_match!(&self.context.library; |cont, lib| {
            let mut temp_princ = null_mut();
            let name = CString::new(name)?;
            let code = unsafe {
                cont.krb5_parse_name(
                    self.context.context as lib!(krb5_context),
                    name.as_ptr().cast_mut(),
                    &mut temp_princ,
                ).into()
            };
            krb5_error_code_escape_hatch(&self.context, code)?;

            let mut canon = null_mut();
            let code = unsafe {
                cont.krb5_unparse_name(
                    self.context.context as lib!(krb5_context),
                    temp_princ,
                    &mut canon,
                ).into()
            };
            krb5_error_code_escape_hatch(&self.context, code)?;

            let mut princ_ent: lib!(_kadm5_principal_ent_t) = Default::default();
            let princ_ptr = ptr::from_mut(&mut princ_ent);
            let code = unsafe {
                cont.kadm5_get_principal(
                    self.server_handle,
                    temp_princ,
                    princ_ptr,
                    ((lib!(KADM5_PRINCIPAL_NORMAL_MASK)) as u32).into(),
                ).into()
            };
            unsafe {
                cont.krb5_free_principal(
                    self.context.context as lib!(krb5_context),
                    temp_princ,
                );
            }
            let unk_princ: i64 = lib!(KADM5_UNK_PRINC).into();
            if code == unk_princ {
                return Ok(None)
            }
            kadm5_ret_t_escape_hatch(&self.context, code)?;

            let princ = Principal::from_raw(&self.context, princ_ptr as *const c_void)?;
            unsafe {
                cont.kadm5_free_principal_ent(self.server_handle, princ_ptr);
            }
            Ok(Some(princ))
        })
    }

    fn principal_change_password(
        &self,
        name: &str,
        password: &str,
        #[cfg(any(mit_client, mit_server, heimdal_server))] keepold: Option<bool>,
        #[cfg(any(mit_client, mit_server, heimdal_server))] keysalts: Option<&KeySalts>,
    ) -> Result<()> {
        let password = CString::new(password)?;
        let princ = parse_name(&self.context, name)?;

        let code = library_match!(
            &self.context.library;
            mit_client, mit_server, heimdal_server => |cont, lib| {
                let keepold = keepold.unwrap_or(false);

                let mut keysalts: Option<Vec<lib!(krb5_key_salt_tuple)>> = keysalts.map(|ks| ks.into());
                let (n_ks_tuple, ks_tuple) = if let Some(ref mut keysalts) = keysalts {
                    (keysalts.len(), keysalts.as_mut_ptr())
                } else {
                    (0, null_mut())
                };

                if keepold || keysalts.is_some() {
                    unsafe {
                        cont.kadm5_chpass_principal_3(
                            self.server_handle,
                            princ.raw as lib!(krb5_principal),
                            keepold.into(),
                            n_ks_tuple as i32,
                            ks_tuple,
                            password.as_ptr().cast_mut(),
                        ).into()
                    }
                } else {
                    unsafe {
                        cont.kadm5_chpass_principal(
                            self.server_handle,
                            princ.raw as lib!(krb5_principal),
                            password.as_ptr().cast_mut(),
                        ).into()
                    }
                }
            },
            heimdal_client => |cont, lib| {
                unsafe {
                    cont.kadm5_chpass_principal(
                        self.server_handle,
                        princ.raw as lib!(krb5_principal),
                        password.as_ptr().cast_mut(),
                    ).into()
                }
            }
        );

        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(())
    }

    fn principal_randkey(
        &self,
        name: &str,
        #[cfg(any(mit_client, mit_server, heimdal_server))] keepold: Option<bool>,
        #[cfg(any(mit_client, mit_server, heimdal_server))] keysalts: Option<&KeySalts>,
    ) -> Result<()> {
        let princ = parse_name(&self.context, name)?;

        let code = library_match!(
            &self.context.library;
            mit_client, mit_server, heimdal_server => |cont, lib| {
                let keepold = keepold.unwrap_or(false);

                let mut keysalts: Option<Vec<lib!(krb5_key_salt_tuple)>> = keysalts.map(|ks| ks.into());
                let (n_ks_tuple, ks_tuple) = if let Some(ref mut keysalts) = keysalts {
                    (keysalts.len(), keysalts.as_mut_ptr())
                } else {
                    (0, null_mut())
                };

                let code = unsafe {
                    cont.kadm5_randkey_principal_3(
                        self.server_handle,
                        princ.raw as lib!(krb5_principal),
                        keepold.into(),
                        n_ks_tuple as i32,
                        ks_tuple,
                        null_mut(),
                        null_mut(),
                    ).into()
                };

                let rpc_error: i64 = lib!(KADM5_RPC_ERROR).into();
                if code == rpc_error && !keepold && keysalts.is_none() {
                    unsafe {
                        cont.kadm5_randkey_principal (
                            self.server_handle,
                            princ.raw as lib!(krb5_principal),
                            null_mut(),
                            null_mut(),
                        ).into()
                    }
                } else {
                    code
                }
            },
            heimdal_client => |cont, lib| unsafe {
                cont.kadm5_randkey_principal (
                    self.server_handle,
                    princ.raw as lib!(krb5_principal),
                    null_mut(),
                    null_mut(),
                ).into()
            }
        );
        kadm5_ret_t_escape_hatch(&self.context, code)?;
        Ok(())
    }

    #[cfg(any(mit_client, mit_server))]
    fn principal_get_strings(&self, name: &str) -> Result<HashMap<String, String>> {
        library_match!(
            &self.context.library;
            heimdal_client, heimdal_server => |_cont, _lib| {
                Err(Error::LibraryMismatch(
                    "Principal strings are only available on MIT libraries.",
                ))
            },
            mit_client, mit_server => |cont, lib| {
                let princ = parse_name(&self.context, name)?;

                let mut count = 0;
                let mut raw_strings = null_mut();

                let code = unsafe {
                    cont.kadm5_get_strings(
                        self.server_handle,
                        princ.raw as lib!(krb5_principal),
                        &mut raw_strings,
                        &mut count,
                    )
                };
                kadm5_ret_t_escape_hatch(&self.context, code)?;

                let mut strings = HashMap::with_capacity(count as usize);

                if raw_strings.is_null() {
                    return Ok(strings);
                }

                for raw in unsafe { std::slice::from_raw_parts(raw_strings, count as usize) }.iter() {
                    strings.insert(c_string_to_string(raw.key)?, c_string_to_string(raw.value)?);
                }

                unsafe { cont.kadm5_free_strings(self.server_handle, raw_strings, count) };

                Ok(strings)
            }
        )
    }

    #[cfg(any(mit_client, mit_server))]
    fn principal_set_string(&self, name: &str, key: &str, value: Option<&str>) -> Result<()> {
        library_match!(
            &self.context.library;
            heimdal_client, heimdal_server => |_cont, _lib| {
                Err(Error::LibraryMismatch(
                    "Principal strings are only available on MIT libraries.",
                ))
            },
            mit_client, mit_server => |cont, lib| {
                let princ = parse_name(&self.context, name)?;
                let key = CString::new(key)?;
                let value = value.map(CString::new).transpose()?;

                let code = unsafe {
                    cont.kadm5_set_string(
                        self.server_handle,
                        princ.raw as lib!(krb5_principal),
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
        )
    }

    fn list_principals(&self, query: Option<&str>) -> Result<Vec<String>> {
        let query = CString::new(query.unwrap_or("*"))?;
        let mut princs: *mut *mut c_char = null_mut();
        let mut count = 0;

        let code = library_match!(&self.context.library; |cont, _lib| unsafe {
            cont.kadm5_get_principals(
                self.server_handle,
                query.as_ptr().cast_mut(),
                &mut princs,
                &mut count,
            ).into()
        });
        kadm5_ret_t_escape_hatch(&self.context, code)?;

        let mut result = Vec::with_capacity(count as usize);
        if count == 0 {
            return Ok(result);
        }

        let mut ret = None;
        for raw in unsafe { std::slice::from_raw_parts(princs, count as usize) }.iter() {
            match c_string_to_string(*raw) {
                Ok(princ) => result.push(princ),
                Err(err) => {
                    ret = Some(Err(err));
                    break;
                }
            }
        }

        library_match!(
            &self.context.library;
            mit_client, mit_server => |cont, _lib| unsafe {
                cont.kadm5_free_name_list(self.server_handle, princs, count);
            },
            heimdal_client, heimdal_server => |cont, _lib| unsafe {
                cont.kadm5_free_name_list(self.server_handle, princs, &mut count);
            }
        );

        if let Some(ret) = ret { ret } else { Ok(result) }
    }

    #[cfg(any(mit_client, mit_server, heimdal_server))]
    fn add_policy(&self, builder: &PolicyBuilder) -> Result<()> {
        library_match!(
            &self.context.library;
            heimdal_client => |_cont, _lib| {
                Err(Error::LibraryMismatch(
                    "Policy operations are only available for MIT and Heimdal server-side libraries",
                ))
            },
            mit_client, mit_server, heimdal_server => |cont, lib| {
                let (entry, mask) = builder.make_entry(&self.context)?;
                let mask = mask | lib!(KADM5_POLICY) as i64;

                let code = unsafe {
                    cont.kadm5_create_policy(
                        self.server_handle,
                        entry.raw as *mut lib!(_kadm5_policy_ent_t),
                        mask,
                    ).into()
                };
                kadm5_ret_t_escape_hatch(&self.context, code)?;
                Ok(())
            }
        )
    }

    #[cfg(any(mit_client, mit_server, heimdal_server))]
    fn modify_policy(&self, modifier: &PolicyModifier) -> Result<()> {
        library_match!(
            &self.context.library;
            heimdal_client => |_cont, _lib| {
                Err(Error::LibraryMismatch(
                    "Policy operations are only available for MIT and Heimdal server-side libraries",
                ))
            },
            mit_client, mit_server, heimdal_server => |cont, lib| {
                let (entry, mask) = modifier.make_entry(&self.context)?;

                let code = unsafe {
                    cont.kadm5_modify_policy(
                        self.server_handle,
                        entry.raw as *mut lib!(_kadm5_policy_ent_t),
                        (mask as u32).into(),
                    ).into()
                };
                kadm5_ret_t_escape_hatch(&self.context, code)?;
                Ok(())
            }
        )
    }

    #[cfg(any(mit_client, mit_server, heimdal_server))]
    fn delete_policy(&self, name: &str) -> Result<()> {
        library_match!(
            &self.context.library;
            heimdal_client => |_cont, _lib| {
                Err(Error::LibraryMismatch(
                    "Policy operations are only available on MIT and Heimdal server-side libraries.",
                ))
            },
            mit_client, mit_server, heimdal_server => |cont, _lib| {
                let name = CString::new(name)?;
                let code = unsafe {
                    cont.kadm5_delete_policy(
                        self.server_handle,
                        name.as_ptr().cast_mut()
                    ).into()
                };
                kadm5_ret_t_escape_hatch(&self.context, code)?;
                Ok(())
            }
        )
    }

    #[cfg(any(mit_client, mit_server, heimdal_server))]
    fn get_policy(&self, name: &str) -> Result<Option<Policy>> {
        library_match!(
            &self.context.library;
            mit_client, mit_server, heimdal_server => |cont, lib| {
                let name = CString::new(name)?;
                let mut policy_ent: lib!(_kadm5_policy_ent_t) = Default::default();
                let policy_ptr = ptr::from_mut(&mut policy_ent);

                let code = unsafe {
                    cont.kadm5_get_policy(
                        self.server_handle,
                        name.as_ptr().cast_mut(),
                        policy_ptr,
                    ).into()
                };
                let unk_policy: i64 = lib!(KADM5_UNK_POLICY).into();
                if code == unk_policy {
                    return Ok(None);
                }
                kadm5_ret_t_escape_hatch(&self.context, code)?;

                let policy = Policy::from_raw(self.server_handle, &self.context, policy_ptr as *const c_void)?;
                Ok(Some(policy))
            },
            heimdal_client => |_cont, _lib| {
                Err(Error::LibraryMismatch(
                    "Policy operations are only available for MIT and Heimdal server libraries",
                ))
            }
        )
    }

    #[cfg(any(mit_client, mit_server, heimdal_server))]
    fn list_policies(&self, query: Option<&str>) -> Result<Vec<String>> {
        let res: Result<_> = library_match!(
            &self.context.library;
            heimdal_client => |_cont, _lib| {
                Err(Error::LibraryMismatch(
                    "Principal strings are only available on MIT Heimdal server-side libraries.",
                ))
            },
            mit_client, mit_server, heimdal_server => |cont, _lib| {
                let query = CString::new(query.unwrap_or("*"))?;
                let mut policies: *mut *mut c_char = null_mut();
                let mut count = 0;

                let code = unsafe {
                    cont.kadm5_get_policies(
                        self.server_handle,
                        query.as_ptr().cast_mut(),
                        &mut policies,
                        &mut count,
                    ).into()
                };
                kadm5_ret_t_escape_hatch(&self.context, code)?;

                let mut result = Vec::with_capacity(count as usize);
                if count == 0 {
                    return Ok(result);
                }
                let mut ret = None;
                for raw in unsafe { std::slice::from_raw_parts(policies, count as usize) }.iter() {
                    match c_string_to_string(*raw) {
                        Ok(pol) => result.push(pol),
                        Err(err) => {
                            ret = Some((policies, count, Err(err)));
                            break;
                        }
                    }
                }
                if let Some(ret) = ret {
                    Ok(ret)
                } else {
                    Ok((policies, count, Ok(result)))
                }

            }
        );
        let (raw, mut count, result) = res?;

        library_match!(
            &self.context.library;
            mit_client, mit_server => |cont, _lib| unsafe {
                cont.kadm5_free_name_list(self.server_handle, raw, count);
            },
            heimdal_client, heimdal_server => |cont, _lib| unsafe {
                cont.kadm5_free_name_list(self.server_handle, raw, &mut count);
            }
        );

        result
    }

    fn get_privileges(&self) -> Result<i64> {
        library_match!(&self.context.library; |cont, _lib| {
            let mut privs = 0;
            let code = unsafe { cont.kadm5_get_privs(self.server_handle, &mut privs).into() };
            kadm5_ret_t_escape_hatch(&self.context, code)?;
            Ok(privs.into())
        })
    }
}

impl Drop for KAdmin {
    fn drop(&mut self) {
        if self.server_handle.is_null() {
            return;
        }
        if let Ok(_guard) = KADMIN_INIT_LOCK.lock() {
            library_match!(&self.context.library; |cont, _lib| unsafe {
                cont.kadm5_flush(self.server_handle);
                cont.kadm5_destroy(self.server_handle);
            });
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
    fn get_kadmin(self) -> Result<(KAdmin, Params, DbArgs, u32, CString, u32)> {
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

        let service_name =
            library_match!(&kadmin.context.library; |_cont, lib| lib!(KADM5_ADMIN_SERVICE))
                .to_owned();
        let struct_version =
            library_match!(&kadmin.context.library; |_cont, lib| lib!(KADM5_STRUCT_VERSION));

        Ok((
            kadmin,
            params,
            db_args,
            api_version,
            service_name,
            struct_version,
        ))
    }

    /// Construct a [`KAdmin`] object from this builder using a client name (usually a principal
    /// name) and a password
    pub fn with_password(self, client_name: &str, password: &str) -> Result<KAdmin> {
        let _guard = KADMIN_INIT_LOCK.lock().map_err(|_| Error::LockError)?;

        let (mut kadmin, params, db_args, api_version, service_name, struct_version) =
            self.get_kadmin()?;
        let params_raw = ParamsRaw::build(&kadmin.context, &params)?;

        let client_name = CString::new(client_name)?;
        let password = CString::new(password)?;

        let code = library_match!(
            &kadmin.context.library;
            mit_client, mit_server => |cont, lib| unsafe {
                cont.kadm5_init_with_password(
                    kadmin.context.context as lib!(krb5_context),
                    client_name.as_ptr().cast_mut(),
                    password.as_ptr().cast_mut(),
                    service_name.as_ptr().cast_mut(),
                    params_raw.raw as *mut lib!(kadm5_config_params),
                    struct_version,
                    api_version,
                    db_args.db_args,
                    &mut kadmin.server_handle,
                )
            },
            heimdal_client, heimdal_server => |cont, lib| unsafe {
                cont.kadm5_init_with_password_ctx(
                    kadmin.context.context as lib!(krb5_context),
                    client_name.as_ptr().cast_mut(),
                    password.as_ptr().cast_mut(),
                    service_name.as_ptr().cast_mut(),
                    params_raw.raw as *mut lib!(kadm5_config_params),
                    struct_version.into(),
                    api_version.into(),
                    &mut kadmin.server_handle,
                ).into()
            }
        );

        drop(params_raw);
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
        let params_raw = ParamsRaw::build(&kadmin.context, &params)?;

        let client_name = if let Some(client_name) = client_name {
            CString::new(client_name)?
        } else {
            let princ_type = library_match!(
                &kadmin.context.library;
                mit_client, mit_server => |_cont, lib| lib!(KRB5_NT_SRV_HST) as i32,
                heimdal_client, heimdal_server => |_cont, lib| lib!(NAME_TYPE_KRB5_NT_SRV_HST)
            );
            library_match!(&kadmin.context.library; |cont, lib| {
                let mut princ_ptr: MaybeUninit<lib!(krb5_principal)> =
                    MaybeUninit::zeroed();
                let code = unsafe {
                    cont.krb5_sname_to_principal(
                        kadmin.context.context as lib!(krb5_context),
                        null_mut(),
                        CString::new("host")?.as_ptr().cast_mut(),
                        princ_type as i32,
                        princ_ptr.as_mut_ptr(),
                    )
                };
                krb5_error_code_escape_hatch(&kadmin.context, code.into())?;
                let princ = unsafe { princ_ptr.assume_init() };
                let princ_name = unparse_name(&kadmin.context, princ as *const c_void);
                unsafe {
                    cont.krb5_free_principal(
                        kadmin.context.context as lib!(krb5_context),
                        princ,
                    );
                }
                CString::new(princ_name?.unwrap())?
            })
        };
        let keytab = if let Some(keytab) = keytab {
            CString::new(keytab)?
        } else {
            CString::new("/etc/krb5.keytab")?
        };

        let code = library_match!(
            &kadmin.context.library;
            mit_client, mit_server => |cont, lib| unsafe {
                cont.kadm5_init_with_skey(
                    kadmin.context.context as lib!(krb5_context),
                    client_name.as_ptr().cast_mut(),
                    keytab.as_ptr().cast_mut(),
                    service_name.as_ptr().cast_mut(),
                    params_raw.raw as *mut lib!(kadm5_config_params),
                    struct_version,
                    api_version,
                    db_args.db_args,
                    &mut kadmin.server_handle,
                )
            },
            heimdal_client, heimdal_server => |cont, lib| unsafe {
                cont.kadm5_init_with_skey_ctx(
                    kadmin.context.context as lib!(krb5_context),
                    client_name.as_ptr().cast_mut(),
                    keytab.as_ptr().cast_mut(),
                    service_name.as_ptr().cast_mut(),
                    params_raw.raw as *mut lib!(kadm5_config_params),
                    struct_version.into(),
                    api_version.into(),
                    &mut kadmin.server_handle,
                ).into()
            }
        );

        drop(params_raw);
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
        let params_raw = ParamsRaw::build(&kadmin.context, &params)?;

        let ccache = library_match!(&kadmin.context.library; |cont, lib| {
            let mut ccache: MaybeUninit<lib!(krb5_ccache)> = MaybeUninit::zeroed();
            let code = if let Some(ccache_name) = ccache_name {
                let ccache_name = CString::new(ccache_name)?;
                unsafe {
                    cont.krb5_cc_resolve(
                        kadmin.context.context as lib!(krb5_context),
                        ccache_name.as_ptr().cast_mut(),
                        ccache.as_mut_ptr(),
                    )
                }
            } else {
                unsafe {
                    cont.krb5_cc_default(
                        kadmin.context.context as lib!(krb5_context),
                        ccache.as_mut_ptr(),
                    )
                }
            };
            krb5_error_code_escape_hatch(&kadmin.context, code.into())?;
            let ccache = unsafe { ccache.assume_init() };
            ccache as *const c_void
        });

        let client_name = if let Some(client_name) = client_name {
            CString::new(client_name)?
        } else {
            library_match!(&kadmin.context.library; |cont, lib| {
                let mut princ_ptr: MaybeUninit<lib!(krb5_principal)> =
                    MaybeUninit::zeroed();
                let code = unsafe {
                    cont.krb5_cc_get_principal(
                        kadmin.context.context as lib!(krb5_context),
                        ccache as lib!(krb5_ccache),
                        princ_ptr.as_mut_ptr(),
                    )
                };
                krb5_error_code_escape_hatch(&kadmin.context, code.into())?;
                let princ = unsafe { princ_ptr.assume_init() };
                let princ_name = unparse_name(&kadmin.context, princ as *const c_void);
                unsafe {
                    cont.krb5_free_principal(
                        kadmin.context.context as lib!(krb5_context),
                        princ,
                    );
                }
                CString::new(princ_name?.unwrap())?
            })
        };

        let code = library_match!(
            &kadmin.context.library;
            mit_client, mit_server => |cont, lib| unsafe {
                cont.kadm5_init_with_creds(
                    kadmin.context.context as lib!(krb5_context),
                    client_name.as_ptr().cast_mut(),
                    ccache as lib!(krb5_ccache),
                    service_name.as_ptr().cast_mut(),
                    params_raw.raw as *mut lib!(kadm5_config_params),
                    struct_version,
                    api_version,
                    db_args.db_args,
                    &mut kadmin.server_handle,
                )
            },
            heimdal_client, heimdal_server => |cont, lib| unsafe {
                cont.kadm5_init_with_creds_ctx(
                    kadmin.context.context as lib!(krb5_context),
                    client_name.as_ptr().cast_mut(),
                    ccache as lib!(krb5_ccache),
                    service_name.as_ptr().cast_mut(),
                    params_raw.raw as *mut lib!(kadm5_config_params),
                    struct_version.into(),
                    api_version.into(),
                    &mut kadmin.server_handle,
                ).into()
            }
        );

        drop(params_raw);
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

    #[cfg(any(mit_server, heimdal_server))]
    /// Construct a [`KAdmin`] object from this builder for local database manipulation.
    ///
    /// Only available on server-side libraries.
    pub fn with_local(self) -> Result<KAdmin> {
        let _guard = KADMIN_INIT_LOCK.lock().map_err(|_| Error::LockError)?;

        let (mut kadmin, params, db_args, api_version, service_name, struct_version) =
            self.get_kadmin()?;
        let params_raw = ParamsRaw::build(&kadmin.context, &params)?;

        let client_name = if let Some(default_realm) = &kadmin.context.default_realm {
            let mut concat = CString::new("root/admin@")?.into_bytes();
            concat.extend_from_slice(default_realm.to_bytes_with_nul());
            CString::from_vec_with_nul(concat)?
        } else {
            CString::new("root/admin")?
        };

        let res: Result<_> = library_match!(
            &kadmin.context.library;
            mit_client, heimdal_client => |_cont, _lib| {
                Err(Error::LibraryMismatch(
                    "with_local can only be used with server-side libraries",
                ))
            },
            mit_server => |cont, lib| unsafe {
                Ok(cont.kadm5_init_with_creds(
                    kadmin.context.context as lib!(krb5_context),
                    client_name.as_ptr().cast_mut(),
                    null_mut(),
                    service_name.as_ptr().cast_mut(),
                    params_raw.raw as *mut lib!(kadm5_config_params),
                    struct_version,
                    api_version,
                    db_args.db_args,
                    &mut kadmin.server_handle,
                ))
            },
            heimdal_server => |cont, lib| unsafe {
                Ok(cont.kadm5_init_with_creds_ctx(
                    kadmin.context.context as lib!(krb5_context),
                    client_name.as_ptr().cast_mut(),
                    null_mut(),
                    service_name.as_ptr().cast_mut(),
                    params_raw.raw as *mut lib!(kadm5_config_params),
                    struct_version.into(),
                    api_version.into(),
                    &mut kadmin.server_handle,
                ).into())
            }
        );
        let code = res?;

        drop(params_raw);
        drop(_guard);

        kadm5_ret_t_escape_hatch(&kadmin.context, code)?;

        Ok(kadmin)
    }
}

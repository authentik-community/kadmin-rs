//! kadm5 principal

use std::{
    collections::HashMap,
    ffi::{CString, c_long, c_uint, c_void},
    ptr::null_mut,
    time::Duration,
};

use chrono::{DateTime, Utc};
use getset::{CopyGetters, Getters};
#[cfg(feature = "python")]
use pyo3::prelude::*;

use crate::{
    context::Context,
    conv::{c_string_to_string, delta_to_dur, dt_to_ts, dur_to_delta, ts_to_dt, unparse_name},
    db_args::DbArgs,
    error::{Result, krb5_error_code_escape_hatch},
    kadmin::KAdminImpl,
    keysalt::KeySalts,
    sys::{self, KAdm5Variant, cfg_match, library_match},
    tl_data::{TlData, TlDataEntry, TlDataRaw},
};

/// A kadm5 principal
#[derive(Clone, Debug, Default, Getters, CopyGetters)]
#[getset(get_copy = "pub")]
#[cfg_attr(feature = "python", pyclass(get_all))]
pub struct Principal {
    /// The principal name
    #[getset(skip)]
    name: String,
    /// When the principal expires
    expire_time: Option<DateTime<Utc>>,
    /// When the password was last changed
    last_password_change: Option<DateTime<Utc>>,
    /// When the password expires
    password_expiration: Option<DateTime<Utc>>,
    /// Maximum ticket life
    max_life: Option<Duration>,
    /// Last principal to modify this principal
    #[getset(skip)]
    modified_by: Option<String>,
    /// When the principal was last modified
    modified_at: Option<DateTime<Utc>>,
    /// See [`PrincipalAttributes`]
    attributes: i32,
    /// Current key version number
    kvno: u32,
    /// Master key version number
    mkvno: u32,
    /// Associated policy
    #[getset(skip)]
    policy: Option<String>,
    /// Extra attributes
    aux_attributes: c_long,
    /// Maximum renewable ticket life
    max_renewable_life: Option<Duration>,
    /// When the last successful authentication occurred
    last_success: Option<DateTime<Utc>>,
    /// When the last failed authentication occurred
    last_failed: Option<DateTime<Utc>>,
    /// Number of failed authentication attempts
    fail_auth_count: c_uint,
    /// TL-data
    #[getset(skip)]
    tl_data: TlData,
    // TODO: key_data
}

impl Principal {
    /// Create a [`Principal`] from `_kadm5_principal_ent_t`
    pub(crate) fn from_raw(context: &Context, entry: *const c_void) -> Result<Self> {
        library_match!(&context.library; |_cont, lib| {
            let entry = entry as *const lib!(_kadm5_principal_ent_t);

            Ok(Self {
                // can never be None, unwraping is ok
                name: unparse_name(context, unsafe { *entry }.principal as *const c_void)?.unwrap(),
                expire_time: ts_to_dt(unsafe { *entry }.princ_expire_time.into())?,
                last_password_change: ts_to_dt(unsafe { *entry }.last_pwd_change.into())?,
                password_expiration: ts_to_dt(unsafe { *entry }.pw_expiration.into())?,
                max_life: delta_to_dur(unsafe { *entry }.max_life.into()),
                modified_by: unparse_name(context, unsafe { *entry }.mod_name as *const c_void)?,
                modified_at: ts_to_dt(unsafe { *entry }.mod_date.into())?,
                attributes: unsafe { *entry }.attributes as i32,
                kvno: unsafe { *entry }.kvno as u32,
                mkvno: unsafe { *entry }.mkvno as u32,
                policy: if ! unsafe { *entry }.policy.is_null() {
                    Some(c_string_to_string(unsafe { *entry }.policy)?)
                } else { None },
                aux_attributes: unsafe { *entry }.aux_attributes.into(),
                max_renewable_life: delta_to_dur(unsafe { *entry }.max_renewable_life.into()),
                last_success: ts_to_dt(unsafe { *entry }.last_success.into())?,
                last_failed: ts_to_dt(unsafe { *entry }.last_failed.into())?,
                fail_auth_count: unsafe { *entry }.fail_auth_count as u32,
                tl_data: TlData::from_raw(context, unsafe { *entry }.n_tl_data, unsafe { *entry }.tl_data as *const c_void),
            })
        })
    }

    /// Name of the policy
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Last principal to modify this principal
    pub fn modified_by(&self) -> Option<&str> {
        self.modified_by.as_deref()
    }

    /// Associated policy
    pub fn policy(&self) -> Option<&str> {
        self.policy.as_deref()
    }

    /// TL-data
    pub fn tl_data(&self) -> &TlData {
        &self.tl_data
    }

    /// Construct a new [`PrincipalBuilder`] for a principal with `name`
    ///
    /// ```no_run
    /// # use crate::kadmin::{KAdmin, KAdminImpl, Principal};
    /// # #[cfg(feature = "client")]
    /// # fn example() {
    /// let kadm = kadmin::KAdmin::builder().with_ccache(None, None).unwrap();
    /// let princname = "myuser";
    /// let policy = Some("default");
    /// let princ = Principal::builder(princname)
    ///     .policy(policy)
    ///     .create(&kadm)
    ///     .unwrap();
    /// assert_eq!(princ.policy(), policy);
    /// # }
    /// ```
    pub fn builder(name: &str) -> PrincipalBuilder {
        PrincipalBuilder::new(name)
    }

    /// Construct a new [`PrincipalModifier`] from this principal
    ///
    /// ```no_run
    /// # use crate::kadmin::{KAdmin, KAdminImpl, Principal};
    /// # #[cfg(feature = "client")]
    /// # fn example() {
    /// let kadm = kadmin::KAdmin::builder().with_ccache(None, None).unwrap();
    /// let princname = "myuser";
    /// let princ = kadm.get_principal(&princname).unwrap().unwrap();
    /// let princ = princ.modifier().policy(None).modify(&kadm).unwrap();
    /// assert_eq!(princ.policy(), None);
    /// # }
    /// ```
    pub fn modifier(&self) -> PrincipalModifier {
        PrincipalModifier::from_principal(self)
    }

    /// Delete this principal
    ///
    /// The [`Principal`] object is not consumed by this method, but after deletion, it shouldn't be
    /// used for modifying, as the principal may not exist anymore
    pub fn delete<K: KAdminImpl>(&self, kadmin: &K) -> Result<()> {
        kadmin.delete_principal(&self.name)
    }

    /// Change the password of the principal
    ///
    /// * `keepold`: Keeps the existing keys in the database. This flag is usually not necessary
    ///   except perhaps for krbtgt principals. Defaults to false. With Heimdal client, this option
    ///   is silently ignored.
    /// * `keysalts`: Uses the specified keysalt list for setting the keys of the principal. With
    ///   Heimdal client, this option is silently ignored.
    ///
    /// Note that principal data will have changed after this, so you may need to refresh it
    pub fn change_password<K: KAdminImpl>(
        &self,
        kadmin: &K,
        password: &str,
        #[cfg(any(mit_client, mit_server, heimdal_server))] keepold: Option<bool>,
        #[cfg(any(mit_client, mit_server, heimdal_server))] keysalts: Option<&KeySalts>,
    ) -> Result<()> {
        kadmin.principal_change_password(&self.name, password, keepold, keysalts)
    }

    /// Sets the key of the principal to a random value
    ///
    /// * `keepold`: Keeps the existing keys in the database. This flag is usually not necessary
    ///   except perhaps for krbtgt principals. Defaults to false
    /// * `keysalts`: Uses the specified keysalt list for setting the keys of the principal
    ///
    /// Note that principal data will have changed after this, so you may need to refresh it
    pub fn randkey<K: KAdminImpl>(
        &self,
        kadmin: &K,
        keepold: Option<bool>,
        keysalts: Option<&KeySalts>,
    ) -> Result<()> {
        kadmin.principal_randkey(&self.name, keepold, keysalts)
    }

    /// Unlocks a locked principal (one which has received too many failed authentication attempts
    /// without enough time between them according to its password policy) so that it can
    /// successfully authenticate
    ///
    /// Note that principal data will have changed after this, so you may need to refresh it
    pub fn unlock<K: KAdminImpl>(&self, kadmin: &K) -> Result<()> {
        let tl_entry_data_type = match kadmin.variant() {
            #[cfg(mit_client)]
            KAdm5Variant::MitClient => Some(sys::mit_client::KRB5_TL_LAST_ADMIN_UNLOCK as i16),
            #[cfg(mit_server)]
            KAdm5Variant::MitServer => Some(sys::mit_server::KRB5_TL_LAST_ADMIN_UNLOCK as i16),
            #[cfg(heimdal_client)]
            KAdm5Variant::HeimdalClient => None,
            #[cfg(heimdal_server)]
            KAdm5Variant::HeimdalServer => None,
        };
        let mut modifier = self.modifier().fail_auth_count(0);
        if let Some(data_type) = tl_entry_data_type {
            modifier = modifier.tl_data(TlData {
                entries: vec![TlDataEntry {
                    data_type,
                    contents: dt_to_ts(Some(Utc::now()))?.to_le_bytes().to_vec(),
                }],
            });
        }
        modifier.modify(kadmin)?;
        Ok(())
    }

    #[cfg(any(mit_client, mit_server))]
    /// Retrieve string attributes on this principal
    ///
    /// Only available for MIT variants
    pub fn get_strings<K: KAdminImpl>(&self, kadmin: &K) -> Result<HashMap<String, String>> {
        kadmin.principal_get_strings(&self.name)
    }

    #[cfg(any(mit_client, mit_server))]
    /// Set string attribute on this principal
    ///
    /// Set `value` to None to remove the string
    ///
    /// Only available for MIT variants
    pub fn set_string<K: KAdminImpl>(
        &self,
        kadmin: &K,
        key: &str,
        value: Option<&str>,
    ) -> Result<()> {
        kadmin.principal_set_string(&self.name, key, value)
    }
}

macro_rules! principal_doer_struct {
    (
        $(#[$outer:meta])*
        $StructName:ident { $($manual_fields:tt)* }
    ) => {
        $(#[$outer])*
        pub struct $StructName {
            pub(crate) name: String,
            pub(crate) mask_mit_client: i64,
            pub(crate) mask_mit_server: i64,
            pub(crate) mask_heimdal_client: i64,
            pub(crate) mask_heimdal_server: i64,
            pub(crate) expire_time: Option<Option<DateTime<Utc>>>,
            pub(crate) password_expiration: Option<Option<DateTime<Utc>>>,
            pub(crate) max_life: Option<Option<Duration>>,
            pub(crate) attributes: Option<i32>,
            pub(crate) policy: Option<Option<String>>,
            pub(crate) aux_attributes: Option<c_long>,
            pub(crate) max_renewable_life: Option<Option<Duration>>,
            pub(crate) fail_auth_count: Option<u32>,
            pub(crate) tl_data: Option<TlData>,
            pub(crate) db_args: Option<DbArgs>,
            $($manual_fields)*
        }
    }
}

macro_rules! set_mask {
    ($self:ident, $mask:ident) => {
        cfg_match!(
            mit_client => |lib| $self.mask_mit_client |= lib!($mask) as i64,
            mit_server => |lib| $self.mask_mit_server |= lib!($mask) as i64,
            heimdal_client => |lib| $self.mask_heimdal_client |= lib!($mask) as i64,
            heimdal_server => |lib| $self.mask_heimdal_server |= lib!($mask) as i64
        )
    };

    ($self:ident; $($libname:ident),+ => $mask:ident) => {
        cfg_match!(
            $(
                $libname => |lib| set_mask!(@attr $self, $libname) |= lib!($mask) as i64
            ),+
        )
    };

    (@attr $self:ident, mit_client) => {
        $self.mask_mit_client
    };
    (@attr $self:ident, mit_server) => {
        $self.mask_mit_server
    };
    (@attr $self:ident, heimdal_client) => {
        $self.mask_heimdal_client
    };
    (@attr $self:ident, heimdal_server) => {
        $self.mask_heimdal_server
    };
}

macro_rules! principal_doer_impl {
    () => {
        /// Set when the principal expires
        ///
        /// Pass `None` to clear it. Defaults to not set
        pub fn expire_time(mut self, expire_time: Option<DateTime<Utc>>) -> Self {
            self.expire_time = Some(expire_time);
            set_mask!(self, KADM5_PRINC_EXPIRE_TIME);
            self
        }

        /// Set the password expiration time
        ///
        /// Pass `None` to clear it. Defaults to not set
        pub fn password_expiration(mut self, password_expiration: Option<DateTime<Utc>>) -> Self {
            self.password_expiration = Some(password_expiration);
            set_mask!(self, KADM5_PW_EXPIRATION);
            self
        }

        /// Set the maximum ticket life
        pub fn max_life(mut self, max_life: Option<Duration>) -> Self {
            self.max_life = Some(max_life);
            set_mask!(self, KADM5_MAX_LIFE);
            self
        }

        /// Set the principal attributes
        ///
        /// Note that this completely overrides existing attributes. Make sure to re-use the old
        /// ones if needed
        pub fn attributes(mut self, attributes: i32) -> Self {
            self.attributes = Some(attributes);
            set_mask!(self, KADM5_ATTRIBUTES);
            self
        }

        /// Set the principal policy
        ///
        /// Pass `None` to clear it. Defaults to not set
        pub fn policy(mut self, policy: Option<&str>) -> Self {
            self.policy = Some(policy.map(String::from));
            cfg_match!(
                mit_client => |lib| {
                    let (flag, nflag) = if policy.is_some() {
                        (lib!(KADM5_POLICY) as i64, lib!(KADM5_POLICY_CLR) as i64)
                    } else {
                        (lib!(KADM5_POLICY_CLR) as i64, lib!(KADM5_POLICY) as i64)
                    };
                    self.mask_mit_client |= flag;
                    self.mask_mit_client &= nflag;
                },
                mit_server => |lib| {
                    let (flag, nflag) = if policy.is_some() {
                        (lib!(KADM5_POLICY) as i64, lib!(KADM5_POLICY_CLR) as i64)
                    } else {
                        (lib!(KADM5_POLICY_CLR) as i64, lib!(KADM5_POLICY) as i64)
                    };
                    self.mask_mit_server |= flag;
                    self.mask_mit_server &= nflag;
                },
                heimdal_client => |lib| {
                    let (flag, nflag) = if policy.is_some() {
                        (lib!(KADM5_POLICY) as i64, lib!(KADM5_POLICY_CLR) as i64)
                    } else {
                        (lib!(KADM5_POLICY_CLR) as i64, lib!(KADM5_POLICY) as i64)
                    };
                    self.mask_heimdal_client |= flag;
                    self.mask_heimdal_client &= nflag;
                },
                heimdal_server => |lib| {
                    let (flag, nflag) = if policy.is_some() {
                        (lib!(KADM5_POLICY) as i64, lib!(KADM5_POLICY_CLR) as i64)
                    } else {
                        (lib!(KADM5_POLICY_CLR) as i64, lib!(KADM5_POLICY) as i64)
                    };
                    self.mask_heimdal_server |= flag;
                    self.mask_heimdal_server &= nflag;
                }
            );
            self
        }

        /// Set auxiliary attributes
        pub fn aux_attributes(mut self, aux_attributes: c_long) -> Self {
            self.aux_attributes = Some(aux_attributes);
            set_mask!(self, KADM5_AUX_ATTRIBUTES);
            self
        }

        /// Set the maximum renewable ticket life
        pub fn max_renewable_life(mut self, max_renewable_life: Option<Duration>) -> Self {
            self.max_renewable_life = Some(max_renewable_life);
            set_mask!(self, KADM5_MAX_RLIFE);
            self
        }

        /// Set the number of failed authentication attempts
        pub fn fail_auth_count(mut self, fail_auth_count: u32) -> Self {
            self.fail_auth_count = Some(fail_auth_count);
            set_mask!(self, KADM5_FAIL_AUTH_COUNT);
            self
        }

        /// Add new TL-data
        pub fn tl_data(mut self, tl_data: TlData) -> Self {
            self.tl_data = Some(tl_data);
            set_mask!(self, KADM5_TL_DATA);
            self
        }

        #[cfg(any(mit_client, mit_server))]
        /// Database specific arguments
        pub fn db_args(mut self, db_args: DbArgs) -> Self {
            self.db_args = Some(db_args);
            set_mask!(self, KADM5_TL_DATA);
            self
        }

        /// Create a `_kadm5_principal_ent_t` from this builder
        pub(crate) fn make_entry<'a>(&self, context: &'a Context) -> Result<(PrincipalEntryRaw<'a>, i64)> {
            let mask = library_match!(
                &context.library;
                mit_client => |_cont, _lib| self.mask_mit_client,
                mit_server => |_cont, _lib| self.mask_mit_server,
                heimdal_client => |_cont, _lib| self.mask_heimdal_client,
                heimdal_server => |_cont, _lib| self.mask_heimdal_server
            );

            let entry = library_match!(&context.library; |cont, lib| {
                let mut entry: lib!(_kadm5_principal_ent_t) = Default::default();

                if let Some(expire_time) = self.expire_time {
                    entry.princ_expire_time = dt_to_ts(expire_time)?.into();
                }
                if let Some(password_expiration) = self.password_expiration {
                    entry.pw_expiration = dt_to_ts(password_expiration)?.into();
                }
                if let Some(max_life) = self.max_life {
                    entry.max_life = dur_to_delta(max_life)?.into();
                }
                if let Some(attributes) = self.attributes {
                    entry.attributes = attributes as lib!(krb5_flags);
                }
                let policy = if let Some(policy) = &self.policy {
                    if let Some(policy) = policy {
                        let raw = CString::new(policy.clone())?;
                        entry.policy = raw.as_ptr().cast_mut();
                        Some(raw)
                    } else {
                        entry.policy = null_mut();
                        None
                    }
                } else {
                    None
                };
                if let Some(aux_attributes) = self.aux_attributes {
                    entry.aux_attributes = (aux_attributes as u32).into();
                }
                if let Some(max_renewable_life) = self.max_renewable_life {
                    entry.max_renewable_life = dur_to_delta(max_renewable_life)?.into();
                }

                let tl_data = if let Some(db_args) = &self.db_args {
                    let mut tl_data: TlData = db_args.into();
                    if let Some(entry_tl_data) = &self.tl_data {
                        tl_data.entries.extend_from_slice(&entry_tl_data.entries);
                    }
                    &Some(tl_data)
                } else {
                    &self.tl_data
                };
                let tl_data = if let Some(tl_data) = tl_data {
                    let raw_tl_data = TlDataRaw::build(context, &tl_data);
                    entry.n_tl_data = tl_data.entries.len() as i16;
                    entry.tl_data = raw_tl_data.raw as *mut lib!(_krb5_tl_data);
                    Some(raw_tl_data)
                } else {
                    None
                };

                // This is done at the end so we don't leak memory if anything else fails
                let name = CString::new(self.name.clone())?;
                let code = unsafe {
                    cont.krb5_parse_name(
                        context.context as lib!(krb5_context),
                        name.as_ptr().cast_mut(),
                        &mut entry.principal,
                    ).into()
                };
                krb5_error_code_escape_hatch(context, code)?;

                let entry = Box::new(entry);
                let raw = Box::into_raw(entry) as *mut c_void;
                let raw = self.make_entry_extra(context, raw);

                PrincipalEntryRaw {
                    raw,
                    context,
                    _raw_policy: policy,
                    _raw_tl_data: tl_data,
                }
            });

            Ok((entry, mask))
        }
    };
}

principal_doer_struct!(
    /// Utility to create a principal
    ///
    /// ```no_run
    /// # use crate::kadmin::{KAdmin, KAdminImpl, Principal};
    /// # #[cfg(feature = "client")]
    /// # fn example() {
    /// let kadm = kadmin::KAdmin::builder().with_ccache(None, None).unwrap();
    /// let princname = "myuser";
    /// let policy = Some("default");
    /// let princ = Principal::builder(princname)
    ///     .policy(policy)
    ///     .create(&kadm)
    ///     .unwrap();
    /// assert_eq!(princ.policy(), policy);
    /// # }
    /// ```
    #[derive(Clone, Debug, Default)]
    PrincipalBuilder {
        pub(crate) kvno: Option<u32>,
        pub(crate) key: PrincipalBuilderKey,
        #[cfg(any(mit_client, mit_server, heimdal_server))]
        pub(crate) keysalts: Option<KeySalts>,
    }
);

impl PrincipalBuilder {
    principal_doer_impl!();

    /// Construct a new [`PrincipalBuilder`] for a principal with `name`
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            ..Default::default()
        }
    }

    /// Set the name of the principal
    pub fn name(mut self, name: &str) -> Self {
        self.name = name.to_owned();
        self
    }

    /// Set the initial key version number
    pub fn kvno(mut self, kvno: u32) -> Self {
        self.kvno = Some(kvno);
        set_mask!(self, KADM5_KVNO);
        self
    }

    /// How the principal key should be set
    ///
    /// See [`PrincipalBuilderKey`] for the default value
    pub fn key(mut self, key: &PrincipalBuilderKey) -> Self {
        self.key = key.clone();
        self
    }

    #[cfg(any(mit_client, mit_server, heimdal_server))]
    /// Use the specified keysalt list for setting the keys of the principal
    ///
    /// Only available on MIT and Heimdal server libraries, and silently ignored otherwise
    pub fn keysalts(mut self, keysalts: &KeySalts) -> Self {
        self.keysalts = Some(keysalts.clone());
        self
    }

    fn make_entry_extra(&self, context: &Context, raw: *mut c_void) -> *const c_void {
        library_match!(&context.library; |_cont, lib| {
            let mut entry: Box<lib!(_kadm5_principal_ent_t)> = unsafe {
                Box::from_raw(raw as *mut lib!(_kadm5_principal_ent_t))
            };

            if let Some(kvno) = self.kvno {
                entry.kvno = kvno as lib!(krb5_kvno);
            }
            if self.key == PrincipalBuilderKey::OldStyleRandKey {
                entry.attributes |= lib!(KRB5_KDB_DISALLOW_ALL_TIX) as lib!(krb5_flags);
            }

            Box::into_raw(entry) as *const c_void
        })
    }

    /// Create the principal
    pub fn create<K: KAdminImpl>(&self, kadmin: &K) -> Result<Principal> {
        kadmin.add_principal(self)?;
        Ok(kadmin.get_principal(&self.name)?.unwrap())
    }
}

principal_doer_struct!(
    /// Utility to modify a principal
    ///
    /// ```no_run
    /// # use crate::kadmin::{KAdmin, KAdminImpl, Principal};
    /// # #[cfg(feature = "client")]
    /// # fn example() {
    /// let kadm = kadmin::KAdmin::builder().with_ccache(None, None).unwrap();
    /// let princname = "myuser";
    /// let princ = kadm.get_principal(&princname).unwrap().unwrap();
    /// let princ = princ.modifier().policy(None).modify(&kadm).unwrap();
    /// assert_eq!(princ.policy(), None);
    /// # }
    /// ```
    #[derive(Clone, Debug, Default)]
    PrincipalModifier {}
);

impl PrincipalModifier {
    principal_doer_impl!();

    /// Construct a new [`PrincipalModifier`] from a [`Principal`]
    pub fn from_principal(principal: &Principal) -> Self {
        Self {
            name: principal.name.to_owned(),
            attributes: Some(principal.attributes),
            ..Default::default()
        }
    }

    fn make_entry_extra(&self, _context: &Context, raw: *mut c_void) -> *const c_void {
        raw.cast_const()
    }

    /// Modify the principal
    ///
    /// A new up-to-date instance of [`Principal`] is returned, but the old one is still available
    pub fn modify<K: KAdminImpl>(&self, kadmin: &K) -> Result<Principal> {
        kadmin.modify_principal(self)?;
        Ok(kadmin.get_principal(&self.name)?.unwrap())
    }
}

/// How the principal key should be set
///
/// The default is [`Self::RandKey`]
#[derive(Clone, Debug, PartialEq)]
#[allow(clippy::exhaustive_enums)]
pub enum PrincipalBuilderKey {
    /// Provide a password to use
    Password(String),
    /// No key should be set on the principal
    NoKey,
    /// A random key should be generated for the principal. Tries `ServerRandKey` and falls back to
    /// `OldStyleRandKey`
    RandKey,
    /// A random key should be generated for the principal by the server
    ServerRandKey,
    /// Old-style random key. Creates the principal with [`KRB5_KDB_DISALLOW_ALL_TIX`] and a
    /// generated dummy key, then calls `randkey` on the principal and finally removes
    /// [`KRB5_KDB_DISALLOW_ALL_TIX`]
    OldStyleRandKey,
}

impl Default for PrincipalBuilderKey {
    fn default() -> Self {
        Self::RandKey
    }
}

pub(crate) struct PrincipalEntryRaw<'a> {
    pub(crate) raw: *const c_void,
    context: &'a Context,
    _raw_policy: Option<CString>,
    _raw_tl_data: Option<TlDataRaw<'a>>,
}

impl Drop for PrincipalEntryRaw<'_> {
    fn drop(&mut self) {
        if self.raw.is_null() {
            return;
        }
        library_match!(&self.context.library; |cont, lib| {
            let raw: Box<lib!(_kadm5_principal_ent_t)> = unsafe { Box::from_raw(self.raw as *mut lib!(_kadm5_principal_ent_t)) };
            unsafe {
                cont.krb5_free_principal(
                    self.context.context as lib!(krb5_context),
                    raw.principal,
                );
            };
            drop(raw);
        });
    }
}

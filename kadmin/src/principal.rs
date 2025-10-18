//! kadm5 principal

use std::{
    collections::HashMap,
    ffi::{CString, c_long, c_uint},
    ptr::null_mut,
    time::Duration,
};

use chrono::{DateTime, Utc};
use getset::{CopyGetters, Getters};
#[cfg(feature = "python")]
use pyo3::prelude::*;

use crate::{
    context::Context,
    conv::{c_string_to_string, delta_to_dur, dt_to_ts, dur_to_delta, ts_to_dt},
    db_args::DbArgs,
    error::{Error, Result, krb5_error_code_escape_hatch},
    kadmin::{KAdmin, KAdminImpl},
    keysalt::KeySalts,
    sys::{self, Library},
    tl_data::{TlData, TlDataEntry},
};
#[cfg(heimdal)]
use crate::{conv::unparse_name_heimdal, tl_data::TlDataRawHeimdal};
#[cfg(mit)]
use crate::{conv::unparse_name_mit, tl_data::TlDataRawMit};

/// A kadm5 principal
#[derive(Clone, Debug, Getters, CopyGetters)]
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
    #[cfg(mit)]
    /// Create a [`Principal`] from [`sys::mit::_kadm5_principal_ent_t`]
    pub(crate) fn from_raw_mit(
        kadmin: &KAdmin,
        entry: &sys::mit::_kadm5_principal_ent_t,
    ) -> Result<Self> {
        Ok(Self {
            name: unparse_name_mit(&kadmin.context, entry.principal)?.unwrap(), // can never be None
            expire_time: ts_to_dt(entry.princ_expire_time.into())?,
            last_password_change: ts_to_dt(entry.last_pwd_change.into())?,
            password_expiration: ts_to_dt(entry.pw_expiration.into())?,
            max_life: delta_to_dur(entry.max_life.into()),
            modified_by: unparse_name_mit(&kadmin.context, entry.mod_name)?,
            modified_at: ts_to_dt(entry.mod_date.into())?,
            attributes: entry.attributes,
            kvno: entry.kvno,
            mkvno: entry.mkvno,
            policy: if !entry.policy.is_null() {
                Some(c_string_to_string(entry.policy)?)
            } else {
                None
            },
            aux_attributes: entry.aux_attributes,
            max_renewable_life: delta_to_dur(entry.max_renewable_life.into()),
            last_success: ts_to_dt(entry.last_success.into())?,
            last_failed: ts_to_dt(entry.last_failed.into())?,
            fail_auth_count: entry.fail_auth_count,
            tl_data: TlData::from_raw_mit(entry.n_tl_data, entry.tl_data),
        })
    }

    #[cfg(heimdal)]
    /// Create a [`Principal`] from [`sys::heimdal::_kadm5_principal_ent_t`]
    pub(crate) fn from_raw_heimdal(
        kadmin: &KAdmin,
        entry: &sys::heimdal::_kadm5_principal_ent_t,
    ) -> Result<Self> {
        Ok(Self {
            name: unparse_name_heimdal(&kadmin.context, entry.principal)?.unwrap(), /* can never be None */
            expire_time: ts_to_dt(entry.princ_expire_time)?,
            last_password_change: ts_to_dt(entry.last_pwd_change)?,
            password_expiration: ts_to_dt(entry.pw_expiration)?,
            max_life: delta_to_dur(entry.max_life.into()),
            modified_by: unparse_name_heimdal(&kadmin.context, entry.mod_name)?,
            modified_at: ts_to_dt(entry.mod_date)?,
            attributes: entry.attributes as i32,
            kvno: entry.kvno as u32,
            mkvno: entry.mkvno as u32,
            policy: if !entry.policy.is_null() {
                Some(c_string_to_string(entry.policy)?)
            } else {
                None
            },
            aux_attributes: entry.aux_attributes as i64,
            max_renewable_life: delta_to_dur(entry.max_renewable_life.into()),
            last_success: ts_to_dt(entry.last_success)?,
            last_failed: ts_to_dt(entry.last_failed)?,
            fail_auth_count: entry.fail_auth_count as u32,
            tl_data: TlData::from_raw_heimdal(entry.n_tl_data, entry.tl_data),
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
    ///   except perhaps for krbtgt principals. Defaults to false
    /// * `keysalts`: Uses the specified keysalt list for setting the keys of the principal
    ///
    /// Note that principal data will have changed after this, so you may need to refresh it
    pub fn change_password<K: KAdminImpl>(
        &self,
        kadmin: &K,
        password: &str,
        keepold: Option<bool>,
        keysalts: Option<&KeySalts>,
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

    #[cfg(mit)]
    /// Unlocks a locked principal (one which has received too many failed authentication attempts
    /// without enough time between them according to its password policy) so that it can
    /// successfully authenticate
    ///
    /// Note that principal data will have changed after this, so you may need to refresh it
    ///
    /// Only available for MIT variants
    pub fn unlock<K: KAdminImpl>(&self, kadmin: &K) -> Result<()> {
        if !kadmin.variant().is_mit() {
            return Err(Error::LibraryMismatch(
                "Principal unlocking is only available for MIT kadm5",
            ));
        }
        self.modifier()
            .fail_auth_count(0)
            .tl_data(TlData {
                entries: vec![TlDataEntry {
                    data_type: sys::mit::KRB5_TL_LAST_ADMIN_UNLOCK as i16,
                    contents: dt_to_ts(Some(Utc::now()))?.to_le_bytes().to_vec(),
                }],
            })
            .modify(kadmin)?;
        Ok(())
    }

    #[cfg(mit)]
    /// Retrieve string attributes on this principal
    ///
    /// Only available for MIT variants
    pub fn get_strings<K: KAdminImpl>(&self, kadmin: &K) -> Result<HashMap<String, String>> {
        kadmin.principal_get_strings(&self.name)
    }

    #[cfg(mit)]
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
            pub(crate) mask_mit: i64,
            pub(crate) mask_heimdal: u32,
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

macro_rules! principal_doer_impl {
    () => {
        /// Set when the principal expires
        ///
        /// Pass `None` to clear it. Defaults to not set
        pub fn expire_time(mut self, expire_time: Option<DateTime<Utc>>) -> Self {
            self.expire_time = Some(expire_time);
            #[cfg(mit)]
            {
                self.mask_mit |= sys::mit::KADM5_PRINC_EXPIRE_TIME as i64;
            }
            #[cfg(heimdal)]
            {
                self.mask_heimdal |= sys::heimdal::KADM5_PRINC_EXPIRE_TIME;
            }
            self
        }

        /// Set the password expiration time
        ///
        /// Pass `None` to clear it. Defaults to not set
        pub fn password_expiration(mut self, password_expiration: Option<DateTime<Utc>>) -> Self {
            self.password_expiration = Some(password_expiration);
            #[cfg(mit)]
            {
                self.mask_mit |= sys::mit::KADM5_PW_EXPIRATION as i64;
            }
            #[cfg(heimdal)]
            {
                self.mask_heimdal |= sys::heimdal::KADM5_PW_EXPIRATION;
            }
            self
        }

        /// Set the maximum ticket life
        pub fn max_life(mut self, max_life: Option<Duration>) -> Self {
            self.max_life = Some(max_life);
            #[cfg(mit)]
            {
                self.mask_mit |= sys::mit::KADM5_MAX_LIFE as i64;
            }
            #[cfg(heimdal)]
            {
                self.mask_heimdal |= sys::heimdal::KADM5_MAX_LIFE;
            }
            self
        }

        /// Set the principal attributes
        ///
        /// Note that this completely overrides existing attributes. Make sure to re-use the old
        /// ones if needed
        pub fn attributes(mut self, attributes: i32) -> Self {
            self.attributes = Some(attributes);
            #[cfg(mit)]
            {
                self.mask_mit |= sys::mit::KADM5_ATTRIBUTES as i64;
            }
            #[cfg(heimdal)]
            {
                self.mask_heimdal |= sys::heimdal::KADM5_ATTRIBUTES;
            }
            self
        }

        /// Set the principal policy
        ///
        /// Pass `None` to clear it. Defaults to not set
        pub fn policy(mut self, policy: Option<&str>) -> Self {
            #[cfg(mit)]
            {
                let (flag, nflag) = if policy.is_some() {
                    (sys::mit::KADM5_POLICY, sys::mit::KADM5_POLICY_CLR)
                } else {
                    (sys::mit::KADM5_POLICY_CLR, sys::mit::KADM5_POLICY)
                };
                self.mask_mit |= (flag as i64);
                self.mask_mit &= !(nflag as i64);
            }
            #[cfg(heimdal)]
            {
                let (flag, nflag) = if policy.is_some() {
                    (sys::heimdal::KADM5_POLICY, sys::heimdal::KADM5_POLICY_CLR)
                } else {
                    (sys::heimdal::KADM5_POLICY_CLR, sys::heimdal::KADM5_POLICY)
                };
                self.mask_heimdal |= flag;
                self.mask_heimdal &= !nflag;
            }
            self.policy = Some(policy.map(String::from));
            self
        }

        /// Set auxiliary attributes
        pub fn aux_attributes(mut self, aux_attributes: c_long) -> Self {
            self.aux_attributes = Some(aux_attributes);
            #[cfg(mit)]
            {
                self.mask_mit |= sys::mit::KADM5_AUX_ATTRIBUTES as i64;
            }
            #[cfg(heimdal)]
            {
                self.mask_heimdal |= sys::heimdal::KADM5_AUX_ATTRIBUTES;
            }
            self
        }

        /// Set the maximum renewable ticket life
        pub fn max_renewable_life(mut self, max_renewable_life: Option<Duration>) -> Self {
            self.max_renewable_life = Some(max_renewable_life);
            #[cfg(mit)]
            {
                self.mask_mit |= sys::mit::KADM5_MAX_RLIFE as i64;
            }
            #[cfg(heimdal)]
            {
                self.mask_heimdal |= sys::heimdal::KADM5_MAX_RLIFE;
            }
            self
        }

        /// Set the number of failed authentication attempts
        pub fn fail_auth_count(mut self, fail_auth_count: u32) -> Self {
            self.fail_auth_count = Some(fail_auth_count);
            #[cfg(mit)]
            {
                self.mask_mit |= sys::mit::KADM5_FAIL_AUTH_COUNT as i64;
            }
            #[cfg(heimdal)]
            {
                self.mask_heimdal |= sys::heimdal::KADM5_FAIL_AUTH_COUNT;
            }
            self
        }

        /// Add new TL-data
        pub fn tl_data(mut self, tl_data: TlData) -> Self {
            self.tl_data = Some(tl_data);
            #[cfg(mit)]
            {
                self.mask_mit |= sys::mit::KADM5_TL_DATA as i64;
            }
            #[cfg(heimdal)]
            {
                self.mask_heimdal |= sys::heimdal::KADM5_TL_DATA;
            }
            self
        }

        #[cfg(mit)]
        /// Database specific arguments
        ///
        /// No-op for non MIT-variants
        pub fn db_args(mut self, db_args: DbArgs) -> Self {
            self.db_args = Some(db_args);
            self.mask_mit |= sys::mit::KADM5_TL_DATA as i64;
            self
        }

        #[cfg(mit)]
        /// Create a [`sys::mit::_kadm5_principal_ent_t`] from this builder
        pub(crate) fn make_entry_mit<'a>(
            &self,
            context: &'a Context,
        ) -> Result<PrincipalEntryRawMit<'a>> {
            let mut entry = sys::mit::_kadm5_principal_ent_t::default();

            if let Some(expire_time) = self.expire_time {
                entry.princ_expire_time = dt_to_ts(expire_time)?;
            }
            if let Some(password_expiration) = self.password_expiration {
                entry.pw_expiration = dt_to_ts(password_expiration)?;
            }
            if let Some(max_life) = self.max_life {
                entry.max_life = dur_to_delta(max_life)?;
            }
            if let Some(attributes) = self.attributes {
                entry.attributes = attributes;
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
                entry.aux_attributes = aux_attributes;
            }
            if let Some(max_renewable_life) = self.max_renewable_life {
                entry.max_renewable_life = dur_to_delta(max_renewable_life)?;
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
                let raw_tl_data = tl_data.to_raw_mit();
                entry.n_tl_data = tl_data.entries.len() as i16;
                entry.tl_data = raw_tl_data.raw;
                Some(raw_tl_data)
            } else {
                None
            };

            // This is done at the end so we don't leak memory if anything else fails
            let name = CString::new(self.name.clone())?;
            let code = match &context.library {
                Library::MitClient(cont) | Library::MitServer(cont) => unsafe {
                    cont.krb5_parse_name(
                        context.context as sys::mit::krb5_context,
                        name.as_ptr().cast_mut(),
                        &mut entry.principal,
                    )
                },
                _ => unreachable!(),
            };
            krb5_error_code_escape_hatch(context, code.into())?;

            Ok(PrincipalEntryRawMit {
                raw: entry,
                context,
                _raw_policy: policy,
                _raw_tl_data: tl_data,
            })
        }

        #[cfg(heimdal)]
        /// Create a [`sys::heimdal::_kadm5_principal_ent_t`] from this builder
        pub(crate) fn make_entry_heimdal<'a>(
            &self,
            context: &'a Context,
        ) -> Result<PrincipalEntryRawHeimdal<'a>> {
            let mut entry = sys::heimdal::_kadm5_principal_ent_t::default();

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
                entry.attributes = attributes as u32;
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
                entry.aux_attributes = aux_attributes as u32;
            }
            if let Some(max_renewable_life) = self.max_renewable_life {
                entry.max_renewable_life = dur_to_delta(max_renewable_life)?.into();
            }
            let tl_data = if let Some(tl_data) = &self.tl_data {
                let raw_tl_data = tl_data.to_raw_heimdal();
                entry.n_tl_data = tl_data.entries.len() as i16;
                entry.tl_data = raw_tl_data.raw;
                Some(raw_tl_data)
            } else {
                None
            };

            // This is done at the end so we don't leak memory if anything else fails
            let name = CString::new(self.name.clone())?;
            let code = match &context.library {
                Library::HeimdalClient(cont) | Library::HeimdalServer(cont) => unsafe {
                    cont.krb5_parse_name(
                        context.context as sys::heimdal::krb5_context,
                        name.as_ptr().cast_mut(),
                        &mut entry.principal,
                    )
                },
                _ => unreachable!(),
            };
            krb5_error_code_escape_hatch(context, code.into())?;

            Ok(PrincipalEntryRawHeimdal {
                raw: entry,
                context,
                _raw_policy: policy,
                _raw_tl_data: tl_data,
            })
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
        #[cfg(mit)]
        {
            self.mask_mit |= sys::mit::KADM5_KVNO as i64;
        }
        #[cfg(heimdal)]
        {
            self.mask_heimdal |= sys::heimdal::KADM5_KVNO;
        }
        self
    }

    /// How the principal key should be set
    ///
    /// See [`PrincipalBuilderKey`] for the default value
    pub fn key(mut self, key: &PrincipalBuilderKey) -> Self {
        self.key = key.clone();
        self
    }

    /// Use the specified keysalt list for setting the keys of the principal
    pub fn keysalts(mut self, keysalts: &KeySalts) -> Self {
        self.keysalts = Some(keysalts.clone());
        self
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

#[cfg(mit)]
pub(crate) struct PrincipalEntryRawMit<'a> {
    pub(crate) raw: sys::mit::_kadm5_principal_ent_t,
    context: &'a Context,
    _raw_policy: Option<CString>,
    _raw_tl_data: Option<TlDataRawMit>,
}

#[cfg(mit)]
impl Drop for PrincipalEntryRawMit<'_> {
    fn drop(&mut self) {
        match &self.context.library {
            Library::MitClient(cont) | Library::MitServer(cont) => unsafe {
                cont.krb5_free_principal(
                    self.context.context as sys::mit::krb5_context,
                    self.raw.principal,
                );
            },
            _ => unreachable!(),
        }
    }
}

#[cfg(heimdal)]
pub(crate) struct PrincipalEntryRawHeimdal<'a> {
    pub(crate) raw: sys::heimdal::_kadm5_principal_ent_t,
    context: &'a Context,
    _raw_policy: Option<CString>,
    _raw_tl_data: Option<TlDataRawHeimdal>,
}

#[cfg(heimdal)]
impl Drop for PrincipalEntryRawHeimdal<'_> {
    fn drop(&mut self) {
        match &self.context.library {
            Library::HeimdalClient(cont) | Library::HeimdalServer(cont) => unsafe {
                cont.krb5_free_principal(
                    self.context.context as sys::heimdal::krb5_context,
                    self.raw.principal,
                );
            },
            _ => unreachable!(),
        }
    }
}

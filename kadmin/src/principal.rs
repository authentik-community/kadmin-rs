//! kadm5 principal

use std::{ffi::CString, ptr::null_mut, time::Duration};

use bitflags::bitflags;
use chrono::{DateTime, Utc};
use getset::{CopyGetters, Getters};
use kadmin_sys::*;
#[cfg(feature = "python")]
use pyo3::prelude::*;

use crate::{
    context::Context,
    conv::{c_string_to_string, delta_to_dur, dt_to_ts, dur_to_delta, ts_to_dt, unparse_name},
    error::{Result, krb5_error_code_escape_hatch},
    kadmin::{KAdmin, KAdminImpl},
};

bitflags! {
    /// Attributes set on a principal
    ///
    /// See `man kadmin(1)`, under the `add_principal` section for an explanation
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    #[repr(transparent)]
    #[cfg_attr(feature = "python", pyclass)]
    pub struct PrincipalAttributes: i32 {
        /// Prohibits the principal from obtaining postdated tickets
        const DisallowPostated = KRB5_KDB_DISALLOW_POSTDATED as i32;
        /// Prohibits the principal from obtaining forwardable tickets
        const DisallowForwardable = KRB5_KDB_DISALLOW_FORWARDABLE as i32;
        /// Specifies that a Ticket-Granting Service (TGS) request for a service ticket for the principal is not permitted
        const DisallowTgtBased = KRB5_KDB_DISALLOW_TGT_BASED as i32;
        /// Prohibits the principal from obtaining renewable tickets
        const DisallowRenewable = KRB5_KDB_DISALLOW_RENEWABLE as i32;
        /// Prohibits the principal from obtaining proxiable tickets
        const DisallowProxiable = KRB5_KDB_DISALLOW_PROXIABLE as i32;
        /// Disables user-to-user authentication for the principal by prohibiting this principal from obtaining a session key for another user
        const DisallowDupSkey = KRB5_KDB_DISALLOW_DUP_SKEY as i32;
        /// Forbids the issuance of any tickets for the principal
        const DisallowAllTix = KRB5_KDB_DISALLOW_ALL_TIX as i32;
        /// Requires the principal to preauthenticate before being allowed to kinit
        const RequiresPreAuth = KRB5_KDB_REQUIRES_PRE_AUTH as i32;
        /// Requires the principal to preauthenticate using a hardware device before being allowed to kinit
        const RequiresHwAuth = KRB5_KDB_REQUIRES_HW_AUTH as i32;
        /// Force a password change
        const RequiresPwChange = KRB5_KDB_REQUIRES_PWCHANGE as i32;
        /// Prohibits the issuance of service tickets for the principal
        const DisallowSvr = KRB5_KDB_DISALLOW_SVR as i32;
        /// Marks the principal as a password change service principal
        const PwChangeService = KRB5_KDB_PWCHANGE_SERVICE as i32;
        /// An AS_REQ for a principal with this bit set and an encrytion type of ENCTYPE_DES_CBC_CRC causes the encryption type ENCTYPE_DES_CBC_MD5 to be used instead
        const SupportDesMd5 = KRB5_KDB_SUPPORT_DESMD5 as i32;
        /// Allow kadmin administrators with `add` acls to modify the principal until this bit is cleared
        const NewPrinc = KRB5_KDB_NEW_PRINC as i32;
        /// Sets the OK-AS-DELEGATE flag on tickets issued for use with the principal as the service, which clients may use as a hint that credentials can and should be delegated when authenticating to the service
        const OkAsDelegate = KRB5_KDB_OK_AS_DELEGATE as i32;
        /// Sets the service to allow the use of S4U2Self
        const OkToAuthAsDelegate = KRB5_KDB_OK_TO_AUTH_AS_DELEGATE as i32;
        /// Prevents PAC or AD-SIGNEDPATH data from being added to service tickets for the principal
        const NoAuthDataRequired = KRB5_KDB_NO_AUTH_DATA_REQUIRED as i32;
        /// Prevents keys for the principal from being extracted or set to a known value by the kadmin protocol
        const LockdownKeys = KRB5_KDB_LOCKDOWN_KEYS as i32;

        const _ = !0;
    }
}

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
    attributes: PrincipalAttributes,
    /// Current key version number
    kvno: u32,
    /// Master key version number
    mkvno: u32,
    /// Associated policy
    #[getset(skip)]
    policy: Option<String>,
    /// Extra attributes
    aux_attributes: i64,
    /// Maximum renewable ticket life
    max_renewable_life: Option<Duration>,
    /// When the last successful authentication occurred
    last_success: Option<DateTime<Utc>>,
    /// When the last failed authentication occurred
    last_failed: Option<DateTime<Utc>>,
    /// Number of failed authentication attempts
    fail_auth_count: u32,
    // TODO: key_data
    // TODO: tl_data
}

impl Principal {
    /// Create a [`Principal`] from [`_kadm5_principal_ent_t`]
    pub(crate) fn from_raw(kadmin: &KAdmin, entry: &_kadm5_principal_ent_t) -> Result<Self> {
        Ok(Self {
            name: unparse_name(&kadmin.context, entry.principal)?.unwrap(), // can never be None
            expire_time: ts_to_dt(entry.princ_expire_time)?,
            last_password_change: ts_to_dt(entry.last_pwd_change)?,
            password_expiration: ts_to_dt(entry.pw_expiration)?,
            max_life: delta_to_dur(entry.max_life.into()),
            modified_by: unparse_name(&kadmin.context, entry.mod_name)?,
            modified_at: ts_to_dt(entry.mod_date)?,
            attributes: PrincipalAttributes::from_bits_retain(entry.attributes),
            kvno: entry.kvno,
            mkvno: entry.mkvno,
            policy: if !entry.policy.is_null() {
                Some(c_string_to_string(entry.policy)?)
            } else {
                None
            },
            aux_attributes: entry.aux_attributes,
            max_renewable_life: delta_to_dur(entry.max_renewable_life.into()),
            last_success: ts_to_dt(entry.last_success)?,
            last_failed: ts_to_dt(entry.last_failed)?,
            fail_auth_count: entry.fail_auth_count,
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

    /// Construct a new [`PrincipalBuilder`] for a principal with `name`
    // TODO: doc example
    pub fn builder(name: &str) -> PrincipalBuilder {
        PrincipalBuilder::new(name)
    }

    /// Construct a new [`PrincipalModifier`] from this principal
    // TODO: doc example
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
    // TODO: add keysalt
    pub fn change_password<K: KAdminImpl>(&self, kadmin: &K, password: &str) -> Result<()> {
        kadmin.principal_change_password(&self.name, password)
    }

    /// Set the key of the principal to a random value
    pub fn randkey<K: KAdminImpl>(&self, kadmin: &K, keepold: Option<bool>) -> Result<()> {
        kadmin.principal_randkey(&self.name, keepold)
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
            pub(crate) mask: i64,
            pub(crate) expire_time: Option<Option<DateTime<Utc>>>,
            pub(crate) password_expiration: Option<Option<DateTime<Utc>>>,
            pub(crate) max_life: Option<Option<Duration>>,
            pub(crate) attributes: Option<PrincipalAttributes>,
            pub(crate) policy: Option<Option<String>>,
            pub(crate) aux_attributes: Option<i64>,
            pub(crate) max_renewable_life: Option<Option<Duration>>,
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
            self.mask |= KADM5_PRINC_EXPIRE_TIME as i64;
            self
        }

        /// Set the password expiration time
        ///
        /// Pass `None` to clear it. Defaults to not set
        pub fn password_expiration(mut self, password_expiration: Option<DateTime<Utc>>) -> Self {
            self.password_expiration = Some(password_expiration);
            self.mask |= KADM5_PW_EXPIRATION as i64;
            self
        }

        /// Set the maximum ticket life
        pub fn max_life(mut self, max_life: Option<Duration>) -> Self {
            self.max_life = Some(max_life);
            self.mask |= KADM5_MAX_LIFE as i64;
            self
        }

        /// Set the principal attributes
        ///
        /// Note that this completely overrides existing attributes. Make sure to re-use the old
        /// ones if needed
        pub fn attributes(mut self, attributes: PrincipalAttributes) -> Self {
            self.attributes = Some(attributes);
            self.mask |= KADM5_ATTRIBUTES as i64;
            self
        }

        /// Set the principal policy
        ///
        /// Pass `None` to clear it. Defaults to not set
        pub fn policy(mut self, policy: Option<&str>) -> Self {
            let (flag, nflag) = if policy.is_some() {
                (KADM5_POLICY, KADM5_POLICY_CLR)
            } else {
                (KADM5_POLICY_CLR, KADM5_POLICY)
            };
            self.policy = Some(policy.map(String::from));
            self.mask |= flag as i64;
            self.mask &= !(nflag as i64);
            self
        }

        /// Set auxiliary attributes
        pub fn aux_attributes(mut self, aux_attributes: i64) -> Self {
            self.aux_attributes = Some(aux_attributes);
            self.mask |= KADM5_AUX_ATTRIBUTES as i64;
            self
        }

        /// Set the maximum renewable ticket life
        pub fn max_renewable_life(mut self, max_renewable_life: Option<Duration>) -> Self {
            self.max_renewable_life = Some(max_renewable_life);
            self.mask |= KADM5_MAX_RLIFE as i64;
            self
        }

        /// Create a [`_kadm5_principal_ent_t`] from this builder
        pub(crate) fn make_entry<'a>(
            &self,
            context: &'a Context,
        ) -> Result<PrincipalEntryRaw<'a>> {
            let mut entry = _kadm5_principal_ent_t::default();

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
                entry.attributes = attributes.bits();
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

            // This is done at the end so we don't leak memory if anything else fails
            let name = CString::new(self.name.clone())?;
            let code = unsafe {
                krb5_parse_name(
                    context.context,
                    name.as_ptr().cast_mut(),
                    &mut entry.principal,
                )
            };
            krb5_error_code_escape_hatch(context, code)?;

            Ok(PrincipalEntryRaw {
                raw: entry,
                context,
                _raw_policy: policy,
            })
        }
    };
}

principal_doer_struct!(
    /// Utility to create a principal
    // TODO: doc example
    #[derive(Clone, Debug, Default)]
    PrincipalBuilder {
        pub(crate) key: PrincipalBuilderKey,
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

    /// How the principal key should be set
    ///
    /// See [`PrincipalBuilderKey`] for the default value
    pub fn key(mut self, key: &PrincipalBuilderKey) -> Self {
        self.key = key.clone();
        self
    }

    /// Create the principal
    // TODO: add db_args
    pub fn create<K: KAdminImpl>(&self, kadmin: &K) -> Result<Principal> {
        kadmin.add_principal(self)?;
        Ok(kadmin.get_principal(&self.name)?.unwrap())
    }
}

principal_doer_struct!(
    /// Utility to modify a principal
    // TODO: doc example
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
            // TODO: tl_data
            ..Default::default()
        }
    }

    /// Modify the principal
    // TODO: add db_args
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
    pub(crate) raw: _kadm5_principal_ent_t,
    context: &'a Context,
    _raw_policy: Option<CString>,
}

impl Drop for PrincipalEntryRaw<'_> {
    fn drop(&mut self) {
        unsafe {
            krb5_free_principal(self.context.context, self.raw.principal);
        }
    }
}

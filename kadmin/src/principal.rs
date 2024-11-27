//! kadm5 principal

use std::time::Duration;

use bitflags::bitflags;
use chrono::{DateTime, Utc};
use getset::Getters;
use kadmin_sys::*;

use crate::{
    conv::{c_string_to_string, ts_to_dt, unparse_name},
    error::Result,
    kadmin::{KAdmin, KAdminImpl},
};

bitflags! {
    /// Attributes set on a principal
    ///
    /// See `man kadmin(1)`, under the `add_principal` section for an explanation
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
#[derive(Debug, Getters)]
#[getset(get = "pub")]
pub struct Principal {
    /// The principal name
    name: String,
    /// When the principal expires
    expire_time: Option<DateTime<Utc>>,
    /// When the password was last changed
    last_password_change: Option<DateTime<Utc>>,
    /// When the password expires
    password_expiration: Option<DateTime<Utc>>,
    /// Max ticket life
    max_life: Duration,
    /// Last principal to modify this principal
    modified_by: String,
    /// When the principal was last modified
    modified_at: Option<DateTime<Utc>>,
    /// See [`PrincipalAttributes`]
    attributes: PrincipalAttributes,
    /// Current key version number
    kvno: u32,
    /// Master key version number
    mkvno: u32,
    /// Associated policy
    policy: Option<String>,
    /// Extra attributes
    aux_attributes: i64,
    /// Max renewable ticket life
    max_renewable_life: Duration,
    /// When the last successful authentication occurred
    last_success: Option<DateTime<Utc>>,
    /// When the last failed authentication occurred
    last_failed: Option<DateTime<Utc>>,
    /// Number of failed authentication attempts
    fail_auth_count: u32,
}

impl Principal {
    /// Create a [`Principal`] from [`_kadm5_principal_ent_t`]
    pub(crate) fn from_raw(kadmin: &KAdmin, entry: &_kadm5_principal_ent_t) -> Result<Self> {
        Ok(Self {
            name: unparse_name(&kadmin.context, entry.principal)?,
            expire_time: ts_to_dt(entry.princ_expire_time)?,
            last_password_change: ts_to_dt(entry.last_pwd_change)?,
            password_expiration: ts_to_dt(entry.pw_expiration)?,
            max_life: Duration::from_secs(entry.max_life as u64),
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
            max_renewable_life: Duration::from_secs(entry.max_renewable_life as u64),
            last_success: ts_to_dt(entry.last_success)?,
            last_failed: ts_to_dt(entry.last_failed)?,
            fail_auth_count: entry.fail_auth_count,
        })
    }

    /// Construct a new [`PrincipalBuilder`] for a principal with `name`
    pub fn builder(name: &str) -> PrincipalBuilder {
        PrincipalBuilder::new(name)
    }

    /// Change the password of the principal
    pub fn change_password<K: KAdminImpl>(&self, kadmin: &K, password: &str) -> Result<()> {
        kadmin.principal_change_password(&self.name, password)
    }
}

/// Utility to create a principal
#[derive(Clone, Debug, Default)]
pub struct PrincipalBuilder {
    name: String,
    mask: i64,
    expire_time: Option<Option<DateTime<Utc>>>,
    password_expiration: Option<Option<DateTime<Utc>>>,
    max_life: Option<Duration>,
    attributes: Option<PrincipalAttributes>,
    policy: Option<Option<String>>,
    max_renewable_life: Option<Duration>,
    key: PrincipalBuilderKey,
}

// TODO: enctypes
// TODO: db_args
impl PrincipalBuilder {
    /// Construct a new [`PrincipalBuilder`] for a principal with `name`
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ..Default::default()
        }
    }

    /// Set the principal name
    pub fn name(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }

    /// Set the expiry time for the principal
    ///
    /// Pass `None` to clear it. Defaults to not set
    pub fn expire_time(mut self, expire_time: Option<DateTime<Utc>>) -> Self {
        self.expire_time = Some(expire_time);
        self.mask |= KADM5_PRINC_EXPIRE_TIME as i64;
        self
    }

    /// Set the password expiration for the principal
    ///
    /// Pass `None` to clear it. Defaults to not set
    pub fn password_expiration(mut self, password_expiration: Option<DateTime<Utc>>) -> Self {
        self.password_expiration = Some(password_expiration);
        self.mask |= KADM5_PW_EXPIRATION as i64;
        self
    }

    /// Set the maximum ticket life for the principal
    ///
    /// Pass `None` to clear it. Defaults to not set
    pub fn max_life(mut self, max_life: Duration) -> Self {
        self.max_life = Some(max_life);
        self.mask |= KADM5_MAX_LIFE as i64;
        self
    }

    /// Set principal attributes
    ///
    /// By default no attributes are set
    pub fn attributes(mut self, attributes: PrincipalAttributes) -> Self {
        self.attributes = Some(attributes);
        self.mask |= KADM5_ATTRIBUTES as i64;
        self
    }

    /// Set the principal policy
    ///
    /// By default, the policy named `default` is used if it exists. If no policy should be set,
    /// pass `None` to this method
    pub fn policy(mut self, policy: Option<&str>) -> Self {
        let flag = if policy.is_some() {
            KADM5_POLICY
        } else {
            KADM5_POLICY_CLR
        };
        self.policy = Some(policy.map(String::from));
        self.mask |= flag as i64;
        self
    }

    /// Set the maximum renewable life of tickets for the principal
    ///
    /// Pass `None` to clear it. Defaults to not set
    pub fn max_renewable_life(mut self, max_renewable_life: Duration) -> Self {
        self.max_renewable_life = Some(max_renewable_life);
        self.mask |= KADM5_MAX_RLIFE as i64;
        self
    }

    /// How the principal key should be set
    ///
    /// Defaults to randkey
    pub fn key(mut self, key: &PrincipalBuilderKey) -> Self {
        self.key = key.clone();
        self
    }

    /// Create the principal
    pub fn create<K: KAdminImpl>(&self, kadmin: &K) -> Result<()> {
        kadmin.add_principal(self)?;
        Ok(())
    }
}

/// How the principal key should be set
#[derive(Clone, Debug)]
pub enum PrincipalBuilderKey {
    /// Provide a password to use
    Password(String),
    /// No key should be set on the principal
    NoKey,
    /// A random key should be generated for the principal
    RandKey,
}

impl Default for PrincipalBuilderKey {
    fn default() -> Self {
        Self::RandKey
    }
}

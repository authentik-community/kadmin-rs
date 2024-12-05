//! kadm5 policy
use std::{ffi::CString, ptr::null_mut, time::Duration};

use getset::{CopyGetters, Getters};
use kadmin_sys::*;
#[cfg(feature = "python")]
use pyo3::prelude::*;

use crate::{
    conv::{c_string_to_string, delta_to_dur, dur_to_delta},
    error::Result,
    kadmin::KAdminImpl,
    keysalt::KeySalts,
    tl_data::{TlData, TlDataRaw},
};

/// A kadm5 policy
#[derive(Clone, Debug, Getters, CopyGetters)]
#[getset(get_copy = "pub")]
#[cfg_attr(feature = "python", pyclass(get_all))]
pub struct Policy {
    /// The policy name
    #[getset(skip)]
    name: String,
    /// Minimum lifetime of a password
    password_min_life: Option<Duration>,
    /// Maximum lifetime of a password
    password_max_life: Option<Duration>,
    /// Minimum length of a password
    password_min_length: i64,
    /// Minimum number of character classes required in a password. The five character classes are
    /// lower case, upper case, numbers, punctuation, and whitespace/unprintable characters
    password_min_classes: i64,
    /// Number of past keys kept for a principal. May not be filled if used with other database
    /// modules such as the MIT krb5 LDAP KDC database module
    password_history_num: i64,
    /// How many principals use this policy. Not filled for at least MIT krb5
    policy_refcnt: i64,
    /// Number of authentication failures before the principal is locked. Authentication failures
    /// are only tracked for principals which require preauthentication. The counter of failed
    /// attempts resets to 0 after a successful attempt to authenticate. A value of 0 disables
    /// lock‐out
    ///
    /// Only available in [version][`crate::kadmin::KAdminApiVersion`] 3 and above
    password_max_fail: u32,
    /// Allowable time between authentication failures. If an authentication failure happens after
    /// this duration has elapsed since the previous failure, the number of authentication failures
    /// is reset to 1. A value of `None` means forever
    ///
    /// Only available in [version][`crate::kadmin::KAdminApiVersion`] 3 and above
    password_failcount_interval: Option<Duration>,
    /// Duration for which the principal is locked from authenticating if too many authentication
    /// failures occur without the specified failure count interval elapsing. A duration of `None`
    /// means the principal remains locked out until it is administratively unlocked
    ///
    /// Only available in [version][`crate::kadmin::KAdminApiVersion`] 3 and above
    password_lockout_duration: Option<Duration>,
    /// Policy attributes
    ///
    /// Only available in [version][`crate::kadmin::KAdminApiVersion`] 4 and above
    attributes: i32,
    /// Maximum ticket life
    ///
    /// Only available in [version][`crate::kadmin::KAdminApiVersion`] 4 and above
    max_life: Option<Duration>,
    /// Maximum renewable ticket life
    ///
    /// Only available in [version][`crate::kadmin::KAdminApiVersion`] 4 and above
    max_renewable_life: Option<Duration>,
    /// Allowed keysalts
    ///
    /// Only available in [version][`crate::kadmin::KAdminApiVersion`] 4 and above
    #[getset(skip)]
    allowed_keysalts: Option<KeySalts>,
    /// TL-data
    ///
    /// Only available in [version][`crate::kadmin::KAdminApiVersion`] 4 and above
    #[getset(skip)]
    tl_data: TlData,
}

impl Policy {
    /// Create a [`Policy`] from [`_kadm5_policy_ent_t`]
    pub(crate) fn from_raw(entry: &_kadm5_policy_ent_t) -> Result<Self> {
        Ok(Self {
            name: c_string_to_string(entry.policy)?,
            password_min_life: delta_to_dur(entry.pw_min_life),
            password_max_life: delta_to_dur(entry.pw_max_life),
            password_min_length: entry.pw_min_length,
            password_min_classes: entry.pw_min_classes,
            password_history_num: entry.pw_history_num,
            policy_refcnt: entry.policy_refcnt,
            password_max_fail: entry.pw_max_fail,
            password_failcount_interval: delta_to_dur(entry.pw_failcnt_interval.into()),
            password_lockout_duration: delta_to_dur(entry.pw_lockout_duration.into()),
            attributes: entry.attributes,
            max_life: delta_to_dur(entry.max_life.into()),
            max_renewable_life: delta_to_dur(entry.max_renewable_life.into()),
            allowed_keysalts: if !entry.allowed_keysalts.is_null() {
                Some(KeySalts::from_str(&c_string_to_string(
                    entry.allowed_keysalts,
                )?)?)
            } else {
                None
            },
            tl_data: TlData::from_raw(entry.n_tl_data, entry.tl_data),
        })
    }

    /// Name of the policy
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Allowed keysalts
    ///
    /// Only available in [version][`crate::kadmin::KAdminApiVersion`] 4 and above
    pub fn allowed_keysalts(&self) -> Option<&KeySalts> {
        self.allowed_keysalts.as_ref()
    }

    /// TL-data
    ///
    /// Only available in [version][`crate::kadmin::KAdminApiVersion`] 4 and above
    pub fn tl_data(&self) -> &TlData {
        &self.tl_data
    }

    /// Construct a new [`PolicyBuilder`] for a policy with `name`
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # use crate::kadmin::{KAdmin, KAdminImpl, Policy};
    /// # #[cfg(feature = "client")]
    /// # fn example() {
    /// let kadm = kadmin::KAdmin::builder().with_ccache(None, None).unwrap();
    /// let polname = String::from("mynewpol");
    /// let password_max_life = Some(Duration::from_secs(365 * 24 * 60 * 60));
    /// let policy = Policy::builder(&polname)
    ///     .password_max_life(password_max_life)
    ///     .create(&kadm)
    ///     .unwrap();
    /// assert_eq!(policy.password_max_life(), password_max_life);
    /// # }
    /// ```
    pub fn builder(name: &str) -> PolicyBuilder {
        PolicyBuilder::new(name)
    }

    /// Construct a new [`PolicyModifier`] from this policy
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # use crate::kadmin::{KAdmin, KAdminImpl, Policy};
    /// # #[cfg(feature = "client")]
    /// # fn example() {
    /// let kadm = kadmin::KAdmin::builder().with_ccache(None, None).unwrap();
    /// let polname = String::from("mynewpol");
    /// let policy = kadm.get_policy(&polname).unwrap().unwrap();
    /// let policy = policy
    ///     .modifier()
    ///     .password_min_length(16)
    ///     .modify(&kadm)
    ///     .unwrap();
    /// assert_eq!(policy.password_min_length(), 16);
    /// # }
    /// ```
    pub fn modifier(&self) -> PolicyModifier {
        PolicyModifier::from_policy(self)
    }

    /// Delete this policy
    ///
    /// The [`Policy`] object is not consumed by this method, but after deletion, it shouldn't be
    /// used for modifying, as the policy may not exist anymore
    pub fn delete<K: KAdminImpl>(&self, kadmin: &K) -> Result<()> {
        kadmin.delete_policy(&self.name)
    }
}

macro_rules! policy_doer_struct {
    (
        $(#[$outer:meta])*
        $StructName:ident { $($manual_fields:tt)* }
    ) => {
        $(#[$outer])*
        pub struct $StructName {
            pub(crate) name: String,
            pub(crate) mask: i64,
            pub(crate) password_min_life: Option<Option<Duration>>,
            pub(crate) password_max_life: Option<Option<Duration>>,
            pub(crate) password_min_length: Option<i64>,
            pub(crate) password_min_classes: Option<i64>,
            pub(crate) password_history_num: Option<i64>,
            pub(crate) password_max_fail: Option<u32>,
            pub(crate) password_failcount_interval: Option<Option<Duration>>,
            pub(crate) password_lockout_duration: Option<Option<Duration>>,
            pub(crate) attributes: Option<i32>,
            pub(crate) max_life: Option<Option<Duration>>,
            pub(crate) max_renewable_life: Option<Option<Duration>>,
            pub(crate) allowed_keysalts: Option<Option<KeySalts>>,
            pub(crate) tl_data: Option<TlData>,
            $($manual_fields)*
        }
    }
}

macro_rules! policy_doer_impl {
    () => {
        /// Set the minimum lifetime of a password
        ///
        /// Pass `None` to clear it. Defaults to not set
        pub fn password_min_life(mut self, password_min_life: Option<Duration>) -> Self {
            self.password_min_life = Some(password_min_life);
            self.mask |= KADM5_PW_MIN_LIFE as i64;
            self
        }

        /// Set the maximum lifetime of a password
        ///
        /// Pass `None` to clear it. Defaults to not set
        pub fn password_max_life(mut self, password_max_life: Option<Duration>) -> Self {
            self.password_max_life = Some(password_max_life);
            self.mask |= KADM5_PW_MAX_LIFE as i64;
            self
        }

        /// Set the minimum length of a password
        ///
        /// Defaults to not set
        pub fn password_min_length(mut self, password_min_length: i64) -> Self {
            self.password_min_length = Some(password_min_length);
            self.mask |= KADM5_PW_MIN_LENGTH as i64;
            self
        }

        /// Set the minimum number of character classes required in a password. The five character
        /// classes are lower case, upper case, numbers, punctuation, and whitespace/unprintable
        /// characters
        ///
        /// Defaults to not set
        pub fn password_min_classes(mut self, password_min_classes: i64) -> Self {
            self.password_min_classes = Some(password_min_classes);
            self.mask |= KADM5_PW_MIN_CLASSES as i64;
            self
        }

        /// Set the number of past keys kept for a principal. May be ignored if used with other
        /// database modules such as the MIT krb5 LDAP KDC database module
        ///
        /// Defaults to not set
        pub fn password_history_num(mut self, password_history_num: i64) -> Self {
            self.password_history_num = Some(password_history_num);
            self.mask |= KADM5_PW_HISTORY_NUM as i64;
            self
        }

        /// Set the number of authentication failures before the principal is locked. Authentication
        /// failures are only tracked for principals which require preauthentication. The counter of
        /// failed attempts resets to 0 after a successful attempt to authenticate. A value of 0
        /// disables lock‐out
        ///
        /// Defaults to not set
        pub fn password_max_fail(mut self, password_max_fail: u32) -> Self {
            self.password_max_fail = Some(password_max_fail);
            self.mask |= KADM5_PW_MAX_FAILURE as i64;
            self
        }

        /// Set the allowable time between authentication failures. If an authentication failure
        /// happens after this duration has elapsed since the previous failure, the number of
        /// authentication failures is reset to 1.
        ///
        /// Setting this to `None` means forever. Defaults to not set
        pub fn password_failcount_interval(
            mut self,
            password_failcount_interval: Option<Duration>,
        ) -> Self {
            self.password_failcount_interval = Some(password_failcount_interval);
            self.mask |= KADM5_PW_FAILURE_COUNT_INTERVAL as i64;
            self
        }

        /// Set the duration for which the principal is locked from authenticating if too many
        /// authentication failures occur without the specified failure count interval elapsing.
        ///
        /// Setting this to `None` means the principal remains locked out until it is
        /// administratively unlocked. Defaults to not set
        pub fn password_lockout_duration(
            mut self,
            password_lockout_duration: Option<Duration>,
        ) -> Self {
            self.password_lockout_duration = Some(password_lockout_duration);
            self.mask |= KADM5_PW_LOCKOUT_DURATION as i64;
            self
        }

        /// Set policy attributes
        pub fn attributes(mut self, attributes: i32) -> Self {
            self.attributes = Some(attributes);
            self.mask |= KADM5_POLICY_ATTRIBUTES as i64;
            self
        }

        /// Set the maximum ticket life
        pub fn max_life(mut self, max_life: Option<Duration>) -> Self {
            self.max_life = Some(max_life);
            self.mask |= KADM5_POLICY_MAX_LIFE as i64;
            self
        }

        /// Set the maximum renewable ticket life
        pub fn max_renewable_life(mut self, max_renewable_life: Option<Duration>) -> Self {
            self.max_renewable_life = Some(max_renewable_life);
            self.mask |= KADM5_POLICY_MAX_RLIFE as i64;
            self
        }

        /// Set the allowed keysalts
        ///
        /// Pass `None` to clear it. Defaults to not set
        pub fn allowed_keysalts(mut self, allowed_keysalts: Option<KeySalts>) -> Self {
            self.allowed_keysalts = Some(allowed_keysalts);
            self.mask |= KADM5_POLICY_ALLOWED_KEYSALTS as i64;
            self
        }

        /// Add new TL-data
        pub fn tl_data(mut self, tl_data: TlData) -> Self {
            self.tl_data = Some(tl_data);
            self.mask |= KADM5_POLICY_TL_DATA as i64;
            self
        }

        /// Create a [`_kadm5_policy_ent_t`] from this builder
        pub(crate) fn make_entry(&self) -> Result<PolicyEntryRaw> {
            let mut policy = _kadm5_policy_ent_t::default();
            let name = CString::new(self.name.clone())?;
            policy.policy = name.as_ptr().cast_mut();
            if let Some(password_min_life) = self.password_min_life {
                policy.pw_min_life = dur_to_delta(password_min_life)?.into();
            }
            if let Some(password_max_life) = self.password_max_life {
                policy.pw_max_life = dur_to_delta(password_max_life)?.into();
            }
            if let Some(password_min_length) = self.password_min_length {
                policy.pw_min_length = password_min_length;
            }
            if let Some(password_min_classes) = self.password_min_classes {
                policy.pw_min_classes = password_min_classes;
            }
            if let Some(password_history_num) = self.password_history_num {
                policy.pw_history_num = password_history_num;
            }
            if let Some(password_max_fail) = self.password_max_fail {
                policy.pw_max_fail = password_max_fail;
            }
            if let Some(password_failcount_interval) = self.password_failcount_interval {
                policy.pw_failcnt_interval = dur_to_delta(password_failcount_interval)?;
            }
            if let Some(password_lockout_duration) = self.password_lockout_duration {
                policy.pw_lockout_duration = dur_to_delta(password_lockout_duration)?;
            }
            if let Some(attributes) = self.attributes {
                policy.attributes = attributes;
            }
            if let Some(max_life) = self.max_life {
                policy.max_life = dur_to_delta(max_life)?;
            }
            if let Some(max_renewable_life) = self.max_renewable_life {
                policy.max_renewable_life = dur_to_delta(max_renewable_life)?;
            }
            let allowed_keysalts = if let Some(allowed_keysalts) = &self.allowed_keysalts {
                if let Some(allowed_keysalts) = allowed_keysalts {
                    let raw_allowed_keysalts = allowed_keysalts.to_cstring()?;
                    policy.allowed_keysalts = raw_allowed_keysalts.as_ptr().cast_mut();
                    Some(raw_allowed_keysalts)
                } else {
                    policy.allowed_keysalts = null_mut();
                    None
                }
            } else {
                None
            };
            let tl_data = if let Some(tl_data) = &self.tl_data {
                //  We store the raw data in PolicyEntryRaw
                let mut raw_tl_data = tl_data.to_raw();
                if let Some(ref mut raw_tl_data) = &mut raw_tl_data {
                    policy.n_tl_data = tl_data.entries.len() as i16;
                    policy.tl_data = &mut raw_tl_data.raw;
                } else {
                    policy.n_tl_data = 0;
                    policy.tl_data = null_mut();
                }
                raw_tl_data
            } else {
                None
            };
            Ok(PolicyEntryRaw {
                raw: policy,
                _raw_name: name,
                _raw_allowed_keysalts: allowed_keysalts,
                _raw_tl_data: tl_data,
            })
        }
    };
}

policy_doer_struct!(
    /// Utility to create a policy
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # use crate::kadmin::{KAdmin, KAdminImpl, Policy};
    /// # #[cfg(feature = "client")]
    /// # fn example() {
    /// let kadm = kadmin::KAdmin::builder().with_ccache(None, None).unwrap();
    /// let polname = String::from("mynewpol");
    /// let password_max_life = Some(Duration::from_secs(365 * 24 * 60 * 60));
    /// let policy = Policy::builder(&polname)
    ///     .password_max_life(password_max_life)
    ///     .create(&kadm)
    ///     .unwrap();
    /// assert_eq!(policy.password_max_life(), password_max_life);
    /// # }
    /// ```
    #[derive(Clone, Debug, Default)]
    PolicyBuilder {}
);

impl PolicyBuilder {
    policy_doer_impl!();

    /// Construct a new [`PolicyBuilder`] for a policy with `name`
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            ..Default::default()
        }
    }

    /// Set the name of the policy
    pub fn name(mut self, name: &str) -> Self {
        self.name = name.to_owned();
        self
    }

    /// Create the policy
    pub fn create<K: KAdminImpl>(&self, kadmin: &K) -> Result<Policy> {
        kadmin.add_policy(self)?;
        Ok(kadmin.get_policy(&self.name)?.unwrap())
    }
}

policy_doer_struct!(
    /// Utility to modify a policy
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # use crate::kadmin::{KAdmin, KAdminImpl, Policy};
    /// # #[cfg(feature = "client")]
    /// # fn example() {
    /// let kadm = kadmin::KAdmin::builder().with_ccache(None, None).unwrap();
    /// let polname = String::from("mynewpol");
    /// let policy = kadm.get_policy(&polname).unwrap().unwrap();
    /// let policy = policy.modifier().password_min_length(16).modify(&kadm).unwrap();
    /// assert_eq!(policy.password_min_length(), 16);
    /// # }
    /// ```
    #[derive(Clone, Debug, Default)]
    PolicyModifier {}
);

impl PolicyModifier {
    policy_doer_impl!();

    /// Construct a new [`PolicyModifier`] from a [`Policy`]
    pub fn from_policy(policy: &Policy) -> Self {
        Self {
            name: policy.name().to_owned(),
            ..Default::default()
        }
    }

    /// Modify the policy
    ///
    /// A new up-to-date instance of [`Policy`] is returned, but the old one is still available
    pub fn modify<K: KAdminImpl>(&self, kadmin: &K) -> Result<Policy> {
        kadmin.modify_policy(self)?;
        Ok(kadmin.get_policy(&self.name)?.unwrap())
    }
}

pub(crate) struct PolicyEntryRaw {
    pub(crate) raw: _kadm5_policy_ent_t,
    _raw_name: CString,
    _raw_allowed_keysalts: Option<CString>,
    _raw_tl_data: Option<TlDataRaw>,
}

//! kadm5 policy
use std::{
    ffi::{CString, c_long, c_void},
    ptr::null_mut,
    time::Duration,
};

use getset::{CopyGetters, Getters};
#[cfg(feature = "python")]
use pyo3::prelude::*;

use crate::{
    KeySalts,
    context::Context,
    conv::{c_string_to_string, delta_to_dur, dur_to_delta},
    error::Result,
    kadmin::KAdminImpl,
    sys::{cfg_match, library_match},
    tl_data::{TlData, TlDataRaw},
};

/// A kadm5 policy
#[derive(Clone, Debug, Default, Getters, CopyGetters)]
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
    #[cfg(any(mit_client, mit_server))]
    /// Number of authentication failures before the principal is locked. Authentication failures
    /// are only tracked for principals which require preauthentication. The counter of failed
    /// attempts resets to 0 after a successful attempt to authenticate. A value of 0 disables
    /// lock‐out
    ///
    /// Only available in MIT and [version][`crate::kadmin::KAdminApiVersion`] 3 and above
    password_max_fail: u32,
    #[cfg(any(mit_client, mit_server))]
    /// Allowable time between authentication failures. If an authentication failure happens after
    /// this duration has elapsed since the previous failure, the number of authentication failures
    /// is reset to 1. A value of `None` means forever
    ///
    /// Only available in MIT and [version][`crate::kadmin::KAdminApiVersion`] 3 and above
    password_failcount_interval: Option<Duration>,
    #[cfg(any(mit_client, mit_server))]
    /// Duration for which the principal is locked from authenticating if too many authentication
    /// failures occur without the specified failure count interval elapsing. A duration of `None`
    /// means the principal remains locked out until it is administratively unlocked
    ///
    /// Only available in MIT and [version][`crate::kadmin::KAdminApiVersion`] 3 and above
    password_lockout_duration: Option<Duration>,
    #[cfg(any(mit_client, mit_server))]
    /// Policy attributes
    ///
    /// Only available in MIT and [version][`crate::kadmin::KAdminApiVersion`] 4 and above
    attributes: i32,
    #[cfg(any(mit_client, mit_server))]
    /// Maximum ticket life
    ///
    /// Only available in MIT and [version][`crate::kadmin::KAdminApiVersion`] 4 and above
    max_life: Option<Duration>,
    #[cfg(any(mit_client, mit_server))]
    /// Maximum renewable ticket life
    ///
    /// Only available in MIT and [version][`crate::kadmin::KAdminApiVersion`] 4 and above
    max_renewable_life: Option<Duration>,
    #[cfg(any(mit_client, mit_server))]
    /// Allowed keysalts
    ///
    /// Only available in MIT and [version][`crate::kadmin::KAdminApiVersion`] 4 and above
    #[getset(skip)]
    allowed_keysalts: Option<KeySalts>,
    #[cfg(any(mit_client, mit_server))]
    /// TL-data
    ///
    /// Only available in MIT and [version][`crate::kadmin::KAdminApiVersion`] 4 and above
    #[getset(skip)]
    tl_data: TlData,
}

impl Policy {
    /// Create a [`Policy`] from [`_kadm5_policy_ent_t`]
    pub(crate) fn from_raw(context: &Context, entry: *const c_void) -> Result<Self> {
        let mut pol = library_match!(&context.library; |_cont, lib| {
            let entry = entry as *const lib!(_kadm5_policy_ent_t);

            Self {
                name: c_string_to_string(unsafe { *entry }.policy)?,
                password_min_life: delta_to_dur(unsafe { *entry }.pw_min_life.into()),
                password_max_life: delta_to_dur(unsafe { *entry }.pw_max_life.into()),
                password_min_length: unsafe { *entry }.pw_min_length.into(),
                password_min_classes: unsafe { *entry }.pw_min_classes.into(),
                password_history_num: unsafe { *entry }.pw_history_num.into(),
                policy_refcnt: unsafe { *entry }.policy_refcnt.into(),
                ..Default::default()
            }
        });

        library_match!(
            &context.library;
            mit_client, mit_server => |_cont, lib| {
                let entry = entry as *const lib!(_kadm5_policy_ent_t);

                pol.password_max_fail = unsafe { *entry }.pw_max_fail.into();
                pol.password_failcount_interval = delta_to_dur(unsafe { *entry }.pw_failcnt_interval.into());
                pol.password_lockout_duration = delta_to_dur(unsafe { *entry }.pw_lockout_duration.into());
                pol.attributes = unsafe { *entry }.attributes;
                pol.max_life = delta_to_dur(unsafe { *entry }.max_life.into());
                pol.max_renewable_life = delta_to_dur(unsafe { *entry }.max_renewable_life.into());
                pol.allowed_keysalts = if ! unsafe { *entry }.allowed_keysalts.is_null() {
                    Some(KeySalts::from_str(
                        context,
                        &c_string_to_string(unsafe { *entry }.allowed_keysalts)?,
                    )?)
                } else {
                    None
                };
                pol.tl_data = TlData::from_raw(
                    context,
                    unsafe { *entry }.n_tl_data,
                    unsafe { *entry }.tl_data as *const c_void
                );
            },
            heimdal_client, heimdal_server => |_cont, _lib| {}
        );
        Ok(pol)
    }

    /// Name of the policy
    pub fn name(&self) -> &str {
        &self.name
    }

    #[cfg(any(mit_client, mit_server))]
    /// Allowed keysalts
    ///
    /// Only available in MIT and [version][`crate::kadmin::KAdminApiVersion`] 4 and above
    pub fn allowed_keysalts(&self) -> Option<&KeySalts> {
        self.allowed_keysalts.as_ref()
    }

    #[cfg(any(mit_client, mit_server))]
    /// TL-data
    ///
    /// Only available in MIT and [version][`crate::kadmin::KAdminApiVersion`] 4 and above
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

            #[cfg(mit_client)]
            pub(crate) mask_mit_client: c_long,
            #[cfg(mit_server)]
            pub(crate) mask_mit_server: c_long,
            #[cfg(heimdal_server)]
            pub(crate) mask_heimdal_server: c_long,

            pub(crate) password_min_life: Option<Option<Duration>>,
            pub(crate) password_max_life: Option<Option<Duration>>,
            pub(crate) password_min_length: Option<c_long>,
            pub(crate) password_min_classes: Option<c_long>,
            pub(crate) password_history_num: Option<c_long>,
            #[cfg(any(mit_client, mit_server))]
            pub(crate) password_max_fail: Option<u32>,
            #[cfg(any(mit_client, mit_server))]
            pub(crate) password_failcount_interval: Option<Option<Duration>>,
            #[cfg(any(mit_client, mit_server))]
            pub(crate) password_lockout_duration: Option<Option<Duration>>,
            #[cfg(any(mit_client, mit_server))]
            pub(crate) attributes: Option<i32>,
            #[cfg(any(mit_client, mit_server))]
            pub(crate) max_life: Option<Option<Duration>>,
            #[cfg(any(mit_client, mit_server))]
            pub(crate) max_renewable_life: Option<Option<Duration>>,
            #[cfg(any(mit_client, mit_server))]
            pub(crate) allowed_keysalts: Option<Option<KeySalts>>,
            #[cfg(any(mit_client, mit_server))]
            pub(crate) tl_data: Option<TlData>,
            $($manual_fields)*
        }
    }
}

macro_rules! set_mask {
    ($self:ident, $mask:ident) => {
        cfg_match!(
            mit_client => |lib| $self.mask_mit_client |= lib!($mask) as i64,
            mit_server => |lib| $self.mask_mit_server |= lib!($mask) as i64,
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
    (@attr $self:ident, heimdal_server) => {
        $self.mask_heimdal_server
    };
}

macro_rules! policy_doer_impl {
    () => {
        /// Set the minimum lifetime of a password
        ///
        /// Pass `None` to clear it. Defaults to not set
        pub fn password_min_life(mut self, password_min_life: Option<Duration>) -> Self {
            self.password_min_life = Some(password_min_life);
            set_mask!(self, KADM5_PW_MIN_LIFE);
            self
        }

        /// Set the maximum lifetime of a password
        ///
        /// Pass `None` to clear it. Defaults to not set
        pub fn password_max_life(mut self, password_max_life: Option<Duration>) -> Self {
            self.password_max_life = Some(password_max_life);
            set_mask!(self, KADM5_PW_MAX_LIFE);
            self
        }

        /// Set the minimum length of a password
        ///
        /// Defaults to not set
        pub fn password_min_length(mut self, password_min_length: c_long) -> Self {
            self.password_min_length = Some(password_min_length);
            set_mask!(self, KADM5_PW_MIN_LENGTH);
            self
        }

        /// Set the minimum number of character classes required in a password. The five character
        /// classes are lower case, upper case, numbers, punctuation, and whitespace/unprintable
        /// characters
        ///
        /// Defaults to not set
        pub fn password_min_classes(mut self, password_min_classes: c_long) -> Self {
            self.password_min_classes = Some(password_min_classes);
            set_mask!(self, KADM5_PW_MIN_CLASSES);
            self
        }

        /// Set the number of past keys kept for a principal. May be ignored if used with other
        /// database modules such as the MIT krb5 LDAP KDC database module
        ///
        /// Defaults to not set
        pub fn password_history_num(mut self, password_history_num: c_long) -> Self {
            self.password_history_num = Some(password_history_num);
            set_mask!(self, KADM5_PW_HISTORY_NUM);
            self
        }

        #[cfg(any(mit_client, mit_server))]
        /// Set the number of authentication failures before the principal is locked. Authentication
        /// failures are only tracked for principals which require preauthentication. The counter of
        /// failed attempts resets to 0 after a successful attempt to authenticate. A value of 0
        /// disables lock‐out
        ///
        /// Defaults to not set
        ///
        /// Only available in MIT and [version][`crate::kadmin::KAdminApiVersion`] 3 and above
        pub fn password_max_fail(mut self, password_max_fail: u32) -> Self {
            self.password_max_fail = Some(password_max_fail);
            set_mask!(self; mit_client, mit_server => KADM5_PW_MAX_FAILURE);
            self
        }

        #[cfg(any(mit_client, mit_server))]
        /// Set the allowable time between authentication failures. If an authentication failure
        /// happens after this duration has elapsed since the previous failure, the number of
        /// authentication failures is reset to 1.
        ///
        /// Setting this to `None` means forever. Defaults to not set
        ///
        /// Only available in MIT and [version][`crate::kadmin::KAdminApiVersion`] 3 and above
        pub fn password_failcount_interval(
            mut self,
            password_failcount_interval: Option<Duration>,
        ) -> Self {
            self.password_failcount_interval = Some(password_failcount_interval);
            set_mask!(self; mit_client, mit_server => KADM5_PW_FAILURE_COUNT_INTERVAL);
            self
        }

        #[cfg(any(mit_client, mit_server))]
        /// Set the duration for which the principal is locked from authenticating if too many
        /// authentication failures occur without the specified failure count interval elapsing.
        ///
        /// Setting this to `None` means the principal remains locked out until it is
        /// administratively unlocked. Defaults to not set
        ///
        /// Only available in MIT and [version][`crate::kadmin::KAdminApiVersion`] 3 and above
        pub fn password_lockout_duration(
            mut self,
            password_lockout_duration: Option<Duration>,
        ) -> Self {
            self.password_lockout_duration = Some(password_lockout_duration);
            set_mask!(self; mit_client, mit_server => KADM5_PW_LOCKOUT_DURATION);
            self
        }

        #[cfg(any(mit_client, mit_server))]
        /// Set policy attributes
        ///
        /// Only available in MIT and [version][`crate::kadmin::KAdminApiVersion`] 3 and above
        pub fn attributes(mut self, attributes: i32) -> Self {
            self.attributes = Some(attributes);
            set_mask!(self; mit_client, mit_server => KADM5_POLICY_ATTRIBUTES);
            self
        }

        #[cfg(any(mit_client, mit_server))]
        /// Set the maximum ticket life
        ///
        /// Only available in MIT and [version][`crate::kadmin::KAdminApiVersion`] 3 and above
        pub fn max_life(mut self, max_life: Option<Duration>) -> Self {
            self.max_life = Some(max_life);
            set_mask!(self; mit_client, mit_server => KADM5_POLICY_MAX_LIFE);
            self
        }

        #[cfg(any(mit_client, mit_server))]
        /// Set the maximum renewable ticket life
        ///
        /// Only available in MIT and [version][`crate::kadmin::KAdminApiVersion`] 3 and above
        pub fn max_renewable_life(mut self, max_renewable_life: Option<Duration>) -> Self {
            self.max_renewable_life = Some(max_renewable_life);
            set_mask!(self; mit_client, mit_server => KADM5_POLICY_MAX_RLIFE);
            self
        }

        #[cfg(any(mit_client, mit_server))]
        /// Set the allowed keysalts
        ///
        /// Pass `None` to clear it. Defaults to not set
        ///
        /// Only available in MIT and [version][`crate::kadmin::KAdminApiVersion`] 3 and above
        pub fn allowed_keysalts(mut self, allowed_keysalts: Option<KeySalts>) -> Self {
            self.allowed_keysalts = Some(allowed_keysalts);
            set_mask!(self; mit_client, mit_server => KADM5_POLICY_ALLOWED_KEYSALTS);
            self
        }

        #[cfg(any(mit_client, mit_server))]
        /// Add new TL-data
        ///
        /// Only available in MIT and [version][`crate::kadmin::KAdminApiVersion`] 3 and above
        pub fn tl_data(mut self, tl_data: TlData) -> Self {
            self.tl_data = Some(tl_data);
            set_mask!(self; mit_client, mit_server => KADM5_POLICY_TL_DATA);
            self
        }

        /// Create a [`_kadm5_policy_ent_t`] from this builder
        pub(crate) fn make_entry<'a>(&self, context: &'a Context) -> Result<(PolicyEntryRaw<'a>, i64)> {
            let mask = library_match!(
                &context.library;
                mit_client => |_cont, _lib| self.mask_mit_client,
                mit_server => |_cont, _lib| self.mask_mit_server,
                heimdal_server => |_cont, _lib| self.mask_heimdal_server,
                heimdal_client => |_cont, _lib| 0
            );

            let name = CString::new(self.name.clone())?;
            let policy = library_match!(&context.library; |_cont, lib| {
                let mut policy: lib!(_kadm5_policy_ent_t) = Default::default();

                policy.policy = name.as_ptr().cast_mut();
                if let Some(password_min_life) = self.password_min_life {
                    policy.pw_min_life = dur_to_delta(password_min_life)?.try_into().unwrap();
                }
                if let Some(password_max_life) = self.password_max_life {
                    policy.pw_max_life = dur_to_delta(password_max_life)?.try_into().unwrap();
                }
                if let Some(password_min_length) = self.password_min_length {
                    policy.pw_min_length = password_min_length.try_into().unwrap();
                }
                if let Some(password_min_classes) = self.password_min_classes {
                    policy.pw_min_classes = password_min_classes.try_into().unwrap();
                }
                if let Some(password_history_num) = self.password_history_num {
                    policy.pw_history_num = password_history_num.try_into().unwrap();
                }

                let policy = Box::new(policy);
                Box::into_raw(policy) as *const c_void
            });

            let (policy, allowed_keysalts, tl_data) = library_match!(
                &context.library;
                mit_client, mit_server => |_cont, lib| {
                    let mut policy: Box<lib!(_kadm5_policy_ent_t)> = unsafe { Box::from_raw(policy as *mut lib!(_kadm5_policy_ent_t)) };

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
                            let raw_allowed_keysalts = allowed_keysalts.to_cstring(context)?;
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
                        let raw_tl_data = TlDataRaw::build(context, tl_data);
                        policy.n_tl_data = tl_data.entries.len() as i16;
                        policy.tl_data = raw_tl_data.raw as *mut lib!(_krb5_tl_data);
                        Some(raw_tl_data)
                    } else {
                        None
                    };

                    (Box::into_raw(policy) as *const c_void, allowed_keysalts, tl_data)
                },
                heimdal_server, heimdal_client => |_cont, _lib| {(policy, None, None)}
            );

            Ok((PolicyEntryRaw {
                raw: policy,
                context,
                _raw_name: name,
                _raw_allowed_keysalts: allowed_keysalts,
                _raw_tl_data: tl_data,
            }, mask))
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

pub(crate) struct PolicyEntryRaw<'a> {
    pub(crate) raw: *const c_void,
    context: &'a Context,

    _raw_name: CString,
    _raw_allowed_keysalts: Option<CString>,
    _raw_tl_data: Option<TlDataRaw<'a>>,
}

impl Drop for PolicyEntryRaw<'_> {
    fn drop(&mut self) {
        if self.raw.is_null() {
            return;
        }
        library_match!(&self.context.library; |_cont, lib| {
            let raw: Box<lib!(_kadm5_policy_ent_t)> = unsafe { Box::from_raw(self.raw as *mut lib!(_kadm5_policy_ent_t)) };
            drop(raw);
        });
    }
}

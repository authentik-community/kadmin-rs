use std::{os::raw::c_char, ptr::null_mut, time::Duration};

use chrono::{DateTime, Utc};
use kadmin_sys::*;

use crate::{
    error::{Error, Result, krb5_error_code_escape_hatch},
    kadmin::{KAdmin, KAdminImpl},
    strconv::c_string_to_string,
};

fn ts_to_dt(ts: krb5_timestamp) -> Result<DateTime<Utc>> {
    DateTime::from_timestamp((ts as u32).into(), 0).ok_or(Error::TimestampConversion)
}

#[derive(Debug)]
#[allow(dead_code)] // TODO: remove me once implemented
pub struct Principal {
    name: String,
    expire_time: DateTime<Utc>,
    last_password_change: DateTime<Utc>,
    password_expiration: DateTime<Utc>,
    max_life: Duration,
    modified_by: String,
    modified_at: DateTime<Utc>,
    // TODO: enum
    attributes: i32,
    kvno: u32,
    mkvno: u32,
    policy: Option<String>,
    // TODO: figure out what that does
    aux_attributes: i64,
    max_renewable_life: Duration,
    last_success: DateTime<Utc>,
    last_failed: DateTime<Utc>,
    fail_auth_count: u32,
    // TODO: key data
}

impl Principal {
    pub(crate) fn from_raw(kadmin: &KAdmin, entry: &_kadm5_principal_ent_t) -> Result<Self> {
        // TODO: make a function out of this
        let name = {
            let mut raw_name: *mut c_char = null_mut();
            let code = unsafe { krb5_unparse_name(kadmin.context.context, entry.principal, &mut raw_name) };
            krb5_error_code_escape_hatch(&kadmin.context, code)?;
            let name = c_string_to_string(raw_name)?;
            unsafe {
                krb5_free_unparsed_name(kadmin.context.context, raw_name);
            }
            name
        };
        let modified_by = {
            let mut raw_name: *mut c_char = null_mut();
            let code = unsafe { krb5_unparse_name(kadmin.context.context, entry.mod_name, &mut raw_name) };
            krb5_error_code_escape_hatch(&kadmin.context, code)?;
            let name = c_string_to_string(raw_name)?;
            unsafe {
                krb5_free_unparsed_name(kadmin.context.context, raw_name);
            }
            name
        };
        Ok(Self {
            name,
            expire_time: ts_to_dt(entry.princ_expire_time)?,
            last_password_change: ts_to_dt(entry.last_pwd_change)?,
            password_expiration: ts_to_dt(entry.pw_expiration)?,
            max_life: Duration::from_secs(entry.max_life as u64),
            modified_by,
            modified_at: ts_to_dt(entry.mod_date)?,
            attributes: entry.attributes,
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

    pub fn change_password<K: KAdminImpl>(&self, kadmin: &K, password: &str) -> Result<()> {
        kadmin.principal_change_password(&self.name, password)
    }
}

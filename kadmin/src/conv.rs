//! Conversion utilities

use std::{ffi::CStr, os::raw::c_char, time::Duration};

use chrono::{DateTime, Utc};
use kadmin_sys::*;

use crate::error::{Error, Result};

/// Convert a `*const c_char` to a [`String`]
pub(crate) fn c_string_to_string(c_string: *const c_char) -> Result<String> {
    if c_string.is_null() {
        return Err(Error::NullPointerDereference);
    }

    match unsafe { CStr::from_ptr(c_string) }.to_owned().into_string() {
        Ok(string) => Ok(string),
        Err(error) => Err(error.into()),
    }
}

/// Convert a [`krb5_timestamp`] to a [`DateTime<Utc>`]
pub(crate) fn ts_to_dt(ts: krb5_timestamp) -> Result<Option<DateTime<Utc>>> {
    if ts == 0 {
        return Ok(None);
    }
    DateTime::from_timestamp((ts as u32).into(), 0)
        .map(Some)
        .ok_or(Error::TimestampConversion)
}

/// Convert a [`krb5_deltat`] to a [`Duration`]
pub(crate) fn delta_to_dur(delta: i64) -> Option<Duration> {
    if delta == 0 {
        return None;
    }
    Some(Duration::from_secs(delta as u64))
}

/// Convert a [`Duration`] to a [`krb5_deltat`]
pub(crate) fn dur_to_delta(dur: Option<Duration>) -> Result<krb5_deltat> {
    if let Some(dur) = dur {
        dur.as_secs().try_into().map_err(Error::DateTimeConversion)
    } else {
        Ok(0)
    }
}

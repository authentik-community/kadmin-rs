//! Conversion utilities

use std::{ffi::CStr, os::raw::c_char};

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
pub(crate) fn ts_to_dt(ts: krb5_timestamp) -> Result<DateTime<Utc>> {
    DateTime::from_timestamp((ts as u32).into(), 0).ok_or(Error::TimestampConversion)
}

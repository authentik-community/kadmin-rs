//! Conversion utilities

use std::{ffi::CStr, os::raw::c_char, ptr::null_mut};

use chrono::{DateTime, Utc};
use kadmin_sys::*;

use crate::{
    context::Context,
    error::{Error, Result, krb5_error_code_escape_hatch},
};

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
        .map(|dt| Some(dt))
        .ok_or(Error::TimestampConversion)
}

/// Convert a [`krb5_principal`] to a [`String`]
pub(crate) fn unparse_name(context: &Context, principal: krb5_principal) -> Result<String> {
    let mut raw_name: *mut c_char = null_mut();
    let code = unsafe { krb5_unparse_name(context.context, principal, &mut raw_name) };
    krb5_error_code_escape_hatch(context, code)?;
    let name = c_string_to_string(raw_name)?;
    unsafe {
        krb5_free_unparsed_name(context.context, raw_name);
    }
    Ok(name)
}

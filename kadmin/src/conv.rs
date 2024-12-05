//! Conversion utilities

use std::{ffi::{CString, CStr}, os::raw::c_char, ptr::null_mut, time::Duration};

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
        .map(Some)
        .ok_or(Error::TimestampConversion)
}

/// Convert a [`DateTime<Utc>`] to a [`krb5_timestamp`]
pub(crate) fn dt_to_ts(dt: Option<DateTime<Utc>>) -> Result<krb5_timestamp> {
    if let Some(dt) = dt {
        dt.timestamp().try_into().map_err(Error::DateTimeConversion)
    } else {
        Ok(0)
    }
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

/// Convert a [`krb5_principal`] to a [`String`]
pub(crate) fn unparse_name(context: &Context, principal: krb5_principal) -> Result<Option<String>> {
    if principal.is_null() {
        return Ok(None);
    }
    let mut raw_name: *mut c_char = null_mut();
    let code = unsafe { krb5_unparse_name(context.context, principal, &mut raw_name) };
    krb5_error_code_escape_hatch(context, code)?;
    let name = c_string_to_string(raw_name)?;
    unsafe {
        krb5_free_unparsed_name(context.context, raw_name);
    }
    Ok(Some(name))
}

pub(crate) fn parse_name<'a>(context: &'a Context, name: &str) -> Result<ParsedName<'a>> {
    let name = CString::new(name)?;
    let mut parsed_name = ParsedName {
        raw: null_mut(),
        context,
    };

    let code = unsafe {
        krb5_parse_name(
            context.context,
            name.as_ptr().cast_mut(),
            &mut parsed_name.raw,
        )
    };
    krb5_error_code_escape_hatch(context, code)?;
    let mut canon = null_mut();
    let code = unsafe {
        krb5_unparse_name(context.context, parsed_name.raw, &mut canon)
    };
    krb5_error_code_escape_hatch(context, code)?;
    Ok(parsed_name)
}

pub(crate) struct ParsedName<'a> {
    pub(crate) raw: krb5_principal,
    context: &'a Context,
}

impl Drop for ParsedName<'_> {
    fn drop(&mut self) {
        if self.raw.is_null() { return; }
        unsafe { krb5_free_principal(self.context.context, self.raw) }
    }
}

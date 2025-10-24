//! Conversion utilities

use std::{
    ffi::{CStr, CString, c_void},
    os::raw::c_char,
    ptr::null_mut,
    time::Duration,
};

use chrono::{DateTime, Utc};

use crate::{
    context::Context,
    error::{Error, Result, krb5_error_code_escape_hatch},
    sys::library_match,
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
pub(crate) fn ts_to_dt(ts: i64) -> Result<Option<DateTime<Utc>>> {
    if ts == 0 {
        return Ok(None);
    }
    DateTime::from_timestamp((ts as u32).into(), 0)
        .map(Some)
        .ok_or(Error::TimestampConversion)
}

/// Convert a [`DateTime<Utc>`] to a [`krb5_timestamp`]
pub(crate) fn dt_to_ts(dt: Option<DateTime<Utc>>) -> Result<i32> {
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
pub(crate) fn dur_to_delta(dur: Option<Duration>) -> Result<i32> {
    if let Some(dur) = dur {
        dur.as_secs().try_into().map_err(Error::DateTimeConversion)
    } else {
        Ok(0)
    }
}

/// Convert a `krb5_principal` to a [`String`]
pub(crate) fn unparse_name(context: &Context, principal: *const c_void) -> Result<Option<String>> {
    if principal.is_null() {
        return Ok(None);
    }
    let mut raw_name: *mut c_char = null_mut();
    let code = library_match!(&context.library; |cont, lib| unsafe {
        cont.krb5_unparse_name(
            context.context as lib!(krb5_context),
            principal as lib!(krb5_const_principal),
            &mut raw_name
        )
    });
    krb5_error_code_escape_hatch(context, code.into())?;
    let name = c_string_to_string(raw_name)?;
    library_match!(&context.library; |cont, lib| unsafe {
        cont.krb5_free_unparsed_name(
            context.context as lib!(krb5_context),
            raw_name,
        );
    });
    Ok(Some(name))
}

pub(crate) fn parse_name<'a>(context: &'a Context, name: &str) -> Result<ParsedName<'a>> {
    let name = CString::new(name)?;

    let (raw, code) = library_match!(&context.library; |cont, lib| {
        let mut raw: lib!(krb5_principal) = null_mut();
        let code = unsafe { cont.krb5_parse_name(
            context.context as lib!(krb5_context),
            name.as_ptr().cast_mut(),
            &mut raw,
        ) };
        (raw as *mut c_void, code)
    });

    let parsed_name = ParsedName { raw, context };

    krb5_error_code_escape_hatch(context, code.into())?;
    let mut canon = null_mut();
    let code = library_match!(&context.library; |cont, lib| unsafe {
        cont.krb5_unparse_name(
            context.context as lib!(krb5_context),
            parsed_name.raw as lib!(krb5_principal),
            &mut canon,
        )
    });
    krb5_error_code_escape_hatch(context, code.into())?;
    Ok(parsed_name)
}

pub(crate) struct ParsedName<'a> {
    pub(crate) raw: *mut c_void,
    context: &'a Context,
}

impl Drop for ParsedName<'_> {
    fn drop(&mut self) {
        if self.raw.is_null() {
            return;
        }
        library_match!(&self.context.library; |cont, lib| unsafe {
            cont.krb5_free_principal(
                self.context.context as lib!(krb5_context),
                self.raw as lib!(krb5_principal),
            );
        });
    }
}

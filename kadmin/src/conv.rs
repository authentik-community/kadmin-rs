use std::{ffi::CStr, os::raw::c_char};

use crate::error::{Error, Result};

pub(crate) fn c_string_to_string(c_string: *const c_char) -> Result<String> {
    if c_string.is_null() {
        return Err(Error::NullPointerDereference);
    }

    match unsafe { CStr::from_ptr(c_string) }.to_owned().into_string() {
        Ok(string) => Ok(string),
        Err(error) => Err(error.into()),
    }
}

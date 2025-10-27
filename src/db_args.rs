//! Define [`DbArgs`] to pass to kadm5

use std::{ffi::CString, os::raw::c_char, ptr::null_mut};

#[cfg(feature = "python")]
use pyo3::prelude::*;

use crate::{
    error::Result,
    tl_data::{TlData, TlDataEntry},
};

/// Database specific arguments
///
/// See `man kadmin(1)` for a list of supported arguments
///
/// ```
/// let db_args = kadmin::DbArgs::builder()
///     .arg("host", Some("ldap.example.org"))
///     .build()
///     .unwrap();
/// ```
#[derive(Debug)]
#[cfg_attr(feature = "python", pyclass)]
pub struct DbArgs {
    /// NULL-terminated list of strings of the form `arg[=value]`
    ///
    /// There are additional fields to store transient strings so the pointer stored in db_args
    /// doesn't become invalid while this struct lives
    pub(crate) db_args: *mut *mut c_char,

    /// Store CStrings that are of the form `arg[=value]`
    _origin_args: Vec<CString>,
    /// Store the Vec containing the pointers to the above CStrings
    _ptr_vec: Vec<*mut c_char>,
}

// Pointees are contained in the struct itself
unsafe impl Send for DbArgs {}
unsafe impl Sync for DbArgs {}

impl Clone for DbArgs {
    fn clone(&self) -> Self {
        let mut _origin_args = vec![];
        let mut _ptr_vec = vec![];
        for arg in &self._origin_args {
            let c_arg = arg.clone();
            _ptr_vec.push(c_arg.as_ptr().cast_mut());
            _origin_args.push(c_arg);
        }
        // Null terminated
        _ptr_vec.push(null_mut());

        let db_args = _ptr_vec.as_mut_ptr();

        DbArgs {
            db_args,
            _origin_args,
            _ptr_vec,
        }
    }
}

impl DbArgs {
    /// Construct a new [`DbArgsBuilder`]
    pub fn builder() -> DbArgsBuilder {
        DbArgsBuilder::default()
    }
}

impl Default for DbArgs {
    /// Construct an empty [`DbArgs`]
    fn default() -> Self {
        Self::builder().build().unwrap()
    }
}

impl From<&DbArgs> for TlData {
    fn from(db_args: &DbArgs) -> Self {
        Self {
            entries: db_args
                ._origin_args
                .iter()
                .map(|arg| TlDataEntry {
                    data_type: 0,
                    contents: arg.to_bytes_with_nul().to_vec(),
                })
                .collect(),
        }
    }
}

/// [`DbArgs`] builder
#[derive(Clone, Debug, Default)]
pub struct DbArgsBuilder(Vec<(String, Option<String>)>);

impl DbArgsBuilder {
    /// Add an argument with an optional value
    pub fn arg(mut self, name: &str, value: Option<&str>) -> Self {
        self.0.push((name.to_owned(), value.map(|s| s.to_owned())));
        self
    }

    /// Construct [`DbArgs`] from the provided arguments
    pub fn build(&self) -> Result<DbArgs> {
        let formatted_args = self.0.clone().into_iter().map(|(name, value)| {
            if let Some(value) = value {
                format!("{name}={value}")
            } else {
                name
            }
        });
        let mut _origin_args = vec![];
        let mut _ptr_vec = vec![];
        for arg in formatted_args {
            let c_arg = CString::new(arg)?;
            _ptr_vec.push(c_arg.as_ptr().cast_mut());
            _origin_args.push(c_arg);
        }
        // Null terminated
        _ptr_vec.push(null_mut());

        let db_args = _ptr_vec.as_mut_ptr();

        Ok(DbArgs {
            db_args,
            _origin_args,
            _ptr_vec,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use super::*;

    #[test_log::test]
    #[serial_test::serial]
    fn build_empty() {
        let db_args = DbArgs::builder().build().unwrap();

        unsafe {
            assert_eq!(*db_args.db_args, null_mut());
        }
    }

    #[test_log::test]
    #[serial_test::serial]
    fn build_no_value() {
        let db_args = DbArgs::builder().arg("lockiter", None).build().unwrap();
        assert_eq!(
            unsafe { CStr::from_ptr(*db_args.db_args).to_owned() },
            CString::new("lockiter").unwrap()
        );
    }

    #[test_log::test]
    #[serial_test::serial]
    fn build_with_value() {
        let db_args = DbArgs::builder()
            .arg("host", Some("ldap.test"))
            .build()
            .unwrap();
        assert_eq!(
            unsafe { CStr::from_ptr(*db_args.db_args).to_owned() },
            CString::new("host=ldap.test").unwrap()
        );
    }
}

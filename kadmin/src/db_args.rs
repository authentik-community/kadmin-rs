use std::{ffi::CString, os::raw::c_char, ptr::null_mut};

use crate::error::Result;

#[derive(Debug)]
pub struct KAdminDbArgs {
    pub(crate) db_args: *mut *mut c_char,

    // Additional fields to store transient strings so the pointer stored in db_args
    // doesn't become invalid while this struct lives.
    _origin_args: Vec<CString>,
    _ptr_vec: Vec<*mut c_char>,
}

impl KAdminDbArgs {
    pub fn builder() -> KAdminDbArgsBuilder {
        KAdminDbArgsBuilder::default()
    }
}

impl Default for KAdminDbArgs {
    fn default() -> Self {
        Self::builder().build().unwrap()
    }
}

#[derive(Clone, Debug, Default)]
pub struct KAdminDbArgsBuilder(Vec<(String, Option<String>)>);

impl KAdminDbArgsBuilder {
    pub fn arg(mut self, name: &str, value: Option<&str>) -> Self {
        self.0.push((name.to_owned(), value.map(|s| s.to_owned())));
        self
    }

    pub fn build(&self) -> Result<KAdminDbArgs> {
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

        Ok(KAdminDbArgs {
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

    #[test]
    fn build_empty() {
        let db_args = KAdminDbArgs::builder().build().unwrap();

        unsafe {
            assert_eq!(*db_args.db_args, null_mut());
        }
    }

    #[test]
    fn build_no_value() {
        let db_args = KAdminDbArgs::builder().arg("lockiter", None).build().unwrap();
        assert_eq!(
            unsafe { CStr::from_ptr(*db_args.db_args).to_owned() },
            CString::new("lockiter").unwrap()
        );
    }

    #[test]
    fn build_with_value() {
        let db_args = KAdminDbArgs::builder().arg("host", Some("ldap.test")).build().unwrap();
        assert_eq!(
            unsafe { CStr::from_ptr(*db_args.db_args).to_owned() },
            CString::new("host=ldap.test").unwrap()
        );
    }
}

//! Manage [kerberos contexts][`KAdminContext`]

use std::{
    ffi::{CStr, CString},
    mem::MaybeUninit,
    os::raw::c_char,
    ptr::null_mut,
    sync::Mutex,
};

use kadmin_sys::*;

use crate::{
    error::{Result, krb5_error_code_escape_hatch},
    conv::c_string_to_string,
};

static CONTEXT_INIT_LOCK: Mutex<()> = Mutex::new(());

/// A Kerberos context (`krb5_context`) for use with KAdmin
#[derive(Debug)]
pub struct KAdminContext {
    pub(crate) context: krb5_context,
    pub(crate) default_realm: Option<CString>,
}

impl KAdminContext {
    /// Create a default context
    pub fn new() -> Result<Self> {
        Self::builder().build()
    }

    /// Construct a new [builder][`KAdminContextBuilder`] for custom contexts
    pub fn builder() -> KAdminContextBuilder {
        KAdminContextBuilder::default()
    }

    /// Try to fill the `default_realm` field
    fn fill_default_realm(&mut self) {
        self.default_realm = {
            let mut raw_default_realm: *mut c_char = null_mut();
            let code = unsafe { krb5_get_default_realm(self.context, &mut raw_default_realm) };
            match code {
                KRB5_OK => {
                    let default_realm = unsafe { CStr::from_ptr(raw_default_realm) }.to_owned();
                    unsafe {
                        krb5_free_default_realm(self.context, raw_default_realm);
                    }
                    Some(default_realm)
                }
                _ => None,
            }
        };
    }

    /// Get the error message from a kerberos error code
    ///
    /// Only works for krb5 errors, not for kadm5 errors
    pub(crate) fn error_code_to_message(&self, code: krb5_error_code) -> String {
        let message: *const c_char = unsafe { krb5_get_error_message(self.context, code) };

        match c_string_to_string(message) {
            Ok(string) => {
                unsafe { krb5_free_error_message(self.context, message) };
                string
            }
            Err(error) => error.to_string(),
        }
    }
}

impl Default for KAdminContext {
    fn default() -> Self {
        Self::builder().build().unwrap()
    }
}

/// Builder for [`KAdminContext`]
#[derive(Debug, Default)]
pub struct KAdminContextBuilder {
    /// Optional [`krb5_context`] provided by the user
    context: Option<krb5_context>,
}

impl KAdminContextBuilder {
    /// Use a custom [`krb5_context`]
    ///
    /// # Safety
    ///
    /// Context will be freed with [`krb5_free_context`] when [`KAdminContext`] is dropped.
    pub unsafe fn context(mut self, context: krb5_context) -> Self {
        self.context = Some(context);
        self
    }

    /// Build a [`KAdminContext`] instance
    ///
    /// If no context was provided, a default one is created with [`kadm5_init_krb5_context`]
    pub fn build(self) -> Result<KAdminContext> {
        if let Some(ctx) = self.context {
            let mut context = KAdminContext {
                context: ctx,
                default_realm: None,
            };
            context.fill_default_realm();
            return Ok(context);
        }

        let _guard = CONTEXT_INIT_LOCK
            .lock()
            .expect("Failed to lock context initialization.");

        let mut context_ptr: MaybeUninit<krb5_context> = MaybeUninit::zeroed();

        let code = unsafe { kadm5_init_krb5_context(context_ptr.as_mut_ptr()) };
        let mut context = KAdminContext {
            context: unsafe { context_ptr.assume_init() },
            default_realm: None,
        };
        krb5_error_code_escape_hatch(&context, code)?;
        context.fill_default_realm();
        Ok(context)
    }
}

impl Drop for KAdminContext {
    fn drop(&mut self) {
        let _guard = CONTEXT_INIT_LOCK
            .lock()
            .expect("Failed to lock context for de-initialization.");

        unsafe { krb5_free_context(self.context) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new() {
        let context = KAdminContext::new();
        assert!(context.is_ok());
    }

    #[test]
    fn error_code_to_message() {
        let context = KAdminContext::new().unwrap();
        let message = context.error_code_to_message(-1765328384);
        assert_eq!(message, "No error".to_string());
    }

    #[test]
    fn error_code_to_message_wrong_code() {
        let context = KAdminContext::new().unwrap();
        let message = context.error_code_to_message(-1);
        assert_eq!(message, "Unknown code ____ 255".to_string());
    }
}

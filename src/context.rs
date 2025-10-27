//! Manage [kerberos contexts][`Context`]

use std::{
    ffi::{CStr, CString, c_void},
    mem::MaybeUninit,
    os::raw::c_char,
    ptr::null_mut,
    sync::Mutex,
};

use crate::{
    Error,
    conv::c_string_to_string,
    error::{Result, krb5_error_code_escape_hatch},
    sys::{Library, library_match},
};

/// Lock acquired when creating or dropping a [`Context`] instance
pub static CONTEXT_INIT_LOCK: Mutex<()> = Mutex::new(());

/// A Kerberos context (`krb5_context`) for use with KAdmin
pub struct Context {
    pub(crate) library: Library,
    pub(crate) context: *mut c_void,
    pub(crate) default_realm: Option<CString>,
}

impl Context {
    /// Create a default context
    pub fn new(library: Library) -> Result<Self> {
        Self::builder().build(library)
    }

    /// Construct a new [builder][`ContextBuilder`] for custom contexts
    pub fn builder() -> ContextBuilder {
        ContextBuilder::default()
    }

    /// Try to fill the `default_realm` field
    fn fill_default_realm(&mut self) {
        self.default_realm = {
            let mut raw_default_realm: *mut c_char = null_mut();
            let code = library_match!(&self.library; |cont, lib| unsafe {
                cont.krb5_get_default_realm(
                    self.context as lib!(krb5_context),
                    &mut raw_default_realm,
                )
            });
            if krb5_error_code_escape_hatch(self, code.into()).is_ok() {
                let default_realm = unsafe { CStr::from_ptr(raw_default_realm) }.to_owned();
                library_match!(&self.library; |cont, lib| unsafe {
                    cont.krb5_free_default_realm(
                        self.context as lib!(krb5_context),
                        raw_default_realm,
                    );
                });
                Some(default_realm)
            } else {
                None
            }
        };
    }

    /// Get the error message from a kerberos error code
    ///
    /// Only works for krb5 errors, not for kadm5 errors
    pub(crate) fn error_code_to_message(&self, code: i64) -> String {
        let message: *const c_char = library_match!(&self.library; |cont, lib| unsafe {
            cont.krb5_get_error_message(
                self.context as lib!(krb5_context),
                code as lib!(krb5_error_code),
            )
        });

        match c_string_to_string(message) {
            Ok(string) => {
                library_match!(&self.library; |cont, lib| unsafe {
                    cont.krb5_free_error_message(
                        self.context as lib!(krb5_context),
                        message,
                    );
                });
                string
            }
            Err(error) => error.to_string(),
        }
    }
}

/// Builder for [`Context`]
#[derive(Debug, Default)]
pub struct ContextBuilder {
    /// Optional [`krb5_context`] provided by the user
    context: Option<*mut c_void>,
}

impl ContextBuilder {
    /// Use a custom `krb5_context`
    ///
    /// # Safety
    ///
    /// Context will be freed with `krb5_free_context` when [`Context`] is dropped.
    ///
    /// Context must have been built with the same [`Library`] as passed to [`Self::build`]
    pub unsafe fn context(mut self, context: *mut c_void) -> Self {
        self.context = Some(context);
        self
    }

    /// Build a [`Context`] instance
    ///
    /// If no context was provided, a default one is created with `kadm5_init_krb5_context`
    pub fn build(self, library: Library) -> Result<Context> {
        if let Some(ctx) = self.context {
            let mut context = Context {
                library,
                context: ctx,
                default_realm: None,
            };
            context.fill_default_realm();
            return Ok(context);
        }

        let _guard = CONTEXT_INIT_LOCK.lock().map_err(|_| Error::LockError)?;

        let (context, code) = library_match!(
            &library;
            mit_client, mit_server => |cont, lib| {
                let mut context_ptr: MaybeUninit<lib!(krb5_context)> =
                    MaybeUninit::zeroed();
                let code = unsafe { cont.kadm5_init_krb5_context(context_ptr.as_mut_ptr()) };
                (unsafe { context_ptr.assume_init() } as *mut c_void, code)
            },
            heimdal_client, heimdal_server => |cont, lib| {
                let mut context_ptr: MaybeUninit<lib!(krb5_context)> =
                    MaybeUninit::zeroed();
                let code = unsafe { cont.krb5_init_context(context_ptr.as_mut_ptr()) };
                (unsafe { context_ptr.assume_init() } as *mut c_void, code)
            }
        );

        drop(_guard);
        let mut context = Context {
            library,
            context,
            default_realm: None,
        };
        krb5_error_code_escape_hatch(&context, code.into())?;
        context.fill_default_realm();
        Ok(context)
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if let Ok(_guard) = CONTEXT_INIT_LOCK.lock() {
            library_match!(&self.library; |cont, lib| unsafe {
                cont.krb5_free_context(self.context as lib!(krb5_context));
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::KAdm5Variant;

    #[cfg(mit_client)]
    #[test_log::test]
    #[serial_test::serial]
    fn new_mit_client() -> Result<()> {
        let lib = Library::from_variant(KAdm5Variant::MitClient)?;
        let context = Context::new(lib);
        assert!(context.is_ok());
        Ok(())
    }

    #[cfg(mit_server)]
    #[test_log::test]
    #[serial_test::serial]
    fn new_mit_server() -> Result<()> {
        let lib = Library::from_variant(KAdm5Variant::MitServer)?;
        let context = Context::new(lib);
        assert!(context.is_ok());
        Ok(())
    }

    #[cfg(heimdal_client)]
    #[test_log::test]
    #[serial_test::serial]
    fn new_heimdal_client() -> Result<()> {
        let lib = Library::from_variant(KAdm5Variant::HeimdalClient)?;
        let context = Context::new(lib);
        assert!(context.is_ok());
        Ok(())
    }

    #[cfg(heimdal_server)]
    #[test_log::test]
    #[serial_test::serial]
    fn new_heimdal_server() -> Result<()> {
        let lib = Library::from_variant(KAdm5Variant::HeimdalServer)?;
        let context = Context::new(lib);
        assert!(context.is_ok());
        Ok(())
    }

    #[cfg(mit_client)]
    #[test_log::test]
    #[serial_test::serial]
    fn error_code_to_message_mit() -> Result<()> {
        let lib = Library::from_variant(KAdm5Variant::MitClient)?;
        let context = Context::new(lib).unwrap();
        let message = context.error_code_to_message(-1_765_328_384);
        assert_eq!(message, "No error");
        Ok(())
    }

    #[cfg(heimdal_client)]
    #[test_log::test]
    #[serial_test::serial]
    fn error_code_to_message_heimdal() -> Result<()> {
        let lib = Library::from_variant(KAdm5Variant::HeimdalClient)?;
        let context = Context::new(lib).unwrap();
        let message = context.error_code_to_message(-1_765_328_384);
        assert_eq!(message, "No error");
        Ok(())
    }

    #[cfg(mit_client)]
    #[test_log::test]
    #[serial_test::serial]
    fn error_code_to_message_wrong_code_mit() -> Result<()> {
        let lib = Library::from_variant(KAdm5Variant::MitClient)?;
        let context = Context::new(lib).unwrap();
        let message = context.error_code_to_message(-1);
        assert_eq!(message, "Unknown code ____ 255");
        Ok(())
    }

    #[cfg(heimdal_client)]
    #[test_log::test]
    #[serial_test::serial]
    fn error_code_to_message_wrong_code_heimdal() -> Result<()> {
        let lib = Library::from_variant(KAdm5Variant::HeimdalClient)?;
        let context = Context::new(lib).unwrap();
        let message = context.error_code_to_message(-1);
        assert_eq!(message, "Unknown error -1");
        Ok(())
    }
}

//! [`Error`] type for various errors this library can encounter

use kadmin_sys::*;

use crate::context::Context;

/// Errors this library can encounter
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Represent a Kerberos error.
    ///
    /// Provided are the origin error code plus an error message as
    /// returned by [`krb5_get_error_message`]
    #[error("Kerberos error: {message} (code: {code})")]
    Kerberos {
        /// Kerberos error code
        code: krb5_error_code,
        /// Kerberos error message
        message: String,
    },

    /// Represent a kadm5 error.
    ///
    /// Provided are the origin error code plus an error message
    /// from the MIT krb5 implementation (which are not exposed via a function)
    #[error("KAdmin error: {message} (code: {code})")]
    KAdmin {
        /// kadm5 error code
        code: kadm5_ret_t,
        /// kadm5 error message
        message: String,
    },

    /// Conversion to an encryption type failed
    #[error("Conversion to encryption type failed")]
    EncryptionTypeConversion,

    /// Conversion to a salt type failed
    #[error("Conversion to salt type failed")]
    SaltTypeConversion,

    /// When converting a `*c_char` to a [`String`], if the provided pointer was `NULL`, this error
    /// is returned
    #[error("NULL pointer dereference error")]
    NullPointerDereference,

    /// Couldn't convert a [`CString`][`std::ffi::CString`] to a [`String`]
    #[error(transparent)]
    CStringConversion(#[from] std::ffi::IntoStringError),
    /// Couldn't import a `Vec<u8>` as a [`CString`][`std::ffi::CString`]
    #[error(transparent)]
    CStringImportFromVec(#[from] std::ffi::FromVecWithNulError),
    /// Couldn't convert a [`CString`][`std::ffi::CString`] to a [`String`] because an interior nul
    /// byte was found
    #[error(transparent)]
    StringConversion(#[from] std::ffi::NulError),
    /// Failed to send an operation to the sync executor
    #[error("Failed to send operation to executor")]
    ThreadSendError,
    /// Failed to receive the result from an operatior from the sync executor
    #[error("Failed to receive result from executor")]
    ThreadRecvError(#[from] std::sync::mpsc::RecvError),
    /// Failed to convert a [`krb5_timestamp`] to a [`chrono::DateTime`]
    #[error("Failed to convert krb5 timestamp to chrono DateTime")]
    TimestampConversion,
    /// Failed to convert a [`chrono::DateTime`] to a [`krb5_timestamp`]
    #[error("Failed to convert chrono DateTime to krb5 timestamp")]
    DateTimeConversion(std::num::TryFromIntError),
    /// Failed to convert a [`Duration`][`std::time::Duration`] to a [`krb5_deltat`]
    #[error("Failed to convert Duration to a krb5 deltat")]
    DurationConversion(std::num::TryFromIntError),
}

impl<T> From<std::sync::mpsc::SendError<T>> for Error {
    fn from(_error: std::sync::mpsc::SendError<T>) -> Self {
        Self::ThreadSendError
    }
}

/// Helper type for errors sent from this library
pub type Result<T> = std::result::Result<T, Error>;

/// Helper function to "raise" an error from a [`krb5_error_code`]
pub(crate) fn krb5_error_code_escape_hatch(context: &Context, code: krb5_error_code) -> Result<()> {
    if code == KRB5_OK {
        Ok(())
    } else {
        Err(Error::Kerberos {
            code,
            message: context.error_code_to_message(code),
        })
    }
}

/// Helper function to "raise" an error from a [`kadm5_ret_t`]
pub(crate) fn kadm5_ret_t_escape_hatch(context: &Context, code: kadm5_ret_t) -> Result<()> {
    if code == KADM5_OK as kadm5_ret_t {
        return Ok(());
    }
    let message = match code as u32 {
        KADM5_FAILURE => "Operation failed for unspecified reason",
        KADM5_AUTH_GET => "Operation requires ``get'' privilege",
        KADM5_AUTH_ADD => "Operation requires ``add'' privilege",
        KADM5_AUTH_MODIFY => "Operation requires ``modify'' privilege",
        KADM5_AUTH_DELETE => "Operation requires ``delete'' privilege",
        KADM5_AUTH_INSUFFICIENT => "Insufficient authorization for operation",
        KADM5_BAD_DB => "Database inconsistency detected",
        KADM5_DUP => "Principal or policy already exists",
        KADM5_RPC_ERROR => "Communication failure with server",
        KADM5_NO_SRV => "No administration server found for realm",
        KADM5_BAD_HIST_KEY => "Password history principal key version mismatch",
        KADM5_NOT_INIT => "Connection to server not initialized",
        KADM5_UNK_PRINC => "Principal does not exist",
        KADM5_UNK_POLICY => "Policy does not exist",
        KADM5_BAD_MASK => "Invalid field mask for operation",
        KADM5_BAD_CLASS => "Invalid number of character classes",
        KADM5_BAD_LENGTH => "Invalid password length",
        KADM5_BAD_POLICY => "Illegal policy name",
        KADM5_BAD_PRINCIPAL => "Illegal principal name",
        KADM5_BAD_AUX_ATTR => "Invalid auxillary attributes",
        KADM5_BAD_HISTORY => "Invalid password history count",
        KADM5_BAD_MIN_PASS_LIFE => "Password minimum life is greater then password maximum life",
        KADM5_PASS_Q_TOOSHORT => "Password is too short",
        KADM5_PASS_Q_CLASS => "Password does not contain enough character classes",
        KADM5_PASS_Q_DICT => "Password is in the password dictionary",
        KADM5_PASS_REUSE => "Cannot reuse password",
        KADM5_PASS_TOOSOON => "Current password's minimum life has not expired",
        KADM5_POLICY_REF => "Policy is in use",
        KADM5_INIT => "Connection to server already initialized",
        KADM5_BAD_PASSWORD => "Incorrect password",
        KADM5_PROTECT_PRINCIPAL => "Cannot change protected principal",
        KADM5_BAD_SERVER_HANDLE => "Programmer error! Bad Admin server handle",
        KADM5_BAD_STRUCT_VERSION => "Programmer error! Bad API structure version",
        KADM5_OLD_STRUCT_VERSION => {
            "API structure version specified by application is no longer supported (to fix, \
             recompile application against current Admin API header files and libraries)"
        }
        KADM5_NEW_STRUCT_VERSION => {
            "API structure version specified by application is unknown to libraries (to fix, \
             obtain current Admin API header files and libraries and recompile application)"
        }
        KADM5_BAD_API_VERSION => "Programmer error! Bad API version",
        KADM5_OLD_LIB_API_VERSION => {
            "API version specified by application is no longer supported by libraries (to fix, \
             update application to adhere to current API version and recompile)"
        }
        KADM5_OLD_SERVER_API_VERSION => {
            "API version specified by application is no longer supported by server (to fix, update \
             application to adhere to current API version and recompile)"
        }
        KADM5_NEW_LIB_API_VERSION => {
            "API version specified by application is unknown to libraries (to fix, obtain current \
             Admin API header files and libraries and recompile application)"
        }
        KADM5_NEW_SERVER_API_VERSION => {
            "API version specified by application is unknown to server (to fix, obtain and install \
             newest Admin Server)"
        }
        KADM5_SECURE_PRINC_MISSING => "Database error! Required principal missing",
        KADM5_NO_RENAME_SALT => {
            "The salt type of the specified principal does not support renaming"
        }
        KADM5_BAD_CLIENT_PARAMS => "Illegal configuration parameter for remote KADM5 client",
        KADM5_BAD_SERVER_PARAMS => "Illegal configuration parameter for local KADM5 client.",
        KADM5_AUTH_LIST => "Operation requires ``list'' privilege",
        KADM5_AUTH_CHANGEPW => "Operation requires ``change-password'' privilege",
        KADM5_GSS_ERROR => "GSS-API (or Kerberos) error",
        KADM5_BAD_TL_TYPE => "Programmer error! Illegal tagged data list element type",
        KADM5_MISSING_CONF_PARAMS => "Required parameters in kdc.conf missing",
        KADM5_BAD_SERVER_NAME => "Bad krb5 admin server hostname",
        KADM5_AUTH_SETKEY => "Operation requires ``set-key'' privilege",
        KADM5_SETKEY_DUP_ENCTYPES => "Multiple values for single or folded enctype",
        KADM5_SETV4KEY_INVAL_ENCTYPE => "Invalid enctype for setv4key",
        KADM5_SETKEY3_ETYPE_MISMATCH => "Mismatched enctypes for setkey3",
        KADM5_MISSING_KRB5_CONF_PARAMS => {
            "Missing parameters in krb5.conf required for kadmin client"
        }
        KADM5_XDR_FAILURE => "XDR encoding error",
        KADM5_CANT_RESOLVE => "",
        KADM5_PASS_Q_GENERIC => "Database synchronization failed",
        _ => "Unknown error",
    }
    .to_owned();
    if message != "Unknown error" {
        Err(Error::KAdmin { code, message })
    } else {
        krb5_error_code_escape_hatch(context, code as krb5_error_code)
    }
}

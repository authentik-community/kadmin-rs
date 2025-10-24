//! [`Error`] type for various errors this library can encounter

use crate::{context::Context, sys::library_match};

const KADM5_OK: i32 = 0;
const KRB5_OK: i32 = 0;

/// Errors this library can encounter
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Represent a Kerberos error.
    ///
    /// Provided are the origin error code plus an error message as
    /// returned by `krb5_get_error_message`
    #[error("Kerberos error: {message} (code: {code})")]
    Kerberos {
        /// Kerberos error code
        code: i64,
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
        code: i64,
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

    /// Failed to convert a `krb5_timestamp` to a [`chrono::DateTime`]
    #[error("Failed to convert krb5 timestamp to chrono DateTime")]
    TimestampConversion,
    /// Failed to convert a [`chrono::DateTime`] to a `krb5_timestamp`
    #[error("Failed to convert chrono DateTime to krb5 timestamp")]
    DateTimeConversion(std::num::TryFromIntError),
    /// Failed to convert a [`Duration`][`std::time::Duration`] to a `krb5_deltat`
    #[error("Failed to convert Duration to a krb5 deltat")]
    DurationConversion(std::num::TryFromIntError),

    /// Failed to acquire [`crate::kadmin::KADMIN_INIT_LOCK`] or
    /// [`crate::context::CONTEXT_INIT_LOCK`]
    #[error("Failed to acquire the kadmin initialisation lock")]
    LockError,

    /// Failed to load the kadm5 library
    #[error("Failed to load the kadm5 library")]
    LibraryLoadError(#[from] dlopen2::Error),
    /// The library is not compatible with the current operation
    #[error("The library is not compatible with the current operation")]
    LibraryMismatch(&'static str),
}

impl<T> From<std::sync::mpsc::SendError<T>> for Error {
    fn from(_error: std::sync::mpsc::SendError<T>) -> Self {
        Self::ThreadSendError
    }
}

/// Helper type for errors sent from this library
pub type Result<T> = std::result::Result<T, Error>;

/// Helper function to "raise" an error from a [`krb5_error_code`]
pub(crate) fn krb5_error_code_escape_hatch(context: &Context, code: i64) -> Result<()> {
    if code == KRB5_OK as i64 {
        Ok(())
    } else {
        Err(Error::Kerberos {
            code,
            message: context.error_code_to_message(code),
        })
    }
}

macro_rules! kadm5_error_enum {
    (
        $libname:ident;
        $(#[$outer:meta])*
        $EnumName:ident { $($manual_fields:tt)* }
    ) => {
        $(#[$outer])*
        enum $EnumName {
            #[error("Operation failed for unspecified reason")]
            Failure = kadm5_error_enum!($libname, KADM5_FAILURE),
            #[error("Operation requires ``get'' privilege")]
            AuthGet = kadm5_error_enum!($libname, KADM5_AUTH_GET),
            #[error("Operation requires ``add'' privilege")]
            AuthAdd = kadm5_error_enum!($libname, KADM5_AUTH_ADD),
            #[error("Operation requires ``modify'' privilege")]
            AuthModify = kadm5_error_enum!($libname, KADM5_AUTH_MODIFY),
            #[error("Operation requires ``delete'' privilege")]
            AuthDelete = kadm5_error_enum!($libname, KADM5_AUTH_DELETE),
            #[error("Insufficient authorization for operation")]
            AuthInsufficient = kadm5_error_enum!($libname, KADM5_AUTH_INSUFFICIENT),
            #[error("Database inconsistency detected")]
            BadDb = kadm5_error_enum!($libname, KADM5_BAD_DB),
            #[error("Principal or policy already exists")]
            Dup = kadm5_error_enum!($libname, KADM5_DUP),
            #[error("Communication failure with server")]
            RpcError = kadm5_error_enum!($libname, KADM5_RPC_ERROR),
            #[error("No administration server found for realm")]
            NoSrv = kadm5_error_enum!($libname, KADM5_NO_SRV),
            #[error("Password history entry (kadmin/history) contains unsupported key type")]
            BadHistKey = kadm5_error_enum!($libname, KADM5_BAD_HIST_KEY),
            #[error("Connection to server not initialized")]
            NotInit = kadm5_error_enum!($libname, KADM5_NOT_INIT),
            #[error("Principal does not exist")]
            UnkPrinc = kadm5_error_enum!($libname, KADM5_UNK_PRINC),
            #[error("Policy does not exist")]
            UnkPolicy = kadm5_error_enum!($libname, KADM5_UNK_POLICY),
            #[error("Invalid field mask for operation")]
            BadMask = kadm5_error_enum!($libname, KADM5_BAD_MASK),
            #[error("Invalid number of character classes")]
            BadClass = kadm5_error_enum!($libname, KADM5_BAD_CLASS),
            #[error("Invalid password length")]
            BadLength = kadm5_error_enum!($libname, KADM5_BAD_LENGTH),
            #[error("Illegal policy name")]
            BadPolicy = kadm5_error_enum!($libname, KADM5_BAD_POLICY),
            #[error("Illegal principal name")]
            BadPrincipal = kadm5_error_enum!($libname, KADM5_BAD_PRINCIPAL),
            #[error("Invalid auxillary attributes")]
            BadAuxAttr = kadm5_error_enum!($libname, KADM5_BAD_AUX_ATTR),
            #[error("Invalid password history count")]
            BadHistory = kadm5_error_enum!($libname, KADM5_BAD_HISTORY),
            #[error("Password minimum life is greater then password maximum life")]
            BadMinPassLife = kadm5_error_enum!($libname, KADM5_BAD_MIN_PASS_LIFE),
            #[error("Password is too short")]
            PassQTooshort = kadm5_error_enum!($libname, KADM5_PASS_Q_TOOSHORT),
            #[error("Password does not contain enough character classes")]
            PassQClass = kadm5_error_enum!($libname, KADM5_PASS_Q_CLASS),
            #[error("Password is in the password dictionary")]
            PassQDict = kadm5_error_enum!($libname, KADM5_PASS_Q_DICT),
            #[error("Cannot reuse password")]
            PassReuse = kadm5_error_enum!($libname, KADM5_PASS_REUSE),
            #[error("Current password's minimum life has not expired")]
            PassToosoon = kadm5_error_enum!($libname, KADM5_PASS_TOOSOON),
            #[error("Policy is in use")]
            PolicyRef = kadm5_error_enum!($libname, KADM5_POLICY_REF),
            #[error("Connection to server already initialized")]
            Init = kadm5_error_enum!($libname, KADM5_INIT),
            #[error("Incorrect password")]
            BadPassword = kadm5_error_enum!($libname, KADM5_BAD_PASSWORD),
            #[error("Cannot change protected principal")]
            ProtectPrincipal = kadm5_error_enum!($libname, KADM5_PROTECT_PRINCIPAL),
            #[error("Programmer error! Bad Admin server handle")]
            BadServerHandle = kadm5_error_enum!($libname, KADM5_BAD_SERVER_HANDLE),
            #[error("Programmer error! Bad API structure version")]
            BadStructVersion = kadm5_error_enum!($libname, KADM5_BAD_STRUCT_VERSION),
            #[error("API structure version specified by application is no longer supported (to fix, recompile application against current Admin API header files and libraries)")]
            OldStructVersion = kadm5_error_enum!($libname, KADM5_OLD_STRUCT_VERSION),
            #[error("API structure version specified by application is unknown to libraries (to fix, obtain current Admin API header files and libraries and recompile application)")]
            NewStructVersion = kadm5_error_enum!($libname, KADM5_NEW_STRUCT_VERSION),
            #[error("Programmer error! Bad API version")]
            BadApiVersion = kadm5_error_enum!($libname, KADM5_BAD_API_VERSION),
            #[error("API version specified by application is no longer supported by libraries (to fix, update application to adhere to current API version and recompile)")]
            OldLibApiVersion = kadm5_error_enum!($libname, KADM5_OLD_LIB_API_VERSION),
            #[error("API version specified by application is no longer supported by server (to fix, update application to adhere to current API version and recompile)")]
            OldServerApiVersion = kadm5_error_enum!($libname, KADM5_OLD_SERVER_API_VERSION),
            #[error("API version specified by application is unknown to libraries (to fix, obtain current Admin API header files and libraries and recompile application)")]
            NewLibApiVersion = kadm5_error_enum!($libname, KADM5_NEW_LIB_API_VERSION),
            #[error("API version specified by application is unknown to server (to fix, obtain and install newest Admin Server)")]
            NewServerApiVersion = kadm5_error_enum!($libname, KADM5_NEW_SERVER_API_VERSION),
            #[error("Database error! Required principal missing")]
            SecurePrincMissing = kadm5_error_enum!($libname, KADM5_SECURE_PRINC_MISSING),
            #[error("The salt type of the specified principal does not support renaming")]
            NoRenameSalt = kadm5_error_enum!($libname, KADM5_NO_RENAME_SALT),
            #[error("Illegal configuration parameter for remote KADM5 client")]
            BadClientParams = kadm5_error_enum!($libname, KADM5_BAD_CLIENT_PARAMS),
            #[error("Illegal configuration parameter for local KADM5 client.")]
            BadServerParams = kadm5_error_enum!($libname, KADM5_BAD_SERVER_PARAMS),
            #[error("Operation requires ``list'' privilege")]
            AuthList = kadm5_error_enum!($libname, KADM5_AUTH_LIST),
            #[error("Operation requires ``change-password'' privilege")]
            AuthChangepw = kadm5_error_enum!($libname, KADM5_AUTH_CHANGEPW),
            #[error("Programmer error! Illegal tagged data list element type")]
            BadTlType = kadm5_error_enum!($libname, KADM5_BAD_TL_TYPE),
            #[error("Required parameters in kdc.conf missing")]
            MissingConfParams = kadm5_error_enum!($libname, KADM5_MISSING_CONF_PARAMS),
            #[error("Bad krb5 admin server hostname")]
            BadServerName = kadm5_error_enum!($libname, KADM5_BAD_SERVER_NAME),
            #[error("Mismatched enctypes for setkey3")]
            Setkey3EtypeMismatch = kadm5_error_enum!($libname, KADM5_SETKEY3_ETYPE_MISMATCH),

            $($manual_fields)*
        }

        impl From<$EnumName> for Error {
            fn from(error: $EnumName) -> Self {
                Error::KAdmin {
                    code: error as i64,
                    message: error.to_string()
                }
            }
        }
    };

    (mit_client, $const:ident) => {
        crate::sys::mit_client::$const as i64
    };
    (mit_server, $const:ident) => {
        crate::sys::mit_server::$const as i64
    };
    (heimdal_client, $const:ident) => {
        crate::sys::heimdal_client::$const as i64
    };
    (heimdal_server, $const:ident) => {
        crate::sys::heimdal_server::$const as i64
    };
}

#[cfg(mit_client)]
kadm5_error_enum!(
    mit_client;
    #[derive(thiserror::Error, strum::FromRepr, Copy, Clone, Debug)]
    #[non_exhaustive]
    #[repr(i64)]
    KAdm5ErrorMitClient {
        #[error("Unspecified password quality failure")]
        PassQGeneric = kadm5_error_enum!(mit_client, KADM5_PASS_Q_GENERIC),
        #[error("GSS-API (or Kerberos) error")]
        GssError = kadm5_error_enum!(mit_client, KADM5_GSS_ERROR),
        #[error("Operation requires ``set-key'' privilege")]
        AuthSetkey = kadm5_error_enum!(mit_client, KADM5_AUTH_SETKEY),
        #[error("Multiple values for single or folded enctype")]
        SetkeyDupEnctypes = kadm5_error_enum!(mit_client, KADM5_SETKEY_DUP_ENCTYPES),
        #[error("Invalid enctype for setv4key")]
        Setv4keyInvalEnctype = kadm5_error_enum!(mit_client, KADM5_SETV4KEY_INVAL_ENCTYPE),
        #[error("Missing parameters in krb5.conf required for kadmin client")]
        MissingKrb5ConfParams = kadm5_error_enum!(mit_client, KADM5_MISSING_KRB5_CONF_PARAMS),
        #[error("XDR encoding error")]
        XdrFailure = kadm5_error_enum!(mit_client, KADM5_XDR_FAILURE),
        #[error("Cannot resolve network address for admin server in requested realm")]
        CantResolve = kadm5_error_enum!(mit_client, KADM5_CANT_RESOLVE),
        #[error("Invalid key/salt tuples")]
        BadKeysalts = kadm5_error_enum!(mit_client, KADM5_BAD_KEYSALTS),
        #[error("Invalid multiple or duplicate kvnos in setkey operation")]
        SetkeyBadKvno = kadm5_error_enum!(mit_client, KADM5_SETKEY_BAD_KVNO),
        #[error("Operation requires ``extract-keys'' privilege")]
        AuthExtract = kadm5_error_enum!(mit_client, KADM5_AUTH_EXTRACT),
        #[error("Principal keys are locked down")]
        ProtectKeys = kadm5_error_enum!(mit_client, KADM5_PROTECT_KEYS),
        #[error("Operation requires initial ticket")]
        AuthInitial = kadm5_error_enum!(mit_client, KADM5_AUTH_INITIAL),
    }
);

#[cfg(mit_server)]
kadm5_error_enum!(
    mit_server;
    #[derive(thiserror::Error, strum::FromRepr, Copy, Clone, Debug)]
    #[non_exhaustive]
    #[repr(i64)]
    KAdm5ErrorMitServer {
        #[error("Unspecified password quality failure")]
        PassQGeneric = kadm5_error_enum!(mit_server, KADM5_PASS_Q_GENERIC),
        #[error("GSS-API (or Kerberos) error")]
        GssError = kadm5_error_enum!(mit_server, KADM5_GSS_ERROR),
        #[error("Operation requires ``set-key'' privilege")]
        AuthSetkey = kadm5_error_enum!(mit_server, KADM5_AUTH_SETKEY),
        #[error("Multiple values for single or folded enctype")]
        SetkeyDupEnctypes = kadm5_error_enum!(mit_server, KADM5_SETKEY_DUP_ENCTYPES),
        #[error("Invalid enctype for setv4key")]
        Setv4keyInvalEnctype = kadm5_error_enum!(mit_server, KADM5_SETV4KEY_INVAL_ENCTYPE),
        #[error("Missing parameters in krb5.conf required for kadmin client")]
        MissingKrb5ConfParams = kadm5_error_enum!(mit_server, KADM5_MISSING_KRB5_CONF_PARAMS),
        #[error("XDR encoding error")]
        XdrFailure = kadm5_error_enum!(mit_server, KADM5_XDR_FAILURE),
        #[error("Cannot resolve network address for admin server in requested realm")]
        CantResolve = kadm5_error_enum!(mit_server, KADM5_CANT_RESOLVE),
        #[error("Invalid key/salt tuples")]
        BadKeysalts = kadm5_error_enum!(mit_server, KADM5_BAD_KEYSALTS),
        #[error("Invalid multiple or duplicate kvnos in setkey operation")]
        SetkeyBadKvno = kadm5_error_enum!(mit_server, KADM5_SETKEY_BAD_KVNO),
        #[error("Operation requires ``extract-keys'' privilege")]
        AuthExtract = kadm5_error_enum!(mit_server, KADM5_AUTH_EXTRACT),
        #[error("Principal keys are locked down")]
        ProtectKeys = kadm5_error_enum!(mit_server, KADM5_PROTECT_KEYS),
        #[error("Operation requires initial ticket")]
        AuthInitial = kadm5_error_enum!(mit_server, KADM5_AUTH_INITIAL),
    }
);

#[cfg(heimdal_client)]
kadm5_error_enum!(
    heimdal_client;
    #[derive(thiserror::Error, strum::FromRepr, Copy, Clone, Debug)]
    #[non_exhaustive]
    #[repr(i64)]
    KAdm5ErrorHeimdalClient {
        #[error("Key/salt tuples not supported by this function")]
        KsTupleNosupp = kadm5_error_enum!(heimdal_client, KADM5_KS_TUPLE_NOSUPP),
        #[error("Given usage of kadm5_decrypt() not supported")]
        DecryptUsageNosupp = kadm5_error_enum!(heimdal_client, KADM5_DECRYPT_USAGE_NOSUPP),
        #[error("Policy operations not supported")]
        PolicyOpNosupp = kadm5_error_enum!(heimdal_client, KADM5_POLICY_OP_NOSUPP),
        #[error("Operation requires `get_keys' privilege")]
        AuthGetKeys = kadm5_error_enum!(heimdal_client, KADM5_AUTH_GET_KEYS),
        #[error("Database already locked")]
        AlreadyLocked = kadm5_error_enum!(heimdal_client, KADM5_ALREADY_LOCKED),
        #[error("Database not locked")]
        NotLocked = kadm5_error_enum!(heimdal_client, KADM5_NOT_LOCKED),
        #[error("Incremental propagation log got corrupted")]
        LogCorrupt = kadm5_error_enum!(heimdal_client, KADM5_LOG_CORRUPT),
        #[error("Incremental propagation log must be upgraded")]
        LogNeedsUpgrade = kadm5_error_enum!(heimdal_client, KADM5_LOG_NEEDS_UPGRADE),
        #[error("Keep old keys option not supported")]
        KeepoldNosupp = kadm5_error_enum!(heimdal_client, KADM5_KEEPOLD_NOSUPP),
        #[error("Bad KADM5 server hook")]
        BadServerHook = kadm5_error_enum!(heimdal_client, KADM5_BAD_SERVER_HOOK),
        #[error("Cannot find KADM5 server hook")]
        ServerHookNotFound = kadm5_error_enum!(heimdal_client, KADM5_SERVER_HOOK_NOT_FOUND),
        #[error("KADM5 server hook is too old for this version of Heimdal")]
        OldServerHookVersion = kadm5_error_enum!(heimdal_client, KADM5_OLD_SERVER_HOOK_VERSION),
        #[error("KADM5 server hook is too new for this version of Heimdal")]
        NewServerHookVersion = kadm5_error_enum!(heimdal_client, KADM5_NEW_SERVER_HOOK_VERSION),
        #[error("Database is read-only; try primary server")]
        ReadOnly = kadm5_error_enum!(heimdal_client, KADM5_READ_ONLY),
    }
);

#[cfg(heimdal_server)]
kadm5_error_enum!(
    heimdal_server;
    #[derive(thiserror::Error, strum::FromRepr, Copy, Clone, Debug)]
    #[non_exhaustive]
    #[repr(i64)]
    KAdm5ErrorHeimdalServer {
        #[error("Key/salt tuples not supported by this function")]
        KsTupleNosupp = kadm5_error_enum!(heimdal_server, KADM5_KS_TUPLE_NOSUPP),
        #[error("Given usage of kadm5_decrypt() not supported")]
        DecryptUsageNosupp = kadm5_error_enum!(heimdal_server, KADM5_DECRYPT_USAGE_NOSUPP),
        #[error("Policy operations not supported")]
        PolicyOpNosupp = kadm5_error_enum!(heimdal_server, KADM5_POLICY_OP_NOSUPP),
        #[error("Operation requires `get_keys' privilege")]
        AuthGetKeys = kadm5_error_enum!(heimdal_server, KADM5_AUTH_GET_KEYS),
        #[error("Database already locked")]
        AlreadyLocked = kadm5_error_enum!(heimdal_server, KADM5_ALREADY_LOCKED),
        #[error("Database not locked")]
        NotLocked = kadm5_error_enum!(heimdal_server, KADM5_NOT_LOCKED),
        #[error("Incremental propagation log got corrupted")]
        LogCorrupt = kadm5_error_enum!(heimdal_server, KADM5_LOG_CORRUPT),
        #[error("Incremental propagation log must be upgraded")]
        LogNeedsUpgrade = kadm5_error_enum!(heimdal_server, KADM5_LOG_NEEDS_UPGRADE),
        #[error("Keep old keys option not supported")]
        KeepoldNosupp = kadm5_error_enum!(heimdal_server, KADM5_KEEPOLD_NOSUPP),
        #[error("Bad KADM5 server hook")]
        BadServerHook = kadm5_error_enum!(heimdal_server, KADM5_BAD_SERVER_HOOK),
        #[error("Cannot find KADM5 server hook")]
        ServerHookNotFound = kadm5_error_enum!(heimdal_server, KADM5_SERVER_HOOK_NOT_FOUND),
        #[error("KADM5 server hook is too old for this version of Heimdal")]
        OldServerHookVersion = kadm5_error_enum!(heimdal_server, KADM5_OLD_SERVER_HOOK_VERSION),
        #[error("KADM5 server hook is too new for this version of Heimdal")]
        NewServerHookVersion = kadm5_error_enum!(heimdal_server, KADM5_NEW_SERVER_HOOK_VERSION),
        #[error("Database is read-only; try primary server")]
        ReadOnly = kadm5_error_enum!(heimdal_server, KADM5_READ_ONLY),
}
);

/// Helper function to "raise" an error from a [`kadm5_ret_t`]
pub(crate) fn kadm5_ret_t_escape_hatch(context: &Context, code: i64) -> Result<()> {
    if code == KADM5_OK as i64 {
        return Ok(());
    }

    if let Some(err) = library_match!(
        &context.library;
        mit_client => |_cont, _lib| {
            KAdm5ErrorMitClient::from_repr(code).map(|e| e.into())
        },
        mit_server => |_cont, _lib| {
            KAdm5ErrorMitServer::from_repr(code).map(|e| e.into())
        },
        heimdal_client => |_cont, _lib| {
            KAdm5ErrorHeimdalClient::from_repr(code).map(|e| e.into())
        },
        heimdal_server => |_cont, _lib| {
            KAdm5ErrorHeimdalServer::from_repr(code).map(|e| e.into())
        }
    ) {
        Err(err)
    } else {
        krb5_error_code_escape_hatch(context, code)
    }
}

//! Kerberos keysalt lists
use std::{
    collections::HashSet,
    ffi::{CStr, CString, c_char, c_void},
    ptr::null_mut,
};

#[cfg(feature = "python")]
use pyo3::prelude::*;

use crate::{
    context::Context,
    error::{Error, Result, krb5_error_code_escape_hatch},
    sys::{self, library_match},
};

/// Kerberos encryption type
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[allow(clippy::exhaustive_enums)]
#[repr(transparent)]
#[cfg_attr(feature = "python", pyclass)]
pub struct EncryptionType(i32);

impl From<EncryptionType> for i32 {
    fn from(enctype: EncryptionType) -> Self {
        enctype.0
    }
}

impl From<i32> for EncryptionType {
    fn from(enctype: i32) -> Self {
        Self(enctype)
    }
}

impl EncryptionType {
    fn from_str(context: &Context, s: &str) -> Result<Self> {
        let s = CString::new(s)?;
        let mut enctype = -1;
        let code = library_match!(
            &context.library;
            mit_client, mit_server => |cont, _lib| unsafe {
                cont.krb5_string_to_enctype(s.as_ptr().cast_mut(), &mut enctype)
            },
            heimdal_client, heimdal_server => |cont, lib| unsafe {
                cont.krb5_string_to_enctype(
                    context.context as lib!(krb5_context),
                    s.as_ptr().cast_mut(),
                    &mut enctype,
                )
            }
        );
        if krb5_error_code_escape_hatch(context, code.into()).is_err() {
            Err(Error::EncryptionTypeConversion)
        } else {
            Ok(enctype.into())
        }
    }

    fn to_string(self, context: &Context) -> Result<String> {
        library_match!(
            &context.library;
            mit_client, mit_server => |cont, _lib| {
                let buffer = [0; 100];
                let code = unsafe {
                    let mut b: [c_char; 100] = std::mem::transmute(buffer);
                    cont.krb5_enctype_to_string(self.into(), b.as_mut_ptr(), 100)
                };
                if krb5_error_code_escape_hatch(context, code.into()).is_err() {
                    return Err(Error::EncryptionTypeConversion);
                }
                let s = CStr::from_bytes_until_nul(&buffer)
                    .map_err(|_| Error::EncryptionTypeConversion)?;
                Ok(s.to_owned().into_string()?)
            },
            heimdal_client, heimdal_server => |cont, lib| {
                let mut raw: *mut i8 = null_mut();
                let code = unsafe {
                    cont.krb5_enctype_to_string(
                        context.context as lib!(krb5_context),
                        self.into(),
                        &mut raw,
                    )
                };
                if raw.is_null() {
                    return Err(Error::EncryptionTypeConversion);
                }
                let s = unsafe { CStr::from_ptr(raw) };
                if krb5_error_code_escape_hatch(context, code.into()).is_err() {
                    unsafe { libc::free(raw as *mut c_void) };
                    return Err(Error::EncryptionTypeConversion);
                }
                let res = s.to_owned().into_string()?;
                unsafe { libc::free(raw as *mut c_void) };
                Ok(res)
            }
        )
    }
}

/// Kerberos salt type
// In MIT krb5: src/lib/krb5/krb/str_conv.c
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
#[allow(clippy::exhaustive_enums)]
#[repr(transparent)]
#[cfg_attr(feature = "python", pyclass)]
pub struct SaltType(i32);

impl From<SaltType> for i32 {
    fn from(salttype: SaltType) -> Self {
        salttype.0
    }
}

impl From<i32> for SaltType {
    fn from(salttype: i32) -> Self {
        Self(salttype)
    }
}

impl SaltType {
    fn from_str(context: &Context, enctype: EncryptionType, s: &str) -> Result<Self> {
        let s = CString::new(s)?;
        let (salttype, code) = library_match!(
            &context.library;
            mit_client, mit_server => |cont, _lib| {
                let mut salttype = -1;
                let code =
                    unsafe { cont.krb5_string_to_salttype(s.as_ptr().cast_mut(), &mut salttype) };
                (salttype, code)
            },
            heimdal_client, heimdal_server => |cont, lib| {
                let mut salttype = 0;
                let code = unsafe {
                    cont.krb5_string_to_salttype(
                        context.context as lib!(krb5_context),
                        enctype.into(),
                        s.as_ptr().cast_mut(),
                        &mut salttype,
                    )
                };
                (salttype as i32, code)
            }
        );
        if krb5_error_code_escape_hatch(context, code.into()).is_err() {
            Err(Error::EncryptionTypeConversion)
        } else {
            Ok(salttype.into())
        }
    }

    fn to_string(self, context: &Context, enctype: EncryptionType) -> Result<String> {
        library_match!(
            &context.library;
            mit_client, mit_server => |cont, _lib| {
                let buffer = [0; 100];
                let code = unsafe {
                    let mut b: [c_char; 100] = std::mem::transmute(buffer);
                    cont.krb5_salttype_to_string(self.into(), b.as_mut_ptr(), 100)
                };
                if krb5_error_code_escape_hatch(context, code.into()).is_err() {
                    return Err(Error::SaltTypeConversion);
                }
                let s =
                    CStr::from_bytes_until_nul(&buffer).map_err(|_| Error::SaltTypeConversion)?;
                Ok(s.to_owned().into_string()?)
            },
            heimdal_client, heimdal_server => |cont, lib| {
                let mut raw: *mut i8 = null_mut();
                let code = unsafe {
                    cont.krb5_salttype_to_string(
                        context.context as lib!(krb5_context),
                        enctype.into(),
                        Into::<i32>::into(self) as u32,
                        &mut raw,
                    )
                };
                if raw.is_null() {
                    return Err(Error::SaltTypeConversion);
                }
                let s = unsafe { CStr::from_ptr(raw) };
                if krb5_error_code_escape_hatch(context, code.into()).is_err() {
                    unsafe { libc::free(raw as *mut c_void) };
                    return Err(Error::SaltTypeConversion);
                }
                let res = s.to_owned().into_string()?;
                unsafe { libc::free(raw as *mut c_void) };
                Ok(res)
            }
        )
    }
}

/// Kerberos keysalt
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[allow(clippy::exhaustive_structs)]
#[cfg_attr(feature = "python", pyclass(get_all, set_all))]
pub struct KeySalt {
    /// Encryption type
    pub enctype: EncryptionType,
    /// Salt type
    pub salttype: SaltType,
}

impl KeySalt {
    fn from_str(context: &Context, s: &str) -> Result<Self> {
        let (enctype, salttype) = if let Some((enctype, salttype)) = s.split_once(":") {
            let enctype = EncryptionType::from_str(context, enctype)?;
            let salttype = SaltType::from_str(context, enctype, salttype)?;
            (enctype, salttype)
        } else {
            let enctype = EncryptionType::from_str(context, s)?;
            (enctype, Default::default())
        };
        Ok(Self { enctype, salttype })
    }

    fn to_string(self, context: &Context) -> Result<String> {
        let enctype = self.enctype.to_string(context)?;
        let salttype = self.salttype.to_string(context, self.enctype)?;
        Ok(enctype + ":" + &salttype)
    }
}

#[cfg(mit_client)]
impl From<KeySalt> for sys::mit_client::krb5_key_salt_tuple {
    fn from(ks: KeySalt) -> Self {
        Self {
            ks_enctype: ks.enctype.into(),
            ks_salttype: ks.salttype.into(),
        }
    }
}

#[cfg(mit_server)]
impl From<KeySalt> for sys::mit_server::krb5_key_salt_tuple {
    fn from(ks: KeySalt) -> Self {
        Self {
            ks_enctype: ks.enctype.into(),
            ks_salttype: ks.salttype.into(),
        }
    }
}

#[cfg(heimdal_client)]
impl From<KeySalt> for sys::heimdal_client::krb5_key_salt_tuple {
    fn from(ks: KeySalt) -> Self {
        Self {
            ks_enctype: ks.enctype.into(),
            ks_salttype: ks.salttype.into(),
        }
    }
}

#[cfg(heimdal_server)]
impl From<KeySalt> for sys::heimdal_server::krb5_key_salt_tuple {
    fn from(ks: KeySalt) -> Self {
        Self {
            ks_enctype: ks.enctype.into(),
            ks_salttype: ks.salttype.into(),
        }
    }
}

/// Kerberos keysalt list
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::exhaustive_structs)]
#[cfg_attr(feature = "python", pyclass(get_all, set_all))]
pub struct KeySalts {
    /// Keysalt list
    pub keysalts: HashSet<KeySalt>,
}

impl KeySalts {
    pub(crate) fn from_str(context: &Context, s: &str) -> Result<Self> {
        let mut keysalts = HashSet::new();
        for ks in s.split([',', ' ', '\t']) {
            keysalts.insert(KeySalt::from_str(context, ks)?);
        }

        Ok(Self { keysalts })
    }

    pub(crate) fn to_string(&self, context: &Context) -> Result<String> {
        Ok(self
            .keysalts
            .iter()
            .map(|ks| ks.to_string(context))
            .collect::<Result<Vec<String>>>()?
            .join(","))
    }

    pub(crate) fn to_cstring(&self, context: &Context) -> Result<CString> {
        let s: String = self.to_string(context)?;
        Ok(CString::new(s)?)
    }
}

#[cfg(mit_client)]
impl From<&KeySalts> for Vec<sys::mit_client::krb5_key_salt_tuple> {
    fn from(kss: &KeySalts) -> Self {
        kss.keysalts.iter().map(|ks| (*ks).into()).collect()
    }
}

#[cfg(mit_server)]
impl From<&KeySalts> for Vec<sys::mit_server::krb5_key_salt_tuple> {
    fn from(kss: &KeySalts) -> Self {
        kss.keysalts.iter().map(|ks| (*ks).into()).collect()
    }
}

#[cfg(heimdal_client)]
impl From<&KeySalts> for Vec<sys::heimdal_client::krb5_key_salt_tuple> {
    fn from(kss: &KeySalts) -> Self {
        kss.keysalts.iter().map(|ks| (*ks).into()).collect()
    }
}

#[cfg(heimdal_server)]
impl From<&KeySalts> for Vec<sys::heimdal_server::krb5_key_salt_tuple> {
    fn from(kss: &KeySalts) -> Self {
        kss.keysalts.iter().map(|ks| (*ks).into()).collect()
    }
}

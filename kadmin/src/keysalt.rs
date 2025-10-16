//! Kerberos keysalt lists
use std::{
    collections::HashSet,
    ffi::{CStr, CString, c_char},
    str::FromStr,
};

#[cfg(feature = "python")]
use pyo3::prelude::*;

use crate::error::{Error, Result};

/// Kerberos encryption type
// In MIT krb5: src/lib/crypto/krb/etypes.c
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[allow(clippy::exhaustive_enums)]
#[repr(transparent)]
#[cfg_attr(feature = "python", pyclass(eq, eq_int))]
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

// impl FromStr for EncryptionType {
//     type Err = Error;
//
//     fn from_str(s: &str) -> Result<Self> {
//         let s = CString::new(s)?;
//         let mut enctype = -1;
//         let code = unsafe { krb5_string_to_enctype(s.as_ptr().cast_mut(), &mut enctype) };
//         if code != KRB5_OK {
//             Err(Error::EncryptionTypeConversion)
//         } else {
//             enctype.try_into()
//         }
//     }
// }

// impl TryFrom<&str> for EncryptionType {
//     type Error = Error;
//
//     fn try_from(s: &str) -> Result<Self> {
//         Self::from_str(s)
//     }
// }

// impl TryFrom<EncryptionType> for String {
//     type Error = Error;
//
//     fn try_from(enctype: EncryptionType) -> Result<Self> {
//         let buffer = [0; 100];
//         let code = unsafe {
//             let mut b: [c_char; 100] = std::mem::transmute(buffer);
//             krb5_enctype_to_string(enctype.into(), b.as_mut_ptr(), 100)
//         };
//         if code != KRB5_OK {
//             return Err(Error::EncryptionTypeConversion);
//         }
//         let s = CStr::from_bytes_until_nul(&buffer).map_err(|_|
// Error::EncryptionTypeConversion)?;         Ok(s.to_owned().into_string()?)
//     }
// }

/// Kerberos salt type
// In MIT krb5: src/lib/krb5/krb/str_conv.c
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
#[allow(clippy::exhaustive_enums)]
#[repr(transparent)]
#[cfg_attr(feature = "python", pyclass(eq, eq_int))]
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

// impl FromStr for SaltType {
//     type Err = Error;
//
//     fn from_str(s: &str) -> Result<Self> {
//         if s.is_empty() {
//             return Ok(SaltType::Normal);
//         }
//         let s = CString::new(s)?;
//         let mut salttype = 0;
//         let code = unsafe { krb5_string_to_salttype(s.as_ptr().cast_mut(), &mut salttype) };
//         if code != KRB5_OK {
//             Err(Error::SaltTypeConversion)
//         } else {
//             salttype.try_into()
//         }
//     }
// }

// impl TryFrom<&str> for SaltType {
//     type Error = Error;
//
//     fn try_from(s: &str) -> Result<Self> {
//         Self::from_str(s)
//     }
// }

// impl TryFrom<Option<&str>> for SaltType {
//     type Error = Error;
//
//     fn try_from(s: Option<&str>) -> Result<Self> {
//         if let Some(s) = s {
//             s.try_into()
//         } else {
//             Ok(SaltType::Normal)
//         }
//     }
// }

// impl TryFrom<SaltType> for String {
//     type Error = Error;
//
//     fn try_from(salttype: SaltType) -> Result<Self> {
//         let buffer = [0; 100];
//         let code = unsafe {
//             let mut b: [c_char; 100] = std::mem::transmute(buffer);
//             krb5_enctype_to_string(salttype.into(), b.as_mut_ptr(), 100)
//         };
//         if code != KRB5_OK {
//             return Err(Error::SaltTypeConversion);
//         }
//         let s = CStr::from_bytes_until_nul(&buffer).map_err(|_| Error::SaltTypeConversion)?;
//         Ok(s.to_owned().into_string()?)
//     }
// }

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

// impl TryFrom<KeySalt> for String {
//     type Error = Error;
//
//     fn try_from(ks: KeySalt) -> Result<Self> {
//         let enctype: String = ks.enctype.try_into()?;
//         let salttype: String = ks.salttype.try_into()?;
//         Ok(enctype + ":" + &salttype)
//     }
// }
//
// impl From<KeySalt> for krb5_key_salt_tuple {
//     fn from(ks: KeySalt) -> Self {
//         Self {
//             ks_enctype: ks.enctype.into(),
//             ks_salttype: ks.salttype.into(),
//         }
//     }
// }

/// Kerberos keysalt list
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::exhaustive_structs)]
#[cfg_attr(feature = "python", pyclass(get_all, set_all))]
pub struct KeySalts {
    /// Keysalt list
    pub keysalts: HashSet<KeySalt>,
}

// impl TryFrom<&KeySalts> for String {
//     type Error = Error;
//
//     fn try_from(ksl: &KeySalts) -> Result<Self> {
//         Ok(ksl
//             .keysalts
//             .iter()
//             .map(|ks| (*ks).try_into())
//             .collect::<Result<Vec<String>>>()?
//             .join(","))
//     }
// }

impl KeySalts {
    // pub(crate) fn from_str(s: &str) -> Result<Self> {
    //     let mut keysalts = HashSet::new();
    //     for ks in s.split([',', ' ', '\t']) {
    //         let (enctype, salttype) = if let Some((enctype, salttype)) = ks.split_once(":") {
    //             (enctype.try_into()?, salttype.try_into()?)
    //         } else {
    //             (ks.try_into()?, Default::default())
    //         };
    //         keysalts.insert(KeySalt { enctype, salttype });
    //     }
    //
    //     Ok(Self { keysalts })
    // }

    // pub(crate) fn to_cstring(&self) -> Result<CString> {
    //     let s: String = self.try_into()?;
    //     Ok(CString::new(s)?)
    // }

    // pub(crate) fn to_raw(&self) -> Vec<krb5_key_salt_tuple> {
    //     self.keysalts.iter().map(|ks| (*ks).into()).collect()
    // }
}

//! Kerberos keysalt lists
use std::{
    collections::HashSet,
    ffi::{CStr, CString, c_char},
    str::FromStr,
};

use kadmin_sys::*;
#[cfg(feature = "python")]
use pyo3::prelude::*;
use strum::FromRepr;

use crate::error::{Error, Result};

/// Kerberos encryption type
// In MIT krb5: src/lib/crypto/krb/etypes.c
#[derive(Copy, Clone, Debug, FromRepr, PartialEq, Eq, Hash)]
#[allow(clippy::exhaustive_enums)]
#[repr(i32)]
#[cfg_attr(feature = "python", pyclass(eq, eq_int))]
pub enum EncryptionType {
    /// Triple DES cbc mode raw (weak, deprecated)
    Des3CbcRaw = ENCTYPE_DES3_CBC_RAW as krb5_enctype,
    /// Triple DES cbc mode with HMAC/sha1 (deprecated)
    Des3CbcSha1 = ENCTYPE_DES3_CBC_SHA1 as krb5_enctype,
    /// ArcFour with HMAC/md5 (deprecated)
    ArcfourHmac = ENCTYPE_ARCFOUR_HMAC as krb5_enctype,
    /// Exportable ArcFour with HMAC/md5 (weak, deprecated)
    ArcfourHmacExp = ENCTYPE_ARCFOUR_HMAC_EXP as krb5_enctype,
    /// AES-128 CTS mode with 96-bit SHA-1 HMAC
    Aes128CtsHmacSha196 = ENCTYPE_AES128_CTS_HMAC_SHA1_96 as krb5_enctype,
    /// AES-256 CTS mode with 96-bit SHA-1 HMAC
    Aes256CtsHmacSha196 = ENCTYPE_AES256_CTS_HMAC_SHA1_96 as krb5_enctype,
    /// Camellia-128 CTS mode with CMAC
    Camellia128CtsCmac = ENCTYPE_CAMELLIA128_CTS_CMAC as krb5_enctype,
    /// Camellia-256 CTS mode with CMAC
    Camellia256CtsCmac = ENCTYPE_CAMELLIA256_CTS_CMAC as krb5_enctype,
    /// AES-128 CTS mode with 128-bit SHA-256 HMAC
    Aes128CtsHmacSha256128 = ENCTYPE_AES128_CTS_HMAC_SHA256_128 as krb5_enctype,
    /// AES-256 CTS mode with 192-bit SHA-384 HMAC
    Aes256CtsHmacSha384192 = ENCTYPE_AES256_CTS_HMAC_SHA384_192 as krb5_enctype,
}

impl From<EncryptionType> for krb5_enctype {
    fn from(enctype: EncryptionType) -> Self {
        enctype as Self
    }
}

impl TryFrom<krb5_enctype> for EncryptionType {
    type Error = Error;

    fn try_from(enctype: krb5_enctype) -> Result<Self> {
        Self::from_repr(enctype).ok_or(Error::EncryptionTypeConversion)
    }
}

impl FromStr for EncryptionType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = CString::new(s)?;
        let mut enctype = -1;
        let code = unsafe { krb5_string_to_enctype(s.as_ptr().cast_mut(), &mut enctype) };
        if code != KRB5_OK {
            Err(Error::EncryptionTypeConversion)
        } else {
            enctype.try_into()
        }
    }
}

impl TryFrom<&str> for EncryptionType {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        Self::from_str(s)
    }
}

impl TryFrom<EncryptionType> for String {
    type Error = Error;

    fn try_from(enctype: EncryptionType) -> Result<Self> {
        let buffer = [0; 100];
        let code = unsafe {
            let mut b: [c_char; 100] = std::mem::transmute(buffer);
            krb5_enctype_to_string(enctype.into(), b.as_mut_ptr(), 100)
        };
        if code != KRB5_OK {
            return Err(Error::EncryptionTypeConversion);
        }
        let s = CStr::from_bytes_until_nul(&buffer).map_err(|_| Error::EncryptionTypeConversion)?;
        Ok(s.to_owned().into_string()?)
    }
}

/// Kerberos salt type
// In MIT krb5: src/lib/krb5/krb/str_conv.c
#[derive(Copy, Clone, Debug, FromRepr, PartialEq, Eq, Hash)]
#[allow(clippy::exhaustive_enums)]
#[repr(i32)]
#[cfg_attr(feature = "python", pyclass(eq, eq_int))]
pub enum SaltType {
    /// Default for Kerberos Version 5
    #[default]
    Normal = KRB5_KDB_SALTTYPE_NORMAL as krb5_int32,
    /// Same as the default, without using realm information
    NoRealm = KRB5_KDB_SALTTYPE_NOREALM as krb5_int32,
    /// Uses only realm information as the salt
    OnlyRealm = KRB5_KDB_SALTTYPE_ONLYREALM as krb5_int32,
    /// Generate a random salt
    Special = KRB5_KDB_SALTTYPE_SPECIAL as krb5_int32,
}

impl From<SaltType> for krb5_int32 {
    fn from(salttype: SaltType) -> Self {
        salttype as Self
    }
}

impl TryFrom<krb5_int32> for SaltType {
    type Error = Error;

    fn try_from(salttype: krb5_int32) -> Result<Self> {
        Self::from_repr(salttype).ok_or(Error::SaltTypeConversion)
    }
}

impl FromStr for SaltType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            return Ok(SaltType::Normal);
        }
        let s = CString::new(s)?;
        let mut salttype = 0;
        let code = unsafe { krb5_string_to_salttype(s.as_ptr().cast_mut(), &mut salttype) };
        if code != KRB5_OK {
            Err(Error::SaltTypeConversion)
        } else {
            salttype.try_into()
        }
    }
}

impl TryFrom<&str> for SaltType {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        Self::from_str(s)
    }
}

impl TryFrom<Option<&str>> for SaltType {
    type Error = Error;

    fn try_from(s: Option<&str>) -> Result<Self> {
        if let Some(s) = s {
            s.try_into()
        } else {
            Ok(SaltType::Normal)
        }
    }
}

impl TryFrom<SaltType> for String {
    type Error = Error;

    fn try_from(salttype: SaltType) -> Result<Self> {
        let buffer = [0; 100];
        let code = unsafe {
            let mut b: [c_char; 100] = std::mem::transmute(buffer);
            krb5_enctype_to_string(salttype.into(), b.as_mut_ptr(), 100)
        };
        if code != KRB5_OK {
            return Err(Error::SaltTypeConversion);
        }
        let s = CStr::from_bytes_until_nul(&buffer).map_err(|_| Error::SaltTypeConversion)?;
        Ok(s.to_owned().into_string()?)
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

impl TryFrom<KeySalt> for String {
    type Error = Error;

    fn try_from(ks: KeySalt) -> Result<Self> {
        let enctype: String = ks.enctype.try_into()?;
        let salttype: String = ks.salttype.try_into()?;
        Ok(enctype + ":" + &salttype)
    }
}

impl From<KeySalt> for krb5_key_salt_tuple {
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

impl TryFrom<&KeySalts> for String {
    type Error = Error;

    fn try_from(ksl: &KeySalts) -> Result<Self> {
        Ok(ksl
            .keysalts
            .iter()
            .map(|ks| (*ks).try_into())
            .collect::<Result<Vec<String>>>()?
            .join(","))
    }
}

impl KeySalts {
    pub(crate) fn from_str(s: &str) -> Result<Self> {
        let mut keysalts = HashSet::new();
        for ks in s.split([',', ' ', '\t']) {
            let (enctype, salttype) = if let Some((enctype, salttype)) = ks.split_once(":") {
                (enctype.try_into()?, salttype.try_into()?)
            } else {
                (ks.try_into()?, Default::default())
            };
            keysalts.insert(KeySalt { enctype, salttype });
        }

        Ok(Self { keysalts })
    }

    pub(crate) fn to_cstring(&self) -> Result<CString> {
        let s: String = self.try_into()?;
        Ok(CString::new(s)?)
    }

    pub(crate) fn to_raw(&self) -> Vec<krb5_key_salt_tuple> {
        self.keysalts.iter().map(|ks| (*ks).into()).collect()
    }
}

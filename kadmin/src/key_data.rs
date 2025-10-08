//! Kadm5 [`KeyData`]

use std::{ffi::c_char, ptr::null_mut};

use kadmin_sys::*;
#[cfg(feature = "python")]
use pyo3::prelude::*;

use crate::{EncryptionType, SaltType, error::Result};

/// Kerberos data
#[allow(clippy::exhaustive_structs)]
#[derive(Clone, Debug)]
#[cfg_attr(feature = "python", pyclass(get_all, set_all))]
pub struct Krb5Data {
    /// Magic number
    pub magic: krb5_magic,
    /// Data
    pub data: Vec<c_char>,
}

impl Krb5Data {
    pub(crate) fn from_raw(data: &krb5_data) -> Self {
        dbg!(data);
        Self {
            magic: data.magic,
            data: unsafe { std::slice::from_raw_parts(data.data, data.length as usize) }.to_vec(),
        }
    }
}

/// Salt associated with a key
#[allow(clippy::exhaustive_structs)]
#[derive(Clone, Debug)]
#[cfg_attr(feature = "python", pyclass(get_all, set_all))]
pub struct KeyDataSalt {
    /// Salt type
    pub r#type: SaltType,
    /// Data
    pub data: Krb5Data,
}

impl KeyDataSalt {
    pub(crate) fn from_raw(keysalt: &krb5_keysalt) -> Result<Option<Self>> {
        if keysalt.type_ == 0 {
            return Ok(None);
        }
        Ok(Some(Self {
            r#type: keysalt.type_.try_into()?,
            data: Krb5Data::from_raw(&keysalt.data),
        }))
    }
}

/// Key block
#[allow(clippy::exhaustive_structs)]
#[derive(Clone, Debug)]
#[cfg_attr(feature = "python", pyclass(get_all, set_all))]
pub struct KeyDataBlock {
    /// Magic number
    pub magic: krb5_magic,
    /// Encryption type
    pub enctype: EncryptionType,
    /// Data
    pub contents: Vec<krb5_octet>,
}

impl KeyDataBlock {
    pub(crate) fn from_raw(block: &krb5_keyblock) -> Result<Self> {
        Ok(Self {
            magic: block.magic,
            enctype: block.enctype.try_into()?,
            contents: unsafe { std::slice::from_raw_parts(block.contents, block.length as usize) }
                .to_vec(),
        })
    }
}

/// A single key data entry
#[allow(clippy::exhaustive_structs)]
#[derive(Clone, Debug)]
#[cfg_attr(feature = "python", pyclass(get_all, set_all))]
pub struct KeyDataEntry {
    /// Key version number
    pub kvno: krb5_kvno,
    /// Key
    pub key: KeyDataBlock,
    /// Salt
    pub salt: Option<KeyDataSalt>,
}

/// Key data entries
#[derive(Clone, Debug)]
#[allow(clippy::exhaustive_structs)]
#[cfg_attr(feature = "python", pyclass(get_all, set_all))]
pub struct KeyData {
    /// Key data entries
    pub entries: Vec<KeyDataEntry>,
}

impl KeyData {
    pub(crate) fn from_raw(n_key_data: krb5_int32, key_data: *mut kadm5_key_data) -> Result<Self> {
        dbg!(n_key_data);
        dbg!(key_data);
        let raw_entries = unsafe { std::slice::from_raw_parts(key_data, n_key_data as usize) };
        let mut entries = Vec::with_capacity(n_key_data as usize);

        for raw_entry in raw_entries {
            // We've checked above that the pointer is not null
            entries.push(KeyDataEntry {
                kvno: raw_entry.kvno,
                key: KeyDataBlock::from_raw(&raw_entry.key)?,
                salt: KeyDataSalt::from_raw(&raw_entry.salt)?,
            });
        }

        Ok(Self { entries })
    }
}

// impl TlData {
//     /// Create a [`TlData`] from [`_krb5_tl_data`]
//     pub(crate) fn from_raw(n_tl_data: krb5_int16, mut tl_data: *mut _krb5_tl_data) -> Self {
//         let mut entries = Vec::with_capacity(n_tl_data as usize);
//
//         while !tl_data.is_null() {
//             // We've checked above that the pointer is not null
//             let data_type = unsafe { (*tl_data).tl_data_type };
//             let contents_length = unsafe { (*tl_data).tl_data_length };
//             let contents = unsafe {
//                 std::slice::from_raw_parts((*tl_data).tl_data_contents, contents_length.into())
//             }
//             .to_vec();
//             entries.push(TlDataEntry {
//                 data_type,
//                 contents,
//             });
//             tl_data = unsafe { (*tl_data).tl_data_next };
//         }
//
//         Self { entries }
//     }
//
//     /// Create a [`_krb5_tl_data`] from [`TlData`]
//     ///
//     /// Returns None if there are not TL-data.
//     pub(crate) fn to_raw(&self) -> TlDataRaw {
//         if self.entries.is_empty() {
//             return TlDataRaw {
//                 raw: null_mut(),
//                 _raw_entries: vec![],
//                 _raw_contents: vec![],
//             };
//         }
//
//         let mut raw_contents = Vec::new();
//         let mut raw_entries: Vec<_> = self
//             .entries
//             .iter()
//             .map(|entry| {
//                 let contents = entry.contents.clone();
//                 let data = _krb5_tl_data {
//                     tl_data_type: entry.data_type,
//                     tl_data_length: entry.contents.len() as krb5_ui_2,
//                     tl_data_contents: contents.as_ptr().cast_mut(),
//                     tl_data_next: null_mut(),
//                 };
//                 raw_contents.push(contents);
//                 data
//             })
//             .collect();
//
//         for i in 1..raw_entries.len() {
//             raw_entries[i - 1].tl_data_next = &mut raw_entries[i];
//         }
//
//         TlDataRaw {
//             raw: raw_entries.as_mut_ptr(),
//             _raw_entries: raw_entries,
//             _raw_contents: raw_contents,
//         }
//     }
// }
//
// #[derive(Debug)]
// pub(crate) struct TlDataRaw {
//     pub(crate) raw: *mut krb5_tl_data,
//     pub(crate) _raw_entries: Vec<_krb5_tl_data>,
//     pub(crate) _raw_contents: Vec<Vec<krb5_octet>>,
// }

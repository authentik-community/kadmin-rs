//! Kadm5 [`TlData`]

use std::ptr::null_mut;

use kadmin_sys::*;
#[cfg(feature = "python")]
use pyo3::prelude::*;

/// A single TL-data entry
#[allow(clippy::exhaustive_structs)]
#[derive(Clone, Debug)]
#[cfg_attr(feature = "python", pyclass(get_all, set_all))]
pub struct TlDataEntry {
    /// TL-data type
    pub data_type: i16,
    /// Entry contents
    pub contents: Vec<u8>,
}

/// TL-data entries
#[derive(Clone, Debug, Default)]
#[allow(clippy::exhaustive_structs)]
#[cfg_attr(feature = "python", pyclass(get_all, set_all))]
pub struct TlData {
    /// TL-data entries
    pub entries: Vec<TlDataEntry>,
}

impl TlData {
    /// Create a [`TlData`] from [`_krb5_tl_data`]
    pub(crate) fn from_raw(n_tl_data: i16, mut tl_data: *mut _krb5_tl_data) -> Self {
        let mut entries = Vec::with_capacity(n_tl_data as usize);

        while !tl_data.is_null() {
            // We've checked above that the pointer is not null
            let data_type = unsafe { (*tl_data).tl_data_type };
            let contents_length = unsafe { (*tl_data).tl_data_length };
            let contents = unsafe {
                std::slice::from_raw_parts((*tl_data).tl_data_contents, contents_length.into())
            }
            .to_vec();
            entries.push(TlDataEntry {
                data_type,
                contents,
            });
            tl_data = unsafe { (*tl_data).tl_data_next };
        }

        Self { entries }
    }

    /// Create a [`_krb5_tl_data`] from [`TlData`]
    ///
    /// Returns None if there are not TL-data.
    ///
    /// # Safety
    ///
    /// The element in the second position of the returned tuple needs to live as long as
    /// [`_krb5_tl_data`] lives
    pub(crate) unsafe fn to_raw(&self) -> Option<TlDataRaw> {
        if self.entries.is_empty() {
            return None;
        }

        let mut raw_contents = Vec::new();
        let mut raw_entries: Vec<_> = self
            .entries
            .iter()
            .map(|entry| {
                let contents = entry.contents.clone();
                let data = _krb5_tl_data {
                    tl_data_type: entry.data_type,
                    tl_data_length: entry.contents.len() as u16,
                    tl_data_contents: contents.as_ptr().cast_mut(),
                    tl_data_next: null_mut(),
                };
                raw_contents.push(contents);
                data
            })
            .collect();

        for i in 1..raw_entries.len() {
            raw_entries[i - 1].tl_data_next = &mut raw_entries[i];
        }

        Some(TlDataRaw {
            raw: raw_entries[0],
            _raw_entries: raw_entries,
            _raw_contents: raw_contents,
        })
    }
}

pub(crate) struct TlDataRaw {
    pub(crate) raw: _krb5_tl_data,
    pub(crate) _raw_entries: Vec<_krb5_tl_data>,
    pub(crate) _raw_contents: Vec<Vec<u8>>,
}
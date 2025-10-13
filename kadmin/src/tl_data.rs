//! Kadm5 [`TlData`]

#[cfg(heimdal)]
use std::ffi::c_void;
use std::ptr::null_mut;

#[cfg(feature = "python")]
use pyo3::prelude::*;

use crate::sys;

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
#[derive(Clone, Debug)]
#[allow(clippy::exhaustive_structs)]
#[cfg_attr(feature = "python", pyclass(get_all, set_all))]
pub struct TlData {
    /// TL-data entries
    pub entries: Vec<TlDataEntry>,
}

impl TlData {
    #[cfg(mit)]
    /// Create a [`TlData`] from [`sys::mit::_krb5_tl_data`]
    pub(crate) fn from_raw_mit(n_tl_data: i16, mut tl_data: *mut sys::mit::_krb5_tl_data) -> Self {
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

    #[cfg(heimdal)]
    /// Create a [`TlData`] from [`sys::heimdal::_krb5_tl_data`]
    pub(crate) fn from_raw_heimdal(
        n_tl_data: i16,
        mut tl_data: *mut sys::heimdal::_krb5_tl_data,
    ) -> Self {
        let mut entries = Vec::with_capacity(n_tl_data as usize);

        while !tl_data.is_null() {
            // We've checked above that the pointer is not null
            let data_type = unsafe { (*tl_data).tl_data_type };
            let contents_length = unsafe { (*tl_data).tl_data_length };
            let contents = unsafe {
                std::slice::from_raw_parts(
                    (*tl_data).tl_data_contents as *mut u8,
                    contents_length as usize,
                )
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

    #[cfg(mit)]
    /// Create a [`sys::mit::_krb5_tl_data`] from [`TlData`]
    ///
    /// Returns None if there are not TL-data.
    pub(crate) fn to_raw_mit(&self) -> TlDataRawMit {
        if self.entries.is_empty() {
            return TlDataRawMit {
                raw: null_mut(),
                _raw_entries: vec![],
                _raw_contents: vec![],
            };
        }

        let mut raw_contents = Vec::new();
        let mut raw_entries: Vec<_> = self
            .entries
            .iter()
            .map(|entry| {
                let contents = entry.contents.clone();
                let data = sys::mit::_krb5_tl_data {
                    tl_data_type: entry.data_type,
                    tl_data_length: entry.contents.len().try_into().unwrap(),
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

        TlDataRawMit {
            raw: raw_entries.as_mut_ptr(),
            _raw_entries: raw_entries,
            _raw_contents: raw_contents,
        }
    }

    #[cfg(heimdal)]
    /// Create a [`sys::heimdal::_krb5_tl_data`] from [`TlData`]
    ///
    /// Returns None if there are not TL-data.
    pub(crate) fn to_raw_heimdal(&self) -> TlDataRawHeimdal {
        if self.entries.is_empty() {
            return TlDataRawHeimdal {
                raw: null_mut(),
                _raw_entries: vec![],
                _raw_contents: vec![],
            };
        }

        let mut raw_contents = Vec::new();
        let mut raw_entries: Vec<_> = self
            .entries
            .iter()
            .map(|entry| {
                let contents = entry.contents.clone();
                let data = sys::heimdal::_krb5_tl_data {
                    tl_data_type: entry.data_type,
                    tl_data_length: entry.contents.len().try_into().unwrap(),
                    tl_data_contents: contents.as_ptr().cast_mut() as *mut c_void,
                    tl_data_next: null_mut(),
                };
                raw_contents.push(contents);
                data
            })
            .collect();

        for i in 1..raw_entries.len() {
            raw_entries[i - 1].tl_data_next = &mut raw_entries[i];
        }

        TlDataRawHeimdal {
            raw: raw_entries.as_mut_ptr(),
            _raw_entries: raw_entries,
            _raw_contents: raw_contents,
        }
    }
}

#[cfg(mit)]
#[derive(Debug)]
pub(crate) struct TlDataRawMit {
    pub(crate) raw: *mut sys::mit::krb5_tl_data,
    pub(crate) _raw_entries: Vec<sys::mit::_krb5_tl_data>,
    pub(crate) _raw_contents: Vec<Vec<u8>>,
}

#[cfg(heimdal)]
#[derive(Debug)]
pub(crate) struct TlDataRawHeimdal {
    pub(crate) raw: *mut sys::heimdal::krb5_tl_data,
    pub(crate) _raw_entries: Vec<sys::heimdal::_krb5_tl_data>,
    pub(crate) _raw_contents: Vec<Vec<u8>>,
}

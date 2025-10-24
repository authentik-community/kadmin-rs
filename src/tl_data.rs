//! Kadm5 [`TlData`]

use std::{ffi::c_void, ptr::null_mut};

#[cfg(feature = "python")]
use pyo3::prelude::*;

use crate::{context::Context, sys::library_match};

/// A single TL-data entry
#[allow(clippy::exhaustive_structs)]
#[derive(Clone, Default, Debug)]
#[cfg_attr(feature = "python", pyclass(get_all, set_all))]
pub struct TlDataEntry {
    /// TL-data type
    pub data_type: i16,
    /// Entry contents
    pub contents: Vec<u8>,
}

/// TL-data entries
#[derive(Clone, Default, Debug)]
#[allow(clippy::exhaustive_structs)]
#[cfg_attr(feature = "python", pyclass(get_all, set_all))]
pub struct TlData {
    /// TL-data entries
    pub entries: Vec<TlDataEntry>,
}

impl TlData {
    /// Create a [`TlData`] from `_krb5_tl_data`
    pub(crate) fn from_raw(context: &Context, n_tl_data: i16, tl_data: *const c_void) -> Self {
        let mut entries = Vec::with_capacity(n_tl_data as usize);

        library_match!(
            &context.library;
            mit_client, mit_server => |_cont, lib| {
                let mut tl_data = tl_data as *const lib!(_krb5_tl_data);
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
            },
            heimdal_client, heimdal_server => |_cont, lib| {
                let mut tl_data = tl_data as *mut lib!(_krb5_tl_data);
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
            }
        );

        Self { entries }
    }
}

pub(crate) struct TlDataRaw<'a> {
    pub(crate) raw: *const c_void,
    context: &'a Context,

    _contents: Vec<Vec<u8>>,
}

impl<'a> TlDataRaw<'a> {
    #[allow(clippy::field_reassign_with_default)]
    pub(crate) fn build(context: &'a Context, tl_data: &TlData) -> Self {
        if tl_data.entries.is_empty() {
            return Self {
                raw: null_mut(),
                context,
                _contents: vec![],
            };
        }

        let mut contents = Vec::new();

        let raw = library_match!(
            &context.library;
            mit_client, mit_server => |_cont, lib| {
                let mut raw: Vec<_> = tl_data
                    .entries
                    .iter()
                    .map(|entry| {
                        let entry_contents = entry.contents.clone();
                        let mut data: lib!(_krb5_tl_data) = Default::default();
                        data.tl_data_type = entry.data_type;
                        data.tl_data_length = entry_contents.len() as u16;
                        data.tl_data_contents = entry_contents.as_ptr().cast_mut();
                        contents.push(entry_contents);
                        data
                    })
                    .collect();

                for i in 1..raw.len() {
                    raw[i - 1].tl_data_next = &mut raw[i];
                }

                let raw = Box::new(raw);
                Box::into_raw(raw) as *const c_void
            },
            heimdal_client, heimdal_server => |_cont, lib| {
                let mut raw: Vec<_> = tl_data
                    .entries
                    .iter()
                    .map(|entry| {
                        let entry_contents = entry.contents.clone();
                        let mut data: lib!(_krb5_tl_data) = Default::default();
                        data.tl_data_type = entry.data_type;
                        data.tl_data_length = entry_contents.len() as i16;
                        data.tl_data_contents = entry_contents.as_ptr().cast_mut() as *mut c_void;
                        contents.push(entry_contents);
                        data
                    })
                    .collect();

                for i in 1..raw.len() {
                    raw[i - 1].tl_data_next = &mut raw[i];
                }

                let raw = Box::new(raw);
                Box::into_raw(raw) as *const c_void
            }
        );

        Self {
            raw,
            context,
            _contents: contents,
        }
    }
}

impl Drop for TlDataRaw<'_> {
    fn drop(&mut self) {
        if self.raw.is_null() {
            return;
        }
        library_match!(&self.context.library; |_cont, lib| {
            let raw: Box<Vec<lib!(_krb5_tl_data)>> = unsafe { Box::from_raw(self.raw as *mut Vec<lib!(_krb5_tl_data)>) };
            drop(raw);
        });
    }
}

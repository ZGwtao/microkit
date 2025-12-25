//
// Copyright 2025, UNSW
//
// SPDX-License-Identifier: BSD-2-Clause
//

use crate::{
    MAX_CHANNELS
};

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MemoryMapping {
    pub vaddr: u64,
    pub page: u64,
    pub number_of_pages: u64,
    pub page_size: u64,
    pub rights: u64,
    pub attrs: u64,
}
impl Default for MemoryMapping {
    fn default() -> Self {
        MemoryMapping {
            vaddr: 0,
            page: 0,
            number_of_pages: 0,
            page_size: 0,
            rights: 0,
            attrs: 0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct StrippedMapping {
    pub vaddr: u64,
    pub number_of_pages: u64,
    pub page_size: u64,
}
impl Default for StrippedMapping {
    fn default() -> Self {
        StrippedMapping {
            vaddr: 0,
            number_of_pages: 0,
            page_size: 0,
        }
    }
}

#[repr(C)]
pub struct TrustedLoaderMetadata {
    pub child_id:   usize,
    pub system_hash: u64,
    pub public_key: [u8; 32],
    pub channels:   [u8; MAX_CHANNELS],
    pub cstate:     [u8; MAX_CHANNELS],
    pub irqs:       [u64; MAX_CHANNELS],
    pub mappings:   [MemoryMapping; 62],
    pub init:       u8,
}

impl Default for TrustedLoaderMetadata {
    fn default() -> Self {
        TrustedLoaderMetadata {
            child_id:   0,
            system_hash: 0,
            public_key: [0u8; 32],
            channels:   [0u8; MAX_CHANNELS],
            cstate:     [0u8; MAX_CHANNELS],
            irqs:       [0u64; MAX_CHANNELS],
            mappings:   [MemoryMapping::default(); 62],
            init:       0
        }
    }
}

#[repr(C)]
pub struct TrustedLoaderMetadataArray {
    pub avail_trusted_loader: u8,
    /* maximum is 64 per monitor */
    pub trusted_loader_md_array: [TrustedLoaderMetadata; 16],
}
impl Default for TrustedLoaderMetadataArray {
    fn default() -> Self {
        use std::array::from_fn;
        let trusted_loader_md_array = from_fn(|i| {
            let mut md = TrustedLoaderMetadata::default();
            md.child_id = i as usize; // 0..63
            md
        });
        TrustedLoaderMetadataArray { avail_trusted_loader: 0, trusted_loader_md_array }
    }
}


pub const MAX_NAME: usize = 63;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DataNameCStr {
    pub bytes: [u8; MAX_NAME + 1], // always null-terminated
}

impl Default for DataNameCStr {
    #[inline]
    fn default() -> Self { Self { bytes: [0; MAX_NAME + 1] } }
}

impl DataNameCStr {
    /// Set name; errors if `s.len() > MAX_NAME`.
    #[inline]
    pub fn set(&mut self, s: &str) -> Result<(), ()> {
        let n = s.as_bytes().len();
        if n > MAX_NAME { return Err(()); }
        // write bytes
        self.bytes[..n].copy_from_slice(s.as_bytes());
        // write terminator and clear the tail (optional but neat)
        self.bytes[n] = 0;
        if n + 1 < self.bytes.len() {
            self.bytes[n + 1..].fill(0);
        }
        Ok(())
    }

    /// Truncating setter (keeps API total if you prefer no Result).
    #[inline]
    pub fn set_trunc(&mut self, s: &str) {
        let n = core::cmp::min(s.len(), MAX_NAME);
        self.bytes[..n].copy_from_slice(&s.as_bytes()[..n]);
        self.bytes[n] = 0;
        if n + 1 < self.bytes.len() {
            self.bytes[n + 1..].fill(0);
        }
    }

    /// Returns as &str (UTF-8). Safe because we only accept &str on input.
    #[inline]
    pub fn as_str(&self) -> &str {
        let n = self.bytes.iter().position(|&b| b == 0).unwrap_or(self.bytes.len());
        // Safety: constructed from &str; we never write non-UTF8.
        unsafe { str::from_utf8_unchecked(&self.bytes[..n]) }
    }

    /// Get raw C pointer if you pass it to C.
    #[inline]
    pub fn as_ptr(&self) -> *const u8 { self.bytes.as_ptr() }

    #[inline]
    pub fn clear(&mut self) { self.bytes = [0; MAX_NAME + 1]; }

    /// Is it empty ("")?
    #[inline]
    pub fn is_empty(&self) -> bool { self.bytes[0] == 0 }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct AcGrp {
    pub grp_init:   bool,
    pub grp_idx:    u8,
    pub grp_type:   u8,
    pub channels:   [u8; 8],
    pub irqs:       [u8; 8],
    pub mappings:   [StrippedMapping; 16],
    pub data_name:  DataNameCStr,
}
impl Default for AcGrp {
    fn default() -> Self {
        AcGrp {
            grp_init:   false,
            grp_idx:    0,
            grp_type:   0,
            channels:   [!0u8; 8],
            irqs:       [!0u8; 8],
            mappings:   [StrippedMapping::default(); 16],
            data_name:  DataNameCStr::default(),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct AcGrpArr {
    pub pd_idx: u8,
    // number of available grps in the list...
    // FIXME: sequential ID required
    pub grp_num: u8,
    // FIXME: I don't think have 64 acgroups is practical...
    pub array: [AcGrp; 32],
}
impl Default for AcGrpArr {
    fn default() -> Self {
        use std::array::from_fn;
        let arr = from_fn(|_| {
            let grp = AcGrp::default();
            grp
        });
        AcGrpArr { pd_idx: 0, grp_num: 0, array: arr }
    }
}

#[repr(C)]
pub struct AcGrpArrList {
    // FIXME: we are assuming all acg_arr IDs are sequential
    pub num: usize,
    // FIXME: also 64 child PD is not practical...
    pub list: [AcGrpArr; 16],
}
impl Default for AcGrpArrList {
    fn default() -> Self {
        use std::array::from_fn;
        let arr_list = from_fn(|i| {
            let mut grp_arr = AcGrpArr::default();
            grp_arr.pd_idx = i as u8;
            grp_arr
        });
        AcGrpArrList { num: 0, list: arr_list }
    }
}


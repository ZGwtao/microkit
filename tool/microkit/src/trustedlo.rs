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
pub struct OSSvc {
    pub svc_init:   bool,
    pub svc_idx:    u8,
    pub svc_type:   u8,
    pub channels:   [u8; 4],
    pub irqs:       [u8; 4],
    pub mappings:   [StrippedMapping; 4],
    pub data_name:  DataNameCStr,
}
impl Default for OSSvc {
    fn default() -> Self {
        OSSvc {
            svc_init:   false,
            svc_idx:    0,
            svc_type:   0,
            channels:   [!0u8; 4],
            irqs:       [!0u8; 4],
            mappings:   [StrippedMapping::default(); 4],
            data_name:  DataNameCStr::default(),
        }
    }
}

/// ProtoconSvcDatabase:
///  records the available os services (svc) that belongs to
///  one dynamic PD, whose limit for the domains equals 16
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ProtoconSvcDatabase {
    pub pd_idx: u8,
    // number of available os services in a dynamic PD
    pub svc_num: u8,
    // Each dynamic PD has at most 16 os services available
    pub array: [OSSvc; 16],
}
impl Default for ProtoconSvcDatabase {
    fn default() -> Self {
        use std::array::from_fn;
        let svc_db = from_fn(|_| {
            let svc = OSSvc::default();
            svc
        });
        ProtoconSvcDatabase { pd_idx: 0, svc_num: 0, array: svc_db }
    }
}

/// MonitorSvcDatabase:
///  records the list of os services compilation of each dynamic PD
///  that belongs to one monitor PD
#[repr(C)]
pub struct MonitorSvcDatabase {
    // The number of available dynamic PD in a monitor PD
    pub num: usize,
    // Each monitor PD has at most 16 dynamic PD available
    pub list: [ProtoconSvcDatabase; 16],
}
impl Default for MonitorSvcDatabase {
    fn default() -> Self {
        use std::array::from_fn;
        let monitor_svc_db = from_fn(|i| {
            let mut protocon_svc_db = ProtoconSvcDatabase::default();
            protocon_svc_db.pd_idx = i as u8;
            protocon_svc_db
        });
        MonitorSvcDatabase { num: 0, list: monitor_svc_db }
    }
}


//
// Copyright 2025, UNSW
//
// SPDX-License-Identifier: BSD-2-Clause
//

use crate::{
    MAX_CHANNELS
};

/// Below are the data structures for recording the trusted loading information of each dynamic PD
pub const MAX_NAME: usize = 63;
pub const MAX_MAPPINGS: usize = MAX_CHANNELS;

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TSLDRMappingInfo {
    pub vaddr: u64,
    pub page: u64,
    pub page_num: u64,
    pub page_size: u64,
    pub rights: u64,
    pub attrs: u64,
}
impl Default for TSLDRMappingInfo {
    fn default() -> Self {
        TSLDRMappingInfo {
            vaddr: 0,
            page: 0,
            page_num: 0,
            page_size: 0,
            rights: 0,
            attrs: 0,
        }
    }
}

/// TSLDRMetadataInfo:
///  records the information of one child (dynamic) PD that is loaded by the monitor PD, including:
///  - the child PD index and system hash of the child PD
///  - the channels and irqs used by the child PD
///  - the memory mappings used by the child PD
///  - whether the child PD is initialised, which is used by the monitor to determine trusted loading states

#[repr(C)]
pub struct TSLDRMetadataInfo {
    pub child_id:   usize,
    pub system_hash: u64,
    pub channels:   [u8; MAX_CHANNELS],
    pub cstate:     [u8; MAX_CHANNELS],
    pub irqs:       [u64; MAX_CHANNELS],
    pub mappings:   [TSLDRMappingInfo; MAX_MAPPINGS],
    pub init:       u8,
}
impl Default for TSLDRMetadataInfo {
    fn default() -> Self {
        TSLDRMetadataInfo {
            child_id:   0,
            system_hash: 0,
            channels:   [0u8; MAX_CHANNELS],
            cstate:     [0u8; MAX_CHANNELS],
            irqs:       [0u64; MAX_CHANNELS],
            mappings:   [TSLDRMappingInfo::default(); MAX_MAPPINGS],
            init:       0
        }
    }
}

/// TSLDRMDInfoDB:
///  records the available child (dynamic) PDs information that is loaded by the monitor PD
///  that belongs to one monitor PD, whose limit for the child PDs equals 16
///  The monitor PD will use this information to determine the trusted loading states of each child PD
#[repr(C)]
pub struct TSLDRMDInfoDB {
    /// maximum is 16 per monitor
    pub avail_metadata_info: u8,
    /// maximum is 16 per monitor
    pub trusted_loading_metadata_info_database: [TSLDRMetadataInfo; 16],
}
impl Default for TSLDRMDInfoDB {
    fn default() -> Self {
        use std::array::from_fn;
        let trusted_loading_metadata_info_database = from_fn(|i| {
            let mut md = TSLDRMetadataInfo::default();
            md.child_id = i as usize;
            md
        });
        TSLDRMDInfoDB { avail_metadata_info: 0, trusted_loading_metadata_info_database }
    }
}


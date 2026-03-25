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

/// Below are the data structures for recording the OS services information of each dynamic PD,
/// which will be used by the monitor to determine the OS services compilation of each dynamic PD
/// and then load the corresponding data file for each dynamic PD.

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DataNameCStr {
    pub bytes: [u8; MAX_NAME + 1],
}
impl Default for DataNameCStr {
    #[inline]
    fn default() -> Self { Self { bytes: [0; MAX_NAME + 1] } }
}
impl DataNameCStr {
    #[inline]
    pub fn set_trunc(&mut self, s: &str) {
        let n = core::cmp::min(s.len(), MAX_NAME);
        self.bytes[..n].copy_from_slice(&s.as_bytes()[..n]);
        self.bytes[n] = 0;
        if n + 1 < self.bytes.len() {
            self.bytes[n + 1..].fill(0);
        }
    }
}

/// SvcMappingInfo:
///  records the information of one memory mapping used by one os service (svc), including:
///  - the virtual address of the mapping
///  - the number of pages and page size of the mapping
/// This is a stripped down version of TSLDRMappingInfo,
///     we use it to setup tsldr_context from OS service information

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SvcMappingInfo {
    pub vaddr: u64,
    pub page_num: u64,
    pub page_size: u64,
}
impl Default for SvcMappingInfo {
    fn default() -> Self {
        SvcMappingInfo {
            vaddr: 0,
            page_num: 0,
            page_size: 0,
        }
    }
}

/// OSSvc:
///  records the information of one os service (svc) that belongs to one dynamic PD, including:
///  - whether the os service is initialised
///  - the os service type and index
///  - the channels and irqs used by the os service
///  - the memory mappings used by the os service
///  - the data file name for the os service, which is used by the monitor to load the corresponding data file
//      for the os service based on the os service type and index

#[repr(C)]
#[derive(Copy, Clone)]
pub struct OSSvc {
    pub svc_init:   bool,
    pub svc_idx:    u8,
    pub svc_type:   u8,
    pub channels:   [u8; 4],
    pub irqs:       [u8; 4],
    pub mappings:   [SvcMappingInfo; 4],
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
            mappings:   [SvcMappingInfo::default(); 4],
            data_name:  DataNameCStr::default(),
        }
    }
}

/// ProtoconSvcDatabase:
///  records the available os services (svc) that belongs to
///  one dynamic PD, whose limit for the svcs equals 16
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


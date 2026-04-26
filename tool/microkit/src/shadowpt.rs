use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::path::{Path, PathBuf};

use crate::elf::ElfFile;
use crate::sdf::{CpuCore, ProtectionDomain, SystemDescription, SysMemoryRegion};
use crate::sel4::{Arch, Config, PageSize};

const SYMBOL_IPC_BUFFER: &str = "__sel4_ipc_buffer_obj";

#[derive(Debug, Clone)]
pub struct ShadowPageTable {
    pub name: String,
    pub pd_names: Vec<String>,
    pub cpus: Vec<CpuCore>,
    pub program_image: PathBuf,

    pub root: ShadowObjectId,
    pub objects: BTreeMap<ShadowObjectId, ShadowObject>,

    /// Total bytes required by page table structures only.
    pub total_page_table_bytes: u64,

    next_object_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowObject {
    pub id: ShadowObjectId,
    pub kind: ShadowObjectKind,
    pub phys: Option<ShadowPhys>,
    pub parent: Option<ShadowObjectId>,
    pub parent_slot: Option<usize>,
    pub children: BTreeMap<usize, ShadowObjectId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShadowObjectKind {
    PageTable {
        level: usize,
        is_root: bool,
        coverage: Range<u64>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShadowObjectId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShadowPhys {
    pub paddr: u64,
    pub size_bytes: u64,
}

fn shadow_top_pt_level_number(sel4_config: &Config) -> usize {
    if sel4_config.arch == Arch::Aarch64 && sel4_config.aarch64_vspace_s2_start_l1() {
        1
    } else {
        0
    }
}

fn shadow_get_pt_level_index(sel4_config: &Config, level: usize, vaddr: u64) -> usize {
    let levels = sel4_config.num_page_table_levels();
    assert!(level < levels);

    let index_bits = |level: usize| -> u64 {
        if level == shadow_top_pt_level_number(sel4_config)
            && sel4_config.arch == Arch::Aarch64
            && sel4_config.aarch64_vspace_s2_start_l1()
        {
            10
        } else {
            9
        }
    };

    let page_bits = 12;
    let bits_from_higher_lvls: u64 = ((level + 1)..levels).map(index_bits).sum();
    let shift = page_bits + bits_from_higher_lvls;
    let width = index_bits(level);
    let mask = (1u64 << width) - 1;

    ((vaddr >> shift) & mask) as usize
}

fn shadow_get_pt_level_coverage(sel4_config: &Config, level: usize, vaddr: u64) -> Range<u64> {
    let levels = sel4_config.num_page_table_levels() as u64;
    let page_bits = 12;
    let bits_from_higher_lvls: u64 = (levels - (level as u64)) * 9;

    let coverage_bits = page_bits + bits_from_higher_lvls;

    let low = (vaddr >> coverage_bits) << coverage_bits;
    let high = vaddr | ((1 << coverage_bits) - 1);

    low..high
}

fn shadow_get_pt_level_to_insert(sel4_config: &Config, page_size_bytes: u64) -> usize {
    const SMALL_PAGE_BYTES: u64 = PageSize::Small as u64;
    const LARGE_PAGE_BYTES: u64 = PageSize::Large as u64;

    match page_size_bytes {
        SMALL_PAGE_BYTES => sel4_config.num_page_table_levels() - 1,
        LARGE_PAGE_BYTES => sel4_config.num_page_table_levels() - 2,
        _ => unreachable!(
            "internal bug: shadow_get_pt_level_to_insert(): unknown page_size_bytes: {page_size_bytes}"
        ),
    }
}

fn round_down(x: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    x & !(align - 1)
}

impl ShadowPageTable {
    pub fn new(sel4_config: &Config, pd_name: &str, root_vaddr_hint: u64) -> ShadowPageTable {
        let root_level = shadow_top_pt_level_number(sel4_config);
        let root_coverage = shadow_get_pt_level_coverage(sel4_config, root_level, root_vaddr_hint);
        let root_id = ShadowObjectId(0);

        let root_obj = ShadowObject {
            id: root_id,
            kind: ShadowObjectKind::PageTable {
                level: root_level,
                is_root: true,
                coverage: root_coverage,
            },
            phys: None,
            parent: None,
            parent_slot: None,
            children: BTreeMap::new(),
        };

        ShadowPageTable {
            name: pd_name.to_string(),
            pd_names: vec![pd_name.to_string()],
            cpus: vec![],
            program_image: PathBuf::new(),
            root: root_id,
            objects: BTreeMap::from([(root_id, root_obj)]),
            total_page_table_bytes: PageSize::Small as u64,
            next_object_id: 1,
        }
    }

    fn alloc_object_id(&mut self) -> ShadowObjectId {
        let id = ShadowObjectId(self.next_object_id);
        self.next_object_id += 1;
        id
    }

    fn allocate_and_insert_page_table_object(
        &mut self,
        level: usize,
        is_root: bool,
        coverage: Range<u64>,
        parent: Option<ShadowObjectId>,
        parent_slot: Option<usize>,
    ) -> ShadowObjectId {
        let id = self.alloc_object_id();

        let obj = ShadowObject {
            id,
            kind: ShadowObjectKind::PageTable {
                level,
                is_root,
                coverage,
            },
            phys: None,
            parent,
            parent_slot,
            children: BTreeMap::new(),
        };

        self.objects.insert(id, obj);
        self.total_page_table_bytes += PageSize::Small as u64;
        id
    }

    pub fn assign_object_paddr(
        &mut self,
        obj_id: ShadowObjectId,
        paddr: u64,
        size_bytes: u64,
    ) -> Result<(), String> {
        let obj = self
            .objects
            .get_mut(&obj_id)
            .ok_or_else(|| format!("unknown shadow object id {:?}", obj_id))?;

        if obj.phys.is_some() {
            return Err(format!(
                "shadow object {:?} already has physical memory assigned",
                obj_id
            ));
        }

        obj.phys = Some(ShadowPhys { paddr, size_bytes });
        Ok(())
    }
}

fn shadow_map_intermediary_level(
    shadow: &mut ShadowPageTable,
    sel4_config: &Config,
    cur_level_obj_id: ShadowObjectId,
    cur_level: usize,
    cur_level_slot: usize,
    vaddr: u64,
) -> Result<ShadowObjectId, String> {
    let existing_child = {
        let cur_obj = shadow
            .objects
            .get(&cur_level_obj_id)
            .ok_or_else(|| format!("unknown current shadow pt object {:?}", cur_level_obj_id))?;

        match &cur_obj.kind {
            ShadowObjectKind::PageTable { .. } => {}
        }

        cur_obj.children.get(&cur_level_slot).copied()
    };

    if let Some(child_id) = existing_child {
        return Ok(child_id);
    }

    let next_level = cur_level + 1;
    let next_level_coverage = shadow_get_pt_level_coverage(sel4_config, next_level, vaddr);
    let next_level_obj_id = shadow.allocate_and_insert_page_table_object(
        next_level,
        false,
        next_level_coverage,
        Some(cur_level_obj_id),
        Some(cur_level_slot),
    );

    let cur_obj = shadow.objects.get_mut(&cur_level_obj_id).unwrap();
    cur_obj.children.insert(cur_level_slot, next_level_obj_id);

    Ok(next_level_obj_id)
}

fn shadow_map_recursive(
    shadow: &mut ShadowPageTable,
    sel4_config: &Config,
    pt_obj_id: ShadowObjectId,
    cur_level: usize,
    page_size_bytes: u64,
    vaddr: u64,
) -> Result<ShadowObjectId, String> {
    if cur_level >= sel4_config.num_page_table_levels() {
        unreachable!("internal bug: shadow_map_recursive() recursed too far");
    }

    let target_level = shadow_get_pt_level_to_insert(sel4_config, page_size_bytes);

    if cur_level == target_level {
        return Ok(pt_obj_id);
    }

    let this_level_index = shadow_get_pt_level_index(sel4_config, cur_level, vaddr);

    let next_level_pt_obj_id = shadow_map_intermediary_level(
        shadow,
        sel4_config,
        pt_obj_id,
        cur_level,
        this_level_index,
        vaddr,
    )?;

    shadow_map_recursive(
        shadow,
        sel4_config,
        next_level_pt_obj_id,
        cur_level + 1,
        page_size_bytes,
        vaddr,
    )
}

pub fn shadow_map_page(
    shadow: &mut ShadowPageTable,
    sel4_config: &Config,
    page_size_bytes: u64,
    vaddr: u64,
) -> Result<ShadowObjectId, String> {
    let root_id = shadow.root;

    let root_level = match &shadow.objects.get(&root_id).unwrap().kind {
        ShadowObjectKind::PageTable { level, .. } => *level,
    };

    shadow_map_recursive(
        shadow,
        sel4_config,
        root_id,
        root_level,
        page_size_bytes,
        vaddr,
    )
}

pub fn emulate_elf_shadow_pagetable(
    sel4_config: &Config,
    pd_name: &str,
    elf: &ElfFile,
) -> Result<ShadowPageTable, String> {
    let root_vaddr_hint = elf
        .loadable_segments()
        .first()
        .map(|seg| seg.virt_addr)
        .unwrap_or(0);

    let mut shadow = ShadowPageTable::new(sel4_config, pd_name, root_vaddr_hint);

    for segment in elf.loadable_segments().iter() {
        if segment.data().is_empty() {
            continue;
        }

        let seg_base_vaddr = segment.virt_addr;
        let seg_mem_size: u64 = segment.mem_size();

        let page_size = PageSize::Small;
        let page_size_bytes = page_size as u64;

        let mut cur_vaddr = round_down(seg_base_vaddr, page_size_bytes);
        while cur_vaddr < seg_base_vaddr + seg_mem_size {
            shadow_map_page(&mut shadow, sel4_config, page_size_bytes, cur_vaddr).map_err(
                |reason| {
                    format!(
                        "emulate_elf_shadow_pagetable(): failed to materialise shadow pagetable for pd '{}' because: {}",
                        pd_name, reason
                    )
                },
            )?;

            cur_vaddr += page_size_bytes;
        }
    }

    Ok(shadow)
}

fn get_full_path(path: &Path, search_paths: &[PathBuf]) -> Option<PathBuf> {
    for search_path in search_paths {
        let full_path = search_path.join(path);
        if full_path.exists() {
            return Some(full_path);
        }
    }

    None
}

pub fn build_shared_shadow_pagetables(
    system: &SystemDescription,
    sel4_config: &Config,
    search_paths: &[PathBuf],
) -> Result<Vec<ShadowPageTable>, String> {
    let mut shadows = Vec::new();

    for pagetable in &system.pagetables {
        let users: Vec<&ProtectionDomain> = system
            .protection_domains
            .values()
            .filter(|pd| pd.pagetable.as_deref() == Some(pagetable.name.as_str()))
            .collect();

        if users.is_empty() {
            continue;
        }

        let first_pd = users[0];

        let elf_path = get_full_path(&first_pd.program_image, search_paths).ok_or_else(|| {
            format!(
                "unable to find program image '{}' for pagetable '{}'",
                first_pd.program_image.display(),
                pagetable.name
            )
        })?;

        let elf = ElfFile::from_path(&elf_path)?;

        let mut shadow =
            emulate_elf_shadow_pagetable(sel4_config, &pagetable.name, &elf).map_err(|e| {
                format!(
                    "failed to emulate shadow pagetable '{}' from ELF '{}': {}",
                    pagetable.name,
                    elf_path.display(),
                    e
                )
            })?;

        shadow.name = pagetable.name.clone();
        shadow.pd_names = users.iter().map(|pd| pd.name.clone()).collect();
        shadow.cpus = users
            .iter()
            .map(|pd| pd.cpu)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        shadow.program_image = elf_path;

        shadows.push(shadow);
    }

    Ok(shadows)
}

fn populate_shadow_pagetable_with_mr_mappings(
    shadow: &mut ShadowPageTable,
    system: &SystemDescription,
    sel4_config: &Config,
) -> Result<(), String> {
    let mr_by_name: BTreeMap<&str, &SysMemoryRegion> = system
        .memory_regions
        .iter()
        .map(|mr| (mr.name.as_str(), mr))
        .collect();

    let pd_names = shadow.pd_names.clone();

    for pd_name in &pd_names {
        let pd = system
            .protection_domains
            .get(pd_name)
            .ok_or_else(|| {
                format!(
                    "populate_shadow_pagetable_with_mr_mappings(): shadow pagetable '{}' refers to unknown protection domain '{}'",
                    shadow.name, pd_name
                )
            })?;

        for map in &pd.maps {
            let mr = mr_by_name.get(map.mr.as_str()).ok_or_else(|| {
                format!(
                    "populate_shadow_pagetable_with_mr_mappings(): protection domain '{}' maps unknown memory region '{}'",
                    pd.name, map.mr
                )
            })?;

            let page_size_bytes = mr.page_size_bytes();

            for frame_sequence in 0..mr.page_count {
                let vaddr = map.vaddr + (frame_sequence * page_size_bytes);

                shadow_map_page(shadow, sel4_config, page_size_bytes, vaddr).map_err(|reason| {
                    format!(
                        "populate_shadow_pagetable_with_mr_mappings(): failed to map memory region '{}' into shadow pagetable '{}' for protection domain '{}' at vaddr {:#x}: {}",
                        mr.name, shadow.name, pd.name, vaddr, reason
                    )
                })?;
            }
        }
    }

    Ok(())
}

pub fn populate_shared_shadow_pagetables_with_mrs(
    shadow_pagetables: &mut [ShadowPageTable],
    system: &SystemDescription,
    sel4_config: &Config,
) -> Result<(), String> {
    for shadow in shadow_pagetables.iter_mut() {
        populate_shadow_pagetable_with_mr_mappings(shadow, system, sel4_config)?;
    }

    Ok(())
}

fn round_up(x: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (x + align - 1) & !(align - 1)
}

fn populate_shadow_pagetable_with_stack_and_ipc_buffers(
    shadow: &mut ShadowPageTable,
    system: &SystemDescription,
    sel4_config: &Config,
) -> Result<(), String> {

    let elf = ElfFile::from_path(&shadow.program_image).map_err(|e| {
        format!(
            "populate_shadow_pagetable_with_stack_and_ipc_buffers(): failed to open ELF '{}' for shadow pagetable '{}': {}",
            shadow.program_image.display(),
            shadow.name,
            e
        )
    })?;

    let ipcbuf_base_vaddr = elf
        .find_symbol(SYMBOL_IPC_BUFFER)
        .map_err(|e| {
            format!(
                "populate_shadow_pagetable_with_stack_and_ipc_buffers(): failed to find symbol '{}' in ELF '{}' for shadow pagetable '{}': {}",
                SYMBOL_IPC_BUFFER,
                shadow.program_image.display(),
                shadow.name,
                e
            )
        })?
        .0;

    let page_size_bytes = PageSize::Small as u64;

    let mut pd_names = shadow.pd_names.clone();
    pd_names.sort();

    let mut next_ipcbuf_vaddr = ipcbuf_base_vaddr;
    let mut next_stack_top = sel4_config.user_top();

    for pd_name in &pd_names {
        let pd = system.protection_domains.get(pd_name).ok_or_else(|| {
            format!(
                "populate_shadow_pagetable_with_stack_and_ipc_buffers(): shadow pagetable '{}' refers to unknown protection domain '{}'",
                shadow.name, pd_name
            )
        })?;
        // 1. Populate one IPC buffer page for this PD.
        shadow_map_page(shadow, sel4_config, page_size_bytes, next_ipcbuf_vaddr).map_err(
            |reason| {
                format!(
                    "populate_shadow_pagetable_with_stack_and_ipc_buffers(): failed to map ipc_buffer for PD '{}' into shadow pagetable '{}' at vaddr {:#x}: {}",
                    pd.name, shadow.name, next_ipcbuf_vaddr, reason
                )
            },
        )?;

        next_ipcbuf_vaddr = next_ipcbuf_vaddr
            .checked_add(page_size_bytes)
            .ok_or_else(|| {
                format!(
                    "populate_shadow_pagetable_with_stack_and_ipc_buffers(): ipc_buffer virtual address overflow for shadow pagetable '{}'",
                    shadow.name
                )
            })?;

        // 2. Populate this PD's stack pages.
        let stack_size_rounded = round_up(pd.stack_size, page_size_bytes);
        let stack_bottom = next_stack_top
            .checked_sub(stack_size_rounded)
            .ok_or_else(|| {
                format!(
                    "populate_shadow_pagetable_with_stack_and_ipc_buffers(): stack allocation underflow for PD '{}' in shadow pagetable '{}'",
                    pd.name, shadow.name
                )
            })?;

        let mut cur_vaddr = stack_bottom;
        while cur_vaddr < next_stack_top {
            shadow_map_page(shadow, sel4_config, page_size_bytes, cur_vaddr).map_err(
                |reason| {
                    format!(
                        "populate_shadow_pagetable_with_stack_and_ipc_buffers(): failed to map stack for PD '{}' into shadow pagetable '{}' at vaddr {:#x}: {}",
                        pd.name, shadow.name, cur_vaddr, reason
                    )
                },
            )?;

            cur_vaddr += page_size_bytes;
        }

        next_stack_top = stack_bottom;
    }

    Ok(())
}

pub fn populate_shared_shadow_pagetables_with_stack_and_ipc_buffers(
    shadow_pagetables: &mut [ShadowPageTable],
    system: &SystemDescription,
    sel4_config: &Config,
) -> Result<(), String> {
    for shadow in shadow_pagetables.iter_mut() {
        populate_shadow_pagetable_with_stack_and_ipc_buffers(
            shadow,
            system,
            sel4_config,
        )?;
    }

    Ok(())
}

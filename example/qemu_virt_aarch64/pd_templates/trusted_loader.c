/*
 * Copyright 2021, Breakaway Consulting Pty. Ltd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdint.h>
#include <microkit.h>
#include <stdarg.h>
#include "elf_utils.h"
#include "elf.h"
#include <stdbool.h>

// - increase size of cnode just for trusted loader
// - or create separate cnode
/* both child caps are only valid when the PD is a template (they refer to the child PD) */
#define CHILD_ID 1
#define CHILD_CSPACE_CAP 8
#define CHILD_VSPACE_CAP 9
#define CHILD_BASE_OUTPUT_NOTIFICATION_CAP 394
#define CHILD_BASE_IRQ_CAP 458
#define CHILD_BASE_MAPPING_CAP 522
#define PD_TEMPLATE_CNODE_ROOT 586

#define PD_CAP_BITS 10
#define PROGNAME "[trusted_loader] "

#define MAX_ACCESS_RIGHTS 100

typedef enum {
    ACCESS_TYPE_CHANNEL = 0x01,
    ACCESS_TYPE_IRQ     = 0x02,
    ACCESS_TYPE_MEMORY  = 0x03
} AccessType;

// Structure to hold each access right entry
typedef struct {
    AccessType type;
    seL4_Word data; // For CHANNEL and IRQ: ID; For MEMORY: VADDR
} AccessRightEntry;

// Structure to hold all access rights
typedef struct {
    seL4_Word system_hash;
    seL4_Word num_entries;
    AccessRightEntry entries[MAX_ACCESS_RIGHTS];
} AccessRights;

typedef struct {
    seL4_Word vaddr;
    seL4_Word page;
    seL4_Word number_of_pages;
    seL4_Word page_size;
    seL4_Word rights;
    seL4_Word attrs;
} OptionalMapping;

// Global variable to store access rights
AccessRights access_rights;

// Global lists to track allowed channels, IRQs, and memory mappings
bool allowed_channels[MICROKIT_MAX_CHANNELS] = {false};
bool allowed_irqs[MICROKIT_MAX_CHANNELS] = {false};
OptionalMapping allowed_mappings[MICROKIT_MAX_CHANNELS];
int num_allowed_mappings = 0;

// Contents of receiver.elf
extern char _receiver[];
extern char _receiver_end[];

// Contents of sender.elf
extern char _sender[];
extern char _sender_end[];

uintptr_t user_program;
seL4_Word system_hash;

seL4_Word channels[MICROKIT_MAX_CHANNELS];
seL4_Word irqs[MICROKIT_MAX_CHANNELS];
// In reality, there could be an unlimited number of memory mappings,
// but for now, we just limit to the maximum number of channels.
OptionalMapping mappings[MICROKIT_MAX_CHANNELS];

void reset(void);

OptionalMapping* find_mapping_by_vaddr(seL4_Word vaddr) {
    for (int i = 0; i < MICROKIT_MAX_CHANNELS; i++) {
        if (mappings[i].vaddr == vaddr) {
            return &mappings[i];
        }
    }
    return 0;
}

// Validate ELF header and return 1 if valid, 0 if invalid
int validate_elf_header(Elf64_Ehdr *ehdr, seL4_Word elf_size) {
    if (elf_size < sizeof(Elf64_Ehdr)) {
        debug_printf(PROGNAME "Invalid ELF size\n");
        return 0;
    }

    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 || 
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 || 
        ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        debug_printf(PROGNAME "Invalid ELF magic\n");
        return 0;
    }

    debug_printf(PROGNAME "Verified ELF header\n");
    return 1;
}

// Helper to find memory protection for a segment
seL4_Word find_symbol(const char *symbol_name, Elf64_Ehdr *ehdr) {
    Elf64_Shdr *shdr = (Elf64_Shdr *)((char*)ehdr + ehdr->e_shoff);
    Elf64_Sym *symtab = 0;
    const char *strtab = 0;
    seL4_Word sym_count = 0;

    // Locate the symbol and string tables
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_SYMTAB) {
            symtab = (Elf64_Sym *)((char*)ehdr + shdr[i].sh_offset);
            sym_count = shdr[i].sh_size / sizeof(Elf64_Sym);
        } else if (shdr[i].sh_type == SHT_STRTAB && ehdr->e_shstrndx != i) {
            strtab = (char*)ehdr + shdr[i].sh_offset;
        }
    }

    // Check if symbol or string table is missing
    if (!symtab || !strtab) {
        debug_printf(PROGNAME "Symbol or string table not found\n");
        return 0;
    }

    // Search for the symbol in the symbol table
    for (seL4_Word i = 0; i < sym_count; i++) {
        const char *name = strtab + symtab[i].st_name;
        if (custom_strcmp(name, symbol_name) == 0) {
            debug_printf(PROGNAME "Found symbol: %s\n", name);
            return symtab[i].st_value;
        }
    }

    debug_printf(PROGNAME "Symbol not found\n");
    return 0;
}

void load_elf_segments(Elf64_Ehdr *ehdr) {
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char*)ehdr + ehdr->e_phoff);

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            void *src = (char*)ehdr + phdr[i].p_offset;
            void *dest = (void *)(user_program + phdr[i].p_vaddr - 0x200000);

            /*
            debug_printf(PROGNAME "Segment index: %d\n", (seL4_Word)i);
            debug_printf(PROGNAME "p_vaddr: 0x%x\n", (seL4_Word)phdr[i].p_vaddr);
            debug_printf(PROGNAME "user_program: 0x%x\n", (seL4_Word)user_program);
            debug_printf(PROGNAME "dest: 0x%x\n", (seL4_Word)dest);
            debug_printf(PROGNAME "src: 0x%x\n", (seL4_Word)src);
            debug_printf(PROGNAME "phdr[i].p_filesz: %d\n", (seL4_Word)phdr[i].p_filesz);
            */

            custom_memcpy(dest, src, phdr[i].p_filesz);

            if (phdr[i].p_memsz > phdr[i].p_filesz) {
                seL4_Word bss_size = phdr[i].p_memsz - phdr[i].p_filesz;
                custom_memset((char *)dest + phdr[i].p_filesz, 0, bss_size);
            }
        }
    }
}

void init(void)
{
    debug_printf(PROGNAME "Entered init\n");
    debug_printf(PROGNAME "System hash: 0x%x\n", system_hash);

    char *elf_start, *elf_end;
    
    // Could also just strcmp microkit_name
    if (user_program == 0x400000) {
        elf_start = _receiver;
        elf_end = _receiver_end;
        debug_printf(PROGNAME "Loading receiver program\n");
    } else if (user_program == 0x600000) {
        elf_start = _sender;
        elf_end = _sender_end;
        debug_printf(PROGNAME "Loading sender program\n");
    } else {
        debug_printf(PROGNAME "Couldn't determine what program to load\n");
        return;
    }

    seL4_Word elf_size = (seL4_Word)(elf_end - elf_start); // Corrected subtraction
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_start;

    if (!validate_elf_header(ehdr, elf_size)) {
        return;
    }

    // Locate and parse the .access_rights section
    AccessRights *rights = &access_rights;
    rights->num_entries = 0;
    rights->system_hash = 0;

    // Locate the section header string table
    Elf64_Shdr *shdr = (Elf64_Shdr *)((char*)ehdr + ehdr->e_shoff);
    const char *shstrtab = (char*)ehdr + shdr[ehdr->e_shstrndx].sh_offset;

    // Locate the .access_rights section
    char *access_rights_section = 0;
    seL4_Word access_rights_size = 0;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *section_name = shstrtab + shdr[i].sh_name;
        if (custom_strcmp(section_name, ".access_rights") == 0) {
            access_rights_section = (char*)ehdr + shdr[i].sh_offset;
            access_rights_size = shdr[i].sh_size;
            break;
        }
    }

    if (!access_rights_section) {
        debug_printf(PROGNAME "Access rights section not found in ELF\n");
        return;
    }

    // Ensure the section has at least system_hash and num_entries
    if (access_rights_size < 12) {
        debug_printf(PROGNAME "Access rights section too small\n");
        return;
    }

    // Parse system_hash
    rights->system_hash = *((seL4_Word*)access_rights_section);
    if (rights->system_hash != system_hash) {
        debug_printf(PROGNAME "System hash mismatch, Microkit tool hash 0x%x does not equal ELF access rights hash 0x%x\n", system_hash, rights->system_hash);
        return;
    }

    uint32_t num_access_rights = *((uint32_t*)(access_rights_section + 8));

    if (access_rights_size < 12 + num_access_rights * 9) {
        debug_printf(PROGNAME "Access rights section size mismatch\n");
        return;
    }

    // Parse each access right entry
    for (uint32_t i = 0; i < num_access_rights && i < MAX_ACCESS_RIGHTS; i++) {
        uint8_t type = *(uint8_t*)(access_rights_section + 12 + i * 9);
        seL4_Word data = *((seL4_Word*)(access_rights_section + 12 + i * 9 + 1));
        rights->entries[rights->num_entries].type = (AccessType)type;
        rights->entries[rights->num_entries].data = data;
        rights->num_entries++;
    }

    debug_printf(PROGNAME "Number of access rights: %d\n", rights->num_entries);

     // Process access rights to build allowed lists
    for (seL4_Word i = 0; i < rights->num_entries; i++) {
        AccessRightEntry *entry = &rights->entries[i];
        switch (entry->type) {
            case ACCESS_TYPE_CHANNEL:
                if (entry->data < MICROKIT_MAX_CHANNELS) {
                    allowed_channels[entry->data] = true;
                    debug_printf(PROGNAME "Allowed channel ID: %d\n", entry->data);
                } else {
                    debug_printf(PROGNAME "Invalid channel ID: %d\n", entry->data);
                }
                break;
            case ACCESS_TYPE_IRQ:
                if (entry->data < MICROKIT_MAX_CHANNELS) {
                    allowed_irqs[entry->data] = true;
                    debug_printf(PROGNAME "Allowed IRQ ID: %d\n", entry->data);
                } else {
                    debug_printf(PROGNAME "Invalid IRQ ID: %d\n", entry->data);
                }
                break;
            case ACCESS_TYPE_MEMORY:
                if (num_allowed_mappings < MICROKIT_MAX_CHANNELS) {
                    seL4_Word vaddr = entry->data;
                    OptionalMapping *mapping = find_mapping_by_vaddr(vaddr);
                    if (mapping) {
                        allowed_mappings[num_allowed_mappings++] = *mapping;
                        debug_printf(PROGNAME "Allowed memory vaddr: 0x%x\n", vaddr);
                    } else {
                        debug_printf(PROGNAME "Mapping not found for vaddr: 0x%x\n", vaddr);
                    }
                } else {
                    debug_printf(PROGNAME "Exceeded maximum allowed mappings\n");
                }
                break;
            default:
                debug_printf(PROGNAME "Unknown access type: %d\n", entry->type);
        }
    }

    debug_printf(PROGNAME "Channels allowed: ");
    for (int i = 0; i < MICROKIT_MAX_CHANNELS; i++) {
        if (allowed_channels[i]) debug_printf("%d ", i);
    }
    debug_printf("\n");

    debug_printf(PROGNAME "IRQs allowed: ");
    for (int i = 0; i < MICROKIT_MAX_CHANNELS; i++) {
        if (allowed_irqs[i]) debug_printf("%d ", i);
    }
    debug_printf("\n");

    debug_printf(PROGNAME "Memory mappings allowed: %d\n", num_allowed_mappings);

    // Delete channels that are not allowed
    for (int channel_id = 0; channel_id < MICROKIT_MAX_CHANNELS; channel_id++) {
        if (channels[channel_id] && !allowed_channels[channel_id]) {
            seL4_Error error = seL4_CNode_Delete(CHILD_CSPACE_CAP, CHILD_BASE_OUTPUT_NOTIFICATION_CAP + channel_id, PD_CAP_BITS);
            debug_printf(PROGNAME "Deleted child PD's output notification cap: channel_id=%d error=%d\n", channel_id, error);
        }
    }

    // Delete IRQs that are not allowed
    for (int irq_id = 0; irq_id < MICROKIT_MAX_CHANNELS; irq_id++) {
        if (irqs[irq_id] && !allowed_irqs[irq_id]) {
            seL4_Error error = seL4_CNode_Delete(CHILD_CSPACE_CAP, CHILD_BASE_IRQ_CAP + irq_id, PD_CAP_BITS);
            debug_printf(PROGNAME "Deleted child PD's IRQ cap: irq_id=%d error=%d\n", irq_id, error);
        }
    }

    // Unmap memory regions that are not allowed
    for (int mapping_idx = 0; mapping_idx < MICROKIT_MAX_CHANNELS; mapping_idx++) {
        bool is_allowed = false;
        for (int j = 0; j < num_allowed_mappings; j++) {
            if (mappings[mapping_idx].vaddr == allowed_mappings[j].vaddr) {
                is_allowed = true;
                break;
            }
        }
        if (!is_allowed && mappings[mapping_idx].number_of_pages > 0) {
            // Unmap this memory region
            for (int slot = 0; slot < mappings[mapping_idx].number_of_pages; slot++) {
                seL4_CNode page = mappings[mapping_idx].page + slot;
                seL4_Error error = seL4_ARM_Page_Unmap(page);
                debug_printf(PROGNAME "Unmapped memory: page=0x%x error=%d\n", page, error);
            }
        }
    }

    // Map only the allowed memory regions
    for (int mapping_idx = 0; mapping_idx < num_allowed_mappings; mapping_idx++) {
        OptionalMapping mapping = allowed_mappings[mapping_idx];
        debug_printf(
            PROGNAME "Mapping allowed memory: vaddr=0x%x\n",
            mapping.vaddr
        );

        seL4_CapRights_t rights;
        rights.words[0] = mapping.rights;

        seL4_Error error = seL4_ARM_Page_Map(
            mapping.page,
            CHILD_VSPACE_CAP,
            mapping.vaddr,
            rights,
            mapping.attrs
        );

        if (error != seL4_NoError) {
            debug_printf(PROGNAME "Failed to map memory: vaddr=0x%x error=%d\n", mapping.vaddr, error);
        } else {
            debug_printf(PROGNAME "Mapped allowed memory: page=0x%x vaddr=0x%x\n", mapping.page, mapping.vaddr);
        }
    }


    // print_elf(elf_start, elf_end);

    load_elf_segments(ehdr);
    debug_printf(PROGNAME "Copied program to child PD's memory region\n");

    microkit_pd_restart(CHILD_ID, ehdr->e_entry);
    debug_printf(
        PROGNAME "Started child PD at entrypoint address: 0x%x\n",
        ehdr->e_entry
    );

    debug_printf(PROGNAME "Finished init\n");
}

void reset(void)
{
    debug_printf(PROGNAME "Entered reset\n");

    AccessRights *rights = &access_rights;

    // Restore allowed channels
    for (seL4_Word i = 0; i < rights->num_entries; i++) {
        if (rights->entries[i].type == ACCESS_TYPE_CHANNEL) {
            seL4_Word channel_id = rights->entries[i].data;
            if (channel_id < MICROKIT_MAX_CHANNELS && !allowed_channels[channel_id]) {
                // Remint the channel cap
                seL4_Error error = seL4_CNode_Copy(
                    CHILD_CSPACE_CAP,
                    CHILD_BASE_OUTPUT_NOTIFICATION_CAP + channel_id,
                    PD_CAP_BITS,
                    PD_TEMPLATE_CNODE_ROOT,
                    CHILD_BASE_OUTPUT_NOTIFICATION_CAP + channel_id,
                    PD_CAP_BITS,
                    seL4_AllRights
                );
                debug_printf(PROGNAME "Reminted child PD's output notification cap: channel_id=%llu error=%d\n", channel_id, error);
            }
        }
    }

    // Restore allowed IRQs
    for (seL4_Word i = 0; i < rights->num_entries; i++) {
        if (rights->entries[i].type == ACCESS_TYPE_IRQ) {
            seL4_Word irq_id = rights->entries[i].data;
            if (irq_id < MICROKIT_MAX_CHANNELS && !allowed_irqs[irq_id]) {
                // Remint the IRQ cap
                seL4_Error error = seL4_CNode_Copy(
                    CHILD_CSPACE_CAP,
                    CHILD_BASE_IRQ_CAP + irq_id,
                    PD_CAP_BITS,
                    PD_TEMPLATE_CNODE_ROOT,
                    CHILD_BASE_IRQ_CAP + irq_id,
                    PD_CAP_BITS,
                    seL4_AllRights
                );
                debug_printf(PROGNAME "Reminted child PD's IRQ cap: irq_id=%llu error=%d\n", irq_id, error);
            }
        }
    }

    // Restore allowed memory mappings
    for (int mapping_idx = 0; mapping_idx < num_allowed_mappings; mapping_idx++) {
        OptionalMapping mapping = allowed_mappings[mapping_idx];
        debug_printf(
            PROGNAME "Restoring mapping: vaddr=0x%llx\n",
            mapping.vaddr
        );

        seL4_CapRights_t rights;
        rights.words[0] = mapping.rights;

        seL4_Error error = seL4_ARM_Page_Map(
            mapping.page,
            CHILD_VSPACE_CAP,
            mapping.vaddr,
            rights,
            mapping.attrs
        );

        if (error != seL4_NoError) {
            debug_printf(PROGNAME "Failed to restore mapping: vaddr=0x%llx error=%d\n", mapping.vaddr, error);
        } else {
            debug_printf(PROGNAME "Restored mapping: page=0x%x vaddr=0x%llx\n", mapping.page, mapping.vaddr);
        }
    }

    debug_printf(PROGNAME "Finished reset\n");
}

void notified(microkit_channel ch)
{
    debug_printf(PROGNAME "Received notification on channel: %d\n", ch);
}

seL4_MessageInfo_t protected(microkit_channel ch, microkit_msginfo msginfo)
{
    debug_printf(PROGNAME "Received protected message on channel: %d\n", ch);

    return microkit_msginfo_new(0, 0);
}

seL4_Bool fault(microkit_child child, microkit_msginfo msginfo, microkit_msginfo *reply_msginfo)
{
    debug_printf(PROGNAME "Received fault message for child PD: %d\n", child);
    
    seL4_Word label = microkit_msginfo_get_label(msginfo);
    debug_printf(PROGNAME "Fault label: %d\n", label);

    if (label == seL4_Fault_VMFault) {
        seL4_Word ip = microkit_mr_get(seL4_VMFault_IP);
        seL4_Word address = microkit_mr_get(seL4_VMFault_Addr);
        debug_printf(PROGNAME "Fault address: 0x%x\n", address);
        debug_printf(PROGNAME "Fault instruction pointer: 0x%x\n", ip);
    }

    microkit_pd_stop(child);
    
    /* We explicitly restart the thread so we do not need to 'reply' to the fault. */
    return seL4_False;
}

/*
 * Trusted loader for loading ELF binaries into child PDs.
 *
 * Copyright 2024, UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

#include <microkit.h>

#include "ed25519.h"
#include "elf.h"
#include "elf_utils.h"

#define PROGNAME "[trusted_loader] "

// Child PD caps
#define CHILD_ID                            1
#define CHILD_CSPACE_CAP                    8
#define CHILD_VSPACE_CAP                    9
#define CHILD_BASE_OUTPUT_NOTIFICATION_CAP  394
#define CHILD_BASE_IRQ_CAP                  458
#define CHILD_BASE_MAPPING_CAP              522
#define PD_TEMPLATE_CNODE_ROOT              586

#define PD_CAP_BITS                         10
#define ED25519_PUBLIC_KEY_BYTES            32
#define ED25519_SIGNATURE_BYTES             64
#define MAX_ACCESS_RIGHTS                   MICROKIT_MAX_CHANNELS * 3
#define MAX_MAPPINGS                        MICROKIT_MAX_CHANNELS

// Maximum size calculations
#define SYSTEM_HASH_SIZE                    sizeof(seL4_Word)
#define NUM_ENTRIES_SIZE                    sizeof(uint32_t)
#define ACCESS_RIGHT_ENTRY_SIZE             9 // 1 byte for type + 8 bytes for data

// Access types
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
    uint32_t num_entries;
    AccessRightEntry entries[MAX_ACCESS_RIGHTS];
} AccessRights;

// Structure for memory mapping
typedef struct {
    seL4_Word vaddr;
    seL4_Word page;
    seL4_Word number_of_pages;
    seL4_Word page_size;
    seL4_Word rights;
    seL4_Word attrs;
} MemoryMapping;

// Public key for verifying signatures (256-bit for Ed25519)
// Initialize with zeros; should be patched externally with the actual public key
unsigned char public_key[ED25519_PUBLIC_KEY_BYTES];

// Global variables (patched externally)
seL4_Word channels[MICROKIT_MAX_CHANNELS];
seL4_Word irqs[MICROKIT_MAX_CHANNELS];
MemoryMapping mappings[MAX_MAPPINGS];
uintptr_t user_program;
uintptr_t client_program;
uintptr_t shared1;
uintptr_t shared2;
seL4_Word system_hash;

#define TSLDR_MD_SIZE 0x1000
typedef struct {
    seL4_Word system_hash;
    unsigned char public_key[ED25519_PUBLIC_KEY_BYTES];
    seL4_Word channels[MICROKIT_MAX_CHANNELS];
    seL4_Word irqs[MICROKIT_MAX_CHANNELS];
    MemoryMapping mappings[MICROKIT_MAX_CHANNELS];
    /* for recording ... */
    bool init;
    uint8_t padding[TSLDR_MD_SIZE
                    - ( sizeof(seL4_Word) 
                      + ED25519_PUBLIC_KEY_BYTES 
                      + sizeof(seL4_Word) * MICROKIT_MAX_CHANNELS 
                      + sizeof(seL4_Word) * MICROKIT_MAX_CHANNELS 
                      + sizeof(MemoryMapping) * MICROKIT_MAX_CHANNELS
                      + sizeof(bool) )];
} tsldr_md_t;

/* 4KB in size */
uintptr_t tsldr_metadata;

// Global variables
static AccessRights access_rights = {0};
static bool allowed_channels[MICROKIT_MAX_CHANNELS] = {false};
static bool allowed_irqs[MICROKIT_MAX_CHANNELS] = {false};
static MemoryMapping allowed_mappings[MAX_MAPPINGS] = {0};
static int num_allowed_mappings = 0;
static bool removed_caps = false;

// Function prototypes
static seL4_Error populate_rights(AccessRights *rights, const unsigned char *verified_data, size_t verified_data_len);
static seL4_Error populate_allowed(const AccessRights *rights);
static void load_elf(void *dest_vaddr, const Elf64_Ehdr *ehdr);
static MemoryMapping* find_mapping_by_vaddr(seL4_Word vaddr);
static void remove_caps();
static void restore_caps();

void init(void)
{
    microkit_dbg_printf(PROGNAME "Entered init\n");
    microkit_dbg_printf(PROGNAME "System hash: 0x%x\n", (unsigned long long)system_hash);
    microkit_dbg_printf(PROGNAME "Finished init\n");
}

void notified(microkit_channel ch)
{
    microkit_dbg_printf(PROGNAME "Received notification on channel: %d\n", ch);
}

seL4_MessageInfo_t protected(microkit_channel ch, microkit_msginfo msginfo)
{
    microkit_dbg_printf(PROGNAME "Received protected message on channel: %d\n", ch);
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)shared1;

    if (custom_memcmp(ehdr->e_ident, (const unsigned char*)ELFMAG, SELFMAG) != 0) {
        microkit_dbg_printf(PROGNAME "Data in shared memory region must be an ELF file\n");
        return microkit_msginfo_new(seL4_InvalidArgument, 0);
    }

    microkit_dbg_printf(PROGNAME "Verified ELF header\n");

    // Locate the .access_rights section
    Elf64_Shdr *shdr = (Elf64_Shdr *)((char*)ehdr + ehdr->e_shoff);
    const char *shstrtab = (char*)ehdr + shdr[ehdr->e_shstrndx].sh_offset;

    char *section = NULL;
    seL4_Word section_size = 0;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *section_name = shstrtab + shdr[i].sh_name;
        if (custom_strcmp(section_name, ".access_rights") == 0) {
            section = (char*)ehdr + shdr[i].sh_offset;
            section_size = shdr[i].sh_size;
            break;
        }
    }

    if (section == NULL) {
        microkit_dbg_printf(PROGNAME ".access_rights section not found in ELF\n");
        return microkit_msginfo_new(seL4_InvalidArgument, 0);
    }

    seL4_Error error;

    /* initialise trusted loader metadata */
    tsldr_md_t *md = (tsldr_md_t *)tsldr_metadata;
    if (!md->init) {
        md->system_hash = system_hash;
        custom_memcpy(md->public_key, public_key, sizeof(md->public_key));
        custom_memcpy(md->channels,   channels,   sizeof(md->channels));
        custom_memcpy(md->irqs,       irqs,       sizeof(md->irqs));
        custom_memcpy(md->mappings,   mappings,   sizeof(md->mappings));
        md->init = true;
    }

    // Verify the signature (only the relevant part of the section)
    error = populate_rights(
        &access_rights,                   // Pointer to AccessRights structure
        (unsigned char*)section,          // Pointer to signature || data
        section_size                      // Length of signed message
    );
    if (error != seL4_NoError) {
        return microkit_msginfo_new(error, 0);
    }

    // Restore deleted caps if a program has previously been loaded
    // Must be done before allowed lists are populated
    if (removed_caps) {
        restore_caps();
    }

    error = populate_allowed(&access_rights);
    if (error != seL4_NoError) {
        return microkit_msginfo_new(error, 0);
    }

    remove_caps();
    removed_caps = true;

    load_elf((void*)user_program, ehdr);
    microkit_dbg_printf(PROGNAME "Copied program to child PD's memory region\n");

    custom_memcpy((void*)client_program, (char *)shared2, 0x800000);
    microkit_dbg_printf(PROGNAME "Copied client program to child PD's memory region\n");

    // Restart the child PD at the entry point
    microkit_pd_restart(CHILD_ID, ehdr->e_entry);
    microkit_dbg_printf(PROGNAME "Started child PD at entrypoint address: 0x%x\n", (unsigned long long)ehdr->e_entry);
    return microkit_msginfo_new(seL4_NoError, 0);
}

seL4_Bool fault(microkit_child child, microkit_msginfo msginfo, microkit_msginfo *reply_msginfo)
{
    microkit_dbg_printf(PROGNAME "Received fault message for child PD: %d\n", child);

    seL4_Word label = microkit_msginfo_get_label(msginfo);
    microkit_dbg_printf(PROGNAME "Fault label: %d\n", label);

    if (label == seL4_Fault_VMFault) {
        seL4_Word ip = microkit_mr_get(seL4_VMFault_IP);
        seL4_Word address = microkit_mr_get(seL4_VMFault_Addr);
        microkit_dbg_printf(PROGNAME "seL4_Fault_VMFault\n");
        microkit_dbg_printf(PROGNAME "Fault address: 0x%x\n", (unsigned long long)address);
        microkit_dbg_printf(PROGNAME "Fault instruction pointer: 0x%x\n", (unsigned long long)ip);
    }

    microkit_pd_stop(child);

    // Stop the thread explicitly; no need to reply to the fault
    return seL4_False;
}

/**
 * @brief Populates access rights and verifies the Ed25519 signature of the data.
 *
 * @param rights Pointer to the AccessRights structure to be populated.
 * @param signed_message Pointer to the signed message (signature || data).
 * @param signed_message_len Length of the signed message in bytes.
 * @return true if the signature is valid, false otherwise.
 */
static seL4_Error populate_rights(AccessRights* rights, const unsigned char *signed_message, size_t signed_message_len)
{
    custom_memset(&access_rights, 0, sizeof(AccessRights));

    // Calculate the minimum required size: signature + system_hash + num_access_rights
    size_t min_required_size = ED25519_SIGNATURE_BYTES + SYSTEM_HASH_SIZE + NUM_ENTRIES_SIZE;
    
    if (signed_message_len < min_required_size) {
        microkit_dbg_printf(PROGNAME "Signed message length (%d) is too short. Minimum required: %d bytes.\n",
                           signed_message_len, min_required_size);
        return seL4_InvalidArgument;
    }

    // Extract signature and data
    const unsigned char *signature = signed_message;
    const unsigned char *data = signed_message + ED25519_SIGNATURE_BYTES;

    // Parse system_hash and num_entries from the verified data
    custom_memcpy(&rights->system_hash, data, SYSTEM_HASH_SIZE);
    custom_memcpy(&rights->num_entries, data + SYSTEM_HASH_SIZE, NUM_ENTRIES_SIZE);

    microkit_dbg_printf(PROGNAME "System hash (from access rights section of ELF file): 0x%x\n", rights->system_hash);
    microkit_dbg_printf(PROGNAME "Number of access rights: %d\n", rights->num_entries);

    // Check if the number of access rights exceeds the maximum allowed
    if (rights->num_entries > MAX_ACCESS_RIGHTS) {
        microkit_dbg_printf(PROGNAME "Number of access rights (%d) exceeds maximum allowed (%d)\n", rights->num_entries, MAX_ACCESS_RIGHTS);
        return seL4_InvalidArgument;
    }

    // Verify system_hash matches
    if (rights->system_hash != system_hash) {
        microkit_dbg_printf(PROGNAME "System hash mismatch: expected 0x%x, found 0x%x\n",
                           (unsigned long)system_hash,
                           (unsigned long)rights->system_hash);
        return seL4_InvalidArgument;
    }

    microkit_dbg_printf(PROGNAME "Extracted system hash and trusted loader's system hash matched successfully\n");

    // Calculate the expected total size based on the number of access rights
    size_t data_size = SYSTEM_HASH_SIZE + NUM_ENTRIES_SIZE + (rights->num_entries * ACCESS_RIGHT_ENTRY_SIZE);
    
    if (signed_message_len < ED25519_SIGNATURE_BYTES + data_size) {
        microkit_dbg_printf(PROGNAME "Verified data size (%d) is less than expected size (%d)\n", signed_message_len, ED25519_SIGNATURE_BYTES + data_size);
        return seL4_InvalidArgument;
    }

    // Print the public key in hex
    microkit_dbg_printf(PROGNAME "Public key: 0x");
    for (int i = 0; i < ED25519_PUBLIC_KEY_BYTES; i++) {
        microkit_dbg_printf("%x", public_key[i]);
    }
    microkit_dbg_printf("\n");

    // Print the signature in hex
    microkit_dbg_printf(PROGNAME "Signature: 0x");
    for (int i = 0; i < ED25519_SIGNATURE_BYTES; i++) {
        microkit_dbg_printf("%x", signature[i]);
    }
    microkit_dbg_printf("\n");

    // Print the data in hex (optional, can be removed in production)
    microkit_dbg_printf(PROGNAME "Data (size %d bytes): 0x", data_size);
    for (size_t i = 0; i < data_size; i++) {
        microkit_dbg_printf("%x", data[i]);
    }
    microkit_dbg_printf("\n");

    // Perform signature verification
    int valid_signature = ed25519_verify(signature, data, data_size, public_key);

    if (valid_signature != 1) {
        microkit_dbg_printf(PROGNAME "ed25519_verify failed. Invalid signature.\n");
        return seL4_InvalidArgument;
    }

    microkit_dbg_printf(PROGNAME "ed25519_verify succeeded. Signature is valid.\n");

    const unsigned char *access_rights_table = data + SYSTEM_HASH_SIZE + NUM_ENTRIES_SIZE;

    // Parse each access right entry
    for (uint32_t i = 0; i < rights->num_entries; i++) {
        AccessRightEntry *entry = &rights->entries[i];
        entry->type = (AccessType)*(access_rights_table + i * ACCESS_RIGHT_ENTRY_SIZE);
        entry->data = *((seL4_Word*)(access_rights_table + i * ACCESS_RIGHT_ENTRY_SIZE + sizeof(uint8_t)));
        microkit_dbg_printf(PROGNAME "Parsed access right %d: type=%d, data=0x%x\n", i, entry->type, (unsigned long long)entry->data);
    }

    return seL4_NoError;
}

/**
 * @brief Loads ELF segments into the child PD's memory.
 *
 * @param ehdr Pointer to ELF header.
 */
static void load_elf(void *dest_vaddr, const Elf64_Ehdr *ehdr)
{
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char*)ehdr + ehdr->e_phoff);

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) {
            continue;
        }

        void *src = (char*)ehdr + phdr[i].p_offset;
        void *dest = (void *)(dest_vaddr + phdr[i].p_vaddr - ehdr->e_entry);

        custom_memcpy(dest, src, phdr[i].p_filesz);

        if (phdr[i].p_memsz > phdr[i].p_filesz) {
            seL4_Word bss_size = phdr[i].p_memsz - phdr[i].p_filesz;
            custom_memset((char *)dest + phdr[i].p_filesz, 0, bss_size);
        }
    }

    microkit_dbg_printf(PROGNAME "Loaded ELF segments into memory\n");
}

/**
 * @brief Finds a memory mapping by virtual address.
 *
 * @param vaddr Virtual address to search for.
 * @return Pointer to the MemoryMapping if found, NULL otherwise.
 */
static MemoryMapping* find_mapping_by_vaddr(seL4_Word vaddr)
{
    for (seL4_Word i = 0; i < MICROKIT_MAX_CHANNELS; i++) {
        if (mappings[i].vaddr == vaddr) {
            return &mappings[i];
        }
    }
    return NULL;
}

/**
 * @brief Applies access rights to build allowed lists.
 *
 * @param rights Pointer to AccessRights structure.
 */
static seL4_Error populate_allowed(const AccessRights *rights)
{
    // Reset allowed lists
    custom_memset(allowed_channels, 0, sizeof(allowed_channels));
    custom_memset(allowed_irqs, 0, sizeof(allowed_irqs));
    num_allowed_mappings = 0;

    for (uint32_t i = 0; i < rights->num_entries; i++) {
        const AccessRightEntry *entry = &rights->entries[i];
        switch (entry->type) {
            case ACCESS_TYPE_CHANNEL:
                if (entry->data < MICROKIT_MAX_CHANNELS && channels[entry->data]) {
                    allowed_channels[entry->data] = true;
                    microkit_dbg_printf(PROGNAME "Allowed channel ID: %d\n", (unsigned long long)entry->data);
                } else {
                    microkit_dbg_printf(PROGNAME "Invalid channel ID: %d\n", (unsigned long long)entry->data);
                    return seL4_InvalidArgument;
                }
                break;

            case ACCESS_TYPE_IRQ:
                if (entry->data < MICROKIT_MAX_CHANNELS && irqs[entry->data]) {
                    allowed_irqs[entry->data] = true;
                    microkit_dbg_printf(PROGNAME "Allowed IRQ ID: %d\n", (unsigned long long)entry->data);
                } else {
                    microkit_dbg_printf(PROGNAME "Invalid IRQ ID: %d\n", (unsigned long long)entry->data);
                    return seL4_InvalidArgument;
                }
                break;

            case ACCESS_TYPE_MEMORY:
                if (num_allowed_mappings < MAX_MAPPINGS) {
                    seL4_Word vaddr = entry->data;
                    MemoryMapping *mapping = find_mapping_by_vaddr(vaddr);
                    if (mapping != NULL) {
                        allowed_mappings[num_allowed_mappings++] = *mapping;
                        microkit_dbg_printf(PROGNAME "Allowed memory vaddr: 0x%x\n", (unsigned long long)vaddr);
                    } else {
                        microkit_dbg_printf(PROGNAME "Mapping not found for vaddr: 0x%x\n", (unsigned long long)vaddr);
                        return seL4_InvalidArgument;
                    }
                } else {
                    microkit_dbg_printf(PROGNAME "Number of allowed mappings exceeded\n");
                    return seL4_InvalidArgument;
                }
                break;

            default:
                microkit_dbg_printf(PROGNAME "Unknown access type: %d\n", (unsigned int)entry->type);
                return seL4_InvalidArgument;
        }
    }

    return seL4_NoError;
}

static void remove_caps()
{
    // Delete disallowed channel capabilities
    for (seL4_Word channel_id = 0; channel_id < MICROKIT_MAX_CHANNELS; channel_id++) {
        if (allowed_channels[channel_id] || !channels[channel_id]) {
            continue;
        }

        seL4_Error error = seL4_CNode_Delete(
            CHILD_CSPACE_CAP,
            BASE_OUTPUT_NOTIFICATION_CAP + channel_id,
            PD_CAP_BITS
        );

        if (error != seL4_NoError) {
            microkit_dbg_printf(PROGNAME "Failed to delete channel cap: channel_id=%d error=%d\n", channel_id, error);
            microkit_internal_crash(error);
        }

        microkit_dbg_printf(PROGNAME "Deleted channel cap: channel_id=%d\n", channel_id);   
    }

    // Delete disallowed IRQ capabilities
    for (seL4_Word irq_id = 0; irq_id < MICROKIT_MAX_CHANNELS; irq_id++) {
        if (allowed_irqs[irq_id] || !irqs[irq_id]) {
            continue;
        }

        seL4_Error error = seL4_CNode_Delete(
            CHILD_CSPACE_CAP,
            BASE_IRQ_CAP + irq_id,
            PD_CAP_BITS
        );

        if (error != seL4_NoError) {
            microkit_dbg_printf(PROGNAME "Failed to delete IRQ cap: irq_id=%d error=%d\n", irq_id, error);
            microkit_internal_crash(error);
        }

        microkit_dbg_printf(PROGNAME "Deleted IRQ cap: irq_id=%d\n", irq_id);
    }

    // Map only the allowed memory regions
    for (seL4_Word i = 0; i < num_allowed_mappings; i++) {
        const MemoryMapping *mapping = &allowed_mappings[i];
        microkit_dbg_printf(PROGNAME "Mapping allowed memory: vaddr=0x%x\n", mapping->vaddr);

        seL4_CapRights_t rights = seL4_AllRights;
        rights.words[0] = mapping->rights;

        seL4_Error error = seL4_ARM_Page_Map(
            mapping->page,
            CHILD_VSPACE_CAP,
            mapping->vaddr,
            rights,
            mapping->attrs
        );

        if (error != seL4_NoError) {
            microkit_dbg_printf(PROGNAME "Failed to map memory: vaddr=0x%x error=%d\n", mapping->vaddr, error);
            microkit_internal_crash(error);
        }

        microkit_dbg_printf(PROGNAME "Mapped allowed memory: page=0x%x vaddr=0x%x\n", mapping->page, mapping->vaddr);
    }
}

/**
 * @brief Restores capabilities based on access rights during reset.
 *
 * @param rights Pointer to AccessRights structure.
 */
static void restore_caps()
{
    // Restore disallowed channel capabilities
    for (seL4_Word channel_id = 0; channel_id < MICROKIT_MAX_CHANNELS; channel_id++) {
        if (allowed_channels[channel_id] || !channels[channel_id]) {
            continue;
        }

        seL4_Error error = seL4_CNode_Copy(
            CHILD_CSPACE_CAP,
            BASE_OUTPUT_NOTIFICATION_CAP + channel_id,
            PD_CAP_BITS,
            PD_TEMPLATE_CNODE_ROOT,
            CHILD_BASE_OUTPUT_NOTIFICATION_CAP + channel_id,
            PD_CAP_BITS,
            seL4_AllRights
        );

        if (error != seL4_NoError) {
            microkit_dbg_printf(PROGNAME "Failed to restore channel cap: channel_id=%d error=%d\n", channel_id, error);
            microkit_internal_crash(error);
        }

        microkit_dbg_printf(PROGNAME "Restored channel cap: channel_id=%d\n", channel_id);
    }

    // Restore disallowed IRQ capabilities
    for (seL4_Word irq_id = 0; irq_id < MICROKIT_MAX_CHANNELS; irq_id++) {
        if (allowed_irqs[irq_id] || !irqs[irq_id]) {
            continue;
        }

        seL4_Error error = seL4_CNode_Copy(
            CHILD_CSPACE_CAP,
            BASE_IRQ_CAP + irq_id,
            PD_CAP_BITS,
            PD_TEMPLATE_CNODE_ROOT,
            CHILD_BASE_IRQ_CAP + irq_id,
            PD_CAP_BITS,
            seL4_AllRights
        );

        if (error != seL4_NoError) {
            microkit_dbg_printf(PROGNAME "Failed to restore IRQ cap: irq_id=%d error=%d\n", irq_id, error);
            microkit_internal_crash(error);
        }
        
        microkit_dbg_printf(PROGNAME "Restored IRQ cap: irq_id=%d\n", irq_id);
    }

    // Unmapped allowed memory mappings
    for (seL4_Word i = 0; i < num_allowed_mappings; i++) {
        const MemoryMapping *mapping = &allowed_mappings[i];
        microkit_dbg_printf(PROGNAME "Unmapping mapping: vaddr=0x%x\n", mapping->vaddr);

        seL4_Error error = seL4_ARM_Page_Unmap(mapping->page);

        if (error != seL4_NoError) {
            microkit_dbg_printf(PROGNAME "Failed to unmap mapping: vaddr=0x%x error=%d\n", mapping->vaddr, error);
            microkit_internal_crash(error);
        }

        microkit_dbg_printf(PROGNAME "Unmapped mapping: vaddr=0x%x\n", mapping->vaddr);
    }
}

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
#include <string.h>
#include <stdio.h> // Added for debug printing

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
#define MAX_ACCESS_RIGHTS                   100
#define MAX_ALLOWED_MAPPINGS                MICROKIT_MAX_CHANNELS

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
    seL4_Word num_entries;
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

// External ELF binaries
extern char _receiver[];
extern char _receiver_end[];
extern char _sender[];
extern char _sender_end[];

// Global variables (patched externally)
seL4_Word channels[MICROKIT_MAX_CHANNELS] = {0};
seL4_Word irqs[MICROKIT_MAX_CHANNELS] = {0};
MemoryMapping mappings[MICROKIT_MAX_CHANNELS] = {0};
uintptr_t user_program = 0;
seL4_Word system_hash = 0;

// Public key for verifying signatures (256-bit for Ed25519)
// Initialize with zeros; should be patched externally with the actual public key
unsigned char public_key[ED25519_PUBLIC_KEY_BYTES] = {0};

// Maximum size calculations
#define SYSTEM_HASH_SIZE          sizeof(seL4_Word)
#define NUM_ENTRIES_SIZE          sizeof(uint32_t)
#define ACCESS_RIGHT_ENTRY_SIZE   9 // 1 byte for type + 8 bytes for data
#define MAX_VERIFIED_DATA_SIZE    (SYSTEM_HASH_SIZE + NUM_ENTRIES_SIZE + (MAX_ACCESS_RIGHTS * ACCESS_RIGHT_ENTRY_SIZE))

// Global variables
static AccessRights access_rights = {0};
static bool allowed_channels[MICROKIT_MAX_CHANNELS] = {false};
static bool allowed_irqs[MICROKIT_MAX_CHANNELS] = {false};
static MemoryMapping allowed_mappings[MAX_ALLOWED_MAPPINGS] = {0};
static int num_allowed_mappings = 0;

// Function prototypes
static void initialize_access_rights(AccessRights *rights, const unsigned char *verified_data, size_t verified_data_len);
static bool verify_signature(const unsigned char *signed_message, size_t signed_message_len);
static void load_elf_segments(const Elf64_Ehdr *ehdr);
static MemoryMapping* find_mapping_by_vaddr(seL4_Word vaddr);
static void apply_access_rights(const AccessRights *rights);
static void cleanup_capabilities(const AccessRights *rights);
static void map_allowed_memory();
static void unmap_disallowed_memory();
static void restore_capabilities(const AccessRights *rights);

/**
 * @brief Verifies the Ed25519 signature of the access rights data.
 *
 * @param signed_message Pointer to the signed message (signature || data).
 * @param signed_message_len Length of the signed message in bytes.
 * @return true if the signature is valid, false otherwise.
 */
static bool verify_signature(const unsigned char *signed_message, size_t signed_message_len)
{
    // Calculate the minimum required size: signature + system_hash + num_access_rights
    size_t min_required_size = ED25519_SIGNATURE_BYTES + SYSTEM_HASH_SIZE + NUM_ENTRIES_SIZE;
    
    if (signed_message_len < min_required_size) {
        microkit_dbg_printf(PROGNAME "Signed message length (%d) is too short. Minimum required: %d bytes.\n",
                           signed_message_len, min_required_size);
        return false;
    }

    // Extract signature and data
    const unsigned char *signature = signed_message;
    const unsigned char *data = signed_message + ED25519_SIGNATURE_BYTES;
    size_t data_len = signed_message_len - ED25519_SIGNATURE_BYTES;

    // Print the PUBLIC_KEY in hex
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

    // Parse system_hash and num_entries from the verified data
    seL4_Word system_hash_in_section = *((seL4_Word*)(data));
    uint32_t num_access_rights = *((uint32_t*)(data + SYSTEM_HASH_SIZE));

    // Calculate the expected total size based on the number of access rights
    size_t expected_total_size = SYSTEM_HASH_SIZE + NUM_ENTRIES_SIZE + (num_access_rights * ACCESS_RIGHT_ENTRY_SIZE);
    
    if (data_len < expected_total_size) {
        microkit_dbg_printf(PROGNAME "Verified data size (%d) is less than expected size (%d)\n", data_len, expected_total_size);
        return false;
    }

    // Print the data in hex (optional, can be removed in production)
    microkit_dbg_printf(PROGNAME "Data: 0x");
    for (size_t i = 0; i < expected_total_size; i++) {
        microkit_dbg_printf("%x", data[i]);
    }
    microkit_dbg_printf("\n");

    // Perform signature verification
    microkit_dbg_printf(PROGNAME "signature=%x, data=%x, data_len=%d, public_key=%x\n", *signature, *data, expected_total_size, *public_key);
    int verify_result = ed25519_verify(signature, data, expected_total_size, public_key);

    if (verify_result != 1) {
        microkit_dbg_printf(PROGNAME "ed25519_verify failed. Invalid signature.\n");
        return false;
    } else {
        microkit_dbg_printf(PROGNAME "ed25519_verify succeeded. Signature is valid.\n");
    }

    // Now, dynamically calculate the expected size based on the actual number of access rights
    if (data_len < SYSTEM_HASH_SIZE + NUM_ENTRIES_SIZE) {
        microkit_dbg_printf(PROGNAME "Verified data too small for system_hash and num_entries.\n");
        return false;
    }

    microkit_dbg_printf(PROGNAME "Extracted system_hash from verified data: 0x%x\n", (unsigned long)system_hash_in_section);
    microkit_dbg_printf(PROGNAME "Number of access rights: %d\n", num_access_rights);

    // Verify system_hash matches
    if (system_hash_in_section != system_hash) {
        microkit_dbg_printf(PROGNAME "System hash mismatch: expected 0x%lx, found 0x%lx\n",
                           (unsigned long)system_hash,
                           (unsigned long)system_hash_in_section);
        return false;
    }

    // Initialize access_rights structure
    initialize_access_rights(&access_rights, data, data_len);

    return true;
}

void init(void)
{
    microkit_dbg_printf(PROGNAME "Entered init\n");
    microkit_dbg_printf(PROGNAME "System hash (trusted loader): 0x%x\n", (unsigned long long)system_hash);

    char *elf_start = NULL;
    char *elf_end = NULL;

    // Determine which ELF to load based on name
    if (custom_strcmp(microkit_name, "trusted_loader1") == 0) {
        elf_start = _receiver;
        elf_end = _receiver_end;
        microkit_dbg_printf(PROGNAME "Loading receiver program\n");
    } else if (custom_strcmp(microkit_name, "trusted_loader2") == 0) {
        elf_start = _sender;
        elf_end = _sender_end;
        microkit_dbg_printf(PROGNAME "Loading sender program\n");
    } else {
        microkit_dbg_printf(PROGNAME "Unknown program name: %s\n", microkit_name);
        return;
    }

    seL4_Word elf_size = (seL4_Word)(elf_end - elf_start);
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_start;

    if (elf_size < sizeof(Elf64_Ehdr)) {
        microkit_dbg_printf(PROGNAME "Invalid ELF size\n");
        return;
    }

    if (custom_memcmp(ehdr->e_ident, (const unsigned char*)ELFMAG, SELFMAG) != 0) {
        microkit_dbg_printf(PROGNAME "Invalid ELF magic\n");
        return;
    }

    microkit_dbg_printf(PROGNAME "Verified ELF header\n");

    // Locate the .access_rights section
    Elf64_Shdr *shdr = (Elf64_Shdr *)((char*)ehdr + ehdr->e_shoff);
    const char *shstrtab = (char*)ehdr + shdr[ehdr->e_shstrndx].sh_offset;
    char *access_rights_section = NULL;
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
        microkit_dbg_printf(PROGNAME ".access_rights section not found in ELF\n");
        return;
    }

    // The signed_message is expected to be signature || data
    if (access_rights_size < ED25519_SIGNATURE_BYTES + SYSTEM_HASH_SIZE + NUM_ENTRIES_SIZE) {
        microkit_dbg_printf(PROGNAME ".access_rights section too small for signature and data\n");
        return;
    }

    unsigned char *sm = (unsigned char *)access_rights_section;

    // Verify the signature (only the relevant part of the section)
    bool valid_signature = verify_signature(
        sm,                  // Pointer to signature || data
        access_rights_size   // Length of signed message
    );

    if (!valid_signature) {
        microkit_dbg_printf(PROGNAME "Signature verification failed for .access_rights section\n");
        return;
    }

    microkit_dbg_printf(PROGNAME "Signature verification succeeded for .access_rights section\n");

    apply_access_rights(&access_rights);
    cleanup_capabilities(&access_rights);
    map_allowed_memory();

    load_elf_segments(ehdr);
    microkit_dbg_printf(PROGNAME "Copied program to child PD's memory region\n");

    // Restart the child PD at the entry point
    microkit_pd_restart(CHILD_ID, ehdr->e_entry);
    microkit_dbg_printf(PROGNAME "Started child PD at entrypoint address: 0x%x\n", (unsigned long long)ehdr->e_entry);
    microkit_dbg_printf(PROGNAME "Finished init\n");
}

void reset(void)
{
    microkit_dbg_printf(PROGNAME "Entered reset\n");

    restore_capabilities(&access_rights);
    map_allowed_memory();

    microkit_dbg_printf(PROGNAME "Finished reset\n");
}

void notified(microkit_channel ch)
{
    microkit_dbg_printf(PROGNAME "Received notification on channel: %d\n", ch);
}

seL4_MessageInfo_t protected(microkit_channel ch, microkit_msginfo msginfo)
{
    microkit_dbg_printf(PROGNAME "Received protected message on channel: %d\n", ch);
    return microkit_msginfo_new(0, 0);
}

seL4_Bool fault(microkit_child child, microkit_msginfo msginfo, microkit_msginfo *reply_msginfo)
{
    microkit_dbg_printf(PROGNAME "Received fault message for child PD: %d\n", child);

    seL4_Word label = microkit_msginfo_get_label(msginfo);
    microkit_dbg_printf(PROGNAME "Fault label: %d\n", label);

    if (label == seL4_Fault_VMFault) {
        seL4_Word ip = microkit_mr_get(seL4_VMFault_IP);
        seL4_Word address = microkit_mr_get(seL4_VMFault_Addr);
        microkit_dbg_printf(PROGNAME "Fault address: 0x%x\n", (unsigned long long)address);
        microkit_dbg_printf(PROGNAME "Fault instruction pointer: 0x%x\n", (unsigned long long)ip);
    }

    microkit_pd_stop(child);

    // Restart the thread explicitly; no need to reply to the fault
    return seL4_False;
}

/**
 * @brief Initializes access rights from the verified data.
 *
 * @param rights Pointer to AccessRights structure.
 * @param verified_data Pointer to the verified data.
 * @param verified_data_len Length of the verified data.
 */
static void initialize_access_rights(AccessRights *rights, const unsigned char *verified_data, size_t verified_data_len)
{
    // Reset access rights
    custom_memset(rights, 0, sizeof(AccessRights));

    // Ensure there is enough data for system_hash and num_entries
    if (verified_data_len < SYSTEM_HASH_SIZE + NUM_ENTRIES_SIZE) {
        microkit_dbg_printf(PROGNAME "Verified data too small for system_hash and num_entries\n");
        return;
    }

    // Parse system_hash and num_entries
    rights->system_hash = *((seL4_Word*)verified_data);
    microkit_dbg_printf(PROGNAME "Parsed system_hash: 0x%x\n", (unsigned long long)rights->system_hash);

    if (rights->system_hash != system_hash) {
        microkit_dbg_printf(PROGNAME "System hash mismatch: expected 0x%x, found 0x%x\n",
                           (unsigned long long)system_hash,
                           (unsigned long long)rights->system_hash);
        return;
    }

    uint32_t num_access_rights = *((uint32_t*)(verified_data + SYSTEM_HASH_SIZE));
    microkit_dbg_printf(PROGNAME "Parsed num_access_rights: %d\n", num_access_rights);

    // Check if the number of access rights exceeds the maximum allowed
    if (num_access_rights > MAX_ACCESS_RIGHTS) {
        microkit_dbg_printf(PROGNAME "Number of access rights (%d) exceeds maximum allowed (%d)\n", num_access_rights, MAX_ACCESS_RIGHTS);
        return;
    }

    // Calculate expected data size
    size_t expected_size = SYSTEM_HASH_SIZE + NUM_ENTRIES_SIZE + (num_access_rights * ACCESS_RIGHT_ENTRY_SIZE);
    if (verified_data_len < expected_size) {
        microkit_dbg_printf(PROGNAME "Verified data size (%d) is less than expected size (%d)\n", verified_data_len, expected_size);
        return;
    }

    // Parse each access right entry
    for (uint32_t i = 0; i < num_access_rights && rights->num_entries < MAX_ACCESS_RIGHTS; i++) {
        AccessRightEntry *entry = &rights->entries[rights->num_entries];
        entry->type = (AccessType)*(verified_data + SYSTEM_HASH_SIZE + NUM_ENTRIES_SIZE + i * ACCESS_RIGHT_ENTRY_SIZE);
        entry->data = *((seL4_Word*)(verified_data + SYSTEM_HASH_SIZE + NUM_ENTRIES_SIZE + i * ACCESS_RIGHT_ENTRY_SIZE + sizeof(uint8_t)));
        rights->num_entries++;
        microkit_dbg_printf(PROGNAME "Parsed access right %d: type=%d, data=0x%x\n", i + 1, entry->type, (unsigned long long)entry->data);
    }

    microkit_dbg_printf(PROGNAME "Total number of access rights parsed: %d\n", rights->num_entries);
}

/**
 * @brief Loads ELF segments into the child PD's memory.
 *
 * @param ehdr Pointer to ELF header.
 */
static void load_elf_segments(const Elf64_Ehdr *ehdr)
{
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char*)ehdr + ehdr->e_phoff);

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) {
            continue;
        }

        void *src = (char*)ehdr + phdr[i].p_offset;
        void *dest = (void *)(user_program + phdr[i].p_vaddr - 0x200000); // Adjust as per your memory mapping

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
    for (int i = 0; i < MICROKIT_MAX_CHANNELS; i++) {
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
static void apply_access_rights(const AccessRights *rights)
{
    for (seL4_Word i = 0; i < rights->num_entries; i++) {
        const AccessRightEntry *entry = &rights->entries[i];
        switch (entry->type) {
            case ACCESS_TYPE_CHANNEL:
                if (entry->data < MICROKIT_MAX_CHANNELS && channels[entry->data]) {
                    allowed_channels[entry->data] = true;
                    microkit_dbg_printf(PROGNAME "Allowed channel ID: %d\n", (unsigned long long)entry->data);
                } else {
                    microkit_dbg_printf(PROGNAME "Invalid or disallowed channel ID: %d\n", (unsigned long long)entry->data);
                }
                break;

            case ACCESS_TYPE_IRQ:
                if (entry->data < MICROKIT_MAX_CHANNELS && irqs[entry->data]) {
                    allowed_irqs[entry->data] = true;
                    microkit_dbg_printf(PROGNAME "Allowed IRQ ID: %d\n", (unsigned long long)entry->data);
                } else {
                    microkit_dbg_printf(PROGNAME "Invalid or disallowed IRQ ID: %d\n", (unsigned long long)entry->data);
                }
                break;

            case ACCESS_TYPE_MEMORY:
                if (num_allowed_mappings < MAX_ALLOWED_MAPPINGS) {
                    seL4_Word vaddr = entry->data;
                    MemoryMapping *mapping = find_mapping_by_vaddr(vaddr);
                    if (mapping) {
                        allowed_mappings[num_allowed_mappings++] = *mapping;
                        microkit_dbg_printf(PROGNAME "Allowed memory vaddr: 0x%x\n", (unsigned long long)vaddr);
                    } else {
                        microkit_dbg_printf(PROGNAME "Mapping not found for vaddr: 0x%x\n", (unsigned long long)vaddr);
                    }
                } else {
                    microkit_dbg_printf(PROGNAME "Number of allowed mappings exceeded\n");
                }
                break;

            default:
                microkit_dbg_printf(PROGNAME "Unknown access type: %d\n", (unsigned int)entry->type);
        }
    }
}

/**
 * @brief Cleans up capabilities that are not allowed based on access rights.
 *
 * @param rights Pointer to AccessRights structure.
 */
static void cleanup_capabilities(const AccessRights *rights)
{
    // Delete disallowed channel capabilities
    for (int channel_id = 0; channel_id < MICROKIT_MAX_CHANNELS; channel_id++) {
        if (channels[channel_id] && !allowed_channels[channel_id]) {
            seL4_Error error = seL4_CNode_Delete(
                CHILD_CSPACE_CAP,
                CHILD_BASE_OUTPUT_NOTIFICATION_CAP + channel_id,
                PD_CAP_BITS
            );
            microkit_dbg_printf(PROGNAME "Deleted child PD's output notification cap: channel_id=%d error=%d\n", channel_id, error);
        }
    }

    // Delete disallowed IRQ capabilities
    for (int irq_id = 0; irq_id < MICROKIT_MAX_CHANNELS; irq_id++) {
        if (irqs[irq_id] && !allowed_irqs[irq_id]) {
            seL4_Error error = seL4_CNode_Delete(
                CHILD_CSPACE_CAP,
                CHILD_BASE_IRQ_CAP + irq_id,
                PD_CAP_BITS
            );
            microkit_dbg_printf(PROGNAME "Deleted child PD's IRQ cap: irq_id=%d error=%d\n", irq_id, error);
        }
    }
}

/**
 * @brief Maps allowed memory regions for the child PD.
 */
static void map_allowed_memory()
{
    // Unmap disallowed memory regions
    unmap_disallowed_memory();

    // Map only the allowed memory regions
    for (int i = 0; i < num_allowed_mappings; i++) {
        const MemoryMapping *mapping = &allowed_mappings[i];
        microkit_dbg_printf(PROGNAME "Mapping allowed memory: vaddr=0x%x\n", (unsigned long long)mapping->vaddr);

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
            microkit_dbg_printf(PROGNAME "Failed to map memory: vaddr=0x%x error=%d\n", (unsigned long long)mapping->vaddr, error);
        } else {
            microkit_dbg_printf(PROGNAME "Mapped allowed memory: page=0x%x vaddr=0x%x\n", mapping->page, (unsigned long long)mapping->vaddr);
        }
    }
}

/**
 * @brief Unmaps memory regions that are not allowed.
 */
static void unmap_disallowed_memory()
{
    for (int i = 0; i < MICROKIT_MAX_CHANNELS; i++) {
        bool is_allowed = false;
        for (int j = 0; j < num_allowed_mappings; j++) {
            if (mappings[i].vaddr == allowed_mappings[j].vaddr) {
                is_allowed = true;
                break;
            }
        }

        if (!is_allowed && mappings[i].number_of_pages > 0) {
            for (int slot = 0; slot < mappings[i].number_of_pages; slot++) {
                seL4_CNode page = mappings[i].page + slot;
                seL4_Error error = seL4_ARM_Page_Unmap(page);
                microkit_dbg_printf(PROGNAME "Unmapped memory: page=0x%x error=%d\n", page, error);
            }
        }
    }
}

/**
 * @brief Restores capabilities based on access rights during reset.
 *
 * @param rights Pointer to AccessRights structure.
 */
static void restore_capabilities(const AccessRights *rights)
{
    // Restore allowed channel capabilities
    for (seL4_Word i = 0; i < rights->num_entries; i++) {
        if (rights->entries[i].type == ACCESS_TYPE_CHANNEL) {
            seL4_Word channel_id = rights->entries[i].data;
            if (channel_id < MICROKIT_MAX_CHANNELS && !allowed_channels[channel_id]) {
                seL4_Error error = seL4_CNode_Copy(
                    CHILD_CSPACE_CAP,
                    CHILD_BASE_OUTPUT_NOTIFICATION_CAP + channel_id,
                    PD_CAP_BITS,
                    PD_TEMPLATE_CNODE_ROOT,
                    CHILD_BASE_OUTPUT_NOTIFICATION_CAP + channel_id,
                    PD_CAP_BITS,
                    seL4_AllRights
                );
                microkit_dbg_printf(PROGNAME "Restored child PD's output notification cap: channel_id=%d error=%d\n", channel_id, error);
            }
        }
    }

    // Restore allowed IRQ capabilities
    for (seL4_Word i = 0; i < rights->num_entries; i++) {
        if (rights->entries[i].type == ACCESS_TYPE_IRQ) {
            seL4_Word irq_id = rights->entries[i].data;
            if (irq_id < MICROKIT_MAX_CHANNELS && !allowed_irqs[irq_id]) {
                seL4_Error error = seL4_CNode_Copy(
                    CHILD_CSPACE_CAP,
                    CHILD_BASE_IRQ_CAP + irq_id,
                    PD_CAP_BITS,
                    PD_TEMPLATE_CNODE_ROOT,
                    CHILD_BASE_IRQ_CAP + irq_id,
                    PD_CAP_BITS,
                    seL4_AllRights
                );
                microkit_dbg_printf(PROGNAME "Restored child PD's IRQ cap: irq_id=%d error=%d\n", irq_id, error);
            }
        }
    }

    // Restore allowed memory mappings
    for (int i = 0; i < num_allowed_mappings; i++) {
        const MemoryMapping *mapping = &allowed_mappings[i];
        microkit_dbg_printf(PROGNAME "Restoring mapping: vaddr=0x%x\n", (unsigned long long)mapping->vaddr);

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
            microkit_dbg_printf(PROGNAME "Failed to restore mapping: vaddr=0x%x error=%d\n", (unsigned long long)mapping->vaddr, error);
        } else {
            microkit_dbg_printf(PROGNAME "Restored mapping: page=0x%x vaddr=0x%x\n", mapping->page, (unsigned long long)mapping->vaddr);
        }
    }
}

/*
[trusted_loader] System hash (trusted loader): 0xfbe7b4c7b22a3ab9
[trusted_loader] Loading sender program
[trusted_loader] Verified ELF header
[trusted_loader] Public key: 0x3f613216647e7abf53673feb843f27c0d54ded21167afe2e192e591b992e97f9
[trusted_loader] Signature: 0x6ad9b3a1ef88faedd220dce07fd2945c132b6029991c67414a1d455de8ccca1936d6116bd5a1a98f92f53b3015901b324a67fdc6a466e1816533b4547be5
[trusted_loader] Data: 0xb93a2ab2c7b4e7fb0000
[trusted_loader] ed25519_verify succeeded. Signature is valid.
[trusted_loader] signature=2479512, data=2479576, data_len=12, public_key=2491008

[trusted_loader] signature=6a, data=b9, data_len=12, public_key=3f

[trusted_loader] Entered init
[trusted_loader] System hash (trusted loader): 0xfbe7b4c7b22a3ab9
[trusted_loader] Loading receiver program
[trusted_loader] Verified ELF header
[trusted_loader] Public key: 0x3f613216647e7abf53673feb843f27c0d54ded21167afe2e192e591b992e97f9
[trusted_loader] Signature: 0x6ad9b3a1ef88faedd220dce07fd2945c132b6029991c67414a1d455de8ccca1936d6116bd5a1a98f92f53b3015901b324a67fdc6a466e1816533b4547be5
[trusted_loader] Data: 0xb93a2ab2c7b4e7fb0000
[trusted_loader] signature=6a, data=b9, data_len=12, public_key=3f
[trusted_loader] ed25519_verify succeeded. Signature is valid.
*/
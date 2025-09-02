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

#define PROGNAME "[container monitor] "

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
uintptr_t trampoline_elf;
uintptr_t trampoline_exec;
uintptr_t client_program;
uintptr_t shared1;
uintptr_t shared2;
uintptr_t shared3;
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

seL4_MessageInfo_t monitor_call_debute(void);
seL4_MessageInfo_t monitor_call_restart(void);

static void tsldr_init_metadata(void)
{
    /* initialise trusted loader metadata */
    tsldr_md_t *md = (tsldr_md_t *)tsldr_metadata;
    custom_memset((void *)md, 0, sizeof(tsldr_md_t));

    md->system_hash = system_hash;
    custom_memcpy(md->public_key, public_key, sizeof(md->public_key));
    custom_memcpy(md->channels,   channels,   sizeof(md->channels));
    custom_memcpy(md->irqs,       irqs,       sizeof(md->irqs));
    custom_memcpy(md->mappings,   mappings,   sizeof(md->mappings));
    md->init = true;
}

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

    /* get the first word of the message */
    seL4_Word monitorcall_number = microkit_mr_get(0);

    seL4_MessageInfo_t ret;

    /* call for the container monitor */
    switch (monitorcall_number) {
    case 1:
        microkit_dbg_printf(PROGNAME "Loading trusted loader and the first client\n");
        ret = monitor_call_debute();
        break;
    case 2:
        microkit_dbg_printf(PROGNAME "Restart trusted loader and a new client\n");
        ret = monitor_call_restart();
        break;
    default:
        ;
    }

    return ret;
}

seL4_MessageInfo_t monitor_call_debute(void)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)shared1;

    if (custom_memcmp(ehdr->e_ident, (const unsigned char*)ELFMAG, SELFMAG) != 0) {
        microkit_dbg_printf(PROGNAME "Data in shared memory region must be an ELF file\n");
        return microkit_msginfo_new(seL4_InvalidArgument, 0);
    }

    microkit_dbg_printf(PROGNAME "Verified ELF header\n");

    /* init metadata for proto-container's tsldr */
    tsldr_init_metadata();

    load_elf((void*)user_program, ehdr);
    microkit_dbg_printf(PROGNAME "Copied trusted loader to child PD's memory region\n");

    custom_memcpy((void*)client_program, (char *)shared2, 0x800000);
    microkit_dbg_printf(PROGNAME "Copied client program to child PD's memory region\n");

    custom_memcpy((void*)trampoline_elf, (char *)shared3, 0x800000);
    microkit_dbg_printf(PROGNAME "Copied trampoline program to child PD's memory region\n");

    // Restart the child PD at the entry point
    microkit_pd_restart(CHILD_ID, ehdr->e_entry);
    microkit_dbg_printf(PROGNAME "Started child PD at entrypoint address: 0x%x\n", (unsigned long long)ehdr->e_entry);
    return microkit_msginfo_new(seL4_NoError, 0);
}

seL4_MessageInfo_t monitor_call_restart(void)
{
    /* init metadata for proto-container's tsldr */
    tsldr_init_metadata();

    /* bring back cap to background CNode and template PD CNode */
    seL4_Error error = seL4_CNode_Copy(
        CHILD_CSPACE_CAP,
        589,
        PD_CAP_BITS,
        PD_TEMPLATE_CNODE_ROOT,
        CHILD_CSPACE_CAP,
        PD_CAP_BITS,
        seL4_AllRights
    );
    if (error != seL4_NoError) {
        microkit_dbg_printf(PROGNAME "Failed to restore CNode cap for the child\n");
        return microkit_msginfo_new(error, 0);
    }

    error = seL4_CNode_Copy(
        CHILD_CSPACE_CAP,
        588,
        PD_CAP_BITS,
        PD_TEMPLATE_CNODE_ROOT,
        587,
        PD_CAP_BITS,
        seL4_AllRights
    );
    if (error != seL4_NoError) {
        microkit_dbg_printf(PROGNAME "Failed to restore background CNode cap for the child\n");
        return microkit_msginfo_new(error, 0);
    }

    /* reload the trusted loader to the target place */
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)shared1;

    load_elf((void*)user_program, ehdr);
    microkit_dbg_printf(PROGNAME "Copied trusted loader to child PD's memory region\n");

    custom_memcpy((void*)client_program, (char *)shared2, 0x800000);
    microkit_dbg_printf(PROGNAME "Copied client program to child PD's memory region\n");

    /* set a flag for the trusted loader to check whether to boot or to restart... */
    microkit_dbg_printf(PROGNAME "Restart template PD without reloading trusted loader\n");
    //microkit_pd_restart(CHILD_ID, ehdr->e_entry);
    seL4_UserContext ctxt = {0};
    ctxt.pc = ehdr->e_entry;
    ctxt.sp = 0x10000000000;
    error = seL4_TCB_WriteRegisters(
              BASE_TCB_CAP + CHILD_ID,
              seL4_True,
              0, /* No flags */
              1, /* writing 1 register */
              &ctxt
          );

    if (error != seL4_NoError) {
        microkit_dbg_puts("microkit_pd_restart: error writing TCB registers\n");
        microkit_internal_crash(error);
    }
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

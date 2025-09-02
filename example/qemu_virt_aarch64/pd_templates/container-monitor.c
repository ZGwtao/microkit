/*
 * Container monitor prototype.
 *
 * Copyright 2025, UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <microkit.h>
#include <elf_utils.h>
#include <libtrustedlo.h>

#define PROGNAME "[container monitor] "

// Child PD caps
#define CHILD_ID                1
#define CHILD_CSPACE_CAP        8
#define PD_TEMPLATE_CNODE_ROOT  586

// Global variables (patched externally)
seL4_Word channels[MICROKIT_MAX_CHANNELS];
seL4_Word irqs[MICROKIT_MAX_CHANNELS];
MemoryMapping mappings[MICROKIT_MAX_CHANNELS];
uintptr_t user_program;
uintptr_t trampoline_elf;
uintptr_t trampoline_exec;
uintptr_t client_program;
uintptr_t shared1;
uintptr_t shared2;
uintptr_t shared3;
seL4_Word system_hash;
unsigned char public_key[PUBLIC_KEY_BYTES];

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
        /* do nothing for now */
        microkit_dbg_printf(PROGNAME "Undefined container monitor call: %lu\n", monitorcall_number);
        break;
    }

    return ret;
}

seL4_MessageInfo_t monitor_call_debute(void)
{
    seL4_Error error = tsldr_grant_cspace_access();
    if (error != seL4_NoError) {
        return microkit_msginfo_new(error, 0);
    }

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

    seL4_Error error = tsldr_grant_cspace_access();
    if (error != seL4_NoError) {
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

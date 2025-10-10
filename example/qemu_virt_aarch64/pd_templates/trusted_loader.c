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
#include <ed25519.h>
#include <elf_utils.h>
#include <libtrustedlo.h>

#define PROGNAME "[trusted_loader] "

/* patched externally by microkit tool */
tsldr_md_array_t tsldr_metadata_patched;
/* dummy def */
tsldr_md_t *tsldr_metadata;
/* ? */
static tsldr_md_t tsldr_monitor_metadata;

uintptr_t container_exec;
uintptr_t container_elf;
uintptr_t shared1;
uintptr_t shared2;

seL4_Word system_hash;
unsigned char public_key[PUBLIC_KEY_BYTES];

seL4_MessageInfo_t monitor_call_debute(void);
seL4_MessageInfo_t monitor_call_restart(void);

/* trusted loader context */
trusted_loader_t loader_context;


void init(void)
{
    tsldr_metadata = &tsldr_monitor_metadata;
    tsldr_init_metadata(&tsldr_metadata_patched, 2);
    microkit_dbg_printf(PROGNAME "Entered init\n");

    tsldr_md_t *md = (tsldr_md_t *)tsldr_metadata;

    tsldr_init(&loader_context, md->child_id, ed25519_verify, md->system_hash, sizeof(seL4_Word), 64);
    custom_memcpy(loader_context.public_key, md->public_key, sizeof(md->public_key));
    loader_context.flags.init = true;

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

    char *section = NULL;
    seL4_Word section_size = 0;

    /* parse access rights table */
    seL4_Error error = tsldr_parse_rights(ehdr, &section, &section_size);
    if (error) {
        microkit_internal_crash(error);
    }

    error = tsldr_populate_rights(&loader_context, (unsigned char *)section, section_size);
    if (error != seL4_NoError) {
        return microkit_msginfo_new(error, 0);
    }

    tsldr_restore_caps(&loader_context, false);

    //error = populate_allowed(&access_rights);
    error = tsldr_populate_allowed(&loader_context);
    if (error != seL4_NoError) {
        return microkit_msginfo_new(error, 0);
    }
    tsldr_remove_caps(&loader_context, false);

    load_elf((void*)container_exec, ehdr);
    microkit_dbg_printf(PROGNAME "Copied program to child PD's memory region\n");

    // Restart the child PD at the entry point
    microkit_dbg_printf(PROGNAME "Restart child PD with ID: %d\n", loader_context.child_id);
    microkit_pd_restart(loader_context.child_id, ehdr->e_entry);
    microkit_dbg_printf(PROGNAME "Started child PD at entrypoint address: 0x%x\n", (unsigned long long)ehdr->e_entry);
    return microkit_msginfo_new(seL4_NoError, 0);
}

seL4_MessageInfo_t monitor_call_restart(void)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)shared1;

    /* set a flag for the trusted loader to check whether to boot or to restart... */
    microkit_dbg_printf(PROGNAME "Restart template PD without reloading trusted loader\n");
    microkit_pd_restart(loader_context.child_id, ehdr->e_entry);
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

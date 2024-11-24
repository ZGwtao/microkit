/*
 * Copyright 2024, UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "elf_utils.h"
#include <stdint.h>
#include <microkit.h>

#define PROGNAME "[receiver_loader] "

uintptr_t shared;
// External ELF binaries
extern char _receiver[];
extern char _receiver_end[];

extern char _receiver2[];
extern char _receiver2_end[];

void init(void)
{
    microkit_dbg_printf(PROGNAME "Entered init\n");

    custom_memcpy((void *)shared, _receiver, _receiver_end - _receiver);
    microkit_dbg_printf(PROGNAME "Wrote receiver's ELF file into memory\n");

    microkit_dbg_printf(PROGNAME "Making ppc to receiver's trusted loader\n");

    microkit_msginfo info;
    seL4_Error error;
    
    info = microkit_ppcall(1, microkit_msginfo_new(0, 0));
    error = microkit_msginfo_get_label(info);
    if (error != seL4_NoError) {
        microkit_internal_crash(error);
    }

    custom_memcpy((void *)shared, _receiver2, _receiver2_end - _receiver2);
    microkit_dbg_printf(PROGNAME "Wrote receiver2's ELF file into memory\n");

    microkit_dbg_printf(PROGNAME "Making ppc to receiver's trusted loader\n");

    info = microkit_ppcall(1, microkit_msginfo_new(0, 0));
    error = microkit_msginfo_get_label(info);
    if (error != seL4_NoError) {
        microkit_internal_crash(error);
    }

    microkit_dbg_printf(PROGNAME "Finished init\n");
}

void notified(microkit_channel ch)
{
    microkit_dbg_printf(PROGNAME "Received notification on channel: %d\n", ch);
}

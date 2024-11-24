/*
 * Copyright 2024, UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "elf_utils.h"
#include <stdint.h>
#include <microkit.h>

#define PROGNAME "[sender_loader] "

uintptr_t shared;
// External ELF binaries
extern char _sender[];
extern char _sender_end[];

void init(void)
{
    microkit_dbg_printf(PROGNAME "Entered init\n");

    custom_memcpy((void *)shared, _sender, _sender_end - _sender);
    microkit_dbg_printf(PROGNAME "Wrote sender's ELF file into memory\n");

    microkit_dbg_printf(PROGNAME "Making ppc to sender's trusted loader\n");

    microkit_msginfo info = microkit_ppcall(1, microkit_msginfo_new(0, 0));
    seL4_Error error = microkit_msginfo_get_label(info);
    if (error != seL4_NoError) {
        microkit_internal_crash(error);
    }

    microkit_dbg_printf(PROGNAME "Finished init\n");
}

void notified(microkit_channel ch)
{
    microkit_dbg_printf(PROGNAME "Received notification on channel: %d\n", ch);
}

/*
 * Copyright 2021, Breakaway Consulting Pty. Ltd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "elf_utils.h"
#include <stdint.h>
#include <microkit.h>

#define PROGNAME "[receiver] "

uintptr_t test = 0x4000000;

void init(void)
{
    debug_printf(PROGNAME "Entered init\n");

    debug_printf(PROGNAME "Notifying channel: %d\n", 2);
    microkit_notify(2);

    debug_printf(PROGNAME "Writing to 0x%x\n", test);
    *((uintptr_t*)test) = 0xdeadbeef;

    debug_printf(PROGNAME "Finished init\n");
}

void notified(microkit_channel ch)
{
    debug_printf(PROGNAME "Received notification on channel: %d\n", ch);
}

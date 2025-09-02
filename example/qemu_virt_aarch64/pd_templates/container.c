/*
 * Copyright 2024, UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "elf_utils.h"
#include <stdint.h>
#include <stddef.h>
#include <microkit.h>

#define PROGNAME "[container] "

void init(void)
{
    microkit_dbg_printf(PROGNAME "Entered init\n");
    microkit_dbg_printf(PROGNAME "Finished init\n");
}

void notified(microkit_channel ch)
{
    microkit_dbg_printf(PROGNAME "Received notification on channel: %d\n", ch);

    seL4_Signal(12);

    seL4_Signal(11);

    microkit_dbg_printf(PROGNAME "Exit notified() \n");
}

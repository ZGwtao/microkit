/*
 * Copyright 2021, Breakaway Consulting Pty. Ltd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "elf_utils.h"
#include <stdint.h>
#include <microkit.h>

#define PROGNAME "[sender] "

void init(void)
{
    debug_printf(PROGNAME "Entered init\n");

    // seL4_Error error;
    // error = seL4_CNode_Delete(BASE_OUTPUT_NOTIFICATION_CAP + 1, 0, 0);
    // debug_printf(PROGNAME "Error: %d\n", error);

    debug_printf(PROGNAME "Notifying channel: %d\n", 1);
    microkit_notify(1);

    debug_printf(PROGNAME "Finished init\n");
}

void notified(microkit_channel ch)
{
    debug_printf(PROGNAME "Received notification on channel: %d\n", ch);
}

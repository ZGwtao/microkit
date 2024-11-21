/*
 * Copyright 2024, UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "elf_utils.h"
#include <stdint.h>
#include <microkit.h>

#define PROGNAME "[sender] "

void init(void)
{
    microkit_dbg_printf(PROGNAME "Entered init\n");

    // seL4_Error error;
    // error = seL4_CNode_Delete(BASE_OUTPUT_NOTIFICATION_CAP + 1, 0, 0);
    // microkit_dbg_printf(PROGNAME "Error: %d\n", error);

    microkit_dbg_printf(PROGNAME "Notifying channel: %d\n", 1);
    microkit_notify(1);

    microkit_dbg_printf(PROGNAME "Finished init\n");
}

void notified(microkit_channel ch)
{
    microkit_dbg_printf(PROGNAME "Received notification on channel: %d\n", ch);
}

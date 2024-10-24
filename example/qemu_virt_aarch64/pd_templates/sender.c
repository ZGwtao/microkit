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
    microkit_dbg_puts(PROGNAME "Entered init\n");
    microkit_dbg_puts(PROGNAME "Notifying channel 1\n");
    microkit_notify(1);
    microkit_dbg_puts(PROGNAME "Finished init\n");
}

void notified(microkit_channel ch)
{
    microkit_dbg_puts(PROGNAME "Received notification on channel ");
    putdec(ch);
    microkit_dbg_puts("\n");
}

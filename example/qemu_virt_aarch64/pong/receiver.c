/*
 * Copyright 2021, Breakaway Consulting Pty. Ltd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdint.h>
#include <microkit.h>

#define PROGNAME "receiver: "

void init(void)
{
    microkit_dbg_puts(PROGNAME "init called\n");
}

void notified(microkit_channel ch)
{
    microkit_dbg_puts(PROGNAME "received notification\n");
}

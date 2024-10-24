/*
 * Copyright 2021, Breakaway Consulting Pty. Ltd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdint.h>
#include <microkit.h>

#define PROGNAME "[sender] "

static char decchar(unsigned int v)
{
    return '0' + v;
}

static void put8(uint8_t x)
{
    char tmp[4];
    unsigned i = 3;
    tmp[3] = 0;
    do
    {
        uint8_t c = x % 10;
        tmp[--i] = decchar(c);
        x /= 10;
    } while (x);
    microkit_dbg_puts(&tmp[i]);
}

void init(void)
{
    microkit_dbg_puts(PROGNAME "init called\n");
    microkit_dbg_puts(PROGNAME "notifying channel 1\n");
    microkit_notify(1);
    microkit_dbg_puts(PROGNAME "init finished\n");
}

void notified(microkit_channel ch)
{
    microkit_dbg_puts(PROGNAME "received notification on channel ");
    put8(ch);
    microkit_dbg_puts("\n");
}

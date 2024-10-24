/*
 * Copyright 2021, Breakaway Consulting Pty. Ltd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdint.h>
#include <microkit.h>

#define PROGNAME "trusted_loader: "

uintptr_t user_program;
uint64_t system_hash;
static uint8_t restart_count = 0;

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

void put64(uint64_t num) {
    microkit_dbg_puts("0x");

    int started = 0;

    for (int shift = 60; shift >= 0; shift -= 4) {
        uint8_t nibble = (num >> shift) & 0xF;

        if (nibble != 0 || started || shift == 0) {
            started = 1;

            char hex_char;
            if (nibble < 10) {
                hex_char = '0' + nibble;
            } else {
                hex_char = 'a' + (nibble - 10);
            }

            microkit_dbg_putc(hex_char);
        }
    }
}

void init(void)
{
    microkit_dbg_puts(PROGNAME "init called\n");
    microkit_dbg_puts(PROGNAME "system_hash is: ");
    put64(system_hash);
    microkit_dbg_puts("\n");

    microkit_pd_stop(1);
    microkit_dbg_puts(PROGNAME "stopped child pd\n");
}

void notified(microkit_channel ch)
{
    microkit_dbg_puts(PROGNAME "received notification on channel: ");
    put8(ch);
    microkit_dbg_puts("\n");
}

seL4_MessageInfo_t protected(microkit_channel ch, microkit_msginfo msginfo)
{
    microkit_dbg_puts(PROGNAME "received protected message on channel: ");
    put8(ch);
    microkit_dbg_puts("\n");

    return microkit_msginfo_new(0, 0);
}

seL4_Bool fault(microkit_child child, microkit_msginfo msginfo, microkit_msginfo *reply_msginfo)
{
    microkit_dbg_puts(PROGNAME "received fault message for child pd: ");
    put8(child);
    microkit_dbg_puts("\n");

    restart_count++;
    if (restart_count < 10)
    {
        microkit_pd_restart(child, 0x200000);
        microkit_dbg_puts(PROGNAME "restarted\n");
    }
    else
    {
        microkit_pd_stop(child);
        microkit_dbg_puts(PROGNAME "too many restarts - PD stopped\n");
    }

    /* We explicitly restart the thread so we do not need to 'reply' to the fault. */
    return seL4_False;
}

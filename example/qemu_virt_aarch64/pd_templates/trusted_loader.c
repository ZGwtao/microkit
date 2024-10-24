/*
 * Copyright 2021, Breakaway Consulting Pty. Ltd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdint.h>
#include <microkit.h>
#include "elf_utils.h"

#define PROGNAME "[trusted_loader] "

// contents of receiver.elf
extern char _receiver[];
extern char _receiver_end[];

uintptr_t user_program;

uint64_t system_hash;

void init(void)
{
    microkit_dbg_puts(PROGNAME "Entered init\n");
    microkit_dbg_puts(PROGNAME "The system hash is ");
    puthex(system_hash);
    microkit_dbg_puts("\n");

    print_elf(_receiver, _receiver_end);

    uint64_t size = _receiver_end - _receiver;
    custom_memcpy((void *)user_program, _receiver, size);
    microkit_dbg_puts(PROGNAME "Copied user_program to child PD\n");

    microkit_pd_restart(1, 0x4000000);
    microkit_dbg_puts(PROGNAME "Started child pd\n");

    microkit_dbg_puts(PROGNAME "Finished init\n");
}

void notified(microkit_channel ch)
{
    microkit_dbg_puts(PROGNAME "Received notification on channel ");
    putdec(ch);
    microkit_dbg_puts("\n");
}

seL4_MessageInfo_t protected(microkit_channel ch, microkit_msginfo msginfo)
{
    microkit_dbg_puts(PROGNAME "Received protected message on channel ");
    putdec(ch);
    microkit_dbg_puts("\n");

    return microkit_msginfo_new(0, 0);
}

seL4_Bool fault(microkit_child child, microkit_msginfo msginfo, microkit_msginfo *reply_msginfo)
{
    microkit_dbg_puts(PROGNAME "received fault message for child pd ");
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

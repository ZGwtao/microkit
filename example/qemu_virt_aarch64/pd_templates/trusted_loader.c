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
    microkit_dbg_puts(PROGNAME "Received fault message for child PD ");
    putdec(child);
    microkit_dbg_puts("\n");

    seL4_Word label = microkit_msginfo_get_label(msginfo);
    seL4_Word fault_address = microkit_mr_get(seL4_UserException_FaultIP);

    microkit_dbg_puts(PROGNAME "Fault label: ");
    putdec(label);
    microkit_dbg_puts("\n");

    microkit_dbg_puts(PROGNAME "Fault address: ");
    puthex(fault_address);
    microkit_dbg_puts("\n");

    microkit_pd_stop(child);
    
    /* We explicitly restart the thread so we do not need to 'reply' to the fault. */
    return seL4_False;
}

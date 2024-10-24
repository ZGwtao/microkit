/*
 * Copyright 2021, Breakaway Consulting Pty. Ltd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "elf_utils.h"
#include <stdint.h>
#include <microkit.h>

#define PROGNAME "[receiver] "

uintptr_t user_program = 0x4000000;

void init(void)
{
    microkit_dbg_puts(PROGNAME "Entered init\n");
    print_elf((char*)user_program, (char*)user_program + 131824);
    microkit_dbg_puts(PROGNAME "Fnished init\n");
}

void notified(microkit_channel ch)
{
    microkit_dbg_puts(PROGNAME "Received notification on channel ");
    putdec(ch);
    microkit_dbg_puts("\n");
}

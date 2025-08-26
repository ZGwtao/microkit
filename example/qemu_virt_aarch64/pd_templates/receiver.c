/*
 * Copyright 2024, UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "elf.h"
#include "elf_utils.h"
#include <stddef.h>
#include <stdint.h>
#include <microkit.h>

#define PROGNAME "[receiver] "

#define PROG_TCB    (10+64+64+64)

static uintptr_t test = 0x4000000;
static uintptr_t client_elf = 0xA000000;

typedef void (*entry_fn_t)(void);

void init(void)
{
    microkit_dbg_printf(PROGNAME "Entered init\n");
    microkit_dbg_printf(PROGNAME "Writing to 0x%x\n", test);
    *((uintptr_t*)test) = 0xdeadbeef;
    microkit_dbg_printf(PROGNAME "Finished init\n");

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)client_elf;

    if (custom_memcmp(ehdr->e_ident, (const unsigned char*)ELFMAG, SELFMAG) != 0) {
        microkit_dbg_printf(PROGNAME "Data in shared memory region must be an ELF file\n");
        microkit_internal_crash(-1);
    } else {
        microkit_dbg_printf(PROGNAME "Data in shared memory region is an ELF file\n");
    }
    microkit_dbg_printf(PROGNAME "Verified ELF header\n");

    uintptr_t entry = ehdr->e_entry;
    entry_fn_t entry_fn = (entry_fn_t) entry;

    entry_fn();

}

void notified(microkit_channel ch)
{
    microkit_dbg_printf(PROGNAME "Received notification on channel: %d\n", ch);
}

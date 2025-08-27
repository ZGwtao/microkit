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

#define NOTIFICATION_BASE_CAP   10
#define PD_CAP_BITS             10
#define CNODE_BACKGROUND_CAP    588
#define CNODE_SELF_CAP          589
#define CNODE_PARENT_CAP        590

#define PROG_TCB    (10+64+64+64)

static uintptr_t test = 0x4000000;
static uintptr_t client_elf = 0xA000000;
uintptr_t client_start;

typedef void (*entry_fn_t)(void);

static void load_elf(void *dest_vaddr, const Elf64_Ehdr *ehdr)
{
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char*)ehdr + ehdr->e_phoff);

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) {
            continue;
        }

        void *src = (char*)ehdr + phdr[i].p_offset;
        void *dest = (void *)(dest_vaddr + phdr[i].p_vaddr - ehdr->e_entry);

        custom_memcpy(dest, src, phdr[i].p_filesz);

        if (phdr[i].p_memsz > phdr[i].p_filesz) {
            seL4_Word bss_size = phdr[i].p_memsz - phdr[i].p_filesz;
            custom_memset((char *)dest + phdr[i].p_filesz, 0, bss_size);
        }
    }

    microkit_dbg_printf(PROGNAME "Loaded ELF segments into memory\n");
}

void init(void)
{
    __sel4_ipc_buffer = (seL4_IPCBuffer *)0x100000;

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

    microkit_dbg_printf(PROGNAME "Notify base notification\n");
    microkit_notify(2);
    microkit_dbg_printf(PROGNAME "Succeed in notification\n");

    /* delete the cap to current CNode from background CNode */
    seL4_Error error = seL4_CNode_Delete(CNODE_BACKGROUND_CAP, 8, 10);
    if (error != seL4_NoError) {
        microkit_internal_crash(error);
    }
    microkit_dbg_printf(PROGNAME "Succeed in CNode cap deletion from background cap\n");
    /* delete the cap to notification from current CNode */
    error = seL4_CNode_Delete(CNODE_SELF_CAP, 12, 10);
    if (error != seL4_NoError) {
        microkit_internal_crash(error);
    }
    microkit_dbg_printf(PROGNAME "Succeed in notification deletion\n");
    microkit_dbg_printf(PROGNAME "Try notify base notification\n");
    microkit_notify(2);
    microkit_dbg_printf(PROGNAME "Failed in notification invocation\n");

    microkit_dbg_printf(PROGNAME "Copy the notification cap from background CNode\n");
    error = seL4_CNode_Copy(
            CNODE_SELF_CAP,
            12,
            PD_CAP_BITS,
            CNODE_BACKGROUND_CAP,
            12,
            PD_CAP_BITS,
            seL4_AllRights
        );
    if (error != seL4_NoError) {
        microkit_internal_crash(error);
    }
    microkit_dbg_printf(PROGNAME "Succeed in notification restore\n");
    microkit_dbg_printf(PROGNAME "Try notify base notification\n");
    microkit_notify(2);
    microkit_dbg_printf(PROGNAME "Succeed in notification\n");

    client_start = ehdr->e_entry;
    load_elf((void *)client_start, ehdr);

    entry_fn_t entry_fn = (entry_fn_t) client_start;

    entry_fn();

}

void notified(microkit_channel ch)
{
    microkit_dbg_printf(PROGNAME "Received notification on channel: %d\n", ch);
}

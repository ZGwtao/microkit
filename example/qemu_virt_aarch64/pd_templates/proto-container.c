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
#include <ed25519.h>
#include <libtrustedlo.h>

#define PROGNAME "[proto-container] "

/*
 * +-----------------------------------+ <- 0x0FFFFFFFF_FFFFFFFF
 * | Canonical high portion - unusable |
 * | virtual addresses                 |
 * +-----------------------------------+ <- 0x10000000000 (trusted loader stack top)
 * |        Trusted Loader Stack       |                size = 0x1000 (4K)
 * +-----------------------------------+ <- 0x0FFFFFFF000
 * |        Trampoline Stack           |                size = 0x1000
 * +-----------------------------------+ <- 0x0FFFFDFF000
 * |        Container Stack            |                size = 0x1000
 * +-----------------------------------+ <- 0x0FFFFBFF000
 * |//////////(gap / unused)\\\\\\\\\\\|
 * +-----------------------------------+
 * |                                   |
 * |        Container Segments         |                size = 0x800000
 * |                                   |
 * +-----------------------------------+ <- 0x02800000 <= (entry of container client)
 * |                                   |    |
 * |        Container ELF Payload      |  size = 8M
 * |                                   |    |
 * +-----------------------------------+ <- 0x02000000
 * |                                   |    |
 * |        Trampoline Segments        |  size = 8M
 * |                                   |    |
 * +-----------------------------------+ <- 0x01800000 <= (entry of trampoline)
 * |                                   |    |
 * |        Trampoline ELF Payload     |  size = 8M
 * |                                   |    |
 * +-----------------------------------+ <- 0x01000000
 * |//////////(gap / unused)\\\\\\\\\\\|
 * +-----------------------------------+ <- 0x01000000
 * |                                   |   |
 * | trusted loader context (0x200000) | we use this to save the context of last run
 * |                                   |   |
 * +-----------------------------------+ <- 0x00E00000
 * |//////////(gap / unused)\\\\\\\\\\\|
 * +-----------------------------------+ <- 0x00A01000
 * | Trusted Loader Metadata (0x1000)  |
 * +-----------------------------------+ <- 0x00A00000
 * |                                   |
 * | Trusted Loader Segments (0x800000)|
 * |                                   |
 * +-----------------------------------+ <- 0x00200000 <= _start (entry of proto-container)
 * |//////////(gap / unused)\\\\\\\\\\\|
 * +-----------------------------------+ <- 0x00101000
 * | IPC Buffer (0x1000)               |
 * +-----------------------------------+ <- 0x00100000
 * |//////////(gap / unused)\\\\\\\\\\\|
 * +-----------------------------------+ <- 0x0
 */

/* 4KB in size, read-only */
uintptr_t tsldr_metadata    = 0x0A00000;
uintptr_t trampoline_elf    = 0x1000000;
uintptr_t container_elf     = 0x2000000;
uintptr_t container_exec    = 0x2800000;

#define STACKS_SIZE 0x1000

uintptr_t trampoline_stack_top  = (0x0FFFFE00000);
uintptr_t tsldr_stack_bottom    = (0x10000000000 - STACKS_SIZE);
uintptr_t container_stack_top   = (0x0FFFFC00000);

typedef void (*entry_fn_t)(void);

trusted_loader_t loader;

static void load_elf(void *dest_vaddr, const Elf64_Ehdr *ehdr)
{
    microkit_dbg_printf(PROGNAME "Start to load ELF segments into memory\n");

    Elf64_Phdr *phdr = (Elf64_Phdr *)((char*)ehdr + ehdr->e_phoff);

    /* the last section is access right table */
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

    tsldr_md_t *md = (tsldr_md_t *)tsldr_metadata;
    if (!md->init) {
        microkit_internal_crash(-1);
    }

    tsldr_loading_prologue(&loader);

    /* initialise the real trusted loader... */
    if (loader.init != true) {
        tsldr_init(&loader, ed25519_verify, md->system_hash, sizeof(seL4_Word), 64);
        custom_memcpy(loader.public_key, md->public_key, sizeof(md->public_key));
        /* loader is now initialised... */
        loader.init = true;
    }

    seL4_Error error;

    /* start to parse client elf information */
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)container_elf;
    /* check elf integrity */
    if (custom_memcmp(ehdr->e_ident, (const unsigned char*)ELFMAG, SELFMAG) != 0) {
        microkit_dbg_printf(PROGNAME "Data in shared memory region must be an ELF file\n");
        microkit_internal_crash(-1);
    } else {
        microkit_dbg_printf(PROGNAME "Data in shared memory region is an ELF file\n");
    }
    microkit_dbg_printf(PROGNAME "Verified ELF header\n");

    Elf64_Ehdr *trampoline_ehdr = (Elf64_Ehdr *)trampoline_elf;
    /* check elf integrity */
    if (custom_memcmp(trampoline_ehdr->e_ident, (const unsigned char*)ELFMAG, SELFMAG) != 0) {
        microkit_dbg_printf(PROGNAME "Data in trampoline region must be an ELF file\n");
        microkit_internal_crash(-1);
    } else {
        microkit_dbg_printf(PROGNAME "Data in trampoline region is an ELF file\n");
    }
    microkit_dbg_printf(PROGNAME "Verified ELF header\n");

    /* parse access rights table */
    Elf64_Shdr *shdr = (Elf64_Shdr *)((char*)ehdr + ehdr->e_shoff);
    const char *shstrtab = (char*)ehdr + shdr[ehdr->e_shstrndx].sh_offset;

    char *section = NULL;
    seL4_Word section_size = 0;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *section_name = shstrtab + shdr[i].sh_name;
        if (custom_strcmp(section_name, ".access_rights") == 0) {
            section = (char*)ehdr + shdr[i].sh_offset;
            section_size = shdr[i].sh_size;
            break;
        }
    }

    if (section == NULL) {
        microkit_dbg_printf(PROGNAME ".access_rights section not found in ELF\n");
        microkit_internal_crash(-1);
    }

    /* populate the access rights to the loader */
    error = tsldr_populate_rights(&loader, (unsigned char *)section, section_size);
    if (error) {
        microkit_internal_crash(-1);
    }
    microkit_dbg_printf(PROGNAME "Finished up access rights integrity checking\n");

    tsldr_restore_caps(&loader);

    /* (really) populate allowed access rights */
    error = tsldr_populate_allowed(&loader);
    if (error != seL4_NoError) {
        microkit_internal_crash(-1);
    }

    tsldr_remove_caps(&loader);

    tsldr_loading_epilogue(container_exec, (uintptr_t)0x0);

    load_elf((void *)ehdr->e_entry, ehdr);
    microkit_dbg_printf(PROGNAME "Load client elf to the targeting memory region\n");

    load_elf((void *)trampoline_ehdr->e_entry, trampoline_ehdr);
    microkit_dbg_printf(PROGNAME "Load trampoline elf to the targeting memory region\n");

    /* -- now we are ready to jump to the trampoline -- */

    microkit_dbg_printf(PROGNAME "Switch to the trampoline's code to execute\n");
    entry_fn_t entry_fn = (entry_fn_t) trampoline_ehdr->e_entry;

    /* jump tp trampoline */
    asm volatile (
        "mov sp, %[new_stack]\n\t" /* set new SP */
        "br  %[func]\n\t"          /* branch directly, never return */
        :
        : [new_stack] "r" (trampoline_stack_top),
          [func] "r" (entry_fn)
        : "x30", "memory"
    );
    __builtin_unreachable();
}

void notified(microkit_channel ch)
{
    microkit_dbg_printf(PROGNAME "Received notification on channel: %d\n", ch);
}

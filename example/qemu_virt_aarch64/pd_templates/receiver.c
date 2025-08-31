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

#define PROGNAME "[receiver] "

#define NOTIFICATION_BASE_CAP   10

#define PROG_TCB    (10+64+64+64)

/* 4KB in size, read-only */
uintptr_t tsldr_metadata = 0x4000000;
static uintptr_t client_elf = 0xA000000;

typedef void (*entry_fn_t)(void);

trusted_loader_t loader;

static void load_elf(void *dest_vaddr, const Elf64_Ehdr *ehdr)
{
    microkit_dbg_printf(PROGNAME "Start to load ELF segments into memory\n");

    Elf64_Phdr *phdr = (Elf64_Phdr *)((char*)ehdr + ehdr->e_phoff);

    /* the last section is access right table */
    for (int i = 0; i < ehdr->e_phnum - 1; i++) {
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

    /* initialise the real trusted loader... */
    if (loader.init != true) {
        tsldr_init(&loader, ed25519_verify, md->system_hash, sizeof(seL4_Word), 64);
        custom_memcpy(loader.public_key, md->public_key, sizeof(md->public_key));
        /* loader is now initialised... */
        loader.init = true;
    }

    tsldr_loading_prologue(&loader);

    seL4_Error error;

    /* start to parse client elf information */
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)client_elf;
    /* check elf integrity */
    if (custom_memcmp(ehdr->e_ident, (const unsigned char*)ELFMAG, SELFMAG) != 0) {
        microkit_dbg_printf(PROGNAME "Data in shared memory region must be an ELF file\n");
        microkit_internal_crash(-1);
    } else {
        microkit_dbg_printf(PROGNAME "Data in shared memory region is an ELF file\n");
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


    /* (really) populate allowed access rights */
    error = tsldr_populate_allowed(&loader);
    if (error != seL4_NoError) {
        microkit_internal_crash(-1);
    }


    tsldr_remove_caps(&loader);

    tsldr_loading_epilogue();

    load_elf((void *)ehdr->e_entry, ehdr);
    microkit_dbg_printf(PROGNAME "Load client elf to the targeting memory region\n");

    microkit_dbg_printf(PROGNAME "Switch to the client's code to execute\n");
    entry_fn_t entry_fn = (entry_fn_t) ehdr->e_entry;
    entry_fn();
}

void notified(microkit_channel ch)
{
    microkit_dbg_printf(PROGNAME "Received notification on channel: %d\n", ch);
}

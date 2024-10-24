/*
 * Copyright 2021, Breakaway Consulting Pty. Ltd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdint.h>
#include <microkit.h>

#define PROGNAME "[trusted_loader] "

uintptr_t sender_program;
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

void put64(uint64_t num)
{
    microkit_dbg_puts("0x");

    int started = 0;

    for (int shift = 60; shift >= 0; shift -= 4)
    {
        uint8_t nibble = (num >> shift) & 0xF;

        if (nibble != 0 || started || shift == 0)
        {
            started = 1;

            char hex_char;
            if (nibble < 10)
            {
                hex_char = '0' + nibble;
            }
            else
            {
                hex_char = 'a' + (nibble - 10);
            }

            microkit_dbg_putc(hex_char);
        }
    }
}

typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uintptr_t e_entry;
    uintptr_t e_phoff;
    uintptr_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uintptr_t p_offset;
    uintptr_t p_vaddr;
    uintptr_t p_paddr;
    uintptr_t p_filesz;
    uintptr_t p_memsz;
    uintptr_t p_align;
} Elf64_Phdr;

#define PT_LOAD 1

uint64_t calculate_elf_size(uint8_t *elf_data) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_data;
    
    if (ehdr->e_ident[0] != 0x7F || 
        ehdr->e_ident[1] != 'E' || 
        ehdr->e_ident[2] != 'L' || 
        ehdr->e_ident[3] != 'F') {
        microkit_dbg_puts("error: invalid ELF file\n");
        return 0;
    }
    
    uint64_t total_size = 0;
    Elf64_Phdr *phdr = (Elf64_Phdr *)(elf_data + ehdr->e_phoff);
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            uint64_t end = phdr[i].p_offset + phdr[i].p_filesz;
            if (end > total_size) {
                total_size = end;
            }
        }
    }
    
    return total_size;
}

void init(void)
{
    microkit_dbg_puts(PROGNAME "init called\n");
    microkit_dbg_puts(PROGNAME "system_hash is ");
    put64(system_hash);
    microkit_dbg_puts("\n");

    microkit_dbg_puts(PROGNAME "user_program is ");
    put64(sender_program);
    microkit_dbg_puts("\n");

    uint8_t *elf_data = (uint8_t *)sender_program;
    microkit_dbg_puts("first byte: ");
    put8(*(elf_data));
    microkit_dbg_puts("\n");
    uint64_t elf_size = calculate_elf_size(elf_data);
    
    if (elf_size == 0) {
        microkit_dbg_puts(PROGNAME "error: failed to determine ELF size\n");
        return;
    }
    
    microkit_dbg_puts(PROGNAME "determined ELF size to be ");
    put64(elf_size);
    microkit_dbg_puts("\n");

    // microkit_pd_stop(1);
    // microkit_dbg_puts(PROGNAME "stopped child pd\n");

    microkit_dbg_puts(PROGNAME "init finished\n");
}

void notified(microkit_channel ch)
{
    microkit_dbg_puts(PROGNAME "received notification on channel ");
    put8(ch);
    microkit_dbg_puts("\n");
}

seL4_MessageInfo_t protected(microkit_channel ch, microkit_msginfo msginfo)
{
    microkit_dbg_puts(PROGNAME "received protected message on channel ");
    put8(ch);
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

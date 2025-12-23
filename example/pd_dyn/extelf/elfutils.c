/*
 * Copyright 2025, UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <microkit.h>
#include <stdarg.h>

#include "include/elfspec.h"

// Custom memcmp function since string.h is not available
int custom_memcmp(const unsigned char* s1, const unsigned char* s2, int n)
{
    for (int i = 0; i < n; i++) {
        if (s1[i] != s2[i]) {
            return (s1[i] - s2[i]);
        }
    }
    return 0;
}

// Helper function to translate ELF type to string
const char* get_elf_type(uint16_t type)
{
    switch (type) {
        case ET_NONE: return "NONE (No file type)";
        case ET_REL:  return "REL (Relocatable file)";
        case ET_EXEC: return "EXEC (Executable file)";
        case ET_DYN:  return "DYN (Shared object file)";
        case ET_CORE: return "CORE (Core file)";
        default:      return "UNKNOWN";
    }
}

// Helper function to translate ELF data encoding to string
const char* get_elf_data_encoding(uint8_t data)
{
    switch (data) {
        case ELFDATA2LSB: return "Little endian";
        case ELFDATA2MSB: return "Big endian";
        default:          return "Unknown";
    }
}

// Helper function to translate ELF OS/ABI to string
const char* get_elf_osabi(uint8_t osabi)
{
    switch (osabi) {
        case ELFOSABI_LINUX:      return "UNIX - Linux";
        default:                   return "Unknown";
    }
}

// Helper function to translate ELF version to string
const char* get_elf_version(uint32_t version)
{
    switch (version) {
        case EV_CURRENT: return "Current";
        default:         return "Unknown";
    }
}

void* custom_memcpy(void* dest, const void* src, uint64_t n)
{
    uint8_t* d = (uint8_t*)dest;
    const uint8_t* s = (const uint8_t*)src;
    for (uint64_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dest;
}

void custom_memset(void *dest, int value, uint64_t size)
{
    unsigned char *d = (unsigned char *)dest;
    for (uint64_t i = 0; i < size; i++) {
        d[i] = (unsigned char)value;
    }
}

int custom_strcmp(const char *str1, const char *str2)
{
    while (*str1 && *str2) {
        if (*str1 != *str2) {
            return 1;
        }
        str1++;
        str2++;
    }

    return *str1 != '\0' || *str2 != '\0';
}

void load_elf(void *dest_vaddr, const Elf64_Ehdr *ehdr)
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
}

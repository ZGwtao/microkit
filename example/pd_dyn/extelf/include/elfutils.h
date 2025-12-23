#ifndef ELF_CHECKER_H
#define ELF_CHECKER_H

#include <stdint.h>
#include <elfspec.h>

void* custom_memcpy(void* dest, const void* src, uint64_t n);
void custom_memset(void *dest, int value, uint64_t size);
int custom_strcmp(const char *str1, const char *str2);
int custom_memcmp(const unsigned char* s1, const unsigned char* s2, int n);

void load_elf(void *dest_vaddr, const Elf64_Ehdr *ehdr);

#endif /* ELF_CHECKER_H */

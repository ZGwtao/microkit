#ifndef ELF_CHECKER_H
#define ELF_CHECKER_H

#include <stdint.h>

// Define ELF constants manually since elf.h is not available
// #define ELFMAG0 0x7F
// #define ELFMAG1 'E'
// #define ELFMAG2 'L'
// #define ELFMAG3 'F'
// // #define SELFMAG 4

// #define EI_CLASS        4
// #define EI_DATA         5
// #define EI_VERSION      6
// #define EI_OSABI        7
// #define EI_ABIVERSION   8

// #define ELFCLASS32      1
// #define ELFCLASS64      2

// #define ELFDATA2LSB     1
// #define ELFDATA2MSB     2

// #define EV_CURRENT      1

// // ELF Types
// #define ET_NONE         0
// #define ET_REL          1
// #define ET_EXEC         2
// #define ET_DYN          3
// #define ET_CORE         4

// // ELF Machines
// #define EM_NONE         0
// #define EM_M32          1
// #define EM_SPARC        2
// #define EM_386          3
// #define EM_68K          4
// #define EM_88K          5
// #define EM_AARCH64      183
// #define EM_X86_64       62

// // ELF OS/ABI
// #define ELFOSABI_SYSV       0
// #define ELFOSABI_HPUX       1
// #define ELFOSABI_NETBSD     2
// #define ELFOSABI_LINUX      3
// #define ELFOSABI_SOLARIS    6
// #define ELFOSABI_FREEBSD    9
// #define ELFOSABI_ARM_AEABI  97

// Define ELF Header structures manually

// // 32-bit ELF Header
// typedef struct {
//     unsigned char e_ident[16]; /* ELF identification */
//     uint16_t e_type;           /* Object file type */
//     uint16_t e_machine;        /* Machine type */
//     uint32_t e_version;        /* Object file version */
//     uint32_t e_entry;          /* Entry point address */
//     uint32_t e_phoff;          /* Program header offset */
//     uint32_t e_shoff;          /* Section header offset */
//     uint32_t e_flags;          /* Processor-specific flags */
//     uint16_t e_ehsize;         /* ELF header size */
//     uint16_t e_phentsize;      /* Size of program header entry */
//     uint16_t e_phnum;          /* Number of program header entries */
//     uint16_t e_shentsize;      /* Size of section header entry */
//     uint16_t e_shnum;          /* Number of section header entries */
//     uint16_t e_shstrndx;       /* Section name string table index */
// } Elf32_Ehdr;

// // 64-bit ELF Header
// typedef struct {
//     unsigned char e_ident[16]; /* ELF identification */
//     uint16_t e_type;           /* Object file type */
//     uint16_t e_machine;        /* Machine type */
//     uint32_t e_version;        /* Object file version */
//     uint64_t e_entry;          /* Entry point address */
//     uint64_t e_phoff;          /* Program header offset */
//     uint64_t e_shoff;          /* Section header offset */
//     uint32_t e_flags;          /* Processor-specific flags */
//     uint16_t e_ehsize;         /* ELF header size */
//     uint16_t e_phentsize;      /* Size of program header entry */
//     uint16_t e_phnum;          /* Number of program header entries */
//     uint16_t e_shentsize;      /* Size of section header entry */
//     uint16_t e_shnum;          /* Number of section header entries */
//     uint16_t e_shstrndx;       /* Section name string table index */
// } Elf64_Ehdr;

// Function Prototypes

/**
 * @brief Checks whether the ELF file is valid and prints its information.
 *
 * @param _receiver Pointer to the start of the ELF file in memory.
 * @param _receiver_end Pointer to the end of the ELF file in memory.
 */
void print_elf(const char* _receiver, const char* _receiver_end);

/**
 * @brief Outputs a hexadecimal representation of a number.
 *
 * @param num The number to convert and output in hexadecimal.
 */
void puthex(uint64_t num);

/**
 * @brief Outputs a decimal representation of a number.
 *
 * @param num The number to convert and output in decimal.
 */
void putdec(uint64_t num);

void* custom_memcpy(void* dest, const void* src, uint64_t n);
void custom_memset(void *dest, int value, uint64_t size);
int custom_strcmp(const char *str1, const char *str2);
void putvar(uint64_t var, char* name);
void debug_printf(const char *format, ...);

#endif /* ELF_CHECKER_H */

#include "elf_utils.h"
#include <microkit.h>

// Utility function to output a hexadecimal number
void puthex(uint64_t num) {
    char buffer[17]; // Maximum 16 hex digits for 64-bit + null terminator
    int i = 16;
    buffer[i] = '\0';
    if (num == 0) {
        buffer[--i] = '0';
    } else {
        while (num > 0 && i > 0) {
            uint8_t digit = num % 16;
            if (digit < 10) {
                buffer[--i] = '0' + digit;
            } else {
                buffer[--i] = 'a' + (digit - 10);
            }
            num /= 16;
        }
    }
    microkit_dbg_puts("0x");
    microkit_dbg_puts(&buffer[i]);
}

// Utility function to output a decimal number
void putdec(uint64_t num) {
    char buffer[21]; // Maximum 20 digits for uint64_t + null terminator
    int i = 20;
    buffer[i] = '\0';
    if (num == 0) {
        buffer[--i] = '0';
    } else {
        while (num > 0 && i > 0) {
            uint8_t digit = num % 10;
            buffer[--i] = '0' + digit;
            num /= 10;
        }
    }
    microkit_dbg_puts(&buffer[i]);
}

// Custom memcmp function since string.h is not available
int memcmp_custom(const unsigned char* s1, const unsigned char* s2, int n) {
    for (int i = 0; i < n; i++) {
        if (s1[i] != s2[i]) {
            return (s1[i] - s2[i]);
        }
    }
    return 0;
}

// Helper function to translate ELF type to string
const char* get_elf_type(uint16_t type) {
    switch (type) {
        case ET_NONE: return "NONE (No file type)";
        case ET_REL:  return "REL (Relocatable file)";
        case ET_EXEC: return "EXEC (Executable file)";
        case ET_DYN:  return "DYN (Shared object file)";
        case ET_CORE: return "CORE (Core file)";
        default:      return "UNKNOWN";
    }
}

// Helper function to translate ELF machine to string
const char* get_elf_machine(uint16_t machine) {
    switch (machine) {
        case EM_NONE:        return "No machine";
        case EM_M32:         return "AT&T WE 32100";
        case EM_SPARC:       return "Sparc";
        case EM_386:         return "Intel 80386";
        case EM_68K:         return "Motorola 68000";
        case EM_88K:         return "Motorola 88000";
        case EM_AARCH64:     return "ARM AARCH64";
        case EM_X86_64:      return "AMD x86-64";
        // Add more cases as needed
        default:             return "UNKNOWN";
    }
}

// Helper function to translate ELF data encoding to string
const char* get_elf_data_encoding(uint8_t data) {
    switch (data) {
        case ELFDATA2LSB: return "Little endian";
        case ELFDATA2MSB: return "Big endian";
        default:          return "Unknown";
    }
}

// Helper function to translate ELF OS/ABI to string
const char* get_elf_osabi(uint8_t osabi) {
    switch (osabi) {
        case ELFOSABI_SYSV:       return "UNIX - System V";
        case ELFOSABI_HPUX:       return "UNIX - HP-UX";
        case ELFOSABI_NETBSD:     return "UNIX - NetBSD";
        case ELFOSABI_LINUX:      return "UNIX - Linux";
        case ELFOSABI_SOLARIS:    return "UNIX - Solaris";
        case ELFOSABI_FREEBSD:    return "UNIX - FreeBSD";
        case ELFOSABI_ARM_AEABI:  return "ARM EABI";
        // Add more cases as needed
        default:                   return "Unknown";
    }
}

// Helper function to translate ELF version to string
const char* get_elf_version(uint32_t version) {
    switch (version) {
        case EV_CURRENT: return "Current";
        default:         return "Unknown";
    }
}

// Function to check and print ELF info
void print_elf(const char* _receiver, const char* _receiver_end) {
    // Calculate the size of the ELF data
    long elf_size = _receiver_end - _receiver;
    if (elf_size < (long)(sizeof(Elf32_Ehdr))) {
        microkit_dbg_puts("Error: ELF data is too small to contain an ELF header.\n");
        return;
    }

    // Check ELF magic numbers
    if (memcmp_custom((const unsigned char*)_receiver, (const unsigned char*)"\x7F""ELF", SELFMAG) != 0) {
        microkit_dbg_puts("Error: Invalid ELF magic numbers.\n");
        return;
    }

    // Get the ELF identification bytes
    const unsigned char* e_ident = (const unsigned char*)_receiver;

    // Determine ELF class (32-bit or 64-bit)
    if (e_ident[EI_CLASS] == ELFCLASS32) {
        if (elf_size < (long)(sizeof(Elf32_Ehdr))) {
            microkit_dbg_puts("Error: ELF data is too small for Elf32_Ehdr.\n");
            return;
        }

        const Elf32_Ehdr* ehdr32 = (const Elf32_Ehdr*)_receiver;

        microkit_dbg_puts("----- ELF Header (32-bit) -----\n");
        microkit_dbg_puts("  Class:                             ELF32\n");
        microkit_dbg_puts("  Data Encoding:                     ");
        microkit_dbg_puts(get_elf_data_encoding(e_ident[EI_DATA]));
        microkit_dbg_putc('\n');

        microkit_dbg_puts("  Version:                           ");
        putdec(e_ident[EI_VERSION]);
        microkit_dbg_putc('\n');

        microkit_dbg_puts("  OS/ABI:                            ");
        microkit_dbg_puts(get_elf_osabi(e_ident[EI_OSABI]));
        microkit_dbg_putc('\n');

        microkit_dbg_puts("  ABI Version:                       ");
        putdec(e_ident[EI_ABIVERSION]);
        microkit_dbg_putc('\n');

        // Verify ELF version
        if (e_ident[EI_VERSION] != EV_CURRENT) {
            microkit_dbg_puts("Error: Unsupported ELF version.\n");
            return;
        }

        microkit_dbg_puts("  Type:                              ");
        microkit_dbg_puts(get_elf_type(ehdr32->e_type));
        microkit_dbg_putc('\n');

        microkit_dbg_puts("  Machine:                           ");
        microkit_dbg_puts(get_elf_machine(ehdr32->e_machine));
        microkit_dbg_putc('\n');

        microkit_dbg_puts("  Entry Point Address:               0x");
        puthex((uint64_t)(ehdr32->e_entry));
        microkit_dbg_putc('\n');

        microkit_dbg_puts("  Start of Program Headers:          ");
        putdec(ehdr32->e_phoff);
        microkit_dbg_puts(" (bytes into file)\n");

        microkit_dbg_puts("  Start of Section Headers:          ");
        putdec(ehdr32->e_shoff);
        microkit_dbg_puts(" (bytes into file)\n");

        microkit_dbg_puts("  Flags:                             0x");
        puthex((uint64_t)(ehdr32->e_flags));
        microkit_dbg_putc('\n');

        microkit_dbg_puts("  Size of this Header:               ");
        putdec(ehdr32->e_ehsize);
        microkit_dbg_puts(" (bytes)\n");

        microkit_dbg_puts("  Size of Program Headers:           ");
        putdec(ehdr32->e_phentsize);
        microkit_dbg_puts(" (bytes)\n");

        microkit_dbg_puts("  Number of Program Headers:         ");
        putdec(ehdr32->e_phnum);
        microkit_dbg_putc('\n');

        microkit_dbg_puts("  Size of Section Headers:           ");
        putdec(ehdr32->e_shentsize);
        microkit_dbg_puts(" (bytes)\n");

        microkit_dbg_puts("  Number of Section Headers:         ");
        putdec(ehdr32->e_shnum);
        microkit_dbg_putc('\n');

        microkit_dbg_puts("  Section Header String Table Index: ");
        putdec(ehdr32->e_shstrndx);
        microkit_dbg_putc('\n');

    } else if (e_ident[EI_CLASS] == ELFCLASS64) {
        if (elf_size < (long)(sizeof(Elf64_Ehdr))) {
            microkit_dbg_puts("Error: ELF data is too small for Elf64_Ehdr.\n");
            return;
        }

        const Elf64_Ehdr* ehdr64 = (const Elf64_Ehdr*)_receiver;

        microkit_dbg_puts("----- ELF Header (64-bit) -----\n");
        microkit_dbg_puts("  Start address:                     ");
        puthex((uint64_t)_receiver);
        microkit_dbg_putc('\n');
        microkit_dbg_puts("  End address:                       ");
        puthex((uint64_t)_receiver_end);
        microkit_dbg_putc('\n');
        microkit_dbg_puts("  Size:                              ");
        putdec(elf_size);
        microkit_dbg_puts(" (bytes)\n");
        microkit_dbg_puts("  Class:                             ELF64\n");
        microkit_dbg_puts("  Data Encoding:                     ");
        microkit_dbg_puts(get_elf_data_encoding(e_ident[EI_DATA]));
        microkit_dbg_putc('\n');

        microkit_dbg_puts("  Version:                           ");
        putdec(e_ident[EI_VERSION]);
        microkit_dbg_putc('\n');

        microkit_dbg_puts("  OS/ABI:                            ");
        microkit_dbg_puts(get_elf_osabi(e_ident[EI_OSABI]));
        microkit_dbg_putc('\n');

        microkit_dbg_puts("  ABI Version:                       ");
        putdec(e_ident[EI_ABIVERSION]);
        microkit_dbg_putc('\n');

        // Verify ELF version
        if (e_ident[EI_VERSION] != EV_CURRENT) {
            microkit_dbg_puts("Error: Unsupported ELF version.\n");
            return;
        }

        microkit_dbg_puts("  Type:                              ");
        microkit_dbg_puts(get_elf_type(ehdr64->e_type));
        microkit_dbg_putc('\n');

        microkit_dbg_puts("  Machine:                           ");
        microkit_dbg_puts(get_elf_machine(ehdr64->e_machine));
        microkit_dbg_putc('\n');

        microkit_dbg_puts("  Entry Point Address:               0x");
        puthex(ehdr64->e_entry);
        microkit_dbg_putc('\n');

        microkit_dbg_puts("  Start of Program Headers:          ");
        putdec(ehdr64->e_phoff);
        microkit_dbg_puts(" (bytes into file)\n");

        microkit_dbg_puts("  Start of Section Headers:          ");
        putdec(ehdr64->e_shoff);
        microkit_dbg_puts(" (bytes into file)\n");

        microkit_dbg_puts("  Flags:                             0x");
        puthex((uint64_t)(ehdr64->e_flags));
        microkit_dbg_putc('\n');

        microkit_dbg_puts("  Size of this Header:               ");
        putdec(ehdr64->e_ehsize);
        microkit_dbg_puts(" (bytes)\n");

        microkit_dbg_puts("  Size of Program Headers:           ");
        putdec(ehdr64->e_phentsize);
        microkit_dbg_puts(" (bytes)\n");

        microkit_dbg_puts("  Number of Program Headers:         ");
        putdec(ehdr64->e_phnum);
        microkit_dbg_putc('\n');

        microkit_dbg_puts("  Size of Section Headers:           ");
        putdec(ehdr64->e_shentsize);
        microkit_dbg_puts(" (bytes)\n");

        microkit_dbg_puts("  Number of Section Headers:         ");
        putdec(ehdr64->e_shnum);
        microkit_dbg_putc('\n');

        microkit_dbg_puts("  Section Header String Table Index: ");
        putdec(ehdr64->e_shstrndx);
        microkit_dbg_putc('\n');

    } else {
        microkit_dbg_puts("Error: Unknown ELF class.\n");
        return;
    }

    // Basic validation passed
    microkit_dbg_puts("ELF file is valid.\n");
}

void* custom_memcpy(void* dest, const void* src, uint64_t n) {
    uint8_t* d = (uint8_t*)dest;
    const uint8_t* s = (const uint8_t*)src;
    for (uint64_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dest;
}

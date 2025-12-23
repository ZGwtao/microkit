/*
 * Copyright 2025, UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdint.h>
#include <stdarg.h>
#include <microkit.h>
#include <elfutils.h>

uint64_t com1_ioport_id;
uint64_t com1_ioport_addr;

// Shared memory regions with the dynamic PD...
uint64_t image_client_payload   = 0x50000000;
uint64_t image_trampoline       = 0x30000000;
uint64_t image_trusted_loader   = 0x10000000;

// Where to get the image of trusted loader
extern char _loader[];
extern char _loader_end[];
// Also, for the client payload (image)...
extern char _payload[];
extern char _payload_end[];
// and the trampoline image...
extern char _trampoline[];
extern char _trampoline_end[];

void microkit_dbg_printf(const char *format, ...);

static inline void serial_putc(char ch)
{
    // Danger: may overflow hardware FIFO, but we are only writing a small message.
    microkit_x86_ioport_write_8(com1_ioport_id, com1_ioport_addr, ch);
}

static inline void serial_puts(const char *s)
{
    while (*s) {
        if (*s == '\n') {
            serial_putc('\r');
        }
        serial_putc(*s++);
    }
}

void init(void)
{
    //microkit_dbg_puts("hello, world. my name is ");
    microkit_dbg_puts(microkit_name);
    microkit_dbg_puts("\n");

    microkit_dbg_puts("Now writing to serial I/O port: ");
    serial_puts("hello!\n");

    // test capDL spec generation and capability distribution...
    seL4_Signal(410);
}

void notified(microkit_channel ch)
{
}

seL4_Bool fault(microkit_child child, microkit_msginfo msginfo, microkit_msginfo *reply_msginfo)
{
    microkit_dbg_printf("Received fault message for child PD: %d\n", child);

    seL4_Word label = microkit_msginfo_get_label(msginfo);
    microkit_dbg_printf("Fault label: %d\n", label);

    if (label == seL4_Fault_VMFault) {
        seL4_Word ip = microkit_mr_get(seL4_VMFault_IP);
        seL4_Word address = microkit_mr_get(seL4_VMFault_Addr);
        microkit_dbg_printf("seL4_Fault_VMFault\n");
        microkit_dbg_printf("Fault address: %x\n", (unsigned long long)address);
        microkit_dbg_printf("Fault instruction pointer: %x\n", (unsigned long long)ip);
        // You can use microkit_pd_restart to restart the child PD...
        if (ip == 0x0) {
            microkit_pd_stop(child);
            microkit_dbg_printf("Restart faulting PD at the entry of trusted loaders...\n");

            Elf64_Ehdr *ehdr = (Elf64_Ehdr *)_loader;
            if (custom_memcmp(ehdr->e_ident, (const unsigned char*)ELFMAG, SELFMAG) != 0) {
                microkit_dbg_printf("Data in shared memory region must be an ELF file\n");
                return seL4_False;
            }
            load_elf((void*)image_trusted_loader, ehdr);
            // FIXME: do sanity checks when the dynamic PD faults on 0x0
            microkit_pd_restart(child, ehdr->e_entry);
            return seL4_False;
        }
    }
    microkit_pd_stop(child);

    // Stop the thread explicitly; no need to reply to the fault
    return seL4_False;
}


/**
 * @brief Outputs an unsigned 64-bit integer in decimal format.
 *
 * @param val The unsigned 64-bit integer to print.
 */
void putdec(uint64_t val) {
    // Buffer to hold the decimal digits (max 20 digits for uint64_t)
    char buffer[21];
    int index = 20; // Start from the end of the buffer
    buffer[index] = '\0'; // Null-terminate the string

    if (val == 0) {
        buffer[--index] = '0';
    } else {
        while (val > 0 && index > 0) {
            buffer[--index] = '0' + (val % 10);
            val /= 10;
        }
    }

    // Output the resulting string
    const char *str = &buffer[index];
    while (*str) {
        microkit_dbg_putc(*str++);
    }
}

/**
 * @brief Outputs an unsigned 64-bit integer in hexadecimal format.
 *
 * @param val The unsigned 64-bit integer to print.
 */
void puthex(uint64_t val) {
    // Prefix for hexadecimal representation
    microkit_dbg_puts("0x");

    // Buffer to hold the hexadecimal digits (max 16 digits for uint64_t)
    char buffer[17];
    int index = 16; // Start from the end of the buffer
    buffer[index] = '\0'; // Null-terminate the string

    if (val == 0) {
        buffer[--index] = '0';
    } else {
        while (val > 0 && index > 0) {
            uint8_t digit = val & 0xF; // Get the last 4 bits
            if (digit < 10) {
                buffer[--index] = '0' + digit;
            } else {
                buffer[--index] = 'a' + (digit - 10);
            }
            val >>= 4; // Shift right by 4 bits to process the next digit
        }
    }

    // Output the resulting string
    const char *str = &buffer[index];
    while (*str) {
        microkit_dbg_putc(*str++);
    }
}

void microkit_dbg_printf(const char *format, ...) {
    va_list args;
    va_start(args, format);

    const char *ptr = format;

    while (*ptr != '\0') {
        if (*ptr == '%') {
            ptr++; // Move past '%'

            switch (*ptr) {
                case 's': {
                    // String
                    const char *str = va_arg(args, const char *);
                    if (str != 0) {
                        microkit_dbg_puts(str);
                    } else {
                        microkit_dbg_puts("(null)");
                    }
                    break;
                }
                case 'd': {
                    // Decimal
                    uint64_t val = va_arg(args, uint64_t);
                    putdec(val);
                    break;
                }
                case 'x': {
                    // Hexadecimal
                    uint64_t val = va_arg(args, uint64_t);
                    puthex(val);
                    break;
                }
                case 'c': {
                    // Character
                    int c = va_arg(args, int); // char is promoted to int
                    microkit_dbg_putc((char)c);
                    break;
                }
                case '%': {
                    // Literal '%'
                    microkit_dbg_putc('%');
                    break;
                }
                default: {
                    // Unsupported format specifier, print it literally
                    microkit_dbg_putc('%');
                    microkit_dbg_putc(*ptr);
                    break;
                }
            }
            ptr++; // Move past format specifier
        } else {
            // Regular character
            microkit_dbg_putc(*ptr);
            ptr++;
        }
    }

    va_end(args);
}



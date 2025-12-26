/*
 * Copyright 2025, UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdint.h>
#include <stdarg.h>
#include <microkit.h>
#include <elfutils.h>
#include <libtrustedlo.h>

uint64_t com1_ioport_id;
uint64_t com1_ioport_addr;

// Shared memory regions with the dynamic PD...
uint64_t image_client_payload   = 0x50000000;
uint64_t image_trampoline       = 0x30000000;
uint64_t image_trusted_loader   = 0x10000000;

#define ELF_FILE_SIZE           0x800000

// Where to get the image of trusted loader
extern char _loader[];
extern char _loader_end[];
// Also, for the client payload (image)...
extern char _payload[];
extern char _payload_end[];
// and the trampoline image...
extern char _trampoline[];
extern char _trampoline_end[];

// A shared memory region with container, containing content from tsldr_metadata_patched
// Will be init each time the container restarts by copying the data from above
uintptr_t tsldr_metadata;
// base of all shared metadata regions
tsldr_md_t *tsldr_metadata_base = (tsldr_md_t *)0xffc0000;

#define PROGNAME "[@monitor] "

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
    serial_puts("hello!\n");

    tsldr_md_array_t *ptr_spec_trusted_loader = (tsldr_md_array_t *)microkit_template_spec;
    microkit_dbg_printf("%d\n", ptr_spec_trusted_loader->avails);
    microkit_dbg_printf("%s\n", microkit_name);

    int num_assert = 0;
    for (int i = 0; i < 16; ++i) {
        // must provide valid hash to 
        if (ptr_spec_trusted_loader->md_array[i].system_hash != 0xffff) {
            // do not initialise unspecified tsldr metadata
            continue;
        }
        num_assert += 1;
        // adjust global pointer
        tsldr_metadata = (uintptr_t)((char *)tsldr_metadata_base + i * 0x1000);
        microkit_dbg_printf(PROGNAME "tsldr_metadata: 0x%x\n", tsldr_metadata);
        // initialise the target tsldr_metadata
        tsldr_init_metadata(ptr_spec_trusted_loader, i);
    }
    if (num_assert != ptr_spec_trusted_loader->avails) {
        microkit_dbg_printf(PROGNAME "avail num: %d - num assert: %d\n", ptr_spec_trusted_loader->avails, num_assert);
        microkit_internal_crash(-1);
    }
    microkit_dbg_printf(PROGNAME "finished template PD initialization\n");
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
            microkit_dbg_printf(PROGNAME "restart faulting PD at the entry of trusted loaders...\n");

            Elf64_Ehdr *ehdr = (Elf64_Ehdr *)_loader;
            if (custom_memcmp(ehdr->e_ident, (const unsigned char*)ELFMAG, SELFMAG) != 0) {
                microkit_dbg_printf("Data in shared memory region must be an ELF file\n");
                return seL4_False;
            }
            microkit_dbg_printf(PROGNAME "trying to load trusted_loader from: %x\n", _loader);
            microkit_dbg_printf(PROGNAME "trying to load payload from: %x\n", _payload);
            microkit_dbg_printf(PROGNAME "trying to load trampoline from: %x\n", _trampoline);

            load_elf((void*)image_trusted_loader, ehdr);
            microkit_dbg_printf(PROGNAME "loaded trusted loader successfully\n");

            custom_memcpy((void*)((uintptr_t)image_client_payload), (char*)_payload, _payload_end - _payload);
            microkit_dbg_printf(PROGNAME "loaded client payload successfully\n");

            custom_memcpy((void*)((uintptr_t)image_trampoline), (char*)_trampoline, _trampoline_end - _trampoline);
            microkit_dbg_printf(PROGNAME "loaded trampoline payload successfully\n");

            // FIXME: do sanity checks when the dynamic PD faults on 0x0
            microkit_pd_restart(child, ehdr->e_entry);
            return seL4_False;
        }
    }
    microkit_pd_stop(child);

    // Stop the thread explicitly; no need to reply to the fault
    return seL4_False;
}

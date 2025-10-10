
#include "elf_utils.h"
#include <stdint.h>
#include <microkit.h>

#define PROGNAME "[sender_loader] "

uintptr_t shared1;
uintptr_t shared2;

extern char _container[];
extern char _container_end[];

extern char _client[];
extern char _client_end[];

void init(void)
{
    microkit_dbg_printf(PROGNAME "Entered init\n");

    custom_memcpy((void *)shared1, _container, _container_end - _container);
    microkit_dbg_printf(PROGNAME "Wrote sender's ELF file into memory\n");
    custom_memcpy((void *)shared2, _client, _client_end - _client);
    microkit_dbg_printf(PROGNAME "Wrote client's ELF file into memory\n");

    microkit_dbg_printf(PROGNAME "Making ppc to sender's trusted loader\n");

    microkit_msginfo info;
    seL4_Error error;
    
    microkit_mr_set(0, 1);
    /* setup the first container */
    microkit_mr_set(1, 1);
    info = microkit_ppcall(1, microkit_msginfo_new(0, 2));
    error = microkit_msginfo_get_label(info);
    if (error != seL4_NoError) {
        microkit_internal_crash(error);
    }

    microkit_mr_set(0, 1);
    /* setup the second container */
    microkit_mr_set(1, 2);
    info = microkit_ppcall(1, microkit_msginfo_new(0, 2));
    error = microkit_msginfo_get_label(info);
    if (error != seL4_NoError) {
        microkit_internal_crash(error);
    }

    microkit_dbg_printf(PROGNAME "Finished init\n");
}

void notified(microkit_channel ch)
{
    microkit_dbg_printf(PROGNAME "Received notification on channel: %d\n", ch);
}

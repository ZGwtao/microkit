
#include "elf_utils.h"
#include <stdint.h>
#include <microkit.h>

#define PROGNAME "[sender_loader] "

uintptr_t shared1;
uintptr_t shared2;

extern char _sender[];
extern char _sender_end[];

extern char _client[];
extern char _client_end[];

void init(void)
{
    while (1);
    microkit_dbg_printf(PROGNAME "Entered init\n");

    custom_memcpy((void *)shared1, _sender, _sender_end - _sender);
    microkit_dbg_printf(PROGNAME "Wrote sender's ELF file into memory\n");
    custom_memcpy((void *)shared2, _client, _client_end - _client);
    microkit_dbg_printf(PROGNAME "Wrote client's ELF file into memory\n");

    microkit_dbg_printf(PROGNAME "Making ppc to sender's trusted loader\n");

    microkit_msginfo info;
    seL4_Error error;
    
    info = microkit_ppcall(1, microkit_msginfo_new(0, 0));
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

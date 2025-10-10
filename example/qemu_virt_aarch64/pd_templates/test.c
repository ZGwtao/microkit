#include <microkit.h>
#include <elf_utils.h>

void init(void)
{
    microkit_dbg_puts("Hello from test!\n");

    *((seL4_Word *)0xD000000) = 0x10;

    microkit_notify(5);
    microkit_notify(4);
    microkit_notify(3);
    microkit_notify(2);
}

void notified(microkit_channel ch)
{
    microkit_dbg_printf("Received notification on channel: %d\n", ch);
}

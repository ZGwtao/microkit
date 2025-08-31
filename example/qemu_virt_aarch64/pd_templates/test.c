#include <microkit.h>

void init(void)
{
    microkit_dbg_puts("Hello from test!\n");

    *((seL4_Word *)0xD000000) = 0x10;

    microkit_notify(3);
}

void notified(microkit_channel ch)
{
    ;
}

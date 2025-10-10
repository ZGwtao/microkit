#include <microkit.h>

void init(void)
{
    microkit_dbg_puts("Hello from client!\n");

    *((seL4_Word *)0xC000000) = 0x10;

    microkit_notify(2);
    microkit_notify(3);
    microkit_notify(4);
    microkit_notify(5);
}

void notified(microkit_channel ch)
{
    ;
}

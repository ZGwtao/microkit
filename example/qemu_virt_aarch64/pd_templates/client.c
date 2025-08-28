#include <microkit.h>

void init(void)
{
    microkit_dbg_puts("Hello from client!\n");
    microkit_notify(2);
}

void notified(microkit_channel ch)
{
    ;
}

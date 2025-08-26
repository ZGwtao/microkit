#include <microkit.h>

void init(void)
{
    microkit_dbg_puts("Hello from client!\n");
}

void notified(microkit_channel ch)
{
    ;
}

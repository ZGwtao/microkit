/*
 * Copyright 2026, UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdint.h>
#include <stddef.h>
#include <microkit.h>
#include <assert.h>

#include "benchmark.h"
#include "config.h"

void init(void)
{
#if 1
    seL4_Word badge;
    seL4_MessageInfo_t tag UNUSED;
    cycles_t start;
    cycles_t end;

    for (;;) {
        //seL4_Signal(BASE_OUTPUT_NOTIFICATION_CAP + 4);
        microkit_ppcall(2, microkit_msginfo_new(0, 0));
        //print("notified from manager\n");
    }

    /* tell the interference controller that the remote core is started. */
    seL4_Signal(BASE_OUTPUT_NOTIFICATION_CAP + 4);
#endif
    for (;;) {
        microkit_ppcall(2, microkit_msginfo_new(0, 0));
    }
}

DECLARE_SUBVERTED_MICROKIT()

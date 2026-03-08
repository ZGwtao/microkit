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

uintptr_t results;

void init(void)
{
    seL4_Word badge;
    seL4_MessageInfo_t tag UNUSED;
    cycles_t start;
    cycles_t end;

    print("hello world\n");

    /* wait for start notification */
    tag = seL4_Recv(INPUT_CAP, &badge, REPLY_CAP);

    print("received from manager\n");
#if 0
    seL4_Signal(BASE_OUTPUT_NOTIFICATION_CAP + 4);

    print("sent signal to remote client\n");

    for (;;) {
        /* wait for remote client's notification to start local client */
        tag = seL4_Recv(INPUT_CAP, &badge, REPLY_CAP);
        print("received from remote client\n");
    }

    while (1);
#endif
    microkit_notify(1);

    print("notified local client\n");

    /* wait for local client's notification to finish */
    tag = seL4_Recv(INPUT_CAP, &badge, REPLY_CAP);

    print("received results from local client\n");

    microkit_notify(BENCHMARK_START_STOP_CH);
}

DECLARE_SUBVERTED_MICROKIT()

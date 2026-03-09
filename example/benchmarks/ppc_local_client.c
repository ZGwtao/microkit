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

#define PPC_HI_LO_CHANNEL 2

uintptr_t results;

void init(void)
{
    seL4_Word badge;
    seL4_MessageInfo_t tag UNUSED;
    cycles_t start;
    cycles_t end;
    result_t *r = (result_t *)results;
    seL4_Word *sum = &r->sum;
    r->sum = 0;

    /* wait for start notification */
    tag = seL4_Recv(INPUT_CAP, &badge, REPLY_CAP);
    print("received signal from timer\n");

    for (size_t i = 0; i < NUM_WARMUP; i++) {
        seL4_Call(BASE_ENDPOINT_CAP + PPC_HI_LO_CHANNEL, microkit_msginfo_new(0, 0));
    }

    print("finished warmup\n");

    microkit_notify(4);
    tag = seL4_Recv(INPUT_CAP, &badge, REPLY_CAP);
    for (;;) {
        seL4_Call(BASE_ENDPOINT_CAP + PPC_HI_LO_CHANNEL, microkit_msginfo_new(0, 0));
        *sum += 1;
    }
}

DECLARE_SUBVERTED_MICROKIT()

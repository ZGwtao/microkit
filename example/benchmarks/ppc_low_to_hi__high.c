/*
 * Copyright 2026, UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdint.h>
#include <stdbool.h>
#include <microkit.h>

#include "benchmark.h"

#define PPC_HI_LO_CHANNEL 1

void init(void)
{
    print("hello world\n");

    seL4_Word badge;
    seL4_MessageInfo_t tag UNUSED;

    /* Get initialised */
    tag = seL4_Recv(INPUT_CAP, &badge, REPLY_CAP);

    /* To make this simpler this literally just always replies */
    while (true) {
        /* We don't do any measurements here */
        tag = seL4_ReplyRecv(INPUT_CAP, microkit_msginfo_new(0, 0), &badge, REPLY_CAP);
    }
}

DECLARE_SUBVERTED_MICROKIT()

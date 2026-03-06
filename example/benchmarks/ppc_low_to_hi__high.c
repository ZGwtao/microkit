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
}

DECLARE_SUBVERTED_MICROKIT()

microkit_msginfo protected(microkit_channel ch, microkit_msginfo msginfo)
{
    seL4_Word badge;
    seL4_MessageInfo_t tag UNUSED;
    seL4_MessageInfo_t reply_tag;
    /* To make this simpler this literally just always replies */
    while (true) {
        /* We don't do any measurements here */
        tag = seL4_ReplyRecv(INPUT_CAP, reply_tag, &badge, REPLY_CAP);
    }
    return seL4_MessageInfo_new(0, 0, 0, 0);
}

/*
 * Copyright 2026, UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <microkit.h>
#include <assert.h>

#include "benchmark.h"
#include "config.h"

uintptr_t results;

#if 1
uintptr_t timer_regs;

#define TIMER_IRQ_CH 5

#define TIMER_REG_START   0x140

#define TIMER_A_INPUT_CLK 0
#define TIMER_E_INPUT_CLK 8
#define TIMER_A_EN      (1 << 16)
#define TIMER_A_MODE    (1 << 12)

#define TIMESTAMP_TIMEBASE_SYSTEM   0b000
#define TIMESTAMP_TIMEBASE_1_US     0b001
#define TIMESTAMP_TIMEBASE_10_US    0b010
#define TIMESTAMP_TIMEBASE_100_US   0b011
#define TIMESTAMP_TIMEBASE_1_MS     0b100

#define TIMEOUT_TIMEBASE_1_US   0b00
#define TIMEOUT_TIMEBASE_10_US  0b01
#define TIMEOUT_TIMEBASE_100_US 0b10
#define TIMEOUT_TIMEBASE_1_MS   0b11

#define NS_IN_US    1000ULL
#define NS_IN_MS    1000000ULL

typedef struct {
    uint32_t mux;
    uint32_t timer_a;
    uint32_t timer_b;
    uint32_t timer_c;
    uint32_t timer_d;
    uint32_t unused[13];
    uint32_t timer_e;
    uint32_t timer_e_hi;
    uint32_t mux1;
    uint32_t timer_f;
    uint32_t timer_g;
    uint32_t timer_h;
    uint32_t timer_i;
} meson_timer_reg_t;

typedef struct {
    volatile meson_timer_reg_t *regs;
    bool disable;
} meson_timer_t;

meson_timer_t timer;

uint64_t meson_get_time()
{
    uint64_t initial_high = timer.regs->timer_e_hi;
    uint64_t low = timer.regs->timer_e;
    uint64_t high = timer.regs->timer_e_hi;
    if (high != initial_high) {
        low = timer.regs->timer_e;
    }

    uint64_t ticks = (high << 32) | low;
    uint64_t time = ticks * NS_IN_US;
    return time;
}

void meson_set_timeout(uint16_t timeout, bool periodic)
{
    if (periodic) {
        timer.regs->mux |= TIMER_A_MODE;
    } else {
        timer.regs->mux &= ~TIMER_A_MODE;
    }

    timer.regs->timer_a = timeout;

    if (timer.disable) {
        timer.regs->mux |= TIMER_A_EN;
        timer.disable = false;
    }
}

void meson_stop_timer()
{
    timer.regs->mux &= ~TIMER_A_EN;
    timer.disable = true;
}

#endif

void init(void)
{
    seL4_Word badge;
    seL4_MessageInfo_t tag UNUSED;
    cycles_t start;
    cycles_t end;

    print("hello world\n");
#if 1
    timer.regs = (void *)(timer_regs + TIMER_REG_START);

    timer.regs->mux = TIMER_A_EN | (TIMESTAMP_TIMEBASE_1_US << TIMER_E_INPUT_CLK) |
                      (TIMEOUT_TIMEBASE_1_MS << TIMER_A_INPUT_CLK);

    timer.regs->timer_e = 0;
#endif
    /* wait for start notification */
    tag = seL4_Recv(INPUT_CAP, &badge, REPLY_CAP);

#if 1
    seL4_Signal(BASE_OUTPUT_NOTIFICATION_CAP + 4);

    print("sent signal to local client\n");

    /* wait for local client's notification to finish */
    tag = seL4_Recv(INPUT_CAP, &badge, REPLY_CAP);

    print("received results from local client\n");
#else

    RECORDING_BEGIN();

    for (size_t i = 0; i < NUM_WARMUP; i++) {
        start = pmu_read_cycles();
        seL4_Call(BASE_ENDPOINT_CAP + 2, microkit_msginfo_new(0, 0));
        end = pmu_read_cycles();

        asm volatile("" :: "r"(start), "r"(end));
    }

    for (size_t i = 0; i < NUM_SAMPLES; i++) {

        /* ==== Benchmark critical ==== */
        {
            start = pmu_read_cycles();
            /* Call high (does not switch threads) */
            seL4_Call(BASE_ENDPOINT_CAP + 2, microkit_msginfo_new(0, 0));
            end = pmu_read_cycles();
        }

        RECORDING_ADD_SAMPLE(start, end);
    }

    RECORDING_END(results);
#endif
    seL4_Signal(BASE_OUTPUT_NOTIFICATION_CAP + 4);

    pmu_enable();


    meson_set_timeout(10000, false);
    seL4_Word s = pmu_read_cycles();

    seL4_Recv(INPUT_CAP, &badge, REPLY_CAP);

    seL4_Word e = pmu_read_cycles();

    microkit_irq_ack(5);
    print("sum: ");
    puthex64(((result_t *)results)->sum);
    puts("\n");
    print("start: ");
    puthex64(s);
    puts("\n");
    print("end: ");
    puthex64(e);
    puts("\n");
}

DECLARE_SUBVERTED_MICROKIT()

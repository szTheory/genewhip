/* SPDX-License-Identifier: MIT */
#ifndef GW_PSG_H
#define GW_PSG_H

#include "genewhip/genewhip.h"
#include <stdint.h>

/* One SN76489 update every 16 Z80 clocks: 16 * GW_Z80_DIVIDER (15 master
 * ticks), following the SN76489 documentation at smspower.org and plutiedev.com/psg. */
#define GW_PSG_STEP_TICKS UINT64_C(240)

typedef struct gw_psg {
    uint16_t period[4];
    uint8_t attenuation[4];
    uint8_t latched_register;
    uint16_t counter[3];
    uint8_t output[3];
    uint16_t noise_counter;
    uint16_t lfsr;
    uint8_t noise_output;
    uint64_t next_step_tick;
} gw_psg;

void gw_psg_cold_init(gw_machine *machine);
void gw_psg_console_reset(gw_machine *machine);
void gw_psg_advance(gw_machine *machine, uint64_t tick);
/* Apply one latch/data byte and return its affected register (channel*2+type). */
uint8_t gw_psg_write(gw_machine *machine, uint8_t value);
#ifdef GW_TEST_HOOKS
uint64_t gw_psg_digest(const gw_psg *psg, uint64_t hash);
uint16_t gw_test_psg_lfsr(const gw_machine *machine);
int32_t gw_test_psg_level(const gw_machine *machine);
#endif

#endif

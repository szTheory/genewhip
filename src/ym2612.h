/* SPDX-License-Identifier: BSD-3-Clause
BSD 3-Clause License

Copyright (c) 2021, Aaron Giles
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#ifndef GW_YM2612_H
#define GW_YM2612_H
#include "genewhip/genewhip.h"
#include <stdint.h>
#define GW_FM_SAMPLE_TICKS UINT64_C(1008)
typedef struct gw_ym_cache {
    uint32_t phase_step, total_level, block_freq;
    int32_t detune;
    uint32_t multiple, eg_sustain;
    uint8_t eg_rate[6], eg_shift;
} gw_ym_cache;
typedef struct gw_ym_operator {
    uint32_t choffs, opoffs, phase;
    uint16_t env_attenuation;
    uint32_t env_state;
    uint8_t ssg_inverted, key_state, keyon_live;
    gw_ym_cache cache;
} gw_ym_operator;
typedef struct gw_ym_channel {
    uint32_t choffs;
    int16_t feedback[2], feedback_in;
    uint8_t op[4];
} gw_ym_channel;
typedef struct gw_ym2612 {
    uint32_t lfo_counter;
    uint8_t lfo_am, regdata[512];
    uint16_t waveform[1024];
    uint32_t env_counter;
    uint8_t status, clock_prescale, irq_mask, irq_state;
    uint8_t timer_running[2], total_clocks;
    uint32_t active_channels, modified_channels, prepare_count;
    gw_ym_channel channel[6];
    gw_ym_operator operator[24];
    uint16_t address, dac_data;
    uint8_t dac_enable, reset_held;
    uint64_t next_sample_tick, timer_tick[2], busy_end_tick, advanced_tick;
    int32_t last_output[2];
} gw_ym2612;
void gw_ym2612_cold_init(gw_machine *m);
void gw_ym2612_console_reset(gw_machine *m);
void gw_ym2612_reset_line(gw_machine *m, uint64_t tick, int asserted);
void gw_ym2612_advance(gw_machine *m, uint64_t tick);
void gw_ym2612_write(gw_machine *m, uint32_t port, uint8_t value, uint32_t source);
void gw_ym2612_write_at(gw_machine *m, uint64_t tick, uint32_t port, uint8_t value, uint32_t source);
uint8_t gw_ym2612_read_status(gw_machine *m, uint64_t tick);
/* Native sample seam: unscaled, exact pinned-ymfm output for fidelity tests. */
void gw_ym2612_generate(gw_ym2612 *e, int32_t output[2]);
#ifdef GW_TEST_HOOKS
uint64_t gw_ym2612_digest(const gw_ym2612 *e, uint64_t hash);
void gw_test_ym_write(gw_machine *m, unsigned port, uint8_t value);
void gw_test_ym_release_reset(gw_machine *m);
int gw_test_ym_sample(gw_machine *m, int32_t *left, int32_t *right);
#endif
#endif

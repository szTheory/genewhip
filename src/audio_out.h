/* SPDX-License-Identifier: MIT */
#ifndef GW_AUDIO_OUT_H
#define GW_AUDIO_OUT_H

#include "genewhip/genewhip.h"
#include "audio_kernel.h"
#include <stdint.h>

/* D-55/D-57 and the approved mix-a decision: each bipolar PSG channel has a
 * 2048 peak; four channels sum to +/-8192. Six YM channels map to +/-24576
 * through the integer gain derived alongside the ymfm port in plan 03-17.
 * Saturation counts frames where either stereo channel clips. */
#define GW_MIX_V1_PSG_PEAK INT32_C(2048)
/* Pinned ymfm's 9-bit channel output is clipped to [-257,256], then its
 * ladder discontinuity gives [-260,260]. Six channels times 128*64/(6*65)
 * have full scale 32768. D-55 target 24576 / 32768 reduces to 3/4. */
#define GW_MIX_V1_FM_NUM INT32_C(3)
#define GW_MIX_V1_FM_DEN INT32_C(4)

typedef struct gw_audio {
    uint32_t rate_hz;
    int32_t delta_ring[GW_AUDIO_QUEUE_FRAMES + GW_BLEP_TAPS][2];
    int64_t integrator[2];
    uint64_t finalised_frames;
    int16_t queue[GW_AUDIO_QUEUE_FRAMES][2];
    uint32_t queue_head;
    uint32_t queue_count;
    uint64_t first_index;
    uint64_t lost;
    uint64_t clipped;
    size_t trace_capacity;
    gw_audio_write trace[GW_AUDIO_TRACE_CAPACITY];
    size_t trace_count;
    uint64_t trace_dropped;
} gw_audio;

uint64_t gw_audio_frames_at(uint64_t tick, uint32_t rate_hz);
void gw_audio_cold_init(gw_audio *audio, uint32_t rate_hz);
void gw_audio_add_step(gw_machine *machine, uint64_t step_tick,
    int32_t delta_left, int32_t delta_right);
void gw_audio_sync(gw_machine *machine, uint64_t tick);
void gw_audio_finalise(gw_machine *machine, uint64_t tick);
void gw_audio_trace_record(gw_machine *machine, uint32_t chip, uint32_t reg,
    uint32_t value, uint32_t source);
void gw_audio_trace_record_at(gw_machine *machine, uint64_t tick, uint32_t chip,
    uint32_t reg, uint32_t value, uint32_t source);

#ifdef GW_TEST_HOOKS
uint64_t gw_test_audio_frames_at(uint64_t tick, uint32_t rate_hz);
#endif

#endif

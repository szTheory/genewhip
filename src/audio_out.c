/* SPDX-License-Identifier: MIT */
#include "internal.h"
#include "audio_out.h"
#include <limits.h>

uint64_t gw_audio_frames_at(uint64_t tick, uint32_t rate_hz)
{
    uint64_t q = tick / GW_MASTER_HZ;
    uint64_t r = tick % GW_MASTER_HZ;
    return q * rate_hz + (r * rate_hz) / GW_MASTER_HZ;
}

void gw_audio_cold_init(gw_audio *audio, uint32_t rate_hz)
{
    size_t trace_capacity = audio->trace_capacity;
    memset(audio, 0, sizeof(*audio));
    audio->rate_hz = rate_hz;
    audio->trace_capacity = trace_capacity;
}

void gw_audio_add_step(gw_machine *m, uint64_t step_tick,
    int32_t delta_left, int32_t delta_right)
{
    gw_audio *a = &m->audio;
    uint64_t q, r, product, frame;
    uint32_t phase, j;
    int64_t added_left = 0, added_right = 0;
    const uint32_t ring_frames = GW_AUDIO_QUEUE_FRAMES + GW_BLEP_TAPS;
    if (a->rate_hz == 0 || (delta_left == 0 && delta_right == 0)) return;
    q = step_tick / GW_MASTER_HZ;
    r = step_tick % GW_MASTER_HZ;
    product = r * a->rate_hz;
    frame = q * a->rate_hz + product / GW_MASTER_HZ;
    phase = (uint32_t)((product % GW_MASTER_HZ) * GW_BLEP_PHASES / GW_MASTER_HZ);

    /* audio_kernel.h stores the cumulative step response. Inject its adjacent
     * differences into the integrator's delta ring so one step sums to delta. */
    for (j = 0; j < GW_BLEP_TAPS; ++j) {
        int32_t prior = j ? gw_blep_kernel[phase][j - 1] : 0;
        int32_t impulse = gw_blep_kernel[phase][j] - prior;
        uint32_t slot = (uint32_t)((frame + j) % ring_frames);
        int32_t left, right;
        if (j + 1u == GW_BLEP_TAPS) {
            left = (int32_t)(delta_left - added_left);
            right = (int32_t)(delta_right - added_right);
        } else {
            left = (int32_t)((int64_t)delta_left * impulse / GW_BLEP_SCALE);
            right = (int32_t)((int64_t)delta_right * impulse / GW_BLEP_SCALE);
            added_left += left;
            added_right += right;
        }
        a->delta_ring[slot][0] += left;
        a->delta_ring[slot][1] += right;
    }
}

static int16_t saturate_i16(int64_t value, int *clipped)
{
    if (value > INT16_MAX) { *clipped = 1; return INT16_MAX; }
    if (value < INT16_MIN) { *clipped = 1; return INT16_MIN; }
    return (int16_t)value;
}

void gw_audio_finalise(gw_machine *m, uint64_t tick)
{
    gw_audio *a = &m->audio;
    uint64_t end = gw_audio_frames_at(tick, a->rate_hz);
    if (a->rate_hz == 0) return;
    while (a->finalised_frames < end) {
        uint32_t slot = (uint32_t)(a->finalised_frames %
            (GW_AUDIO_QUEUE_FRAMES + GW_BLEP_TAPS));
        int clipped = 0;
        int16_t left, right;
        a->integrator[0] += a->delta_ring[slot][0];
        a->integrator[1] += a->delta_ring[slot][1];
        a->delta_ring[slot][0] = 0;
        a->delta_ring[slot][1] = 0;
        left = saturate_i16(a->integrator[0], &clipped);
        right = saturate_i16(a->integrator[1], &clipped);
        if (clipped && a->clipped != UINT64_MAX) ++a->clipped;
        if (a->queue_count == GW_AUDIO_QUEUE_FRAMES) {
            a->queue_head = (a->queue_head + 1u) % GW_AUDIO_QUEUE_FRAMES;
            --a->queue_count;
            if (a->first_index != UINT64_MAX) ++a->first_index;
            if (a->lost != UINT64_MAX) ++a->lost;
        }
        {
            uint32_t tail = (a->queue_head + a->queue_count) % GW_AUDIO_QUEUE_FRAMES;
            a->queue[tail][0] = left;
            a->queue[tail][1] = right;
            ++a->queue_count;
        }
        ++a->finalised_frames;
    }
}

void gw_audio_sync(gw_machine *m, uint64_t tick)
{
    gw_ym2612_advance(m, tick);
    gw_psg_advance(m, tick);
    gw_audio_finalise(m, tick);
}

gw_status gw_audio_read(gw_machine *m, int16_t *out,
    uint32_t capacity_frames, gw_audio_read_result *result)
{
    uint32_t produced, i;
    gw_audio *a;
    if (!m || !out || !result || capacity_frames == 0 ||
        (size_t)capacity_frames > SIZE_MAX / 4u) return GW_ERROR_ARGUMENT;
    if (result->struct_size != sizeof(*result) || result->version != GW_API_VERSION)
        return GW_ERROR_VERSION;
    if (!m->rom) return GW_ERROR_NOT_LOADED;
    a = &m->audio;
    produced = a->queue_count < capacity_frames ? a->queue_count : capacity_frames;
    for (i = 0; i < produced; ++i) {
        uint32_t slot = (a->queue_head + i) % GW_AUDIO_QUEUE_FRAMES;
        out[2u * i] = a->queue[slot][0];
        out[2u * i + 1u] = a->queue[slot][1];
    }
    result->first_index = a->first_index;
    result->lost = a->lost;
    result->clipped = a->clipped;
    result->produced = produced;
    result->flags = a->rate_hz ? 0u : GW_AUDIO_FLAG_DISABLED;
    result->mix_id = GW_AUDIO_MIX_V1;
    result->filter_id = GW_AUDIO_FILTER_BLEP_V1;
    memset(result->reserved, 0, sizeof(result->reserved));
    a->queue_head = (a->queue_head + produced) % GW_AUDIO_QUEUE_FRAMES;
    a->queue_count -= produced;
    a->first_index += produced;
    result->struct_size = sizeof(*result);
    result->version = GW_API_VERSION;
    return GW_OK;
}

gw_status gw_configure_audio_trace(gw_machine *m, size_t capacity)
{
    if (!m) return GW_ERROR_ARGUMENT;
    if (capacity > GW_AUDIO_TRACE_CAPACITY) return GW_ERROR_CAPACITY;
    m->audio.trace_capacity = capacity;
    m->audio.trace_count = 0;
    m->audio.trace_dropped = 0;
    return GW_OK;
}

gw_status gw_get_audio_writes(const gw_machine *m, gw_audio_write *writes,
    size_t capacity, size_t *count, uint64_t *dropped)
{
    size_t i;
    if (!m || (!writes && capacity) || !count || !dropped) return GW_ERROR_ARGUMENT;
    if (capacity < m->audio.trace_count) return GW_ERROR_CAPACITY;
    for (i = 0; i < m->audio.trace_count; ++i)
        writes[i] = m->audio.trace[i];
    *count = m->audio.trace_count;
    *dropped = m->audio.trace_dropped;
    return GW_OK;
}

void gw_audio_trace_record(gw_machine *m, uint32_t chip, uint32_t reg,
    uint32_t value, uint32_t source)
{
    gw_audio_trace_record_at(m, m->tick, chip, reg, value, source);
}

void gw_audio_trace_record_at(gw_machine *m, uint64_t tick, uint32_t chip,
    uint32_t reg, uint32_t value, uint32_t source)
{
    gw_audio *audio = &m->audio;
    gw_audio_write *write;
    if (audio->trace_capacity == 0) return;
    if (audio->trace_count == audio->trace_capacity) {
        if (audio->trace_dropped != UINT64_MAX) ++audio->trace_dropped;
        return;
    }
    write = &audio->trace[audio->trace_count++];
    write->tick = tick;
    write->chip = chip;
    write->reg = reg;
    write->value = value;
    write->source = source;
}

#ifdef GW_TEST_HOOKS
uint64_t gw_test_audio_frames_at(uint64_t tick, uint32_t rate_hz)
{
    return gw_audio_frames_at(tick, rate_hz);
}
#endif

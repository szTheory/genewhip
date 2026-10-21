/* SPDX-License-Identifier: MIT */
#ifndef GENEWHIP_RUNNER_AUDIO_H
#define GENEWHIP_RUNNER_AUDIO_H

#include <SDL3/SDL.h>
#include <stdio.h>
#include <stdint.h>
#include "stats.h"

#define GW_RUNNER_AUDIO_HZ 48000u
#define GW_RUNNER_AUDIO_TARGET_FRAMES 2403u
#define GW_RUNNER_AUDIO_DEVICE_FRAMES 800u
#define GW_RUNNER_AUDIO_CAP_FRAMES (4u * GW_RUNNER_AUDIO_TARGET_FRAMES)
#define GW_RUNNER_AUDIO_RAMP_FRAMES 240u
#define GW_RUNNER_AUDIO_QUEUE_BUCKETS 6u

typedef uint64_t (*runner_audio_clock_fn)(void *context);

typedef struct runner_audio_counters {
    uint64_t queued_frames, queued_frames_min, queued_frames_max;
    uint64_t queue_source_bytes, queue_source_bytes_min, queue_source_bytes_max;
    uint64_t queue_samples, queue_depth_histogram[GW_RUNNER_AUDIO_QUEUE_BUCKETS];
    uint64_t queue_sample_first_ns, queue_sample_last_ns, queue_exposure_ns;
    uint64_t underruns, overruns, dropped_frames;
    uint64_t produced_frames, consumed_frames;
    uint64_t core_frames, core_lost, core_clipped;
    uint64_t core_lost_frames, core_clipped_frames;
    uint64_t producer_starvation_observations;
    uint64_t host_cap_overruns, host_cap_dropped_frames, intentional_clear_frames;
    uint64_t pause_clear_frames, reprime_clear_frames, stream_failure_dropped_frames;
    uint64_t pause_ramp_frames, reprime_silence_frames, mute_transitions;
    int primed;
    int ratio_seen;
    int queue_clock_seen, queue_clock_regressed, saturated;
    double ratio, ratio_min, ratio_max;
} runner_audio_counters;

static inline uint64_t runner_audio_counter_add(runner_audio_counters *c,
    uint64_t *counter, uint64_t amount)
{
    if (UINT64_MAX - *counter < amount) {
        c->saturated = 1;
        *counter = UINT64_MAX;
    } else {
        *counter += amount;
    }
    return *counter;
}

static inline unsigned runner_audio_queue_bucket(uint64_t frames)
{
    if (frames == 0u) return 0u;
    if (frames == 1u) return 1u;
    if (frames <= GW_RUNNER_AUDIO_TARGET_FRAMES) return 2u;
    if (frames <= 2u * GW_RUNNER_AUDIO_TARGET_FRAMES) return 3u;
    if (frames <= GW_RUNNER_AUDIO_CAP_FRAMES) return 4u;
    return 5u;
}

static inline void runner_audio_sample_queue(runner_audio_counters *c,
    uint64_t observed_frames, uint64_t now_ns)
{
    uint64_t source_bytes;
    unsigned bucket = runner_audio_queue_bucket(observed_frames);
    if (observed_frames > UINT64_MAX / (2u * sizeof(int16_t))) {
        source_bytes = UINT64_MAX;
        c->saturated = 1;
    } else source_bytes = observed_frames * (2u * sizeof(int16_t));
    c->queued_frames = observed_frames;
    c->queue_source_bytes = source_bytes;
    if (observed_frames < c->queued_frames_min) c->queued_frames_min = observed_frames;
    if (observed_frames > c->queued_frames_max) c->queued_frames_max = observed_frames;
    if (source_bytes < c->queue_source_bytes_min) c->queue_source_bytes_min = source_bytes;
    if (source_bytes > c->queue_source_bytes_max) c->queue_source_bytes_max = source_bytes;
    runner_audio_counter_add(c, &c->queue_samples, 1u);
    runner_audio_counter_add(c, &c->queue_depth_histogram[bucket], 1u);
    if (!c->queue_clock_seen) {
        c->queue_sample_first_ns = now_ns;
        c->queue_sample_last_ns = now_ns;
        c->queue_clock_seen = 1;
    } else if (now_ns < c->queue_sample_last_ns) {
        c->queue_clock_regressed = 1;
    } else {
        c->queue_sample_last_ns = now_ns;
        c->queue_exposure_ns = now_ns - c->queue_sample_first_ns;
    }
}

/* Reconcile queued source frames against asynchronous backend consumption,
 * then record the actual SDL input-queue sample and its monotonic exposure. */
static inline void runner_audio_account_queue_observation(runner_audio_counters *c,
    uint64_t expected_frames, uint64_t observed_frames, uint64_t now_ns)
{
    if (expected_frames > observed_frames)
        runner_audio_counter_add(c, &c->consumed_frames, expected_frames - observed_frames);
    runner_audio_sample_queue(c, observed_frames, now_ns);
}

typedef struct runner_audio {
    SDL_AudioStream *stream;
    runner_audio_counters counters;
    int enabled;
    int subsystem_initialized;
    int muted;
    int paused;
    int priming;
    int32_t gain_q15;
    int32_t ramp_target_q15;
    uint32_t ramp_remaining;
    int16_t last_left, last_right;
    runner_audio_clock_fn clock_now;
    void *clock_context;
} runner_audio;

static inline uint64_t runner_audio_now(const runner_audio *audio)
{
    return audio->clock_now ? audio->clock_now(audio->clock_context) : SDL_GetTicksNS();
}

static inline void runner_audio_observe_queue(runner_audio *audio,
    uint64_t expected_frames, uint64_t observed_frames)
{
    runner_audio_account_queue_observation(&audio->counters, expected_frames,
        observed_frames, runner_audio_now(audio));
}

int runner_audio_open(runner_audio *audio);
void runner_audio_put_field(runner_audio *audio, const int16_t *frames, uint32_t count,
    uint64_t core_frames, uint64_t core_lost, uint64_t core_clipped);
void runner_audio_set_muted(runner_audio *audio, int muted);
void runner_audio_pause(runner_audio *audio);
void runner_audio_reprime(runner_audio *audio);
void runner_audio_close(runner_audio *audio);
void runner_audio_print_counters(const runner_audio *audio);
void runner_audio_print_stats(const runner_audio *audio, const runner_stats *stats, FILE *file);
void runner_audio_write_stats_json(const runner_audio *audio, const runner_stats *stats, FILE *file);

#endif

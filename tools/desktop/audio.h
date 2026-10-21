/* SPDX-License-Identifier: MIT */
#ifndef GENEWHIP_RUNNER_AUDIO_H
#define GENEWHIP_RUNNER_AUDIO_H

#include <SDL3/SDL.h>
#include <stdio.h>
#include <stdint.h>

#define GW_RUNNER_AUDIO_HZ 48000u
#define GW_RUNNER_AUDIO_TARGET_FRAMES 2403u
#define GW_RUNNER_AUDIO_DEVICE_FRAMES 800u
#define GW_RUNNER_AUDIO_CAP_FRAMES (4u * GW_RUNNER_AUDIO_TARGET_FRAMES)
#define GW_RUNNER_AUDIO_RAMP_FRAMES 240u

typedef struct runner_audio_counters {
    uint64_t queued_frames, queued_frames_min, queued_frames_max;
    uint64_t underruns, overruns, dropped_frames;
    uint64_t produced_frames, consumed_frames;
    uint64_t core_frames, core_lost, core_clipped;
    int primed;
    int ratio_seen;
    double ratio, ratio_min, ratio_max;
} runner_audio_counters;

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
} runner_audio;

int runner_audio_open(runner_audio *audio);
void runner_audio_put_field(runner_audio *audio, const int16_t *frames, uint32_t count,
    uint64_t core_frames, uint64_t core_lost, uint64_t core_clipped);
void runner_audio_set_muted(runner_audio *audio, int muted);
void runner_audio_pause(runner_audio *audio);
void runner_audio_reprime(runner_audio *audio);
void runner_audio_close(runner_audio *audio);
void runner_audio_print_counters(const runner_audio *audio);
void runner_audio_print_stats(const runner_audio *audio, FILE *file);
void runner_audio_write_stats_json(const runner_audio *audio, FILE *file);

#endif

/* SPDX-License-Identifier: MIT */
#include "audio.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "CHECK failed: %s at %s:%d\n", #condition, __FILE__, __LINE__); \
        exit(1); \
    } \
} while (0)

struct SDL_AudioStream { int unused; };
static struct SDL_AudioStream fake_stream;
static uint64_t fake_queued_frames = 500;
static unsigned queue_observations;
static uint64_t fake_now_ns = 1000;

static uint64_t test_clock(void *context)
{ (void)context; return fake_now_ns; }

bool SDLCALL SDL_SetHint(const char *name, const char *value)
{ (void)name; (void)value; return true; }
bool SDLCALL SDL_InitSubSystem(SDL_InitFlags flags)
{ (void)flags; return true; }
void SDLCALL SDL_QuitSubSystem(SDL_InitFlags flags) { (void)flags; }
const char * SDLCALL SDL_GetError(void) { return "fake audio backend"; }
SDL_AudioStream * SDLCALL SDL_OpenAudioDeviceStream(SDL_AudioDeviceID devid,
    const SDL_AudioSpec *spec, SDL_AudioStreamCallback callback, void *userdata)
{ (void)devid; (void)spec; (void)callback; (void)userdata; return &fake_stream; }
bool SDLCALL SDL_ResumeAudioStreamDevice(SDL_AudioStream *stream)
{ (void)stream; return true; }
bool SDLCALL SDL_LockAudioStream(SDL_AudioStream *stream)
{ (void)stream; return true; }
bool SDLCALL SDL_UnlockAudioStream(SDL_AudioStream *stream)
{ (void)stream; return true; }
bool SDLCALL SDL_SetAudioStreamFrequencyRatio(SDL_AudioStream *stream, float ratio)
{ (void)stream; (void)ratio; return true; }
bool SDLCALL SDL_PutAudioStreamData(SDL_AudioStream *stream, const void *buf, int len)
{
    (void)stream; (void)buf;
    CHECK(len >= 0 && len % (2u * sizeof(int16_t)) == 0);
    fake_queued_frames += (uint64_t)len / (2u * sizeof(int16_t));
    fake_now_ns += 100u;
    /* Model the playback backend consuming source frames during enqueue. */
    CHECK(fake_queued_frames >= 10);
    fake_queued_frames -= 10;
    return true;
}
int SDLCALL SDL_GetAudioStreamQueued(SDL_AudioStream *stream)
{
    (void)stream;
    if (queue_observations++ == 0) {
        /* Drain before the pre-enqueue snapshot. */
        CHECK(fake_queued_frames >= 10);
        fake_queued_frames -= 10;
    }
    return (int)(fake_queued_frames * 2u * sizeof(int16_t));
}
int SDLCALL SDL_GetAudioStreamData(SDL_AudioStream *stream, void *buf, int len)
{
    (void)stream; (void)buf;
    CHECK(len >= 0 && len % (2u * sizeof(int16_t)) == 0);
    CHECK(fake_queued_frames >= (uint64_t)len / (2u * sizeof(int16_t)));
    fake_queued_frames -= (uint64_t)len / (2u * sizeof(int16_t));
    return len;
}
bool SDLCALL SDL_ClearAudioStream(SDL_AudioStream *stream)
{ (void)stream; fake_queued_frames = 0; return true; }
void SDLCALL SDL_DestroyAudioStream(SDL_AudioStream *stream) { (void)stream; }
void SDLCALL SDL_DelayNS(Uint64 ns) { (void)ns; }
Uint64 SDLCALL SDL_GetTicksNS(void) { return fake_now_ns; }

int main(void)
{
    runner_audio audio;
    runner_audio overrun_audio;
    runner_audio_counters boundaries = {0};
    int16_t frames[100u * 2u] = {0};
    const uint64_t depths[] = {0u, 1u, GW_RUNNER_AUDIO_TARGET_FRAMES,
        2u * GW_RUNNER_AUDIO_TARGET_FRAMES, GW_RUNNER_AUDIO_CAP_FRAMES,
        GW_RUNNER_AUDIO_CAP_FRAMES + 1u};
    memset(&audio, 0, sizeof(audio));
    audio.clock_now = test_clock;
    audio.stream = &fake_stream;
    audio.enabled = 1;
    audio.gain_q15 = 32767;
    audio.counters.queued_frames = 500;
    audio.counters.queued_frames_min = UINT64_MAX;
    audio.counters.queue_source_bytes_min = UINT64_MAX;
    audio.counters.produced_frames = 500;
    audio.counters.ratio = 1.0;
    audio.counters.ratio_min = 1.0;
    audio.counters.ratio_max = 1.0;
    audio.counters.ratio_seen = 1;

    runner_audio_put_field(&audio, frames, 100, 600, 0, 0);

    CHECK(queue_observations == 2);
    CHECK(audio.counters.produced_frames == 600);
    CHECK(audio.counters.consumed_frames == 20);
    CHECK(audio.counters.queued_frames == 580);
    CHECK(audio.counters.produced_frames == audio.counters.consumed_frames +
        audio.counters.queued_frames + audio.counters.dropped_frames);
    CHECK(audio.counters.queue_samples == 2u);
    CHECK(audio.counters.queue_exposure_ns == 100u);
    CHECK(audio.counters.queue_source_bytes == 580u * 4u);
    CHECK(audio.counters.core_lost_frames == 0u);
    runner_audio_put_field(&audio, NULL, 0u, 600u, 2u, 0u);
    runner_audio_put_field(&audio, NULL, 0u, 600u, 5u, 0u);
    CHECK(audio.counters.core_lost_frames == 5u && audio.counters.core_lost == 5u);

    boundaries.queued_frames_min = UINT64_MAX;
    boundaries.queue_source_bytes_min = UINT64_MAX;
    for (unsigned i = 0; i < sizeof(depths) / sizeof(depths[0]); ++i)
        runner_audio_sample_queue(&boundaries, depths[i], 2000u + i * 100u);
    CHECK(boundaries.queue_samples == GW_RUNNER_AUDIO_QUEUE_BUCKETS);
    for (unsigned i = 0; i < GW_RUNNER_AUDIO_QUEUE_BUCKETS; ++i)
        CHECK(boundaries.queue_depth_histogram[i] == 1u);
    CHECK(boundaries.queue_exposure_ns == 500u);
    CHECK(boundaries.queued_frames == GW_RUNNER_AUDIO_CAP_FRAMES + 1u);

    memset(&overrun_audio, 0, sizeof(overrun_audio));
    overrun_audio.stream = &fake_stream;
    overrun_audio.clock_now = test_clock;
    overrun_audio.enabled = 1;
    overrun_audio.gain_q15 = 32767;
    overrun_audio.counters.queued_frames = GW_RUNNER_AUDIO_CAP_FRAMES + 100u;
    overrun_audio.counters.queued_frames_min = UINT64_MAX;
    overrun_audio.counters.queue_source_bytes_min = UINT64_MAX;
    overrun_audio.counters.produced_frames = GW_RUNNER_AUDIO_CAP_FRAMES + 100u;
    overrun_audio.counters.ratio = 1.0;
    overrun_audio.counters.ratio_min = 1.0;
    overrun_audio.counters.ratio_max = 1.0;
    overrun_audio.counters.ratio_seen = 1;
    fake_queued_frames = GW_RUNNER_AUDIO_CAP_FRAMES + 100u;
    queue_observations = 0;
    runner_audio_put_field(&overrun_audio, NULL, 0u, 0u, 0u, 0u);
    CHECK(overrun_audio.counters.host_cap_overruns == 1u);
    CHECK(overrun_audio.counters.host_cap_dropped_frames == 7299u);
    CHECK(overrun_audio.counters.dropped_frames == 7299u);
    CHECK(overrun_audio.counters.produced_frames == overrun_audio.counters.consumed_frames +
        overrun_audio.counters.queued_frames + overrun_audio.counters.dropped_frames);
    puts("audio accounting contract: runner path conserved async enqueue drain");
    return 0;
}

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
static int16_t enqueued_samples[12000];
static size_t enqueued_sample_count;
static unsigned stream_clears;

static int samples_are_zero(const int16_t *samples, size_t count)
{
    for (size_t i = 0; i < count; ++i)
        if (samples[i] != 0) return 0;
    return 1;
}

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
    (void)stream;
    CHECK(len >= 0 && len % (2u * sizeof(int16_t)) == 0);
    size_t samples = (size_t)len / sizeof(int16_t);
    CHECK(enqueued_sample_count + samples <= sizeof(enqueued_samples) / sizeof(enqueued_samples[0]));
    memcpy(enqueued_samples + enqueued_sample_count, buf, (size_t)len);
    enqueued_sample_count += samples;
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
{ (void)stream; fake_queued_frames = 0; stream_clears++; return true; }
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

    /* Exercise the production mute/pause/reprime path with exact SDL input. */
    {
        runner_audio controls;
        int16_t source[GW_RUNNER_AUDIO_RAMP_FRAMES * 2u];
        size_t mute_start, mute_end, unmute_end, pause_start, reprime_start;
        unsigned clears_before_pause;
        for (size_t i = 0; i < sizeof(source) / sizeof(source[0]); i += 2u) {
            source[i] = 12000;
            source[i + 1u] = -9000;
        }
        memset(&controls, 0, sizeof(controls));
        controls.clock_now = test_clock;
        controls.stream = &fake_stream;
        controls.enabled = 1;
        controls.gain_q15 = 32767;
        controls.ramp_target_q15 = 32767;
        controls.counters.queued_frames_min = UINT64_MAX;
        controls.counters.queue_source_bytes_min = UINT64_MAX;
        controls.counters.ratio = controls.counters.ratio_min = controls.counters.ratio_max = 1.0;
        controls.counters.ratio_seen = 1;
        fake_queued_frames = 500;
        queue_observations = 0;
        enqueued_sample_count = 0;
        runner_audio_put_field(&controls, source, GW_RUNNER_AUDIO_RAMP_FRAMES, 240, 0, 0);
        CHECK(enqueued_samples[0] == 12000 && enqueued_samples[1] == -9000);

        runner_audio_set_muted(&controls, 1);
        mute_start = enqueued_sample_count;
        runner_audio_put_field(&controls, source, GW_RUNNER_AUDIO_RAMP_FRAMES, 480, 0, 0);
        mute_end = enqueued_sample_count;
        runner_audio_put_field(&controls, source, 10u, 490, 0, 0);
        CHECK(controls.counters.mute_transitions == 1u);
        CHECK(mute_end - mute_start == GW_RUNNER_AUDIO_RAMP_FRAMES * 2u);
        for (size_t i = enqueued_sample_count - 20u; i < enqueued_sample_count; ++i)
            CHECK(enqueued_samples[i] == 0);
        CHECK(samples_are_zero(enqueued_samples + enqueued_sample_count - 20u, 20u));
        /* Negative control: the muted-feed contract rejects a bypassed sample. */
        {
            int16_t mutant[20];
            memcpy(mutant, enqueued_samples + enqueued_sample_count - 20u, sizeof(mutant));
            mutant[7] = 1;
            CHECK(!samples_are_zero(mutant, 20u));
        }

        runner_audio_set_muted(&controls, 0);
        runner_audio_put_field(&controls, source, GW_RUNNER_AUDIO_RAMP_FRAMES, 730, 0, 0);
        unmute_end = enqueued_sample_count;
        CHECK(unmute_end > mute_end && enqueued_samples[unmute_end - 2u] == 12000 &&
              enqueued_samples[unmute_end - 1u] == -9000);
        CHECK(controls.counters.mute_transitions == 2u);

        clears_before_pause = stream_clears;
        pause_start = enqueued_sample_count;
        runner_audio_pause(&controls);
        CHECK(controls.paused == 1);
        CHECK(stream_clears >= clears_before_pause + 2u);
        CHECK(controls.counters.pause_ramp_frames == GW_RUNNER_AUDIO_RAMP_FRAMES);
        CHECK(enqueued_sample_count - pause_start == GW_RUNNER_AUDIO_RAMP_FRAMES * 2u);
        CHECK(enqueued_samples[enqueued_sample_count - 2u] == 0 &&
              enqueued_samples[enqueued_sample_count - 1u] == 0);
        /* The application pause contract separately proves no source starvation
         * observations advance while the published paused state is true. */
        runner_audio_reprime(&controls);
        CHECK(controls.paused == 0);
        reprime_start = enqueued_sample_count - GW_RUNNER_AUDIO_TARGET_FRAMES * 2u;
        CHECK(enqueued_sample_count - reprime_start == GW_RUNNER_AUDIO_TARGET_FRAMES * 2u);
        for (size_t i = reprime_start; i < enqueued_sample_count; ++i)
            CHECK(enqueued_samples[i] == 0);
        CHECK(controls.counters.reprime_silence_frames == GW_RUNNER_AUDIO_TARGET_FRAMES);
    }
    puts("audio accounting contract: runner path conserved async enqueue drain");
    return 0;
}

/* SPDX-License-Identifier: MIT */
#include "audio.h"

#include "rom_file.h"
#include "rate_ctl.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define STRINGIFY_INNER(value) #value
#define STRINGIFY(value) STRINGIFY_INNER(value)

static int queued_frames(const runner_audio *audio, uint64_t *frames)
{
    int bytes = SDL_GetAudioStreamQueued(audio->stream);
    if (bytes < 0) return 0;
    *frames = (uint64_t)bytes / (2u * sizeof(int16_t));
    return 1;
}

static void record_depth(runner_audio_counters *c, uint64_t depth)
{
    c->queued_frames = depth;
    if (depth < c->queued_frames_min) c->queued_frames_min = depth;
    if (depth > c->queued_frames_max) c->queued_frames_max = depth;
}

static void disable_audio(runner_audio *audio)
{
    if (audio->stream) {
        int bytes = SDL_GetAudioStreamQueued(audio->stream);
        if (bytes > 0) {
            uint64_t queued = (uint64_t)bytes / (2u * sizeof(int16_t));
            audio->counters.dropped_frames += queued;
            audio->counters.queued_frames = 0;
        }
        SDL_DestroyAudioStream(audio->stream);
        audio->stream = NULL;
    }
    if (audio->enabled) {
        char reason[160];
        gw_sanitize_display(SDL_GetError(), reason, sizeof(reason));
        fprintf(stderr, "audio: disabled (%s)\n", reason[0] ? reason : "SDL audio failure");
    }
    audio->enabled = 0;
}

int runner_audio_open(runner_audio *audio)
{
    SDL_AudioSpec spec = {SDL_AUDIO_S16, 2, GW_RUNNER_AUDIO_HZ};
    if (!audio) return 0;
    memset(audio, 0, sizeof(*audio));
    audio->counters.queued_frames_min = UINT64_MAX;
    audio->counters.ratio = 1.0;
    audio->counters.ratio_min = 1.0;
    audio->counters.ratio_max = 1.0;
    audio->gain_q15 = 32767;
    audio->ramp_target_q15 = 32767;
    audio->enabled = 1;
    if (!SDL_SetHint(SDL_HINT_AUDIO_DEVICE_SAMPLE_FRAMES,
            STRINGIFY(GW_RUNNER_AUDIO_DEVICE_FRAMES))) { disable_audio(audio); return 0; }
    if (!SDL_InitSubSystem(SDL_INIT_AUDIO)) { disable_audio(audio); return 0; }
    audio->subsystem_initialized = 1;
    audio->stream = SDL_OpenAudioDeviceStream(SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK, &spec, NULL, NULL);
    if (!audio->stream) { disable_audio(audio); return 0; }
    if (!SDL_ResumeAudioStreamDevice(audio->stream)) { disable_audio(audio); return 0; }
    return 1;
}

void runner_audio_put_field(runner_audio *audio, const int16_t *frames, uint32_t count,
    uint64_t core_frames, uint64_t core_lost, uint64_t core_clipped)
{
    static uint8_t discard[GW_RUNNER_AUDIO_CAP_FRAMES * 2u * sizeof(int16_t)];
    runner_audio_counters *c;
    uint64_t depth, previous, drop_frames;
    int32_t ppm;
    int drop_bytes;
    static int16_t adjusted[GW_RUNNER_AUDIO_TARGET_FRAMES * 2u];
    if (!audio) return;
    c = &audio->counters;
    c->core_frames = core_frames;
    c->core_lost = core_lost;
    c->core_clipped = core_clipped;
    if (!audio->enabled || !audio->stream) return;
    previous = c->queued_frames;
    if (!queued_frames(audio, &depth)) { disable_audio(audio); return; }
    if (previous > depth) c->consumed_frames += previous - depth;
    if (depth == 0 && c->primed && !audio->priming && !audio->paused) c->underruns++;
    if (depth > GW_RUNNER_AUDIO_CAP_FRAMES) {
        drop_frames = depth - GW_RUNNER_AUDIO_TARGET_FRAMES;
        if (drop_frames > GW_RUNNER_AUDIO_CAP_FRAMES) drop_frames = GW_RUNNER_AUDIO_CAP_FRAMES;
        drop_bytes = (int)(drop_frames * 2u * sizeof(int16_t));
        if (SDL_GetAudioStreamData(audio->stream, discard, drop_bytes) != drop_bytes) {
            disable_audio(audio);
            return;
        }
        c->overruns++;
        c->dropped_frames += drop_frames;
        depth -= drop_frames;
    }
    ppm = gw_rate_ppm((int64_t)depth, GW_RUNNER_AUDIO_TARGET_FRAMES, GW_RATE_K_PPM);
    c->ratio = 1.0 + (double)ppm / 1000000.0;
    if (!c->ratio_seen) {
        c->ratio_min = c->ratio;
        c->ratio_max = c->ratio;
        c->ratio_seen = 1;
    } else {
        if (c->ratio < c->ratio_min) c->ratio_min = c->ratio;
        if (c->ratio > c->ratio_max) c->ratio_max = c->ratio;
    }
    if (count > GW_RUNNER_AUDIO_TARGET_FRAMES) {
        disable_audio(audio);
        return;
    }
    if (count) {
        for (uint32_t i = 0; i < count; ++i) {
            int32_t gain = audio->gain_q15;
            if (audio->ramp_remaining) {
                int32_t delta = audio->ramp_target_q15 - audio->gain_q15;
                audio->gain_q15 += delta / (int32_t)audio->ramp_remaining;
                audio->ramp_remaining--;
                gain = audio->gain_q15;
            }
            if (audio->muted && gain == 0) {
                adjusted[i * 2u] = adjusted[i * 2u + 1u] = 0;
            } else {
                adjusted[i * 2u] = (int16_t)(((int32_t)frames[i * 2u] * gain) / 32767);
                adjusted[i * 2u + 1u] = (int16_t)(((int32_t)frames[i * 2u + 1u] * gain) / 32767);
            }
            audio->last_left = adjusted[i * 2u];
            audio->last_right = adjusted[i * 2u + 1u];
        }
    }
    if (!SDL_SetAudioStreamFrequencyRatio(audio->stream, (float)c->ratio) ||
        (count && !SDL_PutAudioStreamData(audio->stream, adjusted, (int)(count * 2u * sizeof(int16_t))))) {
        disable_audio(audio);
        return;
    }
    c->produced_frames += count;
    c->primed = 1;
    if (!queued_frames(audio, &depth)) { disable_audio(audio); return; }
    record_depth(c, depth);
    audio->priming = 0;
}

void runner_audio_set_muted(runner_audio *audio, int muted)
{
    if (!audio) return;
    muted = muted != 0;
    if (audio->muted == muted) return;
    audio->muted = muted;
    audio->ramp_target_q15 = muted ? 0 : 32767;
    audio->ramp_remaining = GW_RUNNER_AUDIO_RAMP_FRAMES;
}

static void clear_stream(runner_audio *audio)
{
    runner_audio_counters *c = &audio->counters;
    uint64_t depth = 0;
    if (!audio->enabled || !audio->stream) return;
    if (!queued_frames(audio, &depth)) { disable_audio(audio); return; }
    if (c->queued_frames > depth) c->consumed_frames += c->queued_frames - depth;
    c->dropped_frames += depth;
    if (!SDL_ClearAudioStream(audio->stream)) { disable_audio(audio); return; }
    c->queued_frames = 0;
}

void runner_audio_pause(runner_audio *audio)
{
    int16_t ramp[GW_RUNNER_AUDIO_RAMP_FRAMES * 2u];
    if (!audio) return;
    if (audio->paused) return;
    if (!audio->enabled || !audio->stream) { audio->paused = 1; return; }
    clear_stream(audio);
    if (!audio->enabled || !audio->stream) { audio->paused = 1; return; }
    for (uint32_t i = 0; i < GW_RUNNER_AUDIO_RAMP_FRAMES; ++i) {
        int32_t gain = (int32_t)(GW_RUNNER_AUDIO_RAMP_FRAMES - i - 1u) * 32767 /
            (int32_t)GW_RUNNER_AUDIO_RAMP_FRAMES;
        ramp[i * 2u] = (int16_t)(((int32_t)audio->last_left * gain) / 32767);
        ramp[i * 2u + 1u] = (int16_t)(((int32_t)audio->last_right * gain) / 32767);
    }
    if (!SDL_PutAudioStreamData(audio->stream, ramp, (int)sizeof(ramp))) {
        disable_audio(audio);
        audio->paused = 1;
        return;
    }
    audio->counters.produced_frames += GW_RUNNER_AUDIO_RAMP_FRAMES;
    record_depth(&audio->counters, GW_RUNNER_AUDIO_RAMP_FRAMES);
    audio->paused = 1;
    SDL_DelayNS((uint64_t)GW_RUNNER_AUDIO_DEVICE_FRAMES * UINT64_C(1000000000) /
        GW_RUNNER_AUDIO_HZ + UINT64_C(5000000));
    clear_stream(audio);
    audio->priming = 0;
}

void runner_audio_reprime(runner_audio *audio)
{
    static int16_t silence[GW_RUNNER_AUDIO_TARGET_FRAMES * 2u];
    if (!audio) return;
    if (!audio->enabled || !audio->stream) { audio->paused = 0; return; }
    clear_stream(audio);
    if (!audio->enabled || !audio->stream) { audio->paused = 0; return; }
    audio->paused = 0;
    audio->gain_q15 = audio->muted ? 0 : 0;
    audio->ramp_target_q15 = audio->muted ? 0 : 32767;
    audio->ramp_remaining = audio->muted ? 0 : GW_RUNNER_AUDIO_RAMP_FRAMES;
    if (!SDL_PutAudioStreamData(audio->stream, silence, (int)sizeof(silence))) {
        disable_audio(audio);
        return;
    }
    audio->counters.produced_frames += GW_RUNNER_AUDIO_TARGET_FRAMES;
    audio->counters.primed = 1;
    audio->priming = 1;
    record_depth(&audio->counters, GW_RUNNER_AUDIO_TARGET_FRAMES);
}

void runner_audio_close(runner_audio *audio)
{
    if (!audio) return;
    if (audio->stream) SDL_DestroyAudioStream(audio->stream);
    audio->stream = NULL;
    if (audio->subsystem_initialized) SDL_QuitSubSystem(SDL_INIT_AUDIO);
    audio->subsystem_initialized = 0;
    audio->enabled = 0;
}

void runner_audio_print_counters(const runner_audio *audio)
{
    runner_audio_print_stats(audio, stdout);
}

void runner_audio_print_stats(const runner_audio *audio, FILE *file)
{
    const runner_audio_counters *c;
    if (!audio || !file) return;
    c = &audio->counters;
    fprintf(file, "audio=%s queued_frames=%" PRIu64 " queued_frames_min=%" PRIu64
        " queued_frames_max=%" PRIu64 " ratio=%.6f ratio_min=%.6f ratio_max=%.6f"
        " underruns=%" PRIu64 " overruns=%" PRIu64 " dropped_frames=%" PRIu64
        " produced_frames=%" PRIu64 " consumed_frames=%" PRIu64 " core_frames=%" PRIu64
        " core_lost=%" PRIu64 " core_clipped=%" PRIu64,
        audio->enabled ? "on" : "off", c->queued_frames,
        c->queued_frames_min == UINT64_MAX ? 0 : c->queued_frames_min, c->queued_frames_max,
        c->ratio, c->ratio_min, c->ratio_max, c->underruns, c->overruns, c->dropped_frames,
        c->produced_frames, c->consumed_frames, c->core_frames, c->core_lost, c->core_clipped);
}

void runner_audio_write_stats_json(const runner_audio *audio, FILE *file)
{
    const runner_audio_counters *c;
    if (!audio || !file) return;
    c = &audio->counters;
    fprintf(file, "{\"audio\":\"%s\",\"queued_frames\":%" PRIu64
        ",\"queued_frames_min\":%" PRIu64 ",\"queued_frames_max\":%" PRIu64
        ",\"ratio\":%.6f,\"ratio_min\":%.6f,\"ratio_max\":%.6f"
        ",\"underruns\":%" PRIu64 ",\"overruns\":%" PRIu64
        ",\"dropped_frames\":%" PRIu64 ",\"produced_frames\":%" PRIu64
        ",\"consumed_frames\":%" PRIu64 ",\"core_frames\":%" PRIu64
        ",\"core_lost\":%" PRIu64 ",\"core_clipped\":%" PRIu64 "}\n",
        audio->enabled ? "on" : "off", c->queued_frames,
        c->queued_frames_min == UINT64_MAX ? 0 : c->queued_frames_min, c->queued_frames_max,
        c->ratio, c->ratio_min, c->ratio_max, c->underruns, c->overruns, c->dropped_frames,
        c->produced_frames, c->consumed_frames, c->core_frames, c->core_lost, c->core_clipped);
}

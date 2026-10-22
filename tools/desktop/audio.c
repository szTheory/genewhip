/* SPDX-License-Identifier: MIT */
#include "audio.h"

#include "rom_file.h"
#include "rate_ctl.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define STRINGIFY_INNER(value) #value
#define STRINGIFY(value) STRINGIFY_INNER(value)

typedef enum { CLEAR_FOR_PAUSE, CLEAR_FOR_REPRIME } runner_audio_clear_reason;

static int queued_frames(const runner_audio *audio, uint64_t *frames)
{
    int bytes = SDL_GetAudioStreamQueued(audio->stream);
    if (bytes < 0 || bytes % (2u * sizeof(int16_t)) != 0) return 0;
    *frames = (uint64_t)bytes / (2u * sizeof(int16_t));
    return 1;
}

static void disable_audio(runner_audio *audio)
{
    if (audio->stream) {
        if (SDL_LockAudioStream(audio->stream)) {
            int bytes = SDL_GetAudioStreamQueued(audio->stream);
            if (bytes >= 0 && bytes % (2u * sizeof(int16_t)) == 0) {
                uint64_t queued = (uint64_t)bytes / (2u * sizeof(int16_t));
                runner_audio_observe_queue(audio, audio->counters.queued_frames, queued);
                runner_audio_counter_add(&audio->counters,
                    &audio->counters.dropped_frames, queued);
                runner_audio_counter_add(&audio->counters,
                    &audio->counters.stream_failure_dropped_frames, queued);
                audio->counters.queued_frames = 0;
                audio->counters.queue_source_bytes = 0;
                (void)SDL_ClearAudioStream(audio->stream);
            }
            SDL_UnlockAudioStream(audio->stream);
        } else {
            int bytes = SDL_GetAudioStreamQueued(audio->stream);
            if (bytes >= 0 && bytes % (2u * sizeof(int16_t)) == 0) {
                uint64_t queued = (uint64_t)bytes / (2u * sizeof(int16_t));
                runner_audio_observe_queue(audio, audio->counters.queued_frames, queued);
                runner_audio_counter_add(&audio->counters,
                    &audio->counters.dropped_frames, queued);
                runner_audio_counter_add(&audio->counters,
                    &audio->counters.stream_failure_dropped_frames, queued);
                audio->counters.queued_frames = 0;
                audio->counters.queue_source_bytes = 0;
            }
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
    audio->counters.queue_source_bytes_min = UINT64_MAX;
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
    c->core_lost_frames = core_lost;
    c->core_clipped_frames = core_clipped;
    if (!audio->enabled || !audio->stream) return;
    previous = c->queued_frames;
    if (!queued_frames(audio, &depth)) { disable_audio(audio); return; }
    runner_audio_observe_queue(audio, previous, depth);
    if (depth == 0 && c->primed && !audio->priming && !audio->paused) {
        runner_audio_counter_add(c, &c->underruns, 1u);
        runner_audio_counter_add(c, &c->producer_starvation_observations, 1u);
    }
    if (depth > GW_RUNNER_AUDIO_CAP_FRAMES) {
        if (!SDL_LockAudioStream(audio->stream)) {
            disable_audio(audio);
            return;
        }
        if (!queued_frames(audio, &depth)) {
            SDL_UnlockAudioStream(audio->stream);
            disable_audio(audio);
            return;
        }
        runner_audio_observe_queue(audio, c->queued_frames, depth);
        if (depth > GW_RUNNER_AUDIO_CAP_FRAMES) {
            drop_frames = depth - GW_RUNNER_AUDIO_TARGET_FRAMES;
            if (drop_frames > GW_RUNNER_AUDIO_CAP_FRAMES) drop_frames = GW_RUNNER_AUDIO_CAP_FRAMES;
            drop_bytes = (int)(drop_frames * 2u * sizeof(int16_t));
            int removed_bytes = SDL_GetAudioStreamData(audio->stream, discard, drop_bytes);
            uint64_t removed_frames;
            if (removed_bytes < 0 || removed_bytes % (2u * sizeof(int16_t)) != 0) {
                SDL_UnlockAudioStream(audio->stream);
                disable_audio(audio);
                return;
            }
            removed_frames = (uint64_t)removed_bytes / (2u * sizeof(int16_t));
            runner_audio_counter_add(c, &c->overruns, 1u);
            runner_audio_counter_add(c, &c->host_cap_overruns, 1u);
            runner_audio_counter_add(c, &c->host_cap_dropped_frames, removed_frames);
            runner_audio_counter_add(c, &c->dropped_frames, removed_frames);
            depth -= removed_frames;
            if (!queued_frames(audio, &previous)) {
                SDL_UnlockAudioStream(audio->stream);
                disable_audio(audio);
                return;
            }
            runner_audio_observe_queue(audio, depth, previous);
            depth = previous;
        }
        SDL_UnlockAudioStream(audio->stream);
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
    runner_audio_counter_add(c, &c->produced_frames, count);
    c->primed = 1;
    if (!queued_frames(audio, &depth)) { disable_audio(audio); return; }
    runner_audio_observe_queue(audio, c->queued_frames + count, depth);
    audio->priming = 0;
}

void runner_audio_set_muted(runner_audio *audio, int muted)
{
    if (!audio) return;
    muted = muted != 0;
    if (audio->muted == muted) return;
    audio->muted = muted;
    runner_audio_counter_add(&audio->counters, &audio->counters.mute_transitions, 1u);
    audio->ramp_target_q15 = muted ? 0 : 32767;
    audio->ramp_remaining = GW_RUNNER_AUDIO_RAMP_FRAMES;
}

static void clear_stream(runner_audio *audio, runner_audio_clear_reason reason)
{
    runner_audio_counters *c = &audio->counters;
    uint64_t depth = 0;
    if (!audio->enabled || !audio->stream) return;
    if (!SDL_LockAudioStream(audio->stream)) { disable_audio(audio); return; }
    if (!queued_frames(audio, &depth)) {
        SDL_UnlockAudioStream(audio->stream);
        disable_audio(audio);
        return;
    }
    runner_audio_observe_queue(audio, c->queued_frames, depth);
    if (!SDL_ClearAudioStream(audio->stream)) {
        SDL_UnlockAudioStream(audio->stream);
        disable_audio(audio);
        return;
    }
    runner_audio_counter_add(c, &c->dropped_frames, depth);
    runner_audio_counter_add(c, &c->intentional_clear_frames, depth);
    if (reason == CLEAR_FOR_PAUSE)
        runner_audio_counter_add(c, &c->pause_clear_frames, depth);
    else
        runner_audio_counter_add(c, &c->reprime_clear_frames, depth);
    c->queued_frames = 0;
    c->queue_source_bytes = 0;
    SDL_UnlockAudioStream(audio->stream);
}

void runner_audio_pause(runner_audio *audio)
{
    int16_t ramp[GW_RUNNER_AUDIO_RAMP_FRAMES * 2u];
    uint64_t depth;
    if (!audio) return;
    if (audio->paused) return;
    if (!audio->enabled || !audio->stream) { audio->paused = 1; return; }
    clear_stream(audio, CLEAR_FOR_PAUSE);
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
    runner_audio_counter_add(&audio->counters, &audio->counters.produced_frames,
        GW_RUNNER_AUDIO_RAMP_FRAMES);
    runner_audio_counter_add(&audio->counters, &audio->counters.pause_ramp_frames,
        GW_RUNNER_AUDIO_RAMP_FRAMES);
    if (!queued_frames(audio, &depth)) { disable_audio(audio); audio->paused = 1; return; }
    runner_audio_observe_queue(audio,
        audio->counters.queued_frames + GW_RUNNER_AUDIO_RAMP_FRAMES, depth);
    audio->paused = 1;
    SDL_DelayNS((uint64_t)GW_RUNNER_AUDIO_DEVICE_FRAMES * UINT64_C(1000000000) /
        GW_RUNNER_AUDIO_HZ + UINT64_C(5000000));
    clear_stream(audio, CLEAR_FOR_PAUSE);
    audio->priming = 0;
}

void runner_audio_reprime(runner_audio *audio)
{
    static int16_t silence[GW_RUNNER_AUDIO_TARGET_FRAMES * 2u];
    if (!audio) return;
    if (!audio->enabled || !audio->stream) { audio->paused = 0; return; }
    clear_stream(audio, CLEAR_FOR_REPRIME);
    if (!audio->enabled || !audio->stream) { audio->paused = 0; return; }
    audio->paused = 0;
    audio->gain_q15 = audio->muted ? 0 : 0;
    audio->ramp_target_q15 = audio->muted ? 0 : 32767;
    audio->ramp_remaining = audio->muted ? 0 : GW_RUNNER_AUDIO_RAMP_FRAMES;
    if (!SDL_PutAudioStreamData(audio->stream, silence, (int)sizeof(silence))) {
        disable_audio(audio);
        return;
    }
    runner_audio_counter_add(&audio->counters, &audio->counters.produced_frames,
        GW_RUNNER_AUDIO_TARGET_FRAMES);
    runner_audio_counter_add(&audio->counters, &audio->counters.reprime_silence_frames,
        GW_RUNNER_AUDIO_TARGET_FRAMES);
    audio->counters.primed = 1;
    audio->priming = 1;
    {
        uint64_t depth;
        if (!queued_frames(audio, &depth)) { disable_audio(audio); return; }
        runner_audio_observe_queue(audio,
            audio->counters.queued_frames + GW_RUNNER_AUDIO_TARGET_FRAMES, depth);
    }
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
    runner_audio_print_stats(audio, NULL, stdout);
}

static void print_runner_stats(const runner_stats *s, FILE *file)
{
    if (!s) return;
    fprintf(file, " stats_version=%u scheduled_deadlines=%" PRIu64
        " late_deadlines=%" PRIu64 " lateness_samples=%" PRIu64
        " lateness_total_ns=%" PRIu64 " lateness_max_ns=%" PRIu64
        " lateness_le_0_ns=%" PRIu64 " lateness_le_100us=%" PRIu64
        " lateness_le_250us=%" PRIu64 " lateness_le_500us=%" PRIu64
        " lateness_le_1ms=%" PRIu64 " lateness_le_2ms=%" PRIu64
        " lateness_le_4ms=%" PRIu64 " lateness_gt_4ms=%" PRIu64
        " clock_exposure_ns=%" PRIu64 " emulated_fields=%" PRIu64
        " catchup_fields=%" PRIu64 " discarded_wall_ns=%" PRIu64
        " present_calls=%" PRIu64 " present_successes=%" PRIu64
        " present_errors=%" PRIu64 " last_presented_field_id=%" PRIu64
        " superseded_fields=%" PRIu64 " repeated_field_ids=%" PRIu64
        " stats_saturated=%d presentation_error=%d",
        GW_RUNNER_STATS_VERSION, s->scheduled_deadlines, s->late_deadlines,
        s->lateness_samples, s->lateness_total_ns, s->lateness_max_ns,
        s->lateness_histogram[0], s->lateness_histogram[1], s->lateness_histogram[2],
        s->lateness_histogram[3], s->lateness_histogram[4], s->lateness_histogram[5],
        s->lateness_histogram[6], s->lateness_histogram[7], s->clock_exposure_ns,
        s->emulated_fields, s->catchup_fields, s->discarded_wall_ns, s->present_calls,
        s->present_successes, s->present_errors, s->last_presented_field_id,
        s->superseded_fields, s->repeated_field_ids, s->saturated,
        s->present_error[0] != '\0');
}

void runner_audio_print_stats(const runner_audio *audio, const runner_stats *stats, FILE *file)
{
    const runner_audio_counters *c;
    if (!audio || !file) return;
    c = &audio->counters;
    fprintf(file, "audio=%s queued_frames=%" PRIu64 " queued_frames_min=%" PRIu64
        " queued_frames_max=%" PRIu64 " ratio=%.6f ratio_min=%.6f ratio_max=%.6f"
        " underruns=%" PRIu64 " overruns=%" PRIu64 " dropped_frames=%" PRIu64
        " produced_frames=%" PRIu64 " consumed_frames=%" PRIu64 " core_frames=%" PRIu64
        " core_lost=%" PRIu64 " core_clipped=%" PRIu64
        " queue_source_frames=%" PRIu64 " queue_source_frames_min=%" PRIu64
        " queue_source_frames_max=%" PRIu64 " queue_source_bytes=%" PRIu64
        " queue_source_bytes_min=%" PRIu64 " queue_source_bytes_max=%" PRIu64
        " queue_samples=%" PRIu64 " queue_sample_first_ns=%" PRIu64
        " queue_sample_last_ns=%" PRIu64
        " queue_depth_zero_frames=%" PRIu64 " queue_depth_one_frame=%" PRIu64
        " queue_depth_to_target_frames=%" PRIu64 " queue_depth_to_two_targets_frames=%" PRIu64
        " queue_depth_to_cap_frames=%" PRIu64 " queue_depth_over_cap_frames=%" PRIu64
        " queue_exposure_ns=%" PRIu64 " queue_clock_regressed=%d"
        " producer_starvation_observations=%" PRIu64 " core_lost_frames=%" PRIu64
        " core_clipped_frames=%" PRIu64 " host_cap_overruns=%" PRIu64
        " host_cap_dropped_frames=%" PRIu64 " intentional_clear_frames=%" PRIu64
        " pause_clear_frames=%" PRIu64 " reprime_clear_frames=%" PRIu64
        " stream_failure_dropped_frames=%" PRIu64 " pause_ramp_frames=%" PRIu64
        " reprime_silence_frames=%" PRIu64 " mute_transitions=%" PRIu64
        " audio_paused=%d audio_muted=%d audio_available=%d audio_saturated=%d",
        audio->enabled ? "on" : "off", c->queued_frames,
        c->queued_frames_min == UINT64_MAX ? 0 : c->queued_frames_min, c->queued_frames_max,
        c->ratio, c->ratio_min, c->ratio_max, c->underruns, c->overruns, c->dropped_frames,
        c->produced_frames, c->consumed_frames, c->core_frames, c->core_lost, c->core_clipped,
        c->queued_frames, c->queued_frames_min == UINT64_MAX ? 0 : c->queued_frames_min,
        c->queued_frames_max, c->queue_source_bytes,
        c->queue_source_bytes_min == UINT64_MAX ? 0 : c->queue_source_bytes_min,
        c->queue_source_bytes_max, c->queue_samples, c->queue_sample_first_ns,
        c->queue_sample_last_ns, c->queue_depth_histogram[0],
        c->queue_depth_histogram[1], c->queue_depth_histogram[2], c->queue_depth_histogram[3],
        c->queue_depth_histogram[4], c->queue_depth_histogram[5], c->queue_exposure_ns,
        c->queue_clock_regressed, c->producer_starvation_observations, c->core_lost_frames,
        c->core_clipped_frames, c->host_cap_overruns, c->host_cap_dropped_frames,
        c->intentional_clear_frames, c->pause_clear_frames, c->reprime_clear_frames,
        c->stream_failure_dropped_frames, c->pause_ramp_frames, c->reprime_silence_frames,
        c->mute_transitions, audio->paused, audio->muted, audio->enabled, c->saturated);
    print_runner_stats(stats, file);
}

static void write_json_string(FILE *file, const char *value)
{
    fputc('"', file);
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (*p == '"' || *p == '\\') { fputc('\\', file); fputc(*p, file); }
        else if (*p < 0x20u) fprintf(file, "\\u%04x", (unsigned)*p);
        else fputc(*p, file);
    }
    fputc('"', file);
}

void runner_audio_write_stats_json(const runner_audio *audio, const runner_stats *s, FILE *file)
{
    const runner_audio_counters *c;
    if (!audio || !file) return;
    c = &audio->counters;
    fprintf(file, "{\"audio\":\"%s\",\"stats_version\":%u"
        ",\"scheduled_deadlines\":%" PRIu64 ",\"late_deadlines\":%" PRIu64
        ",\"lateness_samples\":%" PRIu64 ",\"lateness_total_ns\":%" PRIu64
        ",\"lateness_max_ns\":%" PRIu64 ",\"lateness_le_0_ns\":%" PRIu64
        ",\"lateness_le_100us\":%" PRIu64 ",\"lateness_le_250us\":%" PRIu64
        ",\"lateness_le_500us\":%" PRIu64 ",\"lateness_le_1ms\":%" PRIu64
        ",\"lateness_le_2ms\":%" PRIu64 ",\"lateness_le_4ms\":%" PRIu64
        ",\"lateness_gt_4ms\":%" PRIu64 ",\"clock_exposure_ns\":%" PRIu64
        ",\"emulated_fields\":%" PRIu64 ",\"catchup_fields\":%" PRIu64
        ",\"discarded_wall_ns\":%" PRIu64 ",\"present_calls\":%" PRIu64
        ",\"present_successes\":%" PRIu64 ",\"present_errors\":%" PRIu64
        ",\"last_presented_field_id\":%" PRIu64 ",\"superseded_fields\":%" PRIu64
        ",\"repeated_field_ids\":%" PRIu64 ",\"stats_saturated\":%s"
        ",\"presentation_error\":%d"
        ",\"last_present_error\":",
        audio->enabled ? "on" : "off", GW_RUNNER_STATS_VERSION,
        s ? s->scheduled_deadlines : 0u, s ? s->late_deadlines : 0u,
        s ? s->lateness_samples : 0u, s ? s->lateness_total_ns : 0u,
        s ? s->lateness_max_ns : 0u,
        s ? s->lateness_histogram[0] : 0u, s ? s->lateness_histogram[1] : 0u,
        s ? s->lateness_histogram[2] : 0u, s ? s->lateness_histogram[3] : 0u,
        s ? s->lateness_histogram[4] : 0u, s ? s->lateness_histogram[5] : 0u,
        s ? s->lateness_histogram[6] : 0u, s ? s->lateness_histogram[7] : 0u,
        s ? s->clock_exposure_ns : 0u, s ? s->emulated_fields : 0u,
        s ? s->catchup_fields : 0u, s ? s->discarded_wall_ns : 0u,
        s ? s->present_calls : 0u, s ? s->present_successes : 0u,
        s ? s->present_errors : 0u, s ? s->last_presented_field_id : 0u,
        s ? s->superseded_fields : 0u, s ? s->repeated_field_ids : 0u,
        s && s->saturated ? "true" : "false", s && s->present_error[0] != '\0');
    write_json_string(file, s ? s->present_error : "");
    fprintf(file, ",\"queue_source_unit\":\"SDL input bytes and stereo source frames\""
        ",\"queue_source_frames\":%" PRIu64
        ",\"queue_source_frames_min\":%" PRIu64 ",\"queue_source_frames_max\":%" PRIu64
        ",\"queue_sample_first_ns\":%" PRIu64 ",\"queue_sample_last_ns\":%" PRIu64
        ",\"queued_frames\":%" PRIu64
        ",\"queued_frames_min\":%" PRIu64 ",\"queued_frames_max\":%" PRIu64
        ",\"ratio\":%.6f,\"ratio_min\":%.6f,\"ratio_max\":%.6f"
        ",\"underruns\":%" PRIu64 ",\"overruns\":%" PRIu64
        ",\"dropped_frames\":%" PRIu64 ",\"produced_frames\":%" PRIu64
        ",\"consumed_frames\":%" PRIu64 ",\"core_frames\":%" PRIu64
        ",\"core_lost\":%" PRIu64 ",\"core_clipped\":%" PRIu64
        ",\"queue_source_bytes\":%" PRIu64 ",\"queue_source_bytes_min\":%" PRIu64
        ",\"queue_source_bytes_max\":%" PRIu64 ",\"queue_samples\":%" PRIu64
        ",\"queue_depth_zero_frames\":%" PRIu64 ",\"queue_depth_one_frame\":%" PRIu64
        ",\"queue_depth_to_target_frames\":%" PRIu64
        ",\"queue_depth_to_two_targets_frames\":%" PRIu64
        ",\"queue_depth_to_cap_frames\":%" PRIu64 ",\"queue_depth_over_cap_frames\":%" PRIu64
        ",\"queue_exposure_ns\":%" PRIu64 ",\"queue_clock_regressed\":%d"
        ",\"producer_starvation_observations\":%" PRIu64
        ",\"core_lost_frames\":%" PRIu64 ",\"core_clipped_frames\":%" PRIu64
        ",\"host_cap_overruns\":%" PRIu64 ",\"host_cap_dropped_frames\":%" PRIu64
        ",\"intentional_clear_frames\":%" PRIu64 ",\"pause_clear_frames\":%" PRIu64
        ",\"reprime_clear_frames\":%" PRIu64 ",\"stream_failure_dropped_frames\":%" PRIu64
        ",\"pause_ramp_frames\":%" PRIu64 ",\"reprime_silence_frames\":%" PRIu64
        ",\"mute_transitions\":%" PRIu64 ",\"audio_paused\":%d,\"audio_muted\":%d"
        ",\"audio_available\":%d,\"audio_saturated\":%d",
        c->queued_frames, c->queued_frames_min == UINT64_MAX ? 0 : c->queued_frames_min,
        c->queued_frames_max, c->queue_sample_first_ns, c->queue_sample_last_ns,
        c->queued_frames,
        c->queued_frames_min == UINT64_MAX ? 0 : c->queued_frames_min, c->queued_frames_max,
        c->ratio, c->ratio_min, c->ratio_max, c->underruns, c->overruns, c->dropped_frames,
        c->produced_frames, c->consumed_frames, c->core_frames, c->core_lost, c->core_clipped,
        c->queue_source_bytes, c->queue_source_bytes_min == UINT64_MAX ? 0 : c->queue_source_bytes_min,
        c->queue_source_bytes_max, c->queue_samples, c->queue_depth_histogram[0],
        c->queue_depth_histogram[1], c->queue_depth_histogram[2], c->queue_depth_histogram[3],
        c->queue_depth_histogram[4], c->queue_depth_histogram[5], c->queue_exposure_ns,
        c->queue_clock_regressed, c->producer_starvation_observations, c->core_lost_frames,
        c->core_clipped_frames, c->host_cap_overruns, c->host_cap_dropped_frames,
        c->intentional_clear_frames, c->pause_clear_frames, c->reprime_clear_frames,
        c->stream_failure_dropped_frames, c->pause_ramp_frames, c->reprime_silence_frames,
        c->mute_transitions, audio->paused, audio->muted, audio->enabled, c->saturated);
    fputs("}\n", file);
}

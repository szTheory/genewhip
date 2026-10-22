/* SPDX-License-Identifier: MIT
 * Public API equivalence for the admitted successor under field and small-tick calls. */
#include "genewhip/genewhip.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define CHECK(c, name) do { if (!(c)) { fprintf(stderr, "FAIL: %s (line %d)\n", name, __LINE__); exit(1); } } while (0)

static gw_diagnostic_record snapshot(gw_machine *m)
{
    gw_diagnostic_record d = {0};
    d.struct_size = sizeof(d); d.version = GW_API_VERSION;
    CHECK(gw_get_diagnostics(m, &d) == GW_OK, "read CPU/time state");
    return d;
}

#define FIELDS 720u
#define RATE 48000u
#define PCM_CAP (FIELDS * 900u)
#define VIDEO_CAP (FIELDS)

typedef struct result {
    gw_diagnostic_record cpu;
    uint8_t ram[GW_RAM_SIZE];
    uint64_t video[VIDEO_CAP];
    size_t video_count;
    int16_t pcm[PCM_CAP * 2u];
    size_t pcm_frames;
    uint64_t tick;
    uint64_t last_sequence;
} result;

static uint8_t rom[GW_MAX_ROM_SIZE];
static size_t rom_size;

static uint64_t hash_update(uint64_t h, const void *data, size_t size)
{
    const uint8_t *p = data;
    for (size_t i = 0; i < size; ++i) h = (h ^ p[i]) * UINT64_C(1099511628211);
    return h;
}

static uint64_t hash_bytes(const void *data, size_t size)
{
    return hash_update(UINT64_C(14695981039346656037), data, size);
}

static gw_machine *fresh(void)
{
    gw_machine *m = NULL;
    gw_config c = {sizeof(c), GW_API_VERSION, GW_PROFILE_VA3_NTSC_U,
        GW_RESET_DETERMINISTIC_ZERO, 0, {GW_DEVICE_PAD3, GW_DEVICE_PAD3}, RATE};
    CHECK(gw_create(&c, &m) == GW_OK, "create successor instance");
    CHECK(gw_load_rom(m, rom, rom_size) == GW_OK, "load admitted successor");
    const struct { uint64_t field; uint32_t mask; } events[] = {
        {1, GW_BUTTON_START}, {2, 0}, {4, GW_BUTTON_RIGHT}, {84, 0},
        {121, GW_BUTTON_B}, {122, 0}
    };
    for (size_t i = 0; i < sizeof(events) / sizeof(events[0]); ++i) {
        gw_event e = {sizeof(e), GW_API_VERSION, events[i].field * GW_FIELD_TICKS,
            GW_EVENT_PAD_STATE, 0, events[i].mask, 0};
        CHECK(gw_schedule_event(m, &e) == GW_OK, "schedule frozen source-derived input");
    }
    return m;
}

static void observe(gw_machine *m, result *out)
{
    gw_video_field f = {0};
    const uint32_t *pixels = NULL;
    f.struct_size = sizeof(f); f.version = GW_API_VERSION;
    gw_status video_status = gw_get_video_field(m, &f, &pixels);
    CHECK(video_status == GW_OK || video_status == GW_ERROR_EMPTY, "read newest public video field");
    if (video_status == GW_OK && (out->video_count == 0 || out->last_sequence != f.sequence)) {
        CHECK(out->video_count < VIDEO_CAP, "video field bound");
        size_t row_bytes = (size_t)f.width * 4u;
        uint64_t value = UINT64_C(14695981039346656037);
        for (uint32_t y = 0; y < f.height; ++y)
            value = hash_update(value, (const uint8_t *)pixels + (size_t)y * f.pitch_bytes, row_bytes);
        /* Include dimensions and end tick to retain field identity and geometry. */
        value ^= ((uint64_t)f.width << 32) ^ ((uint64_t)f.height << 16) ^ f.end_tick;
        out->video[out->video_count++] = value;
        out->last_sequence = f.sequence;
    }
    int16_t block[GW_AUDIO_QUEUE_FRAMES * 2u];
    gw_audio_read_result audio = {0};
    audio.struct_size = sizeof(audio); audio.version = GW_API_VERSION;
    CHECK(gw_audio_read(m, block, GW_AUDIO_QUEUE_FRAMES, &audio) == GW_OK, "drain bounded PCM block");
    CHECK(audio.lost == 0, "no source PCM loss");
    CHECK(audio.first_index == out->pcm_frames, "continuous PCM frame index");
    CHECK(out->pcm_frames + audio.produced <= PCM_CAP, "PCM frame bound");
    memcpy(out->pcm + out->pcm_frames * 2u, block, (size_t)audio.produced * 2u * sizeof(int16_t));
    out->pcm_frames += audio.produced;
}

static void run_variant(unsigned mode, result *out)
{
    gw_machine *m = fresh();
    memset(out, 0, sizeof(*out));
    uint64_t target = (uint64_t)FIELDS * GW_FIELD_TICKS;
    while (snapshot(m).tick < target) {
        uint64_t now = snapshot(m).tick;
        uint64_t goal = target;
        uint32_t flags = 0;
        if (mode == 0) {
            goal = now + 2u * GW_FIELD_TICKS;
            if (goal > target) goal = target;
        } else {
            goal = now + 17003u;
            if (goal > target) goal = target;
            flags = GW_RUN_CONTINUE_PAST_FIELD;
        }
        gw_run_result r = {0};
        r.struct_size = sizeof(r); r.version = GW_API_VERSION; r.flags = flags;
        CHECK(gw_run_until(m, goal, &r) == GW_OK, "run public supported chunk");
        CHECK(r.actual_tick > now, "run advances emulated time");
        if (mode == 0 && r.stop_reason != GW_STOP_FIELD_COMPLETE && goal < target) {
            fprintf(stderr, "field-stop returned reason=%u actual=%llu target=%llu\n", r.stop_reason,
                (unsigned long long)r.actual_tick, (unsigned long long)goal);
            CHECK(r.stop_reason == GW_STOP_FIELD_COMPLETE, "field-stop mode reaches boundary");
        }
        observe(m, out);
    }
    out->cpu = snapshot(m);
    out->tick = out->cpu.tick;
    CHECK(gw_peek_memory(m, 0xff0000, out->ram, sizeof(out->ram)) == GW_OK, "capture complete work RAM");
    CHECK(out->video_count == FIELDS, "all 720 ordered field observations retained");
    CHECK(out->pcm_frames == (target * RATE) / GW_MASTER_HZ, "full PCM denominator");
    gw_destroy(m);
}

int main(int argc, char **argv)
{
    CHECK(argc == 2, "usage: game_chunking SUCCESSOR_ROM");
    FILE *in = fopen(argv[1], "rb");
    CHECK(in != NULL, "open successor ROM");
    rom_size = fread(rom, 1, sizeof(rom), in);
    CHECK(!ferror(in) && feof(in) && fclose(in) == 0, "read bounded successor ROM");
    result field_stop, small_chunks;
    run_variant(0, &field_stop);
    run_variant(1, &small_chunks);
    CHECK(field_stop.tick == small_chunks.tick, "same final emulated tick");
    CHECK(memcmp(&field_stop.cpu, &small_chunks.cpu, sizeof(field_stop.cpu)) == 0,
        "complete public CPU/time state equal");
    CHECK(memcmp(field_stop.ram, small_chunks.ram, sizeof(field_stop.ram)) == 0,
        "complete 64 KiB public work RAM equal");
    CHECK(field_stop.video_count == small_chunks.video_count, "ordered video denominator equal");
    CHECK(memcmp(field_stop.video, small_chunks.video, sizeof(field_stop.video)) == 0,
        "ordered rendered field observations equal");
    CHECK(field_stop.pcm_frames == small_chunks.pcm_frames, "PCM frame denominator equal");
    CHECK(memcmp(field_stop.pcm, small_chunks.pcm,
        field_stop.pcm_frames * 2u * sizeof(int16_t)) == 0, "raw stereo PCM bytes equal");
    printf("game chunking: %u fields, %zu stereo frames, RAM=%016llx, ordered video and PCM equal\n",
        FIELDS, field_stop.pcm_frames, (unsigned long long)hash_bytes(field_stop.ram, sizeof(field_stop.ram)));
    return 0;
}

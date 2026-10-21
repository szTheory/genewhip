/* SPDX-License-Identifier: MIT
 * Public-API silent PCM pull check. Expected counts derive from integer time,
 * independently multiplying tick*rate as a 128-bit pair before division.
 */
#include "genewhip/genewhip.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c, name) do { if (!(c)) { fprintf(stderr, "FAIL: %s (line %d)\n", name, __LINE__); exit(1); } } while (0)

typedef struct u128_pair { uint64_t hi, lo; } u128_pair;

static u128_pair multiply_u64_u32(uint64_t a, uint32_t b)
{
    uint64_t low = (uint64_t)(uint32_t)a * b;
    uint64_t high = (a >> 32) * b;
    u128_pair p;
    p.lo = low + (high << 32);
    p.hi = (high >> 32) + (p.lo < low);
    return p;
}

static uint64_t divide_u128_u64(u128_pair n, uint64_t d)
{
    uint64_t rem = 0, quotient = 0;
    int bit;
    for (bit = 127; bit >= 0; --bit) {
        uint64_t incoming = bit >= 64 ? ((n.hi >> (bit - 64)) & 1u) : ((n.lo >> bit) & 1u);
        rem = rem * 2u + incoming;
        if (rem >= d) {
            rem -= d;
            if (bit < 64) quotient |= UINT64_C(1) << bit;
            else CHECK(0, "frame quotient fits uint64");
        }
    }
    return quotient;
}

static uint64_t expected_frames(uint64_t tick, uint32_t rate)
{
    return divide_u128_u64(multiply_u64_u32(tick, rate), GW_MASTER_HZ);
}

static size_t read_file(const char *path, uint8_t *bytes, size_t cap)
{
    FILE *f = fopen(path, "rb");
    size_t n;
    CHECK(f != NULL, "open ROM");
    n = fread(bytes, 1, cap, f);
    CHECK(!ferror(f) && fclose(f) == 0, "read ROM");
    return n;
}

int main(int argc, char **argv)
{
    uint8_t rom[4096];
    int16_t pcm[GW_AUDIO_QUEUE_FRAMES * 2];
    int16_t tone[GW_AUDIO_QUEUE_FRAMES * 2];
    gw_config config = {0};
    gw_machine *machine = NULL;
    size_t rom_size;
    size_t tone_count = 0;
    uint64_t cumulative = 0;
    uint64_t tone_start_tick = 0, tone_end_tick = 0;
    uint32_t transitions = 0;
    int previous_negative = 0, have_previous = 0;
    int psg_mode;
    unsigned field;
    CHECK(argc == 3 && (strcmp(argv[1], "silent") == 0 || strcmp(argv[1], "psg") == 0),
        "usage: audio_tracer {silent|psg} ROM");
    psg_mode = strcmp(argv[1], "psg") == 0;
    rom_size = read_file(argv[2], rom, sizeof(rom));
    CHECK(rom_size >= GW_MIN_ROM_SIZE, "ROM size");
    config.struct_size = sizeof(config);
    config.version = GW_API_VERSION;
    config.profile = GW_PROFILE_VA3_NTSC_U;
    config.reset_policy = GW_RESET_DETERMINISTIC_ZERO;
    config.audio_rate_hz = 48000;
    CHECK(gw_create(&config, &machine) == GW_OK, "create audio machine");
    CHECK(gw_load_rom(machine, rom, rom_size) == GW_OK, "load audio machine");
    for (field = 0; field < 3; ++field) {
        gw_run_result run = {0};
        gw_audio_read_result result = {0};
        uint64_t expected;
        size_t i;
        run.struct_size = sizeof(run); run.version = GW_API_VERSION;
        result.struct_size = sizeof(result); result.version = GW_API_VERSION;
        CHECK(gw_run_until(machine, 3u * (uint64_t)GW_FIELD_TICKS, &run) == GW_OK, "field run");
        CHECK(run.stop_reason == GW_STOP_FIELD_COMPLETE, "field boundary");
        CHECK(gw_audio_read(machine, pcm, GW_AUDIO_QUEUE_FRAMES, &result) == GW_OK, "read PCM");
        expected = expected_frames(run.actual_tick, 48000);
        CHECK(result.produced == expected - cumulative, "cumulative N(actual_tick) frame count");
        CHECK(result.first_index == cumulative, "absolute first frame index");
        CHECK(result.lost == 0 && result.clipped == 0, "no loss or clipping");
        CHECK(result.mix_id == GW_AUDIO_MIX_V1 && result.filter_id == GW_AUDIO_FILTER_BLEP_V1,
            "mix and filter identities");
        for (i = 0; i < (size_t)result.produced * 2u; ++i) {
            if (!psg_mode) CHECK(pcm[i] == 0, "silent PCM");
        }
        if (psg_mode) {
            if (field == 0) tone_start_tick = run.actual_tick;
            if (field == 2) tone_end_tick = run.actual_tick;
            if (field >= 1) {
                for (i = 0; i < result.produced; ++i) {
                    int negative = pcm[2u * i] < 0;
                    if (have_previous && negative != previous_negative) ++transitions;
                    previous_negative = negative;
                    have_previous = 1;
                    CHECK(tone_count < sizeof(tone) / sizeof(tone[0]), "tone sample bound");
                    tone[tone_count++] = pcm[2u * i];
                }
            } else if (result.produced) {
                previous_negative = pcm[2u * ((size_t)result.produced - 1u)] < 0;
                have_previous = 1;
            }
        }
        cumulative = expected;
    }
    if (psg_mode) {
        const uint32_t rom_period = UINT32_C(0x0fe);
        uint64_t observed = (uint64_t)transitions * 16u * rom_period * GW_MASTER_HZ;
        uint64_t expected = UINT64_C(3579545) * (tone_end_tick - tone_start_tick);
        uint64_t difference = observed > expected ? observed - expected : expected - observed;
        int saw_positive = 0, saw_negative = 0, saw_peak = 0;
        size_t i;
        for (i = 0; i < tone_count; ++i) {
            if (tone[i] > 0) saw_positive = 1;
            if (tone[i] < 0) saw_negative = 1;
            if (tone[i] == 2048 || tone[i] == -2048) saw_peak = 1;
        }
        CHECK(tone_count > 0, "PSG stream has samples");
        CHECK(saw_positive && saw_negative, "PSG output is bipolar");
        CHECK(saw_peak, "PSG channel reaches approved peak");
        CHECK(transitions > 0 && difference * 100u <= expected * 2u,
            "PSG sign-change frequency within 2 percent of documented formula");
    }
    gw_destroy(machine);

    config.audio_rate_hz = 0;
    machine = NULL;
    CHECK(gw_create(&config, &machine) == GW_OK, "create disabled machine");
    CHECK(gw_load_rom(machine, rom, rom_size) == GW_OK, "load disabled machine");
    {
        gw_run_result run = {0};
        gw_audio_read_result result = {0};
        run.struct_size = sizeof(run); run.version = GW_API_VERSION;
        result.struct_size = sizeof(result); result.version = GW_API_VERSION;
        CHECK(gw_run_until(machine, GW_FIELD_TICKS, &run) == GW_OK, "disabled field run");
        CHECK(gw_audio_read(machine, pcm, GW_AUDIO_QUEUE_FRAMES, &result) == GW_OK, "disabled read");
        CHECK(result.produced == 0 && result.flags == GW_AUDIO_FLAG_DISABLED, "disabled audio observable");
    }
    gw_destroy(machine);
    puts(psg_mode ? "audio_tracer_psg: PASS" : "audio_tracer: PASS");
    return 0;
}

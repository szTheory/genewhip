/* SPDX-License-Identifier: MIT
 * D-55/D-57 properties for PCM, audio trace and execution-state hashing. */
#include "contract.h"
#ifdef GW_TEST_HOOKS
#include "state_digest.h"
#endif
#include <stdlib.h>

#define MODES 6u
#define TEST_RATE 48000u

static uint64_t target_ticks = UINT64_C(4) * GW_FIELD_TICKS;
static size_t expected_trace_count;
static int expect_fm_reset;

typedef struct measured {
    uint64_t pcm_hash;
    uint64_t frames;
    uint64_t final_tick;
    uint64_t digest;
    uint64_t trace_dropped;
    size_t trace_count;
    gw_audio_write trace[GW_AUDIO_TRACE_CAPACITY];
} measured;

static uint8_t rom_image[GW_MAX_ROM_SIZE];
static size_t rom_size;

static uint64_t hash_byte(uint64_t hash, uint8_t value)
{
    return (hash ^ value) * UINT64_C(1099511628211);
}

static uint64_t hash_u16le(uint64_t hash, uint16_t value)
{
    hash = hash_byte(hash, (uint8_t)value);
    return hash_byte(hash, (uint8_t)(value >> 8));
}

static uint64_t frames_at(uint64_t tick, uint32_t rate)
{
    uint64_t q = tick / GW_MASTER_HZ;
    uint64_t r = tick % GW_MASTER_HZ;
    return q * rate + (r * rate) / GW_MASTER_HZ;
}

static uint64_t machine_tick(gw_machine *m)
{
    return snapshot(m).tick;
}

static gw_machine *fresh(uint32_t rate)
{
    gw_machine *m = NULL;
    gw_config c = {sizeof(c), GW_API_VERSION, GW_PROFILE_VA3_NTSC_U,
        GW_RESET_DETERMINISTIC_ZERO, 1, {GW_DEVICE_PAD3, GW_DEVICE_PAD3}, rate};
    CHECK(gw_create(&c, &m) == GW_OK, "create machine");
    CHECK(gw_load_rom(m, rom_image, rom_size) == GW_OK, "load sweep ROM");
    CHECK(gw_configure_audio_trace(m, GW_AUDIO_TRACE_CAPACITY) == GW_OK, "enable full audio trace");
    return m;
}

static void drain(gw_machine *m, measured *result)
{
    int16_t samples[GW_AUDIO_QUEUE_FRAMES][2];
    gw_audio_read_result read = {0};
    read.struct_size = sizeof(read);
    read.version = GW_API_VERSION;
    CHECK(gw_audio_read(m, &samples[0][0], GW_AUDIO_QUEUE_FRAMES, &read) == GW_OK, "drain PCM");
    CHECK(read.lost == 0, "no PCM queue loss");
    CHECK(read.first_index == result->frames, "continuous PCM frame indices");
    for (uint32_t i = 0; i < read.produced; ++i) {
        result->pcm_hash = hash_u16le(result->pcm_hash, (uint16_t)samples[i][0]);
        result->pcm_hash = hash_u16le(result->pcm_hash, (uint16_t)samples[i][1]);
    }
    result->frames += read.produced;
}

static gw_run_result advance(gw_machine *m, uint64_t target, uint32_t flags)
{
    gw_run_result run_result = {0};
    run_result.struct_size = sizeof(run_result);
    run_result.version = GW_API_VERSION;
    run_result.flags = flags;
    CHECK(gw_run_until(m, target, &run_result) == GW_OK, "run to chunk target");
    return run_result;
}

static uint32_t xorshift(uint32_t *state)
{
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    return *state;
}

enum { MODE_TICK, MODE_LINE, MODE_FIELD, MODE_RANDOM, MODE_INSTRUCTION, MODE_FIELD_STOP };

static void run_variant(unsigned mode, measured *out)
{
    gw_machine *m = fresh(TEST_RATE);
    uint32_t random_state = UINT32_C(0x7a51c3d9);
    uint64_t random_chunks[20];
    unsigned random_index = 0;
    uint64_t initial_digest = 0;
    memset(out, 0, sizeof(*out));
    out->pcm_hash = UINT64_C(14695981039346656037);
    for (unsigned i = 0; i < 20; ++i)
        random_chunks[i] = 1000u + (xorshift(&random_state) % 100000u);
#ifdef GW_TEST_HOOKS
    initial_digest = gw_test_state_digest(m);
    if (mode == 0) {
        gw_machine *twin = fresh(TEST_RATE);
        CHECK(gw_test_state_digest(twin) == initial_digest, "fresh identical machines have equal digests");
        gw_destroy(twin);
    }
#endif
    while (machine_tick(m) < target_ticks) {
        uint64_t now = machine_tick(m), goal;
        uint64_t chunk = 1;
        gw_diagnostic_record before = {0};
        gw_diagnostic_record after = {0};
        gw_run_result run_result;
        if (mode == MODE_LINE) chunk = GW_LINE_TICKS;
        else if (mode == MODE_FIELD) chunk = GW_FIELD_TICKS;
        else if (mode == MODE_RANDOM) {
            chunk = random_chunks[random_index];
            random_index = (random_index + 1u) % 20u;
        }
        if (mode == MODE_FIELD_STOP) {
            before.struct_size = sizeof(before);
            before.version = GW_API_VERSION;
            CHECK(gw_get_diagnostics(m, &before) == GW_OK, "read pre-stop state");
            run_result = advance(m, target_ticks, 0);
        } else {
            goal = chunk > target_ticks - now ? target_ticks : now + chunk;
            if (mode == MODE_INSTRUCTION) {
                before.struct_size = sizeof(before);
                before.version = GW_API_VERSION;
                CHECK(gw_get_diagnostics(m, &before) == GW_OK, "read pre-instruction state");
            }
            run_result = advance(m, goal, GW_RUN_CONTINUE_PAST_FIELD);
        }
        CHECK(run_result.actual_tick > now, "each chunk makes forward progress");
        drain(m, out);
        if (mode == MODE_INSTRUCTION) {
            after.struct_size = sizeof(after);
            after.version = GW_API_VERSION;
            CHECK(gw_get_diagnostics(m, &after) == GW_OK, "read post-instruction state");
            /* The 68000 external reset clears diagnostics counters in the long
             * FM fixture, so validate the requested one-step boundary by time. */
            CHECK(after.tick > before.tick && after.tick - before.tick <= 2000u,
                "one-instruction mode advances by one bounded CPU step");
        }
        if (mode == MODE_FIELD_STOP && run_result.actual_tick < target_ticks)
            CHECK(run_result.stop_reason == GW_STOP_FIELD_COMPLETE, "field-stop mode stops at a field");
    }
    out->final_tick = machine_tick(m);
    CHECK(out->final_tick >= target_ticks, "all chunk modes reach the requested field horizon");
    CHECK(out->frames == frames_at(out->final_tick, TEST_RATE), "cumulative N(T) matches final tick");
    CHECK(gw_get_audio_writes(m, out->trace, GW_AUDIO_TRACE_CAPACITY,
        &out->trace_count, &out->trace_dropped) == GW_OK, "copy chip-write trace");
    CHECK(out->trace_count > 0, "sweep emitted PSG trace records");
    CHECK(out->frames > 0, "guest emitted nonempty PCM");
    if (expected_trace_count)
        CHECK(out->trace_count == expected_trace_count, "fixture emitted its full expected trace");
    CHECK(out->trace_dropped == 0, "audio trace remained within capacity");
    if (expect_fm_reset) {
        uint8_t marker[2] = {0};
        CHECK(gw_peek_memory(m, 0xff0000, marker, sizeof(marker)) == GW_OK,
            "read FM reset marker");
        CHECK(marker[0] == 0 && marker[1] == 64,
            "all chunk modes reach the post-reset 64-field marker");
    }
#ifdef GW_TEST_HOOKS
    out->digest = gw_test_state_digest(m);
    if (mode == 0) {
        CHECK(out->trace_count > 0, "guest-driven audio activity observed");
        CHECK(out->digest != initial_digest, "RAM, PSG, VDP and time changes alter the state digest");
    }
#else
    (void)initial_digest;
#endif
    gw_destroy(m);
}

static int same_write(const gw_audio_write *a, const gw_audio_write *b)
{
    return a->tick == b->tick && a->chip == b->chip && a->reg == b->reg &&
        a->value == b->value && a->source == b->source;
}

static void compare_modes(const measured *a, const measured *b)
{
    CHECK(a->final_tick == b->final_tick, "chunk modes reach identical final ticks");
    CHECK(a->frames == b->frames && a->pcm_hash == b->pcm_hash, "chunk modes produce identical PCM");
    CHECK(a->trace_count == b->trace_count && a->trace_dropped == b->trace_dropped,
        "chunk modes retain identical trace denominators");
    for (size_t i = 0; i < a->trace_count; ++i)
        CHECK(same_write(&a->trace[i], &b->trace[i]), "chunk modes produce identical trace records");
#ifdef GW_TEST_HOOKS
    CHECK(a->digest == b->digest, "chunk modes produce identical machine-state digests");
#endif
}

static void run_chunks(void)
{
    measured results[MODES];
    for (unsigned mode = 0; mode < MODES; ++mode) run_variant(mode, &results[mode]);
    for (unsigned mode = 1; mode < MODES; ++mode) compare_modes(&results[0], &results[mode]);
}

#ifdef GW_TEST_HOOKS
static void compare_traces(gw_machine *a, gw_machine *b)
{
    gw_audio_write left[GW_AUDIO_TRACE_CAPACITY], right[GW_AUDIO_TRACE_CAPACITY];
    size_t left_count = 0, right_count = 0;
    uint64_t left_dropped = 0, right_dropped = 0;
    CHECK(gw_get_audio_writes(a, left, GW_AUDIO_TRACE_CAPACITY, &left_count, &left_dropped) == GW_OK,
        "copy enabled trace");
    CHECK(gw_get_audio_writes(b, right, GW_AUDIO_TRACE_CAPACITY, &right_count, &right_dropped) == GW_OK,
        "copy disabled trace");
    CHECK(left_count == right_count && left_dropped == right_dropped && left_dropped == 0,
        "audio-rate variants have equal trace counts");
    for (size_t i = 0; i < left_count; ++i)
        CHECK(same_write(&left[i], &right[i]), "audio-rate variants have equal trace records");
}

static void run_disabled(void)
{
    gw_machine *disabled = fresh(0), *enabled = fresh(TEST_RATE);
    measured disabled_samples = {0}, enabled_samples = {0};
    disabled_samples.pcm_hash = enabled_samples.pcm_hash = UINT64_C(14695981039346656037);
    CHECK(gw_test_state_digest(disabled) == gw_test_state_digest(enabled),
        "audio rate is excluded from fresh machine digest");
    for (unsigned field = 1; field <= 4; ++field) {
        uint64_t target = (uint64_t)field * GW_FIELD_TICKS;
        gw_run_result a = advance(disabled, target, GW_RUN_CONTINUE_PAST_FIELD);
        gw_run_result b = advance(enabled, target, GW_RUN_CONTINUE_PAST_FIELD);
        CHECK(a.actual_tick == b.actual_tick, "audio-rate variants reach equal field ticks");
        drain(disabled, &disabled_samples);
        drain(enabled, &enabled_samples);
        CHECK(disabled_samples.frames == 0, "disabled machine produces no PCM");
        CHECK(enabled_samples.frames == frames_at(b.actual_tick, TEST_RATE), "enabled machine produces N(T) frames");
        CHECK(gw_test_state_digest(disabled) == gw_test_state_digest(enabled),
            "audio enabled and disabled state digests match at every field");
        compare_traces(disabled, enabled);
    }
    {
        uint64_t before = gw_test_state_digest(enabled);
        int16_t samples[GW_AUDIO_QUEUE_FRAMES][2];
        gw_audio_read_result read = {0};
        read.struct_size = sizeof(read);
        read.version = GW_API_VERSION;
        CHECK(gw_audio_read(enabled, &samples[0][0], GW_AUDIO_QUEUE_FRAMES, &read) == GW_OK,
            "read audio observation");
        CHECK(gw_configure_audio_trace(enabled, 0) == GW_OK, "clear audio trace observation");
        CHECK(gw_configure_audio_trace(enabled, GW_AUDIO_TRACE_CAPACITY) == GW_OK,
            "restore audio trace capacity");
        CHECK(gw_configure_diagnostics(enabled, 0) == GW_OK, "clear diagnostics observation");
        CHECK(gw_test_state_digest(enabled) == before,
            "PCM reads, trace configuration and diagnostics are excluded from digest");
    }
    gw_destroy(disabled);
    gw_destroy(enabled);
}

static void event_digest_changes(void)
{
    gw_machine *a = fresh(0), *b = fresh(0);
    gw_event event = {sizeof(event), GW_API_VERSION, 1000, GW_EVENT_PAD_STATE, 0, GW_BUTTON_A, 0};
    uint64_t before = gw_test_state_digest(a);
    CHECK(before == gw_test_state_digest(b), "same fresh inputs have same digest");
    CHECK(gw_schedule_event(a, &event) == GW_OK, "queue an input event");
    CHECK(before != gw_test_state_digest(a), "queued event changes digest");
    gw_destroy(a);
    gw_destroy(b);
}
#endif

int main(int argc, char **argv)
{
    FILE *file;
    CHECK((argc >= 3 && argc <= 5) &&
          (argc == 3 || (strcmp(argv[1], "chunk") == 0 && strtoul(argv[3], NULL, 10) > 0)),
          "usage: audio_chunk_equivalence chunk|disabled ROM [chunk-field-count [trace-count]]");
    file = fopen(argv[2], "rb");
    CHECK(file != NULL, "open sweep ROM");
    rom_size = fread(rom_image, 1, sizeof(rom_image), file);
    CHECK(rom_size >= GW_MIN_ROM_SIZE && fclose(file) == 0, "read sweep ROM");
    if (strcmp(argv[1], "chunk") == 0) {
        if (argc >= 4) {
            char *end = NULL;
            unsigned long fields = strtoul(argv[3], &end, 10);
            CHECK(end != argv[3] && *end == '\0' && fields > 0 && fields <= 1000,
                "chunk field count is a bounded positive integer");
            target_ticks = (uint64_t)fields * GW_FIELD_TICKS;
        }
        if (argc == 5) {
            char *end = NULL;
            unsigned long count = strtoul(argv[4], &end, 10);
            CHECK(end != argv[4] && *end == '\0' && count > 0,
                "trace count is a positive integer");
            expected_trace_count = (size_t)count;
        }
        expect_fm_reset = strstr(argv[2], "fm_script") != NULL;
        run_chunks();
#ifdef GW_TEST_HOOKS
        event_digest_changes();
#endif
    } else if (strcmp(argv[1], "disabled") == 0) {
#ifdef GW_TEST_HOOKS
        run_disabled();
#else
        CHECK(0, "disabled mode requires test hooks");
#endif
    } else {
        CHECK(0, "unknown mode");
    }
    puts("audio_chunk_equivalence: PASS");
    return 0;
}

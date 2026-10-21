/* SPDX-License-Identifier: MIT */
#include "../api/contract.h"

#ifdef GW_TEST_HOOKS
extern uint64_t gw_test_audio_frames_at(uint64_t tick, uint32_t rate_hz);
#endif

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
        uint64_t incoming = bit >= 64 ? ((n.hi >> (bit - 64)) & 1u) :
            ((n.lo >> bit) & 1u);
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

static gw_machine *create_rate(uint32_t rate)
{
    gw_config config = {0};
    gw_machine *m = NULL;
    config.struct_size = sizeof(config);
    config.version = GW_API_VERSION;
    config.profile = GW_PROFILE_VA3_NTSC_U;
    config.reset_policy = GW_RESET_DETERMINISTIC_ZERO;
    config.audio_rate_hz = rate;
    CHECK(gw_create(&config, &m) == GW_OK, "create rate");
    return m;
}

static void load_spin_rom(gw_machine *m)
{
    uint8_t rom[1024];
    rom_init(rom, sizeof(rom));
    CHECK(gw_load_rom(m, rom, sizeof(rom)) == GW_OK, "load spin ROM");
}

static gw_audio_read_result read_audio(gw_machine *m, int16_t *out, uint32_t capacity)
{
    gw_audio_read_result result = {0};
    result.struct_size = sizeof(result);
    result.version = GW_API_VERSION;
    CHECK(gw_audio_read(m, out, capacity, &result) == GW_OK, "audio read");
    return result;
}

static void api_contract(void)
{
    const uint32_t accepted[] = {0, 8000, 192000};
    uint8_t rom[1024];
    size_t i;
    for (i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        gw_machine *m = create_rate(accepted[i]);
        gw_destroy(m);
    }
    {
        const uint32_t rejected[] = {7999, 192001};
        for (i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
            gw_config config = {0};
            gw_machine *m = (gw_machine *)(uintptr_t)0x1234;
            config.struct_size = sizeof(config); config.version = GW_API_VERSION;
            config.profile = GW_PROFILE_VA3_NTSC_U;
            config.reset_policy = GW_RESET_DETERMINISTIC_ZERO;
            config.audio_rate_hz = rejected[i];
            CHECK(gw_create(&config, &m) == GW_ERROR_ARGUMENT, "out-of-range rate rejected");
            CHECK(m == (gw_machine *)(uintptr_t)0x1234, "failed create preserves output");
        }
    }
    rom_init(rom, sizeof(rom));
    {
        gw_machine *unloaded = create_rate(48000);
        int16_t out[8];
        gw_audio_read_result result;
        int16_t before_out[8];
        memset(out, 0xa5, sizeof(out)); memcpy(before_out, out, sizeof(out));
        memset(&result, 0x5a, sizeof(result));
        result.struct_size = sizeof(result); result.version = GW_API_VERSION;
        {
            gw_audio_read_result before = result;
            CHECK(gw_audio_read(unloaded, out, 8, &result) == GW_ERROR_NOT_LOADED,
                "unloaded read rejected");
            CHECK(memcmp(&result, &before, sizeof(result)) == 0 &&
                memcmp(out, before_out, sizeof(out)) == 0, "unloaded read preserves outputs");
        }
        gw_destroy(unloaded);
    }
    {
        gw_machine *m = create_rate(48000);
        int16_t out[8];
        gw_audio_read_result result, before;
        memset(out, 0xa5, sizeof(out));
        memset(&result, 0x6b, sizeof(result)); result.struct_size = sizeof(result);
        result.version = GW_API_VERSION; before = result;
        CHECK(gw_audio_read(NULL, out, 8, &result) == GW_ERROR_ARGUMENT, "null machine");
        CHECK(memcmp(&result, &before, sizeof(result)) == 0, "null machine output unchanged");
        CHECK(gw_audio_read(m, NULL, 8, &result) == GW_ERROR_ARGUMENT, "null output");
        CHECK(memcmp(&result, &before, sizeof(result)) == 0, "null output result unchanged");
        CHECK(gw_audio_read(m, out, 8, NULL) == GW_ERROR_ARGUMENT, "null result");
        CHECK(gw_audio_read(m, out, 0, &result) == GW_ERROR_ARGUMENT, "zero capacity");
        CHECK(memcmp(&result, &before, sizeof(result)) == 0, "argument failures unchanged");
        if (SIZE_MAX == UINT32_MAX) {
            CHECK(gw_audio_read(m, out, UINT32_MAX, &result) == GW_ERROR_ARGUMENT,
                "byte-size overflow rejected");
            CHECK(memcmp(&result, &before, sizeof(result)) == 0, "overflow failure unchanged");
        }
        result.struct_size--;
        CHECK(gw_audio_read(m, out, 8, &result) == GW_ERROR_VERSION, "wrong size rejected");
        result = before; result.version--;
        CHECK(gw_audio_read(m, out, 8, &result) == GW_ERROR_VERSION, "wrong version rejected");
        CHECK(memcmp(out, (int16_t[8]){(int16_t)0xa5a5,(int16_t)0xa5a5,(int16_t)0xa5a5,
            (int16_t)0xa5a5,(int16_t)0xa5a5,(int16_t)0xa5a5,(int16_t)0xa5a5,
            (int16_t)0xa5a5}, sizeof(out)) == 0, "failed reads preserve buffer");
        gw_destroy(m);
    }
    {
        gw_machine *disabled = create_rate(0);
        int16_t out[8];
        gw_audio_read_result result;
        load_spin_rom(disabled);
        CHECK(run_field(disabled, GW_FIELD_TICKS).stop_reason == GW_STOP_FIELD_COMPLETE,
            "disabled audio field run");
        result = read_audio(disabled, out, 8);
        CHECK(result.produced == 0 && result.flags == GW_AUDIO_FLAG_DISABLED,
            "disabled read shape");
        gw_destroy(disabled);
    }
    {
        gw_machine *m = create_rate(48000);
        int16_t out[GW_AUDIO_QUEUE_FRAMES * 2];
        gw_audio_read_result part, rest;
        gw_run_result r;
        load_spin_rom(m);
        r = run_field(m, GW_FIELD_TICKS);
        part = read_audio(m, out, 100);
        rest = read_audio(m, out, GW_AUDIO_QUEUE_FRAMES);
        CHECK(part.first_index == 0 && part.produced == 100, "first partial read");
        CHECK(rest.first_index == 100 && rest.produced > 0, "partial read indices continue");
        CHECK(part.first_index + part.produced == rest.first_index, "partial indices contiguous");
        CHECK(rest.mix_id == GW_AUDIO_MIX_V1 && rest.filter_id == GW_AUDIO_FILTER_BLEP_V1,
            "mix and filter identity");
        (void)r;
        gw_destroy(m);
    }
    {
        gw_machine *m = create_rate(48000);
        int16_t out[GW_AUDIO_QUEUE_FRAMES * 2];
        gw_audio_read_result first, after_reset, after_load;
        load_spin_rom(m);
        run_field(m, GW_FIELD_TICKS);
        first = read_audio(m, out, 100);
        CHECK(gw_console_reset(m) == GW_OK, "console reset preserves audio state");
        run_field(m, 2u * (uint64_t)GW_FIELD_TICKS);
        after_reset = read_audio(m, out, GW_AUDIO_QUEUE_FRAMES);
        CHECK(after_reset.first_index >= first.first_index + first.produced,
            "console reset keeps absolute index");
        CHECK(gw_cold_init(m) == GW_OK, "cold init resets audio indices");
        run_field(m, GW_FIELD_TICKS);
        after_load = read_audio(m, out, GW_AUDIO_QUEUE_FRAMES);
        CHECK(after_load.first_index == 0 && after_load.lost == 0,
            "cold init restarts audio indices");
        CHECK(gw_load_rom(m, rom, sizeof(rom)) == GW_OK, "reload ROM resets audio indices");
        run_field(m, GW_FIELD_TICKS);
        after_load = read_audio(m, out, GW_AUDIO_QUEUE_FRAMES);
        CHECK(after_load.first_index == 0 && after_load.lost == 0, "load restarts audio indices");
        gw_destroy(m);
    }
}

static void count_contract(void)
{
#ifdef GW_TEST_HOOKS
    const uint32_t rates[] = {8000, 44100, 48000, 192000};
    uint64_t seed = UINT64_C(0x9e3779b97f4a7c15);
    size_t r, i;
    for (r = 0; r < sizeof(rates) / sizeof(rates[0]); ++r) {
        uint64_t ticks[] = {0, GW_MASTER_HZ - 1, GW_MASTER_HZ,
            GW_MASTER_HZ + 1, 2u * GW_MASTER_HZ - 1, 2u * GW_MASTER_HZ,
            2u * GW_MASTER_HZ + 1, GW_MAX_TARGET_TICK};
        for (i = 0; i < sizeof(ticks) / sizeof(ticks[0]); ++i)
            CHECK(gw_test_audio_frames_at(ticks[i], rates[r]) ==
                expected_frames(ticks[i], rates[r]), "boundary frame count exact");
    }
    for (i = 0; i < 10000; ++i) {
        uint64_t tick;
        uint32_t rate;
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        tick = seed & GW_MAX_TARGET_TICK;
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        rate = 8000u + (uint32_t)(seed % (192000u - 8000u + 1u));
        CHECK(gw_test_audio_frames_at(tick, rate) == expected_frames(tick, rate),
            "random frame count exact");
    }
#endif
    {
        gw_machine *m = create_rate(48000);
        uint64_t seed = UINT64_C(0xd1b54a32d192ed03);
        uint64_t target = 0, drained = 0;
        int16_t out[GW_AUDIO_QUEUE_FRAMES * 2];
        size_t i;
        load_spin_rom(m);
        for (i = 0; i < 50; ++i) {
            gw_run_result run_result;
            gw_audio_read_result audio;
            seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
            target = (target > snapshot(m).tick ? target : snapshot(m).tick) +
                1000u + (seed % GW_FIELD_TICKS);
            run_result = run(m, target);
            audio = read_audio(m, out, GW_AUDIO_QUEUE_FRAMES);
            CHECK(audio.first_index == drained, "cumulative first index");
            CHECK(audio.produced == expected_frames(run_result.actual_tick, 48000) - drained,
                "public count follows actual tick");
            CHECK(audio.lost == 0, "small split run has no loss");
            drained += audio.produced;
        }
        gw_destroy(m);
    }
}

static void queue_overflow(void)
{
    gw_machine *undrained = create_rate(192000), *drained = create_rate(192000);
    int16_t out[GW_AUDIO_QUEUE_FRAMES * 2];
    gw_run_result last_undrained = {0}, last_drained = {0};
    uint64_t target = 0;
    unsigned field;
    load_spin_rom(undrained); load_spin_rom(drained);
    for (field = 0; field < 4; ++field) {
        gw_audio_read_result audio;
        uint8_t ram_a[GW_RAM_SIZE], ram_b[GW_RAM_SIZE];
        target += GW_FIELD_TICKS;
        last_undrained = run_field(undrained, target);
        last_drained = run_field(drained, target);
        audio = read_audio(drained, out, GW_AUDIO_QUEUE_FRAMES);
        CHECK(audio.lost == 0, "per-field drain avoids overflow");
        CHECK(last_undrained.actual_tick == last_drained.actual_tick &&
            last_undrained.stop_reason == last_drained.stop_reason,
            "field drain does not change run result");
        CHECK(gw_peek_memory(undrained, 0xff0000, ram_a, sizeof(ram_a)) == GW_OK &&
            gw_peek_memory(drained, 0xff0000, ram_b, sizeof(ram_b)) == GW_OK,
            "read per-field comparison RAM");
        CHECK(memcmp(ram_a, ram_b, sizeof(ram_a)) == 0,
            "field drain does not change work RAM");
    }
    {
        gw_audio_read_result result = {0};
        uint64_t expected = expected_frames(last_undrained.actual_tick, 192000);
        result.struct_size = sizeof(result); result.version = GW_API_VERSION;
        CHECK(last_undrained.actual_tick == last_drained.actual_tick &&
            last_undrained.stop_reason == last_drained.stop_reason,
            "overflow does not change execution");
        CHECK(gw_audio_read(undrained, out, GW_AUDIO_QUEUE_FRAMES, &result) == GW_OK,
            "read overflow queue");
        CHECK(expected > GW_AUDIO_QUEUE_FRAMES, "workload exceeds queue");
        CHECK(result.lost == expected - GW_AUDIO_QUEUE_FRAMES, "exact lost count");
        CHECK(result.produced == GW_AUDIO_QUEUE_FRAMES, "queue full after four fields");
        CHECK(result.first_index == expected - GW_AUDIO_QUEUE_FRAMES,
            "overflow retains newest frame indices");
    }
    gw_destroy(undrained); gw_destroy(drained);
}

int main(int argc, char **argv)
{
    CHECK(argc == 2, "usage: audio_contract {api|count|overflow}");
    if (strcmp(argv[1], "api") == 0) api_contract();
    else if (strcmp(argv[1], "count") == 0) count_contract();
    else if (strcmp(argv[1], "overflow") == 0) queue_overflow();
    else CHECK(0, "unknown audio contract mode");
    printf("audio_contract %s: PASS\n", argv[1]);
    return 0;
}

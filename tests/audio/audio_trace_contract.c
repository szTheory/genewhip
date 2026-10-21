/* SPDX-License-Identifier: MIT */
#include "genewhip/genewhip.h"
#include "../api/contract.h"

static size_t read_rom(const char *path, uint8_t *rom, size_t capacity)
{
    FILE *file = fopen(path, "rb");
    size_t size;
    CHECK(file != NULL, "open PSG ROM");
    size = fread(rom, 1, capacity, file);
    CHECK(!ferror(file) && fclose(file) == 0, "read PSG ROM");
    return size;
}

static gw_machine *loaded_machine(const uint8_t *rom, size_t size, uint32_t rate)
{
    gw_config config = {0};
    gw_machine *m = NULL;
    config.struct_size = sizeof(config);
    config.version = GW_API_VERSION;
    config.profile = GW_PROFILE_VA3_NTSC_U;
    config.reset_policy = GW_RESET_DETERMINISTIC_ZERO;
    config.audio_rate_hz = rate;
    CHECK(gw_create(&config, &m) == GW_OK, "create machine");
    CHECK(gw_load_rom(m, rom, size) == GW_OK, "load machine");
    return m;
}

static gw_run_result run_one_field(gw_machine *m)
{
    gw_run_result result = {0};
    result.struct_size = sizeof(result);
    result.version = GW_API_VERSION;
    CHECK(gw_run_until(m, GW_FIELD_TICKS, &result) == GW_OK, "run one field");
    CHECK(result.stop_reason == GW_STOP_FIELD_COMPLETE, "field stop");
    return result;
}

static size_t get_trace(gw_machine *m, gw_audio_write *writes, size_t capacity,
    uint64_t *dropped)
{
    size_t count = SIZE_MAX;
    CHECK(gw_get_audio_writes(m, writes, capacity, &count, dropped) == GW_OK,
        "get trace");
    return count;
}

static void check_three_writes(gw_machine *m, uint64_t actual_tick)
{
    const uint32_t values[3] = {0x8e, 0x0f, 0x90};
    const uint32_t regs[3] = {0, 0, 1};
    gw_audio_write writes[16];
    uint64_t dropped = UINT64_MAX;
    size_t count = get_trace(m, writes, 16, &dropped);
    size_t i;
    CHECK(count == 3 && dropped == 0, "three retained PSG writes");
    for (i = 0; i < count; ++i) {
        CHECK(writes[i].chip == GW_AUDIO_CHIP_PSG, "PSG chip id");
        CHECK(writes[i].source == GW_AUDIO_SOURCE_68000, "68000 write source");
        CHECK(writes[i].reg == regs[i], "PSG affected register");
        CHECK(writes[i].value == values[i], "raw PSG byte");
        CHECK(writes[i].tick > 0 && writes[i].tick <= actual_tick,
            "effective write tick in run");
        if (i) CHECK(writes[i - 1].tick < writes[i].tick, "strict tick ordering");
    }
}

int main(int argc, char **argv)
{
    uint8_t rom[2048];
    size_t rom_size;
    gw_machine *m;
    gw_run_result run;
    CHECK(argc == 2, "usage: audio_trace_contract PSG_ROM");
    rom_size = read_rom(argv[1], rom, sizeof(rom));
    CHECK(rom_size >= GW_MIN_ROM_SIZE, "PSG ROM size");

    m = loaded_machine(rom, rom_size, 48000);
    CHECK(gw_configure_audio_trace(m, 16) == GW_OK, "enable trace");
    run = run_one_field(m);
    check_three_writes(m, run.actual_tick);
    {
        gw_audio_write first[16], second[16];
        uint64_t lost_a, lost_b;
        size_t count_a = get_trace(m, first, 16, &lost_a);
        size_t count_b = get_trace(m, second, 16, &lost_b);
        CHECK(count_a == count_b && lost_a == lost_b, "copy-out metadata repeats");
        CHECK(memcmp(first, second, count_a * sizeof(first[0])) == 0,
            "copy-out does not consume records");
    }
    {
        gw_audio_write sentinel[2];
        size_t count = 444;
        uint64_t dropped = 555;
        memset(sentinel, 0xa5, sizeof(sentinel));
        CHECK(gw_get_audio_writes(m, sentinel, 2, &count, &dropped) == GW_ERROR_CAPACITY,
            "short trace output capacity");
        CHECK(count == 444 && dropped == 555, "short capacity leaves outputs unchanged");
        CHECK(sentinel[0].tick == UINT64_C(0xa5a5a5a5a5a5a5a5),
            "short capacity leaves buffer unchanged");
    }
    CHECK(gw_configure_audio_trace(m, 2) == GW_OK, "set two-entry trace capacity");
    CHECK(gw_cold_init(m) == GW_OK, "restart ROM for overflow case");
    run = run_one_field(m);
    {
        gw_audio_write writes[2];
        uint64_t dropped;
        CHECK(get_trace(m, writes, 2, &dropped) == 2, "two trace entries retained");
        CHECK(dropped == 1 && writes[0].value == 0x8e && writes[1].value == 0x0f,
            "drop newest and count overflow");
    }
    CHECK(gw_configure_audio_trace(m, 0) == GW_OK, "disable trace");
    CHECK(gw_cold_init(m) == GW_OK, "restart ROM for disabled trace case");
    run_one_field(m);
    {
        size_t count;
        uint64_t dropped;
        CHECK(gw_get_audio_writes(m, NULL, 0, &count, &dropped) == GW_OK,
            "zero capacity copy-out");
        CHECK(count == 0 && dropped == 0, "zero capacity records nothing");
    }
    CHECK(gw_configure_audio_trace(m, GW_AUDIO_TRACE_CAPACITY + 1u) == GW_ERROR_CAPACITY,
        "capacity above maximum rejected");
    CHECK(gw_configure_audio_trace(m, 16) == GW_OK, "restore trace");
    CHECK(gw_cold_init(m) == GW_OK, "restart ROM for reset case");
    run_one_field(m);
    CHECK(gw_cold_init(m) == GW_OK, "cold init clears trace");
    {
        size_t count;
        uint64_t dropped;
        CHECK(gw_get_audio_writes(m, NULL, 0, &count, &dropped) == GW_OK &&
            count == 0 && dropped == 0, "cold init empties trace");
    }
    run = run_one_field(m);
    CHECK(gw_console_reset(m) == GW_OK, "console reset");
    {
        gw_audio_write writes[16];
        uint64_t dropped;
        CHECK(get_trace(m, writes, 16, &dropped) == 3 && dropped == 0,
            "console reset preserves trace records");
    }
    CHECK(gw_load_rom(m, rom, rom_size) == GW_OK, "reload clears trace");
    {
        size_t count;
        uint64_t dropped;
        CHECK(gw_get_audio_writes(m, NULL, 0, &count, &dropped) == GW_OK &&
            count == 0 && dropped == 0, "load empties trace");
    }
    gw_destroy(m);

    {
        gw_machine *traced = loaded_machine(rom, rom_size, 48000);
        gw_machine *plain = loaded_machine(rom, rom_size, 48000);
        int16_t pcm_a[GW_AUDIO_QUEUE_FRAMES * 2], pcm_b[GW_AUDIO_QUEUE_FRAMES * 2];
        gw_audio_read_result audio_a = {0}, audio_b = {0};
        gw_run_result run_a, run_b;
        uint8_t ram_a[GW_RAM_SIZE], ram_b[GW_RAM_SIZE];
        CHECK(gw_configure_audio_trace(traced, 16) == GW_OK, "enable equivalence trace");
        run_a = run_one_field(traced);
        run_b = run_one_field(plain);
        CHECK(run_a.actual_tick == run_b.actual_tick && run_a.stop_reason == run_b.stop_reason,
            "trace does not change time or stop reason");
        CHECK(gw_peek_memory(traced, 0xff0000, ram_a, sizeof(ram_a)) == GW_OK &&
            gw_peek_memory(plain, 0xff0000, ram_b, sizeof(ram_b)) == GW_OK,
            "read equivalence RAM");
        CHECK(memcmp(ram_a, ram_b, sizeof(ram_a)) == 0, "trace does not change work RAM");
        audio_a.struct_size = audio_b.struct_size = sizeof(audio_a);
        audio_a.version = audio_b.version = GW_API_VERSION;
        CHECK(gw_audio_read(traced, pcm_a, GW_AUDIO_QUEUE_FRAMES, &audio_a) == GW_OK &&
            gw_audio_read(plain, pcm_b, GW_AUDIO_QUEUE_FRAMES, &audio_b) == GW_OK,
            "read equivalence PCM");
        CHECK(audio_a.produced == audio_b.produced &&
            memcmp(pcm_a, pcm_b, (size_t)audio_a.produced * 2u * sizeof(pcm_a[0])) == 0,
            "trace does not change PCM");
        gw_destroy(traced);
        gw_destroy(plain);
    }

    m = loaded_machine(rom, rom_size, 0);
    CHECK(gw_configure_audio_trace(m, 16) == GW_OK, "enable disabled-rate trace");
    run_one_field(m);
    check_three_writes(m, GW_FIELD_TICKS + 4u * GW_CPU_DIVIDER);
    {
        int16_t pcm[16];
        gw_audio_read_result result = {0};
        result.struct_size = sizeof(result);
        result.version = GW_API_VERSION;
        CHECK(gw_audio_read(m, pcm, 8, &result) == GW_OK, "disabled audio read");
        CHECK(result.produced == 0 && result.flags == GW_AUDIO_FLAG_DISABLED,
            "disabled audio remains observable");
    }
    gw_destroy(m);
    puts("audio_trace_contract: PASS");
    return 0;
}

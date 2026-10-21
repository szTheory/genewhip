/* SPDX-License-Identifier: MIT
 * Public-API cartridge -> bus -> chip -> resampler -> PCM tracer.
 * Frequency oracle: plutiedev.com/ym2612-registers, F-number/block relation.
 * Measure sign-crossing intervals after settling, not FFT-bin quantization.
 */
#include "genewhip/genewhip.h"
#include <stdio.h>
#include <stdlib.h>

#define CHECK(c, n) do { if (!(c)) { fprintf(stderr, "FAIL: %s (line %d)\n", n, __LINE__); exit(1); } } while (0)

int main(int argc, char **argv)
{
    uint8_t rom[4096];
    int16_t pcm[GW_AUDIO_QUEUE_FRAMES * 2];
    gw_config config = {0};
    gw_machine *machine = NULL;
    uint64_t cumulative = 0, first_cross = 0, last_cross = 0, crossings = 0;
    int previous_negative = 0, have_previous = 0, positive = 0, negative = 0;
    FILE *file;
    size_t size;
    CHECK(argc == 2, "usage: fm_tracer fm_tone.bin");
    file = fopen(argv[1], "rb"); CHECK(file != NULL, "open FM ROM");
    size = fread(rom, 1, sizeof(rom), file);
    CHECK(!ferror(file) && fclose(file) == 0 && size >= GW_MIN_ROM_SIZE, "read FM ROM");
    config.struct_size = sizeof(config); config.version = GW_API_VERSION;
    config.profile = GW_PROFILE_VA3_NTSC_U; config.reset_policy = GW_RESET_DETERMINISTIC_ZERO;
    config.audio_rate_hz = 48000;
    CHECK(gw_create(&config, &machine) == GW_OK, "create FM machine");
    CHECK(gw_load_rom(machine, rom, size) == GW_OK, "load FM ROM");
    CHECK(gw_configure_audio_trace(machine, 64) == GW_OK, "configure write trace");
    for (unsigned field = 0; field < 4; ++field) {
        gw_run_result run = {0};
        gw_audio_read_result read = {0};
        uint64_t expected;
        run.struct_size = sizeof(run); run.version = GW_API_VERSION;
        read.struct_size = sizeof(read); read.version = GW_API_VERSION;
        CHECK(gw_run_until(machine, 4u * (uint64_t)GW_FIELD_TICKS, &run) == GW_OK, "run FM field");
        CHECK(run.stop_reason == GW_STOP_FIELD_COMPLETE, "FM field completes");
        CHECK(gw_audio_read(machine, pcm, GW_AUDIO_QUEUE_FRAMES, &read) == GW_OK, "read FM PCM");
        expected = run.actual_tick / GW_MASTER_HZ * 48000u +
            (run.actual_tick % GW_MASTER_HZ) * 48000u / GW_MASTER_HZ;
        CHECK(read.first_index == cumulative && read.produced == expected - cumulative, "FM cumulative N(T)");
        CHECK(read.lost == 0 && read.clipped == 0, "FM no loss/clipping");
        if (field > 0) for (unsigned i = 0; i < read.produced; ++i) {
            int value = pcm[2u*i], sign = value < 0;
            positive |= value > 0; negative |= sign;
            CHECK(pcm[2u*i] == pcm[2u*i+1], "center pan is stereo equal");
            if (have_previous && previous_negative != sign) {
                uint64_t frame = cumulative + i;
                if (!crossings) first_cross = frame;
                last_cross = frame; ++crossings;
            }
            previous_negative = sign; have_previous = 1;
        }
        cumulative = expected;
    }
    CHECK(positive && negative, "FM key-on produces bipolar PCM");
    CHECK(crossings > 20 && last_cross > first_cross, "FM sign-crossing interval exists");
    {
        /* crossings-1 intervals / (2*seconds) agrees with FNUM*2^block*
         * master/(7*144*2^21), using integer cross-products. */
        const uint64_t fnum = 0x284, block_factor = 16;
        uint64_t measured = (crossings - 1) * 48000u * 7u * 144u * UINT64_C(2097152);
        uint64_t formula = 2u * fnum * block_factor * GW_MASTER_HZ * (last_cross - first_cross);
        uint64_t difference = measured > formula ? measured - formula : formula - measured;
        CHECK(difference * 100u <= formula, "FM frequency within 1 percent of F-number/block formula");
        printf("FM pitch: %llu intervals/%llu frames; formula FNUM=644 block=4; error_ppm=%llu\n",
            (unsigned long long)(crossings-1), (unsigned long long)(last_cross-first_cross),
            (unsigned long long)(difference * 1000000u / formula));
    }
    {
        gw_audio_write writes[64]; size_t count; uint64_t dropped; int keyon = 0;
        CHECK(gw_get_audio_writes(machine, writes, 64, &count, &dropped) == GW_OK, "read FM writes");
        CHECK(dropped == 0 && count == 15, "all FM data writes traced");
        for (size_t i = 0; i < count; ++i) {
            CHECK(writes[i].chip == GW_AUDIO_CHIP_YM_PORT0 && writes[i].source == GW_AUDIO_SOURCE_68000,
                "FM 68000 route recorded");
            if (i) CHECK(writes[i].tick > writes[i-1].tick, "FM write timestamps increase");
            if (writes[i].reg == 0x28 && writes[i].value == 0x10) keyon = 1;
        }
        CHECK(keyon, "FM key-on register/data traced");
    }
    gw_destroy(machine);
    puts("fm_tracer: PASS");
    return 0;
}

/* SPDX-License-Identifier: MIT
 * D-55 write-at-sample-boundary contract through the Z80 YM bus route. */
#include "internal.h"
#include <stdio.h>
#include <string.h>

static int z80_write_ym(gw_machine *m, uint64_t tick, uint16_t port, uint8_t value)
{
    m->z80.next_cycle_tick = tick;
    return gw_z80_mem_write(m, port, value, 0);
}

int main(int argc, char **argv)
{
    gw_config config;
    gw_machine *m = NULL;
    int old_behavior = argc == 2 && strcmp(argv[1], "--old-behavior-mutant") == 0;
    uint64_t boundary;
    int32_t left = 0, right = 0;
    memset(&config, 0, sizeof(config));
    config.struct_size = sizeof(config);
    config.version = GW_API_VERSION;
    config.profile = GW_PROFILE_VA3_NTSC_U;
    config.reset_policy = GW_RESET_DETERMINISTIC_ZERO;
    config.audio_rate_hz = 48000;
    if (gw_create(&config, &m) != GW_OK) return 2;
    gw_ym2612_reset_line(m, 0, 0);
    if (!z80_write_ym(m, 0, 0x4000, 0x2b) ||
        !z80_write_ym(m, 0, 0x4001, 0x80)) return 2;

    boundary = m->ym.next_sample_tick + 4u * GW_FM_SAMPLE_TICKS;
    gw_audio_sync(m, boundary - 1u);
    if (old_behavior) gw_audio_sync(m, boundary); /* exact pre-fix behavior */
    if (!z80_write_ym(m, boundary, 0x4000, 0x2a) ||
        !z80_write_ym(m, boundary, 0x4001, 0xff)) return 2;
    m->tick = boundary;
    if (!gw_test_ym_sample(m, &left, &right)) {
        fprintf(stderr, "FAIL: named_check=boundary_DAC_write_affects_same_native_sample detail=no_sample_after_bus_write\n");
        gw_destroy(m);
        return 1;
    }
    if (left == 0 || right == 0) {
        fprintf(stderr, "FAIL: named_check=boundary_DAC_write_affects_same_native_sample detail=sample_is_silent left=%d right=%d\n", left, right);
        gw_destroy(m);
        return 1;
    }
    if (old_behavior) {
        fprintf(stderr, "FAIL: named_check=old_behavior_mutant_must_be_rejected detail=boundary_write_was_accepted\n");
        gw_destroy(m);
        return 1;
    }
    printf("PASS: named_check=boundary_DAC_write_affects_same_native_sample left=%d right=%d tick=%llu\n",
           left, right, (unsigned long long)boundary);
    gw_destroy(m);
    return 0;
}

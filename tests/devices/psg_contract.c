/* SPDX-License-Identifier: MIT */
#include "../api/contract.h"
#include "internal.h"

static uint16_t oracle_shift(uint16_t value, int white)
{
    unsigned feedback = value & 1u;
    if (white) feedback ^= (value >> 3) & 1u;
    return (uint16_t)((value >> 1) | (feedback << 15));
}

static gw_machine *fresh(void)
{
    uint8_t rom[1024];
    gw_machine *m = machine();
    rom_init(rom, sizeof(rom));
    CHECK(gw_load_rom(m, rom, sizeof(rom)) == GW_OK, "load contract ROM");
    return m;
}

static void protocol(void)
{
    gw_machine *m = fresh();
    gw_psg *psg = &m->psg;
    gw_psg_write(m, 0x85); /* tone 0 period low nibble */
    gw_psg_write(m, 0x23); /* data updates the upper six tone bits */
    CHECK(psg->period[0] == 0x235, "data byte updates tone period high bits");
    gw_psg_write(m, 0x9a); /* tone 0 attenuation */
    CHECK(psg->attenuation[0] == 10, "latched attenuation register updates");
    gw_psg_write(m, 0xe4); /* white noise, rate 0; every write resets the LFSR */
    CHECK(psg->lfsr == UINT16_C(0x8000), "noise write resets LFSR to 0x8000");
    gw_psg_advance(m, UINT64_C(17) * GW_PSG_STEP_TICKS);
    CHECK(psg->lfsr != UINT16_C(0x8000), "noise channel advances before reset check");
    gw_psg_write(m, 0xe4);
    CHECK(psg->lfsr == UINT16_C(0x8000), "every noise-register write resets LFSR");
    gw_psg_write(m, 0x80); /* period zero */
    gw_psg_write(m, 0x00);
    gw_psg_advance(m, UINT64_C(1000) * GW_PSG_STEP_TICKS);
    CHECK(psg->output[0] == 1, "tone period zero holds output high");
    gw_psg_write(m, 0x81); /* period one */
    gw_psg_write(m, 0x00);
    gw_psg_advance(m, UINT64_C(2000) * GW_PSG_STEP_TICKS);
    CHECK(psg->output[0] == 1, "tone period one holds output high");
    {
        int64_t expected_q = INT64_C(2048) * 1000000;
        unsigned attenuation;
        for (attenuation = 0; attenuation < 15; ++attenuation) {
            int32_t expected = (int32_t)((expected_q + 500000) / 1000000);
            gw_psg_write(m, (uint8_t)(0x90u | attenuation));
            CHECK(abs(gw_test_psg_level(m) - expected) <= 1,
                "attenuation follows independently calculated 2 dB steps");
            expected_q = expected_q * 794328 / 1000000;
        }
        gw_psg_write(m, 0x9f);
        CHECK(gw_test_psg_level(m) == 0, "attenuation step 15 is silent");
    }
    gw_destroy(m);
}

static void check_lfsr(unsigned rate, int white)
{
    gw_machine *m = fresh();
    uint16_t expected = UINT16_C(0x8000);
    unsigned i;
    uint64_t tick = 0;
    if (rate == 3) {
        gw_psg_write(m, 0xc2); /* tone 2 period 2 */
        gw_psg_write(m, 0xe7); /* white noise clocked by tone 2 */
        for (i = 0; i < 1000; ++i) {
            tick += UINT64_C(2) * GW_PSG_STEP_TICKS;
            gw_psg_advance(m, tick);
            expected = oracle_shift(expected, white);
            CHECK(gw_test_psg_lfsr(m) == expected, "tone-2 driven LFSR step matches independent oracle");
        }
    } else {
        static const unsigned divisor[] = {0x10u, 0x20u, 0x40u};
        gw_psg_write(m, (uint8_t)(0xe0u | (white ? 4u : 0u) | rate));
        for (i = 0; i < 1000; ++i) {
            tick += (uint64_t)divisor[rate] * GW_PSG_STEP_TICKS;
            gw_psg_advance(m, tick);
            expected = oracle_shift(expected, white);
            CHECK(gw_test_psg_lfsr(m) == expected, "fixed-rate LFSR step matches independent oracle");
        }
    }
    gw_destroy(m);
}

static void enabled_tone2_clock(void)
{
    uint8_t rom[1024];
    gw_machine *m = NULL;
    gw_config config = {0};
    rom_init(rom, sizeof(rom));
    config.struct_size = sizeof(config);
    config.version = GW_API_VERSION;
    config.profile = GW_PROFILE_VA3_NTSC_U;
    config.reset_policy = GW_RESET_DETERMINISTIC_ZERO;
    config.audio_rate_hz = 48000;
    CHECK(gw_create(&config, &m) == GW_OK, "create enabled-audio machine");
    CHECK(gw_load_rom(m, rom, sizeof(rom)) == GW_OK, "load enabled-audio ROM");
    gw_psg_write(m, 0xc2);
    gw_psg_write(m, 0xe7);
    gw_psg_advance(m, UINT64_C(2) * GW_PSG_STEP_TICKS);
    CHECK(gw_test_psg_lfsr(m) == oracle_shift(UINT16_C(0x8000), 1),
        "enabled-audio path clocks noise on tone-2 transition");
    gw_destroy(m);
}

int main(int argc, char **argv)
{
    CHECK(argc == 2, "mode required");
    if (!strcmp(argv[1], "protocol")) protocol();
    else if (!strcmp(argv[1], "lfsr")) {
        check_lfsr(0, 1);
        check_lfsr(1, 1);
        check_lfsr(2, 1);
        check_lfsr(3, 1);
        enabled_tone2_clock();
    } else CHECK(0, "unknown mode");
    puts("psg contract: PASS");
    return 0;
}

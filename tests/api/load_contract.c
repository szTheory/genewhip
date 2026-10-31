/* SPDX-License-Identifier: MIT */
#include "contract.h"
#ifdef GW_TEST_HOOKS
#include "internal.h"
#endif

static void rejected(gw_machine *m, const void *rom, size_t size, gw_status expected)
{
    gw_diagnostic_record before = snapshot(m), after;
    uint8_t memory[GW_RAM_SIZE], copy[GW_RAM_SIZE], old_rom[1024], new_rom[1024];
    CHECK(gw_peek_memory(m, 0xff0000, memory, sizeof(memory)) == GW_OK, "prior RAM");
    CHECK(gw_peek_memory(m, 0, old_rom, sizeof(old_rom)) == GW_OK, "prior ROM");
    { gw_status actual = gw_load_rom(m, rom, size);
      if (actual != expected) fprintf(stderr, "load status mismatch: got %d expected %d size %zu\n", actual, expected, size);
      CHECK(actual == expected, "stable load error"); }
    after = snapshot(m);
    CHECK(memcmp(&before, &after, sizeof(before)) == 0, "rejected load preserves CPU/time/counters");
    CHECK(gw_peek_memory(m, 0xff0000, copy, sizeof(copy)) == GW_OK, "retained RAM");
    CHECK(gw_peek_memory(m, 0, new_rom, sizeof(new_rom)) == GW_OK, "retained ROM");
    CHECK(memcmp(memory, copy, sizeof(copy)) == 0, "rejected load preserves RAM");
    CHECK(memcmp(old_rom, new_rom, sizeof(old_rom)) == 0, "rejected load preserves ROM");
}

static gw_machine *audio_machine(void)
{
    gw_config c = { sizeof(c), GW_API_VERSION, GW_PROFILE_VA3_NTSC_U,
        GW_RESET_DETERMINISTIC_ZERO, 1, { GW_DEVICE_PAD3, GW_DEVICE_PAD3 }, 22050 };
    gw_machine *m = NULL;
    CHECK(gw_create(&c, &m) == GW_OK, "audio-enabled control create");
    return m;
}

static void compare_future_observations(gw_machine *a, gw_machine *b)
{
    int16_t aa[GW_AUDIO_QUEUE_FRAMES * 2u], ba[GW_AUDIO_QUEUE_FRAMES * 2u];
    gw_audio_read_result ar = {0}, br = {0};
    uint8_t am[GW_RAM_SIZE], bm[GW_RAM_SIZE];
    gw_run_result ra = run(a, 2u * (uint64_t)GW_FIELD_TICKS);
    gw_run_result rb = run(b, 2u * (uint64_t)GW_FIELD_TICKS);
    CHECK(ra.actual_tick == rb.actual_tick && ra.stop_reason == rb.stop_reason,
        "rejected load continuation tick and stop");
    same(a, b);
    CHECK(gw_peek_memory(a, 0xff0000u, am, sizeof(am)) == GW_OK &&
          gw_peek_memory(b, 0xff0000u, bm, sizeof(bm)) == GW_OK &&
          memcmp(am, bm, sizeof(am)) == 0, "rejected load future RAM");
    same_video(a, b);
    ar.struct_size = br.struct_size = sizeof(ar); ar.version = br.version = GW_API_VERSION;
    CHECK(gw_audio_read(a, aa, GW_AUDIO_QUEUE_FRAMES, &ar) == GW_OK &&
          gw_audio_read(b, ba, GW_AUDIO_QUEUE_FRAMES, &br) == GW_OK, "rejected load future PCM read");
    CHECK(ar.produced == br.produced && ar.first_index == br.first_index && ar.lost == br.lost &&
          memcmp(aa, ba, (size_t)ar.produced * 2u * sizeof(int16_t)) == 0,
          "rejected load future PCM");
}

int main(void)
{
    uint8_t rom[1024], bad[1024], *large;
    gw_machine *m = audio_machine(), *peer = audio_machine(), *out;
    gw_config c = {sizeof(c), GW_API_VERSION, GW_PROFILE_VA3_NTSC_U, GW_RESET_DETERMINISTIC_ZERO, 1};
    gw_event e = {sizeof(e), GW_API_VERSION, 500, GW_EVENT_CONSOLE_RESET, 0};
    rom_init(rom, sizeof(rom));
    /* Guest writes a byte before looping: rejection must preserve nonzero RAM. */
    { const uint8_t code[] = {0x13,0xfc,0,0x42,0,0xff,0,0,0x60,0xfe}; memcpy(rom+512, code, sizeof(code)); }
    CHECK(gw_load_rom(m, rom, sizeof(rom)) == GW_OK, "load");
    CHECK(gw_load_rom(peer, rom, sizeof(rom)) == GW_OK, "peer load");
    CHECK(gw_schedule_event(m, &e) == GW_OK && gw_schedule_event(peer, &e) == GW_OK, "queued reset");
    (void)run(m, 300); (void)run(peer, 300);
    rejected(m, NULL, 0, GW_ERROR_ARGUMENT);
    rejected(m, rom, 0, GW_ERROR_ROM);
    rejected(m, rom, 1, GW_ERROR_ROM);
    rejected(m, rom, 511, GW_ERROR_ROM);
    rejected(m, rom, 512, GW_ERROR_ROM); /* No complete word at PC 512. */
    rejected(m, rom, 513, GW_ERROR_ROM);
    rejected(m, rom, 515, GW_ERROR_ROM);
    rejected(m, rom, 1023, GW_ERROR_ROM);
    rejected(m, rom, (size_t)GW_MAX_ROM_SIZE + 1, GW_ERROR_ROM);
    rejected(m, rom, SIZE_MAX, GW_ERROR_ROM); /* Must reject before dereference. */
    { const uint32_t pcs[] = {0, 510, 513, 1024, UINT32_MAX};
      for (size_t i=0; i<sizeof(pcs)/sizeof(pcs[0]); ++i) {
        memcpy(bad, rom, sizeof(bad)); put32(bad+4, pcs[i]); rejected(m, bad, sizeof(bad), GW_ERROR_ROM);
      } }
    { const uint32_t sps[] = {0, 0xe00004, 0xe00005, 0xfffffd, 0xffffff, UINT32_MAX};
      for (size_t i=0; i<sizeof(sps)/sizeof(sps[0]); ++i) {
        memcpy(bad, rom, sizeof(bad)); put32(bad, sps[i]); rejected(m, bad, sizeof(bad), GW_ERROR_ROM);
      } }
    compare_future_observations(m, peer); /* Rejected loads preserve later RAM/video/PCM. */
    { uint8_t memory[GW_RAM_SIZE+1];
      CHECK(gw_peek_memory(m,0xff0000,memory,GW_RAM_SIZE-1)==GW_OK,"peek below capacity");
      CHECK(gw_peek_memory(m,0xff0000,memory,GW_RAM_SIZE)==GW_OK,"peek at capacity");
      memset(memory,0xa5,sizeof(memory));
      CHECK(gw_peek_memory(m,0xff0000,memory,sizeof(memory))==GW_ERROR_ARGUMENT,"peek above capacity");
      for (size_t i=0;i<sizeof(memory);++i) CHECK(memory[i]==0xa5,"rejected peek preserves output");
      CHECK(gw_peek_memory(m,0,NULL,0)==GW_OK,"empty peek");
    }
    out = m; c.profile = 0;
    CHECK(gw_create(&c, &out) == GW_ERROR_PROFILE && out == m, "reject unspecified profile");
    c.profile = 2;
    CHECK(gw_create(&c, &out) == GW_ERROR_PROFILE && out == m, "reject other region/profile");
    c.profile = UINT32_MAX;
    CHECK(gw_create(&c, &out) == GW_ERROR_PROFILE && out == m, "reject unknown profile");
    c.profile = GW_PROFILE_VA3_NTSC_U; c.reset_policy = 0;
    CHECK(gw_create(&c, &out) == GW_ERROR_UNSUPPORTED && out == m, "unsupported reset policy has distinct error");
    c.reset_policy = GW_RESET_DETERMINISTIC_ZERO; c.diagnostics = 2;
    CHECK(gw_create(&c, &out) == GW_ERROR_ARGUMENT && out == m, "diagnostic choice");
    c.diagnostics = 0; c.version++;
    CHECK(gw_create(&c, &out) == GW_ERROR_VERSION && out == m, "config version");
    c.version = GW_API_VERSION; c.struct_size--;
    CHECK(gw_create(&c, &out) == GW_ERROR_VERSION && out == m, "config size");
    CHECK(gw_create(NULL, &out) == GW_ERROR_ARGUMENT && out == m, "null config");
    CHECK(gw_create(&c, NULL) == GW_ERROR_ARGUMENT, "null owner");
    large = malloc((size_t)GW_MAX_ROM_SIZE + 1); CHECK(large != NULL, "test allocation");
    rom_init(large, (size_t)GW_MAX_ROM_SIZE + 1);
    CHECK(gw_load_rom(m, large, 514) == GW_OK, "minimum executable ROM");
    CHECK(gw_load_rom(m, large, GW_MAX_ROM_SIZE - 2) == GW_OK, "largest below limit even size");
    CHECK(gw_load_rom(m, large, GW_MAX_ROM_SIZE - 1) == GW_ERROR_ROM, "below limit odd size");
    CHECK(gw_load_rom(m, large, GW_MAX_ROM_SIZE) == GW_OK, "exact maximum");
    CHECK(gw_load_rom(m, large, (size_t)GW_MAX_ROM_SIZE + 1) == GW_ERROR_ROM, "above maximum");
    put32(large, 0xe00006); put32(large+4, GW_MAX_ROM_SIZE-2);
    CHECK(gw_load_rom(m, large, GW_MAX_ROM_SIZE) == GW_OK, "lower stack and upper PC boundary");
    put32(large, 0xfffffe); put32(large+4, 512);
    memcpy(large+0x1f0, "J E", 3); /* Advisory conflicting region metadata. */
    CHECK(gw_load_rom(m, large, 1024) == GW_OK, "upper stack boundary and advisory header");
    memset(large, 0, 1024); free(large);
    CHECK(snapshot(m).profile == GW_PROFILE_VA3_NTSC_U, "profile never inferred");
    CHECK(run(m, 113).stop_reason == GW_STOP_TARGET, "ROM copy independent of caller lifetime");
#ifdef GW_TEST_HOOKS
    CHECK(gw_load_rom(m, rom, sizeof(rom)) == GW_OK && gw_load_rom(peer, rom, sizeof(rom)) == GW_OK,
          "reload matched allocation-failure controls");
    (void)run(m, 300); (void)run(peer, 300);
    gw_test_fail_next_rom_allocation(m);
    rejected(m, rom, sizeof(rom), GW_ERROR_MEMORY);
    compare_future_observations(m, peer);
#endif
    {
      FILE *fixture = fopen(GW_FIXTURE_TANK, "rb");
      uint8_t *tank = malloc(524288);
      CHECK(fixture != NULL && tank != NULL, "open admitted Tank fixture");
      CHECK(fread(tank, 1, 524288, fixture) == 524288 && fgetc(fixture) == EOF,
            "read exact admitted Tank bytes");
      fclose(fixture);
      CHECK((((uint32_t)tank[0] << 24) | ((uint32_t)tank[1] << 16) |
             ((uint32_t)tank[2] << 8) | tank[3]) == UINT32_C(0xe1000000) &&
            (((uint32_t)tank[4] << 24) | ((uint32_t)tank[5] << 16) |
             ((uint32_t)tank[6] << 8) | tank[7]) == 0x200,
            "Tank reset vector baseline");
      CHECK(gw_load_rom(m, tank, 524288) == GW_OK, "load exact admitted Tank ROM");
#ifdef GW_TEST_HOOKS
      CHECK(m->initial_ssp == UINT32_C(0xe1000000) && m->cpu.a[7] == UINT32_C(0xe1000000),
            "preserve full 32-bit reset stack register");
#endif
      {
        const uint32_t accepted[] = {0x00e00006, 0x00fffffc, 0x00fffffe, 0x01000000,
                                     0xe0000000, 0xe1000000};
        const uint32_t rejected_sps[] = {0, 0x00e00004, 0x00e00005,
                                         0x00ffffff, 0x01000002, 0xe1000002, UINT32_MAX};
        for (size_t i = 0; i < sizeof(accepted)/sizeof(accepted[0]); ++i) {
          memcpy(bad, rom, sizeof(bad)); put32(bad, accepted[i]); put32(bad + 4, 512);
          CHECK(gw_load_rom(m, bad, sizeof(bad)) == GW_OK, "mapped six-byte reset stack frame");
        }
        for (size_t i = 0; i < sizeof(rejected_sps)/sizeof(rejected_sps[0]); ++i) {
          memcpy(bad, rom, sizeof(bad)); put32(bad, rejected_sps[i]);
          rejected(m, bad, sizeof(bad), GW_ERROR_ROM);
        }
      }
      free(tank);
    }
    gw_destroy(m); gw_destroy(peer); gw_destroy(NULL);
    puts("load_contract: PASS"); return 0;
}

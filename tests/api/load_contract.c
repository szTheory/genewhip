/* SPDX-License-Identifier: MIT */
#include "contract.h"

static void rejected(gw_machine *m, const void *rom, size_t size, gw_status expected)
{
    gw_diagnostic_record before = snapshot(m), after;
    uint8_t memory[GW_RAM_SIZE], copy[GW_RAM_SIZE], old_rom[1024], new_rom[1024];
    CHECK(gw_peek_memory(m, 0xff0000, memory, sizeof(memory)) == GW_OK, "prior RAM");
    CHECK(gw_peek_memory(m, 0, old_rom, sizeof(old_rom)) == GW_OK, "prior ROM");
    CHECK(gw_load_rom(m, rom, size) == expected, "stable load error");
    after = snapshot(m);
    CHECK(memcmp(&before, &after, sizeof(before)) == 0, "rejected load preserves CPU/time/counters");
    CHECK(gw_peek_memory(m, 0xff0000, copy, sizeof(copy)) == GW_OK, "retained RAM");
    CHECK(gw_peek_memory(m, 0, new_rom, sizeof(new_rom)) == GW_OK, "retained ROM");
    CHECK(memcmp(memory, copy, sizeof(copy)) == 0, "rejected load preserves RAM");
    CHECK(memcmp(old_rom, new_rom, sizeof(old_rom)) == 0, "rejected load preserves ROM");
}

int main(void)
{
    uint8_t rom[1024], bad[1024], *large;
    gw_machine *m = machine(), *peer = machine(), *out;
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
    (void)run(m, 1000); (void)run(peer, 1000); same(m, peer); /* Queue also survived. */
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
    gw_destroy(m); gw_destroy(peer); gw_destroy(NULL);
    puts("load_contract: PASS"); return 0;
}

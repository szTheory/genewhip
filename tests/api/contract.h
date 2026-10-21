/* SPDX-License-Identifier: MIT */
#ifndef GW_TEST_CONTRACT_H
#define GW_TEST_CONTRACT_H
#include "genewhip/genewhip.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(c, name) do { if (!(c)) { fprintf(stderr, "FAIL: %s (line %d)\n", name, __LINE__); exit(1); } } while (0)
static inline void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static inline void rom_init(uint8_t *rom, size_t size)
{
    memset(rom, 0, size);
    put32(rom, 0xffff00); put32(rom + 4, 0x200);
    rom[512] = 0x60; rom[513] = 0xfe; /* BRA self */
}
static inline gw_machine *machine(void)
{
    gw_machine *m = NULL;
    gw_config c = {sizeof(c), GW_API_VERSION, GW_PROFILE_VA3_NTSC_U, GW_RESET_DETERMINISTIC_ZERO, 1, {0, 0}};
    CHECK(gw_create(&c, &m) == GW_OK, "create");
    return m;
}
static inline gw_diagnostic_record snapshot(gw_machine *m)
{
    gw_diagnostic_record d = {0}; d.struct_size = sizeof(d); d.version = GW_API_VERSION;
    CHECK(gw_get_diagnostics(m, &d) == GW_OK, "snapshot"); return d;
}
/* Phase 1 amendment (02-01): zero flags -> explicit run request. */
static inline gw_run_result run(gw_machine *m, uint64_t target)
{
    gw_run_result r = {0}; r.struct_size = sizeof(r); r.version = GW_API_VERSION;
    r.flags = GW_RUN_CONTINUE_PAST_FIELD; /* Run-to-target request. */
    CHECK(gw_run_until(m, target, &r) == GW_OK, "run"); return r;
}
/* Phase 1 amendment (02-01): zero flags -> explicit run request. */
static inline gw_run_result run_field(gw_machine *m, uint64_t target)
{
    gw_run_result r = {0}; r.struct_size = sizeof(r); r.version = GW_API_VERSION;
    /* Field-stop request: flags 0. */
    CHECK(gw_run_until(m, target, &r) == GW_OK, "run_field"); return r;
}
static inline void same(gw_machine *a, gw_machine *b)
{
    gw_diagnostic_record x = snapshot(a), y = snapshot(b);
    uint8_t ax[GW_RAM_SIZE], bx[GW_RAM_SIZE];
    CHECK(memcmp(&x, &y, sizeof(x)) == 0, "same CPU/time/counters");
    CHECK(gw_peek_memory(a, 0xff0000, ax, sizeof(ax)) == GW_OK, "read RAM a");
    CHECK(gw_peek_memory(b, 0xff0000, bx, sizeof(bx)) == GW_OK, "read RAM b");
    CHECK(memcmp(ax, bx, sizeof(ax)) == 0, "same RAM");
}
#endif

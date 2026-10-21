/* SPDX-License-Identifier: MIT
 * Private CPU semantic adapter (protocol v2). No new installed API or alternate
 * CPU engine. Built only with GW_TEST_HOOKS: every vector runs against the sparse
 * memory overlay, which serves exactly the addresses the vector lists.
 *
 * One vector per input record:
 *   opcode, 18 initial registers, 18 final registers, initial PC, final PC,
 *   initial RAM count + (address value) pairs, final RAM count + pairs
 * Registers: D0-D7, A0-A6, USP, SSP, SR. Upstream PC is four bytes past the
 * opcode word (two prefetch words), so execution starts at initial PC - 4.
 */
#include "../../src/internal.h"
#include "../api/contract.h"
#include <inttypes.h>

#define MAX_PAIRS GW_TEST_MEMORY_CAPACITY

typedef struct { uint32_t address, value; } pair;

static size_t read_pairs(pair *out)
{
    uint32_t count;
    CHECK(scanf("%" SCNu32, &count) == 1, "RAM pair count");
    CHECK(count <= MAX_PAIRS, "RAM pair count within overlay bound");
    for (size_t i = 0; i < count; ++i) {
        CHECK(scanf("%" SCNu32 " %" SCNu32, &out[i].address, &out[i].value) == 2, "RAM pair");
        CHECK(out[i].address <= UINT32_C(0xffffff) && out[i].value <= 0xffu, "RAM pair range");
    }
    return count;
}

static const pair *find_pair(const pair *list, size_t count, uint32_t address)
{
    for (size_t i = 0; i < count; ++i) if (list[i].address == address) return &list[i];
    return NULL;
}

static const char *verdict(gw_machine *m, const uint32_t *final, uint32_t final_pc,
                           const pair *before, size_t before_count,
                           const pair *after, size_t after_count)
{
    uint32_t address;
    uint8_t byte;
    if (gw_test_memory_miss(m, &address)) return "unlisted memory read";
    if (m->cpu.stop_reason == GW_STOP_UNSUPPORTED_INSTRUCTION) return "UNSUPPORTED instruction";
    if (m->cpu.stop_reason == GW_STOP_UNSUPPORTED_ADDRESS) return "UNSUPPORTED address";
    if (m->cpu.stop_reason == GW_STOP_UNSUPPORTED_STATE) return "UNSUPPORTED state";
    if (m->cpu.stop_reason != GW_STOP_TARGET) return "register mismatch";
    for (size_t i = 0; i < 8; ++i) if (m->cpu.d[i] != final[i]) return "register mismatch";
    for (size_t i = 0; i < 7; ++i) if (m->cpu.a[i] != final[8 + i]) return "register mismatch";
    if (m->cpu.a[7] != final[16] || m->cpu.sr != final[17] || m->cpu.pc != final_pc - 4u)
        return "register mismatch";
    for (size_t i = 0; i < after_count; ++i)
        if (!gw_test_memory_get(m, after[i].address, &byte) || byte != after[i].value)
            return "memory mismatch";
    /* Any byte the instruction touched beyond the final list must be an
     * unchanged initial byte. */
    for (size_t i = 0; i < m->test_memory_count; ++i) {
        const pair *listed = find_pair(after, after_count, m->test_memory[i].address);
        if (listed) continue;
        listed = find_pair(before, before_count, m->test_memory[i].address);
        if (!listed || listed->value != m->test_memory[i].value) return "memory mismatch";
    }
    return "PASS";
}

int main(void)
{
    gw_machine *m = machine();
    uint8_t rom[1024];
    uint32_t op, initial[18], final[18], pc, final_pc;
    static pair before[MAX_PAIRS], after[MAX_PAIRS];
    size_t index = 0;
    rom_init(rom, sizeof(rom));
    CHECK(gw_configure_diagnostics(m, 0) == GW_OK, "disable instrumentation");
    while (scanf("%" SCNu32, &op) == 1) {
        size_t before_count, after_count;
        for (size_t i = 0; i < 18; ++i) CHECK(scanf("%" SCNu32, &initial[i]) == 1, "initial fields");
        for (size_t i = 0; i < 18; ++i) CHECK(scanf("%" SCNu32, &final[i]) == 1, "final fields");
        CHECK(scanf("%" SCNu32 " %" SCNu32, &pc, &final_pc) == 2, "PC fields");
        before_count = read_pairs(before);
        after_count = read_pairs(after);
        (void)op; /* the opcode word is in the overlay at PC - 4 */
        m->test_memory_active = 0; /* the reset vector fetch must see the ROM */
        CHECK(gw_load_rom(m, rom, sizeof(rom)) == GW_OK, "adapter ROM");
        gw_test_memory_reset(m);
        for (size_t i = 0; i < before_count; ++i)
            CHECK(gw_test_memory_set(m, before[i].address, (uint8_t)before[i].value), "overlay capacity");
        for (size_t i = 0; i < 8; ++i) m->cpu.d[i] = initial[i];
        for (size_t i = 0; i < 7; ++i) m->cpu.a[i] = initial[8 + i];
        m->cpu.a[7] = initial[16];
        m->cpu.sr = (uint16_t)initial[17];
        m->cpu.pc = pc - 4u;
        gw_cpu_step(m);
        printf("%zu %s\n", index++, verdict(m, final, final_pc, before, before_count, after, after_count));
    }
    CHECK(feof(stdin), "invalid adapter input");
    CHECK(index > 0, "nonempty applicable denominator");
    gw_destroy(m);
    return 0;
}

/* SPDX-License-Identifier: MIT */
#include "contract.h"
#include "internal.h"

int main(void)
{
    uint8_t first[1024], second[2048], invalid[1024];
    gw_machine *a = machine(), *b = machine();
    size_t a_base = gw_test_owned_bytes_current(a);
    size_t b_base = gw_test_owned_bytes_current(b);
    uint64_t a_calls = gw_test_allocation_count(a);
    uint64_t b_calls = gw_test_allocation_count(b);

    CHECK(a_base > 0 && b_base == a_base, "instance storage counted independently");
    CHECK(gw_test_owned_bytes_peak(a) == a_base, "initial peak includes machine only");
    rom_init(first, sizeof(first)); rom_init(second, sizeof(second));
    memcpy(invalid, first, sizeof(invalid)); put32(invalid + 4, 0);
    CHECK(gw_load_rom(a, first, sizeof(first)) == GW_OK, "first ROM load");
    CHECK(gw_test_owned_bytes_current(a) == a_base + sizeof(first), "current includes owned ROM bytes");
    CHECK(gw_test_owned_bytes_peak(a) == a_base + sizeof(first), "peak follows first ROM load");
    CHECK(gw_test_owned_bytes_current(b) == b_base && gw_test_allocation_count(b) == b_calls,
          "peer accounting is isolated");

    a_calls = gw_test_allocation_count(a);
    CHECK(gw_load_rom(a, invalid, sizeof(invalid)) == GW_ERROR_ROM, "invalid replacement rejected");
    CHECK(gw_test_owned_bytes_current(a) == a_base + sizeof(first) &&
          gw_test_allocation_count(a) == a_calls, "rejected replacement preserves ownership counters");

    CHECK(gw_load_rom(a, second, sizeof(second)) == GW_OK, "valid replacement");
    CHECK(gw_test_owned_bytes_current(a) == a_base + sizeof(second), "replacement current excludes old ROM");
    CHECK(gw_test_owned_bytes_peak(a) == a_base + sizeof(first) + sizeof(second),
          "replacement peak includes allocation overlap");
    a_calls = gw_test_allocation_count(a);
    CHECK(run(a, 20u * GW_FIELD_TICKS).stop_reason == GW_STOP_TARGET, "steady execution target");
    CHECK(gw_test_allocation_count(a) == a_calls &&
          gw_test_owned_bytes_current(a) == a_base + sizeof(second), "steady execution allocates no core storage");
    CHECK(gw_test_owned_bytes_current(b) == b_base && gw_test_owned_bytes_peak(b) == b_base,
          "peer remains unchanged through replacement and execution");
    gw_destroy(a); gw_destroy(b);
    puts("memory_accounting: PASS");
    return 0;
}

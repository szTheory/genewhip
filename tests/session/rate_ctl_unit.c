/* SPDX-License-Identifier: MIT */
#include "rate_ctl.h"

#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "FAIL:%d: %s\n", __LINE__, #expr); return 1; } } while (0)

typedef struct simulation_result {
    int64_t depth;
    unsigned underruns;
    unsigned sign_changes_per_100;
} simulation_result;

static simulation_result simulate(int32_t consumer_drift_ppm)
{
    const int64_t target = 2403;
    const uint64_t master_hz = UINT64_C(53693175);
    const uint64_t field_ticks = UINT64_C(896040);
    const uint64_t denominator = UINT64_C(1000000000000);
    int64_t depth = target;
    uint64_t phase = 0, now_us = 0, next_field_us = 16687;
    int32_t ratio_ppm = 0, previous_sign = 0;
    unsigned underruns = 0, window_changes = 0, max_window_changes = 0;

    for (uint64_t field = 1; field <= 6000; ++field) {
        const uint64_t field_tick = field * field_ticks;
        const uint64_t samples_now = field_tick * UINT64_C(48000) / master_hz;
        const uint64_t samples_before = (field - 1) * field_ticks * UINT64_C(48000) / master_hz;
        const int64_t produced = (int64_t)(samples_now - samples_before);
        const uint64_t field_deadline = next_field_us;

        while (now_us < field_deadline) {
            uint64_t multiplier = (uint64_t)(1000000 + consumer_drift_ppm) *
                (uint64_t)(1000000 + ratio_ppm);
            phase += UINT64_C(48) * multiplier;
            depth -= (int64_t)(phase / denominator);
            phase %= denominator;
            if (depth < 0) { underruns++; depth = 0; }
            now_us += 1000;
        }
        depth += produced;
        ratio_ppm = gw_rate_ppm(depth, target, GW_RATE_K_PPM);
        if (field > 30) {
            int32_t sign = (ratio_ppm > 0) - (ratio_ppm < 0);
            if (sign && previous_sign && sign != previous_sign) window_changes++;
            if (sign) previous_sign = sign;
            if (field % 100 == 0) {
                if (window_changes > max_window_changes) max_window_changes = window_changes;
                window_changes = 0;
            }
        }
        next_field_us += 16687;
    }
    if (window_changes > max_window_changes) max_window_changes = window_changes;
    return (simulation_result){depth, underruns, max_window_changes};
}

int main(void)
{
    const simulation_result fast = simulate(3000);
    const simulation_result slow = simulate(-3000);
    CHECK(gw_rate_ppm(2403, 2403, 1000000) == 0);
    CHECK(gw_rate_ppm(4806, 2403, 1000000) == 5000);
    CHECK(gw_rate_ppm(0, 2403, 1000000) == -5000);
    CHECK(gw_rate_ppm(2408, 2403, 1000000) == 2080);
    CHECK(gw_rate_ppm(INT64_MAX, 1, INT32_MAX) == 5000);
    CHECK(gw_rate_ppm(INT64_MIN, 1, INT32_MAX) == -5000);
    CHECK(gw_rate_ppm(0, 0, INT32_MAX) == 0);
    CHECK(gw_rate_ppm(4806, 2403, INT32_MIN) == -5000);
    CHECK(fast.depth >= 2403 * 3 / 4 && fast.depth <= 2403 * 5 / 4);
    CHECK(slow.depth >= 2403 * 3 / 4 && slow.depth <= 2403 * 5 / 4);
    CHECK(fast.underruns == 0 && slow.underruns == 0);
    CHECK(fast.sign_changes_per_100 <= 2 && slow.sign_changes_per_100 <= 2);
    printf("rate_ctl simulation: fast depth=%" PRId64 " underruns=%u sign_changes=%u; "
        "slow depth=%" PRId64 " underruns=%u sign_changes=%u (k=%d)\n",
        fast.depth, fast.underruns, fast.sign_changes_per_100,
        slow.depth, slow.underruns, slow.sign_changes_per_100, GW_RATE_K_PPM);
    return 0;
}

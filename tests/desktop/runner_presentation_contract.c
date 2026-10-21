/* SPDX-License-Identifier: MIT */
#include "stats.h"

#include <stdio.h>
#include <stdlib.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "CHECK failed: %s at %s:%d\n", #condition, __FILE__, __LINE__); \
        exit(1); \
    } \
} while (0)

int main(void)
{
    runner_stats stats = {0};
    runner_stats saturated = {0};
    const uint32_t same_pixels[] = {0xff123456u, 0xff123456u};

    /* Deterministic clock seam: exact and 450 us-late scheduled deadlines. */
    runner_stats_deadline(&stats, 100u, 100u);
    runner_stats_deadline(&stats, 200u, 450200u);
    runner_stats_exposure(&stats, 500200u);
    CHECK(stats.scheduled_deadlines == 2u);
    CHECK(stats.lateness_samples == 2u && stats.late_deadlines == 1u);
    CHECK(stats.lateness_total_ns == 450000u && stats.lateness_max_ns == 450000u);
    CHECK(stats.lateness_histogram[0] == 1u && stats.lateness_histogram[3] == 1u);
    CHECK(stats.clock_exposure_ns == 500200u);

    /* Identity, not pixels: distinct core IDs with equal pixel content supersede. */
    CHECK(same_pixels[0] == same_pixels[1]);
    runner_stats_field(&stats, 7u, 0);
    runner_stats_field(&stats, 8u, 1);
    CHECK(stats.emulated_fields == 2u && stats.catchup_fields == 1u);
    CHECK(stats.superseded_fields == 1u);
    runner_stats_present(&stats, 8u, 1, NULL);
    runner_stats_present(&stats, 8u, 1, NULL);
    CHECK(stats.present_calls == 2u && stats.present_successes == 2u);
    CHECK(stats.repeated_field_ids == 1u && stats.last_presented_field_id == 8u);

    runner_stats_field(&stats, 9u, 0);
    runner_stats_present(&stats, 9u, 0, "injected renderer error");
    CHECK(stats.present_errors == 1u);
    CHECK(stats.present_error[0] != '\0');
    runner_stats_field(&stats, 10u, 0);
    CHECK(stats.superseded_fields == 2u);
    runner_stats_present(&stats, 10u, 1, NULL);
    CHECK(strcmp(stats.present_error, "injected renderer error") == 0);
    runner_stats_discard_wall(&stats, 12345u);
    CHECK(stats.discarded_wall_ns == 12345u);

    saturated.scheduled_deadlines = UINT64_MAX;
    runner_stats_deadline(&saturated, 0u, 0u);
    CHECK(saturated.scheduled_deadlines == UINT64_MAX && saturated.saturated);
    puts("runner presentation contract: deadline and field identity accounting passed");
    return 0;
}

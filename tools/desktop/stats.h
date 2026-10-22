/* SPDX-License-Identifier: MIT */
#ifndef GENEWHIP_RUNNER_STATS_H
#define GENEWHIP_RUNNER_STATS_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define GW_RUNNER_STATS_VERSION 2u
#define GW_RUNNER_LATENESS_BUCKETS 8u
#define GW_RUNNER_PRESENT_ERROR_SIZE 160u

typedef struct runner_stats {
    uint64_t scheduled_deadlines;
    uint64_t late_deadlines;
    uint64_t lateness_samples;
    uint64_t lateness_total_ns;
    uint64_t lateness_max_ns;
    uint64_t lateness_histogram[GW_RUNNER_LATENESS_BUCKETS];
    uint64_t clock_exposure_ns;
    uint64_t emulated_fields;
    uint64_t catchup_fields;
    uint64_t discarded_wall_ns;
    uint64_t present_calls;
    uint64_t present_successes;
    uint64_t present_errors;
    uint64_t last_presented_field_id;
    uint64_t superseded_fields;
    uint64_t repeated_field_ids;
    uint64_t pending_field_id;
    uint64_t last_attempt_field_id;
    int has_pending_field;
    int has_last_attempt_field;
    int saturated;
    char present_error[GW_RUNNER_PRESENT_ERROR_SIZE];
} runner_stats;

static inline uint64_t runner_stats_add(runner_stats *stats, uint64_t value, uint64_t add)
{
    if (UINT64_MAX - value < add) {
        stats->saturated = 1;
        return UINT64_MAX;
    }
    return value + add;
}

static inline unsigned runner_stats_lateness_bucket(uint64_t ns)
{
    static const uint64_t limits[GW_RUNNER_LATENESS_BUCKETS - 1u] = {
        0u, 100000u, 250000u, 500000u, 1000000u, 2000000u, 4000000u
    };
    unsigned bucket = 0;
    while (bucket + 1u < GW_RUNNER_LATENESS_BUCKETS && ns > limits[bucket]) bucket++;
    return bucket;
}

static inline void runner_stats_deadline(runner_stats *stats, uint64_t deadline_ns,
    uint64_t observed_ns)
{
    uint64_t lateness;
    unsigned bucket;
    stats->scheduled_deadlines = runner_stats_add(stats, stats->scheduled_deadlines, 1u);
    lateness = observed_ns > deadline_ns ? observed_ns - deadline_ns : 0u;
    stats->lateness_samples = runner_stats_add(stats, stats->lateness_samples, 1u);
    stats->lateness_total_ns = runner_stats_add(stats, stats->lateness_total_ns, lateness);
    if (lateness > stats->lateness_max_ns) stats->lateness_max_ns = lateness;
    if (lateness) stats->late_deadlines = runner_stats_add(stats, stats->late_deadlines, 1u);
    bucket = runner_stats_lateness_bucket(lateness);
    stats->lateness_histogram[bucket] = runner_stats_add(stats,
        stats->lateness_histogram[bucket], 1u);
}

static inline void runner_stats_field(runner_stats *stats, uint64_t field_id, int catchup)
{
    if (stats->has_pending_field && stats->pending_field_id != field_id)
        stats->superseded_fields = runner_stats_add(stats, stats->superseded_fields, 1u);
    stats->pending_field_id = field_id;
    stats->has_pending_field = 1;
    stats->emulated_fields = runner_stats_add(stats, stats->emulated_fields, 1u);
    if (catchup) stats->catchup_fields = runner_stats_add(stats, stats->catchup_fields, 1u);
}

static inline void runner_stats_discard_wall(runner_stats *stats, uint64_t debt_ns)
{
    stats->discarded_wall_ns = runner_stats_add(stats, stats->discarded_wall_ns, debt_ns);
}

static inline void runner_stats_exposure(runner_stats *stats, uint64_t exposure_ns)
{
    stats->clock_exposure_ns = exposure_ns;
}

static inline void runner_stats_present(runner_stats *stats, uint64_t field_id,
    int success, const char *error)
{
    stats->present_calls = runner_stats_add(stats, stats->present_calls, 1u);
    if (stats->has_last_attempt_field && stats->last_attempt_field_id == field_id)
        stats->repeated_field_ids = runner_stats_add(stats, stats->repeated_field_ids, 1u);
    stats->last_attempt_field_id = field_id;
    stats->has_last_attempt_field = 1;
    if (success) {
        stats->present_successes = runner_stats_add(stats, stats->present_successes, 1u);
        stats->last_presented_field_id = field_id;
        if (stats->has_pending_field && stats->pending_field_id == field_id)
            stats->has_pending_field = 0;
    } else {
        stats->present_errors = runner_stats_add(stats, stats->present_errors, 1u);
        if (!error) error = "presentation failed without an SDL error";
        (void)snprintf(stats->present_error, sizeof(stats->present_error), "%s", error);
    }
}

#endif

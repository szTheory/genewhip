/* SPDX-License-Identifier: MIT */
#ifndef GW_EVIDENCE_H
#define GW_EVIDENCE_H
#include <stddef.h>
#define GW_EVIDENCE_MAX_BYTES 32768u
#define GW_EVIDENCE_MAX_ROWS 64u
typedef struct gw_evidence_identity {
    const char *revision, *configuration, *fixture, *input, *profile, *oracle;
    const char *const *ids;
    size_t count;
} gw_evidence_identity;
/* Strict canonical JSON v1; bounded, allocation-free, no filesystem access.
 * Success populates counts in pass/fail/unknown/unsupported/skipped/infra order.
 * Qualification also requires clean source and all outcomes pass.
 * Errors are stable reason strings; counts are untouched on malformed input. */
const char *gw_evidence_validate(const char *data, size_t length,
    const gw_evidence_identity *expected, int qualify, size_t counts[6]);
#endif

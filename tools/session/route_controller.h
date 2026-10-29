/* SPDX-License-Identifier: MIT */
#ifndef GW_ROUTE_CONTROLLER_H
#define GW_ROUTE_CONTROLLER_H
#include "session.h"

/* GWRC v1 is a tool-private little-endian u32 stream, never a C struct dump.
 * Header words and section layouts are documented in docs/core.md. */
enum { GW_RC_HEADER_WORDS = 32, GW_RC_MAX_SIGNALS = 128, GW_RC_MAX_RECORDS = 4096 };
typedef struct gw_route_controller {
    uint32_t header[GW_RC_HEADER_WORDS];
    uint32_t *words;
    size_t word_count;
    size_t section[8];
    uint32_t span_address[64], span_length[64], span_count;
    uint32_t signal_span[GW_RC_MAX_SIGNALS];
} gw_route_controller;

typedef struct gw_route_input_record {
    uint64_t tick, field, active;
    uint32_t port, desired, effective;
} gw_route_input_record;
typedef struct gw_route_predicate_observation {
    uint64_t clock;
    uint32_t value, index;
    int reached;
} gw_route_predicate_observation;
typedef struct gw_route_cpu_observation {
    uint64_t tick, instructions;
    uint32_t pc, sr, d[8], a[8];
} gw_route_cpu_observation;
typedef struct gw_route_capture {
    gw_route_input_record *input_records;
    size_t input_capacity, input_count;
    gw_route_predicate_observation *predicate_observations;
    size_t predicate_capacity, predicate_count;
    gw_route_cpu_observation *cpu_observations;
    size_t cpu_capacity, cpu_count;
    uint8_t *span_bytes;
    size_t span_capacity, span_count, capacity_bytes, observed_count;
    uint64_t terminal_tick;
    uint64_t terminal_fields, terminal_active_ticks;
    uint64_t *field_ns;
    size_t field_ns_capacity, field_ns_count;
    uint64_t (*clock_ns)(void *);
    void (*begin_execution)(void *);
    void (*end_execution)(void *);
    void *timer_context;
} gw_route_capture;

/* Full masks go through the client's ordinary input handler before stamping.
 * Return the effective mask in *effective; return nonzero for a host failure. */
typedef int (*gw_route_input_callback)(void *, unsigned, uint32_t, uint32_t *effective);
int gw_route_controller_parse(const uint8_t *, size_t, gw_route_controller **);
void gw_route_controller_free(gw_route_controller *);
int gw_route_controller_run(gw_session *, const gw_route_controller *, FILE *,
    gw_route_input_callback, void *, gw_session_route_field_callback, void *, int audio_open);
int gw_route_controller_run_capture(gw_session *, const gw_route_controller *, gw_route_capture *,
    gw_route_input_callback, void *, gw_session_route_field_callback, void *, int audio_open);

/* Shared public-API boundary runner. retired is zero while STOP waits or an
 * interrupt enters; field callbacks retain real PCM/presentation draining. */
int gw_session_route_boundary(gw_session *, uint64_t, uint32_t,
    gw_session_route_field_callback, void *, int *retired);
#endif

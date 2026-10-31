/* SPDX-License-Identifier: MIT */
#ifndef GW_INTERNAL_H
#define GW_INTERNAL_H
#include "genewhip/genewhip.h"
#include "audio_out.h"
#include "io.h"
#include "psg.h"
#include "ym2612.h"
#include "z80.h"
#include "vdp.h"
#include <limits.h>
#include <string.h>

_Static_assert(CHAR_BIT == 8, "Genewhip requires 8-bit bytes");
_Static_assert(sizeof(uint32_t) == 4 && sizeof(uint64_t) == 8, "Exact integer widths required");

/* MC68000UM: interrupt exception processing takes 44 clock periods (5 reads, 3 writes),
 * assuming a 4-clock acknowledge cycle; acknowledge-cycle variability is not modeled (A11). */
#define GW_INTERRUPT_TICKS (44u * GW_CPU_DIVIDER)

#ifdef GW_TEST_HOOKS
#define GW_TEST_MEMORY_CAPACITY 512
#endif

typedef struct gw_cpu {
    uint32_t d[8], a[8], pc, usp;
    uint16_t sr;
    uint32_t instruction_address, opcode, fault_address, stop_reason;
} gw_cpu;

struct gw_machine {
    gw_config config;
    gw_cpu cpu;
    uint8_t ram[GW_RAM_SIZE];
    uint8_t *rom;
    size_t rom_size;
    uint64_t tick;
    uint32_t initial_ssp, initial_pc;
    gw_event events[GW_EVENT_CAPACITY];
    size_t event_count;
    uint64_t instructions, exceptions, exception_returns, external_resets;
    gw_diagnostic_event diagnostic_events[GW_DIAGNOSTIC_CAPACITY];
    size_t diagnostic_capacity, diagnostic_count;
    uint64_t diagnostic_dropped;
    gw_io io;
    gw_vdp vdp;
    gw_video_out video;
    gw_psg psg;
    gw_ym2612 ym;
    gw_z80 z80;
    gw_audio audio;
#ifdef GW_TEST_HOOKS
    uint64_t allocations;
    size_t owned_bytes_current;
    size_t owned_bytes_peak;
    int fail_next_rom_allocation;
    gw_test_z80_arb_event z80_arb_events[256];
    size_t z80_arb_event_count;
    /* Bounded private test observations; never installed or used by the core. */
    struct { uint64_t tick; uint32_t address, value, prior_long; } writes[16];
    size_t write_count;
    /* Sparse byte overlay for vector adapters. When active it replaces ROM/RAM/
     * device decode so every address a vector lists is served and nothing else. */
    struct { uint32_t address; uint8_t value; } test_memory[GW_TEST_MEMORY_CAPACITY];
    size_t test_memory_count;
    int test_memory_active, test_memory_miss;
    uint32_t test_memory_miss_address;
    struct { uint16_t address; uint8_t value; } z80_overlay[GW_TEST_MEMORY_CAPACITY];
    size_t z80_overlay_count;
    struct { uint16_t address; uint8_t value; } z80_ports[GW_TEST_MEMORY_CAPACITY];
    size_t z80_port_count;
    gw_test_z80_transaction z80_transactions[128];
    size_t z80_transaction_count;
    int32_t ym_test_output[2];
    uint64_t ym_test_sample_count;
    uint8_t z80_overlay_active, z80_overlay_miss;
    uint16_t z80_overlay_miss_address;
#endif
};

static inline uint32_t gw_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}
/* Stop values are unordered identifiers; use this instead of >= comparisons. */
static inline int gw_stop_is_unsupported(uint32_t reason)
{
    return reason == GW_STOP_UNSUPPORTED_INSTRUCTION || reason == GW_STOP_UNSUPPORTED_ADDRESS ||
           reason == GW_STOP_UNSUPPORTED_STATE;
}
static inline void gw_count(gw_machine *m, uint64_t *counter)
{
    if (m->config.diagnostics && *counter != UINT64_MAX) ++*counter;
}

int gw_bus_read(gw_machine *m, uint32_t address, unsigned size, uint32_t *value);
int gw_bus_write(gw_machine *m, uint32_t address, unsigned size, uint32_t value);
int gw_z80_bus_decodes(uint32_t address);
int gw_z80_bus_access(gw_machine *m, uint32_t address, unsigned size, int write, uint32_t *value);
int gw_z80_mem_read(gw_machine *m, uint16_t address, uint8_t *value, uint8_t cycle, uint8_t t_states);
int gw_z80_mem_write(gw_machine *m, uint16_t address, uint8_t value, uint8_t t_states);
int gw_z80_io_read(gw_machine *m, uint16_t address, uint8_t *value);
int gw_z80_io_write(gw_machine *m, uint16_t address, uint8_t value);
void gw_z80_sync(gw_machine *m, uint64_t tick);
int gw_bus_span(const gw_machine *m, uint32_t address, size_t size, int write);
uint8_t gw_bus_peek(const gw_machine *m, uint32_t address);
#ifdef GW_TEST_HOOKS
/* Private vector-adapter seam; absent from hooks-off builds. */
size_t gw_test_owned_bytes_current(const gw_machine *m);
size_t gw_test_owned_bytes_peak(const gw_machine *m);
uint64_t gw_test_allocation_count(const gw_machine *m);
void gw_test_fail_next_rom_allocation(gw_machine *m);
void gw_test_memory_reset(gw_machine *m);
int gw_test_memory_set(gw_machine *m, uint32_t address, uint8_t value);
int gw_test_memory_get(const gw_machine *m, uint32_t address, uint8_t *value);
int gw_test_memory_miss(const gw_machine *m, uint32_t *address);
#endif
void gw_cpu_step(gw_machine *m);
/* Autovectored interrupt entry at an instruction boundary (level 4 or 6); the caller has
 * checked level > SR mask. Returns 0 with an unsupported stop if the frame or vector
 * access fails. Charges GW_INTERRUPT_TICKS in total. */
int gw_cpu_accept_interrupt(gw_machine *m, int level);
void gw_cpu_reset(gw_machine *m);
void gw_diagnostics_clear(gw_machine *m);
void gw_diagnostics_record(gw_machine *m);
#endif

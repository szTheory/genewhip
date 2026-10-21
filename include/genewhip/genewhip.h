/* SPDX-License-Identifier: MIT */
#ifndef GENEWHIP_GENEWHIP_H
#define GENEWHIP_GENEWHIP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Source API/structure version, independent of the 0.x package version.
 * Configuration, event-input and snapshot/result structures must be zero-initialized,
 * with struct_size = sizeof(struct)
 * and version = GW_API_VERSION. This version requires exact sizes; incompatible
 * versions/sizes are rejected before mutation. Recompile on 0.x API upgrades;
 * no cross-compiler binary ABI, snapshot or replay format is promised.
 * Integer fields use native host representation, ROM/memory bytes big endian.
 * Requires 8-bit bytes and exact-width 8/16/32/64-bit unsigned types.
 *
 * All pointers must designate valid suitably aligned objects of the stated size.
 * Caller buffers must not overlap each other or any machine-owned storage.
 * The sole borrowed pointer is the pixel pointer from gw_get_video_field: it is
 * core-owned, read-only, and valid until the next gw_run_until, gw_load_rom,
 * gw_cold_init, gw_console_reset or gw_destroy on that machine. All other
 * outputs are copies that remain valid independently.
 * One host thread may access an instance at a time; callers serialize access.
 * Independent instances can run concurrently. No callbacks or reentrancy.
 * The core uses no clocks, files, environment, network or host device services.
 * Create/load allocate; all other ordinary calls are bounded and allocation-free.
 * Work is bounded by the requested tick span; storage is bounded by limits below.
 * Stop-reason and error values are identifiers, not an ordered scale.
 */
#define GW_API_VERSION UINT32_C(4)
#define GW_PROFILE_VA3_NTSC_U UINT32_C(1)
#define GW_RESET_DETERMINISTIC_ZERO UINT32_C(1)
#define GW_MASTER_HZ UINT64_C(53693175)
#define GW_CPU_DIVIDER UINT32_C(7)
#define GW_MIN_ROM_SIZE UINT32_C(514)
#define GW_MAX_ROM_SIZE UINT32_C(4194304)
#define GW_RAM_SIZE UINT32_C(65536)
#define GW_EVENT_CAPACITY UINT32_C(64)
#define GW_DIAGNOSTIC_CAPACITY UINT32_C(256)
#define GW_AUDIO_MIN_RATE_HZ UINT32_C(8000)
#define GW_AUDIO_MAX_RATE_HZ UINT32_C(192000)
#define GW_AUDIO_QUEUE_FRAMES UINT32_C(8192)
#define GW_AUDIO_TRACE_CAPACITY UINT32_C(4096)
#define GW_AUDIO_MIX_V1 UINT32_C(1)
#define GW_AUDIO_FILTER_BLEP_V1 UINT32_C(1)
#define GW_AUDIO_FLAG_DISABLED UINT32_C(1)
enum { GW_AUDIO_CHIP_YM_PORT0 = 1, GW_AUDIO_CHIP_YM_PORT1 = 2, GW_AUDIO_CHIP_PSG = 3 };
enum { GW_AUDIO_SOURCE_68000 = 1, GW_AUDIO_SOURCE_Z80 = 2 };
/* Integer headroom of 2^32 ticks. The longest single stall inside one bus access is a
 * 65535-word VRAM DMA (2 slots per word, at least 16 slots per line): 8192 lines, about
 * 2.8e7 ticks (< 2^25). One instruction holds a handful of such stalls at most, so 2^32
 * covers well over a hundred of them and tick arithmetic cannot wrap. */
#define GW_MAX_TARGET_TICK (UINT64_MAX - (UINT64_C(1) << 32))
/* NTSC raster in master ticks: 262 lines of 3420 ticks, 224 of them active. */
#define GW_LINE_TICKS UINT32_C(3420)
#define GW_LINES_PER_FIELD UINT32_C(262)
#define GW_ACTIVE_LINES UINT32_C(224)
#define GW_FIELD_TICKS UINT32_C(896040)

typedef struct gw_machine gw_machine;
typedef uint32_t gw_status;
enum {
    GW_OK = 0,
    GW_ERROR_ARGUMENT = 1,
    GW_ERROR_VERSION = 2,
    GW_ERROR_PROFILE = 3,
    GW_ERROR_MEMORY = 4,
    GW_ERROR_ROM = 5,
    GW_ERROR_NOT_LOADED = 6,
    GW_ERROR_TIME = 7,
    GW_ERROR_CAPACITY = 8,
    GW_ERROR_UNSUPPORTED = 9,
    GW_ERROR_EMPTY = 10 /* No completed video field exists yet. */
};
enum {
    GW_STOP_TARGET = 0,
    GW_STOP_CPU_STOPPED = 1,
    GW_STOP_UNSUPPORTED_INSTRUCTION = 2,
    GW_STOP_UNSUPPORTED_ADDRESS = 3,
    GW_STOP_UNSUPPORTED_STATE = 4,
    GW_STOP_FIELD_COMPLETE = 5 /* Run-result reason only; never a sticky CPU stop. */
};
/* Input bit for gw_run_result.flags; unknown bits are rejected. */
#define GW_RUN_CONTINUE_PAST_FIELD UINT32_C(1)
enum { GW_EVENT_CONSOLE_RESET = 1, GW_EVENT_PAD_STATE = 2 };
enum { GW_DEVICE_NONE = 0, GW_DEVICE_PAD3 = 1 };
/* Three-button pad bits in gw_event.mask; a set bit means pressed. */
enum {
    GW_BUTTON_UP = 1, GW_BUTTON_DOWN = 2, GW_BUTTON_LEFT = 4, GW_BUTTON_RIGHT = 8,
    GW_BUTTON_B = 16, GW_BUTTON_C = 32, GW_BUTTON_A = 64, GW_BUTTON_START = 128,
    GW_BUTTON_MASK_PAD3 = 255
};
/* Video pixel formats. GW_PIXEL_XRGB8888 is a Genewhip convention defined
 * byte-wise: each pixel is one uint32_t holding 0x00RRGGBB in host byte order,
 * so the four bytes in memory are B, G, R, 0x00 on little-endian hosts and
 * 0x00, R, G, B on big-endian hosts. */
enum { GW_PIXEL_XRGB8888 = 1 };

typedef struct gw_config {
    uint32_t struct_size;
    uint32_t version;
    uint32_t profile;
    uint32_t reset_policy;
    uint32_t diagnostics; /* 0 or 1: optional counters/records; inspection always works. */
    /* Controller per port (GW_DEVICE_*). Current behavior: GW_DEVICE_NONE and
     * GW_DEVICE_PAD3 are accepted; any other value returns UNSUPPORTED. A pad is
     * read by the guest through the I/O ports (see docs/input.md); a NONE port
     * reads pull-ups and rejects pad events. */
    uint32_t port_device[2];
    /* 0 disables PCM synthesis only; otherwise 8000..192000 Hz. Fixed per instance. */
    uint32_t audio_rate_hz;
} gw_config;

typedef struct gw_audio_read_result {
    uint32_t struct_size;
    uint32_t version;
    uint64_t first_index;
    uint64_t lost;
    uint64_t clipped;
    uint32_t produced;
    uint32_t flags;
    uint32_t mix_id;
    uint32_t filter_id;
    uint32_t reserved[4];
} gw_audio_read_result;

typedef struct gw_audio_write {
    uint64_t tick;
    uint32_t chip;
    uint32_t reg;
    uint32_t value;
    uint32_t source;
} gw_audio_write;

typedef struct gw_run_result {
    uint32_t struct_size;
    uint32_t version;
    /* INPUT, unlike every other field here: zero or GW_RUN_CONTINUE_PAST_FIELD.
     * Zero stops with GW_STOP_FIELD_COMPLETE at the first safe boundary at or
     * after each field end; the flag runs to target and keeps only the latest
     * field (superseded fields count in gw_video_field.dropped). Unknown bits
     * return ARGUMENT before any mutation. Machine results never depend on it. */
    uint32_t flags;
    uint64_t requested_tick;
    uint64_t actual_tick;
    /* max(actual_tick - requested_tick, 0), except GW_STOP_FIELD_COMPLETE where it
     * is actual_tick - end_tick of the completed field (the boundary overshoot). */
    uint64_t overshoot_ticks;
    uint32_t stop_reason;
    uint32_t instruction_address; /* Start of last attempted instruction. */
    uint32_t opcode; /* Low 16 bits; zero if opcode fetch failed. */
    /* Unsupported 68000 address: bus address. Z80 faults set bit 30 (bit 31
     * remains reserved for VDP mode): unsupported instruction uses
     * 0x40000000 | z80_pc and opcode = prefix<<8 | byte; unsupported address
     * uses 0x40000000 | z80_address. */
    uint32_t fault_address;
} gw_run_result;

typedef struct gw_event {
    uint32_t struct_size;
    uint32_t version;
    uint64_t tick;
    uint32_t type; /* GW_EVENT_CONSOLE_RESET or GW_EVENT_PAD_STATE. */
    uint32_t port; /* Controller port 0..1 for pad events; reset requires 0. */
    uint32_t mask; /* Full GW_BUTTON_* state for pad events (a later event replaces it); reset requires 0. */
    uint32_t reserved; /* Must be zero. */
} gw_event;

/* Completed-field description. start_tick is the start tick of line 0 of the
 * field; end_tick is the start tick of line 224 of the same field (the publish
 * tick, field_index * GW_FIELD_TICKS + GW_ACTIVE_LINES * GW_LINE_TICKS).
 * sequence counts fields from zero since cold init. dropped counts fields
 * superseded inside one run call (host observation only, excluded from machine
 * equivalence). Only width * 4 bytes of each pitch_bytes row are defined. */
typedef struct gw_video_field {
    uint32_t struct_size;
    uint32_t version;
    uint32_t pixel_format; /* GW_PIXEL_XRGB8888 */
    uint32_t width;        /* 256 (H32) or 320 (H40), latched at line 0 of the field. */
    uint32_t height;       /* 224 */
    uint32_t pitch_bytes;
    uint64_t start_tick;
    uint64_t end_tick;
    uint64_t sequence;
    uint64_t dropped;
    uint32_t flags;        /* Zero. */
    uint32_t reserved[3];  /* Zero. */
} gw_video_field;

typedef struct gw_diagnostic_record {
    uint32_t struct_size;
    uint32_t version;
    uint64_t tick;
    uint32_t profile;
    uint32_t pc;
    uint32_t sr;
    uint32_t d[8];
    uint32_t a[8];
    uint32_t initial_ssp;
    uint32_t initial_pc;
    uint32_t stop_reason;
    uint32_t diagnostics_enabled;
    uint64_t instructions;
    uint64_t exceptions;
    uint64_t exception_returns;
    uint64_t external_resets;
} gw_diagnostic_record;

/* Copy-out only: no caller initialization needed. One attempted instruction,
 * recorded at its returned CPU boundary; layout follows GW_API_VERSION. */
typedef struct gw_diagnostic_event {
    uint64_t tick;
    uint32_t instruction_address;
    uint32_t opcode;
    uint32_t stop_reason;
    uint32_t fault_address;
} gw_diagnostic_event;

/* Set record capacity 0..GW_DIAGNOSTIC_CAPACITY; zero disables counters and
 * recording. Clears records, dropped count and optional counters, without
 * changing machine execution state. Invalid arguments leave all state intact.
 * config.diagnostics=1 starts with maximum capacity; zero starts disabled.
 * May be called before load. No allocation, callbacks, formatting or output. */
gw_status gw_configure_diagnostics(gw_machine *machine, size_t capacity);
/* Copy earliest retained records without consuming them. Requires space for all
 * retained records; CAPACITY leaves outputs unchanged. NULL events is valid for
 * capacity zero. count/dropped are required. No borrowed pointers. Overflow
 * drops newest records and saturates dropped at UINT64_MAX. Cold init/load
 * clears records/counters; console reset preserves them. Disabled produces none.
 * Tick units, threading and non-overlap rules match the rest of this API. */
gw_status gw_get_diagnostic_events(const gw_machine *machine,
    gw_diagnostic_event *events, size_t capacity, size_t *count, uint64_t *dropped);

/* Configure bounded, disabled-by-default chip-write tracing. Capacity is 0..4096;
 * records are copied without consuming, overflow drops newest and saturates dropped.
 * PSG writes are recorded with effective tick, chip/register/value and source. */
gw_status gw_configure_audio_trace(gw_machine *machine, size_t capacity);
gw_status gw_get_audio_writes(const gw_machine *machine, gw_audio_write *writes,
    size_t capacity, size_t *count, uint64_t *dropped);

uint32_t gw_api_version(void);
/* On failure *out is unchanged. Success transfers ownership to caller.
 * PROFILE rejects any profile other than VA3_NTSC_U (including other regions);
 * region is part of profile, not an independent inferred setting. UNSUPPORTED
 * rejects any reset_policy other than DETERMINISTIC_ZERO. ARGUMENT rejects
 * NULL pointers or diagnostics > 1; VERSION rejects wrong structure size/version.
 * Memory: one fixed machine allocation plus at most GW_MAX_ROM_SIZE ROM bytes.
 * During replacement load both old and new ROM copies may temporarily coexist. */
gw_status gw_create(const gw_config *config, gw_machine **out);
void gw_destroy(gw_machine *machine); /* NULL is permitted; otherwise exactly once. */
/* Copies GW_MIN_ROM_SIZE..GW_MAX_ROM_SIZE even-length bytes. ARGUMENT for NULL
 * machine/bytes; ROM for invalid length or reset vectors; MEMORY if allocation
 * fails. Length is checked before inspecting bytes, allocating or copying.
 * Reset PC must be even, >= 512, and <= size-2; initial SSP must be even and
 * within 0xe00006..0xfffffe. All other bytes are copied unchanged; headers,
 * checksums and instruction support are not validated as cartridge identity.
 * Caller can release bytes after
 * return. Validate size/vectors before replacing ROM. Failure leaves machine
 * unchanged. Header metadata is advisory, never a profile override. Successful
 * load performs cold init. No SRAM, mapper, TMSS or peripheral support. */
gw_status gw_load_rom(gw_machine *machine, const void *bytes, size_t size);
/* Cold init: zero RAM/registers as emulator policy, clear events/counters/stops,
 * restart timeline at zero, fetch SSP/PC (four word cycles, ready tick 112).
 * Console reset: preserve RAM and monotonic time; reset CPU from ROM vectors,
 * clear terminal stop, retain queued events/counters. Both zero D0-D7/A0-A6
 * and set SR=0x2700/A7=SSP as deterministic CPU policy; no claim is made about
 * otherwise unspecified physical CPU register values on reset.
 * Console reset clears VDP registers, command latch and FIFO but keeps VRAM, CRAM,
 * VSRAM, the completed field and the raster phase. Guest RESET only signals
 * external reset and continues; it does not reset the VDP yet. */
gw_status gw_cold_init(gw_machine *machine);
gw_status gw_console_reset(gw_machine *machine);
/* Absolute master ticks; finish current instruction before returning. Actual
 * tick can exceed target; no exact-tick or hardware-cycle accuracy guarantee.
 * target < current or > GW_MAX_TARGET_TICK is rejected without mutation.
 * Due events settle even when target equals current, and after an instruction
 * overshoots target. With no due event, target == current is a no-op. Queued
 * resets may add further overshoot. The 2^32-tick integer headroom
 * (see GW_MAX_TARGET_TICK) is an overflow guard, NOT a promised maximum overshoot
 * or hardware timing bound.
 * GW_OK means the request was valid: ALWAYS inspect stop_reason. Unsupported
 * opcode/address/state stops are sticky until reset/load; partial instruction
 * effects and elapsed bus cycles are retained, with no rollback guarantee.
 * Unknown opcodes (including legal unimplemented ones) never become guest
 * illegal-instruction exceptions. STOP awaits console reset in this subset.
 * With result->flags == 0 the call returns GW_STOP_FIELD_COMPLETE at the first
 * safe boundary at or after the next field end, overshoot as documented on
 * gw_run_result; GW_RUN_CONTINUE_PAST_FIELD runs to target instead. Results
 * never depend on the flag. Invalid requests leave result and machine unchanged. */
gw_status gw_run_until(gw_machine *machine, uint64_t target_tick, gw_run_result *result);
/* Copy oldest interleaved native-endian int16 stereo frames into out. Empty queues
 * return GW_OK with produced=0. NULL arguments, zero capacity, or a byte-size
 * overflow return ARGUMENT; wrong result size/version returns VERSION; unloaded
 * machines return NOT_LOADED. Failure leaves out/result unchanged. Queue overflow
 * drops oldest frames and reports lost; drain at field stops for lossless output.
 * Queue clears on load/cold init/destroy; console reset preserves it and indices.
 * Fixed per-machine storage; no allocation, callback, or borrowed pointer. */
gw_status gw_audio_read(gw_machine *machine, int16_t *out,
    uint32_t capacity_frames, gw_audio_read_result *result);
/* Copy event into bounded queue, sorted by tick and then insertion order.
 * Late events (< current tick) rejected; full queue returns CAPACITY unchanged.
 * Apply at first instruction boundary at/after tick; reset fetches advance time.
 * CPU STOP can advance to a queued reset; unsupported stops require direct reset.
 * Events must be submitted before running across their timestamp.
 * Pad events (GW_EVENT_PAD_STATE) are applied at bus time: a guest I/O read at
 * tick t observes every pad event with tick <= t, in (tick, insertion) order.
 * Validation precedes mutation: port > 1 or mask bits beyond GW_BUTTON_MASK_PAD3
 * return ARGUMENT, a port configured GW_DEVICE_NONE returns UNSUPPORTED. */
gw_status gw_schedule_event(gw_machine *machine, const gw_event *event);
/* Describe the newest completed field and borrow its pixels (see lifetime rule
 * at the top). NULL arguments return ARGUMENT, wrong size/version VERSION, and
 * EMPTY before the first completed field after cold init; outputs stay unchanged
 * on any failure. Pixels are width x height GW_PIXEL_XRGB8888 rows, pitch_bytes
 * apart. */
gw_status gw_get_video_field(const gw_machine *machine, gw_video_field *field,
    const uint32_t **pixels);
/* Copy current CPU snapshot without advancing time or clearing counters.
 * Optional counters saturate at UINT64_MAX; disabled counters read zero. */
gw_status gw_get_diagnostics(const gw_machine *machine, gw_diagnostic_record *record);
/* Side-effect-free byte copy for diagnostic inspection, not an emulated bus
 * read. At most GW_RAM_SIZE bytes; contiguous loaded ROM or work RAM only.
 * 24-bit address space, RAM mirrors at 0xe00000..0xffffff. Zero size permits
 * NULL output. Invalid span leaves output unchanged. No wrapping spans. */
gw_status gw_peek_memory(const gw_machine *machine, uint32_t address, void *output, size_t size);

#ifdef __cplusplus
}
#endif
#endif

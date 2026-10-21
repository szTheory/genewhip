/* SPDX-License-Identifier: MIT
 * Original VDP port, FIFO, DMA and raster-advance model. Semantics informed by
 * plutiedev and Sega documentation; Genesis Plus GX is a behavioural reference
 * only and no third-party code or data is used. See docs/video.md.
 */
#include "internal.h"

/* Timing constants. Each is a model-scoped approximation of independent sources:
 * - 3420 master ticks per line (GW_LINE_TICKS): hardware video measurements,
 *   gendev forum thread t=519, cited via .planning/research/HARDWARE.md.
 * - External-access slots per line (GW_VDP_DMA_RATE_*, vdp.h): Nemesis VRAM-access
 *   hardware measurements, gendev forum thread t=851. H32: 16 active / 166 blank;
 *   H40: 18 active / 204 blank. Slots are spaced evenly within the line here, which
 *   is a Genewhip simplification (model-scoped), not a measured slot schedule. The
 *   same slot table paces FIFO commits and every DMA kind; per-unit slot costs are
 *   GW_VDP_DMA_COST_* (vdp.h). No rate is taken from a reference emulator. */

enum { CODE_VRAM_READ = 0, CODE_VRAM_WRITE = 1, CODE_CRAM_WRITE = 3, CODE_VSRAM_READ = 4,
       CODE_VSRAM_WRITE = 5, CODE_CRAM_READ = 8 };

void gw_vdp_cold_init(gw_machine *m)
{
    memset(&m->vdp, 0, sizeof(m->vdp));
    memset(&m->video, 0, sizeof(m->video));
}

void gw_vdp_console_reset(gw_machine *m)
{
    /* Policy A8: registers, command latch and FIFO clear; memories and the
     * completed field survive; the raster phase and tick timeline continue. */
    memset(m->vdp.reg, 0, sizeof(m->vdp.reg));
    m->vdp.latch_pending = 0;
    m->vdp.latch_first = 0;
    m->vdp.code = 0;
    m->vdp.address = 0;
    m->vdp.fifo_count = 0;
    m->vdp.vint_pending = m->vdp.hint_pending = m->vdp.vint_scheduled = 0; /* Registers cleared: IE bits too. */
    m->vdp.hint_counter = 0;
    memset(&m->vdp.dma, 0, sizeof(m->vdp.dma)); /* A8: reset also clears DMA. */
}

static unsigned slots_for_line(const gw_machine *m, uint64_t line_index)
{
    int h40 = m->vdp.reg[12] & 1u;
    int active = (line_index % GW_LINES_PER_FIELD) < GW_ACTIVE_LINES && (m->vdp.reg[1] & 0x40u);
    return h40 ? (active ? GW_VDP_DMA_RATE_H40_ACTIVE : GW_VDP_DMA_RATE_H40_BLANK)
               : (active ? GW_VDP_DMA_RATE_H32_ACTIVE : GW_VDP_DMA_RATE_H32_BLANK);
}

uint64_t gw_vdp_next_slot(const gw_machine *m, uint64_t tick)
{
    for (;;) {
        uint64_t line = tick / GW_LINE_TICKS, start = line * GW_LINE_TICKS;
        uint64_t n = slots_for_line(m, line);
        uint64_t k = (tick - start) * n / GW_LINE_TICKS;
        while (k < n && start + k * GW_LINE_TICKS / n < tick) ++k;
        if (k < n) return start + k * GW_LINE_TICKS / n;
        tick = start + GW_LINE_TICKS;
    }
}

/* HINT counter (assumption A3, community hardware observation: SpritesMind forum posts
 * and the Sega Retro VDP article; the sources disagree on the exact line range, so the
 * seam classes the absolute counts REF-derived). Evaluated once at the start of each
 * line: on lines 0..224 an expired counter (0) raises HINT and reloads from register 10,
 * otherwise it decrements; on lines 225..261 it reloads. Register 10 therefore takes
 * effect at the next reload. HINT pends regardless of IE1 (enable gates only the level). */
static void hint_line(gw_vdp *v, uint32_t phase)
{
    if (phase > GW_ACTIVE_LINES) {
        v->hint_counter = v->reg[10];
    } else if (v->hint_counter == 0) {
        v->hint_pending = 1;
        v->hint_counter = v->reg[10];
    } else {
        --v->hint_counter;
    }
}

/* VINT is raised once per field at the start of line 224 plus GW_VDP_VINT_OFFSET_TICKS. */
static void vint_due(gw_vdp *v, uint64_t tick)
{
    if (v->vint_scheduled && v->vint_tick <= tick) {
        v->vint_pending = 1;
        v->vint_scheduled = 0;
    }
}

int gw_vdp_irq_level(const gw_machine *m)
{
    const gw_vdp *v = &m->vdp;
    if (v->vint_pending && (v->reg[1] & 0x20u)) return 6;
    if (v->hint_pending && (v->reg[0] & 0x10u)) return 4;
    return 0;
}

void gw_vdp_irq_ack(gw_machine *m, int level)
{
    if (level == 6) m->vdp.vint_pending = 0;
    else if (level == 4) m->vdp.hint_pending = 0;
}

static void commit(gw_vdp *v, const gw_vdp_fifo_entry *e)
{
    unsigned index;
    switch (e->code) {
    case CODE_VRAM_WRITE:
        /* Odd addresses are rejected at enqueue; the address is even here. */
        v->vram[e->address] = (uint8_t)(e->data >> 8);
        v->vram[(e->address + 1u) & 0xffffu] = (uint8_t)e->data;
        break;
    case CODE_CRAM_WRITE:
        v->cram[((unsigned)e->address & 0x7fu) >> 1] = (uint16_t)(e->data & 0x0eeeu);
        break;
    case CODE_VSRAM_WRITE:
        index = ((unsigned)e->address & 0x7fu) >> 1;
        if (index < 40) v->vsram[index] = (uint16_t)(e->data & 0x07ffu);
        break;
    default:
        break; /* Unreachable: other codes are rejected at enqueue. */
    }
}

static void drain(gw_vdp *v, uint64_t tick)
{
    unsigned i;
    while (v->fifo_count && v->fifo[0].commit_tick <= tick) {
        commit(v, &v->fifo[0]);
        --v->fifo_count;
        for (i = 0; i < v->fifo_count; ++i) v->fifo[i] = v->fifo[i + 1];
    }
}

/* Consume `count` consecutive access slots from `*cursor`; returns the tick of the last
 * one and leaves the cursor just past it. Work is bounded by count and the line table. */
static uint64_t dma_take_slots(const gw_machine *m, uint64_t *cursor, unsigned count)
{
    uint64_t at = *cursor;
    while (count--) {
        at = gw_vdp_next_slot(m, *cursor);
        *cursor = at + 1;
    }
    return at;
}

/* Advance a running fill or copy: one VRAM byte per scheduled slot group, due ticks
 * at or before `tick`. VRAM indices are 16-bit by construction. */
static void dma_step(gw_machine *m, uint64_t tick)
{
    gw_vdp *v = &m->vdp;
    gw_vdp_dma *d = &v->dma;
    while ((d->mode == GW_VDP_DMA_FILL || d->mode == GW_VDP_DMA_COPY) && d->next_tick <= tick) {
        uint64_t cursor = d->next_tick + 1u;
        if (d->mode == GW_VDP_DMA_FILL) {
            v->vram[d->dest] = d->fill_byte;
        } else {
            v->vram[d->dest] = v->vram[d->source & 0xffffu];
            d->source = (d->source + 1u) & 0xffffu;
        }
        d->dest = (uint16_t)(d->dest + d->increment);
        if (--d->remaining == 0) {
            d->mode = GW_VDP_DMA_IDLE;
            return;
        }
        d->next_tick = dma_take_slots(m, &cursor,
            d->mode == GW_VDP_DMA_FILL ? GW_VDP_DMA_COST_FILL_BYTE : GW_VDP_DMA_COST_COPY_BYTE);
    }
}

/* D-23: only V28 H32/H40 Mode 5 non-interlace output is modeled. Evaluated at
 * line render points so transient initialization writes never stop the guest.
 * Returns 1 when supported; otherwise sets the sticky unsupported-state stop
 * with fault_address = 0x80000000 | register << 8 | value (bit 31 is never a
 * 24-bit bus address). Non-Mode-5 is only fatal while the display is enabled. */
static int mode_ok(gw_machine *m)
{
    const uint8_t *r = m->vdp.reg;
    unsigned reg = 0;
    if (r[1] & 0x08u) reg = 1;                                        /* V30 */
    else if (r[12] & 0x06u) reg = 12;                                 /* interlace */
    else if (((r[12] & 1u) != 0) != ((r[12] & 0x80u) != 0)) reg = 12; /* RS0 != RS1 */
    else if ((r[1] & 0x40u) && !(r[1] & 0x04u)) reg = 1;              /* display, not Mode 5 */
    if (!reg) return 1;
    m->cpu.stop_reason = GW_STOP_UNSUPPORTED_STATE;
    m->cpu.fault_address = UINT32_C(0x80000000) | ((uint32_t)reg << 8) | r[reg];
    return 0;
}

void gw_vdp_advance(gw_machine *m, uint64_t tick)
{
    gw_vdp *v = &m->vdp;
    gw_video_out *o = &m->video;
    while (tick >= o->next_line_tick) {
        uint32_t phase = (uint32_t)(o->next_line % GW_LINES_PER_FIELD);
        if (gw_stop_is_unsupported(m->cpu.stop_reason)) return;
        if (phase == 0 && v->fifo_count == 0 && v->dma.mode == GW_VDP_DMA_IDLE &&
            v->hint_counter == v->reg[10]) {
            /* Fast-forward whole fields: with no writes pending and no guest access
             * possible inside this call, every skipped field renders identically
             * to the fully simulated field that follows. Phase is preserved. */
            uint64_t pending = (tick - o->next_line_tick) / GW_LINE_TICKS + 1;
            if (pending >= 3u * GW_LINES_PER_FIELD) {
                uint64_t skip;
                if (!mode_ok(m)) return; /* Same stop point as line-by-line advance. */
                skip = pending / GW_LINES_PER_FIELD - 1;
                /* Each skipped field raises VINT and, when the HINT period fits in lines
                 * 0..224, HINT; the counter is back at its reload value at phase 0. */
                v->vint_pending = 1;
                v->vint_scheduled = 0;
                if (v->reg[10] <= GW_ACTIVE_LINES) v->hint_pending = 1;
                o->next_line += skip * GW_LINES_PER_FIELD;
                o->next_line_tick = o->next_line * GW_LINE_TICKS;
                o->fields_this_run = o->fields_this_run > UINT64_MAX - skip
                    ? UINT64_MAX : o->fields_this_run + skip;
                continue;
            }
        }
        drain(v, o->next_line_tick);
        dma_step(m, o->next_line_tick);
        vint_due(v, o->next_line_tick);
        hint_line(v, phase);
        if (phase == GW_ACTIVE_LINES) {
            v->vint_scheduled = 1;
            v->vint_tick = o->next_line_tick + GW_VDP_VINT_OFFSET_TICKS;
            vint_due(v, o->next_line_tick);
        }
        if (phase < GW_ACTIVE_LINES) {
            if (!mode_ok(m)) return;
            gw_render_line(m, phase);
        } else if (phase == GW_ACTIVE_LINES) {
            gw_render_publish(m, o->next_line / GW_LINES_PER_FIELD);
        }
        ++o->next_line;
        o->next_line_tick += GW_LINE_TICKS;
    }
    drain(v, tick);
    dma_step(m, tick);
    vint_due(v, tick);
    v->advanced_tick = tick;
}

static int unsupported_access(gw_machine *m, uint32_t address)
{
    m->cpu.stop_reason = GW_STOP_UNSUPPORTED_ADDRESS;
    m->cpu.fault_address = address;
    return 0;
}

/* Hold the CPU, through bus time, until a running fill or copy has finished. Model-scoped
 * contention rule: the data port and a new DMA command wait for the previous
 * fill/copy (what hardware does is classed unknown in the DMA seam). */
static int vdp_dma_wait_idle(gw_machine *m)
{
    gw_vdp_dma *d = &m->vdp.dma;
    while (d->mode == GW_VDP_DMA_FILL || d->mode == GW_VDP_DMA_COPY) {
        if (d->next_tick > m->tick) m->tick = d->next_tick;
        gw_vdp_advance(m, m->tick);
        if (gw_stop_is_unsupported(m->cpu.stop_reason)) return 0;
    }
    return 1;
}

/* Status register bits (Sega documentation layout; see docs/video.md). */
enum { STATUS_PAL = 0x01, STATUS_DMA = 0x02, STATUS_HBLANK = 0x04, STATUS_VBLANK = 0x08,
       STATUS_SCOL = 0x20, STATUS_SOVR = 0x40, STATUS_VINT = 0x80, STATUS_FIFO_FULL = 0x100,
       STATUS_FIFO_EMPTY = 0x200 };

/* Data-port read: wait (advancing CPU time) until the FIFO has drained, then
 * return the word at the active address for the active read code and apply the
 * register-15 auto-increment. Odd VRAM word addresses stay fail-closed; CRAM and
 * VSRAM ignore address bit 0 like their writes. VSRAM entries 40 and above read 0
 * (a defined Genewhip value; the real value is undocumented, see the seam). */
static int read_data(gw_machine *m, uint32_t address, uint32_t *value)
{
    gw_vdp *v = &m->vdp;
    unsigned index;
    if (v->code != CODE_VRAM_READ && v->code != CODE_CRAM_READ && v->code != CODE_VSRAM_READ)
        return unsupported_access(m, address);
    if (!vdp_dma_wait_idle(m)) return 0;
    if (v->fifo_count) {
        uint64_t last = v->fifo[v->fifo_count - 1].commit_tick;
        if (last > m->tick) m->tick = last;
        gw_vdp_advance(m, m->tick);
        if (gw_stop_is_unsupported(m->cpu.stop_reason)) return 0;
    }
    switch (v->code) {
    case CODE_VRAM_READ:
        if (v->address & 1u) return unsupported_access(m, address);
        *value = ((uint32_t)v->vram[v->address] << 8) | v->vram[(v->address + 1u) & 0xffffu];
        break;
    case CODE_CRAM_READ:
        *value = v->cram[((unsigned)v->address & 0x7fu) >> 1];
        break;
    default:
        index = ((unsigned)v->address & 0x7fu) >> 1;
        *value = index < 40 ? v->vsram[index] : 0u;
        break;
    }
    v->address = (uint16_t)(v->address + v->reg[15]);
    return 1;
}

/* Position of bus time inside the NTSC raster. */
static uint32_t raster_line(const gw_machine *m)
{
    return (uint32_t)((m->tick / GW_LINE_TICKS) % GW_LINES_PER_FIELD);
}

/* Model-scoped horizontal timing: pixels per line and active pixels per line are
 * H32 342/256 and H40 420/320 (Charles MacDonald, genvdp.txt; recalled, not
 * re-read for this plan). The line is mapped linearly, which is a Genewhip
 * simplification: H40 dot clocks differ inside blanking. */
static uint32_t line_offset(const gw_machine *m) { return (uint32_t)(m->tick % GW_LINE_TICKS); }

static unsigned status_word(gw_machine *m)
{
    const gw_vdp *v = &m->vdp;
    int h40 = v->reg[12] & 1u;
    unsigned total = h40 ? 420u : 342u, active = h40 ? 320u : 256u;
    unsigned status = 0;
    if (v->fifo_count == 0) status |= STATUS_FIFO_EMPTY;
    if (v->fifo_count == GW_VDP_FIFO_DEPTH) status |= STATUS_FIFO_FULL;
    status |= v->sprite_flags & (STATUS_SOVR | STATUS_SCOL);
    if (raster_line(m) >= GW_ACTIVE_LINES || !(v->reg[1] & 0x40u)) status |= STATUS_VBLANK;
    if ((uint64_t)line_offset(m) * total >= (uint64_t)active * GW_LINE_TICKS) status |= STATUS_HBLANK;
    /* Busy while a fill or copy is scheduled. A 68000 transfer halts the CPU, so the
     * guest never observes it in flight. The VINT bit reads set from the assertion until
     * the interrupt is acknowledged, so a masked or disabled VINT stays visible (it can
     * read set before acceptance). PAL is 0 on the NTSC profile. */
    if (v->vint_pending) status |= STATUS_VINT;
    if (v->dma.mode == GW_VDP_DMA_FILL || v->dma.mode == GW_VDP_DMA_COPY) status |= STATUS_DMA;
    return status;
}

/* HV counter word: V byte then H byte. V follows the NTSC V28 sequence
 * 0x00..0xEA then 0xE5..0xFF over 262 lines (MacDonald, genvdp.txt). H is a
 * model-scoped linear map onto 0x00..0x93,0xE9..0xFF (H32) or 0x00..0xB6,0xE4..0xFF
 * (H40); the real H value at a given tick is not independently known. */
static unsigned hv_word(const gw_machine *m)
{
    int h40 = m->vdp.reg[12] & 1u;
    uint32_t line = raster_line(m);
    unsigned units = h40 ? 211u : 171u, first = h40 ? 183u : 148u, wrap = h40 ? 0xe4u : 0xe9u;
    unsigned n = (unsigned)((uint64_t)line_offset(m) * units / GW_LINE_TICKS);
    unsigned vcount = line <= 0xeau ? line : 0xe5u + (line - 0xebu);
    unsigned hcount = n < first ? n : wrap + (n - first);
    return (vcount << 8) | hcount;
}

int gw_vdp_read(gw_machine *m, uint32_t address, unsigned size, uint32_t *value)
{
    if (size != 2) return unsupported_access(m, address);
    m->vdp.latch_pending = 0; /* Data, status and HV reads all clear the pending command word. */
    switch (address & 0xcu) {
    case 0x0:
        return read_data(m, address, value);
    case 0x4:
        *value = status_word(m);
        m->vdp.sprite_flags = 0;
        return 1;
    default:
        *value = hv_word(m);
        return 1;
    }
}

/* A write to a full FIFO holds the CPU through bus time until the oldest entry lands at its
 * modeled access slot (D-20). Occupancy therefore never exceeds GW_VDP_FIFO_DEPTH. */
static int vdp_fifo_wait_slot(gw_machine *m)
{
    gw_vdp *v = &m->vdp;
    if (v->fifo_count == GW_VDP_FIFO_DEPTH) {
        if (v->fifo[0].commit_tick > m->tick) m->tick = v->fifo[0].commit_tick;
        gw_vdp_advance(m, m->tick);
        if (gw_stop_is_unsupported(m->cpu.stop_reason)) return 0;
    }
    return 1;
}

static int dma_fill_start(gw_machine *m, uint64_t after_tick, uint16_t data);

static int enqueue_data(gw_machine *m, uint32_t address, uint16_t data)
{
    gw_vdp *v = &m->vdp;
    uint64_t base;
    gw_vdp_fifo_entry *e;
    if (v->code != CODE_VRAM_WRITE && v->code != CODE_CRAM_WRITE && v->code != CODE_VSRAM_WRITE)
        return unsupported_access(m, address);
    if (v->code == CODE_VRAM_WRITE && (v->address & 1u)) return unsupported_access(m, address);
    if (!vdp_dma_wait_idle(m) || !vdp_fifo_wait_slot(m)) return 0;
    base = m->tick;
    if (v->fifo_count && v->fifo[v->fifo_count - 1].commit_tick >= base)
        base = v->fifo[v->fifo_count - 1].commit_tick + 1;
    e = &v->fifo[v->fifo_count++];
    e->commit_tick = gw_vdp_next_slot(m, base);
    e->address = v->address;
    e->data = data;
    e->code = v->code;
    v->address = (uint16_t)(v->address + v->reg[15]);
    if (v->dma.fill_pending) return dma_fill_start(m, e->commit_tick, data);
    return 1;
}

/* Fetch one DMA source word through the mapping checks of the CPU bus path but without
 * charging bus time: DMA time is governed by access slots, not by 68000 transfers
 * (Pattern 4, 02-RESEARCH). Only ROM within its loaded size and work RAM are mapped;
 * anything else stops with the byte address as fault and never reads out of bounds. */
static int vdp_dma_source_word(gw_machine *m, uint32_t byte_address, uint16_t *word)
{
    if (!gw_bus_span(m, byte_address, 2, 0)) return unsupported_access(m, byte_address);
    *word = (uint16_t)(((unsigned)gw_bus_peek(m, byte_address) << 8) |
                       gw_bus_peek(m, byte_address + 1u));
    return 1;
}

static uint32_t dma_length(const gw_vdp *v) { return (uint32_t)v->reg[19] | ((uint32_t)v->reg[20] << 8); }

/* 68000-to-VDP transfer (D-21). The CPU is halted for the whole transfer: words are
 * delivered at consecutive access slots (VRAM two per word, CRAM/VSRAM one), every
 * elapsed line renders through gw_vdp_advance before the word that follows it lands, and
 * m->tick ends at the last delivery. The 23-bit word source increments within its
 * 128 KiB block (low 16 bits only). Length 0 transfers nothing (model-scoped; the
 * hardware meaning is unknown, see docs/video.md). */
static int vdp_dma_68k(gw_machine *m, uint32_t fault)
{
    gw_vdp *v = &m->vdp;
    gw_vdp_dma *d = &v->dma;
    uint32_t count = dma_length(v);
    unsigned cost = v->code == CODE_VRAM_WRITE ? GW_VDP_DMA_COST_VRAM_WORD : GW_VDP_DMA_COST_CRAM_WORD;
    uint64_t cursor = m->tick, last = m->tick;
    int ok = 1;
    if (v->fifo_count && v->fifo[v->fifo_count - 1].commit_tick >= cursor)
        cursor = v->fifo[v->fifo_count - 1].commit_tick + 1u; /* Queued writes land first. */
    d->mode = GW_VDP_DMA_68K;
    d->target_code = v->code;
    d->source = ((uint32_t)(v->reg[23] & 0x7fu) << 16) | ((uint32_t)v->reg[22] << 8) | v->reg[21];
    d->remaining = count;
    while (ok && d->remaining) {
        uint16_t word;
        gw_vdp_fifo_entry e;
        if (!vdp_dma_source_word(m, d->source << 1, &word)) { ok = 0; break; }
        if (v->code == CODE_VRAM_WRITE && (v->address & 1u)) { ok = unsupported_access(m, fault); break; }
        last = dma_take_slots(m, &cursor, cost);
        if (last - 1u > v->advanced_tick) {
            gw_vdp_advance(m, last - 1u); /* Lines before this delivery see the older VRAM. */
            if (gw_stop_is_unsupported(m->cpu.stop_reason)) { ok = 0; break; }
        }
        e.commit_tick = last;
        e.address = v->address;
        e.data = word;
        e.code = v->code;
        commit(v, &e);
        v->address = (uint16_t)(v->address + v->reg[15]);
        d->source = (d->source & UINT32_C(0x7f0000)) | ((d->source + 1u) & 0xffffu);
        --d->remaining;
    }
    d->mode = GW_VDP_DMA_IDLE;
    d->remaining = 0;
    if (!ok) return 0;
    if (last > m->tick) m->tick = last;
    gw_vdp_advance(m, m->tick);
    return !gw_stop_is_unsupported(m->cpu.stop_reason);
}

/* Fill: the command only arms it. The data-port write that follows lands as an ordinary
 * VRAM word through the FIFO; the high byte of that word then fills `length` bytes from
 * the next address, stepping by register 15, at one byte per slot with the CPU running
 * and the DMA status bit set. Byte-lane and odd-address details are unknown (docs/video.md). */
static int dma_fill_start(gw_machine *m, uint64_t after_tick, uint16_t data)
{
    gw_vdp *v = &m->vdp;
    gw_vdp_dma *d = &v->dma;
    uint64_t cursor = after_tick + 1u;
    d->fill_pending = 0;
    if (d->remaining == 0) return 1; /* Length 0: nothing (model-scoped). */
    d->mode = GW_VDP_DMA_FILL;
    d->fill_byte = (uint8_t)(data >> 8);
    d->dest = v->address;
    d->increment = v->reg[15];
    d->next_tick = dma_take_slots(m, &cursor, GW_VDP_DMA_COST_FILL_BYTE);
    return 1;
}

/* Copy: VRAM byte range to the current address, started by the command itself at the
 * copy rate (two slots per byte). The source is the 16-bit byte address in registers 21/22. */
static void dma_copy_start(gw_machine *m)
{
    gw_vdp *v = &m->vdp;
    gw_vdp_dma *d = &v->dma;
    uint64_t cursor = m->tick;
    if (v->fifo_count && v->fifo[v->fifo_count - 1].commit_tick >= cursor)
        cursor = v->fifo[v->fifo_count - 1].commit_tick + 1u;
    d->remaining = dma_length(v);
    if (d->remaining == 0) return;
    d->mode = GW_VDP_DMA_COPY;
    d->source = ((uint32_t)v->reg[22] << 8) | v->reg[21];
    d->dest = v->address;
    d->increment = v->reg[15];
    d->next_tick = dma_take_slots(m, &cursor, GW_VDP_DMA_COST_COPY_BYTE);
}

/* A completed control-port command with CD5 set. `code` is the 6-bit CD5..CD0 value. The
 * DMA mode comes from register 23 and must agree with the code; mismatches, DMA with
 * register 1 M1 clear and read-direction DMA are unmodeled and stop fail-closed. */
static int vdp_dma_command(gw_machine *m, uint32_t fault, unsigned code, uint16_t address)
{
    gw_vdp *v = &m->vdp;
    unsigned dmd = (unsigned)v->reg[23] >> 6;
    int is_write_target = code == (0x20u | CODE_VRAM_WRITE) || code == (0x20u | CODE_CRAM_WRITE) ||
                          code == (0x20u | CODE_VSRAM_WRITE);
    if (!(v->reg[1] & 0x10u)) return unsupported_access(m, fault);
    if (dmd < 2u ? !is_write_target : dmd == 2u ? code != (0x20u | CODE_VRAM_WRITE) : code != 0x30u)
        return unsupported_access(m, fault);
    if (!vdp_dma_wait_idle(m)) return 0;
    v->address = address;
    if (dmd < 2u) {
        v->code = (uint8_t)(code & 0x0fu);
        return vdp_dma_68k(m, fault);
    }
    if (dmd == 2u) {
        v->code = CODE_VRAM_WRITE;
        v->dma.fill_pending = 1;
        v->dma.remaining = dma_length(v);
        return 1;
    }
    v->code = 0x30; /* Data-port access after a copy stays fail-closed until a new command. */
    dma_copy_start(m);
    return 1;
}

static int write_control(gw_machine *m, uint32_t address, uint16_t word)
{
    gw_vdp *v = &m->vdp;
    unsigned code;
    if ((word & 0xc000u) == 0x8000u) { /* Register write clears a pending latch. */
        unsigned reg = (word >> 8) & 0x1fu;
        v->latch_pending = 0;
        if (reg < GW_VDP_REGISTERS) v->reg[reg] = (uint8_t)word;
        return 1;
    }
    if (!v->latch_pending) {
        v->latch_first = word;
        v->latch_pending = 1;
        return 1;
    }
    v->latch_pending = 0;
    code = (unsigned)(v->latch_first >> 14) | (((unsigned)(word >> 4) & 0xfu) << 2);
    v->dma.fill_pending = 0; /* Any new command disarms an unstarted fill. */
    if (code & 0x20u)
        return vdp_dma_command(m, address, code,
            (uint16_t)((v->latch_first & 0x3fffu) | (((unsigned)word & 3u) << 14)));
    if (code != CODE_VRAM_READ && code != CODE_VRAM_WRITE && code != CODE_CRAM_WRITE &&
        code != CODE_VSRAM_READ && code != CODE_VSRAM_WRITE && code != CODE_CRAM_READ)
        return unsupported_access(m, address); /* Undefined codes. */
    v->code = (uint8_t)code;
    v->address = (uint16_t)((v->latch_first & 0x3fffu) | (((unsigned)word & 3u) << 14));
    return 1;
}

int gw_vdp_write(gw_machine *m, uint32_t address, unsigned size, uint32_t value)
{
    if (size != 2) return unsupported_access(m, address); /* Byte writes not modeled. */
    switch (address & 0xcu) {
    case 0x0:
        m->vdp.latch_pending = 0;
        return enqueue_data(m, address, (uint16_t)value);
    case 0x4:
        return write_control(m, address, (uint16_t)value);
    default:
        return unsupported_access(m, address); /* HV counter / PSG range. */
    }
}

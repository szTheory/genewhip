/* SPDX-License-Identifier: MIT */
#include "internal.h"
#include "state_digest.h"

#ifdef GW_TEST_HOOKS
/* D-57 inclusion contract: hash CPU state, RAM, tick, pending events, I/O,
 * VDP registers/memory/latches/FIFO/DMA/interrupt and raster scheduling state,
 * and every PSG register/counter/phase field. Exclude the ROM (a fixed test
 * input), all PCM output state (queue, resampler integrator/deltas, frame
 * indices, loss/clipping and trace), rendered pixel buffers, diagnostics,
 * per-run video scratch and test-hook state. Every scalar is serialized
 * explicitly as little-endian bytes; no struct padding enters the hash. */
static uint64_t digest_byte(uint64_t hash, uint8_t value)
{
    return (hash ^ value) * UINT64_C(1099511628211);
}

static uint64_t digest_u16(uint64_t hash, uint16_t value)
{
    hash = digest_byte(hash, (uint8_t)value);
    return digest_byte(hash, (uint8_t)(value >> 8));
}

static uint64_t digest_u32(uint64_t hash, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) hash = digest_byte(hash, (uint8_t)(value >> (i * 8u)));
    return hash;
}

static uint64_t digest_u64(uint64_t hash, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) hash = digest_byte(hash, (uint8_t)(value >> (i * 8u)));
    return hash;
}

uint64_t gw_test_state_digest(const gw_machine *m)
{
    uint64_t hash = UINT64_C(14695981039346656037);
    if (!m) return hash;
    for (unsigned i = 0; i < 8; ++i) hash = digest_u32(hash, m->cpu.d[i]);
    for (unsigned i = 0; i < 8; ++i) hash = digest_u32(hash, m->cpu.a[i]);
    hash = digest_u32(hash, m->cpu.pc);
    hash = digest_u16(hash, m->cpu.sr);
    hash = digest_u32(hash, m->cpu.instruction_address);
    hash = digest_u32(hash, m->cpu.opcode);
    hash = digest_u32(hash, m->cpu.fault_address);
    hash = digest_u32(hash, m->initial_ssp);
    hash = digest_u32(hash, m->initial_pc);
    hash = digest_u64(hash, m->tick);
    for (size_t i = 0; i < sizeof(m->ram); ++i) hash = digest_byte(hash, m->ram[i]);

    hash = digest_u64(hash, m->event_count);
    for (size_t i = 0; i < m->event_count && i < GW_EVENT_CAPACITY; ++i) {
        const gw_event *e = &m->events[i];
        hash = digest_u64(hash, e->tick);
        hash = digest_u32(hash, e->type);
        hash = digest_u32(hash, e->port);
        hash = digest_u32(hash, e->mask);
    }

    hash = digest_byte(hash, m->io.version);
    for (unsigned i = 0; i < GW_IO_PORTS; ++i) hash = digest_byte(hash, m->io.device[i]);
    for (unsigned i = 0; i < GW_IO_PORTS; ++i) hash = digest_byte(hash, m->io.data[i]);
    for (unsigned i = 0; i < GW_IO_PORTS; ++i) hash = digest_byte(hash, m->io.ctrl[i]);
    for (unsigned i = 0; i < GW_IO_PORTS; ++i) hash = digest_byte(hash, m->io.buttons[i]);

    for (unsigned i = 0; i < GW_VDP_REGISTERS; ++i) hash = digest_byte(hash, m->vdp.reg[i]);
    for (size_t i = 0; i < sizeof(m->vdp.vram); ++i) hash = digest_byte(hash, m->vdp.vram[i]);
    for (unsigned i = 0; i < 64; ++i) hash = digest_u16(hash, m->vdp.cram[i]);
    for (unsigned i = 0; i < 40; ++i) hash = digest_u16(hash, m->vdp.vsram[i]);
    hash = digest_u16(hash, m->vdp.latch_first);
    hash = digest_byte(hash, m->vdp.latch_pending);
    hash = digest_byte(hash, m->vdp.code);
    hash = digest_u16(hash, m->vdp.address);
    hash = digest_byte(hash, m->vdp.fifo_count);
    for (unsigned i = 0; i < m->vdp.fifo_count && i < GW_VDP_FIFO_DEPTH; ++i) {
        const gw_vdp_fifo_entry *e = &m->vdp.fifo[i];
        hash = digest_u64(hash, e->commit_tick);
        hash = digest_u16(hash, e->address);
        hash = digest_u16(hash, e->data);
        hash = digest_byte(hash, e->code);
    }
    hash = digest_byte(hash, m->vdp.dma.mode);
    hash = digest_byte(hash, m->vdp.dma.fill_pending);
    hash = digest_byte(hash, m->vdp.dma.target_code);
    hash = digest_byte(hash, m->vdp.dma.fill_byte);
    hash = digest_byte(hash, m->vdp.dma.increment);
    hash = digest_u16(hash, m->vdp.dma.dest);
    hash = digest_u32(hash, m->vdp.dma.source);
    hash = digest_u32(hash, m->vdp.dma.remaining);
    hash = digest_u64(hash, m->vdp.dma.next_tick);
    hash = digest_byte(hash, m->vdp.vint_pending);
    hash = digest_byte(hash, m->vdp.hint_pending);
    hash = digest_byte(hash, m->vdp.hint_counter);
    hash = digest_byte(hash, m->vdp.vint_scheduled);
    hash = digest_u64(hash, m->vdp.vint_tick);
    hash = digest_byte(hash, m->vdp.sprite_flags);
    hash = digest_u64(hash, m->vdp.advanced_tick);

    hash = digest_byte(hash, m->video.back);
    hash = digest_byte(hash, m->video.has_field);
    hash = digest_u32(hash, m->video.back_width);
    hash = digest_u32(hash, m->video.front_width);
    hash = digest_u64(hash, m->video.front_sequence);
    hash = digest_u64(hash, m->video.next_line);
    hash = digest_u64(hash, m->video.next_line_tick);
    hash = gw_psg_digest(&m->psg, hash);
    hash = gw_ym2612_digest(&m->ym, hash);
    hash = gw_z80_digest(&m->z80, hash);
    /* Zero-default-compatible extension: old states have USP=0. A nonzero
     * USP appends a tagged explicit LE scalar. This preserves the frozen
     * zero-state control while distinguishing future USP read behavior. */
    if (m->cpu.usp) {
        hash = digest_byte(hash, 'U'); hash = digest_byte(hash, 'S');
        hash = digest_byte(hash, 'P'); hash = digest_byte(hash, 1);
        hash = digest_u32(hash, m->cpu.usp);
    }
    if (m->io.ext_data || m->io.ext_ctrl) {
        hash=digest_byte(hash,'E');hash=digest_byte(hash,'X');hash=digest_byte(hash,'T');hash=digest_byte(hash,1);
        hash=digest_byte(hash,m->io.ext_data);hash=digest_byte(hash,m->io.ext_ctrl);
    }
    return hash;
}
#endif

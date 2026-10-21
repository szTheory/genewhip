/* SPDX-License-Identifier: MIT */
#include "internal.h"
#include <stdlib.h>

/* The only core allocation sites. Counting is per-instance, never global. */
static void *core_allocate(gw_machine *owner, size_t size)
{
    void *p = malloc(size);
#ifdef GW_TEST_HOOKS
    if (p && owner) ++owner->allocations;
#else
    (void)owner;
#endif
    return p;
}
static void core_free(void *p) { free(p); }

#ifdef GW_TEST_HOOKS
/* Private test link seam: not declared or installed as public API. */
uint64_t gw_test_allocation_count(const gw_machine *m) { return m->allocations; }
#endif

uint32_t gw_api_version(void) { return GW_API_VERSION; }

gw_status gw_create(const gw_config *config, gw_machine **out)
{
    gw_machine *m;
    if (!config || !out) return GW_ERROR_ARGUMENT;
    if (config->struct_size != sizeof(*config) || config->version != GW_API_VERSION)
        return GW_ERROR_VERSION;
    if (config->profile != GW_PROFILE_VA3_NTSC_U) return GW_ERROR_PROFILE;
    if (config->reset_policy != GW_RESET_DETERMINISTIC_ZERO) return GW_ERROR_UNSUPPORTED;
    if (config->diagnostics > 1) return GW_ERROR_ARGUMENT;
    if (config->audio_rate_hz != 0 && (config->audio_rate_hz < GW_AUDIO_MIN_RATE_HZ ||
        config->audio_rate_hz > GW_AUDIO_MAX_RATE_HZ)) return GW_ERROR_ARGUMENT;
    for (unsigned i = 0; i < 2; ++i)
        if (config->port_device[i] != GW_DEVICE_NONE && config->port_device[i] != GW_DEVICE_PAD3)
            return GW_ERROR_UNSUPPORTED;
    m = core_allocate(NULL, sizeof(*m));
    if (!m) return GW_ERROR_MEMORY;
    memset(m, 0, sizeof(*m));
    m->config = *config;
    m->diagnostic_capacity = config->diagnostics ? GW_DIAGNOSTIC_CAPACITY : 0;
    gw_audio_cold_init(&m->audio, config->audio_rate_hz);
    gw_psg_cold_init(m);
    gw_ym2612_cold_init(m);
    gw_z80_cold_init(&m->z80);
#ifdef GW_TEST_HOOKS
    m->allocations = 1;
#endif
    *out = m;
    return GW_OK;
}

void gw_destroy(gw_machine *m)
{
    if (!m) return;
    core_free(m->rom);
    core_free(m);
}

gw_status gw_load_rom(gw_machine *m, const void *bytes, size_t size)
{
    const uint8_t *input = bytes;
    uint8_t *copy;
    uint32_t sp, pc;
    if (!m || !input) return GW_ERROR_ARGUMENT;
    if (size < GW_MIN_ROM_SIZE || size > GW_MAX_ROM_SIZE || (size & 1u)) return GW_ERROR_ROM;
    sp = gw_be32(input);
    pc = gw_be32(input + 4);
    if ((sp & 1u) || sp < UINT32_C(0xe00006) || sp > UINT32_C(0xfffffe) ||
        (pc & 1u) || pc < 512 || pc > size - 2) return GW_ERROR_ROM;
    copy = core_allocate(m, size);
    if (!copy) return GW_ERROR_MEMORY;
    memcpy(copy, input, size);
    core_free(m->rom);
    m->rom = copy;
    m->rom_size = size;
    return gw_cold_init(m);
}

gw_status gw_cold_init(gw_machine *m)
{
    if (!m) return GW_ERROR_ARGUMENT;
    if (!m->rom) return GW_ERROR_NOT_LOADED;
    memset(m->ram, 0, sizeof(m->ram));
    m->tick = 0;
    m->event_count = 0;
    gw_diagnostics_clear(m);
    gw_audio_cold_init(&m->audio, m->config.audio_rate_hz);
    gw_psg_cold_init(m);
    gw_ym2612_cold_init(m);
    gw_z80_cold_init(&m->z80);
    gw_vdp_cold_init(m);
    gw_io_cold_init(m);
    gw_cpu_reset(m);
    return GW_OK;
}

static void console_reset(gw_machine *m)
{
    gw_vdp_console_reset(m);
    gw_io_console_reset(m); /* Latches clear; held buttons and queued events stay. */
    gw_psg_console_reset(m); /* Model choice: PSG registers and phase are retained. */
    gw_z80_sync(m, m->tick);
    gw_ym2612_console_reset(m);
    gw_z80_console_reset(&m->z80);
    m->z80.next_cycle_tick = m->tick;
    gw_cpu_reset(m);
}

gw_status gw_console_reset(gw_machine *m)
{
    if (!m) return GW_ERROR_ARGUMENT;
    if (!m->rom) return GW_ERROR_NOT_LOADED;
    if (m->tick > GW_MAX_TARGET_TICK) return GW_ERROR_TIME;
    console_reset(m);
    return GW_OK;
}

gw_status gw_schedule_event(gw_machine *m, const gw_event *event)
{
    size_t at;
    if (!m || !event) return GW_ERROR_ARGUMENT;
    if (event->struct_size != sizeof(*event) || event->version != GW_API_VERSION)
        return GW_ERROR_VERSION;
    if (!m->rom) return GW_ERROR_NOT_LOADED;
    if (event->reserved) return GW_ERROR_ARGUMENT;
    if (event->type == GW_EVENT_CONSOLE_RESET) {
        if (event->port || event->mask) return GW_ERROR_ARGUMENT;
    } else if (event->type == GW_EVENT_PAD_STATE) {
        /* Everything is validated before the queue is touched. */
        if (event->port >= 2 || (event->mask & ~(uint32_t)GW_BUTTON_MASK_PAD3)) return GW_ERROR_ARGUMENT;
        if (m->config.port_device[event->port] != GW_DEVICE_PAD3) return GW_ERROR_UNSUPPORTED;
    } else {
        return GW_ERROR_UNSUPPORTED;
    }
    if (event->tick < m->tick || event->tick > GW_MAX_TARGET_TICK) return GW_ERROR_TIME;
    if (m->event_count == GW_EVENT_CAPACITY) return GW_ERROR_CAPACITY;
    at = m->event_count++;
    while (at && m->events[at - 1].tick > event->tick) {
        m->events[at] = m->events[at - 1];
        --at;
    }
    m->events[at] = *event;
    return GW_OK;
}

/* Instruction-boundary application: pad events update held buttons (the same
 * rule the bus applies at I/O reads), resets reset the console, both in
 * (tick, insertion) order. */
static void apply_events(gw_machine *m)
{
    for (;;) {
        gw_io_advance(m, m->tick);
        if (!m->event_count || m->events[0].tick > m->tick) break;
        --m->event_count;
        memmove(m->events, m->events + 1, m->event_count * sizeof(m->events[0]));
        console_reset(m);
    }
}

gw_status gw_run_until(gw_machine *m, uint64_t target, gw_run_result *result)
{
    int field_stop = 0;
    if (!m || !result) return GW_ERROR_ARGUMENT;
    if (result->struct_size != sizeof(*result) || result->version != GW_API_VERSION)
        return GW_ERROR_VERSION;
    if (!m->rom) return GW_ERROR_NOT_LOADED;
    if (target < m->tick || target > GW_MAX_TARGET_TICK) return GW_ERROR_TIME;
    if (result->flags & ~GW_RUN_CONTINUE_PAST_FIELD) return GW_ERROR_ARGUMENT;
    m->video.fields_this_run = 0;
    for (;;) {
        if (gw_stop_is_unsupported(m->cpu.stop_reason)) break;
        apply_events(m);
        gw_vdp_advance(m, m->tick);
        if (gw_stop_is_unsupported(m->cpu.stop_reason)) break;
        if (m->video.fields_this_run && !(result->flags & GW_RUN_CONTINUE_PAST_FIELD)) {
            field_stop = 1;
            break;
        }
        if (m->tick >= target) break;
        if (m->cpu.stop_reason == GW_STOP_CPU_STOPPED) {
            /* STOP (MC68000UM): an interrupt above the mask resumes after the STOP
             * instruction. Otherwise time advances to the next queued event or the target;
             * when a wake or a field stop is possible the step ends at the next line
             * boundary (or the scheduled VINT), so devices and fields stay current. */
            int level = gw_vdp_irq_level(m);
            unsigned mask = (m->cpu.sr >> 8) & 7u;
            if (level > (int)mask) {
                m->cpu.stop_reason = GW_STOP_TARGET;
                (void)gw_cpu_accept_interrupt(m, level);
            } else {
                uint64_t next = target;
                int wakeable = ((m->vdp.reg[1] & 0x20u) && mask < 6u) ||
                               ((m->vdp.reg[0] & 0x10u) && mask < 4u);
                if (m->event_count && m->events[0].tick < next) next = m->events[0].tick;
                if (wakeable || !(result->flags & GW_RUN_CONTINUE_PAST_FIELD)) {
                    if (m->video.next_line_tick < next) next = m->video.next_line_tick;
                    if (m->vdp.vint_scheduled && m->vdp.vint_tick > m->tick &&
                        m->vdp.vint_tick < next) next = m->vdp.vint_tick;
                }
                m->tick = next;
                apply_events(m);
            }
        } else {
            /* Pending interrupts are recognized only between instructions, and only when
             * the level exceeds the SR mask. Entry replaces the instruction fetch. */
            int level = gw_vdp_irq_level(m);
            if (level > (int)((m->cpu.sr >> 8) & 7u)) {
                (void)gw_cpu_accept_interrupt(m, level);
            } else {
                gw_cpu_step(m);
                if (m->config.diagnostics) gw_diagnostics_record(m);
            }
        }
    }
    if (m->video.fields_this_run > 1) {
        uint64_t extra = m->video.fields_this_run - 1;
        m->video.dropped = m->video.dropped > UINT64_MAX - extra ? UINT64_MAX : m->video.dropped + extra;
    }
    gw_z80_sync(m, m->tick);
    gw_audio_sync(m, m->tick);
    result->requested_tick = target;
    result->actual_tick = m->tick;
    result->overshoot_ticks = m->tick > target ? m->tick - target : 0;
    if (field_stop) {
        uint64_t end = m->video.front_sequence * GW_FIELD_TICKS +
                       (uint64_t)GW_ACTIVE_LINES * GW_LINE_TICKS;
        result->overshoot_ticks = m->tick - end;
    }
    result->stop_reason = field_stop ? GW_STOP_FIELD_COMPLETE : m->cpu.stop_reason;
    result->instruction_address = m->cpu.instruction_address;
    result->opcode = m->cpu.opcode;
    result->fault_address = m->cpu.fault_address;
    return GW_OK;
}


gw_status gw_get_video_field(const gw_machine *m, gw_video_field *field, const uint32_t **pixels)
{
    const gw_video_out *o;
    if (!m || !field || !pixels) return GW_ERROR_ARGUMENT;
    if (field->struct_size != sizeof(*field) || field->version != GW_API_VERSION)
        return GW_ERROR_VERSION;
    o = &m->video;
    if (!m->rom) return GW_ERROR_NOT_LOADED;
    if (!o->has_field) return GW_ERROR_EMPTY;
    field->pixel_format = GW_PIXEL_XRGB8888;
    field->width = o->front_width;
    field->height = GW_ACTIVE_LINES;
    field->pitch_bytes = GW_VDP_MAX_WIDTH * (uint32_t)sizeof(uint32_t);
    field->start_tick = o->front_sequence * GW_FIELD_TICKS;
    field->end_tick = field->start_tick + (uint64_t)GW_ACTIVE_LINES * GW_LINE_TICKS;
    field->sequence = o->front_sequence;
    field->dropped = o->dropped;
    field->flags = 0;
    memset(field->reserved, 0, sizeof(field->reserved));
    *pixels = &o->buffers[o->back ^ 1u][0][0];
    return GW_OK;
}

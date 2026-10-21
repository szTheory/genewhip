/* SPDX-License-Identifier: MIT
 * YM2612 timer/status/busy and approved provisional-reset contracts.
 * Timer periods follow plutiedev.com/ym2612-registers; reset behavior is an
 * implementation contract classed unknown for exact VA3 hardware fidelity.
 */
#include "internal.h"
#include <stdio.h>
#include <stdlib.h>

#define CHECK(c, n) do { if (!(c)) { fprintf(stderr, "FAIL: %s (line %d)\n", n, __LINE__); exit(1); } } while (0)

static gw_machine *create_machine(uint32_t rate)
{
    gw_config c = {0}; gw_machine *m = NULL;
    c.struct_size = sizeof(c); c.version = GW_API_VERSION;
    c.profile = GW_PROFILE_VA3_NTSC_U; c.reset_policy = GW_RESET_DETERMINISTIC_ZERO;
    c.audio_rate_hz = rate;
    CHECK(gw_create(&c, &m) == GW_OK, "create YM contract machine");
    gw_ym2612_reset_line(m, 0, 0);
    return m;
}

/* route 0 exercises the Z80's $4000 map, route 1 the granted 68000 window. */
static void write_reg(gw_machine *m, unsigned route, uint64_t tick, unsigned reg, uint8_t value)
{
    unsigned bank = reg >= 0x100 ? 2u : 0u;
    uint32_t data = value;
    uint8_t zvalue = value;
    if (route == 0) {
        m->z80.next_cycle_tick = tick;
        CHECK(gw_z80_mem_write(m, (uint16_t)(0x4000u + bank), (uint8_t)reg, 0), "Z80 YM address write");
        CHECK(gw_z80_mem_write(m, (uint16_t)(0x4000u + bank + 1), zvalue, 0), "Z80 YM data write");
    } else {
        m->z80.busreq = 1;
        m->tick = tick;
        data = reg;
        CHECK(gw_z80_bus_access(m, UINT32_C(0x00a04000) + bank, 1, 1, &data), "68000 YM address write");
        data = value;
        CHECK(gw_z80_bus_access(m, UINT32_C(0x00a04001) + bank, 1, 1, &data), "68000 YM data write");
    }
}

static uint8_t read_status(gw_machine *m, unsigned route, uint64_t tick)
{
    uint32_t value = 0;
    uint8_t zvalue = 0;
    if (route == 0) {
        m->z80.next_cycle_tick = tick;
        CHECK(gw_z80_mem_read(m, 0x4000, &zvalue, 0, 0), "Z80 YM status read");
        return zvalue;
    }
    m->z80.busreq = 1;
    m->tick = tick;
    CHECK(gw_z80_bus_access(m, UINT32_C(0x00a04000), 1, 0, &value), "68000 YM status read");
    return (uint8_t)value;
}

static void set_tone(gw_machine *m, unsigned route, uint64_t tick)
{
    write_reg(m, route, tick, 0xb4, 0xc0); /* both outputs */
    write_reg(m, route, tick, 0xb0, 7);    /* algorithm 7 */
    write_reg(m, route, tick, 0x30, 1);    /* operator multiplier */
    write_reg(m, route, tick, 0x50, 0);    /* maximum attack */
    write_reg(m, route, tick, 0x70, 0);    /* maximum decay */
    write_reg(m, route, tick, 0x80, 0x0f);
    write_reg(m, route, tick, 0xa4, 0x22);
    write_reg(m, route, tick, 0xa0, 0x84);
    write_reg(m, route, tick, 0x28, 0x10);
}

static void timer_and_busy_contract(void)
{
    const uint64_t tick_a = GW_FM_SAMPLE_TICKS;
    const uint64_t busy = 32u * 6u * 7u;
    for (unsigned route = 0; route < 2; ++route) {
        gw_machine *m = create_machine(48000);
        write_reg(m, route, 0, 0x24, 0xff); write_reg(m, route, 0, 0x25, 3);
        write_reg(m, route, 0, 0x27, 5); /* load + enable timer A */
        CHECK((read_status(m, route, tick_a - 1) & 1u) == 0, "TA=1023 has not overflowed before 1008 ticks");
        CHECK((read_status(m, route, tick_a) & 1u) != 0, "TA=1023 overflows at 1008 ticks");
        write_reg(m, route, tick_a, 0x27, 0x15); /* reset flag, retain load/enable */
        CHECK((read_status(m, route, tick_a) & 1u) == 0, "timer A status clears through register 0x27");

        /* A data write raises busy immediately; the pinned port uses 32 FM
         * clocks, each clock_prescale*7 master ticks. */
        write_reg(m, route, tick_a + 10, 0x40, 0x12);
        CHECK(read_status(m, route, tick_a + 10) & 0x80u, "busy set immediately after data write");
        CHECK(read_status(m, route, tick_a + 10 + busy - 1) & 0x80u, "busy remains through penultimate tick");
        CHECK((read_status(m, route, tick_a + 10 + busy) & 0x80u) == 0, "busy clears at 32 prescaled FM clocks");

        /* Other read offsets follow the pinned discrete model: only port 0
         * exposes status; the other three return zero. */
        for (unsigned p = 1; p < 4; ++p) {
            uint32_t value = UINT32_MAX;
            m->z80.busreq = 1;
            CHECK(gw_z80_bus_access(m, UINT32_C(0x00a04000) + p, 1, 0, &value), "other YM port read");
            CHECK(value == 0, "other YM read offsets return documented model zero");
        }
        gw_destroy(m);
    }

    for (unsigned route = 0; route < 2; ++route) {
        gw_machine *m = create_machine(0);
        write_reg(m, route, 0, 0x26, 0xff);
        write_reg(m, route, 0, 0x27, 0x0a); /* load + enable timer B */
        CHECK((read_status(m, route, 16u * tick_a - 1) & 2u) == 0, "TB=255 waits 16 FM samples");
        CHECK((read_status(m, route, 16u * tick_a) & 2u) != 0, "TB=255 overflows after 16 samples");
        write_reg(m, route, 16u * tick_a, 0x27, 0x2a);
        CHECK((read_status(m, route, 16u * tick_a) & 2u) == 0, "timer B status clears through register 0x27");
        gw_destroy(m);
    }

    for (unsigned route = 0; route < 2; ++route) {
        gw_machine *a = create_machine(0), *b = create_machine(0), *disabled = create_machine(0);
        uint64_t end_a = 1024u * tick_a, end_b = 4096u * tick_a;
        write_reg(a, route, 0, 0x24, 0); write_reg(a, route, 0, 0x25, 0); write_reg(a, route, 0, 0x27, 5);
        CHECK((read_status(a, route, end_a - 1) & 1u) == 0, "TA=0 counts 1024 FM samples");
        CHECK((read_status(a, route, end_a) & 1u) != 0, "TA=0 overflows after 1024 FM samples");
        write_reg(a, route, end_a, 0x27, 0x14);
        CHECK((read_status(a, route, end_a) & 1u) == 0, "timer A zero-value status clears through register 0x27");

        write_reg(b, route, 0, 0x26, 0); write_reg(b, route, 0, 0x27, 0x0a);
        CHECK((read_status(b, route, end_b - 1) & 2u) == 0, "TB=0 waits 4096 FM samples");
        CHECK((read_status(b, route, end_b) & 2u) != 0, "TB=0 overflows after 4096 FM samples");
        write_reg(b, route, end_b, 0x27, 0x28);
        CHECK((read_status(b, route, end_b) & 2u) == 0, "timer B zero-value status clears through register 0x27");

        write_reg(disabled, route, 0, 0x24, 0xff); write_reg(disabled, route, 0, 0x25, 3);
        write_reg(disabled, route, 0, 0x27, 1); /* load timer A, interrupt disabled */
        CHECK((read_status(disabled, route, tick_a) & 1u) == 0,
            "timer overflow without enable does not set status");
        gw_destroy(a); gw_destroy(b); gw_destroy(disabled);
    }

    /* Timer/status progression is independent of PCM production. */
    {
        gw_machine *on = create_machine(48000), *off = create_machine(0);
        for (unsigned route = 0; route < 2; ++route) {
            write_reg(on, route, 0, 0x24, 0xfc); write_reg(off, route, 0, 0x24, 0xfc);
            write_reg(on, route, 0, 0x25, 0); write_reg(off, route, 0, 0x25, 0);
            write_reg(on, route, 0, 0x26, 0xfe); write_reg(off, route, 0, 0x26, 0xfe);
            write_reg(on, route, 0, 0x27, 0x0f); write_reg(off, route, 0, 0x27, 0x0f);
        }
        for (uint64_t t = 0; t <= 8u * tick_a; t += tick_a / 2) {
            CHECK(gw_ym2612_read_status(on, t) == gw_ym2612_read_status(off, t), "audio-on/off timer status sequence matches");
        }
        gw_destroy(on); gw_destroy(off);
    }
}

static void reset_contract(void)
{
    for (unsigned route = 0; route < 2; ++route) {
        gw_machine *m = create_machine(48000);
        uint64_t edge = 9u * GW_FM_SAMPLE_TICKS + 100u;
        set_tone(m, route, 0);
        write_reg(m, route, 0, 0x24, 0xff); write_reg(m, route, 0, 0x25, 3);
        write_reg(m, route, 0, 0x27, 5);
        write_reg(m, route, 0, 0x2a, 0x7e); write_reg(m, route, 0, 0x2b, 0x80);
        gw_audio_sync(m, edge);
        CHECK(m->ym.operator[0].key_state && m->ym.timer_running[0] && m->ym.dac_enable,
            "sounding tone, timer, DAC precondition");
        gw_ym2612_reset_line(m, edge, 1);
        CHECK(m->ym.last_output[0] == 0 && m->ym.last_output[1] == 0, "assertion adds timestamped silence step");
        CHECK(m->ym.next_sample_tick > edge && (m->ym.next_sample_tick - GW_FM_SAMPLE_TICKS) % GW_FM_SAMPLE_TICKS == 0,
            "assertion preserves native sample grid");
        CHECK(!m->ym.timer_running[0] && !(m->ym.status & 3u), "reset clears timers and status");
        CHECK(m->ym.dac_enable && m->ym.dac_data == (uint16_t)(0x7e ^ 0x80) * 2u,
            "pinned reset retains enabled DAC data");
        uint64_t grid = m->ym.next_sample_tick;
        uint64_t index = m->audio.first_index, frames = m->audio.finalised_frames;
        uint32_t queued = m->audio.queue_count;
        uint32_t queue_head = m->audio.queue_head;
        int16_t queue[GW_AUDIO_QUEUE_FRAMES][2];
        memcpy(queue, m->audio.queue, sizeof(queue));
        CHECK(m->audio.first_index == index && m->audio.finalised_frames == frames &&
            m->audio.queue_count == queued && memcmp(m->audio.queue, queue, sizeof(queue)) == 0,
            "assertion preserves existing PCM queue and frame indices");
        write_reg(m, route, edge, 0x2b, 0); write_reg(m, route, edge, 0x28, 0xf0);
        CHECK(m->ym.dac_enable && !m->ym.operator[0].key_state, "YM writes ignored on both CPU routes while held");
        gw_ym2612 before_repeat = m->ym;
        gw_ym2612_reset_line(m, edge, 1);
        CHECK(m->ym.next_sample_tick == grid && memcmp(&before_repeat, &m->ym, sizeof(m->ym)) == 0,
            "repeated assertion does not reinitialize chip state or rewind grid");
        gw_audio_sync(m, edge + 3u * GW_FM_SAMPLE_TICKS);
        CHECK(m->ym.last_output[0] == 0 && m->ym.next_sample_tick == grid + 3u * GW_FM_SAMPLE_TICKS,
            "held reset stays silent while existing grid advances");
        CHECK(m->audio.first_index == index && m->audio.finalised_frames >= frames &&
            m->audio.queue_count >= queued && m->audio.queue_head == queue_head,
            "reset preserves PCM indices and queue position as new frames finalize");
        for (uint32_t i = 0; i < queued; ++i) {
            uint32_t slot = (queue_head + i) % GW_AUDIO_QUEUE_FRAMES;
            CHECK(memcmp(m->audio.queue[slot], queue[slot], sizeof(queue[slot])) == 0,
                "reset preserves pre-existing queued PCM frames");
        }
        gw_ym2612_reset_line(m, m->ym.advanced_tick, 0);
        CHECK(!m->ym.operator[0].key_state && !m->ym.operator[0].keyon_live,
            "release does not restore pre-reset note");
        uint64_t resume_tick = m->ym.next_sample_tick;
        gw_audio_sync(m, resume_tick);
        CHECK(m->ym.dac_enable && m->ym.last_output[0] != 0,
            "retained enabled DAC resumes its contribution on the existing grid");
        write_reg(m, route, m->ym.advanced_tick, 0x2b, 0);
        CHECK(m->ym.dac_enable == 0, "writes resume after reset release");
        gw_destroy(m);
    }

    /* Reset is device-state equivalent whether PCM is enabled or disabled. */
    {
        gw_machine *on = create_machine(48000), *off = create_machine(0);
        set_tone(on, 0, 0); set_tone(off, 0, 0);
        write_reg(on, 0, 0, 0x2a, 0x45); write_reg(off, 0, 0, 0x2a, 0x45);
        gw_audio_sync(on, 5u * GW_FM_SAMPLE_TICKS); gw_audio_sync(off, 5u * GW_FM_SAMPLE_TICKS);
        gw_ym2612_reset_line(on, 5u * GW_FM_SAMPLE_TICKS + 20, 1);
        gw_ym2612_reset_line(off, 5u * GW_FM_SAMPLE_TICKS + 20, 1);
        CHECK(memcmp(&on->ym, &off->ym, sizeof(on->ym)) == 0, "audio-enabled/disabled reset state equivalent");
        gw_destroy(on); gw_destroy(off);
    }

    /* One long synchronization and arbitrary split boundaries produce the
     * same chip, resampler and PCM queue continuation around reset. */
    {
        gw_machine *one = create_machine(48000), *split = create_machine(48000);
        uint64_t edge = 4u * GW_FM_SAMPLE_TICKS + 123;
        set_tone(one, 0, 0); set_tone(split, 0, 0);
        gw_audio_sync(one, edge); gw_audio_sync(split, edge - 17);
        gw_audio_sync(split, edge);
        gw_ym2612_reset_line(one, edge, 1); gw_ym2612_reset_line(split, edge, 1);
        gw_audio_sync(one, edge + 7u * GW_FM_SAMPLE_TICKS);
        gw_audio_sync(split, edge + 3u * GW_FM_SAMPLE_TICKS);
        gw_audio_sync(split, edge + 7u * GW_FM_SAMPLE_TICKS);
        CHECK(memcmp(&one->ym, &split->ym, sizeof(one->ym)) == 0, "split reset run has identical FM state and grid");
        CHECK(one->audio.first_index == split->audio.first_index &&
            one->audio.finalised_frames == split->audio.finalised_frames &&
            one->audio.queue_head == split->audio.queue_head && one->audio.queue_count == split->audio.queue_count &&
            one->audio.lost == split->audio.lost && one->audio.clipped == split->audio.clipped &&
            memcmp(one->audio.queue, split->audio.queue, sizeof(one->audio.queue)) == 0 &&
            memcmp(one->audio.delta_ring, split->audio.delta_ring, sizeof(one->audio.delta_ring)) == 0 &&
            memcmp(one->audio.integrator, split->audio.integrator, sizeof(one->audio.integrator)) == 0,
            "split reset run preserves PCM frames, queue and resampler continuation");
        gw_destroy(one); gw_destroy(split);
    }
}

int main(void)
{
    timer_and_busy_contract();
    reset_contract();
    puts("ym_timer_contract: PASS (timer/status/busy; reset behavior is implementation-only, hardware fidelity unknown)");
    return 0;
}

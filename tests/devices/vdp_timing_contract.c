/* SPDX-License-Identifier: MIT
 * Genewhip MODEL CONFORMANCE contract for the VDP write FIFO and DMA scheduling
 * (plan GW-02-08, D-20, D-21). This is not hardware evidence: every expected tick
 * below is computed by an independent restatement of the AUTHORED model written in
 * this file (evenly spaced access slots, 16/18 active and 166/204 blank per line from
 * the gendev t=851 Nemesis measurements, a 4-entry FIFO, per-unit slot costs), and
 * the machine must match it exactly. The documented hardware relationships live in the
 * fifo and dma seam ROMs instead.
 *
 * Observation uses only the private test hook gw_test_bus_write, which logs the tick
 * of work-RAM stores: marker stores placed around the VDP accesses bracket their
 * timing. Hooks-gated; the CMake registration skips this test when hooks are off.
 */
#include "devrom.h"

#ifndef GW_TEST_HOOKS
int main(void) { puts("vdp_timing_contract: SKIPPED (hooks off)"); return 0; }
#else
extern int gw_test_bus_write(const gw_machine *, size_t, uint64_t *, uint32_t *, uint32_t *, uint32_t *);

#define LINE UINT64_C(3420)
#define BURST 24u /* long enough that writes (140 ticks apart) outrun 18 slots per line */
#define UNIT UINT64_C(140) /* move.w #imm,(abs).l: five 4-clock transfers of 28 ticks */

/* Authored model: slot k of n on line L lies at L*3420 + k*3420/n (integer division). */
static uint64_t next_slot(uint64_t base, unsigned n)
{
    uint64_t line = base / LINE;
    for (;; ++line) {
        unsigned k;
        for (k = 0; k < n; ++k) {
            uint64_t t = line * LINE + (uint64_t)k * LINE / n;
            if (t >= base) return t;
        }
    }
}

/* Consume `count` consecutive slots from *cursor; returns the last slot tick. */
static uint64_t take(uint64_t *cursor, unsigned n, unsigned count)
{
    uint64_t at = *cursor;
    while (count--) { at = next_slot(*cursor, n); *cursor = at + 1; }
    return at;
}

static uint64_t marker_tick(gw_machine *m, size_t index)
{
    uint64_t tick; uint32_t address, value, prior;
    CHECK(gw_test_bus_write(m, index, &tick, &address, &value, &prior), "marker store exists");
    return tick;
}

static gw_machine *load(const uint8_t *rom)
{
    gw_machine *m = machine();
    CHECK(gw_load_rom(m, rom, 1024) == GW_OK, "load");
    return m;
}

/* Stores marker `n` (a word to work RAM 0xFF0000 + 2n); each marker is one UNIT long. */
static void marker(rom_emit *e, unsigned n) { emit_move_w(e, n, 0x00ff0000u + 2u * n); }
static void data_word(rom_emit *e, unsigned w) { emit_move_w(e, w, VDP_DATA); }

/* A burst of data-port word writes bracketed by markers, display on or off. */
static void fifo_burst(int display_on)
{
    uint8_t rom[1024];
    rom_emit e;
    gw_machine *m;
    uint64_t m0, m1, c, oldest_free[4], t, last = 0, expect;
    unsigned count = 0, i, j, n = display_on ? 18 : 204;
    rom_begin(&e, rom);
    emit_reg(&e, 12, 0x81);                        /* H40: 18 active / 204 blank slots */
    emit_reg(&e, 15, 2);
    emit_reg(&e, 1, display_on ? 0x44 : 0x04);
    emit_move_l(&e, 0x50000000u, VDP_CTRL);        /* VRAM write, address 0x1000 */
    marker(&e, 0);
    for (i = 0; i < BURST; ++i) data_word(&e, 0x0101u * (i + 1u));
    marker(&e, 1);
    emit_bra_self(&e);
    m = load(rom);
    (void)run(m, 40000);
    m0 = marker_tick(m, 0);
    m1 = marker_tick(m, 1);
    /* Restate the authored FIFO: commit = first slot at or after max(now, last commit + 1). */
    c = m0;
    for (i = 0; i < BURST; ++i) {
        t = c + UNIT;                              /* the write transfer completes here */
        while (count && oldest_free[0] <= t) {     /* drain entries that have landed */
            for (j = 1; j < count; ++j) oldest_free[j - 1] = oldest_free[j];
            --count;
        }
        if (count == 4) {                          /* full: hold the CPU until the oldest lands */
            t = oldest_free[0];
            for (j = 1; j < count; ++j) oldest_free[j - 1] = oldest_free[j];
            --count;
        }
        {
            uint64_t base = t;
            if (count && last >= base) base = last + 1;
            last = next_slot(base, n);
            oldest_free[count++] = last;
            CHECK(count <= 4, "FIFO occupancy never exceeds four");
        }
        c = t;
    }
    expect = c + UNIT;
    CHECK(m1 == expect, display_on ? "active-display burst matches the authored FIFO stall"
                                   : "blanking burst matches the authored FIFO (no stall)");
    if (display_on) CHECK(m1 > m0 + (BURST + 1u) * UNIT, "active display stalls the CPU on a full FIFO");
    else CHECK(m1 == m0 + (BURST + 1u) * UNIT, "blanking drains faster than the burst: no stall");
    gw_destroy(m);
}

/* Commands below use VRAM destinations; vdp register 23/19-22 are programmed first. */
static void dma_regs(rom_emit *e, unsigned len, unsigned src, unsigned r23)
{
    emit_reg(e, 19, len & 0xffu); emit_reg(e, 20, (len >> 8) & 0xffu);
    emit_reg(e, 21, src & 0xffu); emit_reg(e, 22, (src >> 8) & 0xffu);
    emit_reg(e, 23, ((src >> 16) & 0x7fu) | r23);
}

static void dma68k_halts_cpu(void)
{
    uint8_t rom[1024];
    rom_emit e;
    gw_machine *m;
    uint64_t m0, m1, cursor, last;
    rom_begin(&e, rom);
    emit_reg(&e, 15, 2);
    emit_reg(&e, 1, 0x14);                         /* M1, Mode 5, display off: blank slots */
    dma_regs(&e, 64, 0x300u >> 1, 0x00);
    marker(&e, 0);
    emit_move_w(&e, 0x6000, VDP_CTRL);             /* VRAM DMA to 0x2000, first word */
    emit_move_w(&e, 0x0080, VDP_CTRL);             /* second word starts the transfer */
    marker(&e, 1);
    emit_bra_self(&e);
    m = load(rom);
    (void)run(m, 200000);
    m0 = marker_tick(m, 0);
    m1 = marker_tick(m, 1);
    cursor = m0 + 2u * UNIT;                       /* tick at the second command write */
    last = take(&cursor, 166, 128);                /* 64 VRAM words, two slots each */
    CHECK(m1 == last + UNIT, "68000 transfer halts the CPU to the last authored slot");
    gw_destroy(m);
}

static void fill_and_copy_do_not_halt(void)
{
    uint8_t rom[1024];
    rom_emit e;
    gw_machine *m;
    uint64_t m0, m1, m2, cursor, trigger, last;
    /* Fill: the CPU keeps running; a later data-port write waits for the fill (model rule). */
    rom_begin(&e, rom);
    emit_reg(&e, 15, 1);
    emit_reg(&e, 1, 0x14);
    dma_regs(&e, 64, 0, 0x80);                     /* DMD = 10, fill, 64 bytes */
    marker(&e, 0);
    emit_move_w(&e, 0x7010, VDP_CTRL);             /* fill destination 0x3010 */
    emit_move_w(&e, 0x0080, VDP_CTRL);
    data_word(&e, 0xaaaa);                         /* trigger */
    marker(&e, 1);
    emit_move_w(&e, 0x7500, VDP_CTRL);             /* ordinary VRAM write command, 0x3500 */
    emit_move_w(&e, 0x0000, VDP_CTRL);
    data_word(&e, 0x7777);                         /* waits for the fill to finish */
    marker(&e, 2);
    emit_bra_self(&e);
    m = load(rom);
    (void)run(m, 200000);
    m0 = marker_tick(m, 0); m1 = marker_tick(m, 1); m2 = marker_tick(m, 2);
    CHECK(m1 == m0 + 4u * UNIT, "fill runs with the CPU continuing (no halt)");
    trigger = next_slot(m0 + 3u * UNIT, 166);      /* trigger word commit slot (FIFO empty) */
    cursor = trigger + 1u;
    last = take(&cursor, 166, 64);                 /* one slot per fill byte */
    CHECK(m2 == last + UNIT, "data-port write waits for the last fill slot");
    gw_destroy(m);
    /* Copy: two slots per byte, started by the command itself, CPU continues. */
    rom_begin(&e, rom);
    emit_reg(&e, 15, 1);
    emit_reg(&e, 1, 0x14);
    dma_regs(&e, 32, 0x2000, 0xc0);                /* DMD = 11, copy, 32 bytes from VRAM 0x2000 */
    marker(&e, 0);
    emit_move_w(&e, 0x3100, VDP_CTRL);             /* copy destination 0x3100 */
    emit_move_w(&e, 0x00c0, VDP_CTRL);
    marker(&e, 1);
    emit_move_w(&e, 0x7500, VDP_CTRL);
    emit_move_w(&e, 0x0000, VDP_CTRL);
    data_word(&e, 0x7777);                         /* waits for the copy to finish */
    marker(&e, 2);
    emit_bra_self(&e);
    m = load(rom);
    (void)run(m, 200000);
    m0 = marker_tick(m, 0); m1 = marker_tick(m, 1); m2 = marker_tick(m, 2);
    CHECK(m1 == m0 + 3u * UNIT, "copy runs with the CPU continuing (no halt)");
    cursor = m0 + 2u * UNIT;                       /* the second command word starts the copy */
    last = take(&cursor, 166, 64);                 /* two slots per byte */
    CHECK(m2 == last + UNIT, "data-port write waits for the last copy slot");
    gw_destroy(m);
}

static void unmapped_sources_stop(void)
{
    static const struct { unsigned len, src, r23; uint32_t fault; const char *name; } cases[] = {
        {4, 0x280000u, 0x00, 0x500000u, "source beyond the ROM"},
        {4, 0x600000u, 0x00, 0xc00000u, "source in the VDP port range"},
        {2, 0x1ffu, 0x00, 0x400u, "second word past the loaded ROM"},
    };
    unsigned i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint8_t rom[1024];
        rom_emit e;
        gw_machine *m;
        gw_run_result r;
        rom_begin(&e, rom);
        emit_reg(&e, 15, 2);
        emit_reg(&e, 1, 0x14);
        dma_regs(&e, cases[i].len, cases[i].src, cases[i].r23);
        emit_move_w(&e, 0x6000, VDP_CTRL);
        emit_move_w(&e, 0x0080, VDP_CTRL);
        marker(&e, 0);
        emit_bra_self(&e);
        m = load(rom);
        r = run(m, 100000);
        CHECK(r.stop_reason == GW_STOP_UNSUPPORTED_ADDRESS, cases[i].name);
        CHECK(r.fault_address == cases[i].fault, cases[i].name);
        { uint64_t t; uint32_t a, v, p; CHECK(!gw_test_bus_write(m, 0, &t, &a, &v, &p), "no instruction after the fault"); }
        gw_destroy(m);
    }
}

/* The word source increments inside its 128 KiB block: a transfer from the last two RAM words
 * continues at the first RAM words instead of leaving the address space (model behaviour). */
static void source_wraps_within_block(void)
{
    uint8_t rom[1024], got[8];
    rom_emit e;
    gw_machine *m;
    unsigned i;
    rom_begin(&e, rom);
    emit_reg(&e, 15, 2);
    emit_reg(&e, 1, 0x14);
    emit_move_w(&e, 0x1111, 0x00ff0000u); emit_move_w(&e, 0x2222, 0x00ff0002u);
    emit_move_w(&e, 0x3333, 0x00fffffcu); emit_move_w(&e, 0x4444, 0x00fffffeu);
    dma_regs(&e, 4, 0x7ffffeu, 0x00);              /* word address of byte 0xFFFFFC */
    emit_move_w(&e, 0x6200, VDP_CTRL);             /* VRAM DMA to 0x2200 */
    emit_move_w(&e, 0x0080, VDP_CTRL);
    emit_move_l(&e, 0x22000000u, VDP_CTRL);        /* VRAM read 0x2200 */
    for (i = 0; i < 4; ++i) { emit16(&e, 0x33f9); emit32(&e, VDP_DATA); emit32(&e, 0x00ff0100u + 2u * i); }
    emit_bra_self(&e);
    m = load(rom);
    (void)run(m, 200000);
    CHECK(gw_peek_memory(m, 0xff0100, got, 8) == GW_OK, "peek read-back");
    CHECK(got[0] == 0x33 && got[1] == 0x33 && got[2] == 0x44 && got[3] == 0x44 &&
          got[4] == 0x11 && got[5] == 0x11 && got[6] == 0x22 && got[7] == 0x22,
          "source wraps from 0xFFFFFE to 0xFE0000 (work RAM start)");
    gw_destroy(m);
}

/* A 65535-word DMA issued just before GW_MAX_TARGET_TICK stalls the CPU far past the
 * target; time must stay below 2^64 and the run must return (review CR-03). Reaches
 * the window cheaply: a STOPped guest advances to the target, then a reset event reruns
 * the program, which sees its boot flag and starts the DMA instead of stopping again. */
static void dma_near_maximum_target_terminates(void)
{
    static const unsigned back[] = {1300, 1500, 1800, 2100, 2500};
    uint64_t longest = 0;
    for (size_t i = 0; i < sizeof(back) / sizeof(back[0]); ++i) {
        uint8_t rom[1024];
        rom_emit e;
        gw_machine *m;
        gw_run_result r;
        gw_event ev;
        uint64_t t0 = GW_MAX_TARGET_TICK - back[i];
        rom_begin(&e, rom);
        emit16(&e, 0x4a39); emit32(&e, 0x00ff0000u);    /* tst.b (0xFF0000).l */
        emit16(&e, 0x660c);                              /* bne.s +12: skip the first-boot block */
        emit16(&e, 0x13fc); emit16(&e, 0x0001); emit32(&e, 0x00ff0000u); /* move.b #1,(0xFF0000).l */
        emit16(&e, 0x4e72); emit16(&e, 0x2700);          /* stop #$2700 */
        emit_reg(&e, 15, 2);
        emit_reg(&e, 1, 0x14);                           /* DMA enabled, Mode 5, display off */
        dma_regs(&e, 0xffffu, 0xff0000u >> 1, 0x00);     /* 65535 words from work RAM (wraps in its block) */
        emit_move_w(&e, 0x6000, VDP_CTRL);               /* VRAM DMA command, first word */
        emit_move_w(&e, 0x0080, VDP_CTRL);               /* second word starts the transfer */
        emit_bra_self(&e);
        m = load(rom);
        CHECK(run(m, 1000).stop_reason == GW_STOP_CPU_STOPPED, "first boot stops");
        CHECK(run(m, t0).actual_tick == t0, "stopped guest reaches the window");
        memset(&ev, 0, sizeof(ev));
        ev.struct_size = sizeof(ev); ev.version = GW_API_VERSION;
        ev.tick = t0; ev.type = GW_EVENT_CONSOLE_RESET;
        CHECK(gw_schedule_event(m, &ev) == GW_OK, "schedule reset");
        r = run(m, GW_MAX_TARGET_TICK);
        CHECK(r.stop_reason == GW_STOP_TARGET, "run returned at the target");
        CHECK(r.actual_tick >= GW_MAX_TARGET_TICK, "time never wrapped");
        CHECK(r.actual_tick - GW_MAX_TARGET_TICK < (UINT64_C(1) << 26), "stall bounded below the headroom");
        if (r.overshoot_ticks > longest) longest = r.overshoot_ticks;
        gw_destroy(m);
    }
    CHECK(longest > 1000000u, "a DMA straddled the target");
}

int main(void)
{
    dma_near_maximum_target_terminates();
    fifo_burst(1);
    fifo_burst(0);
    dma68k_halts_cpu();
    fill_and_copy_do_not_halt();
    unmapped_sources_stop();
    source_wraps_within_block();
    puts("vdp_timing_contract: PASS (Genewhip model conformance, not hardware evidence)");
    return 0;
}
#endif

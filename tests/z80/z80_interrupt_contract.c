/* SPDX-License-Identifier: MIT */
#include "internal.h"
#include "../api/contract.h"

/* UM0080 pp. 18-19: NMI pushes the next PC, vectors to 0066, copies IFF1 to
 * IFF2, clears IFF1, and RETN restores IFF1 from IFF2. */
int main(void)
{
    gw_machine *m = machine();
    uint8_t rom[1024];
    gw_test_z80_state state = {0}, got = {0};
    rom_init(rom, sizeof(rom));
    CHECK(gw_load_rom(m, rom, sizeof(rom)) == GW_OK, "load contract ROM");
    gw_test_z80_overlay_reset(m);
    CHECK(gw_test_z80_overlay_set(m, 0x0066, 0xed), "NMI vector RETN prefix");
    CHECK(gw_test_z80_overlay_set(m, 0x0067, 0x45), "NMI vector RETN opcode");
    state.pc = 0x2345; state.sp = 0x9000; state.iff1 = 1; state.iff2 = 0;
    CHECK(gw_test_z80_set_state(m, &state), "initial Z80 state");
    uint64_t start = m->z80.next_cycle_tick;
    CHECK(gw_test_z80_nmi(m), "NMI accepted");
    CHECK(gw_test_z80_get_state(m, &got), "state after NMI");
    CHECK(got.pc == 0x0066 && got.sp == 0x8ffe, "NMI vector and stack");
    CHECK(got.iff1 == 0 && got.iff2 == 1, "NMI preserves IFF1 in IFF2");
    uint8_t hi = 0, lo = 0;
    CHECK(gw_test_z80_overlay_get(m, 0x8fff, &hi) && hi == 0x23, "NMI stack high byte");
    CHECK(gw_test_z80_overlay_get(m, 0x8ffe, &lo) && lo == 0x45, "NMI stack low byte");
    CHECK(m->z80.next_cycle_tick - start == UINT64_C(11) * GW_Z80_DIVIDER,
          "NMI entry is 11 T states");
    CHECK(gw_test_z80_step_instruction(m), "execute RETN");
    CHECK(gw_test_z80_get_state(m, &got), "state after RETN");
    CHECK(got.pc == 0x2345 && got.sp == 0x9000, "RETN restores PC and SP");
    CHECK(got.iff1 == 1 && got.iff2 == 1, "RETN restores IFF1 from IFF2");
    state=(gw_test_z80_state){0}; state.pc=0x3456; state.sp=0x9000; state.iff1=0; state.iff2=1;
    CHECK(gw_test_z80_set_state(m, &state), "NMI with IFF1 clear state");
    CHECK(gw_test_z80_nmi(m), "NMI is accepted with IFF1 clear");
    CHECK(gw_test_z80_get_state(m, &got) && got.pc==0x0066 && got.iff1==0 && got.iff2==0,
          "NMI with IFF1 clear preserves the prior clear state");

    /* Execute EI and its following ordinary instruction while INT is pending. */
    CHECK(gw_test_z80_overlay_set(m, 0x0200, 0xfb), "EI latency opcode");
    CHECK(gw_test_z80_overlay_set(m, 0x0201, 0x00), "EI following NOP");
    state = (gw_test_z80_state){0}; state.pc=0x0200; state.sp=0x9000; state.iff1=1; state.iff2=1; state.im=1;
    CHECK(gw_test_z80_set_state(m, &state), "EI latency state");
    CHECK(gw_test_z80_step_instruction(m), "execute EI");
    CHECK(!gw_test_z80_accept_int(m, 0), "pending INT is deferred after EI");
    CHECK(gw_test_z80_step_instruction(m), "execute instruction after EI");
    CHECK(gw_test_z80_accept_int(m, 0), "pending INT accepted after following instruction");
    CHECK(gw_test_z80_get_state(m, &got) && got.pc==0x0038,
          "EI latency ends at following instruction boundary");

    /* A normal, non-HALT instruction retires before INT acceptance as well. */
    CHECK(gw_test_z80_overlay_set(m, 0x0300, 0x00), "non-HALT NOP");
    state=(gw_test_z80_state){0}; state.pc=0x0300; state.sp=0x9000; state.iff1=1; state.im=1;
    CHECK(gw_test_z80_set_state(m, &state), "non-HALT sampling state");
    CHECK(gw_test_z80_step_instruction(m), "execute non-HALT instruction");
    CHECK(gw_test_z80_accept_int(m, 0), "sample INT after non-HALT boundary");
    CHECK(gw_test_z80_get_state(m, &got) && got.pc==0x0038,
          "non-HALT instruction completes before interrupt entry");

    /* INT acknowledge data is supplied explicitly here. The live Genesis
     * interrupt seam leaves that byte unknown, as recorded in docs/z80.md. */
    state = (gw_test_z80_state){0}; state.pc = 0x2345; state.sp = 0x9000;
    state.iff1 = 1; state.iff2 = 1; state.im = 0; state.halted = 1;
    CHECK(gw_test_z80_set_state(m, &state), "IM0 state");
    start = m->z80.next_cycle_tick;
    CHECK(gw_test_z80_accept_int(m, 0xff), "IM0 RST 38 acknowledge");
    CHECK(gw_test_z80_get_state(m, &got), "IM0 state after entry");
    CHECK(got.pc == 0x0038 && !got.halted && got.iff1 == 0 && got.iff2 == 0,
          "IM0 executes supplied RST and exits HALT");
    CHECK(m->z80.next_cycle_tick - start == UINT64_C(13) * GW_Z80_DIVIDER,
          "IM0 RST entry is 13 T states");

    state = (gw_test_z80_state){0}; state.pc = 0x2345; state.sp = 0x9000;
    state.iff1 = 1; state.iff2 = 1; state.im = 1;
    CHECK(gw_test_z80_set_state(m, &state), "IM1 state");
    start = m->z80.next_cycle_tick;
    CHECK(gw_test_z80_accept_int(m, 0), "IM1 accepted");
    CHECK(gw_test_z80_get_state(m, &got) && got.pc == 0x0038,
          "IM1 vectors to 0038");
    CHECK(m->z80.next_cycle_tick - start == UINT64_C(13) * GW_Z80_DIVIDER,
          "IM1 entry is 13 T states");

    state = (gw_test_z80_state){0}; state.pc = 0x2345; state.sp = 0x9000;
    state.iff1 = 1; state.im = 2; state.i = 0x12;
    CHECK(gw_test_z80_overlay_set(m, 0x1234, 0x78), "IM2 vector low");
    CHECK(gw_test_z80_overlay_set(m, 0x1235, 0x56), "IM2 vector high");
    CHECK(gw_test_z80_set_state(m, &state), "IM2 state");
    start = m->z80.next_cycle_tick;
    CHECK(gw_test_z80_accept_int(m, 0x34), "IM2 accepted");
    CHECK(gw_test_z80_get_state(m, &got) && got.pc == 0x5678,
          "IM2 reads vector through I:data table");
    CHECK(m->z80.next_cycle_tick - start == UINT64_C(19) * GW_Z80_DIVIDER,
          "IM2 entry is 19 T states");

    state.iff1 = 0; state.im = 1;
    CHECK(gw_test_z80_set_state(m, &state), "masked INT state");
    CHECK(!gw_test_z80_accept_int(m, 0), "IFF1 masks INT");
    state.iff1 = 1; state.ei_delay = 1;
    CHECK(gw_test_z80_set_state(m, &state), "EI delay state");
    CHECK(!gw_test_z80_accept_int(m, 0), "EI delay defers INT");
    state.ei_delay = 0; state.im = 0;
    CHECK(gw_test_z80_set_state(m, &state), "non-RST IM0 state");
    CHECK(!gw_test_z80_accept_int(m, 0x00), "non-RST acknowledge remains unsupported");
    uint64_t pulse = UINT64_C(224) * GW_LINE_TICKS;
    CHECK(!gw_z80_int_asserted(m, pulse - 1u), "INT low before modeled VBlank pulse");
    CHECK(gw_z80_int_asserted(m, pulse), "INT high at modeled VBlank pulse");
    CHECK(gw_z80_int_asserted(m, pulse + GW_Z80_INT_PULSE_TICKS - 1u),
          "INT remains high for the declared pulse width");
    CHECK(!gw_z80_int_asserted(m, pulse + GW_Z80_INT_PULSE_TICKS),
          "INT deasserts after the declared pulse width");

    /* A released RESET level is not a new reset edge. Real audio clients
     * write $0100 on every BUSREQ poll and bus release. */
    state = (gw_test_z80_state){0};
    state.pc = 0x2345; state.sp = 0x9000; state.iff1 = 1; state.iff2 = 1; state.im = 1;
    CHECK(gw_test_z80_set_state(m, &state), "released RESET idempotence state");
    m->z80.busreq = 1;
    m->z80.next_cycle_tick = UINT64_MAX;
    m->z80.ram[0x0100] = 0x5a;
    uint32_t reset_release = 0x0100;
    CHECK(gw_bus_write(m, 0x00a11200u, 2, reset_release), "repeat released RESET during BUSREQ");
    CHECK(!m->z80.reset_pending, "released RESET level does not schedule another reset");
    CHECK(gw_bus_write(m, 0x00a11100u, 2, 0), "release BUSREQ after repeated RESET level");
    gw_z80_sync(m, m->tick + 100u);
    CHECK(m->z80.pc == 0x2345 && m->z80.iff1 && m->z80.iff2 && m->z80.im == 1,
          "repeated released RESET preserves running CPU state");
    CHECK(m->z80.ram[0x0100] == 0x5a, "repeated released RESET preserves Z80 RAM");

    /* A duplicate release while reset is already asserted and a release edge
     * is pending must leave the originally selected edge unchanged. */
    state = (gw_test_z80_state){0};
    CHECK(gw_test_z80_set_state(m, &state), "pending release state");
    m->z80.busreq = 1;
    m->z80.reset_asserted = 1;
    m->z80.reset_pending = 0;
    m->tick = UINT64_C(3000);
    m->z80.next_cycle_tick = UINT64_MAX;
    uint32_t control_value = reset_release;
    CHECK(gw_z80_bus_access(m, 0x00a11200u, 2, 1, &control_value), "schedule first reset release edge");
    uint64_t selected_reset_edge = m->z80.reset_tick;
    CHECK(m->z80.reset_pending, "first release while asserted schedules an edge");
    CHECK(gw_z80_bus_access(m, 0x00a11200u, 2, 1, &control_value), "repeat pending reset release");
    CHECK(m->z80.reset_pending && m->z80.reset_tick == selected_reset_edge,
          "duplicate pending release does not postpone the selected reset edge");

    puts("z80_interrupt_contract: NMI, IM0/1/2, masking, and pulse pass");
    return 0;
}

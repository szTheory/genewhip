/* SPDX-License-Identifier: MIT
 * Authored 68000 interrupt-entry tests (plan GW-02-10). Expected values come from the
 * Motorola MC68000 User's Manual (MC68000UM) exception-processing text, not from any
 * Genewhip output:
 *   - "Interrupt 44(5/3)": acceptance costs 44 clock periods in total (5 reads, 3 writes),
 *     which is 44 * GW_CPU_DIVIDER = 308 master ticks;
 *   - autovector table: level 4 interrupt autovector vector number 28 at address 0x070,
 *     level 6 autovector vector number 30 at address 0x078;
 *   - exception processing saves the status register, sets the supervisor state, clears
 *     the trace state and raises the interrupt priority mask to the accepted level, then
 *     stacks the program counter (the address of the next instruction) and the saved
 *     status register on the supervisor stack, the status register at the lower address
 *     (SR at A7, PC at A7 + 2);
 *   - "Pending interrupts are detected between instruction executions ... if the priority
 *     of the pending interrupt is lower than or equal to the current processor priority,
 *     the interrupt is postponed" (level 7 is non-maskable and is not produced here).
 * Hooks builds only: the test drives the private acceptance entry and the machine state
 * directly, then uses the public run call for the boundary rules.
 */
#include "../../src/internal.h"
#include "../api/contract.h"

#define ROM_SIZE 1024u
#define STACK 0x00ffff00u
#define HANDLER4 0x00000280u
#define HANDLER6 0x00000300u

static gw_machine *fresh(uint16_t sr, const uint8_t *program, size_t program_size)
{
    static uint8_t rom[ROM_SIZE];
    gw_machine *m = machine();
    rom_init(rom, sizeof(rom));
    memset(rom + 512, 0, sizeof(rom) - 512);
    put32(rom + 0x70, HANDLER4);
    put32(rom + 0x78, HANDLER6);
    memcpy(rom + 512, program, program_size);
    CHECK(gw_load_rom(m, rom, sizeof(rom)) == GW_OK, "load ROM");
    m->cpu.sr = sr;
    CHECK(m->cpu.a[7] == STACK && m->cpu.pc == 0x200u, "reset state");
    return m;
}

static const uint8_t NOPS[] = {0x4e, 0x71, 0x4e, 0x71, 0x4e, 0x71, 0x4e, 0x71};

static uint32_t ram_word(gw_machine *m, uint32_t address)
{
    uint8_t b[2];
    CHECK(gw_peek_memory(m, address, b, 2) == GW_OK, "peek");
    return ((uint32_t)b[0] << 8) | b[1];
}

static void enter(int level, uint16_t sr, uint16_t expected_sr, uint32_t vector)
{
    gw_machine *m = fresh(sr, NOPS, sizeof(NOPS));
    uint64_t before;
    m->vdp.reg[0] = 0x10; /* IE1 */
    m->vdp.reg[1] = 0x20; /* IE0 */
    m->vdp.vint_pending = (uint8_t)(level == 6);
    m->vdp.hint_pending = (uint8_t)(level == 4);
    CHECK(gw_vdp_irq_level(m) == level, "VDP presents the level");
    before = m->tick;
    CHECK(gw_cpu_accept_interrupt(m, level), "interrupt accepted");
    CHECK(m->tick - before == 308u, "entry charges 44 clocks (308 ticks)");
    CHECK(m->cpu.a[7] == STACK - 6u, "six-byte frame");
    CHECK(ram_word(m, STACK - 6u) == sr, "stacked SR at A7 is the pre-entry SR");
    CHECK(((ram_word(m, STACK - 4u) << 16) | ram_word(m, STACK - 2u)) == 0x200u,
          "stacked PC at A7 + 2 is the address of the interrupted instruction");
    CHECK(m->cpu.sr == expected_sr, "S set, T clear, mask equal to the level, CCR kept");
    CHECK(m->cpu.pc == vector, "PC is the autovector contents");
    CHECK(m->cpu.stop_reason == GW_STOP_TARGET, "no stop");
    CHECK(m->exceptions == 1u, "counted as one exception");
    CHECK(m->vdp.vint_pending == 0 && m->vdp.hint_pending == 0, "taken source acknowledged");
    gw_destroy(m);
}

static void priority_and_ack(void)
{
    gw_machine *m = fresh(0x2000, NOPS, sizeof(NOPS));
    m->vdp.reg[0] = 0x10;
    m->vdp.reg[1] = 0x20;
    m->vdp.vint_pending = m->vdp.hint_pending = 1;
    CHECK(gw_vdp_irq_level(m) == 6, "VINT has priority over HINT");
    CHECK(gw_cpu_accept_interrupt(m, 6), "VINT taken first");
    CHECK(m->vdp.vint_pending == 0 && m->vdp.hint_pending == 1, "VINT acknowledge leaves HINT");
    CHECK(gw_vdp_irq_level(m) == 4, "acknowledging VINT re-evaluates to HINT");
    gw_destroy(m);

    m = fresh(0x2000, NOPS, sizeof(NOPS));
    m->vdp.reg[0] = 0x10;
    m->vdp.reg[1] = 0x20;
    m->vdp.vint_pending = m->vdp.hint_pending = 1;
    CHECK(gw_cpu_accept_interrupt(m, 4), "HINT acceptance");
    CHECK(m->vdp.vint_pending == 1 && m->vdp.hint_pending == 0, "HINT acknowledge leaves VINT");
    CHECK(gw_vdp_irq_level(m) == 6, "acknowledging HINT re-evaluates to VINT");
    gw_destroy(m);

    m = fresh(0x2000, NOPS, sizeof(NOPS));
    m->vdp.vint_pending = m->vdp.hint_pending = 1;
    CHECK(gw_vdp_irq_level(m) == 0, "a pending source without its enable bit presents no level");
    m->vdp.reg[1] = 0x20;
    CHECK(gw_vdp_irq_level(m) == 6, "enabling IE0 while pending presents the level");
    m->vdp.reg[1] = 0;
    m->vdp.reg[0] = 0x10;
    CHECK(gw_vdp_irq_level(m) == 4, "enabling IE1 while pending presents the level");
    gw_destroy(m);
}

/* Genewhip model rule (not an MC68000UM statement): the status VINT bit reads set from the
 * assertion until acknowledgement, so a masked or disabled pending VINT stays visible. */
static void status_bit(void)
{
    gw_machine *m = fresh(0x2700, NOPS, sizeof(NOPS));
    uint32_t status = 0;
    CHECK(gw_vdp_read(m, 0xc00004u, 2, &status) && !(status & 0x80u), "VINT bit clear before assertion");
    m->vdp.vint_pending = 1;
    CHECK(gw_vdp_read(m, 0xc00004u, 2, &status) && (status & 0x80u), "VINT bit set while pending");
    CHECK(gw_vdp_read(m, 0xc00004u, 2, &status) && (status & 0x80u), "a status read does not clear it");
    gw_vdp_irq_ack(m, 6);
    CHECK(gw_vdp_read(m, 0xc00004u, 2, &status) && !(status & 0x80u), "acknowledgement clears it");
    gw_destroy(m);
}

/* Boundary rule: a level not above the mask is postponed and the CPU steps normally. */
static void postponed(uint16_t sr, int level)
{
    gw_machine *m = fresh(sr, NOPS, sizeof(NOPS));
    gw_run_result r;
    m->vdp.reg[0] = 0x10;
    m->vdp.reg[1] = 0x20;
    m->vdp.vint_pending = (uint8_t)(level == 6);
    m->vdp.hint_pending = (uint8_t)(level == 4);
    r = run(m, m->tick + 28);
    CHECK(r.stop_reason == GW_STOP_TARGET, "postponed run continues");
    CHECK(m->cpu.pc == 0x202u && m->cpu.a[7] == STACK && m->exceptions == 0, "NOP executed, no frame");
    CHECK(level == 6 ? m->vdp.vint_pending : m->vdp.hint_pending, "the postponed source is still pending");
    /* Lowering the mask lets the pending interrupt in at the next boundary. */
    m->cpu.sr = 0x2000;
    r = run(m, m->tick + 1);
    CHECK(m->exceptions == 1u && m->cpu.a[7] == STACK - 6u, "accepted once the mask is lowered");
    CHECK(m->cpu.pc == (level == 6 ? HANDLER6 : HANDLER4), "handler entered");
    CHECK(m->cpu.stop_reason == GW_STOP_TARGET, "no stop");
    gw_destroy(m);
}

static void frame_failure(void)
{
    gw_machine *m = fresh(0x2000, NOPS, sizeof(NOPS));
    m->cpu.a[7] = 0x00000100u; /* ROM: the frame write cannot land */
    m->vdp.reg[1] = 0x20;
    m->vdp.vint_pending = 1;
    CHECK(!gw_cpu_accept_interrupt(m, 6), "frame write to an unwritable stack fails");
    CHECK(m->cpu.stop_reason == GW_STOP_UNSUPPORTED_ADDRESS, "sticky unsupported-address stop");
    gw_destroy(m);
}

/* Phase 1 amendment (02-18): STOP awaits console reset -> STOP also resumes on an accepted
 * interrupt above the SR mask (D-22, research Open Question 5); a masked interrupt does not. */
static void stop_wakes(void)
{
    static const uint8_t stop_open[] = {0x4e, 0x72, 0x20, 0x00};
    static const uint8_t stop_masked[] = {0x4e, 0x72, 0x27, 0x00};
    gw_machine *m = fresh(0x2700, stop_masked, sizeof(stop_masked));
    gw_run_result r = run(m, m->tick + 100);
    CHECK(r.stop_reason == GW_STOP_CPU_STOPPED, "STOP reached");
    m->vdp.reg[1] = 0x20;
    m->vdp.vint_pending = 1;
    r = run(m, m->tick + 200000);
    CHECK(r.stop_reason == GW_STOP_CPU_STOPPED && m->exceptions == 0, "mask 7 keeps the CPU stopped");
    CHECK(r.actual_tick == r.requested_tick, "stopped run ends at the target");
    gw_destroy(m);
    m = fresh(0x2700, stop_open, sizeof(stop_open));
    r = run(m, m->tick + 100);
    CHECK(r.stop_reason == GW_STOP_CPU_STOPPED, "STOP reached (open mask)");
    m->vdp.reg[1] = 0x20;
    m->vdp.vint_pending = 1;
    r = run(m, m->tick + 2000);
    CHECK(m->exceptions == 1 && m->vdp.vint_pending == 0, "VINT above the mask wakes STOP into the handler");
    CHECK(m->cpu.stop_reason != GW_STOP_CPU_STOPPED, "no longer stopped");
    gw_destroy(m);
}

int main(void)
{
    enter(6, 0x2000, 0x2600, HANDLER6);
    enter(4, 0x2000, 0x2400, HANDLER4);
    enter(6, 0x2015, 0x2615, HANDLER6); /* X, Z and C survive in the entered SR */
    enter(6, 0x2500, 0x2600, HANDLER6); /* mask 5 < 6 */
    enter(4, 0x2300, 0x2400, HANDLER4); /* mask 3 < 4 */
    priority_and_ack();
    status_bit();
    postponed(0x2600, 6); /* level equal to the mask */
    postponed(0x2700, 6); /* mask 7 */
    postponed(0x2400, 4); /* level equal to the mask */
    postponed(0x2600, 4); /* level below the mask */
    frame_failure();
    stop_wakes();
    puts("cpu_interrupt: PASS");
    return 0;
}

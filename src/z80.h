/* SPDX-License-Identifier: MIT */
#ifndef GW_Z80_H
#define GW_Z80_H
#include <stdint.h>
#include <stddef.h>

struct gw_machine;

#define GW_Z80_RAM_SIZE 8192u
#define GW_Z80_DIVIDER 15u
/* A7: model VBlank INT for 32 T states. The documented instruction forms
 * implemented here take at most 23 T states, so this spans one boundary plus
 * phase slack; it ends before the guest ISR can EI/RETI and retrigger. This
 * is a chosen sampling assumption, not a measured Genesis pulse width. */
#define GW_Z80_INT_PULSE_TICKS (UINT64_C(32) * GW_Z80_DIVIDER)

/* Original implementation based on Zilog UM0080 and cited community
 * documentation. No third-party CPU implementation is incorporated. */
typedef struct gw_z80 {
    uint16_t af, bc, de, hl, af_alt, bc_alt, de_alt, hl_alt, ix, iy, sp, pc, wz;
    uint8_t i, r, iff1, iff2, im, q, halted, ei_delay;
    uint8_t reset_asserted, busreq, busreq_pending, reset_pending, micro_op, opcode, instruction_active;
    uint8_t source_reg, destination_reg, cycle_kind, retired;
    uint8_t operand_lo, operand_hi, temp, stage, pending_cycles;
    /* Prefix decode is retained across cycle boundaries so BUSREQ can grant
     * during a prefixed instruction and execution can resume without replay. */
    uint8_t prefix, subopcode, displacement, prefix_count, prefetched, index_active;
    uint16_t effective_address, temporary_pc;
    uint16_t bank;
    uint8_t bank_shift_count;
    uint64_t next_cycle_tick, busreq_tick, reset_tick;
    uint8_t ram[GW_Z80_RAM_SIZE];
} gw_z80;

void gw_z80_cold_init(gw_z80 *z);
void gw_z80_console_reset(gw_z80 *z);
int gw_z80_cycle(struct gw_machine *m);
int gw_z80_at_boundary(const gw_z80 *z);
uint64_t gw_z80_digest(const gw_z80 *z, uint64_t hash);
int gw_z80_int_asserted(const struct gw_machine *m, uint64_t tick);
void gw_z80_sample_interrupt(struct gw_machine *m, uint64_t tick);

#ifdef GW_TEST_HOOKS
enum { GW_TEST_Z80_ARB_REQUEST=1, GW_TEST_Z80_ARB_GRANT=2, GW_TEST_Z80_ARB_RELEASE=3,
       GW_TEST_Z80_ARB_RESET_ASSERT=4, GW_TEST_Z80_ARB_RESET_RELEASE=5 };
typedef struct gw_test_z80_arb_event {
    uint8_t kind, opcode, instruction_active, stage;
    uint64_t tick;
} gw_test_z80_arb_event;
typedef struct gw_test_z80_state {
    uint16_t af, bc, de, hl, af_alt, bc_alt, de_alt, hl_alt, ix, iy, sp, pc, wz;
    uint8_t i, r, iff1, iff2, im, q, halted, ei_delay;
} gw_test_z80_state;
typedef struct gw_test_z80_transaction {
    uint8_t type, data, t_states;
    uint16_t address;
} gw_test_z80_transaction;
int gw_test_z80_set_state(struct gw_machine *, const gw_test_z80_state *);
int gw_test_z80_get_state(const struct gw_machine *, gw_test_z80_state *);
int gw_test_z80_step_instruction(struct gw_machine *);
int gw_test_z80_nmi(struct gw_machine *);
int gw_test_z80_accept_int(struct gw_machine *, uint8_t acknowledge_data);
void gw_test_z80_overlay_reset(struct gw_machine *);
int gw_test_z80_overlay_set(struct gw_machine *, uint16_t, uint8_t);
int gw_test_z80_overlay_get(const struct gw_machine *, uint16_t, uint8_t *);
int gw_test_z80_overlay_port_set(struct gw_machine *, uint16_t, uint8_t);
int gw_test_z80_overlay_port_get(const struct gw_machine *, uint16_t, uint8_t *);
size_t gw_test_z80_transaction_count(const struct gw_machine *);
int gw_test_z80_transaction_get(const struct gw_machine *, size_t, gw_test_z80_transaction *);
size_t gw_test_z80_arb_event_count(const struct gw_machine *);
int gw_test_z80_arb_event_get(const struct gw_machine *, size_t, gw_test_z80_arb_event *);
#endif
#endif

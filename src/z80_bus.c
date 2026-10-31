/* SPDX-License-Identifier: MIT */
/* 68000-visible Z80 bus control, RAM window and deterministic clock catch-up.
 * BUSREQ status follows Sega Technical Overview 1.00 p.76; the contrary
 * Genesis Sound Software Manual 1992-02-21 p.2 remains an unresolved source. */
#include "internal.h"

#define GW_Z80_BUSREQ_ADDRESS UINT32_C(0x00a11100)
#define GW_Z80_RESET_ADDRESS UINT32_C(0x00a11200)
#define GW_Z80_BANK_ADDRESS UINT32_C(0x00a06000)
#define GW_Z80_WINDOW_ACCESS_TICKS (4u * GW_CPU_DIVIDER)
#define GW_Z80_UNKNOWN_READ UINT8_C(0xff)
/* Model-scoped one-Z80-T-state ROM-window wait; no primary source specifies
 * this wait. Evidence asserts causal ordering, never a hardware wait total. */
#define GW_Z80_BANK_WAIT_TICKS GW_Z80_DIVIDER

enum { Z80_ARB_REQUEST=1, Z80_ARB_GRANT=2, Z80_ARB_RELEASE=3,
       Z80_ARB_RESET_ASSERT=4, Z80_ARB_RESET_RELEASE=5 };
static void arb_record(gw_machine *m, uint8_t kind, uint64_t tick);

static uint64_t next_clock_edge(uint64_t tick)
{
    return (tick / GW_Z80_DIVIDER + 1u) * GW_Z80_DIVIDER;
}

static void reset_on_edge(gw_machine *m, uint64_t edge)
{
    gw_z80 *z=&m->z80;
    uint8_t asserted=z->reset_asserted, busreq=z->busreq;
    uint8_t busreq_pending=z->busreq_pending, reset_pending=z->reset_pending;
    uint64_t busreq_tick=z->busreq_tick, reset_tick=z->reset_tick;
    gw_z80_console_reset(z);
    z->reset_asserted=asserted; z->busreq=busreq;
    z->busreq_pending=busreq_pending; z->reset_pending=reset_pending;
    z->busreq_tick=busreq_tick; z->reset_tick=reset_tick;
    z->next_cycle_tick=edge;
    z->reset_pending=0; z->reset_asserted=0;
    gw_ym2612_reset_line(m, edge, 0);
    arb_record(m,Z80_ARB_RESET_RELEASE,edge);
}

static void arb_record(gw_machine *m, uint8_t kind, uint64_t tick)
{
#ifdef GW_TEST_HOOKS
    if (m->z80_arb_event_count < sizeof(m->z80_arb_events)/sizeof(m->z80_arb_events[0])) {
        gw_test_z80_arb_event *e=&m->z80_arb_events[m->z80_arb_event_count++];
        e->kind=kind; e->tick=tick; e->opcode=m->z80.opcode;
        e->instruction_active=m->z80.instruction_active; e->stage=m->z80.stage;
    }
#else
    (void)m; (void)kind; (void)tick;
#endif
}

int gw_z80_bus_decodes(uint32_t address)
{
    return (address >= UINT32_C(0x00a00000) && address <= UINT32_C(0x00a03fff)) ||
           (address >= UINT32_C(0x00a04000) && address <= UINT32_C(0x00a04003)) ||
           address == GW_Z80_BUSREQ_ADDRESS || address == GW_Z80_RESET_ADDRESS ||
           address == GW_Z80_BANK_ADDRESS;
}

void gw_z80_sync(gw_machine *m, uint64_t tick)
{
    gw_z80 *z=&m->z80;
    size_t guard=0;
    /* Reset holds the Z80 clocks, but the 68000 owns the bus at power-on.
     * A request made in this state is therefore granted at the next modeled
     * clock boundary without issuing a Z80 machine cycle. */
    if (z->reset_asserted && z->busreq_pending && z->busreq_tick <= tick) {
        uint64_t boundary=next_clock_edge(z->busreq_tick);
        z->busreq_pending=0; z->busreq=1; arb_record(m,Z80_ARB_GRANT,boundary);
    }
    if (z->reset_asserted && z->reset_pending && z->reset_tick <= tick) {
        reset_on_edge(m,z->reset_tick);
    }
    while (!z->reset_asserted && !z->busreq && z->next_cycle_tick <= tick && guard++ < 1000000u) {
        uint64_t boundary=z->next_cycle_tick;
        if (z->busreq_pending && boundary > z->busreq_tick) {
            z->busreq_pending=0;
            z->busreq=1;
            arb_record(m,Z80_ARB_GRANT,boundary);
            break;
        }
        if (z->reset_pending && boundary >= z->reset_tick) {
            reset_on_edge(m,boundary);
        }
        if (!gw_z80_cycle(m)) break;
        gw_z80_sample_interrupt(m, z->next_cycle_tick);
        /* Some decoder transitions consume no bus phase; model that internal
         * transition at the current boundary and force monotonic progress. */
        if (z->next_cycle_tick == boundary) z->next_cycle_tick += GW_Z80_DIVIDER;
    }
    if (guard >= 1000000u && !z->reset_asserted && !z->busreq && z->next_cycle_tick <= tick) {
        /* Never return a digest/audio boundary that claims an unprocessed
         * Z80 interval. The caller receives an explicit unsupported stop. */
        m->cpu.stop_reason=GW_STOP_UNSUPPORTED_STATE;
        m->cpu.fault_address=UINT32_C(0x40000000) | z->pc;
        m->cpu.opcode=z->opcode;
    }
}

int gw_z80_int_asserted(const gw_machine *m, uint64_t tick)
{
    (void)m;
    uint64_t field = tick / GW_FIELD_TICKS;
    uint64_t start = field * (uint64_t)GW_FIELD_TICKS +
                     (uint64_t)224u * GW_LINE_TICKS;
    return tick >= start && tick - start < GW_Z80_INT_PULSE_TICKS;
}

static int z80_ram_access(gw_machine *m,uint32_t address,unsigned size,int write,uint32_t *value)
{
    gw_z80 *z=&m->z80;
    if (size != 1 || address > UINT32_C(0x00a03fff)) goto unsupported;
    if (z->busreq) {
        uint16_t at=(uint16_t)(address & UINT32_C(0x1fff));
        if (write) z->ram[at]=(uint8_t)*value;
        else *value=z->ram[at];
    } else if (!write) {
        *value=GW_Z80_UNKNOWN_READ; /* ungranted/reset read value is unknown */
    }
    return 1;
unsupported:
    m->cpu.stop_reason=GW_STOP_UNSUPPORTED_ADDRESS; m->cpu.fault_address=address; return 0;
}

static int control_access(gw_machine *m,uint32_t address,unsigned size,int write,uint32_t *value)
{
    gw_z80 *z=&m->z80;
    int high_byte=size==1 && !(address&1u);
    if ((size!=1 && size!=2) || (size==1 && !high_byte) || (size==2 && (address&1u))) goto unsupported;
    if (write) {
        unsigned control=size==2 ? (*value & UINT32_C(0x0100)) : ((*value & 1u) ? UINT32_C(0x0100):0u);
        if (address==GW_Z80_BUSREQ_ADDRESS) {
            if (control) {
                z->busreq_pending=1; z->busreq_tick=m->tick;
                arb_record(m,Z80_ARB_REQUEST,m->tick);
            } else {
                if (z->busreq) arb_record(m,Z80_ARB_RELEASE,m->tick);
                z->busreq=0; z->busreq_pending=0;
                if (z->next_cycle_tick <= m->tick)
                    z->next_cycle_tick=next_clock_edge(m->tick);
            }
        } else if (address==GW_Z80_RESET_ADDRESS) {
            if (!control) {
                /* A low level cancels an as-yet-uncommitted release. Apply CPU
                 * and FM reset effects only on the asserted transition. */
                z->reset_pending=0;
                if (!z->reset_asserted) {
                    /* 03-FM-RESET-AMENDMENT.md and docs/audio.md Reset search
                     * record: exact VA3 reset fidelity remains classed unknown. */
                    gw_ym2612_reset_line(m, m->tick, 1);
                    z->reset_asserted=1; z->instruction_active=0; z->prefix=0;
                    arb_record(m,Z80_ARB_RESET_ASSERT,m->tick);
                }
            } else if (z->reset_asserted && !z->reset_pending) {
                /* A repeated high level is not a new release edge. Preserve
                 * an already selected edge while reset remains asserted. */
                uint64_t edge=next_clock_edge(m->tick);
                z->reset_pending=1; z->reset_tick=edge;
            }
        } else goto unsupported;
    } else if (address==GW_Z80_BUSREQ_ADDRESS) {
        int granted=z->busreq;
        *value=size==2 ? (granted ? 0u : UINT32_C(0x0100)) : (granted ? 0u : 1u);
    } else goto unsupported;
    return 1;
unsupported:
    m->cpu.stop_reason=GW_STOP_UNSUPPORTED_ADDRESS; m->cpu.fault_address=address; return 0;
}

int gw_z80_bus_access(gw_machine *m,uint32_t address,unsigned size,int write,uint32_t *value)
{
    (void)GW_Z80_WINDOW_ACCESS_TICKS;
    if (address == GW_Z80_BANK_ADDRESS) {
        /* Sega Technical Overview p.77 and MacDonald hardware notes v0.8
         * sections2.1/2.3 identify this 68000 bank-register path. Reuse the
         * existing serial state, ownership gate and outer bus timing. Reads,
         * other widths and additional mirrors remain outside this model. */
        if (size != 1 || !write) {
            m->cpu.stop_reason=GW_STOP_UNSUPPORTED_ADDRESS;
            m->cpu.fault_address=address;
            return 0;
        }
        return !m->z80.busreq || gw_z80_mem_write(m,UINT16_C(0x6000),(uint8_t)*value,0);
    }
    if (address>=UINT32_C(0x00a04000) && address<=UINT32_C(0x00a04003)) {
        if (size != 1) {
            m->cpu.stop_reason=GW_STOP_UNSUPPORTED_ADDRESS;
            m->cpu.fault_address=address;
            return 0;
        }
        if (m->z80.busreq) {
            if (write) gw_ym2612_write(m, address & 3u, (uint8_t)*value, GW_AUDIO_SOURCE_68000);
            else {
                gw_audio_sync(m, m->tick);
                /* Pinned ymfm discrete-YM2612 read: only offset 0 exposes
                 * status. Other offsets return 0, an unqualified value. */
                *value=(address & 3u) == 0 ? gw_ym2612_read_status(m, m->tick) : 0;
            }
        } else if (!write) *value=GW_Z80_UNKNOWN_READ;
        return 1;
    }
    if (address>=UINT32_C(0x00a00000) && address<=UINT32_C(0x00a03fff))
        return z80_ram_access(m,address,size,write,value);
    return control_access(m,address,size,write,value);
}

static int z80_map_fault(gw_machine *m, uint16_t address)
{
    m->cpu.stop_reason=GW_STOP_UNSUPPORTED_ADDRESS;
    m->cpu.fault_address=UINT32_C(0x40000000) | address;
    m->cpu.opcode=m->z80.opcode;
    return 0;
}

int gw_z80_mem_read(gw_machine *m,uint16_t address,uint8_t *value,uint8_t cycle,uint8_t t_states)
{
    gw_z80 *z=&m->z80;
    (void)cycle; (void)t_states;
    if (address < UINT16_C(0x4000)) {
        *value=z->ram[address & UINT16_C(0x1fff)];
        return 1;
    }
    if (address <= UINT16_C(0x4003)) {
        gw_audio_sync(m, z->next_cycle_tick);
        *value=(address & 3u) == 0 ? gw_ym2612_read_status(m, z->next_cycle_tick) : 0;
        return 1;
    }
    if (address >= UINT16_C(0x8000)) {
        uint32_t mapped=(uint32_t)z->bank*UINT32_C(0x8000)+(uint32_t)(address-UINT16_C(0x8000));
        /* A mapped read must land in the loaded ROM itself. gw_bus_span also
         * accepts 68000 work RAM, which is outside this cartridge window. */
        if (mapped >= m->rom_size) return z80_map_fault(m,address);
        *value=gw_bus_peek(m,mapped);
        z->next_cycle_tick+=GW_Z80_BANK_WAIT_TICKS;
        return 1;
    }
    return z80_map_fault(m,address);
}

int gw_z80_mem_write(gw_machine *m,uint16_t address,uint8_t value,uint8_t t_states)
{
    gw_z80 *z=&m->z80;
    (void)t_states;
    if (address < UINT16_C(0x4000)) {
        z->ram[address & UINT16_C(0x1fff)]=value;
        return 1;
    }
    if (address <= UINT16_C(0x4003)) {
        gw_ym2612_write_at(m, z->next_cycle_tick, address & 3u, value, GW_AUDIO_SOURCE_Z80);
        return 1;
    }
    if (address >= UINT16_C(0x6000) && address <= UINT16_C(0x60ff)) {
        if (z->bank_shift_count==0) z->bank=0;
        z->bank=(uint16_t)((z->bank>>1)|((uint16_t)(value&1u)<<8));
        if (++z->bank_shift_count==9) z->bank_shift_count=0;
        return 1;
    }
    if (address==UINT16_C(0x7f11)) {
        uint8_t reg;
        uint64_t tick=z->next_cycle_tick;
        gw_audio_sync(m,tick);
        reg=gw_psg_write(m,value);
        gw_audio_trace_record_at(m,tick,GW_AUDIO_CHIP_PSG,reg,value,GW_AUDIO_SOURCE_Z80);
        return 1;
    }
    return z80_map_fault(m,address);
}

int gw_z80_io_read(gw_machine *m,uint16_t address,uint8_t *value)
{ (void)value; return z80_map_fault(m,address); }
int gw_z80_io_write(gw_machine *m,uint16_t address,uint8_t value)
{ (void)value; return z80_map_fault(m,address); }

#ifdef GW_TEST_HOOKS
size_t gw_test_z80_arb_event_count(const gw_machine *m) { return m ? m->z80_arb_event_count : 0; }
int gw_test_z80_arb_event_get(const gw_machine *m,size_t i,gw_test_z80_arb_event *e)
{ if(!m||!e||i>=m->z80_arb_event_count)return 0;*e=m->z80_arb_events[i];return 1; }
#endif

/* SPDX-License-Identifier: MIT */
#include "internal.h"

#ifdef GW_TEST_HOOKS
/* Copy the first bounded write observations, captured before each side effect.
 * Private test symbol: absent from hooks-off builds, no public header change. */
int gw_test_bus_write(const gw_machine *m, size_t index, uint64_t *tick,
                      uint32_t *address, uint32_t *value, uint32_t *prior_long)
{
    if (index >= m->write_count) return 0;
    *tick = m->writes[index].tick;
    *address = m->writes[index].address;
    *value = m->writes[index].value;
    *prior_long = m->writes[index].prior_long;
    return 1;
}

/* Sparse byte overlay: reset clears and activates; set updates or appends within
 * the bound (overflow records a miss); get reads a listed byte. */
void gw_test_memory_reset(gw_machine *m)
{
    m->test_memory_count = 0;
    m->test_memory_active = 1;
    m->test_memory_miss = 0;
    m->test_memory_miss_address = 0;
}

int gw_test_memory_set(gw_machine *m, uint32_t address, uint8_t value)
{
    address &= UINT32_C(0xffffff);
    for (size_t i = 0; i < m->test_memory_count; ++i) {
        if (m->test_memory[i].address == address) { m->test_memory[i].value = value; return 1; }
    }
    if (m->test_memory_count >= GW_TEST_MEMORY_CAPACITY) {
        m->test_memory_miss = 1;
        m->test_memory_miss_address = address;
        return 0;
    }
    m->test_memory[m->test_memory_count].address = address;
    m->test_memory[m->test_memory_count].value = value;
    ++m->test_memory_count;
    return 1;
}

int gw_test_memory_get(const gw_machine *m, uint32_t address, uint8_t *value)
{
    address &= UINT32_C(0xffffff);
    for (size_t i = 0; i < m->test_memory_count; ++i) {
        if (m->test_memory[i].address == address) { *value = m->test_memory[i].value; return 1; }
    }
    return 0;
}

int gw_test_memory_miss(const gw_machine *m, uint32_t *address)
{
    if (m->test_memory_miss) *address = m->test_memory_miss_address;
    return m->test_memory_miss;
}

static int overlay_unsupported(gw_machine *m, uint32_t address)
{
    m->cpu.stop_reason = GW_STOP_UNSUPPORTED_ADDRESS;
    m->cpu.fault_address = address;
    return 0;
}

static int overlay_read(gw_machine *m, uint32_t address, unsigned size, uint32_t *value)
{
    uint8_t hi, lo;
    if (size != 1 && (address & 1u)) return overlay_unsupported(m, address);
    if (!gw_test_memory_get(m, address, &hi)) {
        m->test_memory_miss = 1;
        m->test_memory_miss_address = address;
        return overlay_unsupported(m, address);
    }
    *value = hi;
    if (size == 2) {
        if (!gw_test_memory_get(m, address + 1, &lo)) {
            m->test_memory_miss = 1;
            m->test_memory_miss_address = (address + 1) & UINT32_C(0xffffff);
            return overlay_unsupported(m, address + 1);
        }
        *value = ((uint32_t)hi << 8) | lo;
    }
    m->tick += 4 * GW_CPU_DIVIDER;
    return 1;
}

static int overlay_write(gw_machine *m, uint32_t address, unsigned size, uint32_t value)
{
    if (size != 1 && (address & 1u)) return overlay_unsupported(m, address);
    m->tick += 4 * GW_CPU_DIVIDER;
    if (size == 1) return gw_test_memory_set(m, address, (uint8_t)value) || overlay_unsupported(m, address);
    return (gw_test_memory_set(m, address, (uint8_t)(value >> 8)) &&
            gw_test_memory_set(m, address + 1, (uint8_t)value)) || overlay_unsupported(m, address);
}
#endif

int gw_bus_span(const gw_machine *m, uint32_t address, size_t size, int write)
{
    if (address > UINT32_C(0xffffff) || size > UINT32_C(0x1000000) - address)
        return 0;
    if (address >= UINT32_C(0xe00000)) return 1;
    return !write && address <= m->rom_size && size <= m->rom_size - address;
}

uint8_t gw_bus_peek(const gw_machine *m, uint32_t address)
{
    return address >= UINT32_C(0xe00000) ? m->ram[address & 0xffffu] : m->rom[address];
}

static int is_vdp(uint32_t address) { return address >= UINT32_C(0xc00000) && address < UINT32_C(0xc00010); }
static int is_psg(uint32_t address) { return address == UINT32_C(0xc00011); }

/* VDP port access: word-aligned only. The VDP is brought to bus time before any
 * port side effect, so register and FIFO effects land after earlier raster work. */
static int vdp_access(gw_machine *m, uint32_t address, unsigned size, int write, uint32_t *value)
{
    if (size != 2 || (address & 1u)) {
        m->cpu.stop_reason = GW_STOP_UNSUPPORTED_ADDRESS;
        m->cpu.fault_address = address;
        return 0;
    }
    m->tick += 4 * GW_CPU_DIVIDER;
    gw_vdp_advance(m, m->tick);
    if (gw_stop_is_unsupported(m->cpu.stop_reason)) return 0;
    return write ? gw_vdp_write(m, address, size, *value) : gw_vdp_read(m, address, size, value);
}

/* I/O register access: byte only at the modeled odd addresses. Pad events due at
 * bus time are applied before the register is touched, so what a read observes
 * never depends on how the host split its run calls. */
static int io_access(gw_machine *m, uint32_t address, int write, uint32_t *value)
{
    m->tick += 4 * GW_CPU_DIVIDER;
    gw_io_advance(m, m->tick);
    if (write) gw_io_write(m, address, *value);
    else gw_io_read(m, address, value);
    return 1;
}

/* Only the verified PSG data port is decoded. Other sizes, reads and mirrors
 * fail closed with an unsupported-address stop. */
static int psg_access(gw_machine *m, uint32_t address, unsigned size, int write, uint32_t *value)
{
    if (size != 1 || !write) {
        m->cpu.stop_reason = GW_STOP_UNSUPPORTED_ADDRESS;
        m->cpu.fault_address = address;
        return 0;
    }
    m->tick += 4 * GW_CPU_DIVIDER;
    gw_audio_sync(m, m->tick);
    {
        uint8_t reg = gw_psg_write(m, (uint8_t)*value);
        gw_audio_trace_record(m, GW_AUDIO_CHIP_PSG, reg, (uint8_t)*value,
            GW_AUDIO_SOURCE_68000);
    }
    return 1;
}

static int access_ok(gw_machine *m, uint32_t address, unsigned size, int write)
{
    if ((size != 1 && (address & 1u)) || !gw_bus_span(m, address, size, write)) {
        m->cpu.stop_reason = GW_STOP_UNSUPPORTED_ADDRESS;
        m->cpu.fault_address = address;
        return 0;
    }
    return 1;
}

int gw_bus_read(gw_machine *m, uint32_t address, unsigned size, uint32_t *value)
{
    uint32_t hi, lo;
    address &= UINT32_C(0xffffff);
    gw_z80_sync(m,m->tick);
    /* Longwords are two independently decoded word transfers, including
     * 24-bit wrap. A completed first transfer is not undone by the second. */
    if (size == 4) {
        if (!gw_bus_read(m, address, 2, &hi) || !gw_bus_read(m, address + 2, 2, &lo)) return 0;
        *value = (hi << 16) | lo;
        return 1;
    }
#ifdef GW_TEST_HOOKS
    if (m->test_memory_active) return overlay_read(m, address, size, value);
#endif
    if (gw_z80_bus_decodes(address)) {
        m->tick += 4 * GW_CPU_DIVIDER;
        gw_z80_sync(m,m->tick);
        return gw_z80_bus_access(m,address,size,0,value);
    }
    if (is_vdp(address)) return vdp_access(m, address, size, 0, value);
    if (is_psg(address)) return psg_access(m, address, size, 0, value);
    if (size == 1 && gw_io_decodes(address)) return io_access(m, address, 0, value);
    if (!access_ok(m, address, size, 0)) return 0;
    /* Ordered four-CPU-cycle transfers, before sampling/committing data.
     * ROM/RAM have no advancing devices or waits in this subset. */
    m->tick += 4 * GW_CPU_DIVIDER;
    *value = gw_bus_peek(m, address);
    if (size == 2) *value = (*value << 8) | gw_bus_peek(m, address + 1);
    return 1;
}

int gw_bus_write(gw_machine *m, uint32_t address, unsigned size, uint32_t value)
{
    address &= UINT32_C(0xffffff);
    gw_z80_sync(m,m->tick);
    if (size == 4) {
        return gw_bus_write(m, address, 2, value >> 16) &&
               gw_bus_write(m, address + 2, 2, value & 0xffffu);
    }
#ifdef GW_TEST_HOOKS
    if (m->test_memory_active) return overlay_write(m, address, size, value);
#endif
    if (gw_z80_bus_decodes(address)) {
        m->tick += 4 * GW_CPU_DIVIDER;
        gw_z80_sync(m,m->tick);
        return gw_z80_bus_access(m,address,size,1,&value);
    }
    if (is_vdp(address)) return vdp_access(m, address, size, 1, &value);
    if (is_psg(address)) return psg_access(m, address, size, 1, &value);
    if (size == 1 && gw_io_decodes(address)) return io_access(m, address, 1, &value);
    if (!access_ok(m, address, size, 1)) return 0;
    m->tick += 4 * GW_CPU_DIVIDER;
#ifdef GW_TEST_HOOKS
    if (m->write_count < sizeof(m->writes)/sizeof(m->writes[0])) {
        size_t i = m->write_count++;
        m->writes[i].tick = m->tick;
        m->writes[i].address = address;
        m->writes[i].value = value;
        m->writes[i].prior_long = gw_be32(m->ram + (address & 0xfffcu));
    }
#endif
    if (size == 1) {
        m->ram[address & 0xffffu] = (uint8_t)value;
    } else {
        m->ram[address & 0xffffu] = (uint8_t)(value >> 8);
        m->ram[(address + 1) & 0xffffu] = (uint8_t)value;
    }
    return 1;
}

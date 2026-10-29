/* SPDX-License-Identifier: MIT
 * Original I/O device: version register, two controller-port data/control
 * register pairs and the three-button pad TH protocol, with timestamped pad
 * events applied at bus time. Register map and pad protocol follow the
 * plutiedev controllers/io-ports pages; the Genesis Plus GX behaviour was
 * consulted as a behavioural reference only and no code was copied.
 * See docs/input.md for the contract and limitations.
 */
#include "internal.h"

#define IO_VERSION_ADDRESS UINT32_C(0xa10001)
#define IO_DATA0_ADDRESS UINT32_C(0xa10003)
#define IO_DATA1_ADDRESS UINT32_C(0xa10005)
#define IO_CTRL0_ADDRESS UINT32_C(0xa10009)
#define IO_CTRL1_ADDRESS UINT32_C(0xa1000b)
#define IO_EXT_DATA_ADDRESS UINT32_C(0xa10007)
#define IO_EXT_CTRL_ADDRESS UINT32_C(0xa1000d)
/* Assumption A6: bit 7 overseas, bit 6 NTSC (0), bit 5 no expansion unit (1),
 * bits 3-0 hardware version 0. plutiedev io-ports documents this layout; the
 * value is the profile's documented choice, not measured from a console. */
#define IO_VERSION_VALUE 0xa0u
#define PIN_ALL_HIGH 0x7fu /* Assumption A7: an empty port reads pull-ups. */

void gw_io_cold_init(gw_machine *m)
{
    gw_io *io = &m->io;
    memset(io, 0, sizeof(*io));
    io->version = IO_VERSION_VALUE;
    for (unsigned i = 0; i < GW_IO_PORTS; ++i) io->device[i] = (uint8_t)m->config.port_device[i];
}

void gw_io_console_reset(gw_machine *m)
{
    m->io.ext_data = m->io.ext_ctrl = 0;
    for (unsigned i = 0; i < GW_IO_PORTS; ++i) {
        m->io.data[i] = 0;
        m->io.ctrl[i] = 0;
    }
}

static void set_buttons(gw_machine *m, uint32_t port, uint32_t mask)
{
    if (port < GW_IO_PORTS) m->io.buttons[port] = (uint8_t)(mask & GW_BUTTON_MASK_PAD3);
}

void gw_io_advance(gw_machine *m, uint64_t tick)
{
    while (m->event_count && m->events[0].type == GW_EVENT_PAD_STATE && m->events[0].tick <= tick) {
        gw_event e = m->events[0];
        --m->event_count;
        memmove(m->events, m->events + 1, m->event_count * sizeof(m->events[0]));
        set_buttons(m, e.port, e.mask);
    }
}

int gw_io_decodes(uint32_t address)
{
    return address == IO_VERSION_ADDRESS || address == IO_DATA0_ADDRESS ||
           address == IO_DATA1_ADDRESS || address == IO_CTRL0_ADDRESS ||
           address == IO_CTRL1_ADDRESS || address == IO_EXT_DATA_ADDRESS ||
           address == IO_EXT_CTRL_ADDRESS;
}

uint32_t gw_io_pad_pins(uint32_t buttons, int th_high)
{
    uint32_t pins = th_high ? 0x40u : 0u;
    uint32_t pressed = th_high
        ? (((buttons & GW_BUTTON_C) ? 0x20u : 0u) | ((buttons & GW_BUTTON_B) ? 0x10u : 0u) |
           ((buttons & GW_BUTTON_RIGHT) ? 0x08u : 0u) | ((buttons & GW_BUTTON_LEFT) ? 0x04u : 0u))
        : (((buttons & GW_BUTTON_START) ? 0x20u : 0u) | ((buttons & GW_BUTTON_A) ? 0x10u : 0u));
    pressed |= ((buttons & GW_BUTTON_DOWN) ? 0x02u : 0u) | ((buttons & GW_BUTTON_UP) ? 0x01u : 0u);
    /* Active low: the lines a pad drives stay high unless pressed. TH low
     * additionally drives bits 3-2 low. */
    pins |= (th_high ? 0x3fu : 0x33u) & ~pressed;
    return pins;
}

static unsigned port_index(uint32_t address)
{
    return (address == IO_DATA0_ADDRESS || address == IO_CTRL0_ADDRESS) ? 0u : 1u;
}

static uint32_t read_data(const gw_machine *m, unsigned port)
{
    const gw_io *io = &m->io;
    uint32_t out_mask = (uint32_t)io->ctrl[port] | 0x80u; /* Bit 7 is always latch-backed. */
    int th_high = (io->ctrl[port] & 0x40u) ? ((io->data[port] >> 6) & 1u) : 1;
    uint32_t pins = io->device[port] == GW_DEVICE_PAD3
        ? gw_io_pad_pins(io->buttons[port], th_high) : PIN_ALL_HIGH;
    return ((uint32_t)io->data[port] & out_mask) | (pins & ~out_mask & 0xffu);
}

void gw_io_read(gw_machine *m, uint32_t address, uint32_t *value)
{
    switch (address) {
    case IO_VERSION_ADDRESS: *value = m->io.version; break;
    case IO_EXT_CTRL_ADDRESS: *value = m->io.ext_ctrl; break;
    case IO_EXT_DATA_ADDRESS: {
        uint32_t outputs=(uint32_t)m->io.ext_ctrl|0x80u;
        *value=((uint32_t)m->io.ext_data&outputs)|(PIN_ALL_HIGH&~outputs);
        break;
    }
    case IO_DATA0_ADDRESS:
    case IO_DATA1_ADDRESS: *value = read_data(m, port_index(address)); break;
    default: *value = m->io.ctrl[port_index(address)]; break;
    }
}

void gw_io_write(gw_machine *m, uint32_t address, uint32_t value)
{
    switch (address) {
    case IO_VERSION_ADDRESS: break; /* Read-only: writes are ignored. */
    case IO_EXT_CTRL_ADDRESS: m->io.ext_ctrl=(uint8_t)value; break;
    case IO_EXT_DATA_ADDRESS: m->io.ext_data=(uint8_t)value; break;
    case IO_DATA0_ADDRESS:
    case IO_DATA1_ADDRESS: m->io.data[port_index(address)] = (uint8_t)value; break;
    default: m->io.ctrl[port_index(address)] = (uint8_t)value; break;
    }
}

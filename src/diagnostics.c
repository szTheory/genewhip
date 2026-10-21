/* SPDX-License-Identifier: MIT */
#include "internal.h"

void gw_diagnostics_clear(gw_machine *m)
{
    m->diagnostic_count = 0;
    m->diagnostic_dropped = 0;
    m->instructions = m->exceptions = m->exception_returns = m->external_resets = 0;
}

gw_status gw_configure_diagnostics(gw_machine *m, size_t capacity)
{
    if (!m) return GW_ERROR_ARGUMENT;
    if (capacity > GW_DIAGNOSTIC_CAPACITY) return GW_ERROR_CAPACITY;
    m->diagnostic_capacity = capacity;
    m->config.diagnostics = capacity != 0;
    gw_diagnostics_clear(m);
    return GW_OK;
}

gw_status gw_get_diagnostic_events(const gw_machine *m, gw_diagnostic_event *events,
    size_t capacity, size_t *count, uint64_t *dropped)
{
    if (!m || (!events && capacity) || !count || !dropped) return GW_ERROR_ARGUMENT;
    if (capacity < m->diagnostic_count) return GW_ERROR_CAPACITY;
    if (m->diagnostic_count)
        memcpy(events, m->diagnostic_events, m->diagnostic_count * sizeof(*events));
    *count = m->diagnostic_count;
    *dropped = m->diagnostic_dropped;
    return GW_OK;
}

void gw_diagnostics_record(gw_machine *m)
{
    gw_diagnostic_event *event;
    if (!m->config.diagnostics) return;
    if (m->diagnostic_count == m->diagnostic_capacity) {
        if (m->diagnostic_dropped != UINT64_MAX) ++m->diagnostic_dropped;
        return;
    }
    event = &m->diagnostic_events[m->diagnostic_count++];
    event->tick = m->tick;
    event->instruction_address = m->cpu.instruction_address;
    event->opcode = m->cpu.opcode;
    event->stop_reason = m->cpu.stop_reason;
    event->fault_address = m->cpu.fault_address;
}

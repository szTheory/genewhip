/* SPDX-License-Identifier: MIT */
#include "internal.h"

gw_status gw_get_diagnostics(const gw_machine *m, gw_diagnostic_record *record)
{
    if (!m || !record) return GW_ERROR_ARGUMENT;
    if (record->struct_size != sizeof(*record) || record->version != GW_API_VERSION)
        return GW_ERROR_VERSION;
    if (!m->rom) return GW_ERROR_NOT_LOADED;
    record->tick = m->tick;
    record->profile = m->config.profile;
    record->pc = m->cpu.pc;
    record->sr = m->cpu.sr;
    memcpy(record->d, m->cpu.d, sizeof(record->d));
    memcpy(record->a, m->cpu.a, sizeof(record->a));
    record->initial_ssp = m->initial_ssp;
    record->initial_pc = m->initial_pc;
    record->stop_reason = m->cpu.stop_reason;
    record->diagnostics_enabled = m->config.diagnostics;
    record->instructions = m->instructions;
    record->exceptions = m->exceptions;
    record->exception_returns = m->exception_returns;
    record->external_resets = m->external_resets;
    return GW_OK;
}

gw_status gw_peek_memory(const gw_machine *m, uint32_t address, void *output, size_t size)
{
    uint8_t *bytes = output;
    size_t i;
    if (!m || (!output && size)) return GW_ERROR_ARGUMENT;
    if (!m->rom) return GW_ERROR_NOT_LOADED;
    if (size > GW_RAM_SIZE || !gw_bus_span(m, address, size, 0)) return GW_ERROR_ARGUMENT;
    for (i = 0; i < size; ++i) bytes[i] = gw_bus_peek(m, address + (uint32_t)i);
    return GW_OK;
}

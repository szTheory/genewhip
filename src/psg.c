/* SPDX-License-Identifier: MIT
 * Original SN76489-compatible PSG model, written from the SN76489 documentation
 * at smspower.org and plutiedev.com/psg. No third-party code was used.
 */
#include "internal.h"

/* Nearest integer to 2048 * 10^(-2*n/20), with register 15 silent. */
static const int16_t psg_amplitude[16] = {
    2048, 1628, 1293, 1027, 816, 648, 515, 409,
    325, 258, 205, 163, 129, 103, 82, 0
};

static int32_t psg_level(const gw_psg *psg)
{
    int32_t level = 0;
    unsigned channel;
    for (channel = 0; channel < 3; ++channel) {
        int32_t amplitude = psg_amplitude[psg->attenuation[channel]];
        level += psg->output[channel] ? amplitude : -amplitude;
    }
    {
        int32_t amplitude = psg_amplitude[psg->attenuation[3]];
        level += psg->noise_output ? amplitude : -amplitude;
    }
    return level;
}

/* SMS Power documents Genesis white-noise taps 0 and 3 and periodic feedback
 * from bit 0, shifted right with feedback inserted at bit 15. */
static uint16_t psg_noise_shift(uint16_t state, uint8_t white)
{
    unsigned feedback = (unsigned)(state & 1u);
    if (white) feedback ^= (unsigned)((state >> 3) & 1u);
    return (uint16_t)((state >> 1) | (feedback << 15));
}

/* A nonzero 16-bit PSG sequence repeats within at most 32767 shifts. Keeping
 * this loop bounded makes audio-disabled large-tick runs independent of span. */
static uint16_t psg_noise_advance(uint16_t state, uint8_t white, uint64_t shifts)
{
    uint64_t i, limit = shifts % UINT64_C(32767);
    for (i = 0; i < limit; ++i) state = psg_noise_shift(state, white);
    return state;
}

static unsigned psg_noise_divisor(const gw_psg *psg)
{
    switch (psg->period[3] & 3u) {
    case 0: return 0x10u;
    case 1: return 0x20u;
    case 2: return 0x40u;
    default: return 0u; /* tone 2 transitions clock this mode */
    }
}

static void psg_noise_clocks(gw_psg *psg, uint64_t clocks)
{
    uint64_t shifts;
    unsigned divisor = psg_noise_divisor(psg);
    if (!divisor || !clocks) return;
    if (psg->noise_counter == 0) psg->noise_counter = (uint16_t)divisor;
    if (clocks < psg->noise_counter) {
        psg->noise_counter = (uint16_t)(psg->noise_counter - clocks);
        return;
    }
    clocks -= psg->noise_counter;
    shifts = 1u + clocks / divisor;
    psg->noise_counter = (uint16_t)(divisor - clocks % divisor);
    psg->lfsr = psg_noise_advance(psg->lfsr, (uint8_t)((psg->period[3] & 4u) != 0), shifts);
    psg->noise_output = (uint8_t)(psg->lfsr & 1u);
}

void gw_psg_cold_init(gw_machine *m)
{
    unsigned channel;
    memset(&m->psg, 0, sizeof(m->psg));
    m->psg.lfsr = UINT16_C(0x8000);
    for (channel = 0; channel < 4; ++channel) m->psg.attenuation[channel] = 15;
    for (channel = 0; channel < 3; ++channel) m->psg.output[channel] = 1;
    m->psg.noise_counter = UINT16_C(0x10);
    m->psg.next_step_tick = GW_PSG_STEP_TICKS;
}

/* The console-reset policy is a model choice: retain registers and phase. */
void gw_psg_console_reset(gw_machine *m)
{
    (void)m;
}

uint8_t gw_psg_write(gw_machine *m, uint8_t value)
{
    gw_psg *psg = &m->psg;
    unsigned channel;
    unsigned type;
    uint8_t reg;
    int32_t before = psg_level(psg);
    if (value & 0x80u) {
        channel = (value >> 5) & 3u;
        type = (value >> 4) & 1u;
        reg = (uint8_t)(channel * 2u + type);
        psg->latched_register = reg;
        if (type == 0) {
            if (channel < 3) {
                psg->period[channel] = (uint16_t)((psg->period[channel] & 0x03f0u) | (value & 0x0fu));
                psg->counter[channel] = psg->period[channel];
            } else {
                psg->period[3] = (uint16_t)(value & 0x07u);
                psg->noise_counter = (psg->period[3] & 3u) == 3u ? 0 :
                    (uint16_t)(UINT16_C(0x10) << (psg->period[3] & 3u));
                psg->lfsr = UINT16_C(0x8000);
                psg->noise_output = 0;
            }
        } else {
            psg->attenuation[channel] = value & 0x0fu;
        }
    } else {
        reg = psg->latched_register;
        channel = reg / 2u;
        type = reg & 1u;
        if (type == 0 && channel < 3) {
            psg->period[channel] = (uint16_t)((psg->period[channel] & 0x000fu) |
                ((uint32_t)(value & 0x3fu) << 4));
            psg->counter[channel] = psg->period[channel];
        }
    }
    {
        int32_t after = psg_level(psg);
        if (after != before) gw_audio_add_step(m, m->tick, after - before, after - before);
    }
    return reg;
}

void gw_psg_advance(gw_machine *m, uint64_t tick)
{
    gw_psg *psg = &m->psg;
    if (m->audio.rate_hz == 0 && psg->next_step_tick <= tick) {
        uint64_t steps = (tick - psg->next_step_tick) / GW_PSG_STEP_TICKS + 1u;
        unsigned channel;
        uint64_t tone2_transitions = 0;
        uint16_t tone2_period = psg->period[2];
        if ((psg->period[3] & 3u) == 3u && tone2_period > 1) {
            uint64_t first = psg->counter[2] ? psg->counter[2] : 1u;
            if (steps >= first) tone2_transitions = 1u + (steps - first) / tone2_period;
        }
        /* Audio-disabled machines still reach the exact PSG state at `tick`.
         * With no output to inject, fold periodic tone counters arithmetically. */
        for (channel = 0; channel < 3; ++channel) {
            uint16_t period = psg->period[channel];
            uint64_t until_toggle;
            if (period <= 1) {
                psg->counter[channel] = period;
                psg->output[channel] = 1;
                continue;
            }
            until_toggle = psg->counter[channel] ? psg->counter[channel] : 1u;
            if (steps < until_toggle) {
                psg->counter[channel] = (uint16_t)(psg->counter[channel] - steps);
            } else {
                uint64_t after_first = steps - until_toggle;
                uint64_t toggles = 1u + after_first / period;
                uint64_t remainder = after_first % period;
                if (toggles & 1u) psg->output[channel] ^= 1u;
                psg->counter[channel] = (uint16_t)(period - remainder);
            }
        }
        {
            if ((psg->period[3] & 3u) == 3u && tone2_transitions) {
                psg->lfsr = psg_noise_advance(psg->lfsr,
                    (uint8_t)((psg->period[3] & 4u) != 0), tone2_transitions);
                psg->noise_output = (uint8_t)(psg->lfsr & 1u);
            } else if ((psg->period[3] & 3u) != 3u) {
                psg_noise_clocks(psg, steps);
            }
        }
        if (steps > (UINT64_MAX - psg->next_step_tick) / GW_PSG_STEP_TICKS)
            psg->next_step_tick = UINT64_MAX;
        else
            psg->next_step_tick += steps * GW_PSG_STEP_TICKS;
        return;
    }
    while (psg->next_step_tick <= tick) {
        uint64_t step_tick = psg->next_step_tick;
        int32_t before = psg_level(psg);
        unsigned channel;
        uint8_t tone2_before = psg->output[2];
        /* Flush complete frames before this step. A fixed-size ring then remains
         * safe even when one public run spans more than the PCM queue capacity. */
        gw_audio_finalise(m, step_tick);
        for (channel = 0; channel < 3; ++channel) {
            uint16_t period = psg->period[channel];
            if (period > 1) {
                if (psg->counter[channel] > 1) {
                    --psg->counter[channel];
                } else {
                    psg->counter[channel] = period;
                    psg->output[channel] ^= 1u;
                }
            } else {
                psg->counter[channel] = period;
                psg->output[channel] = 1;
            }
        }
        {
            unsigned divisor = psg_noise_divisor(psg);
            if (divisor) {
                if (psg->noise_counter == 0) psg->noise_counter = (uint16_t)divisor;
                else if (psg->noise_counter > 1) --psg->noise_counter;
                else {
                    psg->noise_counter = (uint16_t)divisor;
                    psg->lfsr = psg_noise_shift(psg->lfsr,
                        (uint8_t)((psg->period[3] & 4u) != 0));
                    psg->noise_output = (uint8_t)(psg->lfsr & 1u);
                }
            } else if (tone2_before != psg->output[2]) {
                psg->lfsr = psg_noise_shift(psg->lfsr,
                    (uint8_t)((psg->period[3] & 4u) != 0));
                psg->noise_output = (uint8_t)(psg->lfsr & 1u);
            }
        }
        {
            int32_t after = psg_level(psg);
            if (after != before) gw_audio_add_step(m, step_tick, after - before, after - before);
        }
        if (psg->next_step_tick > UINT64_MAX - GW_PSG_STEP_TICKS) {
            psg->next_step_tick = UINT64_MAX;
            break;
        }
        psg->next_step_tick += GW_PSG_STEP_TICKS;
    }
}

#ifdef GW_TEST_HOOKS
static uint64_t psg_digest_byte(uint64_t hash, uint8_t value)
{
    return (hash ^ value) * UINT64_C(1099511628211);
}

static uint64_t psg_digest_u16(uint64_t hash, uint16_t value)
{
    hash = psg_digest_byte(hash, (uint8_t)value);
    return psg_digest_byte(hash, (uint8_t)(value >> 8));
}

static uint64_t psg_digest_u64(uint64_t hash, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) hash = psg_digest_byte(hash, (uint8_t)(value >> (i * 8u)));
    return hash;
}

uint64_t gw_psg_digest(const gw_psg *psg, uint64_t hash)
{
    for (unsigned i = 0; i < 4; ++i) hash = psg_digest_u16(hash, psg->period[i]);
    for (unsigned i = 0; i < 4; ++i) hash = psg_digest_byte(hash, psg->attenuation[i]);
    hash = psg_digest_byte(hash, psg->latched_register);
    for (unsigned i = 0; i < 3; ++i) hash = psg_digest_u16(hash, psg->counter[i]);
    for (unsigned i = 0; i < 3; ++i) hash = psg_digest_byte(hash, psg->output[i]);
    hash = psg_digest_u16(hash, psg->noise_counter);
    hash = psg_digest_u16(hash, psg->lfsr);
    hash = psg_digest_byte(hash, psg->noise_output);
    return psg_digest_u64(hash, psg->next_step_tick);
}

uint16_t gw_test_psg_lfsr(const gw_machine *machine)
{
    return machine ? machine->psg.lfsr : 0;
}

int32_t gw_test_psg_level(const gw_machine *machine)
{
    return machine ? psg_level(&machine->psg) : 0;
}
#endif

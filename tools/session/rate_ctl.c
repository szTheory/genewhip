/* SPDX-License-Identifier: MIT */
#include "rate_ctl.h"

#include <limits.h>

static unsigned add_mod(uint64_t *value, uint64_t addend, uint64_t modulus)
{
    uint64_t distance = modulus - addend;
    if (*value >= distance) {
        *value -= distance;
        return 1u;
    }
    *value += addend;
    return 0u;
}

/* Computes floor(a*b/d) for 0 <= a < d and b <= 2^31 without overflowing. */
static uint64_t fractional_product(uint64_t a, uint64_t b, uint64_t d)
{
    uint64_t quotient = 0, remainder = 0;
    for (int bit = 31; bit >= 0; --bit) {
        unsigned carry = add_mod(&remainder, remainder, d);
        quotient *= 2u;
        if ((b >> (unsigned)bit) & 1u) carry += add_mod(&remainder, a, d);
        quotient += carry;
    }
    return quotient;
}

int32_t gw_rate_ppm(int64_t depth_frames, int64_t target_frames, int32_t k_ppm)
{
    uint64_t difference, target, gain, whole, remainder, magnitude;
    int negative;
    if (target_frames <= 0 || k_ppm == 0 || depth_frames == target_frames) return 0;
    target = (uint64_t)target_frames;
    negative = (depth_frames < target_frames) != (k_ppm < 0);
    difference = depth_frames >= target_frames
        ? (uint64_t)depth_frames - target
        : target - (uint64_t)depth_frames;
    gain = k_ppm < 0 ? (uint64_t)(-(int64_t)k_ppm) : (uint64_t)k_ppm;
    whole = difference / target;
    remainder = difference % target;
    if (whole > (uint64_t)GW_RATE_LIMIT_PPM / gain)
        return negative ? -GW_RATE_LIMIT_PPM : GW_RATE_LIMIT_PPM;
    magnitude = whole * gain + fractional_product(remainder, gain, target);
    if (magnitude > (uint64_t)GW_RATE_LIMIT_PPM) magnitude = (uint64_t)GW_RATE_LIMIT_PPM;
    return negative ? -(int32_t)magnitude : (int32_t)magnitude;
}

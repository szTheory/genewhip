/* SPDX-License-Identifier: BSD-3-Clause
BSD 3-Clause License

Copyright (c) 2021, Aaron Giles
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/* C17 specialization of ymfm 81aec25ccbb98f4873a255f7551ac4dadac59b4a.
 * File/function mapping: ymfm_fm.ipp helpers -> same names; fm_operator -> op_*;
 * fm_channel -> ch_*; fm_engine_base -> engine_*; ymfm_opn.{h,cpp}
 * opn_registers_base<true> (opna_registers) -> reg_*; ym2612 -> gw_ym2612_*.
 * Only OPN2 is specialized: SSG, ADPCM, OPL rhythm, OPM and other chips omitted.
 * See packaging/notices/THIRD-PARTY-ymfm.txt for exact source hashes and ledger.
 */
#include "internal.h"
#include <assert.h>
#include <stdbool.h>
#include <limits.h>
enum { EG_DEPRESS, EG_ATTACK, EG_DECAY, EG_SUSTAIN, EG_RELEASE, EG_REVERB, EG_STATES };
enum { KEYON_NORMAL, KEYON_RHYTHM, KEYON_CSM };
static uint32_t bitfield(uint32_t value, unsigned start, unsigned count)
{ return (value >> start) & ((UINT32_C(1) << count) - 1); }
static uint32_t min_u32(uint32_t a, uint32_t b) { return a < b ? a : b; }
static int32_t clamp(int32_t value, int32_t low, int32_t high)
{ return value < low ? low : value > high ? high : value; }
/* Equivalent to an arithmetic right shift, defined also for negative C17
 * operands. n is in 0..31 at every call site. */
static int32_t asr(int32_t value, unsigned n)
{
    if (value >= 0) return (int32_t)((uint32_t)value >> n);
    return -1 - (int32_t)((uint32_t)(-(value + 1)) >> n);
}
static uint32_t effective_rate(uint32_t rate, uint32_t ksr)
{ return rate == 0 ? 0 : min_u32(rate + ksr, 63); }
/* ymfm: ymfm_fm.ipp abs_sin_attenuation */
static uint32_t abs_sin_attenuation(uint32_t input)
{
    // the values here are stored as 4.8 logarithmic values for 1/4 phase
    // this matches the internal format of the OPN chip, extracted from the die
    static uint16_t const s_sin_table[256] =
    {
        0x859,0x6c3,0x607,0x58b,0x52e,0x4e4,0x4a6,0x471,0x443,0x41a,0x3f5,0x3d3,0x3b5,0x398,0x37e,0x365,
        0x34e,0x339,0x324,0x311,0x2ff,0x2ed,0x2dc,0x2cd,0x2bd,0x2af,0x2a0,0x293,0x286,0x279,0x26d,0x261,
        0x256,0x24b,0x240,0x236,0x22c,0x222,0x218,0x20f,0x206,0x1fd,0x1f5,0x1ec,0x1e4,0x1dc,0x1d4,0x1cd,
        0x1c5,0x1be,0x1b7,0x1b0,0x1a9,0x1a2,0x19b,0x195,0x18f,0x188,0x182,0x17c,0x177,0x171,0x16b,0x166,
        0x160,0x15b,0x155,0x150,0x14b,0x146,0x141,0x13c,0x137,0x133,0x12e,0x129,0x125,0x121,0x11c,0x118,
        0x114,0x10f,0x10b,0x107,0x103,0x0ff,0x0fb,0x0f8,0x0f4,0x0f0,0x0ec,0x0e9,0x0e5,0x0e2,0x0de,0x0db,
        0x0d7,0x0d4,0x0d1,0x0cd,0x0ca,0x0c7,0x0c4,0x0c1,0x0be,0x0bb,0x0b8,0x0b5,0x0b2,0x0af,0x0ac,0x0a9,
        0x0a7,0x0a4,0x0a1,0x09f,0x09c,0x099,0x097,0x094,0x092,0x08f,0x08d,0x08a,0x088,0x086,0x083,0x081,
        0x07f,0x07d,0x07a,0x078,0x076,0x074,0x072,0x070,0x06e,0x06c,0x06a,0x068,0x066,0x064,0x062,0x060,
        0x05e,0x05c,0x05b,0x059,0x057,0x055,0x053,0x052,0x050,0x04e,0x04d,0x04b,0x04a,0x048,0x046,0x045,
        0x043,0x042,0x040,0x03f,0x03e,0x03c,0x03b,0x039,0x038,0x037,0x035,0x034,0x033,0x031,0x030,0x02f,
        0x02e,0x02d,0x02b,0x02a,0x029,0x028,0x027,0x026,0x025,0x024,0x023,0x022,0x021,0x020,0x01f,0x01e,
        0x01d,0x01c,0x01b,0x01a,0x019,0x018,0x017,0x017,0x016,0x015,0x014,0x014,0x013,0x012,0x011,0x011,
        0x010,0x00f,0x00f,0x00e,0x00d,0x00d,0x00c,0x00c,0x00b,0x00a,0x00a,0x009,0x009,0x008,0x008,0x007,
        0x007,0x007,0x006,0x006,0x005,0x005,0x005,0x004,0x004,0x004,0x003,0x003,0x003,0x002,0x002,0x002,
        0x002,0x001,0x001,0x001,0x001,0x001,0x001,0x001,0x000,0x000,0x000,0x000,0x000,0x000,0x000,0x000
    };

    // if the top bit is set, we're in the second half of the curve
    // which is a mirror image, so invert the index
    if (bitfield(input, 8, 1))
        input = ~input;

    // return the value from the table
    return s_sin_table[input & 0xff];
}

/* ymfm: ymfm_fm.ipp attenuation_to_volume */
static uint32_t attenuation_to_volume(uint32_t input)
{
    // the values here are 10-bit mantissas with an implied leading bit
    // this matches the internal format of the OPN chip, extracted from the die

    // as a nod to performance, the implicit 0x400 bit is pre-incorporated, and
    // the values are left-shifted by 2 so that a simple right shift is all that
    // is needed; also the order is reversed to save a NOT on the input
#define X(a) (((a) | 0x400) << 2)
    static uint16_t const s_power_table[256] =
    {
        X(0x3fa),X(0x3f5),X(0x3ef),X(0x3ea),X(0x3e4),X(0x3df),X(0x3da),X(0x3d4),
        X(0x3cf),X(0x3c9),X(0x3c4),X(0x3bf),X(0x3b9),X(0x3b4),X(0x3ae),X(0x3a9),
        X(0x3a4),X(0x39f),X(0x399),X(0x394),X(0x38f),X(0x38a),X(0x384),X(0x37f),
        X(0x37a),X(0x375),X(0x370),X(0x36a),X(0x365),X(0x360),X(0x35b),X(0x356),
        X(0x351),X(0x34c),X(0x347),X(0x342),X(0x33d),X(0x338),X(0x333),X(0x32e),
        X(0x329),X(0x324),X(0x31f),X(0x31a),X(0x315),X(0x310),X(0x30b),X(0x306),
        X(0x302),X(0x2fd),X(0x2f8),X(0x2f3),X(0x2ee),X(0x2e9),X(0x2e5),X(0x2e0),
        X(0x2db),X(0x2d6),X(0x2d2),X(0x2cd),X(0x2c8),X(0x2c4),X(0x2bf),X(0x2ba),
        X(0x2b5),X(0x2b1),X(0x2ac),X(0x2a8),X(0x2a3),X(0x29e),X(0x29a),X(0x295),
        X(0x291),X(0x28c),X(0x288),X(0x283),X(0x27f),X(0x27a),X(0x276),X(0x271),
        X(0x26d),X(0x268),X(0x264),X(0x25f),X(0x25b),X(0x257),X(0x252),X(0x24e),
        X(0x249),X(0x245),X(0x241),X(0x23c),X(0x238),X(0x234),X(0x230),X(0x22b),
        X(0x227),X(0x223),X(0x21e),X(0x21a),X(0x216),X(0x212),X(0x20e),X(0x209),
        X(0x205),X(0x201),X(0x1fd),X(0x1f9),X(0x1f5),X(0x1f0),X(0x1ec),X(0x1e8),
        X(0x1e4),X(0x1e0),X(0x1dc),X(0x1d8),X(0x1d4),X(0x1d0),X(0x1cc),X(0x1c8),
        X(0x1c4),X(0x1c0),X(0x1bc),X(0x1b8),X(0x1b4),X(0x1b0),X(0x1ac),X(0x1a8),
        X(0x1a4),X(0x1a0),X(0x19c),X(0x199),X(0x195),X(0x191),X(0x18d),X(0x189),
        X(0x185),X(0x181),X(0x17e),X(0x17a),X(0x176),X(0x172),X(0x16f),X(0x16b),
        X(0x167),X(0x163),X(0x160),X(0x15c),X(0x158),X(0x154),X(0x151),X(0x14d),
        X(0x149),X(0x146),X(0x142),X(0x13e),X(0x13b),X(0x137),X(0x134),X(0x130),
        X(0x12c),X(0x129),X(0x125),X(0x122),X(0x11e),X(0x11b),X(0x117),X(0x114),
        X(0x110),X(0x10c),X(0x109),X(0x106),X(0x102),X(0x0ff),X(0x0fb),X(0x0f8),
        X(0x0f4),X(0x0f1),X(0x0ed),X(0x0ea),X(0x0e7),X(0x0e3),X(0x0e0),X(0x0dc),
        X(0x0d9),X(0x0d6),X(0x0d2),X(0x0cf),X(0x0cc),X(0x0c8),X(0x0c5),X(0x0c2),
        X(0x0be),X(0x0bb),X(0x0b8),X(0x0b5),X(0x0b1),X(0x0ae),X(0x0ab),X(0x0a8),
        X(0x0a4),X(0x0a1),X(0x09e),X(0x09b),X(0x098),X(0x094),X(0x091),X(0x08e),
        X(0x08b),X(0x088),X(0x085),X(0x082),X(0x07e),X(0x07b),X(0x078),X(0x075),
        X(0x072),X(0x06f),X(0x06c),X(0x069),X(0x066),X(0x063),X(0x060),X(0x05d),
        X(0x05a),X(0x057),X(0x054),X(0x051),X(0x04e),X(0x04b),X(0x048),X(0x045),
        X(0x042),X(0x03f),X(0x03c),X(0x039),X(0x036),X(0x033),X(0x030),X(0x02d),
        X(0x02a),X(0x028),X(0x025),X(0x022),X(0x01f),X(0x01c),X(0x019),X(0x016),
        X(0x014),X(0x011),X(0x00e),X(0x00b),X(0x008),X(0x006),X(0x003),X(0x000)
    };
#undef X

    // look up the fractional part, then shift by the whole
    return s_power_table[input & 0xff] >> (input >> 8);
}

/* ymfm: ymfm_fm.ipp attenuation_increment */
static uint32_t attenuation_increment(uint32_t rate, uint32_t index)
{
    static uint32_t const s_increment_table[64] =
    {
        0x00000000, 0x00000000, 0x10101010, 0x10101010,  // 0-3    (0x00-0x03)
        0x10101010, 0x10101010, 0x11101110, 0x11101110,  // 4-7    (0x04-0x07)
        0x10101010, 0x10111010, 0x11101110, 0x11111110,  // 8-11   (0x08-0x0B)
        0x10101010, 0x10111010, 0x11101110, 0x11111110,  // 12-15  (0x0C-0x0F)
        0x10101010, 0x10111010, 0x11101110, 0x11111110,  // 16-19  (0x10-0x13)
        0x10101010, 0x10111010, 0x11101110, 0x11111110,  // 20-23  (0x14-0x17)
        0x10101010, 0x10111010, 0x11101110, 0x11111110,  // 24-27  (0x18-0x1B)
        0x10101010, 0x10111010, 0x11101110, 0x11111110,  // 28-31  (0x1C-0x1F)
        0x10101010, 0x10111010, 0x11101110, 0x11111110,  // 32-35  (0x20-0x23)
        0x10101010, 0x10111010, 0x11101110, 0x11111110,  // 36-39  (0x24-0x27)
        0x10101010, 0x10111010, 0x11101110, 0x11111110,  // 40-43  (0x28-0x2B)
        0x10101010, 0x10111010, 0x11101110, 0x11111110,  // 44-47  (0x2C-0x2F)
        0x11111111, 0x21112111, 0x21212121, 0x22212221,  // 48-51  (0x30-0x33)
        0x22222222, 0x42224222, 0x42424242, 0x44424442,  // 52-55  (0x34-0x37)
        0x44444444, 0x84448444, 0x84848484, 0x88848884,  // 56-59  (0x38-0x3B)
        0x88888888, 0x88888888, 0x88888888, 0x88888888   // 60-63  (0x3C-0x3F)
    };
    return bitfield(s_increment_table[rate], 4*index, 4);
}

/* ymfm: ymfm_fm.ipp detune_adjustment */
static int32_t detune_adjustment(uint32_t detune, uint32_t keycode)
{
    static uint8_t const s_detune_adjustment[32][4] =
    {
        { 0,  0,  1,  2 },  { 0,  0,  1,  2 },  { 0,  0,  1,  2 },  { 0,  0,  1,  2 },
        { 0,  1,  2,  2 },  { 0,  1,  2,  3 },  { 0,  1,  2,  3 },  { 0,  1,  2,  3 },
        { 0,  1,  2,  4 },  { 0,  1,  3,  4 },  { 0,  1,  3,  4 },  { 0,  1,  3,  5 },
        { 0,  2,  4,  5 },  { 0,  2,  4,  6 },  { 0,  2,  4,  6 },  { 0,  2,  5,  7 },
        { 0,  2,  5,  8 },  { 0,  3,  6,  8 },  { 0,  3,  6,  9 },  { 0,  3,  7, 10 },
        { 0,  4,  8, 11 },  { 0,  4,  8, 12 },  { 0,  4,  9, 13 },  { 0,  5, 10, 14 },
        { 0,  5, 11, 16 },  { 0,  6, 12, 17 },  { 0,  6, 13, 19 },  { 0,  7, 14, 20 },
        { 0,  8, 16, 22 },  { 0,  8, 16, 22 },  { 0,  8, 16, 22 },  { 0,  8, 16, 22 }
    };
    int32_t result = s_detune_adjustment[keycode][detune & 3];
    return bitfield(detune, 2, 1) ? -result : result;
}

/* ymfm: ymfm_fm.ipp opn_lfo_pm_phase_adjustment */
static int32_t opn_lfo_pm_phase_adjustment(uint32_t fnum_bits, uint32_t pm_sensitivity, int32_t lfo_raw_pm)
{
    // this table encodes 2 shift values to apply to the top 7 bits
    // of fnum; it is effectively a cheap multiply by a constant
    // value containing 0-2 bits
    static uint8_t const s_lfo_pm_shifts[8][8] =
    {
        { 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77 },
        { 0x77, 0x77, 0x77, 0x77, 0x72, 0x72, 0x72, 0x72 },
        { 0x77, 0x77, 0x77, 0x72, 0x72, 0x72, 0x17, 0x17 },
        { 0x77, 0x77, 0x72, 0x72, 0x17, 0x17, 0x12, 0x12 },
        { 0x77, 0x77, 0x72, 0x17, 0x17, 0x17, 0x12, 0x07 },
        { 0x77, 0x77, 0x17, 0x12, 0x07, 0x07, 0x02, 0x01 },
        { 0x77, 0x77, 0x17, 0x12, 0x07, 0x07, 0x02, 0x01 },
        { 0x77, 0x77, 0x17, 0x12, 0x07, 0x07, 0x02, 0x01 }
    };

    // look up the relevant shifts
    int32_t abs_pm = (lfo_raw_pm < 0) ? -lfo_raw_pm : lfo_raw_pm;
    uint32_t const shifts = s_lfo_pm_shifts[pm_sensitivity][bitfield((uint32_t)abs_pm, 0, 3)];

    // compute the adjustment
    int32_t adjust = (int32_t)((fnum_bits >> bitfield(shifts, 0, 4)) + (fnum_bits >> bitfield(shifts, 4, 4)));
    if (pm_sensitivity > 5)
        adjust <<= pm_sensitivity - 5;
    adjust >>= 2;

    // every 16 cycles it inverts sign
    return (lfo_raw_pm < 0) ? -adjust : adjust;
}

/* ymfm: ymfm_opn.h opn_registers_base<true>::byte */
static uint32_t reg_byte(gw_ym2612 *e, uint32_t offset, uint32_t start, uint32_t count, uint32_t extra_offset)
{
        return bitfield(e->regdata[offset + extra_offset], start, count);
    }

/* ymfm: ymfm_opn.h opn_registers_base<true>::word */
static uint32_t reg_word(gw_ym2612 *e, uint32_t offset1, uint32_t start1, uint32_t count1, uint32_t offset2, uint32_t start2, uint32_t count2, uint32_t extra_offset)
{
        return (reg_byte(e, offset1, start1, count1, extra_offset) << count2) | reg_byte(e, offset2, start2, count2, extra_offset);
    }

/* ymfm: ymfm_opn.h opn_registers_base<true>::lfo_enable */
static uint32_t reg_lfo_enable(gw_ym2612 *e)
{ return reg_byte(e, 0x22, 3, 1, 0); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::lfo_rate */
static uint32_t reg_lfo_rate(gw_ym2612 *e)
{ return reg_byte(e, 0x22, 0, 3, 0); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::timer_a_value */
static uint32_t reg_timer_a_value(gw_ym2612 *e)
{ return reg_word(e, 0x24, 0, 8, 0x25, 0, 2, 0); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::timer_b_value */
static uint32_t reg_timer_b_value(gw_ym2612 *e)
{ return reg_byte(e, 0x26, 0, 8, 0); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::csm */
static uint32_t reg_csm(gw_ym2612 *e)
{ return (reg_byte(e, 0x27, 6, 2, 0) == 2); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::multi_freq */
static uint32_t reg_multi_freq(gw_ym2612 *e)
{ return (reg_byte(e, 0x27, 6, 2, 0) != 0); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::reset_timer_b */
static uint32_t reg_reset_timer_b(gw_ym2612 *e)
{ return reg_byte(e, 0x27, 5, 1, 0); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::reset_timer_a */
static uint32_t reg_reset_timer_a(gw_ym2612 *e)
{ return reg_byte(e, 0x27, 4, 1, 0); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::enable_timer_b */
static uint32_t reg_enable_timer_b(gw_ym2612 *e)
{ return reg_byte(e, 0x27, 3, 1, 0); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::enable_timer_a */
static uint32_t reg_enable_timer_a(gw_ym2612 *e)
{ return reg_byte(e, 0x27, 2, 1, 0); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::load_timer_b */
static uint32_t reg_load_timer_b(gw_ym2612 *e)
{ return reg_byte(e, 0x27, 1, 1, 0); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::load_timer_a */
static uint32_t reg_load_timer_a(gw_ym2612 *e)
{ return reg_byte(e, 0x27, 0, 1, 0); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::multi_block_freq */
static uint32_t reg_multi_block_freq(gw_ym2612 *e, uint32_t num)
{ return reg_word(e, 0xac, 0, 6, 0xa8, 0, 8, num); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::ch_block_freq */
static uint32_t reg_ch_block_freq(gw_ym2612 *e, uint32_t choffs)
{ return reg_word(e, 0xa4, 0, 6, 0xa0, 0, 8, choffs); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::ch_feedback */
static uint32_t reg_ch_feedback(gw_ym2612 *e, uint32_t choffs)
{ return reg_byte(e, 0xb0, 3, 3, choffs); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::ch_algorithm */
static uint32_t reg_ch_algorithm(gw_ym2612 *e, uint32_t choffs)
{ return reg_byte(e, 0xb0, 0, 3, choffs); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::ch_output_any */
static uint32_t reg_ch_output_any(gw_ym2612 *e, uint32_t choffs)
{ return reg_byte(e, 0xb4, 6, 2, choffs); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::ch_output_0 */
static uint32_t reg_ch_output_0(gw_ym2612 *e, uint32_t choffs)
{ return reg_byte(e, 0xb4, 7, 1, choffs); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::ch_output_1 */
static uint32_t reg_ch_output_1(gw_ym2612 *e, uint32_t choffs)
{ return reg_byte(e, 0xb4, 6, 1, choffs); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::ch_lfo_am_sens */
static uint32_t reg_ch_lfo_am_sens(gw_ym2612 *e, uint32_t choffs)
{ return reg_byte(e, 0xb4, 4, 2, choffs); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::ch_lfo_pm_sens */
static uint32_t reg_ch_lfo_pm_sens(gw_ym2612 *e, uint32_t choffs)
{ return reg_byte(e, 0xb4, 0, 3, choffs); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::op_detune */
static uint32_t reg_op_detune(gw_ym2612 *e, uint32_t opoffs)
{ return reg_byte(e, 0x30, 4, 3, opoffs); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::op_multiple */
static uint32_t reg_op_multiple(gw_ym2612 *e, uint32_t opoffs)
{ return reg_byte(e, 0x30, 0, 4, opoffs); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::op_total_level */
static uint32_t reg_op_total_level(gw_ym2612 *e, uint32_t opoffs)
{ return reg_byte(e, 0x40, 0, 7, opoffs); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::op_ksr */
static uint32_t reg_op_ksr(gw_ym2612 *e, uint32_t opoffs)
{ return reg_byte(e, 0x50, 6, 2, opoffs); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::op_attack_rate */
static uint32_t reg_op_attack_rate(gw_ym2612 *e, uint32_t opoffs)
{ return reg_byte(e, 0x50, 0, 5, opoffs); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::op_decay_rate */
static uint32_t reg_op_decay_rate(gw_ym2612 *e, uint32_t opoffs)
{ return reg_byte(e, 0x60, 0, 5, opoffs); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::op_lfo_am_enable */
static uint32_t reg_op_lfo_am_enable(gw_ym2612 *e, uint32_t opoffs)
{ return reg_byte(e, 0x60, 7, 1, opoffs); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::op_sustain_rate */
static uint32_t reg_op_sustain_rate(gw_ym2612 *e, uint32_t opoffs)
{ return reg_byte(e, 0x70, 0, 5, opoffs); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::op_sustain_level */
static uint32_t reg_op_sustain_level(gw_ym2612 *e, uint32_t opoffs)
{ return reg_byte(e, 0x80, 4, 4, opoffs); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::op_release_rate */
static uint32_t reg_op_release_rate(gw_ym2612 *e, uint32_t opoffs)
{ return reg_byte(e, 0x80, 0, 4, opoffs); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::op_ssg_eg_enable */
static uint32_t reg_op_ssg_eg_enable(gw_ym2612 *e, uint32_t opoffs)
{ return reg_byte(e, 0x90, 3, 1, opoffs); }

/* ymfm: ymfm_opn.h opn_registers_base<true>::op_ssg_eg_mode */
static uint32_t reg_op_ssg_eg_mode(gw_ym2612 *e, uint32_t opoffs)
{ return reg_byte(e, 0x90, 0, 3, opoffs); }

static uint32_t reg_compute_phase_step(gw_ym2612 *e, uint32_t choffs, uint32_t opoffs, const gw_ym_cache *cache, int32_t lfo_raw_pm);
/* ymfm: ymfm_opn.cpp opn_registers_base<true>::reset */
static void reg_reset(gw_ym2612 *e)
{
    memset(e->regdata, 0, sizeof(e->regdata));
    {
        // enable output on both channels by default
        e->regdata[0xb4] = e->regdata[0xb5] = e->regdata[0xb6] = 0xc0;
        e->regdata[0x1b4] = e->regdata[0x1b5] = e->regdata[0x1b6] = 0xc0;
    }
}

/* ymfm: ymfm_opn.cpp opn_registers_base<true>::write */
static bool reg_write(gw_ym2612 *e, uint16_t index, uint8_t data, uint32_t *channel, uint32_t *opmask)
{
    assert(index < 512);

    // writes in the 0xa0-af/0x1a0-af region are handled as latched pairs
    // borrow unused registers 0xb8-bf as temporary holding locations
    if ((index & 0xf0) == 0xa0)
    {
        if (bitfield(index, 0, 2) == 3)
            return false;

        uint32_t latchindex = 0xb8 | bitfield(index, 3, 1);

        // writes to the upper half just latch (only low 6 bits matter)
        if (bitfield(index, 2, 1))
            e->regdata[latchindex] = data & 0x3f;

        // writes to the lower half also apply said latch
        else
        {
            e->regdata[index] = data;
            e->regdata[index | 4] = e->regdata[latchindex];
        }
        return false;
    }
    else if ((index & 0xf8) == 0xb8)
    {
        // registers 0xb8-0xbf are used internally
        return false;
    }

    // everything else is normal
    e->regdata[index] = data;

    // handle writes to the key on index
    if (index == 0x28)
    {
        *channel = bitfield(data, 0, 2);
        if (*channel == 3)
            return false;
        *channel += bitfield(data, 2, 1) * 3;
        *opmask = bitfield(data, 4, 4);
        return true;
    }
    return false;
}

/* ymfm: ymfm_opn.cpp opn_registers_base<true>::clock_noise_and_lfo */
static int32_t reg_clock_noise_and_lfo(gw_ym2612 *e)
{
    // OPN has no noise generation

    // if LFO not enabled (not present on OPN), quick exit with 0s
    if (!reg_lfo_enable(e))
    {
        e->lfo_counter = 0;

        // special case: if LFO is disabled on OPNA, it basically just keeps the counter
        // at 0; since position 0 gives an AM value of 0x3f, it is important to reflect
        // that here; for example, MegaDrive Venom plays some notes with LFO globally
        // disabled but enabling LFO on the operators, and it expects this added attenutation
        e->lfo_am = 0x3f;
        return 0;
    }

    // this table is based on converting the frequencies in the applications
    // manual to clock dividers, based on the assumption of a 7-bit LFO value
    static uint8_t const lfo_max_count[8] = { 109, 78, 72, 68, 63, 45, 9, 6 };
    uint32_t subcount = (uint8_t)(e->lfo_counter++);

    // when we cross the divider count, add enough to zero it and cause an
    // increment at bit 8; the 7-bit value lives from bits 8-14
    if (subcount >= lfo_max_count[reg_lfo_rate(e)])
    {
        // note: to match the published values this should be 0x100 - subcount;
        // however, tests on the hardware and nuked bear out an off-by-one
        // error exists that causes the max LFO rate to be faster than published
        e->lfo_counter += 0x101 - subcount;
    }

    // AM value is 7 bits, staring at bit 8; grab the low 6 directly
    e->lfo_am = (uint8_t)bitfield(e->lfo_counter, 8, 6);

    // first half of the AM period (bit 6 == 0) is inverted
    if (bitfield(e->lfo_counter, 8+6, 1) == 0)
        e->lfo_am ^= 0x3f;

    // PM value is 5 bits, starting at bit 10; grab the low 3 directly
    int32_t pm = (int32_t)bitfield(e->lfo_counter, 10, 3);

    // PM is reflected based on bit 3
    if (bitfield(e->lfo_counter, 10+3, 1))
        pm ^= 7;

    // PM is negated based on bit 4
    return bitfield(e->lfo_counter, 10+4, 1) ? -pm : pm;
}

/* ymfm: ymfm_opn.cpp opn_registers_base<true>::lfo_am_offset */
static uint32_t reg_lfo_am_offset(gw_ym2612 *e, uint32_t choffs)
{
    // shift value for AM sensitivity is [7, 3, 1, 0],
    // mapping to values of [0, 1.4, 5.9, and 11.8dB]
    uint32_t am_shift = (1u << (reg_ch_lfo_am_sens(e, choffs) ^ 3)) - 1;

    // QUESTION: max sensitivity should give 11.8dB range, but this value
    // is directly added to an x.8 attenuation value, which will only give
    // 126/256 or ~4.9dB range -- what am I missing? The calculation below
    // matches common YM2612 attenuation arithmetic.

    // raw LFO AM value on OPN is 0-3F, scale that up by a factor of 2
    // (giving 7 bits) before applying the final shift
    return ((uint32_t)e->lfo_am << 1) >> am_shift;
}

/* ymfm: ymfm_opn.cpp opn_registers_base<true>::cache_operator_data */
static void reg_cache_operator_data(gw_ym2612 *e, uint32_t choffs, uint32_t opoffs, gw_ym_cache *cache)
{
    // set up the easy stuff

    // get frequency from the channel
    uint32_t block_freq = cache->block_freq = reg_ch_block_freq(e, choffs);

    // if multi-frequency mode is enabled and this is channel 2,
    // fetch one of the special frequencies
    if (reg_multi_freq(e) && choffs == 2)
    {
        if (opoffs == 2)
            block_freq = cache->block_freq = reg_multi_block_freq(e, 1);
        else if (opoffs == 10)
            block_freq = cache->block_freq = reg_multi_block_freq(e, 2);
        else if (opoffs == 6)
            block_freq = cache->block_freq = reg_multi_block_freq(e, 0);
    }

    // compute the keycode: block_freq is:
    //
    //     BBBFFFFFFFFFFF
    //     ^^^^???
    //
    // the 5-bit keycode uses the top 4 bits plus a magic formula
    // for the final bit
    uint32_t keycode = bitfield(block_freq, 10, 4) << 1;

    // lowest bit is determined by a mix of next lower FNUM bits
    // according to this equation from the YM2608 manual:
    //
    //   (F11 & (F10 | F9 | F8)) | (!F11 & F10 & F9 & F8)
    //
    // for speed, we just look it up in a 16-bit constant
    keycode |= bitfield(0xfe80, bitfield(block_freq, 7, 4), 1);

    // detune adjustment
    cache->detune = detune_adjustment(reg_op_detune(e, opoffs), keycode);

    // multiple value, as an x.1 value (0 means 0.5)
    cache->multiple = reg_op_multiple(e, opoffs) * 2;
    if (cache->multiple == 0)
        cache->multiple = 1;

    // phase step, or 1 if PM is active; this depends on
    // block_freq, detune, and multiple, so compute it after we've done those
    if (reg_lfo_enable(e) == 0 || reg_ch_lfo_pm_sens(e, choffs) == 0)
        cache->phase_step = reg_compute_phase_step(e, choffs, opoffs, cache, 0);
    else
        cache->phase_step = 1;

    // total level, scaled by 8
    cache->total_level = reg_op_total_level(e, opoffs) << 3;

    // 4-bit sustain level, but 15 means 31 so effectively 5 bits
    cache->eg_sustain = reg_op_sustain_level(e, opoffs);
    cache->eg_sustain |= (cache->eg_sustain + 1) & 0x10;
    cache->eg_sustain <<= 5;

    // determine KSR adjustment for enevlope rates
    uint32_t ksrval = keycode >> (reg_op_ksr(e, opoffs) ^ 3);
    cache->eg_rate[EG_ATTACK] = (uint8_t)effective_rate(reg_op_attack_rate(e, opoffs) * 2, ksrval);
    cache->eg_rate[EG_DECAY] = (uint8_t)effective_rate(reg_op_decay_rate(e, opoffs) * 2, ksrval);
    cache->eg_rate[EG_SUSTAIN] = (uint8_t)effective_rate(reg_op_sustain_rate(e, opoffs) * 2, ksrval);
    cache->eg_rate[EG_RELEASE] = (uint8_t)effective_rate(reg_op_release_rate(e, opoffs) * 4 + 2, ksrval);
}

/* ymfm: ymfm_opn.cpp opn_registers_base<true>::compute_phase_step */
static uint32_t reg_compute_phase_step(gw_ym2612 *e, uint32_t choffs, uint32_t opoffs, const gw_ym_cache *cache, int32_t lfo_raw_pm)
{
    (void)opoffs;
    // OPN phase calculation has only a single detune parameter
    // and uses FNUMs instead of keycodes

    // extract frequency number (low 11 bits of block_freq)
    uint32_t fnum = bitfield(cache->block_freq, 0, 11) << 1;

    // if there's a non-zero PM sensitivity, compute the adjustment
    uint32_t pm_sensitivity = reg_ch_lfo_pm_sens(e, choffs);
    if (pm_sensitivity != 0)
    {
        // apply the phase adjustment based on the upper 7 bits
        // of FNUM and the PM depth parameters
        fnum += (uint32_t)opn_lfo_pm_phase_adjustment(bitfield(cache->block_freq, 4, 7), pm_sensitivity, lfo_raw_pm);

        // keep fnum to 12 bits
        fnum &= 0xfff;
    }

    // apply block shift to compute phase step
    uint32_t block = bitfield(cache->block_freq, 11, 3);
    uint32_t phase_step = (fnum << block) >> 2;

    // apply detune based on the keycode
    phase_step += (uint32_t)cache->detune;

    // clamp to 17 bits in case detune overflows
    // QUESTION: is this specific to the YM2612/3438?
    phase_step &= 0x1ffff;

    // apply frequency multiplier (which is cached as an x.1 value)
    return (phase_step * cache->multiple) >> 1;
}

static void op_reset(gw_ym2612 *e, gw_ym_operator *o);
static bool op_prepare(gw_ym2612 *e, gw_ym_operator *o);
static void op_clock(gw_ym2612 *e, gw_ym_operator *o, uint32_t env_counter, int32_t lfo_raw_pm);
static int32_t op_compute_volume(gw_ym2612 *e, gw_ym_operator *o, uint32_t phase, uint32_t am_offset);
static void op_keyonoff(gw_ym2612 *e, gw_ym_operator *o, uint32_t on, uint32_t type);
static void op_start_attack(gw_ym2612 *e, gw_ym_operator *o, bool is_restart);
static void op_start_release(gw_ym2612 *e, gw_ym_operator *o);
static void op_clock_keystate(gw_ym2612 *e, gw_ym_operator *o, uint32_t keystate);
static void op_clock_ssg_eg_state(gw_ym2612 *e, gw_ym_operator *o);
static void op_clock_envelope(gw_ym2612 *e, gw_ym_operator *o, uint32_t env_counter);
static void op_clock_phase(gw_ym2612 *e, gw_ym_operator *o, int32_t lfo_raw_pm);
static uint32_t op_envelope_attenuation(gw_ym2612 *e, gw_ym_operator *o, uint32_t am_offset);
/* ymfm: ymfm_fm.ipp fm_operator::reset */
static void op_reset(gw_ym2612 *e, gw_ym_operator *o)
{
    (void)e;
    // reset our data
    o->phase = 0;
    o->env_attenuation = 0x3ff;
    o->env_state = EG_RELEASE;
    o->ssg_inverted = 0;
    o->key_state = 0;
    o->keyon_live = 0;
}

/* ymfm: ymfm_fm.ipp fm_operator::prepare */
static bool op_prepare(gw_ym2612 *e, gw_ym_operator *o)
{
    // cache the data
    reg_cache_operator_data(e, o->choffs, o->opoffs, &o->cache);

    // clock the key state
    op_clock_keystate(e, o, (uint32_t)(o->keyon_live != 0));
    o->keyon_live &= ~(1 << KEYON_CSM);

    // we're active until we're quiet after the release
    return (o->env_state != EG_RELEASE || o->env_attenuation < 0x380);
}

/* ymfm: ymfm_fm.ipp fm_operator::clock */
static void op_clock(gw_ym2612 *e, gw_ym_operator *o, uint32_t env_counter, int32_t lfo_raw_pm)
{
    // clock the SSG-EG state (OPN/OPNA)
    if (reg_op_ssg_eg_enable(e, o->opoffs))
        op_clock_ssg_eg_state(e, o);
    else
        o->ssg_inverted = false;

    // clock the envelope if on an envelope cycle; env_counter is a x.2 value
    if (bitfield(env_counter, 0, 2) == 0)
        op_clock_envelope(e, o, env_counter >> 2);

    // clock the phase
    op_clock_phase(e, o, lfo_raw_pm);
}

/* ymfm: ymfm_fm.ipp fm_operator::compute_volume */
static int32_t op_compute_volume(gw_ym2612 *e, gw_ym_operator *o, uint32_t phase, uint32_t am_offset)
{
    // the low 10 bits of phase represents a full 2*PI period over
    // the full sin wave

    // early out if the envelope is effectively off
    if (o->env_attenuation > 0x380)
        return 0;

    // get the absolute value of the sin, as attenuation, as a 4.8 fixed point value
    uint32_t sin_attenuation = e->waveform[phase & (1024 - 1)];

    // get the attenuation from the evelope generator as a 4.6 value, shifted up to 4.8
    uint32_t env_attenuation = op_envelope_attenuation(e, o, am_offset) << 2;

    // combine into a 5.8 value, then convert from attenuation to 13-bit linear volume
    int32_t result = (int32_t)attenuation_to_volume((sin_attenuation & 0x7fff) + env_attenuation);

    // negate if in the negative part of the sin wave (sign bit gives 14 bits)
    return bitfield(sin_attenuation, 15, 1) ? -result : result;
}

/* ymfm: ymfm_fm.ipp fm_operator::keyonoff */
static void op_keyonoff(gw_ym2612 *e, gw_ym_operator *o, uint32_t on, uint32_t type)
{
    (void)e;
    o->keyon_live = (uint8_t)((o->keyon_live & ~(1u << type)) | (bitfield(on, 0, 1) << type));
}

/* ymfm: ymfm_fm.ipp fm_operator::start_attack */
static void op_start_attack(gw_ym2612 *e, gw_ym_operator *o, bool is_restart)
{
    // don't change anything if already in attack state
    if (o->env_state == EG_ATTACK)
        return;
    o->env_state = EG_ATTACK;

    // generally not inverted at start, except if SSG-EG is enabled and
    // one of the inverted modes is specified; leave this alone on a
    // restart, as it is managed by the op_clock_ssg_eg_state(e, o) code
    if (!is_restart)
        o->ssg_inverted = (uint8_t)(reg_op_ssg_eg_enable(e, o->opoffs) & bitfield(reg_op_ssg_eg_mode(e, o->opoffs), 2, 1));

    // reset the phase when we start an attack due to a key on
    // (but not when due to an SSG-EG restart except in certain cases
    // managed directly by the SSG-EG code)
    if (!is_restart)
        o->phase = 0;

    // if the attack rate >= 62 then immediately go to max attenuation
    if (o->cache.eg_rate[EG_ATTACK] >= 62)
        o->env_attenuation = 0;
}

/* ymfm: ymfm_fm.ipp fm_operator::start_release */
static void op_start_release(gw_ym2612 *e, gw_ym_operator *o)
{
    (void)e;
    // don't change anything if already in release state
    if (o->env_state >= EG_RELEASE)
        return;
    o->env_state = EG_RELEASE;

    // if attenuation if inverted due to SSG-EG, snap the inverted attenuation
    // as the starting point
    if (o->ssg_inverted)
    {
        o->env_attenuation = (0x200 - o->env_attenuation) & 0x3ff;
        o->ssg_inverted = false;
    }
}

/* ymfm: ymfm_fm.ipp fm_operator::clock_keystate */
static void op_clock_keystate(gw_ym2612 *e, gw_ym_operator *o, uint32_t keystate)
{
    assert(keystate == 0 || keystate == 1);

    // has the key changed?
    if ((keystate ^ o->key_state) != 0)
    {
        o->key_state = (uint8_t)keystate;

        // if the key has turned on, start the attack
        if (keystate != 0)
        {
            op_start_attack(e, o, false);
        }

        // otherwise, start the release
        else
            op_start_release(e, o);
    }
}

/* ymfm: ymfm_fm.ipp fm_operator::clock_ssg_eg_state */
static void op_clock_ssg_eg_state(gw_ym2612 *e, gw_ym_operator *o)
{
    // work only happens once the attenuation crosses above 0x200
    if (!bitfield(o->env_attenuation, 9, 1))
        return;

    // 8 SSG-EG modes:
    //    000: repeat normally
    //    001: run once, hold low
    //    010: repeat, alternating between inverted/non-inverted
    //    011: run once, hold high
    //    100: inverted repeat normally
    //    101: inverted run once, hold low
    //    110: inverted repeat, alternating between inverted/non-inverted
    //    111: inverted run once, hold high
    uint32_t mode = reg_op_ssg_eg_mode(e, o->opoffs);

    // hold modes (1/3/5/7)
    if (bitfield(mode, 0, 1))
    {
        // set the inverted flag to the end state (0 for modes 1/7, 1 for modes 3/5)
        o->ssg_inverted = (uint8_t)(bitfield(mode, 2, 1) ^ bitfield(mode, 1, 1));

        // if holding, force the attenuation to the expected value once we're
        // past the attack phase
        if (o->env_state != EG_ATTACK)
            o->env_attenuation = o->ssg_inverted ? 0x200 : 0x3ff;
    }

    // continuous modes (0/2/4/6)
    else
    {
        // toggle invert in alternating mode (even in attack state)
        o->ssg_inverted ^= bitfield(mode, 1, 1);

        // restart attack if in decay/sustain states
        if (o->env_state == EG_DECAY || o->env_state == EG_SUSTAIN)
            op_start_attack(e, o, true);

        // phase is reset to 0 in modes 0/4
        if (bitfield(mode, 1, 1) == 0)
            o->phase = 0;
    }

    // in all modes, once we hit release state, attenuation is forced to maximum
    if (o->env_state == EG_RELEASE)
        o->env_attenuation = 0x3ff;
}

/* ymfm: ymfm_fm.ipp fm_operator::clock_envelope */
static void op_clock_envelope(gw_ym2612 *e, gw_ym_operator *o, uint32_t env_counter)
{
    // handle attack->decay transitions
    if (o->env_state == EG_ATTACK && o->env_attenuation == 0)
        o->env_state = EG_DECAY;

    // handle decay->sustain transitions; it is important to do this immediately
    // after the attack->decay transition above in the event that the sustain level
    // is set to 0 (in which case we will skip right to sustain without doing any
    // decay); as an example where this can be heard, check the cymbals sound
    // in channel 0 of shinobi's test mode sound #5
    if (o->env_state == EG_DECAY && o->env_attenuation >= o->cache.eg_sustain)
        o->env_state = EG_SUSTAIN;

    // fetch the appropriate 6-bit rate value from the cache
    uint32_t rate = o->cache.eg_rate[o->env_state];

    // compute the rate shift value; this is the shift needed to
    // apply to the env_counter such that it becomes a 5.11 fixed
    // point number
    uint32_t rate_shift = rate >> 2;
    env_counter <<= rate_shift;

    // see if the fractional part is 0; if not, it's not time to clock
    if (bitfield(env_counter, 0, 11) != 0)
        return;

    // determine the increment based on the non-fractional part of env_counter
    uint32_t relevant_bits = bitfield(env_counter, (rate_shift <= 11) ? 11 : rate_shift, 3);
    uint32_t increment = attenuation_increment(rate, relevant_bits);

    // attack is the only one that increases
    if (o->env_state == EG_ATTACK)
    {
        // glitch means that attack rates of 62/63 don't increment if
        // changed after the initial key on (where they are handled
        // specially); nukeykt confirms this happens on OPM, OPN, OPL/OPLL
        // at least so assuming it is true for everyone
        if (rate < 62)
            o->env_attenuation += ((uint32_t)~o->env_attenuation * increment) >> 4;
    }

    // all other cases are similar
    else
    {
        // non-SSG-EG cases just apply the increment
        if (!reg_op_ssg_eg_enable(e, o->opoffs))
            o->env_attenuation += increment;

        // SSG-EG only applies if less than mid-point, and then at 4x
        else if (o->env_attenuation < 0x200)
            o->env_attenuation += 4 * increment;

        // clamp the final attenuation
        if (o->env_attenuation >= 0x400)
            o->env_attenuation = 0x3ff;

    }
}

/* ymfm: ymfm_fm.ipp fm_operator::clock_phase */
static void op_clock_phase(gw_ym2612 *e, gw_ym_operator *o, int32_t lfo_raw_pm)
{
    // read from the cache, or recalculate if PM active
    uint32_t phase_step = o->cache.phase_step;
    if (phase_step == 1)
        phase_step = reg_compute_phase_step(e, o->choffs, o->opoffs, &o->cache, lfo_raw_pm);

    // finally apply the step to the current phase value
    o->phase += phase_step;
}

/* ymfm: ymfm_fm.ipp fm_operator::envelope_attenuation */
static uint32_t op_envelope_attenuation(gw_ym2612 *e, gw_ym_operator *o, uint32_t am_offset)
{
    uint32_t result = o->env_attenuation >> o->cache.eg_shift;

    // invert if necessary due to SSG-EG
    if (o->ssg_inverted)
        result = (0x200 - result) & 0x3ff;

    // add in LFO AM modulation
    if (reg_op_lfo_am_enable(e, o->opoffs))
        result += am_offset;

    // add in total level and KSL from the cache
    result += o->cache.total_level;

    // clamp to max, apply shift, and return
    return min_u32(result, 0x3ff);
}

/* ymfm: ymfm_fm.ipp fm_channel::add_to_output */
static void ch_add_to_output(gw_ym2612 *e, uint32_t choffs, int32_t output[2], int32_t value)
{
    if (reg_ch_output_0(e, choffs)) output[0] += value;
    if (reg_ch_output_1(e, choffs)) output[1] += value;
}
/* ymfm: ymfm_fm.ipp fm_channel::reset */
static void ch_reset(gw_ym2612 *e, gw_ym_channel *c)
{
    (void)e;
    // reset our data
    c->feedback[0] = c->feedback[1] = 0;
    c->feedback_in = 0;
}

/* ymfm: ymfm_fm.ipp fm_channel::keyonoff */
static void ch_keyonoff(gw_ym2612 *e, gw_ym_channel *c, uint32_t states, uint32_t type, uint32_t chnum)
{
    (void)chnum;
    for (uint32_t opnum = 0; opnum < 4; opnum++)
        op_keyonoff(e, &e->operator[c->op[opnum]], bitfield(states, opnum, 1), type);
}

/* ymfm: ymfm_fm.ipp fm_channel::prepare */
static bool ch_prepare(gw_ym2612 *e, gw_ym_channel *c)
{
    uint32_t active_mask = 0;

    // prepare all operators and determine if they are active
    for (uint32_t opnum = 0; opnum < 4; opnum++)
        if (op_prepare(e, &e->operator[c->op[opnum]]))
            active_mask |= 1u << opnum;

    return (active_mask != 0);
}

/* ymfm: ymfm_fm.ipp fm_channel::clock */
static void ch_clock(gw_ym2612 *e, gw_ym_channel *c, uint32_t env_counter, int32_t lfo_raw_pm)
{
    // clock the feedback through
    c->feedback[0] = c->feedback[1];
    c->feedback[1] = c->feedback_in;

    for (uint32_t opnum = 0; opnum < 4; opnum++)
        op_clock(e, &e->operator[c->op[opnum]], env_counter, lfo_raw_pm);

}

/* ymfm: ymfm_fm.ipp fm_channel::output_4op */
static void ch_output_4op(gw_ym2612 *e, gw_ym_channel *c, int32_t output[2], uint32_t rshift, int32_t clipmax)
{
    // all 4 operators should be populated

    // AM amount is the same across all operators; compute it once
    uint32_t am_offset = reg_lfo_am_offset(e, c->choffs);

    // operator 1 has optional self-feedback
    int32_t opmod = 0;
    uint32_t feedback = reg_ch_feedback(e, c->choffs);
    if (feedback != 0)
        opmod = asr(c->feedback[0] + c->feedback[1], 10 - feedback);

    // compute the 14-bit volume/value of operator 1 and update the feedback
    int32_t op1value = c->feedback_in = (int16_t)op_compute_volume(e, &e->operator[c->op[0]], (e->operator[c->op[0]].phase >> 10) + (uint32_t)opmod, am_offset);

    // now that the feedback has been computed, skip the rest if all volumes
    // are clear; no need to do all this work for nothing
    if (reg_ch_output_any(e, c->choffs) == 0)
        return;

    // OPN2 offers 8 connection algorithms for 4 operators.
    //
    // The operators are computed in order, with the inputs pulled from
    // an array of values (opout) that is populated as we go:
    //    0 = 0
    //    1 = O1
    //    2 = O2
    //    3 = O3
    //    4 = (O4)
    //    5 = O1+O2
    //    6 = O1+O3
    //    7 = O2+O3
    //
    // The s_algorithm_ops table describes the inputs and outputs of each
    // algorithm as follows:
    //
    //      ---------x use opout[x] as operator 2 input
    //      ------xxx- use opout[x] as operator 3 input
    //      ---xxx---- use opout[x] as operator 4 input
    //      --x------- include opout[1] in final sum
    //      -x-------- include opout[2] in final sum
    //      x--------- include opout[3] in final sum
    #define ALGORITHM(op2in, op3in, op4in, op1out, op2out, op3out) \
        ((op2in) | ((op3in) << 1) | ((op4in) << 4) | ((op1out) << 7) | ((op2out) << 8) | ((op3out) << 9))
    static uint16_t const s_algorithm_ops[8] =
    {
        ALGORITHM(1,2,3, 0,0,0),    //  0: O1 -> O2 -> O3 -> O4 -> out (O4)
        ALGORITHM(0,5,3, 0,0,0),    //  1: (O1 + O2) -> O3 -> O4 -> out (O4)
        ALGORITHM(0,2,6, 0,0,0),    //  2: (O1 + (O2 -> O3)) -> O4 -> out (O4)
        ALGORITHM(1,0,7, 0,0,0),    //  3: ((O1 -> O2) + O3) -> O4 -> out (O4)
        ALGORITHM(1,0,3, 0,1,0),    //  4: ((O1 -> O2) + (O3 -> O4)) -> out (O2+O4)
        ALGORITHM(1,1,1, 0,1,1),    //  5: ((O1 -> O2) + (O1 -> O3) + (O1 -> O4)) -> out (O2+O3+O4)
        ALGORITHM(1,0,0, 0,1,1),    //  6: ((O1 -> O2) + O3 + O4) -> out (O2+O3+O4)
        ALGORITHM(0,0,0, 1,1,1)    //  7: (O1 + O2 + O3 + O4) -> out (O1+O2+O3+O4)
    };
    uint32_t algorithm_ops = s_algorithm_ops[reg_ch_algorithm(e, c->choffs)];

    // populate the opout table
    int16_t opout[8];
    opout[0] = 0;
    opout[1] = (int16_t)op1value;

    // compute the 14-bit volume/value of operator 2
    opmod = asr(opout[bitfield(algorithm_ops, 0, 1)], 1);
    opout[2] = (int16_t)op_compute_volume(e, &e->operator[c->op[1]], (e->operator[c->op[1]].phase >> 10) + (uint32_t)opmod, am_offset);
    opout[5] = opout[1] + opout[2];

    // compute the 14-bit volume/value of operator 3
    opmod = asr(opout[bitfield(algorithm_ops, 1, 3)], 1);
    opout[3] = (int16_t)op_compute_volume(e, &e->operator[c->op[2]], (e->operator[c->op[2]].phase >> 10) + (uint32_t)opmod, am_offset);
    opout[6] = opout[1] + opout[3];
    opout[7] = opout[2] + opout[3];

    // compute the 14-bit volume/value of operator 4; this could be a noise
    // value on the OPM; all algorithms consume OP4 output at a minimum
    int32_t result;
    {
        opmod = asr(opout[bitfield(algorithm_ops, 4, 3)], 1);
        result = op_compute_volume(e, &e->operator[c->op[3]], (e->operator[c->op[3]].phase >> 10) + (uint32_t)opmod, am_offset);
    }
    result = asr(result, rshift);

    // optionally add OP1, OP2, OP3
    int32_t clipmin = -clipmax - 1;
    if (bitfield(algorithm_ops, 7, 1) != 0)
        result = clamp(result + (asr(opout[1], rshift)), clipmin, clipmax);
    if (bitfield(algorithm_ops, 8, 1) != 0)
        result = clamp(result + (asr(opout[2], rshift)), clipmin, clipmax);
    if (bitfield(algorithm_ops, 9, 1) != 0)
        result = clamp(result + (asr(opout[3], rshift)), clipmin, clipmax);

    // add to the output
    ch_add_to_output(e, c->choffs, output, result);
}

/* ymfm_fm.ipp fm_engine_base specialized for opna_registers. Interface timers
 * are expressed in master ticks (YM clock = master/7). No host clock or IRQ
 * callback: the Genesis does not route the YM IRQ to either CPU. */
/* ymfm: ymfm_fm.ipp fm_engine_base::check_interrupts */
static void engine_check_interrupts(gw_ym2612 *e)
{
    e->irq_state = (e->status & e->irq_mask) != 0;
}

/* ymfm: ymfm_fm.ipp fm_engine_base::set_reset_status */
static uint8_t engine_set_reset_status(gw_ym2612 *e, uint8_t set, uint8_t reset)
{
    e->status = (uint8_t)((e->status | set) & ~(reset | 0x80));
    engine_check_interrupts(e);
    return e->status;
}

/* ymfm: ymfm_fm.ipp fm_engine_base::update_timer */
static void engine_update_timer(gw_ym2612 *e, unsigned tnum,
    uint32_t enable, int32_t delta_clocks)
{
    if (enable && !e->timer_running[tnum]) {
        uint32_t period = tnum == 0 ? 1024 - reg_timer_a_value(e) :
            16 * (256 - reg_timer_b_value(e));
        period += (uint32_t)delta_clocks;
        e->timer_tick[tnum] = e->advanced_tick +
            (uint64_t)period * 24u * e->clock_prescale * 7u;
        e->timer_running[tnum] = 1;
    } else if (!enable) {
        e->timer_tick[tnum] = UINT64_MAX;
        e->timer_running[tnum] = 0;
    }
}

/* ymfm: ymfm_fm.ipp fm_engine_base::mode_write */
static void engine_mode_write(gw_ym2612 *e, uint8_t data)
{
    uint32_t dummy1, dummy2;
    uint8_t reset_mask = 0;
    e->modified_channels = 63;
    (void)reg_write(e, 0x27, data, &dummy1, &dummy2);
    if (reg_reset_timer_b(e)) reset_mask |= 2;
    if (reg_reset_timer_a(e)) reset_mask |= 1;
    (void)engine_set_reset_status(e, 0, reset_mask);
    engine_update_timer(e, 1, reg_load_timer_b(e), -(e->total_clocks & 15));
    engine_update_timer(e, 0, reg_load_timer_a(e), 0);
}

/* ymfm: ymfm_fm.ipp fm_engine_base::write */
static void engine_write(gw_ym2612 *e, uint16_t regnum, uint8_t data)
{
    uint32_t keyon_channel, keyon_opmask;
    if (regnum == 0x27) { engine_mode_write(e, data); return; }
    e->modified_channels = 63;
    if (reg_write(e, regnum, data, &keyon_channel, &keyon_opmask) && keyon_channel < 6)
        ch_keyonoff(e, &e->channel[keyon_channel], keyon_opmask,
            KEYON_NORMAL, keyon_channel);
}

/* ymfm: ymfm_fm.ipp fm_engine_base::reset */
static void engine_reset(gw_ym2612 *e)
{
    (void)engine_set_reset_status(e, 0, 0xff);
    reg_reset(e);
    engine_write(e, 0x27, 0);
    for (unsigned i = 0; i < 6; ++i) ch_reset(e, &e->channel[i]);
    for (unsigned i = 0; i < 24; ++i) op_reset(e, &e->operator[i]);
}

/* ymfm: ymfm_fm.ipp fm_engine_base::clock */
static void engine_clock(gw_ym2612 *e)
{
    int32_t lfo_raw_pm;
    ++e->total_clocks;
    if (e->modified_channels != 0 || e->prepare_count++ >= 4096) {
        e->active_channels = 0;
        for (unsigned i = 0; i < 6; ++i)
            if (ch_prepare(e, &e->channel[i])) e->active_channels |= 1u << i;
        e->modified_channels = e->prepare_count = 0;
    }
    if (bitfield(++e->env_counter, 0, 2) == 3) ++e->env_counter;
    lfo_raw_pm = reg_clock_noise_and_lfo(e);
    for (unsigned i = 0; i < 6; ++i)
        ch_clock(e, &e->channel[i], e->env_counter, lfo_raw_pm);
}

/* ymfm: ymfm_fm.ipp fm_engine_base::output */
static void engine_output(gw_ym2612 *e, unsigned channel, int32_t output[2])
{
    output[0] = output[1] = 0;
    if (bitfield(e->active_channels, channel, 1))
        ch_output_4op(e, &e->channel[channel], output, 5, 256);
}

/* ymfm: ymfm_fm.ipp fm_engine_base::timer_expired */
static void engine_timer_expired(gw_ym2612 *e, unsigned tnum)
{
    if (tnum == 0 && reg_enable_timer_a(e)) (void)engine_set_reset_status(e, 1, 0);
    else if (tnum == 1 && reg_enable_timer_b(e)) (void)engine_set_reset_status(e, 2, 0);
    if (tnum == 0 && reg_csm(e)) {
        ch_keyonoff(e, &e->channel[2], 15, KEYON_CSM, 2);
        e->modified_channels |= 4;
    }
    e->timer_running[tnum] = 0;
    engine_update_timer(e, tnum, 1, 0);
}

/* ymfm_opn.h ym2612::dac_discontinuity, always enabled: docs/audio.md
 * "Variant source (D-48)" confirms the discrete YM2612 on VA3 Model 1.
 * Do not smooth this step or replace the exact logarithmic waveform tables. */
/* ymfm: ymfm_opn.h ym2612::dac_discontinuity */
static int32_t dac_discontinuity(int32_t value)
{
    return value < 0 ? value - 3 : value + 4;
}

/* ymfm: ymfm_opn.cpp ym2612::generate */
void gw_ym2612_generate(gw_ym2612 *e, int32_t output[2])
{
    int32_t temp[2];
    unsigned last_fm_channel = e->dac_enable ? 5u : 6u;
    engine_clock(e);
    output[0] = output[1] = 0;
    for (unsigned channel = 0; channel < last_fm_channel; ++channel) {
        engine_output(e, channel, temp);
        output[0] += dac_discontinuity(temp[0]);
        output[1] += dac_discontinuity(temp[1]);
    }
    if (e->dac_enable) {
        /* Explicit sign extension of upstream int16_t(m_dac_data << 7) >> 7. */
        int32_t signed_dac = (e->dac_data & 0x100) ? (int32_t)e->dac_data - 512 : e->dac_data;
        int32_t dacval = dac_discontinuity(signed_dac);
        output[0] += reg_ch_output_0(e, 0x102) ? dacval : dac_discontinuity(0);
        output[1] += reg_ch_output_1(e, 0x102) ? dacval : dac_discontinuity(0);
    }
    output[0] = (output[0] * 128) * 64 / (6 * 65);
    output[1] = (output[1] * 128) * 64 / (6 * 65);
}

void gw_ym2612_cold_init(gw_machine *m)
{
    gw_ym2612 *e = &m->ym;
    /* Construction is distinct from ymfm reset: initialize every retained
     * field once, then use only the pinned reset routine for subsequent resets. */
    memset(e, 0, sizeof(*e));
    e->clock_prescale = 6;
    e->irq_mask = 3;
    e->active_channels = e->modified_channels = 63;
    for (unsigned i = 0; i < 1024; ++i)
        e->waveform[i] = (uint16_t)(abs_sin_attenuation(i) | (bitfield(i, 9, 1) << 15));
    for (unsigned i = 0; i < 6; ++i) {
        gw_ym_channel *c = &e->channel[i];
        unsigned base = i % 3 + 12 * (i / 3);
        c->choffs = i % 3 + 0x100 * (i / 3);
        /* opn_registers_base<true>::operator_map: O1,O3,O2,O4 register order. */
        c->op[0] = (uint8_t)base; c->op[1] = (uint8_t)(base + 6);
        c->op[2] = (uint8_t)(base + 3); c->op[3] = (uint8_t)(base + 9);
        for (unsigned j = 0; j < 4; ++j) e->operator[c->op[j]].choffs = c->choffs;
    }
    for (unsigned i = 0; i < 24; ++i)
        e->operator[i].opoffs = i % 12 + (i % 12) / 3 + 0x100 * (i / 12);
    e->next_sample_tick = GW_FM_SAMPLE_TICKS;
    engine_reset(e);
    e->reset_held = 1; /* Power-on Z80 reset is asserted. */
}

static void mix_output(gw_machine *m, uint64_t tick, int32_t left, int32_t right)
{
    gw_ym2612 *e = &m->ym;
    int32_t l = left * GW_MIX_V1_FM_NUM / GW_MIX_V1_FM_DEN;
    int32_t r = right * GW_MIX_V1_FM_NUM / GW_MIX_V1_FM_DEN;
    gw_audio_add_step(m, tick, l - e->last_output[0], r - e->last_output[1]);
    e->last_output[0] = l; e->last_output[1] = r;
}

void gw_ym2612_advance(gw_machine *m, uint64_t tick)
{
    gw_ym2612 *e = &m->ym;
    if (tick < e->advanced_tick) return;
    if (e->reset_held) {
        if (e->next_sample_tick <= tick)
            e->next_sample_tick += ((tick - e->next_sample_tick) / GW_FM_SAMPLE_TICKS + 1) * GW_FM_SAMPLE_TICKS;
        e->advanced_tick = tick;
        return;
    }
    for (;;) {
        uint64_t next = e->next_sample_tick;
        for (unsigned i = 0; i < 2; ++i)
            if (e->timer_running[i] && e->timer_tick[i] < next) next = e->timer_tick[i];
        if (next > tick) break;
        /* Merge PSG and FM events chronologically before finalising PCM. */
        gw_psg_advance(m, next);
        gw_audio_finalise(m, next);
        e->advanced_tick = next;
        for (unsigned i = 0; i < 2; ++i)
            if (e->timer_running[i] && e->timer_tick[i] == next) engine_timer_expired(e, i);
        if (e->next_sample_tick == next) {
            int32_t output[2];
            gw_ym2612_generate(e, output);
#ifdef GW_TEST_HOOKS
            m->ym_test_output[0] = output[0];
            m->ym_test_output[1] = output[1];
            ++m->ym_test_sample_count;
#endif
            mix_output(m, next, output[0], output[1]);
            e->next_sample_tick += GW_FM_SAMPLE_TICKS;
        }
    }
    e->advanced_tick = tick;
}

void gw_ym2612_reset_line(gw_machine *m, uint64_t tick, int asserted)
{
    gw_ym2612 *e = &m->ym;
    gw_audio_sync(m, tick);
    if (asserted && !e->reset_held) {
        /* Approved 03-FM-RESET-AMENDMENT.md, docs/audio.md Reset search record:
         * exact VA3 reset fidelity is classed unknown. Preserve upstream reset
         * retention, then suppress output and writes while reset is held.
         * Master time, native grid, queued PCM and BLEP continuation survive. */
        engine_reset(e);
        mix_output(m, tick, 0, 0);
    }
    e->reset_held = asserted != 0;
}

void gw_ym2612_console_reset(gw_machine *m)
{
    /* Model choice: console reset asserts the same provisional YM reset line. */
    gw_ym2612_reset_line(m, m->tick, 1);
}

void gw_ym2612_write_at(gw_machine *m, uint64_t tick, uint32_t port, uint8_t data, uint32_t source)
{
    gw_ym2612 *e = &m->ym;
    /* D-55: a write stamped at a native sample tick is committed before that
       sample is emitted. Leave the exact tick pending while synchronizing all
       strictly earlier device events; the next sync then samples new state. */
    gw_audio_sync(m, tick ? tick - 1u : 0u);
    if (e->reset_held) return;
    port &= 3;
    if ((port & 1) == 0) {
        e->address = (uint16_t)(data | ((port & 2) << 7));
        return;
    }
    /* One shared address latch in ymfm: mismatched-bank data writes ignored. */
    if ((e->address >> 8) != (port >> 1)) return;
    gw_audio_trace_record_at(m, tick, (port & 2) ? GW_AUDIO_CHIP_YM_PORT1 :
        GW_AUDIO_CHIP_YM_PORT0, e->address, data, source);
    if (e->address == 0x2a)
        e->dac_data = (uint16_t)((e->dac_data & ~0x1fe) | ((data ^ 0x80) << 1));
    else if (e->address == 0x2b) e->dac_enable = (uint8_t)(data >> 7);
    else if (e->address == 0x2c) e->dac_data = (uint16_t)((e->dac_data & ~1) | ((data >> 3) & 1));
    else engine_write(e, e->address, data);
    e->busy_end_tick = tick + 32u * e->clock_prescale * 7u;
}

void gw_ym2612_write(gw_machine *m, uint32_t port, uint8_t data, uint32_t source)
{ gw_ym2612_write_at(m, m->tick, port, data, source); }

uint8_t gw_ym2612_read_status(gw_machine *m, uint64_t tick)
{
    gw_audio_sync(m, tick);
    return (uint8_t)(m->ym.status | (tick < m->ym.busy_end_tick ? 0x80 : 0));
}

#ifdef GW_TEST_HOOKS
void gw_test_ym_write(gw_machine *m, unsigned port, uint8_t value)
{
    gw_ym2612_write(m, port, value, GW_AUDIO_SOURCE_Z80);
}

void gw_test_ym_release_reset(gw_machine *m)
{
    gw_ym2612_reset_line(m, m->tick, 0);
}

int gw_test_ym_sample(gw_machine *m, int32_t *left, int32_t *right)
{
    uint64_t prior = m->ym_test_sample_count;
    gw_ym2612_advance(m, m->tick);
    if (m->ym_test_sample_count == prior) return 0;
    *left = m->ym_test_output[0];
    *right = m->ym_test_output[1];
    return 1;
}

static uint64_t ym_digest_scalar(uint64_t hash, uint64_t value, unsigned bytes)
{
    for (unsigned i = 0; i < bytes; ++i)
        hash = (hash ^ (uint8_t)(value >> (8u * i))) * UINT64_C(1099511628211);
    return hash;
}

uint64_t gw_ym2612_digest(const gw_ym2612 *e, uint64_t hash)
{
    /* Explicit little-endian scalar serialization. Waveform is immutable,
     * reconstructed at cold init; PCM/trace remain excluded by D-57. */
#define D(field, bytes) hash = ym_digest_scalar(hash, (uint64_t)(field), bytes)
    D(e->lfo_counter, 4); D(e->lfo_am, 1);
    for (unsigned i = 0; i < 512; ++i) D(e->regdata[i], 1);
    D(e->env_counter, 4); D(e->status, 1); D(e->clock_prescale, 1);
    D(e->irq_mask, 1); D(e->irq_state, 1); D(e->total_clocks, 1);
    D(e->active_channels, 4); D(e->modified_channels, 4); D(e->prepare_count, 4);
    for (unsigned i = 0; i < 2; ++i) {
        D(e->timer_running[i], 1); D(e->timer_tick[i], 8);
    }
    for (unsigned i = 0; i < 6; ++i) {
        const gw_ym_channel *c = &e->channel[i];
        D(c->choffs, 4); D((uint16_t)c->feedback[0], 2);
        D((uint16_t)c->feedback[1], 2); D((uint16_t)c->feedback_in, 2);
        for (unsigned j = 0; j < 4; ++j) D(c->op[j], 1);
    }
    for (unsigned i = 0; i < 24; ++i) {
        const gw_ym_operator *o = &e->operator[i];
        const gw_ym_cache *cache = &o->cache;
        D(o->choffs, 4); D(o->opoffs, 4); D(o->phase, 4);
        D(o->env_attenuation, 2); D(o->env_state, 4); D(o->ssg_inverted, 1);
        D(o->key_state, 1); D(o->keyon_live, 1);
        D(cache->phase_step, 4); D(cache->total_level, 4); D(cache->block_freq, 4);
        D((uint32_t)cache->detune, 4); D(cache->multiple, 4); D(cache->eg_sustain, 4);
        for (unsigned j = 0; j < 6; ++j) D(cache->eg_rate[j], 1);
        D(cache->eg_shift, 1);
    }
    D(e->address, 2); D(e->dac_data, 2); D(e->dac_enable, 1); D(e->reset_held, 1);
    D(e->next_sample_tick, 8); D(e->busy_end_tick, 8); D(e->advanced_tick, 8);
    /* last_output belongs to the PCM step renderer, not the chip. */
#undef D
    return hash;
}
#endif

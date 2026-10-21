/* SPDX-License-Identifier: MIT
 * Original directive-only ROM. FM channel 0, algorithm 7, one carrier,
 * MUL=1, F-number=0x284, block=4. Primary frequency relation as documented
 * at plutiedev.com/ym2612-registers: FNUM * 2^block * YMclk / (144 * 2^21).
 */
.org 0x0000
.long 0x00ffff00
.long 0x00000200
.org 0x200
/* Request bus; poll the implemented grant status (0 means granted). */
.word 0x33fc
.word 0x0100
.long 0x00a11100
.word 0x3039
.long 0x00a11100
.word 0x4a40
.word 0x66f6
/* Release Z80 reset, retaining the bus while the FM patch is written. */
.word 0x33fc
.word 0x0100
.long 0x00a11200
.word 0x4e71
.word 0x4e71
/* Frequency multiplier 1 on all four slots. */
.word 0x13fc
.word 0x0030
.long 0x00a04000
.word 0x13fc
.word 0x0001
.long 0x00a04001
.word 0x13fc
.word 0x0034
.long 0x00a04000
.word 0x13fc
.word 0x0001
.long 0x00a04001
.word 0x13fc
.word 0x0038
.long 0x00a04000
.word 0x13fc
.word 0x0001
.long 0x00a04001
.word 0x13fc
.word 0x003c
.long 0x00a04000
.word 0x13fc
.word 0x0001
.long 0x00a04001
/* One audible carrier, other slots silent. */
.word 0x13fc
.word 0x0040
.long 0x00a04000
.word 0x13fc
.word 0x0000
.long 0x00a04001
.word 0x13fc
.word 0x0044
.long 0x00a04000
.word 0x13fc
.word 0x007f
.long 0x00a04001
.word 0x13fc
.word 0x0048
.long 0x00a04000
.word 0x13fc
.word 0x007f
.long 0x00a04001
.word 0x13fc
.word 0x004c
.long 0x00a04000
.word 0x13fc
.word 0x007f
.long 0x00a04001
/* Immediate attack, sustain with no decay, maximum release rate. */
.word 0x13fc
.word 0x0050
.long 0x00a04000
.word 0x13fc
.word 0x001f
.long 0x00a04001
.word 0x13fc
.word 0x0080
.long 0x00a04000
.word 0x13fc
.word 0x000f
.long 0x00a04001
.word 0x13fc
.word 0x00b0
.long 0x00a04000
.word 0x13fc
.word 0x0007
.long 0x00a04001
.word 0x13fc
.word 0x00b4
.long 0x00a04000
.word 0x13fc
.word 0x00c0
.long 0x00a04001
/* High frequency byte first; low write commits the pair. */
.word 0x13fc
.word 0x00a4
.long 0x00a04000
.word 0x13fc
.word 0x0022
.long 0x00a04001
.word 0x13fc
.word 0x00a0
.long 0x00a04000
.word 0x13fc
.word 0x0084
.long 0x00a04001
.word 0x13fc
.word 0x0028
.long 0x00a04000
.word 0x13fc
.word 0x0010
.long 0x00a04001
/* Stop the Z80 before returning its bus; it executes HALT repeatedly. */
.word 0x13fc
.word 0x0076
.long 0x00a00000
.word 0x33fc
.word 0x0000
.long 0x00a11100
.word 0x60fe
.org 0x5fe
.word 0

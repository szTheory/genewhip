/* SPDX-License-Identifier: MIT
 * Original reset observer, Zilog UM0080 documented instructions. No stack
 * access: SP's model reset value is outside RAM. RAM survives reset. */
.text
ld a,(0x1000)
inc a
ld (0x1000),a
ld a,i
ld (0x1001),a
/* Absolute target is byte offset 0x13 in this address-zero payload. GNU as
 * retains absolute label relocations; the ROM extractor rejects relocations. */
jp po,0x0013
ld a,1
jr store_iff
iff_clear:
ld a,0
store_iff:
ld (0x1002),a
loop:
jr loop

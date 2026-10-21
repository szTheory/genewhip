/* SPDX-License-Identifier: MIT
 * Original Genewhip toolchain smoke; opcode values from Zilog UM0080
 * Z80 CPU User Manual instruction tables (NOP, LD r,n, JP nn). */
        .text
        nop             /* 00 */
        ld a,0x42       /* 3E 42 */
        jp 0x1234       /* C3 34 12, little endian */

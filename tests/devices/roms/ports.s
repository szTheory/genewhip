/* SPDX-License-Identifier: MIT
 * Original Genewhip VDP ports seam ROM (plan GW-02-03). Straight-line code only:
 * documented port sequences, results copied into work RAM at 0xFF0000 for the
 * seam checker. Expected values are in ports.expect.json, written from cited
 * documentation and not from emulator output.
 */
        .cpu 68000
        .text
        .org    0x0000
        .long   0x00ffff00              /* initial stack in work RAM */
        .long   0x00000200              /* reset vector */
        .org    0x0100
        .ascii  "SEGA MEGA DRIVE "
        .ascii  "(C)26 GENEWHIP  "
        .ascii  "GENEWHIP PORTS SEAM"
        .org    0x01f0
        .ascii  "JUE"

        .org    0x0200
start:
        move.w  #0x8f02,0x00c00004      /* register 15: auto-increment 2 */

        /* vram-write-readback: write two words at VRAM 0x1000, read them back */
        move.l  #0x50000000,0x00c00004  /* VRAM write, address 0x1000 */
        move.w  #0x1234,0x00c00000
        move.w  #0xabcd,0x00c00000
        move.l  #0x10000000,0x00c00004  /* VRAM read, address 0x1000 */
        move.w  0x00c00000,0x00ff0000
        move.w  0x00c00000,0x00ff0002

        /* cram-write-readback: CRAM address 4 (0000 BBB0 GGG0 RRR0 words) */
        move.l  #0xc0040000,0x00c00004  /* CRAM write, address 4 */
        move.w  #0x0e4a,0x00c00000
        move.w  #0x0a28,0x00c00000
        move.l  #0x00040020,0x00c00004  /* CRAM read, address 4 */
        move.w  0x00c00000,0x00ff0004
        move.w  0x00c00000,0x00ff0006

        /* vsram-write-readback: VSRAM address 2 */
        move.l  #0x40020010,0x00c00004  /* VSRAM write, address 2 */
        move.w  #0x0123,0x00c00000
        move.w  #0x0456,0x00c00000
        move.l  #0x00020010,0x00c00004  /* VSRAM read, address 2 */
        move.w  0x00c00000,0x00ff0008
        move.w  0x00c00000,0x00ff000a

        /* autoincrement-4: register 15 = 4, VRAM 0x2000 and 0x2004 */
        move.w  #0x8f04,0x00c00004
        move.l  #0x60000000,0x00c00004  /* VRAM write, address 0x2000 */
        move.w  #0x1111,0x00c00000
        move.w  #0x2222,0x00c00000
        move.l  #0x20000000,0x00c00004  /* VRAM read, address 0x2000 */
        move.w  0x00c00000,0x00ff000c
        move.w  0x00c00000,0x00ff000e

        /* port mirrors: register, command and data through 0xC00002 / 0xC00006 */
        move.w  #0x8f02,0x00c00006      /* register 15 = 2 through the mirror */
        move.w  #0x7000,0x00c00006      /* VRAM write, address 0x3000: two words, since a */
        move.w  #0x0000,0x00c00006      /* long at 0xC00006 would continue into 0xC00008 */
        move.w  #0x5a5a,0x00c00002
        move.w  #0x3000,0x00c00006      /* VRAM read, address 0x3000 */
        move.w  #0x0000,0x00c00006
        move.w  0x00c00002,0x00ff0010

        /* status register: the read above waited for the FIFO to drain */
        move.w  0x00c00004,0x00ff0012
        move.w  0x00c00006,0x00ff0014

        /* latch: first command word, status read, then a complete command */
        move.w  #0x7800,0x00c00004      /* first word of a VRAM write command */
        move.w  0x00c00004,0x00ff0016   /* status read (value unused) */
        move.l  #0x44000000,0x00c00004  /* VRAM write, address 0x0400 if the latch cleared */
        move.w  #0x7e7e,0x00c00000
        move.l  #0x04000000,0x00c00004  /* VRAM read, address 0x0400 */
        move.w  0x00c00000,0x00ff0018

        move.w  0x00c00008,0x00ff001a   /* HV counter */

        /* VSRAM entry 40 lies past the 40 entries of the VSRAM */
        move.l  #0x00500010,0x00c00004  /* VSRAM read, address 0x50 */
        move.w  0x00c00000,0x00ff001c

        move.w  #0x600d,0x00ff00fe      /* completion marker */
done:   bra.s   done

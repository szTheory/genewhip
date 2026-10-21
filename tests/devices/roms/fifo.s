/* SPDX-License-Identifier: MIT
 * Original Genewhip VDP write-FIFO seam ROM (plan GW-02-08, genewhip-seam-fifo-v1). The
 * program issues documented data-port write bursts, reads the status register and the
 * written memory back, and copies each observation into work RAM at 0xFF0100.. for the
 * seam checker. Expected values are in fifo.expect.json, written from the cited
 * documentation and never from emulator output. Absolute slot positions and instruction
 * counts are not asserted: only orderings and relationships (full flag under a sustained
 * burst in active display, no full flag in blanking, empty flag after a wait, entries
 * keeping their captured address).
 *
 * Work RAM layout (offsets from 0xFF0000):
 *   0x100 status read right after the 8-word burst, display on
 *   0x102 status after polling for FIFO empty
 *   0x104 the 8 burst words read back from VRAM 0x1000 (16 bytes)
 *   0x114 status read right after the same burst with the display off
 *   0x116 words read back from VRAM 0x1200 and 0x1202, then 0x1300 (6 bytes)
 *   0x120 twelve status words, one read after each of twelve single writes
 *   0x1FE completion marker 0x600d
 */
        .cpu 68000
        .text

        .macro  vdpreg reg,val          /* register write: 0x8000 + reg * 256 + value */
        move.w  #(0x8000+((\reg)<<8)+(\val)),(%a0)
        .endm
        .macro  cmdw hi,lo,addr         /* two-word command: address bits 13-0 and 15-14 */
        move.w  #((\hi)+((\addr)&0x3fff)),(%a0)
        move.w  #((\lo)+(((\addr)>>14)&3)),(%a0)
        .endm
        .macro  vramwr addr             /* VRAM write command */
        cmdw    0x4000,0x0000,\addr
        .endm
        .macro  vramrd addr             /* VRAM read command */
        cmdw    0x0000,0x0000,\addr
        .endm
        .macro  rd dest                 /* one data-port read into work RAM */
        move.w  (%a1),\dest
        .endm
        .macro  burst base              /* eight word writes: 0x1111, 0x2222 ... 0x8888 */
        vramwr  \base
        move.w  #0x1111,(%a1)
        move.w  #0x2222,(%a1)
        move.w  #0x3333,(%a1)
        move.w  #0x4444,(%a1)
        move.w  #0x5555,(%a1)
        move.w  #0x6666,(%a1)
        move.w  #0x7777,(%a1)
        move.w  #0x8888,(%a1)
        .endm
        .macro  waitempty               /* poll status bit 9 (FIFO empty) */
1:      move.w  (%a0),%d0
        btst    #9,%d0
        beq.s   1b
        .endm
        .macro  wst ram                 /* one write, then the status word */
        move.w  #0x0000,(%a1)
        move.w  (%a0),\ram
        .endm

        .org    0x0000
        .long   0x00ffff00              /* initial stack in work RAM */
        .long   0x00000200              /* reset vector */
        .org    0x0100
        .ascii  "SEGA MEGA DRIVE "
        .ascii  "(C)26 GENEWHIP  "
        .ascii  "GENEWHIP FIFO SEAM"
        .org    0x01f0
        .ascii  "JUE"

        .org    0x0200
start:
        lea     0x00c00004,%a0          /* control port */
        lea     0x00c00000,%a1          /* data port */
        vdpreg  15,2                    /* auto-increment 2 */

        /* Active display (register 1: display on, Mode 5): a sustained burst of eight
         * word writes outruns the access slots, so the write FIFO is full afterwards. */
        vdpreg  1,0x44
        burst   0x1000
        move.w  (%a0),0x00ff0100        /* fifo-full-flag-in-burst */
        waitempty
        move.w  (%a0),0x00ff0102        /* fifo-empty-flag-after-wait */
        vramrd  0x1000
        rd      0x00ff0104
        rd      0x00ff0106
        rd      0x00ff0108
        rd      0x00ff010a
        rd      0x00ff010c
        rd      0x00ff010e
        rd      0x00ff0110
        rd      0x00ff0112

        /* Blanking (display off) drains faster than active display: the same burst
         * leaves the FIFO not full. */
        vdpreg  1,0x04
        burst   0x1100
        move.w  (%a0),0x00ff0114        /* fifo-no-full-in-blanking */
        waitempty

        /* Entries keep the address captured at enqueue: change the address with two
         * writes still pending. */
        vdpreg  1,0x44
        vramwr  0x1200
        move.w  #0xaaaa,(%a1)
        move.w  #0xbbbb,(%a1)
        vramwr  0x1300
        move.w  #0xcccc,(%a1)
        waitempty
        vramrd  0x1200
        rd      0x00ff0116
        rd      0x00ff0118
        vramrd  0x1300
        rd      0x00ff011a

        /* Status after each of twelve single writes (the instruction count at which the
         * full flag first reads set is not independently known). */
        vramwr  0x1400
        wst     0x00ff0120
        wst     0x00ff0122
        wst     0x00ff0124
        wst     0x00ff0126
        wst     0x00ff0128
        wst     0x00ff012a
        wst     0x00ff012c
        wst     0x00ff012e
        wst     0x00ff0130
        wst     0x00ff0132
        wst     0x00ff0134
        wst     0x00ff0136
        waitempty

        move.w  #0x600d,0x00ff01fe      /* completion marker */
done:   bra.s   done

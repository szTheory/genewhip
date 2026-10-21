/* SPDX-License-Identifier: MIT
 * Original Genewhip VDP DMA seam ROM (plan GW-02-08, genewhip-seam-dma-v1). The program
 * uses documented command and register sequences only: it programs DMA through the VDP
 * registers and control port, reads the destination memories back through the data port
 * and copies each observation into work RAM at 0xFF0100.. for the seam checker. Expected
 * values are in dma.expect.json, written from the cited documentation and the data
 * tables below, never from emulator output.
 *
 * Work RAM layout (offsets from 0xFF0000):
 *   0x100 first word of the 64-word table, DMA'd to VRAM 0x2000
 *   0x102 word 32 of that transfer     0x104 word 63     0x106 sentinel just past the end
 *   0x108 HV counter before that DMA command, 0x10A after it
 *   0x10C first and 0x10E last of four words DMA'd to CRAM address 8
 *   0x110 first and 0x112 last of three words DMA'd to VSRAM address 2
 *   0x114 four words of a transfer whose source crosses a 128 KiB boundary (8 bytes)
 *   0x11C and 0x11E interior words and 0x120 a far sentinel of a 64-byte VRAM fill
 *   0x122 status right after the fill trigger, 0x124 status after polling busy clear
 *   0x126 and 0x128 the first and last words touched by that fill (edge semantics)
 *   0x12A status right after a copy command, 0x12C status after polling busy clear
 *   0x12E, 0x130, 0x132 first, middle and last word of a 16-byte VRAM copy
 *   0x134 a VRAM word after a length-0 transfer
 *   0x136 two words after an 8-byte fill whose trigger word has distinct bytes
 *   0x13A a word written through the data port while a fill is running
 *   0x1FE completion marker 0x600d
 */
        .cpu 68000
        .text

/* Source table placement: 64 words at a fixed ROM address (word i is
 * ((i + 1) << 8) | (0xc0 + i), so the bytes are never confusable). */
        .equ    TABLE, 0x0600
        .equ    CDATA, 0x0680           /* four CRAM words, then three VSRAM words */
        .equ    VDATA, 0x0688

        .macro  vdpreg reg,val          /* register write: 0x8000 + reg * 256 + value */
        move.w  #(0x8000+((\reg)<<8)+(\val)),(%a0)
        .endm
        .macro  dmaregs len,src,dmd     /* length, source (as the register bytes) and DMD */
        vdpreg  19,((\len)&0xff)
        vdpreg  20,(((\len)>>8)&0xff)
        vdpreg  21,((\src)&0xff)
        vdpreg  22,(((\src)>>8)&0xff)
        vdpreg  23,((((\src)>>16)&0x7f)+(\dmd))
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
        .macro  skip                    /* one data-port read, discarded */
        move.w  (%a1),%d0
        .endm
        .macro  waitdma                 /* poll status bit 1 (DMA busy) until clear */
1:      move.w  (%a0),%d0
        btst    #1,%d0
        bne.s   1b
        .endm

        .org    0x0000
        .long   0x00ffff00              /* initial stack in work RAM */
        .long   0x00000200              /* reset vector */
        .org    0x0100
        .ascii  "SEGA MEGA DRIVE "
        .ascii  "(C)26 GENEWHIP  "
        .ascii  "GENEWHIP DMA SEAM"
        .org    0x01f0
        .ascii  "JUE"

        .org    0x0200
start:
        lea     0x00c00004,%a0          /* control port */
        lea     0x00c00000,%a1          /* data port */
        vdpreg  15,2                    /* auto-increment 2 */
        vdpreg  1,0x14                  /* M1 (DMA enable) and Mode 5, display off */

        /* dma68k-vram: 64 words from ROM to VRAM 0x2000 (plutiedev dma-transfer) */
        vramwr  0x2080
        move.w  #0x5a5a,(%a1)           /* sentinel one word past the transfer */
        dmaregs 64,(TABLE>>1),0x00
        move.w  0x00c00008,0x00ff0108   /* HV counter before the command */
        cmdw    0x4000,0x0080,0x2000    /* VRAM DMA command starts the transfer */
        move.w  0x00c00008,0x00ff010a   /* HV counter after: the CPU was held */
        vramrd  0x2000
        rd      0x00ff0100              /* word 0 */
        vramrd  0x2040
        rd      0x00ff0102              /* word 32 */
        vramrd  0x207e
        rd      0x00ff0104              /* word 63 */
        rd      0x00ff0106              /* sentinel at 0x2080 */

        /* dma68k-cram: four colour words to CRAM address 8 (CRAM DMA command 0xC0000080) */
        dmaregs 4,(CDATA>>1),0x00
        cmdw    0xc000,0x0080,8
        cmdw    0x0000,0x0020,8         /* CRAM read command */
        rd      0x00ff010c
        skip
        skip
        rd      0x00ff010e

        /* dma68k-vsram: three words to VSRAM address 2 (VSRAM DMA command 0x40000090) */
        dmaregs 3,(VDATA>>1),0x00
        cmdw    0x4000,0x0090,2
        cmdw    0x0000,0x0010,2         /* VSRAM read command */
        rd      0x00ff0110
        skip
        rd      0x00ff0112

        /* 128 KiB boundary: the last two work-RAM words, then the source continues inside
         * the same 128 KiB block (0xFE0000 mirrors the start of work RAM) */
        move.w  #0x1111,0x00ff0000
        move.w  #0x2222,0x00ff0002
        move.w  #0x3333,0x00fffffc
        move.w  #0x4444,0x00fffffe
        dmaregs 4,0x7ffffe,0x00         /* word address of byte 0xFFFFFC */
        cmdw    0x4000,0x0080,0x2200
        vramrd  0x2200
        rd      0x00ff0114
        rd      0x00ff0116
        rd      0x00ff0118
        rd      0x00ff011a

        /* vram-fill: DMD = 10; the command arms it and the next data-port write starts it.
         * Register 15 = 1 steps the fill one byte at a time. */
        vdpreg  15,1
        vramwr  0x3060
        move.w  #0x0000,(%a1)           /* far sentinel, outside the filled range */
        dmaregs 0x40,0,0x80
        cmdw    0x4000,0x0080,0x3010
        move.w  #0xaaaa,(%a1)           /* trigger: both bytes 0xaa */
        move.w  (%a0),0x00ff0122        /* DMA busy right after the trigger */
        waitdma
        move.w  (%a0),0x00ff0124        /* busy clear after polling */
        vdpreg  15,2
        vramrd  0x3010
        rd      0x00ff0126
        vramrd  0x3014
        rd      0x00ff011c
        vramrd  0x3040
        rd      0x00ff011e
        vramrd  0x3050
        rd      0x00ff0128
        vramrd  0x3060
        rd      0x00ff0120

        /* vram-copy: DMD = 11; 16 bytes from VRAM 0x2000 to 0x3100, started by the command */
        vdpreg  15,1
        dmaregs 0x10,0x2000,0xc0        /* source is a VRAM byte address in registers 21/22 */
        cmdw    0x0000,0x00c0,0x3100
        move.w  (%a0),0x00ff012a        /* DMA busy right after the command */
        waitdma
        move.w  (%a0),0x00ff012c        /* busy clear after polling */
        vdpreg  15,2
        vramrd  0x3100
        rd      0x00ff012e
        vramrd  0x3108
        rd      0x00ff0130
        vramrd  0x310e
        rd      0x00ff0132

        /* length 0: the hardware meaning is not independently known */
        vramwr  0x3200
        move.w  #0xbeef,(%a1)
        dmaregs 0,(TABLE>>1),0x00
        cmdw    0x4000,0x0080,0x3200
        vramrd  0x3200
        rd      0x00ff0134

        /* fill trigger word with distinct bytes (byte-lane and odd-address behaviour unknown) */
        vdpreg  15,1
        dmaregs 8,0,0x80
        cmdw    0x4000,0x0080,0x3300
        move.w  #0xab12,(%a1)
        waitdma
        vdpreg  15,2
        vramrd  0x3300
        rd      0x00ff0136
        rd      0x00ff0138

        /* a data-port write while a fill is running (hardware behaviour unknown) */
        vdpreg  15,1
        dmaregs 0x40,0,0x80
        cmdw    0x4000,0x0080,0x3400
        move.w  #0xaaaa,(%a1)
        vramwr  0x3500
        move.w  #0x7777,(%a1)
        waitdma
        vdpreg  15,2
        vramrd  0x3500
        rd      0x00ff013a

        move.w  #0x600d,0x00ff01fe      /* completion marker */
done:   bra.s   done

        .org    TABLE
table:
        .set    i,0
        .rept   64
        .word   ((i+1)<<8)+(0xc0+i)
        .set    i,i+1
        .endr

        .org    CDATA
        .word   0x0e4a,0x0a28,0x0246,0x0888     /* valid CRAM words (even colour nibbles) */
        .org    VDATA
        .word   0x0123,0x0456,0x0155            /* VSRAM words */

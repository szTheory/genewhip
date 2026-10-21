/* SPDX-License-Identifier: MIT
 * Original Genewhip raster toy (plan GW-02-11, genewhip-raster-toy-v1). Authored solely
 * for Genewhip; no third-party code, data, graphics or sound. All pictures are generated
 * by the assembler expressions below. Expected pixels are derived from the constants in
 * scenario.json and the documented tile, name-table, palette and scroll formats.
 *
 * ROM data blocks (fixed addresses, DMA'd to the VDP by start-up code or the handler):
 *   0x0600 CRAM (64 words)      0x0700 tiles 0-7 (256 bytes)
 *   0x1000 plane B table (64x32) 0x2000 plane A table (64x32)  0x3000 window table (64x3)
 *   0x3300 line hscroll (224 x A,B)  0x3700 2-cell vscroll (20 x A,B)
 *   0x3800 cell hscroll (224 line slots x A,B; only the first slot of each 8-line cell is read)
 *
 * VINT handler: work RAM word 0xFF0000 counts handler runs (c). Before the field after
 * run c is rendered: c <  16 full-screen scroll, plane B hscroll = 3c, plane A vscroll = 2c;
 *                     c == 16 cell hscroll table loaded (register 11 = 2), motion stops;
 *                     c == 32 line hscroll and 2-cell vscroll tables loaded (register 11 = 7);
 *                     c == 48 plane size 32x32 (register 16 = 0); c == 64 size 128x32 (register 16 = 3);
 *                     c == 80 register 12 = 0x89 (shadow/highlight): low-priority plane pixels and the
 *                     backdrop are drawn at the shadow level, high-priority plane pixels stay normal.
 * Plane A vscroll keeps 2c while c < 32. Start-up finishes inside field 0 so the first
 * handler run is the VINT at the end of field 0.
 *
 * Sprites (plans GW-02-12 and GW-02-19): two 8x8 high-priority sprites (tile 7, solid colour 15;
 * no other layer uses colour 15 of palette lines 0 and 2) linked 0 -> 1 in the table at VRAM
 * 0xF000 (register 5 = 0x78); entry 0 is at 0xF000, entry 1 at 0xF008. Start-up writes both
 * entries with Y = 0 (top -128, never visible). Sprite 0 uses palette 0 and follows port 1 (the
 * first pad, data register 0xA10003); sprite 1 uses palette 2 and follows port 2 (data register
 * 0xA10005, control 0xA1000B). Work RAM words hold X and Y including the +128 sprite offset:
 * sprite 0 at 0xFF0002/0xFF0004, initially (160 + 128, 100 + 128); sprite 1 at
 * 0xFF0006/0xFF0008, initially (60 + 128, 150 + 128). Every handler run reads each port with TH
 * held high: Right/Left/Down/Up bits 3..0 read 0 when pressed. When any direction is pressed the
 * run moves that port's sprite per pressed direction (2 pixels for sprite 0, 3 for sprite 1;
 * Right +x, Left -x, Down +y, Up -y) and rewrites its whole entry; with nothing pressed the entry
 * is left alone, so a sprite stays off screen until its first press. The ports are read
 * independently. The read happens at the run's VINT (line 224 of field c-1); an entry written
 * there is first drawn in field c, so a sprite in field s sits at start + step * (pressed runs
 * c <= s) of its own port.
 */
        .cpu 68000
        .text

        .equ    PAD_A_MASK,0x40
        .equ    PAD_B_MASK,0x10
        .equ    PAD_C_MASK,0x20
        .equ    PAD_A_PIN,0x10
        .equ    Z80_MAILBOX,0x1010
        .equ    Z80_DRIVER_BYTES,1344

        .macro  vdpreg reg,val          /* register write: 0x8000 + reg * 256 + value */
        move.w  #(0x8000+((\reg)<<8)+(\val)),(%a0)
        .endm
        .macro  dmaregs len,src,dmd     /* length, word source address and DMD bits */
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

        .org    0x0000
        .long   0x00ffff00              /* initial stack in work RAM */
        .long   0x00000200              /* reset vector */
        .org    0x0070
        .long   0x000003f0              /* level 4 (HINT disabled): rte */
        .long   0x000003f0
        .long   0x00000400                    /* level 6 autovector (VINT) */
        .org    0x0100
        .ascii  "SEGA MEGA DRIVE "
        .ascii  "(C)26 GENEWHIP  "
        .ascii  "GENEWHIP RASTER"
        .org    0x01f0
        .ascii  "JUE"

        .org    0x0200
start:
        move.w  #0x2700,%sr
        lea     0x00c00004,%a0          /* control port */
        lea     0x00c00000,%a1          /* data port */
        vdpreg  0,0x04
        vdpreg  1,0x14                  /* DMA enable and Mode 5, display off */
        vdpreg  2,0x30                  /* plane A at VRAM 0xC000 */
        vdpreg  3,0x28                  /* window at VRAM 0xA000 */
        vdpreg  4,0x07                  /* plane B at VRAM 0xE000 */
        vdpreg  5,0x78                  /* sprite table at VRAM 0xF000 */
        vdpreg  7,0x00                  /* backdrop: CRAM entry 0 */
        vdpreg  11,0x00                 /* full-screen scroll */
        vdpreg  12,0x81                 /* H40 */
        vdpreg  13,0x2e                 /* hscroll table at VRAM 0xB800 */
        vdpreg  15,2
        vdpreg  16,0x01                 /* planes 64 cells wide, 32 high */
        vdpreg  17,0x00                 /* window: no columns ... */
        vdpreg  18,0x03                 /* ... rows above line 24 */
        dmaregs 128,(0x0700>>1),0x00    /* tiles 0-7 to VRAM 0 */
        cmdw    0x4000,0x0080,0x0000
        dmaregs 64,(0x0600>>1),0x00     /* palette to CRAM */
        cmdw    0xc000,0x0080,0x0000
        dmaregs 2048,(0x1000>>1),0x00   /* plane B table to VRAM 0xE000 */
        cmdw    0x4000,0x0080,0xe000
        dmaregs 2048,(0x2000>>1),0x00   /* plane A table to VRAM 0xC000 */
        cmdw    0x4000,0x0080,0xc000
        dmaregs 192,(0x3000>>1),0x00    /* window table to VRAM 0xA000 */
        cmdw    0x4000,0x0080,0xa000
        move.l  #0x78000002,(%a0)       /* hscroll entry 0 (planes A and B) = 0 */
        move.l  #0,(%a1)
        move.l  #0x40000010,(%a0)       /* VSRAM entries 0 and 1 = 0 */
        move.l  #0,(%a1)
        move.w  #(160+128),0x00ff0002   /* sprite 0 X, Y with the +128 offset */
        move.w  #(100+128),0x00ff0004
        move.w  #(60+128),0x00ff0006    /* sprite 1 X, Y with the +128 offset */
        move.w  #(150+128),0x00ff0008
        move.b  #0x40,0x00a10009        /* port 1 control: TH output */
        move.b  #0x40,0x00a10003        /* port 1 data: TH high (direction layout) */
        move.b  #0x40,0x00a1000b        /* port 2 control: TH output */
        move.b  #0x40,0x00a10005        /* port 2 data: TH high (direction layout) */
        /* Start the original Z80 sound guest while the bus is granted. */
        move.w  #0x0100,0x00a11100
z80_boot_grant:
        move.b  0x00a11100,%d0
        btst    #0,%d0
        bne.s   z80_boot_grant
        move.w  #0x0000,0x00a11200
        lea     0x00005000,%a2
        lea     0x00a00000,%a3
        move.w  #(Z80_DRIVER_BYTES-1),%d0
z80_upload:
        move.b  (%a2)+,(%a3)+
        dbf     %d0,z80_upload
        move.w  #0x0100,0x00a11200
        move.w  #0x0000,0x00a11100
        move.b  #0,0x00ff000a          /* previous sound buttons */
        move.l  #0x70000003,(%a0)       /* VRAM write 0xF000: both entries off screen (Y = 0) */
        move.w  #0x0000,(%a1)           /* sprite 0: Y (top -128, never visible) */
        move.w  #0x0001,(%a1)           /* size 1x1 cells, link 1 */
        move.w  #0x8007,(%a1)           /* high priority, palette 0, tile 7 */
        move.w  #0x0000,(%a1)           /* X */
        move.w  #0x0000,(%a1)           /* sprite 1: Y */
        move.w  #0x0000,(%a1)           /* size 1x1 cells, link 0 (end of list) */
        move.w  #0xc007,(%a1)           /* high priority, palette 2, tile 7 */
        move.w  #0x0000,(%a1)           /* X */
        vdpreg  1,0x74                  /* display on, VINT enabled */
        move.w  #0x2000,%sr
main:
        stop    #0x2000
        bra.s   main

        .org    0x03f0
handler_rte:
        rte

        .org    0x0400
vint:
        lea     0x00c00004,%a0
        lea     0x00c00000,%a1
        move.w  0x00ff0000,%d0
        addq.w  #1,%d0
        move.w  %d0,0x00ff0000
        /* Sample A with TH low, B/C with TH high; enqueue only press edges. */
        move.b  #0x00,0x00a10003
        move.b  0x00a10003,%d5
        not.b   %d5
        and.b   #PAD_A_PIN,%d5
        lsr.b   #4,%d5
        move.b  #0x40,0x00a10003
        move.b  0x00a10003,%d6
        not.b   %d6
        and.b   #(PAD_B_MASK+PAD_C_MASK),%d6
        lsr.b   #3,%d6
        or.b    %d6,%d5               /* A=1, B=2, C=4 */
        tst.b   0x00ff000b
        bne.s   sound_edges
        move.b  #1,0x00ff000b         /* seed held state once; startup pins are not press edges */
        move.b  %d5,0x00ff000a
        bra.s   sound_done
sound_edges:
        move.b  0x00ff000a,%d6
        move.b  %d5,0x00ff000a
        not.b   %d6
        and.b   %d5,%d6
        and.b   #7,%d6
        beq.s   sound_done
        move.w  #0x0100,0x00a11100
sound_grant:
        move.b  0x00a11100,%d7
        btst    #0,%d7
        bne.s   sound_grant
        move.b  %d6,(0x00a00000+Z80_MAILBOX)
        move.w  #0x0000,0x00a11100
sound_done:
        move.b  0x00a10003,%d2          /* port 1, TH high: pressed buttons read 0 */
        not.b   %d2
        and.w   #15,%d2
        beq.s   9f
        move.w  0x00ff0002,%d3
        move.w  0x00ff0004,%d4
        btst    #3,%d2                  /* Right */
        beq.s   7f
        addq.w  #2,%d3
7:      btst    #2,%d2                  /* Left */
        beq.s   7f
        subq.w  #2,%d3
7:      btst    #1,%d2                  /* Down */
        beq.s   7f
        addq.w  #2,%d4
7:      btst    #0,%d2                  /* Up */
        beq.s   7f
        subq.w  #2,%d4
7:      move.w  %d3,0x00ff0002
        move.w  %d4,0x00ff0004
        move.l  #0x70000003,(%a0)       /* VRAM write 0xF000: sprite 0 entry */
        move.w  %d4,(%a1)               /* Y */
        move.w  #0x0001,(%a1)           /* size 1x1 cells, link 1 (sprite 1 follows) */
        move.w  #0x8007,(%a1)           /* high priority, palette 0, tile 7 */
        move.w  %d3,(%a1)               /* X */
9:
        move.b  0x00a10005,%d2          /* port 2, TH high: pressed buttons read 0 */
        not.b   %d2
        and.w   #15,%d2
        beq.s   9f
        move.w  0x00ff0006,%d3
        move.w  0x00ff0008,%d4
        btst    #3,%d2                  /* Right */
        beq.s   7f
        addq.w  #3,%d3
7:      btst    #2,%d2                  /* Left */
        beq.s   7f
        subq.w  #3,%d3
7:      btst    #1,%d2                  /* Down */
        beq.s   7f
        addq.w  #3,%d4
7:      btst    #0,%d2                  /* Up */
        beq.s   7f
        subq.w  #3,%d4
7:      move.w  %d3,0x00ff0006
        move.w  %d4,0x00ff0008
        move.l  #0x70080003,(%a0)       /* VRAM write 0xF008: sprite 1 entry */
        move.w  %d4,(%a1)               /* Y */
        move.w  #0x0000,(%a1)           /* size 1x1 cells, link 0 (end of list) */
        move.w  #0xc007,(%a1)           /* high priority, palette 2, tile 7 */
        move.w  %d3,(%a1)               /* X */
9:
        cmp.w   #16,%d0
        bge.s   1f
        move.w  %d0,%d1                 /* plane B hscroll = 3c */
        add.w   %d0,%d1
        add.w   %d0,%d1
        move.l  #0x78020002,(%a0)       /* VRAM write 0xB802 */
        move.w  %d1,(%a1)
1:      cmp.w   #32,%d0
        bge.s   2f
        move.w  %d0,%d1                 /* plane A vscroll = 2c */
        add.w   %d1,%d1
        move.l  #0x40000010,(%a0)       /* VSRAM write 0 */
        move.w  %d1,(%a1)
2:      cmp.w   #16,%d0
        bne.s   3f
        dmaregs 448,(0x3800>>1),0x00
        cmdw    0x4000,0x0080,0xb800
        vdpreg  11,0x02
3:      cmp.w   #32,%d0
        bne.s   4f
        dmaregs 448,(0x3300>>1),0x00
        cmdw    0x4000,0x0080,0xb800
        dmaregs 40,(0x3700>>1),0x00
        cmdw    0x4000,0x0090,0x0000
        vdpreg  11,0x07
4:      cmp.w   #48,%d0
        bne.s   5f
        vdpreg  16,0x00
5:      cmp.w   #64,%d0
        bne.s   6f
        vdpreg  16,0x03
6:      cmp.w   #80,%d0
        bne.s   8f
        vdpreg  12,0x89                 /* H40 plus S/TE: shadow/highlight on */
8:      rte

/* Palette: entry (p, i) = BBB GGG RRR with b = (i + 3p) & 7, g = (7 - (i & 7) + p) & 7,
 * r = (5i + 2p) & 7; entry 0 is the backdrop 0x0A60. */
        .org    0x0600
        .word   0x0a60
        .set    pal_i,1
        .rept   15
        .word   ((((pal_i)&7)<<9)+(((7-(pal_i&7))&7)<<5)+(((5*pal_i)&7)<<1))
        .set    pal_i,pal_i+1
        .endr
        .set    pal_p,1
        .rept   3
        .set    pal_i,0
        .rept   16
        .word   ((((pal_i+3*pal_p)&7)<<9)+(((7-(pal_i&7)+pal_p)&7)<<5)+(((5*pal_i+2*pal_p)&7)<<1))
        .set    pal_i,pal_i+1
        .endr
        .set    pal_p,pal_p+1
        .endr

/* Tiles: 0 empty; 1-4 solid colours 1-4; 5 gradient pixel(x, y) = (x + y) & 7;
 * 6 solid colour 9; 7 solid colour 15. */
        .org    0x0700
        .rept   8
        .long   0
        .endr
        .rept   8
        .long   0x11111111
        .endr
        .rept   8
        .long   0x22222222
        .endr
        .rept   8
        .long   0x33333333
        .endr
        .rept   8
        .long   0x44444444
        .endr
        .macro  grad r
        .long   ((((0+\r)&7)<<28)+(((1+\r)&7)<<24)+(((2+\r)&7)<<20)+(((3+\r)&7)<<16)+(((4+\r)&7)<<12)+(((5+\r)&7)<<8)+(((6+\r)&7)<<4)+((7+\r)&7))
        .endm
        .irp    r,0,1,2,3,4,5,6,7
        grad    \r
        .endr
        .rept   8
        .long   0x99999999
        .endr
        .rept   8
        .long   0xffffffff
        .endr

/* Plane B table (64 x 32 cells): tile 1 + ((col + row) & 3), palette (col >> 4) & 3, high
 * priority for rows 10-13 and cols 14-29; rows 20-23 are empty (tile 0). */
        .org    0x1000
        .set    gy,0
        .rept   32
        .set    gx,0
        .rept   64
        .set    nt,((((gx>>4)&3)<<13)+1+((gx+gy)&3))
        .if     (gy>=10)&(gy<=13)&(gx>=14)&(gx<=29)
        .set    nt,nt+0x8000
        .endif
        .if     (gy>=20)&(gy<=23)
        .set    nt,0
        .endif
        .word   nt
        .set    gx,gx+1
        .endr
        .set    gy,gy+1
        .endr

/* Plane A table (64 x 32 cells), default empty:
 *   rows 4-7, cols 4-9: tile 5, palette 1, H-flip = col & 1, V-flip = row & 1, low priority
 *   rows 10-11, cols 10-19: tile 6, palette 2, low priority (B high shows over cols 14-19)
 *   rows 12-13, cols 10-19: tile 6, palette 2, high priority (over B high)
 *   rows 20-21, cols 20-27: tile 5, palette 3, low priority (over the empty B band) */
        .org    0x2000
        .set    gy,0
        .rept   32
        .set    gx,0
        .rept   64
        .set    nt,0
        .if     (gy>=4)&(gy<=7)&(gx>=4)&(gx<=9)
        .set    nt,5+(1<<13)+((gx&1)<<11)+((gy&1)<<12)
        .endif
        .if     (gy>=10)&(gy<=11)&(gx>=10)&(gx<=19)
        .set    nt,6+(2<<13)
        .endif
        .if     (gy>=12)&(gy<=13)&(gx>=10)&(gx<=19)
        .set    nt,6+(2<<13)+0x8000
        .endif
        .if     (gy>=20)&(gy<=21)&(gx>=20)&(gx<=27)
        .set    nt,5+(3<<13)
        .endif
        .word   nt
        .set    gx,gx+1
        .endr
        .set    gy,gy+1
        .endr

/* Window table (64 x 3 cells): tile 5 where (col + row) is even, else tile 6; palette 3. */
        .org    0x3000
        .set    gy,0
        .rept   3
        .set    gx,0
        .rept   64
        .word   (3<<13)+5+((gx+gy)&1)
        .set    gx,gx+1
        .endr
        .set    gy,gy+1
        .endr

/* Line hscroll (224 lines): plane A = (1024 - (y & 15)) & 0x3ff, plane B = (3y + 7) & 0x3ff. */
        .org    0x3300
        .set    gy,0
        .rept   224
        .word   (1024-(gy&15))&0x3ff
        .word   (3*gy+7)&0x3ff
        .set    gy,gy+1
        .endr

/* 2-cell vscroll (20 column pairs): plane A = 9k, plane B = 13k + 3. */
        .org    0x3700
        .set    gy,0
        .rept   20
        .word   9*gy
        .word   13*gy+3
        .set    gy,gy+1
        .endr

/* Cell hscroll: the table keeps its line layout (4 bytes per line, plane A then plane B); in
 * cell mode the entry for line y is the one at line (y & ~7) (YaVDP: "every 8th line, two words
 * in the horizontal scroll table affect the scrolling of the corresponding cell"). Cell k = y >> 3
 * has plane A = 6 * (k & 3), plane B = 5k + 3 in its first slot. The other seven slots of each
 * cell hold decoys (A = 0x155, B = 0x2aa) that a correct cell-mode reader never uses. */
        .org    0x3800
        .set    gy,0
        .rept   224
        .if     (gy&7)==0
        .word   6*((gy>>3)&3)
        .word   5*(gy>>3)+3
        .else
        .word   0x155
        .word   0x2aa
        .endif
        .set    gy,gy+1
        .endr

        .org    0x5000
        .include "fixtures/raster-toy/z80/driver.inc"

        .org    0x8000-2
        .word   0

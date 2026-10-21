/* SPDX-License-Identifier: MIT
 * Original Genewhip VDP sprite seam ROM (plan GW-02-12, genewhip-seam-sprites-v1). The
 * program runs twelve phases, one rendered field each. A phase writes a sprite table at
 * VRAM 0x1000 (register 5 = 0x08) from a ROM block, selects H40 or H32 through register 12,
 * waits for the VINT that ends its field, then reads the status register twice and stores
 * both words in work RAM. Phase p (1..12) is rendered as field p; the seam checker also
 * samples pixels of the published field at the end of each phase. Expected values are in
 * sprites.expect.json, written from the cited documentation and never from emulator output.
 *
 * Work RAM layout (offsets from 0xFF0000):
 *   0x00 VINT handler entry count
 *   0x10 + 4 * (p - 1)      first status read of phase p (after the field's VINT)
 *   0x12 + 4 * (p - 1)      second status read of phase p (flags cleared by the first)
 *   0xFE completion marker 0x600D
 *
 * Tiles in VRAM: 1-4 solid colour 1, 5-8 solid colour 2, 9-12 solid colour 3 (a sprite of
 * up to four cells uses four consecutive tiles). CRAM: 0 black, 1 green, 2 red, 3 blue.
 * Sprites are one cell high; macro "spr" takes screen coordinates (+128 is added).
 *
 * Phases (screen coordinates; y is the sprite's top line):
 *   1  H40 link order: entries 0 -> 2 -> 1; entry 3 is unreachable
 *   2  H40 exactly 20 sprites on one line          3  H40 21 sprites on one line
 *   4  H32 exactly 16 sprites on one line          5  H32 17 sprites on one line
 *   6  H40 chain of 100 entries (80 per frame)     7  H32 chain of 70 entries (64 per frame)
 *   8  H40 eleven 32-pixel sprites (320 pixel limit)
 *   9  H32 nine 32-pixel sprites (256 pixel limit)
 *   10 H40 thirteen 24-pixel sprites, then a 32-pixel one crossing the 320 pixel limit
 *   11 H40 a sprite with X = 0 between two sprites (masking is unmodeled)
 *   12 H40 cyclic list 0 -> 1 -> 2 -> 1
 */
        .cpu 68000
        .text

        .macro  vdpreg reg,val          /* register write: 0x8000 + reg * 256 + value */
        move.w  #(0x8000+((\reg)<<8)+(\val)),(%a0)
        .endm
        .macro  filltiles val           /* four solid 8x8 tiles (32 longwords) */
        move.w  #31,%d1
1:      move.l  #\val,(%a1)
        dbra    %d1,1b
        .endm
        .macro  spr y,x,w,link,tile     /* one sprite entry, screen coordinates, one cell high */
        .word   (\y)+128
        .byte   (((\w)-1)<<2),(\link)
        .word   \tile
        .word   (\x)+128
        .endm
        .macro  descr regval,first,last /* phase descriptor: register 12 word, size, data offset */
        .word   0x8c00+(\regval)
        .word   (\last)-(\first)
        .word   (\first)-phases
        .endm

        .org    0x0000
        .long   0x00ffff00              /* initial stack in work RAM */
        .long   0x00000200              /* reset vector */
        .org    0x0070
        .long   0x000003c0              /* level 4: rte */
        .long   0x000003c0              /* level 5 */
        .long   0x000003d0              /* level 6 autovector (VINT) */
        .org    0x0100
        .ascii  "SEGA MEGA DRIVE "
        .ascii  "(C)26 GENEWHIP  "
        .ascii  "GENEWHIP SPRITES SEAM"
        .org    0x01f0
        .ascii  "JUE"

        .org    0x0200
start:
        move.w  #0x2700,%sr
        lea     0x00c00004,%a0          /* control port */
        lea     0x00c00000,%a1          /* data port */
        vdpreg  0,0x04
        vdpreg  1,0x14                  /* Mode 5, display off, DMA allowed */
        vdpreg  2,0x30                  /* plane A at VRAM 0xC000 (empty) */
        vdpreg  4,0x07                  /* plane B at VRAM 0xE000 (empty) */
        vdpreg  5,0x08                  /* sprite table at VRAM 0x1000 */
        vdpreg  7,0x00
        vdpreg  11,0x00
        vdpreg  13,0x2e                 /* hscroll table at VRAM 0xB800 (zero) */
        vdpreg  15,2
        vdpreg  16,0x01
        vdpreg  17,0x00
        vdpreg  18,0x00
        move.l  #0xc0000000,(%a0)       /* CRAM write, address 0 */
        move.w  #0x0000,(%a1)
        move.w  #0x00e0,(%a1)
        move.w  #0x000e,(%a1)
        move.w  #0x0e00,(%a1)
        move.l  #0x40200000,(%a0)       /* VRAM write, address 0x20: tile 1 */
        filltiles 0x11111111
        filltiles 0x22222222
        filltiles 0x33333333
        vdpreg  1,0x74                  /* display on, VINT enabled */
        move.w  #0x2000,%sr
        bsr.s   waitvint                /* end of field 0 */
        lea     phases(%pc),%a5
        movea.l %a5,%a2
        lea     0x00ff0010,%a4
        moveq   #11,%d6
phase:
        move.w  (%a0),%d0               /* status read: clears the sprite flags */
        move.w  (%a2)+,(%a0)            /* register 12 */
        move.w  (%a2)+,%d1              /* table bytes */
        move.w  (%a2)+,%d3
        lea     0(%a5,%d3.w),%a3
        move.l  #0x50000000,(%a0)       /* VRAM write, address 0x1000 */
        lsr.w   #1,%d1
        subq.w  #1,%d1
1:      move.w  (%a3)+,(%a1)
        dbra    %d1,1b
        bsr.s   waitvint                /* the field rendered with this phase ends */
        move.w  (%a0),(%a4)+            /* first status read */
        move.w  (%a0),(%a4)+            /* second status read */
        dbra    %d6,phase
        move.w  #0x600d,0x00ff00fe
done:   stop    #0x2000
        bra.s   done

waitvint:
        move.w  0x00ff0000,%d2
1:      stop    #0x2000
        cmp.w   0x00ff0000,%d2
        beq.s   1b
        rts

        .org    0x03c0
handler_rte:
        rte
        .org    0x03d0
vint:
        addq.w  #1,0x00ff0000
        rte

        .org    0x0800
phases:
        descr   0x81,p1,p1_end
        descr   0x81,p2,p2_end
        descr   0x81,p3,p3_end
        descr   0x00,p4,p4_end
        descr   0x00,p5,p5_end
        descr   0x81,p6,p6_end
        descr   0x00,p7,p7_end
        descr   0x81,p8,p8_end
        descr   0x00,p9,p9_end
        descr   0x81,p10,p10_end
        descr   0x81,p11,p11_end
        descr   0x81,p12,p12_end

/* Phase 1: traversal order 0 -> 2 -> 1; entry 2 (x 104) is drawn before entry 1 (x 100), so it
 * wins the overlap 104..107; entry 3 is not on the list and is not drawn. */
p1:
        spr     50,40,1,2,1
        spr     50,100,1,0,5
        spr     50,104,1,1,9
        spr     50,200,1,0,1
p1_end:

/* Phase 2: 20 sprites at x = 8 + 12 i on line 60 (H40 draws all 20). */
p2:
        .set    i,0
        .rept   20
        .set    lk,i+1
        .ifeq   i-19
        .set    lk,0
        .endif
        spr     60,8+12*i,1,lk,1
        .set    i,i+1
        .endr
p2_end:

/* Phase 3: 21 sprites; the 21st (x 248) exceeds the H40 limit of 20 per line. */
p3:
        .set    i,0
        .rept   21
        .set    lk,i+1
        .ifeq   i-20
        .set    lk,0
        .endif
        spr     60,8+12*i,1,lk,1
        .set    i,i+1
        .endr
p3_end:

/* Phase 4: 16 sprites at x = 4 + 12 i (H32 draws all 16). */
p4:
        .set    i,0
        .rept   16
        .set    lk,i+1
        .ifeq   i-15
        .set    lk,0
        .endif
        spr     60,4+12*i,1,lk,1
        .set    i,i+1
        .endr
p4_end:

/* Phase 5: 17 sprites; the 17th (x 196) exceeds the H32 limit of 16 per line. */
p5:
        .set    i,0
        .rept   17
        .set    lk,i+1
        .ifeq   i-16
        .set    lk,0
        .endif
        spr     60,4+12*i,1,lk,1
        .set    i,i+1
        .endr
p5_end:

/* Phase 6: chain of 100 entries in a grid of 20 columns (16 px apart), 16 px rows from
 * line 8; entries 0..79 are visited in H40, entries 80..99 (rows 4 and below) are not. */
p6:
        .set    i,0
        .set    row,0
        .rept   5
        .set    col,0
        .rept   20
        .set    lk,i+1
        .ifeq   i-99
        .set    lk,0
        .endif
        spr     16*row+8,16*col,1,lk,1
        .set    i,i+1
        .set    col,col+1
        .endr
        .set    row,row+1
        .endr
p6_end:

/* Phase 7: chain of 70 entries in a grid of 16 columns; entries 0..63 are visited in H32. */
p7:
        .set    i,0
        .set    row,0
        .rept   5
        .set    col,0
        .rept   16
        .ifle   i-69
        .set    lk,i+1
        .ifeq   i-69
        .set    lk,0
        .endif
        spr     16*row+8,16*col,1,lk,1
        .set    i,i+1
        .endif
        .set    col,col+1
        .endr
        .set    row,row+1
        .endr
p7_end:

/* Phase 8: eleven 32-pixel sprites; ten at x 100 (colour 1) use the 320 pixel budget, the
 * eleventh (x 116, colour 2) is not drawn, so x 140 shows the backdrop. */
p8:
        .set    i,0
        .rept   10
        spr     60,100,4,i+1,1
        .set    i,i+1
        .endr
        spr     60,116,4,0,5
p8_end:

/* Phase 9: nine 32-pixel sprites; eight at x 40 use the 256 pixel budget, the ninth (x 56,
 * colour 2) is not drawn, so x 80 shows the backdrop. */
p9:
        .set    i,0
        .rept   8
        spr     60,40,4,i+1,1
        .set    i,i+1
        .endr
        spr     60,56,4,0,5
p9_end:

/* Phase 10: thirteen 24-pixel sprites at x 100 use 312 of 320 pixels; the 32-pixel sprite at
 * x 140 crosses the limit (8 pixels left). */
p10:
        .set    i,0
        .rept   13
        spr     60,100,3,i+1,1
        .set    i,i+1
        .endr
        spr     60,140,4,0,5
p10_end:

/* Phase 11: entry 1 has X = 0 (screen x -128) between entries 0 and 2. */
p11:
        spr     60,50,1,1,1
        spr     60,-128,1,2,5
        spr     60,70,1,0,9
p11_end:

/* Phase 12: link list 0 -> 1 -> 2 -> 1 -> 2 ... (cyclic); the traversal bound ends it. */
p12:
        spr     100,20,1,1,1
        spr     100,60,1,2,5
        spr     100,100,1,1,9
p12_end:

        .org    0x2000-2
        .word   0

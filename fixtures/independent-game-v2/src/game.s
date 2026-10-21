/* SPDX-License-Identifier: MIT
 * Original, asset-free Genewhip game source. This source is independently
 * authored; v1 is consulted only as a statement of the desired title/start/
 * movement behavior, never as the source text or an emulator-derived oracle.
 */
        .cpu 68000
        .text
        .org    0x0000
        .long   0x00ffff00
        .long   0x00000200
        .org    0x0100
        .ascii  "SEGA MEGA DRIVE "
        .ascii  "(C)26 GENEWHIP  "
        .ascii  "GENEWHIP SOUND GAME"
        .space  29
        .ascii  "GENEWHIP SOUND GAME"
        .space  29
        .ascii  "GM 00000000-00"
        .word   0
        .ascii  "J               "
        .long   0
        .long   0x3fff
        .long   0
        .long   0
        .ascii  "GENEWHIP"
        .space  4
        .ascii  "NO ASSETS"
        .space  3
        .space  40
        .ascii  "JUE             "

        .org    0x0200
reset:
        move.w  #0x2700,%sr
        lea     0x00c00000,%a0           /* VDP data port */
        lea     0x00c00004,%a1           /* VDP control port */
        move.w  #0x8004,(%a1)
        move.w  #0x8144,(%a1)           /* Display enabled; Genesis Mode 5 bit set (Sega register 1 bit 2) */
        move.w  #0x8230,(%a1)
        move.w  #0x8407,(%a1)
        move.w  #0x8f02,(%a1)
        move.w  #0x8700,(%a1)
        move.l  #0xc0000000,(%a1)       /* CRAM entry 0, code 3 */
        move.w  #0x000e,(%a0)
        move.l  #0xc0020000,(%a1)       /* CRAM entry 1, code 3 */
        move.w  #0x0eee,(%a0)
        move.l  #0xc0040000,(%a1)       /* CRAM entry 2, code 3 */
        move.w  #0x00e0,(%a0)
        move.l  #0x40200000,(%a1)       /* VRAM tile 1 pattern at byte address 0x0040 */
        moveq   #7,%d0
tile:
        move.l  #0x11111111,(%a0)
        dbra    %d0,tile
        move.l  #0x40400000,(%a1)       /* VRAM tile 2 pattern at byte address 0x0080 */
        moveq   #7,%d0
marker:
        move.l  #0x22222222,(%a0)
        dbra    %d0,marker
        move.l  #0x40000003,(%a1)       /* Plane A title cells at VRAM 0xc000, code 4 */
        moveq   #9,%d0
title_cells:
        move.w  #1,(%a0)
        dbra    %d0,title_cells

        clr.w   0x00ff0000              /* 0 title, 1 playing */
        clr.w   0x00ff0002              /* source-defined horizontal cell */
        clr.w   0x00ff0004              /* PSG action edge latch */
        move.b  #0x40,0x00a10009

title_wait:
        move.b  #0x00,0x00a10003
        move.b  0x00a10003,%d0
        move.b  #0x40,0x00a10003
        btst    #5,%d0                  /* active-low Start */
        bne.s   title_wait
        move.w  #1,0x00ff0000
        move.l  #0x40000003,(%a1)       /* Clear title cells at VRAM 0xc000 */
        moveq   #9,%d0
clear_title:
        clr.w   (%a0)
        dbra    %d0,clear_title

play:
        move.b  0x00a10003,%d0          /* TH high: directions and B/C */
        btst    #2,%d0                  /* active-low left */
        bne.s   check_right
        subq.w  #1,0x00ff0002
        bpl.s   check_right
        clr.w   0x00ff0002
check_right:
        btst    #3,%d0                  /* active-low right */
        bne.s   check_sound
        addq.w  #1,0x00ff0002
        cmpi.w  #39,0x00ff0002
        ble.s   check_sound
        move.w  #39,0x00ff0002

check_sound:
        btst    #4,%d0                  /* active-low B triggers one PSG note */
        bne.s   sound_released
        tst.w   0x00ff0004
        bne.s   draw_wait
        move.w  #1,0x00ff0004
        move.b  #0x84,0x00c00011        /* tone 0 period low nibble */
        move.b  #0x02,0x00c00011        /* tone 0 period high bits */
        move.b  #0x90,0x00c00011        /* tone 0 audible volume */
        bra.s   draw_wait
sound_released:
        clr.w   0x00ff0004

draw_wait:
        move.w  (%a1),%d0
        btst    #3,%d0
        beq.s   draw_wait
        move.l  #0x42000003,(%a1)       /* Clear play row at VRAM 0xc200, code 4 */
        moveq   #39,%d1
clear_player_row:
        clr.w   (%a0)
        dbra    %d1,clear_player_row
        moveq   #0,%d1
        move.w  0x00ff0002,%d1
        add.w   #64,%d1
        lsl.w   #1,%d1
        swap    %d1
        move.l  #0x42000003,%d2
        add.l   %d1,%d2
        move.l  %d2,(%a1)               /* Marker at VRAM 0xc280 + position * 2 */
        move.w  #2,(%a0)
        bra.w   play

        .org    0x3fff
        .byte   0xff

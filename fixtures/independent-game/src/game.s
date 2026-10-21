/* SPDX-License-Identifier: MIT
 * Original Genewhip asset-free game candidate, written for Phase 1 plan 01-11.
 * Graphics are generated from these instructions; no third-party assets/code.
 */
        .cpu 68000
        .text
        .org    0x0000
        .long   0x00ffff00              /* initial stack in work RAM */
        .long   0x00000200              /* reset vector; code starts at 0x200 */
        .org    0x0100
        .ascii  "SEGA MEGA DRIVE "
        .ascii  "(C)26 GENewhip  "
        .ascii  "GENEWHIP GAME"
        .space  35
        .ascii  "GENEWHIP GAME"
        .space  35
        .ascii  "GM 00000000-00"
        .word   0
        .ascii  "J               "
        .long   0x00000000
        .long   0x00003fff              /* filled with final ROM size below */
        .long   0x00000000
        .long   0x00000000
        .ascii  "GENEWHIP"
        .space  4
        .ascii  "NO ASSETS"
        .space  3
        .space  40
        .ascii  "JUE             "

        .org    0x0200
start:
        move.w  #0x2700,%sr
        lea     0x00c00000,%a0           /* VDP data */
        lea     0x00c00004,%a1           /* VDP control */
        move.w  #0x8004,(%a1)            /* disable H interrupt */
        move.w  #0x8140,(%a1)            /* display on, 28-cell mode */
        move.w  #0x8230,(%a1)            /* plane A at VRAM 0xc000 */
        move.w  #0x8407,(%a1)            /* plane B at VRAM 0xe000 */
        move.w  #0x8f02,(%a1)            /* VRAM auto-increment */
        move.w  #0x8700,(%a1)            /* backdrop uses palette 0, color 0 */
        move.l  #0xc0000000,(%a1)        /* CRAM color zero */
        move.w  #0x000e,(%a0)            /* dark blue backdrop */
        move.l  #0xc0000008,(%a1)        /* CRAM color one */
        move.w  #0x0eee,(%a0)            /* white tile */
        move.l  #0xc0000010,(%a1)        /* CRAM color two */
        move.w  #0x00e0,(%a0)            /* green marker */

        move.l  #0x40000080,(%a1)        /* tile 1 pattern at VRAM 32 */
        moveq   #7,%d0
1:      move.l  #0x11111111,(%a0)        /* generated solid tile */
        dbra    %d0,1b
        move.l  #0x400000c0,(%a1)        /* tile 2 pattern at VRAM 48 */
        moveq   #7,%d0
2:      move.l  #0x22222222,(%a0)        /* generated marker tile */
        dbra    %d0,2b
        move.l  #0x40030000,(%a1)        /* plane A map at VRAM 0xc000 */
        moveq   #9,%d0
3:      move.w  #0x0001,(%a0)            /* title card: bright ten-cell stripe */
        dbra    %d0,3b

        clr.w   0x00ff0000              /* title state: player position */
        move.b  #0x40,0x00a10009        /* configure controller TH output */
title:
        move.b  #0x00,0x00a10003        /* TH low exposes A and Start */
        move.b  0x00a10003,%d0
        move.b  #0x40,0x00a10003        /* restore TH high */
        btst    #5,%d0                  /* Start pressed (active low) */
        bne.s   title

        move.l  #0x40030000,(%a1)       /* clear the title stripe */
        moveq   #9,%d0
4:      clr.w   (%a0)
        dbra    %d0,4b
        move.w  #0x0000,0x00ff0002      /* game state: position starts at zero */
        bra.s   draw_player

play:
        move.b  0x00a10003,%d0          /* TH high exposes directions and B/C */
        btst    #2,%d0                  /* left is active low */
        bne.s   5f
        subq.w  #1,0x00ff0002
        bpl.s   5f
        clr.w   0x00ff0002
5:      btst    #3,%d0                  /* right is active low */
        bne.s   draw_player
        addq.w  #1,0x00ff0002
        cmpi.w  #39,0x00ff0002
        ble.s   draw_player
        move.w  #39,0x00ff0002

draw_player:
wait_vblank:
        move.w  (%a1),%d0
        btst    #3,%d0
        beq.s   wait_vblank
        move.l  #0x40030200,(%a1)       /* plane row one, first cell */
        moveq   #39,%d1
6:      clr.w   (%a0)
        dbra    %d1,6b
        moveq   #0,%d1
        move.w  0x00ff0002,%d1
        add.w   #64,%d1
        lsl.w   #1,%d1
        move.l  #0x40030200,%d2
        add.l   %d1,%d2
        move.l  %d2,(%a1)
        move.w  #0x0002,(%a0)            /* visible player marker */
        bra.s   play
        .org    0x3fff
        .byte   0xff                    /* 16 KiB ordinary linear cartridge */

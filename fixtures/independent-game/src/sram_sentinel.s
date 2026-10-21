/* SPDX-License-Identifier: MIT
 * Authored bus-hook calibration ROM; never used as a candidate fixture.
 */
        .cpu 68000
        .text
        .org    0x0000
        .long   0x00ffff00
        .long   0x00000200
        .org    0x0100
        .ascii  "SEGA MEGA DRIVE "
        .ascii  "(C)26 GENewhip  "
        .ascii  "GW TRACE SENTINEL"
        .space  31
        .ascii  "GW TRACE SENTINEL"
        .space  31
        .ascii  "GM 00000000-00"
        .word   0
        .ascii  "J               "
        .long   0x00000000
        .long   0x00003fff
        .long   0x00000000
        .long   0x00000000
        .ascii  "GENEWHIP"
        .space  4
        .ascii  "TRACE ONLY"
        .space  2
        .space  40
        .ascii  "JUE             "

        .org    0x0200
start:
        move.w  #0x55aa,0x00200000
        move.w  0x00200000,%d0
        move.b  #0x01,0x00a130f1
        move.b  0x00a130f1,%d1
1:      bra.s   1b
        .org    0x3fff
        .byte   0xff

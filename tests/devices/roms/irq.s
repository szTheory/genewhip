/* SPDX-License-Identifier: MIT
 * Original Genewhip VDP interrupt seam ROM (plan GW-02-10, genewhip-seam-irq-v1). The
 * program drives the vertical and horizontal interrupts through enable, mask and
 * priority situations and records what its level-4 and level-6 handlers and its main
 * code observed in work RAM at 0xFF0100.. for the seam checker. Expected values are in
 * irq.expect.json, written from the cited documentation and never from emulator output.
 *
 * Work RAM layout (offsets from 0xFF0000):
 *   0x100 VINT handler entry count        0x102 HINT handler entry count
 *   0x108 SR at the latest VINT entry
 *   0x10A SR at the latest HINT entry
 *   0x110 VINT count when the third VINT had been handled (VINT-only phase)
 *   0x112 0x114 0x116 HINT entries between two consecutive VINT entries, register 10 =
 *         0, 7, 223 (first window);  0x118 0x11A 0x11C the next window
 *   0x120 flag: counts strictly decrease with the period and are nonzero
 *   0x122 0x124 0x126 flags: count within one of 224/(N+1) (N = 0, 7), count 1 or 2 (N = 223)
 *   0x130 HINT entries before the first VINT entry when both were pending (0 = VINT first)
 *   0x132 flag: the pending HINT ran after the VINT handler returned
 *   0x140 status word once VINT read set under mask 6
 *   0x142 status word after a delay under mask 6
 *   0x144 VINT entries during that delay (mask 6 blocks level 6)
 *   0x146 VINT entries after lowering the mask and a short settle (MOVE to SR)
 *   0x148 VINT entries counted immediately after the mask-lowering instruction
 *   0x150 VINT entries while IE0 was clear and VINT pending
 *   0x152 VINT entries after enabling IE0 and a short settle
 *   0x154 VINT entries counted immediately after the IE0 write
 *   0x160 ordered markers: 0x1111 main, 0x0006 VINT handler, 0x2222 main after RTE
 *   0x168 SR read by main after the RTE
 *   0x180.. log of every VINT entry (0x0006), bounded by the number of fields run
 *   0x170 VINT entries between the sync point and the instruction after the first STOP
 *   0x172 marker 0x3333 written by the instruction after the first STOP
 *   0x174 VINT entries between the sync point and the instruction after the second STOP
 *   0x1FE completion marker 0x600d
 *   0x200 table: HINT entry count sampled at VINT entry number i, at 0x200 + 2 * i
 *   0x240 table: V/H counter word read at VINT entry number i, at 0x240 + 2 * i
 *
 * Register use: d7 is handler scratch; a4 is the shared marker log pointer; a5 the
 * table base; a0 the VDP control port. Main code uses d0-d6 and a1.
 */
        .cpu 68000
        .text

        .macro  vdpreg reg,val          /* register write: 0x8000 + reg * 256 + value */
        move.w  #(0x8000+((\reg)<<8)+(\val)),(%a0)
        .endm
        .macro  pollvint                /* wait until status bit 7 (VINT) reads set */
1:      move.w  (%a0),%d0
        btst    #7,%d0
        beq.s   1b
        .endm
        .macro  waitvints n             /* wait for n more VINT handler entries */
        move.w  0x00ff0100,%d3
        addq.w  #\n,%d3
1:      cmp.w   0x00ff0100,%d3
        bgt.s   1b
        .endm
        .macro  settle                  /* a bounded wait of about 500 clocks */
        move.w  #40,%d1
1:      dbf     %d1,1b
        .endm
        .macro  longwait                /* a bounded wait of about 30000 clocks */
        move.w  #3000,%d1
1:      dbf     %d1,1b
        .endm
        .macro  delta cur,base,slot     /* slot = word at cur minus the word in base register */
        move.w  \cur,%d5
        sub.w   \base,%d5
        move.w  %d5,\slot
        .endm
        .macro  hintwin n,w1,w2         /* HINT entries between consecutive VINT entries */
        move.w  #0x2700,%sr
        vdpreg  10,\n
        move.w  0x00ff0100,%d2          /* c: VINT entries so far */
        move.w  #0x2000,%sr
        waitvints 4                     /* VINT entries c+1 .. c+4 */
        move.w  #0x2700,%sr
        move.w  %d2,%d4
        add.w   %d4,%d4                 /* 2 * c */
        move.w  6(%a5,%d4.w),%d5        /* table[c+3] */
        sub.w   4(%a5,%d4.w),%d5        /* minus table[c+2] */
        move.w  %d5,\w1
        move.w  8(%a5,%d4.w),%d5        /* table[c+4] */
        sub.w   6(%a5,%d4.w),%d5
        move.w  %d5,\w2
        .endm

        .org    0x0000
        .long   0x00ffff00              /* initial stack in work RAM */
        .long   0x00000200              /* reset vector */
        .org    0x0070
        .long   0x00000700              /* level 4 autovector (HINT): hint below */
        .long   0x00000710              /* level 5: never raised by the VDP: spurious below */
        .long   0x00000720              /* level 6 autovector (VINT): vint below */
        .org    0x0100
        .ascii  "SEGA MEGA DRIVE "
        .ascii  "(C)26 GENEWHIP  "
        .ascii  "GENEWHIP IRQ SEAM"
        .org    0x01f0
        .ascii  "JUE"

        .org    0x0200
start:
        lea     0x00c00004,%a0          /* control port */
        lea     0x00ff0180,%a4          /* marker log pointer */
        lea     0x00ff0200,%a5          /* table base */

        /* Phase A: VINT only. The handler counts fields; three entries, then mask 7. */
        vdpreg  1,0x64                  /* display on, IE0 (VINT enable), Mode 5 */
        move.w  #0x2000,%sr             /* mask 0: interrupts accepted */
wait:
        cmpi.w  #3,0x00ff0100
        blt.s   wait
        move.w  #0x2700,%sr             /* mask 7: no further interrupts */
        move.w  0x00ff0100,0x00ff0110

        /* Phase B: HINT entries between consecutive VINT entries for three register-10
         * values (IE1 on). */
        vdpreg  0,0x14                  /* IE1 (HINT enable) */
        hintwin 0,0x00ff0112,0x00ff0118
        hintwin 7,0x00ff0114,0x00ff011a
        hintwin 223,0x00ff0116,0x00ff011c
        clr.w   0x00ff0120              /* flags: periods and counts */
        move.w  0x00ff0112,%d2
        move.w  0x00ff0114,%d3
        move.w  0x00ff0116,%d4
        cmp.w   %d3,%d2
        ble.s   1f
        cmp.w   %d4,%d3
        ble.s   1f
        tst.w   %d4
        beq.s   1f
        move.w  #1,0x00ff0120
1:      clr.w   0x00ff0122
        cmpi.w  #223,%d2
        blt.s   2f
        cmpi.w  #225,%d2
        bgt.s   2f
        move.w  #1,0x00ff0122
2:      clr.w   0x00ff0124
        cmpi.w  #27,%d3
        blt.s   3f
        cmpi.w  #29,%d3
        bgt.s   3f
        move.w  #1,0x00ff0124
3:      clr.w   0x00ff0126
        cmpi.w  #1,%d4
        blt.s   4f
        cmpi.w  #2,%d4
        bgt.s   4f
        move.w  #1,0x00ff0126
4:

        /* Phase C: both pending (HINT every line, VINT at line 224), mask 7 raised, then
         * lowered: the level-6 interrupt is taken first. */
        vdpreg  10,0
        pollvint
        move.w  0x00ff0102,%d2          /* HINT entries so far */
        move.w  0x00ff0100,%d3          /* VINT entries so far */
        move.w  #0x2000,%sr
        settle
        move.w  %d3,%d4
        add.w   %d4,%d4
        move.w  2(%a5,%d4.w),%d5        /* HINT entry count at the first new VINT entry */
        sub.w   %d2,%d5
        move.w  %d5,0x00ff0130
        clr.w   0x00ff0132
        move.w  0x00ff0102,%d5
        cmp.w   %d2,%d5
        ble.s   5f
        move.w  #1,0x00ff0132
5:

        /* Phase D: mask 6 blocks the level-6 interrupt while the status VINT bit reads set. */
        move.w  #0x2700,%sr
        vdpreg  0,0x04                  /* IE1 clear */
        move.w  #0x2000,%sr
        waitvints 1                     /* acknowledges any VINT left pending */
        move.w  #0x2600,%sr             /* mask 6 */
        pollvint
        move.w  (%a0),0x00ff0140
        move.w  0x00ff0100,%d2
        longwait
        move.w  (%a0),0x00ff0142
        delta   0x00ff0100,%d2,0x00ff0144
        move.w  #0x2000,%sr             /* MOVE to SR lowers the mask */
        delta   0x00ff0100,%d2,0x00ff0148
        settle
        delta   0x00ff0100,%d2,0x00ff0146

        /* Phase E: enabling IE0 while VINT is pending. */
        move.w  #0x2700,%sr
        vdpreg  1,0x44                  /* IE0 clear */
        move.w  #0x2000,%sr
        pollvint
        move.w  0x00ff0100,%d2
        longwait
        delta   0x00ff0100,%d2,0x00ff0150
        vdpreg  1,0x64                  /* IE0 set while VINT is pending */
        delta   0x00ff0100,%d2,0x00ff0154
        settle
        delta   0x00ff0100,%d2,0x00ff0152

        /* Phase F: marker order across the interrupt and RTE. */
        move.w  #0x2700,%sr
        lea     0x00ff0160,%a4
        pollvint
        move.w  0x00ff0100,%d2
        move.w  #0x1111,(%a4)+
        move.w  #0x2000,%sr
7:      cmp.w   0x00ff0100,%d2
        bge.s   7b                      /* until the handler has run */
        move.w  #0x2222,(%a4)+
        move.w  %sr,0x00ff0168

        /* Phase G: STOP waits for VINT. Synchronize on a handler run so the next VINT is a
         * whole field away, then STOP: the handler runs once and execution continues after
         * the STOP (stacked PC), so two entries have occurred since the sync point and three after the second STOP. */
        move.w  #0x2700,%sr
        lea     0x00ff01e0,%a4          /* keep the Phase F markers intact */
        move.w  0x00ff0100,%d2
        move.w  #0x2000,%sr
8:      cmp.w   0x00ff0100,%d2
        bge.s   8b
        stop    #0x2000
        move.w  #0x3333,0x00ff0172
        delta   0x00ff0100,%d2,0x00ff0170
        stop    #0x2000
        delta   0x00ff0100,%d2,0x00ff0174
        move.w  #0x2700,%sr
        move.w  #0x600d,0x00ff01fe      /* completion marker */
done:   bra.s   done

        .org    0x0700                  /* handler addresses are fixed: no relocations in the image */
hint:
        addq.w  #1,0x00ff0102
        move.w  %sr,0x00ff010a
        rte
        .org    0x0710
spurious:
        rte

        .org    0x0720
vint:
        addq.w  #1,0x00ff0100
        move.w  0x00ff0100,%d7          /* entry number i */
        add.w   %d7,%d7
        move.w  0x00ff0102,0(%a5,%d7.w) /* table[i] = HINT entries so far */
        move.w  0x00c00008,0x40(%a5,%d7.w) /* V/H counter word at entry i */
        move.w  %sr,0x00ff0108
        move.w  #0x0006,(%a4)+
        rte

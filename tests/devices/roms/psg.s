/* SPDX-License-Identifier: MIT
 * Original Genewhip PSG seam ROM (genewhip-seam-psg-v1). Expectations come
 * from the SN76489 notes at smspower.org and the PSG description at
 * plutiedev.com/psg, never from emulator output. The phase id in work RAM
 * marks the guest's six test windows; source-ordered port writes mark their
 * exact PCM boundaries in the audio trace.
 */
        .cpu 68000
        .text
        .org    0x0000
        .long   0x00ffff00
        .long   0x00000200
        .org    0x0100
        .ascii  "SEGA MEGA DRIVE "
        .ascii  "(C)26 GENEWHIP  "
        .ascii  "GENEWHIP PSG SEAM"
        .org    0x01f0
        .ascii  "JUE"
        .org    0x0200
start:
        move.b  #0x9f,0x00c00011        /* mute all four voices (byte writes only) */
        move.b  #0xbf,0x00c00011
        move.b  #0xdf,0x00c00011
        move.b  #0xff,0x00c00011

        move.w  #1,0x00ff0100
        move.b  #0x80,0x00c00011        /* tone 0, N=0x80 */
        move.b  #0x08,0x00c00011
        move.b  #0x90,0x00c00011
        bsr     wait_window
        move.b  #0x9f,0x00c00011

        move.w  #2,0x00ff0100
        move.b  #0xa0,0x00c00011        /* tone 1, N=0xc0 */
        move.b  #0x0c,0x00c00011
        move.b  #0xb0,0x00c00011
        bsr     wait_window
        move.b  #0xbf,0x00c00011

        move.w  #3,0x00ff0100
        move.b  #0xc0,0x00c00011        /* tone 2, N=0x100 */
        move.b  #0x10,0x00c00011
        move.b  #0xd0,0x00c00011
        bsr     wait_window
        move.b  #0xdf,0x00c00011

        move.w  #4,0x00ff0100
        move.b  #0x9f,0x00c00011
        move.b  #0xbf,0x00c00011
        move.b  #0xdf,0x00c00011
        move.b  #0xff,0x00c00011
        bsr     wait_window

        move.w  #5,0x00ff0100
        move.b  #0xe4,0x00c00011        /* white noise, fixed rate 0 */
        move.b  #0xf0,0x00c00011
        bsr     wait_window
        move.b  #0xff,0x00c00011

        move.w  #6,0x00ff0100
        move.b  #0xe3,0x00c00011        /* periodic noise, tone-2 clock */
        move.b  #0xf0,0x00c00011
        bsr     wait_window
        move.b  #0xff,0x00c00011
        move.w  #0x600d,0x00ff01fe
done:   stop    #0x2000
        bra.s   done

wait_window:
        moveq   #9,%d1
1:      move.w  #60000,%d0
2:      dbra    %d0,2b
        dbra    %d1,1b
        rts

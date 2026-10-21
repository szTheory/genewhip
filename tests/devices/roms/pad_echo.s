/* SPDX-License-Identifier: MIT
 * Original Genewhip pad-echo ROM (plan GW-02-07). Configures both controller
 * ports with TH as an output driven high, then loops forever: read both data
 * ports into work RAM and show them as the backdrop colour.
 *
 * Work RAM layout (the contract tests read these):
 *   0xFF0000  port 0 data byte      0xFF0001  port 1 data byte
 *   0xFF0002  copy of port 1 byte   0xFF0003  copy of port 0 byte
 * so the word at 0xFF0002 is (port 1 << 8) | port 0 and is written to CRAM
 * index 1, the backdrop colour (register 7 = 1). Every pressed button of either
 * port that changes a CRAM colour bit therefore changes the published field.
 * Expectations are computed in the tests from the documented active-low pad
 * protocol, not captured from Genewhip output.
 */
        .cpu 68000
        .text
        .org    0x0000
        .long   0x00ffff00              /* initial stack in work RAM */
        .long   0x00000200              /* reset vector */
        .org    0x0100
        .ascii  "SEGA MEGA DRIVE "
        .ascii  "(C)26 GENEWHIP  "
        .ascii  "GENEWHIP PAD ECHO"
        .org    0x01f0
        .ascii  "JUE"

        .org    0x0200
start:
        move.w  #0x8f02,0x00c00004      /* register 15: auto-increment 2 */
        move.w  #0x8701,0x00c00004      /* register 7: backdrop is CRAM index 1 */
        move.b  #0x40,0x00a10009        /* port 0 control: TH is an output */
        move.b  #0x40,0x00a1000b        /* port 1 control: TH is an output */
        move.b  #0x40,0x00a10003        /* port 0 data: TH high */
        move.b  #0x40,0x00a10005        /* port 1 data: TH high */

loop:
        move.b  0x00a10003,0x00ff0000   /* port 0 */
        move.b  0x00a10005,0x00ff0001   /* port 1 */
        move.b  0x00ff0000,0x00ff0003
        move.b  0x00ff0001,0x00ff0002
        move.l  #0xc0020000,0x00c00004  /* CRAM write, address 2 (index 1) */
        move.w  0x00ff0002,0x00c00000
        bra.s   loop

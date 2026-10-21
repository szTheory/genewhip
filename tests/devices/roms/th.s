/* SPDX-License-Identifier: MIT
 * Original Genewhip three-button TH-protocol seam ROM (plan GW-02-17, genewhip-seam-th-v1).
 * Straight-line code only: both controller ports are configured with TH as an
 * output, each TH phase of each port is read into work RAM at 0xFF0000 and the
 * results are judged by th.expect.json, written from the plutiedev controllers
 * and io-ports pages and never from emulator output.
 *
 * Work RAM layout:
 *   0xFF0000 port 1 read, TH high    0xFF0001 port 1 read, TH low
 *   0xFF0002 port 2 read, TH low     0xFF0003 port 2 read, TH high
 *   0xFF0004 port 1 read, TH input    0xFF0005 port 2 read, TH input
 *   0xFF0006 version register 0xA10001
 *   0xFF00FE completion marker 0x600d
 */
        .cpu 68000
        .text
        .org    0x0000
        .long   0x00ffff00              /* initial stack in work RAM */
        .long   0x00000200              /* reset vector */
        .org    0x0100
        .ascii  "SEGA MEGA DRIVE "
        .ascii  "(C)26 GENEWHIP  "
        .ascii  "GENEWHIP TH SEAM"
        .org    0x01f0
        .ascii  "JUE"

        .org    0x0200
start:
        move.b  #0x40,0x00a10009        /* port 1 control: TH is an output */
        move.b  #0x40,0x00a1000b        /* port 2 control: TH is an output */
        move.b  #0x40,0x00a10003        /* port 1 data: TH high */
        move.b  #0x40,0x00a10005        /* port 2 data: TH high */
        move.b  0x00a10003,0x00ff0000   /* port 1, TH high */
        move.b  0x00a10005,0x00ff0003   /* port 2, TH high */
        move.b  #0x00,0x00a10003        /* port 1 data: TH low */
        move.b  #0x00,0x00a10005        /* port 2 data: TH low */
        move.b  0x00a10003,0x00ff0001   /* port 1, TH low */
        move.b  0x00a10005,0x00ff0002   /* port 2, TH low */

        move.b  #0x00,0x00a10009        /* port 1 control: TH is an input */
        move.b  #0x00,0x00a1000b        /* port 2 control: TH is an input */
        move.b  0x00a10003,0x00ff0004   /* port 1, TH input */
        move.b  0x00a10005,0x00ff0005   /* port 2, TH input */
        move.b  0x00a10001,0x00ff0006   /* version register */

        move.w  #0x600d,0x00ff00fe      /* completion marker */
done:   bra.s   done

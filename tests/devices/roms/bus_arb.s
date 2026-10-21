/* SPDX-License-Identifier: MIT
 * Original Genewhip BUSREQ/RESET model-conformance seam.
 * Sega Technical Overview 1.00 p.76: word D8/even-byte bit 0 clear means
 * granted. Contrary Sound Software Manual (1992) p.2 remains unresolved;
 * see 03-BUSREQ-SOURCE-RECONCILIATION.md. No output-derived expectations.
 */
.org 0
.long 0x00ffff00,0x00000200
.org 0x0100
.ascii "SEGA MEGA DRIVE "
.ascii "(C)26 GENEWHIP  "
.ascii "GENEWHIP BUS ARB"
.org 0x01f0
.ascii "JUE"
.org 0x0200
/* Preserve unknown status before any request and during reset. Neither value
 * controls guest execution. */
.word 0x33fc,0x0100
.long 0x00a11200
.word 0x3039
.long 0x00a11100
.word 0x33c0
.long 0x00ff00a0
.word 0x33fc,0x0000
.long 0x00a11200
.word 0x3039
.long 0x00a11100
.word 0x33c0
.long 0x00ff00a2
.word 0x33fc,0x0100
.long 0x00a11100
/* Reset is held. ROM reads advance past the next Z80 edge, granting the
 * request before the first upload store. Unroll using supported MOVE.B
 * absolute-long,absolute-long (seven 28-tick transfers per byte). */
.set upload_index,0
.rept 26
.word 0x13f9
.long 0x0700+upload_index
.long 0x00a00000+upload_index
.set upload_index,upload_index+1
.endr
/* Seed while granted. The Z80 NEVER writes the sentinel; an erroneously
 * accepted 5A cannot be masked by a later Z80 store. */
.word 0x13fc,0x00a5
.long 0x00a01003
.word 0x207c
.long 0x00ff0100
.word 0x227c
.long 0x00a11100
.word 0x7400
.word 0x33fc,0x0100
.long 0x00a11200
.word 0x33fc,0x0000
.long 0x00a11100
/* Reset path: 13+4+13+9+13+10+7+13 = 82 Z80 T states (1230 master
 * ticks), then JR $ repeats with
 * fetch 4T, displacement read 3T, internal delay 5T: 12T per instruction,
 * NOT a single machine cycle. Each 68000 transfer costs 28 master ticks.
 * Source-derived model arithmetic (not captured output): reset vectors 112;
 * pre-upload transfers 868; 26 uploads * 196; seed 140; poll setup 196;
 * RESET release 140; BUSREQ release 140 => release commit 6692. First strict
 * 15-tick edge is 6705. Startup 82T ends at 7935. Following 101 NOPs (2828),
 * attempted write (140), unknown read/store (112+112), request (140) gives
 * request tick 10024. JR iteration 11 starts 9915: boundaries 9915, 9975,
 * 10020, 10095. Request is inside the 5T internal delay, so the first (A1)
 * read commits 56 ticks later at 10080, before grant at 10095. The next
 * recorded read must be clear. This establishes busy-then-granted without
 * assuming the whole 12T instruction is one machine cycle. */
.rept 101
.word 0x4e71
.endr
/* Ungranted write and source-unknown read before another BUSREQ. */
.word 0x13fc,0x005a
.long 0x00a01003
.word 0x1039
.long 0x00a00010
.word 0x13c0
.long 0x00ff00a5
.word 0x33fc,0x0100
.long 0x00a11100
/* Record every even-byte status poll. Runner/checker rejects missing grant
 * or an observation count beyond the 64-slot log. */
poll:
.word 0x1011,0x10c0,0x5242,0x33c2
.long 0x00ff0080
.word 0x0800,0x0000,0x66ee
.set result_index,0
.rept 4
.word 0x1039
.long 0x00a01000+result_index
.word 0x13c0
.long 0x00ff0090+result_index
.set result_index,result_index+1
.endr
/* Reset while held; allow the complete startup path after release. */
.word 0x33fc,0x0000
.long 0x00a11200
.word 0x33fc,0x0100
.long 0x00a11200
.word 0x33fc,0x0000
.long 0x00a11100
.rept 100
.word 0x4e71
.endr
.word 0x33fc,0x0100
.long 0x00a11100
restart_poll:
.word 0x1039
.long 0x00a11100
.word 0x0800,0x0000,0x66f4
.set result_index,0
.rept 4
.word 0x1039
.long 0x00a01000+result_index
.word 0x13c0
.long 0x00ff0094+result_index
.set result_index,result_index+1
.endr
.word 0x33fc,0x0000
.long 0x00a11100
.word 0x60fe
.org 0x0700
z80_start:
.include "tests/devices/roms/z80/bus_arb.inc"
z80_end:
.if z80_end-z80_start != 26
.error "update upload length and timing proof with payload changes"
.endif
.org 0x07fe
.word 0

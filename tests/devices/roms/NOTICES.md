# Original seam ROM notices

Every `*.s` file in this directory is original source solely authored for Genewhip under the repository MIT license (`../../../LICENSE`). Each ROM is a small 68000 program (straight-line port sequences, or for `pad_echo` a bounded polling loop) that writes documented VDP or I/O port sequences and records the observed values in work RAM; no third-party code, data, graphics or sound is included, and the ROMs are not derived from any emulator output.

`psg.s` is an original sound-register sequence. Its tone, noise and LFSR expectations are derived from the cited SN76489/PSG documentation and its source-defined periods; no emulator output or third-party implementation is used as an oracle.

`bus_arb.s` is an original 68000/Z80 arbitration seam. Its original Z80 payload is `z80/bus_arb.s`, assembled with the pinned `z80-elf-as` into `z80/bus_arb.inc` by the nested build stage. Arbitration expectations are based on the cited Sega Technical Overview p.76 while retaining the contrary 1992 Sound Software Manual statement as unresolved. The seam demonstrates conformance to that selected model, not physical hardware truth. Its source derives the polling phase from guest transfer costs and individual Z80 cycle boundaries; no observation supplies an expected byte.

`z80_bank.s` and its `z80/z80_bank.s` payload are original bank-window and PSG guest sources. The marker bytes are authored in the ROM source at bank-one offset 0x8000; expectations follow the nine serial bank-bit writes and guest LDIR copy. PSG frequency follows the documented SN76489 formula and source-defined period. The one-T-state bank-window wait is model-scoped, not a hardware claim.

`z80_guest.s` and `z80/z80_guest.s` are original interrupt/reset guest sources. Expected values are derived from the authored Z80 program and Zilog UM0080; the VBlank pulse width is the named 32-T-state A7 assumption, not a measured Genesis value.

`bus_arb_midinstr.s` and its `z80/bus_arb_midinstr.s` payload are original arbitration sources. The ROM seeds stack bytes independently, then records them across grant and release; the stack order expectation follows Zilog UM0080 PUSH behavior. Separate contract tests interrupt PUSH and LDIR between Z80 micro-operations.

`fm_script.s` and `z80/fm_script.s` are original YM2612 register-script sources. The Z80 IM1 handler advances one authored register tuple on each VBlank, polls the busy bit before writing, and records timer status observations. The opening audible patch uses the Sega Genesis Software Manual's YM2612 register map and field descriptions (pp. 10–16; archival scan/transcription at https://www.smspower.org/maxim/Documents/YM2612); the D50 register-boundary experiments retain their Plutiedev register-reference cases. The patch is a channel-0 algorithm-7 carrier at FNUM/block 0x284 with maximum attack; eight LFO-off writes preserve an audible interval before the original D50 sequence. The final channel-four reset-coupling probe remains an unknown provisional implementation behavior under the approved D-42 amendment. `dac.s` and `z80/dac.s` are original streaming sources; their 256-byte triangle PCM table is defined by assembler expressions and their loop timing is derived from Zilog UM0080 instruction T-state tables. Neither seam's FM/PCM output is an oracle.

## Assets and tool provenance

- No bundled assets are present.
- ROMs are built with the source-built GNU Binutils 2.47 `m68k-elf-as` pinned by `fixtures/independent-game/toolchain.lock` through `scripts/fixtures/build-original-roms.sh`. No Binutils source or executable is bundled or linked into a ROM; upstream GPL-3.0-or-later notices are identified by path and digest in that lock.
- Expectations for each ROM live in `NAME.expect.json`, authored from the cited documentation, never captured from Genewhip output.

# Pinned CPU semantic evidence

These tests compare Genewhip's 68000 data-movement, arithmetic, control-flow, bit,
logic, shift/rotate and status-register behavior with
[SingleStepTests/m68000](https://github.com/SingleStepTests/m68000/tree/64b253116a3de04aaac4346c43680960dc9b67e5)
revision `64b253116a3de04aaac4346c43680960dc9b67e5`. The corpus was generated
with MAME's microcoded M68000. It is **oracle agreement, not independently
measured hardware evidence**. Upstream does not give an exact MAME generator
revision; that ancestry detail remains unknown. The original Genewhip system
diagnostic has its own authored expectations and is a separate evidence class.

## Admission and identity

`manifest.json` identifies exact upstream binary paths, sizes, SHA256 hashes,
license, decoder and README hashes. The MIT license was reviewed before data
admission. `upstream/LICENSE` retains the complete notice. `upstream/decode.py`
and `upstream/README.md` are unmodified pinned copies; decoder review found only
binary parsing and explicit local conversion, no network or package installation.
Only its parsing functions are used, after binary hash verification. No MAME CPU
code is included. Test data is not linked into or required by the installed core.

`selected.json` contains the first 32 decoded records from each named source file in
`manifest.json`, preserving source order and all fields, including unsupported cases.
Selection is by index, never by observed pass/fail. The scheduled lane runs every
record of every named source. Every processed record receives an outcome;
`--report` retains all rows, a `sub_forms` object with per-sub-form
pass/fail/unsupported/total counts per source, and the denominators.

Each source row names its `family` and `sub_forms`: the number of records per
mnemonic form (for example `ADD`, `ADDI`, `ADDQ` inside `ADD.b`), classified from
the opcode word. Register, immediate and memory variants of one mnemonic are separate
sub-forms (`BTST.reg`, `BTST.imm`, `ASL`, `ASL.mem`). The sum must equal the source's `tests`, a decoded record that
falls outside its source's declared sub-forms is an infrastructure error, and the
full lane requires the decoded totals to match the manifest. A mismatch is reported
as `sub-form denominator mismatch`.

The upstream tree has 127 binary files. Those not named in `manifest.json` are
outside this admission, are not run, and have an unknown record denominator here.
That includes upstream's unresolved **TAS** five-cycle read-modify-write timing
and **TRAPV** S-bit triggering caveats. Neither is counted as a pass.

### Scheduled-lane denominators

<!-- counts:begin -->
| Source | Records | Pass | Fail | Unsupported: user/trace state | Unsupported: address-error frame | Unsupported: instruction form |
|---|---|---|---|---|---|---|
| `v1/NOP.json.bin` | 2500 | 673 | 0 | 1827 | 0 | 0 |
| `v1/MOVE.q.json.bin` | 2500 | 652 | 0 | 1848 | 0 | 0 |
| `v1/MOVE.w.json.bin` | 2500 | 248 | 0 | 1873 | 379 | 0 |
| `v1/MOVE.b.json.bin` | 2500 | 613 | 0 | 1887 | 0 | 0 |
| `v1/MOVE.l.json.bin` | 2500 | 258 | 0 | 1872 | 370 | 0 |
| `v1/MOVEA.w.json.bin` | 2500 | 420 | 0 | 1874 | 206 | 0 |
| `v1/MOVEA.l.json.bin` | 2500 | 400 | 0 | 1878 | 222 | 0 |
| `v1/LEA.json.bin` | 2500 | 614 | 0 | 1886 | 0 | 0 |
| `v1/CLR.b.json.bin` | 2500 | 617 | 0 | 1883 | 0 | 0 |
| `v1/CLR.w.json.bin` | 2500 | 372 | 0 | 1895 | 233 | 0 |
| `v1/CLR.l.json.bin` | 2500 | 379 | 0 | 1892 | 229 | 0 |
| `v1/TST.b.json.bin` | 2500 | 646 | 0 | 1854 | 0 | 0 |
| `v1/TST.w.json.bin` | 2500 | 391 | 0 | 1858 | 251 | 0 |
| `v1/TST.l.json.bin` | 2500 | 363 | 0 | 1895 | 242 | 0 |
| `v1/ADD.b.json.bin` | 2500 | 628 | 0 | 1872 | 0 | 0 |
| `v1/ADD.w.json.bin` | 2500 | 397 | 0 | 1873 | 230 | 0 |
| `v1/ADD.l.json.bin` | 2500 | 389 | 0 | 1863 | 248 | 0 |
| `v1/ADDA.w.json.bin` | 2500 | 436 | 0 | 1853 | 211 | 0 |
| `v1/ADDA.l.json.bin` | 2500 | 444 | 0 | 1865 | 191 | 0 |
| `v1/SUB.b.json.bin` | 2500 | 597 | 0 | 1903 | 0 | 0 |
| `v1/SUB.w.json.bin` | 2500 | 417 | 0 | 1842 | 241 | 0 |
| `v1/SUB.l.json.bin` | 2500 | 408 | 0 | 1866 | 226 | 0 |
| `v1/SUBA.w.json.bin` | 2500 | 417 | 0 | 1875 | 208 | 0 |
| `v1/SUBA.l.json.bin` | 2500 | 408 | 0 | 1894 | 198 | 0 |
| `v1/CMP.b.json.bin` | 2500 | 593 | 0 | 1835 | 0 | 72 |
| `v1/CMP.w.json.bin` | 2500 | 365 | 0 | 1882 | 195 | 58 |
| `v1/CMP.l.json.bin` | 2500 | 360 | 0 | 1894 | 192 | 54 |
| `v1/CMPA.w.json.bin` | 2500 | 403 | 0 | 1877 | 220 | 0 |
| `v1/CMPA.l.json.bin` | 2500 | 421 | 0 | 1871 | 208 | 0 |
| `v1/Bcc.json.bin` | 2500 | 470 | 0 | 1862 | 168 | 0 |
| `v1/DBcc.json.bin` | 2500 | 475 | 0 | 1876 | 149 | 0 |
| `v1/BSR.json.bin` | 2500 | 277 | 0 | 1871 | 352 | 0 |
| `v1/JSR.json.bin` | 2500 | 328 | 0 | 1903 | 269 | 0 |
| `v1/JMP.json.bin` | 2500 | 337 | 0 | 1831 | 332 | 0 |
| `v1/RTS.json.bin` | 2500 | 298 | 0 | 1908 | 294 | 0 |
| `v1/BTST.json.bin` | 2500 | 634 | 0 | 1866 | 0 | 0 |
| `v1/BSET.json.bin` | 2500 | 631 | 0 | 1869 | 0 | 0 |
| `v1/BCLR.json.bin` | 2500 | 646 | 0 | 1854 | 0 | 0 |
| `v1/BCHG.json.bin` | 2500 | 641 | 0 | 1859 | 0 | 0 |
| `v1/AND.b.json.bin` | 2500 | 629 | 0 | 1871 | 0 | 0 |
| `v1/AND.w.json.bin` | 2500 | 379 | 0 | 1864 | 257 | 0 |
| `v1/AND.l.json.bin` | 2500 | 348 | 0 | 1901 | 251 | 0 |
| `v1/OR.b.json.bin` | 2500 | 602 | 0 | 1898 | 0 | 0 |
| `v1/OR.w.json.bin` | 2500 | 353 | 0 | 1882 | 265 | 0 |
| `v1/OR.l.json.bin` | 2500 | 359 | 0 | 1855 | 286 | 0 |
| `v1/EOR.b.json.bin` | 2500 | 607 | 0 | 1893 | 0 | 0 |
| `v1/EOR.w.json.bin` | 2500 | 383 | 0 | 1865 | 252 | 0 |
| `v1/EOR.l.json.bin` | 2500 | 376 | 0 | 1911 | 213 | 0 |
| `v1/NOT.b.json.bin` | 2500 | 612 | 0 | 1888 | 0 | 0 |
| `v1/NOT.w.json.bin` | 2500 | 355 | 0 | 1876 | 269 | 0 |
| `v1/NOT.l.json.bin` | 2500 | 359 | 0 | 1886 | 255 | 0 |
| `v1/NEG.b.json.bin` | 2500 | 605 | 0 | 1895 | 0 | 0 |
| `v1/NEG.w.json.bin` | 2500 | 340 | 0 | 1909 | 251 | 0 |
| `v1/NEG.l.json.bin` | 2500 | 398 | 0 | 1848 | 254 | 0 |
| `v1/EXT.w.json.bin` | 2500 | 611 | 0 | 1889 | 0 | 0 |
| `v1/EXT.l.json.bin` | 2500 | 599 | 0 | 1901 | 0 | 0 |
| `v1/SWAP.json.bin` | 2500 | 631 | 0 | 1869 | 0 | 0 |
| `v1/ASL.b.json.bin` | 2500 | 654 | 0 | 1846 | 0 | 0 |
| `v1/ASL.w.json.bin` | 2500 | 559 | 0 | 1882 | 59 | 0 |
| `v1/ASL.l.json.bin` | 2500 | 542 | 0 | 1958 | 0 | 0 |
| `v1/ASR.b.json.bin` | 2500 | 661 | 0 | 1839 | 0 | 0 |
| `v1/ASR.w.json.bin` | 2500 | 578 | 0 | 1870 | 52 | 0 |
| `v1/ASR.l.json.bin` | 2500 | 656 | 0 | 1844 | 0 | 0 |
| `v1/LSL.b.json.bin` | 2500 | 635 | 0 | 1865 | 0 | 0 |
| `v1/LSL.w.json.bin` | 2500 | 532 | 0 | 1890 | 78 | 0 |
| `v1/LSL.l.json.bin` | 2500 | 607 | 0 | 1893 | 0 | 0 |
| `v1/LSR.b.json.bin` | 2500 | 632 | 0 | 1868 | 0 | 0 |
| `v1/LSR.w.json.bin` | 2500 | 569 | 0 | 1846 | 85 | 0 |
| `v1/LSR.l.json.bin` | 2500 | 619 | 0 | 1881 | 0 | 0 |
| `v1/ROL.b.json.bin` | 2500 | 632 | 0 | 1868 | 0 | 0 |
| `v1/ROL.w.json.bin` | 2500 | 550 | 0 | 1866 | 84 | 0 |
| `v1/ROL.l.json.bin` | 2500 | 620 | 0 | 1880 | 0 | 0 |
| `v1/ROR.b.json.bin` | 2500 | 670 | 0 | 1830 | 0 | 0 |
| `v1/ROR.w.json.bin` | 2500 | 553 | 0 | 1872 | 75 | 0 |
| `v1/ROR.l.json.bin` | 2500 | 616 | 0 | 1884 | 0 | 0 |
| `v1/MOVEtoSR.json.bin` | 2500 | 90 | 0 | 2192 | 218 | 0 |
| `v1/MOVEfromSR.json.bin` | 2500 | 389 | 0 | 1874 | 237 | 0 |
| `v1/MOVEtoCCR.json.bin` | 2500 | 402 | 0 | 1857 | 241 | 0 |
| `v1/ANDItoSR.json.bin` | 2500 | 324 | 0 | 2176 | 0 | 0 |
| `v1/ORItoSR.json.bin` | 2500 | 320 | 0 | 2180 | 0 | 0 |
| `v1/EORItoSR.json.bin` | 2500 | 143 | 0 | 2357 | 0 | 0 |
| `v1/ANDItoCCR.json.bin` | 2500 | 658 | 0 | 1842 | 0 | 0 |
| `v1/ORItoCCR.json.bin` | 2500 | 609 | 0 | 1891 | 0 | 0 |
| `v1/EORItoCCR.json.bin` | 2500 | 665 | 0 | 1835 | 0 | 0 |
| **All** | 210000 | 41097 | 0 | 158773 | 9946 | 184 |
<!-- counts:end -->

Only supervisor, non-trace states (`SR & 0xA000 == 0x2000`) apply. User and trace
states need stack switching and trace exceptions and are counted unsupported.
Vectors whose upstream transactions contain an address-error access are counted
unsupported (`address-error frame not modeled`): the core stops at the odd access
with `GW_STOP_UNSUPPORTED_ADDRESS`, and the harness requires that stop to coincide
with an upstream address-error vector, otherwise it is a failure. Unsupported
is never a pass. Records the core cannot execute are reported as `instruction form not
implemented`. The only such records are the CMPM forms inside the `CMP.*` files
(not in the implemented subset), counted under their own `CMPM` sub-form.
ROXL/ROXR, MULU/MULS, DIVU/DIVS, MOVEM, ABCD/SBCD/NBCD, CHK and TAS are not pinned
sources and remain unsupported instructions.

A taken branch, jump or return to an odd address would raise an address error on the
next fetch; the core stops with `GW_STOP_UNSUPPORTED_ADDRESS` and these vectors are
counted in the address-error column. An SR write that clears S or sets T (ANDI/EORI/ORI
to SR, MOVE to SR) stops with `GW_STOP_UNSUPPORTED_STATE`; the oracle vectors that begin
in user or trace state are counted in the user/trace column.

### Per-sub-form denominators

Sub-form totals are record counts of each source file, with applicable records
split into pass/unsupported as in the table above (scheduled lane):

<!-- forms:begin -->
| Source | Sub-form | Records | Applicable pass | Unsupported (all reasons) |
|---|---|---|---|---|
| `v1/ADD.b.json.bin` | ADD | 1561 | 399 | 1162 |
| `v1/ADD.b.json.bin` | ADDI | 116 | 37 | 79 |
| `v1/ADD.b.json.bin` | ADDQ | 823 | 192 | 631 |
| `v1/ADD.l.json.bin` | ADD | 1538 | 233 | 1305 |
| `v1/ADD.l.json.bin` | ADDI | 90 | 10 | 80 |
| `v1/ADD.l.json.bin` | ADDQ | 872 | 146 | 726 |
| `v1/ADD.w.json.bin` | ADD | 1538 | 249 | 1289 |
| `v1/ADD.w.json.bin` | ADDI | 91 | 15 | 76 |
| `v1/ADD.w.json.bin` | ADDQ | 871 | 133 | 738 |
| `v1/ADDA.l.json.bin` | ADDA | 2500 | 444 | 2056 |
| `v1/ADDA.w.json.bin` | ADDA | 2500 | 436 | 2064 |
| `v1/AND.b.json.bin` | AND | 2324 | 589 | 1735 |
| `v1/AND.b.json.bin` | ANDI | 176 | 40 | 136 |
| `v1/AND.l.json.bin` | AND | 2371 | 326 | 2045 |
| `v1/AND.l.json.bin` | ANDI | 129 | 22 | 107 |
| `v1/AND.w.json.bin` | AND | 2342 | 352 | 1990 |
| `v1/AND.w.json.bin` | ANDI | 158 | 27 | 131 |
| `v1/ANDItoCCR.json.bin` | ANDItoCCR | 2500 | 658 | 1842 |
| `v1/ANDItoSR.json.bin` | ANDItoSR | 2500 | 324 | 2176 |
| `v1/ASL.b.json.bin` | ASL | 2500 | 654 | 1846 |
| `v1/ASL.l.json.bin` | ASL | 2500 | 542 | 1958 |
| `v1/ASL.w.json.bin` | ASL | 1890 | 476 | 1414 |
| `v1/ASL.w.json.bin` | ASL.mem | 610 | 83 | 527 |
| `v1/ASR.b.json.bin` | ASR | 2500 | 661 | 1839 |
| `v1/ASR.l.json.bin` | ASR | 2500 | 656 | 1844 |
| `v1/ASR.w.json.bin` | ASR | 1903 | 496 | 1407 |
| `v1/ASR.w.json.bin` | ASR.mem | 597 | 82 | 515 |
| `v1/BCHG.json.bin` | BCHG.imm | 275 | 71 | 204 |
| `v1/BCHG.json.bin` | BCHG.reg | 2225 | 570 | 1655 |
| `v1/BCLR.json.bin` | BCLR.imm | 296 | 69 | 227 |
| `v1/BCLR.json.bin` | BCLR.reg | 2204 | 577 | 1627 |
| `v1/BSET.json.bin` | BSET.imm | 281 | 62 | 219 |
| `v1/BSET.json.bin` | BSET.reg | 2219 | 569 | 1650 |
| `v1/BSR.json.bin` | BSR | 2500 | 277 | 2223 |
| `v1/BTST.json.bin` | BTST.imm | 260 | 51 | 209 |
| `v1/BTST.json.bin` | BTST.reg | 2240 | 583 | 1657 |
| `v1/Bcc.json.bin` | BRA | 166 | 21 | 145 |
| `v1/Bcc.json.bin` | Bcc | 2334 | 449 | 1885 |
| `v1/CLR.b.json.bin` | CLR | 2500 | 617 | 1883 |
| `v1/CLR.l.json.bin` | CLR | 2500 | 379 | 2121 |
| `v1/CLR.w.json.bin` | CLR | 2500 | 372 | 2128 |
| `v1/CMP.b.json.bin` | CMP | 1991 | 526 | 1465 |
| `v1/CMP.b.json.bin` | CMPI | 233 | 67 | 166 |
| `v1/CMP.b.json.bin` | CMPM | 276 | 0 | 276 |
| `v1/CMP.l.json.bin` | CMP | 2063 | 334 | 1729 |
| `v1/CMP.l.json.bin` | CMPI | 190 | 26 | 164 |
| `v1/CMP.l.json.bin` | CMPM | 247 | 0 | 247 |
| `v1/CMP.w.json.bin` | CMP | 2032 | 330 | 1702 |
| `v1/CMP.w.json.bin` | CMPI | 207 | 35 | 172 |
| `v1/CMP.w.json.bin` | CMPM | 261 | 0 | 261 |
| `v1/CMPA.l.json.bin` | CMPA | 2500 | 421 | 2079 |
| `v1/CMPA.w.json.bin` | CMPA | 2500 | 403 | 2097 |
| `v1/DBcc.json.bin` | DBcc | 2500 | 475 | 2025 |
| `v1/EOR.b.json.bin` | EOR | 2233 | 544 | 1689 |
| `v1/EOR.b.json.bin` | EORI | 267 | 63 | 204 |
| `v1/EOR.l.json.bin` | EOR | 2238 | 337 | 1901 |
| `v1/EOR.l.json.bin` | EORI | 262 | 39 | 223 |
| `v1/EOR.w.json.bin` | EOR | 2237 | 343 | 1894 |
| `v1/EOR.w.json.bin` | EORI | 263 | 40 | 223 |
| `v1/EORItoCCR.json.bin` | EORItoCCR | 2500 | 665 | 1835 |
| `v1/EORItoSR.json.bin` | EORItoSR | 2500 | 143 | 2357 |
| `v1/EXT.l.json.bin` | EXT | 2500 | 599 | 1901 |
| `v1/EXT.w.json.bin` | EXT | 2500 | 611 | 1889 |
| `v1/JMP.json.bin` | JMP | 2500 | 337 | 2163 |
| `v1/JSR.json.bin` | JSR | 2500 | 328 | 2172 |
| `v1/LEA.json.bin` | LEA | 2500 | 614 | 1886 |
| `v1/LSL.b.json.bin` | LSL | 2500 | 635 | 1865 |
| `v1/LSL.l.json.bin` | LSL | 2500 | 607 | 1893 |
| `v1/LSL.w.json.bin` | LSL | 1888 | 452 | 1436 |
| `v1/LSL.w.json.bin` | LSL.mem | 612 | 80 | 532 |
| `v1/LSR.b.json.bin` | LSR | 2500 | 632 | 1868 |
| `v1/LSR.l.json.bin` | LSR | 2500 | 619 | 1881 |
| `v1/LSR.w.json.bin` | LSR | 1875 | 473 | 1402 |
| `v1/LSR.w.json.bin` | LSR.mem | 625 | 96 | 529 |
| `v1/MOVE.b.json.bin` | MOVE | 2500 | 613 | 1887 |
| `v1/MOVE.l.json.bin` | MOVE | 2500 | 258 | 2242 |
| `v1/MOVE.q.json.bin` | MOVEQ | 2500 | 652 | 1848 |
| `v1/MOVE.w.json.bin` | MOVE | 2500 | 248 | 2252 |
| `v1/MOVEA.l.json.bin` | MOVEA | 2500 | 400 | 2100 |
| `v1/MOVEA.w.json.bin` | MOVEA | 2500 | 420 | 2080 |
| `v1/MOVEfromSR.json.bin` | MOVEfromSR | 2500 | 389 | 2111 |
| `v1/MOVEtoCCR.json.bin` | MOVEtoCCR | 2500 | 402 | 2098 |
| `v1/MOVEtoSR.json.bin` | MOVEtoSR | 2500 | 90 | 2410 |
| `v1/NEG.b.json.bin` | NEG | 2500 | 605 | 1895 |
| `v1/NEG.l.json.bin` | NEG | 2500 | 398 | 2102 |
| `v1/NEG.w.json.bin` | NEG | 2500 | 340 | 2160 |
| `v1/NOP.json.bin` | NOP | 2500 | 673 | 1827 |
| `v1/NOT.b.json.bin` | NOT | 2500 | 612 | 1888 |
| `v1/NOT.l.json.bin` | NOT | 2500 | 359 | 2141 |
| `v1/NOT.w.json.bin` | NOT | 2500 | 355 | 2145 |
| `v1/OR.b.json.bin` | OR | 2339 | 553 | 1786 |
| `v1/OR.b.json.bin` | ORI | 161 | 49 | 112 |
| `v1/OR.l.json.bin` | OR | 2340 | 338 | 2002 |
| `v1/OR.l.json.bin` | ORI | 160 | 21 | 139 |
| `v1/OR.w.json.bin` | OR | 2351 | 334 | 2017 |
| `v1/OR.w.json.bin` | ORI | 149 | 19 | 130 |
| `v1/ORItoCCR.json.bin` | ORItoCCR | 2500 | 609 | 1891 |
| `v1/ORItoSR.json.bin` | ORItoSR | 2500 | 320 | 2180 |
| `v1/ROL.b.json.bin` | ROL | 2500 | 632 | 1868 |
| `v1/ROL.l.json.bin` | ROL | 2500 | 620 | 1880 |
| `v1/ROL.w.json.bin` | ROL | 1902 | 480 | 1422 |
| `v1/ROL.w.json.bin` | ROL.mem | 598 | 70 | 528 |
| `v1/ROR.b.json.bin` | ROR | 2500 | 670 | 1830 |
| `v1/ROR.l.json.bin` | ROR | 2500 | 616 | 1884 |
| `v1/ROR.w.json.bin` | ROR | 1866 | 466 | 1400 |
| `v1/ROR.w.json.bin` | ROR.mem | 634 | 87 | 547 |
| `v1/RTS.json.bin` | RTS | 2500 | 298 | 2202 |
| `v1/SUB.b.json.bin` | SUB | 1567 | 382 | 1185 |
| `v1/SUB.b.json.bin` | SUBI | 122 | 26 | 96 |
| `v1/SUB.b.json.bin` | SUBQ | 811 | 189 | 622 |
| `v1/SUB.l.json.bin` | SUB | 1527 | 234 | 1293 |
| `v1/SUB.l.json.bin` | SUBI | 115 | 17 | 98 |
| `v1/SUB.l.json.bin` | SUBQ | 858 | 157 | 701 |
| `v1/SUB.w.json.bin` | SUB | 1514 | 242 | 1272 |
| `v1/SUB.w.json.bin` | SUBI | 100 | 13 | 87 |
| `v1/SUB.w.json.bin` | SUBQ | 886 | 162 | 724 |
| `v1/SUBA.l.json.bin` | SUBA | 2500 | 408 | 2092 |
| `v1/SUBA.w.json.bin` | SUBA | 2500 | 417 | 2083 |
| `v1/SWAP.json.bin` | SWAP | 2500 | 631 | 1869 |
| `v1/TST.b.json.bin` | TST | 2500 | 646 | 1854 |
| `v1/TST.l.json.bin` | TST | 2500 | 363 | 2137 |
| `v1/TST.w.json.bin` | TST | 2500 | 391 | 2109 |
<!-- forms:end -->

## Adapter scope

Upstream PC is the next-prefetch address, four bytes beyond the executing opcode
word. The instruction stream starts at `PC - 4`: the opcode, then the extension
words. The adapter (`cpu_vectors.c`, stdin protocol v2) places the vector's
initial RAM bytes in a private `GW_TEST_HOOKS` sparse-memory overlay that replaces
ROM/RAM/device decode for the run, so the original bus addresses are used
unchanged and no relocation is needed. It seeds D0-D7, A0-A6, SSP/A7, SR and PC
through the private seam, executes the production `gw_cpu_step` once, then compares
those registers, SR, PC (final minus four) and memory. A read of an address the
vector did not list is reported as `unlisted memory read`, distinct from a mismatch.
Memory comparison covers every final byte the oracle lists, plus any byte the core
touched outside that list (which must equal its initial value). Upstream lists
whole words, so the untouched partner of a byte write is excluded unless it was
initially listed.

Runner results: `PASS`, `register mismatch`, `memory mismatch`,
`unlisted memory read`, `UNSUPPORTED instruction`, `UNSUPPORTED address`,
`UNSUPPORTED state`. The overlay and the vector tests exist only in hooks builds;
hooks-off builds register `cpu_overlay_absent`, which fails if the core library
contains any `gw_test_memory` symbol.

The oracle's USP must remain unchanged (the core has no user stack model).
Prefetch queues, bus-cycle order and transactions, interrupt behavior and cycle
counts are **unchecked**, not passing evidence. CLR's read-before-write cycle is
not modeled.

## Reproduce

Tests require Python 3.8+ standard library and the native C runner. Core-only
`BUILD_TESTING=OFF` configure/build/install requires neither Python nor downloads.

```sh
cmake --build build/phase2
ctest --test-dir build/phase2 -R cpu_vectors --output-on-failure
python3 tests/vectors/run_vectors.py --runner build/phase2/tests/vectors/cpu_vector_runner --report build/vector-selected.json
python3 tests/vectors/run_vectors.py --runner build/phase2/tests/vectors/cpu_vector_runner --full --corpus-dir build/vector-corpus --fetch --report build/vector-full.json
```

The last command is the broader scheduled lane input. Explicit
`--fetch` downloads only the pinned immutable source files, verifies size/hash before
saving, and uses no credentials. Omit `--fetch` to replay a verified local cache
offline. Full runs also compare the checked-in subset to the decoded originals.
Missing/corrupt data, wrong denominators or runner failures exit as infrastructure
errors; semantic failures exit nonzero with the failing identity. Unsupported
states remain visible and never count as passing tests.

`cpu_vectors_negative_control` changes one expected D0 after checking fixture
identity and requires the specific `register mismatch` observation. A crash or
unrelated nonzero exit cannot satisfy it. This is a test of the comparator, not
a passing CPU vector result.

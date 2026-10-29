# Fixture admission

For the current v0.2 five-title screening roster, title-keyed budgets, resource
caps and Phase 5 evidence-stage boundaries, see
[`docs/phase5-evidence.md`](../docs/phase5-evidence.md) and
[`candidate-screening.json`](candidate-screening.json). All five leads remain
unattempted until exact material rights, build inputs and independent routes are
reviewed; the existing control and diagnostic fixtures do not count as new
games.

The manifest keeps the original Genewhip diagnostic and two versioned independent
game records. `genewhip-independent-game-v1` is retained as historical bounded MAME
admission evidence; its exact old MAME executable is unavailable for a fresh probe,
so the current probe has 2 explicit skips and 77 unknown cases. Do not use that
historical admission as current Genewhip gameplay evidence. Corrected v2 is the
current admitted reference fixture, with a separate bounded Genewhip gameplay
qualification. Source, ROM, scenario, oracle and report identities remain distinct.
`manifest.json` identifies its authored source, MIT notice, deterministic emitter,
SHA256, input schedule and independent expected observations. Build it with
`cmake --build build/phase1`; the emitter has no SDK, assets or runtime linked into
the ROM. Two independent output files must have the manifest hash. Native C17
compiler details belong to the configuration identity in each run report.

`ctest --test-dir build/phase1 -R fixture_manifest --output-on-failure` checks
the original diagnostic source/emitter/ROM bytes and provenance. The independent
game has its own strict source/build/route/runtime validator and controlled
admission/consumer tests; changing a manifest status alone cannot admit its bytes.

## Phase 5 pair admission

`genewhip-phase5-a` is Tank Battle from `monteslu/retro-homebrew-games` at
`eb7dc3044f9d2f76047f3b3573971bf86575ca52`. `genewhip-phase5-b` is RECURSION 94
from `baba20o/RECURSION94` at `ab73bc9c7d2bbc4fcd94b3e0e2b89756cb1dc0cd`.
Their source, material, notice, build, ROM and frozen route identities are
bound through production admission records in `evidence/phase5-admission-*.json`.
Per-material rights are enumerated in each fixture's `materials.json`, with
applicable notices retained in `NOTICES.md`. RECURSION 94's public source archive
is an exact reviewed-source export with a member map back to its original archive.

Both routes are independently qualified against D-118. That is reference-side
evidence, not a claim that Genewhip plays either game. The baseline uses twelve
cases (six unchanged control cases and three cases per new fixture), two fresh
repetitions and five distinct stages. The retained headless client cannot
dispatch RECURSION's source-step-conditioned controller program; its route
interaction and sustained stages remain visibly unsupported. See
[`docs/phase5-evidence.md`](../docs/phase5-evidence.md) for commands, results,
and limits.

## Historical independent game v1

`genewhip-independent-game-v1` is admitted under the MIT license. Its original
assembly source is `fixtures/independent-game/src/game.s` (revision
`9c27f9ad0369ffa8cb8ca935dab887a3ccccc9e2`); `NOTICES.md` records that there are
no third-party assets or game materials. GNU Binutils 2.47 was built from the
signature-verified official source archive for `m68k-elf`; its source, signature,
toolchain, host build inputs and notices are identified in `toolchain.lock`. The
reproducible build command is
`fixtures/independent-game/build.sh --verify-reproducible`.

The historical v1 ROM SHA-256 is
`c17ad98e22d3237feac4f2dfe9d96295f32398a9ce8e4cf0b0542b1035bb0fc1`. Evidence
uses the `VA3-NTSC-U` profile and scenario
`genewhip-independent-game-start-right-ntscu-v1`: Start is asserted at frame 1
and released at 20; Right is asserted at 25 and released at 50. Over 60 frames,
the independent work-RAM oracle at `0xFF0002` requires progression from 3 through
39; the observed value was 39. The ordered trace contains 1,664,728 rows and
101,382,173 bytes over the full 24-bit span. Candidate SRAM storage and enable
control reads and writes were both zero; the separate SRAM sentinel observed all
four positive read/write cases. The normal consumer validates current admission,
identities and repository-contained ROM bytes before returning a path:
`python3 scripts/fixtures/run_admitted.py --fixture-id genewhip-independent-game`.

Evidence preserves all six statuses: pass, fail, unknown, unsupported, skipped,
and infrastructure_error. The independent-game report denominator is 2
(candidate route sentinel and bounded gameplay), with 2 pass and 0 in each
remaining status in the stored historical report. This is bounded evidence for
that exact game/profile/scenario, not broad compatibility or hardware timing
proof. A fresh MAME probe cannot currently reproduce its exact executable and
reports 2 skipped / 77 unknown; v1 remains immutable. Pong remains rejected with
unresolved generated-byte rights, reproducible-build provenance and scripted
runtime/SRAM proof; its outcome remains unknown.

The oracle is the authored instructions and constants in `tests/consumer/main.c`,
not values harvested from emulator output. SingleStepTests CPU vectors have a
separate manifest in `tests/vectors/`; their MAME ancestry is not independent
hardware truth and must never be merged into the original diagnostic oracle.

## Rejected playable candidate

The exact [Free Retro Games Pong revision](https://github.com/monteslu/retro-homebrew-games/tree/eb7dc3044f9d2f76047f3b3573971bf86575ca52/genesis/pong)
was inspected on 2026-10-03. `pong-candidate-audit.json` inventories all three game
files and supporting source/build/notice files, with hashes. Generated tiles and
PSG calls have no external game art, but text and executable output incorporate
SGDK/font/startup/runtime and compiler-library material. Repository MIT alone
does not settle that transitive generated-byte audit.

The immutable Linux/amd64 image digest was retrieved and metadata/SDK layer
inspected without execution. It reports SGDK 2.09, with no matching exact source
revision/compiler version or complete component notices established. Nothing was
installed. ROM builds, output hash/reproducibility and scripted bus/SRAM tracing
are **unrun**, and no ROM is admitted or included. Upstream CI suppresses build
failure; its success is not an admission result. The audit describes the required
future fail-closed build and bounded scenario. Existing instruction records do
not pretend to be a complete bus trace.

The header advertises SRAM at `0x200000..0x20ffff`. It remains untouched and
advisory; SRAM is unsupported. Source inspection found no game save calls, but
that is not a runtime proof. The candidate is rejected by unresolved rights/build/
runtime gates, not repaired by a header patch.

The corrected v2 successor supplies the current lawful fixture: its source,
generated ROM rights, zero-asset inventory, exact toolchain/build, byte identity
and bounded route/runtime evidence passed the independent admission validator.
KłełeAtoms MD remains an unadmitted alternative, with external-art and
SRAM/mouse/controller concerns.

## Current successor v2

`genewhip-independent-game-v2` binds source SHA-256
`b74cd12ec371767e8fb338feca808e59e63f569eb93298bb2470d20f8e4e9cfe`, the MIT
notice, reproducible GNU Binutils 2.47 build, ROM SHA-256
`7bdffe43fc1b6e4ac623e16298e3bd0a775de6cb4db2758695dbef0e200f4adb`, scenario,
oracle, and fresh MAME 0.289 evidence. Its six source-derived reference cases
pass with zero failure, unknown, skipped, unsupported, or infrastructure-error
outcomes. Reference admission is MAME-side evidence only.

Genewhip's separate public-client report (`evidence/phase4-gameplay.json`, also
included in the desktop package) covers six frozen cases and 840 requested fields
through both headless and desktop clients. Field, RAM and raw PCM results agree;
action-triggered sound and matched no-trigger silence are checked. A separate
720-field case passed. This is evidence for the exact guest/profile/scenarios, not
a hardware oracle or broad game compatibility. The raster toy remains a
PSG/FM/DAC diagnostic, not game-audio evidence. Native host observations and
unknown presentation/audio quality outcomes are in the Phase 4 records.

## Original ROMs

Seam ROMs and the raster toy are original cartridges written in GNU as syntax
and assembled with the pinned GNU Binutils 2.47 `m68k-elf` assembler recorded in
`fixtures/independent-game/toolchain.lock`. They are admitted as manifest rows
of kind `original-rom`, validated by `_validate_original_rom` in
`tools/evidence/fixture_manifest.py`.

A row must carry: `status` admitted with `outcome` pass; `source` and
`source_sha256`; `rom`, `rom_bytes` and the ROM `sha256`; `build.source`
(`scripts/fixtures/build-original-roms.sh`) with its `build.sha256`;
`build.toolchain` equal to `fixtures/independent-game/toolchain.lock`;
`build.name` and `build.command`; the MIT `license`, a `notices` list and
`assets` of `[]`; and an `oracle`. Every path must be repository-relative. The
validator rejects a changed ROM byte or length (`content`), a changed source
digest (`source`), a changed build-script digest or toolchain reference
(`build`), a missing notice (`notice`), a non-public path (`path`) and a
disallowed oracle (`oracle`).

The only oracle classes are `documented-hardware-behaviour` and
`guest-source-derived-arithmetic`. An expected value must never be taken from
Genewhip output; such a row is rejected.

### Raster toy (`genewhip-raster-toy-v1`)

`fixtures/raster-toy/` holds an original 16 KiB cartridge (`src/toy.s`, `toy.bin`,
`NOTICES.md`, `scenario.json`) admitted as an `original-rom` row with oracle
`guest-source-derived-arithmetic`. Its pictures, tables and scroll schedule are
produced by assembler expressions; `scenario.json` records the same constants
(palette words, tile pixels, name-table rules, scroll step and the phase schedule).
`tests/devices/raster_toy.py` computes expected XRGB pixels from those constants and the
documented tile, name-table and CRAM formats, checks that the ROM blocks equal the
scenario-derived bytes, and compares them with fields written by
`gw_headless --dump-fields`. Rebuild: `scripts/fixtures/build-original-roms.sh
--update raster-toy`; verify: `--verify-reproducible raster-toy`. Tests are
`raster_toy_planes`, `raster_toy_scroll` and `raster_toy_negative_control`;
`tests/evidence/fixture_manifest.py` rejects a flipped `toy.bin` byte, a missing notice
and an oracle naming Genewhip output.

The toy is original diagnostic evidence for the renderer. It is separate from the
independent game. The corrected v2 game's independent MAME admission and bounded
Genewhip gameplay evidence are described above; neither widens this toy's oracle or
establishes general game compatibility.

Verification and rebuilding are separate. The required gate is offline: it
checks committed bytes, digests and notices only. Rebuilding is
`scripts/fixtures/build-original-roms.sh --verify-reproducible [NAME...]`
(two clean assemblies must be byte-identical and equal the committed ROM);
`--update NAME` rewrites a ROM and `--self-test` exercises the pipeline on an
inline source. NAME maps to `tests/devices/roms/NAME.s` and `NAME.bin` (1,024
bytes) unless a row's `build.name` supplies `source`, `rom` and `rom_bytes`.

`scripts/fixtures/m68k-as.sh` prints the assembler path. It caches the
executable under `build/tool-cache/` and reuses it only when its SHA-256 equals
`assembler.executable.sha256` in the lock; otherwise it rebuilds through
`fixtures/independent-game/toolchain/build-binutils.sh --verify-lock`, which
enforces the archive SHA-256 and the GOODSIG/VALIDSIG check for the pinned
signer. The pinned executable record is for macOS arm64, so rebuilding ROMs
needs that host and network access (the first build takes tens of minutes);
running the committed ROMs does not.

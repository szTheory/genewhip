# Independent game fixture notices

`src/game.s` is original source solely authored for Genewhip under the repository MIT license (`../../LICENSE`). The game logic, vectors, generated tile patterns, and ROM bytes are independent of the emulator implementation, the diagnostic ROM, Pong, third-party game sources, and third-party game assets. No outside author or material is included.

## Assets and tool provenance

- No bundled assets are present. Graphics, music, sound effects, and fonts are absent; VDP tile patterns are emitted directly by the original assembly instructions.
- Third-party game content is absent. Pong has a separate record in `fixtures/manifest.json` with unresolved generated-byte rights, exact compiler/SDK provenance, reproducible build, and runtime SRAM evidence.
- The ROM was built with the source-built GNU Binutils 2.47 assembler. No Binutils source or executable is bundled or linked into the game. Upstream GPL-3.0-or-later notices are identified by path and digest in `toolchain.lock`.

The versioned fixture manifest records the fixture disposition. The linked runtime record is a historical pre-admission capture of the bounded qualification scenario: its two stored checks passed, and this notice/evidence reconciliation did not rerun MAME gameplay. SRAM remains unsupported, and the bounded result makes no broad compatibility claim.

## Runtime outcome categories

The stored runtime evidence uses a denominator of 2. All six runtime outcome categories remain visible below.

| Outcome | Meaning | Recorded count |
|---|---|---:|
| pass | The named bounded check met its expected condition. | 2 |
| fail | An observed result violated its expected condition. | 0 |
| unknown | Available observations do not classify the condition. | 0 |
| unsupported | The tested behavior is outside the implemented or admitted scope. | 0 |
| skipped | The check was not run; it does not count as a pass. | 0 |
| infrastructure_error | The environment or instrumentation prevented a valid result. | 0 |

# Reproducible diagnostic evidence

Build current tools before qualification (the build refreshes their expected
revision, dirty state and source/configuration identity on every invocation):

```sh
cmake -S . -B build/phase1
cmake --build build/phase1
build/phase1/gw_diagnostic_runner build/phase1/diagnostic.bin > build/phase1/run.json
build/phase1/gw_validate_evidence build/phase1/run.json
```

The headless client executes the admitted original ROM through the public API.
It compares six independently authored groups: reset vectors, RAM lanes/longword,
TRAP frame, RTE state, STOP and bounded execution. Its target is 10,000 master
ticks with no events, seed zero, deterministic-zero reset and diagnostics enabled.
`input.json` is that fixed scenario's identity; the runner does not accept arbitrary
input scripts. The report contains actual observations and all six outcomes.
This is diagnostic qualification, not game compatibility or hardware timing proof.

`--inspect` validates identities/structure and displays every outcome, including
fail, unknown, unsupported, skipped and infrastructure-error. Default qualification
additionally requires all rows pass and both producing and validating builds be
clean. Dirty development runs are inspectable but cannot qualify. A missing ROM
or byte mismatch produces a designated error before execution and no report;
a core infrastructure error after fixture admission emits all six error rows.

`schema.json` documents the logical JSON shape. The C parser intentionally accepts
only its canonical field order (shown in the schema's required arrays), compact
key punctuation, unescaped ASCII token strings of 1–128 characters, 1–64 rows,
and at most 32,768 bytes. Whitespace is accepted between parsed tokens. Unknown,
duplicate/reordered fields, trailing data, escapes, NULs, unsupported versions,
bad hashes and missing/duplicate/substituted/reordered case IDs fail closed.
This is a narrow evidence format, not a general JSON parser.

The trusted expected denominator and ordered case IDs live in the validator,
not in the report. It compares the exact source revision, configuration, fixture,
input, profile and original-oracle identities; hashes do not establish rights
or authenticity. Reports are unsigned local observations. A malicious producer
can forge observations; this gate prevents accidental stale/incomplete evidence,
not adversarial attestation. Never validate release evidence with an old binary
without rebuilding it against the required source/configuration.

Configuration SHA256 binds the compiler executable hash, compiler ID/version,
driver arguments/target/toolchain command templates, archive/link tools, CMake
version/generator and generated CMake file-API compile groups and link/archive
fragments for the core, ROM builder, runner and validator. These resolve target
IPO (including per-configuration IPO), PIC, definitions, includes, per-source
options and toolchain-injected options. Source/build roots are normalized before
hashing so relocating the same configuration preserves identity. OS/deployment
settings, C17/API version and the listed source/header/tool/schema/fixture files
in `cmake/EvidenceIdentity.cmake.in` are also bound. Raw paths/flags are not emitted.
Evidence tools require CMake 3.27+ and single-config Unix Makefiles or Ninja;
multi-config, other generators and command launchers that could rewrite generated
commands fail configuration explicitly. Git-less source
archives produce a zero revision and dirty state, so can build/run but cannot
qualify a revision. Core-only users can set `GENEWHIP_BUILD_TOOLS=OFF` and
`BUILD_TESTING=OFF`; no Python, Git or SDL is needed by the core.

Run `ctest --test-dir build/phase1 -R 'evidence_|fixture_manifest' --output-on-failure`
for actual parser and public-runner negative controls. Repeated runs with the
same built inputs are byte-identical. MAME-derived vectors retain their separate
ancestry and are never represented as this original diagnostic's oracle.

## Independent playable fixture

`evidence/independent-game.json` records the separately admitted fixture
`genewhip-independent-game-v1`; it does not modify or reuse the original
diagnostic's evidence. The fixture source is MIT-licensed original Genewhip
assembly at `fixtures/independent-game/src/game.s`, revision
`9c27f9ad0369ffa8cb8ca935dab887a3ccccc9e2`, with no third-party assets. The
source-built, signature-verified GNU Binutils 2.47 `m68k-elf` toolchain and its
upstream notices are identified in `fixtures/independent-game/toolchain.lock`.
The ROM SHA-256 is
`c17ad98e22d3237feac4f2dfe9d96295f32398a9ce8e4cf0b0542b1035bb0fc1`.

The bounded `VA3-NTSC-U` scenario
`genewhip-independent-game-start-right-ntscu-v1` runs Start and Right inputs for
60 frames. Its independent work-RAM progression oracle expects 3–39 at
`0xFF0002`; observed 39. The gameplay trace has 1,664,728 ordered rows and
101,382,173 bytes, spanning addresses `0x000000` through `0xFFFFF4` under the
24-bit mask. The separate SRAM route sentinel observed storage and enable reads
and writes; the candidate run made zero SRAM storage or enable accesses. Ordinary
fixture consumption validates the current manifest/evidence and exact contained
ROM bytes before returning the path:
`python3 scripts/fixtures/run_admitted.py --fixture-id genewhip-independent-game`.

The independent-game outcome denominator is 2 runs: route sentinel and bounded
gameplay, both pass. The record keeps all six status values visible—pass, fail,
unknown, unsupported, skipped, infrastructure_error—with counts 2, 0, 0, 0, 0,
0 respectively. These results do not establish broad game compatibility, SRAM
support, hardware-cycle accuracy, host performance or another platform. Pong
remains rejected: generated-byte rights, reproducible build provenance, and
runtime/SRAM evidence are unresolved. Its outcome remains unknown.

## Phase 2 evidence report

`python3 scripts/evidence/phase2_report.py --build BUILD_DIR --out FILE` runs every Phase 2
check against a build directory (hooks and tools on) and writes one report; `--validate FILE`
re-checks an existing report against the explicit row roster and `git rev-parse HEAD`. CTest
`phase2_report_contract` builds the report and asserts each negative control is rejected for its
own named reason. The extended gate writes `build/extended/reports/phase2-evidence.json`.

Schema `genewhip-phase2-evidence` version 1:

| Field | Meaning |
|---|---|
| `source_revision`, `source_state` | `git rev-parse HEAD`; `dirty` when tracked non-planning files differ |
| `configuration`, `profile`, `api_version` | build type, flags, hooks/tools switches, C compiler id and version, host; `VA3-NTSC-U`; `GW_API_VERSION` |
| `rows` | `{id, kind, oracle_class, outcome, observed, gating}` plus optional `expected`, `mask`, `run`, `reason` |
| `denominator`, `vector_denominator` | fixed row roster size (218) and CPU vector record total (2688) |
| `counts` | rows per outcome, recomputed from `rows` |

`kind` is `seam` (ports, TH, DMA, FIFO, interrupts including the STOP-wake case, sprites),
`toy` (raster toy planes, scroll, sprites), `vectors` (one row per selected CPU vector source plus
the authored interrupt-entry test), `session` (cadence, split-run equivalence) or `smoke`.
`outcome` is `pass`, `fail`, `unknown`, `unsupported`, `skipped` or `infrastructure-error`; nothing
is upgraded, so a seam case with no independent expected value stays `unknown`, a vector source with
any unsupported record stays `unsupported`, and a build without hooks reports its vector rows
`skipped`. `oracle_class` is `documented`, `REF-derived` or `unknown` for seams, `MAME-derived`
for vector sources, and `authored-oracle`, `authored-contract` or `scenario-oracle` for the
independently computed toy, session and smoke checks. `gating` is true when a `fail` or
`infrastructure-error` fails the aggregator: seam cases of class `unknown`, skipped rows and the
smoke are not gating. The roster pins each row's class, so a REF-derived row relabelled
`documented` fails with `relabelled-class`.

Validator reasons: `missing-row`, `duplicate-row`, `unexpected-row`, `stale-revision`,
`denominator`, `counts`, `relabelled-outcome` (a class-`unknown` row, a vector source with
non-pass counts, or a smoke without an in-range value reported `pass`) and `relabelled-class`.

The Phase 3 independent-game core smoke (`independent_game_core_smoke`, label `non-gating`)
replayed the historical v1 scenario through `gw_headless` and stopped with an
`unsupported-address` at `0xc00006`; that result remains historical and unsupported. Phase 4
separately admits corrected v2 for its exact MAME reference scenario and records a six-case,
840-field Genewhip public-client gameplay result plus a distinct 720-field scenario. These
identity-bound outcomes do not imply broad game compatibility. See `phase4-gameplay.json` and
the Phase 4 summary for the exact source, ROM, scenario, input and client identities.

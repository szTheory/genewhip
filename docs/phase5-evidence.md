# Phase 5 fixture screening and evidence

## Phase 5-07 admitted pair and Genewhip baseline

The current admitted pair is fixed to two independently authored lineages:
Tank Battle (`monteslu/retro-homebrew-games`, revision
`eb7dc3044f9d2f76047f3b3573971bf86575ca52`) and RECURSION 94
(`baba20o/RECURSION94`, revision `ab73bc9c7d2bbc4fcd94b3e0e2b89756cb1dc0cd`).
The actual public admission records are
[`phase5-admission-a.json`](../evidence/phase5-admission-a.json) and
[`phase5-admission-b.json`](../evidence/phase5-admission-b.json). Each binds
the frozen D-118 current reference pointer, selected eligibility/ledger,
source/material inventory, reviewed tool/build records, two raw build outputs,
canonical ROM, notices, route program/oracle and exact canonical JSON captures
of both trusted D-118 report runs. RECURSION's source export keeps its original
archive ancestry in the reviewed member map. The source-derived reference
executable is represented by a data pin; no MAME binary is copied into the
fixture. The original failed `evidence/phase5-reference.json` remains untouched.

The real production consumer now resolves both exact promoted ROMs. Verify
admission, consumer resolution, and preserved historical rows with:

```sh
python3 -I tests/evidence/phase5_admission_contract.py --verify-admitted-pair
```

The command also runs each ID against a manifest with the Phase 5 rows removed
and confirms refusal before checking the admitted manifest. The retained
historical manifest rows have canonical SHA-256
`dd50c8977a8f14b3bc9fc52dcf70f5a38b0c7d41d257f7409a435e239c481085`.

The baseline denominator was frozen before collection in
[`phase5-baseline-roster.json`](../evidence/phase5-baseline-roster.json): six
unchanged control cases, three source-derived cases per new game, two fresh
repetitions and five explicit stages per case (120 rows). It binds the exact
manifest, eligibility, D-118 report, CMake cache, client, source inputs, ROMs,
scenarios, oracles, consumer script and source-provenance adapter. The report
binds the canonical roster digest, and validation rejects a stale or altered
roster identity. The real collection command is:

```sh
python3 -I tests/fixtures/phase5_game.py --collect build/phase5/tools/session/gw_headless \
  --roster evidence/phase5-baseline-roster.json --output evidence/phase5-baseline.json
```

The collector resolves the admitted control and candidate ROMs through
`scripts/fixtures/run_admitted.py`, then runs the unchanged
`tests/fixtures/phase4_game.py` assertions for the control in two fresh
repetitions. The final collection took **6.358017 seconds** on the recorded local run. The
baseline is **188,679 bytes**; its failure inventory is **78,207 bytes**. The
baseline and inventory validators pass with the full frozen denominator.

| Fixture and stage | Two-run result | What was observed |
| --- | --- | --- |
| Existing control, load/boot/interaction | 36 pass | All six existing Phase 4 source-state, rendered/audio, and public-client assertions pass in each repetition. |
| Existing control, sustained | 2 pass | Sustained-play passes exactly 720 fields in each repetition; both observed machine digests agree. |
| Existing control, other sustained rows | 10 skipped | Sustained play is only applicable to the predeclared sustained-play case. |
| Existing control, completion | 12 unknown | The control oracle declares no completion predicate. |
| Tank Battle, load | 6 fail | Public core explicitly returns `REJECT: invalid-rom` for the admitted 512 KiB image across three cases and two repetitions. This is a real load-stage core rejection. PC/opcode/access width/tick were not emitted. Later stages are skipped as unreached. |
| RECURSION 94, load | 6 pass | The admitted ROM loads through the public client. Field completion does not imply boot success. |
| RECURSION 94, boot | 6 fail | Existing diagnostics report stop_reason 2, unsupported 1, instruction address 0x1822 and opcode 0x48e7. |
| RECURSION 94, interaction/sustained/completion | 18 skipped | Unreached after the observed core stop. State-driven controller dispatch is also unsupported by this client; no approximate replay was substituted. |

All later Tank rows are explicit skips following the load rejection, rather than
invented guest failures. No new-game pass is inferred from D-118. New-game
interaction, sustained progress, completion and causes remain unproven. The
precise case/run rows, paths, commands, public-client identities, stop text and
unknown PC/opcode/tick observations are retained in
[`phase5-baseline.json`](../evidence/phase5-baseline.json) and
[`phase5-failure-inventory.json`](../evidence/phase5-failure-inventory.json).
That inventory also retains the five-title screening dispositions and their
original unknown/rejected/unattempted outcomes. Phase 6 should first investigate
Tank's actual invalid-ROM rejection and RECURSION's opcode stop. Exact source-state input dispatch
is also needed before claiming interaction or sustained play.

Validate both reports offline with:

```sh
python3 -I scripts/evidence/phase5_baseline.py --validate evidence/phase5-baseline.json
python3 -I scripts/evidence/phase5_baseline.py --validate-handoff evidence/phase5-failure-inventory.json \
  --baseline evidence/phase5-baseline.json
```

The required CTest lanes are `phase5_game_contract`, `phase5_admitted_pair`,
and `phase5_baseline_evidence`; the repeated public-client collection remains
opt-in through `GENEWHIP_PHASE5_ENABLE_BASELINE_COLLECTION=ON` with a finite
1,800-second lane timeout. The collector enforces a 600-second overall collection deadline and a combined
1 MiB output capture cap per process, with process-group cleanup and privacy checks before publication. The local collection is not promoted to hosted CI based on one
fast run. This phase introduces no CPU/VDP/audio repair or public API change,
and does not start Phase 6.

The dated narrative below is retained as a historical log. Its earlier
screening and reference statuses describe the evidence captured at those dates;
the Plan 07 admitted pair and baseline above are the current Phase 5 record.

## New fixture admission boundary

New game rows use the explicit `phase5-independent-game-v1` manifest kind and
the fixed IDs `genewhip-phase5-a` and `genewhip-phase5-b`. The production
`scripts/fixtures/run_admitted.py` consumer resolves a ROM only when its
content-bound admission record validates the anchored v2 screening and
eligibility records, the current D-118 reference pointer/report, the selected
lineage, retained material terms/notices, build recipe/tool/runtime identities,
two identical raw ROM outputs, and the canonical ROM bytes. It also requires
two distinct fresh reference receipts with their raw captures and frozen
scenario, schedule, input program, oracle, script and reference-tool identities
bound together. The RECURSION input program is retained in full; it is not
collapsed into field-only replay data.

Manifest status alone cannot admit a fixture. New rows keep a versioned
admission record digest; the `source_provenance` consumer adapter rejects missing or stale bindings,
quarantine paths, symlinks, missing material terms or notices, altered bytes,
and private-path/secret/raw-log fields. Validation reads data and hashes bytes;
it never imports or executes candidate build, source, route, or copied helper
code. The historical v1 and successor v2 validators remain separate, and the
existing v2 source-revision bridge continues to require exact source bytes and
an ancestor or immutable source tag. No source revision is inferred from the
current repository HEAD for the new fixture kind.

The offline production-consumer contract uses temporary, explicitly synthetic
gate records. These tests exercise the consumer's acceptance and rejection
paths only; they do not qualify either actual candidate or create promotion
evidence. Phase 5-04 does not promote candidate ROMs. Current D-118 reference
qualification remains independent of Genewhip playability, and Phase 6/7 still
require separate phase starts. No package dependency or core/public emulation
API change is introduced.

The accepted admission record schema is `genewhip-phase5-admission-v1`. Its
fixed slot mapping is `phase5-a` → `genewhip-phase5-a` → `tank-battle` and
`phase5-b` → `genewhip-phase5-b` → `recursion94`. The exact top-level fields are
`schema`, `fixture_id`, `slot_id`, `title_id`, `lineage_id`, `source_revision`,
`status`, `outcome`, `project`, `license`, `assets`, `gates`, `promotion`,
`route_evidence`, and `identities`. The `identities` object has a fixed key set
for screening/eligibility/current-reference/report, source archive/inventory/
terms, build recipe/tool lock/linked runtime/build record, raw outputs/canonical
ROM, notices/notice index, scenario/schedule/program/oracle/reference script/
executable/build, reference-pair receipt, and two fresh run receipts with raw
captures. Unknown fields fail closed.

`promotion` maps `source_tree_identity` to the content inventory, `build_lock`
to the tool lock, `notices` to the notice index, `build_receipt_sha256` to the
validated build record, and `rom` to the canonical ROM. `route_evidence` binds
that ROM, the canonical digest of frozen scenario/schedule/program/oracle/script
identities, and the reference-pair receipt digest. Plans 05-05/06 can project
these exact `slot_id`, `promotion`, and `route_evidence` fields into their
eligibility entries for the existing `phase5_candidate.py --verify-slot`
consumer; the frozen fixture bytes remain separately hash-checked.

The legacy `fixture_manifest.py` bytes remain identical to their historical
v2 evidence-bound version. New-kind dispatch therefore lives in the existing
`source_provenance.py` adapter, which validates the complete new chain and
passes all other manifest rows through the unchanged historical validator.
This compatibility choice preserves the archived successor evidence's exact
validator digest while keeping `run_admitted.py` as the single ROM consumer.

CTest keeps admission, policy and reference parser contracts as required
offline tests. Actual container enforcement and local reference-pair checks
are separately labeled capability lanes; long MAME qualification is disabled
unless `GENEWHIP_PHASE5_ENABLE_REFERENCE_QUALIFY=ON` is explicitly selected.

Phase 5 distinguishes documentary/build eligibility, independent route
qualification, and Genewhip public-client baseline evidence. A passing reference
route does not prove Genewhip playability. A Genewhip failure cannot reject a
candidate before its independent route has qualified. Completion is not claimed
by this phase's control tracer.

The explicitly resumed D-116 recovery freezes Tank route-v3 and unchanged
RECURSION route-v2 after actual Lua controller tooling tests. This uses separate
authorization, freeze and single-use attempt files; D-115 report/attempt and
old packages remain immutable. Legacy correction/build counters remain unchanged;
title-keyed identity events charge the new exception separately. The exact
producer, ledger, eligibility and freeze must be committed before the exclusive,
fsynced attempt receipt is created. Use explicit `--decision D-116` and
`--output evidence/phase5-reference-d116.json`; the default remains D-115.
The same pinned MAME uses `-nothrottle` only to remove host wall-clock pacing.
Guest field clocks, unchanged score windows, repetitions, stop bounds and caps
remain enforced. A further failure/disagreement consumes the cycle and stops.
LuaJIT fakeMAME trajectory tests establish controller behavior only; they never
qualify a ROM or copy/execute game code on the host.

D-116 is now consumed. Tank passes all6 case captures with two agreeing fresh
repetitions and unchanged score windows. RECURSION completed3 first-repetition
captures but its frozen Lua clock stopped at3598/7200. Separate retained-source
analysis supports3600 actual source ticks and locates the deficit before C
replacements; early dependency and stable-completion predicates remain
unobserved, so a clock-only reconciliation cannot qualify the route. All9 raw
receipts/99 files verified. See the immutable
[`native report`](../evidence/phase5-reference-d116.json),
[`separate outcome`](../evidence/phase5-reference-d116-outcome.json) and
[`offline RECURSION analysis`](../evidence/phase5-recursion-d116-offline-analysis.json).
The pair gate remains blocked; no further native execution, admission or
candidate baseline follows. Neither title infeasibility nor a Genewhip failure
is established.

## Promoted payload binding details

The admission validator inventories source tar members without extracting or
executing them. It accepts ordinary directory entries, while rejecting links,
special files, traversal, non-canonical names, duplicate members, and archives
over the fixed member and expanded-size bounds. `materials.json` retains the
exact `material_locations` map: upstream bytes name their reviewed archive
member, while approved build-tool overrides name a separately hash-pinned
workspace file and its reviewed source revision.

For privacy-reviewed source exports, `content_inventory.source_origin` binds
the original archive digest and source revision plus a complete member map.
The public archive must contain exactly the reviewed upstream source files,
with unchanged paths, sizes, and hashes; it cannot omit files or add unrelated
archive content. Frozen scenario/oracle comparisons use canonical JSON
digests, while file identity records continue to bind their raw bytes. The
reference executable identity is a public data-only pin descriptor, not a
copied emulator binary; its descriptor hash and pinned executable hash serve
separate evidence roles.

## Current versioned policy and history

The D-108–D-112 migration preserves the original ledger, eligibility record and
halted 05-02 summary byte for byte. The new
[`phase5-policy-v2.json`](../fixtures/phase5-policy-v2.json),
[`candidate-screening-v2.json`](../fixtures/candidate-screening-v2.json),
[`phase5-eligibility-v2.json`](../evidence/phase5-eligibility-v2.json) and
[`migration receipt`](../evidence/phase5-policy-migration.json) bind those
three historical SHA-256 anchors, the exact ordered event prefix and all four
failed probe receipts. Historical v1 records keep their original meaning.

The selected policy declares **64 Linux tasks including threads, 4 CPUs and at
most 4 concurrent build jobs** independently. It retains the prior numeric
caps, nonroot user, no network, read-only root, dropped capabilities, minimal
environment, no host mounts, 8 GiB aggregate memory with no extra swap, 8 GiB
per-process address space and 8 GiB workspace. `/work` defaults to noexec;
exactly declared native tools may require exec with nosuid/nodev retained.
`/tmp` stays noexec. The local
[`enforcement receipt`](../evidence/phase5-enforcement.json) records 23 passing
required controls for its exact source/policy/test identities. Its latest run
took 10.456096 seconds. Both process and pthread pressure reached kernel
`pids.peak=64` and rejected the next task with EAGAIN; five authored make jobs
showed a maximum of four active, with the fifth queued. The retained 64-task
configuration also passed CPU, memory/swap, address-space, nonroot, network,
read-only-root, capability, environment, mount, cleanup, output/archive and disk
checks. This is local Linux-container evidence on macOS arm64 using the pinned
amd64 image through the host's translation capability; it does not prove SGDK
sufficiency, candidate rights, hosted CI, game compatibility or platform support.

Current execution uses `genewhip-phase5-build-config-v2`, binding policy,
migration, recipe/makefile hashes, exact native inputs/outputs/commands and
separate task/CPU/job/mount declarations. The supported recipe is an exact
`exec make -jN -f file [targets]` wrapper, with N at most four and literal
reviewed make commands. Recursive make, jobserver overrides, shell indirection,
undeclared native commands, interpreter recipes and compiler plugins are
rejected. Unsupported upstream recipes require an inspected flattened recipe;
CPU quota never substitutes for a job bound. V1 screening is read-only.
The supervisor refuses stale/missing/partial enforcement receipts and reruns
offline semantic controls before candidate work. Every resumed child receives
the remaining monotonic deadline; a changed configuration cannot reuse a setup
receipt. Materials-stage slot validation requires source/build/notices and
build-receipt identities; the complete stage additionally requires final ROM and
independent route identities.

The first harmless lane attempt hit a reporting KeyError; the second rejected
an invalid 64-MiB AS probe because Rosetta failed before the intended allocation
assertion. Neither was treated as passing. The corrected smaller AS control
uses 1 GiB with an 8 GiB allocation request, and aggregate-memory pressure uses
256 MiB with a reached 512 MiB allocation; these exercise actual rejection while
the production 8 GiB declarations are checked separately. No large virtual
allocation is touched in the AS control. All final controls pass without a
candidate-specific Java initialization, source compilation or ROM invocation.

The single Tank setup continuation has been **consumed once**. Its producer
receipt is retained at
[`phase5-setup-continuation.json`](../evidence/phase5-setup-continuation.json).
The JVM initialization succeeded in 0.324270 seconds under the same pinned image,
with kernel pids.peak9. Including 0.628522 seconds of preceding read-only identity
lookups, the ledger charged 1.448431 seconds; measured controller closeout was
1.455844 seconds. Total charged setup is 380.487818 seconds, within the original
1800-second ceiling. The unused 1419.512182 seconds do not grant another use.
The original screen/correction and zero ROM invocations remain unchanged.
Accounting uses integer microseconds, rounds elapsed upward and persists use
before initialization. Repeating migration cannot reissue it. No automatic
128-task fallback exists.

The first post-setup check exposed a semantic test that depended on the live
ledger being unused. That test now constructs a pristine migrated fixture;
all current offline tests and harmless enforcement pass. The original setup
receipt and its exact producer identities remain unchanged. Its original
enforcement snapshot is retained byte for byte at
[`phase5-enforcement-setup.json`](../evidence/phase5-enforcement-setup.json).
An offline audit matched its producer source, original test snapshot, raw log
hashes, effective controls, single-use state and time bounds. The strict
current-identity continuation verifier rejects that historical receipt after
the test identity changed. It has not been rewritten to appear current, and
the single-use initialization will not be repeated automatically.

The current material review retains all five leads and their exact component
dispositions. Tank and RECURSION 94 now have actual repeatable clean-build pairs,
verified together as two distinct build-qualified lineages. These receipts
establish build repeatability only; independent route qualification, candidate
Genewhip baselines, admission and Phase 6 remain pending.

## Bounded reference-route capture

`tests/fixtures/phase5_reference.py` freezes source-authored route identities,
uses only the locked MAME executable, applies declared controller inputs, and
samples only declared RAM bytes. Each capture is ordered and bounded to a
600-second process watchdog, 1 MiB stdout/stderr per run, 16 MiB/100,000
selected rows, 8 MiB evidence records and 6 GiB temporary disk. Lua never writes
guest memory or registers. Two fresh runs are required; semantic disagreement
is unknown. This differential evidence follows source semantics and does not
claim hardware authority.

The new helper has been exercised on the unchanged 720-field sustained control:
24 selected-RAM rows ended with source play state 1 and position 39. Its receipt
binds the original scenario, oracle and ROM digests. A fresh pinned-MAME snapshot
and WAV were also captured through the current headless Lua path; the WAV has
nonzero samples, and a selected rendered pixel differs from its background.
The retained control's tracked marker is offscreen at that sampled position, so
this is render-path capability evidence rather than visual gameplay
corroboration. Existing same-case VRAM geometry and PSG traces remain historical
references by digest. None of these control observations counts as a candidate
route or substitutes for candidate-run render/audio evidence.

The Tank Battle and RECURSION94 routes are authored from their pinned source,
maps and build identities in ignored local quarantine. Their exact script,
scenario, oracle, input and build hashes passed `--author-check` before any
candidate reference observation. The routes use 3,600 source-active ticks,
source-defined progress signals, separated late milestones and matched withheld
action controls. Both source-frozen route attempts stopped in the primary `full-route` case at the
3,600 active-field guard. No matched control case ran. This is an unqualified
observation, not a gameplay rejection: the helper did not retain sampled rows,
the exact maximum, or raw temporary process output when the guard fired. The
receipt and limitation are recorded in
[`phase5-reference.json`](../evidence/phase5-reference.json). The corrected
RECURSION observer also retains its first duplicate-signal parse failure in
`prior_failures`. No candidate baseline or admission claim follows from these
attempts; root cause remains unresolved pending offline inspection.

```sh
python3 -I scripts/fixtures/phase5_candidate.py --verify-policy-migration \
  --ledger fixtures/candidate-screening-v2.json \
  --eligibility evidence/phase5-eligibility-v2.json \
  --policy fixtures/phase5-policy-v2.json
```

## Frozen screening roster

The following roster and initial dispositions retain the historical 05-02
review. Current migration/setup results are above; current feasibility is below.

[`fixtures/candidate-screening.json`](../fixtures/candidate-screening.json)
freezes exactly five documentary leads and their starting source revisions:
Tank Battle and Alex vs Bus are the primaries; Space Shooter can replace Tank
Battle only and shares its lineage; RECURSION 94 and KłełeAtoms MD are reserve
lineages. A reserve can be activated only after a missing lineage is documented
and its documentary, build and route viability is established. Repository names
and top-level license files do not establish author ancestry or grant rights to
all source, runtime, startup code, fonts, music, assets, generated data or ROM
bytes. Each material needs its own exact source, revision, terms and retained
notice review. Build-tool terms and generated-ROM distribution terms are
separate findings.

Actual source archives and title materials were reviewed under the frozen
revisions, with per-file SHA-256 records for both Tank/Space subtrees (4 and 3
files), Alex vs Bus (143 files), RECURSION 94 (314 archived files), and
KłełeAtoms MD (62 files). The public eligibility record also lists exact
reviewed image tool/library hashes and explicit category dispositions; source
bytes, archives and logs stay in ignored local quarantine.

Tank and Space Shooter share one source lineage. Their MIT game-code path and a
plausible SGDK/GCC Runtime Library Exception output path are documented, with
the image/source makefile mismatch and missing image notices preserved as
caveats. The pinned SGDK image failed both default and minimized Java startup
because its Finalizer thread could not start under the frozen `pids.max=4` task
cap. One Tank screen and one build-environment correction are consumed; no ROM
invocation or route ran. Alex has identified code/art grants and notices, but
the exact official freeware-font notice does not resolve whether its derived
logo raster may be distributed in a ROM. KłełeAtoms MD credits external
graphics without an applicable grant in its pinned tree. RECURSION 94 has an
MIT/provenance path and a non-commercial vasm source path, but its
platform-equivalent toolchain/build and route remain untested. It is one reserve
lineage and cannot form the required pair alone.

All five remain unqualified. The ledger records one of four full screens, one
environment correction, zero ROM invocations, zero routes and zero new
admissions; three full-screen slots remain. The bounded stop reflects the
current roster and controls: no second independent build is presently eligible
and evidenced, so no reserve is screened merely to consume budget. This does
not claim that every possible future build method has been disproved.

## Historical v1 resource and correction limits

The machine-readable limits in the ledger are exact upper bounds. The network
fetch cap is 120 seconds with one retry inside a 1,800-second total toolchain
setup budget. Each reviewed build invocation is limited to 1,800 seconds, four
cgroup tasks, 8 GiB virtual address space per build process, 8 GiB active
workspace per title and 24 GiB total quarantine. Each process may emit
at most 1 MiB stdout and 1 MiB stderr. A generated ROM is limited to 16 MiB;
source archives are limited to 256 MiB compressed, 1 GiB expanded and 20,000
entries. A reference or public-client run has a 600-second watchdog and 6 GiB
disk cap; targeted traces are limited to 16 MiB and 100,000 rows, with 8 MiB
summary output per run.

Enforcement must count bytes while streaming, terminate the whole process group
at a timeout or cap breach, and record `infrastructure-error` without discarding
raw identities. If the host cannot enforce build isolation or required resource
controls, eligibility remains unknown before candidate execution; available
tool names alone do not prove that the restrictions work. No candidate build
tool is installed by this plan.

Each title permits one named build/environment correction, one route-authoring
correction before route freeze and one targeted reference/harness correction.
Successful repeatability requires two isolated clean builds from the same
pinned inputs. At most four ROM-producing invocations per title cover an initial
pair and one correction followed by a fresh pair. Preserve both raw output
hashes and byte counts; explained variation is never called byte reproducible.
The append-only identity history and its hash chain derive title counters across
source/build identity changes.

## Historical v1 candidate build supervisor

`scripts/fixtures/phase5_candidate.py` owns the candidate screening entry points
and subprocess/build boundary. Its `--self-test` runs an actual harmless source
through the same supervisor in two clean workspaces, then exercises the container
restrictions. It requires a locally present `repository@sha256` image; it never
pulls an image or installs a tool. The daemon endpoint must be a local Unix
socket, and the controller uses an empty Docker credential configuration.

Candidate code runs as UID/GID 65532 with no network, dropped Linux capabilities,
`no-new-privileges`, a read-only image root, a four-task cgroup PID ceiling,
8 GiB memory and 4 CPU limit. The build wrapper applies an 8 GiB `RLIMIT_AS`
through the shell's `ulimit -v`; memory swap is disabled by setting the Docker
swap limit equal to its memory limit. An 8 GiB tmpfs bounds the workspace. The
supervisor checks the aggregate ignored phase5 quarantine tree against its 24
GiB cap before transfer and reserves output/log space before builds, then checks
retained outputs as it writes them. Inputs are transferred as a bounded archive
into that temporary workspace; no host path, repository, credential, Docker
socket, or host workspace is mounted. The build receives only explicit PATH and
declared fixed build variables plus fixed HOME, TMPDIR and locale settings.
Candidate stdout/stderr are streamed and capped while produced; ROM transfer has
its separate 16 MiB cap. Timeout and output violations kill the container and
its descendants. An unavailable daemon, missing exact image, failed restriction
probe or unsupported host blocks screening before candidate code executes.

The cgroup `pids.max=4` bound counts tasks, including JVM threads. The SGDK 2.09
image's Java helper failed to start the Finalizer thread under this exact bound,
including a minimized-JVM probe. This is recorded as a concrete toolchain
incompatibility; the task cap was not raised and no candidate source was run.

The source-to-output receipt preserves invocation order, input identity, image
ID, output length and SHA-256 for both raw outputs. Empty output fails; equal
bytes are byte-reproducible; differing bytes remain blocked until every exact
differing byte range, both raw range hashes, cause, implication and canonical
ordinal are recorded. Counter events are hash-chained by title and retain changed
source/tool identities, so a new identity cannot reset a consumed screen/build.

The record helper also checks exhaustive material-category coverage. Code, media,
fonts, music, resources, converters, startup/runtime objects, compiler libraries,
build tools and generated ROMs must each be inventoried or explicitly declared
absent. Exact hash, source revision, terms source, license and retained notice
are required for each present material. A repository-level license cannot
substitute for these facts, and documentary metadata alone does not authorize a
build.

`--verify-slot {a|b} --stage materials|complete` checks the identity-bound local
promotion directly from the eligibility record, without fixture-manifest
admission and without executing a build or route. The materials stage checks
the source-tree identity file, build lock, notices and canonical ROM hashes;
the complete stage also requires frozen route evidence bound to that ROM and a
reference-pair identity. Missing promotion data remains blocked.

Pre-build material eligibility requires exact source/material terms, notices,
lineage evidence, and pinned inputs. `repeatable_build` is explicitly a
post-build check: it is recorded only after the supervisor retains both raw
outputs and compares them. It is not a prerequisite for the build that measures
repeatability.

`--documentary` requires `--ledger`; omitted `--eligibility` selects the canonical
`evidence/phase5-eligibility.json`. `--screen-next` requires `--ledger` and
`--eligibility`; a build config is required only after a documentary-eligible
title is selected. If none is eligible, the CLI returns its semantic blocked
status without requiring a config. The
config uses schema `genewhip-phase5-build-config-v1` with exactly these fields:
`title_id`, frozen `source_revision`, exact `build_image` repository digest, two
ROOT-relative workspaces under ignored `local-fixtures/phase5`, `output_relative`,
`build_recipe` (`path` plus string `args`), and explicit `build_environment`
constants including the in-image `PATH`. A resumed setup may also name its
`setup_receipt` by quarantined path and SHA-256. The config file itself is also
kept in that ignored quarantine. Before candidate code runs, the supervisor
checks that each workspace exactly matches the exhaustive material hashes,
compares both clean input identities, probes local isolation, and requires the
digest-pinned image to already exist. It atomically appends `screen_started`
and `build_setup_started` before image/setup work; a failed setup still consumes
that screen and records its elapsed time. Setup time cannot exceed 1,800 seconds.
Each ROM invocation appends its own title-keyed event before launching.

Both raw ROM files and bounded stderr logs stay in ignored local quarantine.
The receipt stores output ordinals, relative quarantine paths, raw lengths and
hashes, image ID, source/config identities, and the exact comparison result.
The ledger records build repeatability separately from route qualification.
The scheduler screens eligible primaries first, permits same-lineage or
distinct-lineage reserves only for a documented missing primary, and stops
after two successful distinct source lineages even when one is a reserve. It
never selects more than four full title screens. No Genewhip or reference route
runs as part of this command.

Material entries identify `origin` as `workspace` (the default) or `image`.
Workspace entries must exactly match the two clean source/recipe trees. Image
entries use absolute container paths and their hashes are checked inside the
exact read-only, network-disabled toolchain image before any candidate recipe
runs. The eligibility record's reviewed `build_image` must equal the config pin.
When resuming an already-consumed screen, the config includes a `setup_receipt`
with its quarantine-relative `path` and SHA-256. The supervisor verifies that
receipt's exact title, source revision, image, timestamp and identity hash
against the existing `screen_started` event; it does not increment that screen
again.

## Evidence commands

Configure and build the known control client before tracing:

```sh
cmake -S . -B build/phase5 -G Ninja -DBUILD_TESTING=ON -DGENEWHIP_BUILD_TOOLS=ON
cmake --build build/phase5 --parallel
python3 -I tests/evidence/phase5_baseline_contract.py --tracer build/phase5/tools/session/gw_headless
python3 -I scripts/evidence/phase5_baseline.py --validate build/phase5/phase5-tracer.json
```

The tracer resolves the v2 control only through the existing fixture manifest
and source-provenance admission boundary. It verifies the source, notice,
toolchain, ROM, scenario, oracle, MAME reference and build identities, then runs
the unchanged `title-no-start` case through the public `gw_headless` interfaces
and source-derived state/geometry checks. The generated local report remains in
the ignored build directory; it is not an admitted candidate or a new title.
The tracer writes only the dedicated `build/phase5/phase5-tracer.json` path so a
caller-supplied output cannot overwrite repository or unrelated files.

Offline CTest contracts validate parser mutations, the fixed screening roster,
title/lineage pair rules, bounded counters and the real control tracer. Longer
candidate builds and reference routes are local capability lanes in later
plans. Missing capability is visible as unknown/blocked and cannot qualify a
candidate. Long optional capability lanes must use CTest skip code 77 when a
named tool/device is unavailable; a skip never counts as admission. Historical
v1 fixture `infrastructure_error` and Phase 4 report
`infrastructure-error` spellings are converted only by explicit schema-specific
adapters; unknown schema/status pairs and status-only passes are rejected.

The first measured local required lane used macOS arm64, Python 3.14.4 and the
Ninja build above. CTest completed the six selected checks in 0.64 seconds:
`evidence_contract` 0.00 s, `phase5_admission_contract` 0.03 s,
`phase5_baseline_contract` 0.03 s, `phase5_tracer` 0.25 s,
`evidence_integration` 0.06 s, and `fixture_manifest` 0.26 s. The tracer did not
skip. These timings describe this local run and are not a hosted-CI performance
claim.

## Current evidence boundary

The v2 admitted control is unchanged. Its public-client tracer is useful for
proving the evidence path and does not count toward the two new-game minimum.
No candidate ROM was built and no independent route was run. The amended task
policy resolved the observed JVM initialization obstacle, with the historical
four-task failure retained. Exact SGDK image/runtime source correspondence is
still unknown after one bounded documentary clarification. The supplied source
snapshots' `libmd.a` and makefile digests differ from the image. Different binary
digests do not prove different source or unlicensed content, but the supplied
records establish correlation rather than an exact source/build-input chain.
The MIT and GCC Runtime Library Exception texts provide a conditional path;
they do not fill that missing provenance or identify a particular generated
ROM's linked members/notices. The current eligibility record retains the exact
comparison digests, all five leads and every prior material unknown.

Phase 05-10 stops before ROM production or reserve activation. Space Shooter
shares the unresolved SGDK image chain; RECURSION 94 cannot activate before a
viable Tank build path, while Alex's logo grant and Klele's credited graphics
remain unknown. One screen/correction and the one continuation are consumed;
three screening slots remain unused. This is a bounded prerequisite stop,
not a claim that all possible builds or all four screens were exhausted.
The separate current-identity continuation gate also remains blocked as
described above. An explicit feasibility/reselection or scope decision is
needed; automatic retries would violate the preserved single-use contract.
No new-game playability, broader compatibility, performance, release or
requirement-completion claim follows. Phase 6 remains unstarted.

## Phase5 execution recovery (2026-10-22)

The earlier current-test-identity blocker is repaired in1459c8b: historical setup verification checks immutable bytes and the actual producer, archived enforcement, raw logs, exact configuration and cumulative accounting. It does not require an unchanged current test file and does not authorize repeating setup. Current prelaunch controls remain separately mandatory. The original setup/config/recipe bytes and all consumed counters remain unchanged.

The image runtime ancestry is now reconciled in [phase5-runtime-provenance.json](../evidence/phase5-runtime-provenance.json):178 nongenerated runtime/build inputs match official SGDK180afae85ebd3b75ed4d5101937956eb4baa369b. The earlier2f50 snapshot preceded its March2025 changes; the archive hash mismatch did not imply unlicensed content. Official CMake/Docker/workflow sources, actual image/compiler/library identities and explained generated inputs identify the source/build chain. Exact historical workflow run/trigger and mutable GCC base-image digest remain unknown; no signed attestation or reproduction of the old archive is claimed.

Applicable notices now separately include SGDK MIT, MD Debugger2.6 MIT, MiniMusic zlib and the GCC Runtime Library Exception. The image config disables MegaWiFi, and its actual archive members have no symbols; unknown MPL-version source is outside the included runtime code. The counted-build link maps must establish the final linked members. Original reviews and their unknowns remain historical; current eligibility records22 exact materials and the resolved terms before ROM production.

bb7d08a retains a bounded exact `out/link.map` beside each current Tank ROM and requires its hash/size during pair verification. Reviewed material revisions identify the game, SGDK and authored wrapper separately. Fresh31/31 build and24/24 admission tests pass; current harmless enforcement23/23 passed in10.610312s. These are harness/input results; no game build, route, admission or playability follows from them.

### Current Tank build result

[The Tank build summary](../evidence/phase5-tank-build-summary.json) records two actual ordered524288-byte outputs with exact byte equality and matching linker maps. Exactly two invocations were consumed. A relative-path filing defect after the first successful build was fixed in7486c4e; [explicit recovery evidence](../evidence/phase5-tank-build-recovery.json) preserves its original bytes/counter and leaves unsaved timing/transfer observations unknown. Only the originally planned second build followed. No setup, correction or first build repeated.

This establishes one build-qualified lineage. The two-distinct-lineage verifier still rejects the absent second game; independent routes, admission and candidate Genewhip baseline remain pending. The user resolved RECURSION’s restricted-assembler use purpose as non-commercial. Tank’s completed actions must not rerun on resume.

### First RECURSION setup failure (historical)

The user's non-commercial-use clarification resolved the documented vasm use
condition. One RECURSION screen and its single named environment correction were
consumed. A counted, isolated Linux-equivalent setup compiled vasm 2.0f,
SjASMPlus 1.23.1, zlib 1.3.1 and CPython 3.12.10; its log records both
assembler version checks and the CPython zlib smoke check. The setup script
then rejected output symlinks. The wrapper's subsequent archive capture reached
its 256 MiB stdout cap while traversing the compiler source tree.

Read-only inspection of the preserved capped archive found the complete regular
CPython executable, zlib shared library, stdlib and extension modules, but not
the required `vasmm68k_mot.exe` or `sjasmplus.exe` paths. SjASMPlus's binary is
present only under its source directory; VASM's output is absent from the
archive. Therefore no complete confined tool tree can be recovered from this
capture. The RECURSION ROM invocation counter remains zero and no candidate compiler
script or native ROM build ran. The original setup, correction and screen
counters remain consumed; no additional setup or correction is authorized by
the bounded plan. [The sanitized failure record](../evidence/phase5-recursion-setup-failure.json)
preserves the exact inputs, policy, producer snapshot, captured output and
named blocker. The D-114 continuation below supersedes that attempt's current
status without replacing its evidence.

## D-114 RECURSION setup and clean-build result

The user authorized exactly one additional isolated setup, bound to the original
proposal, ledger, failure event and failed setup receipt. The one-use record
[`phase5-recursion-setup-attempt.json`](../evidence/phase5-recursion-setup-attempt.json)
shows a durable `started` event followed by a successful terminal event. It
preserves the original counters and charges218.514471 seconds against the
remaining1573.190865 seconds. Together with the earlier226.809135 seconds, the
screen used445.323606 seconds of the original1800-second setup ceiling, leaving
1354.676394 seconds unused and unavailable for another attempt.

The repaired selective exporter produced a74,830,336-byte archive. Its
identity-bound receipt records the pinned Linux-equivalent vasm2.0f,
SjASMPlus1.23.1, zlib1.3.1 and CPython3.12.10 outputs and 2,860 declared regular
runtime/output files. The complete toolchain receipt is
[`phase5-recursion-setup.json`](../evidence/phase5-recursion-setup.json); raw
toolchain and ROM bytes remain in ignored local quarantine.

The production screen then performed exactly two clean RECURSION94 builds. Both
ordered outputs are1,048,576 bytes with SHA-256
`d334b18a46c4ffa6436b3e0bb95c0947cf6047ac96d5145cbf2d0f0ead5071ff`; the
comparison is `byte-identical`. The sanitized record is
[`phase5-recursion-build-summary.json`](../evidence/phase5-recursion-build-summary.json),
with the full ignored receipt at its recorded quarantine path. Current counters
remain one screen, one correction and two ROM invocations. The pair verifier
passed for Tank Battle and RECURSION94 as two distinct build-qualified lineages.

Current harmless enforcement passed23/23 after the final producer/test identity
was committed, and the45 build-contract and24 admission-contract tests pass.
The prior pre-consumption enforcement receipt is retained byte-for-byte at
[`phase5-enforcement-d114-preconsumption.json`](../evidence/phase5-enforcement-d114-preconsumption.json);
the current receipt records the post-consumption controls. No ROM bytes or
toolchain binaries are published. No independent route, candidate Genewhip
baseline, admission or playability claim follows from build repeatability.


The offline packaging repair now includes strict declared runtime export,
normal stdlib directory/empty-module handling and string hash propagation into
both clean workspaces. It is not a successful candidate setup observation.
RECURSION has1573.190865s unused under its original1800s setup ceiling, but its
ordinary one-correction permission is consumed. The [single additional setup
proposal](../.planning/phases/GW-05-candidate-admission-and-baseline/05-10-CONTINUATION.md)
is pending explicit authorization; it preserves failed events/counters and
permits no automatic further retry. Non-commercial purpose is settled, and no
new broad phase discussion is needed. Tank's completed pair remains retained.


### Parent offline audit of03

The previous controls-unrun description is superseded: producer control flow shows all three first-repetition captures returned before the aggregate active-field guard; predicate evaluation and repetition2 were not reached. Original report bytes are retained in `evidence/phase5-reference-original-attempts.json`; missing raw values remain unrecoverable.

`evidence/phase5-reference-offline-audit.json` records source authoring defects: the loaded B01 campaign has echo cap2, a plate at x64 and a24-step held-B interaction; the frozen route used a four-echo legacy-layout oracle. At-cap replacement requires C, absent from its schedule. Tank's startup input coverage and fixed spawn-row blockers also require source-backed authoring. These findings concern our route contract, not demonstrated title infeasibility.

Offline controller repairs retain bounded raw outputs/selected traces/producer snapshots and completed-case/max-clock diagnostics on failure, enforce output caps while streaming, and strengthen late-progress and raw-receipt pair validation. Nineteen focused regressions pass without candidate execution. Further source authoring after freeze/qualification needs the [specific correction disposition](../.planning/phases/GW-05-candidate-admission-and-baseline/05-03-CORRECTION.md); no new native work, build repeat, admission or baseline has occurred. Phase5 remains incomplete.

The earlier pending D-114 setup proposal is historical: authorization was granted and consumed successfully, and both distinct repeatable-build pairs are retained. The current stop is reference qualification. Build verification now uses the completed build stage independently of unknown reference outcomes, while retaining exact receipt/output checks. No new candidate setup or build was performed during the offline repair.


### D-115 approved source correction and pre-observation freeze

The user explicitly approved the concrete post-freeze correction. `evidence/phase5-reference-correction-authorization.json` binds the old packages/ledger/reference and one whole-pair cycle. The old reference report is retained byte-for-byte as `evidence/phase5-reference-before-d115.json`; old route-v1 packages remain immutable. The new route-v2 source identities, read-only observers and source reviews are bound in `evidence/phase5-reference-correction-freeze.json`. An initial prelaunch identity-key normalization is separately retained and journaled; it changed no source expectation or input.

Tank selects two human players, uses source-clear lanes, and records an early hit and a distinct late hit. RECURSION uses the actual two-echo B01 campaign, a vertical detour through the canonical static opening, C replacement/release controls, and a24-step final B interaction. Each package declares a bounded source-clocked controller; its input identity binds both the legacy schedule and the full program. Actual driven transitions are retained for exact replay and must agree across fresh repetitions. Read-only state can choose declared controller input; it cannot mutate guest progress.

Before launch,26 reference regressions,24 admission regressions, six syntax-only compilations and actual build-pair verification pass. Source review found no remaining actionable high/medium issue; gameplay remains unqualified. The gate requires committed source/controller bindings and writes an exclusive, durable cycle receipt before any process. Failure, disagreement or interruption consumes the cycle; another output filename cannot renew it. The unchanged3,600 active-field endpoint is explicit and7,200total remains a ceiling. No build, setup, title replacement or Phase6 is permitted.


### D-115 terminal result

The approved cycle is consumed. One Tank primary process timed out at the early action before any scored hit; controls, second repetition and corrected RECURSION were not run. Raw evidence is fully retained and verified. Source explains an authored first-shot parity mistake (movement precedes firing, so the first two-cell bullet path cannot hit stationary P2's even column); the route also equated main-loop iterations with video fields without establishing that timing. The actual Up input lasted216 fields before alignment. These are route-authoring failures, not proven title infeasibility or a Genewhip result.

`evidence/phase5-reference-d115-outcome.json` separates actual process attempts from successful cases and preserves the native report/receipt hashes. The replay gate rejected reuse without entering a process. Phase5 remains incomplete, later gates stay closed, and no further correction/retry follows from D-115. Both distinct construction pairs remain retained; no new build, admission, baseline, public ROM or Phase6 occurred.

### 05-04 fail-closed admission boundary

The new `phase5-independent-game-v1` consumer requires canonical screening,
eligibility, current-reference and report paths. It checks source archive bytes
against the selected eligibility digest, inventories every archived workspace
material, and joins the canonical ROM/build summary to the selected output
receipts. The frozen scenario's ROM, schedule, full input program, oracle,
script, reference build/tool and source identities must match eligibility and
the current D-118 route report. Each admitted reference capture is the canonical
run record from that report, including its cases and input rows. A changed
status, hashes that are merely self-consistent, or an alternate caller-selected
ledger/report cannot create admission.

`tests/evidence/phase5_admission_contract.py --consumer-self-test` uses a
coherent temporary trust context for its synthetic positive case; these bytes
are contract fixtures only. Named cases rewrite their own admission, archive,
pair and route hashes while leaving eligibility or the reference report fixed,
and confirm the production consumer rejects the substitution. The current
enforcement receipt was refreshed after the new validator/test identities
changed; both the earlier receipt and its pre-hardening successor are retained
as separate files. No candidate build or reference emulator was started.

### 05-07 baseline closeout repair

The current baseline is `evidence/phase5-baseline.json`, its complete failure
handoff is `evidence/phase5-failure-inventory.json`, and selected actual process
observations are retained separately in `evidence/phase5-baseline-process.json`.
Production validation checks the frozen roster against current file bytes and
source cases, all row/collection identities, and named stage predicates derived
from the retained process receipt. Rewriting an outcome, reason and observations
cannot promote a failed or unreached stage against unchanged process proof.
Synthetic unit evidence has an explicit separate context. Collection checks the
selected executable against the frozen client before executing it.

First-party capture has a1MiB combined output cap, a600-second total collection
deadline and dependent process-group termination. Public receipts, report and
handoff undergo recursive privacy rejection before writes; arbitrary stderr and
RAM/peek bytes are not published. The offline self-test exercises subprocess
status, output overflow, timeout and chronology without a configured client.

The security-repair collection took6.201968s (superseded by the CR-01 collection above):120 rows,44 pass,12 fail,52 skipped,
12 unknown,0 unsupported and0 infrastructure-error. All six unchanged control
cases pass twice, with both sustained repetitions reaching exactly720 fields.
Tank fails at load. Existing diagnostic output shows RECURSION stops during its
bounded boot prefix with `stop_reason=2`, `unsupported=1`, instruction address
`0x1822`, opcode`0x48e7` and fault address0. Its interaction/sustained/completion
rows are therefore unreached. The retained final machine tick8529990/PC6180
is distinguished from an unknown exact earliest-stop tick: the bounded trace
dropped98483 events after retaining256. A120-iteration host field count alone
does not demonstrate continued guest execution or game compatibility.

The report is188684 bytes, handoff78212 bytes and process receipt27620 bytes.
Thirty-one contract tests include the original forged-pass regression, identity
substitutions, privacy injections, real capture boundaries and dependent-process
termination. Both current artifacts validate; the existing selected9 CTest lanes
and23 harmless enforcement checks pass. Earlier snapshots remain in Git history.
No enforcement producer identity changed, so no refresh was needed. No build,
setup or reference-emulator execution was performed; Phase5 remains pending
parent verification, and Phase6 is unstarted.

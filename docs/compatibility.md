# Compatibility evidence

Genewhip publishes scoped evidence for three named titles: the independently authored Genewhip control, Tank Battle, and RECURSION94. Each title is tied to its admitted source revision, fixture, VA3-NTSC-U profile, scenario, route oracle, input program and build identity. Shared Genewhip runtime and CMake/toolchain ancestry is disclosed; it does not merge the games' author lineages.

The generated v0.2 matrix separates the `core`, `software-sdl`, and `native-sdl` clients and reports `load`, `boot`, `interaction`, `sustained`, and `completion` stages. Every cell has one of six outcomes: `pass`, `fail`, `unsupported`, `skipped`, `unknown`, or `infrastructure-error`, together with a reason, whether the stage was reached, and its evidence dependencies. A pass requires source-derived progress observations and bound evidence identities. A status string alone cannot qualify a row.

## Denominators and limits

The declared core roster contains 24 fresh executions: six control cases repeated twice, plus three source-derived cases for each of the two newly admitted games, also repeated twice. Five stage cells are recorded for every execution, for 120 core stage cells. The separate software-SDL and native-SDL rosters each contain six title cases across Tank Battle and RECURSION94. Their cases do not inherit the core repetition count. The original control-session host roster remains separate from these two-title host denominators.

These counts describe the declared matrix. They are not a compatibility percentage or a claim that a stage passed. Until a current v0.2 observation is generated and its public closure verifies, its matrix cells remain `unknown`; retained Phase 5/6 records are historical context and do not qualify those cells. Completion stays `unknown` unless a separate source-backed completion oracle is admitted and observed. Existing bounded route evidence does not establish whole-game completion, all Genesis software compatibility, physical audio/display quality, or unmeasured platform support.

Phase 5 baselines, failed attempts, excluded candidates and unattempted rows remain retained as separate historical records. The roster keeps the baseline and failure-inventory digests, dispositions, reasons and lineages; the generated matrix marks those historical details as not independently re-verified. See [Phase 5 evidence](phase5-evidence.md) for the full historical record. Equality and content hashes establish byte identity; they do not establish hardware truth, rights or authorship on their own.

## Generate and verify a public closure

Real process contract controls require a host context that can signal and reap
their owned process groups. Local contract invocations opt in with
`--host-process-context` on `v02_qualification_contract.py` or
`v02_matrix_contract.py`; the fast gate accepts the explicit caller marker
`GENEWHIP_PROCESS_CONTEXT=host-cleanup-v1`. Hosted CI declares that marker.
Missing admission fails with `process-host-admission-required`, before process
creation, and is non-qualifying. It is never a successful skip. The marker
records admission, not an OS capability or security guarantee. Use an authorized
host execution context for these controls; a sandbox with denied group signals
does not qualify. The independent no-child regression is
`python3 -I tests/evidence/phase7_process_admission_contract.py`.

Production evidence, benchmark, packaging and adoption executable entry points
declare their host context internally, preserving their normal interfaces.
Importing those modules grants no admission. Pure and mocked tests remain usable
without starting children; fake-launch tests scope the marker while independently
denying OS process creation. Ordinary core builds and the isolated public matrix
verifier do not require this tooling marker.

Given a validated `roster.json` and complete `observations.json` in the input directory, generate the allowlisted public closure:

```sh
python3 -I scripts/evidence/v02_matrix.py project \
  --records-root build/v02/public-input \
  --out build/v02/public
```

The output contains the schema, roster, sanitized observations, isolated verifier, deterministic Markdown and a manifest that binds each member. Copy that directory to an independent location and verify it there:

```sh
python3 -I build/v02/public/verifier.py verify \
  --root build/v02/public \
  --independent-roster evidence/v02-roster.json
```

The verifier reads only the listed closure members, rejects missing, changed, private or unexpected files, validates every matrix key and observation, and regenerates the Markdown for a byte comparison. Historical dispositions are disclosed as digest-only context, not independently verified claims. The closure does not require repository paths or private launch records.

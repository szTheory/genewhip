> **UNACCEPTED WIP — Plan30 HALTED0/3.** Actual admitted tracer failed0/4 on posted-base derivation; matrix/oracle/live/retained acceptance did not run. SOURCE-REVIEW is withdrawn. No live ledger or receipt changed, and no current scoped reader is accepted. The API descriptions below document unaccepted implementation; do not use them as execution authority. See [.planning Plan30 summary](../.planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-30-SUMMARY.md).

# D133 policy settlement and current readers

The D133 scope is a prospective policy liability disposition. It preserves the
original posted actual total and unknown historical delivery tails. It does not
measure those unknown tails, refund selected allocations, renew a purpose, or
accept game compatibility. The exact actual total remains unknown.

The new `scripts/evidence/phase6_settlement.py` module owns policy interpretation;
`phase6_accounting.py` continues to own neutral journal, lock, atomic ledger and
create-once receipt storage. Original ledger objects and D132 source/evidence
remain immutable. Source provenance is the original Genewhip implementation and
the existing repository transaction primitive; no third-party code is added.

The single transaction is `D133-settlement30`; its flat receipt is
`phase6-d133-settlement30-receipt.json`. Its engineering metadata envelope carries
`phase6-policy-settlement-v1`, the original 68-object digest map and raw baseline
SHA, exact authority/source review identities, seven cumulative allocations,
same-boot own-purpose lower bound, and explicit unknown final tails. Units are
seconds. Decimal arithmetic preserves approval values without intermediate
rounding; thresholds never gain an epsilon allowance.
Policy numeric inputs have at most 128 significant decimal digits and exponent
magnitude 128, with a finite nonnegative maximum of one trillion seconds.
Arithmetic uses a local 512-digit context, so accepted precision cannot round an
above-threshold request into admission. The observation-origin comparison has a
0.1-microsecond allowance for binary monotonic-clock serialization; capacity
comparisons have no allowance.

The constructor takes explicit `authority`, `reader_pin`, `observation`,
`expected_objects`, and `baseline_sha256` keyword arguments. The validator accepts
the record plus the same identities. Storage/current-view calls additionally
take an explicit ledger path, `project_root`, and `lock_root`; commit takes the
record, while recovery reloads its original persisted bytes. Contract failures
raise the same freshly loaded canonical `AccountingError` class. CLI failures
return status 1 and a JSON blocked result with unknown actual total. Returned
records and views own their JSON-native data; callers cannot mutate retained
producer state through them. Construction is deterministic for those explicit
inputs and samples no host clock or environment variable.

Current scoped readers validate the original objects, journal and receipt under
the actual canonical lock. Before intent the complete approved allocation is
reserved. A pending receipt retains every liability and denies capacity. A
published receipt changes representation without adding the allocations again.
Conflicting or invalid policy data blocks the D133 scope.

The explicit coordinator selector is `--accounting-preflight --accounting-scope
D133 --settlement-approval PATH --reader-pin PATH`. The settlement CLI provides
`read-current`, `remaining`, `recompute-receipt`, `commit-settlement`, and
`recover-settlement`. Current outputs distinguish posted actual closed seconds,
policy liability/exposure, process protection, remaining policy capacity,
admissible headroom, publication state, and unknown actual total.

Independent clone oracle evidence and exact source admission precede any live
capability. The separate D133 guard denies unselected modes, project reads and
writes, imports, process/network/native execution, unknown descriptors and
directory-relative operations. It is an accidental-execution boundary for
reviewed Python, not a hostile-code security sandbox. Parent-owned approval and
review bytes confer scoped authority; their hashes establish integrity, not
signatures. The live lock-location correction requires separately pinned
explicit approval before live admission.

No current source or clone result establishes retained game/native/build
qualification. Changed coordinator behavior invalidates affected earlier caller
qualification. Product requirements and Phase 6 remain incomplete.

> Closeout update: independent result review accepted50/50 named clone cases. The read-only final-package check passed50/50 retained rows with0 canonical calls and0 unexpected denials. It did not rerun tests. Live ledger/config/protected integrity passed. Pending labels in the preserved prereview evidence section below describe that earlier stage and are superseded by this update. Full records: `.planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-29-SUMMARY.md`. No production settlement or retained-consumer acceptance follows.

# Evidence ledger metadata transactions

`scripts/evidence/phase6_accounting.py` owns `commit_ledger_transaction` and
`recover_ledger_transaction`. These operations add bounded engineering metadata
to a ledger and publish one immutable receipt. They grant no reservation,
financial settlement, normal accounting close, retained-consumer acceptance,
game execution or phase authority. D132 execution is limited to disposable,
byte-identical copies of the approved 68-object entry ledger.

The parent executed the independently source-admitted revision on 2026-10-26:
tracer 3/3, fault matrix 44/44 and oracle controls 3/3 passed. Every lane exited
zero with 14 expected bootstrap denials and zero unexpected denials. Independent
final result review and read-only final packaging are still pending; this is
runtime evidence for the bounded clone slice, not final acceptance.

The exact commands used `python3 -I -B
tests/evidence/phase6_d132_clone_guard.py --case LANE --review-pin
.planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-29-SOURCE-REVIEW.json
--output-root temporary`, substituting `tracer`, `fault-matrix` and
`oracle-negative-controls` for `LANE`. The parent bounded each child to 60
seconds. Recorded child durations were 0.448879, 7.712715 and 0.559253 seconds;
these are process durations, not total purpose wall or a financial settlement.

[Run records](../.planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-29-GREEN-RUNS.json)
bind the exact commands, raw stdout/stderr hashes, source pins and denominators.
Raw passing reports are retained for
[tracer](../.planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-29-GREEN-tracer.stdout.json),
[fault matrix](../.planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-29-GREEN-fault-matrix.stdout.json)
and [oracle controls](../.planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-29-GREEN-oracle-negative-controls.stdout.json).
The matrix denominator is five checkpoint rows, one repeated interrupted
recovery row and 38 rejection/valid-boundary rows. The three negative controls
reached their intended independent semantic assertions. The actual canonical
helper traces are retained; the guard did not substitute a synthetic writer.

Executed source SHA-256 pins:

| Source | SHA-256 |
|---|---|
| `scripts/evidence/phase6_accounting.py` | `ea56fe5a3cc0d7bbadab493bb9fe809899ff04169ae053f90ccc1b577e5d55be` |
| `tests/evidence/phase6_d132_clone_guard.py` | `d0b3cc4b8cf4e58268bd218719e6c953f6172bbc24a52d614ad10e4356005c91` |
| `tests/evidence/test_phase6_ledger_transaction.py` | `53b1c6c189b03f71ce0b7a04f85c61b4bda1ebcce9b337057c224d6bf6242960` |

All runs used the approved entry snapshot SHA-256
`18fd6dbc2f892e4aa5c4c1847adf3b272e6cc71e31f91093d8a6fe1dd6281e5a`.
Results cover serial synchronous exceptions and fresh-object reconstruction
over retained files. They do not prove actual process kill/relaunch, power
loss, arbitrary partial-write interruption, concurrency or hostile containment.
No live-ledger mutation, financial settlement, A/B acceptance, game acceptance
or downstream authority follows. Retained reports establish the observations;
the independent final reviewer owns acceptance.

Both functions take a ledger path and keyword-only `project_root`,
`transaction_id`, `receipt_path`, `expected_objects`, `lock_root`, and optional
`checkpoint`. Commit also takes `record`. The caller owns the root directory,
ledger and flat receipt destination throughout each call. Paths must be free
of symlink redirects and traversal; relative receipt names and canonical
absolute paths immediately beneath that root are accepted. This is a trusted
directory protocol, not protection against hostile concurrent path replacement.

IDs use 1–40 ASCII letters, digits, underscores or hyphens. Records are
JSON-native dictionaries with `kind: "engineering-metadata"`, finite numbers,
string keys, maximum nesting depth 32 and canonical UTF-8 encoding no larger
than 65,536 bytes. Validation snapshots caller data before intent. Expected
objects map each original top-level key to its canonical JSON SHA-256; every
original object must remain exact. Only `ledger_transactions_v1` may be added.
No existing total, policy, anchor or counter is charged or updated.

The journal has schema `ledger-transactions-v1` and a `transactions` dictionary
of at most 128 entries. Each ID binds schema `ledger-transaction-intent-v1`,
its flat receipt path, record, original-object map, canonical `intent_bytes`
and SHA-256, and immutable `receipt_bytes` and SHA-256. Receipts have schema
`ledger-transaction-receipt-v1`, ID, destination, record and intent digest.
Reload validates the complete journal and reconstructs its expected encoding;
missing intent, altered data, digest mismatch and unsupported schema reject.
Digests detect accidental changes; they are not signatures or authorization.

The existing `_locked`, `_load`, `_write`, `_receipt_payload` and
`_publish_receipt_once` implement storage. The same exclusive lock covers path
and original-object revalidation, persisted intent, publication and final
verification. Optional keyword-only `_locked(lock_root=..., timeout_seconds=...)`
permits a caller-owned local lock with nonblocking acquisition capped at two
seconds; omitted keywords retain legacy location and blocking behavior.

Commit durably writes intent through the canonical ledger replacement before
publication. Repeating identical semantics preserves ledger and receipt bytes
and the receipt inode. Identity reuse with changed record or destination
rejects. An identical preexisting receipt is accepted without replacement;
conflicting bytes or links reject. The publisher uses its existing hard-link
create-once operation. A `FileExistsError` collision is revalidated under the
same lock and cannot overwrite a conflicting publication. A failed publication
can leave honest durable intent; it does not imply completion.

Recovery requires existing valid intent and publishes its persisted receipt
bytes. It accepts no replacement record and never appends a second entry.
Its returned `metadata-published` label is not evidence by itself: callers and
independent oracles inspect retained ledger and receipt bytes.

The optional callback receives exactly these named synchronous boundaries:
`before_intent`, `after_intent`, `before_publication`, `after_publication`, and
`after_verification`. `after_intent` follows the completed canonical replace and
fsync. Repeated calls may visit these boundaries over already retained intent;
no second write is required for an identical transaction. An exception propagates
without rollback. Before intent there is no transaction; after intent recovery
can complete publication. Published receipt bytes remain intact at the final
two boundaries.

The clone guard preloads legitimate standard-library dependencies, validates
parent approval/snapshot pins, installs filesystem/import/process/network/native
denials, and exercises named denials before compiling reviewer-pinned project
source. It registers descriptors from its allowed `os.open` calls, validates
descriptor identity, rejects unknown descriptors and `dir_fd`, checks metadata
reads, and wraps the actual `fcntl.flock` primitive. Unexpected attempts remain
sticky failures even when caught. Network/native audit-event probes are labeled
as such. This guard targets accidental execution by trusted code; it is not a
hostile-code sandbox. It never opens fixture paths referenced by ledger data.

`--case tracer`, `fault-matrix`, `oracle-negative-controls` and `final-package`
run only under an independently accepted exact source pin. `--output-root
temporary` allocates a fresh direct system-temporary directory. Parent retains
raw outputs and clone artifacts before cleanup. Lane bounds are parent 60
seconds, internal 55 seconds and lock acquisition two seconds. The matrix tests
five named boundaries, repeated interrupted recovery, rejection/preservation
rows and three independent oracle mutations. Publication collision injection
creates a destination immediately before delegating the actual `os.link` call;
it is a deterministic collision test, not concurrent-writer evidence.

Final packaging does not compile canonical/oracle source or call their APIs.
It checks 50 retained passing rows from the preceding tracer (3), fault matrix
(44) and oracle controls (3), validates exact source/result/snapshot pins and
completed independent result review, then writes only its package report.
Parent-controlled evidence is staged read-only before denial; canonical source
hashes are checked after denial. No hash of this future package is required.

The reviewer-owned final JSON pin uses the ordinary accepted source fields
(`decision: "accepted"`, `reviewer_identity`, `bootstrap_before_compile: true`,
`source_sha256` and `approval_sha256`) plus:

- `stage: "completed-final-result-review"`, `result_review_completed: true`,
  and `scope: "D132 exact clone only"`.
- `entry_sha256` for the actual `06-D132-ENTRY.json`; `source_review_sha256`
  for the actual accepted `06-29-SOURCE-REVIEW.json`. Source review and final
  review use the same reviewer identity, source map, approval and frozen rosters.
- `live_baseline_sha256` equal to the approved entry snapshot,
  `live_baseline_unchanged: true`, and `parent_integrity_checked: true`.
  These record independently reviewed parent integrity evidence; the guard
  never reads the live ledger. Config restoration/protected-path integrity
  remain explicit parent closeout obligations.
- `result_reports` with exactly `tracer`, `fault-matrix` and
  `oracle-negative-controls`. Each binding contains `path` (one exact
  repository-relative file directly in this phase directory), `sha256` (raw
  retained JSON stdout bytes) and `denominator` (3, 44 or 3). Each raw report is
  bounded to 2 MiB and must contain its exact passing roster, source/snapshot
  pins, all 14 named expected denials, zero unexpected denials and actual
  canonical helper coverage. The final pin is written only after these runs.
- `frozen_rosters` from the accepted source review: `tracer`, `checkpoints`,
  `repeated_recovery`, `rejections`, `oracle_controls` and `denial_probes`, with
  lengths 3, 5, 1, 38, 3 and 14 respectively.

Invoke the three executable lanes with `--review-pin` pointing to accepted
`06-29-SOURCE-REVIEW.json`. Invoke `--case final-package` with that flag pointing
to completed `06-29-FINAL-REVIEW.json`. Every invocation also takes
`--output-root temporary`. The owner never creates accepted review pins.

D128 canonical storage and D131's finite synchronous writer probe supply
provenance and failure-model lessons. D132 reuses the real production-owned
storage path instead of substituting the synthetic writer. Current evidence
does not establish arbitrary partial-write/fsync interruption, real process
kill/relaunch, power-loss or directory durability, concurrent writers, hostile
containment, production recovery acceptance or game compatibility. Live ledger
mutation requires separate authority and evidence.

# CI timing baseline

`scripts/evidence/ci_baseline.py` reads completed GitHub Actions workflow runs and
writes a bounded report for analysis. Collection happens after the measured run;
the collector sends only `GET` requests and never dispatches, reruns, cancels, or
changes a workflow. It stores sanitized timing and identity facts, not API
responses or logs.

## Collect and validate

Set `GH_TOKEN` or `GITHUB_TOKEN` in the invoking shell when private repository
access is needed. The collector uses that explicit token only for API requests;
it does not write it to the report. Public repository collection can use the
unauthenticated API subject to GitHub's rate limits.

For an exact measured source, set `PHASE8_SOURCE_SHA` to the full SHA of the
workflow execution checkout, then run:

```sh
python3 -I scripts/evidence/ci_baseline.py collect \
  --repo szTheory/genewhip \
  --workflow .github/workflows/ci.yml \
  --source-sha "$PHASE8_SOURCE_SHA" \
  --max-runs 3 \
  --max-attempts 3 \
  --output evidence/phase8-ci-baseline.json

python3 -I scripts/evidence/ci_baseline.py validate \
  --input evidence/phase8-ci-baseline.json \
  --require-source "$PHASE8_SOURCE_SHA" \
  --require-libretro
```

`collect` exits nonzero and writes an incomplete report when it observes a
bounded or identity failure that can be recorded safely. The report's `errors`
and `unknowns` retain those reasons. Input, API, or output failures that prevent
creating a report are printed as stable rejection codes. `validate` is offline;
it checks the report against its source and timing invariants.

## Bounds and identity

The defaults collect at most three matching runs and three attempts per run.
The CLI accepts a maximum of 100 runs and three attempts per run. An exceeded
attempt limit is recorded as truncated and cannot produce a complete baseline.
Each response and the final report are capped at 1 MiB; workflow source is
capped at 256 KiB; one request is capped at 30 seconds and one collection at
180 seconds. The collector reads at most 100 jobs per attempt and 100 steps per
job. Pagination, response-size, schema, authentication, and time-limit failures
remain visible and make the collection incomplete.

Every attempt is bound to its run ID and attempt number, event, `head_sha`,
workflow path, and workflow bytes fetched from the repository at that exact
source SHA. The report retains both the Git blob SHA and SHA-256 of those bytes,
plus a digest of the parsed job dependency graph. It does not read the local
checkout to stand in for the measured workflow. A pull request's source means
the execution SHA reported by the workflow run; the collector does not replace
it with a guessed PR head commit. A source filter never falls back to an older
revision.

All observed terminal attempts are retained, including failures, cancellations,
and skips. `--require-libretro` accepts only the latest attempt of a completed,
successful `pull_request`, `merge_group`, or `push` run when its successful
`required-aggregate` job directly requires a successful Linux `libretro` job.
That job must report successful Linux x86_64, actual-module, AddressSanitizer,
and UndefinedBehaviorSanitizer steps. Earlier successful attempts do not hide a
later failed attempt. The lane's separate actual-module route evidence is still
validated by its own production validator.

## Metric definitions

| Field | Meaning |
|---|---|
| `queue_seconds` | Workflow `created_at` to `run_started_at`. |
| `wall_seconds` | Workflow `run_started_at` to authoritative `completed_at`. If the API omits or invalidates the end time, this stays unknown; `updated_at` is not a substitute. |
| Job `elapsed_seconds` | That job's own `started_at` to `completed_at`. A skipped job has no invented interval. |
| Step `elapsed_seconds` | That step's own timestamps when both are present. Steps are observations inside jobs and are not added to runner totals. |
| `critical_path.observed_weighted_seconds` | Longest dependency path in the exact source workflow graph, weighted by observed job elapsed time. Failed and cancelled jobs retain their measured intervals. |
| `critical_path.wall_span_seconds` | Earliest observed start to latest completion on that weighted path. |
| `critical_path.unavailable_gaps_seconds` | Wall span less weighted job time when the span is at least the weighted time. It describes observed scheduling gaps, not measured job queue. |
| `runner_seconds_by_os` | Sum of observed job intervals by normalized runner OS, including failed and cancelled attempts. Skips contribute no interval. |
| Job `job_queue` | Always unknown because the workflow jobs API does not expose an authoritative per-job queue interval. |

Step names are classified as checkout, setup, dependency preparation, build,
test, other, or unknown. Step intervals may overlap, so they are not summed to
derive job duration. The report's critical path is a dependency-weighted
observed path; it is not presented as an exact wall-clock critical path.

`pull_request`, `merge_group`, and `push` remain separate cohorts. `schedule`
and `workflow_dispatch` are also separate and cannot be pooled into a normal
required-check trend. Public standard GitHub-hosted runners have billing marked
`not_applicable`; private or nonstandard runners have billing marked `unknown`
unless an authoritative account-level amount is supplied by another system.
This collector does not estimate or claim actual charges.

## Current evidence status

The contract tests use a fake API transport and make no GitHub requests. They
prove the collector and validator's limits and semantics, not hosted runtime
performance. Phase 8's source-bound hosted collection is performed in Plan
08-05 after the Libretro CI lane is integrated. Until then, there is no Phase 8
CI baseline claim. A single available run is one observation, not a stable
trend; missing event cohorts and unavailable metrics stay visible.

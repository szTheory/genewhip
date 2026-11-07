# CI timing baseline

## Phase 9 observation and no-change decision

After v0.3.0 was published, the read-only collector validated one exact-source
main-push observation: [run 42252014332, attempt 1](https://github.com/szTheory/genewhip/actions/runs/42252014332/attempts/1),
source `f951a3d5b409ea7b291964e2dd4d3dd67e228698`. Its workflow and graph
digests are recorded in
[`evidence/phase9-ci-before.json`](../evidence/phase9-ci-before.json). The run
had a 784-second observed weighted path (`desktop` → `required-aggregate`),
2,293 macOS and 47 Linux runner seconds. The workflow completion time was
unavailable from the API; job queue time remains unknown. These public standard
runner seconds are not a cost estimate.

Two successful post-release pull-request runs were also queried:
[PR #90 run 42249764178](https://github.com/szTheory/genewhip/actions/runs/42249764178)
and [PR #91 run 42252598866](https://github.com/szTheory/genewhip/actions/runs/42252598866).
Their workflow artifacts retained their exact merge-checkout source identities,
but the later read-only Actions API responses no longer included the associated
pull-request identity. The collector therefore marked both reports incomplete
(`pull-request-identity-missing`) instead of treating the current squash merge
SHA as the original run source. Their report digests, run identities, and
rejection reasons are retained in
[`evidence/phase9-ci-comparison.json`](../evidence/phase9-ci-comparison.json).
No PR timing sample was accepted from those incomplete reports.

The observed repeated setup candidate runs the same
`bash scripts/ci/prepare_evidence_dependencies.sh` command: safety recorded 317
seconds and desktop recorded 379 seconds in separate macOS jobs in run 42252014332. The
safety job was not on that run's measured weighted path; the path was desktop
followed by the aggregate. Sharing those outputs would require a new
cross-job artifact producer/consumer boundary and source-bound byte checks.
The workflow has no existing validated transfer boundary for these inputs, and
one run cannot establish net path savings from introducing one. No cache,
dependency, concurrency, or job-graph change was made; `.github/workflows/ci.yml`
is unchanged. The recorded outcome is `no-change`: `phase9-ci-after.json` and a
second release are not applicable.

After the adoption-workflow receipt fix merged, [main run 42255692443](https://github.com/szTheory/genewhip/actions/runs/42255692443)
passed the required lanes at source `9b638f5b16236c28da874cd5f53a1294c99484b9`,
including the Linux container-runner contracts and production package tracer.
It is retained as merge verification, not as an optimization-after sample.

The Phase 8 observation remains unchanged: one pull-request run, 901 weighted
seconds, unavailable workflow completion and job queue times, and public
standard-runner billing marked not applicable. Validate the Phase 9 decision
and its release link with:

```sh
python3 -I tests/evidence/ci_comparison_contract.py
python3 -I scripts/evidence/ci_comparison.py validate \
  --input evidence/phase9-ci-comparison.json \
  --require-first-release evidence/phase9-release.json
```

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
workflow execution checkout. For a pull request, also set `PHASE8_HEAD_SHA` and
`PHASE8_BASE_SHA` to the API head and base SHAs, then run:

```sh
python3 -I scripts/evidence/ci_baseline.py collect \
  --repo szTheory/genewhip \
  --workflow .github/workflows/ci.yml \
  --source-sha "$PHASE8_SOURCE_SHA" \
  --head-sha "$PHASE8_HEAD_SHA" \
  --base-sha "$PHASE8_BASE_SHA" \
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
source SHA. The execution source SHA is distinct from the API's PR head and base
SHAs. For pull requests, collection requires the exact execution source SHA and
checks it against the PR's merge SHA; it also checks the API head and base
identities and derives `refs/pull/<number>/merge` from the API PR association.
The report retains the Git blob SHA and SHA-256 of the workflow bytes plus a
digest of the parsed job dependency graph. It does not read the local checkout
to stand in for the measured workflow. A source filter never falls back to an
older revision.

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

GitHub's [job execution time guidance](https://docs.github.com/en/actions/how-tos/monitor-workflows/view-job-execution-time)
describes displayed job execution time; these are wall-time observations, not
cost measurements. GitHub documents that public repositories using standard
GitHub-hosted runners have no billable minutes; private-repository hosted job
minutes round up per job, with published standard Linux x64 2-core and macOS
3/4-core rates in its [runner pricing reference](https://docs.github.com/en/billing/reference/actions-runner-pricing).
Accordingly, this public run's billing status is `not_applicable`, and its
observed runner time must not be read as an estimated charge.

## Current evidence status

The retained Phase 8 observation is [PR #87](https://github.com/szTheory/genewhip/pull/87),
[run 42118267359](https://github.com/szTheory/genewhip/actions/runs/42118267359),
attempt 1, on
execution checkout `79efa8c5c82ca36e3bbf1fa6c8a3c71fd5f11bf0`. Its PR head is
`8160ee3d10c0e529ead479bc56b3292661b8ddcd`, base is
`6d96c913a7e5c4e5fdd6f2dd01301587ff22038f`, and event ref is
`refs/pull/87/merge`. The run completed successfully: all required jobs and the
`required-ci` aggregate passed, while extended, v0.2 continuation, and
attestation jobs were skipped under PR event policy. The Linux `libretro` job
passed and its run/attempt-scoped route artifact validates against that same
execution checkout and workflow SHA-256
`ea68c685060506d5dd140908cd22ba6e9b2a1ba07b8a694217290eb1c83532b3`.

The observed job span is 905 seconds from 22:04:18Z to 22:19:23Z. The measured
dependency path was safety to required aggregate, with a 903-second wall span,
901 weighted job seconds, and a 2-second observed gap. The workflow run API
returned no `completed_at`, so workflow-level `wall_seconds` remains unknown;
the observed job span is a separate metric. Public standard-runner billing is
not applicable. The baseline contains one PR attempt, zero observations in the
other event cohorts, and is not a stable trend. Unknown and skipped outcomes
remain in [the machine-readable baseline](../evidence/phase8-ci-baseline.json)
and [route report](../evidence/phase8-libretro-route.json).

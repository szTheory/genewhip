# CI delivery and repository preflight

## v0.2.0 exact-byte adoption status

The currently staged v0.2.0 SDK and desktop archives are local development-only
qualification outputs. Their adjacent receipts bind local source-snapshot SHAs,
exact archive SHA-256 values, inventory identities, and extracted-byte smoke
results; they do not establish trusted publication provenance. The public source,
hosted qualification, protected promotion, and post-publication download-adoption
steps remain pending. Public v0.1.0 remains immutable.

For an actual download, the protected publisher validates the exact source,
workflow, ref, run and attempt, inventory, signed attestation invocation, and
archive subject digests before promotion. The adopter must complete those trusted
checks before executing a bundled verifier, executable, or build script. An
authenticated archive may provide its own verifier after that check; a separate
source download is not an adopter prerequisite. A checksum sidecar and an
archive's self-hashed manifest establish byte consistency, not trusted origin.

Package version 0.2.0 retains C API version 4 and input-log format
`genewhip-input-log 1`; neither contract changed for this package release. SDK
build/embed examples run offline from relocated package bytes. A host that cannot
open audio continues video-only, but that outcome cannot qualify an audio row.

Pull requests, default-branch pushes, merge-queue (`merge_group`) events, and
manual runs use the same `required-ci` aggregate. The required fast lanes include
privacy, rights, package, documentation, schema, matrix, and delivery contracts,
plus a bounded current-source smoke through both public title paths. Expensive
v0.2 runtime and three-workload qualification lanes run only on a default-branch
push or explicit manual dispatch. Their source, head, base, run, and attempt
identities are joined before attestation; the three workload jobs are ordered
serially and keep separate host identities. A schedule runs the informational
extended workflow. Performance thresholds remain informational; measurement
and output contracts are required. Fork pull requests have read-only workflow
permissions, no secrets, and checkout credentials disabled. The trusted
merge-group lane builds the merge-group commit itself; successful PR artifacts
do not qualify a later integration SHA. A passing plan-only receipt does not
establish compatibility, native capability, or publication provenance.

The package job emits an attempt-scoped evidence closure that retains bounded
dimension inputs and referenced child reports. The final qualification job
reopens those bytes and calls the same semantic validators as the producer; it
does not rerun guest workloads. This is prepublication readiness only. Final
release credit still requires authenticated downloaded-byte adoption.

## Local repository preflight

### Phase 7 v0.2 sanitized source preparation

The v0.2 coordinator resolves the previously authorized public destination from
the retained local Phase 4 preflight packet. It checks out the destination's
current `main`, overlays only the tracked product source, and excludes planning
history, generated build/package output, Phase 5 historical evidence/receipts
and screening ledger, crosswalks, environment files, and local caches. The
source, retained fixture bytes, and
upstream notices remain together. For the two Phase 5 fixtures, preparation
revalidates the full local historical admission first, then emits
`evidence/phase5-public-admissions.json`, a narrow projection of source archive,
material terms, ROM, route-input, and notice identities. The public validator
checks those retained bytes without `.planning`; it does not reproduce the
omitted private selection ledger or historical run receipts. It then requires
the new snapshot's only
parent to be the observed public `main`, scans the reachable public history and
current tree, and re-reads the destination's visibility, branch policy, write
capability, head, and base through the repository preflight.

Prepare a reviewable local candidate and policy packet with:

```sh
python3 -I scripts/release/v02_qualification.py \
  --mode stage-public --prepare-only \
  --publication-copy build/v02/publication \
  --scope evidence/v02-execution.json \
  --out build/v02/preflight.json
```

This command does not push, open a pull request, merge, or dispatch hosted
work. The packet records separate private-source, public-tree, public-base, and
public-head identities. A `blocked` packet preserves the observed preflight
blockers; a local snapshot or synthetic contract alone does not qualify any
Phase 7 requirement. The candidate and packet are ignored local outputs and
must be reviewed before the later protected pull request step.

If a pushed source candidate fails its exact required CI check before merge or
qualification dispatch, the coordinator supports an explicit `retry-source`
transition with a newly reviewed packet. It reopens the exact old PR and check,
confirms the same public base and original qualification budget, archives the
prior journal bytes with a digest under `build/v02/failures/`, and starts a new
candidate attempt without carrying forward prior qualification credit. The
original `started_at` is preserved across the retry; ordinary delivery still
rejects an implicit candidate/journal mismatch. A merged, dispatched, active,
ambiguous, or stale attempt cannot be replaced through this path.

Run the synthetic contract check with:

```sh
python3 scripts/ci/repository_preflight.py --self-test
python3 tests/evidence/repository_preflight_contract.py
```

`--self-test` parses recorded synthetic GitHub API response shapes only. Its
`kind` is `synthetic_contract_only`, `hosted_evidence.outcome` is `not_run`,
`qualifies_rel_03` is false, and `mutations_performed` is zero. These results
are not observations of an account or hosted CI and cannot close REL-03.

Before selecting or publishing a first remote, prepare a local-only source and
artifact packet from the reviewed Phase 3 base:

```sh
python3 scripts/ci/repository_preflight.py \
  --prepare-packet --phase3-base <full-phase-3-commit> \
  --repository-search <not_observed|timeout|found|no_match> \
  --out build/phase4/delivery-preflight-packet.json
```

Add `--account-connected` only when an authorized account context was actually
observed. This mode performs local reads only. It records the current branch
and source SHA, reachable history counts, dirty project-relative paths,
current-tree and history privacy findings, exact local archive/log digests,
and whether the staged release inventory matches its listed bytes. Matched
content, account identity, and Git remote URLs are never included. History
findings identify only repository-relative paths and finding categories;
commit identity values are counted but redacted. Binary versions are kept in
a separate inventory when the current fixture path passes its manifest,
source, and notice checks; that current check does not claim every historical
binary digest matches today's manifest. The packet deliberately leaves owner,
visibility, history disposition, repository settings, hosted checks, and release
results unset. Resolve those against an explicitly named destination before
any remote write.

When the authorized repository is known, a maintainer can run a GET-only
inspection by naming it explicitly. The script never discovers a remote or
chooses an owner/repository on the caller's behalf:

```sh
GH_TOKEN=... python3 scripts/ci/repository_preflight.py \
  --inspect --repository OWNER/REPO \
  --expected-head <40-character-source-sha> \
  --expected-base <40-character-base-sha>
```

The token is optional for public metadata. The inspector reads the current
default branch's effective active rules from
`GET /repos/{owner}/{repo}/rules/branches/{branch}`. That endpoint includes
applicable organization and repository rules and requires only repository
metadata read access. The desired publisher policy is an active ruleset
targeting `main` that requires `required-ci` and pull requests; the accepted
project policy does not impose a human approval count. Disabled, evaluating,
nonmatching, or missing rules do not qualify.

The classic branch-protection endpoint requires repository Administration
read. If that read is denied, preflight and the release publisher accept policy
only when the effective branch-rules response independently confirms both the
required aggregate and pull-request policy. No minimum human approval count is
imposed by this project; the internal code review and required automated gate
remain in place. A denied effective-rules request or an incomplete rules
response is a blocker. The trusted publisher uses the
standard `GITHUB_TOKEN` with its existing `contents: write`, `actions: read`,
and `attestations: read` permissions; the effective-rules endpoint is available
with metadata read, so no Administration permission, PAT, or additional App
credential is needed for the supported ruleset path. Classic-only protection
can qualify when the inspection credential can read it; if neither path proves
the required policy, publication stops before the visibility change.

The token is read only from the process environment, sent only in the HTTPS
Authorization header, and never included in output or exception text. All
requests use HTTP GET. The tool does not create runs, change settings, modify
protections, merge, or publish. Nonzero exit means the inspection contains
blockers. Output contains
the destination, visibility, default branch, Actions policy/workflow
permissions, auto-merge setting, branch protection/ruleset check and review
policy, expected source/base identities, allowed merge methods, and the
authenticated caller's repository write-capability record. Unknown is retained
as a blocker.

Repository REST settings cannot prove that GitHub-hosted macOS runners are
available to the account or that Cocoa/CoreAudio tests actually run there.
Accordingly, native `macOS-15` capability remains `unverified` in repository
preflight and does not count as a repository-policy blocker. Only a real
source-bound hosted lane can establish it; neither a local mock nor an API
policy response is a hosted pass.

For this authorized publication, the actual destination and history choice are
recorded in `build/phase4/delivery-preflight.json`; the public copy is a pair
of sanitized snapshots anchored at the reviewed Phase 3 tree, preserving the
original local history. Recreate the record after the final snapshot is built:

```sh
python3 scripts/ci/repository_preflight.py --inspect-authorized \
  --repository szTheory/genewhip --destination szTheory/genewhip \
  --visibility public \
  --history-disposition sanitized-snapshots-preserve-local-history \
  --publication-copy build/phase4/publication \
  --expected-head <publication-phase-4-sha> \
  --expected-base <public-main-sha> \
  --out build/phase4/delivery-preflight.json
```

## GitHub policy and authorization notes

The workflow is designed for an active ruleset targeting the current default
branch that requires `required-ci` and a pull request. This is the policy path the
release job can re-read with its standard token immediately before publication.
Classic branch protection may also qualify when directly readable. Do not
weaken either policy to clear a failed preflight. If neither observed policy
path proves both requirements, use the emitted blocker names to prepare a
reviewable, repository-specific policy change packet; an authorized owner must
apply any settings change. Repository API errors are typed as missing,
permission denied, unsupported service, or transport failure. A denied
effective-rules endpoint is never treated as an empty or successful policy.

Workflow `GITHUB_TOKEN` permissions are explicitly read-only for untrusted
fork validation. Events caused by `GITHUB_TOKEN` normally do not start another
workflow. The documented exceptions are `workflow_dispatch` and
`repository_dispatch`, which always start a run. A token-created or token-
updated PR can start `pull_request` workflows for `opened`, `synchronize`, or
`reopened`, but those runs enter an approval-required state; other PR activity
types do not start runs. GitHub also may hold fork PR runs for approval under
repository, organization, or enterprise policy (by default, first-time
contributors require approval). A maintainer with write access reviews the
workflow diff and approves the run in the PR UI. A PAT or GitHub App is not a
default requirement: GitHub documents them when automation must create a PR
whose workflows run without that approval state. Repository/API preflight
does not inspect organization-level policy the caller cannot read and never
performs approval actions.

The workflow uses GitHub's `merge_group` event so required checks can report
on the integration commit used by a merge queue. The REST preflight follows
the documented repository, Actions-permissions, effective branch-rules, and
(when readable) classic branch-protection read endpoints. Current syntax and
endpoint references:

- [Workflow syntax and permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)
- [Events that trigger workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)
- [Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GITHUB_TOKEN event behavior](https://docs.github.com/en/actions/concepts/security/github_token#when-github_token-triggers-workflow-runs)
- [Approving workflow runs from forks](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/approve-runs-from-forks)
- [Protected-branch REST API](https://docs.github.com/en/rest/branches/branch-protection)
- [Get rules for a branch (active rulesets with metadata-read permission)](https://docs.github.com/en/rest/repos/rules#get-rules-for-a-branch)
- [Actions permissions REST API](https://docs.github.com/en/rest/actions/permissions)
- [Repository rulesets REST API](https://docs.github.com/en/rest/repos/rules)
- [Get a repository](https://docs.github.com/en/rest/repos/repos#get-a-repository)

Repository settings and the sanitized publication copy are recorded by the
authorized preflight command above. Hosted qualification, merge, release and
download evidence remain pending until `qualify_delivery.py --run` and
`--verify` record actual results; local contracts are not hosted evidence.

## Trusted release promotion

After pushing a clean sanitized source branch and opening its pull request,
run the delivery monitor with the exact PR head and current `main` base. Once
`required-ci` succeeds and the head/base are rechecked, enable native
auto-merge through the GitHub connector. The monitor then observes the merged
source, the complete trusted CI run, dispatches the publisher, and writes a
local-only run record:

```sh
python3 scripts/release/qualify_delivery.py --self-test
python3 scripts/release/qualify_delivery.py --prepare-merge \
  --repository szTheory/genewhip --preflight build/phase4/delivery-preflight.json \
  --pull-request <number> --expected-head <40-character-pr-head> \
  --expected-base <40-character-main-base>
# Enable native auto-merge with the GitHub connector after prepare-merge reports ready.
python3 scripts/release/qualify_delivery.py --run \
  --repository szTheory/genewhip --preflight build/phase4/delivery-preflight.json \
  --pull-request <number> --expected-head <40-character-pr-head> \
  --expected-base <40-character-main-base> \
  --evidence-out build/phase4/delivery-evidence.json
python3 scripts/release/qualify_delivery.py --verify \
  --repository szTheory/genewhip --preflight build/phase4/delivery-preflight.json \
  --evidence build/phase4/delivery-evidence.json \
  --download-dir build/phase4/downloaded-release
```

`--self-test` is synthetic and never counts as hosted evidence. `--prepare-merge`
waits for `required-ci` and rechecks the current head/base without mutation.
Enable native auto-merge through the GitHub connector only after it reports
ready, then run `--run` to observe the merge. It never bypasses a rule or merges
directly. `--verify`
checks the successful CI and publisher workflow paths, exact merged source,
release/tag, all eight advertised asset digests, the package inventory and
privacy scan, then executes the downloaded SDK and desktop adoption commands.
The report at `build/phase4/delivery-evidence.json` is local evidence input to
the existing Phase 4 report; it is not committed into the sanitized public
source or release archive.

The package lane assembles the two exact archives already qualified by
`scripts/package_sdk.py` and `scripts/package_desktop.py`, their checksum files,
their qualification receipts, a deterministic inventory, and `SHA256SUMS`.
It never rebuilds either archive in the publisher. The CI workflow uploads the
flat inventory as an immutable Actions artifact named with the run ID and
attempt. On a successful push to `main`, that package job also creates GitHub
artifact attestations for both archives and `inventory.json`; the attestation
permission and OIDC token are limited to that job.

Publication is an explicit `workflow_dispatch` on `main`. The operator supplies
the successful `Required preview checks` run ID, attempt, and full source SHA.
The publisher checks those inputs against the GitHub Actions API, confirms that
the source run is a successful same-repository push to `main`, resolves the
workflow ID to `.github/workflows/ci.yml`, and requires that run's `required-ci`
job to have succeeded. It downloads only the matching run artifact and verifies
the archives and inventory with `gh attestation verify`, constrained to the
repository, CI workflow, `refs/heads/main`, source commit, GitHub OIDC issuer,
and exact SLSA invocation ID containing both run ID and attempt. A checksum
alone is never accepted as provenance. The publisher runs code checked out from
the protected default branch; it treats downloaded content only as data.

The selected release inventory has eight named files: two archives, two
sidecars, two qualification receipts, `inventory.json`, and `SHA256SUMS`.
Package archives carry their evidence and required license notices. The
publisher validates the full local inventory, creates or reuses only a tag
pointing at the qualified source SHA, resumes an identical draft, and re-reads
server asset digests before making the release public. Existing mismatched
tags, conflicting assets, empty inventories, and published partial releases
fail closed. Ambiguous create/upload/publish responses are resolved with a
read-only requery. A repository-wide Actions concurrency queue serializes
publication and does not cancel an in-progress publisher.

The publisher needs only the workflow-dispatch event and the run-specific
Actions artifact. Its `GITHUB_TOKEN` has `actions: read`, `attestations: read`,
and `contents: write`; no PAT, Git push, package install, or build permission is
used. GitHub currently offers artifact attestations on Free/Pro/Team plans only
for public repositories; private/internal repositories require Enterprise
Cloud. The actual destination's plan, rules, token behavior, hosted macOS lane,
run, source merge, and publication still require the plan 04-14 preflight and
explicit release packet. Local synthetic contracts and package receipts do not
close REL-03.

The trigger uses the `workflow_dispatch` event rather than automatically
publishing every successful main push. GitHub documents that `workflow_run`
starts with write permissions and warns against running downloaded code on that
event; it also documents that `workflow_dispatch` is an exception to the usual
`GITHUB_TOKEN` event suppression. This flow therefore keeps release intent
explicit and consumes only an exact attested artifact from a previously
successful CI run.

Current primary references:

- [Workflow syntax, job permissions, and concurrency queues](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)
- [Workflow events, including workflow_run security behavior and workflow_dispatch](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)
- [Artifact attestations and `gh attestation verify`](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
- [GitHub CLI attestation identity and provenance flags](https://cli.github.com/manual/gh_attestation_verify)
- [Actions artifact REST API](https://docs.github.com/en/rest/actions/artifacts)
- [Workflow-run and attempt APIs](https://docs.github.com/en/rest/actions/workflow-runs)
- [Workflow-job attempt API](https://docs.github.com/en/rest/actions/workflow-jobs)
- [Git reference API](https://docs.github.com/en/rest/git/refs)
- [Release API and uploaded asset digests](https://docs.github.com/en/rest/releases/releases)

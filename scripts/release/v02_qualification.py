#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-bound v0.2 qualification plan, runtime orchestration and proof close."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time
import datetime
import urllib.parse
import uuid
import shutil
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
DIMENSIONS = ("core", "host", "host-native", "media", "safety", "determinism", "measurements",
              "public-matrix", "package", "docs", "privacy", "rights")
REQUIRED_DIMENSIONS = DIMENSIONS
IDENTITY_FIELDS = ("source_sha", "head_sha", "base_sha", "run_id", "run_attempt")
NATIVE_REQUIRED = "host-native"
PUBLIC_PHASE5_HISTORY = {
    "phase5-baseline.json", "phase5-baseline-roster.json", "phase5-failure-inventory.json",
    "phase5-current-reference.json", "phase5-reference-d118.json",
}


def _sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(root: pathlib.Path, *args: str, check: bool = True) -> str:
    """Run a bounded Git read/write without including remote diagnostics in errors."""
    try:
        result = subprocess.run(["git", *args], cwd=root, text=True,
                                capture_output=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("public-snapshot-git-command-failed") from None
    if check and result.returncode:
        raise ValueError("public-snapshot-git-command-failed")
    return result.stdout.strip()


def _external(argv: list[str], *, cwd: pathlib.Path = ROOT, timeout: int = 120,
              check: bool = True, env: dict[str, str] | None = None,
              phase: str | None = None,
              owned_roots: tuple[pathlib.Path, ...] = (),
              scratch_limit_bytes: int | None = None,
              stdout_limit_bytes: int | None = None) -> subprocess.CompletedProcess[str]:
    """Run delivery commands under the established monitored PGID boundary."""
    scope = json.loads((ROOT / "evidence/v02-execution.json").read_text(encoding="utf-8"))
    child_env = os.environ.copy()
    if env:
        child_env.update(env)
    started_at = child_env.get("GENEWHIP_QUALIFICATION_STARTED_AT")
    phase = phase or child_env.get("GENEWHIP_QUALIFICATION_PHASE") or "preparation"
    if started_at:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        _require_hosted_budget(started_at, now, scope, phase=phase)
        elapsed = (_parse_utc(now) - _parse_utc(started_at)).total_seconds()
        batch = scope["qualification_batch"]
        boundary = (batch["runtime_wall_seconds"] if phase == "runtime" else
            batch["runtime_wall_seconds"] + batch["package_wall_seconds"] if phase == "package" else
            batch["wall_seconds"] if phase == "close" else
            batch["wall_seconds"] - batch["close_wall_seconds"])
        timeout = min(timeout, max(0.001, boundary - elapsed))
    limits = dict(scope["per_child_limits"])
    if scratch_limit_bytes is not None:
        limits["max_scratch_bytes"] = min(limits["max_scratch_bytes"], scratch_limit_bytes)
    if stdout_limit_bytes is not None:
        if stdout_limit_bytes <= 0:
            raise ValueError("hosted-delivery-stdout-limit-invalid")
        for key in ("max_stdout_stderr_bytes", "max_capture_bytes", "max_retained_bytes"):
            limits[key] = min(limits[key], stdout_limit_bytes)
    limits["wall_seconds"] = timeout
    scratch = ROOT / "build/v02/coordinator-external-attempts"
    label = f"external-{os.getpid()}-{time.monotonic_ns()}"
    temporary_root = scratch / (label + ".tmp")
    temporary_root.mkdir(parents=True, exist_ok=False)
    child_env.update({"TMPDIR": str(temporary_root), "TMP": str(temporary_root),
                      "TEMP": str(temporary_root)})
    try:
        attempt = _bounded_command(argv, limits=limits, scratch=scratch, timeout=timeout,
            label=label, env=child_env, cwd=cwd, check=check,
            scratch_roots=(temporary_root, *owned_roots))
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        raise ValueError("hosted-delivery-command-unavailable:" + pathlib.Path(argv[0]).name) from None
    result = subprocess.CompletedProcess(argv, int(attempt.get("returncode") or 0),
        str(attempt.get("streams", {}).get("stdout", {}).get("text", attempt.get("stdout_tail", ""))),
        str(attempt.get("streams", {}).get("stderr", {}).get("text", attempt.get("stderr_tail", ""))))
    if stdout_limit_bytes is not None:
        stream = attempt.get("streams", {}).get("stdout", {})
        encoded = result.stdout.encode("utf-8")
        if (stream.get("truncated") is not False or
                stream.get("observed_bytes") != stream.get("retained_bytes") or
                stream.get("observed_bytes", stdout_limit_bytes + 1) > stdout_limit_bytes or
                stream.get("sha256") != hashlib.sha256(encoded).hexdigest()):
            raise ValueError("hosted-delivery-stdout-not-byte-exact")
    if result.returncode == 0 and attempt.get("process_group_cleanup") == "confirmed":
        shutil.rmtree(temporary_root)
    if check and result.returncode:
        combined = (result.stdout + "\n" + result.stderr).lower()
        if any(term in combined for term in ("not logged in", "not authenticated", "unauthorized", "401")):
            raise ValueError("github-authentication-required")
        raise ValueError("hosted-delivery-command-failed:" + pathlib.Path(argv[0]).name)
    return result


def read_bounded_git_blob(candidate: pathlib.Path, ref: str) -> bytes:
    """Read a small Git blob through the monitored process-group boundary."""
    ceiling = 128 * 1024
    result = _external(["git", "show", ref], cwd=candidate, timeout=15,
        scratch_limit_bytes=ceiling, stdout_limit_bytes=ceiling)
    return result.stdout.encode("utf-8")


def _gh_json(repository: str, endpoint: str, *, phase: str = "preparation") -> Any:
    encoded = urllib.parse.quote(repository, safe="/")
    result = _external(["gh", "api", f"repos/{encoded}/{endpoint}"], timeout=45, phase=phase)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        raise ValueError("github-response-invalid") from None


def _parse_utc(value: str) -> datetime.datetime:
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        raise ValueError("hosted-time-identity-invalid") from None
    if parsed.tzinfo is None:
        raise ValueError("hosted-time-identity-invalid")
    return parsed.astimezone(datetime.timezone.utc)


def _validate_hosted_run(run: dict[str, Any], repository: str,
                         expected_source_sha: str, *, allow_active: bool = False,
                         expected_event: str = "push", expected_nonce: str | None = None) -> dict[str, str]:
    """Validate the selected exact-source attempt and immutable run facts."""
    if not isinstance(run, dict):
        raise ValueError("hosted-run-record-invalid")
    run_id = run.get("id")
    attempt = run.get("run_attempt")
    created_at = run.get("created_at")
    repo_record = run.get("repository")
    path = run.get("path")
    if (not isinstance(run_id, (int, str)) or not str(run_id).isdigit()
            or not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1
            or not isinstance(path, str)
            or path.split("@", 1)[0] != ".github/workflows/ci.yml"
            or run.get("event") != expected_event or run.get("head_branch") != "main"
            or run.get("head_sha") != expected_source_sha
            or (run.get("status") != "completed" and not (allow_active and run.get("status") in
                {"queued", "in_progress", "requested", "waiting", "pending"}))
            or (run.get("status") == "completed" and run.get("conclusion") != "success")
            or not isinstance(repo_record, dict) or repo_record.get("full_name") != repository
            or not isinstance(created_at, str)):
        raise ValueError("hosted-run-source-event-or-result-mismatch")
    expected_title = "Plan10 qualification " + expected_nonce if expected_nonce else None
    if expected_title is not None and run.get("display_title") != expected_title:
        raise ValueError("hosted-run-dispatch-nonce-mismatch")
    _parse_utc(created_at)
    return {"run_id": str(run_id), "run_attempt": str(attempt), "created_at": created_at,
            "event": expected_event}


def _validate_workflow_clock(started_at: str, run_created_at: str,
                             nonce: str, base_sha: str,
                             now: str | None = None,
                             phase: str = "runtime") -> str:
    """Validate carried publication time against immutable Actions queue evidence."""
    start = _parse_utc(started_at)
    created = _parse_utc(run_created_at)
    current = _parse_utc(now or datetime.datetime.now(datetime.timezone.utc).isoformat())
    if not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise ValueError("qualification-dispatch-nonce-invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", base_sha):
        raise ValueError("qualification-dispatch-base-invalid")
    if start > current or created < start or created > current:
        raise ValueError("qualification-dispatch-clock-invalid")
    scope = json.loads((ROOT / "evidence/v02-execution.json").read_text(encoding="utf-8"))
    _require_hosted_budget(started_at, current.isoformat(), scope, phase=phase)
    return started_at


def _bind_qualification_clock(journal: dict[str, Any], run_created_at: str) -> dict[str, Any]:
    """Keep the publication journal start as the immutable batch cutoff."""
    started_at = journal.get("started_at") if isinstance(journal, dict) else None
    if not isinstance(started_at, str):
        raise ValueError("hosted-delivery-journal-clock-missing")
    start = _parse_utc(started_at)
    run_created = _parse_utc(run_created_at)
    now = datetime.datetime.now(datetime.timezone.utc)
    if start > now:
        raise ValueError("hosted-delivery-journal-clock-is-future")
    if run_created < start or run_created > now:
        raise ValueError("hosted-run-creation-clock-invalid")
    existing = journal.get("qualification_started_at")
    env_start = os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT")
    if existing is not None and existing != started_at:
        raise ValueError("hosted-delivery-journal-qualification-clock-replaced")
    if env_start is not None and env_start != started_at:
        raise ValueError("workflow-qualification-clock-does-not-match-publication-journal")
    if existing is None:
        journal["qualification_started_at"] = started_at
    prior_run_created = journal.get("selected_run_created_at")
    if prior_run_created is not None and prior_run_created != run_created_at:
        raise ValueError("selected-hosted-run-creation-clock-replaced")
    journal["selected_run_created_at"] = run_created_at
    return journal


def _check_environment_clock(scope: dict[str, Any], phase: str | None = None) -> None:
    started = os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT")
    if started:
        _require_hosted_budget(started, datetime.datetime.now(datetime.timezone.utc).isoformat(),
            scope, phase=phase or os.environ.get("GENEWHIP_QUALIFICATION_PHASE") or "package")


def _require_hosted_budget(started_at: str, now: str,
                           scope: dict[str, Any], *, phase: str | None = None) -> float:
    """Keep one shared deadline and the declared final-close time reserved."""
    batch = scope.get("qualification_batch") if isinstance(scope, dict) else None
    if not isinstance(batch, dict):
        raise ValueError("qualification-common-cutoff-invalid")
    total = batch.get("wall_seconds")
    runtime = batch.get("runtime_wall_seconds")
    package = batch.get("package_wall_seconds")
    close = batch.get("close_wall_seconds")
    if (any(not isinstance(item, int) or isinstance(item, bool) or item <= 0
            for item in (total, runtime, package, close))
            or runtime + package + close > total):
        raise ValueError("qualification-common-cutoff-invalid")
    elapsed = (_parse_utc(now) - _parse_utc(started_at)).total_seconds()
    if elapsed < 0 or elapsed >= total:
        raise ValueError("qualification-common-cutoff-exhausted")
    remaining = total - elapsed
    if phase == "runtime" and elapsed >= runtime:
        raise ValueError("qualification-runtime-partition-deadline-exhausted")
    if phase == "package" and elapsed >= runtime + package:
        raise ValueError("qualification-package-partition-deadline-exhausted")
    if remaining <= close and phase != "close":
        raise ValueError("qualification-final-close-reserve-exhausted")
    return remaining


def _validate_package_transfer_identity(inventory: Any, source_sha: str) -> dict[str, Any]:
    if (not isinstance(inventory, dict)
            or inventory.get("schema") != "genewhip.v02-package-transfer.v1"
            or inventory.get("source_sha") != source_sha
            or not isinstance(source_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", source_sha)
            or not isinstance(inventory.get("members"), dict)
            or inventory.get("member_count") != len(inventory["members"])
            or not inventory["members"]):
        raise ValueError("hosted-package-transfer-identity-invalid")
    total = 0
    for name, facts in inventory["members"].items():
        if (not isinstance(name, str) or not isinstance(facts, dict)
                or not re.fullmatch(r"[0-9a-f]{64}", str(facts.get("sha256", "")))
                or not isinstance(facts.get("size"), int) or isinstance(facts.get("size"), bool)
                or facts["size"] < 0):
            raise ValueError("hosted-package-transfer-member-invalid")
        total += facts["size"]
    if total != inventory.get("total_bytes"):
        raise ValueError("hosted-package-transfer-total-mismatch")
    return inventory


def _validate_release_transfer_join(assets: Any, release_assets: pathlib.Path,
                                   transfer_members: dict[str, Any]) -> dict[str, str]:
    """Require every staged release byte to equal its authenticated transfer member."""
    if not isinstance(assets, dict) or len(assets) != 6:
        raise ValueError("hosted-release-inventory-roster-invalid")
    joined: dict[str, str] = {}
    names = set(assets) | {"inventory.json", "SHA256SUMS"}
    for name in sorted(names):
        if not isinstance(name, str) or pathlib.PurePosixPath(name).name != name:
            raise ValueError("hosted-release-input-name-invalid")
        actual = release_assets / name
        transfer_record = transfer_members.get("artifacts/release-assets/" + name)
        if (actual.is_symlink() or not actual.is_file() or not isinstance(transfer_record, dict)
                or actual.stat().st_size > 512 * 1024 * 1024):
            raise ValueError("hosted-release-input-differs-from-authenticated-package-transfer:" + name)
        digest = _sha(actual)
        expected = assets.get(name) if name in assets else None
        if (expected is not None and (not isinstance(expected, dict)
                or expected.get("sha256") != digest or expected.get("size") != actual.stat().st_size)):
            raise ValueError("hosted-release-inventory-member-mismatch:" + name)
        if (transfer_record.get("sha256") != digest
                or transfer_record.get("size") != actual.stat().st_size):
            raise ValueError("hosted-release-input-differs-from-authenticated-package-transfer:" + name)
        joined[name] = digest
    return joined


def _validate_hosted_release_inputs(release_assets: pathlib.Path, source_sha: str,
                                    transfer_members: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, str], list[str]]:
    """Require the selected v0.2 release roster and exact transfer bytes."""
    try:
        inventory = json.loads((release_assets / "inventory.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise ValueError("hosted-release-inventory-invalid") from None
    assets = inventory.get("assets") if isinstance(inventory, dict) else None
    if not isinstance(source_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("hosted-release-inventory-source-invalid")
    suffix = "-" + source_sha[:12] + ".tar.gz"
    archives = [f"genewhip-0.2.0-sdk-diagnostic-darwin-arm64{suffix}",
                f"genewhip-0.2.0-playable-preview-macos-arm64{suffix}"]
    expected_assets = {name + ending for name in archives
                       for ending in ("", ".sha256", ".qualification.json")}
    if (not isinstance(inventory, dict)
            or inventory.get("schema") != "genewhip.release-inventory.v2"
            or inventory.get("version") != "0.2.0"
            or inventory.get("source_revision") != source_sha
            or not isinstance(assets, dict) or set(assets) != expected_assets):
        raise ValueError("hosted-release-inventory-roster-invalid")
    joined = _validate_release_transfer_join(assets, release_assets, transfer_members)
    return inventory, assets, joined, archives


def _validate_docs_adoption_receipt(receipt: Any, assets: dict[str, Any],
                                    source_sha: str) -> dict[str, dict[str, str]]:
    """Bind documentation adoption receipts to the exact authenticated SDK/desktop archives."""
    if (not isinstance(receipt, dict)
            or receipt.get("schema") != "genewhip-docs-command-qualification-v2"
            or receipt.get("version") != "0.2.0" or receipt.get("outcome") != "pass"
            or receipt.get("mode") != "clean-local-qualified"):
        raise ValueError("hosted-docs-adoption-receipt-invalid")
    expected = {
        "sdk": "genewhip-0.2.0-sdk-diagnostic-darwin-arm64-",
        "desktop": "genewhip-0.2.0-playable-preview-macos-arm64-",
    }
    packages = receipt.get("packages")
    if not isinstance(packages, dict) or set(packages) != set(expected):
        raise ValueError("hosted-docs-adoption-package-roster-invalid")
    identities = {}
    for role, prefix in expected.items():
        package = packages[role]
        archive = next((name for name in assets if name.startswith(prefix)
                        and name.endswith(".tar.gz")), None)
        if (archive is None or not isinstance(package, dict)
                or package.get("archive") != archive
                or package.get("archive_sha256") != assets[archive].get("sha256")
                or package.get("source_revision") != source_sha
                or package.get("source_state") != "clean"):
            raise ValueError("hosted-docs-receipt-does-not-name-authenticated-release-bytes:" + role)
        identities[role] = {"archive": archive,
            "archive_sha256": package["archive_sha256"], "source_revision": source_sha}
    return identities


def _valid_packet_for_delivery(packet_path: pathlib.Path,
                               publication_copy: pathlib.Path) -> dict[str, Any]:
    packet_path = packet_path.resolve(strict=True)
    if packet_path.is_symlink():
        raise ValueError("public-preflight-packet-unsafe")
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    if not isinstance(packet, dict):
        raise ValueError("public-preflight-packet-invalid")
    candidate = publication_copy.resolve(strict=True)
    identity = packet.get("public_identity", {})
    source_identity = packet.get("source_identity", {})
    manifest = packet.get("source_manifest")
    privacy = packet.get("privacy", {})
    if (packet.get("schema") != "genewhip.v02-public-source-preflight.v1"
            or packet.get("status") != "prepared"
            or not isinstance(identity, dict)
            or not isinstance(source_identity, dict)
            or not isinstance(manifest, list)
            or not isinstance(privacy, dict)
            or packet.get("repository") != _authorized_public_repository(ROOT)
            or packet.get("mutations_performed") != 0
            or packet.get("push_performed") is not False
            or packet.get("pull_request_opened") is not False
            or packet.get("workflow_dispatched") is not False
            or privacy.get("status") != "pass"
            or packet.get("blockers")
            or packet.get("source_manifest_sha256") != source_identity.get("source_manifest_sha256")
            or source_identity.get("private_git_head") != _git(ROOT, "rev-parse", "HEAD")
            or any(not isinstance(row, dict) or not isinstance(row.get("path"), str) for row in manifest)
            or _git(candidate, "rev-parse", "HEAD") != identity.get("head_sha")
            or _git(candidate, "rev-parse", "HEAD^{tree}") != identity.get("tree_sha")
            or _git(candidate, "rev-parse", "HEAD^") != identity.get("base_sha")):
        raise ValueError("public-preflight-packet-does-not-bind-candidate")
    validate_public_snapshot(candidate, identity["base_sha"], identity["head_sha"],
                             [row["path"] for row in manifest])
    return packet


def _fresh_public_policy(packet: dict[str, Any], publication_copy: pathlib.Path) -> dict[str, Any]:
    """Re-read main and effective policy immediately before a source branch push."""
    repository = packet["repository"]
    identity = packet["public_identity"]
    candidate = publication_copy.resolve(strict=True)
    remote = _external(["git", "remote", "get-url", "origin"], cwd=candidate,
                       timeout=30, phase="preparation").stdout.strip()
    owner, name = repository.split("/", 1)
    allowed = {f"https://github.com/{owner}/{name}.git", f"https://github.com/{owner}/{name}"}
    if remote not in allowed:
        raise ValueError("public-snapshot-remote-is-not-authorized-destination")
    _external(["git", "fetch", "--no-tags", "origin", "main"], cwd=candidate, timeout=300)
    fetched_main = _external(["git", "rev-parse", "refs/remotes/origin/main"], cwd=candidate,
                             timeout=30, phase="preparation").stdout.strip()
    if fetched_main != identity["base_sha"]:
        raise ValueError("public-main-moved-after-candidate-freeze")
    preflight_out = ROOT / "build/v02" / f"repository-preflight-{identity['head_sha']}-delivery.json"
    preflight_out.parent.mkdir(parents=True, exist_ok=True)
    _external([sys.executable, str(ROOT / "scripts/ci/repository_preflight.py"),
        "--inspect-authorized", "--repository", repository, "--destination", repository,
        "--visibility", "public", "--history-disposition",
        "sanitized-snapshots-preserve-local-history", "--publication-copy", str(candidate),
        "--expected-head", identity["head_sha"], "--expected-base", identity["base_sha"],
        "--out", preflight_out.relative_to(ROOT).as_posix()], timeout=90)
    policy = json.loads(preflight_out.read_text(encoding="utf-8"))
    observations = policy.get("repository_observations", {}).get("observations", {})
    branch = observations.get("branch_protection", {})
    if (policy.get("schema") != "genewhip.publication-readiness-packet.v1"
            or policy.get("repository") != repository
            or policy.get("mutations_performed") != 0
            or policy.get("repository_observations", {}).get("ready") is not True
            or policy.get("repository_observations", {}).get("blockers")
            or policy.get("privacy_scan", {}).get("publication_copy", {}).get("status") != "pass"
            or observations.get("visibility") != "public"
            or observations.get("default_branch") != "main"
            or observations.get("expected_identity", {}).get("observed_default_branch_sha") != identity["base_sha"]
            or "required-ci" not in branch.get("required_status_checks", [])
            or branch.get("pull_request_required") is not True
            or observations.get("auto_merge_enabled") is not True
            or observations.get("caller_write_permission") != "write"
            or not isinstance(observations.get("permitted_merge_methods"), list)
            or not set(observations["permitted_merge_methods"]) & {"merge", "squash"}):
        raise ValueError("live-public-repository-policy-not-qualified")
    return policy


def _pr_body(candidate_sha: str, base_sha: str) -> str:
    return f"""## Summary

```text
sanitized private source snapshot
  -> one-parent public-main commit {candidate_sha}
  -> required public CI checks
```

This PR adds the reviewed v0.2 source snapshot. It excludes `.planning`, local receipts, build output, secrets, and private history.

## Evidence

- **Before:** existing public `main` at `{base_sha}`.
- **After:** frozen candidate `{candidate_sha}`; source and history privacy scans passed.
- Public PR checks run on this exact head. Full v0.2 hosted qualification follows the protected `main` merge.

## Merge Danger

**Door:** One-way for public disclosure; the source branch can be removed, but a public source disclosure cannot be recalled.

**Blast Radius:** Repository
"""


def _verified_merge_receipt(pr: dict[str, Any], repository: str, candidate: pathlib.Path,
                            head: str, base: str, branch: str, *,
                            phase: str = "preparation") -> dict[str, Any]:
    """Reopen a completed protected merge after a client-side interruption."""
    if pr.get("state") != "MERGED" or pr.get("headRefOid") != head or pr.get("baseRefName") != "main":
        raise ValueError("public-source-pull-request-identity-or-base-changed")
    merge_sha = pr.get("mergeCommit", {}).get("oid")
    if not isinstance(merge_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", merge_sha):
        raise ValueError("protected-merge-commit-identity-invalid")
    commit = _gh_json(repository, f"commits/{merge_sha}", phase=phase)
    parents = [row.get("sha") for row in commit.get("parents", [])]
    expected_tree = _git(candidate, "rev-parse", "HEAD^{tree}")
    actual_tree = commit.get("commit", {}).get("tree", {}).get("sha")
    if actual_tree != expected_tree or parents not in ([base], [base, head], [head, base]):
        raise ValueError("protected-merge-parents-or-tree-mismatch")
    return {"pull_request": str(pr["number"]), "pull_request_url": pr.get("url"),
        "public_source_sha": merge_sha, "candidate_sha": head, "public_base_sha": base,
        "merge_parents": parents, "branch": branch,
        "merge_strategy": "squash" if parents == [base] else "merge", "tree_sha": actual_tree}


def _validate_source_retry_history(journal: dict[str, Any]) -> None:
    """Reopen the immutable prior attempt before trusting an active retry journal."""
    retry = journal.get("source_retry") if isinstance(journal, dict) else None
    if retry is None:
        return
    if (not isinstance(retry, dict) or retry.get("schema") != "genewhip.v02-source-retry.v1"
            or not isinstance(retry.get("archive"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", str(retry.get("archive_sha256", "")))
            or retry.get("started_at") != journal.get("started_at")
            or retry.get("active_source_head") != journal.get("source_head")
            or retry.get("active_repository") != journal.get("repository")
            or retry.get("active_base_sha") != journal.get("public_base_sha")):
        raise ValueError("hosted-delivery-journal-source-retry-identity-invalid")
    archive_input = ROOT / retry["archive"]
    if archive_input.is_symlink():
        raise ValueError("hosted-delivery-journal-source-retry-archive-invalid")
    archive = archive_input.resolve(strict=True)
    expected_root = (ROOT / "build/v02/failures").resolve()
    if not archive.is_relative_to(expected_root):
        raise ValueError("hosted-delivery-journal-source-retry-archive-invalid")
    raw = archive.read_bytes()
    if hashlib.sha256(raw).hexdigest() != retry["archive_sha256"]:
        raise ValueError("hosted-delivery-journal-source-retry-archive-digest-mismatch")
    try:
        prior = json.loads(raw)
    except json.JSONDecodeError:
        raise ValueError("hosted-delivery-journal-source-retry-archive-invalid") from None
    if (not isinstance(prior, dict)
            or prior.get("schema") != "genewhip.v02-delivery-journal.v1"
            or prior.get("started_at") != journal.get("started_at")
            or prior.get("source_head") != retry.get("prior_source_head")
            or prior.get("repository") != journal.get("repository")
            or prior.get("public_base_sha") != journal.get("public_base_sha")
            or prior.get("push_performed") is not True
            or any(key in prior for key in ("public_source_sha", "merge_commit", "merge_parents",
                "candidate_sha", "merge_strategy", "qualification_started_at", "source_sha",
                "run_id", "run_attempt"))
            or any(key.startswith(("qualification_", "selected_run_")) for key in prior)
            or not isinstance(retry.get("failed_pull_request"), str)
            or retry.get("failed_required_check") != {"name": "required-ci",
                "status": "COMPLETED", "conclusion": "FAILURE"}):
        raise ValueError("hosted-delivery-journal-source-retry-archive-conflicts")


def retry_sanitized_source(packet_path: pathlib.Path, publication_copy: pathlib.Path,
                           journal_path: pathlib.Path) -> dict[str, Any]:
    """Explicitly archive a failed, unmerged source attempt and bind a replacement."""
    packet = _valid_packet_for_delivery(packet_path, publication_copy)
    if journal_path.is_symlink():
        raise ValueError("source-retry-journal-path-invalid")
    journal_path = journal_path.resolve()
    build_root = (ROOT / "build/v02").resolve()
    if not journal_path.parent.is_relative_to(build_root):
        raise ValueError("source-retry-journal-path-invalid")
    try:
        original_bytes = journal_path.read_bytes()
        previous = json.loads(original_bytes)
    except (OSError, json.JSONDecodeError):
        raise ValueError("source-retry-prior-journal-unavailable") from None
    new_head = packet["public_identity"]["head_sha"]
    new_base = packet["public_identity"]["base_sha"]
    repository = packet["repository"]
    forbidden = ("public_source_sha", "merge_commit", "merge_parents", "candidate_sha",
                 "merge_strategy", "pull_request_url", "source_sha", "run_id", "run_attempt")
    if (not isinstance(previous, dict)
            or previous.get("schema") != "genewhip.v02-delivery-journal.v1"
            or previous.get("repository") != repository
            or previous.get("public_base_sha") != new_base
            or previous.get("source_head") == new_head
            or previous.get("push_performed") is not True
            or any(key in previous for key in forbidden)
            or any(key.startswith(("qualification_", "selected_run_")) for key in previous)
            or not isinstance(previous.get("started_at"), str)
            or not isinstance(previous.get("branch"), str)
            or not re.fullmatch(r"[0-9a-f]{40}", str(previous.get("source_head", "")))
            or previous["branch"] != "v0.2-source-" + previous["source_head"][:12]):
        raise ValueError("source-retry-prior-journal-not-retryable")
    start = previous["started_at"]
    workflow_start = os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT")
    if workflow_start and workflow_start != start:
        raise ValueError("source-retry-clock-conflicts-with-workflow")
    scope = json.loads((ROOT / "evidence/v02-execution.json").read_text(encoding="utf-8"))
    _require_hosted_budget(start, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           scope, phase="preparation")
    prior_env = {key: os.environ.get(key) for key in
                 ("GENEWHIP_QUALIFICATION_STARTED_AT", "GENEWHIP_QUALIFICATION_PHASE")}
    os.environ["GENEWHIP_QUALIFICATION_STARTED_AT"] = start
    os.environ["GENEWHIP_QUALIFICATION_PHASE"] = "preparation"
    try:
        return _retry_sanitized_source_bound(packet, publication_copy, journal_path,
            original_bytes, previous, start, scope, build_root)
    finally:
        for key, value in prior_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _retry_sanitized_source_bound(packet: dict[str, Any], publication_copy: pathlib.Path,
                                  journal_path: pathlib.Path, original_bytes: bytes,
                                  previous: dict[str, Any], start: str,
                                  scope: dict[str, Any], build_root: pathlib.Path) -> dict[str, Any]:
    """Perform retry reads and journal replacement under the selected cutoff."""
    new_head = packet["public_identity"]["head_sha"]
    new_base = packet["public_identity"]["base_sha"]
    repository = packet["repository"]
    policy = _fresh_public_policy(packet, publication_copy)
    _require_hosted_budget(start, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           scope, phase="preparation")
    if (policy.get("repository") != repository
            or policy.get("repository_observations", {}).get("observations", {})
                .get("expected_identity", {}).get("observed_default_branch_sha") != new_base):
        raise ValueError("source-retry-live-public-base-mismatch")

    repository_q = urllib.parse.quote(repository, safe="/")
    listing = _external(["gh", "pr", "list", "--repo", repository, "--head", previous["branch"],
        "--state", "all", "--json",
        "number,url,state,headRefName,headRefOid,baseRefName,baseRefOid,mergeCommit,autoMergeRequest,statusCheckRollup"],
        timeout=45, phase="preparation")
    _require_hosted_budget(start, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           scope, phase="preparation")
    try:
        prs = json.loads(listing.stdout)
    except json.JSONDecodeError:
        raise ValueError("source-retry-pull-request-list-invalid") from None
    matches = [row for row in prs if isinstance(row, dict)
               and row.get("headRefOid") == previous["source_head"]]
    if len(matches) != 1:
        raise ValueError("source-retry-prior-pull-request-ambiguous")
    pr = matches[0]
    if (pr.get("state") != "OPEN" or pr.get("headRefName") != previous["branch"]
            or pr.get("baseRefName") != "main"
            or pr.get("baseRefOid") != new_base or pr.get("mergeCommit")
            or pr.get("autoMergeRequest") is not None
            or str(pr.get("number", "")) == ""):
        raise ValueError("source-retry-prior-pull-request-not-open-unmerged")
    checks = pr.get("statusCheckRollup")
    required = [row for row in checks if isinstance(row, dict) and row.get("name") == "required-ci"] \
        if isinstance(checks, list) else []
    if (len(required) != 1 or required[0].get("status") != "COMPLETED"
            or required[0].get("conclusion") != "FAILURE"
            or any(not isinstance(row, dict) or row.get("status") != "COMPLETED" for row in checks)):
        raise ValueError("source-retry-required-check-not-exact-failure")
    runs_response = _external(["gh", "api",
        f"repos/{repository_q}/actions/runs?head_sha={previous['source_head']}&per_page=100"],
        timeout=45, phase="preparation")
    _require_hosted_budget(start, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           scope, phase="preparation")
    try:
        runs_value = json.loads(runs_response.stdout)
    except json.JSONDecodeError:
        raise ValueError("source-retry-workflow-runs-invalid") from None
    runs = runs_value.get("workflow_runs") if isinstance(runs_value, dict) else None
    if (not isinstance(runs, list) or runs_value.get("total_count") != len(runs)
            or len(runs) >= 100):
        raise ValueError("source-retry-workflow-runs-incomplete")
    if any(row.get("status") != "completed"
           or row.get("event") == "workflow_dispatch"
           or str(row.get("display_title", "")).startswith("Plan10 qualification ")
           for row in runs if isinstance(row, dict)):
        raise ValueError("source-retry-prior-workflow-active-or-qualified")
    if any(not isinstance(row, dict) for row in runs):
        raise ValueError("source-retry-workflow-run-invalid")
    _require_hosted_budget(start, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           scope, phase="preparation")

    old_head = previous["source_head"]
    archive_sha = hashlib.sha256(original_bytes).hexdigest()
    archive_dir = journal_path.parent / "failures"
    archive_root = ROOT / "build/v02/failures"
    if archive_root.is_symlink() or archive_dir.is_symlink():
        raise ValueError("source-retry-archive-path-invalid")
    archive_root.mkdir(parents=True, exist_ok=True)
    archive_dir.mkdir(parents=True, exist_ok=True)
    if (not archive_root.resolve().is_relative_to(build_root)
            or not archive_dir.resolve().is_relative_to(archive_root.resolve())):
        raise ValueError("source-retry-archive-path-invalid")
    archive = archive_dir / f"source-attempt-{old_head}-{archive_sha}.json"
    try:
        with archive.open("xb") as stream:
            stream.write(original_bytes)
    except FileExistsError:
        if archive.read_bytes() != original_bytes:
            raise ValueError("source-retry-archive-path-conflicts") from None
    archive_relative = archive.resolve().relative_to(ROOT.resolve()).as_posix()
    retry_record = {"schema": "genewhip.v02-source-retry.v1",
        "archive": archive_relative, "archive_sha256": archive_sha,
        "started_at": start, "prior_source_head": old_head,
        "active_source_head": new_head, "active_repository": repository,
        "active_base_sha": new_base, "failed_pull_request": str(pr["number"]),
        "failed_required_check": {"name": "required-ci", "status": "COMPLETED",
                                  "conclusion": "FAILURE"}}
    active = {"schema": "genewhip.v02-delivery-journal.v1", "started_at": start,
        "repository": repository, "source_head": new_head, "public_base_sha": new_base,
        "branch": "v0.2-source-" + new_head[:12], "push_performed": False,
        "source_retry": retry_record}
    _validate_source_retry_history(active)
    _require_hosted_budget(start, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           scope, phase="preparation")
    temporary_journal = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=journal_path.parent,
                prefix=journal_path.name + ".retry-", suffix=".tmp", delete=False) as stream:
            temporary_journal = pathlib.Path(stream.name)
            stream.write((json.dumps(active, sort_keys=True, indent=2) + "\n").encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        _require_hosted_budget(start, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                               scope, phase="preparation")
        os.replace(temporary_journal, journal_path)
        temporary_journal = None
    finally:
        if temporary_journal is not None:
            temporary_journal.unlink(missing_ok=True)
    return {"archive": archive_relative, "archive_sha256": archive_sha,
        "prior_source_head": old_head, "source_head": new_head,
        "public_base_sha": new_base, "repository": repository,
        "failed_pull_request": str(pr["number"]), "started_at": start,
        "push_performed": False}


def publish_sanitized_source(packet_path: pathlib.Path, publication_copy: pathlib.Path,
                             journal_path: pathlib.Path) -> dict[str, Any]:
    """Push only the reviewed sanitized candidate, merge through required protection."""
    packet = _valid_packet_for_delivery(packet_path, publication_copy)
    journal_path = journal_path.resolve()
    previous = None
    if journal_path.is_file():
        previous = json.loads(journal_path.read_text(encoding="utf-8"))
        _validate_source_retry_history(previous)
        if (not isinstance(previous, dict)
                or previous.get("schema") != "genewhip.v02-delivery-journal.v1"
                or previous.get("repository") != packet["repository"]
                or previous.get("source_head") != packet["public_identity"]["head_sha"]
                or previous.get("public_base_sha") != packet["public_identity"]["base_sha"]
                or not isinstance(previous.get("started_at"), str)):
            raise ValueError("hosted-delivery-journal-conflicts-with-candidate")
        workflow_start = os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT")
        if workflow_start and workflow_start != previous.get("started_at"):
            raise ValueError("hosted-delivery-journal-clock-conflicts-with-workflow")
        _require_hosted_budget(previous["started_at"],
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
            json.loads((ROOT / "evidence/v02-execution.json").read_text()))
        os.environ["GENEWHIP_QUALIFICATION_STARTED_AT"] = previous["started_at"]
        if previous.get("public_source_sha"):
            # A local journal is a resume hint only. Reopen the actual PR and
            # merge commit (including parents and tree) before treating it as
            # authority, exactly as on the uninterrupted path.
            required = ("pull_request", "pull_request_url", "candidate_sha", "public_base_sha",
                        "merge_parents", "branch")
            if any(key not in previous for key in required):
                raise ValueError("hosted-delivery-journal-merge-receipt-incomplete")
            resume_phase = "package" if previous.get("qualification_started_at") else "runtime"
            listing = _external(["gh", "pr", "list", "--repo", packet["repository"],
                "--head", previous["branch"], "--state", "all", "--json",
                "number,url,headRefOid,baseRefName,state,mergeCommit"], timeout=45, phase=resume_phase)
            try:
                prs = json.loads(listing.stdout)
            except json.JSONDecodeError:
                raise ValueError("github-pull-request-list-invalid") from None
            matches = [row for row in prs if str(row.get("number")) == str(previous["pull_request"])]
            if len(matches) != 1:
                raise ValueError("hosted-delivery-journal-merge-pr-not-reopened")
            receipt = _verified_merge_receipt(matches[0], packet["repository"], publication_copy.resolve(strict=True),
                packet["public_identity"]["head_sha"], packet["public_identity"]["base_sha"],
                previous["branch"], phase=resume_phase)
            if any(previous.get(key) != receipt.get(key) for key in
                   ("public_source_sha", "candidate_sha", "public_base_sha", "merge_parents")):
                raise ValueError("hosted-delivery-journal-merge-receipt-conflicts-with-remote")
            main = _gh_json(packet["repository"], "git/ref/heads/main", phase=resume_phase)
            if main.get("object", {}).get("sha") != receipt["public_source_sha"]:
                raise ValueError("public-main-moved-after-journaled-merge")
            return {**receipt, "pull_request_url": matches[0].get("url")}
    policy = _fresh_public_policy(packet, publication_copy)
    candidate = publication_copy.resolve(strict=True)
    head, base = packet["public_identity"]["head_sha"], packet["public_identity"]["base_sha"]
    repository = packet["repository"]
    started_at = os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT") or datetime.datetime.now(datetime.timezone.utc).isoformat()
    if previous is not None:
        if (previous.get("source_head") != head or previous.get("public_base_sha") != base
                or previous.get("repository") != repository):
            raise ValueError("hosted-delivery-journal-conflicts-with-candidate")
        started_at = previous.get("started_at", started_at)
    branch = "v0.2-source-" + head[:12]
    journal_path.parent.mkdir(parents=True, exist_ok=True)
    journal_header = {"schema": "genewhip.v02-delivery-journal.v1",
        "started_at": started_at, "repository": repository, "source_head": head,
        "public_base_sha": base, "branch": branch, "push_performed": False}
    if previous and "source_retry" in previous:
        journal_header["source_retry"] = previous["source_retry"]
    _write_json(journal_path, journal_header)
    os.environ["GENEWHIP_QUALIFICATION_STARTED_AT"] = started_at
    os.environ["GENEWHIP_QUALIFICATION_PHASE"] = "preparation"
    process = _external(["git", "push", "origin", f"HEAD:refs/heads/{branch}"],
                        cwd=candidate, timeout=300, check=False)
    if process.returncode:
        raise ValueError("sanitized-public-branch-push-failed")
    journal = {"schema": "genewhip.v02-delivery-journal.v1", "started_at": started_at,
        "repository": repository, "source_head": head, "public_base_sha": base,
        "branch": branch, "push_performed": True, "policy_sha256": hashlib.sha256(
            json.dumps(policy, sort_keys=True).encode()).hexdigest()}
    if previous and "source_retry" in previous:
        journal["source_retry"] = previous["source_retry"]
    _write_json(journal_path, journal)
    listed = _external(["gh", "pr", "list", "--repo", repository, "--head", branch,
                        "--state", "all", "--json", "number,url,headRefOid,baseRefName,state,mergeCommit"], timeout=45)
    try:
        prs = json.loads(listed.stdout)
    except json.JSONDecodeError:
        raise ValueError("github-pull-request-list-invalid") from None
    if not prs:
        body_path = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                    prefix="genewhip-pr-body-", suffix=".md", delete=False) as body_file:
                body_path = pathlib.Path(body_file.name)
                body_file.write(_pr_body(head, base))
            created = _external(["gh", "pr", "create", "--repo", repository, "--base", "main",
                "--head", branch, "--title", "Prepare sanitized v0.2 source snapshot",
                "--body-file", str(body_path)], timeout=120)
        finally:
            if body_path is not None:
                body_path.unlink(missing_ok=True)
        number = re.search(r"/pull/([0-9]+)", created.stdout)
        if number is None:
            raise ValueError("github-pull-request-number-unavailable")
        pr_number = number.group(1)
    elif len(prs) == 1 and prs[0].get("state") == "MERGED":
        receipt = _verified_merge_receipt(prs[0], repository, candidate, head, base, branch)
        journal.update(receipt)
        _write_json(journal_path, journal)
        return receipt
    elif len(prs) == 1 and prs[0].get("state") == "OPEN" \
            and prs[0].get("headRefOid") == head and prs[0].get("baseRefName") == "main":
        pr_number = str(prs[0]["number"])
    else:
        raise ValueError("conflicting-public-source-pull-request-exists")
    while True:
        _require_hosted_budget(started_at, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                               json.loads((ROOT / "evidence/v02-execution.json").read_text()))
        pr_data = _external(["gh", "pr", "view", pr_number, "--repo", repository,
            "--json", "number,state,headRefOid,baseRefOid,mergeStateStatus,statusCheckRollup,url"], timeout=45)
        try:
            current = json.loads(pr_data.stdout)
        except json.JSONDecodeError:
            raise ValueError("github-pull-request-state-invalid") from None
        if (current.get("headRefOid") != head or current.get("baseRefOid") != base
                or current.get("state") != "OPEN"):
            raise ValueError("public-source-pull-request-identity-or-base-changed")
        checks = current.get("statusCheckRollup")
        required = [item for item in checks or [] if item.get("name") == "required-ci"]
        if any(item.get("conclusion") in {"FAILURE", "CANCELLED", "TIMED_OUT", "ACTION_REQUIRED"}
               for item in required):
            raise ValueError("required-public-pull-request-check-failed")
        if len(required) == 1 and required[0].get("conclusion") == "SUCCESS":
            break
        time.sleep(30)
    # The PR can wait for checks for hours. Re-open effective protection and
    # base immediately before the merge decision.
    policy = _fresh_public_policy(packet, publication_copy)
    policy_observations = policy["repository_observations"]["observations"]
    strategy = ("merge" if "merge" in policy_observations["permitted_merge_methods"]
                else "squash")
    _external(["gh", "pr", "merge", pr_number, "--repo", repository,
               "--match-head-commit", head,
               "--" + strategy], timeout=300)
    while True:
        _require_hosted_budget(started_at, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                               json.loads((ROOT / "evidence/v02-execution.json").read_text()))
        merged = _external(["gh", "pr", "view", pr_number, "--repo", repository,
            "--json", "state,mergedAt,mergeCommit,headRefOid,baseRefOid"], timeout=45)
        current = json.loads(merged.stdout)
        if current.get("state") == "MERGED":
            receipt = _verified_merge_receipt({**current, "number": pr_number,
                "baseRefName": "main"}, repository, candidate, head, base, branch)
            if receipt["merge_strategy"] != strategy:
                raise ValueError("protected-merge-strategy-mismatch")
            journal.update(receipt)
            _write_json(journal_path, journal)
            return receipt
        if current.get("state") != "OPEN":
            raise ValueError("public-source-pull-request-closed-without-merge")
        time.sleep(30)


def _publication_paths(root: pathlib.Path) -> list[str]:
    """Return the tracked product tree, excluding local planning/runtime material."""
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
    names = [item.decode("utf-8") for item in raw.split(b"\0") if item]
    excluded = {".planning", "build", "artifacts", "node_modules", "target", "dist",
                "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
    result = []
    for name in names:
        path = pathlib.PurePosixPath(name)
        parts = path.parts
        if (not parts or any(part in excluded for part in parts)
                or path.name == ".DS_Store" or path.name.startswith(".env")
                or (parts[0] == "evidence" and path.name.startswith("phase5-")
                    and path.name not in PUBLIC_PHASE5_HISTORY)
                or name == "fixtures/candidate-screening-v2.json"
                or any(part.lower() in {"private-receipts", "private-receipt", "crosswalks"}
                       for part in parts)
                or path.name.startswith("raw-build-") and path.suffix.lower() == ".bin"
                or path.suffix.lower() == ".json" and
                   ("-red-" in path.name or path.name.endswith("-red.json")
                    or name == "evidence/phase6-repairs.json")):
            continue
        candidate = root / name
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError("public-snapshot-source-entry-invalid")
        result.append(name)
    if not result:
        raise ValueError("public-snapshot-source-empty")
    return sorted(result)


def _projection_crosswalk(root: pathlib.Path, included: list[str]) -> dict[str, Any]:
    """Account for every filtered tracked path; retain exact local receipt/binary rows."""
    names = [item.decode("utf-8") for item in
             subprocess.check_output(["git", "ls-files", "-z"], cwd=root).split(b"\0") if item]
    counts: dict[str, int] = {}
    exact: list[dict[str, str]] = []
    for name in names:
        if name in included:
            continue
        path = pathlib.PurePosixPath(name)
        parts = path.parts
        if ".planning" in parts:
            reason = "private-planning-history-and-crosswalks"
        elif (parts[0] == "evidence" and path.name.startswith("phase5-")
              and path.name not in PUBLIC_PHASE5_HISTORY):
            reason = "private-phase5-historical-evidence-and-receipts"
            exact.append({"path": name, "reason": reason})
        elif name == "fixtures/candidate-screening-v2.json":
            reason = "private-phase5-screening-history"
            exact.append({"path": name, "reason": reason})
        elif any(part in {"build", "artifacts", "node_modules", "target", "dist",
                          "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"} for part in parts):
            reason = "generated-output-or-cache"
        elif path.name.startswith(".env"):
            reason = "local-environment-file"
        elif path.name.startswith("raw-build-") and path.suffix.lower() == ".bin":
            reason = "intermediate-fixture-build-product"
            exact.append({"path": name, "reason": reason})
        elif path.suffix.lower() == ".json" and ("-red-" in path.name or path.name.endswith("-red.json")
                                                   or name == "evidence/phase6-repairs.json"):
            reason = "local-failed-or-diagnostic-receipt"
            exact.append({"path": name, "reason": reason})
        elif path.name == ".DS_Store":
            reason = "local-filesystem-metadata"
        elif any(part.lower() in {"private-receipts", "private-receipt", "crosswalks"} for part in parts):
            reason = "private-receipt-or-crosswalk"
        else:
            raise ValueError("public-snapshot-exclusion-unclassified")
        counts[reason] = counts.get(reason, 0) + 1
    retained_history = [{"path": f"evidence/{name}",
                         "sha256": _sha(root / "evidence" / name),
                         "reason": "required-by-public-matrix-and-current-route-consumers; historical-only"}
                        for name in sorted(PUBLIC_PHASE5_HISTORY)
                        if f"evidence/{name}" in included]
    return {"excluded_path_counts": dict(sorted(counts.items())),
            "exact_local_exclusions": sorted(exact, key=lambda row: row["path"]),
            "retained_historical_evidence": retained_history}


def _authorized_public_repository(root: pathlib.Path) -> str:
    """Resolve the previously authorized destination from local Phase 4 policy records."""
    candidates = (root / "build/phase4/delivery-preflight.json",
                  root / "build/phase4/authorized-preflight.json")
    for path in candidates:
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(record, dict):
            continue
        repository = record.get("repository")
        destination = record.get("destination")
        if (record.get("schema") == "genewhip.publication-readiness-packet.v1"
                and record.get("history_disposition") == "sanitized-snapshots-preserve-local-history"
                and isinstance(destination, dict)
                and destination.get("owner_repository") == repository
                and destination.get("visibility") == "public"
                and isinstance(repository, str)
                and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
                and all(part and part not in (".", "..") for part in repository.split("/"))):
            return repository
    raise ValueError("authorized-public-destination-record-unavailable")


def preserve_existing_public_fixture_revision(source: pathlib.Path, candidate: pathlib.Path,
                                              public_base: str) -> None:
    """Keep unchanged Genewhip fixture bytes bound to prior public source revisions."""
    manifest_rel = "fixtures/manifest.json"
    try:
        base_manifest = json.loads(_git(candidate, "show", f"{public_base}:{manifest_rel}"))
        manifest_path = candidate / manifest_rel
        current_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, KeyError):
        raise ValueError("public-fixture-source-baseline-unavailable") from None
    fixture_inputs = {
        "genewhip-independent-game-v1": ("fixtures/independent-game/src/game.s",
            "fixtures/independent-game/game.bin", "evidence/independent-game.json"),
        "genewhip-independent-game-v2": ("fixtures/independent-game-v2/src/game.s",
            "fixtures/independent-game-v2/game.bin", "evidence/independent-game-v2.json"),
    }
    base_rows = {row.get("id"): row for row in base_manifest.get("fixtures", [])}
    current_rows = {row.get("id"): row for row in current_manifest.get("fixtures", [])}
    changed = False
    for fixture_id, (source_rel, rom_rel, evidence_rel) in fixture_inputs.items():
        old, current = base_rows.get(fixture_id), current_rows.get(fixture_id)
        if not isinstance(old, dict) or not isinstance(current, dict):
            continue
        if (old.get("status") != "admitted" or old.get("outcome") != "pass"
                or old.get("source") != source_rel or old.get("rom") != rom_rel
                or current.get("source") != source_rel or current.get("rom") != rom_rel
                or current.get("source_sha256") != old.get("source_sha256")
                or current.get("sha256") != old.get("sha256")
                or _sha(source / source_rel) != old.get("source_sha256")
                or _sha(source / rom_rel) != old.get("sha256")):
            raise ValueError("public-fixture-source-or-rom-bytes-changed")
        base_evidence_bytes = read_bounded_git_blob(candidate, f"{public_base}:{evidence_rel}")
        base_evidence = json.loads(base_evidence_bytes)
        evidence_path = candidate / evidence_rel
        current_evidence_bytes = evidence_path.read_bytes()
        current_evidence = json.loads(current_evidence_bytes)
        if (old.get("evidence_sha256") != hashlib.sha256(base_evidence_bytes).hexdigest()
                or current.get("evidence_sha256") != hashlib.sha256(current_evidence_bytes).hexdigest()):
            raise ValueError("public-fixture-evidence-source-mismatch")
        old_identity, current_identity = base_evidence.get("identities"), current_evidence.get("identities")
        old_revision = old.get("revision")
        if not isinstance(old_identity, dict) or not isinstance(current_identity, dict):
            raise ValueError("public-fixture-evidence-revision-mismatch")
        if fixture_id == "genewhip-independent-game-v1" and "source_revision" not in old_identity:
            if current_evidence_bytes != base_evidence_bytes:
                raise ValueError("public-fixture-evidence-changed-beyond-source-revision")
            current["revision"] = old_revision
            changed = True
            continue
        if (old_identity.get("source_revision") != old_revision
                or current_identity.get("source_revision") != current.get("revision")):
            raise ValueError("public-fixture-evidence-revision-mismatch")
        old_identity, current_identity = dict(old_identity), dict(current_identity)
        old_identity.pop("source_revision", None)
        current_identity.pop("source_revision", None)
        if (old_identity != current_identity
                or {key: value for key, value in base_evidence.items() if key != "identities"}
                != {key: value for key, value in current_evidence.items() if key != "identities"}):
            raise ValueError("public-fixture-evidence-changed-beyond-source-revision")
        current["revision"] = old_revision
        current_evidence["identities"]["source_revision"] = old_revision
        evidence_bytes = (json.dumps(current_evidence, sort_keys=True, indent=2) + "\n").encode()
        evidence_path.write_bytes(evidence_bytes)
        current["evidence_sha256"] = hashlib.sha256(evidence_bytes).hexdigest()
        changed = True
    if changed:
        manifest_path.write_text(json.dumps(current_manifest, sort_keys=True, indent=2) + "\n",
                                 encoding="utf-8")


def preserved_fixture_provenance(source_manifest: dict[str, Any],
                                 public_manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Describe only v1/v2 fixture source histories retained from the public base."""
    public_by_id = {row.get("id"): row for row in public_manifest.get("fixtures", [])
                    if isinstance(row, dict)}
    result = []
    for source_fixture in source_manifest.get("fixtures", []):
        if not isinstance(source_fixture, dict) or source_fixture.get("id") not in {
                "genewhip-independent-game-v1", "genewhip-independent-game-v2"}:
            continue
        public_fixture = public_by_id.get(source_fixture["id"])
        if not isinstance(public_fixture, dict):
            continue
        result.append({"fixture_id": source_fixture["id"], "source_path": source_fixture["source"],
            "source_sha256": source_fixture["source_sha256"], "rom_path": source_fixture["rom"],
            "rom_sha256": source_fixture["sha256"],
            "private_tree_revision": source_fixture["revision"],
            "public_source_revision": public_fixture["revision"],
            "evidence_sha256": public_fixture["evidence_sha256"],
            "basis": "unchanged-source-and-ROM-bytes-match-existing-public-main-source-history"})
    return result


def validate_public_snapshot(candidate: pathlib.Path, base_sha: str, head_sha: str,
                             expected_paths: list[str] | None = None,
                             *, require_hygiene: bool = True) -> dict[str, Any]:
    """Reopen ancestry, refs, filtered tree, notices, and public hygiene at the consumer."""
    candidate = candidate.resolve(strict=True)
    if (not candidate.is_dir() or candidate.is_symlink() or
            _git(candidate, "rev-parse", "HEAD") != head_sha or
            _git(candidate, "symbolic-ref", "--short", "HEAD") != "main"):
        raise ValueError("public-snapshot-head-identity-invalid")
    parents = _git(candidate, "show", "-s", "--format=%P", head_sha).split()
    if parents != [base_sha]:
        raise ValueError("public-snapshot-parent-is-not-observed-main")
    refs = [item for item in _git(candidate, "for-each-ref", "--format=%(refname)").splitlines() if item]
    if any(item.startswith("refs/tags/") for item in refs) or any(
            item not in ("refs/heads/main", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
            for item in refs):
        raise ValueError("public-snapshot-unexpected-refs")
    tracked = [item for item in _git(candidate, "ls-files", "-z").split("\0") if item]
    if expected_paths is not None and tracked != sorted(expected_paths):
        raise ValueError("public-snapshot-tree-does-not-match-source-manifest")
    forbidden = {".planning", "build", "artifacts", "node_modules", "target", "dist",
                 "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
                 "private-receipts", "private-receipt", "crosswalks"}
    for name in tracked:
        path = pathlib.PurePosixPath(name)
        if (any(part in forbidden for part in path.parts) or path.name.startswith(".env")
                or path.name == ".DS_Store"):
            raise ValueError("public-snapshot-private-or-generated-path-present")
        if (candidate / name).is_symlink():
            raise ValueError("public-snapshot-symlink-present")
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "gw_v02_public_hygiene", ROOT / "scripts/ci/public_hygiene.py")
    if spec is None or spec.loader is None:
        raise ValueError("public-snapshot-hygiene-unavailable")
    hygiene = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hygiene)
    findings = hygiene.inspect(candidate, tracked)
    history = hygiene.scan_git_history(candidate)
    if require_hygiene and (findings or history.get("findings")):
        raise ValueError("public-snapshot-hygiene-rejected")
    manifest = [{"path": name, "size_bytes": (candidate / name).stat().st_size,
                 "sha256": _sha(candidate / name)} for name in tracked]
    return {"parent_shas": parents, "refs": refs, "tracked_paths": tracked,
            "manifest": manifest, "history_commits": history["commits_scanned"],
            "history_blobs": history["unique_blobs_scanned"],
            "current_findings": [{"path": path, "reason": reason} for path, reason in findings],
            "history_findings": history.get("findings", []),
            "finding_counts": history.get("finding_counts", {})}


def _inspect_preparation_policy(root: pathlib.Path, destination: pathlib.Path,
                                repository: str, public_head: str,
                                base: str) -> tuple[pathlib.Path, dict[str, Any]]:
    """Consume only a successful inspector invocation's fresh output."""
    output_root = root / "build/v02"
    output_root.mkdir(parents=True, exist_ok=True)
    attempt = pathlib.Path(tempfile.mkdtemp(prefix="repository-preflight-", dir=output_root))
    output = attempt / "policy.json"
    try:
        result = subprocess.run([sys.executable, str(root / "scripts/ci/repository_preflight.py"),
            "--inspect-authorized", "--repository", repository, "--destination", repository,
            "--visibility", "public", "--history-disposition",
            "sanitized-snapshots-preserve-local-history", "--publication-copy", str(destination),
            "--expected-head", public_head, "--expected-base", base, "--out",
            str(output.relative_to(root))], cwd=root, text=True, capture_output=True,
            timeout=180, check=True)
        if result.returncode:
            raise subprocess.CalledProcessError(result.returncode, result.args)
    except (OSError, subprocess.SubprocessError, ValueError):
        policy = {"blockers": ["repository_preflight_inspection_failed"]}
    else:
        try:
            policy = json.loads(output.read_text(encoding="utf-8"))
            if not isinstance(policy, dict):
                raise ValueError("repository-preflight-object-required")
        except (OSError, ValueError):
            policy = {"blockers": ["repository_preflight_output_invalid"]}
    output.write_text(json.dumps(policy, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return output, policy


def prepare_public_snapshot(publication_copy: pathlib.Path, scope: pathlib.Path,
                            out: pathlib.Path, authorization: pathlib.Path | None = None,
                            *, root: pathlib.Path = ROOT) -> dict[str, Any]:
    """Build a local sanitized checkout rooted at the currently observed public main."""
    root = root.resolve(strict=True)
    scope = scope.resolve(strict=True)
    if json.loads(scope.read_text(encoding="utf-8")).get("schema") != "genewhip-v02-execution-v1":
        raise ValueError("public-snapshot-execution-scope-invalid")
    auth_input = authorization or root / "build/phase4/delivery-preflight.json"
    if auth_input.is_symlink():
        raise ValueError("authorized-public-destination-record-unavailable")
    auth_path = auth_input.resolve(strict=True)
    if root not in auth_path.parents or not auth_path.is_file():
        raise ValueError("authorized-public-destination-record-unavailable")
    repository = _authorized_public_repository(root) if authorization is None else None
    if authorization is not None:
        record = json.loads(auth_path.read_text(encoding="utf-8"))
        destination_record = record.get("destination") if isinstance(record, dict) else None
        # Explicit records use the same complete authorization contract as the default.
        if (not isinstance(record, dict) or not isinstance(destination_record, dict) or
                record.get("schema") != "genewhip.publication-readiness-packet.v1" or
                record.get("history_disposition") != "sanitized-snapshots-preserve-local-history" or
                destination_record.get("visibility") != "public" or
                destination_record.get("owner_repository") != record.get("repository")):
            raise ValueError("authorized-public-destination-record-invalid")
        repository = record["repository"]
    source_head = _git(root, "rev-parse", "HEAD")
    paths = _publication_paths(root)
    projection = _projection_crosswalk(root, paths)
    destination = publication_copy if publication_copy.is_absolute() else root / publication_copy
    if destination.is_symlink():
        raise ValueError("public-snapshot-destination-must-be-new-workspace-child")
    destination = destination.resolve()
    if root not in destination.parents or destination.exists():
        raise ValueError("public-snapshot-destination-must-be-new-workspace-child")
    destination.parent.mkdir(parents=True, exist_ok=True)
    owner, name = repository.split("/", 1)
    remote = f"https://github.com/{owner}/{name}.git"
    try:
        subprocess.run(["git", "clone", "--single-branch", "--no-tags", "--branch", "main",
                        remote, str(destination)], cwd=root, text=True,
                       capture_output=True, timeout=300, check=True)
    except (OSError, subprocess.SubprocessError):
        raise ValueError("authorized-public-main-checkout-failed") from None
    base = _git(destination, "rev-parse", "HEAD")
    if len(base) != 40 or _git(destination, "symbolic-ref", "--short", "HEAD") != "main":
        raise ValueError("public-snapshot-base-identity-invalid")

    # Make the snapshot tree equal to the filtered source tree while retaining the
    # cloned public main commit as its sole parent.
    existing = _git(destination, "ls-files", "-z").split("\0")
    if any((destination / item).is_symlink() for item in existing if item):
        raise ValueError("public-snapshot-base-contains-symlink")
    for name_in_public in (item for item in existing if item):
        candidate = destination / name_in_public
        if name_in_public not in paths and candidate.is_file() and not candidate.is_symlink():
            candidate.unlink()
    for name_in_source in paths:
        source = root / name_in_source
        target = destination / name_in_source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        target.chmod(source.stat().st_mode & 0o777)
    # Recheck the full local admission chains, then carry only a narrow public
    # byte/rights projection. The historical records themselves stay private.
    manifest_path = destination / "fixtures/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    validator_spec = __import__("importlib.util", fromlist=["spec_from_file_location"])
    validator_loader = validator_spec.spec_from_file_location(
        "gw_stage_fixture_manifest", root / "tools/evidence/fixture_manifest.py")
    provenance_loader = validator_spec.spec_from_file_location(
        "gw_stage_source_provenance", root / "scripts/fixtures/source_provenance.py")
    public_loader = validator_spec.spec_from_file_location(
        "gw_stage_public_admission", root / "scripts/fixtures/public_admission.py")
    if any(item is None or item.loader is None for item in
           (validator_loader, provenance_loader, public_loader)):
        raise ValueError("phase5-public-admission-projection-unavailable")
    validator = validator_spec.module_from_spec(validator_loader)
    validator_loader.loader.exec_module(validator)
    provenance = validator_spec.module_from_spec(provenance_loader)
    provenance_loader.loader.exec_module(provenance)
    public_admission = validator_spec.module_from_spec(public_loader)
    public_loader.loader.exec_module(public_admission)
    source_manifest = json.loads((root / "fixtures/manifest.json").read_text(encoding="utf-8"))
    private_rows = [row for row in source_manifest["fixtures"]
                    if row.get("kind") == "phase5-independent-game-v1"]
    projections = []
    for source_row in private_rows:
        private_record = provenance._phase5_candidate_record(validator, source_row, root)
        projection_record = public_admission.project_private_record(private_record)
        if public_admission.validate_projection(projection_record, root, source_row["id"]) != "ok":
            raise ValueError("phase5-public-admission-projection-invalid")
        projections.append(projection_record)
    if {item["fixture_id"] for item in projections} != {
            "genewhip-phase5-a", "genewhip-phase5-b"}:
        raise ValueError("phase5-public-admission-roster-incomplete")
    public_projection = {"schema": "genewhip-phase5-public-admission-set-v1",
                         "admissions": projections}
    projection_bytes = (json.dumps(public_projection, sort_keys=True, indent=2) + "\n").encode()
    projection_path = destination / "evidence/phase5-public-admissions.json"
    projection_path.parent.mkdir(parents=True, exist_ok=True)
    projection_path.write_bytes(projection_bytes)
    paths = sorted([*paths, "evidence/phase5-public-admissions.json"])
    projection_digest = hashlib.sha256(projection_bytes).hexdigest()
    for row in manifest["fixtures"]:
        if row.get("kind") == "phase5-independent-game-v1":
            row["admission"] = {"path": "evidence/phase5-public-admissions.json",
                                "sha256": projection_digest}
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n",
                             encoding="utf-8")
    preserve_existing_public_fixture_revision(root, destination, base)
    source_manifest = json.loads((root / "fixtures/manifest.json").read_text(encoding="utf-8"))
    public_manifest = json.loads((destination / "fixtures/manifest.json").read_text(encoding="utf-8"))
    projection["provenance_preserved"] = preserved_fixture_provenance(source_manifest, public_manifest)
    if any((destination / part).exists() for part in (".planning", "build", "artifacts")):
        raise ValueError("public-snapshot-private-or-generated-tree-present")
    _git(destination, "add", "--all")
    _git(destination, "-c", "user.name=Genewhip Maintainers", "-c",
         "user.email=maintainers@users.noreply.github.com", "commit", "-m",
         "chore(v0.2): prepare sanitized public source snapshot")
    public_head = _git(destination, "rev-parse", "HEAD")
    parents = _git(destination, "show", "-s", "--format=%P", public_head).split()
    if parents != [base]:
        raise ValueError("public-snapshot-parent-is-not-observed-main")
    if _git(destination, "tag", "--list"):
        raise ValueError("public-snapshot-unexpected-tags")

    reopened = validate_public_snapshot(destination, base, public_head, paths, require_hygiene=False)
    hygiene_ready = not reopened["current_findings"] and not reopened["history_findings"]
    tree = _git(destination, "rev-parse", "HEAD^{tree}")
    manifest = reopened["manifest"]
    # The repository preflight reopens live visibility, rules, write permission,
    # public head and exact candidate identities; it never mutates GitHub.
    preflight_out, preflight = _inspect_preparation_policy(
        root, destination, repository, public_head, base)
    ready = (hygiene_ready and preflight.get("expected_identity", {}).get("head") == public_head and
             preflight.get("expected_identity", {}).get("base") == base and
             preflight.get("repository_observations", {}).get("ready") is True and
             preflight.get("privacy_scan", {}).get("publication_copy", {}).get("status") == "pass")
    packet = {"schema": "genewhip.v02-public-source-preflight.v1",
        "status": "prepared" if ready else "blocked",
        "repository": repository, "source_identity": {"private_git_head": source_head,
            "source_manifest_sha256": hashlib.sha256(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()},
        "public_identity": {"base_sha": base, "head_sha": public_head, "tree_sha": tree,
            "parent_shas": parents}, "publication_copy": str(destination.relative_to(root)),
        "source_manifest": manifest, "source_manifest_sha256": hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "privacy": {"status": "pass" if hygiene_ready else "blocked",
            "current_findings": reopened["current_findings"],
            "history_findings": reopened["history_findings"],
            "finding_counts": reopened["finding_counts"],
            "commits_scanned": reopened["history_commits"],
            "blobs_scanned": reopened["history_blobs"]},
        "repository_preflight": str(preflight_out.relative_to(root)),
        "blockers": list(preflight.get("blockers", [])) if not ready else [],
        "projection_crosswalk": projection,
        "mutations_performed": 0, "push_performed": False, "pull_request_opened": False,
        "workflow_dispatched": False, "requirements_qualified": []}
    if not hygiene_ready and "public-snapshot-hygiene-rejected" not in packet["blockers"]:
        packet["blockers"].append("public-snapshot-hygiene-rejected")
    output = out if out.is_absolute() else root / out
    output = output.resolve()
    if root not in output.parents or output == preflight_out.resolve():
        raise ValueError("public-preflight-output-path-invalid")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(packet, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return packet


def _workflow_runs(repository: str, source_sha: str) -> list[dict[str, Any]]:
    owner, name = repository.split("/", 1)
    response = _external(["gh", "api", f"repos/{owner}/{name}/actions/workflows/ci.yml/runs?branch=main&per_page=100"],
                         timeout=45)
    try:
        value = json.loads(response.stdout)
    except json.JSONDecodeError:
        raise ValueError("github-workflow-run-list-invalid") from None
    runs = value.get("workflow_runs") if isinstance(value, dict) else None
    if not isinstance(runs, list):
        raise ValueError("github-workflow-run-list-invalid")
    return [row for row in runs if isinstance(row, dict) and row.get("head_sha") == source_sha]


def _dispatch_qualification_run(repository: str, source_sha: str, base_sha: str,
                                journal_path: pathlib.Path, journal: dict[str, Any],
                                scope: dict[str, Any]) -> str:
    """Dispatch exact main qualification while carrying the existing journal cutoff."""
    started_at = journal.get("started_at")
    _require_hosted_budget(started_at,
        datetime.datetime.now(datetime.timezone.utc).isoformat(), scope, phase="runtime")
    nonce = journal.get("qualification_dispatch_nonce")
    if nonce is None:
        nonce = uuid.uuid4().hex
        journal["qualification_dispatch_nonce"] = nonce
        journal["qualification_dispatch_requested"] = True
        journal["qualification_started_at"] = started_at
        _write_json(journal_path, journal)
        _external(["gh", "workflow", "run", ".github/workflows/ci.yml", "--repo", repository,
            "--ref", "main", "--field", "qualification_started_at=" + started_at,
            "--field", "qualification_base_sha=" + base_sha,
            "--field", "qualification_nonce=" + nonce], timeout=120, phase="runtime")
        journal["qualification_dispatch_submitted"] = True
        _write_json(journal_path, journal)
    elif (not re.fullmatch(r"[0-9a-f]{32}", nonce)
          or journal.get("qualification_started_at") != started_at):
        raise ValueError("hosted-delivery-journal-dispatch-identity-invalid")
    elif journal.get("qualification_dispatch_submitted") is not True:
        _external(["gh", "workflow", "run", ".github/workflows/ci.yml", "--repo", repository,
            "--ref", "main", "--field", "qualification_started_at=" + started_at,
            "--field", "qualification_base_sha=" + base_sha,
            "--field", "qualification_nonce=" + nonce], timeout=120, phase="runtime")
        journal["qualification_dispatch_submitted"] = True
        _write_json(journal_path, journal)
    return nonce


def _wait_for_exact_qualification_run(repository: str, source_sha: str, base_sha: str,
                                      started_at: str, nonce: str,
                                      scope: dict[str, Any]) -> dict[str, Any]:
    began = time.monotonic()
    next_notice = began
    while True:
        remaining = _require_hosted_budget(started_at,
            datetime.datetime.now(datetime.timezone.utc).isoformat(), scope, phase="runtime")
        matching = [run for run in _workflow_runs(repository, source_sha)
                    if run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main"
                    and run.get("path", "").split("@", 1)[0] == ".github/workflows/ci.yml"
                    and run.get("display_title") == "Plan10 qualification " + nonce]
        if len(matching) > 1:
            raise ValueError("duplicate-exact-source-hosted-runs")
        if matching:
            run = matching[0]
            if run.get("status") == "completed":
                if run.get("conclusion") != "success":
                    raise ValueError("exact-source-hosted-qualification-failed")
                identity = _validate_hosted_run(run, repository, source_sha,
                    expected_event="workflow_dispatch", expected_nonce=nonce)
                _validate_workflow_clock(started_at, identity["created_at"], nonce, base_sha)
                return run
            if run.get("status") not in {"queued", "in_progress", "requested", "waiting", "pending"}:
                raise ValueError("exact-source-hosted-run-status-invalid")
            identity = _validate_hosted_run(run, repository, source_sha, allow_active=True,
                expected_event="workflow_dispatch", expected_nonce=nonce)
            _validate_workflow_clock(started_at, identity["created_at"], nonce, base_sha)
            return run
        elif time.monotonic() - began > 300:
            # The protected main push is the only accepted trigger because the
            # attestation lane is intentionally limited to push on main.
            raise ValueError("exact-main-dispatched-qualification-run-not-found")
        if time.monotonic() >= next_notice:
            print("hosted-qualification: waiting for exact public main run; remaining_seconds=" + str(remaining))
            next_notice = time.monotonic() + 60
        time.sleep(min(30, max(1, remaining - scope["qualification_batch"]["close_wall_seconds"])))


def _wait_for_selected_run_completion(repository: str, source_sha: str,
                                      selected: dict[str, Any], started_at: str,
                                      scope: dict[str, Any], *, nonce: str,
                                      base_sha: str) -> dict[str, Any]:
    """Wait within the selected run creation cutoff; reruns keep that same clock."""
    initial = _validate_hosted_run(selected, repository, source_sha, allow_active=True,
        expected_event="workflow_dispatch", expected_nonce=nonce)
    _validate_workflow_clock(started_at, initial["created_at"], nonce, base_sha)
    selected_id = initial["run_id"]
    current_attempt = int(initial["run_attempt"])
    while True:
        _require_hosted_budget(started_at,
            datetime.datetime.now(datetime.timezone.utc).isoformat(), scope, phase="runtime")
        matching = [row for row in _workflow_runs(repository, source_sha)
                    if str(row.get("id")) == selected_id]
        if len(matching) != 1:
            raise ValueError("selected-hosted-run-disappeared-or-duplicated")
        run = matching[0]
        identity = _validate_hosted_run(run, repository, source_sha, allow_active=True,
            expected_event="workflow_dispatch", expected_nonce=nonce)
        if identity["created_at"] != initial["created_at"]:
            raise ValueError("selected-hosted-run-creation-clock-changed")
        _validate_workflow_clock(started_at, identity["created_at"], nonce, base_sha)
        attempt = int(identity["run_attempt"])
        if attempt < current_attempt:
            raise ValueError("selected-hosted-run-attempt-regressed")
        current_attempt = attempt
        if run.get("status") == "completed":
            if run.get("conclusion") != "success":
                raise ValueError("exact-source-hosted-qualification-failed")
            return run
        remaining = _require_hosted_budget(started_at,
            datetime.datetime.now(datetime.timezone.utc).isoformat(), scope, phase="runtime")
        time.sleep(min(30, max(1, remaining - scope["qualification_batch"]["close_wall_seconds"])))


def _download_run_artifact(repository: str, run_id: str, run_attempt: str,
                           artifact_prefix: str, directory: pathlib.Path, *,
                           phase: str = "preparation") -> None:
    if directory.exists():
        raise ValueError("hosted-artifact-download-path-collision")
    directory.parent.mkdir(parents=True, exist_ok=True)
    directory.mkdir()
    _external(["gh", "run", "download", run_id, "--repo", repository,
        "--name", f"{artifact_prefix}-{run_id}-{run_attempt}", "--dir", str(directory)],
        timeout=4 * 60 * 60, phase=phase, owned_roots=(directory,))
    if not directory.is_dir() or not any(directory.iterdir()):
        raise ValueError("hosted-artifact-download-empty")


def _verify_attestation(subject: pathlib.Path, repository: str, source_sha: str,
                        run_id: str, run_attempt: int, expected_sha256: str) -> dict[str, Any]:
    """Delegate signer, issuer and exact invocation checks to the publisher verifier."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("gw_v02_promotion_attestation",
        ROOT / "scripts/release/promote.py")
    if spec is None or spec.loader is None:
        raise ValueError("hosted-attestation-verifier-unavailable")
    promote = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = promote
    spec.loader.exec_module(promote)
    try:
        verified = promote.verify_attestation(subject, repository, source_sha,
            str(run_id), int(run_attempt), expected_sha256=expected_sha256,
            runner=lambda command: _external(command, timeout=60, phase="package"))
    except (promote.PromotionError, OSError, ValueError, TypeError) as error:
        raise ValueError("hosted-attestation-rejected:" + str(error)) from None
    return {"status": "verified", "subject": subject.name, "sha256": expected_sha256,
            "repository": repository, "source_sha": source_sha,
            "run_id": str(run_id), "run_attempt": str(run_attempt),
            "signer_workflow": verified["workflow"], "oidc_issuer": "https://token.actions.githubusercontent.com"}


def run_hosted_qualification(packet_path: pathlib.Path, publication_copy: pathlib.Path,
                             scope_path: pathlib.Path, out: pathlib.Path) -> dict[str, Any]:
    """Merge sanitized source through protection, consume its exact CI artifacts, and freeze them."""
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    journal_path = ROOT / "build/v02/hosted-delivery-journal.json"
    source_receipt = publish_sanitized_source(packet_path, publication_copy, journal_path)
    existing = json.loads(journal_path.read_text(encoding="utf-8"))
    started_at = existing["started_at"]
    repository = existing["repository"]
    source_sha = source_receipt["public_source_sha"]
    main_ref = _gh_json(repository, "git/ref/heads/main", phase="preparation")
    if main_ref.get("object", {}).get("sha") != source_sha:
        raise ValueError("public-main-moved-before-hosted-qualification")
    nonce = _dispatch_qualification_run(repository, source_sha,
        source_receipt["public_base_sha"], journal_path, existing, scope)
    base_sha = source_receipt["public_base_sha"]
    run = _wait_for_exact_qualification_run(repository, source_sha, base_sha,
        started_at, nonce, scope)
    run_identity = _validate_hosted_run(run, repository, source_sha, allow_active=True,
        expected_event="workflow_dispatch", expected_nonce=nonce)
    existing = _bind_qualification_clock(existing, run_identity["created_at"])
    _write_json(journal_path, existing)
    started_at = existing["qualification_started_at"]
    os.environ["GENEWHIP_QUALIFICATION_STARTED_AT"] = started_at
    os.environ["GENEWHIP_QUALIFICATION_PHASE"] = "runtime"
    os.environ["GENEWHIP_QUALIFICATION_NONCE"] = nonce
    run = _wait_for_selected_run_completion(repository, source_sha, run, started_at, scope,
        nonce=nonce, base_sha=base_sha)
    run_identity = _validate_hosted_run(run, repository, source_sha,
        expected_event="workflow_dispatch", expected_nonce=nonce)
    run_id, run_attempt = run_identity["run_id"], run_identity["run_attempt"]
    if _require_hosted_budget(started_at,
            datetime.datetime.now(datetime.timezone.utc).isoformat(), scope, phase="runtime") <= 0:
        raise ValueError("qualification-common-cutoff-exhausted")
    os.environ["GENEWHIP_QUALIFICATION_PHASE"] = "package"

    download_root = ROOT / "build/v02/hosted-downloads" / f"{run_id}-{run_attempt}"
    package_download = download_root / "v02-package"
    release_download = download_root / "release-input"
    identity_download = download_root / "release-identity"
    for prefix, target in (("v02-package", package_download),
                           ("release-input", release_download),
                           ("release-identity", identity_download)):
        _require_hosted_budget(started_at, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                               scope, phase="package")
        _download_run_artifact(repository, run_id, run_attempt, prefix, target, phase="package")
        _require_hosted_budget(started_at, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                               scope, phase="package")
    transfer_inventory_path = package_download / "inventory.json"
    package_payload = package_download / "payload"
    transfer_inventory = _validate_package_transfer_identity(
        json.loads(transfer_inventory_path.read_text(encoding="utf-8")), source_sha)

    hosted_root = ROOT / "build/v02" / f"hosted-source-{source_sha[:12]}"
    if hosted_root.exists():
        if _git(hosted_root, "rev-parse", "HEAD") != source_sha:
            raise ValueError("hosted-source-checkout-collision")
    else:
        owner, name = repository.split("/", 1)
        remote = f"https://github.com/{owner}/{name}.git"
        hosted_root.mkdir(parents=True)
        _external(["git", "clone", "--no-tags", "--no-checkout", remote, str(hosted_root)],
                  timeout=300, phase="package", owned_roots=(hosted_root,))
        _external(["git", "checkout", "--detach", source_sha], cwd=hosted_root,
                  phase="package", owned_roots=(hosted_root,))
    if _git(hosted_root, "rev-parse", "HEAD") != source_sha or (hosted_root / ".planning").exists():
        raise ValueError("hosted-source-checkout-identity-invalid")
    install = _external([sys.executable, "-I", str(hosted_root / "scripts/release/v02_transfer.py"),
        "install-package", "--payload", str(package_payload), "--inventory", str(transfer_inventory_path),
        "--root", str(hosted_root), "--source-sha", source_sha], cwd=hosted_root,
        timeout=4 * 60 * 60, phase="package", owned_roots=(hosted_root,))
    installed = json.loads(install.stdout)
    if installed.get("status") != "pass" or installed.get("member_count") != transfer_inventory["member_count"]:
        raise ValueError("hosted-package-transfer-install-rejected")

    identity_file = identity_download / "_ci-identity.json"
    ci_identity = json.loads(identity_file.read_text(encoding="utf-8"))
    expected_identity = {"repository": repository, "source_sha": source_sha, "run_id": run_id,
        "run_attempt": run_attempt, "event": run_identity["event"], "ref": "refs/heads/main",
        "workflow": "Required preview checks", "workflow_file": ".github/workflows/ci.yml",
        "qualification_started_at": started_at, "qualification_nonce": nonce,
        "base_sha": base_sha}
    if ci_identity != expected_identity:
        raise ValueError("hosted-package-run-identity-mismatch")
    environment = os.environ.copy()
    environment.update({"GITHUB_REPOSITORY": repository, "GITHUB_SHA": source_sha,
        "GITHUB_BASE_SHA": base_sha, "GITHUB_RUN_ID": run_id,
        "GITHUB_RUN_ATTEMPT": run_attempt, "GITHUB_EVENT_NAME": run_identity["event"],
        "GITHUB_REF": "refs/heads/main", "GITHUB_WORKFLOW": "Required preview checks",
        "GENEWHIP_QUALIFICATION_STARTED_AT": started_at,
        "GENEWHIP_QUALIFICATION_NONCE": nonce})
    semantic_expected = {"source_sha": source_sha, "head_sha": source_sha, "base_sha": base_sha,
        "run_id": str(run_id), "run_attempt": str(run_attempt)}
    semantic_mutants_out = hosted_root / "build/v02/semantic-mutant-receipt.json"
    _external([sys.executable, "-I", str(hosted_root / "scripts/release/v02_qualification.py"),
        "--mode", "semantic-mutants", "--out", "build/v02/semantic-mutant-receipt.json",
        *_semantic_identity_args(semantic_expected)],
        cwd=hosted_root, timeout=900, env={**environment,
            "GENEWHIP_QUALIFICATION_PHASE": "package"}, phase="package",
        owned_roots=(hosted_root,))
    semantic_mutant_receipt = json.loads(semantic_mutants_out.read_text(encoding="utf-8"))
    _validate_semantic_mutant_receipt(semantic_mutant_receipt, semantic_expected, hosted_root,
                                      source_root=hosted_root)
    # The workflow uploads several globbed files from one common directory;
    # upload-artifact strips that common root, so the inventory is at the
    # downloaded artifact root alongside its archives.
    release_assets = release_download
    release_identity = identity_download
    _external([sys.executable, "-I", str(hosted_root / "scripts/ci/verify_attestation_inputs.py"),
        "verify", "--directory", str(release_assets), "--identity-directory", str(release_identity)],
        cwd=hosted_root, timeout=300, env={**environment,
            "GENEWHIP_QUALIFICATION_PHASE": "package"}, phase="package",
        owned_roots=(hosted_root,))
    inventory, assets, release_transfer_join, archives = _validate_hosted_release_inputs(
        release_assets, source_sha, transfer_inventory["members"])
    attestation_results = []
    subjects = [*(release_assets / name for name in archives), release_assets / "inventory.json"]
    for subject in subjects:
        if not subject.is_file() or subject.is_symlink():
            raise ValueError("hosted-release-inventory-member-missing")
        digest = _sha(subject)
        if subject.name in assets and (assets[subject.name].get("sha256") != digest
                                       or assets[subject.name].get("size") != subject.stat().st_size):
            raise ValueError("hosted-release-inventory-member-mismatch")
        attestation_results.append(_verify_attestation(subject, repository, source_sha,
            run_id, int(run_attempt), digest))


    close_out = hosted_root / "build/v02/hosted-close.json"
    _external([sys.executable, "-I", str(hosted_root / "scripts/release/v02_qualification.py"),
        "--mode", "validate", "--evidence", "build/v02/qualification-dimensions.json",
        "--out", "build/v02/hosted-close.json"], cwd=hosted_root, timeout=300,
        env={**environment, "GENEWHIP_QUALIFICATION_PHASE": "package"}, phase="package",
        owned_roots=(hosted_root,))
    close_evidence = hosted_root / "build/v02/qualification-dimensions.json"
    close_closure = hosted_root / "build/v02/qualification-evidence-closure.json"
    close_scope = hosted_root / "evidence/v02-execution.json"
    close_expected = {"source_sha": source_sha, "head_sha": source_sha,
        "base_sha": base_sha, "run_id": run_id, "run_attempt": run_attempt}
    close_receipt = json.loads(close_out.read_text(encoding="utf-8"))
    _validate_validation_readiness_receipt(close_receipt, close_expected,
        evidence_path=close_evidence, closure_path=close_closure, scope_path=close_scope)
    docs_out = hosted_root / "build/v02/hosted-docs-adoption.json"
    _external([sys.executable, "-I", str(hosted_root / "tests/package/docs_commands.py"),
        "--local-artifacts", "artifacts/v02", "--version", "0.2.0",
        "--expected-source", source_sha, "--require-clean-local", "--offline",
        "--out", "build/v02/hosted-docs-adoption.json"],
        cwd=hosted_root, timeout=4 * 60 * 60, env={**environment,
            "GENEWHIP_QUALIFICATION_PHASE": "package"}, phase="package",
        owned_roots=(hosted_root,))
    docs_receipt = json.loads(docs_out.read_text(encoding="utf-8"))
    docs_archive_identities = _validate_docs_adoption_receipt(docs_receipt, assets, source_sha)
    latest_main = _gh_json(repository, "git/ref/heads/main", phase="package")
    if latest_main.get("object", {}).get("sha") != source_sha:
        raise ValueError("public-main-moved-during-hosted-qualification")
    _require_hosted_budget(started_at, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           scope, phase="package")
    result = {"schema": "genewhip.v02-hosted-qualification.v1",
        "status": "prepublication-ready", "final_qualified": False,
        "reason": "postpublication-download-adoption-remains-required",
        "repository": repository, "source_sha": source_sha,
        "public_base_sha": source_receipt["public_base_sha"], "run_id": run_id,
        "run_attempt": run_attempt, "run_created_at": run_identity["created_at"],
        "pull_request": source_receipt, "transfer_inventory_sha256": _sha(transfer_inventory_path),
        "transfer_member_count": transfer_inventory["member_count"],
        "qualification_close": {"path": "build/v02/hosted-close.json", "sha256": _sha(close_out)},
        "semantic_mutant_receipt": {"path": "build/v02/semantic-mutant-receipt.json",
                                     "sha256": _sha(semantic_mutants_out),
                                     "core_denominator": semantic_mutant_receipt["core"]["denominator"],
                                     "host_denominator": semantic_mutant_receipt["host"]["denominator"]},
        "docs_adoption": {"path": "build/v02/hosted-docs-adoption.json", "sha256": _sha(docs_out)},
        "release_inventory_sha256": _sha(release_assets / "inventory.json"),
        "release_transfer_join": release_transfer_join,
        "asset_count": len(assets), "attestations": attestation_results,
        "required_dimensions": list(DIMENSIONS), "qualified_requirements": []}
    _write_json(out, result)
    staged = {"schema": "genewhip.v02-staged-inventory.v1", "repository": repository,
        "source_sha": source_sha, "run_id": run_id, "run_attempt": run_attempt,
        "inventory_path": "release-assets/inventory.json", "inventory_sha256": _sha(release_assets / "inventory.json"),
        "assets": [{"path": name, "size_bytes": (release_assets / name).stat().st_size,
                    "sha256": _sha(release_assets / name)} for name in sorted(assets)],
        "attestations": attestation_results,
        "transfer_inventory_sha256": _sha(transfer_inventory_path),
        "release_transfer_join": release_transfer_join,
        "docs_archive_identities": docs_archive_identities,
        "qualification_close_sha256": _sha(close_out), "docs_adoption_sha256": _sha(docs_out)}
    _write_json(ROOT / "build/v02/staged-inventory.json", staged)
    return result


def _identity() -> dict[str, str]:
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                          text=True, capture_output=True).stdout.strip()
    base = os.environ.get("GITHUB_BASE_SHA")
    if not base and os.environ.get("GITHUB_EVENT_PATH"):
        try:
            event = json.loads(pathlib.Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
            base = event.get("before") or event.get("pull_request", {}).get("base", {}).get("sha")
        except (OSError, ValueError, TypeError):
            base = None
    return {"source_sha": head, "head_sha": os.environ.get("GITHUB_SHA", head),
            "base_sha": base or head,
            "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1")}


def _step(name: str, argv: list[str], output: str, files: list[str]) -> dict[str, Any]:
    return {"name": name, "argv": argv, "output": output,
            "identity_dependencies": files, "source_sha": _identity()["source_sha"]}


def qualification_plan(build: pathlib.Path, scope: pathlib.Path) -> dict[str, Any]:
    """Resolve executable runtime, safety, chunk, measurement and package commands without starts."""
    build = build.resolve(strict=True)
    scope = scope.resolve(strict=True)
    if not (build / "CMakeCache.txt").is_file():
        raise ValueError("qualification-build-identity-missing")
    scope_data = json.loads(scope.read_text(encoding="utf-8"))
    if scope_data.get("schema") != "genewhip-v02-execution-v1":
        raise ValueError("qualification-execution-scope-invalid")
    ident = _identity()
    out = pathlib.Path("build/v02/qualification")
    runner = ROOT / "scripts/evidence/v02_run.py"
    commands = []
    for mode in ("full", "safety", "chunk"):
        target = out / f"{mode}.json"
        commands.append(_step(mode, [sys.executable, "-I", str(runner), "--mode", mode,
            "--build", str(build), "--scope", str(scope), "--plan-only", "--out", str(ROOT / target)],
            str(target), ["CMakeCache.txt", "evidence/v02-execution.json", "fixtures/phase6/"]))
    benchmark = ROOT / "tools/evidence/core_benchmark.py"
    for workload in ("control", "recursion94", "tank-battle"):
        target = out / "measurements" / f"{workload}.json"
        commands.append(_step("benchmark-" + workload, [sys.executable, "-I", str(benchmark),
            "--build", str(build), "--workload", workload, "--scope", str(scope),
            "--out", str(ROOT / target)], str(target), ["CMakeCache.txt", "evidence/v02-execution.json"]))
    commands.extend([
        _step("public-matrix", [sys.executable, "-I", str(ROOT / "scripts/evidence/v02_matrix.py"),
            "verify", "--bundle", str(ROOT / "build/v02/public/bundle.json"), "--roster",
            str(ROOT / "evidence/v02-roster.json"), "--schema", str(ROOT / "evidence/v02-schema.json")],
            "build/v02/qualification/public-matrix.json", ["evidence/v02-roster.json", "evidence/v02-schema.json"]),
        _step("package-sdk", [sys.executable, "-I", str(ROOT / "scripts/package_sdk.py"),
            "--release-version", "0.2.0", "--source-sha", ident["source_sha"],
            "--public-evidence", str(ROOT / "build/v02/public"), "--output-dir", str(ROOT / "artifacts/v02")],
            "artifacts/v02/sdk-archive-and-receipt", ["scripts/package_sdk.py", "packaging/", "build/v02/public/"]),
        _step("package-desktop", [sys.executable, "-I", str(ROOT / "scripts/package_desktop.py"),
            "--release-version", "0.2.0", "--source-sha", ident["source_sha"],
            "--public-evidence", str(ROOT / "build/v02/public"), "--output-dir", str(ROOT / "artifacts/v02")],
            "artifacts/v02/desktop-archive-and-receipt", ["scripts/package_desktop.py", "packaging/", "build/v02/public/"]),
        _step("docs", [sys.executable, "-I", str(ROOT / "tests/package/docs_commands.py"),
            "--local-artifacts", "artifacts/v02", "--version", "0.2.0", "--refresh-local", "--offline", "--out",
            str(ROOT / "build/v02/qualification/docs.json")], "build/v02/qualification/docs.json", ["docs/", "packaging/"]),
        _step("privacy", ["bash", "scripts/ci/public-hygiene.sh", "--self-test"],
            "build/v02/qualification/privacy.json", ["scripts/ci/public-hygiene.sh"]),
    ])
    return {"schema": "genewhip.v02-qualification-plan.v1", "status": "plan-only",
        "identity": ident, "build": str(build), "build_sha256": _sha(build / "CMakeCache.txt"),
        "scope": str(scope), "scope_sha256": _sha(scope), "dimensions": list(DIMENSIONS),
        "host_native_required": True, "launch_count": 0, "commands": commands,
        "limits": {"batch_seconds": 86400, "runtime_seconds": 64800,
            "benchmark_jobs": 3, "benchmark_job_seconds": 14400,
            "package_seconds": 14400, "close_reserve_seconds": 7200},
        "proof_order": ["runtime", "public-projection", "package-and-docs", "inventory", "attestation", "external-download-adoption", "final-conjunction"],
        "publisher_packet_schema": "genewhip.v02-publisher-packet.v1",
        "final_credit_source": "authenticated-downloaded-byte-adoption-only"}


def _run_semantic_mutant_suites(out: pathlib.Path, expected: dict[str, str],
                                scope: dict[str, Any]) -> dict[str, Any]:
    """Run the retained actual-validator mutation duties against fresh v0.2 reports."""
    import importlib.util
    _check_environment_clock(scope, "package")
    runtime_root = ROOT / "build/v02/runtime-observation"
    candidate_path = runtime_root / "candidate.json"
    core_path = runtime_root / "core-report.json"
    media_path = runtime_root / "media-report.json"
    software_path = runtime_root / "host-software.json"
    native_path = runtime_root / "host-native.json"
    if runtime_root.is_symlink() or not runtime_root.resolve(strict=True).is_relative_to(ROOT.resolve(strict=True)):
        raise ValueError("qualification-semantic-mutant-root-invalid")
    for path in (candidate_path, core_path, media_path, software_path, native_path):
        if (path.is_symlink() or not path.is_file() or not path.resolve(strict=True).is_relative_to(ROOT.resolve(strict=True))
                or path.stat().st_size > 32 * 1024 * 1024):
            raise ValueError("qualification-semantic-mutant-input-invalid:" + path.name)
    evidence = ROOT / "build/v02/evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    build = ROOT / "build/v02"
    fixture_spec = importlib.util.spec_from_file_location("gw_v02_mutant_fixture",
        ROOT / "tests/fixtures/phase6_game.py")
    host_spec = importlib.util.spec_from_file_location("gw_v02_mutant_host",
        ROOT / "tests/desktop/phase6_routes.py")
    if not fixture_spec or not fixture_spec.loader or not host_spec or not host_spec.loader:
        raise ValueError("qualification-semantic-mutant-module-unavailable")
    fixture = importlib.util.module_from_spec(fixture_spec)
    fixture_spec.loader.exec_module(fixture)
    host = importlib.util.module_from_spec(host_spec)
    host_spec.loader.exec_module(host)
    core_out = evidence / "core-mutants.json"
    host_out = evidence / "host-mutants.json"
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    if fixture.core_contract(build, candidate_path, core_out, core_path, media_path) != 0:
        raise ValueError("qualification-core-semantic-mutants-failed")
    if host.negative_controls(build, ROOT / "fixtures/phase6/recursion94-consumed-map-v1.json",
            ROOT / "fixtures/phase6/recursion94-consumed-map-v1.json", host_out,
            candidate_path, software_override=software_path, native_override=native_path,
            semantic_only=True) != 0:
        raise ValueError("qualification-host-semantic-mutants-failed")
    _check_environment_clock(scope, "package")
    core_result = json.loads(core_out.read_text(encoding="utf-8"))
    host_result = json.loads(host_out.read_text(encoding="utf-8"))
    core_rows = core_result.get("negative_controls")
    host_rows = host_result.get("mutations")
    if (core_result.get("status") != "pass" or core_result.get("candidate_sha256") != fixture.canonical_sha(candidate)
            or not isinstance(core_rows, list) or not core_rows
            or host_result.get("outcome") != "pass" or not isinstance(host_rows, list) or not host_rows
            or any(row.get("status") != "pass" for row in core_rows)
            or any(row.get("rejected") is not True for row in host_rows)):
        raise ValueError("qualification-semantic-mutant-roster-invalid")
    reports = {path.name: _sha(path) for path in (candidate_path, core_path, media_path, software_path, native_path)}
    receipt = {"schema": "genewhip.v02-semantic-mutants.v1", "status": "pass",
        "identity": expected, "candidate_sha256": fixture.canonical_sha(candidate),
        "positive_reports": reports,
        "core": {"denominator": len(core_rows), "pass": sum(row.get("status") == "pass" for row in core_rows),
                 "rows_sha256": hashlib.sha256(json.dumps(core_rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()},
        "host": {"denominator": len(host_rows), "pass": sum(row.get("rejected") is True for row in host_rows),
                 "rows_sha256": hashlib.sha256(json.dumps(host_rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()},
        "mutant_results": {"core": {"path": core_out.relative_to(ROOT).as_posix(), "sha256": _sha(core_out),
                "rows_sha256": hashlib.sha256(json.dumps(core_rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()},
            "host": {"path": host_out.relative_to(ROOT).as_posix(), "sha256": _sha(host_out),
                "rows_sha256": hashlib.sha256(json.dumps(host_rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}},
        "production_consumers": ["scripts/evidence/phase6_routes.py::validate_product_report",
                                 "scripts/evidence/phase6_routes.py::validate_media_report",
                                 "scripts/evidence/phase6_routes.py::validate_host_report"],
        "positive_validated_before_mutants": True, "host_native_positive_validated": True,
        "coverage_transfer": {"from": ["phase6_core_report_contract", "phase6_host_contract"],
            "to": "required-v02-hosted-source-qualified-runtime",
            "core_media_mutants": 32, "host_mutants": 21,
            "includes": ["core-report", "candidate-identities", "raw-native", "media-capture",
                "media-image", "media-audio", "six-host-roster", "native-host-capability",
                "host-process-receipts", "raw-input-audio-renderer-core-output"],
            "skip_allowed": False},
        "new_title_launches": 0}
    _validate_semantic_mutant_receipt(receipt, expected)
    _check_environment_clock(scope, "package")
    _write_json(out, receipt)
    return receipt


def _validate_semantic_mutant_receipt(receipt: Any, expected: dict[str, str],
                                      root: pathlib.Path = ROOT,
                                      source_root: pathlib.Path | None = None) -> None:
    """Single receipt gate shared by hosted orchestration and dimension consumers."""
    import importlib.util
    required = {"source_sha", "head_sha", "base_sha", "run_id", "run_attempt"}
    if (not isinstance(receipt, dict) or not isinstance(expected, dict) or set(expected) != required
            or any(not isinstance(expected.get(key), str) or
                not re.fullmatch(r"[0-9a-f]{40}", expected[key])
                for key in ("source_sha", "head_sha", "base_sha"))
            or not re.fullmatch(r"[0-9]+", str(expected.get("run_id", "")))
            or not re.fullmatch(r"[1-9][0-9]*", str(expected.get("run_attempt", "")))):
        raise ValueError("qualification-semantic-mutant-receipt-invalid")
    runtime = root / "build/v02/runtime-observation"
    report_names = ("candidate.json", "core-report.json", "media-report.json",
                    "host-software.json", "host-native.json")
    expected_reports = {}
    for name in report_names:
        path = runtime / name
        if (path.is_symlink() or not path.is_file() or
                not path.resolve(strict=True).is_relative_to(root.resolve(strict=True))):
            raise ValueError("qualification-semantic-mutant-positive-report-invalid:" + name)
        expected_reports[name] = _sha(path)
    candidate_doc = json.loads((runtime / "candidate.json").read_text(encoding="utf-8"))
    candidate_sha = hashlib.sha256(json.dumps(candidate_doc, sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()
    specs = (
        ("core", "tests/fixtures/phase6_game.py", "CORE_SEMANTIC_MUTANT_EXPECTATIONS", "negative_controls", "name", "reason", "status"),
        ("host", "tests/desktop/phase6_routes.py", "HOST_SEMANTIC_MUTANT_EXPECTATIONS", "mutations", "id", "expected_reason", "rejected"),
    )
    source_root = (source_root or pathlib.Path(__file__).resolve().parents[2]).resolve(strict=True)
    expected_receipt_rows = {}
    for name, source_path, constant_name, rows_key, name_key, reason_key, pass_key in specs:
        spec = importlib.util.spec_from_file_location("gw_expected_" + name, source_root / source_path)
        if spec is None or spec.loader is None:
            raise ValueError("qualification-semantic-mutant-roster-unavailable:" + name)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        expectations = getattr(module, constant_name, None)
        if not isinstance(expectations, tuple) or not expectations:
            raise ValueError("qualification-semantic-mutant-roster-unavailable:" + name)
        expected_rows = ([{name_key: ident, reason_key: reason, pass_key: "pass"}
                          for ident, reason in expectations] if name == "core" else
                         [{"id": ident, "expected_reason": reason, "actual_reason": reason,
                           "rejected": True} for ident, reason in expectations])
        result_refs = receipt.get("mutant_results")
        if not isinstance(result_refs, dict) or not isinstance(receipt.get(name), dict):
            raise ValueError("qualification-semantic-mutant-result-roster-invalid:" + name)
        result_ref = result_refs.get(name, {})
        if not isinstance(result_ref, dict):
            raise ValueError("qualification-semantic-mutant-result-invalid:" + name)
        relative = pathlib.PurePosixPath(result_ref.get("path", "")) if isinstance(result_ref, dict) else pathlib.PurePosixPath("/")
        result_path = root / relative
        if (relative.is_absolute() or ".." in relative.parts or result_path.is_symlink()
                or not result_path.is_file() or result_path.stat().st_size > 8 * 1024 * 1024
                or not result_path.resolve(strict=True).is_relative_to(root.resolve(strict=True))
                or _sha(result_path) != result_ref.get("sha256")):
            raise ValueError("qualification-semantic-mutant-result-invalid:" + name)
        result = json.loads(result_path.read_text(encoding="utf-8"))
        rows = result.get(rows_key) if isinstance(result, dict) else None
        expected_digest = hashlib.sha256(json.dumps(expected_rows, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        if rows != expected_rows or receipt.get(name, {}).get("rows_sha256") != expected_digest:
            raise ValueError("qualification-semantic-mutant-result-roster-invalid:" + name)
        if (result_ref.get("rows_sha256") != expected_digest
                or len(expected_rows) != (32 if name == "core" else 21)):
            raise ValueError("qualification-semantic-mutant-result-roster-invalid:" + name)
        expected_receipt_rows[name] = {"denominator": len(expected_rows),
            "pass": len(expected_rows), "rows_sha256": expected_digest}
    coverage = {"from": ["phase6_core_report_contract", "phase6_host_contract"],
        "to": "required-v02-hosted-source-qualified-runtime", "core_media_mutants": 32,
        "host_mutants": 21, "includes": ["core-report", "candidate-identities", "raw-native",
            "media-capture", "media-image", "media-audio", "six-host-roster",
            "native-host-capability", "host-process-receipts", "raw-input-audio-renderer-core-output"],
        "skip_allowed": False}
    if (receipt.get("schema") != "genewhip.v02-semantic-mutants.v1" or receipt.get("status") != "pass"
            or receipt.get("identity") != expected or receipt.get("positive_reports") != expected_reports
            or receipt.get("candidate_sha256") != candidate_sha or receipt.get("coverage_transfer") != coverage
            or receipt.get("positive_validated_before_mutants") is not True
            or receipt.get("host_native_positive_validated") is not True
            or receipt.get("new_title_launches") != 0
            or receipt.get("core") != expected_receipt_rows.get("core")
            or receipt.get("host") != expected_receipt_rows.get("host")):
        raise ValueError("qualification-semantic-mutant-receipt-invalid")


def _semantic_identity_args(identity: dict[str, str]) -> list[str]:
    return [item for key in ("source_sha", "head_sha", "base_sha", "run_id", "run_attempt")
            for item in ("--" + key.replace("_", "-"), str(identity[key]))]


def _selected_semantic_identity(args: argparse.Namespace) -> dict[str, str]:
    values = {"source_sha": args.source_sha, "head_sha": args.head_sha,
        "base_sha": args.base_sha, "run_id": args.run_id, "run_attempt": args.run_attempt}
    if (any(not isinstance(value, str) or not value for value in values.values())
            or any(not re.fullmatch(r"[0-9a-f]{40}", values[key])
                   for key in ("source_sha", "head_sha", "base_sha"))
            or not re.fullmatch(r"[0-9]+", values["run_id"])
            or not re.fullmatch(r"[1-9][0-9]*", values["run_attempt"])):
        raise ValueError("qualification-semantic-mutant-explicit-identity-required")
    return values


def _dimension_semantic_errors(name: str, evidence_path: pathlib.Path,
                               expected: dict[str, Any]) -> list[str]:
    """Reopen one bounded raw dimension with the producer's authoritative validators."""
    try:
        if evidence_path.is_symlink() or not evidence_path.is_file() or evidence_path.stat().st_size > 32 * 1024 * 1024:
            return ["proof-evidence-file-type-or-size-invalid:" + name]
        doc = json.loads(evidence_path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            return ["proof-evidence-not-object:" + name]
        runtime = _load_runtime_module()
        fixture = runtime._module(ROOT / "tests/fixtures/phase6_game.py", "gw_v02_dimension_fixture")
        route = runtime._module(ROOT / "scripts/evidence/phase6_routes.py", "gw_v02_dimension_routes")
        candidate_path = ROOT / "build/v02/runtime-observation/candidate.json"
        if name in ("core", "host", "host-native", "media", "safety", "determinism"):
            if candidate_path.is_symlink() or not candidate_path.is_file() or candidate_path.stat().st_size > 8 * 1024 * 1024:
                return ["proof-current-candidate-unavailable:" + name]
            candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        if name == "core":
            route.validate_product_report(doc, candidate)
            if (doc.get("outcomes", {}).get("status") not in ("pass", "pass-diagnostic") or
                    len(doc.get("runs", [])) != 24 or len(doc.get("stages", [])) != 120 or
                    len(doc.get("media_captures", [])) < 2):
                return ["proof-core-roster-progress-or-media-invalid"]
            mutant_error = _semantic_mutant_receipt_error(expected)
            if mutant_error: return [mutant_error]
        elif name in ("host", "host-native"):
            route.validate_host_report(doc, candidate)
            backend = "software" if name == "host" else "native"
            if (doc.get("backend") != backend or doc.get("outcome", doc.get("status")) not in ("pass", "pass-diagnostic") or
                    len(doc.get("runs", [])) != 6):
                return ["proof-host-roster-or-backend-invalid:" + name]
            mutant_error = _semantic_mutant_receipt_error(expected)
            if mutant_error: return [mutant_error]
        elif name == "media":
            route.validate_media_report(doc, candidate)
            if doc.get("result") != "pass":
                return ["proof-media-outcome-invalid"]
        elif name == "safety":
            safety = runtime._module(ROOT / "tests/api/safety_contract.py", "gw_v02_dimension_safety")
            reason = safety.validate_phase6_safety_report(doc)
            if reason:
                return ["proof-safety-semantic-invalid:" + str(reason)]
            if (doc.get("schema") != "genewhip-phase6-safety-v1" or doc.get("status") != "pass" or
                    doc.get("candidate_sha256") != fixture.canonical_sha(candidate) or
                    doc.get("source_provenance") != {path: _sha(ROOT / path) for path in fixture.SAFETY_SOURCE_PATHS} or
                    any(row.get("bounded_fuzz", {}).get("denominator") != 4096 or
                        row.get("bounded_fuzz", {}).get("pass") != 4096 or
                        row.get("bounded_fuzz", {}).get("unknown") != 0 or
                        row.get("bounded_fuzz", {}).get("skipped") != 0 for row in doc["variants"])):
                return ["proof-safety-current-roster-or-fuzz-invalid"]
            ref = doc.get("build_evidence")
            manifest_path = pathlib.Path(ref.get("path", "")) if isinstance(ref, dict) else pathlib.Path()
            if not manifest_path.is_absolute(): manifest_path = ROOT / manifest_path
            if manifest_path.is_symlink() or not manifest_path.is_file() or _sha(manifest_path) != ref.get("sha256"):
                return ["proof-safety-build-evidence-binding-invalid"]
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if (manifest.get("schema") != "genewhip.v02-safety-build-evidence.v2" or
                    manifest.get("identity") != json.loads((ROOT / "build/v02/runtime-identity.json").read_text(encoding="utf-8")) or
                    manifest.get("evidence_basis") != "producer-observed-source-identities-plus-portable-facts"):
                return ["proof-safety-build-evidence-identity-invalid"]
            expected_binaries = {}
            expected_variants = {}
            for variant in doc["variants"]:
                directory = pathlib.PurePosixPath(variant.get("build_directory", ""))
                if (directory.is_absolute() or ".." in directory.parts or
                        not str(directory).startswith("build/v02/")):
                    return ["proof-safety-build-directory-invalid"]
                identity = variant.get("build_identity", {})
                variant_sources = {(directory / "CMakeCache.txt").as_posix(): identity.get("cache_sha256"),
                    (directory / "phase6_safety").as_posix(): identity.get("phase6_safety_sha256")}
                variant_sources.update(identity.get("test_executables", {}))
                expected_binaries.update(variant_sources)
                expected_variants[variant.get("variant")] = variant_sources
            entries = manifest.get("entries", [])
            observed_binaries = {row.get("source_path"): row.get("source_sha256") for row in entries if isinstance(row, dict)}
            if (manifest.get("raw_build_artifact_bytes_transferred") is not False or
                    len(entries) != manifest.get("entry_count") or observed_binaries != expected_binaries or
                    sum(row.get("source_size", 0) for row in entries) != manifest.get("source_bytes_total")):
                return ["proof-safety-build-roster-invalid"]
            import importlib.util
            facts_spec = importlib.util.spec_from_file_location("gw_v02_validate_safety_facts",
                ROOT / "scripts/evidence/v02_safety_build_facts.py")
            facts_module = importlib.util.module_from_spec(facts_spec)
            facts_spec.loader.exec_module(facts_module)
            compiler_identity = None
            for variant, sources in expected_variants.items():
                variant_rows = [row for row in entries if row.get("variant") == variant]
                if len(variant_rows) != len(sources):
                    return ["proof-safety-build-facts-roster-invalid"]
                facts_paths = {row.get("path") for row in variant_rows}
                if len(facts_paths) != 1:
                    return ["proof-safety-build-facts-roster-invalid"]
                fact_path = pathlib.PurePosixPath(next(iter(facts_paths)))
                if fact_path.is_absolute() or ".." in fact_path.parts:
                    return ["proof-safety-build-facts-path-invalid"]
                facts_file = ROOT / fact_path
                if facts_file.is_symlink() or not facts_file.is_file() or facts_file.stat().st_size > 1024 * 1024:
                    return ["proof-safety-build-facts-unavailable"]
                facts = json.loads(facts_file.read_text(encoding="utf-8"))
                observed_sources = {row.get("source_path"): row.get("sha256")
                    for row in facts.get("raw_build_artifact_identities", [])}
                if (facts.get("schema") != "genewhip.v02-portable-build-facts.v1" or
                        facts.get("variant") != variant or observed_sources != sources or
                        facts.get("raw_build_artifact_bytes_transferred") is not False or
                        facts.get("evidence_basis") != "producer-observed-source-identities-plus-portable-facts" or
                        facts_module.validate_projection(facts, variant, sources)):
                    return ["proof-safety-build-facts-invalid"]
                facts_identity = (facts["build_facts"]["CMAKE_C_COMPILER_ID"],
                    facts["build_facts"]["CMAKE_C_COMPILER_VERSION"])
                if compiler_identity is not None and facts_identity != compiler_identity:
                    return ["proof-safety-build-facts-compiler-mismatch"]
                compiler_identity = facts_identity
            portable_paths = {row.get("path") for row in entries}
            if sum((ROOT / name).stat().st_size for name in portable_paths) != manifest.get("portable_fact_bytes_total"):
                return ["proof-safety-build-facts-total-invalid"]
            for entry in entries:
                facts_file = ROOT / entry["path"]
                if (facts_file.is_symlink() or not facts_file.is_file() or
                        facts_file.stat().st_size != entry.get("size") or _sha(facts_file) != entry.get("sha256")):
                    return ["proof-safety-build-facts-identity-invalid"]
        elif name == "determinism":
            if doc.get("schema") != "genewhip-phase6-chunk-v1" or doc.get("status") != "pass" or len(doc.get("routes", [])) != 2:
                return ["proof-chunk-roster-invalid"]
            chunk_module = runtime._module(ROOT / "tests/fixtures/phase6_game.py", "gw_v02_dimension_chunk")
            seen = set()
            for row in doc["routes"]:
                title = row.get("fixture")
                if title not in ("recursion94", "tank-battle") or title in seen or row.get("status") != "pass":
                    return ["proof-chunk-title-roster-invalid"]
                seen.add(title)
                native, _ = _read_project_json(row.get("source_run", {}).get("native_report"), "chunk-native")
                child, _ = _read_project_json(row.get("chunk_report"), "chunk-child")
                cap = 100_000_000 if title == "recursion94" else 10_000_000
                chunk_module._validate_title_pair_facts(child, native, cap, title)
                if (child.get("events") != row.get("source_run", {}).get("inputs") or
                        row.get("process", {}).get("process_group_cleanup") != "confirmed" or
                        row.get("process", {}).get("bound_violation")):
                    return ["proof-chunk-event-or-cleanup-invalid"]
        elif name == "measurements":
            if doc.get("schema") != "genewhip-v02-measurement-summary-v1" or set(doc.get("workloads", {})) != {
                    "control", "recursion94", "tank-battle"} or any(doc.get(k) != expected.get(k) for k in IDENTITY_FIELDS):
                return ["proof-measurement-roster-invalid"]
            benchmark = _load_benchmark_module()
            scope = json.loads((ROOT / "evidence/v02-execution.json").read_text(encoding="utf-8"))
            for workload, facts in doc["workloads"].items():
                report_path = pathlib.Path(facts.get("path", ""))
                if not report_path.is_absolute(): report_path = ROOT / report_path
                if report_path.is_symlink() or not report_path.is_file() or report_path.stat().st_size > 32 * 1024 * 1024 or _sha(report_path) != facts.get("sha256"):
                    return ["proof-measurement-bytes-mismatch:" + workload]
                report = json.loads(report_path.read_text(encoding="utf-8"))
                errors = benchmark.validate_workload_report(report, workload, benchmark.source_identity(), scope["scope_id"])
                if (errors or report.get("head_sha") != expected.get("head_sha") or report.get("base_sha") != expected.get("base_sha") or
                        report.get("run_id") != expected.get("run_id") or report.get("run_attempt") != expected.get("run_attempt") or
                        report.get("host_identity") != facts.get("host_identity") or facts.get("process_starts") != 21):
                    return ["proof-measurement-semantics-invalid:" + workload]
        elif name == "public-matrix":
            identity_path = ROOT / "build/v02/runtime-identity.json"
            identity = json.loads(identity_path.read_text(encoding="utf-8"))
            matrix = _load_matrix_module()
            matrix.verify_public_closure(evidence_path.parent, ROOT / "evidence/v02-roster.json", identity)
            matrix.validate_qualification_matrix(json.loads((evidence_path.parent / "observations.json").read_text(encoding="utf-8")))
        elif name in ("package", "rights"):
            promote = runtime._module(ROOT / "scripts/release/promote.py", "gw_v02_dimension_promote")
            inventory_path = evidence_path
            if name == "package":
                inventory_path = pathlib.Path(doc.get("inventory", ""))
                if not inventory_path.is_absolute(): inventory_path = ROOT / inventory_path
                if doc.get("schema") != "genewhip.v02-package-receipt.v1" or doc.get("source_sha") != expected["source_sha"]:
                    return ["proof-package-receipt-invalid"]
                if inventory_path.is_symlink() or not inventory_path.is_file() or _sha(inventory_path) != doc.get("inventory_sha256"):
                    return ["proof-package-inventory-binding-invalid"]
                attempts = doc.get("attempts", [])
                if (doc.get("identity") != expected or len(attempts) != 4 or
                        [attempt.get("label") for attempt in attempts] != ["package-sdk", "package-desktop", "package-docs", "package-inventory"] or
                        any(attempt.get("returncode") != 0 or attempt.get("process_group_cleanup") != "confirmed" or
                            len(attempt.get("processes", [])) != 1 for attempt in attempts)):
                    return ["proof-package-attempts-invalid"]
            inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
            asset_dir = inventory_path.parent
            _, errors = promote.validate_release_inventory(asset_dir, inventory)
            if not errors: errors = promote.validate_qualified_inventory(asset_dir, inventory, expected["source_sha"])
            if errors: return ["proof-rights-inventory-invalid:" + ",".join(errors)]
        elif name == "docs":
            packages = doc.get("packages", {})
            if (doc.get("schema") != "genewhip-docs-command-qualification-v2" or doc.get("version") != "0.2.0" or
                    doc.get("outcome") != "pass" or doc.get("mode") != "clean-local-qualified" or
                    doc.get("local_source_identity") != expected["source_sha"] or
                    set(packages) != {"sdk", "desktop"} or any(
                        not isinstance(item, dict) or item.get("source_revision") != expected["source_sha"] or
                        item.get("source_state") != "clean" or not isinstance(item.get("archive_sha256"), str) or
                        len(item["archive_sha256"]) != 64 for item in packages.values()) or
                    set(doc.get("commands", {}).values()) != {"pass"} or
                    any(row.get("process_group_cleanup") != "confirmed" for row in doc.get("processes", []))):
                return ["proof-docs-command-semantics-invalid"]
        elif name == "privacy":
            attempt_path = ROOT / "artifacts/qualification-command-attempts/public-hygiene.attempt.json"
            if (doc.get("schema") != "genewhip-v02-public-hygiene-v1" or doc.get("status") != "pass" or
                    doc.get("identity") != expected or attempt_path.is_symlink() or not attempt_path.is_file() or
                    _sha(attempt_path) != doc.get("attempt_sha256")):
                return ["proof-privacy-attempt-binding-invalid"]
            attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
            if (attempt.get("label") != "public-hygiene" or attempt.get("argv") != ["bash", "scripts/ci/public-hygiene.sh", "--self-test"] or
                    attempt.get("returncode") != 0 or
                    attempt.get("process_group_cleanup") != "confirmed" or
                    attempt.get("streams", {}).get("stdout", {}).get("sha256") != doc.get("stdout_sha256") or
                    attempt.get("streams", {}).get("stdout", {}).get("text", "").strip() != "public hygiene: PASS"):
                return ["proof-privacy-attempt-invalid"]
        else:
            return ["proof-dimension-validator-missing:" + name]
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
        return ["proof-dimension-semantic-invalid:" + name + ":" + type(error).__name__]
    return []


def _referenced_evidence_files(dimension_sources: dict[str, pathlib.Path]) -> dict[str, str]:
    """Collect and bound every path+digest attachment reachable from direct evidence JSON."""
    found: dict[str, str] = {}
    total = 0
    visited_documents: set[str] = set()
    def add_file(relative: str, digest: str) -> tuple[str, pathlib.Path]:
        path = pathlib.Path(relative)
        if not path.is_absolute(): path = ROOT / path
        try: name = path.resolve(strict=True).relative_to(ROOT.resolve()).as_posix()
        except (OSError, ValueError) as error: raise ValueError("qualification-evidence-reference-outside-root") from error
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024 or _sha(path) != digest:
            raise ValueError("qualification-evidence-reference-invalid:" + name)
        prior = found.get(name)
        if prior is not None and prior != digest:
            raise ValueError("qualification-evidence-reference-conflict:" + name)
        found[name] = digest
        return name, path
    def visit(value: Any, depth: int = 0) -> None:
        nonlocal total
        if isinstance(value, dict):
            for ref_key in ("path", "retained_path"):
                relative, digest = value.get(ref_key), value.get("sha256")
                if isinstance(relative, str) and isinstance(digest, str) and len(digest) == 64:
                    name, path = add_file(relative, digest)
                    if path.suffix == ".json" and name not in visited_documents and depth < 4:
                        visited_documents.add(name)
                        visit(json.loads(path.read_text(encoding="utf-8")), depth + 1)
            for child in value.values(): visit(child, depth)
        elif isinstance(value, list):
            for child in value: visit(child, depth)
    for path in dimension_sources.values():
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
            raise ValueError("qualification-evidence-source-invalid")
        visit(json.loads(path.read_text(encoding="utf-8")))
    if len(found) > 256:
        raise ValueError("qualification-evidence-reference-count-cap")
    for name in found:
        total += (ROOT / name).stat().st_size
    if total > 512 * 1024 * 1024:
        raise ValueError("qualification-evidence-reference-byte-cap")
    return dict(sorted(found.items()))


def validate_conjunction(evidence: Any, expected: dict[str, Any], closure: Any = None) -> list[str]:
    """Validate exact-source dimension receipts before any qualification credit."""
    problems: list[str] = []
    if not isinstance(evidence, dict):
        return ["qualification-evidence-not-object"]
    closure_dimensions = closure.get("dimensions") if isinstance(closure, dict) else None
    references = closure.get("referenced_files") if isinstance(closure, dict) else None
    if (not isinstance(closure, dict) or closure.get("schema") != "genewhip.v02-evidence-closure.v1" or
            closure.get("identity") != expected or not isinstance(closure_dimensions, dict) or
            set(closure_dimensions) != set(REQUIRED_DIMENSIONS) or not isinstance(references, dict) or len(references) > 256):
        problems.append("qualification-evidence-closure-invalid")
    else:
        closure_bytes = 0
        for name, digest in references.items():
            if not isinstance(name, str) or pathlib.Path(name).is_absolute() or ".." in pathlib.PurePosixPath(name).parts:
                problems.append("qualification-evidence-closure-reference-invalid")
                continue
            path = ROOT / name
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024 or _sha(path) != digest:
                problems.append("qualification-evidence-closure-reference-invalid")
                continue
            closure_bytes += path.stat().st_size
        if closure_bytes > 512 * 1024 * 1024:
            problems.append("qualification-evidence-closure-byte-cap")
    for name in REQUIRED_DIMENSIONS:
        row = evidence.get(name)
        if not isinstance(row, dict):
            problems.append("proof-missing:" + name)
            continue
        if row.get("outcome") != "pass":
            problems.append("proof-not-pass:" + name)
        if row.get("schema") != "genewhip.v02-dimension-proof.v1" or row.get("dimension") != name:
            problems.append("proof-dimension-binding-invalid:" + name)
        if row.get("evidence_schema") != "genewhip.v02-dimension-observation.v1":
            problems.append("proof-evidence-schema-invalid:" + name)
        for field in IDENTITY_FIELDS:
            if row.get(field) != expected.get(field):
                problems.append(f"proof-identity-mismatch:{name}:{field}")
        digest = row.get("output_sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            problems.append("proof-output-digest-invalid:" + name)
        output = row.get("output")
        if not isinstance(output, str) or not output:
            problems.append("proof-output-missing:" + name)
        else:
            path = pathlib.Path(output)
            if not path.is_absolute():
                path = ROOT / path
            try:
                if path.is_symlink() or not path.is_file() or _sha(path) != digest:
                    problems.append("proof-output-bytes-mismatch:" + name)
                else:
                    observation = json.loads(path.read_text(encoding="utf-8"))
                    if (observation.get("schema") != "genewhip.v02-dimension-observation.v1" or
                            observation.get("dimension") != name or observation.get("outcome") != "pass" or
                            observation.get("identity") != expected):
                        problems.append("proof-observation-binding-invalid:" + name)
                    evidence_path = pathlib.Path(observation.get("evidence_path", ""))
                    if not evidence_path.is_absolute():
                        evidence_path = ROOT / evidence_path
                    if (evidence_path.is_symlink() or not evidence_path.is_file() or
                            _sha(evidence_path) != observation.get("evidence_sha256")):
                        problems.append("proof-evidence-bytes-mismatch:" + name)
                    elif isinstance(closure, dict):
                        entry = closure.get("dimensions", {}).get(name, {})
                        if not isinstance(entry, dict):
                            problems.append("proof-closure-binding-invalid:" + name)
                            continue
                        try:
                            relative = evidence_path.resolve().relative_to(ROOT.resolve()).as_posix()
                        except ValueError:
                            relative = ""
                        if (entry.get("path") != relative or entry.get("sha256") != _sha(evidence_path) or
                                entry.get("identity") != expected):
                            problems.append("proof-closure-binding-invalid:" + name)
                        else:
                            problems.extend(_dimension_semantic_errors(name, evidence_path, expected))
            except OSError:
                problems.append("proof-output-unavailable:" + name)
            except (ValueError, TypeError):
                problems.append("proof-observation-invalid:" + name)
    native = evidence.get(NATIVE_REQUIRED)
    if not isinstance(native, dict) or native.get("capability") != "present":
        problems.append("native-capability-missing")
    if isinstance(closure, dict) and isinstance(closure_dimensions, dict):
        source_paths = {}
        for name, row in evidence.items():
            if not isinstance(row, dict) or not isinstance(row.get("output"), str): continue
            output = pathlib.Path(row["output"])
            if not output.is_absolute(): output = ROOT / output
            if not output.is_file() or output.is_symlink(): continue
            try:
                observation = json.loads(output.read_text(encoding="utf-8"))
                direct = pathlib.Path(observation.get("evidence_path", ""))
                if not direct.is_absolute(): direct = ROOT / direct
                if direct.is_file() and not direct.is_symlink(): source_paths[name] = direct
            except (OSError, ValueError, TypeError):
                continue
        if set(source_paths) == set(REQUIRED_DIMENSIONS):
            try:
                if _referenced_evidence_files(source_paths) != references:
                    problems.append("qualification-evidence-closure-reference-set-mismatch")
            except (OSError, ValueError, TypeError):
                problems.append("qualification-evidence-closure-reference-invalid")
    return problems


def _write_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _public_argv(command: list[str]) -> list[str]:
    """Represent repository-local absolute argv paths as portable project paths."""
    result = []
    for argument in command:
        try:
            result.append(pathlib.Path(argument).resolve().relative_to(ROOT.resolve()).as_posix()
                if pathlib.Path(argument).is_absolute() else argument)
        except (OSError, ValueError):
            result.append(argument)
    return result


def _bounded_command(command: list[str], *, limits: dict[str, Any], scratch: pathlib.Path,
                     timeout: int, label: str, env: dict[str, str] | None = None,
                     cwd: pathlib.Path = ROOT, check: bool = True,
                     scratch_roots: tuple[pathlib.Path, ...] | None = None) -> dict[str, Any]:
    """Run one coordinator child through the existing monitored PGID launcher and journal it first."""
    import importlib.util
    boundary_path = ROOT / "tests/session/phase6_route_contract.py"
    spec = importlib.util.spec_from_file_location("gw_v02_coordinator_boundary", boundary_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("qualification-bounded-launcher-import")
    boundary = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(boundary)
    scratch.mkdir(parents=True, exist_ok=True)
    monitored_roots = scratch_roots if scratch_roots is not None else (scratch,)
    receipt: list[dict[str, Any]] = []; streams: dict[str, Any] = {}
    output = scratch / (label + ".json")
    launch_error=None;returncode=None;stdout="";stderr=""
    try:
        result = boundary._run_client(pathlib.Path(command[0]), command, receipt,
            report=output, timeout=min(timeout, limits["wall_seconds"]), cwd=cwd, env=env,
            retained_streams=streams, limits=limits, scratch_roots=monitored_roots)
        returncode=result.returncode;stdout=result.stdout;stderr=result.stderr
    except BaseException as exc:
        launch_error=f"{type(exc).__name__}: {exc}"
    for name in ("stdout","stderr"):
        streams.setdefault(name,{"status":"not-started","observed_bytes":0,"retained_bytes":0,
            "sha256":hashlib.sha256(b"").hexdigest(),"truncated":False})
    attempt = {"schema":"genewhip.v02-coordinator-child-attempt.v1", "label":label,
        "argv":_public_argv(command), "returncode":returncode, "launch_error":launch_error,
        "stdout_tail":stdout[-8192:],"stderr_tail":stderr[-8192:],"processes":receipt,
        "streams":streams, "process_group_cleanup":receipt[-1].get("process_group_cleanup") if receipt else "missing",
        "output":str(output.relative_to(ROOT)) if output.is_file() else None,
        "output_sha256":_sha(output) if output.is_file() else None}
    _write_json(scratch / (label + ".attempt.json"), attempt)
    if launch_error is not None:
        raise RuntimeError("qualification-child-boundary-error:"+label+":"+launch_error)
    if (len(receipt) != 1 or
            receipt[0].get("process_group_cleanup") != "confirmed" or receipt[0].get("bound_violation")):
        raise RuntimeError(f"qualification-child-failed:{label}:{returncode}:{stderr[-2048:]}")
    if check and returncode != 0:
        raise RuntimeError(f"qualification-child-failed:{label}:{returncode}:{stderr[-2048:]}")
    return attempt


def run_runtime(build: pathlib.Path, scope: pathlib.Path, out: pathlib.Path) -> dict[str, Any]:
    """Run an explicitly selected bounded v02 mode and retain its actual receipt."""
    plan = qualification_plan(build, scope)
    command = [sys.executable, "-I", str(ROOT / "scripts/evidence/v02_run.py"),
               "--mode", "full", "--build", str(build), "--scope", str(scope), "--out", str(out)]
    started = time.monotonic()
    scope_data=json.loads(pathlib.Path(scope).read_text(encoding="utf-8"))
    limits=dict(scope_data["per_child_limits"])
    runtime_budget = int(plan["limits"]["runtime_seconds"])
    shared_start = os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT")
    if shared_start:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        _require_hosted_budget(shared_start, now, scope_data, phase="runtime")
        elapsed = (_parse_utc(now) - _parse_utc(shared_start)).total_seconds()
        runtime_budget = min(runtime_budget,
            max(1, int(scope_data["qualification_batch"]["runtime_wall_seconds"] - elapsed)))
    limits["wall_seconds"] = runtime_budget
    scratch=out.parent/(out.stem+"-attempts")
    attempt=_bounded_command(command,limits=limits,scratch=scratch,
        timeout=runtime_budget,label="runtime")
    if shared_start:
        _require_hosted_budget(shared_start, datetime.datetime.now(datetime.timezone.utc).isoformat(),
                               scope_data, phase="runtime")
    stdout=attempt["streams"].get("stdout",{}).get("text","")
    stderr=attempt["streams"].get("stderr",{}).get("text","")
    record = {"schema": "genewhip.v02-runtime-attempt.v1", "command": command,
        "identity": plan["identity"], "returncode": attempt["returncode"],
        "stdout": stdout[-8192:], "stderr": stderr[-8192:], "processes":attempt["processes"],
        "stream_receipts":attempt["streams"],"cleanup":attempt["process_group_cleanup"],
        "elapsed_seconds": round(time.monotonic() - started, 3), "receipt": str(out)}
    _write_json(out.with_suffix(out.suffix + ".attempt.json"), record)
    if attempt["returncode"] != 0:
        raise RuntimeError("qualification-runtime-failed:" + str(attempt["returncode"]))
    import importlib.util
    transfer_spec = importlib.util.spec_from_file_location("gw_v02_runtime_transfer",
        ROOT / "scripts/release/v02_transfer.py")
    transfer = importlib.util.module_from_spec(transfer_spec)
    transfer_spec.loader.exec_module(transfer)
    transfer.export(ROOT, ROOT / "build/v02/runtime-transfer")
    return record


def validate_receipt_map(path: pathlib.Path, expected: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    closure_path = ROOT / "build/v02/qualification-evidence-closure.json"
    if closure_path.is_symlink() or not closure_path.is_file() or closure_path.stat().st_size > 1024 * 1024:
        raise ValueError("qualification-close-evidence-closure-missing")
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    if isinstance(value, dict) and set(value) == set(REQUIRED_DIMENSIONS):
        dimensions = value
    elif isinstance(value, dict) and isinstance(value.get("dimensions"), dict):
        dimensions = value["dimensions"]
    else:
        dimensions = None
    problems = validate_conjunction(dimensions, expected, closure)
    if problems:
        raise ValueError("qualification-close-rejected:" + ",".join(problems))
    return {"dimensions": dimensions, "evidence": value, "closure": closure}


def _validation_readiness_receipt(validated: dict[str, Any], expected: dict[str, Any],
                                  evidence_path: pathlib.Path, scope_path: pathlib.Path) -> dict[str, Any]:
    closure_path = ROOT / "build/v02/qualification-evidence-closure.json"
    dimensions = validated["dimensions"]
    canonical_dimensions = json.dumps(dimensions, sort_keys=True, separators=(",", ":")).encode()
    return {"schema": "genewhip.v02-validation-readiness.v1",
        "status": "readiness-pass", "final_qualified": False,
        "reason": "postpublication-download-adoption-required", "identity": expected,
        "dimensions": dimensions, "dimension_count": len(dimensions),
        "dimensions_sha256": hashlib.sha256(canonical_dimensions).hexdigest(),
        "evidence_sha256": _sha(evidence_path.resolve(strict=True)),
        "closure_sha256": _sha(closure_path),
        "scope_sha256": _sha(scope_path.resolve(strict=True)),
        "qualified_requirements": []}


def _validate_validation_readiness_receipt(receipt: Any, expected: dict[str, Any], *,
                                           evidence_path: pathlib.Path,
                                           closure_path: pathlib.Path,
                                           scope_path: pathlib.Path) -> dict[str, Any]:
    """Reopen the hosted validator's exact readiness output before hashing it into qualification."""
    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        dimensions = evidence.get("dimensions") if isinstance(evidence, dict) else None
        if not isinstance(dimensions, dict) and isinstance(evidence, dict) and set(evidence) == set(REQUIRED_DIMENSIONS):
            dimensions = evidence
        closure = json.loads(closure_path.read_text(encoding="utf-8"))
        if (not isinstance(receipt, dict)
                or receipt.get("schema") != "genewhip.v02-validation-readiness.v1"
                or receipt.get("status") != "readiness-pass"
                or receipt.get("final_qualified") is not False
                or receipt.get("reason") != "postpublication-download-adoption-required"
                or receipt.get("identity") != expected
                or receipt.get("dimensions") != dimensions
                or receipt.get("dimension_count") != len(REQUIRED_DIMENSIONS)
                or not isinstance(dimensions, dict)
                or set(dimensions) != set(REQUIRED_DIMENSIONS)
                or not isinstance(closure, dict)
                or closure.get("schema") != "genewhip.v02-evidence-closure.v1"
                or closure.get("identity") != expected
                or not isinstance(closure.get("dimensions"), dict)
                or set(closure["dimensions"]) != set(REQUIRED_DIMENSIONS)
                or receipt.get("evidence_sha256") != _sha(evidence_path)
                or receipt.get("closure_sha256") != _sha(closure_path)
                or receipt.get("scope_sha256") != _sha(scope_path)):
            raise ValueError("hosted-validation-readiness-receipt-invalid")
        for name, row in dimensions.items():
            if (not isinstance(row, dict) or row.get("outcome") != "pass"
                    or any(row.get(field) != expected.get(field) for field in IDENTITY_FIELDS)):
                raise ValueError("hosted-validation-readiness-dimension-invalid")
        canonical_dimensions = json.dumps(dimensions, sort_keys=True, separators=(",", ":")).encode()
        if receipt.get("dimensions_sha256") != hashlib.sha256(canonical_dimensions).hexdigest():
            raise ValueError("hosted-validation-readiness-dimensions-digest-invalid")
        return receipt
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        raise ValueError("hosted-validation-readiness-receipt-invalid") from None


def run_package(public_evidence: pathlib.Path, out: pathlib.Path) -> dict[str, Any]:
    """Build actual clean-source archives and bind every proof dimension to retained bytes."""
    public_evidence = public_evidence.resolve(strict=True)
    out = out.resolve()
    expected = _identity()
    source = expected["source_sha"]
    runtime_identity_path = public_evidence.parent / "runtime-identity.json"
    runtime_identity = json.loads(runtime_identity_path.read_text(encoding="utf-8"))
    runtime_module = _load_runtime_module()
    route_module = runtime_module._module(ROOT / "scripts/evidence/phase6_routes.py", "gw_v02_package_routes")
    current_product_identity = runtime_module.source_identity(route_module)
    if (runtime_identity.get("source_sha256") != current_product_identity.get("source_sha256") or
            runtime_identity.get("git_head") != expected["head_sha"] or
            runtime_identity.get("base_sha") != expected["base_sha"] or
            runtime_identity.get("run_id") != expected["run_id"] or
            runtime_identity.get("run_attempt") != expected["run_attempt"]):
        raise ValueError("qualification-runtime-identity-mismatch")
    matrix_module = _load_matrix_module()
    matrix_module.verify_public_closure(public_evidence, ROOT / "evidence/v02-roster.json", runtime_identity)
    observations = json.loads((public_evidence / "observations.json").read_text(encoding="utf-8"))
    matrix_module.validate_qualification_matrix(observations)
    scope=json.loads((ROOT/"evidence/v02-execution.json").read_text(encoding="utf-8"))
    limits=scope["per_child_limits"]
    batch_start_value = os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT")
    try:
        batch_start = (datetime.datetime.fromisoformat(batch_start_value.replace("Z", "+00:00"))
            if batch_start_value else datetime.datetime.now(datetime.timezone.utc))
        now = datetime.datetime.now(datetime.timezone.utc)
        if batch_start.tzinfo is None or (now - batch_start).total_seconds() < 0:
            raise ValueError("timezone-or-future-start")
    except ValueError as error:
        raise ValueError("qualification-common-batch-start-invalid") from error
    package_deadline = batch_start + datetime.timedelta(seconds=scope["qualification_batch"]["runtime_wall_seconds"] +
        scope["qualification_batch"]["package_wall_seconds"])
    if batch_start_value and (now - batch_start).total_seconds() >= scope["qualification_batch"]["runtime_wall_seconds"]:
        raise RuntimeError("qualification-runtime-partition-deadline-exhausted")
    # Validate the exact-attempt reports and materialize the required public
    # projection before crossing either package-builder boundary.
    benchmark_reports = {}
    benchmark_documents = {}
    benchmark_root = ROOT / "build/v02/collected"
    benchmark_module = _load_benchmark_module()
    scope_path = ROOT / "evidence/v02-execution.json"
    for workload in ("control", "recursion94", "tank-battle"):
        report_path = benchmark_root / ("benchmark-" + workload) / ("benchmark-" + workload + ".json")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        errors = benchmark_module.validate_workload_report(report, workload,
            benchmark_module.source_identity(), scope["scope_id"])
        if errors or report.get("head_sha") != expected["head_sha"] or report.get("base_sha") != expected["base_sha"] or \
                report.get("run_id") != expected["run_id"] or report.get("run_attempt") != expected["run_attempt"]:
            raise ValueError("qualification-benchmark-invalid:" + workload + ":" + ",".join(errors))
        benchmark_reports[workload] = report_path
        benchmark_documents[workload] = report
    performance_projection = benchmark_module.build_public_performance_projection(
        benchmark_documents, {name: _sha(path) for name, path in benchmark_reports.items()},
        identity=expected, source_identity_sha256=benchmark_module.source_identity(),
        scope_id=scope["scope_id"], scope_sha256=_sha(scope_path))
    _write_json(public_evidence / "performance.json", performance_projection)

    def package_budget():
        remaining = min(4 * 60 * 60, int((package_deadline - datetime.datetime.now(datetime.timezone.utc)).total_seconds()))
        if remaining <= 0:
            raise RuntimeError("qualification-package-partition-deadline-exhausted")
        return remaining, {**limits, "wall_seconds": remaining}
    out.mkdir(parents=True, exist_ok=False)
    attempts=[]
    command_scratch = out.parent / "qualification-command-attempts"
    def run_package_child(command: list[str], label: str, *, cap: int | None = None) -> dict[str, Any]:
        budget, package_limits = package_budget()
        if cap is not None: budget = min(budget, cap)
        package_temp = command_scratch / (label + "-tmp")
        if package_temp.exists() or package_temp.is_symlink():
            raise RuntimeError("qualification-package-scratch-collision:" + label)
        package_temp.mkdir(parents=True)
        child_env = os.environ.copy()
        child_env["TMPDIR"] = str(package_temp)
        package_limits["wall_seconds"] = budget
        return _bounded_command(command, limits=package_limits, scratch=command_scratch,
            timeout=budget, label=label, env=child_env)
    for role in ("sdk", "desktop"):
        script = ROOT / ("scripts/package_sdk.py" if role == "sdk" else "scripts/package_desktop.py")
        command = [sys.executable, "-I", str(script), "--release-version", "0.2.0",
            "--source-sha", source, "--public-evidence", str(public_evidence), "--output-dir", str(out)]
        attempts.append(run_package_child(command, "package-" + role))
    docs = out.parent / "qualification-docs.json"
    command = [sys.executable, "-I", str(ROOT / "tests/package/docs_commands.py"),
        "--local-artifacts", str(out), "--version", "0.2.0", "--expected-source", source,
        "--require-clean-local", "--offline", "--out", str(docs)]
    attempts.append(run_package_child(command, "package-docs"))
    inventory = out.parent / "release-assets"
    command = [sys.executable, "-I", str(ROOT / "scripts/release/promote.py"), "prepare",
        "--input-dir", str(out), "--output-dir", str(inventory), "--source-sha", source,
        "--release-version", "0.2.0"]
    attempts.append(run_package_child(command, "package-inventory", cap=300))
    value = {"schema": "genewhip.v02-package-receipt.v1", "identity": expected,
        "source_sha": source, "archives": sorted(p.name for p in out.glob("*.tar.gz")),
        "performance_projection_sha256": _sha(public_evidence / "performance.json"),
        "inventory": (inventory / "inventory.json").relative_to(ROOT).as_posix(), "inventory_sha256": _sha(inventory / "inventory.json"),
        "docs_receipt": docs.relative_to(ROOT).as_posix(), "docs_sha256": _sha(docs),
        "rights_and_members_checked_by": "scripts/release/promote.py prepare --release-version 0.2.0",
        "attempts": attempts, "commands": [_public_argv(command)]}
    _write_json(out.parent / "package-receipt.json", value)
    runtime_root = public_evidence.parent / "runtime-observation"
    runtime_receipt_path = public_evidence.parent / "runtime-observation.json"
    runtime_receipt = json.loads(runtime_receipt_path.read_text(encoding="utf-8"))
    if (runtime_receipt.get("status") != "pass" or runtime_receipt.get("scope_id") != scope["scope_id"] or
            runtime_receipt.get("current_execution_identity") != runtime_identity):
        raise ValueError("qualification-runtime-observation-invalid")
    core_report_path = runtime_root / "core-report.json"
    core_report = json.loads(core_report_path.read_text(encoding="utf-8"))
    candidate_ref = core_report.get("candidate_manifest", {})
    candidate_path = pathlib.Path(candidate_ref.get("path", ""))
    if not candidate_path.is_absolute(): candidate_path = ROOT / candidate_path
    if (candidate_path.is_symlink() or not candidate_path.is_file() or
            hashlib.sha256(candidate_path.read_bytes()).hexdigest() != candidate_ref.get("sha256")):
        raise ValueError("qualification-current-candidate-manifest-invalid")
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    route_module.validate_product_report(core_report, candidate)
    media_path = runtime_root / "media-report.json"
    media_report = json.loads(media_path.read_text(encoding="utf-8"))
    route_module.validate_media_report(media_report, candidate)
    for backend in ("software", "native"):
        host_report = json.loads((runtime_root / f"host-{backend}.json").read_text(encoding="utf-8"))
        route_module.validate_host_report(host_report, candidate)
    chunk_report_path = runtime_root / "chunk.json"
    chunk_report = json.loads(chunk_report_path.read_text(encoding="utf-8"))
    if chunk_report.get("schema") != "genewhip-phase6-chunk-v1" or chunk_report.get("status") != "pass" or \
            len(chunk_report.get("routes", [])) != 2:
        raise ValueError("qualification-chunk-report-roster-invalid")
    fixture_module = runtime_module._module(ROOT / "tests/fixtures/phase6_game.py", "gw_v02_package_chunk_validator")
    chunk_fixtures = set()
    for row in chunk_report["routes"]:
        fixture = row.get("fixture")
        if fixture not in ("recursion94", "tank-battle") or fixture in chunk_fixtures or row.get("status") != "pass":
            raise ValueError("qualification-chunk-route-identity-invalid")
        chunk_fixtures.add(fixture)
        native, native_path = _read_project_json(row.get("source_run", {}).get("native_report"), "chunk-native")
        child, _ = _read_project_json(row.get("chunk_report"), "chunk-child")
        cap = 100_000_000 if fixture == "recursion94" else 10_000_000
        fixture_module._validate_title_pair_facts(child, native, cap, fixture)
        if (child.get("events") != row.get("source_run", {}).get("inputs") or
                row.get("process", {}).get("process_group_cleanup") != "confirmed" or
                row.get("process", {}).get("bound_violation")):
            raise ValueError("qualification-chunk-event-or-cleanup-invalid")
    if chunk_fixtures != {"recursion94", "tank-battle"}:
        raise ValueError("qualification-chunk-title-roster-invalid")
    measurement_summary = ROOT / "build/v02/measurements.json"
    _write_json(measurement_summary, {"schema": "genewhip-v02-measurement-summary-v1",
        "source_sha": expected["source_sha"], "head_sha": expected["head_sha"],
        "base_sha": expected["base_sha"], "run_id": expected["run_id"],
        "run_attempt": expected["run_attempt"], "workloads": {name: {
            "path": path.relative_to(ROOT).as_posix(), "sha256": _sha(path),
            "host_identity": json.loads(path.read_text(encoding="utf-8"))["host_identity"],
            "process_starts": 21} for name, path in benchmark_reports.items()}})
    hygiene_path = ROOT / "build/v02/public-hygiene.json"
    hygiene_attempt = run_package_child(["bash", "scripts/ci/public-hygiene.sh", "--self-test"],
        "public-hygiene", cap=300)
    _write_json(hygiene_path, {"schema": "genewhip-v02-public-hygiene-v1", "status": "pass",
        "identity": expected, "attempt_sha256": _sha(out.parent / "qualification-command-attempts/public-hygiene.attempt.json"),
        "stdout_sha256": hygiene_attempt["streams"]["stdout"]["sha256"]})
    dimension_sources = {
        "core": runtime_root / "core-report.json",
        "host": runtime_root / "host-software.json",
        "host-native": runtime_root / "host-native.json",
        "media": media_path,
        "safety": runtime_root / "safety.json",
        "determinism": runtime_root / "chunk.json",
        "measurements": measurement_summary,
        "public-matrix": public_evidence / "manifest.json",
        "package": out.parent / "package-receipt.json",
        "docs": docs,
        "privacy": ROOT / "build/v02/public-hygiene.json",
        "rights": inventory / "inventory.json"}
    dimensions = {}
    closure_dimensions = {}
    for name, proof_path in dimension_sources.items():
        if proof_path.is_symlink() or not proof_path.is_file():
            raise ValueError("qualification-dimension-source-missing:" + name)
        if name in ("core", "host", "host-native", "safety", "determinism"):
            report = json.loads(proof_path.read_text(encoding="utf-8"))
            outcome = (report.get("outcomes", {}).get("status") if name == "core" else
                report.get("outcome", report.get("status")))
            if outcome not in ("pass", "pass-diagnostic"):
                raise ValueError("qualification-dimension-not-pass:" + name)
            if name == "core" and (len(report.get("runs", [])) != 24 or len(report.get("stages", [])) != 120 or
                    len(report.get("media_captures", [])) < 2):
                raise ValueError("qualification-core-roster-or-media-incomplete")
            if name in ("host", "host-native") and (len(report.get("runs", [])) != 6 or
                    report.get("backend") != ("software" if name == "host" else "native")):
                raise ValueError("qualification-host-roster-incomplete:" + name)
            if name == "safety" and (len(report.get("variants", [])) != 3 or any(
                    row.get("bounded_fuzz", {}).get("denominator") != 4096 or
                    row.get("bounded_fuzz", {}).get("pass") != 4096 or
                    row.get("bounded_fuzz", {}).get("unknown") != 0 or
                    row.get("bounded_fuzz", {}).get("skipped") != 0 for row in report["variants"])):
                raise ValueError("qualification-safety-variants-or-fuzz-incomplete")
            if name == "determinism" and (len(report.get("routes", [])) != 2 or any(
                    row.get("status") != "pass" for row in report["routes"])):
                raise ValueError("qualification-chunk-route-roster-incomplete")
        if name == "media" and (json.loads(proof_path.read_text(encoding="utf-8")).get("result") != "pass"):
            raise ValueError("qualification-media-report-not-pass")
        semantic_errors = _dimension_semantic_errors(name, proof_path, expected)
        if semantic_errors:
            raise ValueError("qualification-dimension-semantic-invalid:" + ",".join(semantic_errors))
        dimension_doc = {"schema": "genewhip.v02-dimension-observation.v1", "dimension": name,
            "outcome": "pass", "evidence_path": proof_path.relative_to(ROOT).as_posix(), "evidence_sha256": _sha(proof_path),
            "identity": expected}
        observation_path = out.parent / ("dimension-" + name + ".json")
        _write_json(observation_path, dimension_doc)
        row = {"schema": "genewhip.v02-dimension-proof.v1", "dimension": name,
            "evidence_schema": dimension_doc["schema"], "outcome": "pass", **expected,
            "output": observation_path.relative_to(ROOT).as_posix(), "output_sha256": _sha(observation_path)}
        if name == "host-native": row["capability"] = "present"
        dimensions[name] = row
        closure_dimensions[name] = {"path": proof_path.relative_to(ROOT).as_posix(),
            "sha256": _sha(proof_path), "identity": expected}
    dimensions_path = ROOT / "build/v02/qualification-dimensions.json"
    _write_json(dimensions_path, dimensions)
    closure = {"schema": "genewhip.v02-evidence-closure.v1", "identity": expected,
        "dimensions": closure_dimensions, "referenced_files": _referenced_evidence_files(dimension_sources)}
    _write_json(ROOT / "build/v02/qualification-evidence-closure.json", closure)
    problems = validate_conjunction(dimensions, expected, closure)
    if problems:
        raise ValueError("qualification-dimensions-rejected:" + ",".join(problems))
    return value


def _load_benchmark_module():
    import importlib.util
    path = ROOT / "tools/evidence/core_benchmark.py"
    spec = importlib.util.spec_from_file_location("gw_v02_coordinator_benchmark", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("qualification-benchmark-validator-import")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_matrix_module():
    import importlib.util
    path = ROOT / "scripts/evidence/v02_matrix.py"
    spec = importlib.util.spec_from_file_location("gw_v02_coordinator_matrix", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("qualification-matrix-validator-import")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_runtime_module():
    import importlib.util
    path = ROOT / "scripts/evidence/v02_run.py"
    spec = importlib.util.spec_from_file_location("gw_v02_coordinator_runtime", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("qualification-runtime-validator-import")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read_project_json(reference: Any, label: str) -> tuple[dict[str, Any], pathlib.Path]:
    if not isinstance(reference, dict) or not isinstance(reference.get("path"), str):
        raise ValueError("qualification-artifact-reference-invalid:" + label)
    path = pathlib.Path(reference["path"])
    if not path.is_absolute(): path = ROOT / path
    root = ROOT.resolve()
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root) or \
            path.stat().st_size > 32 * 1024 * 1024 or _sha(path) != reference.get("sha256"):
        raise ValueError("qualification-artifact-reference-identity:" + label)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict): raise ValueError("qualification-artifact-reference-json:" + label)
    return value, path


def _semantic_mutant_receipt_error(expected: dict[str, Any]) -> str | None:
    path = ROOT / "build/v02/semantic-mutant-receipt.json"
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            return "proof-semantic-mutant-receipt-missing"
        receipt = json.loads(path.read_text(encoding="utf-8"))
        _validate_semantic_mutant_receipt(receipt, expected, ROOT)
        return None
    except ValueError as error:
        message = str(error)
        if "result-roster" in message:
            return "proof-semantic-mutant-result-roster-invalid"
        if "result-invalid" in message:
            return "proof-semantic-mutant-result-invalid"
        return "proof-semantic-mutant-receipt-invalid"
    except (OSError, TypeError, KeyError, AttributeError):
        return "proof-semantic-mutant-receipt-invalid"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True, choices=("plan", "runtime", "package", "validate", "semantic-mutants", "semantic-mutants-worker", "stage-public", "retry-source", "hosted", "close"))
    parser.add_argument("--build", type=pathlib.Path, default=ROOT / "build/phase6")
    parser.add_argument("--scope", type=pathlib.Path, default=ROOT / "evidence/v02-execution.json")
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--evidence", type=pathlib.Path)
    parser.add_argument("--public-evidence", type=pathlib.Path)
    parser.add_argument("--prepare-only", action="store_true",
                        help="prepare a sanitized local public snapshot and read-only policy packet")
    parser.add_argument("--publication-copy", type=pathlib.Path)
    parser.add_argument("--preflight", type=pathlib.Path,
                        default=ROOT / "build/v02/preflight.json",
                        help="frozen sanitized-source and policy packet used by delivery modes")
    parser.add_argument("--journal", type=pathlib.Path,
                        default=ROOT / "build/v02/hosted-delivery-journal.json",
                        help="persistent bounded delivery journal")
    parser.add_argument("--authorization", type=pathlib.Path,
                        help="previously authorized public destination packet")
    parser.add_argument("--contracts-only", action="store_true")
    parser.add_argument("--source-sha")
    parser.add_argument("--head-sha")
    parser.add_argument("--base-sha")
    parser.add_argument("--run-id")
    parser.add_argument("--run-attempt")
    args = parser.parse_args(argv)
    try:
        if args.prepare_only and args.mode != "stage-public":
            raise ValueError("prepare-only-is-only-valid-for-stage-public")
        if args.mode == "plan":
            value = qualification_plan(args.build, args.scope)
            _write_json(args.out, value)
            print(f"qualification-plan: {len(value['commands'])} concrete commands; launch_count=0")
        elif args.mode == "runtime":
            value = run_runtime(args.build, args.scope, args.out)
            print("qualification-runtime: returncode=" + str(value["returncode"]))
        elif args.mode == "semantic-mutants":
            scope_value = json.loads(args.scope.read_text(encoding="utf-8"))
            _check_environment_clock(scope_value, "package")
            expected = _selected_semantic_identity(args)
            out = args.out if args.out.is_absolute() else ROOT / args.out
            if out.is_symlink():
                raise ValueError("qualification-semantic-mutant-output-path-invalid")
            out = out.resolve()
            if not out.is_relative_to(ROOT.resolve()) or out == ROOT.resolve():
                raise ValueError("qualification-semantic-mutant-output-path-invalid")
            out.parent.mkdir(parents=True, exist_ok=True)
            command = [sys.executable, "-I", str(ROOT / "scripts/release/v02_qualification.py"),
                "--mode", "semantic-mutants-worker", "--scope", str(args.scope),
                "--out", str(out), *_semantic_identity_args(expected)]
            _external(command, timeout=900, env={"GENEWHIP_SEMANTIC_MUTANTS_WORKER": "1"},
                phase="package", owned_roots=(out.parent,))
            _check_environment_clock(scope_value, "package")
            receipt_path = out
            if receipt_path.is_symlink() or not receipt_path.is_file() or receipt_path.stat().st_size > 1024 * 1024:
                raise ValueError("qualification-semantic-mutant-receipt-missing")
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            _validate_semantic_mutant_receipt(receipt, expected)
            print("qualification-semantic-mutants: core=" + str(receipt["core"]["pass"]) +
                  "; host=" + str(receipt["host"]["pass"]) + "; launches=0")
        elif args.mode == "semantic-mutants-worker":
            if os.environ.get("GENEWHIP_SEMANTIC_MUTANTS_WORKER") != "1":
                raise ValueError("qualification-semantic-mutant-worker-admission-required")
            scope_value = json.loads(args.scope.read_text(encoding="utf-8"))
            _check_environment_clock(scope_value, "package")
            expected = _selected_semantic_identity(args)
            value = _run_semantic_mutant_suites(args.out, expected, scope_value)
            _validate_semantic_mutant_receipt(value, expected)
            _check_environment_clock(scope_value, "package")
            print("qualification-semantic-mutant-worker: core=" + str(value["core"]["pass"]) +
                  "; host=" + str(value["host"]["pass"]) + "; launches=0")
        elif args.mode == "validate":
            if args.evidence is None:
                raise ValueError("qualification-evidence-required")
            scope_value = json.loads(args.scope.read_text(encoding="utf-8"))
            _check_environment_clock(scope_value)
            expected = _identity()
            value = validate_receipt_map(args.evidence, expected)
            _check_environment_clock(scope_value)
            _write_json(args.out, _validation_readiness_receipt(value, expected,
                args.evidence, args.scope))
            print("qualification-evidence: PASS; " + str(len(value["dimensions"])) + " dimensions")
        elif args.mode == "package":
            if args.public_evidence is None:
                raise ValueError("qualification-public-evidence-required")
            value = run_package(args.public_evidence, args.out)
            print("qualification-package: " + str(len(value["archives"])) + " exact archives; inventory=" + value["inventory_sha256"])
        elif args.mode == "hosted":
            if args.publication_copy is None:
                raise ValueError("hosted-publication-copy-required")
            value = run_hosted_qualification(args.preflight, args.publication_copy,
                                             args.scope, args.out)
            print("qualification-hosted: " + value["status"] +
                  "; source=" + value["source_sha"] + "; run=" + value["run_id"] +
                  "; attempt=" + value["run_attempt"] + "; final_qualified=false")
        elif args.mode == "close":
            if args.evidence is None:
                raise ValueError("qualification-evidence-required")
            scope_value = json.loads(args.scope.read_text(encoding="utf-8"))
            _check_environment_clock(scope_value, "close")
            value = validate_receipt_map(args.evidence, _identity())
            _check_environment_clock(scope_value, "close")
            _write_json(args.out, {"schema": "genewhip.v02-final-close.v1", "status": "readiness-pass",
                "final_qualified": False, "reason": "authenticated-download-adoption-required",
                "dimensions": value["dimensions"]})
            print("qualification-close: readiness-pass; final_qualified=false")
        elif args.mode == "stage-public":
            if args.publication_copy is None:
                raise ValueError("stage-public-publication-copy-required")
            if args.prepare_only:
                value = prepare_public_snapshot(args.publication_copy, args.scope, args.out,
                                               args.authorization)
                print("public-source-preparation: " + value["status"] +
                      "; files=" + str(len(value["source_manifest"])) +
                      "; public_head=" + value["public_identity"]["head_sha"] +
                      "; base=" + value["public_identity"]["base_sha"])
                if value["status"] != "prepared":
                    return 1
            else:
                value = publish_sanitized_source(args.preflight, args.publication_copy, args.journal)
                _write_json(args.out, {"schema": "genewhip.v02-public-source-delivery.v1",
                    "status": "merged", **value})
                print("public-source-delivery: merged; public_source_sha=" + value["public_source_sha"])
        elif args.mode == "retry-source":
            if args.publication_copy is None:
                raise ValueError("stage-public-publication-copy-required")
            value = retry_sanitized_source(args.preflight, args.publication_copy, args.journal)
            _write_json(args.out, {"schema": "genewhip.v02-source-retry-transition.v1",
                "status": "prepared", **value})
            print("public-source-retry: prepared; source=" + value["source_head"] +
                  "; original_started_at=" + value["started_at"] + "; push_performed=false")
        return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError,
            subprocess.SubprocessError, RuntimeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    # Executing the production CLI declares host cleanup context. Importing
    # this module never grants admission to contract tests.
    if "--contracts-only" not in sys.argv:
        os.environ["GENEWHIP_PROCESS_CONTEXT"] = "host-cleanup-v1"
    raise SystemExit(main())

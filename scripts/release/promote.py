#!/usr/bin/env python3
"""Prepare and promote exact qualified packages through GitHub's release API.

The publisher only executes this repository-owned file from the default branch.
Downloaded artifacts are data: they are parsed, hashed and uploaded, never run.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import stat
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


API = "https://api.github.com"
API_VERSION = "2026-03-10"
MAX_RELEASE_ASSET_BYTES = 2 * 1024 * 1024 * 1024
WORKFLOW_PATH = ".github/workflows/ci.yml"
RELEASE_TAG_PREFIX = "v"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HEX_RE = re.compile(r"^[0-9a-f]{64}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
RUN_ID_RE = re.compile(r"^[0-9]+$")


class PromotionError(Exception):
    """Stable, non-secret-bearing blocker reported to the workflow log."""


def validate_provenance(statement: dict[str, Any], expected: dict[str, Any]) -> list[str]:
    """Return named blockers unless run identity, qualification and inventory match."""
    fields = (
        ("repository", "provenance-repository-mismatch"),
        ("workflow", "provenance-workflow-mismatch"),
        ("ref", "provenance-ref-mismatch"),
        ("sha", "provenance-sha-mismatch"),
        ("run_id", "provenance-run-id-mismatch"),
        ("run_attempt", "provenance-run-attempt-mismatch"),
        ("event", "provenance-event-mismatch"),
    )
    for field, reason in fields:
        if statement.get(field) != expected.get(field):
            return [reason]
    if statement.get("conclusion") != "success":
        return ["provenance-run-not-success"]
    if statement.get("qualification") != "success":
        return ["qualification-not-success"]
    actual = statement.get("assets")
    wanted = expected.get("assets")
    if not isinstance(actual, dict) or not isinstance(wanted, dict) or set(actual) != set(wanted):
        return ["inventory-incomplete"]
    if actual != wanted:
        return ["inventory-digest-mismatch"]
    return []


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _safe_name(value: str) -> bool:
    return (value not in ("", ".", "..") and pathlib.PurePosixPath(value).name == value
            and "\\" not in value and not value.startswith("."))


def expected_asset_names(inventory: dict[str, Any]) -> set[str]:
    files = inventory.get("assets")
    if not isinstance(files, dict):
        raise PromotionError("inventory-malformed")
    return set(files) | {"inventory.json", "SHA256SUMS"}


def validate_release_inventory(
    directory: pathlib.Path, inventory: dict[str, Any]
) -> tuple[dict[str, str], list[str]]:
    """Validate the complete fixed asset set and return names with SHA-256 values."""
    assets = inventory.get("assets")
    if not isinstance(assets, dict) or not assets:
        return {}, ["inventory-empty"]
    entries = list(directory.iterdir())
    if any(p.is_symlink() or not p.is_file() for p in entries):
        return {}, ["inventory-file-type-or-size-invalid"]
    actual_names = {p.name for p in entries}
    expected_names = expected_asset_names(inventory)
    if actual_names != expected_names:
        return {}, ["inventory-incomplete"]
    digests: dict[str, str] = {}
    for name, row in assets.items():
        if not isinstance(name, str) or not _safe_name(name) or not isinstance(row, dict):
            return {}, ["inventory-malformed"]
        path = directory / name
        try:
            info = path.lstat()
        except OSError:
            return {}, ["inventory-incomplete"]
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_RELEASE_ASSET_BYTES:
            return {}, ["inventory-file-type-or-size-invalid"]
        data = path.read_bytes()
        digest = sha256_bytes(data)
        if row.get("sha256") != digest or row.get("size") != len(data):
            return {}, ["inventory-digest-mismatch"]
        digests[name] = digest
    inventory_path = directory / "inventory.json"
    try:
        inventory_info = inventory_path.lstat()
    except OSError:
        return {}, ["inventory-incomplete"]
    if not stat.S_ISREG(inventory_info.st_mode) or inventory_info.st_size > 1024 * 1024:
        return {}, ["inventory-file-type-or-size-invalid"]
    inventory_data = inventory_path.read_bytes()
    if json.loads(inventory_data) != inventory:
        return {}, ["inventory-digest-mismatch"]
    digests["inventory.json"] = sha256_bytes(inventory_data)
    sums = (directory / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    parsed: dict[str, str] = {}
    for line in sums:
        digest, separator, name = line.partition("  ")
        if not separator or not HEX_RE.fullmatch(digest) or not _safe_name(name) or name in parsed:
            return {}, ["checksum-inventory-malformed"]
        parsed[name] = digest
    if parsed != digests:
        return {}, ["checksum-inventory-mismatch"]
    return digests, []


def validate_qualified_inventory(directory: pathlib.Path, inventory: dict[str, Any],
                                 source_sha: str) -> list[str]:
    """Bind both fixed package archives to their source-matched smoke receipts."""
    if inventory.get("source_revision") != source_sha or inventory.get("version") != "0.1.0":
        return ["inventory-source-mismatch"]
    prefix = f"genewhip-0.1.0-"
    suffix = f"-{source_sha[:12]}.tar.gz"
    packages = {
        "SDL-free API 4 SDK archive": f"{prefix}sdk-diagnostic-darwin-arm64{suffix}",
        "native macOS arm64 desktop archive": f"{prefix}playable-preview-macos-arm64{suffix}",
    }
    assets = inventory.get("assets")
    if not isinstance(assets, dict):
        return ["inventory-package-roster-incomplete"]
    expected_names = {
        name for archive in packages.values()
        for name in (archive, archive + ".sha256", archive + ".qualification.json")
    }
    if set(assets) != expected_names:
        return ["inventory-package-roster-incomplete"]
    members_required = {
        "SDL-free API 4 SDK archive": {"SingleStepTests-LICENSE", "THIRD-PARTY-ymfm.txt",
                                       "diagnostic-evidence.json", "metadata.json"},
        "native macOS arm64 desktop archive": {"LICENSE", "SDL3-LICENSE.txt", "THIRD-PARTY-ymfm.txt",
                                                 "phase4-evidence.json", "phase4-gameplay.json", "manifest.json"},
    }
    observed_kinds: set[str] = set()
    for kind, archive_name in packages.items():
        receipt_name = archive_name + ".qualification.json"
        checksum_name = archive_name + ".sha256"
        try:
            receipt = json.loads((directory / receipt_name).read_text(encoding="utf-8"))
            archive_bytes = (directory / archive_name).read_bytes()
            checksum = (directory / checksum_name).read_text(encoding="utf-8")
        except (OSError, json.JSONDecodeError):
            return ["inventory-package-receipt-invalid"]
        archive_digest = sha256_bytes(archive_bytes)
        if (receipt.get("schema") != "genewhip-local-package-qualification"
                or receipt.get("outcome") != "pass" or receipt.get("kind") != kind
                or receipt.get("source_revision") != source_sha
                or receipt.get("archive") != archive_name
                or receipt.get("archive_sha256") != archive_digest
                or checksum != f"{archive_digest}  {archive_name}\n"):
            return ["inventory-package-receipt-invalid"]
        row = assets.get(archive_name)
        if not isinstance(row, dict) or row.get("sha256") != archive_digest or row.get("size") != len(archive_bytes):
            return ["inventory-package-receipt-invalid"]
        try:
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as package:
                members = package.getmembers()
                if any(pathlib.PurePosixPath(member.name).is_absolute()
                       or ".." in pathlib.PurePosixPath(member.name).parts
                       or not (member.isfile() or member.isdir()) for member in members):
                    return ["inventory-package-archive-invalid"]
                present = {pathlib.PurePosixPath(member.name).name for member in members if member.isfile()}
        except (OSError, tarfile.TarError):
            return ["inventory-package-archive-invalid"]
        if not members_required[kind].issubset(present):
            return ["inventory-package-evidence-incomplete"]
        observed_kinds.add(kind)
    return [] if observed_kinds == set(packages) else ["inventory-package-roster-incomplete"]


def verify_run_event(event: dict[str, Any], expected_repo: str, source_sha: str,
                     run_id: str, attempt: int) -> tuple[dict[str, Any] | None, list[str]]:
    run = event.get("workflow_run") if isinstance(event, dict) else None
    if not isinstance(run, dict):
        return None, ["workflow-run-event-missing"]
    repo = run.get("repository")
    head_repo = run.get("head_repository")
    if not isinstance(repo, dict) or repo.get("full_name") != expected_repo:
        return None, ["provenance-repository-mismatch"]
    if not isinstance(head_repo, dict) or head_repo.get("id") != repo.get("id"):
        return None, ["provenance-fork-source"]
    if run.get("event") != "push":
        return None, ["provenance-event-mismatch"]
    if run.get("head_branch") != "main":
        return None, ["provenance-ref-mismatch"]
    if run.get("head_sha") != source_sha:
        return None, ["provenance-sha-mismatch"]
    if str(run.get("id")) != str(run_id):
        return None, ["provenance-run-id-mismatch"]
    if run.get("run_attempt") != attempt:
        return None, ["provenance-run-attempt-mismatch"]
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        return None, ["provenance-run-not-success"]
    if run.get("name") != "Required preview checks":
        return None, ["provenance-workflow-mismatch"]
    return run, []


def verify_dispatch_event(event: dict[str, Any], expected_repo: str, source_sha: str,
                         run_id: str, attempt: int) -> list[str]:
    repository = event.get("repository") if isinstance(event, dict) else None
    inputs = event.get("inputs") if isinstance(event, dict) else None
    if not isinstance(repository, dict) or repository.get("full_name") != expected_repo:
        return ["provenance-repository-mismatch"]
    if not isinstance(inputs, dict):
        return ["dispatch-inputs-missing"]
    if inputs.get("source_sha") != source_sha:
        return ["provenance-sha-mismatch"]
    if str(inputs.get("run_id")) != str(run_id):
        return ["provenance-run-id-mismatch"]
    if str(inputs.get("run_attempt")) != str(attempt):
        return ["provenance-run-attempt-mismatch"]
    return []


def validate_live_repository_policy(repository: str, repo: Any, protection: Any,
                                    active_rules: Any) -> list[str]:
    """Require current destination protections and publisher write access."""
    if not isinstance(repo, dict) or repo.get("full_name") != repository:
        return ["publication-destination-mismatch"]
    if repo.get("default_branch") != "main":
        return ["publication-default-branch-mismatch"]
    permissions = repo.get("permissions")
    if not isinstance(permissions, dict) or not (
            permissions.get("push") is True or permissions.get("admin") is True):
        return ["publication-write-permission-unavailable"]
    if not isinstance(active_rules, list):
        return ["publication-active-rules-unavailable"]
    if not isinstance(protection, dict) and not active_rules:
        return ["publication-protection-missing"]

    required_checks: set[str] = set()
    pull_request_required = False
    if isinstance(protection, dict):
        status = protection.get("required_status_checks")
        if isinstance(status, dict):
            required_checks.update(item for item in status.get("contexts", []) if isinstance(item, str))
            required_checks.update(item.get("context") for item in status.get("checks", [])
                                   if isinstance(item, dict) and isinstance(item.get("context"), str))
        reviews = protection.get("required_pull_request_reviews")
        pull_request_required = isinstance(reviews, dict)
    for rule in active_rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("parameters"), dict):
            continue
        parameters = rule["parameters"]
        if rule.get("type") == "required_status_checks":
            rows = parameters.get("required_status_checks")
            if isinstance(rows, list):
                required_checks.update(item.get("context") for item in rows
                                       if isinstance(item, dict) and isinstance(item.get("context"), str))
        elif rule.get("type") == "pull_request":
            pull_request_required = True
    problems = []
    if "required-ci" not in required_checks:
        problems.append("publication-required-ci-policy-missing")
    if not pull_request_required:
        problems.append("publication-required-pull-request-policy-missing")
    return problems


def _attestation_statement(result: Any, expected_invocation: str) -> dict[str, Any]:
    rows = result if isinstance(result, list) else [result]
    for row in rows:
        verification = row.get("verificationResult") if isinstance(row, dict) else None
        statement = verification.get("statement") if isinstance(verification, dict) else None
        if not isinstance(statement, dict):
            continue
        predicate = statement.get("predicate")
        run_details = predicate.get("runDetails") if isinstance(predicate, dict) else None
        metadata = run_details.get("metadata") if isinstance(run_details, dict) else None
        if isinstance(metadata, dict) and metadata.get("invocationId") == expected_invocation:
            return statement
    raise PromotionError("attestation-run-attempt-mismatch")


def verify_attestation(path: pathlib.Path, repository: str, source_sha: str,
                       run_id: str, attempt: int) -> dict[str, Any]:
    """Use gh's Sigstore verifier and additionally bind SLSA invocation to this attempt."""
    if not REPO_RE.fullmatch(repository) or not SHA_RE.fullmatch(source_sha):
        raise PromotionError("provenance-expected-identity-invalid")
    command = [
        "gh", "attestation", "verify", str(path), "--repo", repository,
        "--signer-workflow", f"{repository}/{WORKFLOW_PATH}",
        "--signer-digest", source_sha, "--source-ref", "refs/heads/main",
        "--source-digest", source_sha, "--cert-oidc-issuer",
        "https://token.actions.githubusercontent.com", "--format", "json",
    ]
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        raise PromotionError("attestation-verifier-unavailable") from None
    if completed.returncode:
        raise PromotionError("attestation-verification-failed")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError:
        raise PromotionError("attestation-verifier-output-invalid") from None
    invocation = f"https://github.com/{repository}/actions/runs/{run_id}/attempts/{attempt}"
    statement = _attestation_statement(result, invocation)
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise PromotionError("attestation-predicate-missing")
    return {
        "repository": repository,
        "workflow": WORKFLOW_PATH,
        "ref": "refs/heads/main",
        "sha": source_sha,
        "run_id": str(run_id),
        "run_attempt": attempt,
        "event": "push",
        "conclusion": "success",
        "qualification": "success",
        "assets": {},
        "predicate": predicate,
    }


def prepare_assets(input_dir: pathlib.Path, output_dir: pathlib.Path, source_sha: str) -> dict[str, Any]:
    """Collect exactly the two already-smoked archives and create a deterministic inventory."""
    if not SHA_RE.fullmatch(source_sha):
        raise PromotionError("source-sha-invalid")
    receipts = sorted(input_dir.glob("*.tar.gz.qualification.json"))
    selected: list[tuple[pathlib.Path, pathlib.Path, pathlib.Path, dict[str, Any]]] = []
    seen_kinds: set[str] = set()
    for receipt_path in receipts:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        if receipt.get("schema") != "genewhip-local-package-qualification" or receipt.get("outcome") != "pass":
            continue
        if receipt.get("source_revision") != source_sha:
            continue
        archive_name = receipt.get("archive")
        if not isinstance(archive_name, str) or not _safe_name(archive_name):
            raise PromotionError("package-archive-name-invalid")
        archive = input_dir / archive_name
        checksum = input_dir / (archive_name + ".sha256")
        if not archive.is_file() or not checksum.is_file():
            raise PromotionError("qualified-package-files-missing")
        data = archive.read_bytes()
        digest = sha256_bytes(data)
        if receipt.get("archive_sha256") != digest:
            raise PromotionError("package-receipt-digest-mismatch")
        if checksum.read_text(encoding="utf-8") != f"{digest}  {archive_name}\n":
            raise PromotionError("package-checksum-mismatch")
        kind = receipt.get("kind")
        if kind not in ("native macOS arm64 desktop archive", "SDL-free API 4 SDK archive"):
            continue
        if kind in seen_kinds:
            raise PromotionError("duplicate-qualified-package-kind")
        seen_kinds.add(kind)
        selected.append((archive, checksum, receipt_path, receipt))
    if seen_kinds != {"native macOS arm64 desktop archive", "SDL-free API 4 SDK archive"}:
        raise PromotionError("required-qualified-packages-missing")

    required_members = {
        "native macOS arm64 desktop archive": {"LICENSE", "SDL3-LICENSE.txt", "THIRD-PARTY-ymfm.txt",
                                                 "phase4-evidence.json", "phase4-gameplay.json", "manifest.json"},
        "SDL-free API 4 SDK archive": {"SingleStepTests-LICENSE", "THIRD-PARTY-ymfm.txt",
                                       "diagnostic-evidence.json", "metadata.json"},
    }
    for archive, _, _, receipt in selected:
        try:
            with tarfile.open(archive, "r:*") as package:
                members = {pathlib.PurePosixPath(row.name).name for row in package.getmembers() if row.isfile()}
        except (OSError, tarfile.TarError):
            raise PromotionError("qualified-package-archive-invalid") from None
        if not required_members[receipt["kind"]].issubset(members):
            raise PromotionError("package-evidence-or-notices-incomplete")

    output_dir.mkdir(parents=True, exist_ok=True)
    file_rows: dict[str, dict[str, Any]] = {}
    staged: dict[str, bytes] = {}
    version: str | None = None
    for archive, checksum, receipt_path, receipt in selected:
        for path in (archive, checksum, receipt_path):
            data = path.read_bytes()
            staged[path.name] = data
            file_rows[path.name] = {"sha256": sha256_bytes(data), "size": len(data)}
        receipt_version = "0.1.0"
        if version is not None and version != receipt_version:
            raise PromotionError("package-version-mismatch")
        version = receipt_version
    inventory = {"schema": "genewhip.release-inventory.v1", "version": version,
                 "source_revision": source_sha, "assets": dict(sorted(file_rows.items()))}
    inventory_data = _json_bytes(inventory)
    staged["inventory.json"] = inventory_data
    sums = {**{name: row["sha256"] for name, row in file_rows.items()},
            "inventory.json": sha256_bytes(inventory_data)}
    staged["SHA256SUMS"] = "".join(
        f"{digest}  {name}\n" for name, digest in sorted(sums.items())).encode()
    for existing in output_dir.iterdir():
        if not existing.is_file():
            raise PromotionError("release-assets-output-not-flat")
        if existing.name not in staged:
            raise PromotionError("release-assets-output-extra")
        if existing.read_bytes() != staged[existing.name]:
            raise PromotionError("release-assets-output-conflict")
    for name, data in staged.items():
        target = output_dir / name
        if not target.exists():
            target.write_bytes(data)
    _, blockers = validate_release_inventory(output_dir, inventory)
    if blockers:
        raise PromotionError(blockers[0])
    blockers = validate_qualified_inventory(output_dir, inventory, source_sha)
    if blockers:
        raise PromotionError(blockers[0])
    return inventory


def release_plan(release: dict[str, Any] | None, tag_sha: str | None,
                 source_sha: str, desired: dict[str, str]) -> dict[str, Any]:
    """Pure retry decision: never overwrite a conflicting name or publish a partial set."""
    if not desired:
        return {"state": "blocked", "reason": "inventory-empty", "upload": [], "publish": False}
    if tag_sha is not None and tag_sha != source_sha:
        return {"state": "blocked", "reason": "tag-source-conflict", "upload": [], "publish": False}
    if release is None:
        return {"state": "create-draft", "reason": None, "upload": sorted(desired), "publish": False}
    if release.get("tag_sha") != source_sha:
        return {"state": "blocked", "reason": "release-source-conflict", "upload": [], "publish": False}
    current_rows = release.get("assets")
    if not isinstance(current_rows, list):
        return {"state": "blocked", "reason": "release-assets-malformed", "upload": [], "publish": False}
    current: dict[str, str] = {}
    for row in current_rows:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            return {"state": "blocked", "reason": "release-assets-malformed", "upload": [], "publish": False}
        name = row["name"]
        if name in current:
            return {"state": "blocked", "reason": "release-duplicate-asset-name", "upload": [], "publish": False}
        current[name] = row.get("sha256", "")
    for name, digest in current.items():
        if name not in desired or digest != desired[name]:
            return {"state": "blocked", "reason": "release-asset-conflict", "upload": [], "publish": False}
    missing = sorted(set(desired) - set(current))
    if release.get("published"):
        if missing:
            return {"state": "blocked", "reason": "published-inventory-incomplete", "upload": [], "publish": False}
        return {"state": "no-op", "reason": None, "upload": [], "publish": False}
    return {"state": "resume-draft" if current else "stage-draft", "reason": None,
            "upload": missing, "publish": not missing}


@dataclass
class GitHub:
    token: str
    repository: str

    def _request(self, method: str, path: str, body: bytes | None = None,
                 content_type: str = "application/json", host: str = API) -> Any:
        if not self.token or not REPO_RE.fullmatch(self.repository):
            raise PromotionError("github-api-identity-unavailable")
        url = path if path.startswith("https://") else API + path
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION,
                   "User-Agent": "genewhip-release-promoter", "Authorization": "Bearer " + self.token}
        if body is not None:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                data = response.read()
                return json.loads(data.decode("utf-8")) if data else None
        except urllib.error.HTTPError as error:
            if error.code == 404:
                raise PromotionError("not-found") from None
            if error.code in (401, 403):
                raise PromotionError("permission-denied") from None
            if error.code == 422:
                raise PromotionError("request-conflict") from None
            raise PromotionError("github-api-error") from None
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            raise PromotionError("github-api-transport-error") from None

    def get(self, path: str) -> Any:
        return self._request("GET", path)

    def post(self, path: str, value: Any) -> Any:
        return self._request("POST", path, _json_bytes(value))

    def patch(self, path: str, value: Any) -> Any:
        return self._request("PATCH", path, _json_bytes(value))

    def upload(self, upload_url: str, name: str, data: bytes) -> Any:
        parsed = urllib.parse.urlsplit(upload_url.split("{", 1)[0])
        if parsed.scheme != "https" or parsed.hostname != "uploads.github.com" or parsed.username:
            raise PromotionError("release-upload-host-invalid")
        url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                                       "name=" + urllib.parse.quote(name, safe=""), ""))
        return self._request("POST", url, data, "application/octet-stream")

    def release_by_tag(self, tag: str) -> dict[str, Any] | None:
        path = f"/repos/{self.repository}/releases/tags/{urllib.parse.quote(tag, safe='')}"
        try:
            value = self.get(path)
        except PromotionError as error:
            if str(error) == "not-found":
                return None
            raise
        return value if isinstance(value, dict) else None

    def tag_commit(self, tag: str) -> str | None:
        path = f"/repos/{self.repository}/git/ref/tags/{urllib.parse.quote(tag, safe='')}"
        try:
            value = self.get(path)
        except PromotionError as error:
            if str(error) == "not-found":
                return None
            raise
        obj = value.get("object") if isinstance(value, dict) else None
        if not isinstance(obj, dict):
            raise PromotionError("tag-ref-malformed")
        if obj.get("type") == "commit":
            return obj.get("sha")
        if obj.get("type") != "tag" or not isinstance(obj.get("sha"), str):
            raise PromotionError("tag-ref-malformed")
        tag_obj = self.get(f"/repos/{self.repository}/git/tags/{obj['sha']}")
        target = tag_obj.get("object") if isinstance(tag_obj, dict) else None
        if not isinstance(target, dict) or target.get("type") != "commit":
            raise PromotionError("tag-target-not-commit")
        return target.get("sha")

    def release_assets(self, release: dict[str, Any]) -> list[dict[str, Any]]:
        rows = release.get("assets")
        if not isinstance(rows, list):
            raise PromotionError("release-assets-malformed")
        result = []
        for row in rows:
            if not isinstance(row, dict) or row.get("state") != "uploaded":
                raise PromotionError("release-asset-not-uploaded")
            digest = row.get("digest")
            if not isinstance(digest, str) or not digest.startswith("sha256:"):
                raise PromotionError("release-server-digest-unavailable")
            result.append({"name": row.get("name"), "sha256": digest[7:]})
        return result

    def verify_required_check(self, run_id: str, attempt: int) -> None:
        path = f"/repos/{self.repository}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100"
        response = self.get(path)
        rows = response.get("jobs") if isinstance(response, dict) else None
        matching = [row for row in rows or [] if isinstance(row, dict) and row.get("name") == "required-ci"]
        if len(matching) != 1 or matching[0].get("status") != "completed" or matching[0].get("conclusion") != "success":
            raise PromotionError("required-qualification-check-not-success")
        attestation = [row for row in rows or [] if isinstance(row, dict) and row.get("name") == "attestation"]
        if (len(attestation) != 1 or attestation[0].get("status") != "completed"
                or attestation[0].get("conclusion") != "success"):
            raise PromotionError("trusted-attestation-job-not-success")

    def verify_live_publication_policy(self) -> None:
        """Re-read destination policy immediately before making the release public."""
        root = f"/repos/{self.repository}"
        repo = self.get(root)
        if not isinstance(repo, dict) or repo.get("full_name") != self.repository:
            raise PromotionError("publication-destination-mismatch")
        branch = repo.get("default_branch")
        if not isinstance(branch, str) or not branch:
            raise PromotionError("publication-default-branch-unavailable")
        encoded = urllib.parse.quote(branch, safe="")
        # This endpoint returns the effective active rules for the named branch,
        # including organization rulesets, and is readable with repository metadata
        # access. Unlike the classic protection endpoint, it is usable by GITHUB_TOKEN.
        try:
            rules = self.get(f"{root}/rules/branches/{encoded}")
        except PromotionError as error:
            if str(error) == "permission-denied":
                raise PromotionError("publication-effective-rules-unavailable") from None
            raise
        try:
            protection = self.get(f"{root}/branches/{encoded}/protection")
        except PromotionError as error:
            if str(error) in ("not-found", "permission-denied"):
                # GITHUB_TOKEN cannot request Administration permission. Ignore that
                # endpoint only after the effective rules above independently prove
                # both required-ci and required review policy below.
                protection = None
            else:
                raise
        blockers = validate_live_repository_policy(self.repository, repo, protection, rules)
        if blockers:
            raise PromotionError(blockers[0])

    def ensure_tag(self, tag: str, source_sha: str) -> str:
        current = self.tag_commit(tag)
        if current is not None:
            if current != source_sha:
                raise PromotionError("tag-source-conflict")
            return current
        try:
            created = self.post(f"/repos/{self.repository}/git/refs",
                                {"ref": "refs/tags/" + tag, "sha": source_sha})
        except PromotionError:
            # POST may have reached GitHub before the connection failed; inspect once.
            current = self.tag_commit(tag)
            if current == source_sha:
                return current
            raise PromotionError("tag-create-ambiguous-or-conflicting") from None
        obj = created.get("object") if isinstance(created, dict) else None
        if not isinstance(obj, dict) or obj.get("sha") != source_sha:
            current = self.tag_commit(tag)
            if current == source_sha:
                return current
            raise PromotionError("tag-create-result-mismatch")
        return source_sha

    def create_draft(self, tag: str, version: str, source_sha: str) -> dict[str, Any]:
        try:
            value = self.post(f"/repos/{self.repository}/releases", {
                "tag_name": tag, "target_commitish": source_sha, "name": version,
                "body": "Qualified Genewhip preview artifacts; see the attached package inventory and checksums.",
                "draft": True, "prerelease": True,
            })
        except PromotionError:
            value = self.release_by_tag(tag)
            if value is None:
                raise PromotionError("draft-create-ambiguous") from None
        if not isinstance(value, dict) or not isinstance(value.get("id"), int):
            raise PromotionError("draft-create-result-invalid")
        return value

    def upload_asset(self, release: dict[str, Any], name: str, data: bytes) -> None:
        existing = self.release_assets(release)
        matches = [row for row in existing if row.get("name") == name]
        if matches:
            if len(matches) != 1 or matches[0].get("sha256") != sha256_bytes(data):
                raise PromotionError("release-asset-conflict")
            return
        upload_url = release.get("upload_url")
        if not isinstance(upload_url, str):
            raise PromotionError("release-upload-url-missing")
        try:
            self.upload(upload_url, name, data)
        except PromotionError:
            # A timed out upload may have completed. Requery by exact name and digest.
            refreshed = self.release_by_tag(str(release.get("tag_name", "")))
            if refreshed is None:
                raise PromotionError("release-upload-state-unknown") from None
            rows = self.release_assets(refreshed)
            matches = [row for row in rows if row.get("name") == name]
            if len(matches) == 1 and matches[0].get("sha256") == sha256_bytes(data):
                return
            if matches:
                raise PromotionError("release-asset-conflict") from None
            raise PromotionError("release-upload-state-unknown") from None
        refreshed = self.release_by_tag(str(release.get("tag_name", "")))
        if refreshed is None:
            raise PromotionError("release-upload-state-unknown")
        matches = [row for row in self.release_assets(refreshed) if row.get("name") == name]
        if len(matches) != 1 or matches[0].get("sha256") != sha256_bytes(data):
            raise PromotionError("release-server-digest-mismatch")


def _asset_digest_map(digests: dict[str, str]) -> dict[str, str]:
    return dict(sorted(digests.items()))


def publish(repository: str, source_sha: str, run_id: str, attempt: int,
            event_path: pathlib.Path, asset_dir: pathlib.Path, token: str) -> str:
    if (not REPO_RE.fullmatch(repository) or ".." in repository.split("/")
            or not SHA_RE.fullmatch(source_sha) or not RUN_ID_RE.fullmatch(str(run_id))
            or attempt < 1):
        raise PromotionError("expected-identity-invalid")
    event = json.loads(event_path.read_text(encoding="utf-8"))
    event_blockers = verify_dispatch_event(event, repository, source_sha, run_id, attempt)
    if event_blockers:
        raise PromotionError(event_blockers[0])
    inventory = json.loads((asset_dir / "inventory.json").read_text(encoding="utf-8"))
    if inventory.get("schema") != "genewhip.release-inventory.v1" or inventory.get("source_revision") != source_sha:
        raise PromotionError("inventory-source-mismatch")
    digests, blockers = validate_release_inventory(asset_dir, inventory)
    if blockers:
        raise PromotionError(blockers[0])
    blockers = validate_qualified_inventory(asset_dir, inventory, source_sha)
    if blockers:
        raise PromotionError(blockers[0])

    # Verify all publisher inputs, including the manifest, against GitHub's signed provenance.
    expected = {"repository": repository, "workflow": WORKFLOW_PATH, "ref": "refs/heads/main",
                "sha": source_sha, "run_id": str(run_id), "run_attempt": attempt,
                "event": "push", "assets": {}}
    for name in sorted(inventory["assets"]):
        path = asset_dir / name
        if path.suffixes[-2:] == [".tar", ".gz"] or name.endswith(".tar.gz"):
            proof = verify_attestation(path, repository, source_sha, run_id, attempt)
            statement = {**proof, "assets": {}}
            if validate_provenance(statement, expected):
                raise PromotionError("attestation-identity-mismatch")
    manifest_proof = verify_attestation(asset_dir / "inventory.json", repository, source_sha, run_id, attempt)
    if validate_provenance({**manifest_proof, "assets": {}}, expected):
        raise PromotionError("attestation-identity-mismatch")

    api = GitHub(token, repository)
    run = api.get(f"/repos/{repository}/actions/runs/{run_id}/attempts/{attempt}")
    _, run_blockers = verify_run_event({"workflow_run": run}, repository, source_sha, run_id, attempt)
    workflow_id = run.get("workflow_id") if isinstance(run, dict) else None
    if run_blockers or not isinstance(workflow_id, int):
        raise PromotionError(run_blockers[0] if run_blockers else "provenance-workflow-mismatch")
    workflow = api.get(f"/repos/{repository}/actions/workflows/{workflow_id}")
    if not isinstance(workflow, dict) or workflow.get("path") != WORKFLOW_PATH:
        raise PromotionError("provenance-workflow-mismatch")
    api.verify_required_check(run_id, attempt)
    version = inventory.get("version")
    if version != "0.1.0":
        raise PromotionError("release-version-not-allowed")
    tag = RELEASE_TAG_PREFIX + version
    api.ensure_tag(tag, source_sha)
    release = api.release_by_tag(tag)
    if release is None:
        release = api.create_draft(tag, version, source_sha)
        # Re-read after creation so later decisions use server state, not POST response order.
        release = api.release_by_tag(tag)
        if release is None:
            raise PromotionError("draft-state-unavailable")
    tag_sha = api.tag_commit(tag)
    assets = api.release_assets(release)
    decision = release_plan(release={"tag_sha": tag_sha, "assets": assets,
                                    "published": not release.get("draft", False)},
                           tag_sha=tag_sha, source_sha=source_sha,
                           desired=_asset_digest_map(digests))
    if decision["state"] == "blocked":
        raise PromotionError(decision["reason"] or "release-conflict")
    if decision["state"] == "no-op":
        return "identical-published-release-no-op"
    for name in decision["upload"]:
        api.upload_asset(release, name, (asset_dir / name).read_bytes())

    # Requery the entire set and all mutable qualification inputs immediately before visibility.
    release = api.release_by_tag(tag)
    if release is None:
        raise PromotionError("release-state-unavailable")
    tag_sha = api.tag_commit(tag)
    assets = api.release_assets(release)
    decision = release_plan(release={"tag_sha": tag_sha, "assets": assets,
                                    "published": not release.get("draft", False)},
                           tag_sha=tag_sha, source_sha=source_sha,
                           desired=_asset_digest_map(digests))
    if decision["state"] == "blocked":
        raise PromotionError(decision["reason"] or "release-conflict")
    if decision["state"] == "no-op":
        return "identical-published-release-no-op"
    if decision["upload"]:
        raise PromotionError("release-inventory-incomplete-before-publish")
    api.verify_required_check(run_id, attempt)
    if tag_sha != source_sha:
        raise PromotionError("tag-source-conflict-before-publish")
    if release.get("draft") is not True:
        raise PromotionError("release-public-state-unexpected")
    api.verify_live_publication_policy()
    try:
        api.patch(f"/repos/{repository}/releases/{release['id']}", {"draft": False})
    except PromotionError:
        observed = api.release_by_tag(tag)
        if observed and observed.get("draft") is False:
            final = release_plan(release={"tag_sha": api.tag_commit(tag),
                                          "assets": api.release_assets(observed), "published": True},
                                 tag_sha=api.tag_commit(tag), source_sha=source_sha,
                                 desired=_asset_digest_map(digests))
            if final["state"] == "no-op":
                return "published-transition-confirmed-after-ambiguous-response"
        raise PromotionError("publish-transition-state-unknown") from None
    observed = api.release_by_tag(tag)
    if not observed or observed.get("draft") is not False:
        raise PromotionError("publish-transition-not-observed")
    final = release_plan(release={"tag_sha": api.tag_commit(tag),
                                  "assets": api.release_assets(observed), "published": True},
                         tag_sha=api.tag_commit(tag), source_sha=source_sha,
                         desired=_asset_digest_map(digests))
    if final["state"] != "no-op":
        raise PromotionError("published-inventory-mismatch")
    return "published-complete-inventory"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    prepare = sub.add_parser("prepare", help="stage exact qualified local package outputs")
    prepare.add_argument("--input-dir", type=pathlib.Path, required=True)
    prepare.add_argument("--output-dir", type=pathlib.Path, required=True)
    prepare.add_argument("--source-sha", required=True)
    publish_parser = sub.add_parser("publish", help="publish a trusted workflow-dispatch artifact")
    publish_parser.add_argument("--repository", required=True)
    publish_parser.add_argument("--source-sha", required=True)
    publish_parser.add_argument("--run-id", required=True)
    publish_parser.add_argument("--run-attempt", type=int, required=True)
    publish_parser.add_argument("--event", type=pathlib.Path, required=True)
    publish_parser.add_argument("--asset-dir", type=pathlib.Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode == "prepare":
            inventory = prepare_assets(args.input_dir, args.output_dir, args.source_sha)
            print(json.dumps({"outcome": "prepared", "source_revision": args.source_sha,
                              "asset_count": len(expected_asset_names(inventory)),
                              "inventory_sha256": sha256_bytes((args.output_dir / "inventory.json").read_bytes())},
                             sort_keys=True))
            return 0
        if os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
            raise PromotionError("publisher-requires-explicit-workflow-dispatch")
        token = os.environ.get("GH_TOKEN", "")
        result = publish(args.repository, args.source_sha, args.run_id, args.run_attempt,
                         args.event, args.asset_dir, token)
        print(json.dumps({"outcome": result, "source_revision": args.source_sha,
                          "run_id": args.run_id, "run_attempt": args.run_attempt}, sort_keys=True))
        return 0
    except (PromotionError, OSError, ValueError, KeyError, json.JSONDecodeError,
            tarfile.TarError) as error:
        reason = str(error) if isinstance(error, PromotionError) else "promotion-input-invalid"
        print("REJECT: " + reason, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate the exact package artifact before trusted-main attestation."""
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.release import promote

WORKFLOW = ".github/workflows/ci.yml"
PACKAGE_TARGETS = ("sdk-diagnostic-darwin-arm64", "playable-preview-macos-arm64")
SHA = re.compile(r"^[0-9a-f]{40}$")


def identity(repository, source_sha, run_id, run_attempt, event, ref, workflow,
             qualification_started_at=None, qualification_nonce=None, base_sha=None):
    result = {"repository": repository, "source_sha": source_sha, "run_id": str(run_id),
            "run_attempt": str(run_attempt), "event": event, "ref": ref, "workflow": workflow,
            "workflow_file": WORKFLOW}
    if event == "workflow_dispatch":
        if (not isinstance(qualification_started_at, str)
                or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)", qualification_started_at)
                or not isinstance(qualification_nonce, str)
                or not re.fullmatch(r"[0-9a-f]{32}", qualification_nonce)
                or not isinstance(base_sha, str) or not SHA.fullmatch(base_sha)):
            raise ValueError("attestation-input-qualification-identity-invalid")
        result.update({"qualification_started_at": qualification_started_at,
            "qualification_nonce": qualification_nonce, "base_sha": base_sha})
    return result


def validate_inputs(directory, expected, identity_directory=None):
    """Validate artifact identity, complete fixed inventory and bytes; never execute them."""
    directory = Path(directory)
    identity_directory = Path(identity_directory) if identity_directory else directory
    try:
        actual_identity = json.loads((identity_directory / "_ci-identity.json").read_text(encoding="utf-8"))
        inventory = json.loads((directory / "inventory.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ["attestation-input-identity-or-inventory-invalid"]
    if actual_identity != expected:
        return ["attestation-input-run-identity-mismatch"]
    if (expected.get("event") not in {"push", "workflow_dispatch"}
            or expected.get("ref") != "refs/heads/main"
            or expected.get("workflow_file") != WORKFLOW or expected.get("workflow") != "Required preview checks"
            or not SHA.fullmatch(str(expected.get("source_sha", "")))
            or not str(expected.get("run_id", "")).isdigit()
            or not str(expected.get("run_attempt", "")).isdigit()):
        return ["attestation-input-not-trusted-main-event"]
    if expected.get("event") == "workflow_dispatch" and (
            not isinstance(expected.get("qualification_started_at"), str)
            or not re.fullmatch(r"[0-9a-f]{32}", str(expected.get("qualification_nonce", "")))
            or not SHA.fullmatch(str(expected.get("base_sha", "")))):
        return ["attestation-input-qualification-identity-invalid"]
    if not isinstance(inventory, dict) or inventory.get("source_revision") != expected["source_sha"]:
        return ["attestation-input-inventory-source-mismatch"]
    if inventory.get("version") == "0.2.0":
        if inventory.get("schema") != "genewhip.release-inventory.v2":
            return ["attestation-input-inventory-source-mismatch"]
        _, blockers = promote.validate_release_inventory(directory, inventory)
        if blockers:
            return ["attestation-input-inventory-invalid"]
        blockers = promote.validate_v02_inventory(directory, inventory, expected["source_sha"])
        return ["attestation-input-v02-" + blockers[0]] if blockers else []
    if (inventory.get("schema") != "genewhip.release-inventory.v1"
            or inventory.get("version") != "0.1.0"):
        return ["attestation-input-inventory-source-mismatch"]
    assets = inventory.get("assets")
    if not isinstance(assets, dict):
        return ["attestation-input-inventory-invalid"]
    suffix = "-" + expected["source_sha"][:12] + ".tar.gz"
    expected_names = {f"genewhip-0.1.0-{target}{suffix}{ending}"
                      for target in PACKAGE_TARGETS
                      for ending in ("", ".sha256", ".qualification.json")}
    if set(assets) != expected_names:
        return ["attestation-input-inventory-roster-mismatch"]
    for name, row in assets.items():
        path = directory / name
        if not isinstance(row, dict) or not path.is_file() or path.is_symlink():
            return ["attestation-input-asset-missing-or-invalid"]
        data = path.read_bytes()
        if row.get("size") != len(data) or row.get("sha256") != hashlib.sha256(data).hexdigest():
            return ["attestation-input-asset-digest-mismatch"]
    for target in PACKAGE_TARGETS:
        archive_name = f"genewhip-0.1.0-{target}{suffix}"
        archive_digest = assets[archive_name]["sha256"]
        try:
            receipt = json.loads((directory / (archive_name + ".qualification.json")).read_text(encoding="utf-8"))
            checksum = (directory / (archive_name + ".sha256")).read_text(encoding="utf-8")
        except (OSError, json.JSONDecodeError):
            return ["attestation-input-package-receipt-invalid"]
        if (receipt.get("schema") != "genewhip-local-package-qualification"
                or receipt.get("outcome") != "pass" or receipt.get("source_revision") != expected["source_sha"]
                or receipt.get("archive") != archive_name or receipt.get("archive_sha256") != archive_digest
                or checksum != f"{archive_digest}  {archive_name}\n"):
            return ["attestation-input-package-receipt-invalid"]
    return []


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    write = modes.add_parser("write-identity")
    write.add_argument("--directory", type=Path, required=True)
    check = modes.add_parser("verify")
    check.add_argument("--directory", type=Path, required=True)
    check.add_argument("--identity-directory", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.mode == "write-identity":
        value = identity(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"],
                         os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"],
                         os.environ["GITHUB_EVENT_NAME"], os.environ["GITHUB_REF"],
                         os.environ["GITHUB_WORKFLOW"],
                         qualification_started_at=os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT"),
                         qualification_nonce=os.environ.get("GENEWHIP_QUALIFICATION_NONCE"),
                         base_sha=os.environ.get("GITHUB_BASE_SHA"))
        args.directory.mkdir(parents=True, exist_ok=True)
        (args.directory / "_ci-identity.json").write_text(
            json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    expected = identity(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"],
                        os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"],
                        os.environ["GITHUB_EVENT_NAME"], os.environ["GITHUB_REF"],
                        os.environ["GITHUB_WORKFLOW"],
                        qualification_started_at=os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT"),
                        qualification_nonce=os.environ.get("GENEWHIP_QUALIFICATION_NONCE"),
                        base_sha=os.environ.get("GITHUB_BASE_SHA"))
    blockers = validate_inputs(args.directory, expected, args.identity_directory)
    if blockers:
        for blocker in blockers:
            print("REJECT: " + blocker, file=sys.stderr)
        return 1
    print("attestation-inputs: PASS (trusted main push; exact run and inventory)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

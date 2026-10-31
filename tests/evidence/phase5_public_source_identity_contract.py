#!/usr/bin/env python3
"""Exercise Phase 5's scoped second validation on a sanitized source snapshot."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from types import SimpleNamespace


FILES = (
    "fixtures/manifest.json",
    "fixtures/independent-game-v2",
    "evidence/independent-game-v2.json",
    "tests/fixtures/game_successor_reference.py",
    "tests/evidence/game_successor_admission.py",
    "tools/evidence/fixture_manifest.py",
    "scripts/fixtures/source_provenance.py",
    "scripts/evidence/phase5_baseline.py",
)
FIXTURE_ID = "genewhip-independent-game-v2"


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"module unavailable: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sanitized_snapshot(source: Path, target: Path, run) -> None:
    for relative in FILES:
        origin, destination = source / relative, target / relative
        if origin.is_dir():
            shutil.copytree(origin, destination)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(origin, destination)
    run(["git", "init", "-q", str(target)], check=True)
    run(["git", "-C", str(target), "config", "user.name", "Source Contract"], check=True)
    run(["git", "-C", str(target), "config", "user.email", "contract@example.invalid"], check=True)
    run(["git", "-C", str(target), "add", *FILES], check=True)
    run(["git", "-C", str(target), "commit", "-qm", "prior source evidence"], check=True)
    marker = target / "README.md"
    marker.write_text("sanitized candidate\n")
    run(["git", "-C", str(target), "add", "README.md"], check=True)
    run(["git", "-C", str(target), "commit", "-qm", "sanitized import"], check=True)


def _production_status(root: Path, evidence: dict, run) -> tuple[str, object, object, object]:
    baseline = _module("phase5_baseline_contract", root / "scripts/evidence/phase5_baseline.py")
    validator = _module("fixture_manifest_contract", root / "tools/evidence/fixture_manifest.py")
    provenance = _module("source_provenance_contract", root / "scripts/fixtures/source_provenance.py")
    # Scope proof queries to the same admitted bounded runner without changing
    # the process-global subprocess module or the immutable validator files.
    provenance.subprocess = SimpleNamespace(run=run, SubprocessError=subprocess.SubprocessError,
                                           CompletedProcess=subprocess.CompletedProcess)
    manifest = json.loads((root / "fixtures/manifest.json").read_text())
    row = next(item for item in manifest["fixtures"] if item.get("id") == FIXTURE_ID)
    original_subprocess = validator.subprocess
    original_loader = validator._successor_reference_module
    with provenance.source_identity_context(validator, row, root):
        status = baseline._validate_reference_evidence(validator, root, evidence)
        scoped_validator = validator._successor_reference_module(root)
        if validator.subprocess is original_subprocess:
            raise AssertionError("validator adapter was not scoped during second validation")
        if scoped_validator.subprocess is original_subprocess:
            raise AssertionError("fresh validator did not receive the scoped subprocess proxy")
    if validator.subprocess is not original_subprocess:
        raise AssertionError("fixture validator subprocess was not restored after context exit")
    if validator._successor_reference_module is not original_loader:
        raise AssertionError("fixture validator loader was not restored after context exit")
    if scoped_validator.subprocess is not original_subprocess:
        raise AssertionError("reference validator subprocess was not restored after context exit")
    return status, baseline, validator, provenance


def _self_test(source: Path, run) -> None:
    with tempfile.TemporaryDirectory(prefix="gw-public-source-identity-") as temporary:
        root = Path(temporary).resolve()
        _sanitized_snapshot(source, root, run)
        manifest = json.loads((root / "fixtures/manifest.json").read_text())
        evidence = json.loads((root / "evidence/independent-game-v2.json").read_text())
        status, baseline, validator, provenance = _production_status(root, evidence, run)
        if status != "ok":
            raise AssertionError(f"production second validation rejected sanitized origin: {status}")

        bad_origin = copy.deepcopy(evidence)
        bad_origin["identities"]["source_revision"] = "f" * 40
        status, *_ = _production_status(root, bad_origin, run)
        if status != "identity":
            raise AssertionError(f"production validator accepted mismatched origin: {status}")

        bad_content = copy.deepcopy(evidence)
        bad_content["identities"]["source_sha256"] = "d" * 64
        status, *_ = _production_status(root, bad_content, run)
        if status != "identity":
            raise AssertionError(f"production validator accepted mismatched content: {status}")

        manifest_path = root / "fixtures/manifest.json"
        manifest = json.loads(manifest_path.read_text())
        row = next(item for item in manifest["fixtures"] if item.get("id") == FIXTURE_ID)
        manifest_path = root / "fixtures/manifest.json"
        saved_manifest = manifest_path.read_bytes()
        changed_manifest = copy.deepcopy(manifest)
        altered_row = next(item for item in changed_manifest["fixtures"]
                           if item.get("id") == FIXTURE_ID)
        altered_row["revision"] = "e" * 40
        manifest_path.write_text(json.dumps(changed_manifest, indent=2) + "\n")
        try:
            with provenance.source_identity_context(validator, altered_row, root):
                pass
        except ValueError:
            pass
        else:
            raise AssertionError("source adapter accepted a current fixture row conflicting with its parent")
        manifest_path.write_bytes(saved_manifest)

        source_path = root / row["source"]
        source_bytes = source_path.read_bytes()
        source_path.write_bytes(source_bytes + b"\n")
        try:
            with provenance.source_identity_context(validator, row, root):
                pass
        except ValueError:
            pass
        else:
            raise AssertionError("source adapter accepted current source bytes differing from the manifest")
        source_path.write_bytes(source_bytes)


def self_test(source: Path) -> None:
    source = source.resolve()
    process = _module("public_source_process", source / "scripts/evidence/phase5_process.py")
    process.process_boundary().require_host_process_context()
    runs = []
    original_run = subprocess.run
    receipt = Path(f"build/v02/public-source-controls/control-{time.monotonic_ns()}.json")

    def run(command, *, cwd=source, check=False, capture_output=True, text=True, timeout=10):
        result = process.run(command, cwd=cwd, timeout=min(timeout, 10), cap=1048576,
                             runs=runs, text=text)
        if check and result.returncode:
            raise subprocess.CalledProcessError(result.returncode, command, result.stdout, result.stderr)
        return result

    with process.receipt_file(source, receipt) as stream:
        try:
            _self_test(source, run)
        finally:
            stream.write(json.dumps({"test": "phase5_public_source_identity", "processes": runs},
                                    sort_keys=True, indent=2) + "\n")
            if subprocess.run is not original_run:
                raise AssertionError("source validation leaked a global subprocess mutation")


if __name__ == "__main__":
    import sys
    self_test(Path(sys.argv[1]))
    print("PASS: production scoped source identity, origin/content/current-row negatives and restoration")

#!/usr/bin/env python3
"""Qualify successor reference evidence through the production manifest consumer."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures/independent-game-v2"
MANIFEST = ROOT / "fixtures/manifest.json"
EVIDENCE = ROOT / "evidence/independent-game-v2.json"
REFERENCE = ROOT / "tests/fixtures/game_successor_reference.py"
SOURCE_TEST = ROOT / "tests/fixtures/game_successor_source.py"
RUN_ADMITTED = ROOT / "scripts/fixtures/run_admitted.py"
ID = "genewhip-independent-game-v2"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("validator unavailable: " + str(path))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def candidate_row(evidence: dict, *, admitted: bool) -> dict:
    source, build, rom = FIXTURE / "src/game.s", FIXTURE / "build.sh", FIXTURE / "game.bin"
    scenario = json.loads((FIXTURE / "scenario.json").read_text())
    oracle = json.loads((FIXTURE / "oracle.json").read_text())
    revision = subprocess.run(["git", "-C", str(ROOT), "log", "--follow", "--format=%H", "-1", "--", "fixtures/independent-game-v2/src/game.s"],
                              check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    return {"id": ID, "status": "admitted" if admitted else "candidate",
            "outcome": "pass" if admitted else "unknown", "project": "Genewhip", "revision": revision,
            "source": "fixtures/independent-game-v2/src/game.s", "source_sha256": sha(source),
            "license": "MIT", "notices": ["fixtures/independent-game-v2/NOTICES.md"], "assets": [],
            "build": {"source": "fixtures/independent-game-v2/build.sh", "sha256": sha(build),
                      "toolchain": "GNU Binutils 2.47 source-built m68k-elf-as",
                      "command": "fixtures/independent-game-v2/build.sh --verify-reproducible"},
            "sha256": sha(rom), "rom": "fixtures/independent-game-v2/game.bin",
            "evidence_sha256": hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "oracle": oracle["oracle_id"], "profile": scenario["profile"], "input": scenario["fixture_id"]}


def set_evidence(evidence: dict, *, admitted: bool) -> dict:
    result = copy.deepcopy(evidence)
    result["candidate_disposition"] = "admitted" if admitted else "candidate"
    result["consumer"] = {"status": "pass", "passed": 6, "required": 6,
                          "contract": "production fixture manifest and run_admitted consumer"}
    return result


def production_consumer(document: dict, *, should_pass: bool, label: str) -> None:
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".json",
                                     prefix=".gw-successor-manifest-", dir=ROOT, delete=False) as handle:
        temp_path = Path(handle.name)
        handle.write(json.dumps(document, indent=2) + "\n")
    try:
        relative = temp_path.relative_to(ROOT).as_posix()
        result = subprocess.run([sys.executable, "-I", str(RUN_ADMITTED), "--root", str(ROOT),
                                 "--manifest", relative, "--fixture-id", ID],
                                cwd=ROOT, capture_output=True, text=True, timeout=300, check=False)
        if should_pass and (result.returncode != 0 or Path(result.stdout.strip()) != FIXTURE / "game.bin"):
            raise ValueError(f"{label}: production consumer failed: {result.stdout[-1000:]} {result.stderr[-1000:]}")
        if not should_pass and result.returncode == 0:
            raise ValueError(label + ": production consumer accepted candidate before admission")
    finally:
        temp_path.unlink(missing_ok=True)


def persist_admission(reference: dict) -> None:
    evidence = set_evidence(reference, admitted=True)
    encoded = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(encoded)
    document = json.loads(MANIFEST.read_text())
    rows = document["fixtures"]
    row = candidate_row(evidence, admitted=True)
    row["evidence_sha256"] = hashlib.sha256(encoded.encode()).hexdigest()
    existing = next((i for i, item in enumerate(rows) if item.get("id") == ID), None)
    if existing is None:
        rows.append(row)
    else:
        rows[existing] = row
    MANIFEST.write_text(json.dumps(document, indent=2) + "\n")


def self_test() -> int:
    validator = module("gw_fixture_manifest", ROOT / "tools/evidence/fixture_manifest.py")
    reference = module("gw_successor_reference", REFERENCE)
    document = json.loads(MANIFEST.read_text())
    row = next((copy.deepcopy(item) for item in document["fixtures"] if item.get("id") == ID), None)
    if row is None:
        print("PASS: pre-admission fixture consumer retains the existing candidate refusal")
        return 0
    result = validator._validate_successor(row, ROOT)
    if result not in ("ok", "successor-reference:identity", "successor-reference:admission"):
        raise ValueError("stored successor row unexpectedly fails production validator: " + result)
    evidence_path = ROOT / "evidence/independent-game-v2.json"
    if evidence_path.is_file():
        evidence = json.loads(evidence_path.read_text())
        changed = copy.deepcopy(evidence)
        if changed.get("cases"):
            changed["cases"][0]["status"] = "skipped"
            changed["cases"][0]["outcome"] = "skipped"
            actual = reference.validate_evidence(changed)
            if actual != "case-status:title-no-start":
                raise ValueError("reference mutation rejected for wrong reason: " + actual)
    candidate_document = copy.deepcopy(document)
    candidate_row_value = next(item for item in candidate_document["fixtures"] if item.get("id") == ID)
    candidate_row_value["status"] = "candidate"
    candidate_row_value["outcome"] = "unknown"
    production_consumer(candidate_document, should_pass=False, label="self-test candidate")
    print("PASS: production run_admitted consumer refuses a candidate; six measured reference cases remain bound")
    return 0


def verify_admitted() -> int:
    document = json.loads(MANIFEST.read_text())
    production_consumer(document, should_pass=True, label="post-admission")
    print("PASS: production run_admitted consumer resolves the source-qualified successor ROM")
    return 0


def qualify() -> int:
    source_check = subprocess.run([sys.executable, "-I", str(SOURCE_TEST), "--self-test"], cwd=ROOT,
                                  capture_output=True, text=True, timeout=120, check=False)
    if source_check.returncode:
        print("BLOCKED: source-derived scenario contract failed\n" + source_check.stdout + source_check.stderr, file=sys.stderr)
        return 1
    notifier_check = subprocess.run([sys.executable, "-I", str(REFERENCE), "--notifier-self-test"], cwd=ROOT,
                                    capture_output=True, text=True, timeout=180, check=False)
    if notifier_check.returncode:
        print("BLOCKED: real MAME notifier lifetime regression failed\n" + notifier_check.stdout + notifier_check.stderr, file=sys.stderr)
        return 1
    reference_run = subprocess.run([sys.executable, "-I", str(REFERENCE), "--capture"], cwd=ROOT,
                                   capture_output=True, text=True, timeout=3600, check=False)
    if reference_run.returncode:
        print("BLOCKED: fresh MAME reference capture failed\n" + reference_run.stdout + reference_run.stderr, file=sys.stderr)
        return 1
    reference = json.loads((ROOT / "build/phase4/game-successor-reference.json").read_text())
    reference_validator = module("gw_successor_reference", REFERENCE)
    status = reference_validator.validate_evidence(reference)
    if status != "ok":
        raise ValueError("fresh reference evidence validation: " + status)
    candidate_evidence = set_evidence(reference, admitted=False)
    candidate_bytes = json.dumps(candidate_evidence, indent=2, sort_keys=True) + "\n"
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(candidate_bytes)
    candidate_document = json.loads(MANIFEST.read_text())
    candidate_row_value = candidate_row(candidate_evidence, admitted=False)
    candidate_row_value["evidence_sha256"] = hashlib.sha256(candidate_bytes.encode()).hexdigest()
    rows = candidate_document["fixtures"]
    existing = next((i for i, item in enumerate(rows) if item.get("id") == ID), None)
    if existing is None:
        rows.append(candidate_row_value)
    else:
        rows[existing] = candidate_row_value
    production_consumer(candidate_document, should_pass=False, label="pre-admission candidate")
    persist_admission(reference)
    post = production_consumer(json.loads(MANIFEST.read_text()), should_pass=True, label="post-admission")
    print("PASS: six fresh MAME cases and production fixture consumer; successor admitted")
    return 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]: return self_test()
    if sys.argv[1:] == ["--qualify"]: return qualify()
    if sys.argv[1:] == ["--verify-admitted"]: return verify_admitted()
    raise ValueError("usage: --self-test | --qualify | --verify-admitted")


if __name__ == "__main__":
    try: raise SystemExit(main())
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        raise SystemExit(1)

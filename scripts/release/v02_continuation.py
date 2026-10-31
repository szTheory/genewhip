#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Narrow source-continuation checks for the Phase 7 Plan 16 evidence."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PHASE = Path(".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery")
PACKET_SHA = "b09dbe94769204a87ad7a84e9a37a37c81a0c3ae03f5c69fd3e3e1e415923031"
LIVE_SHA = "049c3238764803848b29d41376a299138d714331757280a73b68717e66045934"
CAMPAIGN_SHA = "f309198a4f25fee9ffb017570e0900de70c199732d9880a4f375d70bc847aad1"
RETURN_REVIEW_SHA = "7548a0038a4c91293f9f0f43de92a4d4f7eb5d3f5569ff1ad82686e2eb743f17"
ORIGINAL_RETURN_REVIEW = PHASE / "07-16-RETURN-REVIEW.md"
CONTEXT = PHASE / "07-17-CONTEXT.md"
PLAN = PHASE / "07-17-PLAN.md"
RISK_SOURCE = Path(".planning/debug/targeted-process-cleanup-source.md")
RISK_SECURITY = Path(".planning/debug/targeted-process-cleanup-security.md")
ORIGINAL_REV = "e3abf05"
COORDINATOR = "scripts/release/v02_qualification.py"
PRIVACY_FIXTURE = "tests/evidence/phase7_creation_receipts_contract.py"
PRIVACY_FIXTURE_OLD_SHA = "46abe52e863943c26464143f1d4c98a778077e3b0ffe91c17a5c45f7a94251a0"
PRIVACY_FIXTURE_CURRENT_SHA = "50d3e3f2abf12ba9b359c60eb5c3b9d1ae412b38dc585196a07df8356b85356a"
PRIVACY_SAMPLE = b"/" + b"Users" + b"/example/private-rom.bin"
RUNNER = "tests/evidence/phase7_wrapper_return.py"
PACKET = PHASE / "07-16-ADMISSION.json"
LIVE = Path("build/v02/recovery15/live.json")
CAMPAIGN = Path("build/v02/campaign15/campaign.json")
RETURN_REVIEW = PHASE / "07-16-RETURN-REVIEW.md"
ATTESTATION = PHASE / "07-17-CONTINUATION.json"
CODE_REVIEW = PHASE / "07-17-REVIEW.md"
SECURITY_REVIEW = PHASE / "07-17-SECURITY.md"
CANDIDATE_REVIEW = PHASE / "07-17-CANDIDATE-REVIEW.md"
RETURN = PHASE / "07-17-RETURN.md"
RETURN_REVIEW = PHASE / "07-17-RETURN-REVIEW.md"
CURRENT_NATIVE_CONTINUATION = PHASE / "07-10-CURRENT-SOURCE-CONTINUATION.json"
CURRENT_NATIVE_CODE_REVIEW = PHASE / "07-10-CURRENT-SOURCE-CODE-REVIEW.md"
CURRENT_NATIVE_SECURITY_REVIEW = PHASE / "07-10-CURRENT-SOURCE-SECURITY-REVIEW.md"
CURRENT_NATIVE_CANDIDATE_REVIEW = PHASE / "07-10-CURRENT-SOURCE-CANDIDATE-REVIEW.md"
CURRENT_NATIVE_RETURN = PHASE / "07-10-CURRENT-SOURCE-RETURN.md"
CURRENT_NATIVE_RETURN_REVIEW = PHASE / "07-10-CURRENT-SOURCE-RETURN-REVIEW.md"
CURRENT_NATIVE_PURPOSE = "current-native-preparation"
CURRENT_NATIVE_R3_ARCHIVE = PHASE / "history/07-10-preparation-r3"
CURRENT_RETURN_RECORD = PHASE / "07-10-CURRENT-SOURCE-RETURN.json"
CURRENT_RETURN_REPORT = PHASE / "07-10-RETURN.md"
CURRENT_RETURN_REVIEW = PHASE / "07-10-RETURN-REVIEW.md"
CURRENT_RETURN_CODE_REVIEW = PHASE / "07-10-CURRENT-RETURN-CODE-REVIEW.md"
CURRENT_RETURN_SECURITY_REVIEW = PHASE / "07-10-CURRENT-RETURN-SECURITY-REVIEW.md"
CURRENT_RETURN_CANDIDATE_CODE_REVIEW = PHASE / "07-10-CANDIDATE-R11-REVIEW.md"
CURRENT_RETURN_CANDIDATE_SECURITY_REVIEW = PHASE / "07-10-CANDIDATE-R11-SECURITY.md"
CURRENT_RETURN_PURPOSE = "current-native-return"
CURRENT_RETURN_CANDIDATE_ROOT = Path(
    "build/v02/campaign15/original10/current-source-candidate-final-r8")
R3_PREPARATION_RAW_SHA = "acf381a106bbe3daf170ba8ae7d4ac5986d1023bf6673253fa9fad9f8269ef94"
R3_PREPARATION_PAYLOAD_SHA = "2f3f492d497a2d624ddeadb583e403fad0a5e6d163e31964dce5028722457fbd"
R8_PACKET = Path("build/v02/campaign15/original10/native-source-revalidation-r8/review-packet.json")
R8_PACKET_SHA = "7360e82be98334d31349b5b678ef21166cda0e37e241e6eb1c9d04ca55bf3545"
R8_RESULT = Path("build/v02/campaign15/original10/native-contract-856650313767500/native-contract-run.json")
R8_RESULT_SHA = "518ac190cdefce7198521e80f38d110d8ce6290be6095c36c7038f932bd0d01d"
R8_ATTEMPT = Path("build/v02/campaign15/original10/native-contract-856650313767500/attempts/native-contract-suite.attempt.json")
R8_ATTEMPT_SHA = "905c926741e94d137fd4137d095bfa565056c1051a3ab99dddeaada05cf8f6e5"
R8_NESTED = Path("build/v02/process-admission-controls/nested-parent-856652957004916.json")
R8_NESTED_SHA = "fcf702917207424e181974e2446d8fec057ffbb889f0044095f7d7a665682bd1"
R8_RESULT_REVIEW = PHASE / "07-10-NATIVE-RESULT-R8.md"
R8_RESULT_REVIEW_SHA = "8626155a75edf0e0c6bfbda76c03c619037248a5d4a07e7b1b46296cb4c2fac0"
R8_ADMISSION_REVIEW = PHASE / "07-10-NATIVE-ADMISSION-R8.md"
R8_ADMISSION_REVIEW_SHA = "0f597cc1dc3b66219fdd98b29f01d6df8b08f00df97ee4964aa7b86861488a60"
R8_SOURCE_SNAPSHOT = Path("build/v02/campaign15/original10/native-source-revalidation-r8/source")
R8_NATIVE_SOURCE_PATHS = (
    "scripts/evidence/phase4_report.py", "scripts/evidence/phase5_process.py",
    "scripts/release/v02_continuation.py", "scripts/release/v02_qualification.py",
    "tests/desktop/phase4_sessions.py", "tests/evidence/phase4_report_contract.py",
    "tests/evidence/phase7_darwin_status_contract.py",
    "tests/evidence/phase7_nested_cancellation_contract.py",
    "tests/evidence/phase7_rss_contract.py", "tests/evidence/v02_qualification_contract.py",
    "tests/session/phase6_route_contract.py")
R8_DARWIN_TEST_PATH = "tests/session/phase6_route_contract.py"
R8_DARWIN_TEST_METHOD = "test_darwin_group_liveness_distinguishes_zombies"
R8_DARWIN_TEST_OLD_AST_SHA = "e0f1ced1e88870f92c0fcbd7355f9ed2906e9d0623c2adab71b0f98cd24616bd"
R8_DARWIN_TEST_CURRENT_AST_SHA = "43da5c9f57ec549d6337620923f612d34d1d44954d14b12b5748376115d56ab0"
R8_NATIVE_RUNS = {
    "run": R8_RESULT, "attempt": R8_ATTEMPT, "nested": R8_NESTED}
R8_COORDINATOR_DELTA_FUNCTIONS = ("_campaign_projection", "_require_campaign_for_journal",
    "publish_sanitized_source", "retry_sanitized_source", "_retry_sanitized_source_bound",
    "run_hosted_qualification", "main")
R8_CONTINUATION_DELTA_FUNCTIONS = (
    "_current_native_record_payload", "_top_level_assignment_names",
    "_validate_r8_current_source_delta", "build_current_native_continuation",
    "validate_current_native_continuation", "_validate_r3_preparation_record",
    "_validate_current_native_preparation_record", "_current_return_candidate_facts", "_current_native_return_payload",
    "_write_exclusive_json", "build_current_native_return",
    "_validate_current_return_candidate_review", "validate_current_native_return")
R8_CONTINUATION_DELTA_ASSIGNMENTS = (
    "CURRENT_NATIVE_CONTINUATION", "CURRENT_NATIVE_CODE_REVIEW",
    "CURRENT_NATIVE_SECURITY_REVIEW", "CURRENT_NATIVE_CANDIDATE_REVIEW",
    "CURRENT_NATIVE_RETURN", "CURRENT_NATIVE_RETURN_REVIEW", "CURRENT_NATIVE_PURPOSE",
    "CURRENT_NATIVE_R3_ARCHIVE",
    "CURRENT_RETURN_RECORD", "CURRENT_RETURN_REPORT", "CURRENT_RETURN_REVIEW",
    "CURRENT_RETURN_CODE_REVIEW", "CURRENT_RETURN_SECURITY_REVIEW",
    "CURRENT_RETURN_CANDIDATE_CODE_REVIEW", "CURRENT_RETURN_CANDIDATE_SECURITY_REVIEW",
    "CURRENT_RETURN_PURPOSE", "CURRENT_RETURN_CANDIDATE_ROOT", "R3_PREPARATION_RAW_SHA",
    "R3_PREPARATION_PAYLOAD_SHA",
    "R8_PACKET", "R8_PACKET_SHA", "R8_RESULT", "R8_RESULT_SHA", "R8_ATTEMPT",
    "R8_ATTEMPT_SHA", "R8_NESTED", "R8_NESTED_SHA", "R8_RESULT_REVIEW",
    "R8_RESULT_REVIEW_SHA", "R8_ADMISSION_REVIEW", "R8_ADMISSION_REVIEW_SHA",
    "R8_SOURCE_SNAPSHOT", "R8_NATIVE_SOURCE_PATHS", "R8_NATIVE_RUNS",
    "R8_COORDINATOR_DELTA_FUNCTIONS", "R8_CONTINUATION_DELTA_FUNCTIONS",
    "R8_CONTINUATION_DELTA_ASSIGNMENTS", "R8_DARWIN_TEST_PATH",
    "R8_DARWIN_TEST_METHOD", "R8_DARWIN_TEST_OLD_AST_SHA",
    "R8_DARWIN_TEST_CURRENT_AST_SHA")
RETAINED_DUTIES = {
    "original10": [
        "repair public-export mismatch and refresh affected source/candidate/privacy proofs",
        "fresh sanitized public candidate with exact source, base, ancestry, notices, rights, privacy and policy",
        "independent code/security fixes before protected PR; immediate exact head/base check; green protected merge",
        "full exact-public-source hosted qualification with actual roster, routes, causal and original controls, native/software/media/safety/determinism",
        "correctness, memory and timer evidence plus 60 timed and 3 reference measurements",
        "external public-source closure",
        "actual packages and extracted offline, native/software play, build, embed, error and recovery commands",
        "immutable eight-asset staged inventory joined to source, workflow, run, attempt and attestation",
        "real nested cancellation/control contract roster after accepted current17 return, under same campaign limits",
    ],
    "original11": [
        "protected v0.2.0 prerelease promotes exact staged tested bytes without rebuild or protection bypass",
        "actual provenance, source, workflow, ref, event, run, attempt, inventory and subject joins; preserve immutable v0.1 history",
        "fresh exact downloads in a separate owned location; authenticate provenance and subject digests before bundled tools or extraction",
        "reopen archive members, rights, privacy, portable full roster and link closure",
        "exercise extracted SDK C/C++, offline diagnostics, desktop controls and both-title software/native paths",
        "verify quoted play, build, embed, error and recovery commands",
        "external asset-bound adoption and final conjunction remain outside immutable payloads",
        "published-but-failed remains failed; never overwrite assets; physical output, whole-game and unmeasured platform claims remain unknown",
        "final verifier earns all five outcomes from actual facts",
    ],
}
RETAINED_PLANS = {
    "original10": Path(".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-10-PLAN.md"),
    "original11": Path(".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-11-PLAN.md"),
}


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha(path: Path) -> str:
    return sha_bytes(path.read_bytes())


def _regular(path: Path, *, cap: int = 1024 * 1024) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("continuation-file-missing-or-link")
    info = path.lstat()
    if info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size > cap:
        raise ValueError("continuation-file-bounds-invalid")
    return path.read_bytes()


def _json_object(data: bytes, code: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(code)
            result[key] = value
        return result
    try:
        value = json.loads(data, object_pairs_hook=unique,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError(code)))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
        raise ValueError(code) from None
    if not isinstance(value, dict):
        raise ValueError(code)
    return value


def _load_module(root: Path, relative: str, name: str):
    spec = importlib.util.spec_from_file_location(name, root / relative)
    if spec is None or spec.loader is None:
        raise ValueError("continuation-original-source-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_original_snapshot(repo: Path = ROOT) -> tuple[tempfile.TemporaryDirectory[str], Path, dict[str, Any]]:
    """Copy pinned original Git blobs and bounded evidence inputs into an isolated tree."""
    packet_bytes = _regular(repo / PACKET, cap=65536)
    if sha_bytes(packet_bytes) != PACKET_SHA:
        raise ValueError("continuation-original-packet-stale")
    packet = _json_object(packet_bytes, "continuation-original-packet-invalid")
    pins = packet.get("sources")
    if not isinstance(pins, dict) or len(pins) != 17:
        raise ValueError("continuation-original-source-roster-invalid")
    temporary = tempfile.TemporaryDirectory(prefix="gw17-original-proof-")
    snapshot = Path(temporary.name).resolve()
    total = 0
    try:
        for relative, expected in sorted(pins.items()):
            if (not isinstance(relative, str) or Path(relative).is_absolute()
                    or ".." in Path(relative).parts
                    or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected)):
                raise ValueError("continuation-original-source-pin-invalid")
            result = subprocess.run(["git", "show", f"{ORIGINAL_REV}:{relative}"],
                cwd=repo, capture_output=True, timeout=15, check=False)
            if result.returncode or len(result.stdout) > 1024 * 1024 or sha_bytes(result.stdout) != expected:
                raise ValueError("continuation-original-source-blob-invalid:" + relative)
            total += len(result.stdout)
            target = snapshot / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(result.stdout)
        # The raw evidence is data, not an executable/build tree. Copy only the
        # bounded campaign inputs and receipt roots consumed by the frozen oracle.
        input_paths = [PACKET, PHASE / "07-16-REVIEW.md", PHASE / "07-16-SECURITY.md",
            PHASE / "07-16-PROTOCOL.md", PHASE / "07-16-AUTHORIZATION.md",
            PHASE / "07-16-SUPERSESSION.md", ORIGINAL_RETURN_REVIEW,
            PHASE / "07-15-ADMISSION.json", PHASE / "07-15-PROTOCOL.md",
            PHASE / "07-15-RETURN.md", PHASE / "07-15-SUMMARY.md",
            PHASE / "history/07-15-before-supersession.md",
            Path("evidence/v02-execution.json"), CAMPAIGN,
            Path("build/v02/campaign15/attempt2-started.json"),
            Path("build/v02/campaign15/attempt3-started.json"),
            Path("build/v02/campaign15/attempt4-started.json")]
        input_paths.extend(path.relative_to(repo) for path in sorted((repo / PHASE).glob("07-15-*"))
                           if path.is_file())
        input_paths.extend(path.relative_to(repo) for path in sorted((repo / PHASE).glob("07-16-*"))
                           if path.is_file())
        input_paths.extend([Path("build/v02/recovery15-attempt1"),
                            Path("build/v02/recovery15-attempt2"), LIVE.parent])
        for source in input_paths:
            src = repo / source
            if src.is_symlink():
                raise ValueError("continuation-original-input-link")
            if src.is_dir():
                for file in sorted(src.rglob("*")):
                    if file.is_symlink():
                        raise ValueError("continuation-original-input-link")
                    if file.is_file():
                        data = _regular(file, cap=65536)
                        total += len(data)
                        if total > 16 * 1024 * 1024:
                            raise ValueError("continuation-original-input-budget-exceeded")
                        target = snapshot / file.relative_to(repo)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(data)
            else:
                data = _regular(src, cap=1024 * 1024)
                total += len(data)
                if total > 16 * 1024 * 1024:
                    raise ValueError("continuation-original-input-budget-exceeded")
                target = snapshot / source
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        return temporary, snapshot, packet
    except BaseException:
        temporary.cleanup()
        raise


def verify_original_snapshot(snapshot: Path, packet: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run the original frozen semantic verifier against authenticated temp copies."""
    packet_data = _regular(snapshot / PACKET, cap=65536)
    if sha_bytes(packet_data) != PACKET_SHA:
        raise ValueError("continuation-original-packet-stale")
    trusted_packet = _json_object(packet_data, "continuation-original-packet-invalid")
    if packet is not None and packet != trusted_packet:
        raise ValueError("continuation-original-packet-conflict")
    for relative, expected in trusted_packet.get("sources", {}).items():
        if sha_bytes(_regular(snapshot / relative, cap=1024 * 1024)) != expected:
            raise ValueError("continuation-original-source-snapshot-invalid:" + relative)
    if sha(snapshot / LIVE) != LIVE_SHA or sha(snapshot / CAMPAIGN) != CAMPAIGN_SHA:
        raise ValueError("continuation-original-live-or-campaign-stale")
    review = _regular(snapshot / ORIGINAL_RETURN_REVIEW, cap=1024 * 1024)
    if sha_bytes(review) != RETURN_REVIEW_SHA:
        raise ValueError("continuation-original-case-review-stale")
    review_text = review.decode("utf-8")
    required = ("The complete Plan16 return is not accepted.",
                "The actual case results are `shared_launch` pass and `bounded_command` pass;",
                "No live invocation was repeated.")
    if any(text not in review_text for text in required):
        raise ValueError("continuation-original-case-subclaim-invalid")
    runner = _load_module(snapshot, RUNNER, "gw17_trusted_original_runner")
    if runner.verify_live(snapshot / LIVE) != 0:
        raise ValueError("continuation-original-semantic-verifier-failed")
    live = _json_object(_regular(snapshot / LIVE, cap=65536), "continuation-original-live-invalid")
    if ([row.get("case") for row in live.get("cases", [])]
            != ["shared_launch", "bounded_command"]
            or any(row.get("status") != "pass" or row.get("returncode") != 0
                or row.get("owner_settled") is not True or row.get("leaf_settled") is not True
                for row in live.get("cases", []))
            or live.get("attempt_number") != 4 or live.get("status") != "pass"
            or live.get("historical_identity_liveness") != "UNKNOWN"
            or live.get("historical_T-07-07") != "OPEN/high"
            or live.get("requirements_qualified") != []):
        raise ValueError("continuation-original-live-claims-invalid")
    return {"status": "accepted-original-scope", "packet_sha256": PACKET_SHA,
        "live_sha256": LIVE_SHA, "campaign_sha256": CAMPAIGN_SHA,
        "return_review_sha256": RETURN_REVIEW_SHA, "cases": [
            {"case": row["case"], "status": row["status"], "returncode": row["returncode"],
             "owner_settled": row["owner_settled"], "leaf_settled": row["leaf_settled"]}
            for row in live["cases"]], "full_plan16_return": "blocked",
        "historical_identity_liveness": "UNKNOWN", "historical_T-07-07": "OPEN/high"}


def _source_map(root: Path, packet: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    old = packet.get("sources")
    if not isinstance(old, dict) or len(old) != 17:
        raise ValueError("continuation-source-map-invalid")
    current: dict[str, str] = {}
    changed: list[str] = []
    for relative, expected in sorted(old.items()):
        candidate = root / relative
        actual = sha_bytes(_regular(candidate, cap=2 * 1024 * 1024))
        current[relative] = actual
        if actual != expected:
            changed.append(relative)
    if changed != [COORDINATOR, PRIVACY_FIXTURE]:
        raise ValueError("continuation-unexpected-original-source-delta")
    if (old.get(PRIVACY_FIXTURE) != PRIVACY_FIXTURE_OLD_SHA
            or current[PRIVACY_FIXTURE] != PRIVACY_FIXTURE_CURRENT_SHA):
        raise ValueError("continuation-privacy-fixture-delta-invalid")
    return current, changed


def _module_pin(root: Path) -> str:
    """Bind the dynamically imported continuation gate itself to the payload."""
    return sha_bytes(_regular(root / "scripts/release/v02_continuation.py", cap=2 * 1024 * 1024))


def _attestation_shape(payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    tests = payload.get("current_tests")
    original_proof = payload.get("original_proof")
    source_delta_records = payload.get("source_delta_records")
    if (not isinstance(tests, dict) or not isinstance(original_proof, dict)
            or not isinstance(source_delta_records, dict)
            or set(source_delta_records) != {PRIVACY_FIXTURE}
            or not isinstance(source_delta_records.get(PRIVACY_FIXTURE), dict)):
        raise ValueError("continuation-record-shape-invalid")
    return tests, original_proof, source_delta_records


def build_attestation(root: Path = ROOT, output: Path | None = None) -> dict[str, Any]:
    temp, snapshot, packet = make_original_snapshot(root)
    try:
        original = verify_original_snapshot(snapshot, packet)
    finally:
        temp.cleanup()
    current_sources, changed = _source_map(root, packet)
    test_paths = ["tests/evidence/phase7_continuation_contract.py",
        "tests/evidence/phase7_return_consumer_contract.py"]
    current_tests = {path: sha_bytes(_regular(root / path, cap=2 * 1024 * 1024)) for path in test_paths}
    old_coordinator = subprocess.run(["git", "show", f"{ORIGINAL_REV}:{COORDINATOR}"],
        cwd=root, capture_output=True, timeout=15, check=True).stdout
    new_coordinator = _regular(root / COORDINATOR, cap=2 * 1024 * 1024)
    old_fixture = subprocess.run(["git", "show", f"{ORIGINAL_REV}:{PRIVACY_FIXTURE}"],
        cwd=root, capture_output=True, timeout=15, check=True).stdout
    new_fixture = _regular(root / PRIVACY_FIXTURE, cap=2 * 1024 * 1024)
    payload = {"schema": "genewhip.phase7-source-continuation.v1", "status": "candidate",
        "phase": "GW-07", "plan": "17", "original_revision": ORIGINAL_REV,
        "original_packet": PACKET.as_posix(), "original_packet_sha256": PACKET_SHA,
        "original_source_pins": packet["sources"], "original_proof": original,
        "original_live_path": LIVE.as_posix(), "original_campaign_path": CAMPAIGN.as_posix(),
        "campaign_started_at": "2026-10-30T16:50:39.837827+00:00",
        "runtime_cutoff": "2026-10-31T10:50:39.837827+00:00",
        "package_cutoff": "2026-10-31T14:50:39.837827+00:00",
        "global_cutoff": "2026-10-31T16:50:39.837827+00:00",
        "limits": {"total": 86400, "runtime": 64800, "package": 14400, "close": 7200,
                   "additional_diagnostics": 0},
        "current_source_pins": current_sources, "changed_original_source_paths": changed,
        "continuation_module_sha256": _module_pin(root),
        "retained_duties": RETAINED_DUTIES,
        "retained_plan_sha256": {key: sha_bytes(_regular(root / path, cap=2 * 1024 * 1024))
                                 for key, path in RETAINED_PLANS.items()},
        "coordinator_old_sha256": sha_bytes(old_coordinator),
        "coordinator_current_sha256": sha_bytes(new_coordinator),
        "coordinator_delta_sha256": sha_bytes(old_coordinator + b"\0" + new_coordinator),
        "current_tests": current_tests,
        "unchanged_claims": ["actual launch topology", "receipt schema", "cleanup/status/RSS logic",
            "per-child and campaign limits", "fixture identities", "scope identities"],
        "source_delta_records": {PRIVACY_FIXTURE: {
            "original_sha256": sha_bytes(old_fixture),
            "current_sha256": sha_bytes(new_fixture),
            "original_source_sha256": PRIVACY_FIXTURE_OLD_SHA,
            "current_source_sha256": PRIVACY_FIXTURE_CURRENT_SHA,
            "change": "test-only: construct the same private-path classifier input without embedding an absolute-path literal",
            "semantic_input_sha256": sha_bytes(PRIVACY_SAMPLE)}},
        "current_source_claims": ["owner prelaunch coordinator import/projection",
            "public privacy classifier receives the same test-only private-path value",
            "explicit selector17 propagation", "canonical current17 review and return gates"],
        "not_claimed": ["native execution of current17 source", "historical process settlement",
            "product requirement completion", "hosted qualification or publication"],
        "review_paths": {"code": CODE_REVIEW.as_posix(), "security": SECURITY_REVIEW.as_posix(),
                         "candidate": CANDIDATE_REVIEW.as_posix()},
        "context_sha256": sha_bytes(_regular(root / CONTEXT, cap=2 * 1024 * 1024)),
        "plan_sha256": sha_bytes(_regular(root / PLAN, cap=2 * 1024 * 1024)),
        "current_risk_evidence_sha256": {
            "source": sha_bytes(_regular(root / RISK_SOURCE, cap=2 * 1024 * 1024)),
            "security": sha_bytes(_regular(root / RISK_SECURITY, cap=2 * 1024 * 1024))}}
    if output is not None:
        destination = output if output.is_absolute() else root / output
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return payload


def validate_attestation(root: Path, path: Path, *, require_reviews: bool = True,
                         require_candidate: bool = False, require_return: bool = False) -> dict[str, Any]:
    expected = root / ATTESTATION
    candidate = path if path.is_absolute() else root / path
    if candidate.resolve() != expected.resolve() or candidate.is_symlink():
        raise ValueError("continuation-path-invalid")
    payload = _json_object(_regular(candidate, cap=2 * 1024 * 1024), "continuation-record-invalid")
    if (payload.get("schema") != "genewhip.phase7-source-continuation.v1"
            or payload.get("status") != "candidate" or payload.get("phase") != "GW-07"
            or payload.get("plan") != "17" or payload.get("original_revision") != ORIGINAL_REV
            or payload.get("original_packet_sha256") != PACKET_SHA
            or payload.get("original_live_path") != LIVE.as_posix()
            or payload.get("original_campaign_path") != CAMPAIGN.as_posix()
            or payload.get("campaign_started_at") != "2026-10-30T16:50:39.837827+00:00"
            or payload.get("runtime_cutoff") != "2026-10-31T10:50:39.837827+00:00"
            or payload.get("package_cutoff") != "2026-10-31T14:50:39.837827+00:00"
            or payload.get("global_cutoff") != "2026-10-31T16:50:39.837827+00:00"
            or payload.get("limits") != {"total": 86400, "runtime": 64800,
                "package": 14400, "close": 7200, "additional_diagnostics": 0}
            or payload.get("changed_original_source_paths") != [COORDINATOR, PRIVACY_FIXTURE]):
        raise ValueError("continuation-record-identity-invalid")
    packet = _json_object(_regular(root / PACKET, cap=65536), "continuation-original-packet-invalid")
    if sha(root / PACKET) != PACKET_SHA or payload.get("original_source_pins") != packet.get("sources"):
        raise ValueError("continuation-original-packet-stale")
    tests, original_proof, source_delta_records = _attestation_shape(payload)
    current, changed = _source_map(root, packet)
    if changed != [COORDINATOR, PRIVACY_FIXTURE] or payload.get("current_source_pins") != current:
        raise ValueError("continuation-current-source-stale")
    fixture_record = source_delta_records[PRIVACY_FIXTURE]
    if (fixture_record != {"original_sha256": packet["sources"][PRIVACY_FIXTURE],
            "current_sha256": current[PRIVACY_FIXTURE],
            "original_source_sha256": PRIVACY_FIXTURE_OLD_SHA,
            "current_source_sha256": PRIVACY_FIXTURE_CURRENT_SHA,
            "change": "test-only: construct the same private-path classifier input without embedding an absolute-path literal",
            "semantic_input_sha256": sha_bytes(PRIVACY_SAMPLE)}):
        raise ValueError("continuation-privacy-fixture-delta-invalid")
    if payload.get("continuation_module_sha256") != _module_pin(root):
        raise ValueError("continuation-module-stale")
    expected_plan_pins = {key: sha_bytes(_regular(root / plan, cap=2 * 1024 * 1024))
                          for key, plan in RETAINED_PLANS.items()}
    if (payload.get("retained_duties") != RETAINED_DUTIES
            or payload.get("retained_plan_sha256") != expected_plan_pins):
        raise ValueError("continuation-duty-transfer-stale")
    if (payload.get("context_sha256") != sha_bytes(_regular(root / CONTEXT, cap=2 * 1024 * 1024))
            or payload.get("plan_sha256") != sha_bytes(_regular(root / PLAN, cap=2 * 1024 * 1024))):
        raise ValueError("continuation-plan-context-stale")
    expected_risk = {"source": sha_bytes(_regular(root / RISK_SOURCE, cap=2 * 1024 * 1024)),
        "security": sha_bytes(_regular(root / RISK_SECURITY, cap=2 * 1024 * 1024))}
    if payload.get("current_risk_evidence_sha256") != expected_risk:
        raise ValueError("continuation-current-risk-evidence-stale")
    for path_name, digest in tests.items():
        if path_name not in ("tests/evidence/phase7_continuation_contract.py",
                "tests/evidence/phase7_return_consumer_contract.py") or sha(root / path_name) != digest:
            raise ValueError("continuation-current-test-stale")
    if len(tests) != 2 or any(not isinstance(name, str) or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            for name, digest in tests.items()):
        raise ValueError("continuation-current-test-roster-invalid")
    if original_proof.get("status") != "accepted-original-scope":
        raise ValueError("continuation-original-proof-not-accepted")
    temp, snapshot, trusted_packet = make_original_snapshot(root)
    try:
        reopened = verify_original_snapshot(snapshot, trusted_packet)
    finally:
        temp.cleanup()
    if original_proof != reopened:
        raise ValueError("continuation-original-proof-stale")
    if require_reviews:
        _validate_independent_report(root / CODE_REVIEW, payload, role="gsd-code-reviewer",
            model="gpt-6-luna", count_key="unresolved high/critical")
        _validate_independent_report(root / SECURITY_REVIEW, payload, role="gsd-security-auditor",
            model="gpt-6.1-sol", count_key="unresolved current high/critical")
    if require_candidate:
        _validate_candidate(root, root / CANDIDATE_REVIEW, payload)
    if require_return:
        _validate_return(root, payload)
    return payload


def _top_level_assignment_names(node: Any) -> set[str]:
    import ast
    if not isinstance(node, (ast.Assign, ast.AnnAssign)):
        return set()
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return {target.id for target in targets if isinstance(target, ast.Name)}


def _validate_r8_current_source_delta(root: Path, native_source_pins: dict[str, str],
        current_source_pins: dict[str, str]) -> dict[str, Any]:
    """Prove current source differs from R8 only in reviewed prelaunch gates."""
    import ast
    unchanged: list[str] = []
    changed: list[str] = []
    baseline_bytes: dict[str, bytes] = {}
    for relative in R8_NATIVE_SOURCE_PATHS:
        baseline = _regular(root / R8_SOURCE_SNAPSHOT / relative, cap=2 * 1024 * 1024)
        if sha_bytes(baseline) != native_source_pins.get(relative):
            raise ValueError("current-native-r8-source-snapshot-stale:" + relative)
        current = _regular(root / relative, cap=2 * 1024 * 1024)
        if sha_bytes(current) != current_source_pins.get(relative):
            raise ValueError("current-native-source-pin-conflict:" + relative)
        baseline_bytes[relative] = baseline
        (unchanged if baseline == current else changed).append(relative)
    expected_changed = ["scripts/release/v02_continuation.py",
        "scripts/release/v02_qualification.py", R8_DARWIN_TEST_PATH]
    if changed != expected_changed:
        raise ValueError("current-native-unreviewed-source-delta")

    def functions(data: bytes) -> dict[str, str]:
        tree = ast.parse(data.decode("utf-8"))
        result: dict[str, str] = {}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name in result:
                    raise ValueError("current-native-duplicate-source-function")
                result[node.name] = ast.dump(node, include_attributes=False)
        return result

    def module_shell(data: bytes, skip_assignments: set[str]) -> list[str]:
        tree = ast.parse(data.decode("utf-8"))
        shell = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if _top_level_assignment_names(node) and _top_level_assignment_names(node) <= skip_assignments:
                continue
            shell.append(ast.dump(node, include_attributes=False))
        return shell

    delta: dict[str, Any] = {"unchanged_runtime_source_paths": unchanged}
    for relative, allowed_changed, allowed_added, allowed_assignments in (
            ("scripts/release/v02_qualification.py", set(R8_COORDINATOR_DELTA_FUNCTIONS),
                set(), set()),
            ("scripts/release/v02_continuation.py", {"main"},
                set(R8_CONTINUATION_DELTA_FUNCTIONS), set(R8_CONTINUATION_DELTA_ASSIGNMENTS)),
            (R8_DARWIN_TEST_PATH, set(), set(), set())):
        baseline = baseline_bytes[relative]
        current = _regular(root / relative, cap=2 * 1024 * 1024)
        old_functions, new_functions = functions(baseline), functions(current)
        changed_functions = {name for name in old_functions.keys() & new_functions.keys()
            if old_functions[name] != new_functions[name]}
        added_functions = set(new_functions) - set(old_functions)
        missing_functions = set(old_functions) - set(new_functions)
        if (changed_functions != allowed_changed or added_functions != allowed_added
                or missing_functions):
            raise ValueError("current-native-unreviewed-function-delta:" + relative)
        if relative.endswith("v02_qualification.py"):
            import copy
            def normalize_return_forwarding(function: Any) -> Any:
                node = copy.deepcopy(function)
                args = node.args
                if args.kwonlyargs and args.kwonlyargs[-1].arg == "continuation_purpose":
                    if (len(args.kw_defaults) != len(args.kwonlyargs)
                            or not isinstance(args.kw_defaults[-1], ast.Constant)
                            or args.kw_defaults[-1].value != "original17"):
                        raise ValueError("current-native-return-purpose-default-invalid")
                    args.kwonlyargs.pop()
                    args.kw_defaults.pop()
                elif node.name == "run_hosted_qualification" and args.args[-1].arg == "continuation_purpose":
                    if not isinstance(args.defaults[-1], ast.Constant) or args.defaults[-1].value != "original17":
                        raise ValueError("current-native-return-purpose-default-invalid")
                    args.args.pop()
                    args.defaults.pop()
                class RemovePurposeForwarding(ast.NodeTransformer):
                    def visit_Call(self, call: Any) -> Any:
                        self.generic_visit(call)
                        target = call.func.id if isinstance(call.func, ast.Name) else None
                        allowed_targets = {"_require_campaign_for_journal", "publish_sanitized_source", "_campaign_projection"}
                        if target in allowed_targets:
                            purpose = [kw for kw in call.keywords if kw.arg == "continuation_purpose"]
                            if purpose:
                                if (len(purpose) != 1 or not isinstance(purpose[0].value, ast.Name)
                                        or purpose[0].value.id != "continuation_purpose"):
                                    raise ValueError("current-native-return-purpose-forwarding-invalid")
                                call.keywords = [kw for kw in call.keywords if kw.arg != "continuation_purpose"]
                        return call
                return RemovePurposeForwarding().visit(node)
            effectful_forwarders = {"publish_sanitized_source", "retry_sanitized_source",
                "run_hosted_qualification"}
            old_nodes = {node.name: node for node in ast.parse(baseline.decode("utf-8")).body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
            new_nodes = {node.name: node for node in ast.parse(current.decode("utf-8")).body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
            if "_retry_sanitized_source_bound" in changed_functions:
                old_archive_assignment = ast.parse(
                    "archive_dir = journal_path.parent / 'failures'\n"
                    "archive_root = ROOT / 'build/v02/failures'").body
                new_archive_assignment = ast.parse(
                    "archive_root = ROOT / 'build/v02/failures'\n"
                    "archive_dir = archive_root").body
                canonical_archive_assignment = copy.deepcopy(new_archive_assignment)

                def normalize_retry_archive_assignment(function: Any,
                        expected: list[Any]) -> str:
                    node = copy.deepcopy(function)
                    positions = [index for index, statement in enumerate(node.body)
                        if _top_level_assignment_names(statement) & {"archive_dir", "archive_root"}]
                    if (len(positions) != 2 or positions[1] != positions[0] + 1
                            or any(ast.dump(node.body[position], include_attributes=False)
                                != ast.dump(expected[offset], include_attributes=False)
                                for offset, position in enumerate(positions))):
                        raise ValueError("current-native-retry-archive-assignment-invalid")
                    node.body[positions[0]:positions[1] + 1] = copy.deepcopy(
                        canonical_archive_assignment)
                    return ast.dump(node, include_attributes=False)

                if (normalize_retry_archive_assignment(old_nodes["_retry_sanitized_source_bound"],
                        old_archive_assignment)
                        != normalize_retry_archive_assignment(new_nodes["_retry_sanitized_source_bound"],
                            new_archive_assignment)):
                    raise ValueError("current-native-retry-archive-helper-body-changed")
            for name in effectful_forwarders & changed_functions:
                if (ast.dump(old_nodes[name], include_attributes=False)
                        != ast.dump(normalize_return_forwarding(new_nodes[name]), include_attributes=False)):
                    raise ValueError("current-native-effectful-function-body-changed:" + name)
        if relative.endswith("v02_continuation.py"):
            old_tree = ast.parse(baseline.decode("utf-8"))
            new_tree = ast.parse(current.decode("utf-8"))
            old_assignments = set().union(*(_top_level_assignment_names(node) for node in old_tree.body))
            new_assignments = set().union(*(_top_level_assignment_names(node) for node in new_tree.body))
            if new_assignments - old_assignments != allowed_assignments:
                raise ValueError("current-native-unreviewed-constant-delta")
        test_method_delta = None
        if relative == R8_DARWIN_TEST_PATH:
            import copy
            old_tree = ast.parse(baseline.decode("utf-8"))
            new_tree = ast.parse(current.decode("utf-8"))

            def target_method(tree: Any) -> Any:
                classes = [node for node in tree.body
                    if isinstance(node, ast.ClassDef) and node.name == "NativeParserContract"]
                if len(classes) != 1:
                    raise ValueError("current-native-darwin-test-class-invalid")
                methods = [node for node in classes[0].body
                    if isinstance(node, ast.FunctionDef) and node.name == R8_DARWIN_TEST_METHOD]
                if len(methods) != 1:
                    raise ValueError("current-native-darwin-test-method-invalid")
                return methods[0]

            old_method, new_method = target_method(old_tree), target_method(new_tree)
            old_method_sha = sha_bytes(ast.dump(old_method, include_attributes=False).encode("utf-8"))
            new_method_sha = sha_bytes(ast.dump(new_method, include_attributes=False).encode("utf-8"))
            if old_method_sha != R8_DARWIN_TEST_OLD_AST_SHA:
                raise ValueError("current-native-darwin-baseline-method-stale")
            if new_method_sha != R8_DARWIN_TEST_CURRENT_AST_SHA:
                raise ValueError("current-native-darwin-test-method-unreviewed")
            normalized = copy.deepcopy(new_tree)
            target_method(normalized).__dict__.update(copy.deepcopy(old_method).__dict__)
            if ast.dump(normalized, include_attributes=False) != ast.dump(old_tree, include_attributes=False):
                raise ValueError("current-native-darwin-file-changed-outside-test-method")
            test_method_delta = {"class": "NativeParserContract", "method": R8_DARWIN_TEST_METHOD,
                "r8_ast_sha256": old_method_sha, "current_ast_sha256": new_method_sha,
                "only_fixture_delta": True}
        elif module_shell(current, allowed_assignments) != module_shell(baseline, set()):
            raise ValueError("current-native-unreviewed-module-delta:" + relative)
        delta[relative] = {"r8_source_sha256": native_source_pins[relative],
            "current_source_sha256": current_source_pins[relative],
            "changed_functions": sorted(changed_functions),
            "added_functions": sorted(added_functions),
            **({"test_method_delta": test_method_delta} if test_method_delta is not None else {}),
            "prelaunch_only_review_boundary": True}
    return delta


def _current_native_record_payload(root: Path) -> dict[str, Any]:
    """Build the narrow current-native preparation record from retained R8 facts."""
    packet_bytes = _regular(root / R8_PACKET, cap=1024 * 1024)
    if sha_bytes(packet_bytes) != R8_PACKET_SHA:
        raise ValueError("current-native-r8-packet-stale")
    packet = _json_object(packet_bytes, "current-native-r8-packet-invalid")
    result_data = _regular(root / R8_RESULT, cap=1024 * 1024)
    attempt_data = _regular(root / R8_ATTEMPT, cap=1024 * 1024)
    nested_data = _regular(root / R8_NESTED, cap=1024 * 1024)
    result = _json_object(result_data, "current-native-result-invalid")
    attempt = _json_object(attempt_data, "current-native-attempt-invalid")
    nested = _json_object(nested_data, "current-native-nested-invalid")
    admission_data = _regular(root / R8_ADMISSION_REVIEW, cap=1024 * 1024)
    result_review_data = _regular(root / R8_RESULT_REVIEW, cap=1024 * 1024)
    campaign = packet.get("campaign")
    source_pins = packet.get("source_pins")
    historical_17_pins = packet.get("historical_17_pins")
    command_result = result.get("command_result")
    processes = command_result.get("processes") if isinstance(command_result, dict) else None
    process = processes[0] if isinstance(processes, list) and len(processes) == 1 else None
    streams = command_result.get("streams") if isinstance(command_result, dict) else None
    stderr_stream = streams.get("stderr") if isinstance(streams, dict) else None
    if (sha_bytes(admission_data) != R8_ADMISSION_REVIEW_SHA
            or sha_bytes(result_review_data) != R8_RESULT_REVIEW_SHA
            or not isinstance(campaign, dict) or not isinstance(source_pins, dict)
            or set(source_pins) != set(R8_NATIVE_SOURCE_PATHS)
            or not isinstance(historical_17_pins, dict) or len(historical_17_pins) != 5
            or packet.get("purpose") != "original10-native-source-revalidation-only"
            or packet.get("product_qualification_claim") is not False
            or packet.get("qualification_status") != "current-native-validation-pending"
            or campaign.get("sha256") != CAMPAIGN_SHA
            or campaign.get("started_at") != "2026-10-30T16:50:39.837827+00:00"
            or result.get("purpose") != packet.get("purpose")
            or result.get("qualification_status") != packet.get("qualification_status")
            or result.get("product_qualification_claim") is not False
            or result.get("source_pins") != source_pins
            or result.get("historical_17_pins") != historical_17_pins
            or result.get("entry_sha256") != packet.get("entry_sha256")
            or result.get("continuation_sha256") != packet.get("continuation_sha256")
            or result.get("campaign") != campaign
            or result.get("command_complete") is not True or result.get("returncode") != 0
            or result.get("attempt_read_error") is not None
            or result.get("process_group_cleanup") != "confirmed"
            or result.get("rss_observation_error") is not None
            or result.get("attempt_path") != R8_ATTEMPT.as_posix()
            or result.get("attempt_sha256") != R8_ATTEMPT_SHA
            or attempt.get("argv") != packet.get("child_argv")
            or attempt.get("returncode") != 0 or attempt.get("process_group_cleanup") != "confirmed"
            or attempt.get("scratch_tree_diagnostics") is None
            or len(attempt.get("scratch_tree_diagnostics")) > 8
            or nested.get("cleanup_qualified") is not True):
        raise ValueError("current-native-r8-facts-invalid")
    if (sha_bytes(result_data) != R8_RESULT_SHA or sha_bytes(attempt_data) != R8_ATTEMPT_SHA
            or sha_bytes(nested_data) != R8_NESTED_SHA):
        raise ValueError("current-native-r8-retained-evidence-stale")
    if (not isinstance(process, dict) or command_result.get("returncode") != 0
            or command_result.get("process_group_cleanup") != "confirmed"
            or process.get("rss_bytes_peak", 0) <= 0
            or process.get("bound_violation") is not False
            or not isinstance(stderr_stream, dict) or stderr_stream.get("truncated") is not False
            or "Ran 51 tests" not in attempt.get("stderr_tail", "")
            or "OK" not in attempt.get("stderr_tail", "")):
        raise ValueError("current-native-r8-run-not-accepted")
    current_sources = {relative: sha_bytes(_regular(root / relative, cap=2 * 1024 * 1024))
        for relative in R8_NATIVE_SOURCE_PATHS}
    source_delta = _validate_r8_current_source_delta(root, source_pins, current_sources)
    for relative, expected in historical_17_pins.items():
        if not isinstance(relative, str) or sha_bytes(_regular(root / relative, cap=2 * 1024 * 1024)) != expected:
            raise ValueError("current-native-historical17-input-stale")
    plan_path = RETAINED_PLANS["original10"]
    return {
        "schema": "genewhip.phase7-original10-current-native-continuation.v1",
        "status": "candidate", "phase": "GW-07", "plan": "10",
        "purpose": CURRENT_NATIVE_PURPOSE,
        "qualification_status": "current-native-preparation-only",
        "campaign": campaign,
        "native_review_artifacts": {
            "admission_path": R8_ADMISSION_REVIEW.as_posix(),
            "admission_sha256": R8_ADMISSION_REVIEW_SHA,
            "result_review_path": R8_RESULT_REVIEW.as_posix(),
            "result_review_sha256": R8_RESULT_REVIEW_SHA},
        "native_evidence": {
            "packet_path": R8_PACKET.as_posix(), "packet_sha256": R8_PACKET_SHA,
            "entry_path": packet["entry"], "entry_sha256": packet["entry_sha256"],
            "run_path": R8_RESULT.as_posix(), "run_sha256": R8_RESULT_SHA,
            "attempt_path": R8_ATTEMPT.as_posix(), "attempt_sha256": R8_ATTEMPT_SHA,
            "nested_path": R8_NESTED.as_posix(), "nested_sha256": R8_NESTED_SHA,
            "native_source_pins": source_pins,
            "native_runtime_claim": "R8 native runtime only; not this continuation validator"},
        "historical_17_pins": historical_17_pins,
        "current_source_pins": current_sources,
        "current_source_delta_from_r8": source_delta,
        "current_tests": {relative: sha_bytes(_regular(root / relative, cap=2 * 1024 * 1024))
            for relative in ("tests/evidence/v02_qualification_contract.py",
                "tests/evidence/phase7_continuation_contract.py",
                "tests/evidence/phase7_return_consumer_contract.py",
                "tests/evidence/phase7_sticky_denial.py")},
        "continuation_module_sha256": _module_pin(root),
        "current_risk_evidence_sha256": {
            "source": sha_bytes(_regular(root / RISK_SOURCE, cap=2 * 1024 * 1024)),
            "security": sha_bytes(_regular(root / RISK_SECURITY, cap=2 * 1024 * 1024))},
        "retained_plan_sha256": sha_bytes(_regular(root / plan_path, cap=2 * 1024 * 1024)),
        "allowed_effect": "stage-public --prepare-only candidate generation only",
        "candidate_review_path": CURRENT_NATIVE_CANDIDATE_REVIEW.as_posix(),
        "current_return_path": CURRENT_NATIVE_RETURN.as_posix(),
        "review_paths": {"code": CURRENT_NATIVE_CODE_REVIEW.as_posix(),
            "security": CURRENT_NATIVE_SECURITY_REVIEW.as_posix()},
        "not_claimed": ["native execution of the current continuation validator",
            "fresh current-source product return", "hosted qualification",
            "publication or protected PR", "guest play or packaged artifacts"]}


def build_current_native_continuation(root: Path = ROOT,
        output: Path | None = None) -> dict[str, Any]:
    payload = _current_native_record_payload(root)
    expected = root / CURRENT_NATIVE_CONTINUATION
    destination = expected if output is None else (output if output.is_absolute() else root / output)
    expected = Path(os.path.abspath(expected))
    destination = Path(os.path.abspath(destination))
    if destination != expected:
        raise ValueError("current-native-output-path-invalid")
    try:
        relative = destination.relative_to(root.resolve())
    except ValueError:
        raise ValueError("current-native-output-path-invalid") from None
    cursor = root.resolve()
    for part in relative.parts[:-1]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("current-native-output-parent-invalid")
    if destination.exists() or destination.is_symlink():
        raise ValueError("current-native-output-already-exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")
    try:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise ValueError("current-native-output-already-exists") from None
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    directory_fd = os.open(destination.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return payload


def validate_current_native_continuation(root: Path, path: Path, *,
        require_reviews: bool = True) -> dict[str, Any]:
    expected_path = root / CURRENT_NATIVE_CONTINUATION
    candidate = path if path.is_absolute() else root / path
    if candidate.resolve() != expected_path.resolve() or candidate.is_symlink():
        raise ValueError("current-native-continuation-path-invalid")
    payload = _json_object(_regular(candidate, cap=2 * 1024 * 1024),
        "current-native-continuation-invalid")
    if payload != _current_native_record_payload(root):
        raise ValueError("current-native-continuation-stale")
    if require_reviews:
        _validate_independent_report(root / CURRENT_NATIVE_CODE_REVIEW, payload,
            role="gsd-code-reviewer", model="gpt-6-luna", count_key="unresolved high/critical")
        _validate_independent_report(root / CURRENT_NATIVE_SECURITY_REVIEW, payload,
            role="gsd-security-auditor", model="gpt-6.1-sol",
            count_key="unresolved current high/critical")
    return payload


def _validate_r3_preparation_record(root: Path) -> dict[str, Any]:
    record_relative = CURRENT_NATIVE_R3_ARCHIVE / CURRENT_NATIVE_CONTINUATION.name
    code_relative = CURRENT_NATIVE_R3_ARCHIVE / CURRENT_NATIVE_CODE_REVIEW.name
    security_relative = CURRENT_NATIVE_R3_ARCHIVE / CURRENT_NATIVE_SECURITY_REVIEW.name
    raw = _regular(root / record_relative, cap=2 * 1024 * 1024)
    if sha_bytes(raw) != R3_PREPARATION_RAW_SHA:
        raise ValueError("current-return-r3-preparation-record-stale")
    payload = _json_object(raw, "current-return-r3-preparation-record-invalid")
    if (sha_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
            != R3_PREPARATION_PAYLOAD_SHA
            or payload.get("schema") != "genewhip.phase7-original10-current-native-continuation.v1"
            or payload.get("purpose") != CURRENT_NATIVE_PURPOSE
            or payload.get("qualification_status") != "current-native-preparation-only"
            or payload.get("product_qualification_claim") not in (None, False)):
        raise ValueError("current-return-r3-preparation-record-invalid")
    code_review = root / code_relative
    security_review = root / security_relative
    _validate_independent_report(code_review, payload, role="gsd-code-reviewer",
        model="gpt-6-luna", count_key="unresolved high/critical")
    _validate_independent_report(security_review, payload, role="gsd-security-auditor",
        model="gpt-6.1-sol", count_key="unresolved current high/critical")
    return {"record_path": record_relative.as_posix(),
        "record_sha256": R3_PREPARATION_RAW_SHA,
        "payload_sha256": R3_PREPARATION_PAYLOAD_SHA,
        "code_review_path": code_relative.as_posix(),
        "code_review_sha256": sha(code_review),
        "security_review_path": security_relative.as_posix(),
        "security_review_sha256": sha(security_review),
        "status": "accepted-historical-preparation-r3"}


def _validate_current_native_preparation_record(root: Path,
        source_payload: dict[str, Any]) -> dict[str, Any]:
    raw = _regular(root / CURRENT_NATIVE_CONTINUATION, cap=2 * 1024 * 1024)
    payload = _json_object(raw, "current-native-preparation-record-invalid")
    if (payload != source_payload
            or payload.get("schema") != "genewhip.phase7-original10-current-native-continuation.v1"
            or payload.get("purpose") != CURRENT_NATIVE_PURPOSE
            or payload.get("qualification_status") != "current-native-preparation-only"):
        raise ValueError("current-native-preparation-record-stale")
    code_review = root / CURRENT_NATIVE_CODE_REVIEW
    security_review = root / CURRENT_NATIVE_SECURITY_REVIEW
    _validate_independent_report(code_review, payload, role="gsd-code-reviewer",
        model="gpt-6-luna", count_key="unresolved high/critical")
    _validate_independent_report(security_review, payload, role="gsd-security-auditor",
        model="gpt-6.1-sol", count_key="unresolved current high/critical")
    return {"record_path": CURRENT_NATIVE_CONTINUATION.as_posix(),
        "record_sha256": sha_bytes(raw),
        "payload_sha256": sha_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()),
        "code_review_path": CURRENT_NATIVE_CODE_REVIEW.as_posix(),
        "code_review_sha256": sha(code_review),
        "security_review_path": CURRENT_NATIVE_SECURITY_REVIEW.as_posix(),
        "security_review_sha256": sha(security_review),
        "status": "accepted-current-preparation"}


def _current_return_candidate_facts(root: Path,
        source_payload: dict[str, Any]) -> dict[str, Any]:
    candidate_root = root / CURRENT_RETURN_CANDIDATE_ROOT
    preparation_relative = (CURRENT_RETURN_CANDIDATE_ROOT / "preparation.json").as_posix()
    preparation_path = _candidate_path(root, preparation_relative)
    preparation_bytes = _regular(preparation_path, cap=4 * 1024 * 1024)
    preparation_sha = sha_bytes(preparation_bytes)
    preparation = _json_object(preparation_bytes, "current-return-candidate-preparation-invalid")
    publication_relative = (CURRENT_RETURN_CANDIDATE_ROOT / "publication").as_posix()
    policy_relative = preparation.get("repository_preflight")
    if (not isinstance(policy_relative, str)
            or not re.fullmatch(re.escape(CURRENT_RETURN_CANDIDATE_ROOT.as_posix())
                + r"/repository-preflight-[A-Za-z0-9_-]+/policy\.json", policy_relative)
            or preparation.get("publication_copy") != publication_relative):
        raise ValueError("current-return-candidate-path-invalid")
    policy_path = _candidate_path(root, policy_relative)
    policy_bytes = _regular(policy_path, cap=4 * 1024 * 1024)
    policy_sha = sha_bytes(policy_bytes)
    policy = _json_object(policy_bytes, "current-return-candidate-policy-invalid")
    candidate = _candidate_path(root, publication_relative)
    identity = preparation.get("public_identity")
    source_identity = preparation.get("source_identity")
    manifest = preparation.get("source_manifest")
    privacy = preparation.get("privacy")
    repository = _authorized_repository(root)
    if (not isinstance(identity, dict) or not isinstance(source_identity, dict)
            or not isinstance(manifest, list) or not manifest or len(manifest) > 5000
            or not isinstance(privacy, dict)):
        raise ValueError("current-return-candidate-shape-invalid")
    head, base, tree = identity.get("head_sha"), identity.get("base_sha"), identity.get("tree_sha")
    if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value)
            for value in (head, base, tree)):
        raise ValueError("current-return-candidate-identity-invalid")
    manifest_sha = sha_bytes(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())
    if (preparation.get("schema") != "genewhip.v02-public-source-preflight.v1"
            or preparation.get("status") != "prepared" or preparation.get("blockers") != []
            or preparation.get("repository") != repository
            or preparation.get("mutations_performed") != 0 or preparation.get("push_performed") is not False
            or preparation.get("pull_request_opened") is not False
            or preparation.get("workflow_dispatched") is not False
            or preparation.get("requirements_qualified") != []
            or preparation.get("source_manifest_sha256") != manifest_sha
            or source_identity.get("source_manifest_sha256") != manifest_sha
            or not re.fullmatch(r"[0-9a-f]{40}", str(source_identity.get("private_git_head", "")))
            or source_identity.get("private_git_head") != _candidate_git(root, "rev-parse", "HEAD")
            or identity.get("parent_shas") != [base]
            or preparation.get("repository_preflight") != policy_relative
            or privacy.get("status") != "pass" or privacy.get("current_findings") != []
            or privacy.get("history_findings") != []):
        raise ValueError("current-return-candidate-preparation-invalid")
    manifest_paths: list[str] = []
    total_bytes = 0
    manifest_by_path: dict[str, dict[str, Any]] = {}
    for row in manifest:
        if not isinstance(row, dict) or set(row) != {"path", "size_bytes", "sha256"}:
            raise ValueError("current-return-candidate-manifest-invalid")
        relative = row.get("path")
        if (not isinstance(relative, str) or not relative or "\\" in relative or "\x00" in relative
                or Path(relative).is_absolute() or Path(relative).as_posix() != relative
                or ".." in Path(relative).parts or relative in manifest_by_path
                or any(relative.startswith(prefix) for prefix in (".planning/", "build/", "artifacts/"))
                or relative.startswith(".env")
                or not isinstance(row.get("size_bytes"), int) or isinstance(row.get("size_bytes"), bool)
                or row["size_bytes"] < 0 or not isinstance(row.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])):
            raise ValueError("current-return-candidate-manifest-invalid")
        manifest_paths.append(relative)
        manifest_by_path[relative] = row
        candidate_file = _candidate_path(root, publication_relative + "/" + relative)
        info = candidate_file.lstat()
        total_bytes += info.st_size
        if (info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size > 32 * 1024 * 1024
                or total_bytes > 200 * 1024 * 1024 or info.st_size != row["size_bytes"]
                or sha(candidate_file) != row["sha256"]):
            raise ValueError("current-return-candidate-file-stale-or-unbounded")
    if manifest_paths != sorted(manifest_paths) or "LICENSE" not in manifest_by_path:
        raise ValueError("current-return-candidate-manifest-invalid")
    required_sources = {**source_payload["current_source_pins"], **source_payload["current_tests"],
        "scripts/ci/public_hygiene.py": sha(root / "scripts/ci/public_hygiene.py")}
    for relative, digest in required_sources.items():
        row = manifest_by_path.get(relative)
        if row is None or row.get("sha256") != digest:
            raise ValueError("current-return-candidate-source-stale:" + relative)
    git_identity = {"head": _candidate_git(candidate, "rev-parse", "HEAD"),
        "base": _candidate_git(candidate, "rev-parse", "HEAD^"),
        "tree": _candidate_git(candidate, "rev-parse", "HEAD^{tree}"),
        "branch": _candidate_git(candidate, "symbolic-ref", "--short", "HEAD"),
        "remote": _candidate_git(candidate, "remote", "get-url", "origin"),
        "parents": _candidate_git(candidate, "show", "-s", "--format=%P", "HEAD").split(),
        "refs": _candidate_git(candidate, "for-each-ref", "--format=%(refname)").splitlines(),
        "paths": [item for item in _candidate_git(candidate, "ls-files", "-z").split("\0") if item],
        "status": _candidate_git(candidate, "status", "--porcelain", "--untracked-files=all")}
    owner, name = repository.split("/", 1)
    if (git_identity["head"] != head or git_identity["base"] != base or git_identity["tree"] != tree
            or git_identity["branch"] != "main" or git_identity["remote"] != f"https://github.com/{owner}/{name}.git"
            or git_identity["parents"] != [base]
            or set(git_identity["refs"]) != {"refs/heads/main", "refs/remotes/origin/HEAD", "refs/remotes/origin/main"}
            or git_identity["paths"] != manifest_paths or git_identity["status"]):
        raise ValueError("current-return-candidate-git-identity-invalid")
    findings, history = _candidate_privacy(root, candidate, manifest_paths)
    if (not isinstance(findings, list) or findings or not isinstance(history, dict)
            or not isinstance(history.get("findings"), list) or history["findings"]):
        raise ValueError("current-return-candidate-privacy-invalid")
    observations = policy.get("repository_observations")
    policy_privacy = policy.get("privacy_scan")
    privacy_copy = policy_privacy.get("publication_copy") if isinstance(policy_privacy, dict) else None
    if (policy.get("schema") != "genewhip.publication-readiness-packet.v1"
            or policy.get("repository") != repository
            or policy.get("history_disposition") != "sanitized-snapshots-preserve-local-history"
            or policy.get("hosted_evidence") != {"outcome": "not_run", "qualifies_rel_03": False}
            or policy.get("destination") != {"owner_repository": repository, "visibility": "public"}
            or policy.get("expected_identity") != {"head": head, "base": base}
            or policy.get("mutations_performed") != 0
            or not isinstance(observations, dict) or observations.get("ready") is not True
            or observations.get("blockers") != []
            or not isinstance(observations.get("observations"), dict)
            or not isinstance(privacy_copy, dict)
            or privacy_copy.get("status") != "pass" or privacy_copy.get("current_findings") != []
            or privacy_copy.get("findings") != []):
        raise ValueError("current-return-candidate-policy-invalid")
    observed = observations["observations"]
    protection = observed.get("branch_protection")
    if (observed.get("visibility") != "public" or observed.get("default_branch") != "main"
            or observed.get("auto_merge_enabled") is not True
            or observed.get("caller_write_permission") != "write"
            or not isinstance(protection, dict) or protection.get("pull_request_required") is not True
            or "required-ci" not in protection.get("required_status_checks", [])):
        raise ValueError("current-return-candidate-policy-invalid")
    return {"preparation_path": preparation_relative, "preparation_sha256": preparation_sha,
        "publication_path": publication_relative, "repository_policy_path": policy_relative,
        "repository_policy_sha256": policy_sha, "repository": repository,
        "private_source_head": source_identity["private_git_head"],
        "public_head": head, "public_base": base, "public_tree": tree,
        "source_manifest_sha256": manifest_sha, "tracked_file_count": len(manifest),
        "privacy_status": "pass", "current_findings": 0, "history_findings": 0,
        "hosted_evidence": "not_run", "mutations_performed": 0,
        "push_performed": False, "pull_request_opened": False, "workflow_dispatched": False}


def _current_native_return_payload(root: Path) -> dict[str, Any]:
    preparation_history = _validate_r3_preparation_record(root)
    source_payload = _current_native_record_payload(root)
    current_preparation = _validate_current_native_preparation_record(root, source_payload)
    candidate = _current_return_candidate_facts(root, source_payload)
    return {"schema": "genewhip.phase7-original10-current-native-return.v1",
        "status": "candidate", "phase": "GW-07", "plan": "10",
        "purpose": CURRENT_RETURN_PURPOSE,
        "qualification_status": "current-source-return-pending-parent-review",
        "product_qualification_claim": False,
        "return_scope": "original10 Task1 current-source publication readiness only",
        "campaign": source_payload["campaign"],
        "r8_native_evidence": source_payload["native_evidence"],
        "historical_17_pins": source_payload["historical_17_pins"],
        "r3_preparation_history": preparation_history,
        "current_preparation": current_preparation,
        "current_source_pins": source_payload["current_source_pins"],
        "current_source_delta_from_r8": source_payload["current_source_delta_from_r8"],
        "current_tests": source_payload["current_tests"],
        "continuation_module_sha256": source_payload["continuation_module_sha256"],
        "current_risk_evidence_sha256": source_payload["current_risk_evidence_sha256"],
        "candidate": candidate,
        "candidate_review_paths": {"code": CURRENT_RETURN_CANDIDATE_CODE_REVIEW.as_posix(),
            "security": CURRENT_RETURN_CANDIDATE_SECURITY_REVIEW.as_posix()},
        "review_paths": {"code": CURRENT_RETURN_CODE_REVIEW.as_posix(),
            "security": CURRENT_RETURN_SECURITY_REVIEW.as_posix(),
            "return": CURRENT_RETURN_REVIEW.as_posix(), "return_report": CURRENT_RETURN_REPORT.as_posix()},
        "retained_plan_sha256": source_payload["retained_plan_sha256"],
        "retained_duties_sha256": sha_bytes(json.dumps(RETAINED_DUTIES["original10"],
            sort_keys=True, separators=(",", ":")).encode()),
        "not_claimed": ["requirements qualified", "full product compatibility",
            "hosted qualification", "guest or package execution", "publication or merge",
            "phase completion"]}


def _write_exclusive_json(root: Path, relative: Path, payload: dict[str, Any]) -> None:
    destination = root / relative
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ValueError("current-return-output-path-invalid")
    root_lexical = Path(os.path.abspath(root))
    destination_lexical = Path(os.path.abspath(destination))
    try:
        inside = destination_lexical.relative_to(root_lexical)
    except ValueError:
        raise ValueError("current-return-output-path-invalid") from None
    if not inside.parts or inside.name in ("", ".", ".."):
        raise ValueError("current-return-output-path-invalid")
    encoded = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(root_lexical, directory_flags)
    except OSError:
        raise ValueError("current-return-output-parent-invalid") from None
    try:
        for part in inside.parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=directory_fd)
            except FileExistsError:
                pass
            try:
                next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            except OSError:
                raise ValueError("current-return-output-parent-invalid") from None
            os.close(directory_fd)
            directory_fd = next_fd
        temporary_name = None
        descriptor = None
        for _ in range(3):
            candidate_name = "." + inside.parts[-1] + "." + os.urandom(16).hex() + ".tmp"
            try:
                descriptor = os.open(candidate_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory_fd)
                temporary_name = candidate_name
                break
            except FileExistsError:
                continue
            except OSError:
                raise ValueError("current-return-output-path-invalid") from None
        if descriptor is None or temporary_name is None:
            raise ValueError("current-return-output-temp-collision")
        try:
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary_name, inside.parts[-1], src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd, follow_symlinks=False)
            except FileExistsError:
                raise ValueError("current-return-output-already-exists") from None
            os.unlink(temporary_name, dir_fd=directory_fd)
            temporary_name = None
            os.fsync(directory_fd)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
    finally:
        os.close(directory_fd)


def build_current_native_return(root: Path = ROOT,
        output: Path | None = None) -> dict[str, Any]:
    expected = CURRENT_RETURN_RECORD
    destination = expected if output is None else output
    if Path(os.path.abspath(destination)) != Path(os.path.abspath(expected)):
        raise ValueError("current-return-output-path-invalid")
    payload = _current_native_return_payload(root)
    _write_exclusive_json(root, expected, payload)
    return payload


def _validate_current_return_candidate_review(root: Path, path: Path,
        payload: dict[str, Any], *, role: str) -> None:
    fields = _canonical_frontmatter(path)
    candidate = payload["candidate"]
    expected = {"status": "accepted", "reviewer_role": role,
        "reviewer_model": "gpt-6-luna" if role == "gsd-code-reviewer" else "gpt-6.1-sol",
        "author_role": "gsd-executor",
        "payload_sha256": sha_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()),
        "candidate_preflight_path": candidate["preparation_path"],
        "candidate_preflight_sha256": candidate["preparation_sha256"],
        "repository_policy_path": candidate["repository_policy_path"],
        "repository_policy_sha256": candidate["repository_policy_sha256"],
        "publication_copy_path": candidate["publication_path"],
        "candidate_head_sha256": candidate["public_head"],
        "candidate_base_sha256": candidate["public_base"],
        "candidate_tree_sha256": candidate["public_tree"],
        "candidate_manifest_sha256": candidate["source_manifest_sha256"],
        "tracked_file_count": str(candidate["tracked_file_count"]),
        "privacy": "pass", "destination_policy": "read-only-verified",
        "report_body_sha256": sha_bytes(_report_body(path))}
    if role == "gsd-security-auditor":
        expected.update({"unresolved current high/critical": "0", "critical": "0", "high": "0",
            "current_risk": "open medium nonblocking", "attributable_cleanup_target": "none",
            "user_action_required": "no", "historical_identity_liveness": "UNKNOWN",
            "historical_T-07-07": "OPEN/high",
            "risk_source_sha256": payload["current_risk_evidence_sha256"]["source"],
            "risk_assessment_sha256": payload["current_risk_evidence_sha256"]["security"]})
    else:
        expected.update({"unresolved high/critical": "0", "critical": "0", "high": "0"})
    if set(fields) != set(expected) or any(fields.get(key) != value for key, value in expected.items()):
        raise ValueError("current-return-candidate-review-stale-or-rejected")


def validate_current_native_return(root: Path, path: Path) -> dict[str, Any]:
    expected_path = root / CURRENT_RETURN_RECORD
    candidate_path = path if path.is_absolute() else root / path
    if candidate_path.resolve() != expected_path.resolve() or candidate_path.is_symlink():
        raise ValueError("current-native-return-path-invalid")
    payload = _json_object(_regular(candidate_path, cap=2 * 1024 * 1024),
        "current-native-return-record-invalid")
    if payload != _current_native_return_payload(root):
        raise ValueError("current-native-return-record-stale")
    _validate_independent_report(root / CURRENT_RETURN_CODE_REVIEW, payload,
        role="gsd-code-reviewer", model="gpt-6-luna", count_key="unresolved high/critical")
    _validate_independent_report(root / CURRENT_RETURN_SECURITY_REVIEW, payload,
        role="gsd-security-auditor", model="gpt-6.1-sol",
        count_key="unresolved current high/critical")
    _validate_current_return_candidate_review(root, root / CURRENT_RETURN_CANDIDATE_CODE_REVIEW,
        payload, role="gsd-code-reviewer")
    _validate_current_return_candidate_review(root, root / CURRENT_RETURN_CANDIDATE_SECURITY_REVIEW,
        payload, role="gsd-security-auditor")
    payload_sha = sha_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    code_sha, security_sha = sha(root / CURRENT_RETURN_CODE_REVIEW), sha(root / CURRENT_RETURN_SECURITY_REVIEW)
    candidate_code_sha = sha(root / CURRENT_RETURN_CANDIDATE_CODE_REVIEW)
    candidate_security_sha = sha(root / CURRENT_RETURN_CANDIDATE_SECURITY_REVIEW)
    review_path, report_path = root / CURRENT_RETURN_REVIEW, root / CURRENT_RETURN_REPORT
    review = _canonical_frontmatter(review_path)
    expected_review = {"status": "accepted", "reviewer_role": "gsd-code-reviewer",
        "reviewer_model": "gpt-6-luna", "author_role": "gsd-executor",
        "payload_sha256": payload_sha, "code_review_sha256": code_sha,
        "security_review_sha256": security_sha,
        "candidate_code_review_sha256": candidate_code_sha,
        "candidate_security_review_sha256": candidate_security_sha,
        "unresolved high/critical": "0", "critical": "0", "high": "0",
        "report_body_sha256": sha_bytes(_report_body(review_path))}
    report = _canonical_frontmatter(report_path)
    expected_report = {"status": "accepted", "payload_sha256": payload_sha,
        "review_sha256": sha(review_path), "code_review_sha256": code_sha,
        "security_review_sha256": security_sha,
        "candidate_code_review_sha256": candidate_code_sha,
        "candidate_security_review_sha256": candidate_security_sha,
        "current_risk": "open medium nonblocking", "historical_identity_liveness": "UNKNOWN",
        "historical_T-07-07": "OPEN/high", "requirements_qualified": "none",
        "scope": "original10-current-source-readiness", "product_qualification_claim": "false",
        "retained_duties_sha256": payload["retained_duties_sha256"],
        "report_body_sha256": sha_bytes(_report_body(report_path))}
    if (set(review) != set(expected_review) or any(review.get(key) != value
            for key, value in expected_review.items()) or set(report) != set(expected_report)
            or any(report.get(key) != value for key, value in expected_report.items())):
        raise ValueError("current-native-return-parent-review-missing-or-stale")
    return payload


def _canonical_frontmatter(path: Path) -> dict[str, str]:
    text = _regular(path, cap=1024 * 1024).decode("utf-8")
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---\n", 4)
    if end < 0:
        return {}
    fields: dict[str, str] = {}
    for line in text[4:end].splitlines():
        if not line or line.startswith("#"):
            continue
        if line[0].isspace() or ":" not in line:
            return {}
        key, value = line.split(":", 1)
        value = value.strip()
        if (key != key.strip() or key in fields or not value
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_ /-]*", key)
                or value[0] in "['\"[{" or value.lower() in ("nan", ".nan")):
            return {}
        fields[key] = value
    return fields


def _report_body(path: Path) -> bytes:
    text = _regular(path, cap=1024 * 1024).decode("utf-8")
    if not text.startswith("---\n"):
        raise ValueError("continuation-report-body-invalid")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise ValueError("continuation-report-body-invalid")
    body = text[end + 5:].encode("utf-8")
    if not body.strip():
        raise ValueError("continuation-report-body-invalid")
    return body


def _validate_independent_report(path: Path, payload: dict[str, Any], *, role: str,
                                 model: str, count_key: str) -> None:
    fields = _canonical_frontmatter(path)
    expected = {"status": "accepted", "reviewer_role": role, "reviewer_model": model,
        "author_role": "gsd-executor", "payload_sha256": sha_bytes(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()),
        count_key: "0", "critical": "0", "high": "0"}
    expected["report_body_sha256"] = sha_bytes(_report_body(path))
    if role == "gsd-security-auditor":
        expected.update({"current_risk": "open medium nonblocking",
            "attributable_cleanup_target": "none", "user_action_required": "no",
            "historical_identity_liveness": "UNKNOWN", "historical_T-07-07": "OPEN/high",
            "risk_source_sha256": payload["current_risk_evidence_sha256"]["source"],
            "risk_assessment_sha256": payload["current_risk_evidence_sha256"]["security"]})
    if set(fields) != set(expected) or any(fields.get(key) != value for key, value in expected.items()):
        raise ValueError("continuation-independent-review-stale-or-rejected")


def _candidate_path(root: Path, relative: Any) -> Path:
    if (not isinstance(relative, str) or not relative or Path(relative).is_absolute()
            or ".." in Path(relative).parts):
        raise ValueError("continuation-candidate-path-invalid")
    path = root / relative
    cursor = root
    for part in Path(relative).parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("continuation-candidate-path-invalid")
    resolved = path.resolve(strict=True)
    if root.resolve() not in resolved.parents:
        raise ValueError("continuation-candidate-path-invalid")
    return resolved


def _candidate_git(candidate: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=candidate, text=True, capture_output=True,
        timeout=30, check=False)
    if result.returncode:
        raise ValueError("continuation-candidate-git-identity-invalid")
    return result.stdout.strip()


def _candidate_privacy(root: Path, candidate: Path,
                       paths: list[str]) -> tuple[list[Any], dict[str, Any]]:
    scanner = _load_module(root, "scripts/ci/public_hygiene.py", "gw17_candidate_privacy")
    return scanner.inspect(candidate, paths), scanner.scan_git_history(candidate)


def _authorized_repository(root: Path) -> str:
    for relative in ("build/phase4/delivery-preflight.json", "build/phase4/authorized-preflight.json"):
        try:
            value = _json_object(_regular(root / relative, cap=1024 * 1024),
                "continuation-authorized-destination-invalid")
        except (OSError, ValueError):
            continue
        destination = value.get("destination")
        repository = value.get("repository")
        if (value.get("schema") == "genewhip.publication-readiness-packet.v1"
                and value.get("history_disposition") == "sanitized-snapshots-preserve-local-history"
                and isinstance(destination, dict)
                and destination.get("owner_repository") == repository
                and destination.get("visibility") == "public"
                and isinstance(repository, str)
                and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)):
            return repository
    raise ValueError("continuation-authorized-destination-invalid")


def _validate_candidate(root: Path, path: Path, payload: dict[str, Any]) -> None:
    fields = _canonical_frontmatter(path)
    expected_preflight = "build/v02/campaign15/continuation17-r3/preflight.json"
    expected_candidate = "build/v02/campaign15/continuation17-r3/publication"
    policy_relative = fields.get("repository_policy_path")
    if (fields.get("candidate_preflight_path") != expected_preflight
            or fields.get("publication_copy_path") != expected_candidate
            or not isinstance(policy_relative, str)
            or not re.fullmatch(
                r"build/v02/campaign15/continuation17-r3/repository-preflight-[A-Za-z0-9_-]+/policy\.json",
                policy_relative)):
        raise ValueError("continuation-candidate-path-invalid")
    preflight_path = _candidate_path(root, fields.get("candidate_preflight_path"))
    preflight_bytes = _regular(preflight_path, cap=4 * 1024 * 1024)
    preflight_sha = sha_bytes(preflight_bytes)
    preflight = _json_object(preflight_bytes, "continuation-candidate-preflight-invalid")
    policy_path = _candidate_path(root, fields.get("repository_policy_path"))
    policy_bytes = _regular(policy_path, cap=4 * 1024 * 1024)
    policy_sha = sha_bytes(policy_bytes)
    policy = _json_object(policy_bytes, "continuation-candidate-policy-invalid")
    identity = preflight.get("public_identity")
    if not isinstance(identity, dict):
        raise ValueError("continuation-candidate-identity-invalid")
    repository = _authorized_repository(root)
    head, base, tree = identity.get("head_sha"), identity.get("base_sha"), identity.get("tree_sha")
    if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value)
           for value in (head, base, tree)):
        raise ValueError("continuation-candidate-identity-invalid")
    manifest = preflight.get("source_manifest")
    if not isinstance(manifest, list) or not manifest or len(manifest) > 5000:
        raise ValueError("continuation-candidate-manifest-invalid")
    preflight_privacy = preflight.get("privacy")
    source_identity = preflight.get("source_identity")
    public_identity = preflight.get("public_identity")
    if (not isinstance(preflight_privacy, dict) or not isinstance(source_identity, dict)
            or not isinstance(public_identity, dict)):
        raise ValueError("continuation-candidate-preflight-invalid")
    manifest_sha = sha_bytes(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())
    if (preflight.get("schema") != "genewhip.v02-public-source-preflight.v1"
            or preflight.get("status") != "prepared" or preflight.get("blockers") != []
            or preflight.get("repository") != repository
            or preflight.get("repository") != policy.get("repository")
            or preflight.get("mutations_performed") != 0 or preflight.get("push_performed") is not False
            or preflight.get("pull_request_opened") is not False
            or preflight.get("workflow_dispatched") is not False
            or preflight.get("requirements_qualified") != []
            or preflight_privacy.get("status") != "pass"
            or preflight_privacy.get("current_findings") != []
            or preflight_privacy.get("history_findings") != []
            or preflight.get("source_manifest_sha256") != manifest_sha
            or source_identity.get("source_manifest_sha256") != manifest_sha
            or public_identity.get("parent_shas") != [base]
            or preflight.get("repository_preflight") != fields.get("repository_policy_path")
            or preflight.get("publication_copy") != fields.get("publication_copy_path")
            or ("inspector_exit_code" in policy and
                (type(policy["inspector_exit_code"]) is not int or policy["inspector_exit_code"] != 0))):
        raise ValueError("continuation-candidate-preflight-invalid")
    candidate_dir = _candidate_path(root, fields.get("publication_copy_path"))
    expected_paths: list[str] = []
    total_bytes = 0
    for row in manifest:
        if not isinstance(row, dict) or set(row) != {"path", "size_bytes", "sha256"}:
            raise ValueError("continuation-candidate-manifest-invalid")
        relative = row.get("path")
        if (not isinstance(relative, str) or not relative or "\\" in relative or "\x00" in relative
                or Path(relative).as_posix() != relative or Path(relative).is_absolute()
                or ".." in Path(relative).parts or relative in expected_paths
                or not isinstance(row.get("size_bytes"), int)
                or isinstance(row.get("size_bytes"), bool) or row["size_bytes"] < 0
                or not isinstance(row.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])):
            raise ValueError("continuation-candidate-manifest-invalid")
        expected_paths.append(relative)
        candidate_file = _candidate_path(root, candidate_dir.relative_to(root).as_posix()
            + "/" + relative)
        info = candidate_file.lstat()
        total_bytes += info.st_size
        if (info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size > 32 * 1024 * 1024
                or total_bytes > 200 * 1024 * 1024 or info.st_size != row["size_bytes"]
                or sha(candidate_file) != row["sha256"]):
            raise ValueError("continuation-candidate-file-stale-or-unbounded")
    if expected_paths != sorted(expected_paths) or "LICENSE" not in expected_paths:
        raise ValueError("continuation-candidate-manifest-invalid")
    manifest_by_path = {row["path"]: row for row in manifest}
    required_current_sources = {**payload["current_tests"],
        "scripts/release/v02_continuation.py": payload["continuation_module_sha256"],
        "scripts/ci/public_hygiene.py": sha(root / "scripts/ci/public_hygiene.py")}
    for relative in payload["changed_original_source_paths"]:
        required_current_sources[relative] = payload["current_source_pins"][relative]
    for relative, digest in required_current_sources.items():
        row = manifest_by_path.get(relative)
        if row is None or row["sha256"] != digest:
            raise ValueError("continuation-candidate-current-source-stale")
    git_identity = {
        "head": _candidate_git(candidate_dir, "rev-parse", "HEAD"),
        "base": _candidate_git(candidate_dir, "rev-parse", "HEAD^"),
        "tree": _candidate_git(candidate_dir, "rev-parse", "HEAD^{tree}"),
        "branch": _candidate_git(candidate_dir, "symbolic-ref", "--short", "HEAD"),
        "remote": _candidate_git(candidate_dir, "remote", "get-url", "origin"),
        "parents": _candidate_git(candidate_dir, "show", "-s", "--format=%P", "HEAD").split(),
        "refs": _candidate_git(candidate_dir, "for-each-ref", "--format=%(refname)").splitlines(),
        "paths": [item for item in _candidate_git(candidate_dir, "ls-files", "-z").split("\0") if item],
        "status": _candidate_git(candidate_dir, "status", "--porcelain", "--untracked-files=all"),
    }
    owner, name = repository.split("/", 1)
    expected_remote = f"https://github.com/{owner}/{name}.git"
    expected_refs = {"refs/heads/main", "refs/remotes/origin/HEAD", "refs/remotes/origin/main"}
    if (git_identity["head"] != head or git_identity["base"] != base or git_identity["tree"] != tree
            or git_identity["branch"] != "main" or git_identity["remote"] != expected_remote
            or git_identity["parents"] != [base] or set(git_identity["refs"]) != expected_refs
            or git_identity["paths"] != expected_paths or git_identity["status"]):
        raise ValueError("continuation-candidate-git-identity-invalid")
    current_findings, history = _candidate_privacy(root, candidate_dir, expected_paths)
    if (not isinstance(current_findings, list) or not isinstance(history, dict)
            or not isinstance(history.get("findings"), list)
            or current_findings or history["findings"]):
        raise ValueError("continuation-candidate-privacy-invalid")
    expected_identity = {"head": head, "base": base}
    policy_observations = policy.get("repository_observations")
    policy_privacy = policy.get("privacy_scan")
    if (not isinstance(policy_observations, dict) or not isinstance(policy_privacy, dict)
            or not isinstance(policy_privacy.get("publication_copy"), dict)
            or not isinstance(policy_observations.get("observations"), dict)):
        raise ValueError("continuation-candidate-policy-invalid")
    observed = policy_observations["observations"]
    privacy_copy = policy_privacy["publication_copy"]
    protection = observed.get("branch_protection")
    merge_methods = observed.get("permitted_merge_methods")
    policy_identity = observed.get("expected_identity")
    required_checks = protection.get("required_status_checks") if isinstance(protection, dict) else None
    if (policy.get("schema") != "genewhip.publication-readiness-packet.v1"
            or policy.get("repository") != preflight.get("repository")
            or policy.get("history_disposition") != "sanitized-snapshots-preserve-local-history"
            or policy.get("hosted_evidence") != {"outcome": "not_run", "qualifies_rel_03": False}
            or policy.get("destination") != {"owner_repository": preflight.get("repository"),
                "visibility": "public"}
            or policy.get("expected_identity") != expected_identity
            or policy.get("mutations_performed") != 0
            or policy_observations.get("ready") is not True
            or policy_observations.get("blockers") != []
            or observed.get("visibility") != "public"
            or observed.get("default_branch") != "main"
            or observed.get("auto_merge_enabled") is not True
            or observed.get("caller_write_permission") != "write"
            or not isinstance(policy_identity, dict)
            or policy_identity.get("head") != head or policy_identity.get("base") != base
            or policy_identity.get("observed_default_branch_sha") != base
            or not isinstance(protection, dict)
            or protection.get("pull_request_required") is not True
            or not isinstance(required_checks, list)
            or "required-ci" not in required_checks
            or not isinstance(merge_methods, list)
            or not any(item in ("merge", "squash", "rebase") for item in merge_methods)
            or privacy_copy.get("status") != "pass"
            or privacy_copy.get("current_findings") != []
            or privacy_copy.get("findings") != []):
        raise ValueError("continuation-candidate-policy-invalid")
    expected = {"status": "accepted", "reviewer_role": "gsd-code-reviewer",
        "payload_sha256": sha_bytes(json.dumps(payload, sort_keys=True,
            separators=(",", ":")).encode()), "current_source_sha256": payload["coordinator_current_sha256"],
        "candidate_preflight_path": preflight_path.relative_to(root).as_posix(),
        "candidate_preflight_sha256": preflight_sha,
        "repository_policy_path": policy_path.relative_to(root).as_posix(),
        "repository_policy_sha256": policy_sha,
        "publication_copy_path": candidate_dir.relative_to(root).as_posix(),
        "candidate_head_sha256": head, "candidate_base_sha256": base,
        "candidate_tree_sha256": tree, "candidate_manifest_sha256": manifest_sha,
        "tracked_file_count": str(len(manifest)),
        "privacy": "pass", "destination_policy": "read-only-verified",
        "report_body_sha256": sha_bytes(_report_body(path))}
    if set(fields) != set(expected) or any(fields.get(key) != value for key, value in expected.items()):
        raise ValueError("continuation-candidate-review-stale-or-rejected")


def _validate_return(root: Path, payload: dict[str, Any]) -> None:
    review_path, return_path, security_path = root / RETURN_REVIEW, root / RETURN, root / SECURITY_REVIEW
    fields = _canonical_frontmatter(return_path)
    review = _canonical_frontmatter(review_path)
    payload_sha = sha_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    expected_review = {"status": "accepted", "payload_sha256": payload_sha,
        "candidate_sha256": sha(root / CANDIDATE_REVIEW), "security_sha256": sha(security_path),
        "reviewer_role": "gsd-code-reviewer", "unresolved high/critical": "0",
        "report_body_sha256": sha_bytes(_report_body(review_path))}
    expected_return = {"status": "accepted", "payload_sha256": payload_sha,
        "review_sha256": sha(review_path), "security_sha256": sha(security_path),
        "candidate_review_sha256": sha(root / CANDIDATE_REVIEW),
        "current_risk": "open medium nonblocking", "historical_identity_liveness": "UNKNOWN",
        "historical_T-07-07": "OPEN/high", "requirements_qualified": "none"}
    expected_return["report_body_sha256"] = sha_bytes(_report_body(return_path))
    expected_return["retained_duties_sha256"] = sha_bytes(json.dumps(
        RETAINED_DUTIES, sort_keys=True, separators=(",", ":")).encode())
    if set(review) != set(expected_review) or set(fields) != set(expected_return):
        raise ValueError("continuation-return-report-schema-invalid")
    if any(review.get(key) != value for key, value in expected_review.items()):
        raise ValueError("continuation-return-review-rejected-or-stale")
    if any(fields.get(key) != value for key, value in expected_return.items()):
        raise ValueError("continuation-return-review-rejected-or-stale")


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--build-attestation", action="store_true")
    group.add_argument("--build-current-native", action="store_true")
    group.add_argument("--validate", action="store_true")
    group.add_argument("--validate-current-native", action="store_true")
    group.add_argument("--build-current-return", action="store_true")
    group.add_argument("--validate-current-return", action="store_true")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--attestation", type=Path)
    parser.add_argument("--candidate", action="store_true")
    parser.add_argument("--return-check", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.build_attestation:
            value = build_attestation(args.root, args.attestation or ATTESTATION)
        elif args.build_current_native:
            value = build_current_native_continuation(args.root,
                args.attestation or CURRENT_NATIVE_CONTINUATION)
        elif args.validate_current_native:
            value = validate_current_native_continuation(args.root,
                args.attestation or CURRENT_NATIVE_CONTINUATION)
        elif args.build_current_return:
            value = build_current_native_return(args.root,
                args.attestation or CURRENT_RETURN_RECORD)
        elif args.validate_current_return:
            value = validate_current_native_return(args.root,
                args.attestation or CURRENT_RETURN_RECORD)
        else:
            value = validate_attestation(args.root, args.attestation or ATTESTATION,
                require_candidate=args.candidate, require_return=args.return_check)
        print(json.dumps({"status": "accepted", "payload_sha256": sha_bytes(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode())}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print("REJECT: " + str(error), file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

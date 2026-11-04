#!/usr/bin/env python3
"""Build and verify the bounded, privacy-scanned Phase 7 runtime artifact transfer."""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import sys
import subprocess
import tarfile
import stat

MAX_MEMBERS = 256
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCOPE_SPEC = importlib.util.spec_from_file_location(
    "gw_v02_scope", ROOT / "scripts/evidence/v02_scope.py")
_SCOPE = importlib.util.module_from_spec(_SCOPE_SPEC)
_SCOPE_SPEC.loader.exec_module(_SCOPE)
_HYGIENE_SPEC = importlib.util.spec_from_file_location("gw_v02_transfer_public_hygiene",
    ROOT / "scripts/ci/public_hygiene.py")
_HYGIENE = importlib.util.module_from_spec(_HYGIENE_SPEC)
_HYGIENE_SPEC.loader.exec_module(_HYGIENE)
PERSONAL_PATH = _HYGIENE.PATTERNS["personal-path"]
EMAIL = re.compile(rb"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
SECRET = _HYGIENE.PATTERNS["secret"]
PRIVATE_FIELD = re.compile(r"(?:password|secret|credential|private[_-]?key|access[_-]?token|api[_-]?key|(?:^|_)token(?:$|_))", re.I)
ALLOWED_ROOT_FILES = {"build/v02/runtime-observation.json", "build/v02/runtime-identity.json",
                      "build/v02/runtime-transfer/inventory.json"}
FORBIDDEN_NAMES = {"CMakeCache.txt", "phase6_safety", "gw_headless", "genewhip-desktop", "gw_core_benchmark"}
PUBLIC_CLOSURE = ("compatibility-matrix.md", "manifest.json", "observations.json", "roster.json", "schema.json", "verifier.py")
PUBLIC_SCHEMA_MEMBER = "build/v02/public/schema.json"
CANONICAL_SCHEMA_SOURCE = "evidence/v02-schema.json"
CMAKE_PROVENANCE_SOURCE_PATHS = ("CMakeLists.txt", "tools/session/CMakeLists.txt")
CMAKE_PROVENANCE_MAX_BYTES = 131072
RUNTIME_CANDIDATE_MEMBER = "build/v02/runtime-observation/candidate.json"
CORE_FILES = {"candidate.json", "previous-report-before-new-batch.json", "failed-report-"}
CORE_OUTPUTS = {"route.gwrc", "native.json", "process.json", "run.json", "recovered-run.json",
    "audio.pcm", "audio-trace.jsonl", "control.json"}
REFERENCE_ROLES = {"candidate_manifest", "process_receipt", "native_report", "pcm", "audio",
    "audio_trace", "image", "scene_metadata", "chunk_report", "input_log", "full_pcm",
    "selected_media", "control_report", "core_report", "disk_audio_artifact", "retained_pcm", "path", "members", "entries",
    "core", "core_routes", "media", "host-software", "host-native", "safety", "chunk", "input-software",
    "input-native", "build_evidence", "api_contract", "parser_rejection", "report", "evidence", "controls", "desktop_pcm",
    "headless_pcm", "headless_pixel", "renderer_pixel", "host", "native", "renderer", "delivery_map",
    "input_contract", "public-core", "compiler_identity", "delivery_map_identity",
    "media_expectations_identity", "test_source", "test_executable", "desktop_binary",
    "route_metadata", "stdout", "stderr", "compiler_metadata", "raw_build_artifact_identities", "public-matrix"}
CONTROL_CASE_IDS = ("title-no-start", "start-idle", "start-move", "action-sound",
    "action-no-trigger", "sustained-play")
CONTROL_FIELD_LOG_MAX_BYTES = 1024 * 1024
CONTROL_FIELD_NAME = re.compile(
    r"^build/v02/runtime/core-work/canonical-core-[A-Za-z0-9_-]{8}/controls-([12])/artifacts/"
    r"(title-no-start|start-idle|start-move|action-sound|action-no-trigger|sustained-play)/"
    r"headless/child\.stdout\.raw$")
IDENTITY_REFERENCE_PATHS = {
    "public-core": "build/v02/runtime-build/tools/session/gw_headless",
    "compiler_identity": "scripts/evidence/phase6_routes.py",
    "delivery_map": "fixtures/phase6/recursion94-consumed-map-v1.json",
    "delivery_map_identity": "fixtures/phase6/recursion94-consumed-map-v1.json",
    "media_expectations_identity": "fixtures/phase6/media-expectations-v1.json",
    "test_source": "tests/session/phase6_chunk_contract.c",
    "test_executable": "build/v02/runtime-build/tools/session/phase6_chunk_contract",
    "desktop_binary": "build/v02/runtime-build/tools/desktop/genewhip-desktop",
}
HASH_METADATA_ROLES = {"route_metadata", "stdout", "stderr", "compiler_metadata",
    "raw_build_artifact_identities", "control_session_roster"}
DIMENSIONS = ("core", "host", "host-native", "media", "safety", "determinism", "measurements",
    "public-matrix", "package", "docs", "privacy", "rights")
PACKAGE_DIMENSION_SOURCE_PATHS = {
    "core": "build/v02/runtime-observation/core-report.json",
    "host": "build/v02/runtime-observation/host-software.json",
    "host-native": "build/v02/runtime-observation/host-native.json",
    "media": "build/v02/runtime-observation/media-report.json",
    "safety": "build/v02/runtime-observation/safety.json",
    "determinism": "build/v02/runtime-observation/chunk.json",
    "measurements": "build/v02/measurements.json",
    "public-matrix": "build/v02/public/manifest.json",
    "package": "artifacts/package-receipt.json",
    "docs": "artifacts/qualification-docs.json",
    "privacy": "build/v02/public-hygiene.json",
    "rights": "artifacts/release-assets/inventory.json",
}
BENCHMARKS = ("control", "recursion94", "tank-battle")
PACKAGE_FIXED_MEMBERS = {
    "artifacts/package-receipt.json", "artifacts/qualification-docs.json",
    "artifacts/qualification-command-attempts/public-hygiene.attempt.json",
    "build/v02/qualification-dimensions.json", "build/v02/qualification-evidence-closure.json",
    "build/v02/measurements.json",
    "build/v02/public/performance.json", "build/v02/public-hygiene.json",
    "build/v02/runtime-identity.json", "build/v02/runtime-observation.json",
    "build/v02/runtime-observation/core-report.json", "build/v02/runtime-observation/host-software.json",
    "build/v02/runtime-observation/host-native.json", "build/v02/runtime-observation/media-report.json",
    "build/v02/runtime-observation/safety.json", "build/v02/runtime-observation/safety-build-evidence.json",
    "build/v02/runtime-observation/safety-build-evidence/native.json",
    "build/v02/runtime-observation/safety-build-evidence/sanitize.json",
    "build/v02/runtime-observation/safety-build-evidence/hooks-off.json",
    "build/v02/runtime-observation/chunk.json", "build/v02/public/manifest.json",
    "artifacts/release-assets/inventory.json", "artifacts/release-assets/SHA256SUMS",
    *("artifacts/dimension-" + name + ".json" for name in DIMENSIONS),
    *("build/v02/collected/benchmark-" + name + "/benchmark-" + name + ".json" for name in BENCHMARKS),
}
DIRECT_MEMBERS = (
    "build/v02/runtime-observation.json", "build/v02/runtime-identity.json",
    "build/v02/runtime-observation/candidate.json", "build/v02/runtime-observation/execution-scope.json",
    "build/v02/runtime-observation/core-report.json", "build/v02/runtime-observation/media-report.json",
    "build/v02/runtime-observation/host-software.json", "build/v02/runtime-observation/host-native.json",
    "build/v02/runtime-observation/safety.json", "build/v02/runtime-observation/chunk.json",
    "build/v02/runtime-observation/safety-build-evidence.json",
    "build/v02/runtime/input-contract/software.json", "build/v02/runtime/input-contract/native.json",
    *("build/v02/public/" + name for name in PUBLIC_CLOSURE),
)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _runtime_member_allowed(name):
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name or any(
            part in FORBIDDEN_NAMES or part.endswith((".dylib", ".so", ".dll")) for part in path.parts):
        return False
    if (name in ALLOWED_ROOT_FILES or name in DIRECT_MEMBERS
            or name == "build/v02/public/execution-identity.json"):
        return True
    if re.fullmatch(r"build/v02/runtime-observation/safety-build-evidence/(native|sanitize|hooks-off)\.json", name):
        return True
    if _is_candidate_cmake_snapshot_name(name):
        return True
    core_base = r"build/v02/runtime/core-work/canonical-core-[A-Za-z0-9_-]+/"
    if re.fullmatch(core_base + r"(?:candidate\.json|previous-report-before-new-batch\.json|failed-report-[0-9a-f]{16}\.json)", name):
        return True
    if CONTROL_FIELD_NAME.fullmatch(name):
        return True
    core_case = core_base + r"(?:recursion94|tank-battle)-[A-Za-z0-9_-]+-[12]/"
    if re.fullmatch(core_case + r"(?:route\.gwrc|native\.json|process\.json|run\.json|recovered-run\.json|audio\.pcm|audio-trace\.jsonl)", name):
        return True
    if re.fullmatch(core_case + r"fields/(?:route-capture\.json|field-[0-9]+\.bin)", name):
        return True
    if re.fullmatch(core_base + r"controls-[12]/(?:control\.json|process\.json|artifacts/[A-Za-z0-9_-]+\.pcm)", name):
        return True
    if re.fullmatch(r"build/v02/runtime/chunk-work/phase6-chunk-(?:recursion94|tank-battle)-[A-Za-z0-9_-]+/(?:actual-inputs\.csv|chunk\.json|process\.json)", name):
        return True
    if re.fullmatch(r"build/v02/runtime/host-work/(?:software|native)/phase6-sdl-[A-Za-z0-9_-]+/(?:recursion94-full-route\.gwrc|native\.json|host\.json|process\.json|sdlaudio\.raw)", name):
        return True
    if re.fullmatch(
            r"build/v02/runtime-build/evidence/phase6-sdl-host-[A-Za-z0-9_-]{8}/(?:process\.json|original-host-controls-attempt1\.json)",
            name):
        return True
    host_routes = (
        "recursion94-full-route", "recursion94-withhold-final-b", "recursion94-withhold-first-plate",
        "tank-battle-full-route", "tank-battle-withhold-early-hit", "tank-battle-withhold-late-hit",
    )
    route_pattern = "(?:" + "|".join(re.escape(route) for route in host_routes) + ")"
    if re.fullmatch(
            r"build/v02/runtime-build/evidence/phase6-sdl-host-[A-Za-z0-9_-]{8}/"
            + route_pattern
            + r"-attempt1/(?:host\.json|native\.json|process\.json|audio\.pcm|renderer-field\.bin)",
            name):
        return True
    if name in {
            "build/v02/runtime/safety/native-api.json",
            "build/v02/runtime/safety/sanitize-api.json",
            "build/v02/runtime/safety/hooks-off-api.json",
            "build/v02/runtime/safety/native-parser.json",
    }:
        return True
    return False


def _is_candidate_cmake_snapshot_name(name):
    return (isinstance(name, str) and re.fullmatch(
        r"build/v02/runtime-build/evidence/build-provenance/[0-9a-f]{64}\.cmake", name) is not None)


def _candidate_cmake_source_bindings(candidate):
    if not isinstance(candidate, dict) or not isinstance(candidate.get("source_files"), dict):
        raise ValueError("transfer-cmake-provenance-candidate-invalid")
    rows = {}
    for relative, digest in candidate["source_files"].items():
        if not isinstance(relative, str):
            raise ValueError("transfer-cmake-provenance-candidate-invalid")
        if pathlib.PurePosixPath(relative).name == "CMakeLists.txt":
            if relative not in CMAKE_PROVENANCE_SOURCE_PATHS or not _sha256_string(digest):
                raise ValueError("transfer-cmake-provenance-candidate-invalid")
            rows[relative] = digest
    if set(rows) != set(CMAKE_PROVENANCE_SOURCE_PATHS):
        raise ValueError("transfer-cmake-provenance-candidate-invalid")
    return rows


def _candidate_cmake_snapshot_path(digest):
    return "build/v02/runtime-build/evidence/build-provenance/" + digest + ".cmake"


def _verify_candidate_cmake_snapshot_graph(candidate, members, snapshots):
    """Join only the two named build snapshots to trusted source bytes and candidate hashes."""
    bindings = _candidate_cmake_source_bindings(candidate)
    expected = {}
    for relative, digest in bindings.items():
        expected.setdefault(_candidate_cmake_snapshot_path(digest), []).append((relative, digest))
    observed = {name for name in members if _is_candidate_cmake_snapshot_name(name)}
    if observed != set(expected) or set(snapshots) != set(expected):
        raise ValueError("transfer-cmake-provenance-roster-invalid")
    for name, rows in expected.items():
        facts = members.get(name)
        snapshot_bytes = snapshots.get(name)
        for source_path, digest in rows:
            source_bytes = _read_owned_file_snapshot(ROOT, source_path,
                label="candidate-cmake-source:" + source_path, max_bytes=CMAKE_PROVENANCE_MAX_BYTES)
            if (not isinstance(facts, dict) or type(facts.get("size")) is not int
                    or len(source_bytes) > CMAKE_PROVENANCE_MAX_BYTES
                    or _sha(source_bytes) != digest
                    or not isinstance(snapshot_bytes, bytes)
                    or snapshot_bytes != source_bytes
                    or facts.get("sha256") != digest
                    or facts["size"] != len(source_bytes)):
                raise ValueError("transfer-cmake-provenance-binding-invalid:" + source_path)


def _read_candidate_cmake_source(root, root_fd, relative, digest):
    source_bytes = _read_owned_file_snapshot(root, relative,
        label="candidate-cmake-source:" + relative,
        max_bytes=CMAKE_PROVENANCE_MAX_BYTES, root_fd=root_fd)
    if _sha(source_bytes) != digest:
        raise ValueError("transfer-cmake-provenance-source-mismatch:" + relative)
    return source_bytes


def _package_member_allowed(name):
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name or any(
            part in FORBIDDEN_NAMES or part.endswith((".dylib", ".so", ".dll")) for part in path.parts):
        return False
    return (name in PACKAGE_FIXED_MEMBERS or _runtime_member_allowed(name) or
        re.fullmatch(r"(?:artifacts/v02|artifacts/release-assets)/genewhip-0\.2\.0-(?:sdk-diagnostic-darwin-arm64|playable-preview-macos-arm64)-[0-9a-f]{12}\.tar\.gz(?:\.sha256|\.qualification\.json)?", name) is not None)


def _allowed(name, *, package=False):
    return _package_member_allowed(name) if package else _runtime_member_allowed(name)


def _scan_fields(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if PRIVATE_FIELD.search(str(key)):
                raise ValueError("transfer-private-field:" + str(key))
            _scan_fields(child)
    elif isinstance(value, list):
        for child in value:
            _scan_fields(child)


def _scan(name, data, *, package=False):
    if not _allowed(name, package=package):
        raise ValueError("transfer-member-not-allowlisted:" + name)
    if PERSONAL_PATH.search(data):
        raise ValueError("transfer-private-path:" + name)
    if EMAIL.search(data):
        raise ValueError("transfer-private-email:" + name)
    if SECRET.search(data):
        raise ValueError("transfer-secret-pattern:" + name)
    if name.endswith(".json"):
        try:
            document = json.loads(data)
            _scan_fields(document)
            if not package:
                _validate_runtime_json(name, document)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("transfer-json-invalid:" + name) from error


def _validate_runtime_json(name, document):
    if name == "build/v02/public/observations.json":
        if not isinstance(document, list) or any(not isinstance(row, dict) for row in document):
            raise ValueError("transfer-public-observations-shape")
        return
    if not isinstance(document, dict):
        raise ValueError("transfer-json-role-not-object:" + name)
    basename = pathlib.PurePosixPath(name).name
    schemas = {
        "runtime-observation.json": "genewhip-v02-runtime-observation-v1",
        "runtime-identity.json": "genewhip-v02-runtime-identity-v1",
        "execution-identity.json": "genewhip-v02-runtime-identity-v1",
        "execution-scope.json": "genewhip-v02-execution-v1",
        "candidate.json": "genewhip-phase6-candidate-v1",
        "core-report.json": "genewhip-phase6-product-report-v1",
        "media-report.json": "genewhip-phase6-media-v1",
        "host.json": "genewhip-phase6-host-v1",
        "host-software.json": "genewhip-phase6-host-v1",
        "host-native.json": "genewhip-phase6-host-v1",
        "original-host-controls-attempt1.json": "genewhip-phase4-host-sessions",
        "safety.json": "genewhip-phase6-safety-v1",
        "safety-build-evidence.json": "genewhip.v02-safety-build-evidence.v2",
        "chunk.json": "genewhip-phase6-chunk-v1",
        "native.json": "genewhip-route-native-v1",
        "process.json": None,
        "run.json": None,
        "recovered-run.json": None,
        "native.json": "genewhip-route-native-v1",
        "control.json": None,
        "route-capture.json": None,
        "software.json": "genewhip-phase6-sdl-virtual-input-contract-v1",
        "inventory.json": "genewhip.v02-runtime-transfer.v1",
        "sanitize.json": "genewhip.v02-portable-build-facts.v1",
        "hooks-off.json": "genewhip.v02-portable-build-facts.v1",
    }
    safety_api_paths = {
        "build/v02/runtime/safety/native-api.json",
        "build/v02/runtime/safety/sanitize-api.json",
        "build/v02/runtime/safety/hooks-off-api.json",
    }
    if name in safety_api_paths:
        expected_keys = {
            "allocation_count_peak", "allocation_instrumented", "audio_pass", "cases", "guards_checked",
            "max_tick", "mode", "negative_controls", "output_cap_frames", "returned_frames", "safety_pass",
            "seed", "steady_allocations", "steps", "steps_per_case", "tick_budget",
        }
        integer_keys = expected_keys - {"allocation_instrumented", "mode", "seed"}
        if (set(document) != expected_keys or document.get("mode") not in {"pr", "production"}
                or not isinstance(document.get("allocation_instrumented"), bool)
                or not isinstance(document.get("seed"), str)
                or re.fullmatch(r"[0-9a-f]{8}", document["seed"]) is None
                or any(type(document.get(key)) is not int or document[key] < 0 for key in integer_keys)):
            raise ValueError("transfer-safety-api-contract-shape:" + name)
        return
    if name == "build/v02/runtime/safety/native-parser.json":
        if (set(document) != {"schema", "status", "tests", "runs"}
                or document.get("schema") != "genewhip-phase6-controller-contract-v1"
                or not isinstance(document.get("status"), str)
                or type(document.get("tests")) is not int or document["tests"] < 0
                or not isinstance(document.get("runs"), list)
                or any(not isinstance(row, dict) for row in document["runs"])):
            raise ValueError("transfer-safety-parser-contract-shape:" + name)
        return
    expected = schemas.get(basename)
    if "/safety-build-evidence/" in name:
        expected = "genewhip.v02-portable-build-facts.v1"
    elif "/runtime/chunk-work/" in name and basename == "chunk.json":
        expected = "genewhip-phase6-title-chunk-v1"
    elif ("/runtime-build/evidence/phase6-sdl-host-" in name and basename == "host.json"):
        expected = "genewhip-phase6-sdl-diagnostic-v1"
    elif name.endswith("runtime/input-contract/software.json") or name.endswith("runtime/input-contract/native.json"):
        expected = "genewhip-phase6-sdl-virtual-input-contract-v1"
    if basename not in schemas:
        if name.startswith("build/v02/public/"):
            return
        raise ValueError("transfer-json-role-unknown:" + name)
    if expected is not None and document.get("schema") != expected:
        # The native input-contract report shares a basename with route native
        # reports; its path determines which trusted role applies.
        if not (name.endswith("runtime/input-contract/native.json") and
                document.get("schema") == "genewhip-phase6-sdl-virtual-input-contract-v1"):
            raise ValueError("transfer-json-schema-role-mismatch:" + name)
    if basename == "process.json" and not isinstance(document.get("processes"), list):
        raise ValueError("transfer-process-receipt-schema:" + name)
    if basename == "control.json" and not isinstance(document.get("results"), list):
        raise ValueError("transfer-control-report-schema:" + name)
    if basename == "original-host-controls-attempt1.json":
        if not isinstance(document.get("process_receipts"), list) or not isinstance(document.get("runs"), list):
            raise ValueError("transfer-host-controls-report-schema:" + name)


def _role_allows(role, name):
    if role not in REFERENCE_ROLES:
        return False
    identity_path = IDENTITY_REFERENCE_PATHS.get(role)
    if identity_path is not None:
        return name == identity_path
    if not _runtime_member_allowed(name):
        return False
    # These files are included only by resolving candidate.source_files below.
    # A report path/ref cannot broaden the exact build-input snapshot roster.
    if _is_candidate_cmake_snapshot_name(name):
        return False
    direct_roles = {
        "core": "build/v02/runtime-observation/core-report.json",
        "media": "build/v02/runtime-observation/media-report.json",
        "core_routes": "build/v02/runtime-observation/core-report.json",
        "host-software": "build/v02/runtime-observation/host-software.json",
        "host-native": "build/v02/runtime-observation/host-native.json",
        "safety": "build/v02/runtime-observation/safety.json",
        "chunk": "build/v02/runtime-observation/chunk.json",
        "input-software": "build/v02/runtime/input-contract/software.json",
        "input-native": "build/v02/runtime/input-contract/native.json",
        "public-matrix": "build/v02/public/manifest.json",
        "build_evidence": "build/v02/runtime-observation/safety-build-evidence.json",
    }
    if role in direct_roles:
        return name == direct_roles[role]
    if name in DIRECT_MEMBERS:
        return role in {"evidence", "core_report", "native_report", "host", "renderer", "pcm",
            "candidate_manifest", "process_receipt", "chunk_report", "input_contract", "build_evidence",
            "path", "members", "entries"}
    if role == "evidence":
        return _role_allows("native_report", name) or _role_allows("control_report", name)
    if role in {"native", "host", "renderer", "renderer_pixel"}:
        return pathlib.PurePosixPath(name).name == {"native": "native.json", "host": "host.json",
            "renderer": "renderer-field.bin", "renderer_pixel": "renderer-field.bin"}[role]
    if role == "input_contract":
        return pathlib.PurePosixPath(name).name in {"software.json", "native.json"} and "/input-contract/" in name
    basename = pathlib.PurePosixPath(name).name
    if role in ("candidate_manifest",): return basename == "candidate.json"
    if role in ("process_receipt",): return basename == "process.json"
    if role in ("native_report",): return basename == "native.json"
    if role in ("pcm", "audio", "full_pcm", "desktop_pcm", "headless_pcm", "retained_pcm"):
        return basename in ("audio.pcm", "sdlaudio.raw") or ("/artifacts/" in name and basename.endswith(".pcm"))
    if role in ("audio_trace",): return basename == "audio-trace.jsonl"
    if role in ("image", "selected_media", "headless_pixel"):
        return re.fullmatch(r"field-[0-9]+\.bin", basename) is not None
    if role in ("scene_metadata",): return basename == "route-capture.json"
    if role in ("chunk_report",): return basename == "chunk.json"
    if role in ("input_log",): return basename == "actual-inputs.csv"
    if role in ("control_report", "controls"): return basename == "control.json"
    if role in ("core_report",): return basename == "core-report.json"
    if role == "disk_audio_artifact": return basename == "sdlaudio.raw"
    if role == "entries": return re.fullmatch(r"(native|sanitize|hooks-off)\.json", basename) is not None and "/safety-build-evidence/" in name
    if role == "api_contract": return name in {
        "build/v02/runtime/safety/native-api.json",
        "build/v02/runtime/safety/sanitize-api.json",
        "build/v02/runtime/safety/hooks-off-api.json",
    }
    if role == "parser_rejection": return name == "build/v02/runtime/safety/native-parser.json"
    if role == "report":
        return re.fullmatch(
            r"build/v02/runtime-build/evidence/phase6-sdl-host-[A-Za-z0-9_-]{8}/original-host-controls-attempt1\.json",
            name) is not None
    if role == "members": return name in {"build/v02/public/" + item for item in PUBLIC_CLOSURE}
    if role == "path": return _runtime_member_allowed(name)
    return False


def _sha256_string(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _canonical_control_session_roster():
    source = _read_owned_file_snapshot(ROOT, "evidence/v02-roster.json",
        label="canonical-control-session-roster")
    try:
        document = json.loads(source)
        if not isinstance(document, dict) or document.get("schema") != "genewhip-v02-roster-v1":
            raise ValueError("transfer-control-session-roster-source-invalid")
        roster = document["matrix"]["control_session_roster"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ValueError("transfer-control-session-roster-source-invalid") from error
    expected_keys = {"schema", "sessions", "controls", "sha256"}
    if (not isinstance(roster, dict) or set(roster) != expected_keys
            or roster.get("schema") != "phase6-control-session-roster-v1"
            or not _sha256_string(roster.get("sha256"))):
        raise ValueError("transfer-control-session-roster-source-invalid")
    return roster


def _validate_hash_metadata(role, value):
    digest = value.get("sha256")
    if not _sha256_string(digest) or "retained_path" in value:
        return False
    if role in {"stdout", "stderr"} and "path" in value:
        expected = {"observed_bytes", "path", "retained_bytes", "sha256", "truncated"}
        relative = value.get("path")
        role_suffix = "stdout" if role == "stdout" else "stderr"
        stream_path = (
            r"build/v02/runtime/core-work/canonical-core-[A-Za-z0-9_-]+/controls-[12]/artifacts/"
            r"(?:title-no-start|start-idle|start-move|action-sound|action-no-trigger|sustained-play)/"
            r"headless/child\." + role_suffix + r"\.raw"
        )
        observed, retained = value.get("observed_bytes"), value.get("retained_bytes")
        if (set(value) != expected or not isinstance(relative, str)
                or type(observed) is not int or observed < 0 or type(retained) is not int
                or retained < 0 or not isinstance(value.get("truncated"), bool)):
            return False
        if role == "stdout" and CONTROL_FIELD_NAME.fullmatch(relative):
            return (observed == retained and observed <= CONTROL_FIELD_LOG_MAX_BYTES
                    and value["truncated"] is False)
        return (re.fullmatch(stream_path, relative) is not None
                and retained <= observed and (value["truncated"] or retained == observed))
    if "path" in value:
        return False
    if role == "route_metadata":
        return (set(value) == {"client", "map_id", "original_input_sha256", "schema", "sha256"}
                and value.get("client") == "sdl"
                and value.get("map_id") == "recursion94-genewhip-public-client-v1"
                and _sha256_string(value.get("original_input_sha256"))
                and value.get("schema") == "genewhip-consumed-input-map-v1")
    if role == "control_session_roster":
        return (set(value) == {"schema", "sessions", "controls", "sha256"}
                and _sha256_string(value.get("sha256"))
                and value == _canonical_control_session_roster())
    if role in {"stdout", "stderr"}:
        expected = {"observed_bytes", "retained_bytes", "sha256", "truncated"}
        if set(value) not in (expected, expected | {"text"}):
            return False
        observed, retained = value.get("observed_bytes"), value.get("retained_bytes")
        return (type(observed) is int and observed >= 0 and type(retained) is int
                and 0 <= retained <= observed and isinstance(value.get("truncated"), bool)
                and (value["truncated"] or retained == observed)
                and ("text" not in value or isinstance(value["text"], str)))
    if role == "compiler_metadata":
        source_path = value.get("source_path")
        source_pattern = (
            r"build/v02/runtime-build/CMakeFiles/[0-9]+(?:\.[0-9]+){1,2}/CMakeCCompiler\.cmake|"
            r"build/v02/runtime/safety/(?:asan-ubsan|hooks-off)/CMakeFiles/[0-9]+(?:\.[0-9]+){1,2}/CMakeCCompiler\.cmake"
        )
        return (set(value) == {"sha256", "size", "source_path"}
                and type(value.get("size")) is int and value["size"] > 0
                and isinstance(source_path, str) and re.fullmatch(source_pattern, source_path) is not None)
    if role == "raw_build_artifact_identities":
        source_path = value.get("source_path")
        source_pattern = (
            r"build/v02/runtime-build/(?:CMakeCache\.txt|CMakeFiles/[0-9]+(?:\.[0-9]+){1,2}/CMakeCCompiler\.cmake|"
            r"(?:bus_boundary_contract|gameplay_bus_contract|gw_bounded_fuzz|load_contract|movem_contract|"
            r"phase6_repairs_contract|phase6_safety|reset_contract|time_contract)|"
            r"tools/session/(?:input_log_contract|phase6_chunk_contract|session_contract))|"
            r"build/v02/runtime/safety/(?:asan-ubsan|hooks-off)/(?:CMakeCache\.txt|"
            r"CMakeFiles/[0-9]+(?:\.[0-9]+){1,2}/CMakeCCompiler\.cmake|"
            r"(?:bus_boundary_contract|gameplay_bus_contract|gw_bounded_fuzz|load_contract|movem_contract|"
            r"phase6_repairs_contract|phase6_safety|reset_contract|time_contract)|"
            r"tools/session/(?:input_log_contract|phase6_chunk_contract|session_contract))"
        )
        return (set(value) == {"sha256", "size", "source_path"}
                and type(value.get("size")) is int and value["size"] > 0
                and isinstance(source_path, str) and re.fullmatch(source_pattern, source_path) is not None)
    return False


def _classify_reference(role, value):
    """Classify only the exact runtime artifact refs and known identity metadata records."""
    has_path = "path" in value or "retained_path" in value
    has_digest = "sha256" in value
    if role in IDENTITY_REFERENCE_PATHS:
        expected_keys = {"path", "sha256"}
        if role == "delivery_map_identity":
            expected_keys.add("schema")
        if (set(value) != expected_keys or value.get("path") != IDENTITY_REFERENCE_PATHS[role]
                or not _sha256_string(value.get("sha256"))
                or (role == "delivery_map_identity"
                    and value.get("schema") != "genewhip-consumed-input-map-v1")):
            raise ValueError("transfer-identity-role-or-reference-invalid:" + role)
        return "identity"
    if role in HASH_METADATA_ROLES:
        if not _validate_hash_metadata(role, value):
            raise ValueError("transfer-hash-metadata-invalid:" + role)
        if "path" in value:
            if role == "stdout" and CONTROL_FIELD_NAME.fullmatch(value["path"]):
                return "control-field-log"
            return "stream"
        if role in {"compiler_metadata", "raw_build_artifact_identities"}:
            return "build-identity"
        return "metadata"
    if not has_path and not has_digest:
        return None
    if (not has_path or "path" not in value or "retained_path" in value
            or not isinstance(value.get("path"), str)
            or not _sha256_string(value.get("sha256"))
            or not _role_allows(role, value["path"])):
        raise ValueError("transfer-reference-role-or-identity-invalid:" + role)
    return "artifact"


def _control_case_contract():
    """Load and pin the public control IDs and expected field counts from their fixture source."""
    source = _read_owned_file_snapshot(ROOT, "fixtures/independent-game-v2/scenario.json",
        label="canonical-independent-game-control-scenarios", max_bytes=MAX_FILE_BYTES)
    try:
        document = json.loads(source)
        cases = document["cases"]
        if (not isinstance(document, dict) or document.get("schema_version") != 1
                or document.get("fixture_id") != "genewhip-independent-game-v2"
                or not isinstance(cases, list)):
            raise ValueError("transfer-control-field-source-invalid")
        rows = {}
        for case in cases:
            if (not isinstance(case, dict) or not isinstance(case.get("id"), str)
                    or type(case.get("frames")) is not int or case["frames"] <= 0
                    or case["id"] in rows):
                raise ValueError("transfer-control-field-source-invalid")
            rows[case["id"]] = case["frames"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ValueError("transfer-control-field-source-invalid") from error
    if tuple(rows) != CONTROL_CASE_IDS:
        raise ValueError("transfer-control-field-source-invalid")
    return document, rows, _sha(source)


def _control_field_log_name(name):
    match = CONTROL_FIELD_NAME.fullmatch(name) if isinstance(name, str) else None
    if match is None:
        return None
    parts = pathlib.PurePosixPath(name).parts
    return {"repetition": int(match.group(1)), "case": match.group(2),
        "prefix": "/".join(parts[:5])}


def _json_object_no_duplicates(pairs):
    value = {}
    for key, child in pairs:
        if key in value:
            raise ValueError("duplicate-json-key")
        value[key] = child
    return value


def _reject_json_constant(_value):
    raise ValueError("nonfinite-json-number")


def _validate_control_field_log(name, data):
    """Validate the exact line grammar emitted by the three session.c field-log writers."""
    contract = _control_field_log_name(name)
    if contract is None or not isinstance(data, bytes) or not data or len(data) > CONTROL_FIELD_LOG_MAX_BYTES:
        raise ValueError("transfer-control-field-log-path-or-size-invalid")
    _source, case_frames, _source_sha256 = _control_case_contract()
    expected_fields = case_frames[contract["case"]]
    if not data.endswith(b"\n") or b"\r" in data:
        raise ValueError("transfer-control-field-log-line-ending-invalid")
    lines = data.splitlines(keepends=True)
    if len(lines) != expected_fields + 2 or any(line == b"\n" for line in lines):
        raise ValueError("transfer-control-field-log-row-count-invalid")
    field_keys = ("sequence", "width", "height", "pitch_bytes", "end_tick", "fnv1a64")
    final_keys = ("fields", "ram_fnv1a64", "peek", "unsupported", "stop_reason",
        "instruction_address", "opcode", "fault_address")
    audio_keys = ("audio_rate_hz", "mix_id", "filter_id", "frames", "lost", "clipped",
        "complete", "fnv1a64")
    uint64_max = (1 << 64) - 1
    uint32_max = (1 << 32) - 1

    def parse_line(raw):
        if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
            raise ValueError("transfer-control-field-log-line-invalid")
        try:
            value = json.loads(raw[:-1].decode("utf-8", "strict"),
                object_pairs_hook=_json_object_no_duplicates, parse_constant=_reject_json_constant)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise ValueError("transfer-control-field-log-json-invalid") from error
        if not isinstance(value, dict):
            raise ValueError("transfer-control-field-log-row-not-object")
        return value

    previous_tick = -1
    for index, raw in enumerate(lines[:expected_fields]):
        row = parse_line(raw)
        if tuple(row) != field_keys:
            raise ValueError("transfer-control-field-log-field-shape-invalid")
        if (type(row["sequence"]) is not int or row["sequence"] != index
                or type(row["width"]) is not int or row["width"] != 256
                or type(row["height"]) is not int or row["height"] != 224
                or type(row["pitch_bytes"]) is not int or row["pitch_bytes"] != 1280
                or type(row["end_tick"]) is not int or not 0 <= row["end_tick"] <= uint64_max
                or row["end_tick"] <= previous_tick
                or not isinstance(row["fnv1a64"], str)
                or re.fullmatch(r"[0-9a-f]{16}", row["fnv1a64"]) is None):
            raise ValueError("transfer-control-field-log-field-value-invalid")
        previous_tick = row["end_tick"]

    final = parse_line(lines[expected_fields])
    if tuple(final) != final_keys:
        raise ValueError("transfer-control-field-log-final-shape-invalid")
    if (type(final["fields"]) is not int or final["fields"] != expected_fields
            or not isinstance(final["ram_fnv1a64"], str)
            or re.fullmatch(r"[0-9a-f]{16}", final["ram_fnv1a64"]) is None
            or not isinstance(final["peek"], str)
            or re.fullmatch(r"[0-9a-f]{8}", final["peek"]) is None
            or any(type(final[key]) is not int or not 0 <= final[key] <= uint32_max
                for key in final_keys[4:])
            or type(final["unsupported"]) is not int or final["unsupported"] not in (0, 1)):
        raise ValueError("transfer-control-field-log-final-value-invalid")

    audio = parse_line(lines[expected_fields + 1])
    if tuple(audio) != audio_keys:
        raise ValueError("transfer-control-field-log-audio-shape-invalid")
    if (type(audio["audio_rate_hz"]) is not int or audio["audio_rate_hz"] != 48000
            or any(type(audio[key]) is not int or not 0 <= audio[key] <= uint32_max
                for key in ("mix_id", "filter_id"))
            or any(type(audio[key]) is not int or not 0 <= audio[key] <= uint64_max
                for key in ("frames", "lost", "clipped"))
            or audio["complete"] is not True
            or not isinstance(audio["fnv1a64"], str)
            or re.fullmatch(r"[0-9a-f]{16}", audio["fnv1a64"]) is None):
        raise ValueError("transfer-control-field-log-audio-value-invalid")


def _validate_control_stdout_reference(document_name, value):
    info = _control_field_log_name(value.get("path"))
    parent = re.fullmatch(
        r"(build/v02/runtime/core-work/canonical-core-[A-Za-z0-9_-]{8})/controls-([12])/control\.json",
        document_name or "")
    if (info is None or parent is None or info["prefix"] != parent.group(1)
            or info["repetition"] != int(parent.group(2))):
        raise ValueError("transfer-control-field-log-report-binding-invalid")


def _validate_control_report(document_name, document):
    match = re.fullmatch(
        r"(build/v02/runtime/core-work/canonical-core-[A-Za-z0-9_-]{8})/controls-([12])/control\.json",
        document_name or "")
    if match is None:
        return
    result_rows = document.get("results")
    native_rows = document.get("native_child_processes")
    has_typed_field_log = (
        isinstance(result_rows, list)
        and any(isinstance(row, dict)
            and isinstance(row.get("process_streams"), dict)
            and isinstance(row["process_streams"].get("stdout"), dict)
            and _control_field_log_name(row["process_streams"]["stdout"].get("path")) is not None
            for row in result_rows)
    ) or (
        isinstance(native_rows, list)
        and any(isinstance(row, dict)
            and isinstance(row.get("streams"), dict)
            and isinstance(row["streams"].get("stdout"), dict)
            and _control_field_log_name(row["streams"]["stdout"].get("path")) is not None
            for row in native_rows)
    )
    if not has_typed_field_log:
        return
    scenario, case_frames, scenario_sha256 = _control_case_contract()
    if (document.get("schema") != "genewhip-phase4-gameplay-v1"
            or document.get("fixture_id") != scenario["fixture_id"]
            or document.get("source_sha256") != scenario["source"]["sha256"]
            or document.get("rom_sha256") != scenario["rom"]["sha256"]
            or document.get("scenario_sha256") != scenario_sha256):
        raise ValueError("transfer-control-field-report-source-binding-invalid")
    results = document.get("results")
    native = document.get("native_child_processes")
    if (not isinstance(results, list) or not isinstance(native, list)
            or [row.get("id") for row in results if isinstance(row, dict)] != list(CONTROL_CASE_IDS)
            or [row.get("case") for row in native if isinstance(row, dict)] != list(CONTROL_CASE_IDS)
            or len(results) != len(CONTROL_CASE_IDS) or len(native) != len(CONTROL_CASE_IDS)):
        raise ValueError("transfer-control-field-report-case-roster-invalid")
    repetition = int(match.group(2))
    for result, child in zip(results, native):
        case_id = result["id"]
        expected_path = (match.group(1) + f"/controls-{repetition}/artifacts/{case_id}/"
            "headless/child.stdout.raw")
        expected_fields = case_frames[case_id]
        process_streams = result.get("process_streams")
        child_streams = child.get("streams")
        stdout = process_streams.get("stdout") if isinstance(process_streams, dict) else None
        child_stdout = child_streams.get("stdout") if isinstance(child_streams, dict) else None
        process = result.get("process")
        if (not isinstance(stdout, dict) or stdout != child_stdout
                or stdout.get("path") != expected_path or stdout.get("truncated") is not False
                or type(stdout.get("observed_bytes")) is not int
                or stdout["observed_bytes"] != stdout.get("retained_bytes")
                or stdout["observed_bytes"] > CONTROL_FIELD_LOG_MAX_BYTES
                or not _sha256_string(stdout.get("sha256"))
                or result.get("fields") != expected_fields
                or not isinstance(process, dict)
                or process.get("stdout_sha256") != stdout["sha256"]
                or process.get("stdout_bytes") != stdout["observed_bytes"]
                or child.get("stdout_sha256") != stdout["sha256"]
                or child.get("stdout_bytes") != stdout["observed_bytes"]):
            raise ValueError("transfer-control-field-report-stream-binding-invalid:" + case_id)


def _validate_control_field_log_graph(documents, members):
    """Join the 12 field logs to their paired control reports and one candidate prefix."""
    field_names = {name for name in members if _control_field_log_name(name) is not None}
    if not field_names:
        return
    control_names = {name for name in documents if name.endswith("/control.json")
        and re.fullmatch(r"build/v02/runtime/core-work/canonical-core-[A-Za-z0-9_-]{8}/controls-[12]/control\.json", name)}
    if len(field_names) != 12 or len(control_names) != 2:
        raise ValueError("transfer-control-field-log-roster-incomplete")
    prefix = next(iter(_control_field_log_name(name)["prefix"] for name in field_names))
    expected_controls = {prefix + "/controls-1/control.json", prefix + "/controls-2/control.json"}
    if control_names != expected_controls:
        raise ValueError("transfer-control-field-log-prefix-roster-invalid")
    _scenario, _case_frames, _scenario_sha256 = _control_case_contract()
    expected_names = {prefix + f"/controls-{repetition}/artifacts/{case}/headless/child.stdout.raw"
        for repetition in (1, 2) for case in CONTROL_CASE_IDS}
    if field_names != expected_names:
        raise ValueError("transfer-control-field-log-case-roster-invalid")
    per_case = {}
    for name in sorted(control_names):
        document = documents[name]
        _validate_control_report(name, document)
        for result in document["results"]:
            ref = result["process_streams"]["stdout"]
            facts = (ref["sha256"], ref["observed_bytes"])
            prior = per_case.setdefault(result["id"], facts)
            if prior != facts:
                raise ValueError("transfer-control-field-log-repeat-digest-mismatch:" + result["id"])
    core_report_name = "build/v02/runtime-observation/core-report.json"
    core_report = documents.get(core_report_name)
    if not isinstance(core_report, dict):
        raise ValueError("transfer-control-field-log-core-report-missing")
    candidate_ref = core_report.get("candidate_manifest")
    control_refs = core_report.get("controls")
    expected_candidate = prefix + "/candidate.json"
    if (not isinstance(candidate_ref, dict) or candidate_ref.get("path") != expected_candidate
            or expected_candidate not in members
            or not isinstance(control_refs, list) or len(control_refs) != 2
            or {row.get("path") for row in control_refs if isinstance(row, dict)} != expected_controls
            or any(members.get(row["path"], {}).get("sha256") != row.get("sha256")
                for row in control_refs if isinstance(row, dict))):
        raise ValueError("transfer-control-field-log-candidate-prefix-binding-invalid")
    candidate_document = documents.get(expected_candidate)
    if (not isinstance(candidate_document, dict)
            or candidate_document.get("schema") != "genewhip-phase6-candidate-v1"
            or members.get(expected_candidate, {}).get("sha256") != candidate_ref.get("sha256")):
        raise ValueError("transfer-control-field-log-candidate-prefix-binding-invalid")


def _verify_identity_reference(root, role, value, *, root_fd=None):
    """Confirm source/build identity bytes while deliberately excluding them from export."""
    name = value["path"]
    data = _read_owned_file_snapshot(root, name, label="identity:" + role, root_fd=root_fd)
    if role in {"delivery_map", "delivery_map_identity"}:
        try:
            canonical = json.dumps(json.loads(data.decode("utf-8")),
                sort_keys=True, separators=(",", ":")).encode("utf-8")
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("transfer-identity-source-file-invalid:" + role) from error
        data = canonical
    if _sha(data) != value["sha256"]:
        raise ValueError("transfer-identity-source-digest-mismatch:" + role)


def _verify_stream_reference(root, role, value, *, root_fd=None):
    """Verify a bounded child output digest without exporting the raw stream."""
    data = _read_owned_file_snapshot(root, value["path"], label="stream:" + role,
        expected_size=value["retained_bytes"], root_fd=root_fd)
    if _sha(data) != value["sha256"]:
        raise ValueError("transfer-stream-source-digest-mismatch:" + role)


def _verify_build_identity_reference(root, role, value, *, root_fd=None):
    """Check a named build identity while keeping the build artifact out of transfer."""
    data = _read_owned_file_snapshot(root, value["source_path"], label="build-identity:" + role,
        expected_size=value["size"], root_fd=root_fd)
    if _sha(data) != value["sha256"]:
        raise ValueError("transfer-build-identity-source-digest-mismatch:" + role)


def _file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
        info.st_uid, info.st_gid, info.st_mtime_ns, info.st_ctime_ns)


def _directory_identity(info):
    return info.st_dev, info.st_ino, info.st_mode


def _root_directory_open_flags(label):
    directory = getattr(os, "O_DIRECTORY", None)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if directory is None or nofollow is None:
        raise ValueError("transfer-owned-file-open-flags-unavailable:" + label)
    return os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)


def _open_trusted_root(root, label):
    """Open a resolved root directory and bind its pathname to the descriptor."""
    root_fd = None
    try:
        root_path = pathlib.Path(root).resolve(strict=True)
        before_path = os.stat(root_path, follow_symlinks=False)
        if not stat.S_ISDIR(before_path.st_mode):
            raise ValueError("transfer-owned-root-invalid:" + label)
        root_fd = os.open(root_path, _root_directory_open_flags(label))
        after_fd = os.fstat(root_fd)
        if (not stat.S_ISDIR(after_fd.st_mode)
                or _directory_identity(before_path) != _directory_identity(after_fd)):
            raise ValueError("transfer-owned-root-changed:" + label)
        return root_path, root_fd
    except OSError as error:
        if root_fd is not None:
            os.close(root_fd)
        raise ValueError("transfer-owned-root-open-failed:" + label) from error
    except BaseException:
        if root_fd is not None:
            os.close(root_fd)
        raise


def _check_root_binding(root_path, root_fd, label):
    try:
        path_info = os.stat(root_path, follow_symlinks=False)
        fd_info = os.fstat(root_fd)
    except OSError as error:
        raise ValueError("transfer-owned-root-changed:" + label) from error
    if (not stat.S_ISDIR(path_info.st_mode) or not stat.S_ISDIR(fd_info.st_mode)
            or _directory_identity(path_info) != _directory_identity(fd_info)):
        raise ValueError("transfer-owned-root-changed:" + label)


def _open_parent_directory(root_fd, parts, label):
    directory_flags = _root_directory_open_flags(label)
    current_fd = os.dup(root_fd)
    identities = []
    try:
        for part in parts:
            next_fd = None
            try:
                next_fd = os.open(part, directory_flags, dir_fd=current_fd)
                info = os.fstat(next_fd)
                if not stat.S_ISDIR(info.st_mode):
                    raise ValueError("transfer-owned-parent-invalid:" + label)
                identities.append((part, _directory_identity(info)))
                os.close(current_fd)
                current_fd = next_fd
                next_fd = None
            finally:
                if next_fd is not None:
                    os.close(next_fd)
        return current_fd, identities
    except BaseException:
        os.close(current_fd)
        raise


def _validate_parent_binding(root_fd, parts, identities, label):
    current_fd, observed = _open_parent_directory(root_fd, parts, label)
    try:
        if observed != identities:
            raise ValueError("transfer-owned-parent-changed:" + label)
    finally:
        os.close(current_fd)


def _open_or_create_install_parent(root_path, root_fd, parts, label):
    """Open/create an install parent chain without leaving the destination root."""
    directory_flags = _root_directory_open_flags(label)
    current_fd = os.dup(root_fd)
    identities = []
    try:
        for part in parts:
            next_fd = None
            try:
                try:
                    next_fd = os.open(part, directory_flags, dir_fd=current_fd)
                except FileNotFoundError:
                    try:
                        os.mkdir(part, 0o777, dir_fd=current_fd)
                    except FileExistsError:
                        # Re-open below with O_NOFOLLOW; a racing symlink is rejected.
                        pass
                    next_fd = os.open(part, directory_flags, dir_fd=current_fd)
                info = os.fstat(next_fd)
                if not stat.S_ISDIR(info.st_mode):
                    raise ValueError("transfer-install-parent-invalid:" + label)
                identities.append((part, _directory_identity(info)))
                os.close(current_fd)
                current_fd = next_fd
                next_fd = None
            finally:
                if next_fd is not None:
                    os.close(next_fd)
        _check_root_binding(root_path, root_fd, label)
        _validate_parent_binding(root_fd, parts, identities, label)
        return current_fd, identities
    except OSError as error:
        os.close(current_fd)
        raise ValueError("transfer-install-parent-open-failed:" + label) from error
    except BaseException:
        os.close(current_fd)
        raise


def _write_install_snapshot(root_path, root_fd, relative, data, facts):
    """Create one installed member beneath a held root using only verified bytes."""
    label = "runtime-transfer-install:" + relative
    if not isinstance(relative, str):
        raise ValueError("transfer-install-path-invalid:" + str(relative))
    relative_path = pathlib.PurePosixPath(relative)
    if (not relative or relative_path.is_absolute()
            or not relative_path.parts or ".." in relative_path.parts or "\\" in relative):
        raise ValueError("transfer-install-path-invalid:" + str(relative))
    if (not isinstance(data, bytes) or type(facts.get("size")) is not int
            or len(data) != facts["size"] or len(data) > MAX_FILE_BYTES
            or not _sha256_string(facts.get("sha256"))
            or _sha(data) != facts["sha256"]):
        raise ValueError("transfer-install-verified-snapshot-invalid:" + relative)

    parent_fd = None
    descriptor = None
    created_identity = None
    installed = False
    leaf = relative_path.parts[-1]
    parent_parts = relative_path.parts[:-1]
    try:
        parent_fd, parent_identities = _open_or_create_install_parent(
            root_path, root_fd, parent_parts, label)
        _check_root_binding(root_path, root_fd, label)
        _validate_parent_binding(root_fd, parent_parts, parent_identities, label)
        nofollow = getattr(os, "O_NOFOLLOW", None)
        nonblock = getattr(os, "O_NONBLOCK", None)
        if nofollow is None or nonblock is None:
            raise ValueError("transfer-install-open-flags-unavailable:" + relative)
        flags = (os.O_RDWR | os.O_CREAT | os.O_EXCL | nofollow | nonblock
            | getattr(os, "O_CLOEXEC", 0))
        try:
            descriptor = os.open(leaf, flags, 0o666, dir_fd=parent_fd)
        except FileExistsError as error:
            raise ValueError("transfer-install-collision:" + relative) from error
        before_fd = os.fstat(descriptor)
        created_identity = (before_fd.st_dev, before_fd.st_ino)
        if (not stat.S_ISREG(before_fd.st_mode) or before_fd.st_nlink != 1
                or before_fd.st_size != 0):
            raise ValueError("transfer-install-destination-invalid:" + relative)

        offset = 0
        view = memoryview(data)
        while offset < len(data):
            try:
                written = os.write(descriptor, view[offset:])
            except InterruptedError:
                continue
            if written <= 0:
                raise ValueError("transfer-install-write-failed:" + relative)
            offset += written

        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, facts["size"] - total + 1))
            if not block:
                break
            total += len(block)
            if total > facts["size"] or total > MAX_FILE_BYTES:
                raise ValueError("transfer-install-size-mismatch:" + relative)
            digest.update(block)
        after_fd = os.fstat(descriptor)
        after_path = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(after_fd.st_mode) or after_fd.st_nlink != 1
                or after_fd.st_size != facts["size"] or total != facts["size"]
                or digest.hexdigest() != facts["sha256"]
                or _file_identity(after_fd) != _file_identity(after_path)):
            raise ValueError("transfer-install-identity-mismatch:" + relative)
        _validate_parent_binding(root_fd, parent_parts, parent_identities, label)
        _check_root_binding(root_path, root_fd, label)
        installed = True
        return
    except OSError as error:
        raise ValueError("transfer-install-write-failed:" + relative) from error
    finally:
        try:
            if descriptor is not None:
                if not installed and created_identity is not None and parent_fd is not None:
                    try:
                        current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                        if (current.st_dev, current.st_ino) == created_identity:
                            os.unlink(leaf, dir_fd=parent_fd)
                    except FileNotFoundError:
                        pass
                    except OSError:
                        pass
                os.close(descriptor)
        finally:
            if parent_fd is not None:
                os.close(parent_fd)


def _relative_entry_exists(root_fd, relative, label):
    relative_path = pathlib.PurePosixPath(relative)
    if (not relative_path.parts or relative_path.is_absolute()
            or ".." in relative_path.parts or "\\" in relative):
        raise ValueError("transfer-owned-file-path-invalid:" + label)
    try:
        parent_fd, _identities = _open_parent_directory(root_fd, relative_path.parts[:-1], label)
    except FileNotFoundError:
        return False
    try:
        try:
            os.stat(relative_path.parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False
    finally:
        os.close(parent_fd)


def _read_owned_file_snapshot(root, relative, *, label, expected_size=None,
                              max_bytes=MAX_FILE_BYTES, root_fd=None):
    """Read a bounded file beneath a descriptor-bound root without following links."""
    if not isinstance(relative, str):
        raise ValueError("transfer-owned-file-path-invalid:" + label)
    relative_path = pathlib.PurePosixPath(relative)
    if (not relative or relative_path.is_absolute() or not relative_path.parts
            or ".." in relative_path.parts or "\\" in relative):
        raise ValueError("transfer-owned-file-path-invalid:" + label)
    if type(max_bytes) is not int or max_bytes < 0:
        raise ValueError("transfer-owned-file-size-limit:" + label)
    owned_root = root_fd is None
    root_path = pathlib.Path(root).resolve(strict=True)
    if owned_root:
        root_path, root_fd = _open_trusted_root(root_path, label)
    else:
        _check_root_binding(root_path, root_fd, label)
    parent_fd = None
    descriptor = None
    leaf = relative_path.parts[-1]
    limit = min(MAX_FILE_BYTES, max_bytes)
    try:
        parent_fd, parent_identities = _open_parent_directory(
            root_fd, relative_path.parts[:-1], label)
        _check_root_binding(root_path, root_fd, label)
        before_path = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(before_path.st_mode) or before_path.st_nlink != 1
                or before_path.st_size < 0
                or (expected_size is not None and before_path.st_size != expected_size)):
            raise ValueError("transfer-owned-file-invalid:" + label)
        if before_path.st_size > limit:
            raise ValueError("transfer-owned-file-size-limit:" + label)
        nofollow = getattr(os, "O_NOFOLLOW", None)
        nonblock = getattr(os, "O_NONBLOCK", None)
        if nofollow is None or nonblock is None:
            raise ValueError("transfer-owned-file-open-flags-unavailable:" + label)
        flags = os.O_RDONLY | nofollow | nonblock | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(leaf, flags, dir_fd=parent_fd)
        before_fd = os.fstat(descriptor)
        if (not stat.S_ISREG(before_fd.st_mode) or before_fd.st_nlink != 1
                or before_fd.st_size < 0
                or _file_identity(before_path) != _file_identity(before_fd)
                or (expected_size is not None and before_fd.st_size != expected_size)):
            raise ValueError("transfer-owned-file-invalid:" + label)
        if before_fd.st_size > limit:
            raise ValueError("transfer-owned-file-size-limit:" + label)
        blocks = []
        total = 0
        while True:
            request = min(1024 * 1024, limit - total + 1)
            block = os.read(descriptor, request)
            if not block:
                break
            total += len(block)
            if total > limit:
                raise ValueError("transfer-owned-file-size-limit:" + label)
            blocks.append(block)
        after_fd = os.fstat(descriptor)
        after_path = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(after_fd.st_mode) or after_fd.st_nlink != 1
                or _file_identity(before_fd) != _file_identity(after_fd)
                or _file_identity(after_fd) != _file_identity(after_path)
                or total != after_fd.st_size
                or (expected_size is not None and total != expected_size)):
            raise ValueError("transfer-owned-file-changed-during-read:" + label)
        _validate_parent_binding(root_fd, relative_path.parts[:-1], parent_identities, label)
        _check_root_binding(root_path, root_fd, label)
        return b"".join(blocks)
    except OSError as error:
        raise ValueError("transfer-owned-file-read-failed:" + label) from error
    finally:
        try:
            if descriptor is not None:
                os.close(descriptor)
        finally:
            try:
                if parent_fd is not None:
                    os.close(parent_fd)
            finally:
                if owned_root:
                    os.close(root_fd)


def _canonical_public_schema_bytes():
    source = _read_owned_file_snapshot(ROOT, CANONICAL_SCHEMA_SOURCE,
        label="canonical-public-schema")
    try:
        document = json.loads(source)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("transfer-public-schema-source-invalid") from error
    if not isinstance(document, dict) or document.get("schema") != "genewhip-v02-schema-document-v1":
        raise ValueError("transfer-public-schema-source-invalid")
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _validate_references(value, members, role="", *, document_name=None,
                         document_bytes=None, reference_visitor=None):
    """Validate references in a named document, with one bound structural schema role."""
    if role == "" and document_name == PUBLIC_SCHEMA_MEMBER:
        if not isinstance(document_bytes, (bytes, bytearray)):
            raise ValueError("transfer-public-schema-bytes-required")
        try:
            parsed_bytes = json.loads(document_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("transfer-public-schema-document-invalid") from error
        if parsed_bytes != value or bytes(document_bytes) != _canonical_public_schema_bytes():
            raise ValueError("transfer-public-schema-not-canonical")
        return
    if reference_visitor is not None:
        reference_visitor(value)
        return
    if isinstance(value, dict):
        classification = _classify_reference(role, value)
        if classification in {"artifact", "control-field-log"}:
            relative, digest = value["path"], value["sha256"]
            if relative not in members or members[relative].get("sha256") != digest:
                raise ValueError("transfer-reference-role-or-identity-invalid:" + role)
            if classification == "control-field-log":
                _validate_control_stdout_reference(document_name, value)
                if (type(value.get("observed_bytes")) is not int
                        or value["observed_bytes"] != value.get("retained_bytes")
                        or members[relative].get("size") != value["observed_bytes"]):
                    raise ValueError("transfer-control-field-log-size-binding-invalid")
        for key, child in value.items():
            _validate_references(child, members, key, document_name=document_name)
    elif isinstance(value, list):
        for child in value:
            _validate_references(child, members, role, document_name=document_name)


def _load_benchmark_module():
    spec = importlib.util.spec_from_file_location("gw_v02_transfer_benchmark",
        ROOT / "tools/evidence/core_benchmark.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read_qualification_scope(root, explicit=None):
    """Read the exact repository-pinned public scope as one verified snapshot."""
    try:
        return _SCOPE.read_scope(root, explicit,
            scope_path=os.environ.get("GENEWHIP_QUALIFICATION_SCOPE_PATH", ""),
            scope_sha256=os.environ.get("GENEWHIP_QUALIFICATION_SCOPE_SHA256", ""))
    except _SCOPE.ScopeSelectionError as error:
        label = ("transfer-qualification-scope-not-selected" if error.reason == "not-selected"
                 else "transfer-qualification-scope-profile-invalid")
        raise ValueError(label) from None


def _qualification_scope_path(root, explicit=None):
    """Compatibility wrapper for callers that need only the selected path."""
    path, _raw = _read_qualification_scope(root, explicit)
    return path


def validate_benchmark_report(report_path, workload, scope_path, *, source_sha, head_sha,
                              base_sha, run_id, run_attempt):
    """Validate and privacy-scan one report before its independent CI upload."""
    _scope_path, scope_bytes = _read_qualification_scope(ROOT, scope_path)
    return _validate_benchmark_report_snapshot(report_path, workload, scope_bytes,
        source_sha=source_sha, head_sha=head_sha, base_sha=base_sha,
        run_id=run_id, run_attempt=run_attempt)


def _validate_benchmark_report_snapshot(report_path, workload, scope_bytes, *, source_sha,
                                        head_sha, base_sha, run_id, run_attempt):
    """Validate against one already-selected scope byte snapshot."""
    report_path = pathlib.Path(report_path)
    report_bytes = report_path.read_bytes()
    document = json.loads(report_bytes)
    if not isinstance(document, dict):
        raise ValueError("transfer-benchmark-report-object-required")
    scope = json.loads(scope_bytes)
    scope_sha256 = _sha(scope_bytes)
    if document.get("scope_sha256") != scope_sha256:
        raise ValueError("transfer-benchmark-scope-digest-mismatch")
    validator = _load_benchmark_module()
    errors = validator.validate_workload_report(document, workload, validator.source_identity(), scope["scope_id"])
    expected = {"source_revision": source_sha, "head_sha": head_sha, "base_sha": base_sha,
        "run_id": str(run_id), "run_attempt": str(run_attempt)}
    if errors or any(document.get(key) != value for key, value in expected.items()):
        raise ValueError("transfer-benchmark-invalid:" + workload + ":" + ",".join(errors))
    _scan_content(report_bytes, label="benchmark-" + workload)
    return document


def _scan_content(data, *, label):
    if PERSONAL_PATH.search(data): raise ValueError("transfer-private-path:" + label)
    if EMAIL.search(data): raise ValueError("transfer-private-email:" + label)
    if SECRET.search(data): raise ValueError("transfer-secret-pattern:" + label)
    if label.endswith(".json") or label.startswith("benchmark-"):
        try:
            _scan_fields(json.loads(data))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("transfer-json-invalid:" + label) from error


def _package_asset_names(source_sha):
    suffix = source_sha[:12]
    archives = (f"genewhip-0.2.0-sdk-diagnostic-darwin-arm64-{suffix}.tar.gz",
        f"genewhip-0.2.0-playable-preview-macos-arm64-{suffix}.tar.gz")
    return {name for archive in archives for name in
        (archive, archive + ".sha256", archive + ".qualification.json")}


def _package_closure_member_allowed(name):
    return name in PACKAGE_FIXED_MEMBERS or _runtime_member_allowed(name)


def expected_package_members(source_sha, closure_paths=()):
    names = set(PACKAGE_FIXED_MEMBERS)
    names.update(closure_paths)
    for name in _package_asset_names(source_sha):
        names.add("artifacts/v02/" + name)
        names.add("artifacts/release-assets/" + name)
    return names


def _current_git_revision(root):
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
        capture_output=True, text=True, timeout=10)
    revision = result.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("transfer-current-git-revision-invalid")
    return revision


def _current_product_content_sha256(root):
    run_spec = importlib.util.spec_from_file_location("gw_transfer_current_v02_run",
        root / "scripts/evidence/v02_run.py")
    run_module = importlib.util.module_from_spec(run_spec)
    run_spec.loader.exec_module(run_module)
    run_module.ROOT = root
    route_spec = importlib.util.spec_from_file_location("gw_transfer_current_phase6_routes",
        root / "scripts/evidence/phase6_routes.py")
    route_module = importlib.util.module_from_spec(route_spec)
    route_spec.loader.exec_module(route_module)
    identity = run_module.source_identity(route_module)
    digest = identity.get("source_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("transfer-current-product-content-identity-invalid")
    return digest


def _validate_runtime_identity(identity, *, expected_git_revision, expected_content_sha256):
    matrix_spec = importlib.util.spec_from_file_location("gw_transfer_runtime_identity_policy",
        ROOT / "scripts/evidence/v02_matrix.py")
    matrix_module = importlib.util.module_from_spec(matrix_spec)
    matrix_spec.loader.exec_module(matrix_module)
    try:
        matrix_module.validate_current_execution_identity(identity)
    except (ValueError, TypeError, KeyError) as error:
        raise ValueError("transfer-package-runtime-identity-invalid") from error
    git_revision = identity.get("git_head") if isinstance(identity, dict) else None
    content_sha256 = identity.get("source_sha256") if isinstance(identity, dict) else None
    if (not isinstance(git_revision, str) or not re.fullmatch(r"[0-9a-f]{40}", git_revision) or
            git_revision != expected_git_revision or
            not isinstance(content_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", content_sha256) or
            content_sha256 != expected_content_sha256):
        raise ValueError("transfer-package-source-identity-mismatch")
    return git_revision, content_sha256


def _relative_package_path(name):
    path = pathlib.PurePosixPath(name) if isinstance(name, str) else pathlib.PurePosixPath("/")
    return (isinstance(name, str) and bool(name) and not path.is_absolute() and
        ".." not in path.parts and "." not in path.parts and "\\" not in name and
        _package_closure_member_allowed(name))


def _validate_evidence_closure(root, closure, runtime_identity, *, inventory_members=None):
    """Recompute the bounded transitive references recorded by qualification close."""
    if not isinstance(closure, dict) or closure.get("schema") != "genewhip.v02-evidence-closure.v1":
        raise ValueError("transfer-package-evidence-closure-schema")
    identity = {key: runtime_identity.get(source_key) for key, source_key in (
        ("source_sha", "git_head"), ("head_sha", "git_head"), ("base_sha", "base_sha"),
        ("run_id", "run_id"), ("run_attempt", "run_attempt"))}
    if closure.get("identity") != identity:
        raise ValueError("transfer-package-evidence-closure-identity")
    dimensions = closure.get("dimensions")
    references = closure.get("referenced_files")
    if (not isinstance(dimensions, dict) or set(dimensions) != set(DIMENSIONS) or
            not isinstance(references, dict) or len(references) > MAX_MEMBERS):
        raise ValueError("transfer-package-evidence-closure-roster")

    def checked_file(name, digest):
        if (not _relative_package_path(name) or not isinstance(digest, str) or
                not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError("transfer-package-evidence-reference-path-or-digest")
        if inventory_members is not None:
            item = inventory_members.get(name)
            if not isinstance(item, dict) or item.get("sha256") != digest:
                raise ValueError("transfer-package-evidence-reference-inventory-mismatch:" + name)
        path = root / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError("transfer-package-evidence-reference-file-invalid:" + name)
        data = path.read_bytes()
        if _sha(data) != digest:
            raise ValueError("transfer-package-evidence-reference-digest-mismatch:" + name)
        if name.endswith(".json"):
            _scan(name, data, package=True)
            if _runtime_member_allowed(name):
                _validate_runtime_json(name, json.loads(data))
        elif name.endswith(".bin") and len(data) != 320 * 224 * 4:
            raise ValueError("transfer-package-field-image-size-invalid")
        return path, data

    dimension_paths = set()
    for name, row in dimensions.items():
        if (name not in PACKAGE_DIMENSION_SOURCE_PATHS or not isinstance(row, dict) or
                set(row) != {"path", "sha256", "identity"} or
                row.get("path") != PACKAGE_DIMENSION_SOURCE_PATHS[name] or
                row.get("identity") != identity):
            raise ValueError("transfer-package-evidence-dimension-row:" + str(name))
        dimension_path, _ = checked_file(row.get("path"), row.get("sha256"))
        dimension_paths.add(row["path"])
    observed = {}
    visited = set()

    def visit(value, depth=0, role=""):
        if isinstance(value, dict):
            classification = _classify_reference(role, value)
            if classification == "artifact":
                relative = value.get("path", value.get("retained_path"))
                digest = value["sha256"]
                if not _relative_package_path(relative):
                    raise ValueError("transfer-package-evidence-reference-role:" + relative)
                path, data = checked_file(relative, digest)
                prior = observed.get(relative)
                if prior is not None and prior != digest:
                    raise ValueError("transfer-package-evidence-reference-conflict:" + relative)
                observed[relative] = digest
                if path.suffix == ".json" and relative not in visited and depth < 4:
                    visited.add(relative)
                    visit(json.loads(data), depth + 1)
            elif classification == "stream":
                # Child stdout/stderr bytes stay local; the retained digest and
                # byte counts are sufficient in the transferred report.
                pass
            for key, child in value.items():
                visit(child, depth, key)
        elif isinstance(value, list):
            for child in value:
                visit(child, depth, role)

    for name, row in dimensions.items():
        path, data = checked_file(row["path"], row["sha256"])
        if path.suffix == ".json":
            visited.add(row["path"])
            visit(json.loads(data))
    if observed != references:
        raise ValueError("transfer-package-evidence-closure-incomplete-or-extra")
    return identity, references, dimension_paths


def _scan_archive_members(data, *, label):
    archive_spec = importlib.util.spec_from_file_location("gw_v02_transfer_archive_limits",
        ROOT / "scripts/package_archive.py")
    archive_module = importlib.util.module_from_spec(archive_spec)
    archive_spec.loader.exec_module(archive_module)
    archive_module.preflight_tar_gz(data, max_members=4096, max_expanded_bytes=MAX_TOTAL_BYTES)
    with tarfile.open(fileobj=__import__("io").BytesIO(data), mode="r:gz") as archive:
        for member in archive.getmembers():
            path = pathlib.PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()) or
                    path.suffix.lower() in {".rom", ".srm", ".gen", ".smd", ".sav", ".state"}):
                raise ValueError("transfer-package-archive-member-unsafe:" + label)
            if not member.isfile():
                continue
            if member.size > MAX_FILE_BYTES:
                raise ValueError("transfer-package-archive-member-size-limit:" + label)
            stream = archive.extractfile(member)
            content = stream.read(MAX_FILE_BYTES + 1) if stream else b""
            if len(content) != member.size:
                raise ValueError("transfer-package-archive-member-truncated:" + label)
            _scan_content(content, label=member.name)


def _package_files(root, *, expected_git_revision, expected_product_content_sha256):
    root = pathlib.Path(root)
    release_inventory_path = root / "artifacts/release-assets/inventory.json"
    inventory = json.loads(release_inventory_path.read_text(encoding="utf-8"))
    identity = json.loads((root / "build/v02/runtime-identity.json").read_text(encoding="utf-8"))
    git_revision, product_content_sha256 = _validate_runtime_identity(identity,
        expected_git_revision=expected_git_revision,
        expected_content_sha256=expected_product_content_sha256)
    expected_assets = _package_asset_names(git_revision)
    if inventory.get("source_revision") != git_revision or set(inventory.get("assets", {})) != expected_assets:
        raise ValueError("transfer-package-release-inventory-roster")
    closure_path = root / "build/v02/qualification-evidence-closure.json"
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    _, references, dimension_paths = _validate_evidence_closure(root, closure, identity)
    closure_paths = set(references) | dimension_paths
    expected = expected_package_members(git_revision, closure_paths)
    for name in expected:
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("transfer-package-member-missing-or-unsafe:" + name)
    return sorted(expected), git_revision, product_content_sha256, closure


def prepare_package(root, out, *, expected_source_sha):
    """Create a bounded, privacy-checked package/dimension upload inventory."""
    root = pathlib.Path(root).resolve(strict=True)
    out = pathlib.Path(out).resolve()
    if out.exists() or out.is_symlink():
        raise ValueError("transfer-package-output-collision")
    current_git_revision = _current_git_revision(root)
    if current_git_revision != expected_source_sha:
        raise ValueError("transfer-package-current-git-revision-mismatch")
    current_content_sha256 = _current_product_content_sha256(root)
    names, git_revision, product_content_sha256, _ = _package_files(root,
        expected_git_revision=current_git_revision,
        expected_product_content_sha256=current_content_sha256)
    members, total = {}, 0
    _scope_path, scope_bytes = _read_qualification_scope(root)
    identity = json.loads((root / "build/v02/runtime-identity.json").read_text(encoding="utf-8"))
    for workload in BENCHMARKS:
        _validate_benchmark_report_snapshot(
            root / f"build/v02/collected/benchmark-{workload}/benchmark-{workload}.json",
            workload, scope_bytes, source_sha=git_revision, head_sha=identity["git_head"],
            base_sha=identity["base_sha"], run_id=identity["run_id"], run_attempt=identity["run_attempt"])
    for name in names:
        path = root / name
        info = path.lstat()
        if info.st_nlink != 1 or info.st_size > MAX_FILE_BYTES:
            raise ValueError("transfer-package-member-size-or-link-limit:" + name)
        data = path.read_bytes()
        _scan(name, data, package=True)
        if name.endswith(".tar.gz"):
            _scan_archive_members(data, label=name)
        members[name] = {"sha256": _sha(data), "size": len(data)}
        total += len(data)
        if len(members) > MAX_MEMBERS or total > MAX_TOTAL_BYTES:
            raise ValueError("transfer-package-total-limit")
    payload = out / "payload"
    payload.mkdir(parents=True)
    for name, facts in members.items():
        target = payload / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / name, target)
        if target.stat().st_size != facts["size"] or _sha(target.read_bytes()) != facts["sha256"]:
            raise ValueError("transfer-package-copy-identity-mismatch:" + name)
    out.mkdir(parents=True, exist_ok=True)
    inventory = {"schema": "genewhip.v02-package-transfer.v1", "source_sha": git_revision,
        "product_content_sha256": product_content_sha256,
        "members": members, "member_count": len(members), "total_bytes": total}
    inventory_path = out / "inventory.json"
    inventory_path.write_text(json.dumps(inventory, sort_keys=True, indent=2) + "\n")
    _scan_content(inventory_path.read_bytes(), label="package-transfer-inventory.json")
    verify_package(payload, inventory_path, expected_source_sha=git_revision,
        expected_product_content_sha256=product_content_sha256)
    return inventory


def verify_package(payload_root, inventory_path, *, expected_source_sha=None,
                   expected_product_content_sha256=None):
    payload_root = pathlib.Path(payload_root).resolve(strict=True)
    inventory = json.loads(pathlib.Path(inventory_path).read_text(encoding="utf-8"))
    if expected_source_sha is None or expected_product_content_sha256 is None:
        raise ValueError("transfer-package-current-identity-required")
    if not isinstance(inventory, dict) or not isinstance(inventory.get("members"), dict):
        raise ValueError("transfer-package-inventory-schema-or-roster")
    source_sha = inventory.get("source_sha")
    product_content_sha256 = inventory.get("product_content_sha256")
    runtime_identity_path = payload_root / "build/v02/runtime-identity.json"
    if runtime_identity_path.is_symlink() or not runtime_identity_path.is_file():
        raise ValueError("transfer-package-runtime-identity-missing")
    runtime_identity = json.loads(runtime_identity_path.read_text(encoding="utf-8"))
    if (inventory.get("schema") != "genewhip.v02-package-transfer.v1" or
            not isinstance(source_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", source_sha) or
            (expected_source_sha is not None and source_sha != expected_source_sha) or
            not isinstance(product_content_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", product_content_sha256) or
            (expected_product_content_sha256 is not None and
                product_content_sha256 != expected_product_content_sha256) or
            inventory.get("member_count") != len(inventory["members"])):
        raise ValueError("transfer-package-inventory-schema-or-roster")
    _validate_runtime_identity(runtime_identity, expected_git_revision=source_sha,
        expected_content_sha256=product_content_sha256)
    closure_path = payload_root / "build/v02/qualification-evidence-closure.json"
    if closure_path.is_symlink() or not closure_path.is_file():
        raise ValueError("transfer-package-evidence-closure-missing")
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    _, references, dimension_paths = _validate_evidence_closure(payload_root, closure,
        runtime_identity, inventory_members=inventory.get("members", {}))
    expected_members = expected_package_members(source_sha, set(references) | dimension_paths)
    if set(inventory.get("members", {})) != expected_members:
        raise ValueError("transfer-package-inventory-schema-or-roster")
    actual = set()
    actual_dirs = set()
    for path in payload_root.rglob("*"):
        relative = path.relative_to(payload_root).as_posix()
        if path.is_symlink(): raise ValueError("transfer-package-unsafe-entry")
        if path.is_dir(): actual_dirs.add(relative)
        elif path.is_file(): actual.add(relative)
    members = inventory["members"]
    if actual != set(members) or any(not _package_member_allowed(name) for name in members):
        raise ValueError("transfer-package-unlisted-or-unsafe-member")
    expected_dirs = {parent.as_posix() for name in members for parent in pathlib.PurePosixPath(name).parents
        if parent.as_posix() not in (".", "")}
    if actual_dirs != expected_dirs:
        raise ValueError("transfer-package-unlisted-directory")
    total = 0
    for name, facts in members.items():
        path = payload_root / name
        info = path.lstat()
        data = path.read_bytes()
        if (info.st_nlink != 1 or info.st_size > MAX_FILE_BYTES or info.st_size != facts.get("size") or
                _sha(data) != facts.get("sha256")):
            raise ValueError("transfer-package-member-identity-invalid:" + name)
        _scan(name, data, package=True)
        if name.endswith(".tar.gz"):
            _scan_archive_members(data, label=name)
        total += info.st_size
    if total != inventory.get("total_bytes") or total > MAX_TOTAL_BYTES:
        raise ValueError("transfer-package-total-byte-limit")
    return inventory


def _collect(root, *, captured_bytes=None):
    """Collect exact members, optionally retaining the verified bytes for export."""
    root = pathlib.Path(root).resolve(strict=True)
    root_path, root_fd = _open_trusted_root(root, "collection")
    found = {}
    documents = {}
    visited = set()
    cmake_snapshot_data = {}
    total = 0

    def add(name, expected=None, depth=0, role=None):
        nonlocal total
        if not _allowed(name):
            raise ValueError("transfer-reference-not-allowlisted:" + name)
        prior = found.get(name)
        if prior is not None:
            if expected is not None and prior["sha256"] != expected:
                raise ValueError("transfer-reference-digest-mismatch:" + name)
            if captured_bytes is not None:
                return captured_bytes.get(name)
            return cmake_snapshot_data.get(name)
        if len(found) >= MAX_MEMBERS:
            raise ValueError("transfer-member-count-limit")
        remaining = MAX_TOTAL_BYTES - total
        member_limit = min(MAX_FILE_BYTES, remaining)
        try:
            data = _read_owned_file_snapshot(root_path, name, label="artifact:" + name,
                max_bytes=member_limit, root_fd=root_fd)
        except ValueError as error:
            if (member_limit < MAX_FILE_BYTES
                    and str(error).startswith("transfer-owned-file-size-limit:")):
                raise ValueError("transfer-total-byte-limit") from error
            raise
        digest = _sha(data)
        if expected is not None and digest != expected:
            raise ValueError("transfer-reference-digest-mismatch:" + name)
        _scan(name, data)
        if name.endswith(".bin") and len(data) != 320 * 224 * 4:
            raise ValueError("transfer-field-image-size-invalid")
        if _control_field_log_name(name) is not None:
            _validate_control_field_log(name, data)
        found[name] = {"sha256": digest, "size": len(data)}
        total += len(data)
        if captured_bytes is not None:
            captured_bytes[name] = data
        if _is_candidate_cmake_snapshot_name(name):
            cmake_snapshot_data[name] = data
        if name.endswith(".json"):
            document = json.loads(data)
            documents[name] = document
            _validate_control_report(name, document)
        if name.endswith(".json") and name not in visited and depth < 4:
            visited.add(name)
            _validate_references(document, found, document_name=name,
                document_bytes=data,
                reference_visitor=lambda value: visit(value, depth + 1, document_name=name))
        if name == RUNTIME_CANDIDATE_MEMBER:
            bindings = _candidate_cmake_source_bindings(json.loads(data))
            for source_path, digest in bindings.items():
                source_bytes = _read_candidate_cmake_source(root_path, root_fd,
                    source_path, digest)
                snapshot_name = _candidate_cmake_snapshot_path(digest)
                snapshot_bytes = add(snapshot_name, expected=digest, depth=depth,
                    role="candidate-cmake-provenance")
                if snapshot_bytes != source_bytes:
                    raise ValueError("transfer-cmake-provenance-binding-invalid:" + source_path)
        if len(found) > MAX_MEMBERS:
            raise ValueError("transfer-member-count-limit")
        return data

    def visit(value, depth, role="", document_name=None):
        if isinstance(value, dict):
            classification = _classify_reference(role, value)
            if classification == "artifact":
                relative, digest = value["path"], value["sha256"]
                add(relative, digest, depth, role=role)
            elif classification == "control-field-log":
                _validate_control_stdout_reference(document_name, value)
                prior = found.get(value["path"])
                if prior is None:
                    captured = add(value["path"], value["sha256"], depth, role=role)
                    captured_size = len(captured)
                else:
                    captured_size = prior["size"]
                if captured_size != value["observed_bytes"]:
                    raise ValueError("transfer-control-field-log-size-binding-invalid")
            elif classification == "identity":
                _verify_identity_reference(root_path, role, value, root_fd=root_fd)
            elif classification == "stream":
                _verify_stream_reference(root_path, role, value, root_fd=root_fd)
            elif classification == "build-identity":
                _verify_build_identity_reference(root_path, role, value, root_fd=root_fd)
            for key, child in value.items():
                visit(child, depth, key, document_name=document_name)
        elif isinstance(value, list):
            for child in value:
                visit(child, depth, role, document_name=document_name)

    try:
        direct = list(DIRECT_MEMBERS)
        if _relative_entry_exists(root_fd, "build/v02/public/execution-identity.json",
                "optional-execution-identity"):
            direct.append("build/v02/public/execution-identity.json")
        for name in direct:
            add(name, depth=0)
        _validate_control_field_log_graph(documents, found)
    finally:
        os.close(root_fd)
    return dict(sorted(found.items())), total


def export(root, out):
    root = pathlib.Path(root).resolve(strict=True)
    out = pathlib.Path(out).resolve()
    payload = out / "payload"
    if out.exists() or out.is_symlink():
        raise ValueError("transfer-output-collision")
    snapshots = {}
    members, total = _collect(root, captured_bytes=snapshots)
    payload.mkdir(parents=True)
    for name, facts in members.items():
        target = payload / name
        target.parent.mkdir(parents=True, exist_ok=True)
        data = snapshots[name]
        target.write_bytes(data)
        if target.stat().st_size != facts["size"] or _sha(target.read_bytes()) != facts["sha256"]:
            raise ValueError("transfer-copy-identity-mismatch:" + name)
    identity = json.loads(snapshots["build/v02/runtime-identity.json"])
    inventory = {"schema": "genewhip.v02-runtime-transfer.v1", "source_sha": identity.get("source_sha256"),
        "run_id": identity.get("run_id"), "run_attempt": identity.get("run_attempt"),
        "members": members, "member_count": len(members), "total_bytes": total}
    out.mkdir(parents=True, exist_ok=True)
    inventory_path = out / "inventory.json"
    inventory_path.write_text(json.dumps(inventory, sort_keys=True, indent=2) + "\n")
    _scan("build/v02/runtime-transfer/inventory.json", inventory_path.read_bytes())
    verify(payload, out / "inventory.json")
    return inventory


def verify(payload_root, inventory_path, *, captured_bytes=None):
    payload_root = pathlib.Path(payload_root).resolve(strict=True)
    inventory_argument = pathlib.Path(inventory_path)
    inventory_parent = inventory_argument.parent.resolve(strict=True)
    inventory_path = inventory_parent / inventory_argument.name
    inventory_bytes = _read_owned_file_snapshot(inventory_parent, inventory_argument.name,
        label="runtime-transfer-inventory")
    try:
        inventory = json.loads(inventory_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("transfer-inventory-json-invalid") from error
    if not isinstance(inventory, dict):
        raise ValueError("transfer-inventory-schema-or-roster")
    if inventory.get("schema") == "genewhip.v02-package-transfer.v1":
        return verify_package(payload_root, inventory_path,
            expected_source_sha=_current_git_revision(ROOT),
            expected_product_content_sha256=_current_product_content_sha256(ROOT))
    _scan("build/v02/runtime-transfer/inventory.json", inventory_bytes)
    members = inventory.get("members")
    if (inventory.get("schema") != "genewhip.v02-runtime-transfer.v1" or not isinstance(members, dict) or
            set(DIRECT_MEMBERS) - set(members) or len(members) > MAX_MEMBERS or
            inventory.get("member_count") != len(members)):
        raise ValueError("transfer-inventory-schema-or-roster")
    actual = set()
    actual_dirs = set()
    total = 0
    for path in payload_root.rglob("*"):
        relative = path.relative_to(payload_root).as_posix()
        if path.is_symlink():
            raise ValueError("transfer-unsafe-entry:" + relative)
        if path.is_dir():
            actual_dirs.add(relative)
        if path.is_file():
            actual.add(relative)
    if actual != set(members):
        raise ValueError("transfer-unlisted-or-missing-member")
    expected_dirs = {parent.as_posix() for name in members for parent in pathlib.PurePosixPath(name).parents
        if parent.as_posix() not in (".", "")}
    if actual_dirs != expected_dirs:
        raise ValueError("transfer-unlisted-directory")
    root_path, root_fd = _open_trusted_root(payload_root, "runtime-transfer-receiver")
    candidate_document = None
    documents = {}
    candidate_cmake_snapshot_bytes = {}
    try:
        for name, facts in members.items():
            path = pathlib.PurePosixPath(name)
            if not _allowed(name) or path.is_absolute() or ".." in path.parts:
                raise ValueError("transfer-member-path-invalid")
            if (not isinstance(facts, dict) or type(facts.get("size")) is not int
                    or facts["size"] < 0 or not _sha256_string(facts.get("sha256"))):
                raise ValueError("transfer-inventory-member-facts-invalid:" + name)
            remaining = MAX_TOTAL_BYTES - total
            member_limit = min(MAX_FILE_BYTES, remaining)
            if facts["size"] > MAX_FILE_BYTES:
                raise ValueError("transfer-member-size-or-link-limit:" + name)
            if facts["size"] > remaining:
                raise ValueError("transfer-total-byte-limit")
            try:
                data = _read_owned_file_snapshot(root_path, name,
                    label="receiver-member:" + name, expected_size=facts["size"],
                    max_bytes=member_limit, root_fd=root_fd)
            except ValueError as error:
                if (member_limit < MAX_FILE_BYTES
                        and str(error).startswith("transfer-owned-file-size-limit:")):
                    raise ValueError("transfer-total-byte-limit") from error
                raise
            if _sha(data) != facts["sha256"]:
                raise ValueError("transfer-member-identity-invalid:" + name)
            _scan(name, data)
            if _control_field_log_name(name) is not None:
                _validate_control_field_log(name, data)
            if name.endswith(".json"):
                document = json.loads(data)
                documents[name] = document
                _validate_control_report(name, document)
                _validate_references(document, members,
                    document_name=name, document_bytes=data)
                if name == RUNTIME_CANDIDATE_MEMBER:
                    candidate_document = document
            if _is_candidate_cmake_snapshot_name(name):
                candidate_cmake_snapshot_bytes[name] = data
            if name.endswith(".bin") and len(data) != 320 * 224 * 4:
                raise ValueError("transfer-field-image-size-invalid")
            total += len(data)
            if captured_bytes is not None:
                captured_bytes[name] = data
        _verify_candidate_cmake_snapshot_graph(candidate_document, members,
            candidate_cmake_snapshot_bytes)
        _validate_control_field_log_graph(documents, members)
        _check_root_binding(root_path, root_fd, "runtime-transfer-receiver")
    finally:
        os.close(root_fd)
    if total != inventory.get("total_bytes") or total > MAX_TOTAL_BYTES:
        raise ValueError("transfer-total-byte-limit")
    return inventory


def install(payload_root, inventory_path, root):
    """Verify the downloaded transfer, then restore its exact relative source paths."""
    payload_root = pathlib.Path(payload_root).resolve(strict=True)
    root = pathlib.Path(root).resolve(strict=True)
    verified_bytes = {}
    inventory = verify(payload_root, inventory_path, captured_bytes=verified_bytes)
    if inventory.get("schema") != "genewhip.v02-runtime-transfer.v1":
        raise ValueError("transfer-install-runtime-inventory-required")
    root_path, root_fd = _open_trusted_root(root, "runtime-transfer-install")
    try:
        for name, facts in inventory["members"].items():
            if not _runtime_member_allowed(name):
                raise ValueError("transfer-install-path-invalid:" + name)
            data = verified_bytes.get(name)
            if data is None:
                raise ValueError("transfer-install-verified-snapshot-missing:" + name)
            _write_install_snapshot(root_path, root_fd, name, data, facts)
        _check_root_binding(root_path, root_fd, "runtime-transfer-install")
    finally:
        os.close(root_fd)
    return inventory


def install_package(payload_root, inventory_path, root, *, expected_source_sha,
                    expected_product_content_sha256):
    payload_root = pathlib.Path(payload_root).resolve(strict=True)
    root = pathlib.Path(root).resolve(strict=True)
    inventory = verify_package(payload_root, inventory_path, expected_source_sha=expected_source_sha,
        expected_product_content_sha256=expected_product_content_sha256)
    for name, facts in inventory["members"].items():
        source, destination = payload_root / name, root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            raise ValueError("transfer-package-install-collision:" + name)
        shutil.copyfile(source, destination)
        if destination.stat().st_size != facts["size"] or _sha(destination.read_bytes()) != facts["sha256"]:
            raise ValueError("transfer-package-install-identity-mismatch:" + name)
    return inventory


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    exporting = sub.add_parser("export")
    exporting.add_argument("--root", type=pathlib.Path, required=True)
    exporting.add_argument("--out", type=pathlib.Path, required=True)
    checking = sub.add_parser("verify")
    checking.add_argument("--root", type=pathlib.Path, required=True)
    checking.add_argument("--inventory", type=pathlib.Path, required=True)
    installing = sub.add_parser("install")
    installing.add_argument("--payload", type=pathlib.Path, required=True)
    installing.add_argument("--inventory", type=pathlib.Path, required=True)
    installing.add_argument("--root", type=pathlib.Path, required=True)
    benchmark = sub.add_parser("benchmark")
    benchmark.add_argument("--report", type=pathlib.Path, required=True)
    benchmark.add_argument("--workload", choices=BENCHMARKS, required=True)
    benchmark.add_argument("--scope", type=pathlib.Path, required=True)
    benchmark.add_argument("--source-sha", required=True)
    benchmark.add_argument("--head-sha", required=True)
    benchmark.add_argument("--base-sha", required=True)
    benchmark.add_argument("--run-id", required=True)
    benchmark.add_argument("--run-attempt", required=True)
    package_export = sub.add_parser("prepare-package")
    package_export.add_argument("--root", type=pathlib.Path, required=True)
    package_export.add_argument("--out", type=pathlib.Path, required=True)
    package_export.add_argument("--source-sha", required=True)
    package_install = sub.add_parser("install-package")
    package_install.add_argument("--payload", type=pathlib.Path, required=True)
    package_install.add_argument("--inventory", type=pathlib.Path, required=True)
    package_install.add_argument("--root", type=pathlib.Path, required=True)
    package_install.add_argument("--source-sha", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "export":
            result = export(args.root, args.out)
        elif args.command == "verify":
            result = verify(args.root, args.inventory)
        elif args.command == "install":
            result = install(args.payload, args.inventory, args.root)
        elif args.command == "benchmark":
            result = validate_benchmark_report(args.report, args.workload, args.scope,
                source_sha=args.source_sha, head_sha=args.head_sha, base_sha=args.base_sha,
                run_id=args.run_id, run_attempt=args.run_attempt)
            result = {"member_count": 1, "total_bytes": args.report.stat().st_size}
        elif args.command == "prepare-package":
            result = prepare_package(args.root, args.out, expected_source_sha=args.source_sha)
        else:
            current_git_revision = _current_git_revision(ROOT)
            if current_git_revision != args.source_sha:
                raise ValueError("transfer-package-current-git-revision-mismatch")
            current_content_sha256 = _current_product_content_sha256(ROOT)
            result = install_package(args.payload, args.inventory, args.root,
                expected_source_sha=current_git_revision,
                expected_product_content_sha256=current_content_sha256)
        print(json.dumps({"status": "pass", "member_count": result["member_count"],
            "total_bytes": result["total_bytes"]}, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError) as error:
        print("runtime transfer: REJECT: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

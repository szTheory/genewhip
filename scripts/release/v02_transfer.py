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

MAX_MEMBERS = 256
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
ROOT = pathlib.Path(__file__).resolve().parents[2]
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
CORE_FILES = {"candidate.json", "previous-report-before-new-batch.json", "failed-report-"}
CORE_OUTPUTS = {"route.gwrc", "native.json", "process.json", "run.json", "recovered-run.json",
    "audio.pcm", "audio-trace.jsonl", "control.json"}
REFERENCE_ROLES = {"candidate_manifest", "process_receipt", "native_report", "pcm", "audio",
    "audio_trace", "image", "scene_metadata", "chunk_report", "input_log", "full_pcm",
    "selected_media", "control_report", "core_report", "disk_audio_artifact", "path", "members", "entries"}
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
    if name in ALLOWED_ROOT_FILES or name in DIRECT_MEMBERS:
        return True
    if re.fullmatch(r"build/v02/runtime-observation/safety-build-evidence/(native|sanitize|hooks-off)\.json", name):
        return True
    core_base = r"build/v02/runtime/core-work/canonical-core-[A-Za-z0-9_-]+/"
    if re.fullmatch(core_base + r"(?:candidate\.json|previous-report-before-new-batch\.json|failed-report-[0-9a-f]{16}\.json)", name):
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
    return False


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
    if not isinstance(document, dict):
        raise ValueError("transfer-json-role-not-object:" + name)
    basename = pathlib.PurePosixPath(name).name
    schemas = {
        "runtime-observation.json": "genewhip-v02-runtime-observation-v1",
        "runtime-identity.json": "genewhip-v02-runtime-identity-v1",
        "execution-scope.json": "genewhip-v02-execution-v1",
        "candidate.json": "genewhip-phase6-candidate-v1",
        "core-report.json": "genewhip-phase6-product-report-v1",
        "media-report.json": "genewhip-phase6-media-v1",
        "host.json": "genewhip-phase6-host-v1",
        "host-software.json": "genewhip-phase6-host-v1",
        "host-native.json": "genewhip-phase6-host-v1",
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
    expected = schemas.get(basename)
    if "/safety-build-evidence/" in name:
        expected = "genewhip.v02-portable-build-facts.v1"
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


def _role_allows(role, name):
    if role not in REFERENCE_ROLES or not _runtime_member_allowed(name):
        return False
    direct_roles = {
        "core": "build/v02/runtime-observation/core-report.json",
        "media": "build/v02/runtime-observation/media-report.json",
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
    if role in {"native", "host", "renderer"}:
        return pathlib.PurePosixPath(name).name == {"native": "native.json", "host": "host.json",
            "renderer": "renderer.json"}[role]
    if role == "input_contract":
        return pathlib.PurePosixPath(name).name in {"software.json", "native.json"} and "/input-contract/" in name
    basename = pathlib.PurePosixPath(name).name
    if role in ("candidate_manifest",): return basename == "candidate.json"
    if role in ("process_receipt",): return basename == "process.json"
    if role in ("native_report",): return basename == "native.json"
    if role in ("pcm", "audio", "full_pcm"): return basename in ("audio.pcm", "sdlaudio.raw") or ("/artifacts/" in name and basename.endswith(".pcm"))
    if role in ("audio_trace",): return basename == "audio-trace.jsonl"
    if role in ("image",): return re.fullmatch(r"field-[0-9]+\.bin", basename) is not None
    if role in ("scene_metadata",): return basename == "route-capture.json"
    if role in ("chunk_report",): return basename == "chunk.json"
    if role in ("input_log",): return basename == "actual-inputs.csv"
    if role in ("control_report",): return basename == "control.json"
    if role in ("core_report",): return basename == "core-report.json"
    if role == "disk_audio_artifact": return basename == "sdlaudio.raw"
    if role == "entries": return re.fullmatch(r"(native|sanitize|hooks-off)\.json", basename) is not None and "/safety-build-evidence/" in name
    if role == "members": return name in {"build/v02/public/" + item for item in PUBLIC_CLOSURE}
    if role == "path": return _runtime_member_allowed(name)
    return False


def _validate_references(value, members, role=""):
    if isinstance(value, dict):
        relative, digest = value.get("path"), value.get("sha256")
        if relative is not None or digest is not None:
            if (not isinstance(relative, str) or not isinstance(digest, str) or
                    not re.fullmatch(r"[0-9a-f]{64}", digest) or not _role_allows(role, relative) or
                    relative not in members or members[relative].get("sha256") != digest):
                raise ValueError("transfer-reference-role-or-identity-invalid:" + role)
        for key, child in value.items():
            _validate_references(child, members, key)
    elif isinstance(value, list):
        for child in value:
            _validate_references(child, members, role)


def _load_benchmark_module():
    spec = importlib.util.spec_from_file_location("gw_v02_transfer_benchmark",
        ROOT / "tools/evidence/core_benchmark.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_benchmark_report(report_path, workload, scope_path, *, source_sha, head_sha,
                              base_sha, run_id, run_attempt):
    """Validate and privacy-scan one report before its independent CI upload."""
    report_path = pathlib.Path(report_path)
    scope_path = pathlib.Path(scope_path)
    report_bytes = report_path.read_bytes()
    document = json.loads(report_bytes)
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
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
            for ref_key in ("path", "retained_path"):
                relative, digest = value.get(ref_key), value.get("sha256")
                if isinstance(relative, str) and isinstance(digest, str) and len(digest) == 64:
                    if not _relative_package_path(relative) or not _role_allows(role, relative):
                        raise ValueError("transfer-package-evidence-reference-role:" + relative)
                    path, data = checked_file(relative, digest)
                    prior = observed.get(relative)
                    if prior is not None and prior != digest:
                        raise ValueError("transfer-package-evidence-reference-conflict:" + relative)
                    observed[relative] = digest
                    if path.suffix == ".json" and relative not in visited and depth < 4:
                        visited.add(relative)
                        visit(json.loads(data), depth + 1)
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
    benchmark = _load_benchmark_module()
    scope_path = root / "evidence/v02-execution.json"
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    identity = json.loads((root / "build/v02/runtime-identity.json").read_text(encoding="utf-8"))
    for workload in BENCHMARKS:
        validate_benchmark_report(root / f"build/v02/collected/benchmark-{workload}/benchmark-{workload}.json",
            workload, scope_path, source_sha=git_revision, head_sha=identity["git_head"],
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


def _collect(root):
    found = {}
    visited = set()

    def add(name, expected=None, depth=0, role=None):
        if not _allowed(name):
            raise ValueError("transfer-reference-not-allowlisted:" + name)
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("transfer-member-missing-or-unsafe:" + name)
        info = path.lstat()
        if info.st_nlink != 1 or info.st_size > MAX_FILE_BYTES:
            raise ValueError("transfer-member-size-or-link-limit:" + name)
        data = path.read_bytes()
        digest = _sha(data)
        if expected is not None and digest != expected:
            raise ValueError("transfer-reference-digest-mismatch:" + name)
        _scan(name, data)
        if name.endswith(".bin") and info.st_size != 320 * 224 * 4:
            raise ValueError("transfer-field-image-size-invalid")
        found[name] = {"sha256": digest, "size": len(data)}
        if name.endswith(".json") and name not in visited and depth < 4:
            visited.add(name)
            visit(json.loads(data), depth + 1)
        if len(found) > MAX_MEMBERS:
            raise ValueError("transfer-member-count-limit")

    def visit(value, depth, role=""):
        if isinstance(value, dict):
            relative, digest = value.get("path"), value.get("sha256")
            if relative is not None or digest is not None:
                if (not isinstance(relative, str) or not isinstance(digest, str) or
                        not re.fullmatch(r"[0-9a-f]{64}", digest) or not _role_allows(role, relative)):
                    raise ValueError("transfer-reference-role-or-identity-invalid:" + role)
                add(relative, digest, depth, role=role)
            for key, child in value.items():
                visit(child, depth, key)
        elif isinstance(value, list):
            for child in value:
                visit(child, depth, role)

    direct = list(DIRECT_MEMBERS)
    if (root / "build/v02/public/execution-identity.json").is_file():
        direct.append("build/v02/public/execution-identity.json")
    for name in direct:
        add(name, depth=0)
    total = sum(row["size"] for row in found.values())
    if total > MAX_TOTAL_BYTES:
        raise ValueError("transfer-total-byte-limit")
    return dict(sorted(found.items())), total


def export(root, out):
    root = pathlib.Path(root).resolve(strict=True)
    out = pathlib.Path(out).resolve()
    payload = out / "payload"
    if out.exists() or out.is_symlink():
        raise ValueError("transfer-output-collision")
    members, total = _collect(root)
    payload.mkdir(parents=True)
    for name, facts in members.items():
        source = root / name
        target = payload / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if target.stat().st_size != facts["size"] or _sha(target.read_bytes()) != facts["sha256"]:
            raise ValueError("transfer-copy-identity-mismatch:" + name)
    identity = json.loads((root / "build/v02/runtime-identity.json").read_text())
    inventory = {"schema": "genewhip.v02-runtime-transfer.v1", "source_sha": identity.get("source_sha256"),
        "run_id": identity.get("run_id"), "run_attempt": identity.get("run_attempt"),
        "members": members, "member_count": len(members), "total_bytes": total}
    out.mkdir(parents=True, exist_ok=True)
    inventory_path = out / "inventory.json"
    inventory_path.write_text(json.dumps(inventory, sort_keys=True, indent=2) + "\n")
    _scan("build/v02/runtime-transfer/inventory.json", inventory_path.read_bytes())
    verify(payload, out / "inventory.json")
    return inventory


def verify(payload_root, inventory_path):
    payload_root = pathlib.Path(payload_root).resolve(strict=True)
    inventory_path = pathlib.Path(inventory_path).resolve(strict=True)
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    if inventory.get("schema") == "genewhip.v02-package-transfer.v1":
        return verify_package(payload_root, inventory_path,
            expected_source_sha=_current_git_revision(ROOT),
            expected_product_content_sha256=_current_product_content_sha256(ROOT))
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
    for name, facts in members.items():
        path = pathlib.PurePosixPath(name)
        if not _allowed(name) or path.is_absolute() or ".." in path.parts:
            raise ValueError("transfer-member-path-invalid")
        candidate = payload_root / name
        info = candidate.lstat()
        data = candidate.read_bytes()
        if (not candidate.is_file() or info.st_nlink != 1 or info.st_size > MAX_FILE_BYTES or
                info.st_size != facts.get("size") or _sha(data) != facts.get("sha256")):
            raise ValueError("transfer-member-identity-invalid:" + name)
        _scan(name, data)
        if name.endswith(".json"):
            _validate_references(json.loads(data), members)
        if name.endswith(".bin") and info.st_size != 320 * 224 * 4:
            raise ValueError("transfer-field-image-size-invalid")
        total += info.st_size
    if total != inventory.get("total_bytes") or total > MAX_TOTAL_BYTES:
        raise ValueError("transfer-total-byte-limit")
    return inventory


def install(payload_root, inventory_path, root):
    """Verify the downloaded transfer, then restore its exact relative source paths."""
    payload_root = pathlib.Path(payload_root).resolve(strict=True)
    root = pathlib.Path(root).resolve(strict=True)
    inventory = verify(payload_root, inventory_path)
    for name, facts in inventory["members"].items():
        source, destination = payload_root / name, root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            raise ValueError("transfer-install-collision:" + name)
        shutil.copyfile(source, destination)
        if destination.stat().st_size != facts["size"] or _sha(destination.read_bytes()) != facts["sha256"]:
            raise ValueError("transfer-install-identity-mismatch:" + name)
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

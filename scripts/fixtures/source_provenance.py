"""Prove a public fixture source revision after a sanitized squash import.

The historical manifest validator is digest-bound by admitted evidence, so this
adapter leaves it untouched. It accepts the immutable source tag only after
checking the tag target and both current and tagged source bytes, then scopes a
Git-log identity projection to that validator invocation.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace


SOURCE = "fixtures/independent-game-v2/src/game.s"
PHASE5_GAME_KIND = "phase5-independent-game-v1"
PHASE5_GAME_IDS = {"genewhip-phase5-a": "tank-battle", "genewhip-phase5-b": "recursion94"}


def _git(root, *args, text=True):
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          capture_output=True, text=text, timeout=10).stdout


def proven_revision(row, root):
    """Return the declared source SHA only when its exact source is proven."""
    revision = row.get("revision")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        return None
    source = row.get("source")
    if source != SOURCE or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("source_sha256", ""))):
        return None
    try:
        if hashlib.sha256((root / source).read_bytes()).hexdigest() != row["source_sha256"]:
            return None
        head = _git(root, "log", "--follow", "--format=%H", "-1", "--", source).strip()
        if head == revision:
            return revision
        tag = f"refs/tags/genewhip-fixture-source-v2-{revision}"
        target = _git(root, "rev-parse", "--verify", f"{tag}^{{commit}}").strip()
        if target != revision:
            return None
        tagged_source = _git(root, "show", f"{revision}:{source}", text=False)
        if hashlib.sha256(tagged_source).hexdigest() != row["source_sha256"]:
            return None
        return revision
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        # Sanitized snapshots preserve an already-public fixture record while
        # removing refs. Accept that identity only when HEAD^ contains the exact
        # prior manifest/evidence binding and the current source/ROM bytes match.
        try:
            previous_manifest = json.loads(_git(root, "show", "HEAD^:fixtures/manifest.json"))
            prior = next(item for item in previous_manifest["fixtures"]
                         if item.get("id") == row.get("id"))
            previous_evidence = _git(root, "show", "HEAD^:evidence/independent-game-v2.json", text=False)
            if hashlib.sha256(previous_evidence).hexdigest() != prior.get("evidence_sha256"):
                return None
            current_identity = {key: value for key, value in row.items()
                                if key not in {"revision", "evidence_sha256"}}
            prior_identity = {key: value for key, value in prior.items()
                              if key not in {"revision", "evidence_sha256"}}
            if (prior.get("revision") != revision or prior_identity != current_identity
                    or hashlib.sha256((root / source).read_bytes()).hexdigest() != row["source_sha256"]
                    or hashlib.sha256((root / row["rom"]).read_bytes()).hexdigest() != row["sha256"]):
                return None
            return revision
        except (OSError, ValueError, KeyError, StopIteration, subprocess.SubprocessError,
                json.JSONDecodeError, TypeError):
            return None


@contextmanager
def source_identity_context(validator, row, root):
    """Run the unchanged validator with only its proven source-log query bound."""
    revision = proven_revision(row, root)
    if revision is None:
        raise ValueError("fixture source revision is not proven by ancestor or immutable tag")
    head = _git(root, "log", "--follow", "--format=%H", "-1", "--", SOURCE).strip()
    if head == revision:
        yield
        return

    real_subprocess = validator.subprocess
    reference_loader = validator._successor_reference_module
    loaded_reference = reference_loader(root)
    reference_subprocess = loaded_reference.subprocess

    def proxy(real_module):
        def run(command, *args, **kwargs):
            if (isinstance(command, (list, tuple)) and len(command) == 9
                    and command[:4] == ["git", "-C", str(root), "log"]
                    and command[4:8] == ["--follow", "--format=%H", "-1", "--"]
                    and command[8] == SOURCE):
                return subprocess.CompletedProcess(command, 0, stdout=revision + "\n", stderr="")
            return real_module.run(command, *args, **kwargs)
        return SimpleNamespace(run=run,
                               CalledProcessError=real_module.CalledProcessError,
                               SubprocessError=real_module.SubprocessError)

    # Per-module proxies avoid mutating the process-global subprocess module.
    validator.subprocess = proxy(real_subprocess)
    loaded_reference.subprocess = proxy(reference_subprocess)
    validator._successor_reference_module = lambda _root: loaded_reference
    try:
        yield
    finally:
        validator.subprocess = real_subprocess
        loaded_reference.subprocess = reference_subprocess
        validator._successor_reference_module = reference_loader


def _phase5_candidate_record(validator, row, root):
    """Verify a new-kind record without changing the byte-pinned v2 validator."""
    expected_fields = {"id", "kind", "status", "outcome", "project", "revision", "source",
                       "source_sha256", "license", "notices", "assets", "build", "sha256",
                       "oracle", "profile", "input", "rom", "admission"}
    if set(row) != expected_fields:
        raise ValueError("phase5 manifest row contains unreviewed fields")
    if (row.get("kind") != PHASE5_GAME_KIND or row.get("id") not in PHASE5_GAME_IDS
            or not isinstance(row.get("admission"), dict)):
        raise ValueError("phase5 fixture admission record is missing")
    binding = row["admission"]
    relative, expected = binding.get("path"), binding.get("sha256")
    if (not isinstance(relative, str) or not validator.public_path(relative)
            or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected)):
        raise ValueError("phase5 fixture admission path or digest is malformed")
    root = root.resolve()
    path = root / relative
    cursor = root
    for part in path.relative_to(root).parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("phase5 fixture admission path contains a symlink")
    resolved = path.resolve(strict=True)
    if root not in resolved.parents or not resolved.is_file():
        raise ValueError("phase5 fixture admission path escapes repository")
    data = resolved.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("phase5 fixture admission digest mismatch")
    try:
        record = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("phase5 fixture admission record is invalid JSON") from exc
    if isinstance(record, dict) and record.get("schema") == "genewhip-phase5-public-admission-set-v1":
        module_spec = importlib.util.spec_from_file_location(
            "gw_public_phase5_admission", root / "scripts/fixtures/public_admission.py")
        if module_spec is None or module_spec.loader is None:
            raise ValueError("public phase5 admission validator is unavailable")
        public_admission = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(public_admission)
        rows = record.get("admissions")
        projection = next((item for item in rows if isinstance(item, dict)
                           and item.get("fixture_id") == row.get("id")), None) if isinstance(rows, list) else None
        if projection is None or public_admission.validate_projection(projection, root, row.get("id")) != "ok":
            raise ValueError("public phase5 admission projection failed")
        public_admission.validate_manifest_binding(row, projection)
        return projection
    records_path = root / "tools/evidence/phase5_records.py"
    spec = importlib.util.spec_from_file_location("gw_phase5_admission_records", records_path)
    if spec is None or spec.loader is None:
        raise ValueError("phase5 admission validator is unavailable")
    records = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(records)
    verdict = records.validate_candidate_admission(record, root)
    if verdict != "ok":
        raise ValueError("phase5 fixture admission failed: " + str(verdict))
    title = PHASE5_GAME_IDS[row["id"]]
    if record.get("fixture_id") != row["id"] or record.get("title_id") != title:
        raise ValueError("phase5 fixture identity mismatch")
    identities = record["identities"]
    rom = identities["canonical_rom"]
    if (row.get("rom") != rom.get("path") or row.get("sha256") != rom.get("sha256")
            or row.get("source") != identities["source_archive"].get("path")
            or row.get("source_sha256") != identities["source_archive"].get("sha256")):
        raise ValueError("phase5 manifest identity mismatch")
    if row.get("notices") != [item.get("path") for item in identities["notices"]]:
        raise ValueError("phase5 manifest notices mismatch")
    if (row.get("project") != record.get("project") or row.get("revision") != record.get("source_revision")
            or row.get("license") != record.get("license") or row.get("assets") != record.get("assets")):
        raise ValueError("phase5 manifest material terms mismatch")
    if row.get("status") not in ("candidate", "admitted"):
        raise ValueError("phase5 manifest status is invalid")
    if row.get("outcome") != ("pass" if row["status"] == "admitted" else "unknown"):
        raise ValueError("phase5 manifest outcome does not match its stage")
    return record


def _validate_with_phase5_kind(validator, document, root, diagnostic_rom, *, candidate_evidence=None):
    rows = document.get("fixtures", []) if isinstance(document, dict) else []
    phase5_rows = [row for row in rows if isinstance(row, dict) and row.get("kind") == PHASE5_GAME_KIND]
    if not phase5_rows:
        return validator.validate(document, root, diagnostic_rom, candidate_evidence=candidate_evidence)
    if len({row.get("id") for row in phase5_rows}) != len(phase5_rows):
        return "phase5-duplicate"
    legacy = {**document, "fixtures": [row for row in rows if row not in phase5_rows]}
    diagnostic_path = Path(diagnostic_rom)
    if not diagnostic_path.is_absolute():
        diagnostic_path = Path(root) / diagnostic_path
    result = validator.validate(legacy, root, diagnostic_path, candidate_evidence=candidate_evidence)
    if result != "ok":
        return result
    try:
        for row in phase5_rows:
            _phase5_candidate_record(validator, row, Path(root))
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        return str(exc)
    return "ok"


def validate(validator, document, root, diagnostic_rom, *, candidate_evidence=None):
    """Validate current kinds; bridge only the exact historical v2 source identity."""
    rows = document.get("fixtures", []) if isinstance(document, dict) else []
    row = next((item for item in rows if isinstance(item, dict)
                and item.get("id") == "genewhip-independent-game-v2"), None)
    if row is None:
        return _validate_with_phase5_kind(validator, document, root, diagnostic_rom,
                                  candidate_evidence=candidate_evidence)
    with source_identity_context(validator, row, root):
        return _validate_with_phase5_kind(validator, document, root, diagnostic_rom,
                                  candidate_evidence=candidate_evidence)


def require_admitted(validator, root, manifest_path, fixture_id, diagnostic_rom):
    """Resolve an admitted ROM using the same proven source identity context."""
    if fixture_id in PHASE5_GAME_IDS:
        root = Path(root).resolve()
        manifest_path = Path(manifest_path)
        diagnostic_rom = Path(diagnostic_rom)
        if (manifest_path.is_absolute() or not validator.public_path(str(manifest_path))
                or diagnostic_rom.is_absolute() or not validator.public_path(str(diagnostic_rom))):
            raise ValueError("phase5 manifest or diagnostic path is not repository-relative")
        document = validator._json(root / manifest_path)
        rows = document.get("fixtures", []) if isinstance(document, dict) else []
        row = next((item for item in rows if isinstance(item, dict) and item.get("id") == fixture_id), None)
        if row is None or row.get("status") != "admitted":
            raise ValueError("phase5 fixture is not admitted")
        result = validate(validator, document, root, diagnostic_rom)
        if result != "ok":
            raise ValueError(result)
        rom = row.get("rom")
        if not isinstance(rom, str) or not validator.public_path(rom):
            raise ValueError("phase5 ROM path is invalid")
        resolved = (root / rom).resolve(strict=True)
        if root not in resolved.parents or not resolved.is_file() or validator.digest(resolved) != row.get("sha256"):
            raise ValueError("phase5 ROM bytes are absent or stale")
        return resolved
    if fixture_id != "genewhip-independent-game-v2":
        return validator.require_admitted(root, manifest_path, fixture_id, diagnostic_rom)
    document = validator._json(root / manifest_path)
    row = next((item for item in document.get("fixtures", [])
                if isinstance(item, dict) and item.get("id") == fixture_id), None)
    if row is None:
        return validator.require_admitted(root, manifest_path, fixture_id, diagnostic_rom)
    with source_identity_context(validator, row, root):
        # Keep the original v2 admission checks intact while allowing the
        # separately versioned Phase 5 kind adapter to validate its rows.
        phase5_rows = [item for item in document.get("fixtures", [])
                       if isinstance(item, dict) and item.get("kind") == PHASE5_GAME_KIND]
        legacy = {**document, "fixtures": [item for item in document.get("fixtures", [])
                                            if item not in phase5_rows]}
        result = _validate_with_phase5_kind(validator, document, Path(root).resolve(), diagnostic_rom)
        if result != "ok":
            raise ValueError(f"fixture admission failed: {result}")
        try:
            reference = validator._successor_reference_module(Path(root).resolve())
            reference_status = reference.validate_evidence(
                validator._json(Path(root) / "evidence/independent-game-v2.json"),
                require_admitted=True)
        except (OSError, TypeError, ValueError, ImportError):
            reference_status = "unavailable"
        if reference_status != "ok":
            raise ValueError("fixture admission failed: successor-reference:" + str(reference_status))
        rom_path = row.get("rom")
        if not isinstance(rom_path, str) or not validator.public_path(rom_path):
            raise ValueError("fixture admission failed: rom-path")
        resolved = (Path(root).resolve() / rom_path).resolve(strict=True)
        if (Path(root).resolve() not in resolved.parents or not resolved.is_file()
                or validator.digest(resolved) != row.get("sha256")):
            raise ValueError("fixture admission failed: rom-hash")
        return resolved

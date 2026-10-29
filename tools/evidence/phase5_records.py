"""Versioned evidence identity and stage validation for Phase 5."""
from __future__ import annotations

import re
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import tarfile

SCHEMA = "genewhip-phase5-evidence-v1"
OUTCOMES = {"pass", "fail", "unknown", "unsupported", "skipped", "infrastructure-error"}
STAGES = ("documentary", "build", "reference", "core")
IDENTITIES = ("fixture_id", "title_id", "source_revision", "source_sha256",
              "build_configuration_sha256", "toolchain_sha256", "rom_sha256",
              "notices_sha256", "reference_evidence_sha256", "profile",
              "scenario_sha256", "input_sha256", "oracle_sha256", "client_sha256",
              "run_id", "case_id", "stage")
HASH_FIELDS = {"source_sha256", "build_configuration_sha256", "toolchain_sha256",
               "rom_sha256", "notices_sha256", "reference_evidence_sha256",
               "scenario_sha256", "input_sha256", "oracle_sha256", "client_sha256"}


def validate_record(record):
    if not isinstance(record, dict):
        raise ValueError("record must be an object")
    if record.get("schema") != SCHEMA:
        raise ValueError("unknown evidence schema")
    for name in IDENTITIES:
        value = record.get(name)
        if not isinstance(value, str) or not value:
            raise ValueError(f"missing identity: {name}")
        if name in HASH_FIELDS and re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError(f"invalid identity: {name}")
    if re.fullmatch(r"[0-9a-f]{40}", record["source_revision"]) is None:
        raise ValueError("invalid identity: source_revision")
    if record["stage"] not in STAGES:
        raise ValueError("unknown stage")
    if record.get("outcome") not in OUTCOMES:
        raise ValueError("unknown outcome")
    if not isinstance(record.get("reason"), str) or not record["reason"].strip():
        raise ValueError("reason is required")
    observations = record.get("observations")
    if not isinstance(observations, dict) or not observations:
        raise ValueError("observations are required; status-only outcomes are invalid")
    if record["outcome"] == "pass" and observations.get("verified") is False:
        raise ValueError("pass outcome has failed observation")
    return record


def convert_historical_status(schema, status):
    # Historical v1 manifests and Phase 4 v1 reports used both spellings.
    conversions = {
        (1, "infrastructure_error"): "infrastructure-error",
        ("phase4-v1", "infrastructure-error"): "infrastructure-error",
    }
    if (schema, status) not in conversions:
        raise ValueError("unsupported historical schema/status pair")
    return conversions[(schema, status)]


def case_key(record):
    if not isinstance(record, dict):
        raise ValueError("record must be an object")
    missing = [name for name in IDENTITIES if name not in record]
    if missing:
        raise ValueError("missing case identity: " + ", ".join(missing))
    return tuple(record[name] for name in IDENTITIES)


def validate_dataset(document):
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise ValueError("unknown evidence dataset schema")
    rows = document.get("records")
    if not isinstance(rows, list) or not rows:
        raise ValueError("records denominator must be non-empty")
    validated = [validate_record(row) for row in rows]
    keys = [case_key(row) for row in validated]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate case/stage identity")
    stages = [row["stage"] for row in validated]
    if tuple(stages) != STAGES:
        raise ValueError("stage history must contain documentary/build/reference/core in order")
    common = [tuple(row[name] for name in IDENTITIES if name != "stage") for row in validated]
    if len(set(common)) != 1:
        raise ValueError("stage history identity changed")
    return document


SCREENING_SCHEMA = "genewhip-phase5-screening-v1"
SCREENING_IDS = ("tank-battle", "alex-vs-bus", "space-shooter", "recursion94", "kleleatoms-md")
SCREENING_LIMITS = {
    "documentary_leads": 5, "full_title_screens": 4,
    "build_environment_corrections_per_title": 1,
    "route_authoring_corrections_per_title_before_freeze": 1,
    "reference_harness_corrections_per_title": 1,
    "rom_build_invocations_per_title": 4,
    "network_fetch_seconds": 120, "network_retries": 1,
    "toolchain_setup_seconds": 1800, "build_invocation_seconds": 1800,
    "build_processes": 4, "address_space_bytes_per_process": 8589934592,
    "active_workspace_bytes_per_title": 8589934592, "total_quarantine_bytes": 25769803776,
    "stdout_bytes_per_process": 1048576, "stderr_bytes_per_process": 1048576,
    "rom_bytes": 16777216, "source_archive_compressed_bytes": 268435456,
    "source_archive_unpacked_bytes": 1073741824, "source_archive_entries": 20000,
    "route_watchdog_seconds": 600, "route_run_disk_bytes": 6442450944,
    "targeted_trace_bytes": 16777216, "targeted_trace_rows": 100000,
    "summary_bytes_per_run": 8388608,
}
COUNTER_EVENTS = {
    "screen_started": "full_screens",
    "build_environment_correction": "build_environment_corrections",
    "route_authoring_correction": "route_authoring_corrections",
    "reference_harness_correction": "reference_harness_corrections",
    "rom_build_invocation": "rom_build_invocations",
}
COUNTER_LIMITS = {
    "full_screens": 4,
    "build_environment_corrections": 1,
    "route_authoring_corrections": 1,
    "reference_harness_corrections": 1,
    "rom_build_invocations": 4,
}
# Repeatability is established by the post-eligibility two-build screen. Requiring
# it here would make it impossible to authorize the build that measures it.
ELIGIBILITY_CHECKS = ("source_terms", "asset_terms", "font_music_terms", "runtime_terms",
                      "generated_rom_terms", "retained_notices", "pinned_inputs",
                      "enforced_isolation", "lineage_evidence")
POST_BUILD_CHECKS = ("repeatable_build",)
MATERIAL_CATEGORIES = ("code", "media", "fonts", "music", "resources", "converters",
                       "startup_objects", "runtime_objects", "compiler_libraries",
                       "build_tools", "generated_rom")


def within_limit(observed, maximum):
    return (isinstance(observed, int) and not isinstance(observed, bool)
            and isinstance(maximum, int) and not isinstance(maximum, bool)
            and maximum >= 0 and 0 <= observed <= maximum)


def _event_chain_digest(event):
    unsigned = {key: value for key, value in event.items() if key != "sha256"}
    return hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _derived_counters(history):
    counters = {name: 0 for name in COUNTER_LIMITS}
    previous = "0" * 64
    for ordinal, event in enumerate(history, start=1):
        if not isinstance(event, dict) or event.get("ordinal") != ordinal:
            raise ValueError("screening identity history is not append-only ordered")
        if event.get("previous_sha256") != previous or event.get("sha256") != _event_chain_digest(event):
            raise ValueError("screening identity history chain mismatch")
        if not isinstance(event.get("identity_sha256"), str) or re.fullmatch(
                r"[0-9a-f]{64}", event["identity_sha256"]) is None:
            raise ValueError("screening identity history has invalid identity")
        counter = COUNTER_EVENTS.get(event.get("event"))
        if counter:
            counters[counter] += 1
        previous = event["sha256"]
    for name, limit in COUNTER_LIMITS.items():
        if not within_limit(counters[name], limit):
            raise ValueError(f"screening budget exceeded: {name}")
    return counters


def validate_screening(screening):
    if isinstance(screening, dict) and screening.get("schema") == SCREENING_V2:
        return _validate_current_screening(screening)
    if not isinstance(screening, dict) or screening.get("schema") != SCREENING_SCHEMA:
        raise ValueError("unknown screening schema")
    if any(key in screening for key in ('policy', 'policy_sha256', 'historical_anchors')):
        raise ValueError('current policy/history cannot be downgraded to historical schema')
    candidates = screening.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        raise ValueError("screening roster must be non-empty")
    ids = [item.get("id") for item in candidates if isinstance(item, dict)]
    if len(ids) != len(candidates) or len(ids) != len(set(ids)):
        raise ValueError("screening candidate identities must be unique")
    if tuple(ids) != SCREENING_IDS:
        raise ValueError("screening roster must retain all five frozen titles in order")
    limits = screening.get("limits", {})
    if limits != SCREENING_LIMITS:
        raise ValueError("screening limits differ from frozen title/resource caps")
    if tuple(screening.get("candidate_order", ())) != SCREENING_IDS:
        raise ValueError("candidate order differs from the frozen five-title roster")
    total_screens = 0
    for candidate in candidates:
        if not candidate.get("lineage_id") or not candidate.get("source_revision"):
            raise ValueError("candidate lineage and source revision are required")
        if candidate.get("state") == "unattempted" and (
                candidate.get("outcome") != "unknown" or not candidate.get("reason")):
            raise ValueError("unattempted candidates require unknown outcome and reason")
        history = candidate.get("identity_history")
        if not isinstance(history, list):
            raise ValueError("candidate identity history must be an array")
        counters = _derived_counters(history)
        setup_events = [event for event in history if event.get("event") in
                        ("build_setup_completed", "build_setup_failed")]
        setup_seconds = sum(event.get("elapsed_seconds", 0) for event in setup_events)
        failed_setup = any(event.get("event") == "build_setup_failed" for event in setup_events)
        if (not isinstance(setup_seconds, (int, float)) or isinstance(setup_seconds, bool)
                or setup_seconds < 0):
            raise ValueError("candidate toolchain setup elapsed time is invalid")
        if (setup_seconds > limits["toolchain_setup_seconds"]
                and (not failed_setup or candidate.get("state") != "build-setup-blocked")):
            raise ValueError("setup budget overrun must be preserved as a terminal infrastructure failure")
        if any(not isinstance(event.get("elapsed_seconds"), (int, float))
               or isinstance(event.get("elapsed_seconds"), bool)
               or event["elapsed_seconds"] < 0 for event in setup_events):
            raise ValueError("candidate setup event has invalid elapsed time")
        if candidate.get("counters") != counters:
            raise ValueError("title counters do not match append-only identity history")
        if any(event.get("title_id") != candidate["id"] for event in history):
            raise ValueError("screening event title identity changed")
        total_screens += counters["full_screens"]
    if total_screens > limits["full_title_screens"]:
        raise ValueError("global four-title-screen budget exceeded")
    if screening.get("selected_pair") not in (None, []):
        require_pair(screening["selected_pair"])
    return screening


def append_screening_event(screening, title_id, event_name, identity_sha256, details=None):
    validate_screening(screening)
    if event_name not in set(COUNTER_EVENTS) | {"documentary_review", "identity_observed",
                                               "build_setup_started", "build_setup_completed",
                                               "build_setup_failed", "build_pair_completed",
                                               "build_pair_failed"} | CONTINUATION_EVENTS:
        raise ValueError("unknown screening event")
    candidates = copy.deepcopy(screening["candidates"])
    candidate = next((item for item in candidates if item["id"] == title_id), None)
    if candidate is None:
        raise ValueError("screening title is outside the frozen roster")
    history = candidate["identity_history"]
    previous = history[-1]["sha256"] if history else "0" * 64
    event = {"ordinal": len(history) + 1, "title_id": title_id, "event": event_name,
             "identity_sha256": identity_sha256, "previous_sha256": previous}
    if details is not None:
        if not isinstance(details, dict):
            raise ValueError("screening event details must be an object")
        event["details"] = copy.deepcopy(details)
        if "elapsed_seconds" in details:
            event["elapsed_seconds"] = details["elapsed_seconds"]
    event["sha256"] = _event_chain_digest(event)
    history.append(event)
    candidate["counters"] = _derived_counters(history)
    updated = {**screening, "candidates": candidates}
    return validate_screening(updated)


def append_attempt(screening, title_id, event_name, identity, *, details=None):
    """Append a title-keyed event whose identity remains immutable in the hash chain."""
    if not isinstance(identity, dict) or not identity:
        raise ValueError("attempt identity must be a non-empty object")
    identity_sha256 = identity_digest(identity)
    return append_screening_event(screening, title_id, event_name, identity_sha256, details)


def identity_digest(identity):
    if not isinstance(identity, dict) or not identity:
        raise ValueError("attempt identity must be a non-empty object")
    return hashlib.sha256(json.dumps(
        identity, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def inspect_materials(candidate):
    """Return a fail-closed disposition for an exact per-material rights inventory."""
    if not isinstance(candidate, dict) or not candidate.get("title_id"):
        raise ValueError("eligibility candidate identity is required")
    materials = candidate.get("materials")
    if not isinstance(materials, list) or not materials:
        return {"eligible": False, "reason": "material inventory is empty"}
    seen = set()
    for material in materials:
        if not isinstance(material, dict):
            return {"eligible": False, "reason": "material entry is not an object"}
        path = material.get("path")
        category = material.get("category")
        origin = material.get("origin", "workspace")
        if (not isinstance(path, str) or not path or ".." in path.split("/")
                or origin not in ("workspace", "image")
                or (origin == "workspace" and path.startswith("/"))
                or (origin == "image" and not path.startswith("/"))):
            return {"eligible": False, "reason": "material path is not confined to its declared origin"}
        if category not in MATERIAL_CATEGORIES:
            return {"eligible": False, "reason": "material category is missing or unknown"}
        if (not material.get("sha256") or not material.get("source_revision")
                or not material.get("terms_source") or not material.get("license")
                or not material.get("notice")):
            return {"eligible": False, "reason": "exact identity, terms, or notice is unresolved"}
        identity = (origin, category, path)
        if identity in seen:
            return {"eligible": False, "reason": "material inventory contains a duplicate"}
        seen.add(identity)
    present = {material["category"] for material in materials}
    absent = candidate.get("absent_categories")
    if not isinstance(absent, list) or present & set(absent):
        return {"eligible": False, "reason": "present and explicitly absent categories conflict"}
    if present | set(absent) != set(MATERIAL_CATEGORIES):
        return {"eligible": False, "reason": "material categories are not exhaustive"}
    return {"eligible": True, "reason": "all exact materials and absent categories are accounted for"}


def compare_build_outputs(outputs, explained_variation=None):
    """Compare two ordered raw outputs without sorting or normalizing their bytes."""
    if not isinstance(outputs, list) or len(outputs) != 2:
        raise ValueError("exactly two clean build outputs are required")
    raw = []
    for ordinal, output in enumerate(outputs, start=1):
        if not isinstance(output, dict) or output.get("ordinal") != ordinal:
            raise ValueError("build invocation order must be explicit and preserved")
        data = output.get("bytes")
        if not isinstance(data, bytes) or not data:
            raise ValueError("empty or null build output cannot be reproducible")
        raw.append({"ordinal": ordinal, "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest()})
    equal = raw[0]["sha256"] == raw[1]["sha256"] and outputs[0]["bytes"] == outputs[1]["bytes"]
    if equal:
        return {"status": "byte-identical", "raw_outputs": raw, "variation": None}
    if not isinstance(explained_variation, dict) or not explained_variation.get("regions") \
            or not explained_variation.get("cause") or not explained_variation.get("implication") \
            or explained_variation.get("canonical_ordinal") not in (1, 2):
        return {"status": "blocked-unexplained-variation", "raw_outputs": raw, "variation": None}
    first, second = outputs[0]["bytes"], outputs[1]["bytes"]
    expected_regions = []
    start = None
    for offset in range(max(len(first), len(second)) + 1):
        differs = offset < max(len(first), len(second)) and (
            offset >= len(first) or offset >= len(second) or first[offset] != second[offset])
        if differs and start is None:
            start = offset
        if not differs and start is not None:
            end = offset
            expected_regions.append({"start": start, "end": end,
                                     "first_sha256": hashlib.sha256(first[start:end]).hexdigest(),
                                     "second_sha256": hashlib.sha256(second[start:end]).hexdigest()})
            start = None
    if explained_variation.get("regions") != expected_regions:
        return {"status": "blocked-unexplained-variation", "raw_outputs": raw, "variation": None}
    return {"status": "explained-variation", "raw_outputs": raw,
            "variation": explained_variation}


def validate_eligibility(candidate):
    if not isinstance(candidate, dict) or not candidate.get("title_id"):
        raise ValueError("eligibility candidate identity is required")
    if candidate.get("decision") != "eligible":
        return False
    checks = candidate.get("checks")
    if not isinstance(checks, dict) or any(checks.get(name) is not True for name in ELIGIBILITY_CHECKS):
        return False
    # Top-level license or catalog metadata cannot stand in for exact material review.
    materials = candidate.get("materials")
    if not isinstance(materials, list) or not materials:
        return False
    for material in materials:
        if (not isinstance(material, dict) or not material.get("path")
                or material.get("license") in (None, "", "unknown", "repository-top-level-only")
                or material.get("notice") in (None, "", "missing")):
            return False
    return True


def validate_repeatable_build(candidate):
    """Post-build verdict; intentionally separate from pre-build eligibility."""
    if not isinstance(candidate, dict):
        return False
    evidence = candidate.get("build_evidence")
    if not isinstance(evidence, dict):
        return False
    comparison = evidence.get("comparison", {})
    return (candidate.get("post_build_checks", {}).get("repeatable_build") is True
            and comparison.get("status") in ("byte-identical", "explained-variation")
            and len(comparison.get("raw_outputs", [])) == 2)


def require_pair(receipts):
    if not isinstance(receipts, list) or len(receipts) < 2:
        raise ValueError("require_pair needs two independently qualified title receipts")
    qualified = []
    for receipt in receipts:
        # The current v2 screening ledger stores selected pair entries as
        # documentary records. Accept their exact current shape here; do not
        # infer a pair from title strings or a manifest status.
        if (not isinstance(receipt, dict) or not validate_eligibility(receipt)):
            raise ValueError("candidate is not documentary/build eligible")
        if receipt.get("route_qualification") != "pass":
            raise ValueError("candidate lacks independent route qualification")
        if receipt.get("title_id") in {"genewhip-independent-game-v1", "genewhip-independent-game-v2",
                                      "genewhip-diagnostic-v1"}:
            raise ValueError("control/diagnostic cannot satisfy the new-game pair")
        qualified.append(receipt)
    titles = [item["title_id"] for item in qualified]
    lineages = [item.get("lineage_id") for item in qualified]
    if len(titles) != len(set(titles)):
        raise ValueError("pair receipts contain duplicate title identities")
    if len(lineages) != len(set(lineages)):
        raise ValueError("pair requires distinct source lineages")
    if any(not item.get("independent_authorship_evidence") for item in qualified):
        raise ValueError("pair requires evidence of independent authorship")
    return qualified[:2]


def _bound_file(root, record, *, max_bytes=None):
    """Validate one repository-relative, content-bound file without executing it."""
    if not isinstance(record, dict):
        raise ValueError('admission file binding is missing')
    path, expected = record.get('path'), record.get('sha256')
    if not isinstance(path, str) or not path or path.startswith('/') or '\\' in path or ':' in path:
        raise ValueError('admission file path is not repository-relative')
    parts = Path(path).parts
    if '..' in parts or not re.fullmatch(r'[0-9a-f]{64}', str(expected)):
        raise ValueError('admission file identity is malformed')
    if parts[0] in {'local-fixtures', 'build', 'tmp'} or any(part.startswith('.') for part in parts):
        raise ValueError('quarantined or hidden path cannot be admitted')
    root = Path(root).resolve()
    candidate = root.joinpath(*parts)
    # Reject symlinks at every component, including a symlink whose target is
    # still inside the root. Evidence paths are expected to identify exact files.
    cursor = root
    for part in parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError('admission file path contains a symlink')
    resolved = candidate.resolve(strict=True)
    if root not in resolved.parents or not resolved.is_file():
        raise ValueError('admission file escapes fixture root or is not a file')
    data = resolved.read_bytes()
    if max_bytes is not None and len(data) > max_bytes:
        raise ValueError('admission file exceeds size bound')
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('admission file digest mismatch: ' + path)
    return data


def _read_source_archive(root, archive_binding):
    """Inventory a bounded archive without extracting or executing members."""
    actual = {}
    directories = set()
    member_count = 0
    expanded_bytes = 0
    try:
        with tarfile.open(Path(root) / archive_binding['path'], 'r:*') as archive:
            for member in archive:
                member_count += 1
                if member_count > 20000:
                    raise ValueError('source archive exceeds member-count bound')
                raw_name = member.name
                if not isinstance(raw_name, str) or not raw_name or '\\' in raw_name:
                    raise ValueError('source archive contains an invalid member name')
                path = Path(raw_name.rstrip('/'))
                if (path.is_absolute() or '..' in path.parts or not path.parts
                        or any(part in ('', '.') for part in path.parts)
                        or ':' in raw_name
                        or raw_name not in (path.as_posix(), path.as_posix() + '/')
                        or (raw_name.endswith('/') and not member.isdir())
                        or member.issym() or member.islnk()):
                    raise ValueError('source archive contains an unsafe member')
                name = path.as_posix()
                if name in actual or name in directories:
                    raise ValueError('source archive member is duplicated')
                if member.isdir():
                    directories.add(name)
                    continue
                if not member.isfile() or member.size < 0 or member.size > 256 * 1024 * 1024:
                    raise ValueError('source archive contains a special or oversized member')
                expanded_bytes += member.size
                if expanded_bytes > 1024 * 1024 * 1024:
                    raise ValueError('source archive exceeds expanded-size bound')
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError('source archive member cannot be read')
                data = stream.read(256 * 1024 * 1024 + 1)
                if len(data) != member.size or len(data) > 256 * 1024 * 1024:
                    raise ValueError('source archive member size mismatch')
                actual[name] = {'path': name, 'bytes': len(data),
                                'sha256': hashlib.sha256(data).hexdigest()}
    except (OSError, tarfile.TarError) as exc:
        raise ValueError('source archive cannot be inventoried') from exc
    return actual


def _validate_reviewed_source_export(source_origin, archive_root, actual, material_rows,
                                     eligibility_row, source_revision):
    """Verify a privacy-safe source export against its immutable origin review."""
    if (not isinstance(source_origin, dict)
            or source_origin.get('schema') != 'genewhip-phase5-reviewed-source-export-v1'
            or set(source_origin) != {'schema', 'archive_sha256', 'source_revision',
                                      'root_prefix', 'member_map'}
            or source_origin.get('archive_sha256') != eligibility_row.get('source_archive_sha256')
            or source_origin.get('source_revision') != source_revision
            or not isinstance(source_origin.get('root_prefix'), str)
            or len(Path(source_origin.get('root_prefix', '')).parts) != 1
            or source_origin.get('root_prefix') != f"RECURSION94-{source_revision}"
            or not isinstance(source_origin.get('member_map'), list)):
        raise ValueError('reviewed source export does not retain its exact original archive ancestry')
    source_materials = {row['path']: row for row in material_rows
                        if row.get('origin', 'workspace') == 'workspace'
                        and row.get('source_revision') == source_revision}
    exported = source_origin['member_map']
    if (len(exported) != len(source_materials)
            or any(not isinstance(item, dict)
                   or set(item) != {'logical_path', 'origin_member', 'bytes', 'sha256'}
                   for item in exported)):
        raise ValueError('reviewed source export does not include exactly the upstream source material set')
    exported_by_path = {}
    for item in exported:
        logical = item['logical_path']
        if logical in exported_by_path:
            raise ValueError('reviewed source export mapping is ambiguous')
        exported_by_path[logical] = item
    if set(exported_by_path) != set(source_materials):
        raise ValueError('reviewed source export omits or adds logical source materials')
    expected_archive_files = set()
    for logical, material in source_materials.items():
        item = exported_by_path[logical]
        member = f'{archive_root}/{logical}'
        actual_row = actual.get(member)
        if (item.get('origin_member') != f"{source_origin['root_prefix']}/{logical}"
                or item.get('sha256') != material.get('sha256')
                or type(item.get('bytes')) is not int or item['bytes'] < 0
                or not actual_row or actual_row.get('sha256') != material.get('sha256')
                or actual_row.get('bytes') != item.get('bytes')):
            raise ValueError('reviewed source export changes an upstream path, size, or digest')
        expected_archive_files.add(member)
    if expected_archive_files != set(actual):
        raise ValueError('reviewed source export contains unreviewed or unmapped files')
    return exported_by_path


def validate_candidate_admission(candidate, root):
    """Fail-closed v1 admission chain for the two planned independent slots.

    This validates only declared data and bytes. It never imports or executes
    candidate build, route, source, or copied helper code.
    """
    if not isinstance(candidate, dict) or candidate.get('schema') != 'genewhip-phase5-admission-v1':
        raise ValueError('candidate admission schema mismatch')
    if set(candidate) != {'schema', 'fixture_id', 'slot_id', 'title_id', 'lineage_id', 'source_revision',
                          'status', 'outcome', 'project', 'license', 'assets', 'gates', 'promotion',
                          'route_evidence', 'identities'}:
        raise ValueError('candidate admission record has unreviewed fields')
    def inspect_public_value(value):
        if isinstance(value, dict):
            if any(re.search(r'(?:secret|password|token|stdout|stderr|log)', str(key), re.I) for key in value):
                raise ValueError('candidate admission record contains private or raw-log fields')
            for item in value.values():
                inspect_public_value(item)
        elif isinstance(value, list):
            for item in value:
                inspect_public_value(item)
        elif isinstance(value, str) and (re.search(r'/(?:Users|home)/[^/]+', value)
                                         or re.search(r'\b[^\s@]+@[^\s@]+\.[^\s@]+\b', value)
                                         or re.search(r'\b(?:password|token|secret)\s*[:=]', value, re.I)
                                         or 'BEGIN PRIVATE KEY' in value):
            raise ValueError('candidate admission record contains a private-path or secret sentinel')
    inspect_public_value(candidate)
    expected_ids = {'tank-battle': 'genewhip-phase5-a', 'recursion94': 'genewhip-phase5-b'}
    title, lineage = candidate.get('title_id'), candidate.get('lineage_id')
    slot = 'phase5-a' if title == 'tank-battle' else 'phase5-b'
    if (title not in expected_ids or candidate.get('fixture_id') != expected_ids[title]
            or candidate.get('slot_id') != slot):
        raise ValueError('candidate admission roster mismatch')
    if candidate.get('status') != 'qualified' or candidate.get('outcome') != 'pass':
        raise ValueError('candidate admission gates are not qualified')
    if (not isinstance(candidate.get('project'), str) or not candidate['project']
            or not isinstance(candidate.get('source_revision'), str)
            or not re.fullmatch(r'[0-9a-f]{40}', candidate['source_revision'])
            or not isinstance(lineage, str) or not lineage or candidate.get('license') in (None, '', 'unknown')
            or not isinstance(candidate.get('assets'), list)):
        raise ValueError('candidate source or material identity is incomplete')
    gate = candidate.get('gates')
    if not isinstance(gate, dict) or set(gate) != {'documentary', 'build', 'reference'}:
        raise ValueError('candidate admission gates are incomplete')
    for name in ('documentary', 'build', 'reference'):
        if gate[name] is not True:
            raise ValueError('candidate admission gate failed: ' + name)

    identities = candidate.get('identities')
    required = {'screening_ledger', 'eligibility', 'current_reference', 'reference_report',
                'source_archive', 'content_inventory', 'material_terms', 'build_recipe',
                'tool_lock', 'linked_runtime', 'build_record', 'raw_outputs', 'canonical_rom',
                'notices', 'notice_inventory',
                'scenario', 'input_schedule', 'input_program', 'oracle', 'reference_script',
                'reference_executable', 'reference_build', 'reference_pair', 'runs'}
    if not isinstance(identities, dict) or set(identities) != required:
        raise ValueError('candidate admission identity set is incomplete')
    # These four references are the only trust roots for a new admission.
    # A candidate cannot make its own parallel ledger/report authoritative by
    # naming arbitrary, self-consistent files under its fixture directory.
    if (identities['screening_ledger'].get('path') != 'fixtures/candidate-screening-v2.json'
            or identities['eligibility'].get('path') != 'evidence/phase5-eligibility-v2.json'
            or identities['current_reference'].get('path') != 'evidence/phase5-current-reference.json'):
        raise ValueError('candidate admission trust-root path is not canonical')
    bound = {}
    for name in required - {'raw_outputs', 'notices', 'runs'}:
        bound[name] = _bound_file(root, identities[name],
                                  max_bytes=256 * 1024 * 1024 if name == 'source_archive' else None)
    try:
        ledger = json.loads(bound['screening_ledger'])
        eligibility = json.loads(bound['eligibility'])
        current = json.loads(bound['current_reference'])
        report = json.loads(bound['reference_report'])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError('screening, eligibility, or reference gate is invalid JSON') from exc
    # These gates descend from the anchored v1 history and identify the actual
    # selected pair. A manifest status or a user-supplied title list is not a gate.
    _validate_current_screening(ledger, root)
    validate_current_eligibility(eligibility, root)
    pair = require_pair(ledger.get('selected_pair'))
    selected = next((item for item in pair if item.get('title_id') == title), None)
    if (selected is None or selected.get('lineage_id') != lineage
            or selected.get('source_revision') != candidate.get('source_revision')
            or selected.get('reference_report_sha256') != identities['reference_report']['sha256']):
        raise ValueError('candidate is not the exact selected eligible lineage')
    if (not isinstance(current, dict) or current.get('schema') != 'genewhip-phase5-current-reference-v1'
            or current.get('status') != 'qualified-pair'
            or current.get('selected_pair') != ['tank-battle', 'recursion94']
            or current.get('candidate_baseline') != 'not-run'
            or current.get('report') != {'path': identities['reference_report']['path'],
                                         'sha256': identities['reference_report']['sha256']}):
        raise ValueError('current reference pointer is stale or not qualified')
    if (not isinstance(report, dict) or report.get('schema') != 'genewhip-phase5-reference-v1'
            or report.get('decision') != current.get('decision') or report.get('status') != 'pass'
            or report.get('errors') != [] or report.get('selected_pair') != current['selected_pair']
            or report.get('candidate_genewhip_baseline') != 'not-run'):
        raise ValueError('reference report is stale or does not qualify the selected pair')
    if (identities['reference_report'].get('path') != current.get('report', {}).get('path')
            or identities['reference_report'].get('path') != 'evidence/phase5-reference-d118.json'):
        raise ValueError('reference report trust-root path is not canonical')
    eligibility_row = next((item for item in eligibility.get('candidates', [])
                            if item.get('title_id') == title), None)
    if (not isinstance(eligibility_row, dict) or eligibility_row.get('decision') != 'eligible'
            or eligibility_row.get('lineage_id') != lineage
            or eligibility_row.get('source_revision') != candidate.get('source_revision')):
        raise ValueError('candidate documentary eligibility is missing')
    if (title == 'tank-battle'
            and identities['source_archive'].get('sha256') != eligibility_row.get('source_archive_sha256')):
        raise ValueError('source archive differs from anchored eligibility review')
    frozen = eligibility_row.get('reference_route', {}).get('frozen')
    if not isinstance(frozen, dict):
        raise ValueError('anchored eligibility has no frozen reference route')
    route = next((item for item in report.get('routes', [])
                  if isinstance(item, dict) and item.get('title_id') == title), None)
    if (not isinstance(route, dict) or route.get('frozen') != frozen
            or frozen.get('title_id') != title
            or frozen.get('script_sha256') != identities['reference_script'].get('sha256')):
        raise ValueError('scenario, oracle, or script differs from anchored reference route')
    try:
        scenario = json.loads(bound['scenario'])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError('frozen scenario is invalid JSON') from exc
    canonical_json = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    canonical_digest = lambda value: hashlib.sha256(canonical_json(value)).hexdigest()
    if (not isinstance(scenario, dict) or scenario.get('title_id') != title
            or (scenario.get('rom_sha256') is not None
                and scenario.get('rom_sha256') != identities['canonical_rom'].get('sha256'))
            or canonical_digest(scenario) != frozen.get('scenario_sha256')):
        raise ValueError('scenario ROM or embedded input identities do not match admission bytes')
    try:
        oracle = json.loads(bound['oracle'])
        schedule_file = json.loads(bound['input_schedule'])
        program_file = json.loads(bound['input_program'])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError('oracle or frozen input files are invalid JSON') from exc
    if (canonical_digest(oracle) != frozen.get('oracle_sha256')
            or oracle.get('title_id') != title
            or schedule_file != scenario.get('input_schedule')
            or program_file != scenario.get('input_program')):
        raise ValueError('oracle or input files differ from canonical frozen route data')
    scenario_ids = scenario.get('identities')
    if (not isinstance(scenario_ids, dict)
            or scenario_ids.get('source_archive_sha256') != eligibility_row.get('source_archive_sha256')
            or scenario_ids.get('source_revision') != candidate.get('source_revision')
            or scenario_ids.get('rom_sha256') != identities['canonical_rom'].get('sha256')
            or scenario_ids.get('mame_script_sha256') != identities['reference_script'].get('sha256')
            or scenario_ids.get('input_sha256') != canonical_digest({
                'input_schedule': scenario.get('input_schedule'),
                'input_program': scenario.get('input_program')})):
        raise ValueError('source, ROM, or input identity differs from frozen scenario')
    try:
        executable_pin = json.loads(bound['reference_executable'])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError('reference executable pin descriptor is invalid JSON') from exc
    if (not isinstance(executable_pin, dict)
            or executable_pin.get('schema') != 'genewhip-phase5-reference-executable-v1'
            or set(executable_pin) != {'schema', 'executable_sha256', 'source_revision',
                                      'source_archive_sha256', 'patch_sha256'}
            or executable_pin.get('executable_sha256') != scenario_ids.get('mame_build_sha256')
            or executable_pin.get('source_revision') != scenario_ids.get('mame_source_revision')
            or executable_pin.get('source_archive_sha256') != scenario_ids.get('mame_source_sha256')
            or executable_pin.get('patch_sha256') != scenario_ids.get('mame_patch_sha256')):
        raise ValueError('reference executable pin differs from frozen MAME source/build identities')
    try:
        reference_build = json.loads(bound['reference_build'])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError('reference build identity is invalid JSON') from exc
    if (not isinstance(reference_build, dict)
            or reference_build.get('schema') != 'genewhip-phase5-reference-build-v1'
            or reference_build.get('scenario_sha256') != identities['scenario'].get('sha256')
            or reference_build.get('tool_lock_sha256') != identities['tool_lock'].get('sha256')
            or reference_build.get('executable_sha256') != executable_pin.get('executable_sha256')
            or reference_build.get('script_sha256') != identities['reference_script'].get('sha256')
            or reference_build.get('input_schedule_sha256') != identities['input_schedule'].get('sha256')
            or reference_build.get('input_program_sha256') != identities['input_program'].get('sha256')
            or reference_build.get('mame_source_revision') != scenario_ids.get('mame_source_revision')
            or reference_build.get('mame_source_sha256') != scenario_ids.get('mame_source_sha256')
            or reference_build.get('mame_patch_sha256') != scenario_ids.get('mame_patch_sha256')):
        raise ValueError('reference executable/build does not match frozen scenario and tool lock')
    # Inventory the source archive without extraction, imports, or execution.
    try:
        inventory = json.loads(bound['content_inventory'])
        terms = json.loads(bound['material_terms'])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError('source inventory or material terms is invalid JSON') from exc
    if (not isinstance(inventory, dict) or inventory.get('schema') != 'genewhip-phase5-content-inventory-v1'
            or not isinstance(inventory.get('files'), list) or not inventory['files']
            or not isinstance(inventory.get('archive_root'), str)
            or len(Path(inventory.get('archive_root', '')).parts) != 1
            or inventory.get('archive_root') in ('', '.', '..')
            or not isinstance(terms, dict) or terms.get('schema') != 'genewhip-phase5-material-terms-v1'
            or not isinstance(terms.get('materials'), list)):
        raise ValueError('source inventory or material terms are incomplete')
    archive_binding = identities['source_archive']
    actual = _read_source_archive(root, archive_binding)
    listed = inventory['files']
    if (listed != sorted(listed, key=lambda item: item.get('path', '') if isinstance(item, dict) else '')
            or listed != [actual[key] for key in sorted(actual)]):
        raise ValueError('expanded source content inventory differs from archive bytes')
    archive_root = inventory['archive_root']
    if any(path.split('/', 1)[0] != archive_root for path in actual):
        raise ValueError('source archive does not use its single declared root prefix')
    source_origin = inventory.get('source_origin')
    if title == 'tank-battle' and source_origin is not None:
        raise ValueError('Tank source inventory cannot replace its exact upstream archive')
    material_rows = terms['materials']
    if material_rows != selected.get('materials'):
        raise ValueError('material terms differ from the anchored eligibility review')
    # The source archive may be retained only in local review storage after
    # promotion. Its digest and expanded inventory are still bound together;
    # separately, the exact material terms list must equal the anchored review.
    if len({row.get('path') for row in material_rows if isinstance(row, dict)}) != len(material_rows):
        raise ValueError('eligible material terms contain duplicate paths')
    material_by_path = {material['path']: material for material in material_rows}
    workspace_materials = {row['path']: row for row in material_rows
                           if row.get('origin', 'workspace') == 'workspace'}
    if title == 'recursion94':
        _validate_reviewed_source_export(source_origin, archive_root, actual, material_rows,
                                         eligibility_row, candidate.get('source_revision'))
    locations = terms.get('material_locations')
    if not isinstance(locations, list) or len(locations) != len(workspace_materials):
        raise ValueError('material location map does not cover the exact reviewed workspace set')
    locations_by_path = {}
    for location in locations:
        if not isinstance(location, dict) or not isinstance(location.get('logical_path'), str):
            raise ValueError('material location map has an invalid row')
        logical_path = location['logical_path']
        if logical_path in locations_by_path:
            raise ValueError('material location map is ambiguous')
        locations_by_path[logical_path] = location
    if set(locations_by_path) != set(workspace_materials):
        raise ValueError('material location map differs from exact reviewed workspace set')
    for logical_path, material in workspace_materials.items():
        location = locations_by_path[logical_path]
        kind = location.get('kind')
        if kind == 'archive-member':
            if set(location) != {'logical_path', 'kind', 'member_path', 'sha256'}:
                raise ValueError('archive material location has unknown fields')
            member_path = location['member_path']
            archived = actual.get(member_path)
            if title == 'tank-battle':
                expected_member = (f'{archive_root}/LICENSE' if logical_path == 'LICENSE' else
                                   f'{archive_root}/genesis/tank-battle/{logical_path}')
            elif material.get('source_revision') == candidate.get('source_revision'):
                expected_member = f'{archive_root}/{logical_path}'
            else:
                expected_member = None
            if (not isinstance(member_path, str) or not archived
                    or (expected_member is not None and member_path != expected_member)
                    or location.get('sha256') != material.get('sha256')
                    or archived.get('sha256') != material.get('sha256')):
                raise ValueError('archive material location differs from selected reviewed bytes')
        elif kind == 'reviewed-override':
            if set(location) != {'logical_path', 'kind', 'file', 'source_revision'}:
                raise ValueError('reviewed override location has unknown fields')
            allowed_override = ((title == 'tank-battle' and logical_path in ('Makefile', 'build.sh')
                                 and location.get('source_revision') == '0e04e1c2552fe174ecb3051adf270a65b2b2c819')
                                or (title == 'recursion94' and material.get('category') == 'build_tools'
                                    and isinstance(material.get('source_revision'), str)
                                    and material['source_revision'].startswith('sha256:')
                                    and location.get('source_revision') == material.get('source_revision')))
            if (not allowed_override
                    or location.get('source_revision') != material.get('source_revision')
                    or location.get('source_revision') == candidate.get('source_revision')
                    or not isinstance(location.get('file'), dict)
                    or location['file'].get('sha256') != material.get('sha256')):
                raise ValueError('reviewed override is not the pinned source-context input')
            override_bytes = _bound_file(root, location['file'])
            if hashlib.sha256(override_bytes).hexdigest() != material.get('sha256'):
                raise ValueError('reviewed override bytes differ from selected material hash')
        else:
            raise ValueError('material location kind is unsupported')
    if title == 'recursion94':
        mapped_archive_members = {row['member_path'] for row in locations
                                  if row.get('kind') == 'archive-member'}
        if mapped_archive_members != set(actual):
            raise ValueError('reviewed source export contains unreviewed or unmapped files')
    if any(row.get('origin', 'workspace') == 'image' for row in material_rows):
        for material in material_rows:
            if material.get('origin', 'workspace') != 'image':
                continue
            if (not material.get('image') or not material.get('source_revision')
                    or material.get('license') in (None, '', 'unknown')
                    or not material.get('notice') or not material.get('terms_source')):
                raise ValueError('image-origin material is not bound to reviewed tool/runtime terms')
    if any(path in material_by_path and material_by_path[path]['sha256'] != item['sha256']
           for path, item in actual.items()):
        raise ValueError('expanded source file differs from its eligible material hash')
    for material in material_rows:
        if (material.get('license') in (None, '', 'unknown', 'repository-top-level-only')
                or material.get('notice') in (None, '', 'missing')
                or not isinstance(material.get('terms_source'), str) or not material['terms_source']):
            raise ValueError('source material lacks exact terms or notice')
    if not isinstance(identities['notices'], list) or not identities['notices']:
        raise ValueError('candidate notices are missing')
    for item in identities['notices']:
        _bound_file(root, item)
    notice_paths = {covered for item in identities['notices']
                    for covered in item.get('covers', []) if isinstance(covered, str)}
    expected_notices = {item['notice'] for item in material_rows}
    if notice_paths != expected_notices:
        raise ValueError('source material notice is not retained')
    outputs = identities['raw_outputs']
    if not isinstance(outputs, list) or len(outputs) != 2:
        raise ValueError('exactly two raw build outputs are required')
    for ordinal, output in enumerate(outputs, 1):
        if not isinstance(output, dict) or output.get('ordinal') != ordinal:
            raise ValueError('raw build output order is not explicit')
        _bound_file(root, output)
    if outputs[0]['sha256'] != outputs[1]['sha256']:
        raise ValueError('clean build outputs differ')
    canonical = identities['canonical_rom']
    if canonical.get('sha256') != outputs[0]['sha256']:
        raise ValueError('canonical ROM is not the reproducible build output')
    _bound_file(root, canonical)
    try:
        build_record = json.loads(bound['build_record'])
        notice_index = json.loads(_bound_file(root, identities['notice_inventory']))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError('build or notice record is invalid JSON') from exc
    expected_build_outputs = [{'ordinal': output['ordinal'], 'bytes': (root / output['path']).stat().st_size,
                               'sha256': output['sha256']} for output in outputs]
    # Historical source-build summaries use the short title stem, while
    # promoted fixture folders and admission IDs use the full title ID.
    build_summary_path = {
        'tank-battle': 'evidence/phase5-tank-build-summary.json',
        'recursion94': 'evidence/phase5-recursion-build-summary.json',
    }[title]
    source_build = build_record.get('source_build_summary') if isinstance(build_record, dict) else None
    if not isinstance(source_build, dict) or source_build.get('path') != build_summary_path:
        raise ValueError('build receipt does not cite the selected source build summary')
    try:
        source_summary = json.loads(_bound_file(root, source_build))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError('selected source build summary is invalid JSON') from exc
    if (not isinstance(source_summary, dict) or source_summary.get('title_id') != title
            or source_summary.get('source_revision') != candidate.get('source_revision')):
        raise ValueError('source build summary identity differs from selected eligibility')
    if title == 'tank-battle':
        summary_outputs = source_summary.get('comparison', {}).get('raw_outputs')
        expected_receipt_sha = eligibility_row.get('build_evidence', {}).get('receipt_sha256')
        summary_receipt_sha = source_summary.get('receipt', {}).get('sha256')
    else:
        summary_outputs = source_summary.get('build_pair', {}).get('builds')
        expected_receipt_sha = scenario_ids.get('build_receipt_sha256')
        summary_receipt_sha = source_summary.get('build_pair', {}).get('receipt_sha256')
    if (not isinstance(summary_outputs, list)
            or [{'ordinal': item.get('ordinal'), 'bytes': item.get('bytes', item.get('bytes_count')),
                 'sha256': item.get('sha256')} for item in summary_outputs] != expected_build_outputs
            or summary_receipt_sha != expected_receipt_sha
            or scenario_ids.get('build_receipt_sha256') != summary_receipt_sha):
        raise ValueError('build receipt is not anchored to the selected qualified source build summary')
    recipe_bytes = bound['build_recipe']
    try:
        recipe_document = json.loads(recipe_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        recipe_document = None
    recipe_identity = (identities['build_recipe'].get('sha256')
                       if identities['build_recipe'].get('sha256') ==
                       (build_record or {}).get('build_recipe_sha256') else
                       (recipe_document.get('build_configuration_sha256')
                        if isinstance(recipe_document, dict) else None))
    try:
        runtime_document = json.loads(bound['linked_runtime'])
    except (UnicodeDecodeError, json.JSONDecodeError):
        runtime_document = None
    runtime_identity = (identities['linked_runtime'].get('sha256')
                        if identities['linked_runtime'].get('sha256') ==
                        (build_record or {}).get('linked_runtime_sha256') else
                        (runtime_document.get('linked_runtime_sha256')
                         if isinstance(runtime_document, dict) else None))
    try:
        tool_lock_document = json.loads(bound['tool_lock'])
    except (UnicodeDecodeError, json.JSONDecodeError):
        tool_lock_document = None
    tool_lock_identity = (identities['tool_lock'].get('sha256')
                          if identities['tool_lock'].get('sha256') ==
                          (build_record or {}).get('tool_lock_sha256') else
                          (tool_lock_document.get('build_record_tool_lock_sha256')
                           if isinstance(tool_lock_document, dict) else None))
    if (not isinstance(build_record, dict) or build_record.get('schema') != 'genewhip-phase5-build-record-v1'
            or build_record.get('title_id') != title or build_record.get('source_revision') != candidate['source_revision']
            or build_record.get('status') != 'pass' or build_record.get('comparison') != 'byte-identical'
            or build_record.get('build_recipe_sha256') != recipe_identity
            or build_record.get('tool_lock_sha256') != tool_lock_identity
            or (build_record.get('linked_runtime_sha256') != runtime_identity
                and not (build_record.get('linked_runtime_sha256') is None
                         and isinstance(runtime_document, dict)
                         and runtime_document.get('status') == 'not-applicable'))
            or build_record.get('raw_outputs') != expected_build_outputs
            or build_record.get('canonical_rom_sha256') != canonical['sha256']):
        raise ValueError('repeatable build receipt does not bind selected material and output bytes')
    reviewed_outputs = eligibility_row.get('generated_outputs')
    if isinstance(reviewed_outputs, list) and reviewed_outputs:
        selected_outputs = [item for item in reviewed_outputs if item.get('category') == 'generated_rom']
        expected_reviewed = [{'ordinal': item.get('ordinal'), 'bytes': item.get('bytes'),
                              'sha256': item.get('sha256')} for item in selected_outputs]
        if expected_reviewed != expected_build_outputs:
            raise ValueError('build outputs differ from anchored generated-ROM evidence')
    else:
        route_rom = eligibility_row.get('reference_route', {}).get('rom_sha256')
        if route_rom != canonical.get('sha256'):
            raise ValueError('canonical ROM differs from anchored reference route')
    if (not isinstance(notice_index, dict) or notice_index.get('schema') != 'genewhip-phase5-notice-index-v1'
            or notice_index.get('notices') != identities['notices']):
        raise ValueError('retained notice inventory is stale')
    promotion = candidate.get('promotion')
    expected_promotion = {
        'source_tree_identity': identities['content_inventory']['path'],
        'source_tree_sha256': identities['content_inventory']['sha256'],
        'build_lock': identities['tool_lock']['path'],
        'build_lock_sha256': identities['tool_lock']['sha256'],
        'notices': identities['notice_inventory']['path'],
        'notices_sha256': identities['notice_inventory']['sha256'],
        'build_receipt_sha256': identities['build_record']['sha256'],
        'rom': canonical['path'], 'rom_sha256': canonical['sha256'],
    }
    if promotion != expected_promotion:
        raise ValueError('promotion identities do not map to validated material and build bytes')
    route_evidence = candidate.get('route_evidence')
    frozen_route_sha = identity_digest({key: identities[key]['sha256'] for key in
                                         ('scenario', 'input_schedule', 'input_program', 'oracle', 'reference_script')})
    if (not isinstance(route_evidence, dict)
            or route_evidence.get('canonical_rom_sha256') != canonical['sha256']
            or route_evidence.get('frozen_route_sha256') != frozen_route_sha
            or route_evidence.get('reference_pair_sha256') != identities['reference_pair']['sha256']):
        raise ValueError('route evidence does not bind the promoted ROM and frozen route')

    # The reference binding is a hash of a complete, fresh, distinct two-run
    # pair receipt. Each run and every raw capture is independently bound.
    pair_bytes = _bound_file(root, identities['reference_pair'])
    try:
        pair = json.loads(pair_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError('reference pair receipt is invalid JSON') from exc
    if (not isinstance(pair, dict) or pair.get('schema') != 'genewhip-phase5-reference-pair-v1'
            or pair.get('status') != 'pass' or pair.get('errors') != []
            or pair.get('title_id') != title or pair.get('lineage_id') != lineage
            or pair.get('reference_qualification') != 'qualified'):
        raise ValueError('independent reference pair is not qualified')
    pair_identities = pair.get('identities')
    expected_pair_identities = {
        'scenario': identities['scenario']['sha256'],
        'input_schedule': identities['input_schedule']['sha256'],
        'input_program': identities['input_program']['sha256'],
        'oracle': identities['oracle']['sha256'],
        'reference_script': identities['reference_script']['sha256'],
        'reference_executable': identities['reference_executable']['sha256'],
        'reference_build': identities['reference_build']['sha256'],
        'rom': canonical['sha256'],
    }
    if pair_identities != expected_pair_identities:
        raise ValueError('reference pair is stale for frozen scenario or selected ROM')
    if (not isinstance(route, dict) or route.get('status') != 'pass'
            or route.get('lineage_id') != lineage or route.get('source_revision') != candidate['source_revision']
            or len(route.get('runs', [])) != 2
            or [item.get('repetition') for item in route.get('runs', [])] != [1, 2]):
        raise ValueError('current reference report lacks two fresh candidate runs')
    runs = identities['runs']
    if not isinstance(runs, list) or len(runs) != 2:
        raise ValueError('two fresh reference runs are required')
    ids = set()
    for ordinal, run in enumerate(runs, 1):
        if (not isinstance(run, dict) or run.get('ordinal') != ordinal
                or run.get('status') != 'pass' or run.get('fresh') is not True
                or not isinstance(run.get('run_id'), str) or not run['run_id']
                or run['run_id'] in ids):
            raise ValueError('reference run is not fresh, passing, and distinct')
        ids.add(run['run_id'])
        receipt_bytes = _bound_file(root, run.get('receipt'))
        try:
            receipt_doc = json.loads(receipt_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError('reference run receipt is invalid JSON') from exc
        raw = run.get('raw_captures')
        if (not isinstance(raw, list) or not raw
                or not isinstance(receipt_doc, dict) or receipt_doc.get('schema') != 'genewhip-phase5-reference-run-v1'
                or receipt_doc.get('status') != 'pass' or receipt_doc.get('run_id') != run['run_id']
                or receipt_doc.get('raw_capture_sha256') != [item.get('sha256') for item in raw]):
            raise ValueError('reference run raw captures are missing')
        for capture in raw:
            capture_bytes = _bound_file(root, capture)
            # Captures are canonical report-run records, including all cases,
            # input rows, and controls. This ties their bytes to the trusted
            # reference report instead of accepting a self-hashed placeholder.
            expected_capture = canonical_json(route['runs'][ordinal - 1])
            if capture_bytes != expected_capture:
                raise ValueError('raw capture differs from trusted reference run/case data')
    pair_runs = pair.get('runs')
    expected_runs = [{
        'ordinal': run['ordinal'], 'run_id': run['run_id'],
        'receipt_sha256': run['receipt']['sha256'],
        'raw_captures': [item['sha256'] for item in run['raw_captures']],
    } for run in runs]
    if pair_runs != expected_runs:
        raise ValueError('reference pair does not bind both fresh raw-capture runs')
    if reference_build.get('capture_sha256') != [capture['sha256'] for run in runs for capture in run['raw_captures']]:
        raise ValueError('reference build does not bind actual report-run capture requests')
    return 'ok'

# D-108–D-112 amend only NEW executions. V1 constants and receipts retain
# their original four-task semantics; these anchors are not caller supplied.
SCREENING_V2 = 'genewhip-phase5-screening-v2'
ELIGIBILITY_V2 = 'genewhip-phase5-eligibility-v2'
POLICY_V2 = 'genewhip-phase5-policy-v2'
MIGRATION_V2 = 'genewhip-phase5-policy-migration-v2'
REPO_ROOT = Path(__file__).resolve().parents[2]
HISTORICAL_ANCHORS = {
    'fixtures/candidate-screening.json': '09cf99ed2f42af79f17171880bb9873db178a75ae75ef5201fb386e90c58a78e',
    'evidence/phase5-eligibility.json': '4c90ff33e2414dde1c8854d031de481ce850c57b92adca6bf6c8cdf494355b89',
    '.planning/phases/GW-05-candidate-admission-and-baseline/05-02-SUMMARY.md':
        '94a469ac11f2914a940279bdd501cfc6695e917b25e6f8b735f1c02e9cd6e7b7',
}
SETUP_CONSUMED_US = 379039387
SETUP_REMAINING_US = 1420960613
PROBE_CEILING_US = 120000000
CONTINUATION_EVENTS = {'policy_amendment', 'setup_continuation_started',
                       'setup_continuation_charged', 'setup_continuation_completed'}


def amended_policy():
    return {
        'schema': POLICY_V2, 'amendment': 'D-108-D-112',
        'limits': {k: v for k, v in SCREENING_LIMITS.items() if k != 'build_processes'},
        'linux_tasks_per_container': 64, 'cpus_per_container': 4,
        'concurrent_build_jobs': 4, 'aggregate_container_memory_bytes': 8589934592,
        'swap_bytes': 0, 'address_space_bytes_per_process': 8589934592,
        'user': '65532:65532', 'network': 'none', 'read_only_root': True,
        'cap_drop': ['ALL'], 'no_new_privileges': True, 'host_mounts': [],
        'environment': {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/work/home',
                        'TMPDIR': '/tmp', 'LC_ALL': 'C'},
        'work_mount_mode': 'noexec', 'declared_native_exec_allowed': True,
        'work_mount_bytes': 8589934592, 'work_mount_flags': ['nosuid', 'nodev'],
        'tmp_mount_mode': 'noexec', 'tmp_mount_bytes': 1073741824,
        'continuation': {'title_id': 'tank-battle', 'uses': 1,
                         'total_ceiling_us': 1800000000, 'consumed_us': SETUP_CONSUMED_US,
                         'remaining_us': SETUP_REMAINING_US, 'probe_ceiling_us': PROBE_CEILING_US},
    }


def effective_policy(document):
    if not isinstance(document, dict):
        raise ValueError('policy must be an object')
    if document.get('schema') == SCREENING_SCHEMA:
        validate_screening(document)
        return {'schema': 'genewhip-phase5-policy-v1', 'limits': dict(SCREENING_LIMITS),
                'linux_tasks_per_container': 4, 'cpus_per_container': 4,
                'concurrent_build_jobs': 4, 'work_mount_mode': 'noexec'}
    policy = document.get('policy') if document.get('schema') == SCREENING_V2 else document
    # Equality alone would accept bools/floats in place of integer policy values.
    if (not isinstance(policy, dict) or json.dumps(policy, sort_keys=True) !=
            json.dumps(amended_policy(), sort_keys=True)):
        raise ValueError('amended policy differs from frozen task/CPU/job/resource contract')
    if document.get('schema') == SCREENING_V2 and document.get('policy_sha256') != identity_digest(policy):
        raise ValueError('current policy digest mismatch')
    return copy.deepcopy(policy)


def _historical(root=REPO_ROOT):
    root = Path(root)
    docs = []
    for relative, expected in HISTORICAL_ANCHORS.items():
        data = (root / relative).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('historical byte anchor mismatch: ' + relative)
        if relative.endswith('.json'):
            docs.append(json.loads(data))
    validate_screening(docs[0])
    return docs


def _amendment_identity(policy):
    return {'amendment': 'D-108-D-112', 'historical_anchors': HISTORICAL_ANCHORS,
            'policy_sha256': identity_digest(policy), 'continuation': policy['continuation']}


def _append_current_event(ledger, name, details):
    result = copy.deepcopy(ledger)
    tank = result['candidates'][0]
    history = tank['identity_history']
    event = {'ordinal': len(history) + 1, 'title_id': 'tank-battle', 'event': name,
             'identity_sha256': identity_digest(_amendment_identity(result['policy'])),
             'previous_sha256': history[-1]['sha256'], 'details': copy.deepcopy(details)}
    event['sha256'] = _event_chain_digest(event)
    history.append(event)
    tank['counters'] = _derived_counters(history)
    return result


def migrate_screening(root, policy):
    effective_policy(policy)
    old, eligibility = _historical(root)
    ledger = copy.deepcopy(old)
    ledger.update(schema=SCREENING_V2, policy=copy.deepcopy(policy),
                  policy_sha256=identity_digest(policy), historical_anchors=dict(HISTORICAL_ANCHORS))
    ledger = _append_current_event(ledger, 'policy_amendment', _amendment_identity(policy))
    current_eligibility = copy.deepcopy(eligibility)
    current_eligibility.update(schema=ELIGIBILITY_V2, historical_anchors=dict(HISTORICAL_ANCHORS),
                               policy_sha256=identity_digest(policy))
    receipt = {'schema': MIGRATION_V2, 'historical_anchors': dict(HISTORICAL_ANCHORS),
               'old_policy_sha256': identity_digest(effective_policy(old)),
               'policy_sha256': identity_digest(policy),
               'historical_prefix_sha256': identity_digest({c['id']: c['identity_history'] for c in old['candidates']}),
               'original_probe_receipts': copy.deepcopy(old['candidates'][0]['identity_history'][3]['details']['probe_receipts']),
               'initial_ledger_sha256': identity_digest(ledger),
               'initial_eligibility_sha256': identity_digest(current_eligibility),
               'migration_code': {relative: hashlib.sha256((REPO_ROOT / relative).read_bytes()).hexdigest()
                                  for relative in ('tools/evidence/phase5_records.py', 'scripts/fixtures/phase5_candidate.py')},
               'candidate_execution': False, 'eligibility_granted': False}
    validate_policy_migration(ledger, current_eligibility, receipt, root)
    return ledger, current_eligibility, receipt


def _validate_current_screening(ledger, root=REPO_ROOT):
    effective_policy(ledger)
    if ledger.get('historical_anchors') != HISTORICAL_ANCHORS:
        raise ValueError('historical anchor mismatch')
    old, _ = _historical(root)
    if [c.get('id') for c in ledger.get('candidates', [])] != list(SCREENING_IDS):
        raise ValueError('current screening roster identity mismatch')
    for original, current in zip(old['candidates'], ledger['candidates']):
        history = current.get('identity_history', [])
        prefix = original['identity_history']
        if history[:len(prefix)] != prefix:
            raise ValueError('historical event prefix changed (including original probe receipts)')
        for key in ('source_revision', 'repository', 'lineage_id'):
            if current.get(key) != original[key]:
                raise ValueError('historical title/source identity changed')
        if any(e.get('event') in CONTINUATION_EVENTS for e in history[len(prefix):]) and current['id'] != 'tank-battle':
            raise ValueError('continuation cannot change title identity')
        if _derived_counters(history) != current.get('counters'):
            raise ValueError('title counters do not match append-only identity history')
    # Reuse the original validator without reinterpreting its frozen limits.
    legacy_shape = {k: v for k, v in ledger.items() if k not in
                    ('policy', 'policy_sha256', 'historical_anchors')}
    legacy_shape['schema'] = SCREENING_SCHEMA
    validate_screening(legacy_shape)
    setup_continuation_state(ledger, validate=False)
    return ledger


def validate_current_eligibility(document, root=REPO_ROOT):
    schema = document.get('schema')
    if schema == 'genewhip-phase5-eligibility-v1':
        if any(key in document for key in ('policy_sha256', 'historical_anchors')):
            raise ValueError('current eligibility cannot be downgraded to historical schema')
        return document
    if schema != ELIGIBILITY_V2 or document.get('historical_anchors') != HISTORICAL_ANCHORS:
        raise ValueError('current eligibility schema/ancestry mismatch')
    if document.get('policy_sha256') != identity_digest(amended_policy()):
        raise ValueError('current eligibility policy digest mismatch')
    _, original = _historical(root)
    candidates = document.get('candidates', [])
    if [c.get('title_id') for c in candidates] != list(SCREENING_IDS):
        raise ValueError('current eligibility roster mismatch')
    for candidate, old in zip(candidates, original['candidates']):
        if not set(old).issubset(candidate):
            raise ValueError('historical material review fields were dropped')
        if (candidate.get('review') != old['review']
                or candidate.get('reviewed_materials', [])[:len(old['reviewed_materials'])] != old['reviewed_materials']):
            raise ValueError('historical material review prefix changed')
        if any(candidate.get(k) != old[k] for k in ('title_id', 'source_revision', 'repository', 'lineage_id')):
            raise ValueError('current eligibility historical source identity changed')
        if candidate.get('decision') == 'eligible' and (
                not validate_eligibility(candidate) or not inspect_materials(candidate)['eligible']):
            raise ValueError('current eligibility material rights remain unresolved')
        if candidate.get('decision') != 'eligible' and candidate.get('unverified_categories') != old['unverified_categories']:
            raise ValueError('historical unknown material categories were dropped')
    return document


def validate_policy_migration(ledger, eligibility, receipt, root=REPO_ROOT):
    _validate_current_screening(ledger, root)
    validate_current_eligibility(eligibility, root)
    old, historical_eligibility = _historical(root)
    expected = {'schema': MIGRATION_V2, 'historical_anchors': HISTORICAL_ANCHORS,
                'old_policy_sha256': identity_digest(effective_policy(old)),
                'policy_sha256': ledger['policy_sha256'],
                'historical_prefix_sha256': identity_digest({c['id']: c['identity_history'] for c in old['candidates']}),
                'original_probe_receipts': old['candidates'][0]['identity_history'][3]['details']['probe_receipts'],
                'candidate_execution': False, 'eligibility_granted': False}
    initial = copy.deepcopy(old)
    initial.update(schema=SCREENING_V2, policy=amended_policy(), policy_sha256=ledger['policy_sha256'],
                   historical_anchors=dict(HISTORICAL_ANCHORS))
    initial = _append_current_event(initial, 'policy_amendment', _amendment_identity(initial['policy']))
    initial_eligibility = copy.deepcopy(historical_eligibility)
    initial_eligibility.update(schema=ELIGIBILITY_V2, historical_anchors=dict(HISTORICAL_ANCHORS),
                               policy_sha256=ledger['policy_sha256'])
    expected.update(initial_ledger_sha256=identity_digest(initial),
                    initial_eligibility_sha256=identity_digest(initial_eligibility))
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise ValueError('policy migration receipt mismatch: ' + key)
    code = receipt.get('migration_code')
    if (not isinstance(code, dict) or set(code) != {'tools/evidence/phase5_records.py', 'scripts/fixtures/phase5_candidate.py'}
            or any(not isinstance(v, str) or re.fullmatch('[0-9a-f]{64}', v) is None for v in code.values())):
        raise ValueError('migration code identities are missing')
    return receipt


def setup_continuation_state(ledger, *, validate=True):
    if validate:
        _validate_current_screening(ledger)
    policy = effective_policy(ledger)
    state, elapsed, probe = 'available', 0, None
    events = ledger['candidates'][0]['identity_history'][4:]
    if (not events or events[0].get('event') != 'policy_amendment'
            or events[0].get('details') != _amendment_identity(policy)):
        raise ValueError('single-use policy amendment is missing or changed')
    identity = identity_digest(_amendment_identity(policy))
    for event in events:
        name, details = event.get('event'), event.get('details', {})
        if name in ('build_setup_started', 'build_setup_completed', 'build_setup_failed'):
            raise ValueError('Tank setup must use the single-use cumulative continuation')
        if name not in CONTINUATION_EVENTS:
            continue
        if event.get('identity_sha256') != identity:
            raise ValueError('single-use continuation identity mismatch')
        if name == 'policy_amendment':
            if event is not events[0]:
                raise ValueError('single-use amendment cannot be reissued')
        elif name == 'setup_continuation_started':
            if state != 'available' or details != {'remaining_us': SETUP_REMAINING_US}:
                raise ValueError('single-use continuation cannot restart or renew budget')
            state = 'in-flight'
        elif name == 'setup_continuation_charged':
            value = details.get('elapsed_us')
            if state != 'in-flight' or not within_limit(value, SETUP_REMAINING_US):
                raise ValueError('continuation elapsed/budget is invalid')
            if value < elapsed:
                raise ValueError('continuation elapsed clock reset')
            elapsed = value
            if 'probe_elapsed_us' in details:
                value = details['probe_elapsed_us']
                if probe is not None or not within_limit(value, PROBE_CEILING_US) or value > elapsed:
                    raise ValueError('continuation probe exceeds ceiling or is repeated')
                probe = value
        elif name == 'setup_continuation_completed':
            if state != 'in-flight' or type(details.get('success')) is not bool:
                raise ValueError('single-use continuation completion is invalid')
            if details['success'] and probe is None:
                raise ValueError('successful continuation requires its one initialization probe')
            state = 'completed' if details['success'] else 'failed'
    return {'state': state, 'elapsed_us': elapsed, 'consumed_us': SETUP_CONSUMED_US + elapsed,
            'remaining_us': SETUP_REMAINING_US - elapsed, 'probe_elapsed_us': probe}


def _persist_continuation(path, previous, updated):
    # An exclusive lock plus comparison prevents two controllers consuming the
    # same authorization. A lost controller leaves in-flight state terminal for
    # resumption; this helper never removes a pre-existing lock.
    path = Path(path)
    lock = path.with_name(path.name + '.continuation-lock')
    fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    temp = None
    try:
        if json.loads(path.read_bytes()) != previous:
            raise ValueError('single-use continuation ledger changed concurrently')
        file_fd, temp = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name)
        with os.fdopen(file_fd, 'w') as stream:
            json.dump(updated, stream, indent=2, ensure_ascii=False)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.close(fd)
        if temp and os.path.exists(temp):
            os.unlink(temp)
        lock.unlink()


def begin_setup_continuation(ledger, *, ledger_path=None):
    if setup_continuation_state(ledger)['state'] != 'available':
        raise ValueError('single-use continuation has already been consumed (including interrupted setup)')
    updated = _append_current_event(ledger, 'setup_continuation_started', {'remaining_us': SETUP_REMAINING_US})
    _validate_current_screening(updated)
    if ledger_path is not None:
        _persist_continuation(ledger_path, ledger, updated)
    return updated


def charge_setup_elapsed(ledger, elapsed_us, *, probe_elapsed_us=None, ledger_path=None):
    setup_continuation_state(ledger)
    details = {'elapsed_us': elapsed_us}
    if probe_elapsed_us is not None:
        details['probe_elapsed_us'] = probe_elapsed_us
    updated = _append_current_event(ledger, 'setup_continuation_charged', details)
    _validate_current_screening(updated)
    if ledger_path is not None:
        _persist_continuation(ledger_path, ledger, updated)
    return updated


def complete_setup_continuation(ledger, *, success, ledger_path=None):
    setup_continuation_state(ledger)
    updated = _append_current_event(ledger, 'setup_continuation_completed', {'success': success})
    _validate_current_screening(updated)
    if ledger_path is not None:
        _persist_continuation(ledger_path, ledger, updated)
    return updated

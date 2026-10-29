#!/usr/bin/env python3
"""Versioned, public-safe v0.2 compatibility matrix consumer."""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import importlib.util
import json
import pathlib
import re
import sys

SCHEMA = "genewhip-v02-evidence-v1"
ALLOWED_STATUSES = {"pass", "fail", "unsupported", "skipped", "unknown", "infrastructure-error"}
OBSERVATION_KEYS = {"case_id", "status", "fields", "play_state", "position", "psg_writes",
                    "input_sha256", "pcm_sha256", "video_sha256", "source_predicates"}
MATRIX_STAGES = ("load", "boot", "interaction", "sustained", "completion")
MATRIX_OUTCOMES = ALLOWED_STATUSES
MATRIX_CLIENTS = ("core", "software-sdl", "native-sdl")
MATRIX_ROW_KEYS = {"title_id", "case_id", "client_scope", "stage", "repetition"}
MATRIX_OBSERVATION_KEYS = MATRIX_ROW_KEYS | {
    "outcome", "reason", "reached", "observation_dependencies", "ancestry",
    "denominators", "historic_disposition", "identity", "observations"}
PRIVATE_MARKERS = ("/Users/", "/home/", "/private/var/", "quarantine", "launch_window")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CURRENT_ROUTES = None
PUBLIC_SECRET_PATTERNS = (
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{30,}"),
    re.compile(r"AKIA[A-Z0-9]{16}"),
    re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"),
    re.compile(r"(?i:api[_-]?key|password|secret|token)\s*[=:]\s*[\"'][A-Za-z0-9/+_=.-]{16,}[\"']"),
)


def _reject(reason: str) -> None:
    raise ValueError(reason)


def adapt_record(record: dict) -> dict:
    """Return a narrow normalized status view without mutating retained records."""
    if not isinstance(record, dict):
        _reject("historical-record-shape-invalid")
    source_schema = record.get("schema")
    status = record.get("status", record.get("outcome"))
    if source_schema == SCHEMA:
        if status not in ALLOWED_STATUSES:
            _reject("current-record-status-invalid")
        return {"adapter_id": "genewhip-v02-native-v1", "source_schema": source_schema, "status": status}
    historical_adapters = {
        1: "genewhip-v02-from-phase5-v1",
        "phase4-v1": "genewhip-v02-from-phase4-v1",
        "genewhip-phase4-evidence": "genewhip-v02-from-phase4-v1",
        "genewhip-phase5-evidence-v1": "genewhip-v02-from-phase5-v1",
        "genewhip-phase5-baseline-v1": "genewhip-v02-from-phase5-baseline-v1",
        "genewhip-phase5-failure-inventory-v1": "genewhip-v02-from-phase5-failure-inventory-v1",
        "genewhip-phase6-product-report-v1": "genewhip-v02-from-phase6-product-report-v1",
        "genewhip-phase6-host-v1": "genewhip-v02-from-phase6-host-v1",
    }
    if source_schema not in historical_adapters:
        _reject("unsupported-historical-evidence-schema")
    if status == "infrastructure_error":
        status = "infrastructure-error"
    if status == "unavailable" and source_schema == "genewhip-phase6-host-v1":
        status = "unsupported"
    if status == "incomplete-failed" and source_schema == "genewhip-phase6-host-v1":
        status = "fail"
    if status not in ALLOWED_STATUSES:
        _reject("unsupported-historical-schema-status-pair")
    return {"adapter_id": historical_adapters[source_schema], "source_schema": source_schema, "status": status}


def _canonical_record_sha256(record: dict) -> str:
    return hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_current_execution_identity(identity: object, expected: object | None = None) -> dict:
    """Validate current launch bindings separately from immutable roster history."""
    required = {"schema", "source_sha256", "git_head", "base_sha", "run_id", "run_attempt",
        "scope_sha256", "candidate_sha256", "build_identity"}
    if not isinstance(identity, dict) or set(identity) != required or identity.get("schema") != "genewhip-v02-runtime-identity-v1":
        _reject("current-execution-identity-shape-invalid")
    for name in ("source_sha256", "scope_sha256", "candidate_sha256"):
        if not isinstance(identity.get(name), str) or SHA256.fullmatch(identity[name]) is None:
            _reject("current-execution-identity-invalid:" + name)
    for name in ("git_head", "base_sha"):
        if not isinstance(identity.get(name), str) or not re.fullmatch(r"[0-9a-f]{40}", identity[name]):
            _reject("current-execution-identity-invalid:" + name)
    if (not isinstance(identity.get("run_id"), str) or not identity["run_id"] or
            not isinstance(identity.get("run_attempt"), str) or not identity["run_attempt"].isdigit()):
        _reject("current-execution-identity-invalid:run")
    build = identity.get("build_identity")
    if (not isinstance(build, dict) or set(build) != {"cmake_cache_sha256", "configuration_sha256", "headless_sha256", "desktop_sha256"} or
            any(not isinstance(build.get(name), str) or SHA256.fullmatch(build[name]) is None for name in build)):
        _reject("current-execution-identity-invalid:build")
    if expected is not None:
        validate_current_execution_identity(expected)
        if json.dumps(identity, sort_keys=True, separators=(",", ":")) != json.dumps(expected, sort_keys=True, separators=(",", ":")):
            _reject("current-execution-identity-mismatch")
    return identity


def adapt_phase5(baseline: dict, failure_inventory: dict) -> dict:
    """Create a public-safe historical digest/disposition summary; never upgrade it to current proof."""
    if not isinstance(baseline, dict) or baseline.get("schema") != "genewhip-phase5-baseline-v1":
        _reject("phase5-baseline-schema-unsupported")
    if not isinstance(failure_inventory, dict) or failure_inventory.get("schema") != "genewhip-phase5-failure-inventory-v1":
        _reject("phase5-failure-inventory-schema-unsupported")
    baseline_rows = baseline.get("records")
    failure_rows = failure_inventory.get("records")
    if not isinstance(baseline_rows, list) or not isinstance(failure_rows, list):
        _reject("phase5-historical-records-invalid")
    counts = {status: 0 for status in ALLOWED_STATUSES}
    for row in baseline_rows + failure_rows:
        if not isinstance(row, dict):
            _reject("phase5-historical-records-invalid")
        raw = row.get("outcome", row.get("status"))
        normalized = adapt_record({"schema": "genewhip-phase5-evidence-v1", "outcome": raw})["status"]
        counts[normalized] += 1
    dispositions = failure_inventory.get("screening_dispositions", [])
    if not isinstance(dispositions, list) or any(not isinstance(row, dict) or row.get("outcome") not in {"fail", "unknown", "pass", "skipped"} for row in dispositions):
        _reject("phase5-screening-dispositions-invalid")
    adapted = {"adapter_id": "genewhip-v02-from-phase5-baseline-and-failure-inventory-v1",
            "baseline_record_sha256": _canonical_record_sha256(baseline),
            "failure_inventory_record_sha256": _canonical_record_sha256(failure_inventory),
            "baseline_roster_sha256": baseline.get("roster_sha256"),
            "historical_counts": counts, "screening_dispositions": [
                {"id": row["id"], "lineage_id": row["lineage_id"], "outcome": row["outcome"],
                 "reason": row["reason"], "state": row["state"], "independently_verifiable": False}
                for row in dispositions],
            "independently_verifiable": False,
            "reason": "Retained Phase 5 records are historical context and are not re-verified by this adapter."}
    _public_scan(adapted)
    return adapted


def adapt_phase6(core_report: dict, software_report: dict, native_report: dict) -> dict:
    """Summarize retained Phase 6 route records without relabeling them as v0.2 proof."""
    expected_schemas = ("genewhip-phase6-product-report-v1", "genewhip-phase6-host-v1", "genewhip-phase6-host-v1")
    documents = (core_report, software_report, native_report)
    if any(not isinstance(doc, dict) or doc.get("schema") != schema for doc, schema in zip(documents, expected_schemas)):
        _reject("phase6-historical-schema-unsupported")
    if not isinstance(core_report.get("stages"), list) or any(not isinstance(doc.get("runs"), list) for doc in documents):
        _reject("phase6-historical-records-invalid")
    counts = {scope: {status: 0 for status in ALLOWED_STATUSES} for scope in ("core", "software-sdl", "native-sdl")}
    sources = (("core", core_report["stages"]), ("software-sdl", software_report["runs"]),
               ("native-sdl", native_report["runs"]))
    for scope, rows in sources:
        for row in rows:
            if not isinstance(row, dict):
                _reject("phase6-historical-records-invalid")
            raw = row.get("outcome", row.get("host_outcome", row.get("status")))
            if raw in ALLOWED_STATUSES or raw == "infrastructure_error" or (raw in {"unavailable", "incomplete-failed"} and scope != "core"):
                normalized = adapt_record({"schema": documents[0 if scope == "core" else 1]["schema"], "status": raw})["status"]
                counts[scope][normalized] += 1
    adapted = {"adapter_id": "genewhip-v02-from-phase6-product-and-host-v1",
            "source_record_sha256": [_canonical_record_sha256(doc) for doc in documents],
            "candidate_source_sha256": [doc.get("candidate_sha256") for doc in documents],
            "historical_counts": counts,
            "independently_verifiable": False,
            "reason": "Phase 6 evidence remains tied to its qualified source, client and proof dependencies; v0.2 requires current-source closure."}
    _public_scan(adapted)
    return adapted


def _public_scan(value: object) -> None:
    if isinstance(value, str):
        lowered = value.lower()
        if any(marker.lower() in lowered for marker in PRIVATE_MARKERS):
            _reject("public-private-path-or-record")
        if any(token in lowered for token in ("rom_bytes", "save_bytes", "private_key", "authorization")):
            _reject("public-private-material")
        if any(pattern.search(value) for pattern in PUBLIC_SECRET_PATTERNS):
            _reject("public-secret-material")
    elif isinstance(value, dict):
        for key, item in value.items():
            _public_scan(key)
            _public_scan(item)
    elif isinstance(value, list):
        for item in value:
            _public_scan(item)


def validate_schema_document(schema_doc: object) -> dict:
    if not isinstance(schema_doc, dict) or schema_doc.get("schema") != "genewhip-v02-schema-document-v1":
        _reject("unknown-v02-schema-document")
    if (schema_doc.get("evidence_schema") != SCHEMA or
            schema_doc.get("required") != ["schema", "scope", "source_identity", "roster", "observations", "artifacts"]):
        _reject("v02-schema-contract-invalid")
    properties = schema_doc.get("properties")
    observation = schema_doc.get("observation")
    expected_types = {"schema": "string", "scope": "string", "source_identity": "object",
                      "roster": "array", "observations": "array", "artifacts": "object"}
    if (not isinstance(properties, dict) or set(properties) != set(schema_doc["required"]) or
            any(properties[name].get("type") != kind for name, kind in expected_types.items()) or
            properties["schema"].get("const") != SCHEMA or
            set(properties["scope"].get("enum", [])) != {"control-tracer", "smoke", "full", "safety", "chunk"} or
            not isinstance(observation, dict) or set(observation.get("required", [])) != OBSERVATION_KEYS or
            set(observation.get("status_enum", [])) != ALLOWED_STATUSES or
            observation.get("types") != {"case_id": "string", "status": "string", "fields": "nonnegative-integer",
                "play_state": "nonnegative-integer", "position": "nonnegative-integer", "psg_writes": "integer-array",
                "input_sha256": "sha256-or-empty", "pcm_sha256": "sha256-or-empty",
                "video_sha256": "sha256-or-empty", "source_predicates": "boolean-map"} or
            schema_doc.get("additional_properties") is not False):
        _reject("v02-schema-contract-invalid")
    matrix_observation = schema_doc.get("matrix_observation")
    if (not isinstance(matrix_observation, dict) or
            matrix_observation.get("required") != sorted(MATRIX_OBSERVATION_KEYS) or
            matrix_observation.get("stages") != list(MATRIX_STAGES) or
            set(matrix_observation.get("outcomes", [])) != MATRIX_OUTCOMES or
            matrix_observation.get("client_scopes") != list(MATRIX_CLIENTS)):
        _reject("v02-schema-contract-invalid")
    return schema_doc


def validate_roster(roster: object) -> dict:
    if not isinstance(roster, dict) or roster.get("schema") != "genewhip-v02-roster-v1":
        _reject("roster-schema-invalid")
    case_ids = roster.get("case_ids")
    if (not isinstance(case_ids, list) or not case_ids or any(not isinstance(item, str) or not item for item in case_ids) or
            len(case_ids) != len(set(case_ids))):
        _reject("roster-case-keys-invalid")
    identity = roster.get("source_identity")
    required_hashes = {"scenario_sha256", "oracle_sha256", "rom_sha256", "source_sha256"}
    if (not isinstance(identity, dict) or set(identity) != required_hashes or
            any(not isinstance(identity.get(name), str) or SHA256.fullmatch(identity[name]) is None for name in required_hashes)):
        _reject("roster-source-identity-invalid")
    return roster


def validate_matrix_roster(roster: object) -> dict:
    """Validate the independently declared title/case/client matrix contract."""
    validate_roster(roster)
    matrix = roster.get("matrix")
    if not isinstance(matrix, dict) or set(matrix) != {
            "titles", "stages", "outcomes", "client_scopes", "denominators", "host_case_ids", "history", "control_session_roster"}:
        _reject("matrix-roster-shape-invalid")
    history = matrix["history"]
    if (not isinstance(history, dict) or set(history) != {"baseline_sha256", "failure_inventory_sha256", "preserved_dispositions", "screening_dispositions", "independently_verifiable", "reason"} or
            any(not isinstance(history.get(k), str) or SHA256.fullmatch(history[k]) is None for k in
                ("baseline_sha256", "failure_inventory_sha256")) or
            history["preserved_dispositions"] != ["failed", "unattempted", "excluded", "unknown"] or
            not isinstance(history["screening_dispositions"], list) or len(history["screening_dispositions"]) != 5 or
            any(not isinstance(row, dict) or set(row) != {"id", "lineage_id", "outcome", "state", "reason"} or
                not all(isinstance(row.get(k), str) and row[k] for k in ("id", "lineage_id", "state", "reason")) or
                row["outcome"] not in {"fail", "unknown", "unsupported", "skipped"}
                for row in history["screening_dispositions"]) or
            len({row["id"] for row in history["screening_dispositions"] if isinstance(row, dict) and "id" in row}) != 5 or
            history["independently_verifiable"] is not False or not isinstance(history["reason"], str) or not history["reason"]):
        _reject("matrix-history-roster-invalid")
    titles = matrix["titles"]
    if not isinstance(titles, list) or len(titles) != 3:
        _reject("matrix-title-roster-invalid")
    title_ids, lineages, scenario_ids = [], [], []
    for title in titles:
        required = {"title_id", "fixture_id", "lineage_id", "source_revision", "profile", "cases",
                    "core_repetitions", "scenario_sha256", "oracle_sha256", "rom_sha256", "source_sha256",
                    "build_sha256", "configuration_sha256", "input_sha256", "delivery_map_sha256",
                    "media_expectations_sha256", "client_identity", "ancestry", "historic_disposition"}
        if not isinstance(title, dict) or set(title) != required:
            _reject("matrix-title-identity-shape-invalid")
        if any(not isinstance(title.get(k), str) or not title[k] for k in
               ("title_id", "fixture_id", "lineage_id", "source_revision", "profile")):
            _reject("matrix-title-identity-invalid")
        if any(not isinstance(title.get(k), str) or SHA256.fullmatch(title[k]) is None for k in
               ("scenario_sha256", "oracle_sha256", "rom_sha256", "source_sha256", "build_sha256",
                "configuration_sha256", "input_sha256", "delivery_map_sha256", "media_expectations_sha256")):
            _reject("matrix-title-artifact-identity-invalid")
        if (not isinstance(title.get("client_identity"), dict) or set(title["client_identity"]) != set(MATRIX_CLIENTS) or
                any(not isinstance(v, str) or not v for v in title["client_identity"].values())):
            _reject("matrix-client-identity-invalid")
        cases = title.get("cases")
        if not isinstance(cases, list) or not cases or any(not isinstance(c, str) or not c for c in cases) or len(cases) != len(set(cases)):
            _reject("matrix-title-cases-invalid")
        if type(title.get("core_repetitions")) is not int or title["core_repetitions"] < 1:
            _reject("matrix-title-repetitions-invalid")
        if not isinstance(title.get("ancestry"), list) or not isinstance(title.get("historic_disposition"), dict):
            _reject("matrix-title-history-invalid")
        title_ids.append(title["title_id"])
        lineages.append(title["lineage_id"])
        scenario_ids.append(title["scenario_sha256"])
    if title_ids != ["genewhip-independent-game-v2", "tank-battle", "recursion94"]:
        _reject("matrix-title-roster-mismatch")
    control_identity = titles[0]
    if any(control_identity[name] != roster["source_identity"][source_name] for name, source_name in
           (("scenario_sha256", "scenario_sha256"), ("oracle_sha256", "oracle_sha256"),
            ("rom_sha256", "rom_sha256"), ("source_sha256", "source_sha256"))):
        _reject("matrix-title-source-identity-mismatch")
    if matrix["stages"] != list(MATRIX_STAGES):
        _reject("matrix-stage-roster-mismatch")
    if set(matrix["outcomes"]) != MATRIX_OUTCOMES:
        _reject("matrix-outcome-roster-mismatch")
    if matrix["client_scopes"] != list(MATRIX_CLIENTS):
        _reject("matrix-client-roster-mismatch")
    if len(set(title_ids)) != 3:
        _reject("matrix-title-duplicate")
    if len(set(lineages)) != 3:
        _reject("matrix-lineage-denominator-invalid")
    cases = matrix["host_case_ids"]
    if (not isinstance(cases, list) or len(cases) != 6 or
            any(not isinstance(c, dict) or set(c) != {"title_id", "case_id"} or
                c["title_id"] not in title_ids or not isinstance(c["case_id"], str) or not c["case_id"] for c in cases) or
            len({(c["title_id"], c["case_id"]) for c in cases}) != len(cases)):
        _reject("matrix-host-cases-invalid")
    control_roster = matrix["control_session_roster"]
    if (not isinstance(control_roster, dict) or set(control_roster) != {"schema", "sessions", "controls", "sha256"} or
            control_roster.get("schema") != "phase6-control-session-roster-v1" or
            control_roster.get("sessions") != ["independent-game-v2", "sounded-diagnostic"] or
            control_roster.get("controls") != ["pause", "resume", "reset", "mute", "unmute", "replace", "drop", "reject-cartridge", "exit"] or
            not isinstance(control_roster.get("sha256"), str) or SHA256.fullmatch(control_roster["sha256"]) is None):
        _reject("matrix-control-session-roster-invalid")
    actual = _matrix_denominators(matrix)
    if matrix["denominators"] != actual:
        _reject("matrix-denominator-mismatch")
    return roster


def _matrix_denominators(matrix: dict) -> dict:
    titles = matrix["titles"]
    core_executions = sum(len(t["cases"]) * t["core_repetitions"] for t in titles)
    host_executions = len(matrix["host_case_ids"])
    return {"titles": len(titles), "authored_source_lineages": len({t["lineage_id"] for t in titles}),
            "scenarios": len({t["scenario_sha256"] for t in titles}), "core_executions": core_executions,
            "core_stage_cells": core_executions * len(matrix["stages"]),
            "software_sdl_cases": host_executions, "native_sdl_cases": host_executions}


def expected_matrix_rows(roster: dict) -> list[dict]:
    validate_matrix_roster(roster)
    matrix = roster["matrix"]
    rows = []
    for title in matrix["titles"]:
        for case_id in title["cases"]:
            for repetition in range(1, title["core_repetitions"] + 1):
                for stage in matrix["stages"]:
                    rows.append(_matrix_key(title, case_id, "core", stage, repetition, matrix["denominators"]))
    titles = matrix["titles"][1:]
    for client in ("software-sdl", "native-sdl"):
        for host_case in matrix["host_case_ids"]:
            title = next(t for t in titles if t["title_id"] == host_case["title_id"])
            for stage in matrix["stages"]:
                rows.append(_matrix_key(title, host_case["case_id"], client, stage, 1, matrix["denominators"]))
    return rows


def _matrix_key(title: dict, case_id: str, client: str, stage: str, repetition: int, denominators: dict) -> dict:
    return {"title_id": title["title_id"], "case_id": case_id, "client_scope": client,
            "stage": stage, "repetition": repetition,
            "ancestry": title["ancestry"], "denominators": denominators,
            "historic_disposition": title["historic_disposition"],
            "identity": {"fixture_id": title["fixture_id"], "lineage_id": title["lineage_id"],
                         "source_revision": title["source_revision"], "profile": title["profile"],
                         "scenario_sha256": title["scenario_sha256"], "oracle_sha256": title["oracle_sha256"],
                         "rom_sha256": title["rom_sha256"], "source_sha256": title["source_sha256"],
                         "build_sha256": title["build_sha256"], "configuration_sha256": title["configuration_sha256"],
                         "input_sha256": title["input_sha256"], "delivery_map_sha256": title["delivery_map_sha256"],
                         "media_expectations_sha256": title["media_expectations_sha256"],
                         "client_identity": title["client_identity"][client]}}


def validate_matrix_observation(row: object, expected: dict, current_execution_identity: dict | None = None) -> dict:
    if not isinstance(row, dict) or set(row) != MATRIX_OBSERVATION_KEYS:
        _reject("matrix-observation-shape-invalid")
    if any(row.get(key) != expected.get(key) for key in MATRIX_ROW_KEYS):
        _reject("matrix-client-scope-mismatch" if row.get("client_scope") != expected.get("client_scope")
                else "matrix-observation-identity-mismatch")
    for key in ("ancestry", "denominators", "historic_disposition", "identity"):
        if row.get(key) != expected.get(key):
            _reject("matrix-identity-mismatch" if key == "identity" else "matrix-denominator-mismatch" if key == "denominators" else "matrix-observation-identity-mismatch")
    if row.get("outcome") not in MATRIX_OUTCOMES or not isinstance(row.get("reason"), str) or not row["reason"].strip():
        _reject("matrix-outcome-reason-invalid")
    if type(row.get("reached")) is not bool:
        _reject("matrix-reached-invalid")
    if row["outcome"] == "pass":
        if row["reached"] is not True:
            _reject("matrix-pass-not-reached")
        obs = row.get("observations")
        if not isinstance(obs, dict):
            _reject("matrix-source-progress-invalid")
        stage = expected["stage"]
        if stage == "load" and (obs.get("rom_loaded") is not True or obs.get("fixture_identity_matches") is not True):
            _reject("matrix-load-observation-invalid")
        if stage == "boot" and (obs.get("boot_ready") is not True or type(obs.get("boot_fields")) is not int or obs["boot_fields"] <= 0):
            _reject("matrix-boot-observation-invalid")
        if stage == "interaction" and (obs.get("play_state") != 1 or obs.get("position_in_source_range") is not True):
            _reject("matrix-source-progress-invalid")
        if stage == "interaction" and obs.get("causal_control") is not True:
            _reject("matrix-causal-observation-invalid")
        if stage == "sustained" and (obs.get("play_state") != 1 or type(obs.get("progress_delta_fields")) is not int or
                obs["progress_delta_fields"] <= 0 or obs.get("position_in_source_range") is not True):
            _reject("matrix-sustained-progress-invalid")
        if current_execution_identity is not None and stage in ("interaction", "sustained"):
            _validate_current_progress_observation(expected, stage, obs)
        if stage == "completion" and (obs.get("completion_oracle_proven") is not True or obs.get("completion_predicate") is not True):
            _reject("matrix-completion-oracle-missing")
        if not row.get("observation_dependencies"):
            _reject("matrix-observation-dependency-missing")
        required_dependencies = {"scenario_sha256", "oracle_sha256", "rom_sha256", "source_sha256",
                                "input_sha256", "delivery_map_sha256", "media_expectations_sha256"}
        if current_execution_identity is None:
            required_dependencies |= {"build_sha256", "configuration_sha256"}
        else:
            required_dependencies.add("current_execution_identity_sha256")
        if set(row["observation_dependencies"]) != required_dependencies:
            _reject("matrix-observation-dependency-missing")
        for name, digest in row["observation_dependencies"].items():
            if (not isinstance(digest, str) or SHA256.fullmatch(digest) is None or
                    (name != "current_execution_identity_sha256" and row["identity"].get(name) != digest) or
                    (name == "current_execution_identity_sha256" and digest != _canonical_record_sha256(current_execution_identity))):
                _reject("matrix-observation-dependency-invalid")
    elif row["outcome"] == "fail" and row["reached"]:
        obs = row.get("observations")
        if not isinstance(obs, dict) or not isinstance(obs.get("failure_predicate"), str) or obs.get("failure_observed") is not True:
            _reject("matrix-failure-observation-missing")
    elif row["outcome"] in {"unknown", "skipped", "unsupported"} and row["reached"]:
        _reject("matrix-unqualified-outcome-reached")
    if not isinstance(row.get("ancestry"), list) or not isinstance(row.get("historic_disposition"), dict):
        _reject("matrix-history-invalid")
    if not isinstance(row.get("identity"), dict) or not row["identity"]:
        _reject("matrix-identity-missing")
    _public_scan(row)
    return row


def validate_matrix_observations(observations: object, roster: dict,
        current_execution_identity: dict | None = None) -> list[dict]:
    if current_execution_identity is not None:
        validate_current_execution_identity(current_execution_identity)
    expected = expected_matrix_rows(roster)
    if not isinstance(observations, list):
        _reject("matrix-observations-invalid")
    actual_keys = [tuple(row.get(k) for k in ("title_id", "case_id", "client_scope", "stage", "repetition"))
                   if isinstance(row, dict) else None for row in observations]
    expected_keys = [tuple(row[k] for k in ("title_id", "case_id", "client_scope", "stage", "repetition"))
                     for row in expected]
    if len(actual_keys) != len(expected_keys) or len(set(actual_keys)) != len(expected_keys) or set(actual_keys) != set(expected_keys):
        _reject("matrix-roster-mismatch")
    by_key = {key: row for key, row in zip(actual_keys, observations)}
    ordered = [by_key[key] for key in expected_keys]
    for row, key in zip(ordered, expected):
        validate_matrix_observation(row, key, current_execution_identity)
    by_execution = {}
    stage_index = {stage: index for index, stage in enumerate(MATRIX_STAGES)}
    for row in ordered:
        execution = tuple(row[k] for k in ("title_id", "case_id", "client_scope", "repetition"))
        by_execution.setdefault(execution, {})[row["stage"]] = row
    for stages in by_execution.values():
        for stage, row in stages.items():
            if row["outcome"] == "pass" and stage_index[stage] > 0:
                if stages[MATRIX_STAGES[stage_index[stage] - 1]]["outcome"] != "pass":
                    _reject("matrix-pass-prerequisite-not-qualified")
    return ordered


def validate_qualification_matrix(observations: list[dict]) -> None:
    """Require positive-route progress and explicit intentional-control dispositions."""
    if not isinstance(observations, list) or len(observations) != 180:
        _reject("qualification-matrix-denominator")
    by_key = {(row.get("title_id"), row.get("case_id"), row.get("client_scope"), row.get("stage"), row.get("repetition")): row
        for row in observations if isinstance(row, dict)}
    independent_positive = {"start-idle", "start-move", "action-sound", "sustained-play"}
    for title, case, client, stage, repetition in by_key:
        row = by_key[(title, case, client, stage, repetition)]
        if stage == "completion":
            expected = "unknown"
        elif stage in ("load", "boot"):
            expected = "pass"
        elif case.startswith("withhold-") or case in ("title-no-start", "action-no-trigger"):
            expected = "skipped"
        elif stage == "interaction":
            expected = "pass" if case in independent_positive or case == "full-route" else "skipped"
        elif stage == "sustained":
            expected = "pass" if case in ("sustained-play", "full-route") else "skipped"
        else:
            continue
        if row.get("outcome") != expected:
            _reject("qualification-matrix-required-stage:" + str(title) + ":" + str(case) + ":" + client + ":" + stage)
        if expected == "skipped" and row.get("reached") is not False:
            _reject("qualification-matrix-control-disposition-reached")


def _current_routes() -> dict:
    global _CURRENT_ROUTES
    if _CURRENT_ROUTES is None:
        route_path = pathlib.Path(__file__).with_name("phase6_routes.py")
        spec = importlib.util.spec_from_file_location("gw_v02_matrix_current_routes", route_path)
        if spec is None or spec.loader is None:
            _reject("current-route-source-unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _CURRENT_ROUTES = {(row["fixture"], row["case"]["id"]): row
            for row in module.compile_routes()["routes"]}
    return _CURRENT_ROUTES


def _validate_current_progress_observation(expected: dict, stage: str, observations: dict) -> None:
    route = _current_routes().get((expected["title_id"], expected["case_id"]))
    if route is None:
        _reject("current-route-not-in-independent-roster")
    facts = observations.get("source_predicates")
    if not isinstance(facts, list) or not facts or observations.get("causal_control") is not True:
        _reject("matrix-current-source-progress-missing")
    if expected["title_id"] == "genewhip-independent-game-v2":
        declared = route["case"]["expect"]
        values = {row.get("id"): row.get("value") for row in facts if isinstance(row, dict)}
        if (any(row.get("reached") is not True for row in facts if isinstance(row, dict)) or
                values.get("play_state") != declared["play_state"] or
                type(values.get("position")) is not int or
                not declared["position_min"] <= values["position"] <= declared["position_max"] or
                values.get("psg_writes") != declared["psg_writes"]):
            _reject("matrix-current-source-progress-invalid")
        for name in ("input_sha256", "pcm_sha256", "video_sha256"):
            if not isinstance(observations.get(name), str) or SHA256.fullmatch(observations[name]) is None:
                _reject("matrix-current-media-identity-invalid")
        if stage == "sustained" and (observations.get("source_fields") != route["case"].get("frames") or
                observations.get("progress_delta_fields") != route["case"].get("frames")):
            _reject("matrix-current-sustained-source-window-invalid")
        return
    definitions = {row["id"]: row for row in route["definitions"].get("predicates", [])}
    by_id = {row.get("id"): row for row in facts if isinstance(row, dict)}
    if set(by_id) != set(definitions):
        _reject("matrix-current-source-predicate-roster-invalid")
    fields = []
    for name, definition in definitions.items():
        row = by_id[name]
        if (row.get("reached") is not True or row.get("value") != definition["equals"] or type(row.get("field")) is not int or
                not definition["field_window"][0] <= row["field"] <= definition["field_window"][1]):
            _reject("matrix-current-source-predicate-invalid:" + name)
        fields.append(row["field"])
    if stage == "sustained" and observations.get("progress_delta_fields") != max(fields) - min(fields):
        _reject("matrix-current-sustained-progress-invalid")


def project_current_observations(roster: dict, core_report: dict, host_reports: dict,
        current_execution_identity: dict) -> list[dict]:
    """Adapt validated current collectors to the public stage matrix.

    The Phase 6 roster fields remain historical expectations. Current progress
    comes from the already validated source predicate receipts or the independent
    game's checked source-state/media report; completion remains unknown.
    """
    validate_matrix_roster(roster)
    validate_current_execution_identity(current_execution_identity)
    if (not isinstance(core_report, dict) or core_report.get("schema") != "genewhip-phase6-product-report-v1" or
            not isinstance(core_report.get("runs"), list) or not isinstance(core_report.get("stages"), list) or
            not isinstance(host_reports, dict) or set(host_reports) != {"software-sdl", "native-sdl"}):
        _reject("current-runtime-collector-shape-invalid")
    core_runs = {(r.get("fixture"), r.get("case"), r.get("repetition")): r for r in core_report["runs"] if isinstance(r, dict)}
    core_stages = {(r.get("fixture"), r.get("case"), r.get("repetition"), r.get("stage")): r
        for r in core_report["stages"] if isinstance(r, dict)}
    hosts = {}
    for client, report in host_reports.items():
        if (not isinstance(report, dict) or report.get("schema") != "genewhip-phase6-host-v1" or
                report.get("backend") != client.removesuffix("-sdl") or not isinstance(report.get("runs"), list)):
            _reject("current-host-collector-shape-invalid:" + client)
        hosts[client] = {(r.get("fixture"), r.get("case")): r for r in report["runs"] if isinstance(r, dict)}
    progress = _current_source_progress(core_report, core_runs)
    identity_digest = _canonical_record_sha256(current_execution_identity)
    observations = []
    for expected in expected_matrix_rows(roster):
        title = expected["title_id"]
        fixture = title
        case = expected["case_id"]
        client = expected["client_scope"]
        repetition = expected["repetition"]
        run = core_runs.get((fixture, case, repetition))
        stage_record = core_stages.get((fixture, case, repetition, expected["stage"]))
        host_run = hosts[client].get((fixture, case)) if client in hosts else None
        actual_pass = (run is not None and run.get("status") == "pass" and stage_record is not None and
            stage_record.get("status") == "pass" and stage_record.get("reached") is True and
            (client == "core" or (host_run is not None and host_run.get("status") == "pass" and
                host_run.get("backend") == client.removesuffix("-sdl"))))
        stage = expected["stage"]
        stage_fact = None
        obs: dict[str, object] = {}
        dependencies: dict[str, str] = {}
        if actual_pass and stage == "load":
            route_identity = run.get("identity", {})
            roster_identity = expected["identity"]
            fixture_matches = all(route_identity.get(source) == roster_identity[target] for source, target in (
                ("scenario_sha256", "scenario_sha256"), ("oracle_sha256", "oracle_sha256"),
                ("rom_sha256", "rom_sha256"), ("input_sha256", "input_sha256")))
            actual_pass = fixture_matches
            obs = {"rom_loaded": actual_pass, "fixture_identity_matches": fixture_matches}
        elif actual_pass and stage == "boot":
            boot_fields = run.get("completed_fields", 0)
            actual_pass = type(boot_fields) is int and boot_fields > 0
            obs = {"boot_ready": actual_pass, "boot_fields": boot_fields if type(boot_fields) is int else 0}
        elif actual_pass and stage in ("interaction", "sustained"):
            stage_fact = progress.get((fixture, case, repetition, stage))
            if stage_fact is None:
                actual_pass = False
            elif stage_fact["outcome"] == "pass":
                obs = stage_fact["observations"]
            else:
                outcome, reason, reached, obs = (stage_fact["outcome"], stage_fact["reason"],
                    stage_fact["reached"], stage_fact["observations"])
                actual_pass = False
        if actual_pass:
            dependencies = {name: expected["identity"][name] for name in
                ("scenario_sha256", "oracle_sha256", "rom_sha256", "source_sha256", "input_sha256",
                 "delivery_map_sha256", "media_expectations_sha256")}
            dependencies["current_execution_identity_sha256"] = identity_digest
        if stage == "completion":
            outcome, reason, reached, obs = "unknown", "separate-current-completion-oracle-not-declared", False, {}
        elif stage in ("interaction", "sustained") and not actual_pass and stage_fact is not None and stage_fact["outcome"] == "skipped":
            outcome, reason, reached, obs = (stage_fact["outcome"], stage_fact["reason"],
                stage_fact["reached"], stage_fact["observations"])
            pass
        elif actual_pass:
            outcome, reason, reached = "pass", "current-source-collector-observation", True
        elif client != "core" and host_run is not None and host_run.get("status") != "pass":
            outcome, reason, reached = "fail", "current-host-case-failed", True
            obs = {"failure_predicate": "host-case-success", "failure_observed": True}
        else:
            outcome, reason, reached = "unknown", "current-source-stage-oracle-not-exposed", False
        observations.append({**expected, "outcome": outcome, "reason": reason, "reached": reached,
            "observation_dependencies": dependencies, "observations": obs})
    return validate_matrix_observations(observations, roster, current_execution_identity)


def _current_source_progress(core_report: dict, core_runs: dict) -> dict:
    """Derive interaction/sustained cells only from source-validated observations."""
    if not isinstance(core_report.get("candidate_manifest"), dict):
        # Contract fixtures without a frozen production candidate remain unknown;
        # real runtime reports always carry and validate this manifest.
        return {}
    routes = _current_routes()
    report_cases = {}
    for run in core_runs.values():
        key = (run.get("fixture"), run.get("case"))
        route = routes.get(key)
        if route is None:
            _reject("current-route-not-in-independent-roster")
        if run.get("fixture") == "genewhip-independent-game-v2":
            reference = run.get("control_report")
            if not isinstance(reference, dict):
                _reject("current-independent-source-report-missing")
            path = pathlib.Path(reference.get("path", ""))
            if not path.is_absolute(): path = pathlib.Path(__file__).resolve().parents[2] / path
            root = pathlib.Path(__file__).resolve().parents[2]
            if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root) or \
                    hashlib.sha256(path.read_bytes()).hexdigest() != reference.get("sha256"):
                _reject("current-independent-source-report-identity")
            doc = _load_json(path)
            if doc.get("schema") != "genewhip-phase4-gameplay-v1" or doc.get("outcome") != "pass":
                _reject("current-independent-source-report-invalid")
            report_cases[key + (run.get("repetition"),)] = next((row for row in doc.get("results", [])
                if row.get("id") == key[1]), None)
        else:
            report_cases[key + (run.get("repetition"),)] = run
    out = {}
    for (fixture, case, repetition), run in core_runs.items():
        route = routes[(fixture, case)]
        if route["case"].get("kind") == "causal-control":
            predicates = route["case"].get("withheld_predicates", [])
            facts = run.get("predicate_results", {})
            if (not predicates or any(not isinstance(facts.get(name), dict) or
                    facts[name].get("reached") is not False for name in predicates)):
                _reject("current-counterfactual-predicate-not-withheld")
            common = {"source_predicates": [{"id": name, "reached": False} for name in predicates],
                "causal_control": True}
            for stage in ("interaction", "sustained"):
                out[(fixture, case, repetition, stage)] = {"outcome": "skipped", "reached": False,
                    "reason": "intentional-withheld-predicate-control", "observations": common}
            continue
        if fixture == "genewhip-independent-game-v2":
            fact = report_cases[(fixture, case, repetition)]
            if not isinstance(fact, dict): _reject("current-independent-case-observation-missing")
            expect = route["case"]["expect"]
            matches = (fact.get("outcome") == "pass" and fact.get("play_state") == expect["play_state"] and
                expect["position_min"] <= fact.get("position", -1) <= expect["position_max"] and
                fact.get("psg") == expect["psg_writes"])
            if case in ("title-no-start", "action-no-trigger"):
                for stage in ("interaction", "sustained"):
                    out[(fixture, case, repetition, stage)] = {"outcome": "skipped", "reached": False,
                        "reason": "intentional-negative-source-control", "observations": {
                            "source_case": case, "source_state_matched": matches,
                            "source_predicates": [{"id": "play_state", "value": fact.get("play_state")},
                                {"id": "position", "value": fact.get("position")},
                                {"id": "psg_writes", "value": fact.get("psg")}], "causal_control": matches}}
                continue
            if not matches:
                _reject("current-independent-source-progress-mismatch")
            progress_obs = {"play_state": fact["play_state"], "position_in_source_range": True,
                "causal_control": True, "source_predicates": [
                    {"id": "play_state", "reached": True, "value": fact["play_state"]},
                    {"id": "position", "reached": True, "value": fact["position"]},
                    {"id": "psg_writes", "reached": True, "value": fact["psg"]}],
                "input_sha256": fact.get("input_sha256"),
                "pcm_sha256": fact.get("retained_pcm", {}).get("sha256"),
                "video_sha256": fact.get("raw_geometry_sha256"), "source_fields": fact.get("fields")}
            out[(fixture, case, repetition, "interaction")] = {"outcome": "pass", "reached": True,
                "reason": "independent-source-state-and-media-validated", "observations": progress_obs}
            if case == "sustained-play":
                out[(fixture, case, repetition, "sustained")] = {"outcome": "pass", "reached": True,
                    "reason": "independent-sustained-source-roster-validated",
                    "observations": {**progress_obs, "progress_delta_fields": fact["fields"]}}
            else:
                out[(fixture, case, repetition, "sustained")] = {"outcome": "skipped", "reached": False,
                    "reason": "short-source-control-not-sustained-roster", "observations": {"source_case": case}}
            continue
        definitions = {row["id"]: row for row in route["definitions"].get("predicates", [])}
        positive = validate_current_positive_predicates(route, run)
        controlled_ids = [name for name in definitions if any(route_map["fixture"] == fixture and
            name in route_map["case"].get("withheld_predicates", []) for route_map in routes.values())]
        controls_prove = bool(controlled_ids) and all(any(route_map["fixture"] == fixture and
            route_map["case"].get("kind") == "causal-control" and name in route_map["case"].get("withheld_predicates", []) and
            core_runs[(fixture, route_map["case"]["id"], repetition)].get("predicate_results", {}).get(name, {}).get("reached") is False
            for route_map in routes.values()) for name in controlled_ids)
        if not positive or not controls_prove:
            _reject("current-source-causal-progress-unproven")
        fields = [row["field"] for row in positive]
        shared = {"play_state": 1, "position_in_source_range": True, "causal_control": True,
            "source_predicates": positive}
        out[(fixture, case, repetition, "interaction")] = {"outcome": "pass", "reached": True,
            "reason": "source-predicates-and-withheld-controls-validated", "observations": shared}
        out[(fixture, case, repetition, "sustained")] = {"outcome": "pass", "reached": True,
            "reason": "source-progress-fields-advanced", "observations": {**shared,
                "progress_delta_fields": max(fields) - min(fields)}}
    return out


def validate_current_positive_predicates(route: dict, run: dict) -> list[dict]:
    """Require each independently declared positive predicate at its source window."""
    definitions = {row["id"]: row for row in route["definitions"].get("predicates", [])}
    facts = run.get("predicate_results", {})
    positive = []
    for name, definition in definitions.items():
        observation = facts.get(name)
        if (not isinstance(observation, dict) or observation.get("reached") is not True or
                observation.get("value") != definition["equals"] or
                type(observation.get("field")) is not int or
                not definition["field_window"][0] <= observation["field"] <= definition["field_window"][1]):
            _reject("current-positive-source-predicate-unreached:" + name)
        positive.append({"id": name, "reached": True, "value": observation["value"], "field": observation["field"]})
    if not positive:
        _reject("current-positive-source-predicate-empty")
    return positive


def render_public_matrix(roster: dict, observations: list[dict], current_execution_identity: dict | None = None) -> str:
    validate_matrix_roster(roster)
    observations = validate_matrix_observations(observations, roster, current_execution_identity)
    denominators = roster["matrix"]["denominators"]
    lines = ["# Genewhip v0.2 compatibility evidence", "",
             "Scoped route evidence only; completion remains unknown without a separate completion oracle. No whole-library percentage or aggregate pass badge is implied.", "",
             ("Declared denominators: {titles} titles; {authored_source_lineages} authored source lineages; {scenarios} scenarios; "
              "{core_executions} core executions; {core_stage_cells} core stage cells; {software_sdl_cases} software-SDL cases; "
              "{native_sdl_cases} native-SDL cases.").format(**denominators), "",
             ("The separate original control-session roster is `{schema}` ({sessions} sessions, {controls} controls; SHA-256 `{digest}`); "
              "it is excluded from the two-title desktop host denominators.").format(
                  schema=roster["matrix"]["control_session_roster"]["schema"],
                  sessions=len(roster["matrix"]["control_session_roster"]["sessions"]),
                  controls=len(roster["matrix"]["control_session_roster"]["controls"]),
                  digest=roster["matrix"]["control_session_roster"]["sha256"]), "",
             ("Phase 5 historical baseline SHA-256 `{baseline}` and failure-inventory SHA-256 `{failures}` are retained separately; "
              "their claims are not independently verified by this matrix.").format(
                  baseline=roster["matrix"]["history"]["baseline_sha256"],
                  failures=roster["matrix"]["history"]["failure_inventory_sha256"]), "",
             "### Preserved screening dispositions", "",
             "| Candidate | Source lineage | Historical outcome | State | Reason | Independently verifiable here |",
             "|---|---|---|---|---|---|"]
    for item in roster["matrix"]["history"]["screening_dispositions"]:
        reason = item["reason"].replace("|", "&#124;").replace("\n", " ")
        lines.append(f"| {item['id']} | {item['lineage_id']} | {item['outcome']} | {item['state']} | {reason} | false |")
    lines.extend(["", "## Title and source identities", "",
             "| Title | Source lineage | Revision | Profile | Fixture / ROM SHA-256 | Scenario / oracle SHA-256 | Source / build / configuration SHA-256 | Input / delivery-map / media SHA-256 | Shared ancestry | Phase 5 disposition |",
             "|---|---|---|---|---|---|---|---|---|---|"])
    for title in roster["matrix"]["titles"]:
        identity = "{} / {} / {}".format(title["source_sha256"], title["build_sha256"], title["configuration_sha256"])
        inputs = "{} / {} / {}".format(title["input_sha256"], title["delivery_map_sha256"], title["media_expectations_sha256"])
        history = title["historic_disposition"].get("phase5", "unknown")
        lines.append("| {title} | {lineage} | {revision} | {profile} | `{fixture}` / `{rom}` | `{scenario}` / `{oracle}` | `{identity}` | `{inputs}` | {ancestry} | {history}; independently verifiable: {verified} |".format(
            title=title["title_id"], lineage=title["lineage_id"], revision=title["source_revision"], profile=title["profile"],
            fixture=title["fixture_id"], rom=title["rom_sha256"], scenario=title["scenario_sha256"], oracle=title["oracle_sha256"],
            identity=identity, inputs=inputs, ancestry=", ".join(title["ancestry"]), history=history,
            verified=str(title["historic_disposition"].get("independently_verifiable", False)).lower()))
    lines.extend(["", "## Stage observations", "",
             "| Title | Case | Client | Stage | Repetition | Outcome | Reached | Reason | Evidence dependencies |",
             "|---|---|---|---|---:|---|---|---|---|"])
    for row in observations:
        deps = ", ".join("{}=`{}`".format(name, digest) for name, digest in sorted(row["observation_dependencies"].items())) or "none"
        safe_reason = row["reason"].replace("|", "&#124;").replace("\n", " ")
        lines.append(f"| {row['title_id']} | {row['case_id']} | {row['client_scope']} | {row['stage']} | {row['repetition']} | {row['outcome']} | {str(row['reached']).lower()} | {safe_reason} | {deps} |")
    return "\n".join(lines) + "\n"


def project_public_closure(roster: dict, observations: list[dict], output_dir: pathlib.Path,
        current_execution_identity: dict | None = None, expected_current_execution_identity: dict | None = None) -> dict:
    """Write a sanitized, allowlisted closure that an isolated consumer can verify."""
    validate_matrix_roster(roster)
    validate_matrix_observations(observations, roster, current_execution_identity)
    if current_execution_identity is not None:
        validate_current_execution_identity(current_execution_identity, expected_current_execution_identity)
    elif expected_current_execution_identity is not None:
        _reject("current-execution-identity-missing")
    canonical_path = pathlib.Path(__file__).resolve().parents[2] / "evidence/v02-roster.json"
    canonical_roster = _load_json(canonical_path)
    validate_matrix_roster(canonical_roster)
    if json.dumps(roster, sort_keys=True, separators=(",", ":")) != json.dumps(
            canonical_roster, sort_keys=True, separators=(",", ":")):
        _reject("project-roster-not-canonical")
    output_dir.mkdir(parents=True, exist_ok=True)
    schema_path = pathlib.Path(__file__).resolve().parents[2] / "evidence/v02-schema.json"
    members = {
        "roster.json": json.dumps(roster, sort_keys=True, separators=(",", ":")) + "\n",
        "schema.json": json.dumps(_load_json(schema_path), sort_keys=True, separators=(",", ":")) + "\n",
        "observations.json": json.dumps(observations, sort_keys=True, separators=(",", ":")) + "\n",
        "verifier.py": pathlib.Path(__file__).read_text(),
    }
    if current_execution_identity is not None:
        members["execution-identity.json"] = json.dumps(current_execution_identity, sort_keys=True, separators=(",", ":")) + "\n"
    for name, content in members.items():
        (output_dir / name).write_text(content)
    (output_dir / "compatibility-matrix.md").write_text(render_public_matrix(roster, observations, current_execution_identity))
    digests = {name: hashlib.sha256((output_dir / name).read_bytes()).hexdigest() for name in members}
    digests["compatibility-matrix.md"] = hashlib.sha256((output_dir / "compatibility-matrix.md").read_bytes()).hexdigest()
    closure_id = hashlib.sha256(json.dumps(digests, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    manifest = {"schema": "genewhip-v02-public-closure-v1", "closure_id": closure_id, "members": digests,
                "independently_verifiable": True,
                "verification_scope": {"current_observations": "independently-verifiable",
                    "historical_dispositions": "digest-only-not-independently-verifiable",
                    "hardware_or_whole_game_truth": "not-claimed"}}
    if current_execution_identity is not None:
        manifest["current_identity_policy"] = "separate-current-launch-bindings-v1"
        manifest["current_execution_identity_sha256"] = _canonical_record_sha256(current_execution_identity)
    _public_scan(manifest)
    (output_dir / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
    return manifest


def verify_public_closure(root: pathlib.Path, independent_roster: dict | pathlib.Path,
        expected_current_execution_identity: dict | None = None) -> dict:
    """Verify only allowlisted files beneath root; this function has no repo lookup."""
    if root.is_symlink() or not root.is_dir():
        _reject("public-closure-root-invalid")
    manifest_path = root / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        _reject("public-closure-member-missing")
    manifest = _load_json(manifest_path)
    base_required = {"roster.json", "schema.json", "observations.json", "verifier.py", "compatibility-matrix.md"}
    has_current_identity = isinstance(manifest, dict) and "execution-identity.json" in manifest.get("members", {})
    required = base_required | ({"execution-identity.json"} if has_current_identity else set())
    manifest_keys = {"schema", "closure_id", "members", "independently_verifiable", "verification_scope"}
    if has_current_identity:
        manifest_keys |= {"current_identity_policy", "current_execution_identity_sha256"}
    if (not isinstance(manifest, dict) or manifest.get("schema") != "genewhip-v02-public-closure-v1" or
            set(manifest) != manifest_keys or
            set(manifest.get("members", {})) != required):
        _reject("public-closure-manifest-invalid")
    if has_current_identity and (manifest.get("current_identity_policy") != "separate-current-launch-bindings-v1" or
            expected_current_execution_identity is None):
        _reject("public-current-execution-identity-unverified")
    if manifest["independently_verifiable"] is not True or manifest["verification_scope"] != {
            "current_observations": "independently-verifiable",
            "historical_dispositions": "digest-only-not-independently-verifiable",
            "hardware_or_whole_game_truth": "not-claimed"}:
        _reject("public-closure-scope-invalid")
    computed_closure_id = hashlib.sha256(json.dumps(manifest["members"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if manifest["closure_id"] != computed_closure_id:
        _reject("public-closure-identity-mismatch")
    allowed_files = required | {"manifest.json"}
    entries = list(root.iterdir())
    if any(item.name not in allowed_files for item in entries):
        _reject("public-closure-unexpected-member")
    if (any(item.is_symlink() or not item.is_file() for item in entries) or
            {item.name for item in entries} != allowed_files):
        _reject("public-closure-member-missing")
    _public_scan(manifest)
    for name in sorted(required):
        path = root / name
        if path.is_symlink() or not path.is_file():
            _reject("public-closure-member-missing")
        if hashlib.sha256(path.read_bytes()).hexdigest() != manifest["members"][name]:
            _reject("public-closure-member-digest-mismatch")
        if name != "verifier.py":
            _public_scan(path.read_text(errors="replace"))
    current_identity = None
    if has_current_identity:
        current_identity = validate_current_execution_identity(_load_json(root / "execution-identity.json"),
            expected_current_execution_identity)
        if manifest.get("current_execution_identity_sha256") != _canonical_record_sha256(current_identity):
            _reject("public-current-execution-identity-digest-mismatch")
    roster = _load_json(root / "roster.json")
    if isinstance(independent_roster, pathlib.Path):
        if independent_roster.is_symlink() or not independent_roster.is_file():
            _reject("public-independent-roster-unreadable")
        independent_roster = _load_json(independent_roster)
    validate_matrix_roster(independent_roster)
    if json.dumps(roster, sort_keys=True, separators=(",", ":")) != json.dumps(
            independent_roster, sort_keys=True, separators=(",", ":")):
        _reject("public-independent-roster-mismatch")
    schema_doc = _load_json(root / "schema.json")
    validate_matrix_roster(roster)
    validate_schema_document(schema_doc)
    observations = _load_json(root / "observations.json")
    validate_matrix_observations(observations, roster, current_identity)
    expected_report = render_public_matrix(roster, observations, current_identity)
    if (root / "compatibility-matrix.md").read_text() != expected_report:
        _reject("public-matrix-render-mismatch")
    return {"status": "pass", "independently_verifiable": True,
            "row_count": len(observations), "matrix_sha256": manifest["members"]["compatibility-matrix.md"]}


def validate_public_bundle(bundle: object, *, expected_keys: list[str] | None = None,
                           schema_doc: dict | None = None) -> dict:
    if not isinstance(bundle, dict) or bundle.get("schema") != SCHEMA:
        _reject("unknown-v02-evidence-schema")
    if schema_doc is not None:
        validate_schema_document(schema_doc)
    required = {"schema", "scope", "source_identity", "roster", "observations", "artifacts"}
    if set(bundle) != required:
        _reject("bundle-shape-invalid")
    if bundle.get("scope") not in {"control-tracer", "smoke", "full", "safety", "chunk"}:
        _reject("bundle-scope-invalid")
    if not isinstance(bundle.get("source_identity"), dict):
        _reject("source-identity-missing")
    identity = bundle["source_identity"]
    identity_fields = {"fixture_id", "profile", "machine", "scenario_sha256", "oracle_sha256", "rom_sha256",
                       "source_sha256", "cmake_cache_sha256", "executable_sha256"}
    if set(identity) != identity_fields or any(not isinstance(identity.get(name), str) or not identity[name]
            for name in identity_fields - {"machine"}):
        _reject("source-identity-shape-invalid")
    if (not isinstance(identity.get("machine"), dict) or any(
            not isinstance(identity.get(name), str) or SHA256.fullmatch(identity[name]) is None
            for name in identity_fields - {"fixture_id", "profile", "machine"})):
        _reject("source-identity-invalid")
    roster_keys = bundle.get("roster")
    if (not isinstance(roster_keys, list) or not roster_keys or any(not isinstance(item, str) or not item for item in roster_keys) or
            len(roster_keys) != len(set(roster_keys))):
        _reject("bundle-roster-invalid")
    if not isinstance(bundle.get("observations"), list) or not bundle["observations"]:
        _reject("observations-empty-or-missing")
    _public_scan(bundle)
    keys = []
    for row in bundle["observations"]:
        if not isinstance(row, dict) or set(row) != OBSERVATION_KEYS:
            _reject("observation-shape-invalid")
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            _reject("observation-key-invalid")
        keys.append(case_id)
        if row.get("status") not in ALLOWED_STATUSES:
            _reject("observation-status-invalid")
        if (type(row.get("fields")) is not int or row["fields"] < 0 or
                type(row.get("play_state")) is not int or row["play_state"] < 0 or
                type(row.get("position")) is not int or row["position"] < 0 or
                not isinstance(row.get("psg_writes"), list) or
                any(type(item) is not int or not 0 <= item <= 255 for item in row["psg_writes"]) or
                not isinstance(row.get("source_predicates"), dict) or
                any(type(value) is not bool for value in row["source_predicates"].values())):
            _reject("observation-field-type-invalid")
        if (not isinstance(row.get("input_sha256"), str) or SHA256.fullmatch(row["input_sha256"]) is None or
                any(not isinstance(row.get(name), str) or
                    (row[name] != "" and SHA256.fullmatch(row[name]) is None)
                    for name in ("pcm_sha256", "video_sha256"))):
            _reject("observation-artifact-identity-invalid")
        if row["status"] == "pass":
            predicates = row.get("source_predicates")
            if (not isinstance(predicates, dict) or predicates.get("play_state") is not True or
                    predicates.get("position_in_source_range") is not True or
                    predicates.get("causal_control") is not True):
                _reject("observation-source-predicate-invalid")
            if any(not isinstance(row.get(name), int) or row[name] < 0 for name in ("fields", "play_state", "position")):
                _reject("observation-measurement-invalid")
            if any(not isinstance(row.get(name), str) or SHA256.fullmatch(row[name]) is None
                   for name in ("input_sha256", "pcm_sha256", "video_sha256")):
                _reject("observation-artifact-identity-invalid")
        elif row["status"] == "unknown":
            if any(not isinstance(row.get(name), str) or (row[name] and SHA256.fullmatch(row[name]) is None)
                   for name in ("input_sha256", "pcm_sha256", "video_sha256")):
                _reject("observation-artifact-identity-invalid")
    if len(keys) != len(set(keys)):
        _reject("duplicate-observation-key")
    if keys != roster_keys or (expected_keys is not None and (keys != expected_keys or roster_keys != expected_keys)):
        _reject("observation-roster-mismatch")
    artifacts = bundle.get("artifacts")
    if not isinstance(artifacts, dict):
        _reject("artifact-identities-missing")
    if any(not isinstance(key, str) or not isinstance(value, str) or SHA256.fullmatch(value) is None
           for key, value in artifacts.items()):
        _reject("artifact-identities-invalid")
    return bundle


def render_matrix(bundle: dict) -> str:
    validate_public_bundle(bundle)
    lines = ["# Genewhip v0.2 compatibility evidence", "",
             "This scoped tracer is not a whole-game completion or platform-wide compatibility claim.", "",
             "| Case | Client scope | Fields | State | Position | Status | Evidence |",
             "|---|---|---:|---:|---:|---|---|"]
    for row in bundle["observations"]:
        lines.append("| {case} | core headless | {fields} | {state} | {position} | {status} | `{evidence}` |".format(
            case=row["case_id"], fields=row["fields"], state=row["play_state"],
            position=row["position"], status=row["status"], evidence=row["pcm_sha256"]))
    return "\n".join(lines) + "\n"


def _load_json(path: pathlib.Path) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                _reject("duplicate-json-key")
            result[key] = value
        return result
    try:
        if path.stat().st_size > 33554432:
            _reject("public-json-byte-limit")
        return json.loads(path.read_text(), object_pairs_hook=unique)
    except ValueError:
        raise
    except OSError as error:
        raise ValueError("bundle-unreadable") from error


def _public_path(path: pathlib.Path, root: pathlib.Path) -> pathlib.Path:
    if path.is_symlink() or not path.is_file():
        _reject("public-path-escape")
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError:
        _reject("public-path-escape")
    return resolved


def validate_proof_dependencies(document: object) -> dict:
    if not isinstance(document, dict) or document.get("schema") != "genewhip-v02-proof-dependencies-v1":
        _reject("unknown-proof-dependencies-schema")
    proofs = document.get("all_proofs")
    sources = document.get("source_dependencies")
    graph = document.get("proof_dependencies")
    if (not isinstance(proofs, list) or not proofs or len(proofs) != len(set(proofs)) or
            any(not isinstance(name, str) or not name for name in proofs) or
            not isinstance(sources, dict) or not isinstance(graph, dict)):
        _reject("proof-dependencies-shape-invalid")
    known = set(proofs)
    for pattern, targets in sources.items():
        if (not isinstance(pattern, str) or not pattern or pattern.startswith("/") or
                ".." in pathlib.PurePosixPath(pattern).parts or not isinstance(targets, list) or not targets or
                any(not isinstance(target, str) for target in targets) or len(targets) != len(set(targets)) or
                any(target not in known for target in targets)):
            _reject("proof-source-dependency-invalid")
    graph_sets = {}
    for proof, dependencies in graph.items():
        if (proof not in known or not isinstance(dependencies, list) or
                any(not isinstance(item, str) for item in dependencies) or
                len(dependencies) != len(set(dependencies)) or any(item not in known for item in dependencies)):
            _reject("proof-dependency-edge-invalid")
        graph_sets[proof] = dependencies
    visiting, visited = set(), set()
    def visit(name: str) -> None:
        if name in visiting:
            _reject("proof-dependency-cycle")
        if name in visited:
            return
        visiting.add(name)
        for dependency in graph_sets.get(name, []):
            visit(dependency)
        visiting.remove(name)
        visited.add(name)
    for proof in graph_sets:
        visit(proof)
    return document


def affected_proofs(changed_paths: list[str], dependencies: dict) -> list[str]:
    validate_proof_dependencies(dependencies)
    all_proofs = set(dependencies["all_proofs"])
    affected = set()
    patterns = dependencies["source_dependencies"]
    for name in changed_paths:
        if not isinstance(name, str) or not name:
            _reject("source-path-invalid")
        path = pathlib.PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            _reject("source-path-invalid")
        matched = False
        for pattern, proofs in patterns.items():
            if fnmatch.fnmatchcase(name, pattern):
                affected.update(proofs)
                matched = True
        if not matched:
            return sorted(all_proofs)
    return sorted(affected)


def validate_proof_freshness(changed_paths: list[str], dependencies: dict, proof_receipts: dict,
                             current_source_digests: dict) -> list[str]:
    affected = affected_proofs(changed_paths, dependencies)
    for proof in affected:
        receipt = proof_receipts.get(proof)
        bindings = receipt.get("source_digests") if isinstance(receipt, dict) else None
        for path in changed_paths:
            if proof not in affected_proofs([path], dependencies):
                continue
            if (not isinstance(bindings, dict) or path not in bindings or
                    bindings[path] != current_source_digests.get(path)):
                _reject("stale-proof:" + proof)
    return affected


def _verify_with_roster(bundle_path: pathlib.Path, roster_path: pathlib.Path,
                        schema_path: pathlib.Path) -> dict:
    if roster_path.is_symlink() or not roster_path.is_file():
        _reject("public-path-escape")
    root = roster_path.resolve(strict=True).parent
    bundle_path = _public_path(bundle_path, root)
    roster_path = _public_path(roster_path, root)
    schema_path = _public_path(schema_path, root)
    roster = validate_roster(_load_json(roster_path))
    schema_doc = validate_schema_document(_load_json(schema_path))
    bundle = _load_json(bundle_path)
    identity = bundle.get("source_identity", {})
    if (any(identity.get(name) != value for name, value in roster["source_identity"].items()) or
            identity.get("fixture_id") != roster.get("fixture_id") or
            identity.get("profile") != roster.get("profile") or identity.get("machine") != roster.get("machine")):
        _reject("roster-source-identity-mismatch")
    validate_public_bundle(bundle, expected_keys=roster["case_ids"], schema_doc=schema_doc)
    return {"status": "pass", "schema": bundle["schema"],
            "bundle_sha256": hashlib.sha256(bundle_path.read_bytes()).hexdigest()}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    project = subparsers.add_parser("project")
    project.add_argument("--roster", type=pathlib.Path)
    project.add_argument("--input", type=pathlib.Path)
    project.add_argument("--records-root", type=pathlib.Path)
    project.add_argument("--out", type=pathlib.Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--bundle", type=pathlib.Path)
    verify.add_argument("--roster", type=pathlib.Path)
    verify.add_argument("--schema", type=pathlib.Path)
    verify.add_argument("--public-closure", action="store_true")
    verify.add_argument("--root", type=pathlib.Path)
    verify.add_argument("--independent-roster", type=pathlib.Path)
    verify.add_argument("--current-execution-identity", type=pathlib.Path)
    project.add_argument("--current-execution-identity", type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            if args.public_closure or args.independent_roster is not None:
                if args.independent_roster is None:
                    _reject("public-closure-root-missing")
                root = args.root if args.root is not None else args.independent_roster.parent
                current_identity = _load_json(args.current_execution_identity) if args.current_execution_identity else None
                print(json.dumps(verify_public_closure(root, args.independent_roster, current_identity), sort_keys=True))
                return 0
            if not all((args.bundle, args.roster, args.schema)):
                _reject("verify-inputs-missing")
            print(json.dumps(_verify_with_roster(args.bundle, args.roster, args.schema), sort_keys=True))
            return 0
        if args.records_root is not None:
            roster = _load_json(args.records_root / "roster.json")
            observations = _load_json(args.records_root / "observations.json")
            current_identity = _load_json(args.current_execution_identity) if args.current_execution_identity else None
            result = project_public_closure(roster, observations, args.out,
                current_identity, current_identity)
            print(json.dumps({"status": "pass", "members": result["members"]}, sort_keys=True))
            return 0
        if args.roster is None or args.input is None:
            _reject("project-inputs-missing")
        roster = _load_json(args.roster)
        bundle = _load_json(args.input)
        schema_doc = validate_schema_document(_load_json(ROOT / "evidence/v02-schema.json"))
        expected = validate_roster(roster)["case_ids"]
        validate_public_bundle(bundle, expected_keys=expected, schema_doc=schema_doc)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(render_matrix(bundle))
        print(json.dumps({"status": "pass", "matrix_sha256": hashlib.sha256(args.out.read_bytes()).hexdigest()}))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"REJECT: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate the sanitized shape of a physical Steam Deck observation record.

This tool validates fields and source identities only. It cannot establish that
the listed device, release, game copy, or outcomes were actually observed.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
ROUTE_MAP = ROOT / "fixtures/phase6/recursion94-consumed-map-v1.json"
MAX_RECORD_BYTES = 64 * 1024
SCHEMA = "genewhip.deck-route-observation.v1"
OUTCOMES = ("controls", "progress", "audio", "close", "relaunch")
LAUNCH_PATHS = ("direct-retroarch", "es-de")
OUTCOME_VALUES = ("pass", "fail", "unknown")
TOP_KEYS = {"schema", "status", "release", "route", "copy_availability", "device", "launches"}
RELEASE_KEYS = {"tag", "repository", "source_sha", "source_workflow", "source_run_id",
                "source_run_attempt", "publisher_workflow", "publisher_run_id",
                "publisher_run_attempt", "archive_sha256", "core_sha256"}
ROUTE_KEYS = {"map_id", "title_id", "route_id", "route_map_sha256"}
DEVICE_KEYS = {"model", "steamos", "retroarch", "flatpak", "es_de", "conditions"}
LAUNCH_KEYS = {"path", "outcomes"}
PRIVATE_MARKERS = ("/users/", "/home/", "/private/", "/var/folders/", "\\users\\")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def route_map_identity():
    data = json.loads(ROUTE_MAP.read_text(encoding="utf-8"))
    return data["map_id"], data["title_id"], hashlib.sha256(ROUTE_MAP.read_bytes()).hexdigest()


def template():
    map_id, title_id, map_digest = route_map_identity()
    return {
        "schema": SCHEMA,
        "status": "unknown",
        "release": {key: ("unknown" if key not in
                           ("source_run_attempt", "publisher_run_attempt") else "unknown")
                    for key in RELEASE_KEYS},
        "route": {"map_id": map_id, "title_id": title_id,
                  "route_id": "recursion94-personal-no-sram", "route_map_sha256": map_digest},
        "copy_availability": "unknown",
        "device": {key: "" for key in DEVICE_KEYS},
        "launches": [{"path": name, "outcomes": {key: "unknown" for key in OUTCOMES}}
                     for name in LAUNCH_PATHS],
    }


def exact_keys(value, expected, label, errors):
    if not isinstance(value, dict):
        errors.append(f"{label} must be an object")
        return False
    if set(value) != expected:
        errors.append(f"{label} has missing or unapproved fields")
    return True


def private_text(value):
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    if any(marker in lowered for marker in PRIVATE_MARKERS) or value.startswith("~"):
        return True
    if re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value):
        return True
    return False


def nonempty_string(value, label, errors):
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{label} must be a non-empty string")
        return False
    if private_text(value):
        errors.append(f"{label} contains a private path or account identifier")
        return False
    return True


def validate(data):
    errors = []
    if not exact_keys(data, TOP_KEYS, "record", errors):
        return errors
    if data.get("schema") != SCHEMA:
        errors.append("unsupported schema")
    if data.get("status") not in OUTCOME_VALUES:
        errors.append("status must be pass, fail, or unknown")

    release_ok = exact_keys(data.get("release"), RELEASE_KEYS, "release", errors)
    if release_ok and data.get("status") == "unknown":
        for field in RELEASE_KEYS:
            nonempty_string(data["release"].get(field), f"release.{field}", errors)
    elif release_ok:
        rel = data["release"]
        for field in RELEASE_KEYS:
            if field not in ("source_run_attempt", "publisher_run_attempt"):
                nonempty_string(rel.get(field), f"release.{field}", errors)
        if rel.get("repository") != "szTheory/genewhip":
            errors.append("release repository does not match the project")
        if rel.get("source_workflow") != ".github/workflows/ci.yml":
            errors.append("release source workflow does not match the required CI workflow")
        if rel.get("publisher_workflow") != ".github/workflows/release.yml":
            errors.append("release publisher workflow does not match the protected publisher")
        if not HEX40.fullmatch(str(rel.get("source_sha", ""))):
            errors.append("release source SHA must be a full 40-character commit")
        for field in ("source_run_id", "publisher_run_id"):
            if not re.fullmatch(r"[1-9][0-9]*", str(rel.get(field, ""))):
                errors.append(f"release.{field} must be a positive run ID")
        for field in ("source_run_attempt", "publisher_run_attempt"):
            if type(rel.get(field)) is not int or rel[field] < 1:
                errors.append(f"release.{field} must be a positive integer")
        for field in ("archive_sha256", "core_sha256"):
            if not HEX64.fullmatch(str(rel.get(field, ""))):
                errors.append(f"release.{field} must be a SHA-256 digest")
        if not re.fullmatch(r"v0\.3\.[01]", str(rel.get("tag", ""))):
            errors.append("release tag is not one of the planned v0.3 prereleases")

    route_ok = exact_keys(data.get("route"), ROUTE_KEYS, "route", errors)
    if route_ok:
        map_id, title_id, map_digest = route_map_identity()
        route = data["route"]
        if route.get("map_id") != map_id or route.get("title_id") != title_id:
            errors.append("route map or title identity does not match the accepted RECURSION94 map")
        if route.get("route_id") != "recursion94-personal-no-sram":
            errors.append("route must use the selected personally supplied no-SRAM RECURSION94 copy")
        if route.get("route_map_sha256") != map_digest:
            errors.append("route map digest does not match the accepted source map")
    if data.get("copy_availability") not in ("confirmed_lawful_no_sram", "unavailable", "unknown"):
        errors.append("copy_availability has an unsupported value")

    device_ok = exact_keys(data.get("device"), DEVICE_KEYS, "device", errors)
    if device_ok:
        for field in DEVICE_KEYS:
            nonempty_string(data["device"].get(field), f"device.{field}", errors)

    launches = data.get("launches")
    if not isinstance(launches, list) or len(launches) != len(LAUNCH_PATHS):
        errors.append("both direct RetroArch and ES-DE launch paths are required exactly once")
    else:
        found = []
        for index, launch in enumerate(launches):
            label = f"launches[{index}]"
            if not exact_keys(launch, LAUNCH_KEYS, label, errors):
                continue
            path = launch.get("path")
            found.append(path)
            if path not in LAUNCH_PATHS:
                errors.append(f"{label}.path is not an approved launch path")
            outcomes = launch.get("outcomes")
            if not exact_keys(outcomes, set(OUTCOMES), f"{label}.outcomes", errors):
                continue
            for outcome in OUTCOMES:
                if outcomes.get(outcome) not in OUTCOME_VALUES:
                    errors.append(f"{label}.outcomes.{outcome} must be pass, fail, or unknown")
        if sorted(found) != sorted(LAUNCH_PATHS):
            errors.append("both approved launch paths must appear once")
    return errors


def passes(data, errors):
    if errors or data.get("status") != "pass" or data.get("copy_availability") != "confirmed_lawful_no_sram":
        return False
    return all(launch.get("outcomes", {}).get(outcome) == "pass"
               for launch in data["launches"] for outcome in OUTCOMES)


def read_record(path):
    candidate = Path(path)
    if candidate.stat().st_size > MAX_RECORD_BYTES:
        raise ValueError("record exceeds the 64 KiB size limit")
    raw = candidate.read_bytes()
    if len(raw) > MAX_RECORD_BYTES:
        raise ValueError("record exceeds the 64 KiB size limit")
    return json.loads(raw)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", action="store_true", help="print an unknown observation template")
    parser.add_argument("--validate", metavar="FILE", help="validate a sanitized observation record")
    parser.add_argument("--require-pass", action="store_true", help="require every outcome to pass")
    args = parser.parse_args(argv)
    if args.template == bool(args.validate):
        parser.error("choose exactly one of --template or --validate FILE")
    if args.require_pass and args.template:
        parser.error("--require-pass applies only with --validate FILE")
    if args.template:
        print(json.dumps(template(), indent=2, sort_keys=True))
        return 0
    try:
        data = read_record(args.validate)
        errors = validate(data)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        errors = [f"cannot read record: {type(exc).__name__}"]
        data = {}
    passed = passes(data, errors)
    if args.require_pass and not passed:
        errors = errors + ["record is not a complete physical pass; unknown and unavailable outcomes remain non-passing"]
    result = {"valid": not errors, "status": data.get("status", "unknown"),
              "shape_only": True, "physical_observation_verified": False, "errors": errors}
    print(json.dumps(result, sort_keys=True))
    return 0 if not errors and (not args.require_pass or passed) else 1


if __name__ == "__main__":
    sys.exit(main())

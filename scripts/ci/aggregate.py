#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fail-closed validation for the single required preview CI status."""
import json
import os
import re
import sys

REQUIRED_LANES = ("safety", "gameplay", "desktop", "package", "performance",
                  "product-smoke", "phase7-fast")
FULL_V02_LANE = "v02-release-qualification"
SUPPORTED_EVENTS = ("pull_request", "merge_group", "push", "workflow_dispatch")
SHA = re.compile(r"^[0-9a-f]{40}$")


def validate_lanes(needs, event_name, source_sha, head_sha, base_sha, event_ref=None,
                   expected_run_id=None, expected_run_attempt=None):
    """Return stable rejection codes for incomplete or stale required CI evidence."""
    problems = []
    if event_name not in SUPPORTED_EVENTS:
        return ["unsupported-event"]
    for name, value in (("source", source_sha), ("head", head_sha), ("base", base_sha)):
        if not isinstance(value, str) or not SHA.fullmatch(value):
            return [f"expected-{name}-sha-invalid"]
    if not isinstance(needs, dict):
        return ["needs-not-object"]

    full_v02_required = event_name == "workflow_dispatch"
    required_lanes = REQUIRED_LANES + ((FULL_V02_LANE,) if full_v02_required else ())
    expected = set(required_lanes)
    actual = set(needs) - {"attestation"}
    if not full_v02_required:
        optional = needs.get(FULL_V02_LANE)
        if optional is not None and (not isinstance(optional, dict) or optional.get("result") != "skipped"):
            problems.append("full-v02-lane-must-skip-unselected-event")
        actual.discard(FULL_V02_LANE)
    for lane in required_lanes:
        if lane not in actual:
            problems.append(f"required-lane-missing:{lane}")
    for lane in sorted(actual - expected):
        problems.append(f"unexpected-lane:{lane}")

    expected_identity = {"source_sha": source_sha, "head_sha": head_sha, "base_sha": base_sha}
    for lane in required_lanes:
        if lane not in needs:
            continue
        record = needs[lane]
        if not isinstance(record, dict):
            problems.append(f"required-lane-invalid:{lane}")
            continue
        result = record.get("result")
        if result != "success":
            label = result if isinstance(result, str) and result else "missing"
            problems.append(f"required-lane-{label}:{lane}")
        outputs = record.get("outputs")
        if not isinstance(outputs, dict):
            problems.append(f"lane-identity-missing:{lane}")
            continue
        for field, expected_value in expected_identity.items():
            value = outputs.get(field)
            reason = {"source_sha": "stale-source", "head_sha": "stale-head",
                      "base_sha": "stale-base"}[field]
            if value != expected_value:
                problems.append(f"{reason}:{lane}")
        if lane in ("product-smoke", "phase7-fast", FULL_V02_LANE) and expected_run_id is not None:
            for field, expected_value in (("run_id", str(expected_run_id)),
                                          ("run_attempt", str(expected_run_attempt)),
                                          ("event_name", event_name)):
                if outputs.get(field) != expected_value:
                    problems.append(f"lane-event-identity-mismatch:{lane}:{field}")

    attestation = needs.get("attestation")
    if not isinstance(attestation, dict):
        problems.append("attestation-job-missing")
    elif (event_name in {"push", "workflow_dispatch"} and event_ref == "refs/heads/main"):
        if attestation.get("result") != "success":
            problems.append(f"attestation-job-{attestation.get('result') or 'missing'}:trusted-main-push")
        outputs = attestation.get("outputs")
        if not isinstance(outputs, dict):
            problems.append("attestation-identity-missing")
        else:
            for field, value in expected_identity.items():
                if outputs.get(field) != value:
                    problems.append(f"attestation-stale-{field.removesuffix('_sha')}")
    elif attestation.get("result") != "skipped":
        problems.append(f"attestation-job-must-skip-untrusted:{attestation.get('result') or 'missing'}")
    return problems


def main():
    try:
        needs = json.loads(os.environ["NEEDS_JSON"])
        event_name = os.environ["EVENT_NAME"]
        source_sha = os.environ["EXPECTED_SOURCE_SHA"]
        head_sha = os.environ["EXPECTED_HEAD_SHA"]
        base_sha = os.environ["EXPECTED_BASE_SHA"]
        event_ref = os.environ["EVENT_REF"]
        run_id = os.environ.get("EXPECTED_RUN_ID")
        run_attempt = os.environ.get("EXPECTED_RUN_ATTEMPT")
    except (KeyError, json.JSONDecodeError) as exc:
        print(f"REJECT: aggregate-input-invalid:{type(exc).__name__}", file=sys.stderr)
        return 2
    problems = validate_lanes(needs, event_name, source_sha, head_sha, base_sha, event_ref,
                              run_id, run_attempt)
    if problems:
        for problem in problems:
            print("REJECT: " + problem, file=sys.stderr)
        return 1
    full_v02_required = event_name == "workflow_dispatch"
    required_lanes = REQUIRED_LANES + ((FULL_V02_LANE,) if full_v02_required else ())
    print(f"required-aggregate: PASS ({len(required_lanes)}/{len(required_lanes)} current, successful lanes; " + event_name + ")")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Bounded Phase 6 mapped route tracer and delivery-map contract checks."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import pathlib
import sys
import time
import tempfile
import datetime
import os
import shutil
import struct
import subprocess
import resource
import re
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]

CORE_SEMANTIC_MUTANT_EXPECTATIONS = (
    ("missing-case", "product-run-count"), ("duplicate-repetition", "product-duplicate-run"),
    ("copied-title-repetition", "product-repeat-execution"),
    ("copied-control-repetition", "product-control-binding"),
    ("duplicate-control-report", "product-control-repetitions"),
    ("wrong-fixture-identity", "product-run-identity"), ("missing-stage", "product-stage-count"),
    ("false-completion", "product-invented-completion"), ("false-start-exit", "product-process"),
    ("unconfirmed-reap", "product-process"), ("wrong-compiled-controller", "product-compiled"),
    ("wrong-field-stream-digest", "product-field-stream-binding"),
    ("wrong-map-client", "product-run-map-client"),
    ("wrong-causal-expectation", "native-causal-control-unproven"),
    ("stale-reader-provenance", "product-validation-identities"),
    ("stale-media-validation-identity", "product-validation-identities"),
    ("recomputed-source_files", "product-stale-source"),
    ("recomputed-client_identities", "product-stale-client"),
    ("recomputed-build_identity", "product-stale-build"),
    ("recomputed-delivery_map_identity", "product-map"),
    ("recomputed-compiler_identity", "product-compiler"),
    ("recomputed-configuration_identity", "product-configuration"),
    ("3599-source-steps", "native-incomplete-observation"),
    ("oversized-work", "product-work-cap"), ("oversized-field-count", "product-work-cap"),
    ("missing-media-row", "media-roster"),
    ("stale-media-expectation", "media-expectations-identity"),
    ("blank-rec-scene", "media-rec-source-actor-mask"),
    ("filled-rec-scene", "media-rec-source-actor-mask"),
    ("wrong-tank-tile", "media-tank-source-tile"), ("truncated-pcm", "product-pcm-length"),
    ("dc-only-pcm", "media-audio-source-signal"),
)

# Derived from the pre-change compiler at 40be4d2, with its original 1M cap.
# These are immutable default-output identities, not outputs learned from the map.
DEFAULT_CONTROLLER_SHA256 = {
    'genewhip-independent-game-v2/action-no-trigger': 'ccb61cf77855ae4e5a3a20a02d967cee43c2d89608d48b5f023acf69c4365464',
    'genewhip-independent-game-v2/action-sound': '0e7910700182a56632674c0eee7da643362dd6128964bb49f753a8edac0afbdf',
    'genewhip-independent-game-v2/start-idle': '9d245ad2e1c4a0ae8966cb4a7def2a2f1da3ca237ee1961f46534b3bf43fbc3f',
    'genewhip-independent-game-v2/start-move': '07c3f572c8ff6361d6c7ee855821fd4cc5e6e5fd9316a53e446adca5c7de8028',
    'genewhip-independent-game-v2/sustained-play': '88323fe96df76d2ce7b8cc02af5a01eff3c30f561b5f32df4beee2760b590465',
    'genewhip-independent-game-v2/title-no-start': '1749316c7ad4136d294cbe62a107eaada6f24141832cd577ddc243eae841ac34',
    'recursion94/full-route': '94f7f482aac82438e2df1009be832bb608edb99c3ddf1b6cb5b2a303704e17aa',
    'recursion94/withhold-final-b': '74d85e8de10740d4a9a33f5ec80d2db406be9d47558b6b7867261c84485eb450',
    'recursion94/withhold-first-plate': '5ff73a97420f0b64f6cf60842ea41c780e9b3f54bada7fe9cd60b4c5ad5db8e6',
    'tank-battle/full-route': 'ac086c6c51e6f41a1925967d555f94383e5ca37483744ac6a5ca1bfad22a940d',
    'tank-battle/withhold-early-hit': 'bda7b6a2ebeab8e36bd2d8d39779d7617589c6bb0753b2dafadf0b60846cab5f',
    'tank-battle/withhold-late-hit': '1c8489dbd2dbe5f1b0564fb223aa719e5b530c1ad2ef8804326b92521b11aa95',
}


def load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


compiler = load_module("phase6_routes", ROOT / "scripts/evidence/phase6_routes.py")
contracts = load_module("phase6_route_contract", ROOT / "tests/session/phase6_route_contract.py")


def sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def write_json(path: pathlib.Path, value: object) -> None:
    path=path.absolute()
    if not path.is_relative_to(ROOT):raise RuntimeError("JSON output outside owned project root")
    encoded=(json.dumps(value, sort_keys=True, indent=2)+"\n").encode()
    if len(encoded)>16*1024*1024:raise RuntimeError("JSON report exceeds16MiB")
    if any(p.is_symlink() for p in (path,*path.parents) if p==ROOT or p.is_relative_to(ROOT)):
        raise RuntimeError("symlink JSON output")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        info=path.stat()
        if not path.is_file() or info.st_nlink!=1 or info.st_uid!=os.getuid():raise RuntimeError("non-exclusive JSON output")
    fd,temp=tempfile.mkstemp(prefix=".phase6-json-",dir=path.parent)
    try:
        with os.fdopen(fd,"wb") as stream:stream.write(encoded)
        os.replace(temp,path)
    finally:
        if os.path.exists(temp):os.unlink(temp)


def validate_tracer_report(report: dict, mapping: dict) -> None:
    """The collection and offline mutation paths share this semantic consumer."""
    compiler.validate_delivery_map(mapping)
    if (report.get("schema") != "genewhip-phase6-tracer-v1" or report.get("result") != "pass" or
            report.get("fixture") != "recursion94" or report.get("case") != "full-route" or
            report.get("delivery_client") != "public-core"):
        raise compiler.Invalid("tracer-envelope")
    candidate_ref = report.get("candidate_manifest", {})
    candidate_path = (ROOT / candidate_ref.get("path", "")).resolve()
    if (not candidate_path.is_relative_to(ROOT) or not candidate_path.is_file() or
            candidate_path.is_symlink() or sha(candidate_path) != candidate_ref.get("sha256")):
        raise compiler.Invalid("tracer-candidate-identity")
    candidate = json.loads(candidate_path.read_text())
    if canonical_sha(candidate) != report.get("candidate_sha256"):
        raise compiler.Invalid("tracer-candidate-identity")
    if report.get("delivery_map_sha256") != canonical_sha(mapping):
        raise compiler.Invalid("tracer-map-identity")
    actual = report.get("actual", {})
    if actual.get("active_ticks") != 3600:
        raise compiler.Invalid("tracer-source-duration")
    if type(actual.get("fields")) is not int or not 1 <= actual["fields"] <= 7200:
        raise compiler.Invalid("tracer-field-cap")
    if type(actual.get("boundary_calls")) is not int or not 1 <= actual["boundary_calls"] <= 100_000_000:
        raise compiler.Invalid("tracer-call-cap")
    if type(actual.get("queue_high_water")) is not int or not 0 <= actual["queue_high_water"] <= 64:
        raise compiler.Invalid("tracer-queue-cap")
    predicates = actual.get("predicates", [])
    # Source oracle order and windows; original predicate value must also agree.
    windows = ((1, 600, 1), (1400, 1800, 2), (3500, 3600, 1), (2821, 3600, 1))
    if len(predicates) != len(windows) or any(
            p.get("reached") is not True or p.get("value") != expected or
            type(p.get("clock")) is not int or not start <= p["clock"] <= end
            for p, (start, end, expected) in zip(predicates, windows)):
        raise compiler.Invalid("tracer-source-predicates")
    events = actual.get("mapped_events", [])
    if len(events) != 19:
        raise compiler.Invalid("tracer-event-count")
    for row, event in zip(mapping["events"], events):
        if event.get("event_id") != row["event_id"] or event.get("expected_poll") != row["expected_guest_poll"]:
            raise compiler.Invalid("tracer-event-identity")
        request = event.get("observed_request", {})
        observed = request.get("actual", {})
        if (request.get("found") is not True or observed.get("effective") != row["effective_mask"] or
                observed.get("desired") != row["effective_mask"] or observed.get("port") != 0):
            raise compiler.Invalid("tracer-request-mask")
        point = row["consumer_dispatch"]
        expected_active = (row["consumed"]["completed_source_steps"] if row["clock_kind"] == "paused-ui-state"
                           else point["attempt"] * 720 + max(1, point["tick"]))
        if observed.get("active_ticks") != expected_active:
            raise compiler.Invalid("tracer-request-clock")
        if row["clock_kind"] == "gameplay-source-step":
            poll = event.get("observed_poll", {})
            if poll.get("found") is not True or any(poll.get(k) != row["consumed"][k] for k in ("attempt", "tick")):
                raise compiler.Invalid("tracer-consumed-poll")
    route = next(r for r in compiler.compile_routes()["routes"]
                 if r["fixture"] == "recursion94" and r["case"]["id"] == "full-route")
    _, metadata = compiler.lower_route(route, 100_000_000, mapping)
    signal_indices = {row["name"]: index for index, row in enumerate(metadata["signals"])}
    held_indices = [signal_indices[name] for name in ("source_input_held", "engine_input_held", "gameplay_current_input")]
    samples = [s for s in actual.get("final_attempt_samples", []) if s.get("attempt") == 4 and 697 <= s.get("tick", -1) <= 720]
    # controllers.asm INPUT_BIT_B and engine_layout.asm INPUT_B are both $20.
    # Exactly 24 completed polls, with no gap/duplicate or missing held-B state.
    if [s["tick"] for s in samples] != list(range(697, 721)) or any(
            len(s.get("values", [])) <= max(held_indices) or
            any(s["values"][i] != 0x20 for i in held_indices) or
            s.get("active_ticks") != 2880 + s["tick"] for s in samples):
        raise compiler.Invalid("tracer-final-b-hold")
    process = report.get("process", {})
    if process.get("return_code") != 0 or process.get("bound_violation"):
        raise compiler.Invalid("tracer-process-outcome")
    raw_ref = report.get("raw_native_report", {})
    raw_path = (ROOT / raw_ref.get("path", "")).resolve()
    if (not raw_path.is_relative_to(ROOT) or not raw_path.is_file() or raw_path.stat().st_size > 16*1024*1024 or
            sha(raw_path) != raw_ref.get("sha256")):
        raise compiler.Invalid("tracer-raw-identity")
    raw = json.loads(raw_path.read_text())
    for event, observed in zip(events, raw.get("inputs", [])):
        if event["observed_request"]["actual"] != observed:
            raise compiler.Invalid("tracer-raw-request-binding")
    if len(raw.get("inputs", [])) != 20 or raw["inputs"][-1].get("effective") != 0:
        raise compiler.Invalid("tracer-cleanup-binding")
    for key in ("active_ticks", "fields", "boundary_calls", "queue_high_water", "predicates"):
        if actual.get(key) != raw.get(key):
            raise compiler.Invalid("tracer-raw-result-binding")
    if samples != [s for s in raw.get("samples", []) if s.get("attempt") == 4 and 697 <= s.get("tick", -1) <= 720]:
        raise compiler.Invalid("tracer-raw-hold-binding")
    capture = report.get("media_capture", {})
    if capture.get("capture_proof") is not True:
        raise compiler.Invalid("tracer-media-capture-proof")
    artifact_refs = capture.get("artifacts")
    if not isinstance(artifact_refs, dict) or set(artifact_refs) != {"pcm_sha256", "field_sha256", "metadata_sha256"}:
        raise compiler.Invalid("tracer-media-capture-artifact-set")
    directory = pathlib.PurePosixPath(capture.get("directory", ""))
    if directory.is_absolute() or ".." in directory.parts:
        raise compiler.Invalid("tracer-media-capture-path")
    for name, digest, ceiling, exact in (
            ("pcm", artifact_refs["pcm_sha256"], 16 * 1024 * 1024, None),
            ("field", artifact_refs["field_sha256"], 320 * 224 * 4, 320 * 224 * 4),
            ("capture_metadata", artifact_refs["metadata_sha256"], 8192, None)):
        relative = pathlib.PurePosixPath(capture.get(name, ""))
        if relative.is_absolute() or ".." in relative.parts:
            raise compiler.Invalid("tracer-media-capture-path")
        path = (ROOT / pathlib.Path(*relative.parts)).resolve()
        if (not path.is_relative_to(ROOT) or path.is_symlink() or not path.is_file() or
                path.stat().st_size > ceiling or (exact is not None and path.stat().st_size != exact) or
                sha(path) != digest):
            raise compiler.Invalid("tracer-media-capture-artifact")
    if any(part.is_symlink() for part in (ROOT / pathlib.Path(*directory.parts), *(ROOT / pathlib.Path(*directory.parts)).parents)
           if part == ROOT or part.is_relative_to(ROOT)):
        raise compiler.Invalid("tracer-media-capture-symlink")
    metadata_path = ROOT / pathlib.Path(*pathlib.PurePosixPath(capture["capture_metadata"]).parts)
    field_path = ROOT / pathlib.Path(*pathlib.PurePosixPath(capture["field"]).parts)
    metadata = json.loads(metadata_path.read_text())
    pcm_path = ROOT / pathlib.Path(*pathlib.PurePosixPath(capture["pcm"]).parts)
    if (metadata.get("candidate_sha256") != report.get("candidate_sha256") or
            metadata.get("attempt") != 4 or metadata.get("source_tick", 0) < 690 or
            metadata.get("field_sequence") != int(field_path.stem.removeprefix("field-")) or
            not isinstance(actual.get("audio_frames"), int) or pcm_path.stat().st_size != actual["audio_frames"] * 4):
        raise compiler.Invalid("tracer-media-capture-candidate")
    # C press follows a published terminal marker. Release happens while the
    # completed-source count is paused, before the next attempt's first step.
    # Reference fields are not native absolute-field predictions.
    for press_index, release_index in ((6, 7), (10, 11)):
        press = events[press_index]["observed_request"]["actual"]
        release = events[release_index]["observed_request"]["actual"]
        source_attempt = mapping["events"][press_index]["source_target"]["attempt"]
        terminal = [s for s in raw["samples"] if s.get("attempt") == source_attempt and s.get("tick") == 720 and s.get("state") == 2]
        resumed = [s for s in raw["samples"] if s.get("attempt") == source_attempt + 1 and s.get("tick") == 1 and s.get("state") == 1]
        if (len(terminal) != 1 or len(resumed) != 1 or press["field"] != terminal[0]["field"] or
                not press["field"] < release["field"] < resumed[0]["field"] or
                press["active_ticks"] != release["active_ticks"]):
            raise compiler.Invalid("tracer-paused-meta-order")
    binary, _ = compiler.lower_route(route, 100_000_000, mapping)
    fnv = 14695981039346656037
    for byte in binary:
        fnv = ((fnv ^ byte) * 1099511628211) & ((1 << 64) - 1)
    if (hashlib.sha256(binary).hexdigest() != report.get("route_plan_sha256") or
            raw.get("plan_fnv1a64") != f"{fnv:016x}"):
        raise compiler.Invalid("tracer-native-plan-binding")
    for relative, expected in candidate.get("source_files", {}).items():
        source_path = (ROOT / relative).resolve()
        if not source_path.is_relative_to(ROOT) or not source_path.is_file() or sha(source_path) != expected:
            raise compiler.Invalid("tracer-stale-source")
    identity = candidate.get("client_identities", {}).get("public-core", {})
    client_path = (ROOT / identity.get("path", "")).resolve()
    if not client_path.is_relative_to(ROOT) or not client_path.is_file() or sha(client_path) != identity.get("sha256"):
        raise compiler.Invalid("tracer-stale-client")


def delivery_map_contract(map_path: pathlib.Path, output: pathlib.Path) -> int:
    """Offline map/parser mutants only; never consumes or launches a ROM route."""
    original_popen=subprocess.Popen
    denied=[]
    def deny_popen(*args,**kwargs):
        denied.append((args,kwargs))
        raise AssertionError("Popen denied in delivery-map parser contract")
    subprocess.Popen=deny_popen
    try:
        subprocess.Popen(["phase6-map-contract-self-test"])
    except AssertionError:
        if len(denied)!=1:raise
    else:
        raise AssertionError("Popen denial guard did not reject its self-test")
    mapping = json.loads(map_path.read_text(encoding="utf-8"))
    compiler.validate_delivery_map(mapping)
    actual_defaults = {}
    for route in compiler.compile_routes()["routes"]:
        binary, _ = compiler.lower_route(route)
        actual_defaults[route["fixture"] + "/" + route["case"]["id"]] = hashlib.sha256(binary).hexdigest()
    if actual_defaults != DEFAULT_CONTROLLER_SHA256:
        raise compiler.Invalid("default-controller-byte-identity")
    checks = []
    for mutate, reason in (
        (lambda m: m["events"].pop(), "delivery-map-event-count"),
        (lambda m: m["events"][18].update(consumer_dispatch={"clock":"source-step","attempt":4,"tick":695}), "delivery-map-consumption:19"),
        (lambda m: m["events"][17].update(consumer_dispatch={"clock":"source-step","attempt":4,"tick":676}), "delivery-map-consumption:18"),
        (lambda m: m["events"][6].update(consumer_dispatch={"clock":"source-step","attempt":2,"tick":720}), "delivery-map-paused-meta:7"),
        (lambda m: m["cleanup_release"].update(event_row=True), "delivery-map-cleanup-is-event"),
        (lambda m: m["events"][18].update(expected_guest_poll={"attempt":4,"tick":696}), "delivery-map-expected-poll:19"),
        (lambda m: m["events"][18].update(effective_mask=0), "delivery-map-effective-mask:19"),
        (lambda m: m["events"][18].update(hold_end={"attempt":4,"tick":719}), "delivery-map-hold:19"),
        (lambda m: m["events"][18].update(release_boundary={"cleanup":False}), "delivery-map-release:19"),
        (lambda m: m["events"][6].update(expected_guest_poll={"attempt":2,"tick":720}), "delivery-map-expected-poll:7"),
        (lambda m: m["events"][0].update(hold_end={"next_event_id":"input-event-03"}), "delivery-map-hold:1"),
        (lambda m: m["events"][1].update(release_boundary={}), "delivery-map-release:2"),
        (lambda m: m["source"].update(rom_sha256="0"*64), "delivery-map-source-identity"),
    ):
        candidate = json.loads(json.dumps(mapping))
        mutate(candidate)
        try:
            compiler.validate_delivery_map(candidate)
        except compiler.Invalid as error:
            if str(error) != reason:
                raise
            checks.append({"expected": reason, "actual": str(error), "status": "pass"})
        else:
            raise AssertionError(f"delivery-map mutant accepted: {reason}")
    report = {"schema":"genewhip-phase6-delivery-contract-v1", "map_sha256":sha(map_path),
              "default_controller_bytes":actual_defaults, "baseline_revision":"40be4d2",
              "default_roundtrip_byte_identical":actual_defaults == DEFAULT_CONTROLLER_SHA256,
              "negative_controls":checks,"popen_denial_self_test":len(denied)==1,"status":"pass"}
    write_json(output, report)
    subprocess.Popen=original_popen
    return 0


def contract(map_path: pathlib.Path, output: pathlib.Path) -> int:
    delivery_map_contract(map_path,output)
    mapping = json.loads(map_path.read_text(encoding="utf-8"))
    checks=[]
    retained_path = ROOT / "evidence/phase6-tracer-reviewed.json"
    retained = json.loads((retained_path if retained_path.is_file() else ROOT / "evidence/phase6-tracer.json").read_text())
    validate_tracer_report(retained, mapping)
    for mutate, reason in (
        (lambda r: r["actual"].update(active_ticks=3599), "tracer-source-duration"),
        (lambda r: r["actual"]["final_attempt_samples"][-1]["values"].__setitem__(32, 0), "tracer-final-b-hold"),
        (lambda r: r["actual"]["final_attempt_samples"].pop(), "tracer-final-b-hold"),
        (lambda r: r["actual"]["predicates"][3].update(clock=3601), "tracer-source-predicates"),
        (lambda r: r["actual"]["mapped_events"][18]["observed_poll"].update(tick=696), "tracer-consumed-poll"),
        (lambda r: r["process"].update(bound_violation=True), "tracer-process-outcome"),
        (lambda r: r.update(result="fail"), "tracer-envelope"),
        (lambda r: r.update(candidate_sha256="0"*64), "tracer-candidate-identity"),
        (lambda r: r["raw_native_report"].update(sha256="0"*64), "tracer-raw-identity"),
        (lambda r: r["actual"]["mapped_events"][6]["observed_request"]["actual"].update(active_ticks=2161), "tracer-request-clock"),
        (lambda r: r["actual"]["mapped_events"][6]["observed_request"]["actual"].update(field=2161), "tracer-raw-request-binding"),
        (lambda r: r["actual"]["mapped_events"][18]["observed_request"]["actual"].update(desired=0), "tracer-request-mask"),
        (lambda r: r["actual"]["mapped_events"][18]["observed_request"]["actual"].update(port=1), "tracer-request-mask"),
    ):
        mutant = json.loads(json.dumps(retained))
        mutate(mutant)
        try:
            validate_tracer_report(mutant, mapping)
        except compiler.Invalid as error:
            if str(error) != reason:
                raise
            checks.append({"expected":reason,"actual":str(error),"status":"pass"})
        else:
            raise AssertionError(f"tracer mutant accepted: {reason}")
    report = {"schema":"genewhip-phase6-contract-v1", "map_sha256":sha(map_path),
              "tracer_negative_controls":checks,"status":"pass"}
    write_json(output, report)
    return 0


def media(build: pathlib.Path, candidate_path: pathlib.Path, output: pathlib.Path,
          core_report_path: pathlib.Path | None = None) -> int:
    """Consume captured route artifacts; this mode never launches a client."""
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    route_path = pathlib.Path(core_report_path).resolve(strict=True) if core_report_path else ROOT / "evidence/phase6-core-routes.json"
    routes = json.loads(route_path.read_text(encoding="utf-8"))
    captures = routes.get("media_captures")
    if not isinstance(captures, list):
        raise RuntimeError("media-capture-roster-missing")
    report = {"schema": "genewhip-phase6-media-v1", "result": "pass",
              "candidate_sha256": canonical_sha(candidate), "core_routes_sha256": sha(route_path),
              "core_routes":artifact(route_path),
              "media_expectations_sha256":sha(ROOT/"fixtures/phase6/media-expectations-v1.json"),
              "captures": captures}
    compiler.validate_media_report(report, candidate)
    write_json(output, report)
    return 0


WINDOW_PATH = ROOT / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-50-53-EXECUTION.json"
_EXECUTION_SCOPE = None
_V02_STATE = None
_V02_START = None
_V02_DEADLINE = None


def set_execution_scope(scope: dict | None) -> None:
    """Inject a caller-owned execution scope; Phase 7 must never touch WINDOW_PATH."""
    global _EXECUTION_SCOPE, _V02_STATE, _V02_START, _V02_DEADLINE
    if scope is not None and (scope.get("schema") != "genewhip-v02-execution-v1" or
                              scope.get("scope_id") != "phase7-serial-child-workloads"):
        raise RuntimeError("phase7-execution-scope-invalid")
    # Rebinding an already active scope is used when nested collectors attach
    # their fresh core receipt. Keep its original clock and counters: a helper
    # must never renew the qualification window by calling this setter again.
    same_active_scope = (scope is not None and _EXECUTION_SCOPE is not None and
        scope.get("scope_id") == _EXECUTION_SCOPE.get("scope_id") and _V02_STATE is not None)
    if same_active_scope and (scope.get("qualification_deadline") !=
            _EXECUTION_SCOPE.get("qualification_deadline")):
        raise RuntimeError("phase7-shared-cutoff-mutated")
    _EXECUTION_SCOPE = scope
    if scope is None:
        _V02_STATE = _V02_START = _V02_DEADLINE = None
    elif not same_active_scope:
        # Fresh in-memory accounting only. Phase 7 deliberately does not read or
        # write the retired Phase 6 window or inherit its clock/budget.
        batch_seconds = scope.get("qualification_batch", {}).get("runtime_wall_seconds", 64800)
        if type(batch_seconds) is not int or not 0 < batch_seconds <= 64800:
            raise RuntimeError("phase7-runtime-wall-bound-invalid")
        # The coordinator may provide a generated common cutoff shared by all
        # subprocesses. Convert its absolute UTC deadline to this process's
        # monotonic clock once, without extending it on re-entry.
        started_utc = scope.get("qualification_started_at")
        deadline_utc = scope.get("qualification_deadline")
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        try:
            deadline_dt = datetime.datetime.fromisoformat(deadline_utc) if deadline_utc else now_utc + datetime.timedelta(seconds=batch_seconds)
            started_dt = datetime.datetime.fromisoformat(started_utc) if started_utc else now_utc
            remaining = (deadline_dt - now_utc).total_seconds()
        except (TypeError, ValueError):
            raise RuntimeError("phase7-shared-cutoff-invalid")
        if remaining <= 0 or remaining > batch_seconds:
            raise RuntimeError("phase7-shared-cutoff-exhausted-or-renewed")
        _V02_START = time.monotonic() - max(0.0, (now_utc - started_dt).total_seconds())
        _V02_DEADLINE = time.monotonic() + remaining
        _V02_STATE = {"started_at": started_dt.isoformat(),
            "deadline": deadline_dt.isoformat(),
            "workload_cutoff": deadline_dt.isoformat(),
            "workload_wall_seconds": 0.0, "workload_wall_upper_bound_seconds": 0.0,
            "setup_test_wall_seconds": 0.0, "setup_test_wall_upper_bound_seconds": 0.0,
            "owned_artifact_roots": [], "process_records": [], "setup_test_records": [],
            "exploratory_attempts": {"recursion94": 0}, "status": "running"}


def _read_window() -> dict:
    if _EXECUTION_SCOPE is not None:
        if _V02_STATE is None:
            raise RuntimeError("phase7-runtime-scope-not-initialized")
        return _V02_STATE
    return json.loads(WINDOW_PATH.read_text())


def _write_window(value: dict) -> None:
    if _EXECUTION_SCOPE is not None:
        if value is not _V02_STATE:
            raise RuntimeError("phase7-runtime-state-identity")
        return
    write_json(WINDOW_PATH, value)
READER_PROVENANCE_PATHS = ("scripts/evidence/phase6_routes.py", "tests/fixtures/phase6_game.py",
                          "tests/session/phase6_route_contract.py")


def artifact(path: pathlib.Path) -> dict:
    path = path.resolve(strict=True)
    return {"path":str(path.relative_to(ROOT)),"sha256":sha(path)}


def tree_bytes(path):
    total=0
    for directory,dirs,files in os.walk(path,followlinks=False):
        for name in dirs+files:
            item=pathlib.Path(directory)/name
            if item.is_symlink():continue  # pinned SDL source may contain benign links; never traverse them
            try:
                if item.is_file():total+=item.stat().st_size
            except FileNotFoundError:pass
    return total


def shared_launch(client, command, work, report_path, timeout, *, files=(), directories=(), env=None, plan_id="06-51"):
    """Reuse the actual bounded process boundary; persist accounting even on errors."""
    if _EXECUTION_SCOPE is not None:
        if _V02_STATE is None or _V02_DEADLINE is None:
            raise RuntimeError("phase7-runtime-scope-not-initialized")
        limits = _EXECUTION_SCOPE.get("per_child_limits")
        if not isinstance(limits, dict):
            raise RuntimeError("phase7-runtime-child-limits-missing")
        remaining = min(float(timeout), _V02_DEADLINE - time.monotonic())
        if remaining <= 1:
            raise RuntimeError("phase7-runtime-batch-deadline-exhausted")
        spec = importlib.util.spec_from_file_location("gw_phase7_runtime_boundary", ROOT / "tests/session/phase6_route_contract.py")
        if spec is None or spec.loader is None:
            raise RuntimeError("phase7-runtime-boundary-import")
        route_contract = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(route_contract)
        receipts, streams = [], {}
        started = time.monotonic()
        boundary_error=None; boundary_exception=None; result=None
        try:
            receipt_spec = importlib.util.spec_from_file_location(
                "gw_phase7_process_receipts",
                pathlib.Path(__file__).resolve().parents[2] / "scripts/evidence/phase5_process.py")
            if receipt_spec is None or receipt_spec.loader is None:
                raise RuntimeError("phase7-process-receipt-import")
            receipt_module = importlib.util.module_from_spec(receipt_spec)
            receipt_spec.loader.exec_module(receipt_module)
            receipt_name = pathlib.Path("process-receipts") / (uuid.uuid4().hex + ".json")
            with receipt_module.receipt_file(work, receipt_name) as receipt_stream:
                result = route_contract._run_client(pathlib.Path(command[0]), command, receipts,
                    report=report_path, timeout=remaining, cwd=work, env=env, retained_streams=streams,
                    monitored_files=files, monitored_directories=directories, limits=limits,
                    scratch_roots=(work,), process_receipt_stream=receipt_stream)
        except BaseException as exc:
            boundary_exception=exc
            boundary_error=f"{type(exc).__name__}: {exc}"
        elapsed = time.monotonic() - started
        receipt = receipts[-1] if receipts else {"status": "missing-receipt"}
        for name in ("stdout", "stderr"):
            streams.setdefault(name, {"status": "not-started", "observed_bytes": 0,
                "retained_bytes": 0, "sha256": hashlib.sha256(b"").hexdigest(), "truncated": False})
        # Account the completed launch attempt independently of report persistence.
        _V02_STATE["workload_wall_seconds"] += elapsed
        _V02_STATE["workload_wall_upper_bound_seconds"] += elapsed
        _V02_STATE.setdefault("process_records", []).append({"plan": plan_id, "category": "workload",
            "process": "canonical-core-or-control", "work_directory": str(work.relative_to(ROOT)),
            "elapsed_seconds": elapsed, "receipts": receipts})
        try:
            write_json(work / "process.json", {"processes": receipts, "streams": streams, "wall_seconds": elapsed,
                "scope_id": _EXECUTION_SCOPE.get("scope_id"), "historical_window_access": False,
                "boundary_error":boundary_error})
        except BaseException as persistence_error:
            if boundary_exception is not None:
                raise persistence_error from boundary_exception
            raise
        if time.monotonic() > _V02_DEADLINE:
            raise RuntimeError("phase7-runtime-batch-deadline-exceeded")
        if boundary_error is not None:
            raise RuntimeError("phase7-bounded-child-boundary-error:"+boundary_error) from boundary_exception
        if result is None:
            raise RuntimeError("phase7-bounded-child-result-missing")
        if receipt.get("process_group_cleanup") != "confirmed":
            raise RuntimeError("phase7-shared-child-cleanup-unconfirmed")
        return result, receipt, streams
    state = _read_window()
    owned=sum(tree_bytes(ROOT/p) for p in state.get("owned_artifact_roots",[]))
    reserve=256*1024*1024 if any(str(x).endswith("phase4_game.py") for x in command) else 64*1024*1024
    if owned+reserve>2*1024**3:raise RuntimeError("retained-disk-headroom-exhausted")
    if tree_bytes(ROOT/"build/phase6")>6*1024**3:raise RuntimeError("owned-build-disk-exhausted")
    cutoff = datetime.datetime.fromisoformat(state["workload_cutoff"])
    remaining = (cutoff-datetime.datetime.now(datetime.timezone.utc)).total_seconds()
    remaining = min(remaining,14400-state.get("workload_wall_upper_bound_seconds",state["workload_wall_seconds"]))
    if remaining < min(timeout,30) + 5:
        raise RuntimeError("shared-window-workload-exhausted")
    receipts,streams = [],{}
    started = time.monotonic()
    try:
        result = contracts._run_client(client,command,receipts,report=report_path,
            timeout=min(timeout,remaining-5),cwd=work,retained_streams=streams,
            monitored_files=files,monitored_directories=directories,env=env)
        return result,receipts[-1],streams
    finally:
        elapsed = time.monotonic()-started
        state = _read_window()
        state["workload_wall_seconds"] += elapsed
        if "workload_wall_upper_bound_seconds" in state:state["workload_wall_upper_bound_seconds"]+=elapsed
        state["retained_artifact_bytes"]=sum(tree_bytes(ROOT/p) for p in state.get("owned_artifact_roots",[]))
        if state["retained_artifact_bytes"]>2*1024**3:state["status"]="halted-disk-bound"
        state.setdefault("process_records",[]).append({"plan":plan_id,"category":"workload",
            "process":"canonical-core-or-control", "work_directory":str(work.relative_to(ROOT)),
            "elapsed_seconds":elapsed,"receipts":receipts})
        write_json(work/"process.json",{"processes":receipts,"streams":streams,"wall_seconds":elapsed})
        _write_window(state)
        if state.get("status")=="halted-disk-bound":raise RuntimeError("retained-disk-bound-exceeded")


def freeze_candidate(build, map_path, output):
    paths = set()
    for directory in ("src","include","tools/session","tools/headless"):
        for path in (ROOT/directory).rglob("*"):
            if path.is_file() and (path.suffix in (".c",".h",".inc") or path.name=="CMakeLists.txt"):
                paths.add(str(path.relative_to(ROOT)))
    for path in ("CMakeLists.txt","scripts/evidence/phase6_routes.py","tests/fixtures/phase6_game.py",
                 "tests/session/phase6_route_contract.py","fixtures/phase6/media-expectations-v1.json",
                 "tests/fixtures/phase4_game.py",
                 str(map_path.resolve().relative_to(ROOT)),"evidence/phase5-current-reference.json",
                 "evidence/phase5-reference-d118.json"):
        paths.add(path)
    for directory in ("fixtures/phase5-a","fixtures/phase5-b","fixtures/independent-game-v2"):
        for name in ("scenario.json","oracle.json","input-program.json","host-controls.json","game.bin","source.tar"):
            if (ROOT/directory/name).is_file():paths.add(directory+"/"+name)
    mapping=json.loads(map_path.read_text())
    client=build/"tools/session/gw_headless"
    candidate={"schema":"genewhip-phase6-candidate-v1","source_files":{p:sha(ROOT/p) for p in sorted(paths)},
        "build_identity":{"cmake_cache_sha256":sha(build/"CMakeCache.txt"),"generator":"Ninja","build_type":"Debug"},
        "configuration_identity":{"audio_rate_hz":48000,"profile":"VA3-NTSC-U","test_hooks":True},
        "client_identities":{"public-core":{"path":str(client.relative_to(ROOT)),"sha256":sha(client)}},
        "compiler_identity":{"path":"scripts/evidence/phase6_routes.py","sha256":sha(ROOT/"scripts/evidence/phase6_routes.py")},
        "delivery_map_identity":{"path":str(map_path.resolve().relative_to(ROOT)),"sha256":canonical_sha(mapping),"schema":mapping["schema"]},
        "media_expectations_identity":{"path":"fixtures/phase6/media-expectations-v1.json","sha256":sha(ROOT/"fixtures/phase6/media-expectations-v1.json")},
        "media_expectations_sha256":sha(ROOT/"fixtures/phase6/media-expectations-v1.json"),
        "proof_dependencies":{"core":"headless+core/session+compiler/map+capture+original fixtures","host":"separately qualified in52; SDL-only edits do not invalidate headless"},
        "invalidations":{},"qualification_batch":"canonical two-title three-case x2 plus original six-case control x2"}
    write_json(output,candidate)
    return candidate


def freeze_build_provenance(candidate, build):
    """Retain the exact CMake bytes bound by a candidate before any route launch."""
    destination = (ROOT/"build/v02/runtime/build-provenance") if _EXECUTION_SCOPE is not None else build / "evidence/build-provenance"
    destination.mkdir(parents=True, exist_ok=True)
    for relative, expected in candidate.get("source_files", {}).items():
        if pathlib.PurePosixPath(relative).name != "CMakeLists.txt":
            continue
        retained = destination / f"{expected}.cmake"
        if retained.exists():
            if retained.is_symlink() or not retained.is_file() or sha(retained) != expected:
                raise compiler.Invalid("candidate-cmake-provenance-collision")
        else:
            source = (ROOT / relative).resolve(strict=True)
            if not source.is_relative_to(ROOT) or source.is_symlink() or sha(source) != expected:
                raise compiler.Invalid("candidate-cmake-provenance-mismatch")
            temporary = destination / f".{expected}.cmake.tmp"
            temporary.write_bytes(source.read_bytes())
            if sha(temporary) != expected:
                temporary.unlink(missing_ok=True)
                raise compiler.Invalid("candidate-cmake-provenance-copy")
            temporary.replace(retained)
    return True


SAFETY_TESTS = ("load_contract", "time_contract", "reset_contract", "bus_boundary_contract",
    "gameplay_bus_contract", "movem_contract", "phase6_repairs_contract", "session_contract",
    "input_log_contract", "phase6_chunk_contract", "phase6_safety", "phase6_delivery_map_contract")
SAFETY_SOURCE_PATHS = tuple("tests/api/"+name+".c" for name in SAFETY_TESTS
    if name not in {"session_contract","input_log_contract","phase6_chunk_contract","phase6_delivery_map_contract"}) + (
    "tests/session/session_contract.c","tests/session/input_log_contract.c",
    "tests/session/phase6_chunk_contract.c","tests/session/phase6_controller_contract.py",
    "tests/api/safety_contract.py","tests/api/bounded_fuzz.c","tests/api/contract.h","tests/fixtures/phase6_game.py",
    "CMakeLists.txt","tools/session/CMakeLists.txt")


def _command(command, timeout, *, cwd=ROOT, env=None):
    if _EXECUTION_SCOPE is not None:
        setup_root = ROOT / "build/v02/runtime/setup"
        setup_root.mkdir(parents=True, exist_ok=True)
        work = pathlib.Path(tempfile.mkdtemp(prefix="phase7-setup-", dir=setup_root))
        report = work / "command-output.json"
        scoped_command = [str((cwd / command[0]).resolve()) if not pathlib.Path(command[0]).is_absolute()
            and str(command[0]).startswith("./") else command[0] for command in command]
        result, receipt, streams = shared_launch(pathlib.Path(scoped_command[0]), scoped_command, work, report,
            timeout, plan_id="07-09-setup")
        return subprocess.CompletedProcess(command, result.returncode,
            streams.get("stdout", {}).get("text", ""), streams.get("stderr", {}).get("text", ""))
    try:
        return subprocess.run(command, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"safety-command-timeout:{command[0]}") from error


def _setup_charge(label, elapsed, command):
    state=_read_window()
    state["setup_test_wall_seconds"]+=elapsed
    state["setup_test_wall_upper_bound_seconds"]+=elapsed
    state.setdefault("setup_test_records",[]).append({"plan":"06-53","group":label,
        "elapsed_seconds":elapsed,"classification":"measured","command":command})
    _write_window(state)


def safety(build, candidate_path, output):
    """Run only the finite, named Phase53 safety roster in three build variants."""
    import sysconfig
    base=build.resolve(strict=True)
    candidate=json.loads(candidate_path.read_text())
    freeze_build_provenance(candidate,base)
    rows=[];native_parser_report_path=None
    runtime_root=ROOT/"build/v02/runtime/safety" if _EXECUTION_SCOPE is not None else ROOT/"build"
    for variant,directory,cache_args in (
        ("native",base,[]),
        ("sanitize",runtime_root/("asan-ubsan" if _EXECUTION_SCOPE is not None else "phase6-sanitize"),["-DCMAKE_BUILD_TYPE=Debug",
            "-DGENEWHIP_TEST_HOOKS=ON","-DGENEWHIP_BUILD_DESKTOP=OFF",
            "-DCMAKE_C_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer",
            "-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined"]),
        ("hooks-off",runtime_root/("hooks-off" if _EXECUTION_SCOPE is not None else "phase6-hooks-off"),["-DCMAKE_BUILD_TYPE=Debug",
            "-DGENEWHIP_TEST_HOOKS=OFF","-DGENEWHIP_BUILD_DESKTOP=OFF"]),
    ):
        started=time.monotonic();commands=[]
        child_env=os.environ.copy()
        if variant=="sanitize":
            child_env["ASAN_OPTIONS"]="detect_leaks=0"
            child_env["UBSAN_OPTIONS"]="halt_on_error=1"
        if variant!="native":
            directory.mkdir(parents=True,exist_ok=True)
            configure=["cmake","-S",str(ROOT),"-B",str(directory),"-G","Ninja",
                "-DBUILD_TESTING=ON","-DGENEWHIP_BUILD_TOOLS=ON",*cache_args]
            result=_command(configure,120)
            commands.append(configure)
            if result.returncode:raise RuntimeError(f"{variant}-configure:{result.stderr[-3000:]}")
        targets=["gw_bounded_fuzz","phase6_safety","load_contract","time_contract","reset_contract",
            "bus_boundary_contract","gameplay_bus_contract","movem_contract","phase6_repairs_contract",
            "session_contract","input_log_contract","phase6_chunk_contract","gw_headless"]
        build_cmd=["cmake","--build",str(directory),"--parallel","2","--target",*sorted(set(targets))]
        if variant=="native":
            result=_command(build_cmd,150)
            commands.append(build_cmd)
            if result.returncode:raise RuntimeError(f"{variant}-build:{result.stderr[-3000:]}")
        listing=_command(["ctest","--test-dir",str(directory),"--show-only=json-v1"],30)
        commands.append(["ctest","--show-only=json-v1"])
        if listing.returncode:raise RuntimeError(f"{variant}-ctest-discovery:{listing.stderr[-2000:]}")
        discovered=json.loads(listing.stdout)
        by_name={test["name"]:test for test in discovered.get("tests",[])}
        if set(SAFETY_TESTS)-set(by_name):
            raise RuntimeError(f"{variant}-missing-ctest:{sorted(set(SAFETY_TESTS)-set(by_name))}")
        selected=[]
        for name in SAFETY_TESTS:
            command=" ".join(by_name[name].get("command",[])).lower()
            if any(token in command for token in ("mame","accounting","phase6_core_routes","independent_game_admission")):
                raise RuntimeError(f"{variant}-unsafe-ctest-command:{name}")
            selected.append(name)
        if variant!="native":
            result=_command(build_cmd,150)
            commands.append(build_cmd)
            if result.returncode:raise RuntimeError(f"{variant}-build:{result.stderr[-3000:]}")
        parser_report_path=(ROOT/"build/v02/runtime/safety/native-parser.json" if _EXECUTION_SCOPE is not None and variant=="native"
            else directory/"evidence/controller.json")
        parser_report_path.parent.mkdir(parents=True,exist_ok=True)
        parser_contract=[sys.executable,"-I",str(ROOT/"tests/session/phase6_controller_contract.py"),
            "--build",str(directory),"--parser-only","--out",str(parser_report_path)]
        if variant=="native":
            parser_result=_command(parser_contract,120)
            commands.append(parser_contract)
            if parser_result.returncode:raise RuntimeError(f"native-parser-rejection:{parser_result.stderr[-2000:]}")
            parser_report=json.loads(parser_report_path.read_text())
            if parser_report.get("status")!="pass" or parser_report.get("tests")!=1 or not parser_report.get("runs"):
                raise RuntimeError("native-parser-rejection-report")
            native_parser_report_path=parser_report_path
        # CTest has no exact multi-name selector, so invoke each discovered name
        # separately; this preserves the measured roster and avoids regex aliasing.
        results=[]
        for name in SAFETY_TESTS:
            one=["ctest","--test-dir",str(directory),"--no-tests=error","--output-on-failure","-R",f"^{name}$"]
            commands.append(one);run=_command(one,65,env=child_env)
            if run.returncode:raise RuntimeError(f"{variant}-{name}:{run.stdout[-2000:]}{run.stderr[-1000:]}")
            results.append({"name":name,"exit_code":run.returncode,"skip": "***Skipped" in run.stdout})
        if any(row["skip"] for row in results):raise RuntimeError(f"{variant}-required-ctest-skipped")
        fuzz_bin=directory/"gw_bounded_fuzz"
        fuzz_cmd=[str(fuzz_bin)]
        fuzz_run=_command(fuzz_cmd,90,env=child_env);commands.append(fuzz_cmd)
        if fuzz_run.returncode:raise RuntimeError(f"{variant}-bounded-fuzz:{fuzz_run.stderr[-2000:]}")
        fuzz_summary=json.loads(fuzz_run.stdout.strip().splitlines()[-1])
        if (fuzz_summary.get("denominator")!=4096 or fuzz_summary.get("pass")!=4096 or
                fuzz_summary.get("fail")!=0 or fuzz_summary.get("tick_budget")!=128 or
                fuzz_summary.get("accepted_loads",0)<=0 or fuzz_summary.get("rejected_loads",0)<=0 or
                fuzz_summary.get("accepted_loads",0)+fuzz_summary.get("rejected_loads",0)!=4096):
            raise RuntimeError(f"{variant}-bounded-fuzz-summary")
        report_path=(ROOT/f"build/v02/runtime/safety/{variant}-api.json" if _EXECUTION_SCOPE is not None
            else directory/"evidence/phase6-safety-contract.json")
        report_path.parent.mkdir(parents=True,exist_ok=True)
        contract_cmd=[sys.executable,"-I",str(ROOT/"tests/api/safety_contract.py"),"--build",str(directory),
            "--mode","production" if variant=="hooks-off" else "pr","--out",str(report_path)]
        cr=_command(contract_cmd,90,env=child_env);commands.append(contract_cmd)
        if cr.returncode:raise RuntimeError(f"{variant}-api-safety:{cr.stderr[-2000:]}")
        summary=json.loads(report_path.read_text())
        raw_peak=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        owned_peak=int(raw_peak if sys.platform=="darwin" else raw_peak*1024)
        elapsed=time.monotonic()-started
        _setup_charge("safety-"+variant,elapsed,commands)
        test_binaries={str(fuzz_bin.relative_to(ROOT)):sha(fuzz_bin)}
        for name in SAFETY_TESTS:
            path=pathlib.Path(by_name[name]["command"][0])
            if path.is_relative_to(directory) and path.is_file():
                test_binaries[str(path.relative_to(ROOT))]=sha(path)
        rows.append({"variant":variant,"build_directory":str(directory.resolve().relative_to(ROOT)),
            "selected_tests":selected,"denominator":len(results),
            "pass":sum(r["exit_code"]==0 for r in results),"fail":0,"unknown":0,"skipped":0,
            "steps":summary["safety_pass"]*summary["steps_per_case"],"step_limit":summary["cases"]*summary["steps_per_case"],
            "tick_budget":summary["tick_budget"],"max_tick":summary["max_tick"],
            "returned_frames":summary["returned_frames"],
            "output_cap":summary["cases"]*summary["output_cap_frames"],"guards_checked":summary["safety_pass"],
            "allocation_instrumented":summary["allocation_instrumented"],
            "allocation_count_peak":summary["allocation_count_peak"],"steady_allocations":summary["steady_allocations"],
            "owned_bytes_peak":owned_peak,"owned_bytes_limit":1024**3,
            "bounded_fuzz":{"denominator":4096,"pass":4096,"fail":0,"unknown":0,"skipped":0,
                "tick_budget":128,"accepted_loads":fuzz_summary["accepted_loads"],
                "rejected_loads":fuzz_summary["rejected_loads"]},
            "fuzz":{"summary":fuzz_summary,"command":[str(fuzz_bin.relative_to(ROOT))]},"api_contract":artifact(report_path),
            "ctest_json_sha256":hashlib.sha256(listing.stdout.encode()).hexdigest(),
            "build_identity":{"cache_sha256":sha(directory/"CMakeCache.txt"),"phase6_safety_sha256":sha(directory/"phase6_safety"),
                "test_executables":test_binaries,
                "hooks_off":variant=="hooks-off","sanitizers":variant=="sanitize"}})
    report={"schema":"genewhip-phase6-safety-v1","candidate_sha256":canonical_sha(candidate),
        "source_provenance":{path:sha(ROOT/path) for path in SAFETY_SOURCE_PATHS},
        "variants":rows,"registered_tests":list(SAFETY_TESTS),
        "parser_rejection":artifact(native_parser_report_path),"status":"pass"}
    validator=load_module("phase6_safety_contract",ROOT/"tests/api/safety_contract.py")
    validate_phase6_safety_report=validator.validate_phase6_safety_report
    reason=validate_phase6_safety_report(report)
    if reason:raise RuntimeError("phase6-safety-report:"+reason)
    write_json(output,report)
    return 0


def collect_case(build,route,mapping,candidate,work,rep,remaining_seconds=600,compiled_binary=None):
    if work.exists():
        if work.is_symlink() or not work.is_dir() or sorted(p.name for p in work.iterdir()) != ["fields"]:
            raise RuntimeError("existing incomplete case directory is not the owned prelaunch skeleton")
        fields=work/"fields"
        if fields.is_symlink() or not fields.is_dir() or any(fields.iterdir()):
            raise RuntimeError("existing incomplete case field directory is not empty")
    else:
        work.mkdir();fields=work/"fields";fields.mkdir()
    native_path=work/"native.json";plan_path=work/"route.gwrc";pcm=work/"audio.pcm";trace=work/"audio-trace.jsonl"
    rec=route["fixture"]=="recursion94"
    cap=100_000_000 if rec else 10_000_000
    binary=compiled_binary
    if binary is None:binary,metadata=compiler.lower_route(route,cap,mapping if rec else None)
    plan_path.write_bytes(binary)
    client=build/"tools/session/gw_headless"
    rom=ROOT/compiler.SOURCES[route["fixture"]][3]
    command=[str(client),"--route-plan",str(plan_path),"--route-report",str(native_path),
        "--audio-rate","48000","--dump-audio",str(pcm),"--dump-audio-trace",str(trace),
        "--dump-fields",str(fields),"--capture-identity",canonical_sha(candidate)]
    command += ["--capture-attempt-tick","4","690"] if rec else ["--capture-field","120"]
    command.append(str(rom))
    result,process,streams=shared_launch(client,command,work,native_path,min(600 if rec else 300,remaining_seconds),
        files=((pcm,16*1024*1024),(trace,4*1024*1024)),directories=((fields,3,320*224*4+8192),))
    row={"fixture":route["fixture"],"case":route["case"]["id"],"repetition":rep,
        "client":"public-core","identity":route["identity"],"process":process,
        "delivery_map_sha256":canonical_sha(mapping) if rec else None,
        "compiled_sha256":hashlib.sha256(binary).hexdigest(),"status":"fail",
        "reason":None,"process_receipt":artifact(work/"process.json")}
    write_json(work/"run.json",row)
    if result.returncode or process.get("bound_violation"):
        row["reason"]="client-process-failed";write_json(work/"run.json",row)
        raise RuntimeError(f"{route['fixture']}/{route['case']['id']}: process failed, {result.stderr[-1000:]}")
    native=json.loads(native_path.read_text())
    row.update(native_report=artifact(native_path),pcm=artifact(pcm),audio_trace=artifact(trace),
        predicate_results={p["id"]:{"reached":v["reached"],"value":v.get("value"),"field":v.get("clock")}
                    for p,v in zip(route["definitions"]["predicates"],native["predicates"])})
    compiler._validate_native_facts(route,"sustained",row,mapping if rec else None,cap)
    scene_path=fields/"route-capture.json";scene=json.loads(scene_path.read_text())
    row.update(image=artifact(fields/f"field-{scene['field_sequence']}.bin"),scene_metadata=artifact(scene_path),
        completed_fields=native["fields"],field_sequence=scene["field_sequence"],
        attempt=scene.get("attempt"),source_tick=scene.get("source_tick"),field=scene["field"])
    field_rows=[json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
    field_rows=[x for x in field_rows if "sequence" in x and "fnv1a64" in x]
    if len(field_rows)!=native["fields"]:
        raise RuntimeError("completed-field stdout denominator mismatch")
    row["field_hashes_sha256"]=canonical_sha(field_rows)
    row["status"]="pass";write_json(work/"run.json",row)
    return row


def recover_completed_case(build,route,mapping,candidate,work,rep,compiled_binary=None):
    """Validate and consume a retained completed launch; never starts a child."""
    work=work.resolve(strict=True)
    if not work.is_relative_to((build/"evidence").resolve(strict=True)):
        raise RuntimeError("resume work directory escapes build evidence")
    run_path=work/"run.json";process_path=work/"process.json"
    run=json.loads(run_path.read_text());receipt=json.loads(process_path.read_text())
    if (run.get("fixture")!=route["fixture"] or run.get("case")!=route["case"]["id"] or
            run.get("repetition")!=rep or run.get("identity")!=route["identity"] or
            run.get("status")!="fail" or run.get("reason") is not None):
        raise RuntimeError("resume retained run identity is not the failed canonical row")
    if run.get("process_receipt")!=artifact(process_path):
        raise RuntimeError("resume process receipt digest changed")
    processes=receipt.get("processes")
    if not isinstance(processes,list) or len(processes)!=1:
        raise RuntimeError("resume requires exactly one retained child process")
    process=processes[0]
    if (process!=run.get("process") or process.get("return_code")!=0 or process.get("bound_violation") or
            process.get("process_group_cleanup")!="confirmed" or process.get("status")!="completed" or
            type(process.get("pid")) is not int or process.get("pgid")!=process.get("pid")):
        raise RuntimeError("resume retained process did not complete within its process boundary")
    window=_read_window()
    work_relative=str(work.relative_to(ROOT))
    admitted=[item for item in window.get("process_records",[]) if item.get("process")=="canonical-core-or-control" and
              item.get("work_directory")==work_relative]
    if (len(admitted)!=1 or admitted[0].get("category")!="workload" or
            admitted[0].get("receipts")!=processes or
            not process.get("wall_seconds",0)<=admitted[0].get("elapsed_seconds",-1)<=600):
        raise RuntimeError("resume process receipt is not bound to the actual shared-window workload accounting")
    streams=receipt.get("streams",{});stdout=streams.get("stdout",{});stderr=streams.get("stderr",{})
    if (stdout.get("truncated") or stderr.get("truncated") or
            stdout.get("observed_bytes")!=len(stdout.get("text","").encode()) or
            stderr.get("observed_bytes")!=len(stderr.get("text","").encode()) or
            stdout.get("sha256")!=hashlib.sha256(stdout.get("text","").encode()).hexdigest() or
            stderr.get("sha256")!=hashlib.sha256(stderr.get("text","").encode()).hexdigest()):
        raise RuntimeError("resume retained process streams are incomplete or changed")
    native_path=work/"native.json";plan_path=work/"route.gwrc";pcm=work/"audio.pcm";trace=work/"audio-trace.jsonl"
    if any(path.is_symlink() or not path.is_file() for path in (native_path,plan_path,pcm,trace)):
        raise RuntimeError("resume raw output is missing or symlinked")
    rec=route["fixture"]=="recursion94";cap=100_000_000 if rec else 10_000_000
    binary=compiled_binary
    if binary is None:binary,_=compiler.lower_route(route,cap,mapping if rec else None)
    if plan_path.read_bytes()!=binary or hashlib.sha256(binary).hexdigest()!=run.get("compiled_sha256"):
        raise RuntimeError("resume compiled route differs from frozen launch plan")
    native=json.loads(native_path.read_text())
    if (native.get("schema")!="genewhip-route-native-v1" or native.get("status")!=0 or
            native.get("active_ticks")!=3600 or native.get("fields")!=3631 or
            native.get("audio_complete") is not True or native.get("audio_open") is not True):
        raise RuntimeError("resume native report is not the complete successful canonical route")
    field_rows=[json.loads(line) for line in stdout["text"].splitlines() if line.startswith("{")]
    field_rows=[row for row in field_rows if "sequence" in row and "fnv1a64" in row]
    if len(field_rows)!=native["fields"]:
        raise RuntimeError("resume retained field stream denominator mismatch")
    if pcm.stat().st_size!=native["audio_frames"]*4 or pcm.stat().st_size>16*1024*1024 or trace.stat().st_size>4*1024*1024:
        raise RuntimeError("resume retained PCM/trace size is invalid")
    fields=work/"fields";scene_path=fields/"route-capture.json"
    if fields.is_symlink() or scene_path.is_symlink() or not scene_path.is_file():
        raise RuntimeError("resume selected scene sidecar missing or unsafe")
    scene=json.loads(scene_path.read_text())
    if scene.get("candidate_sha256")!=canonical_sha(candidate):
        raise RuntimeError("resume scene sidecar candidate mismatch")
    field_path=fields/f"field-{scene.get('field_sequence')}.bin"
    if field_path.is_symlink() or not field_path.is_file() or field_path.stat().st_size!=320*224*4:
        raise RuntimeError("resume selected field image missing or invalid")
    if rec and (scene.get("attempt")!=4 or scene.get("source_tick",0)<690):
        raise RuntimeError("resume selected REC scene is outside the declared source window")
    if not rec and scene.get("field")!=120:
        raise RuntimeError("resume selected Tank scene is outside field120")
    row={"fixture":route["fixture"],"case":route["case"]["id"],"repetition":rep,
        "client":"public-core","identity":route["identity"],"process":process,
        "delivery_map_sha256":canonical_sha(mapping) if rec else None,
        "compiled_sha256":hashlib.sha256(binary).hexdigest(),"status":"pass","reason":None,
        "process_receipt":artifact(process_path),"native_report":artifact(native_path),
        "pcm":artifact(pcm),"audio_trace":artifact(trace),
        "predicate_results":{p["id"]:{"reached":v["reached"],"value":v.get("value"),"field":v.get("clock")}
            for p,v in zip(route["definitions"]["predicates"],native["predicates"])}}
    compiler._validate_native_facts(route,"sustained",row,mapping if rec else None,cap)
    row.update(image=artifact(field_path),scene_metadata=artifact(scene_path),completed_fields=native["fields"],
        field_sequence=scene["field_sequence"],attempt=scene.get("attempt"),source_tick=scene.get("source_tick"),field=scene["field"],
        field_hashes_sha256=canonical_sha(field_rows))
    write_json(work/"recovered-run.json",row)
    return row


def contextual_stages(routes,runs):
    by_key={(r["fixture"],r["case"],r["repetition"]):r for r in runs}
    cells=[]
    for route in routes:
        for rep in (1,2):
            run=by_key.get((route["fixture"],route["case"]["id"],rep))
            for stage in compiler.STAGES:
                reached=bool(run and run.get("status")=="pass")
                status="pass" if reached else "unknown"
                detail="Automated declared case observation" if reached else "Not attempted or failed; see run receipt"
                if stage=="completion":status,reached,detail="unknown",False,"No whole-game completion claim; bounded predicates remain in run receipt"
                elif route["fixture"]=="genewhip-independent-game-v2" and stage=="sustained" and route["case"]["id"]!="sustained-play":
                    status,reached,detail="skipped",False,"Short control case; sustained denominator belongs to sustained-play"
                elif route["case"]["id"]=="title-no-start" and stage=="interaction":
                    status,reached,detail="skipped",False,"No Start is the intended negative control"
                cells.append({"fixture":route["fixture"],"case":route["case"]["id"],"repetition":rep,
                    "stage":stage,"status":status,"reached":reached,"detail":detail,
                    "evidence":run.get("native_report",run.get("control_report")) if run else None})
    return cells


def reader_provenance():
    return {path:sha(ROOT/path) for path in READER_PROVENANCE_PATHS}


def validation_identities():
    return {"reader_provenance":reader_provenance(),
            "media_expectations_sha256":sha(ROOT/"fixtures/phase6/media-expectations-v1.json")}


def refresh_reader_bound_proofs(build):
    """Rebind reader-only metadata while preserving canonical candidate and raw runs."""
    candidate_path=ROOT/"evidence/phase6-candidate.json"
    candidate=json.loads(candidate_path.read_text())
    core_path=ROOT/"evidence/phase6-core-routes.json"
    archive=build/"evidence/phase6-core-reader-archive-plan53"
    suffix=1
    while archive.exists():
        suffix+=1;archive=build/f"evidence/phase6-core-reader-archive-plan53-{suffix}"
    archive.mkdir(parents=True)
    shutil.copyfile(core_path,archive/"phase6-core-routes.json")
    window=_read_window()
    rel=str(archive.relative_to(ROOT))
    if rel not in window["owned_artifact_roots"]:window["owned_artifact_roots"].append(rel)
    window["retained_artifact_bytes"]=sum(tree_bytes(ROOT/p) for p in window["owned_artifact_roots"])
    _write_window(window)
    core=json.loads(core_path.read_text())
    core["reader_provenance"]=reader_provenance()
    core["validation_identities"]=validation_identities()
    write_json(core_path,core)
    compiler.validate_product_report(core,candidate)

    media_path=ROOT/"evidence/phase6-media.json"
    media_report=json.loads(media_path.read_text())
    media_report["core_routes"]=artifact(core_path)
    media_report["core_routes_sha256"]=sha(core_path)
    write_json(media_path,media_report)
    compiler.validate_media_report(media_report,candidate)

    rebound=[]
    for relative in ("evidence/phase6-host-software-current.json","evidence/phase6-host-native.json"):
        host_path=ROOT/relative;host=json.loads(host_path.read_text())
        prior=host["host_identity"]["core_report"]["sha256"]
        prior_test=host["host_identity"].get("desktop_test_source_sha256")
        host["host_identity"]["core_report"]=artifact(core_path)
        host["host_identity"]["desktop_test_source_sha256"]=sha(ROOT/"tests/desktop/phase6_routes.py")
        host["host_identity_sha256"]=canonical_sha(host["host_identity"])
        host.setdefault("reader_reconciliations",[]).append({"source":"Plan53 reader refresh",
            "prior_core_report_sha256":prior,"current_core_report_sha256":sha(core_path),
            "prior_desktop_test_source_sha256":prior_test,
            "current_desktop_test_source_sha256":host["host_identity"]["desktop_test_source_sha256"],
            "reason":"offline host-negative reuse changes no qualification route; positive case receipts remain unchanged",
            "archived_core_report":str((archive/"phase6-core-routes.json").relative_to(ROOT))})
        write_json(host_path,host)
        compiler.validate_host_report(host,candidate)
        rebound.append(relative)
    return {"archive":str(archive.relative_to(ROOT)),"core_report":artifact(core_path),
        "media_report":artifact(media_path),"host_reports":rebound,
        "candidate_sha256":canonical_sha(candidate)}


def chunk(build,candidate_path,delivery_map_path,output):
    """Compare actual full-title public API execution at every common field boundary."""
    build=build.resolve(strict=True);candidate=json.loads(candidate_path.read_text())
    mapping=json.loads(delivery_map_path.read_text());compiler.validate_delivery_map(mapping)
    if _EXECUTION_SCOPE is not None:
        core_report_path=_EXECUTION_SCOPE.get("_core_report_path")
        if not isinstance(core_report_path,str):raise RuntimeError("phase7-chunk-current-core-path-missing")
        core_path=pathlib.Path(core_report_path).resolve(strict=True)
    else:
        reader_refresh=refresh_reader_bound_proofs(build)
        core_path=ROOT/"evidence/phase6-core-routes.json"
    core_report=json.loads(core_path.read_text())
    compiler.validate_product_report(core_report,candidate)
    executable=build/"tools/session/phase6_chunk_contract"
    if not executable.is_file():raise RuntimeError("phase6-chunk-executable-missing")
    setup_start=time.monotonic()
    discovery=_command(["ctest","--test-dir",str(build),"--show-only=json-v1"],30)
    if discovery.returncode:raise RuntimeError("phase6-chunk-ctest-discovery")
    tests=json.loads(discovery.stdout).get("tests",[])
    selected=[item for item in tests if item.get("name")=="phase6_chunk_contract"]
    if len(selected)!=1 or any(term in " ".join(selected[0].get("command",[])).lower()
        for term in ("mame","accounting","phase6_core_routes")):
        raise RuntimeError("phase6-chunk-ctest-command")
    command=["ctest","--test-dir",str(build),"--no-tests=error","--output-on-failure",
        "-R","^phase6_chunk_contract$"]
    short=_command(command,65)
    if short.returncode or "100% tests passed" not in short.stdout:
        raise RuntimeError(f"phase6-chunk-short-contract:{short.stdout[-2000:]}{short.stderr[-1000:]}")
    setup_elapsed=time.monotonic()-setup_start
    _setup_charge("phase6-short-chunk-contract",setup_elapsed,[discovery.args,command])
    rows=[];window=_read_window()
    for fixture,cap,timeout in (("recursion94",100_000_000,600),("tank-battle",10_000_000,300)):
        source_run=next((row for row in core_report["runs"] if row.get("fixture")==fixture and
            row.get("case")=="full-route" and row.get("repetition")==1),None)
        if source_run is None:raise RuntimeError(f"chunk-source-route-missing:{fixture}")
        native_ref=source_run.get("native_report",{});native_path=(ROOT/native_ref.get("path","")).resolve()
        if not native_path.is_relative_to(ROOT) or not native_path.is_file() or sha(native_path)!=native_ref.get("sha256"):
            raise RuntimeError(f"chunk-source-native-identity:{fixture}")
        native=json.loads(native_path.read_text())
        inputs=native.get("inputs")
        if not isinstance(inputs,list) or not 1<=len(inputs)<=64 or native.get("status")!=0:
            raise RuntimeError(f"chunk-source-input-roster:{fixture}")
        for row in inputs:
            if (type(row.get("machine_tick")) is not int or row["machine_tick"]<112 or
                type(row.get("port")) is not int or row["port"] not in (0,1) or
                type(row.get("effective")) is not int or not 0<=row["effective"]<=255):
                raise RuntimeError(f"chunk-source-input-invalid:{fixture}")
        rom=(ROOT/pathlib.Path(compiler.SOURCES[fixture][3])).resolve(strict=True)
        if not rom.is_relative_to(ROOT) or rom.is_symlink():raise RuntimeError("chunk-rom-path")
        media_ref=source_run.get("image",{});media_path=(ROOT/media_ref.get("path","")).resolve()
        pcm_ref=source_run.get("pcm",{});pcm_path=(ROOT/pcm_ref.get("path","")).resolve()
        for ref,path,limit in ((media_ref,media_path,320*224*4),(pcm_ref,pcm_path,16*1024*1024)):
            if (not path.is_relative_to(ROOT) or not path.is_file() or path.is_symlink() or
                path.stat().st_size>limit or sha(path)!=ref.get("sha256")):
                raise RuntimeError(f"chunk-source-media-identity:{fixture}")
        def fnv_file(path):
            value=14695981039346656037
            with path.open("rb") as stream:
                while block:=stream.read(65536):
                    for byte in block:value=((value^byte)*1099511628211)&((1<<64)-1)
            return f"{value:016x}"
        expected_pcm_fnv=fnv_file(pcm_path);expected_media_fnv=fnv_file(media_path)
        input_text="".join(f"{row['machine_tick']},{row['port']},{row['effective']}\n" for row in inputs)
        chunk_root=(ROOT/"build/v02/runtime/chunk-work") if _EXECUTION_SCOPE is not None else build/"evidence"
        chunk_root.mkdir(parents=True,exist_ok=True)
        work=pathlib.Path(tempfile.mkdtemp(prefix=f"phase6-chunk-{fixture}-",dir=chunk_root))
        relative=str(work.relative_to(ROOT));window=_read_window()
        if relative not in window["owned_artifact_roots"]:window["owned_artifact_roots"].append(relative)
        window["retained_artifact_bytes"]=sum(tree_bytes(ROOT/p) for p in window["owned_artifact_roots"])
        _write_window(window)
        input_path=work/"actual-inputs.csv";report_path=work/"chunk.json"
        input_path.write_text(input_text)
        command=[str(executable),"--title",str(rom),str(input_path),str(native["fields"]),str(cap),
            str(source_run["field_sequence"]),str(native["final_tick"]),str(report_path)]
        result,process,streams=shared_launch(executable,command,work,report_path,timeout,
            files=((report_path,1024*1024),),plan_id="06-53")
        if result.returncode!=0 or process.get("process_group_cleanup")!="confirmed":
            rows.append({"fixture":fixture,"case":"full-route","source_run":{
                    "candidate_sha256":core_report["candidate_sha256"],"native_report":native_ref,
                    "inputs":len(inputs),"fields":native["fields"],"active_ticks":native["active_ticks"],
                    "full_pcm":pcm_ref,"selected_media":media_ref},
                "input_log":artifact(input_path),"process_receipt":artifact(work/"process.json"),
                "process":process,"streams":streams,"limits":{"boundary_calls":cap,"wall_seconds":timeout},
                "status":"unknown","reason":"variable-run-incomplete-or-cleanup-unconfirmed"})
            continue
        title=json.loads(report_path.read_text())
        _validate_title_pair_facts(title,native,cap,fixture)
        if (title.get("schema")!="genewhip-phase6-title-chunk-v1" or title.get("status")!="pass" or
            title.get("fields")!=native.get("fields") or title.get("events")!=len(inputs) or
            type(title.get("variable_calls")) is not int or title["variable_calls"]<=0 or
            title["variable_calls"]>cap or title.get("pcm_frames")!=native.get("audio_frames") or
            title.get("pcm_fnv1a64")!=expected_pcm_fnv or title.get("media_sequence")!=source_run["field_sequence"] or
            title.get("media_fnv1a64")!=expected_media_fnv or not title.get("boundary_ram_fnv1a64") or
            not title.get("boundary_diagnostic_fnv1a64")):
            raise RuntimeError(f"chunk-title-report:{fixture}")
        rows.append({"fixture":fixture,"case":"full-route","source_run":{
                "candidate_sha256":core_report["candidate_sha256"],"native_report":native_ref,
                "inputs":len(inputs),"fields":native["fields"],"active_ticks":native["active_ticks"],
                "full_pcm":pcm_ref,"selected_media":media_ref},
            "chunk_report":artifact(report_path),"process":process,"streams":streams,
            "variable_calls":title["variable_calls"],"common_boundaries":title["fields"],
            "pcm_frames":title["pcm_frames"],"pcm_fnv1a64_matches_retained_full_pcm":True,
            "selected_media_fnv1a64_matches_retained_frame":True,
            "boundary_ram_fnv1a64":title["boundary_ram_fnv1a64"],
            "boundary_diagnostic_fnv1a64":title["boundary_diagnostic_fnv1a64"],
            "limits":{"boundary_calls":cap,"wall_seconds":timeout},"status":"pass"})
    report={"schema":"genewhip-phase6-chunk-v1","candidate_sha256":canonical_sha(candidate),
        "test_source":artifact(ROOT/"tests/session/phase6_chunk_contract.c"),
        "test_executable":artifact(executable),
        "reader_refresh":reader_refresh,"synthetic_contract":{"test":"phase6_chunk_contract","status":"pass",
            "ctest_json_sha256":hashlib.sha256(discovery.stdout.encode()).hexdigest(),
            "command":["ctest","--test-dir",str(build.relative_to(ROOT)),"--no-tests=error",
                "--output-on-failure","-R","^phase6_chunk_contract$"]},
        "routes":rows,"status":"pass" if all(row["status"]=="pass" for row in rows) else "pending"}
    write_json(output,report)
    return 0


def _close_artifact(ref,label,expected_path,max_bytes=16*1024*1024):
    if not isinstance(ref,dict):
        raise RuntimeError(f"close-{label}-identity")
    raw_path=ROOT/ref.get("path","")
    mutant_root=ROOT/"build/phase6/evidence/phase6-close-mutants"
    is_mutant=raw_path.parent==mutant_root and raw_path.name.startswith(label+"-") and raw_path.suffix==".json"
    if ref.get("path")!=expected_path and not is_mutant:
        raise RuntimeError(f"close-{label}-identity")
    path=raw_path.resolve()
    if (not path.is_relative_to(ROOT) or path.is_symlink() or not path.is_file() or
            path.stat().st_size>max_bytes or sha(path)!=ref.get("sha256")):
        raise RuntimeError(f"close-{label}-artifact")
    try:return path,json.loads(path.read_text())
    except (UnicodeError,json.JSONDecodeError) as error:
        raise RuntimeError(f"close-{label}-json") from error


def _close_fnv(path):
    value=14695981039346656037
    with path.open("rb") as stream:
        while block:=stream.read(65536):
            for byte in block:value=((value^byte)*1099511628211)&((1<<64)-1)
    return f"{value:016x}"


def _validate_title_pair_facts(child,native,cap,fixture):
    """Require actual independent-instance comparisons, beyond recorded hashes."""
    fields=native["fields"]
    if (child.get("pair_comparison")!="pass" or
            child.get("common_boundary_comparisons")!={key:fields for key in ("ram","cpu_state","video","pcm")} or
            child.get("input_order_events_compared")!=len(native["inputs"]) or
            child.get("terminal_tick_target")!=native["final_tick"] or
            child.get("terminal_boundary_comparison")!="pass" or
            child.get("baseline_mode")!=("one-instruction-stop308" if fixture=="recursion94" else "coarse-4096-stop308") or
            child.get("instruction_events_dropped")!=0):
        raise RuntimeError(f"close-chunk-{fixture}-pair-comparison")
    for key in ("baseline_calls","variable_calls","trace_segments","compared_instruction_events","terminal_tick_actual"):
        if type(child.get(key)) is not int or child[key]<=0:
            raise RuntimeError(f"close-chunk-{fixture}-pair-denominator")
    if child["baseline_calls"]+child["variable_calls"]>cap:
        raise RuntimeError(f"close-chunk-{fixture}-aggregate-calls")
    if not native["final_tick"]<=child["terminal_tick_actual"]<=native["final_tick"]+8192:
        raise RuntimeError(f"close-chunk-{fixture}-terminal-boundary")


def _validate_close_chunk(report,candidate):
    if not isinstance(report,dict) or report.get("schema")!="genewhip-phase6-chunk-v1":
        raise RuntimeError("close-chunk-schema")
    if report.get("candidate_sha256")!=canonical_sha(candidate) or report.get("status")!="pass":
        raise RuntimeError("close-chunk-status")
    routes=report.get("routes")
    if not isinstance(routes,list) or len(routes)!=2 or {row.get("fixture") for row in routes if isinstance(row,dict)}!={"recursion94","tank-battle"}:
        raise RuntimeError("close-chunk-roster")
    for key,path in (("test_source","tests/session/phase6_chunk_contract.c"),
            ("test_executable","build/phase6/tools/session/phase6_chunk_contract")):
        ref=report.get(key,{})
        current=ROOT/path
        if ref.get("path")!=path or current.is_symlink() or not current.is_file() or sha(current)!=ref.get("sha256"):
            raise RuntimeError("close-chunk-test-identity")
    for row in routes:
        fixture=row["fixture"]
        if row.get("status")!="pass":raise RuntimeError(f"close-chunk-{fixture}-status")
        source=row.get("source_run")
        if not isinstance(source,dict) or source.get("candidate_sha256")!=canonical_sha(candidate):
            raise RuntimeError(f"close-chunk-{fixture}-source")
        native_ref=source.get("native_report",{});native_path=(ROOT/native_ref.get("path","")).resolve()
        if (not native_path.is_relative_to(ROOT) or native_path.is_symlink() or not native_path.is_file() or
                sha(native_path)!=native_ref.get("sha256")):
            raise RuntimeError(f"close-chunk-{fixture}-native")
        native=json.loads(native_path.read_text())
        if (native.get("status")!=0 or native.get("fields")!=source.get("fields") or
                native.get("active_ticks")!=source.get("active_ticks") or
                type(source.get("inputs")) is not int or source["inputs"]!=len(native.get("inputs",[]))):
            raise RuntimeError(f"close-chunk-{fixture}-native-facts")
        cap,wall=(100_000_000,600) if fixture=="recursion94" else (10_000_000,300)
        if row.get("limits")!={"boundary_calls":cap,"wall_seconds":wall}:
            raise RuntimeError(f"close-chunk-{fixture}-limits")
        child_report_ref=row.get("chunk_report")
        if not isinstance(child_report_ref,dict):raise RuntimeError(f"close-chunk-{fixture}-report-ref")
        child_report_path=(ROOT/child_report_ref.get("path","")).resolve()
        if (not child_report_path.is_relative_to(ROOT/"build/phase6/evidence") or child_report_path.is_symlink() or
                not child_report_path.is_file() or sha(child_report_path)!=child_report_ref.get("sha256")):
            raise RuntimeError(f"close-chunk-{fixture}-report-artifact")
        child=json.loads(child_report_path.read_text());directory=child_report_path.parent
        _validate_title_pair_facts(child,native,cap,fixture)
        input_path=directory/"actual-inputs.csv";receipt_path=directory/"process.json"
        if not input_path.is_file() or input_path.is_symlink() or not receipt_path.is_file() or receipt_path.is_symlink():
            raise RuntimeError(f"close-chunk-{fixture}-receipt-missing")
        expected_inputs="".join(f"{item['machine_tick']},{item['port']},{item['effective']}\n" for item in native["inputs"])
        if input_path.read_text()!=expected_inputs:
            raise RuntimeError(f"close-chunk-{fixture}-input-binding")
        receipt=json.loads(receipt_path.read_text());processes=receipt.get("processes",[])
        if (len(processes)!=1 or processes[0]!=row.get("process") or processes[0].get("return_code")!=0 or
                processes[0].get("process_group_cleanup")!="confirmed" or processes[0].get("bound_violation") is not False or
                processes[0].get("status")!="completed" or type(processes[0].get("pid")) is not int or
                processes[0]["pid"]<=0 or processes[0].get("pgid")!=processes[0]["pid"] or
                type(processes[0].get("wall_seconds")) not in (int,float) or
                not math.isfinite(processes[0]["wall_seconds"]) or not 0<=processes[0]["wall_seconds"]<=wall):
            raise RuntimeError(f"close-chunk-{fixture}-process")
        if receipt.get("streams",{}).get("stdout",{}).get("text")!=(child_report_path.read_text()):
            raise RuntimeError(f"close-chunk-{fixture}-stream-binding")
        if (child.get("schema")!="genewhip-phase6-title-chunk-v1" or child.get("status")!="pass" or
                child.get("fields")!=native["fields"] or child.get("events")!=len(native["inputs"]) or
                type(child.get("variable_calls")) is not int or not 0<child["variable_calls"]<=cap or
                child.get("pcm_frames")!=native.get("audio_frames")):
            raise RuntimeError(f"close-chunk-{fixture}-child-facts")
        for key in ("pcm","image"):
            ref=source.get("full_pcm" if key=="pcm" else "selected_media")
            path=(ROOT/ref.get("path","")).resolve()
            if (not path.is_relative_to(ROOT) or path.is_symlink() or not path.is_file() or
                    path.stat().st_size>(16*1024*1024 if key=="pcm" else 320*224*4) or sha(path)!=ref.get("sha256")):
                raise RuntimeError(f"close-chunk-{fixture}-{key}-source")
        if child.get("pcm_fnv1a64")!=_close_fnv((ROOT/source["full_pcm"]["path"]).resolve()):
            raise RuntimeError(f"close-chunk-{fixture}-pcm-hash")
        expected_core=json.loads((ROOT/"evidence/phase6-core-routes.json").read_text())
        core_run=next((run for run in expected_core["runs"] if run.get("fixture")==fixture and
            run.get("case")=="full-route" and run.get("repetition")==1),None)
        if core_run is None or child.get("media_sequence")!=core_run.get("field_sequence"):
            raise RuntimeError(f"close-chunk-{fixture}-media-sequence")
        image_path=(ROOT/source["selected_media"]["path"]).resolve()
        if child.get("media_fnv1a64")!=_close_fnv(image_path):
            raise RuntimeError(f"close-chunk-{fixture}-media-hash")
        if (not re.fullmatch(r"[0-9a-f]{16}",str(child.get("boundary_ram_fnv1a64"))) or
                not re.fullmatch(r"[0-9a-f]{16}",str(child.get("boundary_diagnostic_fnv1a64"))) or
                type(child.get("final_instructions")) is not int or child["final_instructions"]<=0):
            raise RuntimeError(f"close-chunk-{fixture}-boundary-fingerprints")
    return True


def _validate_close_safety_identity(report):
    if report.get("source_provenance")!={path:sha(ROOT/path) for path in SAFETY_SOURCE_PATHS}:
        raise RuntimeError("close-safety-source-identity")
    for row in report["variants"]:
        variant=row["variant"]
        directory=ROOT/("build/phase6" if variant=="native" else "build/phase6-"+variant)
        identity=row.get("build_identity",{})
        if identity.get("hooks_off")!=(variant=="hooks-off") or identity.get("sanitizers")!=(variant=="sanitize"):
            raise RuntimeError("close-safety-build-identity")
        for path,key in ((directory/"CMakeCache.txt","cache_sha256"),(directory/"phase6_safety","phase6_safety_sha256")):
            if path.is_symlink() or not path.is_file() or sha(path)!=identity.get(key):
                raise RuntimeError("close-safety-build-identity")
        binaries=identity.get("test_executables")
        expected_binaries={str((directory/("tools/session/" if name in
            {"session_contract","input_log_contract","phase6_chunk_contract"} else "")/name).relative_to(ROOT))
            for name in (*SAFETY_TESTS[:-1],"gw_bounded_fuzz")}
        if not isinstance(binaries,dict) or set(binaries)!=expected_binaries:
            raise RuntimeError("close-safety-test-executables")
        for relative,expected in binaries.items():
            path=ROOT/relative
            if not path.is_relative_to(directory) or path.is_symlink() or not path.is_file() or sha(path)!=expected:
                raise RuntimeError("close-safety-test-executables")
        _,raw=_close_artifact(row.get("api_contract"),"safety_api",str((directory/"evidence/phase6-safety-contract.json").relative_to(ROOT)))
        if (raw.get("mode")!=("production" if variant=="hooks-off" else "pr") or
                raw.get("cases")!=16 or raw.get("safety_pass")!=16 or raw.get("audio_pass")!=256 or
                raw.get("negative_controls")!=12 or raw.get("steps_per_case")!=8 or
                raw.get("tick_budget")!=180000 or raw.get("output_cap_frames")!=128 or
                raw.get("allocation_instrumented")!=(variant!="hooks-off") or
                any(raw.get(key)!=row.get(key) for key in ("steps","max_tick","guards_checked",
                    "allocation_count_peak","steady_allocations","returned_frames"))):
            raise RuntimeError("close-safety-api-facts")
    _,parser=_close_artifact(report.get("parser_rejection"),"safety_parser","build/phase6/evidence/controller.json")
    runs=parser.get("runs",[])
    if (parser.get("schema")!="genewhip-phase6-controller-contract-v1" or parser.get("status")!="pass" or
            parser.get("tests")!=1 or len(runs)!=42 or len({r.get("pid") for r in runs})!=42 or
            sorted(r.get("client","") for r in runs)!=["desktop"]*21+["headless"]*21 or
            any(r.get("status")!="completed" or r.get("return_code")!=1 or
                r.get("bound_violation") is not False or r.get("process_group_cleanup")!="confirmed" or
                type(r.get("pid")) is not int or r["pid"]<=0 or r.get("pgid")!=r["pid"] or
                type(r.get("wall_seconds")) not in (int,float) or not math.isfinite(r["wall_seconds"]) or
                not 0<=r["wall_seconds"]<=30 for r in runs)):
        raise RuntimeError("close-safety-parser-facts")


def _validate_close_core_processes(report):
    for row in report["runs"]:
        process=row["process"];wall=process.get("wall_seconds")
        cap=300 if row["fixture"]=="tank-battle" else 600
        if type(wall) not in (int,float) or not math.isfinite(wall) or not 0<=wall<=cap:
            raise RuntimeError("close-core-process-wall")
        if row["fixture"]=="genewhip-independent-game-v2":continue
        path=ROOT/row["native_report"]["path"];native=json.loads(path.read_text())
        if (process.get("report_schema")!=native.get("schema") or process.get("report_status")!=native.get("status") or
                process.get("report_bytes")!=path.stat().st_size):
            raise RuntimeError("close-core-process-native-binding")
        if "native_clock" in process and process["native_clock"]!={key:native[key] for key in ("active_ticks","fields","status","boundary_calls")}:
            raise RuntimeError("close-core-process-native-binding")


def validate_close_report(report,candidate):
    """Production conjunction consumer for the current Phase 6 raw proof."""
    if not isinstance(report,dict) or report.get("schema")!="genewhip-phase6-close-v1":
        raise RuntimeError("close-schema")
    if report.get("candidate_sha256")!=canonical_sha(candidate):raise RuntimeError("close-candidate")
    proofs=report.get("proofs")
    if not isinstance(proofs,dict):raise RuntimeError("close-proof-roster")
    expected={"core":"evidence/phase6-core-routes.json","media":"evidence/phase6-media.json",
        "host_software":"evidence/phase6-host-software-current.json","host_native":"evidence/phase6-host-native.json",
        "host_check":"evidence/phase6-host-check.json","safety":"evidence/phase6-safety.json",
        "chunk":"evidence/phase6-chunk.json","core_check":"build/phase6/evidence/phase6-core-check.json",
        "ci_local":"evidence/phase6-ci-local.json"}
    loaded={}
    for key,path in expected.items():
        if key not in proofs:raise RuntimeError(f"close-{key}-required")
        _,loaded[key]=_close_artifact(proofs[key],key,path)
    ci=loaded["ci_local"]
    if (ci.get("schema")!="genewhip-phase6-local-ci-v1" or ci.get("status")!="pass" or
            ci.get("candidate_sha256")!=canonical_sha(candidate) or ci.get("new_admitted_title_launches")!=0):
        raise RuntimeError("close-ci-local-status")
    if set(ci.get("checks",[]))!={"reader-metadata-refresh","three-variant-safety","core-32-semantic-controls",
            "phase6-media-ctest","phase6-route-self-test","current-host-22-controls-offline"}:
        raise RuntimeError("close-ci-local-check-roster")
    ci_proofs=ci.get("proofs",{})
    for key,path in (("reader_refresh","build/phase6/evidence/phase6-reader-refresh.json"),
            ("safety","evidence/phase6-safety.json"),
            ("core_check","build/phase6/evidence/phase6-core-check.json"),
            ("host_check_offline","build/phase6/evidence/phase6-host-check-offline.json")):
        if key not in ci_proofs:raise RuntimeError("close-ci-local-proofs")
        _,ci_proof=_close_artifact(ci_proofs[key],"ci_local",path)
        if key=="reader_refresh" and (ci_proof.get("schema")!="genewhip-phase6-reader-refresh-v1" or
                ci_proof.get("status")!="pass" or ci_proof.get("candidate_sha256")!=canonical_sha(candidate)):
            raise RuntimeError("close-ci-reader-refresh")
        if key=="host_check_offline":
            fault=next((item for item in ci_proof.get("mutations",[])
                if item.get("id")=="real-sdl-virtual-handler-suppression"),None)
            if (ci_proof.get("schema")!="genewhip-phase6-host-check-v1" or ci_proof.get("outcome")!="pass" or
                    ci_proof.get("new_admitted_title_launches")!=0 or
                    ci_proof.get("launch_accounting")!={"admitted_rom_negative":1,"canonical_qualification":0,
                        "new_launches":0,"reused_historical_fault":1} or len(ci_proof.get("mutations",[]))!=22 or
                    any(item.get("rejected") is not True or item.get("expected_reason")!=item.get("actual_reason")
                        for item in ci_proof["mutations"]) or not isinstance(fault,dict) or
                    fault.get("reused_retained_fault") is not True):
                raise RuntimeError("close-ci-host-offline")
            raw=fault.get("raw_outputs",{})
            for label in ("host","native"):
                ref=raw.get(label,{});raw_path=ROOT/ref.get("path","");path=raw_path.resolve()
                if (not path.is_relative_to(ROOT/"build/phase6/evidence") or raw_path.is_symlink() or
                        not path.is_file() or sha(path)!=ref.get("sha256")):
                    raise RuntimeError("close-ci-host-fault-identity")
                raw[label]=json.loads(path.read_text())
            try:compiler.validate_host_input_observations(raw["host"],raw["native"])
            except compiler.Invalid as error:
                if str(error)!="host-input":raise RuntimeError("close-ci-host-fault-reason") from error
            else:raise RuntimeError("close-ci-host-fault-accepted")
    compiler.validate_product_report(loaded["core"],candidate)
    compiler.validate_media_report(loaded["media"],candidate)
    compiler.validate_host_report(loaded["host_software"],candidate)
    compiler.validate_host_report(loaded["host_native"],candidate)
    safety_module_path=ROOT/"tests/api/safety_contract.py"
    spec=importlib.util.spec_from_file_location("phase6_safety_contract_close",safety_module_path)
    if spec is None or spec.loader is None:raise RuntimeError("close-safety-validator")
    safety_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(safety_module)
    safety_reason=safety_module.validate_phase6_safety_report(loaded["safety"])
    if safety_reason is not None or loaded["safety"].get("candidate_sha256")!=canonical_sha(candidate):
        raise RuntimeError("close-safety-proof")
    _validate_close_safety_identity(loaded["safety"])
    _validate_close_core_processes(loaded["core"])
    if loaded["core_check"].get("schema")!="genewhip-phase6-core-check-v1" or loaded["core_check"].get("status")!="pass":
        raise RuntimeError("close-core-check-status")
    core_mutants=loaded["core_check"].get("negative_controls")
    if (not isinstance(core_mutants,list) or len(core_mutants)!=32 or
            any(item.get("status")!="pass" or item.get("reason") in (None,"") for item in core_mutants)):
        raise RuntimeError("close-core-check-mutants")
    if loaded["core_check"].get("candidate_sha256")!=canonical_sha(candidate):
        raise RuntimeError("close-core-check-candidate")
    host_check=loaded["host_check"]
    if (host_check.get("schema")!="genewhip-phase6-host-check-v1" or host_check.get("outcome")!="pass" or
            host_check.get("production_consumer")!="scripts/evidence/phase6_routes.py::validate_host_report" or
            host_check.get("canonical_qualification_launches")!=0 or host_check.get("admitted_title_launches")!=1 or
            host_check.get("launch_accounting")!={"admitted_rom_negative":1,"canonical_qualification":0}):
        raise RuntimeError("close-host-check-accounting")
    host_mutants=host_check.get("mutations")
    if (not isinstance(host_mutants,list) or len(host_mutants)!=22 or
            any(row.get("rejected") is not True or row.get("actual_reason")!=row.get("expected_reason") for row in host_mutants)):
        raise RuntimeError("close-host-check-mutants")
    _validate_close_chunk(loaded["chunk"],candidate)
    requirements=report.get("requirements")
    ids={row.get("id") for row in requirements if isinstance(row,dict)} if isinstance(requirements,list) else set()
    if ids!={"PLAY-02","HOST-04","SAFE-02"} or any(row.get("evidence_status")!="pass" or
        row.get("phase_status")!="pending-independent-review" for row in requirements):
        raise RuntimeError("close-requirement-conjunction")
    reviews=report.get("reviews")
    if not isinstance(reviews,list) or not any(row.get("id")=="independent-phase-verifier" and row.get("status")=="pending" for row in reviews):
        raise RuntimeError("close-review-state")
    if report.get("status")!="pending-independent-review":raise RuntimeError("close-premature-completion")
    return True


def close(build,candidate_path,output,negative_controls):
    """Validate current evidence; leave phase completion to the independent reviewer."""
    started=time.monotonic()
    candidate=json.loads(candidate_path.read_text());candidate_sha=canonical_sha(candidate)
    proof_paths={"core":"evidence/phase6-core-routes.json","media":"evidence/phase6-media.json",
        "host_software":"evidence/phase6-host-software-current.json","host_native":"evidence/phase6-host-native.json",
        "host_check":"evidence/phase6-host-check.json","safety":"evidence/phase6-safety.json",
        "chunk":"evidence/phase6-chunk.json","core_check":"build/phase6/evidence/phase6-core-check.json",
        "ci_local":"evidence/phase6-ci-local.json"}
    proofs={key:artifact(ROOT/path) for key,path in proof_paths.items()}
    requirement_rows=[{"id":name,"evidence_status":"pass","phase_status":"pending-independent-review",
        "reason":"raw production consumers pass; independent full-phase verification remains outstanding"}
        for name in ("PLAY-02","HOST-04","SAFE-02")]
    review_rows=[{"id":"reader-acceptance-06-52","status":"accepted","source":"06-52-READER-ACCEPTANCE.md"},
        {"id":"media-review-06-51","status":"accepted","source":"06-51-MEDIA-REVIEW.md"},
        {"id":"independent-phase-verifier","status":"pending","reason":"parent full-phase review required before any requirement completion"},
        {"id":"independent-security-review","status":"pending","reason":"final threat/guard review remains part of parent verification"}]
    report={"schema":"genewhip-phase6-close-v1","candidate_sha256":candidate_sha,"status":"pending-independent-review",
        "proofs":proofs,"requirements":requirement_rows,"reviews":review_rows,
        "unknowns":["24/120 canonical contextual completion cells remain unknown from the core report",
            "physical display/acoustic quality, broad accuracy, and unmeasured platforms remain unknown"],
        "failed_attempt_history":[artifact(path) for path in sorted((build.resolve()/"evidence").glob("phase6-chunk-*/process.json"))],
        "claims":{"core_routes":"production product report validated; original unknowns preserved",
            "host":"current software and native reports validated; native capability passed",
            "safety":"three variants and bounded fuzz validated",
            "chunk":"two actual variable-chunk routes match retained full PCM and selected full frame by FNV-1a64",
            "ram_diagnostics":"independent instances compare full RAM and CPU state at each field and final boundary; complete instruction-event sequence compared in bounded diagnostic windows"}}
    validate_close_report(report,candidate)
    if negative_controls:
        mutants=[]
        for key,expected in (("core","close-core-required"),("media","close-media-required"),
            ("host_software","close-host_software-required"),("host_native","close-host_native-required"),
            ("host_check","close-host_check-required"),("safety","close-safety-required"),
            ("chunk","close-chunk-required"),("core_check","close-core_check-required"),
            ("ci_local","close-ci_local-required")):
            altered=json.loads(json.dumps(report));altered["proofs"].pop(key)
            try:validate_close_report(altered,candidate)
            except RuntimeError as error:
                if str(error)!=expected:raise RuntimeError(f"close-mutant-{key}:{error}")
                mutants.append({"name":"missing-"+key,"expected_reason":expected,"actual_reason":str(error),"rejected":True})
            else:raise RuntimeError(f"close-mutant-accepted:{key}")
        for name,mutate,expected in (
            ("core-digest",lambda r:r["proofs"]["core"].update(sha256="0"*64),"close-core-artifact"),
            ("requirement-loss",lambda r:r["requirements"].pop(),"close-requirement-conjunction"),
            ("premature-completion",lambda r:r.update(status="complete"),"close-premature-completion")):
            altered=json.loads(json.dumps(report));mutate(altered)
            # Mutations to report refs are recomputed only when the intended
            # semantic consumer owns the outer identity; evidence bytes stay immutable.
            try:validate_close_report(altered,candidate)
            except RuntimeError as error:
                if str(error)!=expected:raise RuntimeError(f"close-mutant-{name}:{error}")
                mutants.append({"name":name,"expected_reason":expected,"actual_reason":str(error),"rejected":True})
            else:raise RuntimeError(f"close-mutant-accepted:{name}")
        mutant_root=build.resolve()/"evidence/phase6-close-mutants"
        mutant_root.mkdir(parents=True,exist_ok=True)
        def artifact_mutant(name,key,mutate,expected):
            original_path=(ROOT/proofs[key]["path"]).resolve()
            altered=json.loads(original_path.read_text())
            mutate(altered)
            path=mutant_root/f"{key}-{name}.json";write_json(path,altered)
            mutant_report=json.loads(json.dumps(report));mutant_report["proofs"][key]=artifact(path)
            try:validate_close_report(mutant_report,candidate)
            except Exception as error:
                actual=str(error)
                if actual!=expected:raise RuntimeError(f"close-mutant-{name}:{actual}") from error
                mutants.append({"name":name,"expected_reason":expected,"actual_reason":actual,"rejected":True})
            else:raise RuntimeError(f"close-mutant-accepted:{name}")
        artifact_mutant("missing-core-mutant","core_check",lambda r:r.update(negative_controls=[]),"close-core-check-mutants")
        def core_process_mutant(core_report,key,value):
            row=next(row for row in core_report["runs"] if row["fixture"]=="recursion94")
            receipt=json.loads((ROOT/row["process_receipt"]["path"]).read_text())
            row["process"][key]=value
            next(item for item in core_report["processes"] if item["pid"]==row["process"]["pid"])[key]=value
            receipt["processes"]=[row["process"]]
            path=mutant_root/("core-process-"+key+".json");write_json(path,receipt)
            row["process_receipt"]=artifact(path)
        artifact_mutant("core-wall-cap","core",lambda r:core_process_mutant(r,"wall_seconds",601),
            "close-core-process-wall")
        artifact_mutant("core-report-byte-binding","core",lambda r:core_process_mutant(r,"report_bytes",1),
            "close-core-process-native-binding")
        artifact_mutant("missing-media-capture","media",lambda r:r["captures"].pop(),"media-roster")
        artifact_mutant("missing-host-case","host_software",lambda r:r["runs"].pop(),"host-roster")
        artifact_mutant("native-capability-skip","host_native",lambda r:r.update(status="blocked-capability"),"host-native-capability")
        artifact_mutant("missing-safety-variant","safety",lambda r:r.update(variants=r["variants"][:2]),"close-safety-proof")
        artifact_mutant("stale-safety-source","safety",lambda r:r["source_provenance"].update({SAFETY_SOURCE_PATHS[0]:"0"*64}),
            "close-safety-source-identity")
        artifact_mutant("stale-safety-build","safety",lambda r:r["variants"][0]["build_identity"].update(cache_sha256="0"*64),
            "close-safety-build-identity")
        artifact_mutant("stale-safety-api-artifact","safety",lambda r:r["variants"][0]["api_contract"].update(sha256="0"*64),
            "close-safety_api-artifact")
        artifact_mutant("chunk-route-loss","chunk",lambda r:r.update(routes=r["routes"][:1]),"close-chunk-roster")
        artifact_mutant("chunk-test-identity","chunk",lambda r:r["test_source"].update(sha256="0"*64),
            "close-chunk-test-identity")
        def missing_pair_comparison(chunk_report):
            route=next(row for row in chunk_report["routes"] if row["fixture"]=="recursion94")
            child=json.loads((ROOT/route["chunk_report"]["path"]).read_text())
            child.pop("common_boundary_comparisons")
            child_path=mutant_root/"recursion94-missing-boundary-comparison.json"
            write_json(child_path,child)
            route["chunk_report"]=artifact(child_path)
        artifact_mutant("chunk-missing-pair-comparison","chunk",missing_pair_comparison,
            "close-chunk-recursion94-pair-comparison")
        artifact_mutant("ci-false-pass","ci_local",lambda r:r.update(status="fail"),"close-ci-local-status")
        artifact_mutant("host-fault-accounting","host_check",lambda r:r.update(admitted_title_launches=0),
            "close-host-check-accounting")
        for requirement in ("PLAY-02","HOST-04","SAFE-02"):
            altered=json.loads(json.dumps(report))
            next(row for row in altered["requirements"] if row["id"]==requirement)["phase_status"]="complete"
            try:validate_close_report(altered,candidate)
            except RuntimeError as error:
                if str(error)!="close-requirement-conjunction":raise
                mutants.append({"name":"false-"+requirement,"expected_reason":str(error),
                    "actual_reason":str(error),"rejected":True})
            else:raise RuntimeError(f"close-mutant-accepted:{requirement}")
        report["negative_controls"]={"denominator":len(mutants),"pass":len(mutants),"fail":0,"mutants":mutants}
        validate_close_report(report,candidate)
    if report.get("negative_controls") is not None:
        negative=report["negative_controls"]
        if (negative.get("fail")!=0 or negative.get("pass")!=negative.get("denominator") or
                any(item.get("rejected") is not True for item in negative.get("mutants",[]))):
            raise RuntimeError("close-negative-controls")
    if negative_controls:
        window=_read_window()
        rel=str((build.resolve()/"evidence/phase6-close-mutants").relative_to(ROOT))
        if rel not in window["owned_artifact_roots"]:window["owned_artifact_roots"].append(rel)
        window["retained_artifact_bytes"]=sum(tree_bytes(ROOT/path) for path in window["owned_artifact_roots"])
        _write_window(window)
    elapsed=time.monotonic()-started
    _setup_charge("phase6-close-conjunction",elapsed,sys.argv)
    write_json(output,report)
    return 0


def refresh_readers(build,output):
    result=refresh_reader_bound_proofs(build.resolve(strict=True))
    write_json(output,{"schema":"genewhip-phase6-reader-refresh-v1","status":"pass",**result})
    return 0


def validate_frozen_runtime(build,map_path,candidate):
    readers=set(READER_PROVENANCE_PATHS)|{"fixtures/phase6/media-expectations-v1.json"}
    sources=candidate.get("source_files",{})
    if candidate.get("compiler_identity")!={"path":"scripts/evidence/phase6_routes.py",
            "sha256":sources.get("scripts/evidence/phase6_routes.py")}:
        raise RuntimeError("resume frozen compiler identity does not bind captured source manifest")
    for relative,expected in sources.items():
        if relative in readers:continue
        path=(ROOT/relative).resolve()
        if not path.is_relative_to(ROOT) or not path.is_file() or sha(path)!=expected:
            raise RuntimeError(f"resume native runtime source changed: {relative}")
    if sha(build/"tools/session/gw_headless")!=candidate["client_identities"]["public-core"]["sha256"]:
        raise RuntimeError("resume native executable changed")
    if sha(build/"CMakeCache.txt")!=candidate["build_identity"]["cmake_cache_sha256"]:
        raise RuntimeError("resume build configuration changed")
    if (str(map_path.relative_to(ROOT))!=candidate["delivery_map_identity"]["path"] or
            canonical_sha(json.loads(map_path.read_text()))!=candidate["delivery_map_identity"]["sha256"]):
        raise RuntimeError("resume delivery map changed")


def validate_existing_route_row(row,route,batch,mapping,candidate,binary):
    """Recheck a previously collected source-game row before resume skips it."""
    receipt_ref=row.get("process_receipt",{}); receipt_path=(ROOT/receipt_ref.get("path","")).resolve()
    if not receipt_path.is_relative_to(batch.resolve()) or not receipt_path.is_file() or sha(receipt_path)!=receipt_ref.get("sha256"):
        raise RuntimeError("resume existing row process receipt is not batch-owned/current")
    receipt=json.loads(receipt_path.read_text());processes=receipt.get("processes",[])
    if not processes or processes[-1]!=row.get("process"):
        raise RuntimeError("resume existing row process receipt mismatch")
    native_ref=row.get("native_report",{});native_path=(ROOT/native_ref.get("path","")).resolve()
    if not native_path.is_relative_to(batch.resolve()) or not native_path.is_file() or sha(native_path)!=native_ref.get("sha256"):
        raise RuntimeError("resume existing row native report is not batch-owned/current")
    rec=route["fixture"]=="recursion94";cap=100_000_000 if rec else 10_000_000
    native=json.loads(native_path.read_text())
    if (row.get("compiled_sha256")!=hashlib.sha256(binary).hexdigest() or
            (receipt_path.parent/"route.gwrc").read_bytes()!=binary):
        raise RuntimeError("resume existing row compiled identity changed")
    compiler._validate_native_facts(route,"sustained",row,mapping if rec else None,cap)
    pcm=compiler._media_artifact(row.get("pcm",{}),16*1024*1024,"resume-existing-pcm")
    image=compiler._media_artifact(row.get("image",{}),320*224*4,"resume-existing-image")
    if len(pcm)!=native.get("audio_frames",-1)*4 or len(image)!=320*224*4:
        raise RuntimeError("resume existing row raw output size mismatch")
    return True


def preflight_compiled_roster(routes,mapping):
    """Compile every admitted route and check case omissions before any child."""
    source=json.loads((ROOT/"fixtures/phase5-b/scenario.json").read_text())
    scenario_cases=[case["id"] for case in source.get("cases",[]) if isinstance(case,dict) and isinstance(case.get("id"),str)]
    rec_routes=[r for r in routes if r["fixture"]=="recursion94"]
    if [r["case"]["id"] for r in rec_routes]!=scenario_cases:
        raise RuntimeError("REC admitted route roster differs from original source scenario")
    input_program=json.loads((ROOT/"fixtures/phase5-b/input-program.json").read_text())
    map_by_order={row["order"]:row for row in mapping["events"]}
    widths=(4,2,5,2,4,3,6,4)
    compiled={}
    for route in routes:
        is_rec=route["fixture"]=="recursion94"
        limit=100_000_000 if is_rec else 10_000_000
        binary,_=compiler.lower_route(route,limit,mapping if is_rec else None)
        if is_rec:
            words=struct.unpack("<"+"I"*(len(binary)//4),binary)
            counts=words[6:14]
            expected=[(index,event) for index,event in enumerate(input_program["events"],1)
                      if route["case"]["id"] in event.get("cases",[])]
            if counts[6]!=len(expected):
                raise RuntimeError(f"REC {route['case']['id']} compiled event denominator differs from source applicability")
            offset=32
            event_records=[]
            for index,(count,width) in enumerate(zip(counts,widths)):
                if index==6:
                    event_records=[tuple(words[offset+n*width:offset+(n+1)*width]) for n in range(count)]
                offset+=count*width
            for order,event in enumerate(input_program["events"],1):
                if route["case"]["id"] in event.get("cases",[]):continue
                mapped=map_by_order[order]
                schedule=mapped["scheduled_client_point"]["public-core"]
                dispatch=schedule.get("tick",event["tick"])
                port,mask=compiler.control(event["control"])
                omitted=(event["attempt"],dispatch,input_program["state_values"][event["state"]],
                         port,mask,int(event["asserted"]))
                if omitted in event_records:
                    raise RuntimeError(f"REC {route['case']['id']} compiled source-withheld event {order}")
        compiled[(route["fixture"],route["case"]["id"])]=binary
    return compiled


def core(build,map_path,candidate_path,output,resume_batch=None):
    build=build.resolve(strict=True);map_path=map_path.resolve(strict=True)
    mapping=json.loads(map_path.read_text());compiler.validate_delivery_map(mapping)
    routes=compiler.compile_routes()["routes"]
    compiled_plans=preflight_compiled_roster(routes,mapping)
    if resume_batch is None:
        # Freeze original source/case expectations before any canonical child.
        candidate=freeze_candidate(build,map_path,candidate_path)
        freeze_build_provenance(candidate,build)
        batch_root=(ROOT/"build/v02/runtime/core-work") if _EXECUTION_SCOPE is not None else build/"evidence"
        batch_root.mkdir(parents=True,exist_ok=True)
        batch=pathlib.Path(tempfile.mkdtemp(prefix="canonical-core-",dir=batch_root))
        write_json(batch/"candidate.json",candidate)
        report={"schema":"genewhip-phase6-product-report-v1","candidate_sha256":canonical_sha(candidate),
            "candidate_manifest":artifact(batch/"candidate.json"),"reader_provenance":reader_provenance(),
            "roster":[{"fixture":r["fixture"],"case":r["case"],"identity":r["identity"]} for r in routes],
            "runs":[],"stages":[],"controls":[],"media_captures":[],"media":{},"processes":[],
            "resources":{},"outcomes":{"status":"partial","reason":"canonical batch in progress"}}
        if output.exists():
            if output.is_symlink() or not output.is_file() or output.stat().st_nlink!=1:
                raise RuntimeError("existing report path is not a safe regular file")
            shutil.copyfile(output,batch/"previous-report-before-new-batch.json")
    else:
        batch=pathlib.Path(resume_batch).resolve(strict=True)
        if not batch.is_relative_to((build/"evidence").resolve(strict=True)):
            raise RuntimeError("resume batch must be within this build's evidence directory")
        candidate_path_in_batch=batch/"candidate.json"
        candidate=json.loads(candidate_path_in_batch.read_text())
        external=json.loads(candidate_path.resolve(strict=True).read_text())
        if canonical_sha(external)!=canonical_sha(candidate):
            raise RuntimeError("resume candidate does not match immutable canonical launch identity")
        validate_frozen_runtime(build,map_path,candidate)
        if output.is_symlink() or not output.is_file():raise RuntimeError("resume failed report missing or unsafe")
        failure_copy=batch/("failed-report-"+sha(output)[:16]+".json")
        if failure_copy.exists():
            if failure_copy.is_symlink() or sha(failure_copy)!=sha(output):
                raise RuntimeError("resume failed-report history collision")
        else:shutil.copyfile(output,failure_copy)
        report=json.loads(output.read_text())
        if (report.get("candidate_sha256")!=canonical_sha(candidate) or
                report.get("candidate_manifest")!=artifact(candidate_path_in_batch) or
                report.get("outcomes",{}).get("status")!="fail"):
            raise RuntimeError("resume report does not match this retained failed candidate/report")
        report["reader_provenance"]=reader_provenance()
        report["validation_identities"]=validation_identities()
        for row in report.get("runs",[]):
            route=next((r for r in routes if r["fixture"]==row.get("fixture") and r["case"]["id"]==row.get("case")),None)
            if route is None or row.get("fixture")=="genewhip-independent-game-v2":
                raise RuntimeError("resume only accepts independently revalidated source-game rows")
            validate_existing_route_row(row,route,batch,mapping,candidate,
                compiled_plans[(route["fixture"],route["case"]["id"])])
        key=("recursion94","full-route",1)
        if not any((r.get("fixture"),r.get("case"),r.get("repetition"))==key for r in report["runs"]):
            first_work=batch/"recursion94-full-route-1"
            if (first_work/"run.json").is_file() and (first_work/"process.json").is_file():
                recovered=recover_completed_case(build,next(r for r in routes if (r["fixture"],r["case"]["id"])==key[:2]),
                    mapping,candidate,first_work,1,compiled_plans[key[:2]])
                report["runs"].append(recovered);report["processes"].append(recovered["process"])
                capture={k:recovered[k] for k in ("fixture","case","field","field_sequence","attempt","source_tick","completed_fields","image","scene_metadata","audio_trace","native_report")}
                capture["audio"]={**recovered["pcm"],"sample_rate_hz":48000,"encoding":"s16le-stereo"}
                expectations=json.loads((ROOT/"fixtures/phase6/media-expectations-v1.json").read_text())
                source=next(x for x in expectations["captures"] if x["fixture"]==recovered["fixture"])
                scene=json.loads((ROOT/recovered["scene_metadata"]["path"]).read_text())
                compiler._validate_media_image(recovered["fixture"],capture,source,scene,
                    (ROOT/recovered["image"]["path"]).read_bytes())
                capture["audio_features"]=compiler.validate_source_audio(recovered["fixture"],capture,
                    (ROOT/recovered["pcm"]["path"]).read_bytes(),expectations)
                report["media_captures"].append(capture)
    if resume_batch is not None:
        report["media_captures"]=[]
        expectations=json.loads((ROOT/"fixtures/phase6/media-expectations-v1.json").read_text())
        for existing in report["runs"]:
            if existing.get("case")!="full-route" or existing.get("repetition")!=1:continue
            capture={k:existing[k] for k in ("fixture","case","field","field_sequence","attempt","source_tick","completed_fields","image","scene_metadata","audio_trace","native_report")}
            capture["audio"]={**existing["pcm"],"sample_rate_hz":48000,"encoding":"s16le-stereo"}
            source=next(x for x in expectations["captures"] if x["fixture"]==existing["fixture"])
            scene=json.loads((ROOT/existing["scene_metadata"]["path"]).read_text())
            compiler._validate_media_image(existing["fixture"],capture,source,scene,(ROOT/existing["image"]["path"]).read_bytes())
            capture["audio_features"]=compiler.validate_source_audio(existing["fixture"],capture,(ROOT/existing["pcm"]["path"]).read_bytes(),expectations)
            report["media_captures"].append(capture)
    state=_read_window();cutoff=datetime.datetime.fromisoformat(state["workload_cutoff"])
    roots=state.setdefault("owned_artifact_roots",[])
    for path in [batch,*(build/"evidence").glob("phase6-sdl-*"),*(build/"evidence").glob("authored-capture-*"),build/"evidence/phase6-tracer-work"]:
        relative=str(path.relative_to(ROOT))
        if path.is_dir() and relative not in roots:roots.append(relative)
    _write_window(state)
    remaining=(cutoff-datetime.datetime.now(datetime.timezone.utc)).total_seconds()
    if resume_batch is None:
        batch_seconds=min(6600,remaining-5,14400-state.get("workload_wall_upper_bound_seconds",state["workload_wall_seconds"])-5)
        if batch_seconds<600:raise RuntimeError("canonical batch lacks protected workload headroom")
        report["resources"]={"batch_maximum_seconds":batch_seconds,"shared_window_start":state["started_at"],"shared_window_deadline":state["deadline"]}
    else:
        batch_seconds=min(report.get("resources",{}).get("batch_maximum_seconds",0),remaining-5,
            14400-state.get("workload_wall_upper_bound_seconds",state["workload_wall_seconds"])-5)
        if batch_seconds<30:raise RuntimeError("resume batch has no measured shared-window headroom")
        report["resources"]["resume_seconds_available"]=batch_seconds
    deadline=time.monotonic()+batch_seconds
    def persist():
        report["stages"]=contextual_stages(routes,report["runs"])
        report["resources"]["current_shared_resources"]=_read_window()
        report["reader_provenance"]=reader_provenance()
        report["validation_identities"]=validation_identities()
        write_json(output,report)
    persist()
    try:
        games=sorted((r for r in routes if r["fixture"]!="genewhip-independent-game-v2"),key=lambda r:(r["fixture"]!="recursion94",r["case"]["id"]!="full-route",r["case"]["id"]))
        completed={(r["fixture"],r["case"],r["repetition"]) for r in report["runs"]}
        for rep in (1,2):
            for route in games:
                if (route["fixture"],route["case"]["id"],rep) in completed:continue
                if time.monotonic()+30>deadline:raise RuntimeError("canonical aggregate deadline exhausted")
                row=collect_case(build,route,mapping,candidate,batch/f"{route['fixture']}-{route['case']['id']}-{rep}",rep,
                    deadline-time.monotonic()-5,compiled_plans[(route["fixture"],route["case"]["id"])])
                report["runs"].append(row);report["processes"].append(row["process"]);persist()
                if rep==1 and route["case"]["id"]=="full-route":
                    capture={k:row[k] for k in ("fixture","case","field","field_sequence","attempt","source_tick","completed_fields","image","scene_metadata","audio_trace","native_report")}
                    capture["audio"]={**row["pcm"],"sample_rate_hz":48000,"encoding":"s16le-stereo"}
                    source=next(x for x in json.loads((ROOT/"fixtures/phase6/media-expectations-v1.json").read_text())["captures"] if x["fixture"]==route["fixture"])
                    scene=json.loads((ROOT/row["scene_metadata"]["path"]).read_text())
                    expectations=json.loads((ROOT/"fixtures/phase6/media-expectations-v1.json").read_text())
                    compiler._validate_media_image(route["fixture"],capture,source,scene,(ROOT/row["image"]["path"]).read_bytes())
                    capture["audio_features"]=compiler.validate_source_audio(route["fixture"],capture,(ROOT/row["pcm"]["path"]).read_bytes(),expectations)
                    report["media_captures"].append(capture);persist()
        for rep in (1,2):
            if time.monotonic()+30>deadline:raise RuntimeError("canonical aggregate deadline exhausted")
            work=batch/f"controls-{rep}";work.mkdir();retained=work/"artifacts";retained.mkdir();control_path=work/"control.json"
            command=[sys.executable,"-I",str(ROOT/"tests/fixtures/phase4_game.py"),str(build/"tools/session/gw_headless"),
                "--outer-process-group","--report",str(control_path),"--retain-artifacts",str(retained)]
            if _EXECUTION_SCOPE is not None:
                scope_path=_EXECUTION_SCOPE.get("_scope_path")
                if not isinstance(scope_path,str):raise RuntimeError("phase7-control-scope-path-missing")
                command.extend(["--execution-scope",scope_path,
                    "--process-receipt",str(work/"nested-processes.json")])
            result,process,streams=shared_launch(build/"tools/session/gw_headless",command,work,control_path,min(600,deadline-time.monotonic()-5))
            if result.returncode or process.get("bound_violation"):raise RuntimeError("original control driver failed")
            control=json.loads(control_path.read_text());report["controls"].append(artifact(control_path))
            for item in control["results"]:
                route=next(r for r in routes if r["fixture"]=="genewhip-independent-game-v2" and r["case"]["id"]==item["id"])
                report["runs"].append({"fixture":route["fixture"],"case":item["id"],"repetition":rep,"identity":route["identity"],
                    "status":item["outcome"],"process":process,"process_receipt":artifact(work/"process.json"),"control_report":artifact(control_path),"pcm":item["retained_pcm"]})
            report["processes"].append(process);persist()
        report["outcomes"]={"status":"pass","reason":None};persist()
        compiler.validate_product_report(report,candidate)
        media_output=(ROOT/"build/v02/runtime/media-report.json") if _EXECUTION_SCOPE is not None else ROOT/"evidence/phase6-media.json"
        media(build,candidate_path,media_output)
        return 0
    except BaseException as error:
        report["outcomes"]={"status":"fail","reason":f"{type(error).__name__}: {error}"};persist()
        raise


def core_contract(build,candidate_path,output,report_path=None,media_path=None):
    """Offline actual-consumer mutants; no clients, no test-only validator."""
    path=report_path or ROOT/"evidence/phase6-core-routes.json"
    media_path=media_path or ROOT/"evidence/phase6-media.json"
    if not path.is_file():
        write_json(output,{"schema":"genewhip-phase6-core-check-v1","status":"skipped","reason":"no canonical report; source feature checks are a separate test"})
        return 77
    report=json.loads(path.read_text());candidate=json.loads(candidate_path.read_text())
    compiler.validate_product_report(report,candidate)
    checks=[]
    directory=pathlib.Path(tempfile.mkdtemp(prefix="semantic-mutants-",dir=build.resolve()/"evidence"))
    def check(name,mutate,expected,base=report,manifest=candidate,validator=compiler.validate_product_report):
        altered=json.loads(json.dumps(base));selected=json.loads(json.dumps(manifest))
        mutate(altered,selected)
        # Candidate mutations need a matching retained manifest artifact so
        # they exercise the intended downstream identity check, not the
        # earlier candidate-manifest binding.
        if canonical_sha(selected)!=canonical_sha(manifest):
            candidate_file=directory/(name+"-candidate.json");write_json(candidate_file,selected)
            altered["candidate_manifest"]=artifact(candidate_file)
        try:validator(altered,selected)
        except compiler.Invalid as error:
            if str(error)!=expected:raise AssertionError(f"{name}: expected {expected}, got {error}")
            checks.append({"name":name,"reason":str(error),"status":"pass"})
        else:raise AssertionError(f"{name}: semantic mutant accepted")
    for name,mutate,expected in (
        ("missing-case",lambda r,c:r["runs"].pop(),"product-run-count"),
        ("duplicate-repetition",lambda r,c:r["runs"].__setitem__(1,r["runs"][0]),"product-duplicate-run"),
        ("copied-title-repetition",lambda r,c:_copy_repetition(r,"recursion94","full-route"),"product-repeat-execution"),
        ("copied-control-repetition",lambda r,c:_copy_control_repetition(r),"product-control-binding"),
        ("duplicate-control-report",lambda r,c:r["controls"].__setitem__(1,r["controls"][0]),"product-control-repetitions"),
        ("wrong-fixture-identity",lambda r,c:r["runs"][0]["identity"].update(rom_sha256="0"*64),"product-run-identity"),
        ("missing-stage",lambda r,c:r["stages"].pop(),"product-stage-count"),
        ("false-completion",lambda r,c:next(x for x in r["stages"] if x["stage"]=="completion").update(status="pass",reached=True),"product-invented-completion"),
        ("false-start-exit",lambda r,c:r["runs"][0]["process"].update(return_code=1),"product-process"),
        ("unconfirmed-reap",lambda r,c:r["runs"][0]["process"].update(process_group_cleanup="unconfirmed"),"product-process"),
        ("wrong-compiled-controller",lambda r,c:r["runs"][0].update(compiled_sha256="0"*64),"product-compiled"),
        ("wrong-field-stream-digest",lambda r,c:next(x for x in r["runs"] if x["fixture"]!="genewhip-independent-game-v2").update(field_hashes_sha256="0"*64),"product-field-stream-binding"),
        ("wrong-map-client",lambda r,c:r["runs"][0].update(delivery_map_sha256="0"*64),"product-run-map-client"),
        ("wrong-causal-expectation",lambda r,c:next(x for x in r["runs"] if x["fixture"]=="recursion94" and x["case"]=="withhold-final-b")["predicate_results"]["late_program_stable"].update(reached=True),"native-causal-control-unproven"),
        ("stale-reader-provenance",lambda r,c:r["validation_identities"]["reader_provenance"].update({"tests/fixtures/phase6_game.py":"0"*64}),"product-validation-identities"),
        ("stale-media-validation-identity",lambda r,c:r["validation_identities"].update(media_expectations_sha256="0"*64),"product-validation-identities"),
    ):check(name,mutate,expected)
    for field,expected in (("source_files","product-stale-source"),("client_identities","product-stale-client"),("build_identity","product-stale-build"),("delivery_map_identity","product-map"),("compiler_identity","product-compiler"),("configuration_identity","product-configuration")):
        def mutate(r,c,field=field):
            if field=="source_files":c[field][next(iter(c[field]))]="0"*64
            elif field=="client_identities":c[field]["public-core"]["sha256"]="0"*64
            elif field=="build_identity":c[field]["cmake_cache_sha256"]="0"*64
            elif field=="configuration_identity":c[field]["audio_rate_hz"]=0
            else:c[field]["sha256"]="0"*64
            r["candidate_sha256"]=canonical_sha(c)
        check("recomputed-"+field,mutate,expected)
    def raw_mutant(name,change,expected):
        altered=json.loads(json.dumps(report));row=next(x for x in altered["runs"] if x["fixture"]=="recursion94" and x["case"]=="full-route")
        native=json.loads((ROOT/row["native_report"]["path"]).read_text());change(native)
        raw_path=directory/(name+".json");write_json(raw_path,native);row["native_report"]=artifact(raw_path)
        check(name,lambda r,c:r.update(altered),expected)
    raw_mutant("3599-source-steps",lambda r:(r["samples"].pop(),r.update(active_ticks=3599)),"native-incomplete-observation")
    raw_mutant("oversized-work",lambda r:r.update(boundary_calls=100_000_001),"product-work-cap")
    raw_mutant("oversized-field-count",lambda r:r.update(fields=7201),"product-work-cap")
    media_report=json.loads(media_path.read_text());compiler.validate_media_report(media_report,candidate)
    check("missing-media-row",lambda r,c:r["captures"].pop(),"media-roster",media_report,validator=compiler.validate_media_report)
    check("stale-media-expectation",lambda r,c:r.update(media_expectations_sha256="0"*64),"media-expectations-identity",media_report,validator=compiler.validate_media_report)
    def media_file_mutant(name,kind,content,expected,fixture="recursion94"):
        altered=json.loads(json.dumps(media_report));row=next(x for x in altered["captures"] if x["fixture"]==fixture)
        raw=(ROOT/row[kind]["path"]).read_bytes();changed=content(raw);file=directory/(name+".bin");file.write_bytes(changed)
        row[kind].update(artifact(file))
        # Recompute the surrounding capture/report links too: exercise source
        # scene/audio acceptance, not merely a stale enclosing checksum.
        routes=json.loads(json.dumps(report))
        bound=next(x for x in routes["runs"] if x["fixture"]==fixture and x["case"]=="full-route" and x["repetition"]==1)
        bound["pcm" if kind=="audio" else kind]=artifact(file)
        # Repeat-byte consistency is a separate assertion, kept true here so
        # the intended independent source feature is reached.
        repeated=next(x for x in routes["runs"] if x["fixture"]==fixture and x["case"]=="full-route" and x["repetition"]==2)
        repeated["pcm" if kind=="audio" else kind]=artifact(file)
        if kind=="audio" and name=="truncated-pcm":
            # The product consumer correctly catches truncated native PCM first.
            expected="product-pcm-length"
        routes_path=directory/(name+"-routes.json");write_json(routes_path,routes)
        altered["core_routes"]=artifact(routes_path);altered["core_routes_sha256"]=sha(routes_path)
        check(name,lambda r,c:r.update(altered),expected,media_report,validator=compiler.validate_media_report)
    media_file_mutant("blank-rec-scene","image",lambda b:bytes(len(b)),"media-rec-source-actor-mask")
    media_file_mutant("filled-rec-scene","image",lambda b:b"\xff\xff\xff\0"*(len(b)//4),"media-rec-source-actor-mask")
    media_file_mutant("wrong-tank-tile","image",lambda b:b[:(24*320+16)*4]+bytes([b[(24*320+16)*4]^1])+b[(24*320+16)*4+1:],"media-tank-source-tile","tank-battle")
    media_file_mutant("truncated-pcm","audio",lambda b:b[:400],"media-audio-truncated")
    media_file_mutant("dc-only-pcm","audio",lambda b:bytes(len(b)),"media-audio-source-signal")
    expected_checks=[{"name":name,"reason":reason,"status":"pass"}
                     for name,reason in CORE_SEMANTIC_MUTANT_EXPECTATIONS]
    if checks!=expected_checks:
        raise AssertionError("core semantic mutant identities or reasons diverged from declared roster")
    write_json(output,{"schema":"genewhip-phase6-core-check-v1","status":"pass","candidate_sha256":canonical_sha(candidate),
        "positive_report":artifact(path),"positive_media":artifact(media_path),"negative_controls":checks,
        "new_title_launches":0,"semantic_outer_digests_recomputed":True})
    return 0


def _copy_repetition(report,fixture,case):
    source=next(row for row in report["runs"] if row["fixture"]==fixture and row["case"]==case and row["repetition"]==1)
    index=next(i for i,row in enumerate(report["runs"])
               if row["fixture"]==fixture and row["case"]==case and row["repetition"]==2)
    clone=json.loads(json.dumps(source));clone["repetition"]=2
    report["runs"][index]=clone


def _copy_control_repetition(report):
    for index,row in enumerate(report["runs"]):
        if row["fixture"]!="genewhip-independent-game-v2" or row["repetition"]!=2:continue
        source=next(item for item in report["runs"]
                    if item["fixture"]==row["fixture"] and item["case"]==row["case"] and item["repetition"]==1)
        clone=json.loads(json.dumps(source));clone["repetition"]=2
        report["runs"][index]=clone


def tracer(build: pathlib.Path, map_path: pathlib.Path, output: pathlib.Path, candidate_path: pathlib.Path) -> int:
    if _read_window()["exploratory_attempts"]["recursion94"] >= 6:
        raise RuntimeError("REC exploratory allowance is spent; use the frozen canonical --mode core batch")
    build = build.resolve(strict=True)
    client = build / "tools/session/gw_headless"
    cache = build / "CMakeCache.txt"
    if not client.is_file() or not cache.is_file():
        raise RuntimeError("source-bound configured headless build is required")
    mapping = json.loads(map_path.read_text(encoding="utf-8"))
    compiler.validate_delivery_map(mapping)
    roster = compiler.compile_routes(mapping, "public-core")
    route = next(row for row in roster["routes"] if row["fixture"] == "recursion94" and row["case"]["id"] == "full-route")
    binary, metadata = compiler.lower_route(route, boundary_call_limit=100_000_000,
                                             delivery_map=mapping, client="public-core")
    map_sha = canonical_sha(mapping)
    compiled_sha = hashlib.sha256(binary).hexdigest()
    work = build / "evidence/phase6-tracer-work"
    work.mkdir(parents=True, exist_ok=True)
    plan = work / "recursion94-full-route.gwrc"
    report = work / "recursion94-full-route.json"
    media_dir = work / "recursion94-media"
    media_dir.mkdir(parents=True, exist_ok=False)
    pcm_path = work / "recursion94-route.pcm"
    plan.write_bytes(binary)
    source_paths = ["scripts/evidence/phase6_routes.py", "tools/session/route_controller.c",
                    "tools/session/session.c", "tools/headless/main.c", "tools/desktop/main_sdl.c",
                    "fixtures/phase6/recursion94-consumed-map-v1.json", "fixtures/phase6/media-expectations-v1.json",
                    "tests/fixtures/phase6_game.py",
                    "fixtures/phase5-b/scenario.json", "fixtures/phase5-b/input-program.json",
                    "fixtures/phase5-b/oracle.json", "fixtures/phase5-b/game.bin", "evidence/phase5-reference-d118.json"]
    candidate = {"schema":"genewhip-phase6-candidate-v1",
                 "source_files":{path:sha(ROOT/path) for path in source_paths},
                 "build_identity":{"cmake_cache_sha256":sha(cache),"generator":"Ninja","build_type":"Debug",
                                   "headless_sha256":sha(client),"headless_size":client.stat().st_size},
                 "configuration_identity":{"test_hooks":True,"tools":True,"desktop":True,"offline_pinned_sdl":True},
                 "client_identities":{"public-core":{"path":"build/phase6/tools/session/gw_headless","sha256":sha(client)}},
                 "compiler_identity":{"path":"scripts/evidence/phase6_routes.py","sha256":sha(ROOT/"scripts/evidence/phase6_routes.py")},
                 "delivery_map_identity":{"path":"fixtures/phase6/recursion94-consumed-map-v1.json","sha256":map_sha,
                                          "schema":mapping["schema"],"client":"public-core","input_sha256":mapping["source"]["input_program_sha256"]},
                 "media_expectations_identity":{"path":"fixtures/phase6/media-expectations-v1.json",
                     "sha256":sha(ROOT/"fixtures/phase6/media-expectations-v1.json")},
                 "media_expectations_sha256":sha(ROOT/"fixtures/phase6/media-expectations-v1.json"),
                 "proof_dependencies":{"tracer":["source_files","build_identity","client_identities","delivery_map_identity"]},
                 "invalidations":{"map":"REC and client observations","client":"all dependent executions"}}
    write_json(candidate_path, candidate)
    snapshot_path = work / ("candidate-" + canonical_sha(candidate) + ".json")
    write_json(snapshot_path, candidate)
    client_receipts: list[dict] = []
    command = [str(client), "--route-plan", str(plan), "--route-report", str(report), "--audio-rate", "48000",
               "--dump-audio", str(pcm_path), "--dump-fields", str(media_dir),
               "--capture-attempt-tick", "4", "690",
               "--capture-identity", canonical_sha(candidate),
               str(ROOT/"fixtures/phase5-b/game.bin")]
    started = time.monotonic()
    result = contracts._run_client(client, command, client_receipts, report=report, timeout=600,
                                   cwd=work, retained_streams={},
                                   monitored_files=((pcm_path, 16 * 1024 * 1024),),
                                   monitored_directories=((media_dir, 3, 320 * 224 * 4 + 8192),))
    process = client_receipts[-1]
    parsed = json.loads(report.read_text(encoding="utf-8")) if report.is_file() else None
    route_fields = {}
    if isinstance(parsed, dict):
        for key in ("active_ticks","fields","status","boundary_calls","queue_high_water","predicates","samples","inputs","audio_frames","audio_hash","termination"):
            if key in parsed:
                route_fields[key] = parsed[key]
    completed = route_fields.get("active_ticks")
    fields = route_fields.get("fields")
    events = []
    if isinstance(parsed, dict):
        for index, row in enumerate(mapping["events"], 1):
            source_tick = row["consumed"].get("tick")
            actual_sample = (next((sample for sample in parsed.get("samples", [])
                                   if sample.get("attempt") == row["consumed"].get("attempt") and sample.get("tick") == source_tick), None)
                             if row["clock_kind"] == "gameplay-source-step" else None)
            actual_input = parsed.get("inputs", [])[index - 1] if len(parsed.get("inputs", [])) >= index else None
            if actual_input and actual_input.get("effective") != row["effective_mask"]:
                actual_input = None
            events.append({"event_id":row["event_id"],"scheduled":row["scheduled_client_point"]["public-core"],
                           "expected_poll":row["expected_guest_poll"],
                           "observed_request":{"found":actual_input is not None,
                               "actual":actual_input},
                           "observed_poll":{"found":actual_sample is not None if row["clock_kind"] == "gameplay-source-step" else None,
                               "attempt":actual_sample.get("attempt") if actual_sample else None,
                               "tick":actual_sample.get("tick") if actual_sample else None,
                               "field":actual_sample.get("field") if actual_sample else None}})
    input_proof = (len(events) == 19 and all(row["observed_request"]["found"] for row in events) and
                   all(row["observed_poll"]["found"] is True for row in events
                       if mapping["events"][int(row["event_id"][-2:]) - 1]["clock_kind"] == "gameplay-source-step"))
    predicate_proof = (len(route_fields.get("predicates", [])) == 4 and
                       all(item.get("reached") is True for item in route_fields.get("predicates", [])))
    capture_metadata_path = media_dir / "route-capture.json"
    media_metadata = None
    media_field = None
    pcm_bytes = pcm_path.stat().st_size if pcm_path.is_file() and not pcm_path.is_symlink() else 0
    try:
        media_metadata = json.loads(capture_metadata_path.read_text(encoding="utf-8"))
        sequence = media_metadata["field_sequence"]
        media_field = media_dir / f"field-{sequence}.bin"
    except (OSError, ValueError, KeyError, TypeError):
        pass
    capture_proof = (isinstance(media_metadata, dict) and media_metadata.get("candidate_sha256") == canonical_sha(candidate) and
                     media_metadata.get("attempt") == 4 and media_metadata.get("source_tick", 0) >= 690 and
                     media_field is not None and media_field.is_file() and not media_field.is_symlink() and
                     media_field.stat().st_size == 320 * 224 * 4 and 0 < pcm_bytes <= 16 * 1024 * 1024 and pcm_bytes % 4 == 0)
    passed = (result.returncode == 0 and not process.get("bound_violation") and
              completed == 3600 and fields is not None and fields <= 7200 and
              input_proof and predicate_proof and route_fields.get("boundary_calls", 100_000_001) <= 100_000_000 and
              route_fields.get("queue_high_water", 65) <= 64 and capture_proof)
    raw_ref = {"path":str(report.relative_to(ROOT)),"sha256":sha(report)} if report.is_file() else None
    selected_samples = []
    if isinstance(parsed, dict):
        selected_samples = [sample for sample in parsed.get("samples", [])
                            if sample.get("attempt") == 4 and 693 <= sample.get("tick", -1) <= 720]
    receipt = {"schema":"genewhip-phase6-tracer-v1", "candidate_sha256":canonical_sha(candidate),
              "candidate_manifest":{"path":str(snapshot_path.relative_to(ROOT)),"sha256":sha(snapshot_path)},
              "fixture":"recursion94", "case":"full-route", "delivery_map_sha256":map_sha,
              "delivery_client":"public-core", "route_plan_sha256":compiled_sha,
              "route_metadata":metadata.get("delivery_map"), "result":"pass" if passed else "fail",
              "expected":{"completed_source_steps":3600,"maximum_fields":7200,"boundary_call_limit":100_000_000,
                          "queued_event_limit":64},
              "actual":{"active_ticks":completed,"fields":fields,
                        "boundary_calls":route_fields.get("boundary_calls"),
                        "queue_high_water":route_fields.get("queue_high_water"),
                        "predicates":route_fields.get("predicates"),
                        "termination":route_fields.get("termination"),
                        "audio_frames":route_fields.get("audio_frames"),
                        "audio_hash":route_fields.get("audio_hash"),
                        "final_attempt_samples":selected_samples,
                        "mapped_events":events},
              "raw_native_report":raw_ref,
              "media_capture":{"directory":str(media_dir.relative_to(ROOT)),
                  "pcm":str(pcm_path.relative_to(ROOT)),
                  "capture_metadata":str(capture_metadata_path.relative_to(ROOT)),
                  "field":str(media_field.relative_to(ROOT)) if media_field else None,
                  "artifacts":({"pcm_sha256":sha(pcm_path),"field_sha256":sha(media_field),
                      "metadata_sha256":sha(capture_metadata_path)} if capture_proof else None),
                  "capture_proof":capture_proof},
              "process":process,
              "elapsed_seconds":time.monotonic()-started,
              "first_divergence":None if passed else {"exit_code":result.returncode,"stderr":result.stderr[-4000:],
                    "observed_source_steps":completed,"observed_fields":fields},
              "limitations":["One frozen canonical route capture is media corroboration only; it does not complete the two-title roster."]}
    if passed:
        try:
            validate_tracer_report(receipt, mapping)
        except compiler.Invalid as error:
            passed = False
            receipt["result"] = "fail"
            receipt["first_divergence"] = {"reason":str(error)}
    write_json(output, receipt)
    return 0 if passed else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("tracer","contract","delivery-map","media","core","controls","safety","chunk","reader-refresh","close"), required=True)
    parser.add_argument("--build", type=pathlib.Path, required=True)
    parser.add_argument("--delivery-map", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--candidate", type=pathlib.Path, default=ROOT/"evidence/phase6-candidate.json")
    parser.add_argument("--negative-controls", action="store_true")
    parser.add_argument("--resume-batch", type=pathlib.Path)
    parser.add_argument("--execution-scope", type=pathlib.Path)
    parser.add_argument("--core-report", type=pathlib.Path)
    args = parser.parse_args()
    try:
        if args.execution_scope is not None:
            scoped=json.loads(args.execution_scope.read_text(encoding="utf-8"))
            scoped["_scope_path"]=str(args.execution_scope.resolve(strict=True))
            if args.core_report is not None:scoped["_core_report_path"]=str(args.core_report.resolve(strict=True))
            set_execution_scope(scoped)
        if args.mode == "contract":
            return core_contract(args.build,args.candidate,args.output)
        if args.mode == "delivery-map":
            if args.delivery_map is None:raise RuntimeError("delivery-map-required")
            return delivery_map_contract(args.delivery_map,args.output)
        if args.mode == "tracer":
            if args.delivery_map is None:
                raise RuntimeError("delivery-map-required")
            return tracer(args.build, args.delivery_map, args.output, args.candidate)
        if args.mode == "media":
            return media(args.build, args.candidate, args.output)
        if args.mode == "core":
            if args.delivery_map is None:
                raise RuntimeError("delivery-map-required")
            return core(args.build,args.delivery_map,args.candidate,args.output,args.resume_batch)
        if args.mode == "controls":
            report=json.loads((ROOT/"evidence/phase6-core-routes.json").read_text())
            candidate=json.loads(args.candidate.read_text())
            compiler.validate_product_report(report,candidate)
            write_json(args.output,{"schema":"genewhip-phase6-controls-v1","status":"pass","control_reports":report["controls"]})
            return 0
        if args.mode == "safety":
            return safety(args.build,args.candidate,args.output)
        if args.mode == "chunk":
            if args.delivery_map is None:raise RuntimeError("delivery-map-required")
            if _EXECUTION_SCOPE is not None and args.core_report is not None:
                _EXECUTION_SCOPE["_core_report_path"]=str(args.core_report.resolve(strict=True))
            return chunk(args.build,args.candidate,args.delivery_map,args.output)
        if args.mode == "reader-refresh":
            return refresh_readers(args.build,args.output)
        if args.mode == "close":
            return close(args.build,args.candidate,args.output,args.negative_controls)
    except (OSError, ValueError, KeyError, TypeError, compiler.Invalid, RuntimeError) as error:
        print(f"phase6 {args.mode} failed: {error}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    os.environ["GENEWHIP_PROCESS_CONTEXT"] = "host-cleanup-v1"
    raise SystemExit(main())

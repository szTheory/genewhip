#!/usr/bin/env python3
"""Denied-effects contracts for the one-shot diagnostic authority."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import socket
import subprocess
import sys
import ctypes
import datetime
import time
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PUBLIC_STARTED_AT = "2026-11-01T13:09:15.302323+00:00"
ITERATION_BASELINE_FIXTURE = ROOT / "tests/evidence/phase7_iteration_baseline_fixture.json"
DENIED_EFFECTS = []


def _deny_effects(event, args):
    if (event in ("subprocess.Popen", "os.system", "os.fork", "socket.__new__")
            or event.startswith(("os.exec", "os.spawn", "os.posix_spawn", "socket."))):
        DENIED_EFFECTS.append(event)
        raise PermissionError("single-native-contract-denied-effects")


if __name__ == "__main__":
    # Install sticky process/network/native denial only when this contract suite
    # runs as its own process. Other suites import its fixture constructor; a
    # process-wide audit hook there would contaminate their owned subprocess tests.
    sys.addaudithook(_deny_effects)
    _real_popen, _real_socket, _real_cdll = subprocess.Popen, socket.socket, ctypes.CDLL
    subprocess.Popen = lambda *a, **k: (_ for _ in ()).throw(PermissionError("denied subprocess"))
    socket.socket = lambda *a, **k: (_ for _ in ()).throw(PermissionError("denied socket"))
    ctypes.CDLL = lambda *a, **k: (_ for _ in ()).throw(PermissionError("denied native load"))
    try:
        subprocess.Popen(["/definitely-not-executed"])
    except PermissionError:
        DENIED_EFFECTS.append("subprocess.selftest")
    try:
        socket.socket()
    except PermissionError:
        DENIED_EFFECTS.append("socket.selftest")
    try:
        ctypes.CDLL("/definitely-not-loaded")
    except PermissionError:
        DENIED_EFFECTS.append("ctypes.selftest")
    subprocess.Popen, socket.socket, ctypes.CDLL = _real_popen, _real_socket, _real_cdll
SPEC = importlib.util.spec_from_file_location("gw_single_native_contract",
    ROOT / "scripts/release/v02_single_native.py")
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MOD)


class SingleNativeAuthorityContract(unittest.TestCase):
    def _write_public_authority(self, root: Path) -> Path:
        authority = root / MOD.AUTH_REL
        authority.parent.mkdir(parents=True, exist_ok=True)
        (root / MOD.CLAIM_REL).parent.mkdir(parents=True, exist_ok=True)
        authority.write_bytes(MOD.public_authority_fixture_bytes())
        scope = root / MOD.SCOPE_REL
        scope.parent.mkdir(parents=True, exist_ok=True)
        scope.write_bytes((ROOT / MOD.SCOPE_REL).read_bytes())
        return authority

    def _write_iteration_authority(self, root: Path, *, materialize_baseline: bool = False) -> Path:
        authority = root / MOD.ITERATION_AUTH_REL
        authority.parent.mkdir(parents=True, exist_ok=True)
        authority.write_bytes(MOD.public_iteration_authority_fixture_bytes())
        scope = root / MOD.SCOPE_REL
        scope.parent.mkdir(parents=True, exist_ok=True)
        scope.write_bytes((ROOT / MOD.SCOPE_REL).read_bytes())
        fixture = json.loads(ITERATION_BASELINE_FIXTURE.read_text(encoding="utf-8"))
        for relative, contents in fixture.items():
            if relative == MOD.ITERATION_BASELINE_REL.as_posix() and not materialize_baseline:
                continue
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(contents.encode("utf-8"))
        # The older R8 route is a completed historical attempt. A new
        # numbered namespace must preserve it without mistaking it for a live
        # claim in that namespace.
        old_route = root / MOD.ROOT_REL / "native-prefix-diagnostic"
        old_route.mkdir(parents=True, exist_ok=True)
        (old_route / "dispatch.json").write_text(json.dumps({"status": "completed",
            "remote_cleanup_status": "confirmed"}, sort_keys=True), encoding="utf-8")
        (old_route / "result.json").write_text(json.dumps({"status": "fail",
            "remote_cleanup_status": "confirmed", "qualification_accepted": False},
            sort_keys=True), encoding="utf-8")
        return authority

    def _iteration_source_admission_fixture(self, root: Path, context: dict[str, object], *,
            source_head: str = "a" * 40, source_bytes: bytes = b"int fixture_source(void) { return 1; }\n",
            started_at: str = "2026-11-02T12:00:00+00:00"):
        source_path = root / "src/iteration-fixture.c"
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_bytes(source_bytes)
        pins = {source_path.relative_to(root).as_posix(): hashlib.sha256(source_bytes).hexdigest()}
        predecessor = context["predecessor_ref"]
        source = MOD.source_payload(source_head=source_head, started_at=started_at,
            attempt_root=context["attempt_root_rel"], source_pins=pins,
            predecessor_sha256=predecessor["sha256"], authority_sha256=MOD.ITERATION_AUTH_SHA256,
            preparation_revision=context["preparation_revision_rel"],
            attempt_allocation_sha256=context["attempt_allocation_sha256"])
        payload_sha = MOD._digest(MOD._canonical(source))
        review_dir = root / ".planning/phases/GW-07-iteration-fixture"
        review_dir.mkdir(parents=True, exist_ok=True)
        reviews = {}
        for reviewer, role in MOD.SOURCE_ROLES.items():
            review_path = review_dir / f"{reviewer}-{payload_sha[:12]}.md"
            raw = (f"---\nstatus: accepted\nreviewer_role: {role}\n"
                f"payload_sha256: {payload_sha}\n---\nSynthetic source admission review.\n").encode()
            review_path.write_bytes(raw)
            reviews[reviewer] = {"path": review_path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(), "reviewer_role": role,
                "status": "accepted", "payload_sha256": payload_sha}
        record = {"schema": MOD.SCHEMA, "stage": "source-preparation",
            "authority_path": MOD.ITERATION_AUTH_REL.as_posix(),
            "authority_sha256": MOD.ITERATION_AUTH_SHA256,
            "scope_path": MOD.SCOPE_REL.as_posix(), "scope_sha256": MOD.SCOPE_SHA256,
            "attempt_root": context["attempt_root_rel"], "started_at": started_at,
            "source_head": source_head, "source_pins": pins,
            "source_payload_sha256": payload_sha, "source_reviews": reviews,
            "predecessor": predecessor,
            "preparation_revision": context["preparation_revision_rel"],
            "attempt_allocation_sha256": context["attempt_allocation_sha256"]}
        admission = context["preparation_revision"] / "source-admission.json"
        admission.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
        return admission, record

    def _iteration_public_admission_fixture(self, root: Path, context: dict[str, object], *,
            source_head: str = "a" * 40, source_bytes: bytes = b"int fixture_source(void) { return 1; }\n",
            started_at: str = "2026-11-02T12:00:00+00:00"):
        source_path, source_record = self._iteration_source_admission_fixture(root, context,
            source_head=source_head, source_bytes=source_bytes, started_at=started_at)
        artifact_root = Path(context["preparation_revision_rel"])
        source = MOD.source_payload(source_head=source_head,
            started_at=source_record["started_at"],
            attempt_root=context["attempt_root_rel"], source_pins=source_record["source_pins"],
            predecessor_sha256=context["predecessor_ref"]["sha256"],
            authority_sha256=MOD.ITERATION_AUTH_SHA256,
            preparation_revision=context["preparation_revision_rel"],
            attempt_allocation_sha256=context["attempt_allocation_sha256"])
        publication_rel = artifact_root / "publication"
        publication = root / publication_rel
        publication.mkdir(parents=True)
        content = b"public-safe iteration fixture\n"
        (publication / "fixture.txt").write_bytes(content)
        manifest = [{"path": "fixture.txt", "size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest()}]
        manifest_sha = MOD._digest(MOD._canonical(manifest))
        repository_policy_rel = artifact_root / "repository-policy.json"
        repository_policy = {"repository_observations": {"ready": True},
            "privacy_scan": {"publication_copy": {"status": "pass"}}}
        repository_policy_raw = (json.dumps(repository_policy, sort_keys=True) + "\n").encode()
        (root / repository_policy_rel).write_bytes(repository_policy_raw)
        preparation_rel = artifact_root / "preparation.json"
        preparation = {"status": "prepared", "source_identity": {"private_git_head": source_head},
            "publication_copy": publication_rel.as_posix(),
            "repository_preflight": repository_policy_rel.as_posix(),
            "source_manifest": manifest, "source_manifest_sha256": manifest_sha,
            "public_identity": {"head_sha": "b" * 40, "base_sha": "c" * 40,
                "tree_sha": "d" * 40}, "privacy": {"status": "pass"}, "blockers": []}
        preparation_raw = (json.dumps(preparation, sort_keys=True) + "\n").encode()
        (root / preparation_rel).write_bytes(preparation_raw)
        candidate = {"preparation_path": preparation_rel.as_posix(),
            "preparation_sha256": hashlib.sha256(preparation_raw).hexdigest(),
            "publication_path": publication_rel.as_posix(),
            "repository_policy_path": repository_policy_rel.as_posix(),
            "repository_policy_sha256": hashlib.sha256(repository_policy_raw).hexdigest(),
            "public_head": "b" * 40, "public_base": "c" * 40,
            "public_tree": "d" * 40, "source_manifest_sha256": manifest_sha}
        candidate_payload = MOD.candidate_payload(source, candidate)
        candidate_sha = MOD._digest(MOD._canonical(candidate_payload))
        candidate["candidate_payload_sha256"] = candidate_sha
        review_dir = root / ".planning/phases/GW-07-iteration-fixture"
        review_dir.mkdir(parents=True, exist_ok=True)
        candidate_reviews = {}
        for reviewer, role in MOD.SOURCE_ROLES.items():
            review_path = review_dir / f"{reviewer}-candidate-{candidate_sha[:12]}.md"
            raw = (f"---\nstatus: accepted\nreviewer_role: {role}\n"
                f"payload_sha256: {candidate_sha}\n---\nSynthetic candidate admission review.\n").encode()
            review_path.write_bytes(raw)
            candidate_reviews[reviewer] = {"path": review_path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(), "reviewer_role": role,
                "status": "accepted", "payload_sha256": candidate_sha}
        record = {**source_record, "stage": "public-effects", "candidate": candidate,
            "candidate_reviews": candidate_reviews}
        admission = root / artifact_root / "public-admission.json"
        admission.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
        self.assertTrue(source_path.is_file())
        return admission, record

    def _source_ci_failure_fixture(self, root: Path, *, mutation: str | None = None,
            authority: Path | None = None, attempt: dict[str, object] | None = None,
            revision: dict[str, object] | None = None,
            public_record: dict[str, object] | None = None):
        """Build synthetic provider-shaped CI failure evidence for closure contracts only."""
        if attempt is None or revision is None or public_record is None:
            if any(value is not None for value in (attempt, revision, public_record)):
                raise ValueError("source-ci-fixture-existing-revision-requires-all-inputs")
            authority = self._write_iteration_authority(root)
            MOD.write_iteration_baseline(root)
            attempt = MOD.allocate_attempt(root, reason="source CI settlement contract")
            revision = MOD.allocate_revision(root, attempt["attempt_root"],
                reason="reviewed candidate with source CI evidence")
            context = MOD.iteration_context(root, authority,
                revision["preparation_revision"] / "public-admission.json")
            _, record = self._iteration_public_admission_fixture(root, context)
        else:
            authority = authority or root / MOD.ITERATION_AUTH_REL
            record = public_record
        candidate = record["candidate"]
        candidate_head = candidate["public_head"]
        branch = "v0.2-source-" + candidate_head[:12]
        run_id, pull_request_number = 456789, 46
        workflow = {"id": run_id, "run_attempt": 1, "event": "pull_request",
            "head_sha": candidate_head, "head_branch": branch, "status": "completed",
            "conclusion": "failure", "path": ".github/workflows/ci.yml",
            "repository": {"full_name": "szTheory/genewhip"}}
        if mutation == "wrong-head":
            workflow["head_sha"] = "e" * 40
        pull_request = {"number": pull_request_number, "state": "open", "merged": False,
            "head": {"sha": candidate_head, "ref": branch,
                "repo": {"full_name": "szTheory/genewhip"}},
            "base": {"sha": candidate["public_base"], "ref": "main"}}
        if mutation == "wrong-pr":
            pull_request["number"] = pull_request_number + 1
        rows = []
        for index, name in enumerate(sorted(MOD.ITERATION_SOURCE_CI_JOBS), 1):
            status = "in_progress" if mutation == "active-sibling" and name == "desktop" else "completed"
            rows.append({"id": run_id + index, "run_id": run_id, "run_attempt": 1,
                "name": name, "head_sha": candidate_head, "head_branch": branch,
                "status": status,
                "conclusion": (None if status != "completed" else
                    "failure" if name == "required-ci" else "success")})
        jobs = {"total_count": len(rows), "jobs": rows}
        ci_root = revision["preparation_revision"] / "ci-failure"
        ci_root.mkdir(exist_ok=True)
        refs = {}
        for key, name, value in (("source_ci_workflow", "workflow_run.json", workflow),
                ("source_ci_jobs", "jobs.json", jobs),
                ("source_ci_pull_request", "pull_request.json", pull_request)):
            path = ci_root / name
            raw = (json.dumps(value, sort_keys=True) + "\n").encode()
            path.write_bytes(raw)
            refs[key] = {"path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest()}
        evidence = {"schema": "genewhip.phase7-native-iteration-source-ci-failure.v1",
            "candidate_head": candidate_head, "pull_request": str(pull_request_number),
            "pull_request_state": "open", "merged": False,
            "required_ci_status": "COMPLETED", "required_ci_conclusion": "FAILURE",
            "remote_cleanup_status": "confirmed", **refs}
        evidence_path = ci_root / "source-ci-failure.json"
        evidence_path.write_text(json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8")
        return {"authority": authority, "attempt": attempt, "revision": revision,
            "source_head": record["source_head"], "candidate_head": candidate_head,
            "pull_request": str(pull_request_number), "refs": refs,
            "evidence_path": evidence_path.relative_to(root).as_posix(),
            "evidence": evidence}

    def _readiness_fixture(self, root, attempt, admission, record, *, iteration_context=None):
        candidate = record["candidate"]
        source = {"source_head": record["source_head"], "started_at": record["started_at"],
            "source_payload_sha256": record["source_payload_sha256"]}
        source_path = attempt / "source-admission.json"
        if not source_path.exists():
            source_path.write_text(json.dumps(source, sort_keys=True))
        jobs = [{"id": i + 1, "name": name, "status": "completed",
            "conclusion": "success" if name in MOD.PREVIEW_REQUIRED else "skipped"}
            for i, name in enumerate(sorted(MOD.PREVIEW_REQUIRED | MOD.PREVIEW_SKIPPED))]
        delivery = {"status": "diagnostic-ci-complete", "repository": "szTheory/genewhip",
            "diagnostic_only": True, "assessment_required": True, "merge_attempted": False,
            "candidate_sha": candidate["public_head"], "public_base_sha": candidate["public_base"],
            "pull_request": "46"}
        journal = {"repository": "szTheory/genewhip", "source_head": candidate["public_head"],
            "public_base_sha": candidate["public_base"],
            "started_at": (record["started_at"] if iteration_context is not None else PUBLIC_STARTED_AT),
            "branch": "v0.2-source-" + candidate["public_head"][:12], "push_performed": True,
            "diagnostic_only": True, "diagnostic_ci_status": "passed", "assessment_required": True,
            "merge_attempted": False, "pull_request": "46"}
        refs = {}
        for key, value, filename in (("source_delivery", delivery, "source-delivery.json"),
                                     ("journal", journal, "hosted-delivery-journal.json")):
            path = attempt / filename
            path.write_text(json.dumps(value, sort_keys=True))
            refs[key] = {"path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        packet = {"disposition": "diagnostic-preview-green-assessment-required",
            "qualification_credit": False,
            "source_and_candidate": {"source_admission_path": source_path.relative_to(root).as_posix(),
                "source_admission_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
                "public_admission_path": admission.relative_to(root).as_posix(),
                "public_admission_sha256": hashlib.sha256(admission.read_bytes()).hexdigest(),
                "private_source_head": record["source_head"], "candidate_head": candidate["public_head"],
                "public_head": candidate["public_head"], "public_base": candidate["public_base"],
                "public_tree": candidate["public_tree"], "manifest_sha256": candidate["source_manifest_sha256"],
                "preparation_sha256": candidate["preparation_sha256"],
                "candidate_review_payload_sha256": candidate["candidate_payload_sha256"]},
            "hosted_source_delivery": {"source_delivery_path": refs["source_delivery"]["path"],
                "source_delivery_sha256": refs["source_delivery"]["sha256"],
                "journal_path": refs["journal"]["path"], "journal_sha256": refs["journal"]["sha256"]},
            "github": {"repository": "szTheory/genewhip", "pull_request": 46,
                "pull_request_state": "open", "merged": False, "head_sha": candidate["public_head"],
                "base_sha": candidate["public_base"], "workflow_run": {"id": 99, "run_attempt": 1,
                    "event": "pull_request", "status": "completed", "conclusion": "success",
                    "workflow_path": ".github/workflows/ci.yml"}, "jobs": jobs}}
        packet_path = attempt / "ci-failure/assessment.json"
        packet_path.parent.mkdir(parents=True)
        packet_path.write_text(json.dumps(packet, sort_keys=True))
        assessment = {"path": packet_path.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(packet_path.read_bytes()).hexdigest()}
        ready = {"schema": "genewhip.phase7-native-prefix-diagnostic-readiness.v1",
            "diagnostic_only": True, "qualification_accepted": False,
            "plan": {"case": "recursion94-native-prefix", "workloads": [
                {"name": "input-contract", "wall_seconds": 30},
                {"name": "headless-reference", "wall_seconds": 600,
                    "cases": ["full-route", "withhold-first-plate"]},
                {"name": "native-comparison", "wall_seconds": 600,
                    "cases": ["full-route", "withhold-first-plate"]}],
                "outer_wall_seconds": 1800, "job_wall_seconds": 2700,
                "qualification_accepted": False, "stop_after_result": True},
            "started_at": record["started_at"], "source_head": record["source_head"],
            "candidate_head": candidate["public_head"],
            "public_admission": {"path": admission.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(admission.read_bytes()).hexdigest()},
            "diagnostic_assessment": assessment}
        if iteration_context is not None:
            ready.update({"authority_sha256": MOD.ITERATION_AUTH_SHA256,
                "attempt_root": iteration_context["attempt_root_rel"],
                "preparation_revision": iteration_context["preparation_revision_rel"],
                "attempt_allocation_sha256": iteration_context["attempt_allocation_sha256"]})
        ready_payload_sha = hashlib.sha256(json.dumps(ready, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        reviews = {}
        review_dir = root / ".planning/phases/GW-07-single-native-fixture"
        review_dir.mkdir(parents=True, exist_ok=True)
        for key, role in MOD.SOURCE_ROLES.items():
            suffix = ready_payload_sha[:12] + "-" if iteration_context is not None else ""
            review = review_dir / f"readiness-{suffix}{key}.md"
            raw = (f"---\nstatus: accepted\nreviewer_role: {role}\n"
                f"payload_sha256: {ready_payload_sha}\n---\nSynthetic accepted assessment review.\n").encode()
            review.write_bytes(raw)
            reviews[key] = {"path": review.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(), "reviewer_role": role,
                "status": "accepted", "payload_sha256": ready_payload_sha}
        ready["assessment_reviews"] = reviews
        ready_path = attempt / "native-prefix-diagnostic-readiness.json"
        ready_path.write_text(json.dumps(ready, sort_keys=True))
        return ready_path, hashlib.sha256(ready_path.read_bytes()).hexdigest(), candidate

    def _strict_report(self, root, identity):
        spec = importlib.util.spec_from_file_location("terminal_fixture_runtime",
            root / "scripts/evidence/v02_run.py")
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        process = {"return_code": "zero", "status": "completed", "cleanup": "confirmed",
            "bound_violation": False}
        masks = runtime._NATIVE_PREFIX_ROUTE_MASKS
        expected_counts = runtime._NATIVE_PREFIX_INPUT_COUNTS
        route_cases, compare_cases = [], []
        for case in runtime._NATIVE_PREFIX_CASES:
            route_events = [{"index": i, "port": 0, "requested_mask": mask,
                "requested_mask_valid": True, "effective_mask": mask,
                "effective_mask_valid": True, "joystick_mask": "not-reported",
                "joystick_mask_valid": None, "handler": "not-reported"}
                for i, mask in enumerate(masks[case])]
            expected_predicates = runtime._NATIVE_PREFIX_EXPECTED_PREDICATES[case]
            route = {"status": 0, "active_ticks": 3600, "fields": 7000,
                "boundary_calls": 10, "input_event_count": expected_counts[case],
                "input_events": route_events, "input_events_truncated": False,
                "predicate_count": 4, "predicates": [
                    {"id": key, "reached": val[0], "value": val[1], "field": val[2]}
                    for key, val in expected_predicates.items()]}
            route_cases.append({"case": case, "status": "pass", "process": process, "route": route})
            native_events, host_events, input_rows = [], [], []
            for i, mask in enumerate(masks[case]):
                common = {"index": i, "port": 0, "requested_mask": mask,
                    "requested_mask_valid": True, "effective_mask": mask,
                    "effective_mask_valid": True}
                native_events.append({**common, "joystick_mask": "not-reported",
                    "joystick_mask_valid": None, "handler": "not-reported"})
                host_events.append({**common, "joystick_mask": mask,
                    "joystick_mask_valid": True, "handler": "sdl-gamepad-sample-port"})
                input_rows.append({"index": i, "equal": True, "port": 0,
                    "desired": mask, "effective": mask})
            comparison = {"status": "pass", "core_outcome": "pass", "host_outcome": "pass-diagnostic",
                "input_equal": True, "input_rows": input_rows, "native_status": 0,
                "observed_clocks": {"active_ticks": 3600, "fields": 7000, "boundary_calls": 10},
                "core_input_count": expected_counts[case], "host_input_count": expected_counts[case],
                "native_input_events": native_events, "native_input_events_truncated": False,
                "host_input_events": host_events, "host_input_events_truncated": False,
                "reason": None, "failure_presence": {"capture_field_matches": False,
                    "renderer_named": False, "video_driver_named": False, "audio_driver_named": False},
                "source_samples_equal": True, "renderer_pixel_equal": True, "full_pcm_equal": True,
                "renderer_readback": True, "audio_device_activity": True,
                "audio_submitted_frames": 100, "audio_consumed_frames": 100}
            compare_cases.append({"case": case, "status": "pass", "process": process,
                "comparison": comparison})
        input_masks = list(runtime._NATIVE_DIAGNOSTIC_INPUT_MASKS)
        input_stage = {"name": "input-contract", "status": "pass", "process": process,
            "input": {"requested_count": 23, "outcome": "pass", "port_isolation_verified": True,
                "masks": input_masks, "mask_validity": [True] * 23, "mask_count": 23,
                "observations_count": 23, "observations_truncated": False,
                "observations": [{"requested_mask": mask, "effective_mask": mask,
                    "joystick_mask": mask} for mask in input_masks]}}
        report = {"schema": "genewhip-phase7-native-prefix-diagnostic-v1", "status": "pass",
            "diagnostic_only": True, "qualification_accepted": False, "fixture": "recursion94",
            "case_order": list(runtime._NATIVE_PREFIX_CASES), "failure_category": None,
            "stages": [input_stage, {"name": "headless-reference", "status": "pass", "cases": route_cases},
                {"name": "native-comparison", "status": "pass", "cases": compare_cases}],
            "outer_process": process, "outer_rejection": None,
            "collector_read_status": "valid", "identity": identity}
        self.assertTrue(runtime.validate_native_prefix_diagnostic_public(report, identity))
        return report

    def _write_iteration_native_result(self, root: Path, context: dict[str, object],
            admission_path: Path, record: dict[str, object], *, outcome: str,
            started_at: str, nonce: str, run_id: int):
        readiness_path, readiness_sha, candidate = self._readiness_fixture(root,
            context["preparation_revision"], admission_path, record,
            iteration_context=context)
        raw_admission = admission_path.read_bytes()
        MOD.validate_admission(root, context["attempt_root"], admission_path,
            stage="native-prefix-diagnostic", source_head=record["source_head"],
            source_roster=set(record["source_pins"]), authority_path=MOD.ITERATION_AUTH_REL,
            authority_sha256=MOD.ITERATION_AUTH_SHA256,
            admission_sha256=hashlib.sha256(raw_admission).hexdigest(),
            readiness_path=readiness_path, readiness_sha256=readiness_sha)

        deadline = (datetime.datetime.fromisoformat(started_at)
            + datetime.timedelta(seconds=5400)).isoformat()
        branch = "v0.2-source-" + candidate["public_head"][:12]
        claim = MOD.iteration_claim_payload(attempt_root=context["attempt_root_rel"],
            preparation_revision=context["preparation_revision_rel"],
            source_sha=candidate["public_head"], base_sha=candidate["public_base"],
            branch=branch, nonce=nonce, started_at=started_at, deadline=deadline,
            readiness_sha256=readiness_sha)
        claim_raw = (json.dumps(claim, sort_keys=True, indent=2) + "\n").encode()
        claim_anchor = MOD._open_claim_anchor(root, context["claim_rel"])
        try:
            stored_claim, claim_sha = MOD._create_claim_at_anchor(claim_anchor,
                lambda: claim_raw)
        finally:
            MOD._close_claim_anchor(claim_anchor)
        self.assertEqual(stored_claim, claim_raw)

        runtime_root = context["attempt_root"] / "native-prefix-diagnostic"
        download = runtime_root / "download"
        download.mkdir(parents=True)
        identity = {"source_sha": candidate["public_head"],
            "head_sha": candidate["public_head"], "base_sha": candidate["public_base"],
            "run_id": str(run_id), "run_attempt": "1"}
        report = self._strict_report(root, identity)
        if outcome == "fail":
            report["status"] = "fail"
            report["failure_category"] = "bounded-workload-failed"
        report["schema"] = "genewhip-phase7-native-prefix-diagnostic-v2"
        claim_start = datetime.datetime.fromisoformat(started_at)
        job_started = (claim_start + datetime.timedelta(seconds=30)).isoformat()
        server_date = (claim_start + datetime.timedelta(seconds=35)).isoformat()
        local_request = (claim_start + datetime.timedelta(seconds=33)).isoformat()
        response_end = 10_000_000_000_000
        rtt = 2_000_000_000
        projection = MOD.queue_clock_projection(claim_started_at=started_at,
            claim_deadline=deadline, job_started_at=job_started, server_date=server_date,
            round_trip_ns=rtt, response_received_monotonic_ns=response_end,
            local_request_started_at=local_request,
            local_response_at=server_date)
        job_clock = {"schema": MOD.QUEUE_RECEIPT_SCHEMA, "clock_profile": MOD.QUEUE_PROFILE,
            "claim_sha256": claim_sha, "claim_nonce": nonce,
            "claim_started_at": started_at, "claim_deadline": deadline,
            "repository": "szTheory/genewhip", "run_id": str(run_id), "run_attempt": 1,
            "job_id": run_id + 1, "job_name": "v02-runtime",
            "job_status_at_observation": "in_progress", "head_sha": candidate["public_head"],
            "head_branch": branch, "job_started_at": job_started, "server_date": server_date,
            "local_request_started_at": local_request,
            "local_response_at": server_date, "round_trip_ns": rtt,
            "timestamp_precision_seconds": 1,
            "request_started_monotonic_ns": response_end - rtt,
            "response_received_monotonic_ns": response_end, **projection}
        job_clock_path = download / "native-prefix-job-clock.json"
        job_clock_path.write_text(json.dumps(job_clock, sort_keys=True), encoding="utf-8")
        report["clock_completion"] = {
            "schema": "genewhip.phase7-native-prefix-clock-completion.v1",
            "receipt_sha256": hashlib.sha256(job_clock_path.read_bytes()).hexdigest(),
            "collector_deadline_monotonic_ns": projection["collector_deadline_monotonic_ns"],
            "completion_monotonic_ns": projection["collector_deadline_monotonic_ns"] - 1}
        report_path = download / "native-prefix-diagnostic.json"
        report_path.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
        report_sha = hashlib.sha256(report_path.read_bytes()).hexdigest()
        job_clock_sha = hashlib.sha256(job_clock_path.read_bytes()).hexdigest()
        dispatch = {"schema": "genewhip.phase7-native-prefix-diagnostic-dispatch.v1",
            "source_sha": candidate["public_head"], "base_sha": candidate["public_base"],
            "branch": branch, "repository": "szTheory/genewhip", "nonce": nonce,
            "requested_at": started_at, "started_at": started_at,
            "readiness_sha256": readiness_sha, "qualification_accepted": False,
            "status": "completed-assessment-required", "dispatches": 1,
            "native_diagnostic_started_at": started_at,
            "native_diagnostic_deadline": deadline,
            "qualification_started_at": started_at, "run_id": run_id,
            "clock_profile": MOD.QUEUE_PROFILE, "job_clock_receipt_sha256": job_clock_sha,
            "remote_cleanup_status": "confirmed"}
        result = {"schema": "genewhip.phase7-native-prefix-diagnostic-result.v1",
            "status": outcome, "qualification_accepted": False, "assessment_required": True,
            "run_id": str(run_id), "source_sha": candidate["public_head"],
            "run_attempt": "1", "report_sha256": report_sha,
            "report_path": report_path.relative_to(root).as_posix(), "branch": branch,
            "job_clock_receipt_sha256": job_clock_sha,
            "job_clock_receipt_path": job_clock_path.relative_to(root).as_posix()}
        workflow = {"id": run_id, "run_attempt": 1, "event": "workflow_dispatch",
            "head_sha": candidate["public_head"], "head_branch": branch,
            "status": "completed", "conclusion": "success" if outcome == "pass" else "failure",
            "display_title": "Plan10 native prefix diagnostic " + nonce,
            "path": ".github/workflows/ci.yml@refs/heads/" + branch,
            "repository": {"full_name": "szTheory/genewhip"}}
        names = sorted({"safety", "gameplay", "desktop", "package", "performance",
            "product-smoke", "phase7-fast", "v02-runtime", "extended", "attestation",
            "required-ci", "v02-benchmark-control", "v02-benchmark-recursion94",
            "v02-benchmark-tank-battle", "v02-package", "v02-release-qualification"})
        jobs = {"total_count": 16, "jobs": [{"name": name, "status": "completed",
            "conclusion": workflow["conclusion"] if name == "v02-runtime" else "skipped",
            **({"id": run_id + 1, "run_id": run_id, "run_attempt": 1,
                "head_sha": candidate["public_head"], "head_branch": branch,
                "started_at": job_started} if name == "v02-runtime" else {})}
            for name in names]}
        for name, value in (("dispatch.json", dispatch), ("result.json", result),
                ("workflow_run.json", workflow), ("jobs.json", jobs)):
            (runtime_root / name).write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
        return {"claim": claim, "claim_raw": claim_raw, "claim_sha256": claim_sha,
            "dispatch": dispatch, "result": result, "report": report,
            "admission": admission_path, "readiness": readiness_path,
            "candidate": candidate, "runtime_root": runtime_root}

    def _admission_fixture(self, root: Path, *, source_paths: set[str] | None = None):
        self._write_public_authority(root)
        attempt = root / MOD.ROOT_REL
        attempt.mkdir(parents=True)
        prior_root = root / "build/v02/ci-continuation-20261031T124319Z/attempt-0021"
        prior_root.mkdir(parents=True)
        source_sha, run_id = "e" * 40, "1234567890"
        ref_values = {}

        def prior_ref(name, path, data):
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            ref_values[name] = {"path": path, "sha256": hashlib.sha256(data).hexdigest()}

        report_path = "build/v02/ci-continuation-20261031T124319Z/attempt-0021/native-prefix-diagnostic/download/native-prefix-diagnostic.json"
        result_path = "build/v02/ci-continuation-20261031T124319Z/attempt-0021/native-prefix-diagnostic/result.json"
        dispatch_path = "build/v02/ci-continuation-20261031T124319Z/attempt-0021/native-prefix-diagnostic/dispatch.json"
        report = {"schema": "genewhip-phase7-native-prefix-diagnostic-v1", "status": "fail",
            "diagnostic_only": True, "qualification_accepted": False, "fixture": "recursion94",
            "case_order": ["full-route", "withhold-first-plate"], "identity": {"source_sha": source_sha,
                "head_sha": source_sha, "run_id": run_id, "run_attempt": "1"}}
        report_raw = json.dumps(report, sort_keys=True).encode()
        result = {"run_id": run_id, "run_attempt": "1", "source_sha": source_sha,
            "status": "fail", "qualification_accepted": False,
            "report_sha256": hashlib.sha256(report_raw).hexdigest(), "report_path": report_path}
        result_raw = json.dumps(result, sort_keys=True).encode()
        dispatch = {"dispatches": 1, "qualification_accepted": False, "source_sha": source_sha,
            "run_id": int(run_id), "status": "completed-assessment-required"}
        dispatch_raw = json.dumps(dispatch, sort_keys=True).encode()
        prior_ref("dispatch", dispatch_path, dispatch_raw)
        prior_ref("result", result_path, result_raw)
        prior_ref("report", report_path, report_raw)
        workflow = {"selected_run": {"id": int(run_id), "run_attempt": 1, "head_sha": source_sha,
            "event": "workflow_dispatch", "status": "completed", "conclusion": "failure"}}
        prior_ref("workflow_run", "build/v02/ci-continuation-20261031T124319Z/attempt-0021/ci-failure/selected.json",
            json.dumps(workflow, sort_keys=True).encode())
        jobs = b"synthetic jobs output\n"
        prior_ref("jobs_stdout", "build/v02/ci-continuation-20261031T124319Z/attempt-0021/ci-failure/jobs.bin", jobs)
        retained = {"run_id": int(run_id), "run_attempt": 1,
            "dispatch_sha256": hashlib.sha256(dispatch_raw).hexdigest(),
            "result_path": result_path, "result_sha256": hashlib.sha256(result_raw).hexdigest(),
            "report_path": report_path, "report_sha256": hashlib.sha256(report_raw).hexdigest(),
            "retained_receipts": {"jobs": {"stdout_sha256": hashlib.sha256(jobs).hexdigest(),
                "stdout_bytes": len(jobs)}}}
        prior_ref("retention_manifest", "build/v02/ci-continuation-20261031T124319Z/attempt-0021/ci-failure/manifest.json",
            json.dumps(retained, sort_keys=True).encode())
        for name in ("runtime_log", "repair_payload"):
            prior_ref(name, f"build/v02/ci-continuation-20261031T124319Z/attempt-0021/ci-failure/{name}.txt", b"synthetic retained evidence\n")
        for name in ("repair_code_review", "repair_security_review", "result_code_review", "result_security_review"):
            prior_ref(name, f".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/{name}.md", b"accepted synthetic review\n")
        prior = json.dumps({"schema": "genewhip.phase7-single-native-predecessor-observation.v1",
            "source_sha": source_sha, "run_id": run_id, "run_attempt": 1, "diagnostic_status": "fail",
            "first_headless_case": "failed-process-and-route-facts-unavailable",
            "input_contract": "pass-23-observations", "remaining_cases": "unavailable",
            "inner_cleanup": "unknown", "outer_cleanup": "confirmed", "outer_bound_violation": False,
            "hosted_exception": "not-retained-unknown", "full_qualification20_cause": "unknown",
            "qualification_accepted": False,
            "retry_authority": "only new independently reviewed single-run authority; not supplied by this observation",
            "source_repair": "shared headless parent creation locally reproduced and reviewed; no hosted repair credit",
            "references": ref_values}, sort_keys=True).encode() + b"\n"
        prior_path = root / MOD.PREDECESSOR_REL
        prior_path.parent.mkdir(parents=True, exist_ok=True)
        prior_path.write_bytes(prior)
        predecessor_sha = hashlib.sha256(prior).hexdigest()
        source_file = root / "src/source.c"
        source_file.parent.mkdir()
        source_file.write_text("int source(void) { return 1; }\n")
        pins = {"src/source.c": hashlib.sha256(source_file.read_bytes()).hexdigest()}
        for rel in source_paths or set():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / rel).read_bytes())
            pins[rel] = hashlib.sha256(target.read_bytes()).hexdigest()
        started = "2026-11-01T11:27:01Z"
        source_payload = MOD.source_payload(source_head="a" * 40, started_at=started,
            attempt_root=MOD.ROOT_REL.as_posix(), source_pins=pins,
            predecessor_sha256=predecessor_sha)
        source_hash = hashlib.sha256(json.dumps(source_payload, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        review_dir = root / ".planning/phases/GW-07-single-native-fixture"
        review_dir.mkdir(parents=True, exist_ok=True)

        def reviews(payload_sha):
            result = {}
            for key, role in MOD.SOURCE_ROLES.items():
                review_path = review_dir / (key + "-" + payload_sha[:10] + "-review.md")
                raw = (f"---\nstatus: accepted\nreviewer_role: {role}\n"
                       f"payload_sha256: {payload_sha}\n---\nSynthetic acceptance fixture.\n")
                review_path.write_text(raw)
                result[key] = {"path": review_path.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(raw.encode()).hexdigest(),
                    "reviewer_role": role, "status": "accepted", "payload_sha256": payload_sha}
            return result

        source_reviews = reviews(source_hash)
        publication = attempt / "publication"
        publication.mkdir()
        pub_file = publication / "hello.txt"
        pub_file.write_text("public safe fixture\n")
        manifest = [{"path": "hello.txt", "size_bytes": pub_file.stat().st_size,
            "sha256": hashlib.sha256(pub_file.read_bytes()).hexdigest()}]
        manifest_sha = hashlib.sha256(json.dumps(manifest, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        policy_path = attempt / "repository-policy.json"
        policy = {"repository_observations": {"ready": True},
            "privacy_scan": {"publication_copy": {"status": "pass"}}}
        policy_path.write_text(json.dumps(policy, sort_keys=True))
        prep_path = attempt / "preparation.json"
        prep = {"status": "prepared", "source_identity": {"private_git_head": "a" * 40},
            "publication_copy": (MOD.ROOT_REL / "publication").as_posix(),
            "repository_preflight": (MOD.ROOT_REL / "repository-policy.json").as_posix(),
            "source_manifest": manifest, "source_manifest_sha256": manifest_sha,
            "public_identity": {"head_sha": "b" * 40, "base_sha": "c" * 40, "tree_sha": "d" * 40},
            "privacy": {"status": "pass"}, "blockers": []}
        prep_path.write_text(json.dumps(prep, sort_keys=True))
        candidate = {"preparation_path": (MOD.ROOT_REL / "preparation.json").as_posix(),
            "preparation_sha256": hashlib.sha256(prep_path.read_bytes()).hexdigest(),
            "publication_path": (MOD.ROOT_REL / "publication").as_posix(),
            "repository_policy_path": (MOD.ROOT_REL / "repository-policy.json").as_posix(),
            "repository_policy_sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
            "public_head": "b" * 40, "public_base": "c" * 40, "public_tree": "d" * 40,
            "source_manifest_sha256": manifest_sha}
        candidate_review_payload = MOD.candidate_payload(source_payload, candidate)
        candidate_hash = hashlib.sha256(json.dumps(candidate_review_payload, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        candidate["candidate_payload_sha256"] = candidate_hash
        candidate_reviews = reviews(candidate_hash)
        record = {"schema": MOD.SCHEMA, "stage": "public-effects",
            "authority_path": MOD.AUTH_REL.as_posix(), "authority_sha256": MOD.AUTH_SHA256,
            "scope_path": MOD.SCOPE_REL.as_posix(), "scope_sha256": MOD.SCOPE_SHA256,
            "attempt_root": MOD.ROOT_REL.as_posix(), "started_at": started,
            "source_head": "a" * 40, "source_pins": pins,
            "source_payload_sha256": source_hash, "source_reviews": source_reviews,
            "predecessor": {"path": MOD.PREDECESSOR_REL.as_posix(),
                "sha256": predecessor_sha},
            "candidate": candidate, "candidate_reviews": candidate_reviews}
        admission = attempt / "public-admission.json"
        admission.write_text(json.dumps(record, sort_keys=True))
        return attempt, admission, record

    def test_checked_in_public_safe_authority_is_exactly_pinned(self):
        with tempfile.TemporaryDirectory(prefix="single-native-public-authority-") as tmp:
            root = Path(tmp)
            fixture = MOD.public_authority_fixture_bytes()
            self.assertEqual(hashlib.sha256(fixture).hexdigest(), MOD.AUTH_SHA256)
            authority = self._write_public_authority(root)
            self.assertEqual(fixture, authority.read_bytes())
            value = MOD.load_authority(root, MOD.AUTH_REL, MOD.AUTH_SHA256)
            self.assertEqual(value["authority_evidence_sha256"],
                "cf062c97a93818130cdcc580c2e63a8338e9a89bce0c18707d1ad45c85804241")
            self.assertFalse(value["full_qualification_authorized"])
            self.assertFalse(value["merge_authorized"])
            self.assertFalse(value["release_authorized"])
            self.assertFalse(value["next_phase_authorized"])

    def test_iteration_baseline_opens_all_retired_claims_before_allocating_a_fresh_root(self):
        with tempfile.TemporaryDirectory(prefix="single-native-iteration-baseline-") as tmp:
            root = Path(tmp).resolve()
            authority = self._write_iteration_authority(root)
            policy = json.loads(authority.read_text(encoding="utf-8"))
            self.assertEqual(hashlib.sha256(authority.read_bytes()).hexdigest(), MOD.ITERATION_AUTH_SHA256)
            self.assertEqual(policy["attempt_count_limit"], None)
            self.assertFalse(policy["per_attempt_user_approval"])
            self.assertEqual(policy["controller_wall_seconds"], 5400)
            self.assertEqual(policy["job_wall_seconds"], 2700)
            self.assertEqual(policy["setup_wall_seconds"], 600)
            self.assertEqual(len(policy["retired_claims"]), 9)

            baseline_ref = MOD.write_iteration_baseline(root)
            baseline_input = root / MOD.ITERATION_BASELINE_INPUT_REL
            baseline = root / MOD.ITERATION_BASELINE_REL
            self.assertEqual(baseline_ref, {"path": MOD.ITERATION_BASELINE_REL.as_posix(),
                "sha256": MOD.ITERATION_BASELINE_INPUT_SHA256})
            self.assertEqual(baseline.read_bytes(), baseline_input.read_bytes())

            # Each retired claim is still reopened when the public baseline is
            # valid. A changed historical claim must prevent a new attempt.
            for relative in sorted(policy["retired_claims"]):
                target = root / relative
                original = target.read_bytes()
                target.write_bytes(original + b"\nchanged")
                with self.subTest(retired_claim=Path(relative).name), self.assertRaisesRegex(
                        ValueError, "single-native-retired-claim-changed"):
                    MOD.allocate_attempt(root, reason="deterministic retired-claim negative")
                target.write_bytes(original)
                self.assertFalse((root / MOD.ITERATION_POLICY_ROOT_REL / "attempt-0001").exists())

            allocated = MOD.allocate_attempt(root, reason="reviewed source preparation")
            self.assertEqual(allocated["attempt_index"], 1)
            self.assertEqual(allocated["attempt_root_rel"],
                "build/v02/phase7-iterations/attempt-0001")
            self.assertTrue((allocated["attempt_root"] / "allocation.json").is_file())
            # Reopening a completed baseline is byte-stable and leaves its
            # source input and historical records untouched.
            self.assertEqual(MOD.write_iteration_baseline(root), baseline_ref)
            self.assertEqual(baseline.read_bytes(), baseline_input.read_bytes())

    def test_iteration_source_admission_is_revision_bound_and_failed_preparation_advances_immutably(self):
        with tempfile.TemporaryDirectory(prefix="single-native-iteration-revision-") as tmp:
            root = Path(tmp).resolve()
            authority = self._write_iteration_authority(root)
            MOD.write_iteration_baseline(root)
            attempt = MOD.allocate_attempt(root, reason="initial source preparation")
            first = MOD.allocate_revision(root, attempt["attempt_root"],
                reason="reviewed starting source")
            first_admission_path = first["preparation_revision"] / "source-admission.json"
            first_context = MOD.iteration_context(root, authority, first_admission_path)
            first_admission_path, first_record = self._iteration_source_admission_fixture(root, first_context)
            first_admission_raw = first_admission_path.read_bytes()
            first_allocation_raw = (first["preparation_revision"] / "allocation.json").read_bytes()
            accepted = MOD.validate_admission(root, attempt["attempt_root"], first_admission_path,
                stage="source-preparation", source_head=first_record["source_head"],
                source_roster=set(first_record["source_pins"]), authority_path=authority,
                authority_sha256=MOD.ITERATION_AUTH_SHA256,
                admission_sha256=hashlib.sha256(first_admission_raw).hexdigest())
            self.assertEqual(first_context["preparation_revision"], first["preparation_revision"])
            self.assertEqual(accepted["admission"], first_record)

            source_path = root / next(iter(first_record["source_pins"]))
            original_source = source_path.read_bytes()
            source_path.write_bytes(original_source + b"changed")
            with self.assertRaisesRegex(ValueError, "single-native-source-pin-stale"):
                MOD.validate_admission(root, attempt["attempt_root"], first_admission_path,
                    stage="source-preparation", source_head=first_record["source_head"],
                    source_roster=set(first_record["source_pins"]), authority_path=authority,
                    authority_sha256=MOD.ITERATION_AUTH_SHA256,
                    admission_sha256=hashlib.sha256(first_admission_raw).hexdigest())
            source_path.write_bytes(original_source)

            terminal_ref = MOD.write_local_preparation_failure(root, attempt["attempt_root"],
                first["preparation_revision"], source_head=first_record["source_head"],
                stage="source-preparation", reason="source preparation did not complete")
            terminal_raw = (root / terminal_ref["path"]).read_bytes()
            source_path.write_bytes(b"int fixture_source(void) { return 2; }\n")
            second_source_sha = hashlib.sha256(source_path.read_bytes()).hexdigest()
            self.assertNotEqual(second_source_sha, first_record["source_pins"][source_path.relative_to(root).as_posix()])
            second = MOD.allocate_revision(root, attempt["attempt_root"],
                reason="corrected source preparation after retained failure")
            self.assertEqual(second["revision_index"], 2)
            self.assertEqual(second["preparation_allocation"]["predecessor"], terminal_ref)
            self.assertEqual(first_admission_path.read_bytes(), first_admission_raw)
            self.assertEqual((first["preparation_revision"] / "allocation.json").read_bytes(),
                first_allocation_raw)
            self.assertEqual((root / terminal_ref["path"]).read_bytes(), terminal_raw)

            # The latest-only admission path rejects revision1 after revision2
            # is allocated, while the retained source/terminal bytes stay intact.
            with self.assertRaisesRegex(ValueError, "single-native-iteration-revision-not-current"):
                MOD.validate_admission(root, attempt["attempt_root"], first_admission_path,
                    stage="source-preparation", source_head=first_record["source_head"],
                    source_roster=set(first_record["source_pins"]), authority_path=authority,
                    authority_sha256=MOD.ITERATION_AUTH_SHA256,
                    admission_sha256=hashlib.sha256(first_admission_raw).hexdigest())
            retained = MOD.validate_historical_admission(root, attempt["attempt_root"], first_admission_path,
                stage="source-preparation", source_head=first_record["source_head"],
                source_roster=set(first_record["source_pins"]), authority_path=authority,
                authority_sha256=MOD.ITERATION_AUTH_SHA256,
                admission_sha256=hashlib.sha256(first_admission_raw).hexdigest())
            self.assertEqual(retained["preparation_root"], first["preparation_revision"])
            self.assertEqual(retained["admission"], first_record)
            second_path = second["preparation_revision"] / "source-admission.json"
            second_context = MOD.iteration_context(root, authority, second_path)
            second_path, second_record = self._iteration_source_admission_fixture(root,
                second_context, source_head="b" * 40,
                source_bytes=b"int fixture_source(void) { return 2; }\n")
            self.assertEqual(second_record["source_pins"][source_path.relative_to(root).as_posix()], second_source_sha)
            MOD.validate_admission(root, attempt["attempt_root"], second_path,
                stage="source-preparation", source_head=second_record["source_head"],
                source_roster=set(second_record["source_pins"]), authority_path=authority,
                authority_sha256=MOD.ITERATION_AUTH_SHA256,
                admission_sha256=hashlib.sha256(second_path.read_bytes()).hexdigest())
            self.assertEqual(first_admission_path.read_bytes(), first_admission_raw)
            self.assertEqual((root / terminal_ref["path"]).read_bytes(), terminal_raw)

            claim = MOD.iteration_claim_payload(attempt_root=attempt["attempt_root_rel"],
                preparation_revision=second["preparation_revision_rel"], source_sha="b" * 40,
                base_sha="c" * 40, branch="v0.2-source-" + "b" * 12, nonce="d" * 32,
                started_at="2026-11-02T12:00:00+00:00",
                deadline="2026-11-02T13:30:00+00:00", readiness_sha256="e" * 64)
            self.assertEqual((claim["attempt_index"], claim["revision_index"]), (1, 2))
            claim_path = second["attempt_root"] / MOD.ITERATION_CLAIM_LEAF
            with claim_path.open("xb") as stream:
                stream.write((json.dumps(claim, sort_keys=True, indent=2) + "\n").encode())
            with self.assertRaisesRegex(ValueError, "single-native-iteration-claim-already-created"):
                MOD.allocate_revision(root, attempt["attempt_root"], reason="claim must prevent revision reuse")
            self.assertEqual(claim_path.read_bytes(),
                (json.dumps(claim, sort_keys=True, indent=2) + "\n").encode())

    def test_iteration_attempt_allocation_is_exclusive_under_concurrency(self):
        import concurrent.futures
        import threading
        from unittest import mock

        with tempfile.TemporaryDirectory(prefix="single-native-iteration-concurrent-") as tmp:
            root = Path(tmp).resolve()
            self._write_iteration_authority(root)
            MOD.write_iteration_baseline(root)
            original_numbers = MOD._attempt_numbers
            barrier = threading.Barrier(2)

            def observe_same_predecessor(policy_root):
                numbers = original_numbers(policy_root)
                barrier.wait(timeout=5)
                return numbers

            def allocate(reason):
                try:
                    return MOD.allocate_attempt(root, reason=reason)
                except ValueError as exc:
                    return exc

            with mock.patch.object(MOD, "_attempt_numbers", side_effect=observe_same_predecessor):
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                    results = list(executor.map(allocate, ("concurrent preparation A", "concurrent preparation B")))
            successes = [result for result in results if isinstance(result, dict)]
            failures = [result for result in results if isinstance(result, ValueError)]
            self.assertEqual(len(successes), 1)
            self.assertEqual(len(failures), 1)
            self.assertEqual(str(failures[0]), "single-native-iteration-attempt-allocation-unconfirmed")
            attempt_root = root / MOD.ITERATION_POLICY_ROOT_REL / "attempt-0001"
            self.assertTrue((attempt_root / "allocation.json").is_file())
            self.assertTrue((attempt_root / "preparations").is_dir())
            self.assertFalse((root / MOD.ITERATION_POLICY_ROOT_REL / "attempt-0002").exists())

    def test_iteration_prepublication_failure_advances_revision_without_fabricating_ci_or_runtime_closure(self):
        with tempfile.TemporaryDirectory(prefix="single-native-iteration-local-failure-") as tmp:
            root = Path(tmp).resolve()
            self._write_iteration_authority(root)
            MOD.write_iteration_baseline(root)
            attempt = MOD.allocate_attempt(root, reason="local preparation owner")
            revision = MOD.allocate_revision(root, attempt["attempt_root"],
                reason="initial local preparation")
            terminal_ref = MOD.write_local_preparation_failure(root, attempt["attempt_root"],
                revision["preparation_revision"], source_head="a" * 40,
                stage="source-input-snapshot", reason="local preparation failed before publication")
            failure_path = revision["preparation_revision"] / "local-preparation-failure.json"
            failure = json.loads(failure_path.read_text(encoding="utf-8"))
            self.assertEqual(failure["schema"], "genewhip.phase7-native-iteration-local-failure.v1")
            self.assertFalse(failure["publication_attempted"])
            self.assertTrue(failure["dispatch_claim_absent"])
            self.assertFalse(failure["qualification_accepted"])
            self.assertFalse((revision["preparation_revision"] / "source-admission.json").exists())
            self.assertFalse((revision["preparation_revision"] / "source-delivery.json").exists())
            terminal_path = revision["preparation_revision"] / "preparation-terminal.json"
            terminal = json.loads(terminal_path.read_text(encoding="utf-8"))
            self.assertEqual(terminal["status"], "pre-publication-failed")
            self.assertEqual(terminal["evidence_path"], failure_path.relative_to(root).as_posix())
            self.assertEqual(terminal["evidence_sha256"], hashlib.sha256(failure_path.read_bytes()).hexdigest())

            next_revision = MOD.allocate_revision(root, attempt["attempt_root"],
                reason="correct local preparation before source admission")
            self.assertEqual(next_revision["revision_index"], 2)
            self.assertEqual(next_revision["preparation_allocation"]["predecessor"], terminal_ref)
            self.assertEqual(failure_path.read_bytes(),
                (json.dumps(failure, sort_keys=True, indent=2) + "\n").encode())
            # A new numbered runtime attempt is blocked until the prior claimed
            # attempt has a strictly reopened terminal result and settled cleanup.
            with self.assertRaisesRegex(ValueError, "single-native-file-invalid"):
                MOD.allocate_attempt(root, reason="must await terminal result and cleanup")
            self.assertFalse((root / MOD.ITERATION_POLICY_ROOT_REL / "attempt-0002").exists())

    def test_iteration_source_ci_failure_terminal_requires_complete_exact_provider_records(self):
        with tempfile.TemporaryDirectory(prefix="single-native-iteration-ci-closure-") as tmp:
            root = Path(tmp).resolve()
            fixture = self._source_ci_failure_fixture(root)
            jobs = json.loads((root / fixture["refs"]["source_ci_jobs"]["path"]).read_text())
            self.assertEqual(jobs["total_count"], 16)
            self.assertEqual({row["status"] for row in jobs["jobs"]}, {"completed"})
            self.assertEqual([row["name"] for row in jobs["jobs"] if row["conclusion"] == "failure"],
                ["required-ci"])
            terminal_ref = MOD.write_preparation_terminal(root,
                fixture["attempt"]["attempt_root"], fixture["revision"]["preparation_revision"],
                status="source-ci-failed", reason="candidate source CI completed with failure",
                source_head=fixture["source_head"], candidate_head=fixture["candidate_head"],
                pull_request=fixture["pull_request"], evidence_path=fixture["evidence_path"],
                source_ci_workflow=fixture["refs"]["source_ci_workflow"],
                source_ci_jobs=fixture["refs"]["source_ci_jobs"],
                source_ci_pull_request=fixture["refs"]["source_ci_pull_request"])
            terminal = json.loads((root / terminal_ref["path"]).read_text())
            self.assertEqual(terminal["status"], "source-ci-failed")
            self.assertEqual(terminal["remote_cleanup_status"], "confirmed")
            self.assertEqual(terminal["source_ci_jobs"], fixture["refs"]["source_ci_jobs"])
            next_revision = MOD.allocate_revision(root, fixture["attempt"]["attempt_root"],
                reason="completed source CI failure is settled before a corrected revision")
            self.assertEqual(next_revision["revision_index"], 2)
            self.assertEqual(next_revision["preparation_allocation"]["predecessor"], terminal_ref)

        negative_cases = (
            ("active sibling job", "active-sibling", None, "single-native-iteration-source-ci-jobs-unsettled"),
            ("wrong workflow head", "wrong-head", None, "single-native-iteration-source-ci-workflow-unsettled"),
            ("wrong pull request identity", "wrong-pr", None, "single-native-iteration-source-ci-pull-request-invalid"),
            ("missing jobs reference", None, "missing", "single-native-iteration-preparation-ci-reference-invalid"),
            ("misdirected pull request reference", None, "wrong-pr-path", "single-native-iteration-preparation-ci-reference-invalid"))
        for label, mutation, ref_mutation, error in negative_cases:
            with self.subTest(provider_evidence=label), tempfile.TemporaryDirectory(
                    prefix="single-native-iteration-ci-closure-negative-") as tmp:
                root = Path(tmp).resolve()
                fixture = self._source_ci_failure_fixture(root, mutation=mutation)
                refs = dict(fixture["refs"])
                if ref_mutation == "missing":
                    refs["source_ci_jobs"] = None
                elif ref_mutation == "wrong-pr-path":
                    refs["source_ci_pull_request"] = {**refs["source_ci_pull_request"],
                        "path": refs["source_ci_pull_request"]["path"] + ".other"}
                with self.assertRaisesRegex(ValueError, error):
                    MOD.write_preparation_terminal(root,
                        fixture["attempt"]["attempt_root"], fixture["revision"]["preparation_revision"],
                        status="source-ci-failed", reason="candidate source CI evidence negative",
                        source_head=fixture["source_head"], candidate_head=fixture["candidate_head"],
                        pull_request=fixture["pull_request"], evidence_path=fixture["evidence_path"],
                        source_ci_workflow=refs["source_ci_workflow"],
                        source_ci_jobs=refs["source_ci_jobs"],
                        source_ci_pull_request=refs["source_ci_pull_request"])
                self.assertFalse((fixture["revision"]["preparation_revision"]
                    / "preparation-terminal.json").exists())

    def test_iteration_terminal_reader_preserves_attempt1_and_allows_distinct_same_source_attempt2_claim(self):
        with tempfile.TemporaryDirectory(prefix="single-native-iteration-two-attempts-") as tmp:
            root = Path(tmp).resolve()
            authority = self._write_iteration_authority(root)
            MOD.write_iteration_baseline(root)
            runtime_module = root / "scripts/evidence/v02_run.py"
            runtime_module.parent.mkdir(parents=True, exist_ok=True)
            runtime_module.write_bytes((ROOT / "scripts/evidence/v02_run.py").read_bytes())

            first_attempt = MOD.allocate_attempt(root, reason="first same-source diagnostic")
            first_revision = MOD.allocate_revision(root, first_attempt["attempt_root"],
                reason="first reviewed source candidate")
            first_context = MOD.iteration_context(root, authority,
                first_revision["preparation_revision"] / "public-admission.json")
            first_admission, first_record = self._iteration_public_admission_fixture(root,
                first_context, source_head="a" * 40,
                source_bytes=b"int fixture_source(void) { return 1; }\n")
            first_result = self._write_iteration_native_result(root, first_context,
                first_admission, first_record, outcome="fail",
                started_at="2026-11-02T12:00:00+00:00", nonce="1" * 32, run_id=7654321)
            first_terminal_ref = MOD.write_terminal_assessment(root, first_attempt["attempt_root"])
            first_terminal_raw = (root / first_terminal_ref["path"]).read_bytes()
            settled = MOD.validate_result(root, attempt_root=first_attempt["attempt_root"],
                authority_path=authority)
            self.assertEqual((settled["status"], settled["remote_cleanup_status"]),
                ("fail", "confirmed"))
            self.assertFalse(settled["qualification_accepted"])
            with self.assertRaisesRegex(ValueError, "single-native-iteration-claim-already-created"):
                MOD.allocate_revision(root, first_attempt["attempt_root"],
                    reason="claimed revision cannot be replaced")

            second_attempt = MOD.allocate_attempt(root, reason="second justified same-source diagnostic")
            self.assertEqual(second_attempt["attempt_index"], 2)
            second_revision = MOD.allocate_revision(root, second_attempt["attempt_root"],
                reason="same source with a distinct runtime claim")
            second_context = MOD.iteration_context(root, authority,
                second_revision["preparation_revision"] / "public-admission.json")
            second_admission, second_record = self._iteration_public_admission_fixture(root,
                second_context, source_head="a" * 40,
                source_bytes=b"int fixture_source(void) { return 1; }\n")
            second_result = self._write_iteration_native_result(root, second_context,
                second_admission, second_record, outcome="pass",
                started_at="2026-11-02T13:31:00+00:00", nonce="2" * 32, run_id=7654322)
            self.assertEqual(first_result["claim"]["source_sha"], second_result["claim"]["source_sha"])
            self.assertEqual((first_result["claim"]["attempt_index"],
                second_result["claim"]["attempt_index"]), (1, 2))
            self.assertEqual(first_result["claim"]["preparation_revision"],
                first_revision["preparation_revision_rel"])
            self.assertEqual(second_result["claim"]["preparation_revision"],
                second_revision["preparation_revision_rel"])
            self.assertNotEqual(first_result["claim_raw"], second_result["claim_raw"])
            self.assertNotEqual(first_result["claim_sha256"], second_result["claim_sha256"])

            duplicate_anchor = MOD._open_claim_anchor(root, second_context["claim_rel"])
            try:
                with self.assertRaises(FileExistsError):
                    MOD._create_claim_at_anchor(duplicate_anchor,
                        lambda: first_result["claim_raw"])
            finally:
                MOD._close_claim_anchor(duplicate_anchor)
            with self.assertRaisesRegex(ValueError, "single-native-iteration-claim-already-created"):
                MOD.allocate_revision(root, second_attempt["attempt_root"],
                    reason="second attempt claim cannot be rebound to another revision")

            # Historical terminal reading remains available after attempt2 has
            # been allocated, but the current-only admission guard cannot reuse
            # attempt1 readiness to dispatch it again.
            reopened = MOD.validate_result(root, attempt_root=first_attempt["attempt_root"],
                authority_path=authority)
            self.assertEqual((reopened["status"], reopened["remote_cleanup_status"]),
                ("fail", "confirmed"))
            self.assertEqual((root / first_terminal_ref["path"]).read_bytes(), first_terminal_raw)
            with self.assertRaisesRegex(ValueError, "single-native-iteration-attempt-not-current"):
                MOD.validate_admission(root, first_attempt["attempt_root"], first_admission,
                    stage="native-prefix-diagnostic", source_head=first_record["source_head"],
                    source_roster=set(first_record["source_pins"]), authority_path=authority,
                    authority_sha256=MOD.ITERATION_AUTH_SHA256,
                    admission_sha256=hashlib.sha256(first_admission.read_bytes()).hexdigest(),
                    readiness_path=first_result["readiness"],
                    readiness_sha256=hashlib.sha256(first_result["readiness"].read_bytes()).hexdigest())

            # Rehashing a tampered private source admission and its reviews must
            # not make it agree with the immutable public admission/terminal.
            public_admission_raw = first_admission.read_bytes()
            source_admission_path = first_revision["preparation_revision"] / "source-admission.json"
            source_admission = json.loads(source_admission_path.read_text(encoding="utf-8"))
            source_admission["source_pins"]["src/iteration-fixture.c"] = "f" * 64
            source_payload = MOD.source_payload(source_head=source_admission["source_head"],
                started_at=source_admission["started_at"],
                attempt_root=source_admission["attempt_root"],
                source_pins=source_admission["source_pins"],
                predecessor_sha256=source_admission["predecessor"]["sha256"],
                authority_sha256=MOD.ITERATION_AUTH_SHA256,
                preparation_revision=source_admission["preparation_revision"],
                attempt_allocation_sha256=source_admission["attempt_allocation_sha256"])
            source_payload_sha = MOD._digest(MOD._canonical(source_payload))
            source_admission["source_payload_sha256"] = source_payload_sha
            source_reviews = {}
            review_dir = root / ".planning/phases/GW-07-iteration-fixture"
            for reviewer, role in MOD.SOURCE_ROLES.items():
                review = review_dir / f"source-tamper-{reviewer}-{source_payload_sha[:12]}.md"
                raw = (f"---\nstatus: accepted\nreviewer_role: {role}\n"
                    f"payload_sha256: {source_payload_sha}\n---\nSynthetic source review.\n").encode()
                review.write_bytes(raw)
                source_reviews[reviewer] = {"path": review.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(raw).hexdigest(), "reviewer_role": role,
                    "status": "accepted", "payload_sha256": source_payload_sha}
            source_admission["source_reviews"] = source_reviews
            source_admission_path.write_text(json.dumps(source_admission, sort_keys=True), encoding="utf-8")
            terminal_path = root / first_terminal_ref["path"]
            terminal = json.loads(terminal_path.read_text(encoding="utf-8"))
            terminal_body = {key: value for key, value in terminal.items() if key != "record_sha256"}
            terminal_body["source_admission"]["sha256"] = hashlib.sha256(
                source_admission_path.read_bytes()).hexdigest()
            terminal_path.write_bytes(MOD._canonical(MOD._sealed_iteration_record(terminal_body)) + b"\n")
            self.assertEqual(first_admission.read_bytes(), public_admission_raw)
            rejected = MOD.validate_result(root, attempt_root=first_attempt["attempt_root"],
                authority_path=authority)
            self.assertEqual(rejected["status"], "unknown")

    def test_iteration_unsealed_claim_and_uncertain_cleanup_keep_next_attempt_blocked(self):
        with tempfile.TemporaryDirectory(prefix="single-native-iteration-uncertain-cleanup-") as tmp:
            root = Path(tmp).resolve()
            authority = self._write_iteration_authority(root)
            MOD.write_iteration_baseline(root)
            runtime_module = root / "scripts/evidence/v02_run.py"
            runtime_module.parent.mkdir(parents=True, exist_ok=True)
            runtime_module.write_bytes((ROOT / "scripts/evidence/v02_run.py").read_bytes())

            attempt = MOD.allocate_attempt(root, reason="cleanup closure remains required")
            revision = MOD.allocate_revision(root, attempt["attempt_root"],
                reason="reviewed candidate for uncertain cleanup test")
            context = MOD.iteration_context(root, authority,
                revision["preparation_revision"] / "public-admission.json")
            admission, record = self._iteration_public_admission_fixture(root, context)
            result = self._write_iteration_native_result(root, context, admission, record,
                outcome="fail", started_at="2026-11-02T15:00:00+00:00",
                nonce="3" * 32, run_id=7654323)

            # A current O_EXCL claim with no terminal closure keeps the next
            # runtime attempt unavailable even when result files exist.
            with self.assertRaises(ValueError):
                MOD.allocate_attempt(root, reason="unsealed claim must block the next attempt")
            self.assertFalse((root / MOD.ITERATION_POLICY_ROOT_REL / "attempt-0002").exists())

            dispatch_path = result["runtime_root"] / "dispatch.json"
            dispatch = json.loads(dispatch_path.read_text(encoding="utf-8"))
            dispatch["remote_cleanup_status"] = "unknown"
            dispatch_path.write_text(json.dumps(dispatch, sort_keys=True), encoding="utf-8")
            assessment = MOD.validate_result(root, attempt_root=attempt["attempt_root"],
                authority_path=authority)
            self.assertEqual(assessment["status"], "unknown")
            self.assertNotEqual(assessment.get("remote_cleanup_status"), "confirmed")
            with self.assertRaisesRegex(ValueError,
                    "single-native-iteration-terminal-result-not-settled"):
                MOD.write_terminal_assessment(root, attempt["attempt_root"])
            with self.assertRaises(ValueError):
                MOD.allocate_attempt(root, reason="unknown cleanup must block the next attempt")
            self.assertFalse((root / MOD.ITERATION_POLICY_ROOT_REL / "attempt-0002").exists())

    def test_iteration_terminal_reopen_requires_explicit_confirmed_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="single-native-iteration-missing-cleanup-") as tmp:
            root = Path(tmp).resolve()
            authority = self._write_iteration_authority(root)
            MOD.write_iteration_baseline(root)
            runtime_module = root / "scripts/evidence/v02_run.py"
            runtime_module.parent.mkdir(parents=True, exist_ok=True)
            runtime_module.write_bytes((ROOT / "scripts/evidence/v02_run.py").read_bytes())
            attempt = MOD.allocate_attempt(root, reason="explicit cleanup must be retained")
            revision = MOD.allocate_revision(root, attempt["attempt_root"],
                reason="reviewed candidate for cleanup-reopen contract")
            context = MOD.iteration_context(root, authority,
                revision["preparation_revision"] / "public-admission.json")
            started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            admission, record = self._iteration_public_admission_fixture(root, context,
                started_at=started_at)
            result = self._write_iteration_native_result(root, context, admission, record,
                outcome="pass", started_at=started_at, nonce="4" * 32, run_id=7654324)
            terminal_ref = MOD.write_terminal_assessment(root, attempt["attempt_root"])

            dispatch_path = result["runtime_root"] / "dispatch.json"
            dispatch = json.loads(dispatch_path.read_text(encoding="utf-8"))
            self.assertEqual(dispatch.get("remote_cleanup_status"), "confirmed")
            dispatch.pop("remote_cleanup_status")
            dispatch_path.write_text(json.dumps(dispatch, sort_keys=True), encoding="utf-8")
            terminal_path = root / terminal_ref["path"]
            terminal = json.loads(terminal_path.read_text(encoding="utf-8"))
            body = {key: value for key, value in terminal.items() if key != "record_sha256"}
            body["dispatch_sha256"] = hashlib.sha256(dispatch_path.read_bytes()).hexdigest()
            terminal_path.write_bytes(MOD._canonical(MOD._sealed_iteration_record(body)) + b"\n")

            reopened = MOD.validate_result(root, attempt_root=attempt["attempt_root"],
                authority_path=authority)
            self.assertEqual(reopened["status"], "unknown")
            self.assertNotEqual(reopened.get("remote_cleanup_status"), "confirmed")

    def test_iteration_terminal_reopen_revalidates_report_cleanup_and_bound_facts(self):
        mutations = (
            ("outer-cleanup", lambda report: report["outer_process"].update(cleanup="unconfirmed")),
            ("child-bound", lambda report: report["stages"][0]["process"].update(
                bound_violation=True)),
            ("missing-input-child-receipt", lambda report: report["stages"][0].update(
                process={"status": "unavailable", "return_code": "missing",
                    "cleanup": "unavailable", "bound_violation": None})),
            ("missing-headless-full-route-receipt", lambda report: report["stages"][1]["cases"][0].update(
                process={"status": "unavailable", "return_code": "missing",
                    "cleanup": "unavailable", "bound_violation": None})),
            ("missing-headless-withhold-receipt", lambda report: report["stages"][1]["cases"][1].update(
                process={"status": "unavailable", "return_code": "missing",
                    "cleanup": "unavailable", "bound_violation": None})),
            ("missing-native-full-route-receipt", lambda report: report["stages"][2]["cases"][0].update(
                process={"status": "unavailable", "return_code": "missing",
                    "cleanup": "unavailable", "bound_violation": None})),
            ("missing-native-withhold-receipt", lambda report: report["stages"][2]["cases"][1].update(
                process={"status": "unavailable", "return_code": "missing",
                    "cleanup": "unavailable", "bound_violation": None})),
        )
        for label, mutate in mutations:
            with self.subTest(report_fact=label), tempfile.TemporaryDirectory(
                    prefix="single-native-iteration-report-reopen-") as tmp:
                root = Path(tmp).resolve()
                authority = self._write_iteration_authority(root)
                MOD.write_iteration_baseline(root)
                runtime_module = root / "scripts/evidence/v02_run.py"
                runtime_module.parent.mkdir(parents=True, exist_ok=True)
                runtime_module.write_bytes((ROOT / "scripts/evidence/v02_run.py").read_bytes())
                attempt = MOD.allocate_attempt(root, reason="reopen must verify process evidence")
                revision = MOD.allocate_revision(root, attempt["attempt_root"],
                    reason="reviewed candidate for terminal report validation")
                context = MOD.iteration_context(root, authority,
                    revision["preparation_revision"] / "public-admission.json")
                started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
                admission, record = self._iteration_public_admission_fixture(root, context,
                    started_at=started_at)
                result = self._write_iteration_native_result(root, context, admission, record,
                    outcome="pass", started_at=started_at, nonce="5" * 32, run_id=7654325)
                terminal_ref = MOD.write_terminal_assessment(root, attempt["attempt_root"])

                report_path = result["runtime_root"] / "download/native-prefix-diagnostic.json"
                report = json.loads(report_path.read_text(encoding="utf-8"))
                mutate(report)
                if label.startswith("missing-"):
                    self.assertEqual(report["outer_process"]["cleanup"], "confirmed")
                    self.assertFalse(MOD._native_prefix_process_cleanup_is_confirmed(report))
                report_path.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
                result_path = result["runtime_root"] / "result.json"
                result_value = json.loads(result_path.read_text(encoding="utf-8"))
                result_value["report_sha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
                result_path.write_text(json.dumps(result_value, sort_keys=True), encoding="utf-8")
                terminal_path = root / terminal_ref["path"]
                terminal_value = json.loads(terminal_path.read_text(encoding="utf-8"))
                body = {key: value for key, value in terminal_value.items()
                    if key != "record_sha256"}
                body["report"]["sha256"] = result_value["report_sha256"]
                body["result_sha256"] = hashlib.sha256(result_path.read_bytes()).hexdigest()
                terminal_path.write_bytes(MOD._canonical(MOD._sealed_iteration_record(body)) + b"\n")

                reopened = MOD.validate_result(root, attempt_root=attempt["attempt_root"],
                    authority_path=authority)
                self.assertEqual(reopened["status"], "unknown")
                self.assertFalse(reopened["qualification_accepted"])

    def test_iteration_partial_attempt_allocation_is_preserved_and_blocks_the_next_attempt(self):
        from unittest import mock

        with tempfile.TemporaryDirectory(prefix="single-native-iteration-partial-") as tmp:
            root = Path(tmp).resolve()
            self._write_iteration_authority(root)
            MOD.write_iteration_baseline(root)
            original_write = MOD._write_iteration_record

            def fail_allocation_record(write_root, relative, value):
                if relative == MOD.ITERATION_POLICY_ROOT_REL / "attempt-0001/allocation.json":
                    raise OSError("controlled partial allocation")
                return original_write(write_root, relative, value)

            with mock.patch.object(MOD, "_write_iteration_record", side_effect=fail_allocation_record):
                with self.assertRaisesRegex(OSError, "controlled partial allocation"):
                    MOD.allocate_attempt(root, reason="fixture leaves allocated path")
            partial = root / MOD.ITERATION_POLICY_ROOT_REL / "attempt-0001"
            self.assertTrue(partial.is_dir())
            self.assertTrue((partial / "preparations").is_dir())
            self.assertFalse((partial / "allocation.json").exists())
            with self.assertRaisesRegex(ValueError, "single-native-file-invalid"):
                MOD.allocate_attempt(root, reason="must wait for settled predecessor")
            self.assertFalse((root / MOD.ITERATION_POLICY_ROOT_REL / "attempt-0002").exists())

    def test_iteration_claim_anchor_rejects_attempt_ancestor_swap_before_exclusive_create(self):
        with tempfile.TemporaryDirectory(prefix="single-native-iteration-claim-swap-") as tmp:
            root = Path(tmp).resolve()
            authority = self._write_iteration_authority(root)
            MOD.write_iteration_baseline(root)
            attempt = MOD.allocate_attempt(root, reason="claim anchor fixture")
            revision = MOD.allocate_revision(root, attempt["attempt_root"], reason="claim anchor revision")
            admission_path = revision["preparation_revision"] / "source-admission.json"
            context = MOD.iteration_context(root, authority, admission_path)
            relative = Path(context["claim_rel"])
            anchor = MOD._open_claim_anchor(root, relative)
            attempt_root = attempt["attempt_root"]
            moved = attempt_root.with_name("attempt-0001-held")
            try:
                attempt_root.rename(moved)
                attempt_root.symlink_to(moved, target_is_directory=True)
                with self.assertRaisesRegex(ValueError, "single-native-iteration-attempt-root-invalid"):
                    MOD.iteration_context(root, authority, admission_path)
                with self.assertRaisesRegex(ValueError, "single-native-claim-parent-invalid"):
                    MOD._create_claim_at_anchor(anchor, lambda: b"synthetic claim\n")
                self.assertFalse((moved / MOD.ITERATION_CLAIM_LEAF).exists())
            finally:
                MOD._close_claim_anchor(anchor)
                if attempt_root.is_symlink():
                    attempt_root.unlink()
                if moved.exists():
                    moved.rename(attempt_root)
            self.assertFalse((attempt_root / MOD.ITERATION_CLAIM_LEAF).exists())

    def test_repair_authority_keeps_the_original_shared_claim_anchor(self):
        self.assertEqual(MOD.AUTH_REL.as_posix(),
            "build/v02/native-capture-retest-20261102T034752Z-repair/authorization-contract.json")
        self.assertEqual(MOD.CLAIM_REL.as_posix(),
            "build/v02/native-capture-retest-20261102T034752Z/native-dispatch-claim.json")
        self.assertEqual(MOD.LOCAL_CLAIM_REL.as_posix(),
            "build/v02/native-capture-retest-20261102T034752Z-repair/native-dispatch-claim.json")
        self.assertEqual(MOD.PREVIOUS_ATTEMPT_REL.as_posix(),
            "build/v02/native-capture-retest-20261102T034752Z/attempt-0003")
        with tempfile.TemporaryDirectory(prefix="single-native-lineage-anchor-") as tmp:
            root = Path(tmp).resolve()
            self._write_public_authority(root)
            self.assertTrue((root / MOD.AUTH_REL).is_file())
            self.assertTrue((root / MOD.CLAIM_REL).parent.is_dir())
            self.assertFalse((root / MOD.CLAIM_REL).exists())
            self.assertFalse((root / MOD.LOCAL_CLAIM_REL).exists())

    def test_shared_claim_anchor_rejects_parent_swaps_and_competing_exclusive_create(self):
        from unittest import mock
        payload = b"exclusive shared claim fixture\n"
        with tempfile.TemporaryDirectory(prefix="single-native-anchor-exclusive-") as tmp:
            root = Path(tmp).resolve()
            self._write_public_authority(root)
            before_fds = len(os.listdir("/dev/fd"))
            anchor = MOD._open_claim_anchor(root, MOD.CLAIM_REL)
            try:
                created, digest = MOD._create_claim_at_anchor(anchor, lambda: payload)
                self.assertEqual(created, payload)
                self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
                with self.assertRaises(FileExistsError):
                    MOD._create_claim_at_anchor(anchor, lambda: b"must not replace\n")
                self.assertEqual(MOD._verify_claim_at_anchor(anchor), payload)
                self.assertEqual((root / MOD.CLAIM_REL).read_bytes(), payload)
            finally:
                MOD._close_claim_anchor(anchor)
            self.assertEqual(len(os.listdir("/dev/fd")), before_fds)

        # A path that was validated earlier cannot redirect the later open.
        with tempfile.TemporaryDirectory(prefix="single-native-anchor-before-create-") as tmp:
            root = Path(tmp).resolve()
            self._write_public_authority(root)
            MOD._validated_claim_path(root, MOD.CLAIM_REL)
            parent = (root / MOD.CLAIM_REL).parent
            saved = root / "shared-claim-parent-saved"
            decoy = root / "shared-claim-parent-decoy"
            parent.rename(saved)
            decoy.mkdir()
            parent.symlink_to(decoy, target_is_directory=True)
            before_fds = len(os.listdir("/dev/fd"))
            with self.assertRaisesRegex(ValueError, "single-native-claim-parent-invalid"):
                MOD._open_claim_anchor(root, MOD.CLAIM_REL)
            self.assertEqual(len(os.listdir("/dev/fd")), before_fds)
            self.assertFalse((saved / MOD.CLAIM_REL.name).exists())
            self.assertFalse((decoy / MOD.CLAIM_REL.name).exists())

        # A rename after O_EXCL keeps the created bytes in the pinned directory,
        # then the name recheck fails before the coordinator can dispatch.
        with tempfile.TemporaryDirectory(prefix="single-native-anchor-after-create-") as tmp:
            root = Path(tmp).resolve()
            self._write_public_authority(root)
            parent = (root / MOD.CLAIM_REL).parent
            saved = root / "shared-claim-parent-saved"
            decoy = root / "shared-claim-parent-decoy"
            original = parent.stat()
            anchor = MOD._open_claim_anchor(root, MOD.CLAIM_REL)
            real_fsync = os.fsync
            swapped = False

            def fsync_then_swap(descriptor):
                nonlocal swapped
                result = real_fsync(descriptor)
                info = os.fstat(descriptor)
                if not swapped and (info.st_dev, info.st_ino) == (original.st_dev, original.st_ino):
                    parent.rename(saved)
                    decoy.mkdir()
                    parent.symlink_to(decoy, target_is_directory=True)
                    swapped = True
                return result

            try:
                with mock.patch.object(os, "fsync", side_effect=fsync_then_swap):
                    with self.assertRaisesRegex(ValueError, "single-native-claim-parent-invalid"):
                        MOD._create_claim_at_anchor(anchor, lambda: payload)
                self.assertTrue(swapped)
                self.assertEqual((saved / MOD.CLAIM_REL.name).read_bytes(), payload)
                self.assertFalse((decoy / MOD.CLAIM_REL.name).exists())
            finally:
                MOD._close_claim_anchor(anchor)

    def test_claim_leaf_regular_to_fifo_race_is_nonblocking_and_fails_closed(self):
        from unittest import mock
        payload = b"regular shared claim fixture\n"
        with tempfile.TemporaryDirectory(prefix="single-native-anchor-fifo-race-") as tmp:
            root = Path(tmp).resolve()
            self._write_public_authority(root)
            anchor = MOD._open_claim_anchor(root, MOD.CLAIM_REL)
            backup_name = anchor["leaf"] + ".saved"
            backup_path = (root / MOD.CLAIM_REL).with_name(backup_name)
            try:
                MOD._create_claim_at_anchor(anchor, lambda: payload)
                real_open = os.open
                replaced = False

                def replace_regular_with_fifo(path, flags, mode=0o777, *, dir_fd=None):
                    nonlocal replaced
                    if (not replaced and path == anchor["leaf"]
                            and dir_fd == anchor["parent_fd"]):
                        os.rename(path, backup_name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
                        os.mkfifo(path, 0o600, dir_fd=dir_fd)
                        replaced = True
                        if not flags & getattr(os, "O_NONBLOCK", 0):
                            raise AssertionError("claim reader opened a substituted FIFO in blocking mode")
                    return real_open(path, flags, mode, dir_fd=dir_fd)

                started = time.monotonic()
                with mock.patch.object(os, "open", side_effect=replace_regular_with_fifo):
                    with self.assertRaisesRegex(ValueError, "single-native-claim-file-invalid"):
                        MOD._verify_claim_at_anchor(anchor)
                self.assertTrue(replaced)
                self.assertLess(time.monotonic() - started, 1.0)
                self.assertEqual(backup_path.read_bytes(), payload)
            finally:
                MOD._close_claim_anchor(anchor)

    def test_authority_path_digest_scope_and_bytes_are_not_caller_selectable(self):
        with tempfile.TemporaryDirectory(prefix="single-native-public-authority-negative-") as tmp:
            root = Path(tmp)
            self._write_public_authority(root)
            for path, digest, label in (
                (root / "build/v02/ci-continuation-old/authorization.json",
                 MOD.AUTH_SHA256, "single-native-authority-path-invalid"),
                (root / "build/v02/native-prefix-one-shot-20261101T112701Z/authorization-contract.json",
                 MOD.AUTH_SHA256, "single-native-authority-path-invalid"),
                (root / "build/v02/native-media-retest-20261101T143706Z/authorization-contract.json",
                 MOD.AUTH_SHA256, "single-native-authority-path-invalid"),
                (root / "build/v02/native-stop-context-20261101T161645Z/authorization-contract.json",
                 MOD.AUTH_SHA256, "single-native-authority-path-invalid"),
                (root / "build/v02/native-complete-setup-retest-20261102T000552Z/authorization-contract.json",
                 MOD.AUTH_SHA256, "single-native-authority-path-invalid"),
                (root / "build/v02/native-capture-retest-20261102T034752Z/authorization-contract.json",
                 MOD.AUTH_SHA256, "single-native-authority-path-invalid"),
                (MOD.AUTH_REL, "0" * 64, "single-native-authority-pin-invalid"),
            ):
                with self.subTest(label=label), self.assertRaisesRegex(ValueError, label):
                    MOD.load_authority(root, path, digest)
            (root / MOD.SCOPE_REL).write_bytes(b"{}\n")
            with self.assertRaisesRegex(ValueError, "single-native-scope-pin-invalid"):
                MOD.load_authority(root, MOD.AUTH_REL, MOD.AUTH_SHA256)

    def test_attempt_root_is_fixed_and_exclusive(self):
        with tempfile.TemporaryDirectory(prefix="single-native-root-") as tmp:
            root = Path(tmp)
            good = root / MOD.ROOT_REL
            good.mkdir(parents=True)
            self.assertEqual(MOD.ROOT_REL.name, "attempt-0003")
            self.assertEqual(MOD.canonical_root(root, MOD.ROOT_REL), good.resolve())
            with self.assertRaisesRegex(ValueError, "single-native-attempt-root-invalid"):
                MOD.canonical_root(root, MOD.AUTH_REL.parent / "attempt-0021")

    def test_symlink_and_hardlink_files_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="single-native-contract-") as tmp:
            base = Path(tmp)
            outside = base / "outside.json"
            outside.write_text("{}")
            root = base / "root"
            root.mkdir()
            (root / "link.json").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "single-native-path-symlink"):
                MOD._safe_file(root, "link.json")
            (root / "hard.json").hardlink_to(outside)
            with self.assertRaisesRegex(ValueError, "single-native-file-invalid"):
                MOD._safe_file(root, "hard.json")

    def test_contract_payloads_are_directional_and_reproducible(self):
        source = MOD.source_payload(source_head="a" * 40, started_at="2026-11-01T11:27:01Z",
            attempt_root=MOD.ROOT_REL.as_posix(), source_pins={"src/a.c": "b" * 64},
            predecessor_sha256="9" * 64)
        candidate = {"preparation_sha256": "c" * 64, "repository_policy_sha256": "d" * 64,
            "public_head": "e" * 40, "public_base": "f" * 40, "public_tree": "1" * 40,
            "source_manifest_sha256": "2" * 64}
        payload = MOD.candidate_payload(source, candidate)
        self.assertEqual(payload["source_payload_sha256"], hashlib.sha256(
            json.dumps(source, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
        self.assertNotIn("candidate_payload_sha256", payload)
        self.assertNotIn("candidate_reviews", payload)

    def test_queue_clock_projection_is_conservative_and_fixed(self):
        claim_start = "2026-11-01T18:00:00+00:00"
        claim_end = "2026-11-01T19:30:00+00:00"
        started = "2026-11-01T18:01:00+00:00"
        server_date = "2026-11-01T18:01:05+00:00"
        response_end = 10_000_000_000_000
        projection = MOD.queue_clock_projection(claim_started_at=claim_start,
            claim_deadline=claim_end, job_started_at=started, server_date=server_date,
            round_trip_ns=2_000_000_000, response_received_monotonic_ns=response_end,
            local_request_started_at="2026-11-01T18:01:03+00:00",
            local_response_at="2026-11-01T18:01:05+00:00")
        # Date is second precision, so the effective elapsed upper bound is 8 seconds.
        self.assertEqual(projection["job_started_monotonic_ns"], response_end - 8_000_000_000)
        self.assertEqual(projection["job_deadline_monotonic_ns"],
            response_end - 8_000_000_000 + 2700 * 1_000_000_000)
        self.assertEqual(projection["job_cleanup_deadline_monotonic_ns"],
            projection["job_deadline_monotonic_ns"] - 30 * 1_000_000_000)
        self.assertEqual(projection["collector_start_cutoff_monotonic_ns"],
            projection["collector_deadline_monotonic_ns"] - 1800 * 1_000_000_000)
        for kwargs in (
                {"claim_deadline": "2026-11-01T18:45:00+00:00"},
                {"job_started_at": "2026-11-01T18:01:07+00:00"},
                {"server_date": "2026-11-01T18:00:00+00:00"},
                {"server_date": "2026-11-01T18:02:06+00:00"},
                {"round_trip_ns": True},
                {"round_trip_ns": 61_000_000_000},
                {"local_request_started_at": "2026-11-01T18:01:06+00:00"},
                {"claim_started_at": "2026-11-01T18:00:00"}):
            values = {"claim_started_at": claim_start, "claim_deadline": claim_end,
                "job_started_at": started, "server_date": server_date,
                "round_trip_ns": 2_000_000_000,
                "response_received_monotonic_ns": response_end,
                "local_request_started_at": "2026-11-01T18:01:03+00:00",
                "local_response_at": "2026-11-01T18:01:05+00:00"}
            values.update(kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                MOD.queue_clock_projection(**values)
        same_second = MOD.queue_clock_projection(claim_started_at=claim_start,
            claim_deadline=claim_end, job_started_at="2026-11-01T18:01:05.900000+00:00",
            server_date="2026-11-01T18:01:05+00:00", round_trip_ns=2_000_000_000,
            response_received_monotonic_ns=response_end,
            local_request_started_at="2026-11-01T18:01:03+00:00",
            local_response_at="2026-11-01T18:01:05+00:00")
        self.assertEqual(same_second["job_started_monotonic_ns"], response_end - 2_100_000_000)
        stale_but_conservative = MOD.queue_clock_projection(claim_started_at=claim_start,
            claim_deadline=claim_end, job_started_at="2026-11-01T18:01:00+00:00",
            server_date="2026-11-01T18:01:01+00:00", round_trip_ns=2_000_000_000,
            response_received_monotonic_ns=response_end,
            local_request_started_at="2026-11-01T18:01:58+00:00",
            local_response_at="2026-11-01T18:02:00+00:00")
        self.assertEqual(stale_but_conservative["job_started_monotonic_ns"],
            response_end - 60 * 1_000_000_000)

    def test_real_admission_validator_checks_complete_candidate_and_rejects_forgery(self):
        with tempfile.TemporaryDirectory(prefix="single-native-admission-") as tmp:
            root = Path(tmp)
            attempt, admission, record = self._admission_fixture(root)
            gitdir = attempt / "publication/.git"
            gitdir.mkdir()
            (gitdir / "config").write_text("synthetic git metadata\n")
            roster = {"src/source.c"}
            digest = hashlib.sha256(admission.read_bytes()).hexdigest()
            accepted = MOD.validate_admission(root, MOD.ROOT_REL, admission,
                stage="public-effects", source_head="a" * 40, source_roster=roster,
                authority_path=MOD.AUTH_REL, authority_sha256=MOD.AUTH_SHA256,
                admission_sha256=digest)
            self.assertEqual(accepted["candidate"]["public_head"], "b" * 40)
            nested_git = attempt / "publication/sub/.git"
            nested_git.mkdir(parents=True)
            (nested_git / "config").write_text("nested metadata\n")
            with self.assertRaisesRegex(ValueError, "single-native-publication-entry-invalid"):
                MOD.validate_admission(root, MOD.ROOT_REL, admission,
                    stage="public-effects", source_head="a" * 40, source_roster=roster,
                    authority_path=MOD.AUTH_REL, authority_sha256=MOD.AUTH_SHA256,
                    admission_sha256=digest)
            (nested_git / "config").unlink()
            nested_git.rmdir()
            (nested_git.parent).rmdir()
            forged = dict(record)
            forged["source_pins"] = {"src/source.c": "0" * 64}
            admission.write_text(json.dumps(forged, sort_keys=True))
            with self.assertRaisesRegex(ValueError, "single-native-source-pin-stale"):
                MOD.validate_admission(root, MOD.ROOT_REL, admission,
                    stage="public-effects", source_head="a" * 40, source_roster=roster,
                    authority_path=MOD.AUTH_REL, authority_sha256=MOD.AUTH_SHA256,
                    admission_sha256=hashlib.sha256(admission.read_bytes()).hexdigest())

    def test_route_paths_reject_existing_hardlink_aliases(self):
        with tempfile.TemporaryDirectory(prefix="single-native-route-") as tmp:
            root = Path(tmp).resolve()
            attempt = root / MOD.ROOT_REL
            attempt.mkdir(parents=True)
            first = attempt / "input.json"
            first.write_text("{}")
            second = attempt / "output.json"
            second.hardlink_to(first)
            with self.assertRaisesRegex(ValueError, "single-native-route-file-alias"):
                MOD.validate_route_paths(root, [first, second])

    def test_route_outputs_must_be_new_and_distinct_from_consumed_inputs(self):
        with tempfile.TemporaryDirectory(prefix="single-native-output-") as tmp:
            root = Path(tmp).resolve()
            attempt = root / MOD.ROOT_REL
            attempt.mkdir(parents=True)
            source = attempt / "input.json"
            source.write_text("{}")
            MOD.validate_route_paths(root, [attempt])
            with self.assertRaisesRegex(ValueError, "single-native-route-output-stale"):
                MOD.validate_route_paths(root, [source], outputs=[source])
            output = attempt / "new.json"
            MOD.validate_route_paths(root, [source], outputs=[output])

    def test_denied_effect_guards_self_test_before_production_import(self):
        self.assertEqual(DENIED_EFFECTS, ["subprocess.selftest", "socket.selftest", "ctypes.selftest"])

    def test_terminal_assessment_requires_supported_report_workflow_pair(self):
        self.assertTrue(MOD.terminal_conclusion_matches("pass", "success"))
        self.assertTrue(MOD.terminal_conclusion_matches("fail", "failure"))
        for report, conclusion in (("pass", "failure"), ("fail", "success"),
                ("pass", "cancelled"), ("fail", "skipped"), ("pass", "neutral")):
            self.assertFalse(MOD.terminal_conclusion_matches(report, conclusion))

    def test_positive_preview_assessment_joins_actual_fixture_bytes(self):
        with tempfile.TemporaryDirectory(prefix="single-native-preview-") as tmp:
            root = Path(tmp)
            attempt, admission, record = self._admission_fixture(root)
            candidate = record["candidate"]
            source = {"source_head": record["source_head"], "started_at": record["started_at"],
                "source_payload_sha256": record["source_payload_sha256"]}
            source_path = attempt / "source-admission.json"
            source_path.write_text(json.dumps(source, sort_keys=True))
            jobs = [{"id": i + 1, "name": name, "status": "completed",
                "conclusion": "success" if name in MOD.PREVIEW_REQUIRED else "skipped"}
                for i, name in enumerate(sorted(MOD.PREVIEW_REQUIRED | MOD.PREVIEW_SKIPPED))]
            blobs = {
                "source-delivery.json": {"status": "diagnostic-ci-complete", "repository": "szTheory/genewhip",
                    "diagnostic_only": True,
                    "assessment_required": True, "merge_attempted": False,
                    "candidate_sha": candidate["public_head"],
                    "public_base_sha": candidate["public_base"], "pull_request": "46"},
                "hosted-delivery-journal.json": {"repository": "szTheory/genewhip",
                    "branch": "v0.2-source-" + candidate["public_head"][:12], "push_performed": True,
                    "source_head": candidate["public_head"], "public_base_sha": candidate["public_base"],
                    "started_at": PUBLIC_STARTED_AT, "diagnostic_only": True,
                    "diagnostic_ci_status": "passed", "assessment_required": True,
                    "merge_attempted": False, "pull_request": "46"},
            }
            refs = {}
            for filename, value in blobs.items():
                path = attempt / filename
                path.write_text(json.dumps(value, sort_keys=True))
                refs[filename] = {"path": path.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            packet = {"disposition": "diagnostic-preview-green-assessment-required",
                "qualification_credit": False,
                "source_and_candidate": {"source_admission_path": source_path.relative_to(root).as_posix(),
                    "source_admission_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
                    "public_admission_path": admission.relative_to(root).as_posix(),
                    "public_admission_sha256": hashlib.sha256(admission.read_bytes()).hexdigest(),
                    "private_source_head": record["source_head"], "candidate_head": candidate["public_head"],
                    "public_head": candidate["public_head"], "public_base": candidate["public_base"],
                    "public_tree": candidate["public_tree"],
                    "manifest_sha256": candidate["source_manifest_sha256"],
                    "preparation_sha256": candidate["preparation_sha256"],
                    "candidate_review_payload_sha256": candidate["candidate_payload_sha256"]},
                "hosted_source_delivery": {
                    "source_delivery_path": refs["source-delivery.json"]["path"],
                    "source_delivery_sha256": refs["source-delivery.json"]["sha256"],
                    "journal_path": refs["hosted-delivery-journal.json"]["path"],
                    "journal_sha256": refs["hosted-delivery-journal.json"]["sha256"],
                    },
                "github": {"repository": "szTheory/genewhip", "pull_request": 46,
                    "pull_request_state": "open", "merged": False,
                    "head_sha": candidate["public_head"], "base_sha": candidate["public_base"],
                    "workflow_run": {"id": 99, "run_attempt": 1, "event": "pull_request",
                        "status": "completed", "conclusion": "success",
                        "workflow_path": ".github/workflows/ci.yml"}, "jobs": jobs}}
            packet_path = attempt / "ci-failure/assessment.json"
            packet_path.parent.mkdir()
            packet_path.write_text(json.dumps(packet, sort_keys=True))
            ref = {"path": packet_path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(packet_path.read_bytes()).hexdigest()}
            accepted = MOD.validate_preview_assessment(root, ref, attempt=attempt,
                candidate=candidate, admission_path=admission,
                admission_sha256=hashlib.sha256(admission.read_bytes()).hexdigest())
            self.assertEqual(accepted["workflow_run"]["id"], 99)
            self.assertEqual(len(accepted["jobs"]), 16)
            journal_path = attempt / "hosted-delivery-journal.json"
            original_journal = journal_path.read_bytes()
            original_journal_sha = hashlib.sha256(original_journal).hexdigest()
            for value, expected_error in (("2026-11-01T11:00:00+00:00",
                    "single-native-readiness-publication-clock-backdated"),
                    ("2026-11-01T13:09:15", "single-native-readiness-publication-clock-invalid")):
                changed_journal = json.loads(original_journal)
                changed_journal["started_at"] = value
                journal_path.write_text(json.dumps(changed_journal, sort_keys=True))
                packet["hosted_source_delivery"]["journal_sha256"] = hashlib.sha256(
                    journal_path.read_bytes()).hexdigest()
                packet_path.write_text(json.dumps(packet, sort_keys=True))
                bad_ref = {"path": ref["path"],
                    "sha256": hashlib.sha256(packet_path.read_bytes()).hexdigest()}
                with self.assertRaisesRegex(ValueError, expected_error):
                    MOD.validate_preview_assessment(root, bad_ref, attempt=attempt,
                        candidate=candidate, admission_path=admission,
                        admission_sha256=hashlib.sha256(admission.read_bytes()).hexdigest())
            journal_path.write_bytes(original_journal)
            packet["hosted_source_delivery"]["journal_sha256"] = original_journal_sha
            packet_path.write_text(json.dumps(packet, sort_keys=True))
            ref["sha256"] = hashlib.sha256(packet_path.read_bytes()).hexdigest()
            (attempt / "failure.json").write_text("{}")
            with self.assertRaises(ValueError):
                MOD.validate_preview_assessment(root, ref, attempt=attempt,
                    candidate=candidate, admission_path=admission,
                    admission_sha256=hashlib.sha256(admission.read_bytes()).hexdigest())
            (attempt / "failure.json").unlink()
            for change in (
                lambda p: p["github"]["workflow_run"].update(workflow_path="other.yml"),
                lambda p: p["github"]["jobs"].pop(),
                lambda p: p["github"]["jobs"][0].update(conclusion="success"),
                lambda p: p["github"].update(base_sha="f" * 40),
            ):
                forged = json.loads(json.dumps(packet))
                change(forged)
                packet_path.write_text(json.dumps(forged, sort_keys=True))
                bad_ref = {"path": ref["path"], "sha256": hashlib.sha256(packet_path.read_bytes()).hexdigest()}
                with self.assertRaises(ValueError):
                    MOD.validate_preview_assessment(root, bad_ref, attempt=attempt,
                        candidate=candidate, admission_path=admission,
                        admission_sha256=hashlib.sha256(admission.read_bytes()).hexdigest())

    def test_terminal_assessment_reports_missing_and_partial_evidence_as_unknown(self):
        with tempfile.TemporaryDirectory(prefix="single-native-terminal-") as tmp:
            root = Path(tmp).resolve()
            self._write_public_authority(root)
            attempt = root / MOD.ROOT_REL
            attempt.mkdir(parents=True)
            result = MOD.validate_result(root)
            self.assertEqual((result["status"], result["qualification_accepted"], result["reason"]),
                ("unknown", False, "terminal-artifact-missing"))
            diagnostic = attempt / "native-prefix-diagnostic"
            diagnostic.mkdir()
            (diagnostic / "dispatch.json").write_text("{}")
            (diagnostic / "result.json").write_text("{}")
            (diagnostic / "download").mkdir()
            (diagnostic / "download/native-prefix-diagnostic.json").write_text("{}")
            partial = MOD.validate_result(root)
            self.assertEqual(partial["status"], "unknown")
            self.assertFalse(partial["qualification_accepted"])

    def test_complete_terminal_records_reopen_admission_and_join_candidate(self):
        from unittest import mock

        def build(root: Path, outcome: str):
            root = root.resolve(strict=True)
            attempt, admission_path, admission_record = self._admission_fixture(root,
                source_paths={"scripts/release/v02_single_native.py", "scripts/evidence/v02_run.py"})
            ready_path, ready_sha, candidate = self._readiness_fixture(root, attempt,
                admission_path, admission_record)
            claim = attempt / "native-prefix-diagnostic"
            download = claim / "download"
            raw_admission = admission_path.read_bytes()
            MOD.validate_admission(root, MOD.ROOT_REL, admission_path,
                stage="native-prefix-diagnostic", source_head=admission_record["source_head"],
                source_roster=set(admission_record["source_pins"]), authority_path=MOD.AUTH_REL,
                authority_sha256=MOD.AUTH_SHA256, admission_sha256=hashlib.sha256(raw_admission).hexdigest(),
                readiness_path=ready_path, readiness_sha256=ready_sha)
            denied_marker = root / MOD.PREVIOUS_ATTEMPT_REL / "native-prefix-diagnostic"
            denied_marker.parent.mkdir(parents=True, exist_ok=True)
            path_type = type(root)
            original_lstat = path_type.lstat

            def deny_old_marker(path, *args, **kwargs):
                if path == denied_marker:
                    raise PermissionError("controlled inaccessible lineage marker")
                return original_lstat(path, *args, **kwargs)

            with mock.patch.object(path_type, "lstat", new=deny_old_marker):
                with self.assertRaisesRegex(ValueError, "single-native-lineage-conflict"):
                    MOD.validate_admission(root, MOD.ROOT_REL, admission_path,
                        stage="native-prefix-diagnostic", source_head=admission_record["source_head"],
                        source_roster=set(admission_record["source_pins"]), authority_path=MOD.AUTH_REL,
                        authority_sha256=MOD.AUTH_SHA256,
                        admission_sha256=hashlib.sha256(raw_admission).hexdigest(),
                        readiness_path=ready_path, readiness_sha256=ready_sha)
            shared_parent = (root / MOD.CLAIM_REL).parent
            saved_parent = root / "shared-claim-parent-original"
            shared_parent.rename(saved_parent)
            shared_parent.symlink_to(saved_parent, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "single-native-claim-parent-invalid"):
                MOD.validate_admission(root, MOD.ROOT_REL, admission_path,
                    stage="native-prefix-diagnostic", source_head=admission_record["source_head"],
                    source_roster=set(admission_record["source_pins"]), authority_path=MOD.AUTH_REL,
                    authority_sha256=MOD.AUTH_SHA256,
                    admission_sha256=hashlib.sha256(raw_admission).hexdigest(),
                    readiness_path=ready_path, readiness_sha256=ready_sha)
            shared_parent.unlink()
            saved_parent.rename(shared_parent)

            local_claim = root / MOD.LOCAL_CLAIM_REL
            local_claim.write_text("unexpected repair claim\n")
            with self.assertRaisesRegex(ValueError, "single-native-lineage-conflict"):
                MOD.validate_admission(root, MOD.ROOT_REL, admission_path,
                    stage="native-prefix-diagnostic", source_head=admission_record["source_head"],
                    source_roster=set(admission_record["source_pins"]), authority_path=MOD.AUTH_REL,
                    authority_sha256=MOD.AUTH_SHA256,
                    admission_sha256=hashlib.sha256(raw_admission).hexdigest(),
                    readiness_path=ready_path, readiness_sha256=ready_sha)
            local_claim.unlink()
            local_claim.symlink_to(root / "missing-repair-claim-target")
            with self.assertRaisesRegex(ValueError, "single-native-lineage-conflict"):
                MOD.validate_admission(root, MOD.ROOT_REL, admission_path,
                    stage="native-prefix-diagnostic", source_head=admission_record["source_head"],
                    source_roster=set(admission_record["source_pins"]), authority_path=MOD.AUTH_REL,
                    authority_sha256=MOD.AUTH_SHA256,
                    admission_sha256=hashlib.sha256(raw_admission).hexdigest(),
                    readiness_path=ready_path, readiness_sha256=ready_sha)
            local_claim.unlink()

            old_attempt_claim = (root / MOD.PREVIOUS_ATTEMPT_REL
                                 / "native-prefix-diagnostic")
            old_attempt_claim.mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "single-native-lineage-conflict"):
                MOD.validate_admission(root, MOD.ROOT_REL, admission_path,
                    stage="native-prefix-diagnostic", source_head=admission_record["source_head"],
                    source_roster=set(admission_record["source_pins"]), authority_path=MOD.AUTH_REL,
                    authority_sha256=MOD.AUTH_SHA256,
                    admission_sha256=hashlib.sha256(raw_admission).hexdigest(),
                    readiness_path=ready_path, readiness_sha256=ready_sha)
            old_attempt_claim.rmdir()

            legacy_claim = root / MOD.LEGACY_ROOT_REL / "native-prefix-diagnostic"
            legacy_claim.mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "single-native-one-shot-already-claimed"):
                MOD.validate_admission(root, MOD.ROOT_REL, admission_path,
                    stage="native-prefix-diagnostic", source_head=admission_record["source_head"],
                    source_roster=set(admission_record["source_pins"]), authority_path=MOD.AUTH_REL,
                    authority_sha256=MOD.AUTH_SHA256,
                    admission_sha256=hashlib.sha256(raw_admission).hexdigest(),
                    readiness_path=ready_path, readiness_sha256=ready_sha)
            legacy_claim.rmdir()
            global_claim = root / MOD.CLAIM_REL
            global_claim.parent.mkdir(parents=True, exist_ok=True)
            global_claim.symlink_to(root / "missing-shared-claim-target")
            with self.assertRaisesRegex(ValueError, "single-native-one-shot-already-claimed"):
                MOD.validate_admission(root, MOD.ROOT_REL, admission_path,
                    stage="native-prefix-diagnostic", source_head=admission_record["source_head"],
                    source_roster=set(admission_record["source_pins"]), authority_path=MOD.AUTH_REL,
                    authority_sha256=MOD.AUTH_SHA256,
                    admission_sha256=hashlib.sha256(raw_admission).hexdigest(),
                    readiness_path=ready_path, readiness_sha256=ready_sha)
            global_claim.unlink()
            global_claim.write_text("{}\n")
            with self.assertRaisesRegex(ValueError, "single-native-one-shot-already-claimed"):
                MOD.validate_admission(root, MOD.ROOT_REL, admission_path,
                    stage="native-prefix-diagnostic", source_head=admission_record["source_head"],
                    source_roster=set(admission_record["source_pins"]), authority_path=MOD.AUTH_REL,
                    authority_sha256=MOD.AUTH_SHA256,
                    admission_sha256=hashlib.sha256(raw_admission).hexdigest(),
                    readiness_path=ready_path, readiness_sha256=ready_sha)
            global_claim.unlink()
            retired_claim = root / MOD.RETIRED_ROOT_REL / "native-prefix-diagnostic"
            retired_claim.mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "single-native-one-shot-already-claimed"):
                MOD.validate_admission(root, MOD.ROOT_REL, admission_path,
                    stage="native-prefix-diagnostic", source_head=admission_record["source_head"],
                    source_roster=set(admission_record["source_pins"]), authority_path=MOD.AUTH_REL,
                    authority_sha256=MOD.AUTH_SHA256,
                    admission_sha256=hashlib.sha256(raw_admission).hexdigest(),
                    readiness_path=ready_path, readiness_sha256=ready_sha)
            retired_claim.rmdir()

            # The previous namespace's spent claim is historical evidence. It
            # must remain untouched without consuming this newly approved root.
            previous_root = root / "build/v02/native-media-retest-20261101T143706Z"
            old_global_claim = previous_root / "native-dispatch-claim.json"
            old_global_claim.parent.mkdir(parents=True, exist_ok=True)
            old_global_claim.write_text("{}\n")
            old_attempt_claim = previous_root / "attempt-0003/native-prefix-diagnostic"
            old_attempt_claim.mkdir(parents=True)
            MOD.validate_admission(root, MOD.ROOT_REL, admission_path,
                stage="native-prefix-diagnostic", source_head=admission_record["source_head"],
                source_roster=set(admission_record["source_pins"]), authority_path=MOD.AUTH_REL,
                authority_sha256=MOD.AUTH_SHA256,
                admission_sha256=hashlib.sha256(raw_admission).hexdigest(),
                readiness_path=ready_path, readiness_sha256=ready_sha)
            self.assertTrue(old_global_claim.is_file())
            self.assertTrue(old_attempt_claim.is_dir())
            old_attempt_claim.rmdir()
            old_global_claim.unlink()
            self.assertFalse(claim.exists())
            download.mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "single-native-one-shot-already-claimed"):
                MOD.validate_admission(root, MOD.ROOT_REL, admission_path,
                    stage="native-prefix-diagnostic", source_head=admission_record["source_head"],
                    source_roster=set(admission_record["source_pins"]), authority_path=MOD.AUTH_REL,
                    authority_sha256=MOD.AUTH_SHA256,
                    admission_sha256=hashlib.sha256(raw_admission).hexdigest(),
                    readiness_path=ready_path, readiness_sha256=ready_sha)
            run_id = 7654321
            branch = "v0.2-source-" + candidate["public_head"][:12]
            start = "2026-11-01T13:10:00+00:00"
            end = "2026-11-01T14:40:00+00:00"
            dispatch = {"schema": "genewhip.phase7-native-prefix-diagnostic-dispatch.v1",
                "source_sha": candidate["public_head"], "base_sha": candidate["public_base"],
                "branch": branch, "repository": "szTheory/genewhip", "nonce": "a" * 32,
                "requested_at": start, "started_at": start, "readiness_sha256": ready_sha,
                "qualification_accepted": False, "status": "completed-assessment-required",
                "dispatches": 1, "native_diagnostic_started_at": start,
                "native_diagnostic_deadline": end, "qualification_started_at": start,
                "run_id": run_id, "clock_profile": MOD.QUEUE_PROFILE}
            claim_record = MOD.claim_payload(
                attempt_root=MOD.ROOT_REL.as_posix(), source_sha=candidate["public_head"],
                base_sha=candidate["public_base"], branch=branch, nonce=dispatch["nonce"],
                started_at=start, deadline=end, readiness_sha256=ready_sha)
            global_claim.write_text(json.dumps(claim_record, sort_keys=True))
            claim_raw = global_claim.read_bytes()
            job_started = "2026-11-01T13:10:30+00:00"
            server_date = "2026-11-01T13:10:35+00:00"
            response_end = 1_000_000_000_000
            rtt = 2_000_000_000
            projection = MOD.queue_clock_projection(claim_started_at=start,
                claim_deadline=end, job_started_at=job_started, server_date=server_date,
                round_trip_ns=rtt, response_received_monotonic_ns=response_end,
                local_request_started_at="2026-11-01T13:10:33+00:00",
                local_response_at="2026-11-01T13:10:35+00:00")
            job_clock = {"schema": MOD.QUEUE_RECEIPT_SCHEMA, "clock_profile": MOD.QUEUE_PROFILE,
                "claim_sha256": hashlib.sha256(claim_raw).hexdigest(), "claim_nonce": dispatch["nonce"],
                "claim_started_at": start, "claim_deadline": end, "repository": "szTheory/genewhip",
                "run_id": str(run_id), "run_attempt": 1, "job_id": 7654, "job_name": "v02-runtime",
                "job_status_at_observation": "in_progress", "head_sha": candidate["public_head"],
                "head_branch": branch, "job_started_at": job_started, "server_date": server_date,
                "local_request_started_at": "2026-11-01T13:10:33+00:00",
                "local_response_at": server_date,
                "round_trip_ns": rtt, "timestamp_precision_seconds": 1,
                "request_started_monotonic_ns": response_end - rtt,
                "response_received_monotonic_ns": response_end, **projection}
            identity = {"source_sha": candidate["public_head"], "head_sha": candidate["public_head"],
                "base_sha": candidate["public_base"], "run_id": str(run_id), "run_attempt": "1"}
            report = self._strict_report(root, identity)
            if outcome == "fail":
                report["status"] = "fail"
                report["failure_category"] = "bounded-workload-failed"
            report_path = download / "native-prefix-diagnostic.json"
            job_clock_path = download / "native-prefix-job-clock.json"
            job_clock_path.write_text(json.dumps(job_clock, sort_keys=True))
            report["schema"] = "genewhip-phase7-native-prefix-diagnostic-v2"
            report["clock_completion"] = {"schema": "genewhip.phase7-native-prefix-clock-completion.v1",
                "receipt_sha256": hashlib.sha256(job_clock_path.read_bytes()).hexdigest(),
                "collector_deadline_monotonic_ns": projection["collector_deadline_monotonic_ns"],
                "completion_monotonic_ns": projection["collector_deadline_monotonic_ns"] - 1}
            report_path.write_text(json.dumps(report, sort_keys=True))
            dispatch["job_clock_receipt_sha256"] = hashlib.sha256(job_clock_path.read_bytes()).hexdigest()
            result = {"schema": "genewhip.phase7-native-prefix-diagnostic-result.v1",
                "status": report["status"], "qualification_accepted": False,
                "assessment_required": True, "run_id": str(run_id),
                "source_sha": candidate["public_head"], "run_attempt": "1",
                "report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
                "report_path": report_path.relative_to(root).as_posix(), "branch": branch,
                "job_clock_receipt_sha256": dispatch["job_clock_receipt_sha256"],
                "job_clock_receipt_path": job_clock_path.relative_to(root).as_posix()}
            workflow = {"id": run_id, "run_attempt": 1, "event": "workflow_dispatch",
                "head_sha": candidate["public_head"], "head_branch": branch,
                "status": "completed", "conclusion": "success" if outcome == "pass" else "failure",
                "display_title": "Plan10 native prefix diagnostic " + dispatch["nonce"],
                "path": ".github/workflows/ci.yml@refs/heads/" + branch,
                "repository": {"full_name": "szTheory/genewhip"}}
            job_names = sorted({"safety", "gameplay", "desktop", "package", "performance",
                "product-smoke", "phase7-fast", "v02-runtime", "extended", "attestation",
                "required-ci", "v02-benchmark-control", "v02-benchmark-recursion94",
                "v02-benchmark-tank-battle", "v02-package", "v02-release-qualification"})
            jobs = {"total_count": 16, "jobs": [{"name": name, "status": "completed",
                "conclusion": workflow["conclusion"] if name == "v02-runtime" else "skipped",
                **({"id": 7654, "run_id": run_id, "run_attempt": 1,
                    "head_sha": candidate["public_head"], "head_branch": branch,
                    "started_at": job_started} if name == "v02-runtime" else {})}
                for name in job_names]}
            for filename, value in (("dispatch.json", dispatch), ("result.json", result),
                                    ("workflow_run.json", workflow), ("jobs.json", jobs)):
                (claim / filename).write_text(json.dumps(value, sort_keys=True))
            return attempt, claim, dispatch, result, workflow, jobs, report, report_path, global_claim

        for outcome in ("pass", "fail"):
            with tempfile.TemporaryDirectory(prefix="single-native-terminal-complete-") as tmp:
                root = Path(tmp).resolve()
                build(root, outcome)
                self.assertTrue((root / MOD.CLAIM_REL).is_file())
                denied_marker = root / MOD.PREVIOUS_ATTEMPT_REL / "native-prefix-diagnostic"
                denied_marker.parent.mkdir(parents=True, exist_ok=True)
                path_type = type(root)
                original_lstat = path_type.lstat

                def deny_old_marker(path, *args, **kwargs):
                    if path == denied_marker:
                        raise PermissionError("controlled inaccessible lineage marker")
                    return original_lstat(path, *args, **kwargs)

                with mock.patch.object(path_type, "lstat", new=deny_old_marker):
                    inaccessible = MOD.validate_result(root)
                self.assertEqual(inaccessible["status"], "unknown")
                self.assertEqual(inaccessible["reason"], "terminal-lineage-conflict")
                result = MOD.validate_result(root)
                self.assertEqual(result["status"], outcome)
                self.assertFalse(result["qualification_accepted"])

        for tamper in ("candidate-source", "candidate-base", "candidate-branch",
                       "workflow-path", "repository", "global-claim", "global-claim-symlink",
                       "local-repair-claim", "old-attempt-marker", "shared-claim-parent"):
            with tempfile.TemporaryDirectory(prefix="single-native-terminal-negative-") as tmp:
                root = Path(tmp).resolve()
                _, claim, dispatch, result, workflow, jobs, report, report_path, global_claim = build(root, "pass")
                job_clock_path = claim / "download/native-prefix-job-clock.json"
                job_clock = json.loads(job_clock_path.read_text())
                runtime_job = next(row for row in jobs["jobs"] if row["name"] == "v02-runtime")
                if tamper == "candidate-source":
                    forged = "f" * 40
                    dispatch["source_sha"] = result["source_sha"] = workflow["head_sha"] = forged
                    dispatch["branch"] = result["branch"] = workflow["head_branch"] = "v0.2-source-" + forged[:12]
                    report["identity"]["source_sha"] = report["identity"]["head_sha"] = forged
                    forged_claim = json.loads(global_claim.read_text())
                    forged_claim["source_sha"] = forged
                    forged_claim["branch"] = dispatch["branch"]
                    global_claim.write_text(json.dumps(forged_claim, sort_keys=True))
                    job_clock["head_sha"] = forged
                    job_clock["head_branch"] = dispatch["branch"]
                    runtime_job["head_sha"] = forged
                    runtime_job["head_branch"] = dispatch["branch"]
                elif tamper == "candidate-base":
                    forged = "f" * 40
                    dispatch["base_sha"] = report["identity"]["base_sha"] = forged
                    forged_claim = json.loads(global_claim.read_text())
                    forged_claim["base_sha"] = forged
                    global_claim.write_text(json.dumps(forged_claim, sort_keys=True))
                elif tamper == "candidate-branch":
                    dispatch["branch"] = result["branch"] = workflow["head_branch"] = "v0.2-source-forged"
                    job_clock["head_branch"] = dispatch["branch"]
                    runtime_job["head_branch"] = dispatch["branch"]
                elif tamper == "workflow-path":
                    workflow["path"] = ".github/workflows/other.yml@refs/heads/main"
                elif tamper == "repository":
                    workflow["repository"]["full_name"] = "attacker/repo"
                elif tamper == "global-claim":
                    forged_claim = json.loads(global_claim.read_text())
                    forged_claim["base_sha"] = "f" * 40
                    global_claim.write_text(json.dumps(forged_claim, sort_keys=True))
                elif tamper == "global-claim-symlink":
                    shared_copy = global_claim.with_name("native-dispatch-claim-copy.json")
                    global_claim.rename(shared_copy)
                    global_claim.symlink_to(shared_copy)
                elif tamper == "local-repair-claim":
                    (root / MOD.LOCAL_CLAIM_REL).write_text("unexpected repair claim\n")
                elif tamper == "old-attempt-marker":
                    (root / MOD.PREVIOUS_ATTEMPT_REL / "native-prefix-diagnostic").mkdir(parents=True)
                elif tamper == "shared-claim-parent":
                    shared_parent = global_claim.parent
                    saved_parent = root / "shared-claim-parent-original"
                    shared_parent.rename(saved_parent)
                    shared_parent.symlink_to(saved_parent, target_is_directory=True)
                job_clock["claim_sha256"] = hashlib.sha256(global_claim.read_bytes()).hexdigest()
                job_clock_path.write_text(json.dumps(job_clock, sort_keys=True))
                dispatch["job_clock_receipt_sha256"] = hashlib.sha256(job_clock_path.read_bytes()).hexdigest()
                result["job_clock_receipt_sha256"] = dispatch["job_clock_receipt_sha256"]
                report_path.write_text(json.dumps(report, sort_keys=True))
                result["report_sha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
                for filename, value in (("dispatch.json", dispatch), ("result.json", result),
                                        ("workflow_run.json", workflow), ("jobs.json", jobs)):
                    (claim / filename).write_text(json.dumps(value, sort_keys=True))
                assessment = MOD.validate_result(root)
                self.assertEqual(assessment["status"], "unknown", tamper)
                if tamper in ("candidate-source", "candidate-base"):
                    self.assertEqual(assessment["reason"], "dispatch-candidate-identity-mismatch", tamper)

    def test_workflow_and_controller_carry_one_claim_pair_without_legacy_clock_fallback(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        coordinator = (ROOT / "scripts/release/v02_qualification.py").read_text()
        collector = (ROOT / "scripts/evidence/v02_run.py").read_text()
        self.assertIn("native_diagnostic_started_at:", workflow)
        self.assertIn("native_diagnostic_deadline:", workflow)
        self.assertIn("GENEWHIP_NATIVE_DIAGNOSTIC_STARTED_AT", workflow)
        self.assertIn("GENEWHIP_NATIVE_DIAGNOSTIC_DEADLINE", workflow)
        self.assertIn("native_diagnostic_started_at=" + '" + started_at', coordinator)
        self.assertIn("native_diagnostic_deadline=" + '" + diagnostic_deadline', coordinator)
        self.assertIn("_native_prefix_claim_deadline", collector)
        self.assertIn("deadline = started + datetime.timedelta(seconds=scope[\"qualification_batch\"][\"runtime_wall_seconds\"])" , collector)
        self.assertIn("overall_deadline = controller_started + (5100 if diagnostic_deadline is not None else 2640)", coordinator)
        self.assertIn("cleanup_deadline = controller_started + (5400 if diagnostic_deadline is not None else 2640)", coordinator)
        self.assertIn('execution["remote_cleanup_status"] = "confirmed"', coordinator)


if __name__ == "__main__":
    unittest.main()

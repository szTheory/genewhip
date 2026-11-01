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
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PUBLIC_STARTED_AT = "2026-11-01T13:09:15.302323+00:00"
DENIED_EFFECTS = []


def _deny_effects(event, args):
    if (event in ("subprocess.Popen", "os.system", "os.fork", "socket.__new__")
            or event.startswith(("os.exec", "os.spawn", "os.posix_spawn", "socket."))):
        DENIED_EFFECTS.append(event)
        raise PermissionError("single-native-contract-denied-effects")


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
        authority.write_bytes(MOD.public_authority_fixture_bytes())
        scope = root / MOD.SCOPE_REL
        scope.parent.mkdir(parents=True, exist_ok=True)
        scope.write_bytes((ROOT / MOD.SCOPE_REL).read_bytes())
        return authority

    def _readiness_fixture(self, root, attempt, admission, record):
        candidate = record["candidate"]
        source = {"source_head": record["source_head"], "started_at": record["started_at"],
            "source_payload_sha256": record["source_payload_sha256"]}
        source_path = attempt / "source-admission.json"
        source_path.write_text(json.dumps(source, sort_keys=True))
        jobs = [{"id": i + 1, "name": name, "status": "completed",
            "conclusion": "success" if name in MOD.PREVIEW_REQUIRED else "skipped"}
            for i, name in enumerate(sorted(MOD.PREVIEW_REQUIRED | MOD.PREVIEW_SKIPPED))]
        delivery = {"status": "diagnostic-ci-complete", "repository": "szTheory/genewhip",
            "diagnostic_only": True, "assessment_required": True, "merge_attempted": False,
            "candidate_sha": candidate["public_head"], "public_base_sha": candidate["public_base"],
            "pull_request": "46"}
        journal = {"repository": "szTheory/genewhip", "source_head": candidate["public_head"],
            "public_base_sha": candidate["public_base"], "started_at": PUBLIC_STARTED_AT,
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
        ready_payload_sha = hashlib.sha256(json.dumps(ready, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        reviews = {}
        review_dir = root / ".planning/phases/GW-07-single-native-fixture"
        review_dir.mkdir(parents=True, exist_ok=True)
        for key, role in MOD.SOURCE_ROLES.items():
            review = review_dir / f"readiness-{key}.md"
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

    def _admission_fixture(self, root: Path, *, source_paths: set[str] | None = None):
        authority = root / MOD.AUTH_REL
        authority.parent.mkdir(parents=True)
        authority.write_bytes(MOD.public_authority_fixture_bytes())
        scope = root / MOD.SCOPE_REL
        scope.parent.mkdir(parents=True)
        scope.write_bytes((ROOT / MOD.SCOPE_REL).read_bytes())
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
                "fb4ed24ffd8685781fbf33f8e55b19af9756b713a6536031ebf7585140773335")
            self.assertFalse(value["full_qualification_authorized"])
            self.assertFalse(value["merge_authorized"])
            self.assertFalse(value["release_authorized"])
            self.assertFalse(value["next_phase_authorized"])

    def test_authority_path_digest_scope_and_bytes_are_not_caller_selectable(self):
        with tempfile.TemporaryDirectory(prefix="single-native-public-authority-negative-") as tmp:
            root = Path(tmp)
            self._write_public_authority(root)
            for path, digest, label in (
                (root / "build/v02/ci-continuation-old/authorization.json",
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
            root = Path(tmp)
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
            root = Path(tmp)
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
            root = Path(tmp)
            authority = root / MOD.AUTH_REL
            authority.parent.mkdir(parents=True)
            authority.write_bytes(MOD.public_authority_fixture_bytes())
            scope = root / MOD.SCOPE_REL
            scope.parent.mkdir(parents=True)
            scope.write_bytes((ROOT / MOD.SCOPE_REL).read_bytes())
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
        def build(root: Path, outcome: str):
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
            global_claim.write_text("{}\n")
            with self.assertRaisesRegex(ValueError, "single-native-one-shot-already-claimed"):
                MOD.validate_admission(root, MOD.ROOT_REL, admission_path,
                    stage="native-prefix-diagnostic", source_head=admission_record["source_head"],
                    source_roster=set(admission_record["source_pins"]), authority_path=MOD.AUTH_REL,
                    authority_sha256=MOD.AUTH_SHA256,
                    admission_sha256=hashlib.sha256(raw_admission).hexdigest(),
                    readiness_path=ready_path, readiness_sha256=ready_sha)
            self.assertFalse(claim.exists())
            global_claim.unlink()
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
            end = "2026-11-01T13:55:00+00:00"
            dispatch = {"schema": "genewhip.phase7-native-prefix-diagnostic-dispatch.v1",
                "source_sha": candidate["public_head"], "base_sha": candidate["public_base"],
                "branch": branch, "repository": "szTheory/genewhip", "nonce": "a" * 32,
                "requested_at": start, "started_at": start, "readiness_sha256": ready_sha,
                "qualification_accepted": False, "status": "completed-assessment-required",
                "dispatches": 1, "native_diagnostic_started_at": start,
                "native_diagnostic_deadline": end, "qualification_started_at": start,
                "run_id": run_id}
            global_claim.write_text(json.dumps(MOD.claim_payload(
                attempt_root=MOD.ROOT_REL.as_posix(), source_sha=candidate["public_head"],
                base_sha=candidate["public_base"], branch=branch, nonce=dispatch["nonce"],
                started_at=start, deadline=end, readiness_sha256=ready_sha), sort_keys=True))
            identity = {"source_sha": candidate["public_head"], "head_sha": candidate["public_head"],
                "base_sha": candidate["public_base"], "run_id": str(run_id), "run_attempt": "1"}
            report = self._strict_report(root, identity)
            if outcome == "fail":
                report["status"] = "fail"
                report["failure_category"] = "bounded-workload-failed"
            report_path = download / "native-prefix-diagnostic.json"
            report_path.write_text(json.dumps(report, sort_keys=True))
            result = {"schema": "genewhip.phase7-native-prefix-diagnostic-result.v1",
                "status": report["status"], "qualification_accepted": False,
                "assessment_required": True, "run_id": str(run_id),
                "source_sha": candidate["public_head"], "run_attempt": "1",
                "report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
                "report_path": report_path.relative_to(root).as_posix(), "branch": branch}
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
                "conclusion": workflow["conclusion"] if name == "v02-runtime" else "skipped"}
                for name in job_names]}
            for filename, value in (("dispatch.json", dispatch), ("result.json", result),
                                    ("workflow_run.json", workflow), ("jobs.json", jobs)):
                (claim / filename).write_text(json.dumps(value, sort_keys=True))
            return attempt, claim, dispatch, result, workflow, jobs, report, report_path, global_claim

        for outcome in ("pass", "fail"):
            with tempfile.TemporaryDirectory(prefix="single-native-terminal-complete-") as tmp:
                root = Path(tmp)
                build(root, outcome)
                result = MOD.validate_result(root)
                self.assertEqual(result["status"], outcome)
                self.assertFalse(result["qualification_accepted"])

        for tamper in ("candidate-source", "candidate-base", "candidate-branch",
                       "workflow-path", "repository", "global-claim"):
            with tempfile.TemporaryDirectory(prefix="single-native-terminal-negative-") as tmp:
                root = Path(tmp)
                _, claim, dispatch, result, workflow, jobs, report, report_path, global_claim = build(root, "pass")
                if tamper == "candidate-source":
                    forged = "f" * 40
                    dispatch["source_sha"] = result["source_sha"] = workflow["head_sha"] = forged
                    dispatch["branch"] = result["branch"] = workflow["head_branch"] = "v0.2-source-" + forged[:12]
                    report["identity"]["source_sha"] = report["identity"]["head_sha"] = forged
                    forged_claim = json.loads(global_claim.read_text())
                    forged_claim["source_sha"] = forged
                    forged_claim["branch"] = dispatch["branch"]
                    global_claim.write_text(json.dumps(forged_claim, sort_keys=True))
                elif tamper == "candidate-base":
                    forged = "f" * 40
                    dispatch["base_sha"] = report["identity"]["base_sha"] = forged
                    forged_claim = json.loads(global_claim.read_text())
                    forged_claim["base_sha"] = forged
                    global_claim.write_text(json.dumps(forged_claim, sort_keys=True))
                elif tamper == "candidate-branch":
                    dispatch["branch"] = result["branch"] = workflow["head_branch"] = "v0.2-source-forged"
                elif tamper == "workflow-path":
                    workflow["path"] = ".github/workflows/other.yml@refs/heads/main"
                elif tamper == "repository":
                    workflow["repository"]["full_name"] = "attacker/repo"
                elif tamper == "global-claim":
                    forged_claim = json.loads(global_claim.read_text())
                    forged_claim["base_sha"] = "f" * 40
                    global_claim.write_text(json.dumps(forged_claim, sort_keys=True))
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
        self.assertIn("cleanup_deadline = controller_started + (2670 if diagnostic_deadline is not None else 2640)", coordinator)
        self.assertIn('execution["remote_cleanup_status"] = "confirmed"', coordinator)


if __name__ == "__main__":
    unittest.main()

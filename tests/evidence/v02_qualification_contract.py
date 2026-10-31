#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Production consumer contracts for the v0.2 qualification coordinator."""
import base64
import ast
import importlib.util
import json
import hashlib
import inspect
import subprocess
import tempfile
import unittest
import datetime
import os
import signal
import stat
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "scripts/release/v02_qualification.py"


def require_process_context():
    spec = importlib.util.spec_from_file_location("gw_contract_admission", ROOT / "tests/session/phase6_route_contract.py")
    boundary = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(boundary)
    boundary.require_host_process_context()


def retain_control_receipt(name, value):
    """Keep benign control ownership evidence after temporary fixtures vanish."""
    destination = ROOT / "build/v02/process-admission-controls" / f"{name}-{time.monotonic_ns()}.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(payload) > 1024 * 1024:
        raise ValueError("control-receipt-byte-limit")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(destination, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(payload.decode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())


def load_module(test):
    test.assertTrue(MODULE.is_file(), "qualification-coordinator-missing")
    spec = importlib.util.spec_from_file_location("gw_v02_qualification", MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def synthetic_qualified_reports(benchmark, identity, source_digest, scope_id, scope_sha256):
    reports = {}
    for workload in ("control", "recursion94", "tank-battle"):
        fields = {"control": 600, "recursion94": 3631, "tank-battle": 4196}[workload]
        warmup = 120 if workload == "control" else 0
        output = ({"video": [{"sequence": 1}], "pcm_frames": 100,
            "pcm_sha256": "a" * 64, "ram_sha256": "b" * 64, "machine_sha256": "c" * 64}
            if workload == "control" else {key: char * 64 for key, char in
            (("ram_sha256", "a"), ("cpu_sha256", "b"), ("controller_sha256", "c"),
             ("video_sha256", "d"), ("pcm_sha256", "e"))})
        reference = {"fields_completed": fields, "warmup_fields": warmup, "ticks_completed": 1000,
            "actual_tick_start": 0, "actual_tick_end": 1000, "elapsed_ns": 0, "untimed": True,
            "route_status": 0, "output_identity": output, "process_id": 900,
            "process_instance": workload + "-reference"}
        if workload == "recursion94": reference["completed_steps"] = 3600
        timed = []
        for diagnostics in (False, True):
            for observer in ("sampled", "aggregate"):
                for repetition in range(1, 6):
                    row = {"fields_completed": fields, "warmup_fields": warmup,
                        "ticks_completed": 1000, "actual_tick_start": 0, "actual_tick_end": 1000,
                        "elapsed_ns": 10, "untimed": False, "route_status": 0,
                        "output_identity": output, "untimed_output_identity": output,
                        "diagnostics_enabled": diagnostics, "observer": observer, "repetition": repetition,
                        "process_id": 900 + repetition + int(diagnostics) * 10 + int(observer == "aggregate") * 20,
                        "process_instance": f"{workload}-{diagnostics}-{observer}-{repetition}",
                        "field_ns": [1] * fields if observer == "sampled" else []}
                    if workload == "recursion94": row["completed_steps"] = 3600
                    timed.append(row)
        build = {key: "macOS fact" for key in
            ("host_system", "host_release", "host_macos_version", "host_machine", "host_model")}
        build.update({"compiler_sha256": "a" * 64, "build_rules_sha256": "b" * 64,
            "build_configuration_sha256": "c" * 64, "compiler_version_line": "clang version 1",
            "cmake": {"CMAKE_BUILD_TYPE": "Release"}})
        reports[workload] = {"schema": "genewhip.v02-workload-benchmark-v1", "workload": workload,
            "outcome": "pass", "qualification": True, "source_identity_sha256": source_digest,
            "source_revision": identity["source_sha"], "head_sha": identity["head_sha"],
            "base_sha": identity["base_sha"], "scope_id": scope_id, "scope_sha256": scope_sha256,
            "run_id": identity["run_id"], "run_attempt": identity["run_attempt"],
            "build_identity": build, "host_identity": {key: build[key] for key in
                ("host_system", "host_release", "host_macos_version", "host_machine", "host_model")},
            "timed_runs": timed, "untimed_reference": reference,
            "counts": {"timed_children": 20, "untimed_references": 1, "process_starts": 21,
                "timed_samples_per_mode": 5}}
    return reports


class QualificationCoordinatorContract(unittest.TestCase):
    def test_nested_cancellation_fixture_is_durable_bounded_and_narrow(self):
        from types import SimpleNamespace
        source = inspect.getsource(
            QualificationCoordinatorContract.test_parent_term_cleans_nested_bounded_runner_process_group)
        full_source = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        method = next(node for node in ast.walk(full_source)
            if isinstance(node, ast.FunctionDef)
            and node.name == "test_parent_term_cleans_nested_bounded_runner_process_group")
        runner_sources = [ast.literal_eval(node.args[0]) for node in ast.walk(method)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "write_text" and node.args
            and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
            and "runner-receipt.json" in node.args[0].value]
        self.assertEqual(len(runner_sources), 1, "nested-runner-source-missing-or-ambiguous")
        compile(runner_sources[0], "<nested-cleanup-runner>", "exec")
        runner_tree = ast.parse(runner_sources[0])
        expressions = {}
        for node in runner_tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if node.targets[0].id in ("leaf", "code"):
                    expressions[node.targets[0].id] = node.value
        self.assertEqual(set(expressions), {"leaf", "code"}, "nested-generated-command-source-missing")
        fixture_globals = {"__builtins__": {"repr": repr, "str": str},
            "staging": Path("/bounded/staging"), "ready": Path("/bounded/ready"),
            "sys": SimpleNamespace(executable=sys.executable)}
        leaf_source = eval(compile(ast.Expression(expressions["leaf"]), "<nested-leaf-expression>", "eval"),
            fixture_globals)
        fixture_globals["leaf"] = leaf_source
        owner_source = eval(compile(ast.Expression(expressions["code"]), "<nested-owner-expression>", "eval"),
            fixture_globals)
        compile(leaf_source, "<nested-grandchild>", "exec")
        compile(owner_source, "<nested-owner>", "exec")
        for required in ("os.O_EXCL", "os.fsync", "os.replace", "ready_path.read_bytes()",
                        "process_receipt_stream=receipt", "ownership_callback=record_owned",
                        '"remaining": 16', '"wall_seconds": 18',
                        '"max_rss_bytes": 256*1024**2', '"max_stdout_stderr_bytes": 64*1024',
                        "lstart=", "_group_exists_with_budget", "stdout=subprocess.DEVNULL",
                        "stderr=subprocess.DEVNULL", "child.wait(timeout=24)",
                        "compile(leaf,", "compile(code,", "retained_streams=diagnostic_streams",
                        "bounded_snapshot(path)", "cleanup_qualified", "group_settlement"):
            self.assertIn(required, source, "nested-cleanup-boundary-missing:" + required)
        for forbidden in ('["ps",', "time.sleep(90)", "os.kill(child.pid", "child.kill()",
                          "child.communicate(", "stdout=subprocess.PIPE", "stderr=subprocess.PIPE"):
            self.assertNotIn(forbidden, source, "unbounded-or-unowned-cleanup:" + forbidden)

    def test_bounded_command_retains_scratch_diagnostic_on_boundary_exception(self):
        from importlib.machinery import ModuleSpec
        from unittest import mock
        module = load_module(self)
        original_spec = importlib.util.spec_from_file_location
        diagnostic = {"kind": "symlink-file", "path": "owned-relative-fixture/link",
                      "link_count": 1, "owned": True}

        class FakeLoader:
            def create_module(self, _spec):
                return None

            def exec_module(self, boundary):
                def fail_with_scratch_diagnostic(*_args, **kwargs):
                    kwargs["scratch_diagnostics"].append(diagnostic)
                    raise RuntimeError("synthetic-scratch-bound")
                boundary._run_client = fail_with_scratch_diagnostic

        def selected_spec(name, path):
            if Path(path) == ROOT / "tests/session/phase6_route_contract.py":
                return ModuleSpec(name, FakeLoader())
            return original_spec(name, path)

        with tempfile.TemporaryDirectory(prefix="gw-scratch-diagnostic-retention-") as temp:
            scratch = Path(temp) / "attempts"
            scratch.mkdir()
            with mock.patch.object(importlib.util, "spec_from_file_location", side_effect=selected_spec):
                with self.assertRaisesRegex(RuntimeError, "qualification-child-boundary-error"):
                    module._bounded_command([sys.executable, "-c", "pass"],
                        limits={"wall_seconds": 5, "cleanup_grace_seconds": 1,
                            "max_rss_bytes": 1024, "max_stdout_stderr_bytes": 1024,
                            "max_json_bytes": 1024, "max_binary_file_bytes": 1024,
                            "max_capture_bytes": 1024, "max_scratch_bytes": 1024,
                            "max_retained_bytes": 1024, "max_fields": 10, "max_calls": 10},
                        scratch=scratch, timeout=5, label="diagnostic-control", check=False,
                        scratch_roots=(scratch,))
            attempts = list(scratch.glob("*.attempt.json"))
            self.assertEqual(len(attempts), 1)
            attempt = json.loads(attempts[0].read_text(encoding="utf-8"))
            self.assertEqual(attempt["scratch_tree_diagnostics"], [diagnostic])

    def setUp(self):
        # Synthetic journal clocks belong to one case; production helpers may
        # export their clock for subsequent commands in that same workflow.
        from unittest import mock
        environment = mock.patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        for key in ("GENEWHIP_QUALIFICATION_STARTED_AT", "GENEWHIP_QUALIFICATION_PHASE",
                    "GENEWHIP_QUALIFICATION_NONCE"):
            os.environ.pop(key, None)
        for key in tuple(os.environ):
            if key.startswith("GENEWHIP_RECOVERY_"):
                os.environ.pop(key, None)

    def test_preparation_policy_failure_never_reuses_ready_output(self):
        from unittest import mock
        module = load_module(self)
        for failure in (subprocess.CalledProcessError(1, ["inspector"]),
                        subprocess.TimeoutExpired(["inspector"], 1), OSError("unavailable"),
                        subprocess.CompletedProcess(["inspector"], 1)):
            with self.subTest(failure=type(failure).__name__), \
                 tempfile.TemporaryDirectory(prefix="gw-policy-failure-") as temp:
                root = Path(temp)
                stale = root / "build/v02/repository-preflight-head.json"
                stale.parent.mkdir(parents=True)
                ready = {
                    "schema": "genewhip.publication-readiness-packet.v1",
                    "repository": "maintainer/project",
                    "destination": {"owner_repository": "maintainer/project", "visibility": "public"},
                    "expected_identity": {"head": "head", "base": "base"},
                    "mutations_performed": 0,
                    "repository_observations": {"ready": True},
                    "blockers": [],
                }
                stale.write_text(json.dumps(ready))
                reached = []

                def inspector(command, **kwargs):
                    reached.append(command)
                    output = root / command[command.index("--out") + 1]
                    # Even output written by this failed invocation cannot qualify.
                    output.write_text(json.dumps(ready))
                    if isinstance(failure, Exception):
                        raise failure
                    return failure

                with mock.patch.object(module.subprocess, "run", side_effect=inspector):
                    output, policy = module._inspect_preparation_policy(
                        root, root / "publication", "maintainer/project", "head", "base")
                self.assertEqual(len(reached), 1)
                self.assertNotEqual(output, stale)
                self.assertEqual(json.loads(stale.read_text()), ready)
                if isinstance(failure, subprocess.CompletedProcess):
                    self.assertEqual(policy, {**ready, "inspector_exit_code": 1})
                else:
                    self.assertEqual(policy["blockers"], ["repository_preflight_inspection_failed"])
                    self.assertIsNot(policy.get("repository_observations", {}).get("ready"), True)
                self.assertEqual(json.loads(output.read_text()), policy)

    def test_preparation_policy_requires_fresh_well_formed_output(self):
        from unittest import mock
        module = load_module(self)
        for contents in (None, "invalid-json", "[]"):
            with self.subTest(contents=contents), \
                 tempfile.TemporaryDirectory(prefix="gw-policy-output-") as temp:
                root = Path(temp)
                reached = []

                def inspector(command, **kwargs):
                    reached.append(command)
                    if contents is not None:
                        (root / command[command.index("--out") + 1]).write_text(contents)
                    return subprocess.CompletedProcess(command, 0)

                with mock.patch.object(module.subprocess, "run", side_effect=inspector):
                    output, policy = module._inspect_preparation_policy(
                        root, root / "publication", "maintainer/project", "head", "base")
                self.assertEqual(len(reached), 1)
                self.assertEqual(policy["blockers"], ["repository_preflight_output_invalid"])
                self.assertEqual(json.loads(output.read_text()), policy)

    def test_preparation_policy_accepts_only_successful_fresh_output(self):
        from unittest import mock
        module = load_module(self)
        with tempfile.TemporaryDirectory(prefix="gw-policy-fresh-") as temp:
            root = Path(temp)
            ready = {
                "schema": "genewhip.publication-readiness-packet.v1",
                "repository": "maintainer/project",
                "destination": {"owner_repository": "maintainer/project", "visibility": "public"},
                "expected_identity": {"head": "head", "base": "base"},
                "mutations_performed": 0,
                "repository_observations": {"ready": True},
                "blockers": [],
            }
            outputs = []

            def inspector(command, **kwargs):
                output = root / command[command.index("--out") + 1]
                self.assertFalse(output.exists())
                outputs.append(output)
                output.write_text(json.dumps(ready))
                return subprocess.CompletedProcess(command, 0)

            with mock.patch.object(module.subprocess, "run", side_effect=inspector):
                for _ in range(2):
                    output, policy = module._inspect_preparation_policy(
                        root, root / "publication", "maintainer/project", "head", "base")
                    self.assertEqual(policy, ready)
                    self.assertEqual(json.loads(output.read_text()), ready)
            self.assertEqual(len(set(outputs)), 2)

    def _synthetic_validation_inputs(self, root, identity):
        module = load_module(self)
        (root / "build/v02").mkdir(parents=True, exist_ok=True)
        scope = root / "scope.json"
        scope.write_text(json.dumps({"qualification_batch": {
            "wall_seconds": 86400, "runtime_wall_seconds": 64800,
            "package_wall_seconds": 14400, "close_wall_seconds": 7200}}))
        source = root / "source-evidence.json"
        source.write_text('{"source":"synthetic"}\n')
        dimensions = {}
        closure_dimensions = {}
        for name in module.REQUIRED_DIMENSIONS:
            output = root / (name + "-proof.json")
            observation = {"schema": "genewhip.v02-dimension-observation.v1",
                "dimension": name, "outcome": "pass", "identity": identity,
                "evidence_path": source.relative_to(root).as_posix(),
                "evidence_sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
            output.write_text(json.dumps(observation, sort_keys=True) + "\n")
            dimensions[name] = {"schema": "genewhip.v02-dimension-proof.v1",
                "dimension": name, "evidence_schema": observation["schema"],
                "outcome": "pass", **identity,
                "output": output.relative_to(root).as_posix(),
                "output_sha256": hashlib.sha256(output.read_bytes()).hexdigest()}
            closure_dimensions[name] = {"path": source.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "identity": identity}
        dimensions["host-native"]["capability"] = "present"
        evidence = root / "qualification-dimensions.json"
        evidence.write_text(json.dumps({"dimensions": dimensions}, sort_keys=True) + "\n")
        closure = {"schema": "genewhip.v02-evidence-closure.v1", "identity": identity,
            "dimensions": closure_dimensions, "referenced_files": {}}
        closure_path = root / "build/v02/qualification-evidence-closure.json"
        closure_path.write_text(json.dumps(closure, sort_keys=True) + "\n")
        return module, scope, evidence, dimensions

    def test_validate_cli_writes_identity_bound_readiness_receipt_on_success(self):
        from unittest import mock
        module = load_module(self)
        identity = {"source_sha": "a" * 40, "head_sha": "a" * 40,
            "base_sha": "b" * 40, "run_id": "123", "run_attempt": "2"}
        with tempfile.TemporaryDirectory(prefix="gw-validate-readiness-") as temp:
            root = Path(temp)
            module, scope, evidence, dimensions = self._synthetic_validation_inputs(root, identity)
            output = root / "validated.json"
            with mock.patch.object(module, "ROOT", root), \
                 mock.patch.object(module, "_identity", return_value=identity), \
                 mock.patch.object(module, "_dimension_semantic_errors", return_value=[]), \
                 mock.patch.object(module, "_referenced_evidence_files", return_value={}), \
                 mock.patch.dict(os.environ, {}, clear=True):
                result = module.main(["--mode", "validate", "--evidence", str(evidence),
                    "--scope", str(scope), "--out", str(output)])
            self.assertEqual(result, 0)
            self.assertTrue(output.is_file(), "validate --out must write its readiness receipt")
            receipt = json.loads(output.read_text())
            self.assertEqual(receipt["schema"], "genewhip.v02-validation-readiness.v1")
            self.assertEqual(receipt["status"], "readiness-pass")
            self.assertIs(receipt["final_qualified"], False)
            self.assertEqual(receipt["identity"], identity)
            self.assertEqual(receipt["dimensions"], dimensions)
            self.assertEqual(receipt["evidence_sha256"], hashlib.sha256(evidence.read_bytes()).hexdigest())
            closure = root / "build/v02/qualification-evidence-closure.json"
            self.assertEqual(receipt["closure_sha256"], hashlib.sha256(closure.read_bytes()).hexdigest())
            self.assertEqual(receipt["scope_sha256"], hashlib.sha256(scope.read_bytes()).hexdigest())
            self.assertEqual(module._validate_validation_readiness_receipt(receipt, identity,
                evidence_path=evidence, closure_path=closure, scope_path=scope), receipt)
            stale = json.loads(json.dumps(receipt))
            stale["identity"]["run_attempt"] = "3"
            with self.assertRaisesRegex(ValueError, "hosted-validation-readiness-receipt-invalid"):
                module._validate_validation_readiness_receipt(stale, identity,
                    evidence_path=evidence, closure_path=closure, scope_path=scope)
            changed_digest = json.loads(json.dumps(receipt))
            changed_digest["evidence_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "hosted-validation-readiness-receipt-invalid"):
                module._validate_validation_readiness_receipt(changed_digest, identity,
                    evidence_path=evidence, closure_path=closure, scope_path=scope)

    def test_validate_cli_rejects_invalid_dimensions_without_success_receipt(self):
        from unittest import mock
        module = load_module(self)
        identity = {"source_sha": "a" * 40, "head_sha": "a" * 40,
            "base_sha": "b" * 40, "run_id": "123", "run_attempt": "2"}
        with tempfile.TemporaryDirectory(prefix="gw-validate-reject-") as temp:
            root = Path(temp)
            module, scope, evidence, _ = self._synthetic_validation_inputs(root, identity)
            original = json.loads(evidence.read_text())
            mutants = (
                ("missing", lambda rows: rows["dimensions"].pop("core")),
                ("stale-identity", lambda rows: rows["dimensions"]["core"].update({"run_id": "999"})),
                ("non-pass", lambda rows: rows["dimensions"]["core"].update({"outcome": "skipped"})),
            )
            with mock.patch.object(module, "ROOT", root), \
                 mock.patch.object(module, "_identity", return_value=identity), \
                 mock.patch.object(module, "_dimension_semantic_errors", return_value=[]), \
                 mock.patch.object(module, "_referenced_evidence_files", return_value={}), \
                 mock.patch.dict(os.environ, {}, clear=True):
                for label, mutate in mutants:
                    with self.subTest(label=label):
                        changed = json.loads(json.dumps(original))
                        mutate(changed)
                        evidence.write_text(json.dumps(changed, sort_keys=True) + "\n")
                        output = root / (label + "-validated.json")
                        result = module.main(["--mode", "validate", "--evidence", str(evidence),
                            "--scope", str(scope), "--out", str(output)])
                        self.assertNotEqual(result, 0)
                        self.assertFalse(output.exists(), "invalid validation must not leave a success receipt")

    def test_parent_term_cleans_nested_bounded_runner_process_group(self):
        require_process_context()
        with tempfile.TemporaryDirectory(prefix="gw-nested-runner-") as temporary:
            root = Path(temporary)
            ready_path = root / "grandchild.ready"
            staging_path = root / "grandchild.ready.tmp"
            receipt_path = root / "runner-receipt.json"
            ownership_path = root / "runner-owned.json"
            error_path = root / "runner-error.json"
            runner = root / "runner.py"
            runner.write_text("""
import json, os, pathlib, subprocess, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]) / 'tests/session'))
import phase6_route_contract as route
root = pathlib.Path(sys.argv[2])
ready = root / 'grandchild.ready'
staging = root / 'grandchild.ready.tmp'
leaf = ('import os,pathlib,time; p=pathlib.Path(' + repr(str(staging)) +
        '); q=pathlib.Path(' + repr(str(ready)) +
        '); fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(fd,bytes.fromhex("72656164790a")); os.fsync(fd); os.close(fd); os.replace(p,q); time.sleep(15)')
compile(leaf, "<nested-grandchild>", "exec")
code = ('import subprocess,sys; p=subprocess.Popen([sys.executable,"-c",' + repr(leaf) + ']); raise SystemExit(p.wait())')
compile(code, "<nested-owner>", "exec")
runs = []
limits = {"wall_seconds": 18, "cleanup_grace_seconds": 1, "max_rss_bytes": 256*1024**2,
 "max_stdout_stderr_bytes": 64*1024, "max_json_bytes": 64*1024,
 "max_binary_file_bytes": 64*1024, "max_capture_bytes": 64*1024,
 "max_scratch_bytes": 8*1024**2, "max_retained_bytes": 1024**2,
 "max_fields": 10, "max_calls": 100}
def record_owned(entry):
 result = subprocess.run(["/bin/ps", "-p", str(entry["pid"]), "-o", "pid=,pgid=,lstart=,stat="],
   capture_output=True, text=True, timeout=1, check=False)
 raw = result.stdout.encode() + result.stderr.encode()
 parts = result.stdout.split()
 if result.returncode != 0 or len(raw) > 4096 or len(parts) != 8 or parts[0] != str(entry["pid"]) or parts[1] != str(entry["pgid"]) or parts[7].startswith("Z"):
  raise RuntimeError("fresh-owned-child-birth-observation-failed")
 with (root/'runner-owned.json').open('x', encoding='utf-8') as stream:
  json.dump({"pid": entry["pid"], "pgid": entry["pgid"], "status": entry["status"],
    "birth": " ".join(parts[2:7]), "state": parts[7]}, stream)
  stream.flush(); os.fsync(stream.fileno())
with (root/'runner-receipt.json').open('x+', encoding='utf-8') as receipt:
 try:
  diagnostic_streams = {}
  result = route._run_client(pathlib.Path(sys.executable), [sys.executable, "-c", code], runs,
    report=root/'report.json', timeout=18, cwd=root, limits=limits, scratch_roots=(root,),
    retained_streams=diagnostic_streams,
    process_receipt_stream=receipt, ownership_callback=record_owned)
  if result.returncode != 0 or not ready.is_file():
   raise RuntimeError("nested-grandchild-output-missing: " +
       diagnostic_streams.get("stderr", {}).get("text", "")[-2048:])
 except KeyboardInterrupt:
  if len(runs) != 1 or runs[0].get('process_group_cleanup') != 'confirmed':
   raise
 except BaseException as error:
  data = json.dumps({"type": type(error).__name__, "message": str(error)[:1024]}).encode()
  fd = os.open(root/'runner-error.json', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
  with os.fdopen(fd, 'wb') as stream:
   stream.write(data); stream.flush(); os.fsync(stream.fileno())
  raise
""", encoding="utf-8")
            compile(runner.read_text(encoding="utf-8"), str(runner), "exec")
            child = None
            settlement = {"status": "not-launched"}
            group_settlement = {"status": "not-checked"}
            raw_files = {}

            def bounded_snapshot(path):
                try:
                    info = path.lstat()
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                        return {"status": "unsafe-entry", "size": info.st_size}
                    with path.open("rb") as stream:
                        data = stream.read(64 * 1024 + 1)
                    return {"status": "captured", "observed_size": info.st_size,
                        "retained_size": min(len(data), 64 * 1024),
                        "truncated": info.st_size > 64 * 1024 or len(data) > 64 * 1024,
                        "sha256": hashlib.sha256(data[:64 * 1024]).hexdigest(),
                        "raw_base64": base64.b64encode(data[:64 * 1024]).decode("ascii")}
                except FileNotFoundError:
                    return {"status": "absent"}
                except BaseException as error:
                    return {"status": "read-error", "error_type": type(error).__name__}

            def check_inner_group():
                try:
                    owned_snapshot = bounded_snapshot(ownership_path)
                    receipt_snapshot = bounded_snapshot(receipt_path)
                    if owned_snapshot.get("status") != "captured" or receipt_snapshot.get("status") != "captured":
                        return {"status": "unknown", "reason": "durable-identity-unavailable"}
                    owned = json.loads(base64.b64decode(owned_snapshot["raw_base64"], validate=True))
                    receipt = json.loads(base64.b64decode(receipt_snapshot["raw_base64"], validate=True))
                    processes = receipt.get("processes") if isinstance(receipt, dict) else None
                    if (not isinstance(owned, dict) or not isinstance(processes, list) or len(processes) != 1
                            or owned.get("status") != "started" or owned.get("pid") != owned.get("pgid")
                            or not isinstance(owned.get("birth"), str) or not owned["birth"]
                            or processes[0].get("pid") != owned["pid"]
                            or processes[0].get("pgid") != owned["pgid"]):
                        return {"status": "unknown", "reason": "ownership-identity-mismatch"}
                    route_spec = importlib.util.spec_from_file_location(
                        "gw_nested_cleanup_route_final", ROOT / "tests/session/phase6_route_contract.py")
                    if route_spec is None or route_spec.loader is None:
                        return {"status": "unknown", "reason": "status-helper-unavailable"}
                    route_check = importlib.util.module_from_spec(route_spec)
                    route_spec.loader.exec_module(route_check)
                    budget = {"remaining": 16, "attempted": 0}
                    live = route_check._group_exists_with_budget(owned["pgid"], budget)
                    return {"status": "live" if live else "absent",
                        "queries_attempted": budget["attempted"], "queries_remaining": budget["remaining"]}
                except BaseException as error:
                    return {"status": "unknown", "error_type": type(error).__name__}

            argv = [sys.executable, "-I", str(runner), str(ROOT), str(root)]
            try:
                child = subprocess.Popen(argv, cwd=ROOT, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                deadline = time.monotonic() + 10
                while not ready_path.exists() and time.monotonic() < deadline and child.poll() is None:
                    time.sleep(0.01)
                self.assertTrue(ready_path.is_file(), "nested-grandchild-did-not-start")
                self.assertEqual(ready_path.read_bytes(), b"ready\n",
                    "nested-grandchild-ready-marker-content-invalid")
                self.assertFalse(staging_path.exists(), "ready-path-published-before-staging-finished")
                self.assertTrue(receipt_path.is_file(), "durable-child-receipt-missing")
                receipts = json.loads(receipt_path.read_text())
                self.assertEqual(len(receipts["processes"]), 1)
                owned = json.loads(ownership_path.read_text())
                self.assertEqual(owned["pid"], receipts["processes"][0]["pid"])
                self.assertEqual(owned["pgid"], owned["pid"])
                self.assertEqual(owned["status"], "started")
                self.assertFalse(owned["state"].startswith("Z"))
                self.assertTrue(owned["birth"])
                child.send_signal(signal.SIGTERM)
                child.wait(timeout=25)
                self.assertEqual(child.returncode, 0)
                receipts = json.loads(receipt_path.read_text())
                child_receipt = receipts["processes"][0]
                self.assertEqual(child_receipt["process_group_cleanup"], "confirmed")
                self.assertEqual(child_receipt["status"], "exception")
                self.assertEqual(child_receipt["failure_type"], "KeyboardInterrupt")
                group_settlement = check_inner_group()
                self.assertEqual(group_settlement["status"], "absent",
                    "nested-child-group-remains-live-or-status-is-unknown")
                self.assertLessEqual(group_settlement.get("queries_attempted", 0), 16)
            finally:
                try:
                    if child is not None:
                        if child.poll() is None:
                            child.send_signal(signal.SIGTERM)
                        try:
                            child.wait(timeout=24)
                            settlement = {"status": "settled", "pid": child.pid,
                                "pgid": child.pid, "returncode": child.returncode}
                        except BaseException as error:
                            settlement = {"status": "unconfirmed", "pid": child.pid,
                                "pgid": child.pid, "error_type": type(error).__name__}
                except BaseException as error:
                    settlement = {"status": "unconfirmed", "pid": child.pid if child else None,
                        "error_type": type(error).__name__}
                finally:
                    if group_settlement["status"] == "not-checked":
                        group_settlement = check_inner_group()
                    for name, path in (("ready", ready_path), ("staging", staging_path),
                                       ("ownership", ownership_path), ("process", receipt_path),
                                       ("runner_error", error_path)):
                        raw_files[name] = bounded_snapshot(path)
                    raw_files["runner"] = bounded_snapshot(runner)
                    inner_cleanup_confirmed = False
                    if raw_files["process"].get("status") == "captured":
                        try:
                            process_receipt = json.loads(base64.b64decode(
                                raw_files["process"]["raw_base64"], validate=True))
                            processes = process_receipt.get("processes")
                            inner_cleanup_confirmed = (isinstance(processes, list) and len(processes) == 1
                                and processes[0].get("process_group_cleanup") == "confirmed"
                                and processes[0].get("status") == "exception"
                                and processes[0].get("failure_type") == "KeyboardInterrupt"
                                and processes[0].get("bound_violation") is True)
                        except BaseException:
                            inner_cleanup_confirmed = False
                    retain_control_receipt("nested-parent", {
                        "schema": "genewhip.benign-process-control.v1",
                        "command": argv, "runner_sha256": raw_files["runner"].get("sha256"),
                        "settlement": settlement, "group_settlement": group_settlement,
                        "inner_cleanup_confirmed": inner_cleanup_confirmed, "files": raw_files,
                        "cleanup_qualified": settlement.get("status") == "settled" and
                            inner_cleanup_confirmed and group_settlement.get("status") == "absent" and
                            raw_files["runner_error"].get("status") == "absent",
                    })

    def test_hosted_run_identity_rejects_wrong_event_source_attempt_and_conclusion(self):
        module = load_module(self)
        self.assertTrue(hasattr(module, "_validate_hosted_run"),
                        "hosted coordinator must validate actual workflow run identity")
        sha = "a" * 40
        run = {"id": 12345, "path": ".github/workflows/ci.yml", "event": "push",
            "head_branch": "main", "head_sha": sha, "run_attempt": 1,
            "status": "completed", "conclusion": "success",
            "created_at": "2026-10-29T00:00:00Z",
            "repository": {"full_name": "szTheory/genewhip"}}
        self.assertEqual(module._validate_hosted_run(run, "szTheory/genewhip", sha),
                         {"run_id": "12345", "run_attempt": "1", "created_at": run["created_at"],
                          "event": "push"})
        mutants = (
            {"event": "workflow_dispatch"}, {"head_sha": "b" * 40},
            {"run_attempt": 0}, {"conclusion": "failure"}, {"status": "in_progress"},
            {"path": ".github/workflows/other.yml"}, {"path": None}, {"head_branch": "topic"},
            {"repository": {"full_name": "attacker/other"}}, {"repository": None},
        )
        for changes in mutants:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                module._validate_hosted_run({**run, **changes}, "szTheory/genewhip", sha)

    def test_hosted_package_transfer_identity_reopens_member_digests_and_sizes(self):
        module = load_module(self)
        sha = "a" * 40
        inventory = {"schema": "genewhip.v02-package-transfer.v1", "source_sha": sha,
            "member_count": 1, "total_bytes": 3,
            "members": {"build/v02/result.json": {"size": 3, "sha256": "b" * 64}}}
        self.assertEqual(module._validate_package_transfer_identity(inventory, sha), inventory)
        mutants = (
            ({"source_sha": "c" * 40}, "hosted-package-transfer-identity-invalid"),
            ({"member_count": 2}, "hosted-package-transfer-identity-invalid"),
            ({"total_bytes": 4}, "hosted-package-transfer-total-mismatch"),
            ({"members": {"build/v02/result.json": {"size": True, "sha256": "b" * 64}},
              "total_bytes": True}, "hosted-package-transfer-member-invalid"),
            ({"members": {"build/v02/result.json": {"size": 3, "sha256": "bad"}},
              "total_bytes": 3}, "hosted-package-transfer-member-invalid"),
        )
        for changes, reason in mutants:
            changed = {**inventory, **changes}
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, reason):
                module._validate_package_transfer_identity(changed, sha)
        with self.assertRaisesRegex(ValueError, "hosted-package-transfer-identity-invalid"):
            module._validate_package_transfer_identity(inventory, "bad-source")

    def test_hosted_release_download_uses_workflow_common_root_layout(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        legacy_package = workflow.split("  package:\n", 1)[1].split("  attestation:\n", 1)[0]
        self.assertIn("if: github.event_name != 'workflow_dispatch'", legacy_package)
        v02_package = workflow.split("  v02-package:\n", 1)[1].split(
            "  v02-release-qualification:\n", 1)[0]
        self.assertIn("--out build/v02/package-transfer --source-sha \"$GITHUB_SHA\"", v02_package)
        self.assertIn("name: release-input-${{ github.run_id }}-${{ github.run_attempt }}", v02_package)
        self.assertIn("path: build/v02/package-transfer/payload/artifacts/release-assets/*", v02_package)
        attestation = workflow.split("  attestation:\n", 1)[1].split("  performance:\n", 1)[0]
        self.assertIn("needs: [package, v02-package, v02-release-qualification]", attestation)
        self.assertIn("name: release-input-${{ github.run_id }}-${{ github.run_attempt }}", attestation)
        self.assertIn("name: release-identity-${{ github.run_id }}-${{ github.run_attempt }}", attestation)
        self.assertIn("verify_attestation_inputs.py verify", attestation)
        self.assertIn("subject-path: 'build/release-assets/*.tar.gz,build/release-assets/inventory.json'", attestation)
        coordinator = MODULE.read_text()
        self.assertIn("release_assets = release_download\n", coordinator)
        self.assertNotIn("release_assets = release_download / \"release-assets\"", coordinator)

    def test_interrupted_delivery_recovers_only_exact_protected_merge(self):
        require_process_context()
        from unittest import mock

        module = load_module(self)
        with tempfile.TemporaryDirectory(prefix="gw-hosted-merge-recovery-") as temp:
            candidate = Path(temp) / "publication"
            base, head, _ = self._snapshot_repo(candidate, {"README.md": "candidate snapshot\n"})
            tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=candidate,
                                           text=True).strip()
            merge_sha = "c" * 40
            pr = {"state": "MERGED", "number": 7, "url": "https://example.invalid/pull/7",
                "headRefOid": head, "baseRefName": "main", "mergeCommit": {"oid": merge_sha}}
            exact = {"sha": merge_sha, "parents": [{"sha": base}], "tree": {"sha": tree}}
            with mock.patch.object(module, "_gh_json", return_value=exact) as remote:
                receipt = module._verified_merge_receipt(pr, "szTheory/genewhip", candidate,
                    head, base, "v0.2-source-test")
            remote.assert_called_once_with("szTheory/genewhip", f"git/commits/{merge_sha}",
                phase="preparation")
            self.assertEqual(receipt["public_source_sha"], merge_sha)
            self.assertEqual(receipt["merge_strategy"], "squash")
            for bad_commit in (
                {"sha": merge_sha, "parents": [{"sha": "d" * 40}], "tree": {"sha": tree}},
                {"sha": merge_sha, "parents": [{"sha": base}], "tree": {"sha": "e" * 40}},
                {"sha": "f" * 40, "parents": [{"sha": base}], "tree": {"sha": tree}},
            ):
                with mock.patch.object(module, "_gh_json", return_value=bad_commit), \
                        self.assertRaisesRegex(ValueError, "protected-merge-parents-or-tree-mismatch"):
                    module._verified_merge_receipt(pr, "szTheory/genewhip", candidate,
                        head, base, "v0.2-source-test")

    def test_cached_merge_journal_reopens_remote_pr_and_merge_tree(self):
        require_process_context()
        from unittest import mock
        module = load_module(self)
        with tempfile.TemporaryDirectory(prefix="gw-hosted-journal-reopen-") as temp:
            candidate = Path(temp) / "publication"
            base, head, _ = self._snapshot_repo(candidate, {"README.md": "candidate snapshot\n"})
            tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=candidate,
                                           text=True).strip()
            merge_sha = "c" * 40
            started_at = (datetime.datetime.now(datetime.timezone.utc) -
                          datetime.timedelta(minutes=10)).isoformat()
            packet = {"repository": "szTheory/genewhip", "public_identity":
                {"head_sha": head, "base_sha": base}}
            journal_path = Path(temp) / "journal.json"
            failure_root = ROOT / "build/v02/failures"
            failure_root.mkdir(parents=True, exist_ok=True)
            archived_prior = {"schema": "genewhip.v02-delivery-journal.v1",
                "started_at": started_at, "repository": packet["repository"],
                "source_head": "f" * 40, "public_base_sha": base,
                "branch": "v0.2-source-ffffffffffff", "push_performed": True}
            archived_bytes = (json.dumps(archived_prior, sort_keys=True, indent=2) + "\n").encode()
            archive_path = failure_root / f"source-attempt-contract-{hashlib.sha256(archived_bytes).hexdigest()}.json"
            archive_path.write_bytes(archived_bytes)
            cached = {"schema": "genewhip.v02-delivery-journal.v1",
                "started_at": started_at, "repository": packet["repository"],
                "source_head": head, "public_base_sha": base, "branch": "v0.2-source-test",
                "pull_request": "7", "pull_request_url": "https://example.invalid/pull/7",
                "public_source_sha": merge_sha, "candidate_sha": head,
                "merge_parents": [base], "push_performed": True,
                "source_retry": {"schema": "genewhip.v02-source-retry.v1",
                    "archive": archive_path.relative_to(ROOT).as_posix(),
                    "archive_sha256": hashlib.sha256(archived_bytes).hexdigest(),
                    "started_at": started_at, "prior_source_head": "f" * 40,
                    "active_source_head": head, "active_repository": packet["repository"],
                    "active_base_sha": base, "failed_pull_request": "13",
                    "failed_required_check": {"name": "required-ci", "status": "COMPLETED",
                                               "conclusion": "FAILURE"}}}
            journal_path.write_text(json.dumps(cached))
            pr = {"state": "MERGED", "number": 7, "url": cached["pull_request_url"],
                "headRefOid": head, "baseRefName": "main", "mergeCommit": {"oid": merge_sha}}
            listing = mock.Mock(stdout=json.dumps([pr]))
            with mock.patch.dict(os.environ), \
                 mock.patch.object(module, "_valid_packet_for_delivery", return_value=packet), \
                 mock.patch.object(module, "_external", return_value=listing) as external, \
                 mock.patch.object(module, "_gh_json", side_effect=lambda _repo, endpoint, **_kwargs:
                     {"object": {"sha": merge_sha}} if endpoint == "git/ref/heads/main" else
                     {"sha": merge_sha, "parents": [{"sha": base}], "tree": {"sha": tree}}) as remote:
                receipt = module.publish_sanitized_source(Path("packet"), candidate, journal_path)
            external.assert_called_once()
            self.assertEqual(remote.call_count, 2)
            self.assertEqual(receipt["public_source_sha"], merge_sha)
            self.assertEqual(json.loads(journal_path.read_text())["source_retry"], cached["source_retry"])
            with mock.patch.dict(os.environ), \
                 mock.patch.object(module, "_valid_packet_for_delivery", return_value=packet), \
                 mock.patch.object(module, "_external", return_value=listing), \
                 mock.patch.object(module, "_gh_json", return_value={"sha": merge_sha,
                     "parents": [{"sha": "d" * 40}], "tree": {"sha": tree}}), \
                 self.assertRaisesRegex(ValueError, "protected-merge-parents-or-tree-mismatch"):
                module.publish_sanitized_source(Path("packet"), candidate, journal_path)
            archive_path.unlink(missing_ok=True)

    def test_explicit_source_retry_archives_exact_failed_attempt_and_keeps_original_clock(self):
        from unittest import mock
        module = load_module(self)
        root = ROOT / "build/v02/failures/source-retry-contract"
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="valid-", dir=root) as temp:
            area = Path(temp)
            journal_path = area / "hosted-delivery-journal.json"
            start = (datetime.datetime.now(datetime.timezone.utc) -
                     datetime.timedelta(minutes=10)).isoformat()
            old_head, new_head, base = "c" * 40, "b" * 40, "a" * 40
            original = {"schema": "genewhip.v02-delivery-journal.v1", "started_at": start,
                "repository": "szTheory/genewhip", "source_head": old_head,
                "public_base_sha": base, "branch": "v0.2-source-" + old_head[:12],
                "push_performed": True, "policy_sha256": "d" * 64}
            original_bytes = (json.dumps(original, sort_keys=True, indent=2) + "\n").encode()
            journal_path.write_bytes(original_bytes)
            packet = {"repository": "szTheory/genewhip", "public_identity":
                {"head_sha": new_head, "base_sha": base}}
            publication = area / "publication"
            publication.mkdir()
            pr = {"number": 13, "url": "https://example.invalid/pull/13", "state": "OPEN",
                "headRefName": original["branch"], "headRefOid": old_head,
                "baseRefName": "main", "baseRefOid": base,
                "mergeCommit": None, "autoMergeRequest": None,
                "statusCheckRollup": [{"name": "required-ci", "status": "COMPLETED",
                                       "conclusion": "FAILURE"}]}
            observed_env = []
            policy_path = publication.parent / f"repository-preflight-{new_head}-delivery.json"
            self.assertFalse(policy_path.exists())
            policy = {"schema": "genewhip.publication-readiness-packet.v1",
                "repository": packet["repository"], "mutations_performed": 0,
                "repository_observations": {"ready": True, "blockers": [], "observations": {
                    "visibility": "public", "default_branch": "main",
                    "expected_identity": {"observed_default_branch_sha": base},
                    "branch_protection": {"required_status_checks": ["required-ci"],
                        "pull_request_required": True}, "auto_merge_enabled": True,
                    "caller_write_permission": "write", "permitted_merge_methods": ["squash"]}},
                "privacy_scan": {"publication_copy": {"status": "pass"}}}
            def external(argv, **_kwargs):
                observed_env.append((os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT"),
                                     os.environ.get("GENEWHIP_QUALIFICATION_PHASE")))
                if argv[:2] == ["git", "remote"]:
                    return subprocess.CompletedProcess(argv, 0, "https://github.com/szTheory/genewhip.git\n", "")
                if argv[:2] == ["git", "rev-parse"]:
                    return subprocess.CompletedProcess(argv, 0, base + "\n", "")
                if argv[:2] == ["git", "fetch"]:
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if len(argv) > 1 and "repository_preflight.py" in argv[1]:
                    policy_output = ROOT / argv[argv.index("--out") + 1]
                    if policy_output != policy_path:
                        raise AssertionError("retry policy mock path disagrees with production --out")
                    policy_output.write_text(json.dumps(policy))
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if len(argv) > 1 and argv[1:3] == ["pr", "list"]:
                    return subprocess.CompletedProcess(argv, 0, json.dumps([pr]), "")
                if any("actions/runs?head_sha=" in value for value in argv):
                    return subprocess.CompletedProcess(argv, 0,
                        json.dumps({"total_count": 0, "workflow_runs": []}), "")
                raise AssertionError("unexpected retry external command: " + repr(argv))
            with mock.patch.dict(os.environ, {}, clear=True), \
                 mock.patch.object(module, "_valid_packet_for_delivery", return_value=packet), \
                 mock.patch.object(module, "_external", side_effect=external), \
                 mock.patch.object(module.subprocess, "Popen", side_effect=AssertionError("process launch denied")):
                output_path = area / "transition.json"
                self.assertEqual(module.main(["--mode", "retry-source", "--preflight", "packet",
                    "--publication-copy", str(publication), "--journal", str(journal_path),
                    "--out", str(output_path)]), 0)
                transition = json.loads(output_path.read_bytes())
            policy_path.unlink(missing_ok=True)
            transition = {**transition, "started_at": transition["started_at"]}
            self.assertEqual(observed_env, [(start, "preparation")] * 6)
            self.assertEqual(journal_path.read_bytes() != original_bytes, True)
            self.assertEqual(transition["started_at"], start)
            self.assertFalse(transition["push_performed"])
            active = json.loads(journal_path.read_bytes())
            self.assertEqual(active["started_at"], start)
            self.assertFalse(any(key in active for key in
                ("policy_sha256", "pull_request", "public_source_sha", "qualification_dispatch_nonce")))
            archive = ROOT / active["source_retry"]["archive"]
            self.assertEqual(archive.read_bytes(), original_bytes)
            self.assertEqual(hashlib.sha256(original_bytes).hexdigest(),
                             active["source_retry"]["archive_sha256"])
            module._validate_source_retry_history(active)

    def test_source_retry_rejects_ambiguous_or_successful_prior_attempt_without_mutation(self):
        from unittest import mock
        module = load_module(self)
        root = ROOT / "build/v02/failures/source-retry-contract"
        root.mkdir(parents=True, exist_ok=True)
        start = (datetime.datetime.now(datetime.timezone.utc) -
                 datetime.timedelta(minutes=10)).isoformat()
        old_head, new_head, base = "c" * 40, "b" * 40, "a" * 40
        packet = {"repository": "szTheory/genewhip", "public_identity":
            {"head_sha": new_head, "base_sha": base}}
        valid_pr = {"number": 13, "state": "OPEN", "headRefName": "v0.2-source-" + old_head[:12],
            "headRefOid": old_head,
            "baseRefName": "main", "baseRefOid": base, "mergeCommit": None,
            "autoMergeRequest": None, "statusCheckRollup": [{"name": "required-ci",
                "status": "COMPLETED", "conclusion": "FAILURE"}]}
        cases = (({**valid_pr, "state": "MERGED"}, [], "not-open-unmerged", None, None, None, base),
                 ({**valid_pr, "baseRefOid": "e" * 40}, [], "not-open-unmerged", None, None, None, base),
                 ({**valid_pr, "statusCheckRollup": [{"name": "required-ci",
                     "status": "IN_PROGRESS", "conclusion": None}]}, [], "required-check", None, None, None, base),
                 (valid_pr, [{"status": "in_progress", "event": "pull_request"}], "prior-workflow", None, None, None, base),
                 (valid_pr, [{"status": "completed", "event": "workflow_dispatch"}], "active-or-qualified", None, None, None, base),
                 (valid_pr, [], "prior-journal-not-retryable", "elsewhere/repo", None, None, base),
                 (valid_pr, [], "prior-journal-not-retryable", None, old_head, None, base),
                 (valid_pr, [], "live-public-base-mismatch", None, None, None, "e" * 40),
                 (valid_pr, [], "prior-journal-not-retryable", None, None, "e" * 40, "e" * 40),
                 (valid_pr, [], "cutoff-exhausted", None, None,
                    (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=25)).isoformat(), base))
        for pr, runs, error, journal_repo, journal_head, case_start, policy_base in cases:
            with self.subTest(error=error, pr=pr, runs=runs, journal_repo=journal_repo,
                    journal_head=journal_head, case_start=case_start, policy_base=policy_base), tempfile.TemporaryDirectory(
                    prefix="invalid-", dir=root) as temp:
                area = Path(temp)
                journal_path = area / "hosted-delivery-journal.json"
                original = {"schema": "genewhip.v02-delivery-journal.v1", "started_at": case_start or start,
                    "repository": journal_repo or packet["repository"], "source_head": journal_head or old_head,
                    "public_base_sha": base, "branch": "v0.2-source-" + old_head[:12],
                    "push_performed": True}
                original_bytes = (json.dumps(original, sort_keys=True) + "\n").encode()
                journal_path.write_bytes(original_bytes)
                case_packet = {**packet, "public_identity": {**packet["public_identity"]}}
                if journal_head is not None:
                    case_packet["public_identity"]["head_sha"] = journal_head
                if case_start == "same-head":
                    case_packet["public_identity"]["head_sha"] = old_head
                if error == "prior-journal-not-retryable" and policy_base != base:
                    case_packet["public_identity"]["base_sha"] = policy_base
                def external(argv, **_kwargs):
                    payload = [pr] if "pr" in argv else {"total_count": len(runs), "workflow_runs": runs}
                    return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")
                with mock.patch.object(module, "_valid_packet_for_delivery", return_value=case_packet), \
                     mock.patch.object(module, "_fresh_public_policy", return_value={"repository": case_packet["repository"],
                         "repository_observations": {"observations": {"expected_identity":
                             {"observed_default_branch_sha": policy_base}}}}), \
                     mock.patch.object(module, "_external", side_effect=external), \
                     mock.patch.object(module.subprocess, "Popen", side_effect=AssertionError("process launch denied")), \
                     self.assertRaisesRegex(ValueError, error):
                    module.retry_sanitized_source(Path("packet"), area / "publication", journal_path)
                self.assertEqual(journal_path.read_bytes(), original_bytes)
                self.assertFalse((area / "failures").exists())

    def test_expired_retry_cutoff_rejects_before_fresh_policy_or_github_reads(self):
        from unittest import mock
        module = load_module(self)
        root = ROOT / "build/v02/failures/source-retry-contract"
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="expired-", dir=root) as temp:
            area = Path(temp)
            start = (datetime.datetime.now(datetime.timezone.utc) -
                     datetime.timedelta(hours=25)).isoformat()
            old_head, new_head, base = "c" * 40, "b" * 40, "a" * 40
            journal = area / "hosted-delivery-journal.json"
            original = {"schema": "genewhip.v02-delivery-journal.v1", "started_at": start,
                "repository": "szTheory/genewhip", "source_head": old_head,
                "public_base_sha": base, "branch": "v0.2-source-" + old_head[:12],
                "push_performed": True}
            original_bytes = json.dumps(original, sort_keys=True).encode()
            journal.write_bytes(original_bytes)
            packet = {"repository": original["repository"], "public_identity":
                {"head_sha": new_head, "base_sha": base}}
            with mock.patch.dict(os.environ, {}, clear=True), \
                 mock.patch.object(module, "_valid_packet_for_delivery", return_value=packet), \
                 mock.patch.object(module, "_fresh_public_policy") as fresh, \
                 mock.patch.object(module, "_external") as external, \
                 mock.patch.object(module.subprocess, "Popen", side_effect=AssertionError("process launch denied")), \
                 self.assertRaisesRegex(ValueError, "cutoff-exhausted"):
                module.retry_sanitized_source(Path("packet"), area / "publication", journal)
            fresh.assert_not_called()
            external.assert_not_called()
            self.assertEqual(journal.read_bytes(), original_bytes)
            self.assertFalse((area / "failures").exists())

    def test_retry_external_uses_original_clock_to_bound_child_launch(self):
        from unittest import mock
        module = load_module(self)
        scope = json.loads((ROOT / "evidence/v02-execution.json").read_text())
        cutoff = scope["qualification_batch"]["wall_seconds"] - scope["qualification_batch"]["close_wall_seconds"]
        start = (datetime.datetime.now(datetime.timezone.utc) -
                 datetime.timedelta(seconds=cutoff - 3)).isoformat()
        captured = []
        def denied_worker(argv, *, timeout, **_kwargs):
            captured.append((argv, timeout))
            return {"returncode": 0, "process_group_cleanup": "confirmed"}
        with mock.patch.dict(os.environ, {"GENEWHIP_QUALIFICATION_STARTED_AT": start,
                "GENEWHIP_QUALIFICATION_PHASE": "preparation"}), \
             mock.patch.object(module, "_bounded_command", side_effect=denied_worker), \
             mock.patch.object(module.subprocess, "Popen", side_effect=AssertionError("process launch denied")):
            result = module._external(["synthetic-read-only-query"], timeout=120)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(captured), 1)
        self.assertGreater(captured[0][1], 0)
        self.assertLess(captured[0][1], 4)

    def test_retry_cutoff_crossing_during_last_remote_query_keeps_original_journal(self):
        from unittest import mock
        module = load_module(self)
        root = ROOT / "build/v02/failures/source-retry-contract"
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="crossing-", dir=root) as temp:
            area = Path(temp)
            start = (datetime.datetime.now(datetime.timezone.utc) -
                     datetime.timedelta(minutes=10)).isoformat()
            old_head, new_head, base = "c" * 40, "b" * 40, "a" * 40
            journal = area / "hosted-delivery-journal.json"
            original = {"schema": "genewhip.v02-delivery-journal.v1", "started_at": start,
                "repository": "szTheory/genewhip", "source_head": old_head,
                "public_base_sha": base, "branch": "v0.2-source-" + old_head[:12],
                "push_performed": True}
            original_bytes = json.dumps(original, sort_keys=True).encode()
            journal.write_bytes(original_bytes)
            packet = {"repository": original["repository"], "public_identity":
                {"head_sha": new_head, "base_sha": base}}
            pr = {"number": 13, "state": "OPEN", "headRefName": original["branch"],
                "headRefOid": old_head, "baseRefName": "main", "baseRefOid": base,
                "mergeCommit": None, "autoMergeRequest": None,
                "statusCheckRollup": [{"name": "required-ci", "status": "COMPLETED",
                                       "conclusion": "FAILURE"}]}
            crossed = False
            def external(argv, **_kwargs):
                nonlocal crossed
                if "pr" in argv:
                    return subprocess.CompletedProcess(argv, 0, json.dumps([pr]), "")
                crossed = True
                return subprocess.CompletedProcess(argv, 0,
                    json.dumps({"total_count": 0, "workflow_runs": []}), "")
            def budget(*_args, **_kwargs):
                if crossed:
                    raise ValueError("qualification-final-close-reserve-exhausted")
                return 10.0
            with mock.patch.object(module, "_valid_packet_for_delivery", return_value=packet), \
                 mock.patch.object(module, "_fresh_public_policy", return_value={"repository": packet["repository"],
                     "repository_observations": {"observations": {"expected_identity":
                         {"observed_default_branch_sha": base}}}}), \
                 mock.patch.object(module, "_external", side_effect=external), \
                 mock.patch.object(module, "_require_hosted_budget", side_effect=budget), \
                 mock.patch.object(module.subprocess, "Popen", side_effect=AssertionError("process launch denied")), \
                 self.assertRaisesRegex(ValueError, "final-close-reserve-exhausted"):
                module.retry_sanitized_source(Path("packet"), area / "publication", journal)
            self.assertTrue(crossed)
            self.assertEqual(journal.read_bytes(), original_bytes)
            self.assertFalse((area / "failures").exists())

    def test_ordinary_publisher_does_not_implicitly_rebind_a_failed_candidate(self):
        from unittest import mock
        module = load_module(self)
        with tempfile.TemporaryDirectory(prefix="gw-implicit-rebind-") as temp:
            journal = Path(temp) / "journal.json"
            start = (datetime.datetime.now(datetime.timezone.utc) -
                     datetime.timedelta(minutes=10)).isoformat()
            prior = {"schema": "genewhip.v02-delivery-journal.v1", "started_at": start,
                "repository": "szTheory/genewhip", "source_head": "c" * 40,
                "public_base_sha": "a" * 40, "branch": "v0.2-source-cccccccccccc",
                "push_performed": True}
            original = json.dumps(prior, sort_keys=True) + "\n"
            journal.write_text(original)
            packet = {"repository": prior["repository"], "public_identity":
                {"head_sha": "b" * 40, "base_sha": prior["public_base_sha"]}}
            with mock.patch.object(module, "_valid_packet_for_delivery", return_value=packet), \
                 mock.patch.object(module, "_fresh_public_policy") as fresh_policy, \
                 mock.patch.object(module, "_external") as external, \
                 self.assertRaisesRegex(ValueError, "hosted-delivery-journal-conflicts-with-candidate"):
                module.publish_sanitized_source(Path("packet"), Path(temp), journal)
            self.assertEqual(journal.read_text(), original)
            fresh_policy.assert_not_called()
            external.assert_not_called()

    def test_source_retry_journal_resume_reopens_merge_and_retains_original_clock(self):
        from unittest import mock
        module = load_module(self)
        root = ROOT / "build/v02/failures/source-retry-resume-contract"
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="resume-", dir=root) as temp:
            area = Path(temp)
            journal_path = area / "hosted-delivery-journal.json"
            publication = area / "publication"
            publication.mkdir()
            start = (datetime.datetime.now(datetime.timezone.utc) -
                     datetime.timedelta(minutes=10)).isoformat()
            base, active_head, old_head, merge_sha = "a" * 40, "b" * 40, "c" * 40, "d" * 40
            prior = {"schema": "genewhip.v02-delivery-journal.v1", "started_at": start,
                "repository": "szTheory/genewhip", "source_head": old_head,
                "public_base_sha": base, "branch": "v0.2-source-" + old_head[:12],
                "push_performed": True}
            archived = (json.dumps(prior, sort_keys=True, indent=2) + "\n").encode()
            archive = root / ("source-attempt-" + hashlib.sha256(archived).hexdigest() + ".json")
            archive.write_bytes(archived)
            retry = {"schema": "genewhip.v02-source-retry.v1",
                "archive": archive.relative_to(ROOT).as_posix(),
                "archive_sha256": hashlib.sha256(archived).hexdigest(), "started_at": start,
                "prior_source_head": old_head, "active_source_head": active_head,
                "active_repository": "szTheory/genewhip", "active_base_sha": base,
                "failed_pull_request": "13", "failed_required_check":
                    {"name": "required-ci", "status": "COMPLETED", "conclusion": "FAILURE"}}
            cached = {"schema": "genewhip.v02-delivery-journal.v1", "started_at": start,
                "repository": "szTheory/genewhip", "source_head": active_head,
                "public_base_sha": base, "branch": "v0.2-source-" + active_head[:12],
                "pull_request": "14", "pull_request_url": "https://example.invalid/pull/14",
                "public_source_sha": merge_sha, "candidate_sha": active_head,
                "merge_parents": [base], "push_performed": True, "source_retry": retry}
            journal_path.write_text(json.dumps(cached))
            packet = {"repository": cached["repository"], "public_identity":
                {"head_sha": active_head, "base_sha": base}}
            pr = {"number": 14, "url": cached["pull_request_url"], "state": "MERGED",
                "headRefOid": active_head, "baseRefName": "main", "mergeCommit": {"oid": merge_sha}}
            receipt = {"public_source_sha": merge_sha, "candidate_sha": active_head,
                "public_base_sha": base, "merge_parents": [base], "pull_request": "14"}
            with mock.patch.object(module, "_valid_packet_for_delivery", return_value=packet), \
                 mock.patch.object(module, "_external", return_value=subprocess.CompletedProcess(
                     ["gh"], 0, json.dumps([pr]), "")) as external, \
                 mock.patch.object(module, "_verified_merge_receipt", return_value=receipt), \
                 mock.patch.object(module, "_gh_json", return_value={"object": {"sha": merge_sha}}), \
                 mock.patch.object(module.subprocess, "Popen", side_effect=AssertionError("process launch denied")):
                actual = module.publish_sanitized_source(Path("packet"), publication, journal_path)
            self.assertEqual(actual, {**receipt, "pull_request_url": pr["url"]})
            self.assertEqual(external.call_count, 1)
            reopened = json.loads(journal_path.read_text())
            self.assertEqual(reopened["started_at"], start)
            self.assertEqual(reopened["source_retry"], retry)
            archive.unlink(missing_ok=True)

    def test_late_merge_uses_publication_start_and_never_renews_the_batch(self):
        from unittest import mock
        module = load_module(self)
        now = datetime.datetime.now(datetime.timezone.utc)
        start = (now - datetime.timedelta(hours=2, seconds=1)).isoformat()
        run_created = (now - datetime.timedelta(minutes=5)).isoformat()
        journal = {"started_at": start, "schema": "genewhip.v02-delivery-journal.v1"}
        with mock.patch.dict("os.environ", {}, clear=True):
            bound = module._bind_qualification_clock(journal, run_created)
            self.assertEqual(bound["started_at"], start)
            self.assertEqual(bound["qualification_started_at"], start)
            self.assertEqual(bound["selected_run_created_at"], run_created)
            self.assertEqual(module._bind_qualification_clock(bound, run_created)["qualification_started_at"], start)
            remaining = module._require_hosted_budget(start, now.isoformat(),
                {"qualification_batch": {"wall_seconds": 86400, "runtime_wall_seconds": 64800,
                    "package_wall_seconds": 14400, "close_wall_seconds": 7200}}, phase="runtime")
            self.assertLess(remaining, 22 * 60 * 60)
            with self.assertRaisesRegex(ValueError, "clock-replaced"):
                module._bind_qualification_clock({**bound, "qualification_started_at": run_created}, run_created)
        with mock.patch.dict("os.environ", {"GENEWHIP_QUALIFICATION_STARTED_AT": run_created}):
            with self.assertRaisesRegex(ValueError, "does-not-match-publication-journal"):
                module._bind_qualification_clock(bound, run_created)

    def test_workflow_clock_rejects_replacement_future_or_late_dispatch(self):
        module = load_module(self)
        start = "2026-10-29T00:00:00Z"
        nonce = "a" * 32
        base = "b" * 40
        self.assertEqual(module._validate_workflow_clock(start, "2026-10-29T00:01:00Z",
            nonce, base, now="2026-10-29T00:02:00Z"), start)
        with self.assertRaisesRegex(ValueError, "dispatch-clock-invalid"):
            module._validate_workflow_clock(start, "2026-10-29T00:01:00Z", nonce, base,
                now="2026-10-28T23:59:00Z")
        with self.assertRaisesRegex(ValueError, "runtime-partition"):
            module._validate_workflow_clock(start, "2026-10-29T00:01:00Z", nonce, base,
                now="2026-10-29T18:00:01Z")
        with self.assertRaisesRegex(ValueError, "dispatch-nonce"):
            module._validate_workflow_clock(start, "2026-10-29T00:01:00Z", "bad", base,
                now="2026-10-29T00:02:00Z")

    def test_qualification_dispatch_carries_journal_clock_and_resumes_same_nonce(self):
        import subprocess
        from unittest import mock
        module = load_module(self)
        now = datetime.datetime.now(datetime.timezone.utc)
        start = (now - datetime.timedelta(minutes=1)).isoformat()
        base_sha = "b" * 40
        journal = {"schema": "genewhip.v02-delivery-journal.v1", "started_at": start,
            "qualification_started_at": start}
        scope = {"qualification_batch": {"wall_seconds": 86400,
            "runtime_wall_seconds": 64800, "package_wall_seconds": 14400,
            "close_wall_seconds": 7200}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journal.json"
            with mock.patch.object(module, "_external", return_value=subprocess.CompletedProcess([], 0, "", "")) as external:
                nonce = module._dispatch_qualification_run("example/genewhip", "a" * 40,
                    base_sha, path, journal, scope)
                first_command = external.call_args.args[0]
                self.assertIn("qualification_started_at=" + start, first_command)
                self.assertIn("qualification_base_sha=" + base_sha, first_command)
                self.assertIn("qualification_nonce=" + nonce, first_command)
                self.assertEqual(module._dispatch_qualification_run("example/genewhip", "a" * 40,
                    base_sha, path, journal, scope), nonce)
                self.assertEqual(external.call_count, 1)

    def test_selected_run_rerun_keeps_original_queue_clock(self):
        from unittest import mock
        module = load_module(self)
        created = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)).isoformat()
        base = {"id": 12345, "run_attempt": 1, "created_at": created,
            "repository": {"full_name": "szTheory/genewhip"},
            "path": ".github/workflows/ci.yml", "event": "workflow_dispatch",
            "display_title": "Plan10 qualification " + "a" * 32,
            "head_branch": "main", "head_sha": "a" * 40}
        rows = [dict(base, status="in_progress"),
                dict(base, run_attempt=2, status="in_progress"),
                dict(base, run_attempt=2, status="completed", conclusion="success")]
        scope = {"qualification_batch": {"wall_seconds": 86400,
            "runtime_wall_seconds": 64800, "package_wall_seconds": 14400,
            "close_wall_seconds": 7200}}
        nonce = "a" * 32
        with mock.patch.object(module, "_workflow_runs", side_effect=[[rows[1]], [rows[2]]]), \
             mock.patch.object(module.time, "sleep"):
            finished = module._wait_for_selected_run_completion("szTheory/genewhip", "a" * 40,
                rows[0], created, scope, nonce=nonce, base_sha="b" * 40)
        self.assertEqual(finished["run_attempt"], 2)
        self.assertEqual(finished["created_at"], created)
        changed_clock = dict(rows[1], created_at="2026-10-29T04:15:00Z")
        with mock.patch.object(module, "_workflow_runs", return_value=[changed_clock]):
            with self.assertRaisesRegex(ValueError, "creation-clock-changed"):
                module._wait_for_selected_run_completion("szTheory/genewhip", "a" * 40,
                    rows[0], created, scope, nonce=nonce, base_sha="b" * 40)

    def test_release_input_join_rejects_valid_but_different_transfer_bytes(self):
        module = load_module(self)
        with tempfile.TemporaryDirectory(prefix="gw-release-transfer-join-") as temp:
            root = Path(temp)
            names = [f"asset-{index}.tar.gz" for index in range(6)]
            assets = {}
            members = {}
            for index, name in enumerate(names):
                data = f"release-{index}".encode()
                (root / name).write_bytes(data)
                digest = hashlib.sha256(data).hexdigest()
                assets[name] = {"sha256": digest, "size": len(data)}
                members["artifacts/release-assets/" + name] = {"sha256": digest, "size": len(data)}
            for name in ("inventory.json", "SHA256SUMS"):
                data = name.encode()
                (root / name).write_bytes(data)
                members["artifacts/release-assets/" + name] = {
                    "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
            self.assertEqual(len(module._validate_release_transfer_join(assets, root, members)), 8)
            (root / names[0]).write_bytes(b"independently-valid-but-different")
            changed = hashlib.sha256((root / names[0]).read_bytes()).hexdigest()
            assets[names[0]] = {"sha256": changed, "size": (root / names[0]).stat().st_size}
            with self.assertRaisesRegex(ValueError, "authenticated-package-transfer"):
                module._validate_release_transfer_join(assets, root, members)

    def test_docs_adoption_receipt_names_exact_authenticated_archive_bytes(self):
        module = load_module(self)
        source = "a" * 40
        assets = {
            "genewhip-0.2.0-sdk-diagnostic-darwin-arm64-aaaaaaaaaaaa.tar.gz": {"sha256": "b" * 64},
            "genewhip-0.2.0-playable-preview-macos-arm64-aaaaaaaaaaaa.tar.gz": {"sha256": "c" * 64},
        }
        receipt = {"schema": "genewhip-docs-command-qualification-v2", "version": "0.2.0",
            "outcome": "pass", "mode": "clean-local-qualified", "packages": {
                "sdk": {"archive": next(n for n in assets if "sdk-diagnostic" in n),
                    "archive_sha256": "b" * 64, "source_revision": source, "source_state": "clean"},
                "desktop": {"archive": next(n for n in assets if "playable-preview" in n),
                    "archive_sha256": "c" * 64, "source_revision": source, "source_state": "clean"}}}
        bound = module._validate_docs_adoption_receipt(receipt, assets, source)
        self.assertEqual(bound["sdk"]["archive_sha256"], "b" * 64)
        changed = json.loads(json.dumps(receipt))
        changed["packages"]["desktop"]["archive_sha256"] = "d" * 64
        with self.assertRaisesRegex(ValueError, "authenticated-release-bytes"):
            module._validate_docs_adoption_receipt(changed, assets, source)

    def test_hosted_attestation_consumer_binds_run_attempt_signer_and_subject(self):
        from unittest import mock
        module = load_module(self)
        expected = "a" * 64
        invocation = "https://github.com/szTheory/genewhip/actions/runs/12345/attempts/2"
        def response(invocation_id):
            return json.dumps([{"verificationResult": {"statement": {
                "subject": [{"digest": {"sha256": expected}}],
                "predicate": {"runDetails": {"metadata": {"invocationId": invocation_id}}}}}}])
        with mock.patch.object(module, "_external", return_value=subprocess.CompletedProcess(
                [], 0, response(invocation), "")) as run:
            result = module._verify_attestation(Path("archive.tar.gz"), "szTheory/genewhip",
                "b" * 40, "12345", 2, expected)
            command = run.call_args.args[0]
            self.assertIn("--signer-digest", command)
            self.assertIn("--cert-oidc-issuer", command)
            self.assertEqual(result["run_attempt"], "2")
        for bad in ("https://github.com/szTheory/genewhip/actions/runs/999/attempts/2", None,
                    "https://github.com/szTheory/genewhip/actions/runs/12345/attempts/1"):
            with self.subTest(invocation=bad), mock.patch.object(module, "_external",
                    return_value=subprocess.CompletedProcess([], 0, response(bad), "")), \
                    self.assertRaisesRegex(ValueError, "hosted-attestation-rejected"):
                module._verify_attestation(Path("archive.tar.gz"), "szTheory/genewhip",
                    "b" * 40, "12345", 2, expected)

    def test_hosted_deadline_preserves_final_close_reserve(self):
        module = load_module(self)
        self.assertTrue(hasattr(module, "_require_hosted_budget"),
                        "hosted coordinator must preserve the single final-close reserve")
        scope = {"qualification_batch": {"wall_seconds": 86400,
            "runtime_wall_seconds": 64800, "package_wall_seconds": 14400,
            "close_wall_seconds": 7200, "publication_reserve_seconds": 7200}}
        start = "2026-10-29T00:00:00Z"
        self.assertGreater(module._require_hosted_budget(start, "2026-10-29T21:00:00Z", scope), 0)
        with self.assertRaisesRegex(ValueError, "final-close-reserve"):
            module._require_hosted_budget(start, "2026-10-29T22:01:00Z", scope)
        with self.assertRaisesRegex(ValueError, "common-cutoff"):
            module._require_hosted_budget(start, "2026-10-30T00:01:00Z", scope)
        with self.assertRaisesRegex(ValueError, "runtime-partition"):
            module._require_hosted_budget(start, "2026-10-29T18:00:01Z", scope, phase="runtime")
        with self.assertRaisesRegex(ValueError, "package-partition"):
            module._require_hosted_budget(start, "2026-10-29T22:00:01Z", scope, phase="package")

    def test_external_timeout_uses_monitored_process_group_and_retains_cleanup_receipt(self):
        require_process_context()
        import sys
        module = load_module(self)
        scratch = ROOT / "build/v02/coordinator-external-attempts"
        before = set(scratch.glob("*.attempt.json")) if scratch.exists() else set()
        command = [sys.executable, "-c", "import sys,time; print('bounded-output', flush=True); time.sleep(30)"]
        with self.assertRaisesRegex(ValueError, "hosted-delivery-command-unavailable"):
            module._external(command, timeout=1)
        after = set(scratch.glob("*.attempt.json")) - before
        self.assertEqual(len(after), 1, "timed-out process must leave one durable attempt receipt")
        attempt = json.loads(next(iter(after)).read_text())
        self.assertEqual(attempt["process_group_cleanup"], "confirmed")
        self.assertTrue(attempt["processes"])
        self.assertLessEqual(attempt["streams"]["stdout"]["retained_bytes"], 16 * 1024 * 1024)

    def test_git_blob_reader_uses_bounded_monitored_exact_byte_seam(self):
        require_process_context()
        from unittest import mock
        module = load_module(self)
        raw = b'{\r\n  "identity": "preserve exact bytes"\r\n}\r\n'
        with tempfile.TemporaryDirectory(prefix="gw-bounded-git-blob-") as temp:
            root = Path(temp)
            (root / "evidence").mkdir()
            scope = json.loads((ROOT / "evidence/v02-execution.json").read_text())
            (root / "evidence/v02-execution.json").write_text(json.dumps(scope))
            scratch = root / "build/v02/coordinator-external-attempts"
            scratch.mkdir(parents=True)
            calls = []
            starts = []

            def deny_process(*args, **kwargs):
                starts.append((args, kwargs))
                raise AssertionError("synthetic git blob must not start a process")

            def bounded(command, *, limits, scratch, timeout, label, env, cwd, check, scratch_roots):
                calls.append((command, limits, timeout, cwd, scratch_roots))
                return {"returncode": 0, "process_group_cleanup": "confirmed",
                    "streams": {"stdout": {"text": raw.decode("utf-8"),
                        "sha256": hashlib.sha256(raw).hexdigest(), "observed_bytes": len(raw),
                        "retained_bytes": len(raw), "truncated": False},
                        "stderr": {"text": "", "sha256": hashlib.sha256(b"").hexdigest(),
                            "observed_bytes": 0, "retained_bytes": 0, "truncated": False}}}

            with mock.patch.object(module, "ROOT", root), \
                 mock.patch.object(module, "_bounded_command", side_effect=bounded), \
                 mock.patch.object(module.subprocess, "Popen", side_effect=deny_process):
                observed = module.read_bounded_git_blob(root / "candidate", "a" * 40 + ":evidence/fixture.json")
            self.assertEqual(observed, raw, "Git JSON bytes including CRLF and trailing newline remain exact")
            self.assertEqual(starts, [], "independent sticky denial observed no real process start")
            command, limits, timeout, cwd, roots = calls[0]
            self.assertEqual(command, ["git", "show", "a" * 40 + ":evidence/fixture.json"])
            self.assertEqual(cwd, root / "candidate")
            self.assertEqual(timeout, 15)
            self.assertLessEqual(limits["max_scratch_bytes"], 128 * 1024)
            self.assertLessEqual(limits["max_stdout_stderr_bytes"], 128 * 1024)
            self.assertLessEqual(limits["max_capture_bytes"], 128 * 1024)
            self.assertLessEqual(limits["max_retained_bytes"], 128 * 1024)
            self.assertTrue(roots and roots[0].name.endswith(".tmp"))

    def test_hosted_dimension_requires_source_bound_actual_validator_mutant_receipt(self):
        from unittest import mock
        module = load_module(self)
        with tempfile.TemporaryDirectory(prefix="gw-mutant-receipt-contract-") as temp:
            root = Path(temp)
            runtime = root / "build/v02/runtime-observation"
            runtime.mkdir(parents=True)
            names = ("candidate.json", "core-report.json", "media-report.json",
                     "host-software.json", "host-native.json")
            reports = {}
            for name in names:
                path = runtime / name
                path.write_text("{}\n")
                reports[name] = hashlib.sha256(path.read_bytes()).hexdigest()
            fixture_spec = importlib.util.spec_from_file_location(
                "gw_receipt_expected_fixture", ROOT / "tests/fixtures/phase6_game.py")
            host_spec = importlib.util.spec_from_file_location(
                "gw_receipt_expected_host", ROOT / "tests/desktop/phase6_routes.py")
            fixture_module = importlib.util.module_from_spec(fixture_spec)
            fixture_spec.loader.exec_module(fixture_module)
            host_module = importlib.util.module_from_spec(host_spec)
            host_spec.loader.exec_module(host_module)
            core_rows = [{"name": name, "reason": reason, "status": "pass"}
                for name, reason in fixture_module.CORE_SEMANTIC_MUTANT_EXPECTATIONS]
            host_rows = [{"id": name, "expected_reason": reason, "actual_reason": reason, "rejected": True}
                for name, reason in host_module.HOST_SEMANTIC_MUTANT_EXPECTATIONS]
            result_root = root / "build/v02/evidence"
            result_root.mkdir(parents=True)
            result_rows = {"core": core_rows, "host": host_rows}
            mutant_results = {}
            result_paths = {}
            def refresh_result(name, rows):
                result_path = result_root / (name + "-mutants.json")
                result_path.write_text(json.dumps({"negative_controls" if name == "core" else "mutations": rows}))
                row_digest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                ref = {"path": result_path.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(result_path.read_bytes()).hexdigest(), "rows_sha256": row_digest}
                mutant_results[name] = ref
                result_paths[name] = result_path
                receipt[name] = {"denominator": len(rows), "pass": len(rows), "rows_sha256": row_digest}
            expected = {"source_sha": "a" * 40, "head_sha": "a" * 40, "base_sha": "b" * 40,
                "run_id": "123", "run_attempt": "2"}
            receipt = {"schema": "genewhip.v02-semantic-mutants.v1", "status": "pass",
                "identity": expected, "positive_reports": reports,
                "candidate_sha256": hashlib.sha256(b"{}").hexdigest(),
                "positive_validated_before_mutants": True, "host_native_positive_validated": True,
                "mutant_results": mutant_results,
                "coverage_transfer": {"from": ["phase6_core_report_contract", "phase6_host_contract"],
                    "to": "required-v02-hosted-source-qualified-runtime", "core_media_mutants": 32,
                    "host_mutants": 21, "includes": ["core-report", "candidate-identities", "raw-native",
                        "media-capture", "media-image", "media-audio", "six-host-roster",
                        "native-host-capability", "host-process-receipts", "raw-input-audio-renderer-core-output"],
                    "skip_allowed": False}, "new_title_launches": 0}
            for name, rows in result_rows.items():
                refresh_result(name, rows)
            path = root / "build/v02/semantic-mutant-receipt.json"
            path.write_text(json.dumps(receipt))
            starts = []
            def deny(*args, **kwargs):
                starts.append(args)
                raise AssertionError("receipt gate must not start a process")
            with mock.patch.object(module, "ROOT", root), mock.patch.dict(os.environ, {}, clear=True), \
                 mock.patch.object(module.subprocess, "Popen", side_effect=deny):
                module._validate_semantic_mutant_receipt(receipt, expected, root, ROOT)
                self.assertIsNone(module._semantic_mutant_receipt_error(expected))
                wrong_base = {**expected, "base_sha": "c" * 40}
                self.assertEqual(module._semantic_mutant_receipt_error(wrong_base),
                    "proof-semantic-mutant-receipt-invalid")
                cases = (
                    ("core", [{"name": "invented-" + str(i), "reason": "fake", "status": "pass"} for i in range(32)]),
                    ("core", [core_rows[0], core_rows[0], *core_rows[2:]]),
                    ("core", core_rows[:-1]),
                    ("core", [{**core_rows[0], "reason": "wrong-reason"}, *core_rows[1:]]),
                    ("host", [{"id": "invented-" + str(i), "expected_reason": "fake", "actual_reason": "fake", "rejected": True} for i in range(21)]),
                    ("host", [host_rows[0], host_rows[0], *host_rows[2:]]),
                    ("host", host_rows[:-1]),
                    ("host", [{**host_rows[0], "actual_reason": "wrong-reason"}, *host_rows[1:]]),
                )
                for name, altered_rows in cases:
                    refresh_result(name, altered_rows)
                    path.write_text(json.dumps(receipt))
                    self.assertEqual(module._semantic_mutant_receipt_error(expected),
                        "proof-semantic-mutant-result-roster-invalid", (name, altered_rows[0]))
                    result_rows[name] = core_rows if name == "core" else host_rows
                    refresh_result(name, result_rows[name])
                receipt["host"]["pass"] = 20
                path.write_text(json.dumps(receipt))
                self.assertEqual(module._semantic_mutant_receipt_error(expected),
                    "proof-semantic-mutant-receipt-invalid")
                path.unlink()
                self.assertEqual(module._semantic_mutant_receipt_error(expected),
                    "proof-semantic-mutant-receipt-missing")
            self.assertEqual(starts, [], "sticky denial observed zero process starts")

    def test_semantic_mutant_cli_rejects_expired_clock_before_bounded_launch(self):
        from unittest import mock
        module = load_module(self)
        with tempfile.TemporaryDirectory(prefix="gw-mutant-expired-clock-") as temp:
            root = Path(temp)
            (root / "evidence").mkdir()
            (root / "build/v02").mkdir(parents=True)
            scope = {"qualification_batch": {"wall_seconds": 100, "runtime_wall_seconds": 20,
                "package_wall_seconds": 60, "close_wall_seconds": 10},
                "per_child_limits": {"max_scratch_bytes": 1024, "max_stdout_stderr_bytes": 1024,
                    "max_capture_bytes": 1024, "max_retained_bytes": 1024}}
            scope_path = root / "evidence/v02-execution.json"
            scope_path.write_text(json.dumps(scope))
            starts = []
            def deny(*args, **kwargs):
                starts.append(args)
                raise AssertionError("expired semantic suite must not start a child")
            argv = ["--mode", "semantic-mutants", "--scope", str(scope_path), "--out",
                "build/v02/semantic-mutant-receipt.json", "--source-sha", "a"*40,
                "--head-sha", "a"*40, "--base-sha", "b"*40, "--run-id", "123", "--run-attempt", "1"]
            with mock.patch.object(module, "ROOT", root), \
                 mock.patch.dict(os.environ, {"GENEWHIP_QUALIFICATION_STARTED_AT":
                    (datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(seconds=200)).isoformat(),
                    "GENEWHIP_QUALIFICATION_PHASE": "package"}, clear=True), \
                 mock.patch.object(module, "_bounded_command", side_effect=deny), \
                 mock.patch.object(module.subprocess, "Popen", side_effect=deny):
                self.assertEqual(module.main(argv), 1)
            self.assertEqual(starts, [], "expired budget prevented every child start")
            self.assertFalse((root / "build/v02/semantic-mutant-receipt.json").exists(),
                "expired run did not leave a success-shaped receipt")

    def test_semantic_mutant_cli_clamps_worker_to_remaining_package_budget(self):
        from unittest import mock
        module = load_module(self)
        with tempfile.TemporaryDirectory(prefix="gw-mutant-package-clock-") as temp:
            root = Path(temp)
            (root / "evidence").mkdir()
            (root / "build/v02").mkdir(parents=True)
            scope = {"qualification_batch": {"wall_seconds": 100, "runtime_wall_seconds": 20,
                "package_wall_seconds": 60, "close_wall_seconds": 10},
                "per_child_limits": {"max_scratch_bytes": 1024, "max_stdout_stderr_bytes": 1024,
                    "max_capture_bytes": 1024, "max_retained_bytes": 1024}}
            scope_path = root / "evidence/v02-execution.json"
            scope_path.write_text(json.dumps(scope))
            started = (datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(seconds=30)).isoformat()
            observations = []
            def bounded(command, *, limits, timeout, **kwargs):
                observations.append((command, limits, timeout))
                out_path = Path(command[command.index("--out") + 1])
                out_path.write_text(json.dumps({"core": {"pass": 32}, "host": {"pass": 21}}))
                empty = hashlib.sha256(b"").hexdigest()
                return {"returncode": 0, "process_group_cleanup": "confirmed",
                    "streams": {key: {"text": "", "sha256": empty, "observed_bytes": 0,
                        "retained_bytes": 0, "truncated": False} for key in ("stdout", "stderr")}}
            starts = []
            def deny(*args, **kwargs):
                starts.append(args)
                raise AssertionError("fake bounded child must not start an OS process")
            argv = ["--mode", "semantic-mutants", "--scope", str(scope_path), "--out",
                "build/v02/semantic-mutant-receipt.json", "--source-sha", "a"*40,
                "--head-sha", "a"*40, "--base-sha", "b"*40, "--run-id", "123", "--run-attempt", "2"]
            with mock.patch.object(module, "ROOT", root), \
                 mock.patch.dict(os.environ, {"GENEWHIP_QUALIFICATION_STARTED_AT": started,
                    "GENEWHIP_QUALIFICATION_PHASE": "package"}, clear=True), \
                 mock.patch.object(module, "_bounded_command", side_effect=bounded), \
                 mock.patch.object(module, "_validate_semantic_mutant_receipt"), \
                 mock.patch.object(module.subprocess, "Popen", side_effect=deny):
                self.assertEqual(module.main(argv), 0)
            self.assertEqual(starts, [], "fake boundary intercepted all OS process starts")
            self.assertEqual(len(observations), 1)
            command, limits, timeout = observations[0]
            self.assertIn("semantic-mutants-worker", command)
            self.assertGreater(timeout, 40, "remaining package window was preserved")
            self.assertLessEqual(timeout, 52, "requested 900 second cap was reduced to the 50 second package remainder")
            self.assertEqual(limits["wall_seconds"], timeout)
            self.assertEqual(command[command.index("--base-sha") + 1], "b"*40,
                "selected base reached worker explicitly without ambient GitHub variables")

    def test_external_monitors_actual_owned_download_root_and_cleans_process_group(self):
        require_process_context()
        import shutil
        import sys
        import uuid
        module = load_module(self)
        scratch = ROOT / "build/v02/coordinator-external-attempts"
        before = set(scratch.glob("*.attempt.json")) if scratch.exists() else set()
        owned = ROOT / f"build/v02/test-owned-download-{uuid.uuid4().hex}"
        owned.mkdir(parents=True)
        command = [sys.executable, "-c",
            "import pathlib,sys,time; p=pathlib.Path(sys.argv[1])/'payload.bin'; "
            "f=p.open('wb'); "
            "[(f.write(b'x'*2048),f.flush(),time.sleep(.003)) for _ in range(1000)]", str(owned)]
        try:
            with self.assertRaisesRegex(ValueError, "hosted-delivery-command-unavailable"):
                module._external(command, timeout=10, owned_roots=(owned,), scratch_limit_bytes=8192)
            after = set(scratch.glob("*.attempt.json")) - before
            self.assertEqual(len(after), 1)
            attempt = json.loads(next(iter(after)).read_text())
            self.assertEqual(attempt["process_group_cleanup"], "confirmed")
            self.assertTrue(attempt["processes"][0]["bound_violation"])
            self.assertIn("phase7-scratch-byte-limit", attempt["stderr_tail"])
        finally:
            shutil.rmtree(owned)

    def _snapshot_repo(self, root, extra=None):
        require_process_context()
        root.mkdir(parents=True)
        subprocess.run(["git", "init", "-b", "main"], cwd=root, check=True,
                       capture_output=True, text=True)
        for key, value in (("user.name", "Fixture Maintainer"),
                           ("user.email", "maintainer@example.invalid")):
            subprocess.run(["git", "config", key, value], cwd=root, check=True,
                           capture_output=True, text=True)
        (root / "LICENSE").write_text("Permission is hereby granted, free of charge.\n")
        (root / "README.md").write_text("Public source snapshot fixture.\n")
        (root / "tests/vectors").mkdir(parents=True)
        (root / "tests/vectors/manifest.json").write_text('{"retained_files":[]}\n')
        subprocess.run(["git", "add", "--all"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-m", "public base"], cwd=root, check=True,
                       capture_output=True, text=True)
        base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        if extra:
            for name, content in extra.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
        subprocess.run(["git", "add", "--all"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-m", "candidate snapshot"], cwd=root, check=True,
                       capture_output=True, text=True)
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
        return base, head, sorted(path for path in paths if path)

    def test_public_snapshot_reopens_exact_public_parent_and_filtered_tree(self):
        require_process_context()
        module = load_module(self)
        with tempfile.TemporaryDirectory(prefix="gw-v02-public-snapshot-") as temp:
            candidate = Path(temp) / "publication"
            base, head, paths = self._snapshot_repo(candidate,
                {"packaging/NOTICES.md": "Fixture and dependency notices retained.\n"})
            result = module.validate_public_snapshot(candidate, base, head, paths)
            self.assertEqual(result["parent_shas"], [base])
            self.assertEqual(result["tracked_paths"], paths)
            self.assertEqual(result["history_commits"], 2)
            self.assertTrue(any(row["path"] == "LICENSE" for row in result["manifest"]))
            self.assertTrue(any(row["path"] == "packaging/NOTICES.md" for row in result["manifest"]))

    def test_public_snapshot_rejects_private_generated_paths_at_path_guard(self):
        require_process_context()
        module = load_module(self)
        with tempfile.TemporaryDirectory(prefix="gw-v02-public-path-") as temp:
            candidate = Path(temp) / "publication"
            base, head, paths = self._snapshot_repo(candidate,
                {".planning/private/receipt.json": "{}\n"})
            with self.assertRaisesRegex(ValueError, "public-snapshot-private-or-generated-path-present"):
                module.validate_public_snapshot(candidate, base, head, paths)

    def test_public_snapshot_rejects_secret_or_personal_path_from_history_hygiene(self):
        require_process_context()
        module = load_module(self)
        for name, content in (("leak.txt", "path /" + "Users" + "/alice/private/data\n"),
                              ("token.txt", "to" + "ken='ghp_" +
                               "abcdefghijklmnopqrstuvwxyz1234567890'\n")):
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="gw-v02-public-leak-") as temp:
                candidate = Path(temp) / "publication"
                base, head, paths = self._snapshot_repo(candidate, {name: content})
                with self.assertRaisesRegex(ValueError, "public-snapshot-hygiene-rejected"):
                    module.validate_public_snapshot(candidate, base, head, paths)

    def test_public_destination_resolves_only_from_authorized_public_packet(self):
        module = load_module(self)
        with tempfile.TemporaryDirectory(prefix="gw-v02-public-destination-") as temp:
            root = Path(temp)
            packet = root / "build/phase4/delivery-preflight.json"
            packet.parent.mkdir(parents=True)
            packet.write_text(json.dumps({"schema": "genewhip.publication-readiness-packet.v1",
                "repository": "maintainer/project", "destination": {
                    "owner_repository": "maintainer/project", "visibility": "public"},
                "history_disposition": "sanitized-snapshots-preserve-local-history"}))
            self.assertEqual(module._authorized_public_repository(root), "maintainer/project")
            packet.write_text(json.dumps({"schema": "genewhip.publication-readiness-packet.v1",
                "repository": "maintainer/project", "destination": {
                    "owner_repository": "maintainer/project", "visibility": "private"},
                "history_disposition": "sanitized-snapshots-preserve-local-history"}))
            with self.assertRaisesRegex(ValueError, "authorized-public-destination-record-unavailable"):
                module._authorized_public_repository(root)
            packet.write_text("[]\n")
            with self.assertRaisesRegex(ValueError, "authorized-public-destination-record-unavailable"):
                module._authorized_public_repository(root)
            packet.write_text(json.dumps({"schema": "genewhip.publication-readiness-packet.v1",
                "repository": "https://github.com/maintainer/project", "destination": {
                    "owner_repository": "https://github.com/maintainer/project", "visibility": "public"},
                "history_disposition": "sanitized-snapshots-preserve-local-history"}))
            with self.assertRaisesRegex(ValueError, "authorized-public-destination-record-unavailable"):
                module._authorized_public_repository(root)

    def test_public_fixture_projection_restores_only_existing_public_revision(self):
        require_process_context()
        module = load_module(self)
        with tempfile.TemporaryDirectory(prefix="gw-v02-public-fixture-revision-") as temp:
            root = Path(temp)
            public = root / "public"
            public.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=public, check=True,
                           capture_output=True, text=True)
            for key, value in (("user.name", "Fixture Maintainer"),
                               ("user.email", "maintainer@example.invalid")):
                subprocess.run(["git", "config", key, value], cwd=public, check=True,
                               capture_output=True, text=True)
            source_rel = "fixtures/independent-game-v2/src/game.s"
            rom_rel = "fixtures/independent-game-v2/game.bin"
            manifest_rel = "fixtures/manifest.json"
            evidence_rel = "evidence/independent-game-v2.json"
            (public / source_rel).parent.mkdir(parents=True, exist_ok=True)
            (public / source_rel).write_text("source bytes unchanged\n")
            (public / rom_rel).write_bytes(b"admitted-rom")
            subprocess.run(["git", "add", "--all"], cwd=public, check=True)
            subprocess.run(["git", "commit", "-m", "fixture source"], cwd=public, check=True,
                           capture_output=True, text=True)
            public_revision = subprocess.check_output(
                ["git", "log", "--follow", "--format=%H", "-1", "--", source_rel],
                cwd=public, text=True).strip()
            source_sha = hashlib.sha256((public / source_rel).read_bytes()).hexdigest()
            rom_sha = hashlib.sha256((public / rom_rel).read_bytes()).hexdigest()
            evidence = {"identities": {"source_revision": public_revision, "source_sha256": source_sha}}
            evidence_bytes = (json.dumps(evidence, sort_keys=True, indent=2) + "\n").encode()
            evidence_path = public / evidence_rel
            evidence_path.parent.mkdir(parents=True, exist_ok=True)
            evidence_path.write_bytes(evidence_bytes)
            row = {"id": "genewhip-independent-game-v2", "status": "admitted", "outcome": "pass",
                "source": source_rel, "rom": rom_rel, "source_sha256": source_sha,
                "sha256": rom_sha, "revision": public_revision,
                "evidence_sha256": hashlib.sha256(evidence_bytes).hexdigest()}
            manifest_path = public / manifest_rel
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(json.dumps({"fixtures": [row]}))
            subprocess.run(["git", "add", "--all"], cwd=public, check=True)
            subprocess.run(["git", "commit", "-m", "fixture evidence"], cwd=public, check=True,
                           capture_output=True, text=True)
            base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=public, text=True).strip()

            private = root / "private-source"
            (private / source_rel).parent.mkdir(parents=True, exist_ok=True)
            (private / source_rel).write_bytes((public / source_rel).read_bytes())
            (private / rom_rel).parent.mkdir(parents=True, exist_ok=True)
            (private / rom_rel).write_bytes((public / rom_rel).read_bytes())
            private_row = dict(row, revision="f" * 40)
            private_evidence = {"identities": {"source_revision": "f" * 40,
                "source_sha256": source_sha}}
            private_evidence_bytes = (json.dumps(private_evidence, sort_keys=True, indent=2) + "\n").encode()
            private_row["evidence_sha256"] = hashlib.sha256(private_evidence_bytes).hexdigest()
            (private / evidence_rel).parent.mkdir(parents=True, exist_ok=True)
            (private / evidence_rel).write_bytes(private_evidence_bytes)
            (private / manifest_rel).parent.mkdir(parents=True, exist_ok=True)
            (private / manifest_rel).write_text(json.dumps({"fixtures": [private_row]}))
            for rel in (source_rel, rom_rel, evidence_rel, manifest_rel):
                path = public / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((private / rel).read_bytes())
            module.preserve_existing_public_fixture_revision(private, public, base)
            normalized = json.loads((public / manifest_rel).read_text())["fixtures"][0]
            normalized_evidence = json.loads((public / evidence_rel).read_text())
            self.assertEqual(normalized["revision"], public_revision)
            self.assertEqual(normalized_evidence["identities"]["source_revision"], public_revision)
            self.assertEqual(normalized["evidence_sha256"],
                hashlib.sha256((public / evidence_rel).read_bytes()).hexdigest())

    def test_public_fixture_projection_preserves_v1_source_history(self):
        require_process_context()
        module = load_module(self)
        with tempfile.TemporaryDirectory(prefix="gw-v02-public-v1-fixture-revision-") as temp:
            root = Path(temp)
            public = root / "public"
            public.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=public, check=True,
                           capture_output=True, text=True)
            for key, value in (("user.name", "Fixture Maintainer"),
                               ("user.email", "maintainer@example.invalid")):
                subprocess.run(["git", "config", key, value], cwd=public, check=True,
                               capture_output=True, text=True)
            source_rel = "fixtures/independent-game/src/game.s"
            rom_rel = "fixtures/independent-game/game.bin"
            manifest_rel = "fixtures/manifest.json"
            evidence_rel = "evidence/independent-game.json"
            (public / source_rel).parent.mkdir(parents=True)
            (public / source_rel).write_text("public v1 source bytes\n")
            (public / rom_rel).write_bytes(b"admitted-v1-rom")
            subprocess.run(["git", "add", "--all"], cwd=public, check=True)
            subprocess.run(["git", "commit", "-m", "v1 source"], cwd=public, check=True,
                           capture_output=True, text=True)
            revision = subprocess.check_output(["git", "log", "--follow", "--format=%H", "-1", "--", source_rel],
                                               cwd=public, text=True).strip()
            source_sha = hashlib.sha256((public / source_rel).read_bytes()).hexdigest()
            rom_sha = hashlib.sha256((public / rom_rel).read_bytes()).hexdigest()
            evidence = {"identities": {"source_sha256": source_sha, "candidate_source_sha256": source_sha}}
            evidence_bytes = (json.dumps(evidence, indent=2) + "\n").encode()
            (public / evidence_rel).parent.mkdir(parents=True)
            (public / evidence_rel).write_bytes(evidence_bytes)
            row = {"id": "genewhip-independent-game-v1", "status": "admitted", "outcome": "pass",
                "source": source_rel, "rom": rom_rel, "source_sha256": source_sha,
                "sha256": rom_sha, "revision": revision,
                "evidence_sha256": hashlib.sha256(evidence_bytes).hexdigest()}
            (public / manifest_rel).write_text(json.dumps({"fixtures": [row]}))
            subprocess.run(["git", "add", "--all"], cwd=public, check=True)
            subprocess.run(["git", "commit", "-m", "v1 admission"], cwd=public, check=True,
                           capture_output=True, text=True)
            base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=public, text=True).strip()
            private = root / "private-source"
            for rel in (source_rel, rom_rel):
                destination = private / rel
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((public / rel).read_bytes())
            private_row = dict(row, revision="f" * 40)
            private_bytes = evidence_bytes
            private_row["evidence_sha256"] = hashlib.sha256(private_bytes).hexdigest()
            (private / evidence_rel).parent.mkdir(parents=True)
            (private / evidence_rel).write_bytes(private_bytes)
            (private / manifest_rel).parent.mkdir(parents=True, exist_ok=True)
            (private / manifest_rel).write_text(json.dumps({"fixtures": [private_row]}))
            for rel in (evidence_rel, manifest_rel):
                destination = public / rel
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((private / rel).read_bytes())
            module.preserve_existing_public_fixture_revision(private, public, base)
            normalized = json.loads((public / manifest_rel).read_text())["fixtures"][0]
            normalized_evidence = json.loads((public / evidence_rel).read_text())
            self.assertEqual(normalized["revision"], revision)
            self.assertEqual(normalized_evidence, evidence)
            self.assertEqual(normalized["evidence_sha256"], hashlib.sha256((public / evidence_rel).read_bytes()).hexdigest())

    def test_public_provenance_crosswalk_reports_both_fixture_generations(self):
        module = load_module(self)
        source_rows = []
        public_rows = []
        for version in ("v1", "v2"):
            suffix = "" if version == "v1" else "-v2"
            fixture_id = "genewhip-independent-game-" + version
            source_rows.append({"id": fixture_id, "source": f"fixtures/independent-game{suffix}/src/game.s",
                "source_sha256": "a" * 64, "rom": f"fixtures/independent-game{suffix}/game.bin",
                "sha256": "b" * 64, "revision": "c" * 40})
            public_rows.append({"id": fixture_id, "revision": "d" * 40, "evidence_sha256": "e" * 64})
        rows = module.preserved_fixture_provenance({"fixtures": source_rows}, {"fixtures": public_rows})
        self.assertEqual([row["fixture_id"] for row in rows], [
            "genewhip-independent-game-v1", "genewhip-independent-game-v2"])
        self.assertEqual([row["private_tree_revision"] for row in rows], ["c" * 40] * 2)
        self.assertEqual([row["public_source_revision"] for row in rows], ["d" * 40] * 2)

    def test_projection_crosswalk_names_filtered_receipts_and_raw_build_products(self):
        require_process_context()
        module = load_module(self)
        paths = module._publication_paths(ROOT)
        projection = module._projection_crosswalk(ROOT, paths)
        exact = {row["path"]: row["reason"] for row in projection["exact_local_exclusions"]}
        if subprocess.check_output(["git", "ls-files", "evidence/phase6-repairs.json"],
                                   cwd=ROOT, text=True):
            self.assertEqual(exact.get("evidence/phase6-repairs.json"),
                             "local-failed-or-diagnostic-receipt")
        else:
            self.assertNotIn("evidence/phase6-repairs.json", paths)
        if subprocess.check_output(["git", "ls-files", "fixtures/phase5-a/raw-build-1.bin"],
                                   cwd=ROOT, text=True):
            self.assertEqual(exact.get("fixtures/phase5-a/raw-build-1.bin"),
                             "intermediate-fixture-build-product")
        else:
            self.assertNotIn("fixtures/phase5-a/raw-build-1.bin", paths)
        self.assertNotIn(".planning/STATE.md", paths)
        if subprocess.check_output(["git", "ls-files", "evidence/phase5-admission-a.json"],
                                   cwd=ROOT, text=True):
            self.assertEqual(exact.get("evidence/phase5-admission-a.json"),
                             "private-phase5-historical-evidence-and-receipts")
        if subprocess.check_output(["git", "ls-files", "fixtures/candidate-screening-v2.json"],
                                   cwd=ROOT, text=True):
            self.assertEqual(exact.get("fixtures/candidate-screening-v2.json"),
                             "private-phase5-screening-history")
    def test_benchmark_workload_contract_requires_exact21_children_and_one_host(self):
        import importlib.util
        path = ROOT / "tools/evidence/core_benchmark.py"
        spec = importlib.util.spec_from_file_location("gw_v02_benchmark_workload_contract", path)
        benchmark = importlib.util.module_from_spec(spec); spec.loader.exec_module(benchmark)
        for workload in ("control", "recursion94", "tank-battle"):
            fields = {"control": 600, "recursion94": 3631, "tank-battle": 4196}[workload]
            warmup = 120 if workload == "control" else 0
            identity = ({"video": [{"sequence": 1}], "pcm_frames": 100,
                "pcm_sha256": "a" * 64, "ram_sha256": "b" * 64, "machine_sha256": "c" * 64}
                if workload == "control" else {key: char * 64 for key, char in
                (("ram_sha256", "a"), ("cpu_sha256", "b"), ("controller_sha256", "c"),
                 ("video_sha256", "d"), ("pcm_sha256", "e"))})
            reference = {"workload": workload, "fields_completed": fields, "warmup_fields": warmup,
                "ticks_completed": 1000, "actual_tick_start": 0, "actual_tick_end": 1000,
                "elapsed_ns": 0, "untimed": True, "route_status": 0,
                "output_identity": identity, "process_id": 100, "process_instance": "reference"}
            if workload == "recursion94": reference["completed_steps"] = 3600
            timed = []
            for diagnostics in (False, True):
                for observer in ("sampled", "aggregate"):
                    for repetition in range(1, 6):
                        row = {"workload": workload, "fields_completed": fields, "warmup_fields": warmup,
                            "ticks_completed": 1000, "actual_tick_start": 0, "actual_tick_end": 1000,
                            "elapsed_ns": 10, "untimed": False, "route_status": 0,
                            "output_identity": identity, "untimed_output_identity": identity,
                            "diagnostics_enabled": diagnostics, "observer": observer, "repetition": repetition,
                            "process_id": 100 + repetition + (10 if diagnostics else 0) + (20 if observer == "aggregate" else 0),
                            "process_instance": f"{diagnostics}-{observer}-{repetition}"}
                        if workload == "recursion94": row["completed_steps"] = 3600
                        if observer == "sampled": row["field_ns"] = [1] * fields
                        else: row["field_ns"] = []
                        timed.append(row)
            report = {"schema": "genewhip.v02-workload-benchmark-v1", "workload": workload,
                "outcome": "pass", "qualification": True, "source_identity_sha256": "f" * 64,
                "source_revision": "1" * 40, "head_sha": "1" * 40, "base_sha": "2" * 40,
                "scope_id": "phase7-serial-child-workloads", "run_id": "123", "run_attempt": "1",
                "scope_sha256": "e" * 64,
                "build_identity": {**{key: "host" for key in ("host_system", "host_release", "host_macos_version", "host_machine", "host_model")},
                    "compiler_sha256": "a" * 64, "build_rules_sha256": "b" * 64,
                    "build_configuration_sha256": "c" * 64, "compiler_version_line": "clang version 1",
                    "cmake": {"CMAKE_BUILD_TYPE": "Release"}},
                "host_identity": {key: "host" for key in ("host_system", "host_release", "host_macos_version", "host_machine", "host_model")},
                "timed_runs": timed, "untimed_reference": reference,
                "counts": {"timed_children": 20, "untimed_references": 1, "process_starts": 21,
                    "timed_samples_per_mode": 5}}
            self.assertEqual(benchmark.validate_workload_report(report, workload, "f" * 64,
                "phase7-serial-child-workloads"), [])
            for mutation, expected in ((lambda data: data["timed_runs"].pop(), "workload-report-counts"),
                    (lambda data: data["host_identity"].update(host_machine="other"), "workload-report-host-identity"),
                    (lambda data: data.update(source_identity_sha256="0" * 64), "workload-report-source-identity")):
                changed = json.loads(json.dumps(report)); mutation(changed)
                problems = benchmark.validate_workload_report(changed, workload, "f" * 64,
                    "phase7-serial-child-workloads")
                self.assertTrue(any(expected in item for item in problems), (workload, expected, problems))

        identity = {"source_sha": "1" * 40, "head_sha": "1" * 40, "base_sha": "2" * 40,
                    "run_id": "123", "run_attempt": "1"}
        reports = {}
        for workload in ("control", "recursion94", "tank-battle"):
            fields = {"control": 600, "recursion94": 3631, "tank-battle": 4196}[workload]
            warmup = 120 if workload == "control" else 0
            identity_fields = ({"video": [{"sequence": 1}], "pcm_frames": 100,
                "pcm_sha256": "a" * 64, "ram_sha256": "b" * 64, "machine_sha256": "c" * 64}
                if workload == "control" else {key: char * 64 for key, char in
                (("ram_sha256", "a"), ("cpu_sha256", "b"), ("controller_sha256", "c"),
                 ("video_sha256", "d"), ("pcm_sha256", "e"))})
            reference = {"fields_completed": fields, "warmup_fields": warmup, "ticks_completed": 1000,
                "actual_tick_start": 0, "actual_tick_end": 1000, "elapsed_ns": 0, "untimed": True,
                "route_status": 0, "output_identity": identity_fields, "process_id": 900,
                "process_instance": workload + "-reference"}
            if workload == "recursion94": reference["completed_steps"] = 3600
            timed = []
            for diagnostics in (False, True):
                for observer in ("sampled", "aggregate"):
                    for repetition in range(1, 6):
                        row = {"fields_completed": fields, "warmup_fields": warmup,
                            "ticks_completed": 1000, "actual_tick_start": 0, "actual_tick_end": 1000,
                            "elapsed_ns": 10, "untimed": False, "route_status": 0,
                            "output_identity": identity_fields, "untimed_output_identity": identity_fields,
                            "diagnostics_enabled": diagnostics, "observer": observer, "repetition": repetition,
                            "process_id": 900 + repetition + int(diagnostics) * 10 + int(observer == "aggregate") * 20,
                            "process_instance": f"{workload}-{diagnostics}-{observer}-{repetition}"}
                        if workload == "recursion94": row["completed_steps"] = 3600
                        row["field_ns"] = [1] * fields if observer == "sampled" else []
                        timed.append(row)
            build = {**{key: "macOS fact" for key in ("host_system", "host_release", "host_macos_version", "host_machine", "host_model")},
                "compiler_sha256": "a" * 64, "build_rules_sha256": "b" * 64,
                "build_configuration_sha256": ("c" if workload == "control" else "d") * 64,
                "compiler_version_line": "clang version 1", "cmake": {"CMAKE_BUILD_TYPE": "Release"}}
            reports[workload] = {"schema": "genewhip.v02-workload-benchmark-v1", "workload": workload,
                "outcome": "pass", "qualification": True, "source_identity_sha256": "f" * 64,
                "source_revision": identity["source_sha"], "head_sha": identity["head_sha"],
                "base_sha": identity["base_sha"], "scope_id": "phase7-serial-child-workloads",
                "scope_sha256": "e" * 64, "run_id": "123", "run_attempt": "1",
                "build_identity": build, "host_identity": {key: build[key] for key in
                    ("host_system", "host_release", "host_macos_version", "host_machine", "host_model")},
                "timed_runs": timed, "untimed_reference": reference,
                "counts": {"timed_children": 20, "untimed_references": 1, "process_starts": 21,
                    "timed_samples_per_mode": 5}}
        raw_digests = {name: hashlib.sha256(name.encode()).hexdigest() for name in reports}
        projection = benchmark.build_public_performance_projection(reports, raw_digests,
            identity=identity, source_identity_sha256="f" * 64,
            scope_id="phase7-serial-child-workloads", scope_sha256="e" * 64)
        self.assertEqual(benchmark.validate_public_performance_projection(projection,
            identity=identity, source_identity_sha256="f" * 64,
            scope_id="phase7-serial-child-workloads", scope_sha256="e" * 64,
            expected_reports=reports, raw_report_digests=raw_digests), [])
        for workload, mutation, target in (
            ("control", lambda row: row.update(source_revision="9" * 40, head_sha="9" * 40),
             "public-performance-source-projection-mismatch"),
            ("recursion94", lambda row: row["build_identity"].update(build_configuration_sha256="9" * 64),
             "public-performance-source-projection-mismatch"),
            ("tank-battle", lambda row: row.update(scope_id="wrong-scope"), "public-performance-tank-battle"),
            ("control", lambda row: row.update(run_attempt="2"),
             "public-performance-source-projection-mismatch"),
            ("control", lambda row: row.update(workload="recursion94"),
             "public-performance-source-projection-mismatch")):
            changed = json.loads(json.dumps(projection))
            mutation(changed["workloads"][workload]["report"])
            item = changed["workloads"][workload]
            item["host_identity"] = item["report"].get("host_identity")
            item["build_identity"] = item["report"].get("build_identity")
            item["public_report_sha256"] = benchmark._canonical_json_sha256(item["report"])
            problems = benchmark.validate_public_performance_projection(changed,
                identity=identity, source_identity_sha256="f" * 64,
                scope_id="phase7-serial-child-workloads", scope_sha256="e" * 64,
                expected_reports=reports, raw_report_digests=raw_digests)
            self.assertTrue(any(target in item for item in problems), (target, problems))

    def test_plan_has_concrete_full_proof_commands_and_zero_launches(self):
        require_process_context()
        module = load_module(self)
        with tempfile.TemporaryDirectory(prefix="gw-v02-plan-build-") as temp:
            build = Path(temp) / "phase6"
            build.mkdir()
            (build / "CMakeCache.txt").write_text("synthetic plan-only build identity\n")
            plan = module.qualification_plan(build, ROOT / "evidence/v02-execution.json")
        self.assertEqual(plan["schema"], "genewhip.v02-qualification-plan.v1")
        self.assertEqual(plan["launch_count"], 0)
        self.assertEqual(set(plan["dimensions"]), set(module.REQUIRED_DIMENSIONS))
        self.assertTrue(plan["commands"])
        for command in plan["commands"]:
            self.assertTrue(command["argv"])
            self.assertTrue(command["output"])
            self.assertTrue(command["identity_dependencies"])

    def test_conjunction_rejects_missing_stale_skipped_and_native_missing(self):
        module = load_module(self)
        source = "a" * 40
        expected = {"source_sha": source, "head_sha": source, "base_sha": "b" * 40,
                    "run_id": "123", "run_attempt": "2"}
        with tempfile.TemporaryDirectory() as temp:
            module.ROOT = Path(temp)
            module._dimension_semantic_errors = lambda name, path, identity: []
            module._referenced_evidence_files = lambda sources: {}
            data = Path(temp) / "source.bin"
            workloads = {}
            for name in ("control", "recursion94", "tank-battle"):
                report_path = Path(temp) / (name + ".json")
                report = {"head_sha": expected["head_sha"], "base_sha": expected["base_sha"],
                    "run_id": expected["run_id"], "run_attempt": expected["run_attempt"],
                    "host_identity": {"host_model": name}}
                report_path.write_text(json.dumps(report))
                workloads[name] = {"path": str(report_path),
                    "sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
                    "host_identity": report["host_identity"], "process_starts": 21}
            data.write_text(json.dumps({"schema": "genewhip-v02-measurement-summary-v1", **expected,
                "workloads": workloads}))
            module._load_benchmark_module = lambda: type("BenchmarkContract", (), {
                "validate_workload_report": staticmethod(lambda *args: [])})
            evidence = {}
            closure_dimensions = {}
            for name in module.REQUIRED_DIMENSIONS:
                output = Path(temp) / f"{name}.json"
                observation = {"schema": "genewhip.v02-dimension-observation.v1", "dimension": name,
                    "outcome": "pass", "identity": expected, "evidence_path": str(data),
                    "evidence_sha256": hashlib.sha256(data.read_bytes()).hexdigest()}
                output.write_text(json.dumps(observation, sort_keys=True) + "\n")
                evidence[name] = {"schema": "genewhip.v02-dimension-proof.v1", "dimension": name,
                    "evidence_schema": "genewhip.v02-dimension-observation.v1", "outcome": "pass",
                    **expected, "output_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                    "output": str(output)}
                closure_dimensions[name] = {"path": data.relative_to(Path(temp)).as_posix(),
                    "sha256": hashlib.sha256(data.read_bytes()).hexdigest(), "identity": expected}
            evidence["host-native"]["capability"] = "present"
            closure = {"schema": "genewhip.v02-evidence-closure.v1", "identity": expected,
                "dimensions": closure_dimensions, "referenced_files": {}}
            self.assertEqual(module.validate_conjunction(evidence, expected, closure), [])
            for name in module.REQUIRED_DIMENSIONS:
                mutated = dict(evidence)
                mutated.pop(name)
                self.assertTrue(module.validate_conjunction(mutated, expected, closure), name)
            for outcome in ("skipped", "cancelled", "stale"):
                first = module.REQUIRED_DIMENSIONS[0]
                mutated = {**evidence, first: {**evidence[first], "outcome": outcome}}
                self.assertTrue(module.validate_conjunction(mutated, expected, closure), outcome)
            mutated = {**evidence, "host-native": {**evidence["host-native"], "capability": "missing"}}
            self.assertTrue(module.validate_conjunction(mutated, expected, closure), "native-capability")
            mutated = {**evidence, "core": {**evidence["core"], "dimension": "host"}}
            self.assertIn("proof-dimension-binding-invalid:core", module.validate_conjunction(mutated, expected, closure))

    def test_recomputed_outer_digests_still_reach_each_dimension_semantic_validator(self):
        module = load_module(self)
        source = "a" * 40
        expected = {"source_sha": source, "head_sha": source, "base_sha": "b" * 40,
            "run_id": "123", "run_attempt": "2"}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            module.ROOT = root
            def semantic(name, path, identity):
                return [] if json.loads(path.read_text()).get("valid") is True else ["semantic-mutant:" + name]
            module._dimension_semantic_errors = semantic
            evidence, closure_dimensions = {}, {}
            for name in module.REQUIRED_DIMENSIONS:
                raw = root / ("raw-" + name + ".json")
                raw.write_text(json.dumps({"dimension": name, "valid": True}) + "\n")
                output = root / ("proof-" + name + ".json")
                observation = {"schema": "genewhip.v02-dimension-observation.v1", "dimension": name,
                    "outcome": "pass", "identity": expected, "evidence_path": raw.relative_to(root).as_posix(),
                    "evidence_sha256": hashlib.sha256(raw.read_bytes()).hexdigest()}
                output.write_text(json.dumps(observation, sort_keys=True) + "\n")
                evidence[name] = {"schema": "genewhip.v02-dimension-proof.v1", "dimension": name,
                    "evidence_schema": observation["schema"], "outcome": "pass", **expected,
                    "output": output.relative_to(root).as_posix(), "output_sha256": hashlib.sha256(output.read_bytes()).hexdigest()}
                closure_dimensions[name] = {"path": raw.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(raw.read_bytes()).hexdigest(), "identity": expected}
            evidence["host-native"]["capability"] = "present"
            closure = {"schema": "genewhip.v02-evidence-closure.v1", "identity": expected,
                "dimensions": closure_dimensions, "referenced_files": {}}
            self.assertEqual(module.validate_conjunction(evidence, expected, closure), [])
            for name in module.REQUIRED_DIMENSIONS:
                if name == "measurements":
                    continue
                raw = root / ("raw-" + name + ".json")
                raw.write_text(json.dumps({"dimension": name, "valid": False}) + "\n")
                digest = hashlib.sha256(raw.read_bytes()).hexdigest()
                closure["dimensions"][name]["sha256"] = digest
                output = root / ("proof-" + name + ".json")
                observation = json.loads(output.read_text())
                observation["evidence_sha256"] = digest
                output.write_text(json.dumps(observation, sort_keys=True) + "\n")
                evidence[name]["output_sha256"] = hashlib.sha256(output.read_bytes()).hexdigest()
                problems = module.validate_conjunction(evidence, expected, closure)
                self.assertIn("semantic-mutant:" + name, problems)

    def test_coordinator_keeps_started_child_receipt_after_semantic_rejection(self):
        require_process_context()
        module = load_module(self)
        scope = json.loads((ROOT / "evidence/v02-execution.json").read_text())
        (ROOT / "build/v02").mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="gw-v02-coordinator-failure-", dir=ROOT / "build/v02") as temp:
            root = Path(temp)
            prior = root / "prior.json"
            prior.write_text('{"attempt":"preserve"}\n')
            attempt = module._bounded_command([__import__("sys").executable, "-I", "-c",
                "print('bounded coordinator child')"], limits=scope["per_child_limits"],
                scratch=root, timeout=5, label="synthetic")
            problems=module.validate_conjunction({}, {key:"x" for key in module.IDENTITY_FIELDS})
            self.assertIn("proof-missing:core", problems)
            retained = json.loads((root / "synthetic.attempt.json").read_text())
            retain_control_receipt("semantic-rejection", retained)
            self.assertEqual(attempt["process_group_cleanup"], "confirmed")
            self.assertEqual(retained["processes"][0]["status"], "completed")
            self.assertIn("bounded coordinator child", retained["streams"]["stdout"]["text"])
            self.assertEqual(module._public_argv([str(ROOT / "scripts/release/v02_qualification.py")]),
                ["scripts/release/v02_qualification.py"])
            self.assertEqual(module._public_argv(["/usr/bin/python3"]), ["/usr/bin/python3"])
            self.assertEqual(prior.read_text(), '{"attempt":"preserve"}\n')

    def test_fast_target_runs_named_contracts_without_legacy_phase6_window(self):
        text = (ROOT / "scripts/ci/required-gate.sh").read_text()
        self.assertIn("--phase7-fast", text)
        self.assertIn("v02_qualification_contract.py --contracts", text)
        self.assertNotIn("--phase6-local", text.split("--phase7-fast", 1)[1].split("fi", 1)[0])

    def test_workflow_wires_real_product_smoke_and_serial_full_jobs(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertRegex(text, r"(?m)^  product-smoke:\s*$")
        self.assertIn("scripts/evidence/v02_run.py --mode smoke", text)
        self.assertRegex(text, r"(?m)^  v02-release-qualification:\s*$")
        qualification_job = text.split("  v02-release-qualification:", 1)[1].split("\n  required-aggregate:", 1)[0]
        mutant_step = qualification_job.index("--mode semantic-mutants")
        close_step = qualification_job.index("--mode validate")
        self.assertLess(mutant_step, close_step, "actual-validator-mutants-must-precede-required-close")
        self.assertIn("--out build/v02/semantic-mutant-receipt.json", qualification_job)
        package_job = text.split("  v02-package:", 1)[1].split("\n  v02-release-qualification:", 1)[0]
        self.assertLess(package_job.index("--mode semantic-mutants"), package_job.index("--mode package"),
            "semantic-mutants-must-run-after-runtime-transfer-and-before-package-dimension-close")
        for argument in ("--source-sha \"$GITHUB_SHA\"", "--head-sha \"$GITHUB_SHA\"",
                         "--base-sha \"$GITHUB_BASE_SHA\"", "--run-id \"$GITHUB_RUN_ID\"",
                         "--run-attempt \"$GITHUB_RUN_ATTEMPT\""):
            self.assertIn(argument, package_job, "semantic-mutant-identity-not-explicit:" + argument)
        self.assertIn("timeout-minutes: 360", text)
        for name in ("v02-benchmark-control", "v02-benchmark-recursion94", "v02-benchmark-tank-battle"):
            self.assertIn(name, text)
        self.assertIn("name: v02-runtime-${{ github.run_id }}-${{ github.run_attempt }}", text)
        for workload in ("control", "recursion94", "tank-battle"):
            self.assertIn(f"name: v02-benchmark-{workload}-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}", text)
        self.assertGreaterEqual(text.count("uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"), 4)
        self.assertGreaterEqual(text.count("run-id: ${{ github.run_id }}"), 4)
        self.assertGreaterEqual(text.count("github.run_attempt }}"), 8)
        self.assertIn("max-parallel: 1", text)
        self.assertIn("build/v02/runtime-transfer/payload/build/v02/**", text)
        self.assertIn("scripts/release/v02_transfer.py install", text)
        self.assertIn("scripts/release/v02_transfer.py prepare-package", text)
        self.assertGreaterEqual(text.count("uses: ./.github/actions/qualification-clock"), 15)
        self.assertNotIn("GENEWHIP_QUALIFICATION_STARTED_AT: ${{ github.run_started_at }}", text)
        clock_action = (ROOT / ".github/actions/qualification-clock/action.yml").read_text()
        self.assertIn("actions/runs/$GITHUB_RUN_ID", clock_action)
        self.assertIn("--jq .created_at", clock_action)
        self.assertIn("prepare-package --root . --out build/v02/package-transfer --source-sha \"$GITHUB_SHA\"", text)
        self.assertIn("build/v02/package-transfer/payload/**", text)
        self.assertIn("scripts/release/v02_transfer.py install-package", text)
        self.assertNotIn("build/v02/runtime/core-work/**", text)
        self.assertNotIn("build/v02/runtime/chunk-work/**", text)
        self.assertNotIn("build/v02/runtime/input-contract/**", text)
        self.assertIn("artifacts/qualification-command-attempts/public-hygiene.attempt.json",
            (ROOT / "scripts/release/v02_transfer.py").read_text())

    def test_runtime_transfer_download_layout_matches_extracted_artifact_root(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text()
        section = text.split("- name: Download exact runtime attempt", 1)[1].split("- name: Download exact control benchmark attempt", 1)[0]
        self.assertIn("path: build/v02/runtime-transfer", section)
        self.assertIn("--payload build/v02/runtime-transfer/payload", text)
        self.assertIn("--inventory build/v02/runtime-transfer/inventory.json", text)

    def test_run_package_materializes_valid_projection_before_first_builder(self):
        require_process_context()
        import importlib.util
        import subprocess
        from unittest import mock

        module = load_module(self)
        benchmark_spec = importlib.util.spec_from_file_location("gw_v02_ordered_package_benchmark",
            ROOT / "tools/evidence/core_benchmark.py")
        benchmark = importlib.util.module_from_spec(benchmark_spec)
        benchmark_spec.loader.exec_module(benchmark)
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        expected = {"source_sha": head, "head_sha": head, "base_sha": "b" * 40,
            "run_id": "98765", "run_attempt": "3"}
        source_identity = benchmark.source_identity()
        scope_bytes = (ROOT / "evidence/v02-execution.json").read_bytes()
        scope = json.loads(scope_bytes)
        reports = synthetic_qualified_reports(benchmark, expected, source_identity,
            scope["scope_id"], hashlib.sha256(scope_bytes).hexdigest())
        raw_digests = {}

        with tempfile.TemporaryDirectory(prefix="gw-package-projection-order-") as temp:
            root = Path(temp)
            public = root / "build/v02/public"
            public.mkdir(parents=True)
            (root / "build/v02/runtime-identity.json").write_text(json.dumps({
                "source_sha256": source_identity, "git_head": head, "base_sha": expected["base_sha"],
                "run_id": expected["run_id"], "run_attempt": expected["run_attempt"]}))
            (public / "observations.json").write_text("{}")
            (root / "evidence").mkdir()
            (root / "evidence/v02-execution.json").write_bytes(scope_bytes)
            for workload, report in reports.items():
                path = root / "build/v02/collected" / ("benchmark-" + workload) / ("benchmark-" + workload + ".json")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(report, sort_keys=True))
                raw_digests[workload] = hashlib.sha256(path.read_bytes()).hexdigest()

            runtime = type("Runtime", (), {"source_identity": lambda self, routes: {"source_sha256": source_identity},
                "_module": lambda self, path, name: object()})()
            matrix = type("Matrix", (), {"verify_public_closure": lambda *args: None,
                "validate_qualification_matrix": lambda *args: None})()
            module.ROOT = root
            module._identity = lambda: expected
            module._load_runtime_module = lambda: runtime
            module._load_matrix_module = lambda: matrix
            module._load_benchmark_module = lambda: benchmark

            class ReachedFirstBuilder(Exception):
                pass

            def builder_boundary(command, *, limits, scratch, timeout, label, env):
                self.assertEqual(label, "package-sdk")
                projection_path = public / "performance.json"
                self.assertTrue(projection_path.is_file(), "projection must exist before SDK builder invocation")
                projection = json.loads(projection_path.read_text())
                errors = benchmark.validate_public_performance_projection(projection,
                    identity=expected, source_identity_sha256=source_identity,
                    scope_id=scope["scope_id"], scope_sha256=hashlib.sha256(scope_bytes).hexdigest(),
                    expected_reports=reports, raw_report_digests=raw_digests)
                self.assertEqual(errors, [])
                raise ReachedFirstBuilder()

            with mock.patch.object(module, "_bounded_command", side_effect=builder_boundary):
                with self.assertRaises(ReachedFirstBuilder):
                    module.run_package(public, root / "artifacts/v02")


if __name__ == "__main__":
    if "--host-process-context" in sys.argv:
        sys.argv.remove("--host-process-context")
        os.environ["GENEWHIP_PROCESS_CONTEXT"] = "host-cleanup-v1"
    if "--contracts" in __import__("sys").argv:
        require_process_context()
        __import__("sys").argv.remove("--contracts")
    unittest.main(verbosity=2)

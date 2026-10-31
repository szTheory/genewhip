#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""LOCAL-ONLY Phase 7 continuation contract; requires private planning and retained proof inputs."""
from __future__ import annotations

import argparse
import ast
import ctypes
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
PHASE = Path(".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery")
PACKET = PHASE / "07-16-ADMISSION.json"
ORIGINAL_REV = "e3abf05"
NATIVE_DENIALS: list[str] = []
TEMPORARY: tempfile.TemporaryDirectory[str] | None = None
SNAPSHOT: Path | None = None
PACKET_VALUE: dict | None = None
CURRENT_TEMPORARY: tempfile.TemporaryDirectory[str] | None = None
CURRENT_ROOT: Path | None = None
ORIGINAL_BLOBS: dict[str, bytes] = {}


def successful_ledger(result, receipt, *, operator_route, native_denials):
    starts = receipt["real_child_starts"]
    readonly = receipt["readonly_git_starts"]
    children_ok = starts == readonly and starts > 0 if operator_route else starts == readonly == 0
    return (result.wasSuccessful() and receipt["unexpected_denials"] == 0
        and children_ok and native_denials == 2)


def publication_sentinel():
    # Deliberately not a Git SHA or evidence of publication.
    return {"status": "stubbed-at-publish-boundary",
        "public_source_sha": "SYNTHETIC-NON-PUBLICATION"}


def bounded_readonly_git_runner(denial, original_run):
    """One operator check's exact Git policy and POSTCAPTURE rejection limits."""
    git_deadline = time.monotonic() + 180
    git_output_bytes = 0
    git_calls = []

    def check_capture(command, cwd, stdout, stderr):
        nonlocal git_output_bytes
        stdout, stderr = stdout or b"", stderr or b""
        stdout_size = len(stdout.encode() if isinstance(stdout, str) else stdout)
        stderr_size = len(stderr.encode() if isinstance(stderr, str) else stderr)
        # POSTCAPTURE rejection thresholds, not in-flight memory caps. Only
        # frozen-candidate cat-file --batch needs the measured larger stdout.
        _root, normalized = denial.normalized_readonly_git(command, cwd)
        stdout_cap = (64 if normalized == ("git", "cat-file", "--batch") else 32) * 1024 * 1024
        if stdout_size > stdout_cap or stderr_size > 1024 * 1024:
            raise AssertionError("operator route Git output exceeds per-command cap")
        git_output_bytes += stdout_size + stderr_size
        if git_output_bytes > 256 * 1024 * 1024:
            raise AssertionError("operator route Git output exceeds cumulative cap")

    def bounded_readonly_git(command, *args, **kwargs):
        if len(git_calls) >= 64:
            raise AssertionError("operator route Git invocation cap exceeded")
        cwd = kwargs.get("cwd")
        if not denial.readonly_git_event_allowed(kwargs.get("executable"), command, cwd):
            raise AssertionError("operator route attempted unapproved Git: " + repr(command))
        supplied_timeout = kwargs.get("timeout")
        if supplied_timeout is None:
            supplied_timeout = 30
        remaining = git_deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError("operator route read-only Git wall bound exceeded")
        kwargs["timeout"] = min(supplied_timeout, 30, remaining)
        input_value = kwargs.get("input")
        input_size = len(input_value.encode() if isinstance(input_value, str) else input_value or b"")
        if input_size > 16 * 1024 * 1024:
            raise AssertionError("operator route Git input exceeds cap")
        # Count attempted delegation, including failures. Audit equality below
        # still rejects any recorded invocation that never actually started.
        git_calls.append(tuple(command))
        try:
            with denial.owned_readonly_git_cleanup():
                result = original_run(command, *args, **kwargs)
        except subprocess.CalledProcessError as error:
            check_capture(command, cwd, error.stdout, error.stderr)
            raise
        check_capture(command, cwd, result.stdout, result.stderr)
        return result

    return bounded_readonly_git, git_calls


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _prepare_original_snapshot() -> None:
    """Authenticate original blobs before denial hooks, then copy bounded raw inputs."""
    global TEMPORARY, SNAPSHOT, PACKET_VALUE, CURRENT_TEMPORARY, CURRENT_ROOT, ORIGINAL_BLOBS
    packet_bytes = (ROOT / PACKET).read_bytes()
    if sha(packet_bytes) != "b09dbe94769204a87ad7a84e9a37a37c81a0c3ae03f5c69fd3e3e1e415923031":
        raise AssertionError("original packet pin changed")
    PACKET_VALUE = json.loads(packet_bytes)
    sources = PACKET_VALUE.get("sources")
    if not isinstance(sources, dict) or len(sources) != 17:
        raise AssertionError("original source roster is incomplete")
    TEMPORARY = tempfile.TemporaryDirectory(prefix="gw17-test-original-")
    SNAPSHOT = Path(TEMPORARY.name).resolve()
    for relative, expected in sorted(sources.items()):
        result = subprocess.run(["git", "show", f"{ORIGINAL_REV}:{relative}"], cwd=ROOT,
            capture_output=True, timeout=15, check=False)
        if result.returncode or len(result.stdout) > 1024 * 1024 or sha(result.stdout) != expected:
            raise AssertionError("trusted original Git blob mismatch: " + relative)
        target = SNAPSHOT / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(result.stdout)
        ORIGINAL_BLOBS[relative] = result.stdout
    paths = ["evidence/v02-execution.json", "build/phase4/delivery-preflight.json",
        "build/phase4/authorized-preflight.json", "build/v02/campaign15/campaign.json",
        "build/v02/campaign15/attempt2-started.json", "build/v02/campaign15/attempt3-started.json",
        "build/v02/campaign15/attempt4-started.json", "build/v02/recovery15",
        "build/v02/recovery15-attempt1", "build/v02/recovery15-attempt2",
        f"{PHASE}/history/07-15-before-supersession.md"]
    paths.extend(str(path.relative_to(ROOT)) for pattern in ("07-15-*", "07-16-*")
        for path in sorted((ROOT / PHASE).glob(pattern)) if path.is_file())
    total = 0
    for relative in sorted(set(paths)):
        source = ROOT / relative
        if source.is_symlink():
            raise AssertionError("original input unexpectedly linked")
        files = sorted(source.rglob("*")) if source.is_dir() else [source]
        for file in files:
            if file.is_symlink():
                raise AssertionError("raw proof input unexpectedly linked")
            if not file.is_file():
                continue
            info = file.lstat()
            if info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size > 1024 * 1024:
                raise AssertionError("raw proof input exceeds bounded-copy policy")
            data = file.read_bytes()
            total += len(data)
            if total > 16 * 1024 * 1024:
                raise AssertionError("raw proof copy limit exceeded")
            target = SNAPSHOT / file.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    CURRENT_TEMPORARY = tempfile.TemporaryDirectory(prefix="gw17-current-fixture-")
    CURRENT_ROOT = Path(CURRENT_TEMPORARY.name).resolve()
    shutil.copytree(SNAPSHOT, CURRENT_ROOT, dirs_exist_ok=True)
    for relative in ("scripts/release/v02_qualification.py",
            "scripts/release/v02_continuation.py",
            "scripts/ci/public_hygiene.py",
            "tests/evidence/phase7_continuation_contract.py",
            "tests/evidence/phase7_return_consumer_contract.py",
            "tests/evidence/phase7_creation_receipts_contract.py",
            str(PHASE / "07-17-CONTEXT.md"), str(PHASE / "07-17-PLAN.md"),
            str(PHASE / "07-10-PLAN.md"), str(PHASE / "07-11-PLAN.md"),
            ".planning/debug/targeted-process-cleanup-source.md",
            ".planning/debug/targeted-process-cleanup-security.md"):
        source = ROOT / relative
        target = CURRENT_ROOT / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def _deny_native(event, _args):
    if event in ("ctypes.dlopen", "ctypes.dlsym", "ctypes.dlsym/handle"):
        NATIVE_DENIALS.append(event)
        raise PermissionError("sticky-native-denial")


def native_self_test() -> None:
    before = len(NATIVE_DENIALS)
    try:
        ctypes.CDLL("/__gw17_native_denial_probe__")
    except PermissionError as error:
        if str(error) != "sticky-native-denial" or len(NATIVE_DENIALS) != before + 1:
            raise AssertionError("native-denial-self-test-wrong-boundary") from error
    else:
        raise AssertionError("native-denial-self-test-not-reached")


def load(relative: str, name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    if spec is None or spec.loader is None:
        raise AssertionError("module unavailable: " + relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bootstrap() -> None:
    # No production module is imported before both process and native denial self-tests.
    if SNAPSHOT is None:
        _prepare_original_snapshot()
    denial = load("tests/evidence/phase7_sticky_denial.py", "continuation_sticky_denial")
    denial.install()
    sys.addaudithook(_deny_native)
    native_self_test()
    global process_denial, continuation, coordinator, original_runner
    process_denial = denial
    continuation = load("scripts/release/v02_continuation.py", "phase7_continuation")
    coordinator = load("scripts/release/v02_qualification.py", "phase7_current_coordinator")
    original_runner = load("tests/evidence/phase7_wrapper_return.py", "phase7_original_owner")


class ContinuationContracts(unittest.TestCase):
    @staticmethod
    def _fake_git_popen(denial, outcome):
        class FakePopen:
            def __init__(self, command, **kwargs):
                denial.deny("subprocess.Popen", ("git", command, kwargs.get("cwd"), None))
                self.args, self.pid, self.returncode = command, 123456789, None
                self.outcome = outcome(command, kwargs)
            def __enter__(self): return self
            def __exit__(self, *_args): pass
            def communicate(self, _input=None, timeout=None):
                self.returncode, stdout, stderr = self.outcome
                return stdout, stderr
            def poll(self): return self.returncode
        return FakePopen

    def test_failed_git_starts_count_through_real_provenance_fallback(self):
        denial = load("tests/evidence/phase7_sticky_denial.py", "fake_failed_provenance_denial")
        provenance = load("scripts/fixtures/source_provenance.py", "real_failed_provenance")
        with tempfile.TemporaryDirectory(prefix="gw-fake-provenance-no-client-") as temporary:
            root = Path(temporary)
            source, rom = b"synthetic fixture source\n", b"synthetic non-executable fixture\n"
            row = {"id": "synthetic-fixture", "revision": "a" * 40,
                "source": provenance.SOURCE, "source_sha256": sha(source),
                "rom": "fixtures/synthetic.bin", "sha256": sha(rom)}
            for relative, data in ((row["source"], source), (row["rom"], rom)):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            previous_evidence = b"synthetic historical evidence\n"
            prior = {**row, "evidence_sha256": sha(previous_evidence)}
            failures = []
            def outcome(command, kwargs):
                args = command[3:]
                if args[:1] == ["log"]:
                    return 0, "b" * 40 + "\n", ""
                if args[:2] == ["rev-parse", "--verify"]:
                    failures.append(tuple(command))
                    return 128, "", "fatal: missing synthetic immutable tag\n"
                if args == ["show", "HEAD^:fixtures/manifest.json"]:
                    return 0, json.dumps({"fixtures": [prior]}), ""
                if args == ["show", "HEAD^:evidence/independent-game-v2.json"]:
                    return 0, previous_evidence, b""
                raise AssertionError("unexpected fake provenance query")
            denial.enable_readonly_git(root, ROOT)
            original_run = subprocess.run
            run, calls = bounded_readonly_git_runner(denial, original_run)
            with mock.patch.object(subprocess, "Popen", self._fake_git_popen(denial, outcome)), \
                    mock.patch.object(subprocess, "run", side_effect=run):
                for _ in range(2):
                    self.assertEqual(provenance.proven_revision(row, root), row["revision"])
            self.assertEqual(len(failures), 2)
            self.assertEqual(len(calls), 8)
            self.assertEqual(denial.receipt()["readonly_git_starts"], len(calls))
            self.assertEqual(denial.receipt()["unexpected_denials"], 0)
            denial.disable_readonly_git()

    def test_failed_git_output_caps_and_original_check_semantics(self):
        denial = load("tests/evidence/phase7_sticky_denial.py", "fake_failed_output_denial")
        candidate = ROOT / "build/tmp/fake-failed-output"
        denial.enable_readonly_git(candidate, ROOT)
        active = {"stdout": "missing", "stderr": "synthetic missing tag"}
        def outcome(_command, _kwargs): return 128, active["stdout"], active["stderr"]
        original_run = subprocess.run
        run, calls = bounded_readonly_git_runner(denial, original_run)
        ordinary, batch = ["git", "rev-parse", "HEAD"], ["git", "cat-file", "--batch"]
        with mock.patch.object(subprocess, "Popen", self._fake_git_popen(denial, outcome)):
            result = run(ordinary, cwd=candidate, capture_output=True, text=True, check=False)
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                (128, "missing", "synthetic missing tag"))
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                run(ordinary, cwd=candidate, capture_output=True, text=True, check=True)
            self.assertEqual((caught.exception.returncode, caught.exception.cmd,
                caught.exception.stdout, caught.exception.stderr),
                (128, ordinary, "missing", "synthetic missing tag"))
            class SizedCapture:
                def __init__(self, size): self.size = size
                def __len__(self): return self.size
            for command, stdout, stderr in ((ordinary, 32 * 1024 * 1024 + 1, 0),
                    (batch, 64 * 1024 * 1024 + 1, 0), (ordinary, 0, 1024 * 1024 + 1)):
                active.update(stdout=SizedCapture(stdout), stderr=SizedCapture(stderr))
                with self.assertRaisesRegex(AssertionError, "per-command cap"):
                    run(command, cwd=candidate, capture_output=True, check=True)
            self.assertEqual(len(calls), 5)
            run, calls = bounded_readonly_git_runner(denial, original_run)
            active.update(stdout=SizedCapture(64 * 1024 * 1024), stderr=b"")
            for _ in range(4):
                with self.assertRaises(subprocess.CalledProcessError):
                    run(batch, cwd=candidate, capture_output=True, check=True)
            active["stdout"] = SizedCapture(1)
            with self.assertRaisesRegex(AssertionError, "cumulative cap"):
                run(batch, cwd=candidate, capture_output=True, check=True)
            self.assertEqual(len(calls), 5)
            run, calls = bounded_readonly_git_runner(denial, original_run)
            active.update(stdout=b"", stderr=b"missing tag")
            for _ in range(64):
                with self.assertRaises(subprocess.CalledProcessError):
                    run(ordinary, cwd=candidate, capture_output=True, check=True)
            before = denial.receipt()["readonly_git_starts"]
            with self.assertRaisesRegex(AssertionError, "invocation cap"):
                run(ordinary, cwd=candidate, capture_output=True, check=True)
            self.assertEqual(len(calls), 64)
            self.assertEqual(denial.receipt()["readonly_git_starts"], before)
        denial.disable_readonly_git()

    def test_git_unexpected_error_keeps_no_start_mismatch_and_original_error(self):
        denial = load("tests/evidence/phase7_sticky_denial.py", "fake_unstarted_error_denial")
        candidate = ROOT / "build/tmp/fake-unstarted-error"
        denial.enable_readonly_git(candidate, ROOT)
        error = RuntimeError("synthetic unstarted failure")
        def unexpected(*_args, **_kwargs): raise error
        run, calls = bounded_readonly_git_runner(denial, unexpected)
        with self.assertRaises(RuntimeError) as caught:
            run(["git", "rev-parse", "HEAD"], cwd=candidate)
        self.assertIs(caught.exception, error)
        self.assertEqual(len(calls), 1)
        self.assertEqual(denial.receipt()["readonly_git_starts"], 0)
        self.assertNotEqual(denial.receipt()["readonly_git_starts"], len(calls))
        failure = subprocess.CalledProcessError(128, ["git", "rev-parse", "HEAD"],
            output=b"", stderr=b"synthetic failure without process start")
        def unstarted_failure(*_args, **_kwargs): raise failure
        run, calls = bounded_readonly_git_runner(denial, unstarted_failure)
        with self.assertRaises(subprocess.CalledProcessError) as caught:
            run(failure.cmd, cwd=candidate)
        self.assertIs(caught.exception, failure)
        self.assertEqual(len(calls), 1)
        self.assertEqual(denial.receipt()["readonly_git_starts"], 0)
        denial.disable_readonly_git()

    def test_operator_captured_query_surface_replays_only_fake_git(self):
        # Actual-main capture's 28 successful-return rows, authenticated in the
        # debug record. Failed starts are covered by real provenance above.
        # Normalize roots so this replay needs no candidate.
        denial = load("tests/evidence/phase7_sticky_denial.py", "fake_query_denial")
        candidate = ROOT / "build/tmp/fake-operator-candidate"
        denial.enable_readonly_git(candidate, ROOT)
        log = ["log", "--follow", "--format=%H", "-1", "--",
            "fixtures/independent-game-v2/src/game.s"]
        provenance = [(log, 41), (["show", "HEAD^:fixtures/manifest.json"], 23028),
            (["show", "HEAD^:evidence/independent-game-v2.json"], 7951), (log, 41)]
        rows = [(["git", "rev-parse", "HEAD"], ROOT, 0, 41)]
        for args, size in [(["rev-parse", "HEAD"], 41), (["rev-parse", "HEAD^"], 41),
                (["rev-parse", "HEAD^{tree}"], 41), (["symbolic-ref", "--short", "HEAD"], 5),
                (["remote", "get-url", "origin"], 41), (["show", "-s", "--format=%P", "HEAD"], 41),
                (["for-each-ref", "--format=%(refname)"], 66), (["ls-files", "-z"], 20749),
                (["status", "--porcelain", "--untracked-files=all"], 0)]:
            rows.append((["git", *args], candidate, 0, size))
        def provenance_rows():
            return [(["git", "-C", str(candidate), *args], None, 0, size)
                for args, size in provenance]
        rows.extend(provenance_rows())
        for args, input_size, size in [(["rev-list", "HEAD"], 0, 574),
                (["rev-list", "--objects", "HEAD"], 0, 66282),
                (["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"], 38704, 48246),
                (["cat-file", "--batch"], 5248, 9072333)]:
            rows.append((["git", *args], candidate, input_size, size))
        rows.extend(provenance_rows())
        for size in (40394642, 1497941, 3665902, 12468425, 1740726):
            rows.append((["git", "cat-file", "--batch"], candidate,
                3854 if size == 1740726 else 5248, size))
        rows.append((["git", "log", "HEAD", "--format=%an%x00%ae%x00%cn%x00%ce"], candidate, 0, 1040))
        self.assertEqual(len(rows), 28)
        self.assertEqual(sum(row[3] for row in rows), 69039299)
        active = {"size": 0}
        class SizedCapture:
            # Model captured size without allocating the measured 40 MiB blob.
            def __len__(self): return active["size"]
        class FakePopen:
            def __init__(self, command, **kwargs):
                denial.deny("subprocess.Popen", ("git", command, kwargs.get("cwd"), None))
                self.args, self.pid, self.returncode = command, 123456789, None
            def __enter__(self): return self
            def __exit__(self, *_args): self.returncode = 0
            def communicate(self, _input=None, timeout=None):
                self_test.assertLessEqual(timeout, 30)
                self.returncode = 0
                return SizedCapture(), b""
            def poll(self): return self.returncode
        self_test = self
        run, calls = bounded_readonly_git_runner(denial, subprocess.run)
        with mock.patch.object(subprocess, "Popen", FakePopen):
            for command, cwd, input_size, stdout_size in rows:
                active["size"] = stdout_size
                run(command, cwd=cwd, input=b"0" * input_size, capture_output=True, timeout=10)
            # Source-known fallback paths not taken by the observed candidate.
            for command in (["git", "-C", str(candidate), "rev-parse", "--verify",
                    "refs/tags/genewhip-fixture-source-v2-" + "a" * 40 + "^{commit}"],
                    ["git", "-C", str(candidate), "show",
                    "a" * 40 + ":fixtures/independent-game-v2/src/game.s"]):
                active["size"] = 41
                run(command, cwd=None, capture_output=True)
        self.assertEqual(len(calls), 30)
        self.assertEqual(denial.receipt()["readonly_git_starts"], len(calls))
        self.assertEqual(denial.receipt()["unexpected_denials"], 0)
        for command, cwd in ((["git", "-C", str(ROOT), *log], None),
                (["git", "-C", str(candidate) + "/../publication", *log], None),
                (["git", "-C", ".", *log], candidate),
                (["git", "-C", str(candidate), *log], ROOT),
                (["git", "-C", str(candidate), "push", "origin", "main"], None),
                (["git", "-C", str(candidate), "-c", "core.hooksPath=x", *log], None),
                (["git", "-c", "alias.x=!sh", "rev-parse", "HEAD"], candidate),
                (["git", "-C", str(candidate), "show", "HEAD^:../secrets"], None),
                (["git", "show", "a" * 40 + ":fixtures/other.s"], candidate),
                (["git", "rev-parse", "--verify", "refs/tags/other^{commit}"], candidate),
                (["git", "status", "--porcelain", "--untracked-files=all"], ROOT)):
            with self.subTest(command=command, cwd=cwd):
                before = len(calls)
                with self.assertRaises(AssertionError): run(command, cwd=cwd)
                with self.assertRaises(PermissionError):
                    denial.deny("subprocess.Popen", ("git", command, cwd, None))
                self.assertEqual(len(calls), before)
        denial.disable_readonly_git()

    def test_operator_postcapture_limits_only_raise_trusted_batch_stdout(self):
        denial = load("tests/evidence/phase7_sticky_denial.py", "fake_output_denial")
        candidate = ROOT / "build/tmp/fake-output-candidate"
        denial.enable_readonly_git(candidate, ROOT)
        active = {"stdout": 0, "stderr": 0}
        class SizedCapture:
            def __init__(self, key): self.key = key
            def __len__(self): return active[self.key]
        def fake_run(command, **kwargs):
            return SimpleNamespace(stdout=SizedCapture("stdout"), stderr=SizedCapture("stderr"))
        batch, ordinary = ["git", "cat-file", "--batch"], ["git", "rev-list", "HEAD"]
        run, calls = bounded_readonly_git_runner(denial, fake_run)
        for size in (40 * 1024 * 1024, 64 * 1024 * 1024):
            active["stdout"] = size
            run(batch, cwd=candidate)
        for command, stdout, stderr in ((batch, 64 * 1024 * 1024 + 1, 0),
                (ordinary, 32 * 1024 * 1024 + 1, 0), (batch, 1, 1024 * 1024 + 1)):
            active.update(stdout=stdout, stderr=stderr)
            with self.assertRaisesRegex(AssertionError, "per-command cap"):
                run(command, cwd=candidate)
        self.assertEqual(len(calls), 5)
        run, calls = bounded_readonly_git_runner(denial, fake_run)
        active.update(stdout=64 * 1024 * 1024, stderr=0)
        for _ in range(4): run(batch, cwd=candidate)
        active["stdout"] = 1
        with self.assertRaisesRegex(AssertionError, "cumulative cap"):
            run(batch, cwd=candidate)
        denial.disable_readonly_git()

    def test_cli_ledger_requires_mode_specific_children_and_all_success_signals(self):
        result = SimpleNamespace(wasSuccessful=lambda: True)
        for operator, starts, readonly, expected in (
                (False, 0, 0, True), (False, 1, 1, False),
                (True, 1, 1, True), (True, 64, 64, True),
                (True, 0, 0, False), (True, 2, 1, False), (True, 1, 2, False)):
            receipt = {"real_child_starts": starts, "readonly_git_starts": readonly,
                "unexpected_denials": 0}
            with self.subTest(operator=operator, starts=starts, readonly=readonly):
                self.assertEqual(successful_ledger(result, receipt, operator_route=operator,
                    native_denials=2), expected)
        receipt = {"real_child_starts": 1, "readonly_git_starts": 1, "unexpected_denials": 0}
        for changed, native, success in (({"unexpected_denials": 1}, 2, True),
                ({}, 1, True), ({}, 3, True), ({}, 2, False)):
            self.assertFalse(successful_ledger(SimpleNamespace(wasSuccessful=lambda: success),
                {**receipt, **changed}, operator_route=True, native_denials=native))

    def test_publication_sentinel_satisfies_real_main_without_writing_delivery(self):
        with tempfile.TemporaryDirectory(prefix="gw-operator-sentinel-") as temporary:
            output = Path(temporary) / "not-a-delivery.json"
            sentinel = publication_sentinel()
            self.assertEqual(sentinel["public_source_sha"], "SYNTHETIC-NON-PUBLICATION")
            observed = []
            def observe(path, value):
                self.assertEqual(path, output)
                observed.append(value)
            # This pure consumer test uses the ordinary stage-public CLI. The
            # explicit operator integration below keeps its real campaign gates.
            with mock.patch.object(coordinator, "publish_sanitized_source", return_value=sentinel) as publish, \
                    mock.patch.object(coordinator, "_write_json", side_effect=observe) as writer, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(coordinator.main(["--mode", "stage-public", "--out", str(output),
                    "--publication-copy", str(Path(temporary) / "unused"),
                    "--journal", str(Path(temporary) / "unused-journal")]), 0)
            publish.assert_called_once()
            writer.assert_called_once()
            self.assertEqual(len(observed), 1)
            self.assertEqual(observed[0]["status"], "stubbed-at-publish-boundary")
            self.assertFalse(output.exists())

    def test_git_timeout_cleanup_owns_only_its_fresh_unreaped_handle(self):
        import signal
        # Isolated ledger and fake Popen: no actual child or OS signal occurs.
        denial = load("tests/evidence/phase7_sticky_denial.py", "fake_timeout_denial")
        candidate = ROOT / "build/tmp/fake-git-only"
        denial.enable_readonly_git(candidate, ROOT)
        handles = []
        class FakePopen:
            def __init__(self, command, **kwargs):
                denial.deny("subprocess.Popen", ("git", command, kwargs.get("cwd"), None))
                self.pid, self.returncode = 123456789, None
                self.args, self.kills, self.waits = command, 0, 0
                handles.append(self)
            def __enter__(self): return self
            def __exit__(self, *_args): self.wait()
            def communicate(self, *_args, **_kwargs):
                raise subprocess.TimeoutExpired(self.args, 0.01)
            def kill(self):
                # Even inside own cleanup, other PIDs, signals and groups deny.
                for event, args in (("os.kill", (self.pid + 1, signal.SIGKILL)),
                        ("os.kill", (self.pid, signal.SIGTERM)),
                        ("os.killpg", (self.pid, signal.SIGKILL))):
                    with self_test.assertRaises(PermissionError): denial.deny(event, args)
                denial.deny("os.kill", (self.pid, signal.SIGKILL))
                self.kills += 1
            def wait(self):
                self.waits += 1
                self.returncode = -signal.SIGKILL
                return self.returncode
        self_test = self
        original_popen = subprocess.Popen
        with mock.patch.object(subprocess, "Popen", FakePopen):
            with denial.owned_readonly_git_cleanup():
                with self.assertRaises(subprocess.TimeoutExpired):
                    subprocess.run(["git", "rev-parse", "HEAD"], cwd=candidate,
                        capture_output=True, timeout=0.01)
                handle = handles[0]
                self.assertEqual(handle.kills, 1)
                self.assertGreater(handle.waits, 0)
                with self.assertRaises(PermissionError): handle.kill()
            self.assertIs(subprocess.Popen, FakePopen)
        self.assertIs(subprocess.Popen, original_popen)
        with self.assertRaises(PermissionError):
            denial.deny("os.kill", (handle.pid, signal.SIGKILL))
        self.assertIsNone(denial._GIT_CLEANUP)
        self.assertEqual(denial.receipt()["readonly_git_starts"], 1)
        denial.disable_readonly_git()

    def _current_fixture(self):
        if CURRENT_ROOT is None:
            raise AssertionError("current fixture was not prepared")
        temporary = tempfile.TemporaryDirectory(prefix="gw17-selector-fixture-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        shutil.copytree(CURRENT_ROOT, root, dirs_exist_ok=True)
        return root

    @staticmethod
    def _fake_git_show(command, **_kwargs):
        if (not isinstance(command, list) or len(command) != 3 or command[:2] != ["git", "show"]
                or ":" not in command[2]):
            raise AssertionError("unexpected subprocess boundary in denied selector test")
        _revision, relative = command[2].split(":", 1)
        data = ORIGINAL_BLOBS.get(relative)
        if data is None:
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"missing trusted blob")
        return SimpleNamespace(returncode=0, stdout=data, stderr=b"")

    @staticmethod
    def _fake_candidate_git(_candidate, *args):
        joined = " ".join(args)
        if joined == "rev-parse HEAD": return "a" * 40
        if joined == "rev-parse HEAD^": return "b" * 40
        if joined == "rev-parse HEAD^{tree}": return "c" * 40
        if joined == "symbolic-ref --short HEAD": return "main"
        if joined == "remote get-url origin": return "https://github.com/szTheory/genewhip.git"
        if joined == "show -s --format=%P HEAD": return "b" * 40
        if joined == "for-each-ref --format=%(refname)":
            return "refs/heads/main\nrefs/remotes/origin/HEAD\nrefs/remotes/origin/main"
        if joined == "ls-files -z":
            return "\0".join(["LICENSE", "scripts/ci/public_hygiene.py",
                "scripts/release/v02_continuation.py", "scripts/release/v02_qualification.py",
                "tests/evidence/phase7_continuation_contract.py",
                "tests/evidence/phase7_creation_receipts_contract.py",
                "tests/evidence/phase7_return_consumer_contract.py",
                "tests/evidence/phase7_sticky_denial.py"])
        if joined == "status --porcelain --untracked-files=all": return ""
        raise AssertionError("unexpected candidate Git read: " + joined)

    @staticmethod
    def _bound_candidate_git(root, _candidate, *args):
        fields = continuation._canonical_frontmatter(root / continuation.CANDIDATE_REVIEW)
        preflight = json.loads((root / fields["candidate_preflight_path"]).read_bytes())
        joined = " ".join(args)
        identity = preflight["public_identity"]
        if joined == "rev-parse HEAD": return identity["head_sha"]
        if joined == "rev-parse HEAD^": return identity["base_sha"]
        if joined == "rev-parse HEAD^{tree}": return identity["tree_sha"]
        if joined == "symbolic-ref --short HEAD": return "main"
        if joined == "remote get-url origin":
            return f"https://github.com/{preflight['repository']}.git"
        if joined == "show -s --format=%P HEAD": return identity["base_sha"]
        if joined == "for-each-ref --format=%(refname)":
            return "refs/heads/main\nrefs/remotes/origin/HEAD\nrefs/remotes/origin/main"
        if joined == "ls-files -z":
            return "\0".join(row["path"] for row in preflight["source_manifest"])
        if joined == "status --porcelain --untracked-files=all": return ""
        raise AssertionError("unexpected candidate Git read: " + joined)

    def _build_synthetic_independent_reviews(self, root, payload):
        payload_sha = hashlib.sha256(json.dumps(payload, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        code_body = b"Independent source review accepted the exact current source and tests.\n"
        security_body = b"Independent security review accepted scoped preparation; current risk remains open medium nonblocking.\n"
        def write(path, fields, body):
            body_sha = hashlib.sha256(body).hexdigest()
            fields = {**fields, "report_body_sha256": body_sha}
            text = "---\n" + "".join(f"{key}: {value}\n" for key, value in fields.items()) + "---\n"
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(text.encode() + body)
            return hashlib.sha256(target.read_bytes()).hexdigest()
        write(continuation.CODE_REVIEW, {"status": "accepted", "reviewer_role": "gsd-code-reviewer",
            "reviewer_model": "gpt-6-luna", "author_role": "gsd-executor",
            "payload_sha256": payload_sha, "unresolved high/critical": "0", "critical": "0", "high": "0"}, code_body)
        security_sha = write(continuation.SECURITY_REVIEW, {"status": "accepted", "reviewer_role": "gsd-security-auditor",
            "reviewer_model": "gpt-6.1-sol", "author_role": "gsd-executor",
            "payload_sha256": payload_sha, "unresolved current high/critical": "0", "critical": "0", "high": "0",
            "current_risk": "open medium nonblocking", "attributable_cleanup_target": "none",
            "user_action_required": "no", "historical_identity_liveness": "UNKNOWN",
            "historical_T-07-07": "OPEN/high",
            "risk_source_sha256": payload["current_risk_evidence_sha256"]["source"],
            "risk_assessment_sha256": payload["current_risk_evidence_sha256"]["security"]}, security_body)
        return payload_sha, security_sha, write

    def _build_synthetic_candidate_return(self, root, payload, payload_sha, security_sha, write):
        rel = "build/v02/campaign15/continuation17-r3"
        candidate_dir = root / rel / "publication"
        candidate_dir.mkdir(parents=True)
        candidate_relatives = ["LICENSE", "scripts/ci/public_hygiene.py",
            "scripts/release/v02_qualification.py", "scripts/release/v02_continuation.py",
            "tests/evidence/phase7_continuation_contract.py",
            "tests/evidence/phase7_sticky_denial.py",
            "tests/evidence/phase7_return_consumer_contract.py",
            "tests/evidence/phase7_creation_receipts_contract.py"]
        for relative in candidate_relatives:
            source = ROOT / relative
            target = candidate_dir / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        manifest = [{"path": relative, "size_bytes": (candidate_dir / relative).stat().st_size,
            "sha256": hashlib.sha256((candidate_dir / relative).read_bytes()).hexdigest()}
            for relative in sorted(candidate_relatives)]
        manifest_sha = hashlib.sha256(json.dumps(manifest, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        preflight_rel = rel + "/preflight.json"
        policy_rel = rel + "/repository-preflight-fixture/policy.json"
        head, base, tree = "a" * 40, "b" * 40, "c" * 40
        repository = "szTheory/genewhip"
        preflight = {"schema": "genewhip.v02-public-source-preflight.v1", "status": "prepared",
            "blockers": [], "repository": repository, "source_manifest": manifest,
            "source_manifest_sha256": manifest_sha,
            "source_identity": {"source_manifest_sha256": manifest_sha},
            "public_identity": {"head_sha": head, "base_sha": base, "tree_sha": tree,
                "parent_shas": [base]}, "publication_copy": rel + "/publication",
            "repository_preflight": policy_rel,
            "privacy": {"status": "pass", "current_findings": [], "history_findings": []},
            "mutations_performed": 0, "push_performed": False,
            "pull_request_opened": False, "workflow_dispatched": False,
            "requirements_qualified": []}
        policy = {"schema": "genewhip.publication-readiness-packet.v1", "repository": repository,
            "destination": {"owner_repository": repository, "visibility": "public"},
            "expected_identity": {"head": head, "base": base}, "mutations_performed": 0,
            "history_disposition": "sanitized-snapshots-preserve-local-history",
            "hosted_evidence": {"outcome": "not_run", "qualifies_rel_03": False},
            "repository_observations": {"ready": True, "blockers": [], "observations": {
                "visibility": "public", "default_branch": "main", "auto_merge_enabled": True,
                "caller_write_permission": "write", "expected_identity": {
                    "head": head, "base": base,
                    "observed_default_branch_sha": base},
                "branch_protection": {"pull_request_required": True,
                    "required_status_checks": ["required-ci"]},
                "permitted_merge_methods": ["squash"]}},
            "privacy_scan": {"publication_copy": {"status": "pass",
                "current_findings": [], "findings": []}}}
        preflight_path, policy_path = root / preflight_rel, root / policy_rel
        preflight_path.parent.mkdir(parents=True, exist_ok=True)
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        policy_path.write_text(json.dumps(policy, sort_keys=True), encoding="utf-8")
        preflight_path.write_text(json.dumps(preflight, sort_keys=True), encoding="utf-8")
        preflight_sha = hashlib.sha256(preflight_path.read_bytes()).hexdigest()
        policy_sha = hashlib.sha256(policy_path.read_bytes()).hexdigest()
        candidate_body = (f"Independent privacy review accepted candidate head {head}, base {base}, "
            f"tree {tree}, manifest {manifest_sha}, preflight {preflight_sha}, and policy {policy_sha}.\n").encode()
        candidate_sha = write(continuation.CANDIDATE_REVIEW, {
            "status": "accepted", "reviewer_role": "gsd-code-reviewer",
            "payload_sha256": payload_sha,
            "current_source_sha256": payload["coordinator_current_sha256"],
            "candidate_preflight_path": preflight_rel,
            "candidate_preflight_sha256": preflight_sha,
            "repository_policy_path": policy_rel,
            "repository_policy_sha256": policy_sha,
            "publication_copy_path": rel + "/publication",
            "candidate_head_sha256": head, "candidate_base_sha256": base,
            "candidate_tree_sha256": tree, "candidate_manifest_sha256": manifest_sha,
            "tracked_file_count": str(len(manifest)),
            "privacy": "pass", "destination_policy": "read-only-verified"}, candidate_body)
        review_body = b"Independent current return review accepted original proof, current dependencies, candidate and duty transfer.\n"
        review_sha = write(continuation.RETURN_REVIEW, {
            "status": "accepted", "payload_sha256": payload_sha,
            "candidate_sha256": candidate_sha, "security_sha256": security_sha,
            "reviewer_role": "gsd-code-reviewer", "unresolved high/critical": "0"}, review_body)
        return_body = b"Current source-only entry accepted; original10 and original11 duties remain required in full.\n"
        write(continuation.RETURN, {
            "status": "accepted", "payload_sha256": payload_sha,
            "review_sha256": review_sha, "security_sha256": security_sha,
            "candidate_review_sha256": candidate_sha,
            "current_risk": "open medium nonblocking",
            "historical_identity_liveness": "UNKNOWN", "historical_T-07-07": "OPEN/high",
            "requirements_qualified": "none",
            "retained_duties_sha256": hashlib.sha256(json.dumps(
                continuation.RETAINED_DUTIES, sort_keys=True, separators=(",", ":")).encode()).hexdigest()},
            return_body)

    def test_current_continuation_module_exists(self):
        self.assertTrue((ROOT / "scripts/release/v02_continuation.py").is_file())

    def test_original_source_snapshot_reopens_both_actual_cases(self):
        result = continuation.verify_original_snapshot(SNAPSHOT, PACKET_VALUE)
        self.assertEqual(result["status"], "accepted-original-scope")
        self.assertEqual([row["case"] for row in result["cases"]],
            ["shared_launch", "bounded_command"])
        self.assertTrue(all(row["status"] == "pass" and row["returncode"] == 0
            and row["owner_settled"] and row["leaf_settled"] for row in result["cases"]))
        self.assertEqual(result["full_plan16_return"], "blocked")
        self.assertEqual(result["historical_identity_liveness"], "UNKNOWN")
        self.assertEqual(result["historical_T-07-07"], "OPEN/high")

    def test_old16_current_source_gate_still_rejects_changed_coordinator(self):
        packet = json.loads((ROOT / PACKET).read_bytes())
        with self.assertRaisesRegex(ValueError, "source-stale:scripts/release/v02_qualification.py"):
            coordinator._validate_current_admission16(packet,
                hashlib.sha256((ROOT / PACKET).read_bytes()).hexdigest())

    def test_actual_owner_prelaunch_projection_keeps_old16_rejection(self):
        packet_path = ROOT / PACKET
        campaign_path = ROOT / "build/v02/campaign15/campaign.json"
        with self.assertRaisesRegex(ValueError, "return-admission-source-or-scope-stale"):
            original_runner.owner("shared_launch", original_runner.case_root(1),
                controller_pid=os.getppid(), controller_nonce="a" * 64,
                packet_path=packet_path, campaign_path=campaign_path,
                campaign_sha256=hashlib.sha256(campaign_path.read_bytes()).hexdigest())
        self.assertEqual(process_denial.receipt()["real_child_starts"], 0)

    def test_owner_import_and_projection_precede_both_launch_routes(self):
        source = (ROOT / "tests/evidence/phase7_wrapper_return.py").read_text(encoding="utf-8")
        owner = next(node for node in ast.walk(ast.parse(source))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "owner")
        lines = {}
        for node in ast.walk(owner):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.attr if isinstance(node.func, ast.Attribute) else None
            if name in {"spec_from_file_location", "_campaign_projection", "shared_launch", "_bounded_command"}:
                lines.setdefault(name, node.lineno)
        self.assertLess(lines["spec_from_file_location"], lines["_campaign_projection"])
        self.assertLess(lines["_campaign_projection"], lines["shared_launch"])
        self.assertLess(lines["_campaign_projection"], lines["_bounded_command"])

    def test_selector17_preparation_cli_reaches_only_bounded_snapshot_entry(self):
        root = self._current_fixture()
        expected = {"status": "prepared", "source_manifest": [{"path": "README.md"}],
            "public_identity": {"head_sha": "1" * 40, "base_sha": "2" * 40}}
        with mock.patch.object(continuation.subprocess, "run", side_effect=self._fake_git_show), \
             mock.patch.object(coordinator, "ROOT", root), \
             mock.patch.object(coordinator, "prepare_public_snapshot", return_value=expected) as prepare:
            payload = continuation.build_attestation(root, continuation.ATTESTATION)
            payload_sha, security_sha, write = self._build_synthetic_independent_reviews(root, payload)
            campaign_value = json.loads((root / continuation.CAMPAIGN).read_bytes())
            packet_value = json.loads((root / continuation.PACKET).read_bytes())
            self.assertTrue(coordinator._validate_campaign_resume16(packet_value, campaign_value,
                continuation.CAMPAIGN_SHA, continuation.PACKET_SHA, allow_live=True))
            campaign_path = root / continuation.CAMPAIGN
            scope_path = root / "evidence/v02-execution.json"
            packet_path = root / continuation.PACKET
            canonical = json.dumps({key: item for key, item in campaign_value.items()
                if key != "record_sha256"}, sort_keys=True, separators=(",", ":")).encode()
            self.assertEqual(hashlib.sha256(campaign_path.read_bytes()).hexdigest(), continuation.CAMPAIGN_SHA)
            self.assertEqual(campaign_value["record_sha256"], hashlib.sha256(canonical).hexdigest())
            self.assertEqual(campaign_value["scope_sha256"], hashlib.sha256(scope_path.read_bytes()).hexdigest())
            self.assertEqual(packet_path.stat().st_nlink, 1)
            self.assertEqual((campaign_value.get("schema"), campaign_value.get("status"),
                campaign_value.get("campaign_id"), campaign_value.get("scope_path"),
                campaign_value.get("journal_path"), packet_path.stat().st_uid == os.getuid(),
                packet_path.stat().st_size <= 65536),
                (coordinator.RECOVERY_CAMPAIGN_SCHEMA, "started", "phase7-renewed-2026-10-30",
                 "evidence/v02-execution.json", "build/v02/campaign15/hosted-delivery-journal.json", True, True))
            argv = ["--mode", "stage-public", "--prepare-only", "--recovery-selection", "17",
                "--continuation", str(continuation.ATTESTATION), "--campaign",
                "build/v02/campaign15/campaign.json", "--campaign-sha256", continuation.CAMPAIGN_SHA,
                "--journal", "build/v02/campaign15/hosted-delivery-journal.json",
                "--scope", "evidence/v02-execution.json", "--publication-copy",
                "build/v02/campaign15/continuation17-r3/publication", "--out",
                "build/v02/campaign15/continuation17-r3/preflight.json"]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(coordinator.main(argv), 0)
            prepare.assert_called_once()
            forbidden = {
                "runtime": "run_runtime", "package": "run_package",
                "stage-public": "publish_sanitized_source",
                "retry-source": "retry_sanitized_source", "hosted": "run_hosted_qualification",
                "close": "validate_receipt_map",
            }
            for mode, consumer_name in forbidden.items():
                args = ["--mode", mode, "--recovery-selection", "17", "--continuation",
                    str(continuation.ATTESTATION), "--campaign", "build/v02/campaign15/campaign.json",
                    "--campaign-sha256", continuation.CAMPAIGN_SHA, "--journal",
                    "build/v02/campaign15/hosted-delivery-journal.json", "--scope",
                    "evidence/v02-execution.json", "--out",
                    "build/v02/campaign15/continuation17-r3/escalation.json"]
                if mode in ("stage-public", "retry-source", "hosted"):
                    args += ["--publication-copy", "build/v02/campaign15/continuation17-r3/publication"]
                if mode == "runtime":
                    args += ["--prepare-only"]
                if mode == "package":
                    args += ["--public-evidence", "build/v02/campaign15/continuation17-r3/evidence"]
                if mode == "close":
                    args += ["--evidence", "build/v02/campaign15/continuation17-r3/evidence"]
                with self.subTest(mode=mode), mock.patch.object(coordinator, consumer_name) as downstream, \
                     contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(coordinator.main(args), 1)
                    downstream.assert_not_called()
            self._build_synthetic_candidate_return(root, payload, payload_sha, security_sha, write)
            with mock.patch.object(continuation, "_candidate_git",
                    side_effect=self._fake_candidate_git), mock.patch.object(continuation,
                    "_candidate_privacy", return_value=([], {"findings": []})):
                preflight_path = root / "build/v02/campaign15/continuation17-r3/preflight.json"
                preflight_bytes = preflight_path.read_bytes()
                preflight_value = json.loads(preflight_bytes)
                preflight_value["public_identity"]["tree_sha"] = "d" * 40
                preflight_path.write_text(json.dumps(preflight_value, sort_keys=True), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "continuation-candidate-git-identity-invalid"):
                    continuation.validate_attestation(root, continuation.ATTESTATION,
                        require_candidate=True, require_return=True)
                preflight_path.write_bytes(preflight_bytes)
                candidate_report_path = root / continuation.CANDIDATE_REVIEW
                candidate_report_bytes = candidate_report_path.read_bytes()
                candidate_report_path.write_bytes(candidate_report_bytes.replace(
                    b"candidate_preflight_path: build/v02/campaign15/continuation17-r3/preflight.json",
                    b"candidate_preflight_path: build/v02/campaign15/continuation17/preflight.json"))
                with self.assertRaisesRegex(ValueError, "continuation-candidate-path-invalid"):
                    continuation.validate_attestation(root, continuation.ATTESTATION,
                        require_candidate=True, require_return=True)
                candidate_report_path.write_bytes(candidate_report_bytes)
                policy_path = root / "build/v02/campaign15/continuation17-r3/repository-preflight-fixture/policy.json"
                policy_bytes = policy_path.read_bytes()
                for mutate in (
                    lambda value: value["repository_observations"]["observations"][
                        "branch_protection"].update(required_status_checks=[]),
                    lambda value: value.update(history_disposition="private-history-published"),
                    lambda value: value.update(hosted_evidence={"outcome": "passed",
                        "qualifies_rel_03": True}),
                ):
                    policy_value = json.loads(policy_bytes)
                    mutate(policy_value)
                    policy_path.write_text(json.dumps(policy_value, sort_keys=True), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "continuation-candidate-policy-invalid"):
                        continuation.validate_attestation(root, continuation.ATTESTATION,
                            require_candidate=True, require_return=True)
                policy_value = json.loads(policy_bytes)
                policy_value["inspector_exit_code"] = 1
                policy_path.write_text(json.dumps(policy_value, sort_keys=True), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "continuation-candidate-preflight-invalid"):
                    continuation.validate_attestation(root, continuation.ATTESTATION,
                        require_candidate=True, require_return=True)
                policy_path.write_bytes(policy_bytes)
                with mock.patch.object(continuation, "_candidate_privacy",
                        return_value=([], [])):
                    with self.assertRaisesRegex(ValueError, "continuation-candidate-privacy-invalid"):
                        continuation.validate_attestation(root, continuation.ATTESTATION,
                            require_candidate=True, require_return=True)
                candidate_file = root / "build/v02/campaign15/continuation17-r3/publication/LICENSE"
                candidate_bytes = candidate_file.read_bytes()
                candidate_file.write_bytes(candidate_bytes + b"tamper")
                with self.assertRaisesRegex(ValueError, "continuation-candidate-file-stale-or-unbounded"):
                    continuation.validate_attestation(root, continuation.ATTESTATION,
                        require_candidate=True, require_return=True)
                candidate_file.write_bytes(candidate_bytes)
                for report_path in (continuation.SECURITY_REVIEW, continuation.CANDIDATE_REVIEW,
                        continuation.RETURN_REVIEW, continuation.RETURN):
                    report_file = root / report_path
                    original = report_file.read_bytes()
                    frontmatter, body = original.split(b"\n---\n", 1)
                    report_file.write_bytes(frontmatter + b"\n---\n" + body.replace(
                        b"accepted", b"rejected", 1))
                    with self.subTest(report=report_path), self.assertRaises(ValueError):
                        continuation.validate_attestation(root, continuation.ATTESTATION,
                            require_candidate=True, require_return=True)
                    report_file.write_bytes(original)
            candidate_git_patch = mock.patch.object(continuation, "_candidate_git",
                side_effect=self._fake_candidate_git)
            candidate_privacy_patch = mock.patch.object(continuation, "_candidate_privacy",
                return_value=([], {"findings": []}))
            candidate_git_patch.start(); self.addCleanup(candidate_git_patch.stop)
            candidate_privacy_patch.start(); self.addCleanup(candidate_privacy_patch.stop)
            original_spec = coordinator.importlib.util.spec_from_file_location
            def spec_with_candidate_boundary(name, location, *args, **kwargs):
                spec = original_spec(name, location, *args, **kwargs)
                if name in {"v02_continuation_gate", "v02_continuation_return_gate"} \
                        and spec is not None and spec.loader is not None:
                    original_loader = spec.loader
                    class CandidateBoundaryLoader:
                        def create_module(_loader, module_spec):
                            return original_loader.create_module(module_spec)
                        def exec_module(_loader, module):
                            original_loader.exec_module(module)
                            module._candidate_git = self._fake_candidate_git
                            module._candidate_privacy = lambda *_args: ([], {"findings": []})
                    spec.loader = CandidateBoundaryLoader()
                return spec
            spec_patch = mock.patch.object(coordinator.importlib.util,
                "spec_from_file_location", side_effect=spec_with_candidate_boundary)
            spec_patch.start(); self.addCleanup(spec_patch.stop)
            coordinator._campaign_projection(root / continuation.CAMPAIGN,
                root / "evidence/v02-execution.json",
                root / "build/v02/campaign15/hosted-delivery-journal.json",
                phase="runtime", expected_sha256=continuation.CAMPAIGN_SHA,
                selection="17", continuation_path=continuation.ATTESTATION)
            runtime_args = ["--mode", "runtime", "--recovery-selection", "17",
                "--continuation", str(continuation.ATTESTATION), "--campaign",
                "build/v02/campaign15/campaign.json", "--campaign-sha256", continuation.CAMPAIGN_SHA,
                "--journal", "build/v02/campaign15/hosted-delivery-journal.json",
                "--scope", "evidence/v02-execution.json", "--out",
                "build/v02/campaign15/continuation17-r3/runtime.json"]
            with mock.patch.object(coordinator, "run_runtime", return_value={"returncode": 0}) as runtime, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(coordinator.main(runtime_args), 0)
                runtime.assert_called_once()
            with mock.patch.object(coordinator, "_valid_packet_for_delivery",
                    side_effect=FileNotFoundError("synthetic-next-delivery-boundary")) as delivery:
                with self.assertRaisesRegex(FileNotFoundError, "synthetic-next-delivery-boundary"):
                    coordinator.retry_sanitized_source(root / "packet", root / "publication",
                        root / "build/v02/campaign15/hosted-delivery-journal.json",
                        campaign_path=root / continuation.CAMPAIGN,
                        campaign_sha256=continuation.CAMPAIGN_SHA,
                        scope_path=root / "evidence/v02-execution.json", recovery_selection="17",
                        continuation_path=continuation.ATTESTATION)
                delivery.assert_called_once()
        self.assertEqual(process_denial.receipt()["real_child_starts"], 0)

    def test_source_boundary_rejects_new_current_source_delta_without_rebinding_old_record(self):
        with self.assertRaisesRegex(ValueError, "continuation-unexpected-original-source-delta"):
            continuation._source_map(ROOT, PACKET_VALUE)

    def test_retry_source_archives_campaign_journal_under_failures_root(self):
        repository = "szTheory/genewhip"
        old_head, new_head, base = "a" * 40, "b" * 40, "c" * 40
        start = json.loads((ROOT / "build/v02/campaign15/campaign.json").read_bytes())["started_at"]
        scope = json.loads((ROOT / "evidence/v02-execution.json").read_bytes())
        previous = {"schema": "genewhip.v02-delivery-journal.v1", "started_at": start,
            "repository": repository, "source_head": old_head, "public_base_sha": base,
            "branch": "v0.2-source-" + old_head[:12], "push_performed": True}
        original_bytes = (json.dumps(previous, sort_keys=True, indent=2) + "\n").encode()
        packet = {"repository": repository, "public_identity":
            {"head_sha": new_head, "base_sha": base}}
        policy = {"repository": repository, "repository_observations": {"observations": {
            "expected_identity": {"observed_default_branch_sha": base}}}}
        pr = {"number": 17, "state": "OPEN", "headRefName": previous["branch"],
            "headRefOid": old_head, "baseRefName": "main", "baseRefOid": base,
            "mergeCommit": None, "autoMergeRequest": None,
            "statusCheckRollup": [{"name": "required-ci", "status": "COMPLETED",
                "conclusion": "FAILURE"}]}
        calls = []
        def remote_reply(argv, **_kwargs):
            calls.append(tuple(argv))
            if argv[:3] == ["gh", "pr", "list"]:
                return subprocess.CompletedProcess(argv, 0, json.dumps([pr]), "")
            if argv[:2] == ["gh", "api"]:
                return subprocess.CompletedProcess(argv, 0,
                    json.dumps({"total_count": 0, "workflow_runs": []}), "")
            raise AssertionError("retry made an unexpected external call: " + repr(argv))

        archive = None
        campaign_root = ROOT / "build/v02/campaign15"
        with tempfile.TemporaryDirectory(prefix="source-retry-live-journal-", dir=campaign_root) as temp:
            area = Path(temp)
            journal = area / "hosted-delivery-journal.json"
            journal.write_bytes(original_bytes)
            publication = area / "publication"
            publication.mkdir()
            try:
                with mock.patch.object(coordinator, "_fresh_public_policy", return_value=policy), \
                     mock.patch.object(coordinator, "_external", side_effect=remote_reply):
                    result = coordinator._retry_sanitized_source_bound(packet, publication,
                        journal, original_bytes, previous, start, scope, ROOT / "build/v02")
                active = json.loads(journal.read_bytes())
                archive = ROOT / result["archive"]
                self.assertTrue(archive.is_relative_to(ROOT / "build/v02/failures"))
                self.assertEqual(archive.read_bytes(), original_bytes)
                self.assertEqual(active["started_at"], start)
                self.assertEqual(active["source_retry"]["archive_sha256"],
                    hashlib.sha256(original_bytes).hexdigest())
                self.assertEqual(active["source_retry"]["prior_source_head"], old_head)
                self.assertEqual(active["source_head"], new_head)
                self.assertFalse(active["push_performed"])
                coordinator._validate_source_retry_history(active)
                self.assertEqual(len(calls), 2)
                self.assertTrue(all(call[0] == "gh" for call in calls))
            finally:
                if archive is not None:
                    archive.unlink(missing_ok=True)

    def test_privacy_fixture_constructs_original_classifier_input_without_public_path_literal(self):
        path = ROOT / "tests/evidence/phase7_creation_receipts_contract.py"
        source = path.read_text(encoding="utf-8")
        path_literal = "/" + "Users" + "/example/private-rom.bin"
        self.assertNotIn('is_public_text("/' + "Users" + '/example/private-rom.bin")', source)
        tree = ast.parse(source)
        method = next(node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "test_artifact_privacy_filter_rejects_private_markers")
        assignment = next(node for node in method.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "private_path" for target in node.targets))
        value = ast.literal_eval(assignment.value.left.left) + ast.literal_eval(assignment.value.left.right) + ast.literal_eval(assignment.value.right)
        self.assertEqual(value, path_literal)

    def test_policy_inspector_nonzero_preserves_written_privacy_result(self):
        root = self._current_fixture()
        destination = root / "delivery" / "publication"
        expected = {"schema": "genewhip.publication-readiness-packet.v1",
            "repository": "szTheory/genewhip",
            "destination": {"owner_repository": "szTheory/genewhip", "visibility": "public"},
            "expected_identity": {"head": "a" * 40, "base": "b" * 40},
            "mutations_performed": 0,
            "repository_observations": {"ready": False, "blockers": []},
            "privacy_scan": {"publication_copy": {"status": "findings",
                "current_findings": [{"path": "tests/example.py", "reason": "personal-path"}]}}}
        def inspector(command, **_kwargs):
            output = root / command[command.index("--out") + 1]
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(expected), encoding="utf-8")
            return SimpleNamespace(returncode=1, args=command, stdout="", stderr="")
        with mock.patch.object(coordinator.subprocess, "run", side_effect=inspector):
            output, policy = coordinator._inspect_preparation_policy(root, destination,
                "szTheory/genewhip", "a" * 40, "b" * 40)
        self.assertEqual(policy["repository_observations"], expected["repository_observations"])
        self.assertEqual(policy["privacy_scan"], expected["privacy_scan"])
        self.assertEqual(policy["inspector_exit_code"], 1)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), policy)

    def test_continuation_gate_module_has_an_independent_payload_pin(self):
        with tempfile.TemporaryDirectory(prefix="gw17-module-pin-") as temp:
            root = Path(temp)
            target = root / "scripts/release/v02_continuation.py"
            target.parent.mkdir(parents=True)
            target.write_bytes((ROOT / "scripts/release/v02_continuation.py").read_bytes())
            pinned = continuation._module_pin(root)
            self.assertEqual(pinned, continuation._module_pin(root))
            target.write_bytes(target.read_bytes() + b"\n# changed gate\n")
            self.assertNotEqual(pinned, continuation._module_pin(root))

    def test_payload_rejects_unknown_and_duplicate_json_keys(self):
        for data in (b"[]", b'{"schema":"x","schema":"y"}', b'{"x":NaN}'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                continuation._json_object(data, "continuation-record-invalid")

    def test_payload_rejects_wrong_nested_shapes(self):
        for field, value in (("current_tests", []), ("current_tests", None),
                ("original_proof", []), ("original_proof", "accepted"),
                ("source_delta_records", []), ("source_delta_records", None),
                ("source_delta_records", {continuation.PRIVACY_FIXTURE: []})):
            with self.subTest(field=field, value=value), self.assertRaisesRegex(
                    ValueError, "continuation-record-shape-invalid"):
                continuation._attestation_shape({"current_tests": {
                    "tests/evidence/phase7_continuation_contract.py": "0" * 64,
                    "tests/evidence/phase7_return_consumer_contract.py": "1" * 64},
                    "original_proof": {"status": "accepted-original-scope"},
                    "source_delta_records": {continuation.PRIVACY_FIXTURE: {}}, field: value})

    def test_selector17_does_not_allow_unscoped_preparation_authority(self):
        with self.assertRaisesRegex(ValueError, "continuation-preparation-purpose-required"):
            coordinator._campaign_projection(Path("unused"), Path("unused"), Path("unused"),
                phase="runtime", selection="17", require_return=False,
                continuation_path=Path("unused"))

    def test_current_native_continuation_reopens_exact_r8_and_historical_inputs(self):
        self.assertEqual(continuation.CURRENT_RETURN_CANDIDATE_ROOT.as_posix(),
            "build/v02/campaign15/original10/current-source-candidate-final-r10")
        with tempfile.TemporaryDirectory(prefix="gw10-current-native-record-") as temporary:
            root = Path(temporary).resolve()
            required = set(continuation.R8_NATIVE_SOURCE_PATHS)
            required.update(("tests/evidence/v02_qualification_contract.py",
                "tests/evidence/phase7_continuation_contract.py",
                "tests/evidence/phase7_sticky_denial.py",
                "tests/evidence/phase7_return_consumer_contract.py",
                continuation.R8_PACKET.as_posix(), continuation.R8_RESULT.as_posix(),
                continuation.R8_ATTEMPT.as_posix(), continuation.R8_NESTED.as_posix(),
                continuation.R8_RESULT_REVIEW.as_posix(), continuation.R8_ADMISSION_REVIEW.as_posix(),
                continuation.RISK_SOURCE.as_posix(), continuation.RISK_SECURITY.as_posix(),
                continuation.RETAINED_PLANS["original10"].as_posix()))
            packet = json.loads((ROOT / continuation.R8_PACKET).read_bytes())
            required.update(packet["historical_17_pins"])
            required.update((continuation.R8_SOURCE_SNAPSHOT / relative).as_posix()
                for relative in continuation.R8_NATIVE_SOURCE_PATHS)
            for relative in sorted(required):
                source = ROOT / relative
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            record_path = root / continuation.CURRENT_NATIVE_CONTINUATION
            payload = continuation.build_current_native_continuation(root, record_path)
            self.assertEqual(payload["purpose"], "current-native-preparation")
            self.assertEqual(payload["native_evidence"]["run_sha256"], continuation.R8_RESULT_SHA)
            self.assertEqual(payload["native_evidence"]["native_source_pins"], packet["source_pins"])
            safety_delta = payload["current_source_delta_from_r8"][continuation.R8_SAFETY_REPORT_PATH]
            self.assertEqual(safety_delta["safety_summary_contract_delta"], {
                "function": continuation.R8_SAFETY_REPORT_FUNCTION,
                "r8_ast_sha256": continuation.R8_SAFETY_REPORT_OLD_AST_SHA,
                "current_ast_sha256": continuation.R8_SAFETY_REPORT_CURRENT_AST_SHA,
                "only_negative_controls_transition": "6-to-12",
                "native_runtime_changed": False})
            self.assertEqual(safety_delta["sanitized_failure_report_delta"], {
                "functions": {name: {"r8_ast_sha256": old_sha,
                    "current_ast_sha256": current_sha}
                    for name, (old_sha, current_sha)
                    in continuation.R8_DIAGNOSTIC_REPORT_FUNCTION_SHAS.items()},
                "module_assignment_ast_sha256": continuation.R8_DIAGNOSTIC_REPORT_ASSIGNMENT_SHAS,
                "diagnostic_only": True, "native_runtime_changed": False})
            self.assertIs(safety_delta["prelaunch_only_review_boundary"], False)
            fixture_delta = payload["current_source_delta_from_r8"][
                continuation.R8_SAFETY_REPORT_TEST_PATH]["test_fixture_deltas"]
            self.assertEqual(fixture_delta, [
                {"function": continuation.R8_SAFETY_FIXTURE_FUNCTION,
                    "r8_ast_sha256": continuation.R8_SAFETY_FIXTURE_OLD_AST_SHA,
                    "current_ast_sha256": continuation.R8_SAFETY_FIXTURE_CURRENT_AST_SHA,
                    "only_fixture_delta": True},
                {"class": "ReportContract", "method": continuation.R8_SAFETY_TEST_METHOD,
                    "r8_ast_sha256": continuation.R8_SAFETY_TEST_OLD_AST_SHA,
                    "current_ast_sha256": continuation.R8_SAFETY_TEST_CURRENT_AST_SHA,
                    "only_test_delta": True},
                *({"class": "ReportContract", "method": method_name,
                    "r8_ast_sha256": None, "current_ast_sha256": digest,
                    "new_test_method": True, "diagnostic_only": True}
                    for method_name, digest in continuation.R8_DIAGNOSTIC_REPORT_TEST_SHAS.items())])
            self.assertIs(payload["current_source_delta_from_r8"][
                continuation.R8_SAFETY_REPORT_TEST_PATH]["prelaunch_only_review_boundary"], False)
            route_delta = payload["current_source_delta_from_r8"][continuation.R8_DARWIN_TEST_PATH]
            self.assertIs(route_delta["prelaunch_only_review_boundary"], False)
            self.assertEqual(route_delta["test_method_delta"], {
                "class": "NativeParserContract",
                "method": continuation.R8_DARWIN_TEST_METHOD,
                "r8_ast_sha256": continuation.R8_DARWIN_TEST_OLD_AST_SHA,
                "current_ast_sha256": continuation.R8_DARWIN_TEST_CURRENT_AST_SHA,
                "only_fixture_delta": True})
            self.assertEqual(route_delta["sanitized_failure_test_diagnostic_delta"], {
                "main_r8_ast_sha256": continuation.R8_DIAGNOSTIC_ROUTE_MAIN_SHAS[0],
                "main_current_ast_sha256": continuation.R8_DIAGNOSTIC_ROUTE_MAIN_SHAS[1],
                "helper": continuation.R8_DIAGNOSTIC_ROUTE_HELPER,
                "helper_current_ast_sha256": continuation.R8_DIAGNOSTIC_ROUTE_HELPER_SHA,
                "method_set_assignment": continuation.R8_DIAGNOSTIC_ROUTE_METHOD_SET,
                "method_set_current_ast_sha256": continuation.R8_DIAGNOSTIC_ROUTE_METHOD_SET_SHA,
                "diagnostic_only": True, "native_runtime_changed": False})
            reopened = continuation.validate_current_native_continuation(root,
                continuation.CURRENT_NATIVE_CONTINUATION, require_reviews=False)
            self.assertEqual(reopened, payload)
            payload["native_evidence"]["attempt_sha256"] = "0" * 64
            record_path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "current-native-continuation-stale"):
                continuation.validate_current_native_continuation(root,
                    continuation.CURRENT_NATIVE_CONTINUATION, require_reviews=False)
            for relative, old, new, expected_error in (
                    ("scripts/release/v02_qualification.py", "def _bounded_command(",
                        "def _bounded_command_mutant(", "current-native-unreviewed-function-delta"),
                    ("scripts/release/v02_continuation.py",
                        "current-source-candidate-final-r10", "current-source-candidate-final-r9",
                        "current-native-candidate-root-delta-invalid"),
                    ("scripts/release/v02_qualification.py",
                        'archive_sha = hashlib.sha256(original_bytes).hexdigest()',
                        'archive_sha = hashlib.sha256(original_bytes + b"x").hexdigest()',
                        "current-native-retry-archive-helper-body-changed"),
                    ("scripts/release/v02_qualification.py",
                        'archive_dir = archive_root', 'archive_dir = journal_path.parent / "failures"',
                        "current-native-retry-archive-assignment-invalid"),
                    ("scripts/release/v02_qualification.py",
                        "packet = _valid_packet_for_delivery(packet_path, publication_copy)",
                        "packet = None  # changed effectful behavior", "current-native-effectful-function-body-changed"),
                    ("tests/session/phase6_route_contract.py", "def _process_group_rss_bytes(",
                        "def _process_group_rss_bytes_mutant(",
                        "current-native-unreviewed-function-delta"),
                    ("tests/session/phase6_route_contract.py",
                        "self.assertEqual(_process_group_exists(42), expected)",
                        "self.assertEqual(not _process_group_exists(42), expected)",
                        "current-native-darwin-test-method-unreviewed"),
                    ("scripts/evidence/phase4_report.py",
                        '"audio_pass": 256, "negative_controls": 12,',
                        '"audio_pass": 256, "negative_controls": 13,',
                        "current-native-safety-validator-delta-invalid"),
                    ("tests/evidence/phase4_report_contract.py",
                        '"negative_controls": 12, "allocation_instrumented": instrumented,',
                        '"negative_controls": 13, "allocation_instrumented": instrumented,',
                        "current-native-safety-fixture-delta-invalid"),
                    ("scripts/evidence/phase4_report.py",
                        'output.append(f"CTest failure [{kind}]")',
                        'output.append(f"CTest failure: {name} [{kind}]")',
                        "current-native-safety-diagnostic-function-unreviewed:summarize_sanitized_ctest_failures"),
                    ("tests/session/phase6_route_contract.py",
                        'print(f"GENEWHIP_TEST_RESULT:{method}:{kind}", file=sys.stderr)',
                        'print(f"GENEWHIP_TEST_RESULT:{method}:error", file=sys.stderr)',
                        "current-native-route-diagnostic-helper-unreviewed"),
                    ("tests/evidence/phase4_report_contract.py",
                        "test_injected_private_command", "test_injected_unknown_command",
                        "current-native-report-diagnostic-test-unreviewed:test_sanitized_ctest_failure_summary_identifies_only_allowlisted_methods")):
                source = root / relative
                original = (ROOT / relative).read_bytes()
                self.assertIn(old.encode(), original)
                source.write_bytes(original.replace(old.encode(), new.encode(), 1))
                with self.subTest(relative=relative), self.assertRaisesRegex(ValueError, expected_error):
                    continuation._current_native_record_payload(root)
                source.write_bytes(original)

    def test_current_native_cli_defaults_to_own_record_and_cannot_overwrite_original17(self):
        with tempfile.TemporaryDirectory(prefix="gw10-current-native-cli-") as temporary:
            root = Path(temporary).resolve()
            required = set(continuation.R8_NATIVE_SOURCE_PATHS)
            required.update(("tests/evidence/v02_qualification_contract.py",
                "tests/evidence/phase7_continuation_contract.py",
                "tests/evidence/phase7_sticky_denial.py",
                "tests/evidence/phase7_return_consumer_contract.py",
                continuation.R8_PACKET.as_posix(), continuation.R8_RESULT.as_posix(),
                continuation.R8_ATTEMPT.as_posix(), continuation.R8_NESTED.as_posix(),
                continuation.R8_RESULT_REVIEW.as_posix(), continuation.R8_ADMISSION_REVIEW.as_posix(),
                continuation.RISK_SOURCE.as_posix(), continuation.RISK_SECURITY.as_posix(),
                continuation.RETAINED_PLANS["original10"].as_posix()))
            packet = json.loads((ROOT / continuation.R8_PACKET).read_bytes())
            required.update(packet["historical_17_pins"])
            required.update((continuation.R8_SOURCE_SNAPSHOT / relative).as_posix()
                for relative in continuation.R8_NATIVE_SOURCE_PATHS)
            for relative in sorted(required):
                source = ROOT / relative
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            historical = root / continuation.ATTESTATION
            historical_before = historical.read_bytes()
            with mock.patch.object(continuation, "ROOT", root), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(continuation.main(["--build-current-native"]), 0)
                current = root / continuation.CURRENT_NATIVE_CONTINUATION
                self.assertTrue(current.is_file())
                before_collision = current.read_bytes()
                with self.assertRaisesRegex(ValueError, "current-native-output-already-exists"):
                    continuation.build_current_native_continuation(root)
                with contextlib.redirect_stderr(io.StringIO()) as errors:
                    self.assertEqual(continuation.main(["--build-current-native"]), 1)
                self.assertIn("current-native-output-already-exists", errors.getvalue())
                self.assertEqual(current.read_bytes(), before_collision)
                with contextlib.redirect_stderr(io.StringIO()) as errors:
                    self.assertEqual(continuation.main(["--build-current-native", "--attestation",
                        continuation.ATTESTATION.as_posix()]), 1)
                self.assertIn("current-native-output-path-invalid", errors.getvalue())
                with contextlib.redirect_stderr(io.StringIO()) as errors:
                    self.assertEqual(continuation.main(["--build-current-native", "--attestation",
                        "build/v02/unexpected-current-native.json"]), 1)
                self.assertIn("current-native-output-path-invalid", errors.getvalue())
            self.assertEqual(historical.read_bytes(), historical_before)
            self.assertFalse((root / "build/v02/unexpected-current-native.json").exists())

    def test_fresh_current_preparation_validates_separately_from_archived_r3_history(self):
        with tempfile.TemporaryDirectory(prefix="gw10-current-preparation-refresh-") as temporary:
            root = Path(temporary).resolve()
            required = set(continuation.R8_NATIVE_SOURCE_PATHS)
            required.update(("tests/evidence/v02_qualification_contract.py",
                "tests/evidence/phase7_continuation_contract.py",
                "tests/evidence/phase7_sticky_denial.py",
                "tests/evidence/phase7_return_consumer_contract.py",
                continuation.R8_PACKET.as_posix(), continuation.R8_RESULT.as_posix(),
                continuation.R8_ATTEMPT.as_posix(), continuation.R8_NESTED.as_posix(),
                continuation.R8_RESULT_REVIEW.as_posix(), continuation.R8_ADMISSION_REVIEW.as_posix(),
                continuation.RISK_SOURCE.as_posix(), continuation.RISK_SECURITY.as_posix(),
                continuation.RETAINED_PLANS["original10"].as_posix()))
            required.update((continuation.CURRENT_NATIVE_R3_ARCHIVE / name).as_posix()
                for name in (continuation.CURRENT_NATIVE_CONTINUATION.name,
                    continuation.CURRENT_NATIVE_CODE_REVIEW.name,
                    continuation.CURRENT_NATIVE_SECURITY_REVIEW.name))
            packet = json.loads((ROOT / continuation.R8_PACKET).read_bytes())
            required.update(packet["historical_17_pins"])
            required.update((continuation.R8_SOURCE_SNAPSHOT / relative).as_posix()
                for relative in continuation.R8_NATIVE_SOURCE_PATHS)
            for relative in sorted(required):
                source, target = ROOT / relative, root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            payload = continuation.build_current_native_continuation(root,
                continuation.CURRENT_NATIVE_CONTINUATION)
            digest = sha(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
            body = "Current preparation fixture.\n"
            def write_review(path, fields):
                path = root / path
                path.parent.mkdir(parents=True, exist_ok=True)
                complete = {**fields, "report_body_sha256": sha(body.encode())}
                path.write_text("---\n" + "".join(f"{key}: {value}\n"
                    for key, value in sorted(complete.items())) + "---\n" + body, encoding="utf-8")
            write_review(continuation.CURRENT_NATIVE_CODE_REVIEW, {
                "status": "accepted", "reviewer_role": "gsd-code-reviewer", "reviewer_model": "gpt-6-luna",
                "author_role": "gsd-executor", "payload_sha256": digest,
                "unresolved high/critical": "0", "critical": "0", "high": "0"})
            write_review(continuation.CURRENT_NATIVE_SECURITY_REVIEW, {
                "status": "accepted", "reviewer_role": "gsd-security-auditor", "reviewer_model": "gpt-6.1-sol",
                "author_role": "gsd-executor", "payload_sha256": digest,
                "unresolved current high/critical": "0", "critical": "0", "high": "0",
                "current_risk": "open medium nonblocking", "attributable_cleanup_target": "none",
                "user_action_required": "no", "historical_identity_liveness": "UNKNOWN",
                "historical_T-07-07": "OPEN/high",
                "risk_source_sha256": payload["current_risk_evidence_sha256"]["source"],
                "risk_assessment_sha256": payload["current_risk_evidence_sha256"]["security"]})
            reopened = continuation.validate_current_native_continuation(root,
                continuation.CURRENT_NATIVE_CONTINUATION)
            self.assertEqual(reopened, payload)
            self.assertEqual(continuation._validate_current_native_preparation_record(root, payload)["status"],
                "accepted-current-preparation")
            self.assertEqual(continuation._validate_r3_preparation_record(root)["status"],
                "accepted-historical-preparation-r3")
            archive_record = root / continuation.CURRENT_NATIVE_R3_ARCHIVE / continuation.CURRENT_NATIVE_CONTINUATION.name
            old = archive_record.read_bytes()
            archive_record.write_bytes(old + b" ")
            with self.assertRaisesRegex(ValueError, "current-return-r3-preparation-record-stale"):
                continuation._validate_r3_preparation_record(root)
            archive_record.write_bytes(old)

    def test_current_native_purpose_is_restricted_to_prepare_only(self):
        with self.assertRaisesRegex(ValueError, "current-native-purpose-requires-prepare-only"):
            coordinator._campaign_projection(Path("unused"), Path("unused"), Path("unused"),
                phase="runtime", selection="17", require_return=False,
                continuation_path=continuation.CURRENT_NATIVE_CONTINUATION,
                continuation_purpose="current-native-preparation", preparation_only=False)

    def test_current_native_cli_rejects_every_non_prepare_only_mode_before_effects(self):
        for mode in ("runtime", "hosted", "retry-source", "package", "validate"):
            argv = ["--mode", mode, "--out", "build/v02/current-native-denied.json",
                "--recovery-selection", "17", "--continuation",
                continuation.CURRENT_NATIVE_CONTINUATION.as_posix(), "--continuation-purpose",
                "current-native-preparation"]
            with self.subTest(mode=mode), contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(coordinator.main(argv), 1)
                self.assertIn("current-native-purpose-requires-stage-public-prepare-only",
                    errors.getvalue())
        self.assertEqual(process_denial.receipt()["real_child_starts"], 0)

    def test_direct_publication_effect_apis_fail_closed_on_current_return_misrouting(self):
        with tempfile.TemporaryDirectory(prefix="gw10-direct-current-return-") as temporary:
            root = Path(temporary).resolve()
            noncampaign_journal = root / "ordinary-journal.json"
            packet = root / "missing-packet.json"
            publication = root / "missing-publication"
            scope = ROOT / "evidence/v02-execution.json"
            cases = (
                ("wrong selection", "15", None, noncampaign_journal,
                    "current-return-purpose-requires-protected-return-mode"),
                ("missing return record", "17", None, noncampaign_journal,
                    "current-return-purpose-requires-protected-return-mode"),
                ("noncampaign journal", "17", continuation.CURRENT_RETURN_RECORD,
                    noncampaign_journal, "recovery-campaign-selected-journal-required"),
                ("missing campaign", "17", continuation.CURRENT_RETURN_RECORD,
                    ROOT / "build/v02/campaign15/hosted-delivery-journal.json",
                    "recovery-campaign-required-for-selected-journal"))
            functions = (coordinator.publish_sanitized_source, coordinator.retry_sanitized_source)
            with mock.patch.object(coordinator, "_valid_packet_for_delivery",
                    side_effect=AssertionError("packet parsing must follow the return gate")):
                for label, selection, record, journal, expected_error in cases:
                    for function in functions:
                        with self.subTest(case=label, function=function.__name__), \
                                self.assertRaisesRegex(ValueError, expected_error):
                            function(packet, publication, journal, recovery_selection=selection,
                                continuation_path=record, continuation_purpose="current-native-return")
                    with self.subTest(case=label, function="run_hosted_qualification"), \
                            self.assertRaisesRegex(ValueError, expected_error):
                        coordinator.run_hosted_qualification(packet, publication, scope,
                            root / "hosted.json", journal_path=journal, recovery_selection=selection,
                            continuation_path=record, continuation_purpose="current-native-return")
        self.assertEqual(process_denial.receipt()["real_child_starts"], 0)

    def test_current_return_validator_joins_code_security_candidate_and_parent_reviews(self):
        with tempfile.TemporaryDirectory(prefix="gw10-current-return-validator-") as temporary:
            root = Path(temporary).resolve()
            body = b"Bounded source-only review fixture.\n"

            def write_report(relative, fields):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                complete = dict(fields)
                complete["report_body_sha256"] = sha(body)
                text = "---\n" + "".join(f"{key}: {value}\n" for key, value in sorted(complete.items()))
                path.write_text(text + "---\n" + body.decode("utf-8"), encoding="utf-8")
                return path

            payload = {"current_risk_evidence_sha256": {"source": "a" * 64, "security": "b" * 64},
                "retained_duties_sha256": "c" * 64,
                "candidate": {"preparation_path": "candidate/preparation.json",
                    "preparation_sha256": "d" * 64, "repository_policy_path": "candidate/policy.json",
                    "repository_policy_sha256": "e" * 64, "publication_path": "candidate/publication",
                    "public_head": "1" * 40, "public_base": "2" * 40, "public_tree": "3" * 40,
                    "source_manifest_sha256": "f" * 64, "tracked_file_count": 7}}
            payload_sha = sha(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
            code_path = write_report(continuation.CURRENT_RETURN_CODE_REVIEW, {
                "status": "accepted", "reviewer_role": "gsd-code-reviewer", "reviewer_model": "gpt-6-luna",
                "author_role": "gsd-executor", "payload_sha256": payload_sha,
                "unresolved high/critical": "0", "critical": "0", "high": "0"})
            security_path = write_report(continuation.CURRENT_RETURN_SECURITY_REVIEW, {
                "status": "accepted", "reviewer_role": "gsd-security-auditor", "reviewer_model": "gpt-6.1-sol",
                "author_role": "gsd-executor", "payload_sha256": payload_sha,
                "unresolved current high/critical": "0", "critical": "0", "high": "0",
                "current_risk": "open medium nonblocking", "attributable_cleanup_target": "none",
                "user_action_required": "no", "historical_identity_liveness": "UNKNOWN",
                "historical_T-07-07": "OPEN/high", "risk_source_sha256": "a" * 64,
                "risk_assessment_sha256": "b" * 64})

            def candidate_review(role, security=False):
                candidate = payload["candidate"]
                fields = {"status": "accepted", "reviewer_role": role,
                    "reviewer_model": "gpt-6-luna" if role == "gsd-code-reviewer" else "gpt-6.1-sol",
                    "author_role": "gsd-executor", "payload_sha256": payload_sha,
                    "candidate_preflight_path": candidate["preparation_path"],
                    "candidate_preflight_sha256": candidate["preparation_sha256"],
                    "repository_policy_path": candidate["repository_policy_path"],
                    "repository_policy_sha256": candidate["repository_policy_sha256"],
                    "publication_copy_path": candidate["publication_path"],
                    "candidate_head_sha256": candidate["public_head"],
                    "candidate_base_sha256": candidate["public_base"],
                    "candidate_tree_sha256": candidate["public_tree"],
                    "candidate_manifest_sha256": candidate["source_manifest_sha256"],
                    "tracked_file_count": str(candidate["tracked_file_count"]),
                    "privacy": "pass", "destination_policy": "read-only-verified"}
                if security:
                    fields.update({"unresolved current high/critical": "0", "critical": "0", "high": "0",
                        "current_risk": "open medium nonblocking", "attributable_cleanup_target": "none",
                        "user_action_required": "no", "historical_identity_liveness": "UNKNOWN",
                        "historical_T-07-07": "OPEN/high", "risk_source_sha256": "a" * 64,
                        "risk_assessment_sha256": "b" * 64})
                else:
                    fields.update({"unresolved high/critical": "0", "critical": "0", "high": "0"})
                return write_report(continuation.CURRENT_RETURN_CANDIDATE_CODE_REVIEW if not security
                    else continuation.CURRENT_RETURN_CANDIDATE_SECURITY_REVIEW, fields)

            candidate_code = candidate_review("gsd-code-reviewer")
            candidate_security = candidate_review("gsd-security-auditor", security=True)
            candidate_code_sha, candidate_security_sha = sha(candidate_code.read_bytes()), sha(candidate_security.read_bytes())
            code_sha, security_sha = sha(code_path.read_bytes()), sha(security_path.read_bytes())
            return_review = write_report(continuation.CURRENT_RETURN_REVIEW, {
                "status": "accepted", "reviewer_role": "gsd-code-reviewer", "reviewer_model": "gpt-6-luna",
                "author_role": "gsd-executor", "payload_sha256": payload_sha,
                "code_review_sha256": code_sha, "security_review_sha256": security_sha,
                "candidate_code_review_sha256": candidate_code_sha,
                "candidate_security_review_sha256": candidate_security_sha,
                "unresolved high/critical": "0", "critical": "0", "high": "0"})
            return_review_sha = sha(return_review.read_bytes())
            write_report(continuation.CURRENT_RETURN_REPORT, {"status": "accepted",
                "payload_sha256": payload_sha, "review_sha256": return_review_sha,
                "code_review_sha256": code_sha, "security_review_sha256": security_sha,
                "candidate_code_review_sha256": candidate_code_sha,
                "candidate_security_review_sha256": candidate_security_sha,
                "current_risk": "open medium nonblocking", "historical_identity_liveness": "UNKNOWN",
                "historical_T-07-07": "OPEN/high", "requirements_qualified": "none",
                "scope": "original10-current-source-readiness", "product_qualification_claim": "false",
                "retained_duties_sha256": payload["retained_duties_sha256"]})
            record = root / continuation.CURRENT_RETURN_RECORD
            record.parent.mkdir(parents=True, exist_ok=True)
            record.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            with mock.patch.object(continuation, "_current_native_return_payload", return_value=payload):
                self.assertEqual(continuation.validate_current_native_return(root,
                    continuation.CURRENT_RETURN_RECORD), payload)
                accepted_candidate = candidate_code.read_bytes()
                candidate_code.unlink()
                with self.assertRaises((OSError, ValueError)):
                    continuation.validate_current_native_return(root, continuation.CURRENT_RETURN_RECORD)
                candidate_code.write_bytes(accepted_candidate)
                write_report(continuation.CURRENT_RETURN_CANDIDATE_CODE_REVIEW, {
                    "status": "accepted", "reviewer_role": "gsd-code-reviewer", "reviewer_model": "gpt-6-luna",
                    "author_role": "gsd-executor", "payload_sha256": payload_sha,
                    "candidate_preflight_path": payload["candidate"]["preparation_path"],
                    "candidate_preflight_sha256": payload["candidate"]["preparation_sha256"],
                    "repository_policy_path": payload["candidate"]["repository_policy_path"],
                    "repository_policy_sha256": payload["candidate"]["repository_policy_sha256"],
                    "publication_copy_path": payload["candidate"]["publication_path"],
                    "candidate_head_sha256": "0" * 40,
                    "candidate_base_sha256": payload["candidate"]["public_base"],
                    "candidate_tree_sha256": payload["candidate"]["public_tree"],
                    "candidate_manifest_sha256": payload["candidate"]["source_manifest_sha256"],
                    "tracked_file_count": "7", "privacy": "pass", "destination_policy": "read-only-verified",
                    "unresolved high/critical": "0", "critical": "0", "high": "0"})
                with self.assertRaisesRegex(ValueError, "current-return-candidate-review-stale-or-rejected"):
                    continuation.validate_current_native_return(root, continuation.CURRENT_RETURN_RECORD)
                candidate_code.write_bytes(accepted_candidate)
                accepted_parent_review = return_review.read_bytes()
                return_review.write_bytes(accepted_parent_review.replace(payload_sha.encode(), b"0" * 64, 1))
                with self.assertRaisesRegex(ValueError, "current-native-return-parent-review-missing-or-stale"):
                    continuation.validate_current_native_return(root, continuation.CURRENT_RETURN_RECORD)
                return_review.write_bytes(accepted_parent_review)
                return_review.unlink()
                with self.assertRaises((OSError, ValueError)):
                    continuation.validate_current_native_return(root, continuation.CURRENT_RETURN_RECORD)

    def test_current_return_record_writer_uses_exclusive_nofollow_parent_creation(self):
        with tempfile.TemporaryDirectory(prefix="gw10-current-return-write-") as temporary:
            root = Path(temporary).resolve()
            target = Path("records/current-return.json")
            continuation._write_exclusive_json(root, target, {"status": "candidate"})
            written = root / target
            before = written.read_bytes()
            with self.assertRaisesRegex(ValueError, "current-return-output-already-exists"):
                continuation._write_exclusive_json(root, target, {"status": "replacement"})
            self.assertEqual(written.read_bytes(), before)
            outside = root / "outside"
            outside.mkdir()
            (root / "linked").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "current-return-output-parent-invalid"):
                continuation._write_exclusive_json(root, Path("linked/record.json"), {"status": "rejected"})
            self.assertFalse((outside / "record.json").exists())

    def test_current_native_return_operator_route_reaches_only_stubbed_publish_boundary(self):
        candidate_path = ROOT / continuation.CURRENT_RETURN_CANDIDATE_ROOT / "publication"
        if candidate_path.is_symlink():
            raise AssertionError("candidate publication root unexpectedly linked")
        candidate_root = candidate_path.resolve(strict=True)
        output = "build/v02/campaign15/original10/current-return-route-sentinel.json"
        output_path = ROOT / output
        if output_path.exists() or output_path.is_symlink():
            raise AssertionError("operator-route sentinel output already exists")
        original_run = subprocess.run
        bounded_readonly_git, git_calls = bounded_readonly_git_runner(process_denial, original_run)

        publication_result = publication_sentinel()
        writes = []

        def observe_owned_output(path, value):
            if Path(path) != output_path:
                raise AssertionError("operator route attempted an unexpected output write")
            writes.append((Path(path), value))

        argv = ["--mode", "stage-public", "--out", output,
            "--preflight", (continuation.CURRENT_RETURN_CANDIDATE_ROOT / "preparation.json").as_posix(),
            "--publication-copy", (continuation.CURRENT_RETURN_CANDIDATE_ROOT / "publication").as_posix(),
            "--scope", "evidence/v02-execution.json", "--recovery-selection", "17",
            "--continuation", continuation.CURRENT_RETURN_RECORD.as_posix(),
            "--continuation-purpose", "current-native-return", "--campaign",
            "build/v02/campaign15/campaign.json", "--campaign-sha256",
            "f309198a4f25fee9ffb017570e0900de70c199732d9880a4f375d70bc847aad1",
            "--journal", "build/v02/campaign15/hosted-delivery-journal.json"]
        process_denial.enable_readonly_git(candidate_root, ROOT.resolve())
        try:
            with mock.patch.object(coordinator, "publish_sanitized_source",
                    return_value=publication_result) as publish, \
                    mock.patch.object(subprocess, "run", side_effect=bounded_readonly_git), \
                    mock.patch.object(coordinator, "_write_json", side_effect=observe_owned_output) as write_json, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(coordinator.main(argv), 0)
        finally:
            process_denial.disable_readonly_git()
        publish.assert_called_once()
        self.assertEqual(publish.call_args.kwargs["recovery_selection"], "17")
        self.assertEqual(publish.call_args.kwargs["continuation_path"],
            Path(continuation.CURRENT_RETURN_RECORD.as_posix()))
        self.assertEqual(publish.call_args.kwargs["continuation_purpose"], "current-native-return")
        write_json.assert_called_once()
        self.assertEqual(writes[0][0], output_path)
        self.assertFalse(output_path.exists())
        self.assertFalse(candidate_root.is_symlink())
        receipt = process_denial.receipt()
        self.assertGreater(len(git_calls), 0)
        self.assertEqual(receipt["real_child_starts"], len(git_calls))
        self.assertEqual(receipt["readonly_git_starts"], len(git_calls))
        self.assertEqual(receipt["unexpected_denials"], 0)

    def test_operator_readonly_git_allowlist_rejects_mutation_and_other_programs(self):
        self.assertTrue(process_denial.readonly_git_argv_allowed(["git", "rev-parse", "HEAD"]))
        self.assertTrue(process_denial.readonly_git_argv_allowed([
            "git", "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"]))
        for command in (["git", "rev-parse", "--verify", "HEAD"],
                ["git", "push", "origin", "main"], ["python3", "-c", "pass"]):
            with self.subTest(command=command):
                self.assertFalse(process_denial.readonly_git_argv_allowed(command))
        candidate = (ROOT / "build/v02/test-readonly-git-candidate").resolve()
        process_denial.enable_readonly_git(candidate, ROOT.resolve())
        try:
            self.assertTrue(process_denial.readonly_git_event_allowed(None,
                ["git", "rev-parse", "HEAD"], ROOT.resolve()))
            self.assertTrue(process_denial.readonly_git_event_allowed(None,
                ["git", "rev-parse", "HEAD"], candidate))
            self.assertFalse(process_denial.readonly_git_event_allowed(None,
                ["git", "status", "--porcelain"], ROOT.resolve()))
            self.assertFalse(process_denial.readonly_git_event_allowed(None,
                ["git", "rev-parse", "HEAD"], ROOT.resolve() / "other"))
        finally:
            process_denial.disable_readonly_git()

    def test_current_native_return_campaign_projection_does_not_fall_through_to_legacy_validator(self):
        import importlib.machinery
        calls = []
        class FakeLoader:
            def create_module(self, spec):
                return None
            def exec_module(self, module):
                def current_return(root, path):
                    calls.append(("current", path))
                    return {"status": "accepted-current-return-fixture"}
                def legacy_return(*args, **kwargs):
                    calls.append(("legacy", args, kwargs))
                    raise AssertionError("current return must not use the original17 validator")
                module.validate_current_native_return = current_return
                module.validate_attestation = legacy_return
        spec = importlib.machinery.ModuleSpec("gw_current_return_projection_fixture", FakeLoader())
        with mock.patch.object(coordinator.importlib.util, "spec_from_file_location", return_value=spec), \
                mock.patch.dict(os.environ, {}, clear=False):
            result = coordinator._campaign_projection(
                ROOT / "build/v02/campaign15/campaign.json",
                ROOT / "evidence/v02-execution.json",
                ROOT / "build/v02/campaign15/hosted-delivery-journal.json",
                phase="runtime", expected_sha256="f309198a4f25fee9ffb017570e0900de70c199732d9880a4f375d70bc847aad1",
                require_return=True, selection="17",
                continuation_path=continuation.CURRENT_RETURN_RECORD,
                continuation_purpose="current-native-return")
        self.assertEqual(calls, [("current", continuation.CURRENT_RETURN_RECORD)])
        self.assertEqual(result.get("status"), "started")

    def test_current_native_return_cli_denies_prepare_and_unrelated_modes_before_effects(self):
        for mode, extra in (("stage-public", ["--prepare-only"]), ("runtime", []),
                ("package", []), ("validate", []), ("close", [])):
            argv = ["--mode", mode, "--out", "build/v02/current-return-denied.json",
                "--publication-copy", "build/v02/current-return-denied-publication",
                "--recovery-selection", "17", "--continuation",
                continuation.CURRENT_RETURN_RECORD.as_posix(), "--continuation-purpose",
                "current-native-return", *extra]
            with self.subTest(mode=mode, extra=extra), contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(coordinator.main(argv), 1)
                self.assertIn("current-return-purpose-requires-protected-return-mode", errors.getvalue())
        self.assertEqual(process_denial.receipt()["real_child_starts"], 0)

    def test_current_native_return_requires_campaign_before_any_delivery_effect(self):
        argv = ["--mode", "stage-public", "--out", "build/v02/current-return-denied.json",
            "--publication-copy", "build/v02/current-return-denied-publication",
            "--recovery-selection", "17", "--continuation",
            continuation.CURRENT_RETURN_RECORD.as_posix(), "--continuation-purpose",
            "current-native-return"]
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(coordinator.main(argv), 1)
        self.assertIn("recovery-campaign-required-for-selection", errors.getvalue())
        self.assertFalse((ROOT / "build/v02/current-return-denied-publication").exists())
        self.assertFalse((ROOT / "build/v02/current-return-denied.json").exists())
        self.assertEqual(process_denial.receipt()["real_child_starts"], 0)

    def test_current_return_selector_preserves_all_original17_api_defaults(self):
        import inspect
        for function in (coordinator._campaign_projection, coordinator._require_campaign_for_journal,
                coordinator.publish_sanitized_source, coordinator.retry_sanitized_source,
                coordinator.run_hosted_qualification):
            with self.subTest(function=function.__name__):
                self.assertEqual(inspect.signature(function).parameters[
                    "continuation_purpose"].default, "original17")
        with self.assertRaisesRegex(ValueError, "continuation-path-invalid"):
            continuation.validate_attestation(ROOT, continuation.CURRENT_RETURN_RECORD,
                require_reviews=False)

    def test_legacy_current_source_gate_still_requires_original17_record(self):
        with self.assertRaisesRegex(ValueError, "continuation-path-invalid"):
            continuation.validate_attestation(ROOT, continuation.CURRENT_NATIVE_CONTINUATION,
                require_reviews=False)

    def test_independent_review_body_is_bound_to_its_canonical_disposition(self):
        with tempfile.TemporaryDirectory(prefix="gw17-review-body-") as temporary:
            report = Path(temporary) / "review.md"
            payload = {"review_scope": "source-and-return-gates"}
            payload_sha = hashlib.sha256(json.dumps(payload, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()
            body = b"Independent review: accepted. Current findings: zero.\n"
            body_sha = hashlib.sha256(body).hexdigest()
            report.write_bytes(("---\nstatus: accepted\nreviewer_role: gsd-code-reviewer\n"
                "reviewer_model: gpt-6-luna\nauthor_role: gsd-executor\n"
                f"payload_sha256: {payload_sha}\nunresolved high/critical: 0\ncritical: 0\n"
                f"high: 0\nreport_body_sha256: {body_sha}\n---\n").encode() + body)
            continuation._validate_independent_report(report, payload,
                role="gsd-code-reviewer", model="gpt-6-luna",
                count_key="unresolved high/critical")
            report.write_bytes(report.read_bytes().replace(body, b"Independent review: REJECTED; high: 1.\n"))
            with self.assertRaisesRegex(ValueError, "continuation-independent-review-stale-or-rejected"):
                continuation._validate_independent_report(report, payload,
                    role="gsd-code-reviewer", model="gpt-6-luna",
                    count_key="unresolved high/critical")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    choices = ("tracer", "contracts", "operator-route-check", "verify-original",
        "review-check", "candidate-check", "return-check", "build-attestation")
    selected = parser.add_mutually_exclusive_group(required=True)
    for choice in choices:
        selected.add_argument("--" + choice, action="store_true")
    args = parser.parse_args()
    bootstrap()
    try:
        if args.build_attestation:
            with mock.patch.object(continuation.subprocess, "run", side_effect=
                    ContinuationContracts._fake_git_show):
                value = continuation.build_attestation(ROOT, continuation.ATTESTATION)
            print(json.dumps({"status": "candidate", "payload_sha256": hashlib.sha256(
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()},
                sort_keys=True))
        elif args.review_check or args.candidate_check or args.return_check:
            with mock.patch.object(continuation.subprocess, "run", side_effect=
                    ContinuationContracts._fake_git_show), mock.patch.object(continuation,
                    "_candidate_git", side_effect=lambda candidate, *argv:
                        ContinuationContracts._bound_candidate_git(ROOT, candidate, *argv)), \
                    mock.patch.object(continuation, "_candidate_privacy",
                        return_value=([], {"findings": []})):
                value = continuation.validate_attestation(ROOT, continuation.ATTESTATION,
                    require_candidate=args.candidate_check or args.return_check,
                    require_return=args.return_check)
            print(json.dumps({"status": "accepted", "payload_sha256": hashlib.sha256(
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()},
                sort_keys=True))
        if args.operator_route_check:
            selected_tests = unittest.TestSuite([ContinuationContracts(
                "test_current_native_return_operator_route_reaches_only_stubbed_publish_boundary")])
        else:
            selected_tests = unittest.defaultTestLoader.loadTestsFromTestCase(ContinuationContracts)
            # This integration test consumes the fresh R2 candidate and six real reviews.
            # Keep it an explicit post-preparation check so source-only contracts remain
            # runnable before that candidate exists; never treat omission as a pass.
            selected_tests = unittest.TestSuite(test for test in selected_tests
                if test.id().rsplit(".", 1)[-1] !=
                "test_current_native_return_operator_route_reaches_only_stubbed_publish_boundary")
        result = unittest.TextTestRunner(verbosity=2).run(selected_tests)
        process_denial.self_test("after-test-restoration")
        native_self_test()
        receipt = process_denial.receipt()
        receipt["native_denials"] = len(NATIVE_DENIALS)
        print(json.dumps(receipt, sort_keys=True))
        return 0 if successful_ledger(result, receipt, operator_route=args.operator_route_check,
            native_denials=len(NATIVE_DENIALS)) else 1
    finally:
        if TEMPORARY is not None:
            TEMPORARY.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())

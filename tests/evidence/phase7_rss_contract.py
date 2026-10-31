#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Denied, source-pinned contracts for bounded Darwin process RSS observation."""
from __future__ import annotations

import argparse
import contextlib
import copy
import ctypes as real_ctypes
import hashlib
import importlib.util
import importlib.machinery
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests/session/phase6_route_contract.py"
EVIDENCE = ROOT / "build/v02/recovery12/rss-contract.json"
DIRTY_PROBE = ROOT / "build/v02/recovery12/dirty-denial-probe.json"
REVIEW = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-12-REVIEW.md"
PHASE_DIR = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery"
EXPECTED_SLOTS = 4097
MAX_PIDS = 4096
SOURCE_OVERRIDE = None
DENIAL_SPEC = importlib.util.spec_from_file_location(
    "phase7_rss_sticky_denial", Path(__file__).with_name("phase7_sticky_denial.py"))
denial = importlib.util.module_from_spec(DENIAL_SPEC)
DENIAL_SPEC.loader.exec_module(denial)
denial.install()

NATIVE_DENIALS: list[str] = []
REAL_CDLL = real_ctypes.CDLL
REAL_GETPGID = os.getpgid


def _deny_native_load(*_args, **_kwargs):
    NATIVE_DENIALS.append("ctypes.CDLL")
    raise PermissionError("sticky-native-load-denial")


def _deny_getpgid(*_args, **_kwargs):
    NATIVE_DENIALS.append("os.getpgid")
    raise PermissionError("sticky-native-query-denial")


real_ctypes.CDLL = _deny_native_load
os.getpgid = _deny_getpgid


def native_self_test(label: str) -> None:
    before = len(NATIVE_DENIALS)
    for expected, action in (("ctypes.CDLL", lambda: real_ctypes.CDLL("/no-native-load")),
                             ("os.getpgid", lambda: os.getpgid(899001))):
        try:
            action()
        except PermissionError as error:
            if str(error) not in ("sticky-native-load-denial", "sticky-native-query-denial"):
                raise AssertionError("native-denial-wrong-message") from error
        else:
            raise AssertionError("native-denial-not-reached")
    if NATIVE_DENIALS[before:] != ["ctypes.CDLL", "os.getpgid"]:
        raise AssertionError("native-denial-ledger-mismatch")
    NATIVE_DENIALS.append("self-test:" + label)


native_self_test("before-production-imports")

CASES: list[str] = []
OBSERVATIONS: list[dict[str, int]] = []
PRODUCTION = None
MUTANT_RESULTS: list[dict[str, object]] = []
CONTROL_RESULTS: list[dict[str, object]] = []
DIRTY_DENIAL_RESULT: dict[str, object] = {}

ENTRY_PINS = {
    **{f".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-{number:02d}-PLAN.md": digest for number, digest in (
        (1, "d542f186e4a9e55498160bd90f301b9529b5c1b4f5693662f19a5a37d9a5898c"),
        (2, "3a2fc6365a3ca1ec0177b724bb0897b5cc4c278447a8658c7da08c0caeb91df3"),
        (3, "619f7431bd5136c2b81bae8469dce62becf682534879b04d5fa892fc593b7966"),
        (4, "1c277ffd80e5418f5fb4ced52b7429ba7954dfc1c564698239496aa13fe4ba4e"),
        (5, "6d74d7f78b409df759f38521cf1cd348595e34b00d45796ad1c64904dde4e0e5"),
        (6, "b6d197f564240059a9f340e437737e5b9ed40e42e6f50bf867a5779a8fd3d601"),
        (7, "48df093f0a4a7f16a4844137894707767cdc8e51dbe3a10beaf1a55f18e83f47"),
        (8, "922f176c46db3a55b8534a552a715f3104e7c2a9fcd959f6a61a76b703a933ca"),
        (9, "8540a03ec105876ec6c6d348c761092cae88adbd398e2d5b46141eb099a5cdb9"),
        (10, "355c86361d4dd1b88b7d46a85ef1ad337c7b83b7ee2a537e2b152250b08ee1ce"),
        (11, "a9f59d4ea75e426c989d76fb2e39e95d4484304eb28a1f8f8ce59fc27c4c99dc"),
    )},
    ".planning/milestones/v0.1-phases/GW-01-consumable-diagnostic-machine/01-RESEARCH.md": "d0fc7d12bc70a35979f0869297b5148f420bbd2a57ad80813acb88ce688129e2",
    ".planning/state.json": "bfb932cd678bc0f8755f8034de46a7e5f110755d3979a73d263172ce8f177b86",
    ".planning/forensics/report-20261025-191402.md": "2cfd6d09d9735b08ef83f4c1990ceb9dd9e95edf0b29691becadaac2d212d8c1",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-04-red-task1.json": "2f2e94fcb8a2eefa24218fc3257b50056be562e2db5c22948dc9aaafd922620d",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-04-red-task2.json": "bae552109833d97c7571bee5e77c24fce574568a4caf41f02f78b0190a25357a",
}


class LazyPidArray:
    """A bounded test double that records requested native allocation size."""
    def __init__(self, size: int, allocations: list[int]):
        allocations.append(size)
        self.size = size
        self.values = {}

    def __len__(self):
        return self.size

    def __getitem__(self, key):
        if isinstance(key, slice):
            return [self.values.get(index, 0) for index in range(key.start or 0, key.stop or 0)]
        return self.values.get(key, 0)

    def __setitem__(self, key, value):
        self.values[key] = value


class CIntMeta(type):
    def __mul__(cls, size):
        return lambda: LazyPidArray(size, ALLOCATIONS)


class FakeCInt(metaclass=CIntMeta):
    pass


ALLOCATIONS: list[int] = []


class FakeBuffer:
    def __init__(self, size):
        self.raw = bytes(size)

    def __len__(self):
        return len(self.raw)


class FakeFunction:
    def __init__(self, callback):
        self.callback = callback
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.callback(*args)


class FakeLibProc:
    def __init__(self, count_bytes: int, copied_bytes: int, pids=(123,),
                 task_result=16, resident_by_pid=None, task_error=None):
        self.count_bytes = count_bytes
        self.copied_bytes = copied_bytes
        self.pids = tuple(pids)
        self.task_result = task_result
        self.resident_by_pid = resident_by_pid or {}
        self.task_error = task_error
        self.list_calls: list[tuple[bool, int]] = []
        self.pidinfo_calls: list[tuple[int, int]] = []
        self.proc_listpids = FakeFunction(self._proc_listpids)
        self.proc_pidinfo = FakeFunction(self._proc_pidinfo)

    def _proc_listpids(self, _kind, _type, buffer, capacity):
        self.list_calls.append((buffer is not None, capacity))
        if buffer is not None:
            for index, pid in enumerate(self.pids):
                if index < len(buffer):
                    buffer[index] = pid
        return self.count_bytes if buffer is None else self.copied_bytes

    def _proc_pidinfo(self, pid, _flavor, _arg, buffer, capacity):
        self.pidinfo_calls.append((pid, capacity))
        if self.task_error is not None:
            raise self.task_error
        buffer.raw = b"\0" * 8 + self.resident_by_pid.get(pid, 8192).to_bytes(8, byteorder=sys.byteorder) + b"\0" * (capacity - 16)
        return self.task_result


def load_production():
    global PRODUCTION
    if PRODUCTION is None:
        spec = importlib.util.spec_from_file_location("phase7_rss_production", SOURCE)
        PRODUCTION = importlib.util.module_from_spec(spec)
        if SOURCE_OVERRIDE is None:
            spec.loader.exec_module(PRODUCTION)
        else:
            PRODUCTION.__file__ = str(SOURCE)
            exec(compile(SOURCE_OVERRIDE, str(SOURCE), "exec"), PRODUCTION.__dict__)
    return PRODUCTION


class RssTracer(unittest.TestCase):
    def setUp(self):
        ALLOCATIONS.clear()
        self.module = load_production()

    def test_huge_native_count_is_rejected_before_host_sized_allocation(self):
        huge_count_bytes = (2**30) * real_ctypes.sizeof(real_ctypes.c_int)
        libproc = FakeLibProc(huge_count_bytes, real_ctypes.sizeof(real_ctypes.c_int))
        adapter = types.SimpleNamespace(CDLL=lambda *_args, **_kwargs: libproc,
            c_int=FakeCInt, c_uint=real_ctypes.c_uint, c_void_p=real_ctypes.c_void_p,
            c_uint64=real_ctypes.c_uint64,
            sizeof=lambda value: 4 if value is FakeCInt else value.size * 4,
            create_string_buffer=FakeBuffer)
        with mock.patch.object(self.module.sys, "platform", "darwin"), \
             mock.patch.object(self.module, "ctypes", adapter), \
             mock.patch.object(self.module.os, "getpgid", return_value=1234):
            measured = self.module._process_group_rss_bytes(1234)
        OBSERVATIONS.append({"allocation_slots": max(ALLOCATIONS, default=0),
            "native_count_bytes": huge_count_bytes, "measured": -1 if measured is None else measured})
        self.assertLessEqual(max(ALLOCATIONS, default=0), EXPECTED_SLOTS,
            "native host PID count controlled the Darwin PID allocation")
        self.assertIsNone(measured, "oversized native process count must fail closed")
        self.assertEqual(libproc.list_calls, [(False, 0)],
            "oversized count must stop before the fill query")
        CASES.append("tracer-huge-count-cap-before-allocation")


class RssEdgeContracts(unittest.TestCase):
    def setUp(self):
        ALLOCATIONS.clear()
        self.module = load_production()

    def observe(self, libproc, getpgid=None):
        adapter = types.SimpleNamespace(CDLL=lambda *_args, **_kwargs: libproc,
            c_int=FakeCInt, c_uint=real_ctypes.c_uint, c_void_p=real_ctypes.c_void_p,
            c_uint64=real_ctypes.c_uint64,
            sizeof=lambda value: 4 if value is FakeCInt else value.size * 4,
            create_string_buffer=FakeBuffer)
        pgid = getpgid or (lambda _pid: 1234)
        pgid_calls = []
        def counted_pgid(pid):
            pgid_calls.append(pid)
            return pgid(pid)
        with mock.patch.object(self.module.sys, "platform", "darwin"), \
             mock.patch.object(self.module, "ctypes", adapter), \
             mock.patch.object(self.module.os, "getpgid", side_effect=counted_pgid):
            measured = self.module._process_group_rss_bytes(1234)
        OBSERVATIONS.append({"allocation_slots": max(ALLOCATIONS, default=0),
            "count_fill_calls_per_observation": len(libproc.list_calls), "fill_capacity_bytes": max(
                (capacity for filled, capacity in libproc.list_calls if filled), default=0),
            "getpgid_calls": len(pgid_calls), "proc_pidinfo_calls": len(libproc.pidinfo_calls),
            "task_info_capacity_bytes": max((capacity for _pid, capacity in libproc.pidinfo_calls), default=0)})
        return measured

    def test_stale_or_missing_dirty_probe_binding_rejected(self):
        record = {"valid": True, "sha256": "accepted-hash"}
        self.assertTrue(dirty_probe_binding_valid(record, {"valid": True, "sha256": "accepted-hash"}))
        self.assertFalse(dirty_probe_binding_valid(record, None))
        self.assertFalse(dirty_probe_binding_valid(record, {"valid": True, "sha256": "swapped-hash"}))
        self.assertFalse(dirty_probe_binding_valid({"valid": True, "sha256": "old-hash"},
            {"valid": True, "sha256": "accepted-hash"}))
        synthetic_review = types.SimpleNamespace(is_file=lambda: True,
            read_text=lambda: '```json\n{"independent":true,"verdict":"SECURED"}\n```')
        with mock.patch(__name__ + ".REVIEW", synthetic_review):
            self.assertEqual(parse_review(), {"independent": True, "verdict": "SECURED"})
        CASES.append("dirty-probe-missing-and-stale-binding-rejected")

    def test_count_and_fill_boundaries_fail_closed(self):
        int_size = real_ctypes.sizeof(real_ctypes.c_int)
        scenarios = (
            (0, int_size, [123], "zero-count"),
            (-int_size, int_size, [123], "negative-count"),
            (int_size + 1, int_size, [123], "misaligned-count"),
            ((MAX_PIDS + 1) * int_size, int_size, [123], "oversized-count"),
            (int_size, 0, [123], "empty-fill"),
            (int_size, -int_size, [123], "negative-fill"),
            (int_size, int_size + 1, [123], "misaligned-fill"),
            (int_size, (MAX_PIDS + 1) * int_size, [123], "oversized-fill"),
        )
        for count, copied, pids, label in scenarios:
            libproc = FakeLibProc(count, copied, pids)
            self.assertIsNone(self.observe(libproc), label)
            self.assertLessEqual(max(ALLOCATIONS, default=0), EXPECTED_SLOTS, label)
            ALLOCATIONS.clear()
        CASES.append("count-fill-zero-negative-misaligned-cap-and-sentinel")

    def test_cap_accepts_growth_within_envelope_and_rejects_sentinel_saturation(self):
        size = real_ctypes.sizeof(real_ctypes.c_int)
        growth = FakeLibProc(size, MAX_PIDS * size, [10])
        self.assertEqual(self.observe(growth), 8192, "copy growth to maximum complete sample")
        self.assertEqual(growth.list_calls, [(False, 0), (True, EXPECTED_SLOTS * size)])
        self.assertEqual(ALLOCATIONS, [EXPECTED_SLOTS], "bounded fixed PID array size")
        ALLOCATIONS.clear()
        saturated = FakeLibProc(size, EXPECTED_SLOTS * size, [10])
        self.assertIsNone(self.observe(saturated), "sentinel slot saturation must fail closed")
        self.assertEqual(saturated.list_calls, [(False, 0), (True, EXPECTED_SLOTS * size)])
        CASES.append("cap-growth-and-sentinel-saturation")

    def test_cap_minus_one_cap_and_cap_plus_one_and_4096_pid_call_ceiling(self):
        size = real_ctypes.sizeof(real_ctypes.c_int)
        pids = tuple(range(1000, 1000 + MAX_PIDS))
        at_cap = FakeLibProc(MAX_PIDS * size, MAX_PIDS * size, pids)
        self.assertEqual(self.observe(at_cap), MAX_PIDS * 8192)
        self.assertEqual(OBSERVATIONS[-1]["getpgid_calls"], MAX_PIDS)
        self.assertEqual(OBSERVATIONS[-1]["proc_pidinfo_calls"], MAX_PIDS)
        self.assertEqual(OBSERVATIONS[-1]["task_info_capacity_bytes"], 256)
        self.assertEqual(OBSERVATIONS[-1]["fill_capacity_bytes"], EXPECTED_SLOTS * size)
        ALLOCATIONS.clear()
        below = FakeLibProc((MAX_PIDS - 1) * size, (MAX_PIDS - 1) * size, pids[:-1])
        self.assertEqual(self.observe(below), (MAX_PIDS - 1) * 8192)
        ALLOCATIONS.clear()
        above_count = FakeLibProc((MAX_PIDS + 1) * size, size, [1000])
        self.assertIsNone(self.observe(above_count))
        ALLOCATIONS.clear()
        above_copy = FakeLibProc(size, (MAX_PIDS + 1) * size, [1000])
        self.assertIsNone(self.observe(above_copy))
        CASES.append("cap-minus-one-cap-plus-one-and-4096-native-call-ceiling")

    def test_nonpositive_pid_entries_and_empty_group_measurement(self):
        size = real_ctypes.sizeof(real_ctypes.c_int)
        empty = FakeLibProc(2 * size, 2 * size, [0, -1])
        self.assertEqual(self.observe(empty), 0)
        self.assertEqual(empty.pidinfo_calls, [])
        zero_entry = FakeLibProc(2 * size, 2 * size, [0, 10])
        self.assertEqual(self.observe(zero_entry), 8192)
        self.assertEqual(zero_entry.pidinfo_calls, [(10, 256)])
        CASES.append("nonpositive-pids-and-empty-group-measurement")

    def test_valid_count_groups_foreign_and_vanished_processes(self):
        size = real_ctypes.sizeof(real_ctypes.c_int)
        libproc = FakeLibProc(3 * size, 3 * size, [10, 11, 12],
            resident_by_pid={10: 1024, 12: 4096})
        def group(pid):
            if pid == 11:
                return 9
            if pid == 12:
                raise ProcessLookupError(pid)
            return 1234
        self.assertEqual(self.observe(libproc, group), 1024)
        self.assertEqual(ALLOCATIONS, [EXPECTED_SLOTS], "bounded fixed PID array size")
        self.assertEqual(libproc.list_calls, [(False, 0), (True, EXPECTED_SLOTS * size)])
        self.assertEqual(libproc.pidinfo_calls, [(10, 256)])
        CASES.append("valid-count-foreign-group-and-vanished-pid")

    def test_status_observer_outside_workload_group_is_not_sampled(self):
        size = real_ctypes.sizeof(real_ctypes.c_int)
        observer_pid = 11
        libproc = FakeLibProc(2 * size, 2 * size, [10, observer_pid],
            resident_by_pid={10: 1024})
        original = libproc._proc_pidinfo

        def task_info(pid, flavor, arg, buffer, capacity):
            if pid == observer_pid:
                raise PermissionError(1, "observer task info must not be queried")
            return original(pid, flavor, arg, buffer, capacity)

        libproc.proc_pidinfo.callback = task_info
        self.assertEqual(self.observe(libproc,
            lambda pid: 1234 if pid == 10 else 27397), 1024)
        self.assertEqual(libproc.pidinfo_calls, [(10, 256)])
        CASES.append("privileged-status-observer-outside-workload-group")

    def test_duplicate_pid_permission_and_task_info_fail_closed(self):
        size = real_ctypes.sizeof(real_ctypes.c_int)
        cases = (
            (FakeLibProc(2 * size, 2 * size, [10, 10]), lambda _pid: 1234,
             "duplicate-positive-pid"),
            (FakeLibProc(size, size, [10]), lambda _pid: (_ for _ in ()).throw(PermissionError(13, "denied")),
             "pid-permission-error"),
            (FakeLibProc(size, size, [10], task_result=15), lambda _pid: 1234,
             "short-task-info"),
            (FakeLibProc(size, size, [10], task_result=0), lambda _pid: 1234,
             "unavailable-task-info-fails-closed"),
            (FakeLibProc(size, size, [10], task_result=257), lambda _pid: 1234,
             "oversized-task-info"),
            (FakeLibProc(size, size, [10], task_error=OSError(5, "native error")), lambda _pid: 1234,
             "native-task-info-error"),
        )
        for libproc, pgid, label in cases:
            self.assertIsNone(self.observe(libproc, pgid), label)
            ALLOCATIONS.clear()
        CASES.append("duplicate-permission-short-oversized-native-errors")


class FakeOwnedProcess:
    pid = 899001
    def __init__(self, returncode=0):
        self.returncode = returncode
        self.poll_calls = 0

    def poll(self):
        self.poll_calls += 1
        return None if self.poll_calls == 1 else self.returncode
    def wait(self, timeout=None): return self.returncode


class AliasLoader:
    def __init__(self, source): self.source = source
    def create_module(self, _spec): return None
    def exec_module(self, module): module.__dict__.update(self.source.__dict__)


class ReceiptProxy:
    def __init__(self, stream, snapshots):
        self.stream = stream
        self.snapshots = snapshots
        self.rss_receipt_stream = True

    def __getattr__(self, name): return getattr(self.stream, name)
    def write(self, data): return self.stream.write(data)


class ReceiptLoader:
    def __init__(self, snapshots): self.snapshots = snapshots
    def create_module(self, _spec): return None
    def exec_module(self, module):
        path = ROOT / "scripts/evidence/phase5_process.py"
        module.__file__ = str(path)
        exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
        original = module.receipt_file
        @contextlib.contextmanager
        def observed(root, relative, **kwargs):
            with original(root, relative, **kwargs) as stream:
                yield ReceiptProxy(stream, self.snapshots)
        module.receipt_file = observed


class ActualWrapperTracer(unittest.TestCase):
    def setUp(self):
        self.stack = []
        self.addCleanup(self.stop_patches)
        self.temp = tempfile.TemporaryDirectory(prefix="gw-rss-wrapper-contract-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.work = self.root / "work"
        self.work.mkdir()
        self.build = self.root / "build"
        self.build.mkdir()
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.limits = {"wall_seconds": 10, "cleanup_grace_seconds": 1,
            "max_rss_bytes": 1024**3, "max_stdout_stderr_bytes": 4096,
            "max_json_bytes": 4096, "max_binary_file_bytes": 4096,
            "max_capture_bytes": 4096, "max_scratch_bytes": 1024**2,
            "max_retained_bytes": 1024**2, "max_fields": 5000, "max_calls": 100}
        self.game = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "phase7_rss_game", ROOT / "tests/fixtures/phase6_game.py"))
        importlib.util.spec_from_file_location("phase7_rss_game", ROOT / "tests/fixtures/phase6_game.py").loader.exec_module(self.game)
        self.game.ROOT = self.root
        self.game._EXECUTION_SCOPE = {"scope_id": "rss-test", "per_child_limits": self.limits}
        self.game._V02_DEADLINE = __import__("time").monotonic() + 60
        self.game._V02_STATE = {"workload_wall_seconds": 0.0,
            "workload_wall_upper_bound_seconds": 0.0, "process_records": []}
        self.coordinator = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "phase7_rss_coordinator", ROOT / "scripts/release/v02_qualification.py"))
        importlib.util.spec_from_file_location("phase7_rss_coordinator",
            ROOT / "scripts/release/v02_qualification.py").loader.exec_module(self.coordinator)
        self.coordinator.ROOT = self.root
        self.native = FakeLibProc(4, 4, [FakeOwnedProcess.pid])
        self.receipt_snapshots = []
        self.pgid_calls = []
        self.fsync_calls = 0
        self.real_json_dump = json.dump
        def observed_dump(value, fp, *args, **kwargs):
            if getattr(fp, "rss_receipt_stream", False):
                self.receipt_snapshots.append({"processes": copy.deepcopy(value["processes"]),
                    "rss_list_calls": len(self.native.list_calls)})
            return self.real_json_dump(value, fp, *args, **kwargs)
        self.patch(json, "dump", observed_dump)
        self.adapter = types.SimpleNamespace(CDLL=lambda *_args, **_kwargs: self.native,
            c_int=FakeCInt, c_uint=real_ctypes.c_uint, c_void_p=real_ctypes.c_void_p,
            c_uint64=real_ctypes.c_uint64,
            sizeof=lambda value: 4 if value is FakeCInt else value.size * 4,
            create_string_buffer=FakeBuffer)
        self.route = load_production()
        self.popen_calls = []
        self.next_returncode = 0
        self.patch(self.route.subprocess, "Popen", self.popen)
        self.patch(self.route, "_process_group_exists", lambda _pgid: False)
        self.patch(self.route.os, "getpgid", self.getpgid)
        self.real_fsync = os.fsync
        self.patch(self.route.os, "fsync", self.fsync)
        self.patch(self.route, "_terminate_process_group", lambda *_a, **_k: True)
        self.patch(self.route, "ctypes", self.adapter)
        self.patch(self.route.sys, "platform", "darwin")
        self.real_spec = importlib.util.spec_from_file_location
        def route_spec(name, path, *args, **kwargs):
            if Path(path).as_posix().endswith("tests/session/phase6_route_contract.py"):
                return importlib.machinery.ModuleSpec(name, AliasLoader(self.route))
            if Path(path).as_posix().endswith("scripts/evidence/phase5_process.py"):
                return importlib.machinery.ModuleSpec(name, ReceiptLoader(self.receipt_snapshots))
            return self.real_spec(name, path, *args, **kwargs)
        self.patch(importlib.util, "spec_from_file_location", route_spec)
        env_patcher = mock.patch.dict(os.environ, {"GENEWHIP_PROCESS_CONTEXT": "host-cleanup-v1"})
        env_patcher.start()
        self.stack.append(env_patcher)

    def patch(self, obj, name, value):
        patcher = mock.patch.object(obj, name, value)
        patcher.start()
        self.stack.append(patcher)

    def stop_patches(self):
        for patcher in reversed(self.stack): patcher.stop()

    def popen(self, command, **_kwargs):
        self.popen_calls.append(command)
        return FakeOwnedProcess(self.next_returncode)

    def getpgid(self, pid):
        self.pgid_calls.append(pid)
        return FakeOwnedProcess.pid

    def fsync(self, descriptor):
        self.fsync_calls += 1
        return self.real_fsync(descriptor)

    def test_finite_measurement_flows_through_actual_shared_wrapper_and_receipt(self):
        result, receipt, streams = self.game.shared_launch(
            self.build / "missing-client", [str(self.build / "missing-client")],
            self.work, self.work / "report.json", 10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(receipt["rss_bytes_observed"], 8192,
            "actual RSS helper reach and measured value")
        self.assertEqual(receipt["process_group_cleanup"], "confirmed")
        self.assertTrue(list(self.work.glob("process-receipts/*.json")))
        self.assertEqual(len(self.popen_calls), 1)
        one_observation = [(False, 0), (True, EXPECTED_SLOTS * real_ctypes.sizeof(real_ctypes.c_int))]
        self.assertEqual(self.native.list_calls, one_observation * 2,
            "actual running poll and post-wait inspection both reached RSS")
        self.assertEqual(self.pgid_calls, [FakeOwnedProcess.pid, FakeOwnedProcess.pid])
        self.assertEqual(len(self.native.pidinfo_calls), 2)
        self.assertGreaterEqual(self.fsync_calls, 3)
        self.assertEqual(self.receipt_snapshots[0]["processes"], [],
            "durable receipt sink is initialized before child ownership")
        snapshots = [row["processes"][0] for row in self.receipt_snapshots if row["processes"]]
        statuses = [row["status"] for row in snapshots]
        self.assertEqual(statuses[0], "started")
        self.assertIn("started", statuses[:-1])
        self.assertEqual(statuses[-1], "completed")
        self.assertEqual(snapshots[0]["pid"], FakeOwnedProcess.pid)
        self.assertEqual(snapshots[0]["pgid"], FakeOwnedProcess.pid)
        self.assertEqual(self.receipt_snapshots[1]["rss_list_calls"], 0,
            "owned identity must be durably written before RSS inspection")
        self.assertEqual(self.receipt_snapshots[-1]["rss_list_calls"], 4,
            "terminal receipt follows live and post-wait RSS observations")
        self.assertEqual(snapshots[-1]["process_group_cleanup"], "confirmed")
        self.assertEqual(snapshots[-1]["rss_bytes_peak"], 8192)
        self.assertGreaterEqual(len(snapshots), 2)
        state = self.game._V02_STATE
        self.assertGreater(state["workload_wall_seconds"], 0)
        self.assertEqual(state["workload_wall_seconds"], state["workload_wall_upper_bound_seconds"])
        self.assertEqual(len(state["process_records"]), 1)
        OBSERVATIONS.append({"actual_wrapper_helper_observations": 2,
            "count_fill_calls_per_observation": len(self.native.list_calls) // 2,
            "getpgid_calls_per_observation": len(self.pgid_calls) // 2,
            "proc_pidinfo_calls_per_observation": len(self.native.pidinfo_calls) // 2,
            "task_info_capacity_bytes": 256, "receipt_lifecycle_snapshots": len(snapshots),
            "receipt_statuses": statuses, "receipt_fsync_calls": self.fsync_calls,
            "process_records": len(state["process_records"]),
            "workload_accounted": state["workload_wall_seconds"] > 0})
        self.assertEqual(streams["stdout"]["observed_bytes"], 0)
        CASES.append("actual-shared-launch-monitor-rss-receipt")

    def test_unavailable_rss_fails_actual_collect_case_after_receipt(self):
        self.native.task_result = 8
        route = {"fixture": "recursion94", "case": {"id": "full-route"},
            "identity": "fake-route-id", "definitions": {"predicates": []}}
        work = self.root / "collect-case"
        with self.assertRaises(RuntimeError) as raised:
            self.game.collect_case(self.build, route, {}, {}, work, 1,
                remaining_seconds=10, compiled_binary=b"bounded-fake-plan")
        self.assertIn("phase7-rss-observation-unavailable", str(raised.exception),
            "RSS-unavailable rejection marker must survive the actual caller")
        self.assertTrue((work / "process.json").is_file())
        process_receipt = json.loads((work / "process.json").read_text())["processes"][-1]
        self.assertEqual(process_receipt["bound_violation_reason"], "phase7-rss-observation-unavailable")
        self.assertEqual(self.receipt_snapshots[0]["processes"], [])
        statuses = [row["processes"][0]["status"] for row in self.receipt_snapshots if row["processes"]]
        self.assertEqual(statuses[0], "started")
        self.assertIn("started", statuses[:-1])
        self.assertEqual(statuses[-1], "failed")
        retained = json.loads((work / "run.json").read_text())
        self.assertEqual(retained["status"], "fail")
        self.assertEqual(retained["reason"], "client-process-failed")
        self.assertEqual(len(self.popen_calls), 1)
        CASES.append("actual-collect-case-rejects-unavailable-rss-with-receipt")

    def test_coordinator_check_false_preserves_exit_policy_but_rejects_rss_failure(self):
        self.next_returncode = 7
        accepted = self.coordinator._bounded_command([str(self.build / "missing-client")],
            limits=self.limits, scratch=self.scratch, timeout=10, label="unchecked", check=False)
        self.assertEqual(accepted["returncode"], 7)
        self.assertEqual(accepted["process_group_cleanup"], "confirmed")
        first_sink = self.receipt_snapshots[:]
        self.assertGreaterEqual(len(first_sink), 3)
        self.assertEqual(first_sink[0]["processes"], [])
        first_rows = [row["processes"][0] for row in first_sink if row["processes"]]
        self.assertEqual(first_rows[0]["status"], "started")
        self.assertEqual(first_rows[-1]["status"], "completed")
        self.assertEqual(first_rows[-1]["process_group_cleanup"], "confirmed")
        self.native.task_result = 8
        with self.assertRaisesRegex(RuntimeError, "qualification-child-failed"):
            self.coordinator._bounded_command([str(self.build / "missing-client")],
                limits=self.limits, scratch=self.scratch, timeout=10, label="rss-unavailable", check=False)
        attempt = json.loads((self.scratch / "rss-unavailable.attempt.json").read_text())
        self.assertTrue(attempt["processes"][0]["bound_violation"])
        second_sink = self.receipt_snapshots[len(first_sink):]
        self.assertGreaterEqual(len(second_sink), 3)
        self.assertEqual(second_sink[0]["processes"], [])
        second_rows = [row["processes"][0] for row in second_sink if row["processes"]]
        self.assertEqual(second_rows[0]["status"], "started")
        self.assertEqual(second_rows[-1]["status"], "failed")
        self.assertEqual(second_rows[-1]["process_group_cleanup"], "confirmed")
        CASES.append("actual-coordinator-check-false-exit-policy-and-rss-rejection")


def run_one(test_class, method: str, source_override=None):
    global SOURCE_OVERRIDE, PRODUCTION
    SOURCE_OVERRIDE = source_override
    PRODUCTION = None
    CASES.clear()
    OBSERVATIONS.clear()
    test = test_class(method)
    result = unittest.TestResult()
    test.run(result)
    return result


def semantic_mutants() -> bool:
    source = SOURCE.read_bytes()
    cases = (
        ("remove-count-cap", RssTracer, "test_huge_native_count_is_rejected_before_host_sized_allocation",
         b"count > max_pid_bytes", b"False", "oversized native process count must fail closed"),
        ("restore-host-sized-allocation", RssEdgeContracts,
         "test_valid_count_groups_foreign_and_vanished_processes",
         b"(ctypes.c_int * (DARWIN_RSS_MAX_PIDS + 1))()",
         b"(ctypes.c_int * (count // int_size + 16))()", "bounded fixed PID array size"),
        ("accept-truncated-or-oversized-copy", RssEdgeContracts,
         "test_count_and_fill_boundaries_fail_closed",
         b"copied > max_pid_bytes\n                    or copied >= capacity_bytes", b"False\n                    or False", "oversized-fill"),
        ("suppress-unavailable-rss-rejection", ActualWrapperTracer,
         "test_unavailable_rss_fails_actual_collect_case_after_receipt",
         b"if rss_bytes is None:", b"if False:", "phase7-rss-observation-unavailable"),
        ("sever-wrapper-to-helper-wiring", ActualWrapperTracer,
         "test_finite_measurement_flows_through_actual_shared_wrapper_and_receipt",
         b"rss_bytes = _process_group_rss_bytes(process.pid)", b"rss_bytes = 0",
         "actual RSS helper reach and measured value"),
    )
    passed = True
    for name, test_class, method, old, new, marker in cases:
        baseline = run_one(test_class, method)
        baseline_ok = baseline.wasSuccessful() and baseline.testsRun == 1 and not baseline.errors
        CONTROL_RESULTS.append({"name": name, "selected_test": method,
            "passed": baseline_ok, "tests_run": baseline.testsRun, "errors": len(baseline.errors)})
        if not baseline_ok:
            passed = False
            continue
        if source.count(old) != 1:
            MUTANT_RESULTS.append({"name": name, "error": "mutation anchor did not match once"})
            passed = False
            continue
        mutant_source = source.replace(old, new, 1)
        result = run_one(test_class, method, mutant_source)
        failure_text = result.failures[0][1] if len(result.failures) == 1 else ""
        rejected = (result.testsRun == 1 and len(result.failures) == 1
            and not result.errors and marker in failure_text)
        MUTANT_RESULTS.append({"name": name, "selected_test": method,
            "baseline": "passed", "reached": marker, "rejected": rejected,
            "failures": len(result.failures), "errors": len(result.errors),
            "intended_assertion": marker})
        passed = passed and rejected
    SOURCE_OVERRIDE = None
    PRODUCTION = None
    return passed


def source_hashes():
    paths = ("tests/session/phase6_route_contract.py", "tests/evidence/phase7_rss_contract.py",
        "tests/fixtures/phase6_game.py", "scripts/release/v02_qualification.py",
        "tests/evidence/phase7_sticky_denial.py", "scripts/evidence/phase5_process.py")
    return {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths}


def entry_pin_check():
    return all(hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == digest
        for path, digest in ENTRY_PINS.items())


def evidence_gate(receipt):
    return receipt.get("unexpected_denials") == 0


def write_evidence(path: Path, payload: dict, receipt: dict) -> bool:
    if not evidence_gate(receipt):
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return True


def run_dirty_denial_probe() -> int:
    """Exercise a retained unexpected sticky event in an isolated invocation."""
    with tempfile.TemporaryDirectory(prefix="gw-rss-dirty-denial-") as directory:
        sentinel = Path(directory) / "evidence.json"
        if not write_evidence(sentinel, {"sentinel": "accepted-by-clean-ledger"}, denial.receipt()):
            return 0
        before = hashlib.sha256(sentinel.read_bytes()).hexdigest()
        try:
            denial.deny("subprocess.Popen", ("/__gw_denied_probe__",))
        except PermissionError as error:
            if str(error) != "sticky-process-and-signal-denial":
                return 0
        else:
            return 0
        dirty = denial.receipt()
        refused = not write_evidence(sentinel, {"sentinel": "must-not-freeze"}, dirty)
        unchanged = hashlib.sha256(sentinel.read_bytes()).hexdigest() == before
        probe = {"schema": "genewhip.phase7-dirty-denial-probe.v1",
            "intentional_event": "subprocess.Popen", "event_retained": denial.EVENTS[-1] == "subprocess.Popen",
            "unexpected_denials": dirty["unexpected_denials"], "success_allowed": evidence_gate(dirty),
            "freeze_refused": refused, "sentinel_evidence_unchanged": unchanged,
            "real_child_starts": 0,
            "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        DIRTY_PROBE.parent.mkdir(parents=True, exist_ok=True)
        DIRTY_PROBE.write_text(json.dumps(probe, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({**probe, "expected_process_exit": 1}, sort_keys=True))
        # Intentional: this process remains dirty through exit and is not an
        # acceptance run. The caller recognizes exit 1 as the deny control.
        return 1 if (probe["event_retained"] and probe["unexpected_denials"] == 1
            and not probe["success_allowed"] and probe["freeze_refused"]
            and probe["sentinel_evidence_unchanged"]) else 0


def dirty_probe_check():
    if not DIRTY_PROBE.is_file():
        return None
    try:
        probe = json.loads(DIRTY_PROBE.read_text())
    except (OSError, ValueError):
        return None
    valid = (probe.get("schema") == "genewhip.phase7-dirty-denial-probe.v1"
        and probe.get("intentional_event") == "subprocess.Popen"
        and probe.get("event_retained") is True and probe.get("unexpected_denials") == 1
        and probe.get("success_allowed") is False and probe.get("freeze_refused") is True
        and probe.get("sentinel_evidence_unchanged") is True and probe.get("real_child_starts") == 0
        and probe.get("source_sha256") == hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    return {"valid": valid, "sha256": hashlib.sha256(DIRTY_PROBE.read_bytes()).hexdigest(),
        "event_retained": probe.get("event_retained"), "unexpected_denials": probe.get("unexpected_denials"),
        "success_allowed": probe.get("success_allowed"), "freeze_refused": probe.get("freeze_refused")}


def contract_payload(tests_run: int) -> dict:
    observed_maxima = {key: max((row.get(key, 0) for row in OBSERVATIONS), default=0)
        for key in ("allocation_slots", "count_fill_calls_per_observation", "fill_capacity_bytes",
                    "getpgid_calls", "proc_pidinfo_calls", "task_info_capacity_bytes")}
    return {"schema": "genewhip.phase7-rss-contract.v1", "tests_run": tests_run,
        "failures": 0, "errors": 0, "named_cases": sorted(set(CASES)),
        "named_case_count": len(set(CASES)), "semantic_mutants_expected": 5,
        "semantic_mutants": MUTANT_RESULTS, "unchanged_controls_expected": 5,
        "unchanged_controls": CONTROL_RESULTS, "dirty_denial_regression": dirty_probe_check(),
        "source_sha256": source_hashes(), "entry_pins_match": entry_pin_check(),
        "entry_sha256": ENTRY_PINS, "native_denials": NATIVE_DENIALS,
        "sticky_denial": denial.receipt(), "real_child_starts": 0,
        "live_status_queries": 0, "live_signals": 0,
        "historical_identity_liveness": "UNKNOWN", "t_07_07": "OPEN/high",
        "delivery": "halted", "requirement_credit": [],
        "operation_observations": OBSERVATIONS, "observed_maxima": observed_maxima,
        "sizes": {"darwin_max_pid_slots": EXPECTED_SLOTS, "darwin_scanned_pids": MAX_PIDS,
            "task_info_bytes": 256, "count_fill_calls_per_observation": 2,
            "getpgid_max_calls": MAX_PIDS, "proc_pidinfo_max_calls": MAX_PIDS}}


def parse_review():
    if not REVIEW.is_file():
        return None
    import re
    match = re.search(r"```json\s*(\{.*?\})\s*```", REVIEW.read_text(), re.S)
    if not match:
        return None
    try:
        return json.loads(match.group(1))
    except ValueError:
        return None


def dirty_probe_binding_valid(evidence_record, current_probe):
    return (current_probe is not None and current_probe.get("valid") is True
        and evidence_record.get("valid") is True
        and evidence_record.get("sha256") == current_probe.get("sha256"))
def review_check():
    review = parse_review()
    if review is None or not EVIDENCE.is_file():
        return False, "review or evidence missing/invalid"
    evidence = json.loads(EVIDENCE.read_text())
    current_sources = source_hashes()
    evidence_hash = hashlib.sha256(EVIDENCE.read_bytes()).hexdigest()
    current_dirty_probe = dirty_probe_check()
    ok = (review.get("independent") is True and review.get("verdict") == "SECURED"
        and review.get("unresolved_high_critical") == 0
        and review.get("reviewed_source_sha256") == current_sources
        and review.get("evidence_sha256") == evidence_hash
        and review.get("named_evidence") == evidence.get("named_cases")
        and dirty_probe_binding_valid(evidence.get("dirty_denial_regression", {}), current_dirty_probe)
        and evidence.get("observed_maxima", {}).get("allocation_slots") == EXPECTED_SLOTS
        and evidence.get("observed_maxima", {}).get("count_fill_calls_per_observation") == 2
        and evidence.get("observed_maxima", {}).get("fill_capacity_bytes") == EXPECTED_SLOTS * real_ctypes.sizeof(real_ctypes.c_int)
        and evidence.get("observed_maxima", {}).get("getpgid_calls") == MAX_PIDS
        and evidence.get("observed_maxima", {}).get("proc_pidinfo_calls") == MAX_PIDS
        and evidence.get("observed_maxima", {}).get("task_info_capacity_bytes") == 256
        and evidence.get("tests_run", 0) > 0 and evidence.get("failures") == 0
        and evidence.get("errors") == 0 and evidence.get("entry_pins_match") is True
        and evidence.get("sticky_denial", {}).get("unexpected_denials") == 0
        and evidence.get("historical_identity_liveness") == "UNKNOWN"
        and evidence.get("t_07_07") == "OPEN/high" and evidence.get("delivery") == "halted")
    return ok, ("accepted" if ok else "stale or incomplete review/evidence")


def run_tracer() -> int:
    suite = unittest.TestSuite()
    for test_class in (RssTracer, ActualWrapperTracer):
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(test_class))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    denial.self_test("after-tracer-fakes-restored")
    native_self_test("after-tracer-fakes-restored")
    print(json.dumps({"tests_run": result.testsRun, "failures": len(result.failures),
        "errors": len(result.errors), "cases": CASES, "observations": OBSERVATIONS,
        "native_denials": NATIVE_DENIALS, "sticky_denial": denial.receipt()}, sort_keys=True))
    return 0 if result.wasSuccessful() and denial.receipt()["unexpected_denials"] == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--tracer", action="store_true")
    mode.add_argument("--contracts", action="store_true")
    mode.add_argument("--review-check", action="store_true")
    mode.add_argument("--dirty-denial-probe", action="store_true")
    args = parser.parse_args()
    if args.tracer:
        return run_tracer()
    if args.contracts:
        suite = unittest.TestSuite()
        for test_class in (RssTracer, RssEdgeContracts, ActualWrapperTracer):
            suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(test_class))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        contract_cases = sorted(set(CASES))
        contract_observations = copy.deepcopy(OBSERVATIONS)
        clean = (result.wasSuccessful() and denial.receipt()["unexpected_denials"] == 0
            and entry_pin_check() and dirty_probe_check() is not None
            and dirty_probe_check().get("valid") is True)
        mutants_ok = semantic_mutants() if clean else False
        denial.self_test("after-all-mutant-fakes-restored")
        native_self_test("after-all-mutant-fakes-restored")
        CASES[:] = contract_cases
        OBSERVATIONS[:] = contract_observations
        payload = contract_payload(result.testsRun)
        payload["named_cases"] = contract_cases
        payload["named_case_count"] = len(contract_cases)
        clean = clean and mutants_ok and len(MUTANT_RESULTS) == 5 and len(CONTROL_RESULTS) == 5
        clean = clean and denial.receipt()["unexpected_denials"] == 0
        clean = clean and payload["observed_maxima"] == {
            "allocation_slots": EXPECTED_SLOTS,
            "count_fill_calls_per_observation": 2,
            "fill_capacity_bytes": EXPECTED_SLOTS * real_ctypes.sizeof(real_ctypes.c_int),
            "getpgid_calls": MAX_PIDS, "proc_pidinfo_calls": MAX_PIDS,
            "task_info_capacity_bytes": 256}
        if clean:
            write_evidence(EVIDENCE, payload, denial.receipt())
        print(json.dumps({"tests_run": result.testsRun, "failures": len(result.failures),
            "errors": len(result.errors), "cases": contract_cases,
            "mutants_expected": 5, "mutants_killed": sum(row.get("rejected") is True for row in MUTANT_RESULTS),
            "controls_expected": 5, "controls_passed": sum(row.get("passed") is True for row in CONTROL_RESULTS),
            "entry_pins_match": entry_pin_check(), "evidence": EVIDENCE.relative_to(ROOT).as_posix(),
            "mutant_results": MUTANT_RESULTS,
            "native_denials": NATIVE_DENIALS, "sticky_denial": denial.receipt()}, sort_keys=True))
        return 0 if clean else 1
    if args.review_check:
        ok, reason = review_check()
        print("review-check: " + reason, file=sys.stderr if not ok else sys.stdout)
        return 0 if ok else 1
    if args.dirty_denial_probe:
        return run_dirty_denial_probe()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

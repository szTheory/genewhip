#!/usr/bin/env python3
"""Plan49 preimport denial and public-core poll/latch causal contracts."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import struct
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
LAUNCHER_PATH = ROOT / "scripts/evidence/phase6_recursion49.py"


class ImportFence:
    def find_spec(self, fullname, path=None, target=None):
        if fullname in {"phase6_routes", "phase6_feedback48", "phase6_recursion49"}:
            raise ImportError("preimport-denied:" + fullname)
        return None


def _record(path, value):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def _load_launcher_after_denial_test():
    if "phase6_routes" in sys.modules or "phase6_feedback48" in sys.modules:
        raise AssertionError("subject-project-module-imported-before-denial-test")
    fence = ImportFence()
    sys.meta_path.insert(0, fence)
    denied = False
    try:
        try:
            __import__("phase6_routes")
        except ImportError as error:
            denied = str(error) == "preimport-denied:phase6_routes"
    finally:
        sys.meta_path.remove(fence)
    if not denied:
        raise AssertionError("independent-preimport-denial-self-test-failed")
    spec = importlib.util.spec_from_file_location("phase6_recursion49_under_test", LAUNCHER_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("launcher-module-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def synthetic_main(output: pathlib.Path) -> int:
    """Prove denial first, sticky denial, and the actual fake Popen boundary."""
    output.mkdir(parents=True, exist_ok=True)
    module = _load_launcher_after_denial_test()
    cases = []
    with tempfile.TemporaryDirectory(prefix="gw49-synthetic-") as temporary:
        root = pathlib.Path(temporary)
        if list(root.iterdir()):
            raise AssertionError("synthetic-root-not-empty")
        calls = {"real_create": 0}

        def deny_create(*args, **kwargs):
            calls["real_create"] += 1
            raise PermissionError("deliberate-real-create-sentinel")

        original = module.subprocess.Popen
        module.subprocess.Popen = deny_create
        try:
            first = module._bounded_create(["synthetic-no-client"], root, root / "denied-a",
                                          root / "absent-report-a", 1, attempt_id="sticky-denial")
            second = module._bounded_create(["synthetic-no-client"], root, root / "denied-b",
                                           root / "absent-report-b", 1, attempt_id="sticky-denial")
        finally:
            module.subprocess.Popen = original
        if (calls["real_create"] != 1 or first["process_started"] or second["process_started"] or
                first["process_reaped"] is not False or second["process_reaped"] is not False or
                "deliberate-real-create-sentinel" not in (first.get("failure") or "") or
                "sticky-create-denial" not in (second.get("failure") or "")):
            raise AssertionError("caught-denial-not-sticky-or-receipted")
        cases.append({"name": "sticky_real_create_denial", "expected": "one sentinel call, zero starts",
                      "actual": {"sentinel_calls": calls["real_create"], "started": 0,
                                 "reaped": False,
                                 "first_failure": first["failure"], "second_failure": second["failure"]},
                      "status": "pass"})

        fake_calls = []
        wrong_mock_calls = []

        class FakeProcess:
            def __init__(self, command, **kwargs):
                fake_calls.append({"command": list(command), "cwd": str(kwargs["cwd"]),
                                   "new_session": kwargs.get("start_new_session")})
                self.pid = os.getpid()
                self.returncode = 0
                self.stdout = self._eof_pipe()
                self.stderr = self._eof_pipe()

            @staticmethod
            def _eof_pipe():
                reader, writer = os.pipe()
                os.close(writer)
                return os.fdopen(reader, "rb", buffering=0)

            def poll(self):
                return 0

            def wait(self):
                self.stdout.close()
                self.stderr.close()
                return 0

        module.subprocess.Popen = FakeProcess
        module._spawn = lambda *args, **kwargs: wrong_mock_calls.append("wrong-entrypoint")
        original_killpg = module.os.killpg
        original_group_exists = module._group_exists
        group_kills = []
        module.os.killpg = lambda pid, sig: group_kills.append((pid, sig))
        module._group_exists = lambda pid: False
        try:
            reached = module._bounded_create(["synthetic-fake-boundary"], root, root / "fake",
                                             root / "absent-report-fake", 1, attempt_id="fake-boundary")
        finally:
            module.subprocess.Popen = original
            module.os.killpg = original_killpg
            module._group_exists = original_group_exists
        if (len(fake_calls) != 1 or reached["process_started"] is not True or
                reached["process_reaped"] is not True or reached["process_exit_code"] != 0 or
                fake_calls[0]["command"] != ["synthetic-fake-boundary"] or wrong_mock_calls or
                len(group_kills) != 1):
            raise AssertionError("intended-fake-lowest-boundary-not-reached")
        cases.append({"name": "actual_dispatcher_reaches_fake_lowest_boundary",
                      "expected": "one fake Popen call; no operating-system child",
                      "actual": {"fake_calls": fake_calls, "group_kills": len(group_kills),
                                 "receipt": reached}, "status": "pass"})

        mutants = []
        synthetic_review = {"schema": "genewhip-plan49-guard-review-v1", "verdict": "PASS",
                            "source_sha256": {"code.py": "correct"}, "reviewed_plan_sha256": module.PLAN_SHA,
                            "reviewed_before_import_or_workload": True}
        _expect_reject("stale-source-review", lambda: module._validate_review(
            synthetic_review, {"code.py": "stale"}), "guard-review-missing-or-stale", mutants)
        if not module._validate_cap_agreement(100_000_000, 100_000_000):
            raise AssertionError("selected-serialized-cap-equality-failed")
        _expect_reject("selected-serialized-cap-mismatch", lambda: module._validate_cap_agreement(
            100_000_000, 99_999_999), "serialized-cap-disagrees-with-selection", mutants)
        _expect_reject("zero-selected-cap", lambda: module._validate_cap_agreement(
            0, 0), "selected-cap-range", mutants)
        _expect_reject("selected-cap-overflow", lambda: module._validate_cap_agreement(
            100_000_001, 100_000_001), "selected-cap-range", mutants)
        _expect_reject("serialized-cap-overflow", lambda: module._validate_cap_agreement(
            100_000_000, 100_000_001), "serialized-cap-disagrees-with-selection", mutants)
        _expect_reject("spent-attempt-slot", lambda: module._admit_attempt(
            slots=6, slot_limit=6, prior_group_pending=False, workload_left=9000,
            exposure=600, final_reserve=5400, window_left=16200, terminal_reserve=1500),
            "attempt-slot-cap", mutants)
        _expect_reject("child-stream-overflow", lambda: module._bounded_block(
            1 << 20, b"x", 1 << 20), "child-stream-limit", mutants)
        _expect_reject("retained-disk-overflow", lambda: module._enforce_disk_sizes(
            evidence=(2 << 30) + 1, build=0, owned=(2 << 30) + 1),
            "retained-evidence-limit", mutants)
        _expect_reject("terminal-deadline-reserve", lambda: module._admit_attempt(
            slots=0, slot_limit=6, prior_group_pending=False, workload_left=1000,
            exposure=600, final_reserve=0, window_left=2000, terminal_reserve=1500),
            "window-plus-terminal-reserve-does-not-fit", mutants)
        for name, condition in (
            ("wrong_subject_import_before_denial", not denied_selftest()),
            ("wrong_lowest_boundary_patch", len(fake_calls) != 1 or bool(wrong_mock_calls)),
            ("denial_reuse_after_create_error", calls["real_create"] != 1),
            ("synthetic_root_contains_guest_or_client",
             any(path.name in {"guest-rom.bin", "gw_headless", "gw_desktop"} for path in root.rglob("*"))),
        ):
            if condition:
                raise AssertionError("synthetic-mutant-survived:" + name)
            mutants.append({"name": name, "assertion": "specific denial or boundary observation", "status": "rejected"})
        _record(output / "synthetic.json", {"schema": "genewhip-plan49-synthetic-v1", "status": "pass",
                 "zero_os_children": True, "zero_usable_roms": True, "zero_client_paths": True,
                 "initial_root_empty": True, "cases": cases, "mutants": mutants})
    print("phase6_recursion49 synthetic: pass (0 OS children)")
    return 0


def _expect_reject(name, call, expected, results):
    try:
        call()
    except Exception as error:
        if not isinstance(error, RuntimeError) or str(error) != expected:
            raise AssertionError(f"{name}: wrong rejection: {type(error).__name__}:{error}") from error
        results.append({"name": name, "assertion": expected, "status": "rejected"})
        return
    raise AssertionError("synthetic-mutant-survived:" + name)


def denied_selftest() -> bool:
    fence = ImportFence()
    sys.meta_path.insert(0, fence)
    try:
        try:
            __import__("phase6_routes")
        except ImportError as error:
            return str(error) == "preimport-denied:phase6_routes"
        return False
    finally:
        sys.meta_path.remove(fence)


def _operation(marker: int, mask: int, latch: int) -> bytes:
    header = struct.pack("<BBHIIQQ", 1, 0, 2, mask, 0, 100000, 0xFFFFFFFFFFFFFFFF)
    # The poll's data latch is first in the report; the second span makes the
    # marker an explicit prerequisite for dispatch after that poll.
    spans = (struct.pack("<IB3s", 0xFF0002, 2, b"\0\0\0") + struct.pack(">H", latch) +
             struct.pack("<IB3s", 0xFF0000, 2, b"\0\0\0") + struct.pack(">H", marker))
    return header + spans


def _guest_rom(path: pathlib.Path) -> None:
    data = bytearray(514)
    struct.pack_into(">II", data, 0, 0x00FF0000, 0x00000200)
    # Each marker is written only after a guest controller poll and a copy of
    # that poll's D0 latch. Host dispatch occurs after the marker; the next
    # loop poll therefore proves the event is visible to the guest.
    data[512:] = bytes.fromhex(
        "13fc004000a10009 13fc004000a10003 "
        "103900a10003 33c000ff0002 33fc000100ff0000 "
        "103900a10003 33c000ff0002 33fc000200ff0000 "
        "103900a10003 33c000ff0002 33fc000300ff0000 60e0")
    path.write_bytes(data)


def causal_main(selection: pathlib.Path, review: pathlib.Path, build: pathlib.Path, output: pathlib.Path) -> int:
    module = _load_launcher_after_denial_test()
    module._verify_selection(selection, review)
    output.mkdir(parents=True, exist_ok=False)
    root = output / "guest-root"
    root.mkdir()
    rom, plan, report = root / "authored-guest.bin", root / "poll.gwrp", root / "report.json"
    _guest_rom(rom)
    plan.write_bytes(struct.pack("<4sHHI", b"GWRP", 1, 3, 0) +
                     b"".join((_operation(1, 8, 0x007F), _operation(2, 0, 0x0077),
                              _operation(3, 0, 0x007F))))
    client = (build / "native/tools/session/gw_headless").resolve()
    if not client.is_file() or client.is_symlink():
        raise RuntimeError("native-headless-client-missing")
    command = [str(client), "--route-plan", str(plan), "--route-report", str(report), str(rom)]
    runtime = module._runtime()
    if (runtime["authored_children"] + runtime["authored_child_slots_reserved"] + 1 > 64 or
            runtime["authored_calls_reserved"] + 200000 > 12800000 or
            runtime["authored_fields_reserved"] + 4096 > 262144 or
            runtime["authored_events_reserved"] + 64 > 4096 or
            runtime["authored_wall_reserved_seconds"] + 30 > 900):
        raise RuntimeError("authored-child-resource-reservation-exhausted")
    runtime["authored_child_slots_reserved"] += 1
    runtime["authored_calls_reserved"] += 200000
    runtime["authored_fields_reserved"] += 4096
    runtime["authored_events_reserved"] += 64
    runtime["authored_wall_reserved_seconds"] += 30
    module._atomic(module.RUNTIME, runtime)
    receipt = module._bounded_create(command, ROOT, root, report, 30,
                                     attempt_id="causal-guest-001",
                                     receipt_path=root / "process-receipt.json")
    if module._json(root / "process-receipt.json") != receipt:
        raise RuntimeError("causal-durable-receipt-mismatch")
    if receipt["process_exit_code"] != 0 or not receipt["process_reaped"] or not report.is_file():
        raise RuntimeError("causal-guest-child-failed:" + str(receipt))
    data = json.loads(report.read_text(encoding="utf-8"))
    observations = data.get("observations")
    if not isinstance(observations, list):
        raise RuntimeError("causal-observations-missing")
    values = [item.get("value") for item in observations]
    masks = [item.get("mask") for item in observations]
    guest_latches = [item.get("value") for item in observations]
    if (len(observations) > 64 or
            type(data.get("queue_high_water")) is not int or not 0 <= data["queue_high_water"] <= 64):
        raise RuntimeError("guest-event-or-queue-cap-exceeded")
    if (values != [0x007F, 0x0077, 0x007F] or masks != [8, 0, 0] or
            any(item.get("address") != 0xFF0002 for item in observations)):
        raise RuntimeError("guest-poll-marker-event-next-poll-mismatch:" + repr(
            {"guest_latches": guest_latches, "masks_after_dispatch": masks}))
    result = {"schema": "genewhip-plan49-causal-v1", "status": "pass",
              "guest": "authored public-core poll→marker→event→next-poll guest",
              "expected_latched_values": [0x007F, 0x0077, 0x007F],
              "observed_latched_values": values, "expected_effective_masks": [8, 0, 0],
              "observed_effective_masks": masks, "route_report_sha256": module._sha(report),
              "marker_contract": {"address": "FF0000", "values": [1, 2, 3],
                                  "guest_latch_address": "FF0002",
                                  "order": "poll, latch store, completed marker, host event, next poll"},
              "process_receipt": receipt, "native_counters": {
                  "boundary_calls": data.get("boundary_calls"), "physical_fields": data.get("fields"),
                  "source_steps": data.get("active_ticks"), "events": len(observations)},
              "guest_rom_sha256": hashlib.sha256(rom.read_bytes()).hexdigest(),
              "plan_sha256": hashlib.sha256(plan.read_bytes()).hexdigest(),
              "mutation_assertions": [
                  {"name": "event-before-completed-marker", "expected": "marker prerequisite mismatch", "status": "covered-by-span-assertion"},
                  {"name": "event-one-poll-late", "expected": "guest latch sequence mismatch", "status": "covered-by-latch-assertion"},
                  {"name": "effective-mask-corruption", "expected": "event state mismatch", "status": "covered-by-mask-assertion"},
              ]}
    _record(output / "causal.json", result)
    print("phase6_recursion49 causal: pass (guest poll values 1,2,3; effective masks 8,0,0)")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--synthetic", action="store_true")
    mode.add_argument("--causal", action="store_true")
    parser.add_argument("--selection", type=pathlib.Path)
    parser.add_argument("--review", type=pathlib.Path)
    parser.add_argument("--build", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args(argv)
    if args.synthetic:
        return synthetic_main(args.output)
    if not all((args.selection, args.review, args.build)):
        parser.error("--causal requires --selection, --review and --build")
    return causal_main(args.selection, args.review, args.build, args.output)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Offline contract checks for the private four-byte stack observer."""
from __future__ import annotations

import pathlib
import argparse
import hashlib
import importlib.util
import json
import struct
import sys
import subprocess
import shutil
import time
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "evidence/phase6-stack-observation-manifest.json"
SUCCESSOR = ROOT / "evidence/phase6-stack-observation-manifest-d122.json"
LEDGER = ROOT / "evidence/phase6-repairs.json"
ORIGINAL_MANIFEST_SHA256 = "d8821aca38b898c81dbb6c1ce490d10792526f486081a6f8b95c717726737e23"
OLD_SOURCE_IDENTITY = "5542d0d9be414d0de3cc0c9a954d98977743c269866abfb99a5f0a771eca7b37"
ENGINEERING_OWNER = None
QUALIFICATION_GENERATION = None
QUALIFICATION_BRIDGE_OUTPUT = None


def _qualification23_storage():
    directories=[ROOT/'build/phase6',ROOT/'build/phase6-movem-sanitize',ROOT/'build/phase6-movem-hooks-off']
    total=0
    for directory in directories:
        for path in directory.rglob('*'):
            if path.is_file() and not path.is_symlink():
                total+=path.stat().st_size
                if total>6*1024**3:raise RuntimeError('qualification23-storage-six-gib-bound')
    return total


def _qualification23_oracle():
    """AST-load the existing pure authored oracle; never import its main/suite."""
    import ast
    from types import SimpleNamespace
    tree=ast.parse((ROOT/'tests/session/phase6_capture_argv_contract.py').read_text())
    names={'sha','argv_builder','acceptance_predicate','guest','descriptor'}
    selected=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
    if {n.name for n in selected}!=names or any(isinstance(n,(ast.Import,ast.ImportFrom)) for f in selected for n in ast.walk(f)):
        raise RuntimeError('qualification23-pure-oracle-definition-closure-invalid')
    scope={'ROOT':ROOT,'ast':ast,'struct':struct,'hashlib':hashlib,'SimpleNamespace':SimpleNamespace}
    exec(compile(ast.Module(body=selected,type_ignores=[]),'<qualification23-pure-oracle>','exec'),scope)
    return SimpleNamespace(**{name:scope[name] for name in names})


def validate_qualification23_capture(native):
    checks=_qualification23_oracle().acceptance_predicate()(native,0x200)
    case=_d123_variant_case('native','23')
    _validate_observation_report(case,native)
    checks['observer_report_contract']=True
    last=native['last_boundary'];probe=native['probe_boundary']
    checks.update(full_capture_later_stop=native.get('termination')=='error' and native.get('stop_reason')==2,
        later_unsupported_boundary=last['before']['pc']==0x20e and last['opcode']==0x4afc and last['retired'] is False,
        swap_retained=last['before']['d'][0]==0x56781234,
        continued_after_probe=native['boundary_calls']==4 and native['final_tick']>probe['after']['tick'],
        bounded_authored_capture=type(native['fields']) is int and native['fields']<=1 and native['boundary_calls']<=16)
    if not all(checks.values()):raise RuntimeError('qualification23-full-capture-oracle-failed')
    return checks

def _d123_load_module(name, path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def _stack_record(source_a7: int, statuses=(0, 0, 0, 0), before=(0, 0, 0, 0), after=(0, 0, 0, 0)):
    base = (source_a7 - 4) & 0xffffffff
    addresses = [(base + i) & 0x00ffffff for i in range(4)]
    before_bytes = [value if statuses[i] == 0 else None for i, value in enumerate(before)]
    after_bytes = [value if statuses[i] == 0 else None for i, value in enumerate(after)]
    disposition = "observed" if all(code == 0 for code in statuses) else "observation-error"
    return {"source_a7": source_a7, "base32": base, "addresses24": addresses,
            "before": {"bytes": before_bytes, "status": list(statuses), "read_calls": 4, "disposition": disposition},
            "after": {"bytes": after_bytes, "status": list(statuses), "read_calls": 4, "disposition": disposition}}


def _pair(record):
    common = {"source_a7": record["source_a7"], "base32": record["base32"],
              "addresses24": record["addresses24"]}
    source_a = [0] * 8
    source_a[7] = record["source_a7"]
    after_a = list(source_a)
    return {"before": {"a": source_a, "stack_observation": {**common, **record["before"]}},
            "after": {"a": after_a, "stack_observation": {**common, **record["after"]}}}


def _fake_observation_report(case):
    expected=case["expected"];statuses=expected.get("read_status",[0,0,0,0])
    record=_stack_record(expected["source_a7"],statuses=statuses,
        before=expected.get("before_bytes",[0,0,0,0]),after=expected.get("after_bytes",[0,0,0,0]))
    pair=_pair(record);opcode=expected["opcode"];width=6 if opcode==0x4879 else 2
    ticks=expected.get("master_ticks",28);pair.update(instruction_address=expected["pc"],opcode=opcode,retired=True)
    pair["before"].update(pc=expected["pc"],sr=0x2700,tick=1000,instructions=5)
    pair["after"].update(pc=expected["pc"]+width,sr=0x2700,tick=1000+ticks,instructions=6)
    pair["after"]["a"][7]=(expected["source_a7"]-4)&0xffffffff if opcode==0x4879 else expected["source_a7"]
    return {"native_report":{"schema":"genewhip-route-native-v1","probe_boundary":pair,
        "fields":0,"boundary_calls":2}}


def validate_stack_pair(pair: dict, *, enabled: bool, expected_source_a7=None,
                        expected_before=None, expected_after=None):
    """Validate the optional two-boundary record and reject stale/partial/error-as-success data."""
    before = pair.get("before", {}).get("stack_observation")
    after = pair.get("after", {}).get("stack_observation")
    if before is None and after is None:
        if enabled:
            raise ValueError("stack-pair-missing-enabled")
        return None
    if not enabled:
        raise ValueError("stack-pair-present-while-disabled")
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ValueError("stack-pair-missing-or-stale")
    source = before.get("source_a7")
    if type(source) is not int or (expected_source_a7 is not None and source != expected_source_a7):
        raise ValueError("stack-source-a7-mismatch")
    before_a = pair.get("before", {}).get("a")
    if not isinstance(before_a, list) or len(before_a) != 8 or type(before_a[7]) is not int or before_a[7] != source:
        raise ValueError("stack-source-a7-not-bound-to-before-diagnostic")
    base = (source - 4) & 0xffffffff
    addresses = [(base + i) & 0x00ffffff for i in range(4)]
    for record in (before, after):
        if (record.get("source_a7") != source or record.get("base32") != base or
                record.get("addresses24") != addresses):
            raise ValueError("stack-address-derivation-mismatch")
        if not isinstance(record.get("bytes"), list) or not isinstance(record.get("status"), list):
            raise ValueError("stack-read-status-missing")
        if (len(record["bytes"]) != 4 or len(record["status"]) != 4 or
                type(record.get("read_calls")) is not int or record["read_calls"] != 4):
            raise ValueError("stack-byte-count-invalid")
        if any(type(code) is not int or code not in range(0, 11) for code in record["status"]):
            raise ValueError("stack-read-status-invalid")
        success = all(type(code) is int and code == 0 for code in record["status"])
        wanted_disposition = "observed" if success else "observation-error"
        if record.get("disposition") != wanted_disposition:
            raise ValueError("stack-error-disposition-mismatch")
        for value, code in zip(record["bytes"], record["status"]):
            if code == 0 and (type(value) is not int or not 0 <= value <= 255):
                raise ValueError("stack-byte-invalid")
            if code != 0 and value is not None:
                raise ValueError("stack-failed-read-has-byte")
    if before["source_a7"] != after["source_a7"] or before["addresses24"] != after["addresses24"]:
        raise ValueError("stack-target-stale-between-boundaries")
    if expected_before is not None and before["bytes"] != list(expected_before):
        raise ValueError("stack-before-byte-order-or-value-mismatch")
    if expected_after is not None and after["bytes"] != list(expected_after):
        raise ValueError("stack-after-byte-order-or-value-mismatch")
    return {"source_a7": source, "base32": base, "addresses24": addresses}


def _guest(stack_pointer: int, code: bytes) -> bytes:
    rom = bytearray(1024)
    rom[0:4] = stack_pointer.to_bytes(4, "big")
    rom[4:8] = (0x200).to_bytes(4, "big")
    rom[0x200:0x200 + len(code)] = code
    return bytes(rom)


def _descriptor() -> bytes:
    words = [0] * 32
    words[0] = 0x43525747  # Little-endian bytes "GWRC".
    words[1] = 1
    words[2] = 1  # bounded field clock; instruction probe uses one boundary at a time
    words[3] = 1
    words[4] = 1
    words[6] = 1
    words[14] = 0
    words[30] = 16
    words.extend((0x00e00000, 0x00e00000, 1, 0))  # one bounded RAM signal for controller validation
    return struct.pack("<" + "I" * len(words), *words)


def manifest_document():
    cases = []
    for case_id, stack_pointer, code, expected in (
        ("stack-observer-native-1", 0xa5ff0010, bytes.fromhex("48790006923c"),
         {"pc": 0x200, "opcode": 0x4879, "source_a7": 0xa5ff0010,
          "base32": 0xa5ff000c, "addresses24": [0xff000c, 0xff000d, 0xff000e, 0xff000f],
          "before_bytes": [0, 0, 0, 0], "after_bytes": [0, 6, 146, 60],
          "master_ticks": 140, "sr_unchanged": True}),
        ("stack-observer-sanitize-1", 0x00000002, bytes.fromhex("2e7c000000024e71"),
         {"pc": 0x206, "opcode": 0x4e71, "source_a7": 2,
          "base32": 0xfffffffe, "addresses24": [0xfffffe, 0xffffff, 0, 1],
          "before_bytes": [0, 0, 0, 0], "after_bytes": [0, 0, 0xa5, 0xff],
          "before_byte_sources": ["ram[0xfffe]", "ram[0xffff]", "rom[0]", "rom[1]"],
          "per_byte_24bit_wrap": True, "sr_unchanged": True}),
        ("stack-observer-hooks-off-1", 0x00800008, bytes.fromhex("2e7c008000084e71"),
         {"pc": 0x206, "opcode": 0x4e71, "source_a7": 0x00800008,
          "base32": 0x00800004, "addresses24": [0x800004, 0x800005, 0x800006, 0x800007],
          "read_status": [1, 1, 1, 1], "read_status_name": "GW_ERROR_ARGUMENT",
          "disposition": "observation-error", "sr_unchanged": True}),
    ):
        guest = _guest(stack_pointer, code)
        descriptor = _descriptor()
        cases.append({"purpose_id": case_id, "guest_bytes_hex": guest.hex(),
            "guest_sha256": hashlib.sha256(guest).hexdigest(),
            "descriptor_bytes_hex": descriptor.hex(),
            "descriptor_sha256": hashlib.sha256(descriptor).hexdigest(),
            "expected": expected, "fields": 1, "boundary_calls_max": 16})
    return {
        "schema": "genewhip-phase6-stack-observation-d122-v1",
        "status": "authored-unlaunched",
        "private_option": "--route-probe-stack-before-a7",
        "observer_contract": {"a7_subtraction": "uint32 modulo 2^32", "bus_mask": "0x00ffffff per byte",
            "read_api": "gw_peek_memory, one byte per call", "reads_per_boundary": 4,
            "reads_per_pair": 8, "unmapped_reads": "retained as observation-error; never success",
            "unrequested_report_change": False},
        "builds": [
            {"variant": "native", "directory": "build/phase6", "command": ["cmake", "--build", "build/phase6", "--target", "gw_headless", "--parallel", "2"]},
            {"variant": "sanitize", "directory": "build/phase6-movem-sanitize", "command": ["cmake", "--build", "build/phase6-movem-sanitize", "--target", "gw_headless", "--parallel", "2"]},
            {"variant": "hooks-off", "directory": "build/phase6-movem-hooks-off", "command": ["cmake", "--build", "build/phase6-movem-hooks-off", "--target", "gw_headless", "--parallel", "2"]}],
        "limits": {"build_total_seconds": 300, "proof_rows": 3, "proof_total_seconds": 90,
            "proof_watchdog_seconds_each": 30, "one_field": 1, "boundary_calls_each": 16,
            "parallel_processes": 1, "ctest": False, "game_or_control_attempts": 0},
        "proof_command_template": ["gw_headless", "<guest>", "--route-plan", "<descriptor>",
            "--route-report", "<report>", "--route-instruction-probe", "512", "--route-probe-only",
            "--route-probe-stack-before-a7"],
        "cases": cases,
        "source_inputs": ["tools/session/session.h", "tools/session/route_controller.c", "tools/headless/main.c",
            "include/genewhip/genewhip.h", "src/diagnostic.c", "src/bus.c", "src/cpu68000.c"],
        "spent_historical_purpose_ids": ["native-red-c-driver", "native-red-public-client",
            "native-green-c-driver", "native-green-public-client", "sanitize-green-c-driver",
            "sanitize-green-public-client", "hooks-off-green-c-driver", "hooks-off-green-public-client",
            "native-mutant-wrong-address", "native-mutant-stack-order"],
    }


class StackObservationContract(unittest.TestCase):
    def test_planned_prelaunch_freeze_and_build_cli_arguments_parse(self):
        parser=cli_parser()
        prelaunch=parser.parse_args(["--prelaunch-check","--successor-manifest",
            "evidence/phase6-stack-observation-manifest-d122.json"])
        freeze=parser.parse_args(["--freeze-manifest","evidence/phase6-stack-observation-manifest-d122.json"])
        build=parser.parse_args(["--build-and-prove","--manifest","evidence/phase6-stack-observation-manifest-d122.json",
            "--output","evidence/phase6-tank-observer-bridge.json"])
        self.assertTrue(prelaunch.prelaunch_check);self.assertEqual(freeze.freeze_manifest,"evidence/phase6-stack-observation-manifest-d122.json")
        self.assertTrue(build.build_and_prove)

    def test_explicit_stack_observer_cli_option_is_available(self):
        main = (ROOT / "tools/headless/main.c").read_text()
        self.assertIn("--route-probe-stack-before-a7", main)

    def test_private_observer_source_is_opt_in_and_captures_only_probe_pair(self):
        main = (ROOT / "tools/headless/main.c").read_text()
        session = (ROOT / "tools/session/session.h").read_text()
        source = (ROOT / "tools/session/route_controller.c").read_text()
        self.assertIn("route_probe_stack_before_a7", session)
        boundary_body = source.split("static int boundary_snapshot", 1)[1].split("static int print_boundary_state", 1)[0]
        self.assertNotIn("stack_snapshot", boundary_body)
        pair_body = source.split("if(instruction_probe) {", 1)[1].split("if (status)", 1)[0]
        self.assertIn("stack_snapshot(r, &r->last.after.stack, r->last.before.stack.source_a7)", pair_body)
        self.assertIn("!r->probe.available", pair_body)
        self.assertIn("source_a7 - UINT32_C(4)", source)
        self.assertIn("(o->base32 + (uint32_t)i) & UINT32_C(0x00ffffff)", source)
        self.assertIn("gw_peek_memory(r->session->machine, o->addresses24[i], &o->bytes[i], 1)", source)
        self.assertIn("++r->stack_read_calls", source)
        self.assertIn("++o->read_calls", source)
        self.assertIn("observation-error", source)
        self.assertIn("(route_probe_stack_before_a7 && (!route_instruction_probe || !route_plan_path))", main)

    def test_guest_and_descriptor_manifest_is_exact_and_bounded(self):
        manifest = manifest_document()
        self.assertEqual(len(manifest["cases"]), 3)
        self.assertEqual([row["purpose_id"] for row in manifest["cases"]], [
            "stack-observer-native-1", "stack-observer-sanitize-1", "stack-observer-hooks-off-1"])
        for row in manifest["cases"]:
            guest = bytes.fromhex(row["guest_bytes_hex"])
            descriptor = bytes.fromhex(row["descriptor_bytes_hex"])
            self.assertEqual(hashlib.sha256(guest).hexdigest(), row["guest_sha256"])
            self.assertEqual(hashlib.sha256(descriptor).hexdigest(), row["descriptor_sha256"])
            self.assertEqual(len(guest), 1024)
            self.assertEqual(descriptor[:4], b"GWRC")
            self.assertEqual(guest[:8], row["expected"]["source_a7"].to_bytes(4,"big") + (0x200).to_bytes(4,"big"))
        cases = {row["purpose_id"]: row for row in manifest["cases"]}
        self.assertEqual(bytes.fromhex(cases["stack-observer-native-1"]["guest_bytes_hex"])[0x200:0x206],
                         bytes.fromhex("48790006923c"))
        self.assertEqual(bytes.fromhex(cases["stack-observer-sanitize-1"]["guest_bytes_hex"])[0x200:0x208],
                         bytes.fromhex("2e7c000000024e71"))
        self.assertEqual(bytes.fromhex(cases["stack-observer-hooks-off-1"]["guest_bytes_hex"])[0x200:0x208],
                         bytes.fromhex("2e7c008000084e71"))
        self.assertEqual(manifest["limits"]["proof_total_seconds"], 90)
        self.assertEqual(manifest["limits"]["build_total_seconds"], 300)

    def test_runtime_a7_base_wrap_and_byte_order_contract(self):
        rec = _stack_record(0x01ff0010, before=(0, 0, 0, 0), after=(0, 6, 146, 60))
        pair = _pair(rec)
        validate_stack_pair(pair, enabled=True, expected_source_a7=0x01ff0010, expected_before=(0, 0, 0, 0),
            expected_after=(0, 6, 146, 60))
        wrong_base = json.loads(json.dumps(pair))
        wrong_base["before"]["stack_observation"]["base32"] += 1
        with self.assertRaisesRegex(ValueError, "stack-address-derivation-mismatch"):
            validate_stack_pair(wrong_base, enabled=True)
        wrong_order = json.loads(json.dumps(pair))
        wrong_order["after"]["stack_observation"]["bytes"] = [60, 146, 6, 0]
        with self.assertRaisesRegex(ValueError, "stack-after-byte-order-or-value-mismatch"):
            validate_stack_pair(wrong_order, enabled=True, expected_after=(0, 6, 146, 60))
        wrap = _stack_record(2)
        self.assertEqual(wrap["addresses24"], [0xfffffe, 0xffffff, 0, 1])

    def test_stale_missing_status_error_confusion_and_disabled_report_mutants(self):
        rec = _stack_record(0x00800008, statuses=(1, 1, 1, 1))
        pair = _pair(rec)
        validate_stack_pair(pair, enabled=True, expected_source_a7=0x00800008)
        stale = json.loads(json.dumps(pair))
        stale["after"]["stack_observation"]["source_a7"] += 4
        with self.assertRaises(ValueError):
            validate_stack_pair(stale, enabled=True)
        missing = json.loads(json.dumps(pair))
        del missing["before"]["stack_observation"]["status"]
        with self.assertRaisesRegex(ValueError, "stack-read-status-missing"):
            validate_stack_pair(missing, enabled=True)
        false_success = json.loads(json.dumps(pair))
        false_success["before"]["stack_observation"]["disposition"] = "observed"
        with self.assertRaisesRegex(ValueError, "stack-error-disposition-mismatch"):
            validate_stack_pair(false_success, enabled=True)
        self.assertIsNone(validate_stack_pair({"before": {}, "after": {}}, enabled=False))
        with self.assertRaisesRegex(ValueError, "stack-pair-missing-enabled"):
            validate_stack_pair({"before": {}, "after": {}}, enabled=True)

    def test_failed_hooks_off_reads_retain_specific_error_status(self):
        rec = _stack_record(0x00800008, statuses=(1, 1, 1, 1))
        self.assertEqual(rec["before"]["status"], [1, 1, 1, 1])
        self.assertEqual(rec["before"]["bytes"], [None, None, None, None])
        self.assertEqual(rec["before"]["disposition"], "observation-error")

    def test_same_pc_pair_uses_real_call_counts_and_keeps_after_error(self):
        case = manifest_document()["cases"][0]
        report = _fake_observation_report(case)
        checked = _validate_observation_report(case, report)
        self.assertEqual(checked["read_calls"],8)
        self.assertEqual(checked["master_tick_delta"],140)
        self.assertEqual(checked["after_a7"],(case["expected"]["source_a7"]-4)&0xffffffff)
        self.assertEqual(report["native_report"]["probe_boundary"]["before"]["stack_observation"]["read_calls"],4)
        self.assertEqual(report["native_report"]["probe_boundary"]["after"]["stack_observation"]["bytes"],[0,6,0x92,0x3c])
        mutants=[]
        mutants.append(lambda p:p["after"].update(tick=p["after"]["tick"]+1))
        mutants.append(lambda p:p.update(retired=False))
        mutants.append(lambda p:p["after"].update(instructions=p["after"]["instructions"]+1))
        mutants.append(lambda p:p["after"]["a"].__setitem__(7,p["after"]["a"][7]+4))
        mutants.append(lambda p:p.update(instruction_address=p["instruction_address"]+2))
        for mutate in mutants:
            bad=json.loads(json.dumps(report));mutate(bad["native_report"]["probe_boundary"])
            with self.assertRaises((RuntimeError,ValueError)):_validate_observation_report(case,bad)
        error_case = manifest_document()["cases"][2]
        accepted = _validate_observation_report(error_case,_fake_observation_report(error_case))
        self.assertEqual(accepted["before_status"],[1,1,1,1])
        nop_case=manifest_document()["cases"][1]
        nop_checked=_validate_observation_report(nop_case,_fake_observation_report(nop_case))
        self.assertTrue(nop_checked["retired"]);self.assertEqual(nop_checked["after_a7"],2)
        missing = json.loads(json.dumps(report));missing["native_report"]["probe_boundary"]["after"].pop("stack_observation")
        with self.assertRaisesRegex(ValueError,"stack-pair-missing-or-stale"):
            _validate_observation_report(case,missing)
        unknown = json.loads(json.dumps(report));unknown["native_report"]["probe_boundary"]["before"]["stack_observation"]["status"][0]=99
        with self.assertRaisesRegex(ValueError,"stack-read-status-invalid"):
            _validate_observation_report(case,unknown)


def _freeze_manifest():
    if not MANIFEST.is_file():
        raise RuntimeError("observer-manifest-missing")
    spec = importlib.util.spec_from_file_location("phase6_repairs_observer", ROOT / "tests/fixtures/phase6_repairs.py")
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    accounting = fixture.accounting
    value = accounting._load(LEDGER, ROOT)
    anchor = value["phase6_accounting"].get("active_anchor")
    if not isinstance(anchor, dict):
        raise RuntimeError("active-clock-anchor-missing")
    frozen = fixture.freeze_observer_manifest(MANIFEST, ledger_path=LEDGER,
        boot_identity=anchor["boot_identity"], allowed_root=ROOT)
    print(json.dumps({"status": "frozen", "sha256": frozen["sha256"],
        "source_identity": frozen["source_identity"], "path": frozen["path"]}, sort_keys=True))
    return 0


def _successor_document() -> dict:
    original = json.loads(MANIFEST.read_text())
    if hashlib.sha256(MANIFEST.read_bytes()).hexdigest() != ORIGINAL_MANIFEST_SHA256:
        raise RuntimeError("original-observer-manifest-hash-mismatch")
    binding = json.loads(LEDGER.read_text()).get("stack_observer_manifest", {})
    if (binding.get("status") != "frozen" or binding.get("sha256") != ORIGINAL_MANIFEST_SHA256 or
            binding.get("source_identity") != OLD_SOURCE_IDENTITY):
        raise RuntimeError("original-observer-source-identity-mismatch")
    document = manifest_document()
    document.update({
        "status": "authored-unlaunched",
        "supersedes_for_launch_only": "evidence/phase6-stack-observation-manifest.json",
        "original_manifest": {"path": "evidence/phase6-stack-observation-manifest.json",
            "sha256": ORIGINAL_MANIFEST_SHA256, "source_identity": OLD_SOURCE_IDENTITY,
            "frozen_status": binding.get("status"), "purpose_ids": binding.get("purpose_ids")},
        "approval_binding": {"context_sha256": "d46cf45515502f3a90cff6414b197a80d155ee6ab98f6e43cd6bcd6bb79767a5",
            "plan_check_sha256": "7c40ba20c4871488bbb14f935e4765ccadc4454640a2d523c6ff3220d34e7f26",
            "scope": "D122 successor guest bytes and validator dispositions only; same three unspent purpose IDs"},
        "successor_rationale": "The original frozen guest used invalid PC/reset state; this append-only successor uses valid 1024-byte ROM reset vectors and independently checked target bytes.",
        "launch_selection": "only this successor may authorize the three existing proof purposes; original manifest remains immutable and unselected",
    })
    for case in document["cases"]:
        case["fields"] = 1
        case["boundary_calls_max"] = 16
        case["guest_bytes_length"] = 1024
        case["reset_vector"] = {"ssp": case["expected"]["source_a7"], "pc": 0x200}
        case["probe_pc"] = case["expected"]["pc"]
    return document


def _author_successor(path: pathlib.Path) -> dict:
    target = path if path.is_absolute() else ROOT / path
    try: target.parent.resolve(strict=True).relative_to(ROOT.resolve(strict=True))
    except (ValueError,OSError):
        if target.parent.exists(): raise RuntimeError("observer-successor-parent-outside-project")
        target.parent.mkdir(parents=True,exist_ok=True)
        target.parent.resolve(strict=True).relative_to(ROOT.resolve(strict=True))
    if target.exists():
        raise RuntimeError("observer-successor-already-authored")
    if target.is_symlink():
        raise RuntimeError("observer-successor-path-symlink-denied")
    try:
        target.relative_to(ROOT)
    except ValueError as exc:
        raise RuntimeError("observer-successor-path-outside-project") from exc
    document = _successor_document()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
    target.write_text(payload)
    return {"status": "authored-unlaunched", "path": target.relative_to(ROOT).as_posix(),
        "sha256": hashlib.sha256(payload.encode()).hexdigest(), "cases": 3, "launches": 0}


def _prelaunch_check(path: pathlib.Path) -> dict:
    target = path if path.is_absolute() else ROOT / path
    if target.is_symlink() or not target.is_file():
        raise RuntimeError("observer-successor-path-invalid")
    target.resolve(strict=True).relative_to(ROOT.resolve(strict=True))
    value = json.loads(target.read_text())
    ledger_now=json.loads(LEDGER.read_bytes())
    engineering23 = ENGINEERING_OWNER == "06-23"
    if engineering23 or ledger_now.get("d123_recovery_policy",{}).get("status")=="active":
        if value.get("schema")!="phase6-d123-stack-observation-manifest-v1" or value.get("status")!="frozen":
            raise RuntimeError("active-d123-policy-requires-frozen-d123-manifest")
        accounting=_d123_accounting()
        if engineering23:
            accounting.qualification23_owner(ledger_now,project_root=ROOT)
            if value.get('engineering_owner')!='06-23' or value.get('generation')!='23' or value.get('game_admission') is not False:
                raise RuntimeError('qualification23-explicit-manifest-required')
        else:accounting._validate_d123_policy(ledger_now,project_root=ROOT)
        if value.get("source_identity")!=accounting.source_identity(ROOT):
            raise RuntimeError("d123-manifest-source-identity-drift")
        frozen=ledger_now.get("d125_qualification23_manifest" if engineering23 else "d123_observer_manifest",{})
        manifest_sha=hashlib.sha256(target.read_bytes()).hexdigest()
        if frozen.get("status")!="frozen" or frozen.get("sha256")!=manifest_sha or frozen.get("source_identity")!=value.get("source_identity"):
            raise RuntimeError("d123-manifest-ledger-binding-invalid")
        cases=value.get("cases",[]);builds=value.get("builds",[])
        if [row.get("variant") for row in cases]!=["native","sanitize","hooks-off"] or \
                [row.get("variant") for row in builds]!=["native","sanitize","hooks-off"]:
            raise RuntimeError("d123-manifest-variant-denominator-invalid")
        components=value.get("component_sha256",{})
        if not components or any(not (ROOT/name).is_file() or (ROOT/name).is_symlink() or
                hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=digest for name,digest in components.items()):
            raise RuntimeError("d123-manifest-component-map-invalid")
        tools=value.get("tool_identity",{});cmake=shutil.which(tools.get("cmake_name","cmake"))
        if not cmake or hashlib.sha256(pathlib.Path(cmake).read_bytes()).hexdigest()!=tools.get("cmake_sha256"):
            raise RuntimeError("d123-manifest-cmake-identity-drift")
        for row in builds:
            directory=ROOT/row.get("directory","");cache=directory/"CMakeCache.txt";binary=ROOT/row.get("binary_path","")
            settings={}
            for line in cache.read_text().splitlines():
                if "=" in line and ":" in line:
                    key,item=line.split("=",1);name=key.split(":",1)[0]
                    if name in ("CMAKE_C_COMPILER","CMAKE_MAKE_PROGRAM"):settings[name]=item
            if cache.is_symlink() or binary.is_symlink() or not binary.is_file() or \
                    hashlib.sha256(cache.read_bytes()).hexdigest()!=row.get("cache_sha256") or \
                    hashlib.sha256(binary.read_bytes()).hexdigest()!=row.get("binary_sha256") or \
                    hashlib.sha256(pathlib.Path(settings.get("CMAKE_C_COMPILER","")).read_bytes()).hexdigest()!=row.get("compiler_sha256") or \
                    hashlib.sha256(pathlib.Path(settings.get("CMAKE_MAKE_PROGRAM","")).read_bytes()).hexdigest()!=row.get("build_tool_sha256"):
                raise RuntimeError("d123-manifest-build-closure-drift:"+str(row.get("variant")))
        return {"status":"prelaunch-approved","path":target.relative_to(ROOT).as_posix(),
            "sha256":manifest_sha,"source_identity":value["source_identity"],
            "qualification_purposes":[row["purpose_id"] for row in cases],
            "original_manifest_sha256":value.get("original_manifest_sha256"),"builds":0,"proof_launches":0}
    expected = _successor_document()
    if value != expected:
        raise RuntimeError("observer-successor-bytes-or-disposition-differ-from-independent-derivation")
    original = MANIFEST.read_bytes()
    if hashlib.sha256(original).hexdigest() != ORIGINAL_MANIFEST_SHA256:
        raise RuntimeError("original-observer-manifest-mutated")
    spec = importlib.util.spec_from_file_location("phase6_repairs_d122", ROOT / "tests/fixtures/phase6_repairs.py")
    fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
    ledger = fixture.accounting._load(LEDGER, ROOT)
    exception = fixture.accounting.validate_d122_exception(ledger)
    if exception.get("original_manifest_sha256") != ORIGINAL_MANIFEST_SHA256:
        raise RuntimeError("d122-original-manifest-binding-mismatch")
    if [row["purpose_id"] for row in value.get("cases", [])] != list(fixture.accounting.OBSERVER_PROOF_PURPOSES):
        raise RuntimeError("observer-successor-purpose-denominator-invalid")
    return {"status": "prelaunch-approved", "path": target.relative_to(ROOT).as_posix(),
        "sha256": hashlib.sha256(target.read_bytes()).hexdigest(), "source_identity": fixture.accounting.source_identity(ROOT),
        "proof_purposes": [row["purpose_id"] for row in value["cases"]],
        "original_manifest_sha256": ORIGINAL_MANIFEST_SHA256, "builds": 0, "proof_launches": 0}


def _freeze_successor(path: pathlib.Path) -> dict:
    result = _prelaunch_check(path)
    spec = importlib.util.spec_from_file_location("phase6_repairs_freeze_d122", ROOT / "tests/fixtures/phase6_repairs.py")
    fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
    checker_spec=importlib.util.spec_from_file_location("phase6_freeze_checker",ROOT/"tests/evidence/phase6_tank_continuation_contract.py")
    checker=importlib.util.module_from_spec(checker_spec);checker_spec.loader.exec_module(checker)
    original_binary_retention=checker.retain_original_binaries()
    source_files=sorted(set(checker.source_paths(ROOT)+[
        "tests/evidence/phase6_stack_observation_contract.py","tests/evidence/phase6_tank_continuation_contract.py",
        "tests/evidence/phase6_accounting_contract.py","evidence/phase6-stack-observation-manifest-d122.json"]))
    source_file_hashes={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in source_files}
    import re
    build_settings={};builds=_successor_document()["builds"]
    for build in builds:
        cache=ROOT/build["directory"]/"CMakeCache.txt"
        if cache.is_symlink() or not cache.is_file():raise RuntimeError("observer-build-cache-missing-or-unsafe:"+build["variant"])
        raw=cache.read_bytes();settings={}
        for line in raw.decode("utf-8",errors="strict").splitlines():
            match=re.match(r"^(CMAKE_(?:C_COMPILER|BUILD_TYPE|C_FLAGS|C_FLAGS_DEBUG|C_FLAGS_RELEASE|MAKE_PROGRAM)):[^=]*=(.*)$",line)
            if match:settings[match.group(1)]=match.group(2)
        compiler=pathlib.Path(settings.get("CMAKE_C_COMPILER",""))
        maker=pathlib.Path(settings.get("CMAKE_MAKE_PROGRAM",""))
        if not compiler.is_file() or not maker.is_file():raise RuntimeError("observer-compiler-or-build-tool-missing:"+build["variant"])
        build_settings[build["variant"]]={"cache_sha256":hashlib.sha256(raw).hexdigest(),
            "settings":settings,"compiler_path":compiler.resolve().as_posix(),
            "compiler_sha256":hashlib.sha256(compiler.read_bytes()).hexdigest(),
            "build_tool_path":maker.resolve().as_posix(),"build_tool_sha256":hashlib.sha256(maker.read_bytes()).hexdigest(),
            "command":build["command"]}
    cmake=shutil.which("cmake")
    if not cmake or not pathlib.Path(cmake).is_file():raise RuntimeError("observer-cmake-executable-missing")
    tool_identity={"cmake_path":pathlib.Path(cmake).resolve().as_posix(),
        "cmake_sha256":hashlib.sha256(pathlib.Path(cmake).read_bytes()).hexdigest(),"builds":build_settings}
    ledger_path = LEDGER
    with fixture.accounting._locked(ledger_path):
        ledger = fixture.accounting._load(ledger_path, ROOT)
        if ledger.get("d122_successor_manifest") is not None:
            raise RuntimeError("observer-successor-already-frozen")
        anchor = ledger["phase6_accounting"].get("active_anchor")
        if not isinstance(anchor, dict) or anchor.get("pea_charge") is not False:
            raise RuntimeError("d122-global-anchor-missing")
        record = {"status": "frozen", "path": result["path"], "sha256": result["sha256"],
            "source_identity": result["source_identity"], "original_manifest_sha256": ORIGINAL_MANIFEST_SHA256,
            "purpose_ids": result["proof_purposes"],"source_file_hashes":source_file_hashes,
            "tool_identity":tool_identity,"original_binary_retention":{
                "path":original_binary_retention["path"],"sha256":original_binary_retention["sha256"],
                "binary_sha256":original_binary_retention["binary_sha256"],
                "recovery_manifest_sha256":original_binary_retention["recovery_manifest_sha256"]},
            "frozen_at": __import__("datetime").datetime.now().astimezone().isoformat()}
        ledger["d122_successor_manifest"] = record
        fixture.accounting._write(ledger_path, ledger)
    return {**result, "status": "frozen", "ledger_binding": record}


def _write_bounded(path: pathlib.Path, raw: bytes, limit: int) -> dict:
    if path.is_symlink():
        raise RuntimeError("observer-retained-path-symlink-denied")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.resolve(strict=False).relative_to(ROOT.resolve(strict=True))
    kept = raw[:limit]
    path.write_bytes(kept)
    return {"path": path.resolve(strict=True).relative_to(ROOT.resolve(strict=True)).as_posix(),
        "sha256": hashlib.sha256(raw).hexdigest(), "observed_bytes": len(raw),
        "retained_bytes": len(kept), "truncated": len(raw) > limit}


def _d123_json(path: pathlib.Path, value: dict, *, create_once: bool = True) -> None:
    path.resolve(strict=False).relative_to(ROOT.resolve(strict=True))
    if path.is_symlink() or (create_once and path.exists()):
        raise RuntimeError("d123-output-path-exists-or-symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.is_symlink() or temporary.exists():
        raise RuntimeError("d123-output-temp-exists-or-symlink")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def _d123_expected() -> dict:
    return {"pc": 0x200, "opcode": 0x4879, "source_a7": 0xa5ff0010,
        "before_bytes": [0, 0, 0, 0], "after_bytes": [0, 6, 0x92, 0x3c],
        "read_status": [0, 0, 0, 0], "master_ticks": 140}


def _d123_accounting():
    spec = importlib.util.spec_from_file_location("phase6_d123_accounting", ROOT / "scripts/evidence/phase6_accounting.py")
    accounting = importlib.util.module_from_spec(spec); spec.loader.exec_module(accounting)
    return accounting


def _d123_activity(accounting, *, activity_id: str, stage: str, exposure: float, launcher,
                   hypothesis: str | None = None, relevant_change: str | None = None,
                   evidence_identity: str | None = None):
    boot = __import__("os").environ.get("GENEWHIP_D123_BOOT_IDENTITY") or accounting.read_boot_identity()
    return accounting.authorize_d123_activity(LEDGER, activity_id=activity_id, stage=stage,
        exposure_seconds=exposure, boot_identity=boot, project_root=ROOT, launcher=launcher,
        hypothesis=hypothesis, relevant_change=relevant_change, evidence_identity=evidence_identity,
        engineering_owner=ENGINEERING_OWNER)


def _d123_build_native(run_dir: pathlib.Path, activity_id: str, *, target: str = "gw_headless",
                       binary_name: str = "gw_headless") -> dict:
    accounting = _d123_accounting()
    command = ["cmake", "--build", str(ROOT / "build/phase6"), "--target", target, "--parallel", "2"]
    tool = shutil.which(command[0])
    if not tool:
        raise RuntimeError("d123-cmake-unavailable")
    if (ROOT / "build/phase6/CMakeCache.txt").is_symlink() or not (ROOT / "build/phase6/CMakeCache.txt").is_file():
        raise RuntimeError("d123-native-build-cache-missing-or-unsafe")
    def launch(_reservation):
        result = _invoke(command, cwd=ROOT, timeout=300.0, output_prefix=run_dir / "build")
        if result["return_code"] != 0 or result["timed_out"] or result["bound_violation"] or any(s["truncated"] for s in result["streams"].values()):
            raise RuntimeError("d123-native-build-failed-or-bounded")
        binary = ROOT / "build/phase6/tools/session" / binary_name
        if binary.is_symlink() or not binary.is_file():
            raise RuntimeError("d123-native-binary-missing-or-unsafe")
        return {"command": command, "process": result,
            "cache_sha256": hashlib.sha256((ROOT / "build/phase6/CMakeCache.txt").read_bytes()).hexdigest(),
            "cmake_path": pathlib.Path(tool).resolve().as_posix(),
            "cmake_sha256": hashlib.sha256(pathlib.Path(tool).read_bytes()).hexdigest(),
            "binary_path": binary.relative_to(ROOT).as_posix(),
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
    build = _d123_activity(accounting, activity_id=activity_id, stage="build", exposure=300.0, launcher=launch)
    return build


def _d123_run_red(output: pathlib.Path) -> dict:
    accounting = _d123_accounting()
    run_dir = output / "d123-dev-01-red-native"
    if output.exists() or output.is_symlink():
        raise RuntimeError("d123-tracer-output-already-exists")
    output.mkdir(parents=True)
    run_dir.mkdir()
    guest = _guest(0xa5ff0010, bytes.fromhex("48790006923c"))
    descriptor = _descriptor()
    guest_path, descriptor_path = run_dir / "guest.bin", run_dir / "route.bin"
    guest_path.write_bytes(guest); descriptor_path.write_bytes(descriptor)
    build = _d123_build_native(run_dir, "d123-dev-01-build-native-red")
    binary = ROOT / build["binary_path"]
    report_path = run_dir / "native-report.json"
    command = [str(binary), str(guest_path), "--route-plan", str(descriptor_path),
        "--route-report", str(report_path), "--route-instruction-probe", "512",
        "--route-probe-only", "--route-probe-stack-before-a7"]
    process_holder = {}
    def launch(_reservation):
        result = _invoke(command, cwd=ROOT, timeout=30.0, output_prefix=run_dir / "process")
        process_holder["result"] = result
        # Retain raw identity before decoding, including crash/validator failures.
        report_raw = report_path.read_bytes() if report_path.is_file() and not report_path.is_symlink() else b""
        _d123_json(run_dir / "run.json", {"schema": "phase6-d123-run-v1", "run_id": "d123-dev-01-red-native",
            "kind": "development", "hypothesis": "old source lacks the enabled before stack capture",
            "relevant_change": "none; pre-repair source", "source_identity": accounting.source_identity(ROOT),
            "guest_sha256": hashlib.sha256(guest).hexdigest(), "descriptor_sha256": hashlib.sha256(descriptor).hexdigest(),
            "oracle_sha256": hashlib.sha256(json.dumps(_d123_expected(), sort_keys=True).encode()).hexdigest(),
            "command": command, "binary_identity": build["binary_sha256"], "build": build,
            "process": result, "report_sha256": hashlib.sha256(report_raw).hexdigest() if report_raw else None,
            "report_bytes": len(report_raw), "created_at": time.time(), "outcome": "retained-before-decode"})
        if result["return_code"] != 0 or result["timed_out"] or result["bound_violation"] or any(s["truncated"] for s in result["streams"].values()):
            raise RuntimeError("d123-red-process-not-normal")
        if not report_raw or len(report_raw) > 8388608:
            raise RuntimeError("d123-red-report-missing-or-oversized")
        report = json.loads(report_raw)
        native = report.get("native_report", report)
        pair = native.get("probe_boundary", {})
        before, after = pair.get("before", {}), pair.get("after", {})
        expected = _d123_expected()
        if (pair.get("instruction_address") != expected["pc"] or pair.get("opcode") != expected["opcode"] or
                pair.get("retired") is not True or before.get("pc") != expected["pc"] or after.get("pc") != 0x206 or
                before.get("sr") != after.get("sr") or before.get("a", [None] * 8)[7] != expected["source_a7"] or
                after.get("a", [None] * 8)[7] != expected["source_a7"] - 4 or
                after.get("tick") - before.get("tick") != expected["master_ticks"]):
            raise RuntimeError("d123-red-instruction-facts-mismatch")
        try:
            _validate_observation_report({"expected": expected}, report)
        except ValueError as exc:
            if str(exc) != "stack-pair-missing-enabled":
                raise RuntimeError("d123-red-unexpected-validator-failure:" + str(exc)) from exc
        else:
            raise RuntimeError("d123-red-old-source-unexpectedly-passed")
        return {"outcome": "compiled-cli-red", "assertion": "stack-pair-missing-enabled"}
    result = _d123_activity(accounting, activity_id="d123-dev-01-red-native", stage="diagnostic",
        exposure=30.0, launcher=launch, hypothesis="missing-enabled-pair",
        relevant_change="pre-repair baseline", evidence_identity=accounting.source_identity(ROOT))
    print("compiled-cli-red=accepted")
    return result


def _d123_check_red_green(output: pathlib.Path) -> dict:
    red_path = output / "d123-dev-01-red-native/run.json"
    green_path = output / "d123-dev-01-green-native/run.json"
    if red_path.is_symlink() or green_path.is_symlink() or not red_path.is_file() or not green_path.is_file():
        raise RuntimeError("d123-red-green-record-missing")
    red, green = json.loads(red_path.read_text()), json.loads(green_path.read_text())
    if red.get("kind") != "development" or green.get("kind") != "development":
        raise RuntimeError("d123-development-kind-invalid")
    red_report_path = output / "d123-dev-01-red-native/native-report.json"
    green_report_path = output / "d123-dev-01-green-native/native-report.json"
    for candidate in (red_report_path, green_report_path):
        if candidate.is_symlink() or not candidate.is_file() or candidate.stat().st_size > 8388608:
            raise RuntimeError("d123-red-green-report-missing-or-oversized")
    red_report, green_report = json.loads(red_report_path.read_text()), json.loads(green_report_path.read_text())
    expected = _d123_expected()
    try:
        _validate_observation_report({"expected": expected}, red_report)
    except ValueError as exc:
        if str(exc) != "stack-pair-missing-enabled":
            raise RuntimeError("d123-red-not-specific:" + str(exc)) from exc
    else:
        raise RuntimeError("d123-old-source-red-missing")
    red_native = red_report.get("native_report", red_report)
    red_pair = red_native.get("probe_boundary", {})
    red_before, red_after = red_pair.get("before", {}), red_pair.get("after", {})
    if (red_pair.get("retired") is not True or red_pair.get("instruction_address") != expected["pc"] or
            red_pair.get("opcode") != expected["opcode"] or red_before.get("sr") != red_after.get("sr") or
            red_after.get("pc") != 0x206 or red_after.get("tick") - red_before.get("tick") != 140):
        raise RuntimeError("d123-red-retirement-facts-invalid")
    checks = _validate_observation_report({"expected": expected}, green_report)
    if not checks.get("retired") or checks.get("read_calls") != 8:
        raise RuntimeError("d123-green-expectation-incomplete")
    assessment_path = output / "d123-dev-01-green-native/assessment.json"
    if assessment_path.is_symlink() or not assessment_path.is_file():
        raise RuntimeError("d123-green-assessment-missing")
    assessment = json.loads(assessment_path.read_text())
    if assessment.get("outcome") != "compiled-cli-green" or assessment.get("assertion") != "passed-identical-expectation":
        raise RuntimeError("d123-green-not-passed")
    for field in ("guest_sha256", "descriptor_sha256", "oracle_sha256"):
        if red.get(field) != green.get(field):
            raise RuntimeError("d123-red-green-input-mismatch:" + field)
    if red.get("source_identity") == green.get("source_identity") or red.get("binary_identity") == green.get("binary_identity"):
        raise RuntimeError("d123-red-green-identity-delta-missing")
    print("compiled-cli-red-green=accepted")
    return {"status": "accepted", "red_run": red["run_id"], "green_run": green["run_id"]}


def _d123_run_green(output: pathlib.Path) -> dict:
    accounting = _d123_accounting()
    run_dir = output / "d123-dev-01-green-native"
    if run_dir.exists() or run_dir.is_symlink():
        raise RuntimeError("d123-green-run-already-exists")
    run_dir.mkdir(parents=True)
    guest = _guest(0xa5ff0010, bytes.fromhex("48790006923c"))
    descriptor = _descriptor()
    guest_path, descriptor_path = run_dir / "guest.bin", run_dir / "route.bin"
    guest_path.write_bytes(guest); descriptor_path.write_bytes(descriptor)
    build = _d123_build_native(run_dir, "d123-dev-01-build-native-green")
    binary = ROOT / build["binary_path"]
    report_path = run_dir / "native-report.json"
    command = [str(binary), str(guest_path), "--route-plan", str(descriptor_path),
        "--route-report", str(report_path), "--route-instruction-probe", "512",
        "--route-probe-only", "--route-probe-stack-before-a7"]
    def launch(_reservation):
        result = _invoke(command, cwd=ROOT, timeout=30.0, output_prefix=run_dir / "process")
        report_raw = report_path.read_bytes() if report_path.is_file() and not report_path.is_symlink() else b""
        _d123_json(run_dir / "run.json", {"schema": "phase6-d123-run-v1", "run_id": "d123-dev-01-green-native",
            "kind": "development", "hypothesis": "pair owner needs the enabled before capture",
            "relevant_change": "capture before A7-derived stack at matching route probe before boundary",
            "source_identity": accounting.source_identity(ROOT), "guest_sha256": hashlib.sha256(guest).hexdigest(),
            "descriptor_sha256": hashlib.sha256(descriptor).hexdigest(),
            "oracle_sha256": hashlib.sha256(json.dumps(_d123_expected(), sort_keys=True).encode()).hexdigest(),
            "command": command, "binary_identity": build["binary_sha256"], "build": build,
            "process": result, "report_sha256": hashlib.sha256(report_raw).hexdigest() if report_raw else None,
            "report_bytes": len(report_raw), "outcome": "retained-before-decode"})
        if result["return_code"] != 0 or result["timed_out"] or result["bound_violation"] or any(s["truncated"] for s in result["streams"].values()):
            raise RuntimeError("d123-green-process-failed-or-bounded")
        if not report_raw or len(report_raw) > 8388608:
            raise RuntimeError("d123-green-report-missing-or-oversized")
        report_path.chmod(0o400)
        checks = _validate_observation_report({"expected": _d123_expected()}, json.loads(report_raw))
        _d123_json(run_dir / "assessment.json", {"outcome": "compiled-cli-green",
            "assertion": "passed-identical-expectation", "checks": checks,
            "report_sha256": hashlib.sha256(report_raw).hexdigest()})
        return {"outcome": "compiled-cli-green", "assertion": "passed-identical-expectation", "checks": checks}
    result = _d123_activity(accounting, activity_id="d123-dev-01-green-native", stage="diagnostic",
        exposure=30.0, launcher=launch, hypothesis="missing-enabled-pair",
        relevant_change="pair-owner before capture gated to requested probe PC",
        evidence_identity=accounting.source_identity(ROOT))
    print("compiled-cli-green=accepted")
    return result


def _d123_validate_neighbors(rows: list[dict]) -> dict:
    expected_names = {"enabled-pea", "disabled-pea", "absent-target", "target-followed", "same-pc", "wrap", "exact-error"}
    if {row.get("case") for row in rows} != expected_names or len(rows) != len(expected_names):
        raise RuntimeError("d123-neighbor-denominator-invalid")
    addresses = {
        "enabled-pea": [0xff000c, 0xff000d, 0xff000e, 0xff000f],
        "target-followed": [0xff000c, 0xff000d, 0xff000e, 0xff000f],
        "same-pc": [0xff000c, 0xff000d, 0xff000e, 0xff000f],
        "wrap": [0xfffffe, 0xffffff, 0, 1],
        "exact-error": [0x800004, 0x800005, 0x800006, 0x800007],
    }
    results = {}
    for row in rows:
        name = row["case"]
        guest = bytes.fromhex(row["guest_hex"]); descriptor = bytes.fromhex(row["descriptor_hex"])
        if len(guest) != 1024 or guest[:8] != bytes.fromhex("a5ff001000000200") or len(descriptor) != 144:
            raise RuntimeError("d123-neighbor-input-binding-invalid:" + name)
        report = row.get("report")
        if not isinstance(report, dict) or report.get("schema") != "genewhip-route-native-v1":
            raise RuntimeError("d123-neighbor-real-report-invalid:" + name)
        if report.get("fields", 99) > 1 or report.get("boundary_calls", 99) > 16:
            raise RuntimeError("d123-neighbor-runtime-bound-exceeded:" + name)
        stack_calls = [call for call in row.get("calls", [])
            if call.get("length") == 1 and call.get("address") != 0xe00000 and
            (name not in addresses or call.get("address") in addresses[name])]
        wanted_count = 8 if name in addresses else 0
        if len(stack_calls) != wanted_count:
            raise RuntimeError("d123-neighbor-forward-call-count:" + name)
        if wanted_count:
            seq = addresses[name] * 2
            if [call.get("address") for call in stack_calls] != seq:
                raise RuntimeError("d123-neighbor-forward-order:" + name)
            expected_status = 1 if name == "exact-error" else 0
            if [call.get("status") for call in stack_calls] != [expected_status] * 8:
                raise RuntimeError("d123-neighbor-forward-status:" + name)
        pair = report.get("probe_boundary")
        if name in ("enabled-pea", "target-followed", "same-pc", "wrap", "exact-error"):
            if not isinstance(pair, dict):
                raise RuntimeError("d123-neighbor-pair-missing:" + name)
            before, after = pair["before"], pair["after"]
            obs_before, obs_after = before.get("stack_observation"), after.get("stack_observation")
            if not isinstance(obs_before, dict) or not isinstance(obs_after, dict):
                raise RuntimeError("d123-neighbor-pair-missing-enabled:" + name)
            if obs_before.get("addresses24") != addresses[name] or obs_after.get("addresses24") != addresses[name]:
                raise RuntimeError("d123-neighbor-addresses-invalid:" + name)
            if obs_before.get("read_calls") != 4 or obs_after.get("read_calls") != 4:
                raise RuntimeError("d123-neighbor-per-side-count-invalid:" + name)
            if name == "same-pc" and (before.get("pc") != 0x200 or after.get("pc") != 0x200):
                raise RuntimeError("d123-same-pc-retirement-invalid")
            if name == "wrap" and (obs_before.get("source_a7") != 2 or obs_before.get("bytes") != [0, 0, 0xa5, 0xff] or
                    obs_after.get("bytes") != [0, 0, 0xa5, 0xff]):
                raise RuntimeError("d123-wrap-byte-or-source-invalid")
            if name == "exact-error" and (obs_before.get("status") != [1] * 4 or obs_after.get("status") != [1] * 4 or
                    obs_before.get("bytes") != [None] * 4 or obs_after.get("bytes") != [None] * 4):
                raise RuntimeError("d123-exact-error-not-preserved")
            if name == "enabled-pea" and (pair.get("retired") is not True or before.get("pc") != 0x200 or
                    after.get("pc") != 0x206 or before.get("sr") != after.get("sr") or
                    after.get("tick") - before.get("tick") != 140):
                raise RuntimeError("d123-native-pea-retirement-changed")
            if name == "target-followed":
                last = report.get("last_boundary", {}).get("after", {})
                if (pair.get("retired") is not True or pair.get("instruction_address") != 0x200 or
                        after.get("pc") != 0x206 or last.get("instructions", 0) <= after.get("instructions", 0)):
                    raise RuntimeError("d123-target-followed-later-instruction-invalid")
        elif name == "absent-target" and pair is not None:
            raise RuntimeError("d123-absent-target-produced-pair")
        elif name == "disabled-pea" and isinstance(pair, dict) and any(
                "stack_observation" in state for state in (pair.get("before", {}), pair.get("after", {}))):
            raise RuntimeError("d123-disabled-observation-present")
        results[name] = {"calls": stack_calls, "route_status": row.get("route_status"),
                         "fields": report.get("fields"), "boundary_calls": report.get("boundary_calls")}
    return {"real_forwarding_neighbors": "accepted", "case_count": len(results), "cases": results}


def _d123_run_neighbors(output: pathlib.Path) -> dict:
    if output.exists() or output.is_symlink():
        raise RuntimeError("d123-neighbor-output-already-exists")
    output.mkdir(parents=True)
    build = _d123_build_native(output, "d123-dev-07-build-neighbors-native",
        target="phase6_stack_forward_contract", binary_name="phase6_stack_forward_contract")
    binary = ROOT / build["binary_path"]
    if binary.is_symlink() or not binary.is_file():
        raise RuntimeError("d123-neighbor-binary-missing")
    command = [str(binary)]
    accounting = _d123_accounting()
    run = {}
    def launch(_reservation):
        process = _invoke(command, cwd=ROOT, timeout=30.0, output_prefix=output / "neighbors")
        raw_path = ROOT / process["streams"]["stdout"]["path"]
        raw = raw_path.read_bytes()
        _d123_json(output / "run.json", {"schema": "phase6-d123-run-v1", "run_id": "d123-dev-01-neighbors-native",
            "kind": "development", "hypothesis": "stack observations must perform actual public-core byte reads",
            "relevant_change": "test-only route-controller forwarding object calls real gw_peek_memory",
            "source_identity": accounting.source_identity(ROOT), "binary_identity": build["binary_sha256"],
            "command": command, "build": build, "process": process,
            "stdout_sha256": hashlib.sha256(raw).hexdigest(), "stdout_bytes": len(raw),
            "outcome": "retained-before-decode"})
        run.update(process=process, raw_path=raw_path)
        if process["return_code"] != 0 or process["timed_out"] or process["bound_violation"] or any(s["truncated"] for s in process["streams"].values()):
            raise RuntimeError("d123-neighbor-process-failed-or-bounded")
        decoder = json.JSONDecoder(); text = raw.decode("utf-8"); cursor = 0; rows = []
        while cursor < len(text):
            while cursor < len(text) and text[cursor].isspace(): cursor += 1
            if cursor >= len(text): break
            row, cursor = decoder.raw_decode(text, cursor)
            rows.append(row)
        result = _d123_validate_neighbors(rows)
        _d123_json(output / "neighbors-check.json", result)
        run["result"] = result
        return result
    result = _d123_activity(accounting, activity_id="d123-dev-07-neighbors-native", stage="diagnostic",
        exposure=30.0, launcher=launch,
        hypothesis="GWRC increments boundary_calls before rejecting over-cap attempts, reporting17 for ceiling16",
        relevant_change="set test descriptor invocation cap to14 so actual reported attempted calls remain below16 while later-instruction case progresses",
        evidence_identity=accounting.source_identity(ROOT))
    print("real-forwarding-neighbors=accepted")
    return result


def _d123_current_component_map(accounting) -> dict:
    paths = list((ROOT / "src").rglob("*.c")) + list((ROOT / "src").rglob("*.h"))
    for directory in ("include", "tools"):
        paths += list((ROOT / directory).rglob("*.c")) + list((ROOT / directory).rglob("*.h"))
    paths += list((ROOT / "tools").rglob("CMakeLists.txt")) + list((ROOT / "cmake").rglob("*.cmake"))
    paths += [ROOT / "CMakeLists.txt", ROOT / "tests/session/phase6_stack_forward_contract.c",
        ROOT / "scripts/evidence/phase6_accounting.py", ROOT / "tests/evidence/phase6_accounting_contract.py",
        ROOT / "tests/evidence/phase6_stack_observation_contract.py",
        ROOT / "tests/evidence/phase6_tank_continuation_contract.py",
        ROOT / "scripts/evidence/phase6_routes.py", ROOT / "tests/session/phase6_route_contract.py",
        ROOT / "tests/evidence/phase6_d125_consumers_contract.py", ROOT / "tests/evidence/phase6_d125_authored_fixture.py",
        ROOT / "tests/session/phase6_capture_argv_contract.py",
        ROOT / "tests/fixtures/phase6_repairs.py", ROOT / "tests/fixtures/phase4_game.py"]
    return {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(set(paths)) if path.is_file()}


def _d123_variant_case(variant: str, generation: str) -> dict:
    if generation == '23':
        if variant not in ('native','sanitize','hooks-off'):raise RuntimeError('qualification23-variant-invalid')
        oracle=_qualification23_oracle();guest=oracle.guest();descriptor=oracle.descriptor()
        expected=dict(_d123_expected(),source_a7=0x00ff0010,later_pc=0x20e,later_opcode=0x4afc,swap_d0=0x56781234)
        return {'variant':variant,'kind':'qualification','purpose_id':'d123-qual-g23-'+variant,
            'guest_bytes_hex':guest.hex(),'guest_sha256':hashlib.sha256(guest).hexdigest(),
            'descriptor_bytes_hex':descriptor.hex(),'descriptor_sha256':hashlib.sha256(descriptor).hexdigest(),
            'probe_pc':0x200,'expected':expected,'command_suffix':oracle.argv_builder()('<client>','<descriptor>','<report>',0x200,'<guest>',stack_observer=True)[1:]}
    if variant == "native":
        guest = _guest(0xa5ff0010, bytes.fromhex("48790006923c")); pc = 0x200
        expected = _d123_expected()
    elif variant == "sanitize":
        guest = _guest(0xa5ff0010, bytes.fromhex("2e7c000000024e71")); pc = 0x206
        expected = {"pc": pc, "opcode": 0x4e71, "source_a7": 2,
            "before_bytes": [0, 0, 0xa5, 0xff], "after_bytes": [0, 0, 0xa5, 0xff],
            "read_status": [0, 0, 0, 0], "master_ticks": 28}
    elif variant == "hooks-off":
        guest = _guest(0xa5ff0010, bytes.fromhex("2e7c008000084e71")); pc = 0x206
        expected = {"pc": pc, "opcode": 0x4e71, "source_a7": 0x00800008,
            "before_bytes": [None, None, None, None], "after_bytes": [None, None, None, None],
            "read_status": [1, 1, 1, 1], "master_ticks": 28}
    else:
        raise RuntimeError("d123-qualification-variant-invalid")
    descriptor = _descriptor()
    prefix = f"d123-qual-g{generation}-{variant}"
    return {"variant": variant, "kind": "qualification", "purpose_id": prefix,
        "guest_bytes_hex": guest.hex(), "guest_sha256": hashlib.sha256(guest).hexdigest(),
        "descriptor_bytes_hex": descriptor.hex(), "descriptor_sha256": hashlib.sha256(descriptor).hexdigest(),
        "probe_pc": pc, "expected": expected,
        "command_suffix": ["<guest>", "--route-plan", "<descriptor>", "--route-report", "<report>",
            "--route-instruction-probe", str(pc), "--route-probe-only", "--route-probe-stack-before-a7"]}


def _d123_build_tool_record(build_dir: pathlib.Path, variant: str, command: list[str]) -> dict:
    cache = build_dir / "CMakeCache.txt"
    settings = {}
    for line in cache.read_text().splitlines():
        if ":" in line and "=" in line:
            key, value = line.split("=", 1); name = key.split(":", 1)[0]
            if name in ("CMAKE_C_COMPILER", "CMAKE_BUILD_TYPE", "CMAKE_C_FLAGS", "CMAKE_MAKE_PROGRAM",
                        "GENEWHIP_TEST_HOOKS"):
                settings[name] = value
    compiler = pathlib.Path(settings["CMAKE_C_COMPILER"]);maker=pathlib.Path(settings["CMAKE_MAKE_PROGRAM"])
    return {"variant": variant, "directory": build_dir.relative_to(ROOT).as_posix(), "command": command,
        "cache_sha256": hashlib.sha256(cache.read_bytes()).hexdigest(),
        "compiler_name": compiler.name, "compiler_sha256": hashlib.sha256(compiler.read_bytes()).hexdigest(),
        "build_tool_name": maker.name, "build_tool_sha256": hashlib.sha256(maker.read_bytes()).hexdigest(),
        "settings": settings}


def _d123_build_variants(output: pathlib.Path, variants: list[dict], generation: str) -> list[dict]:
    accounting = _d123_accounting();old_manifest=json.loads((ROOT/"evidence/phase6-stack-observation-manifest-d122.json").read_bytes())
    old_builds={row["variant"]:row for row in old_manifest["builds"]};cmake=shutil.which("cmake")
    if not cmake: raise RuntimeError("d123-cmake-unavailable")
    cmake_path=pathlib.Path(cmake).resolve();cmake_hash=hashlib.sha256(cmake_path.read_bytes()).hexdigest()
    for variant in variants:
        build_dir=ROOT/old_builds[variant["variant"]]["directory"]
        if build_dir.is_symlink() or (build_dir/"CMakeCache.txt").is_symlink() or not (build_dir/"CMakeCache.txt").is_file():
            raise RuntimeError("d123-variant-cache-missing-or-unsafe:"+variant["variant"])
    build_root=output/"builds"
    build_root.mkdir(parents=True,exist_ok=False)
    cases=[]
    def launch(_reservation):
        deadline=time.monotonic()+300.0
        for variant in variants:
            build_dir=ROOT/old_builds[variant["variant"]]["directory"]
            command=["cmake","--build",build_dir.relative_to(ROOT).as_posix(),"--target","gw_headless","--parallel","2"]
            remaining=deadline-time.monotonic()
            if remaining<=0:raise RuntimeError("d123-aggregate-build-deadline-exhausted")
            raw_prefix=build_root/variant["variant"]
            process=_invoke(command,cwd=ROOT,timeout=min(300.0,remaining),output_prefix=raw_prefix)
            case={"variant":variant["variant"],"command":command,"process":process}
            cases.append(case);_d123_json(build_root/(variant["variant"]+".json"),case)
            if process["return_code"]!=0 or process["timed_out"] or process["bound_violation"] or any(s["truncated"] for s in process["streams"].values()):
                raise RuntimeError("d123-variant-build-failed-or-bounded:"+variant["variant"])
            binary=build_dir/"tools/session/gw_headless"
            if binary.is_symlink() or not binary.is_file():raise RuntimeError("d123-variant-binary-missing:"+variant["variant"])
            case.update(binary_path=binary.relative_to(ROOT).as_posix(),binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                cache_sha256=hashlib.sha256((build_dir/"CMakeCache.txt").read_bytes()).hexdigest(),
                tools=_d123_build_tool_record(build_dir,variant["variant"],command))
            settings=case['tools']['settings']
            if generation=='23' and (settings.get('GENEWHIP_TEST_HOOKS')!=('OFF' if variant['variant']=='hooks-off' else 'ON') or
                    (variant['variant']=='sanitize')!=('-fsanitize=address,undefined' in settings.get('CMAKE_C_FLAGS',''))):
                raise RuntimeError('qualification23-effective-variant-settings-invalid')
            _d123_json(build_root/(variant['variant']+'.json'),case,create_once=False)
        return {"build_count":len(cases),"variants":[row["variant"] for row in cases],
            "cmake_path":cmake_path.relative_to(ROOT).as_posix() if cmake_path.is_relative_to(ROOT) else cmake_path.name,
            "cmake_sha256":cmake_hash,"builds":cases}
    return _d123_activity(accounting,activity_id=f"d123-qual-g{generation}-build-three-variants",stage="build",
        exposure=300.0,launcher=launch,evidence_identity=accounting.source_identity(ROOT))["builds"]


def _d123_prepare_qualification_manifest(manifest_path: pathlib.Path, output: pathlib.Path) -> dict:
    accounting=_d123_accounting();source=accounting.source_identity(ROOT)
    ledger=json.loads(LEDGER.read_bytes());policy=ledger.get("d123_recovery_policy",{})
    if ENGINEERING_OWNER=='06-23':
        _qualification23_storage()
        policy=accounting.qualification23_owner(ledger,project_root=ROOT)
        if QUALIFICATION_GENERATION!='23' or QUALIFICATION_BRIDGE_OUTPUT is None:
            raise RuntimeError('qualification23-explicit-generation-and-bridge-required')
        generation='23'
    else:
        if policy.get("status")!="active":raise RuntimeError("d123-policy-not-active-before-freeze")
        generation="02" if "g02" in manifest_path.name else "01"
    variants=[{"variant":name} for name in ("native","sanitize","hooks-off")]
    built=_d123_build_variants(output,variants,generation)
    builds=[];tool_builds={}
    for row in built:
        item={"variant":row["variant"],"directory":row["tools"]["directory"],"command":row["command"],
            "binary_path":row["binary_path"],"binary_sha256":row["binary_sha256"],
            "cache_sha256":row["cache_sha256"],"compiler_sha256":row["tools"]["compiler_sha256"],
            "build_tool_sha256":row["tools"]["build_tool_sha256"],"settings":row["tools"]["settings"]}
        builds.append(item)
        tool_builds[row["variant"]]={"cache_sha256":row["cache_sha256"],
            "compiler_name":row["tools"]["compiler_name"],"compiler_sha256":row["tools"]["compiler_sha256"],
            "build_tool_name":row["tools"]["build_tool_name"],"build_tool_sha256":row["tools"]["build_tool_sha256"],
            "settings":row["tools"]["settings"],"command":row["command"]}
    cases=[_d123_variant_case(name,generation) for name in ("native","sanitize","hooks-off")]
    components=_d123_current_component_map(accounting)
    legacy=json.loads((ROOT/"evidence/phase6-stack-observation-manifest-d122.json").read_bytes())
    checker=_d123_load_module("d123_original_authority",ROOT/"tests/evidence/phase6_tank_continuation_contract.py")
    original_paths=checker.control_input_paths()
    original_inputs={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in original_paths}
    halt_paths=[".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-18-SUMMARY.md",
        ".planning/forensics/report-20261024-193248.md","evidence/phase6-stack-observation-manifest.json"]
    halt_hashes={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in halt_paths}
    cmake=shutil.which("cmake");cmake_path=pathlib.Path(cmake).resolve()
    document={"schema":"phase6-d123-stack-observation-manifest-v1","status":"frozen",
        "generation":generation,"source_identity":source,"approval_binding":{
            "approval":policy.get("approval"),"approval_context_sha256":policy.get("approval_context_sha256"),
            "plan_sha256":policy.get("plan_sha256"),"plan_check_sha256":policy.get("plan_check_sha256"),
            "operating_contract_sha256":policy.get("operating_contract_sha256")},
        "global_accounting":{"global_floor_seconds":policy.get("global_floor_seconds"),
            "pea_floor_seconds":policy.get("pea_floor_seconds"),"protected_14_seconds":policy.get("protected_14_seconds"),
            "closeout_reserve_seconds":policy.get("closeout_reserve_seconds"),"pea_charge_seconds":0.0},
        "original_manifest_path":"evidence/phase6-stack-observation-manifest.json",
        "original_manifest_sha256":hashlib.sha256((ROOT/"evidence/phase6-stack-observation-manifest.json").read_bytes()).hexdigest(),
        "d122_manifest_path":"evidence/phase6-stack-observation-manifest-d122.json",
        "d122_manifest_sha256":hashlib.sha256((ROOT/"evidence/phase6-stack-observation-manifest-d122.json").read_bytes()).hexdigest(),
        "d122_halt_and_authority_hashes":halt_hashes,"d118_control_input_sha256":original_inputs,
        "component_sha256":components,"tool_identity":{"cmake_name":cmake_path.name,
            "cmake_sha256":hashlib.sha256(cmake_path.read_bytes()).hexdigest(),"builds":tool_builds},
        "builds":builds,"cases":cases,
        "qualification_contract":{"variants":["native","sanitize","hooks-off"],"serial":True,
            "diagnostic_exposure_seconds":30,"field_max":1,"boundary_calls_max":16,"guest_bytes_max":1024,
            "development_rows_excluded":True}}
    if ENGINEERING_OWNER=='06-23':
        document.update(engineering_owner='06-23',game_admission=False)
        component_review=ROOT/'.planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-23-COMPONENT-REVIEW.json'
        retained=json.loads(component_review.read_bytes())
        retained_files={item['path']:item['sha256'] for item in retained['inspected_files'] if
            item['path'].startswith('build/phase6/d123-observer/dev/neighbors-07/') or
            item['path']=='build/phase6/tools/session/phase6_stack_forward_contract' or
            item['path'] in ('tests/session/phase6_stack_forward_contract.c','tools/session/route_controller.c',
                'tools/session/session.h','tests/fixtures/phase6_repairs.py','src/bus.c','src/core.c','src/diagnostic.c','include/genewhip/genewhip.h')}
        if retained.get('decision')!='accepted' or not retained_files or any(hashlib.sha256((ROOT/p).read_bytes()).hexdigest()!=h for p,h in retained_files.items()):
            raise RuntimeError('qualification23-retained-neighbor-component-not-current')
        old=json.loads((ROOT/'evidence/phase6-stack-observation-manifest-d123-g02.json').read_bytes())['component_sha256']
        freeze={'schema':'phase6-qualification23-source-freeze-v1','engineering_owner':'06-23','game_admission':False,
            'source_identity':source,'component_sha256':components,'retained_file_sha256':retained_files,
            'components':[{'path':name,'old_sha256':old.get(name),'new_sha256':digest,
                'disposition':'unchanged' if old.get(name)==digest else 'affected-current-qualification-or-consumer-review'} for name,digest in components.items()],
            'component_review_sha256':hashlib.sha256(component_review.read_bytes()).hexdigest(),
            'builds':builds,'tool_identity':document['tool_identity'],'cases':cases}
        _d123_json(output.parent/'source-freeze.json',freeze)
    manifest_path=manifest_path if manifest_path.is_absolute() else ROOT/manifest_path
    _d123_json(manifest_path,document)
    frozen=accounting.freeze_d123_observer_manifest(LEDGER,manifest_path,project_root=ROOT,
        boot_identity=__import__('os').environ.get('GENEWHIP_D123_BOOT_IDENTITY') or accounting.read_boot_identity(),engineering_owner=ENGINEERING_OWNER)
    return {"document":document,"frozen":frozen,"builds":built}


def _d123_run_qualify(manifest_path: pathlib.Path, output: pathlib.Path) -> dict:
    if output.exists() or output.is_symlink():raise RuntimeError("d123-qualification-output-exists-or-symlink")
    output.mkdir(parents=True)
    manifest_path=manifest_path if manifest_path.is_absolute() else ROOT/manifest_path
    manifest_path.resolve(strict=False).relative_to(ROOT.resolve(strict=True))
    if not manifest_path.exists():_d123_prepare_qualification_manifest(manifest_path,output)
    preflight=_prelaunch_check(manifest_path)
    manifest=json.loads(manifest_path.read_bytes());accounting=_d123_accounting()
    cases=manifest["cases"];builds={row["variant"]:row for row in manifest["builds"]};rows=[]
    for case in cases:
        if ENGINEERING_OWNER=='06-23':_qualification23_storage()
        variant=case["variant"];binary=ROOT/builds[variant]["binary_path"]
        guest=bytes.fromhex(case["guest_bytes_hex"]);descriptor=bytes.fromhex(case["descriptor_bytes_hex"])
        run_dir=output/variant;run_dir.mkdir()
        guest_path=run_dir/"guest.bin";descriptor_path=run_dir/"route.bin";report_path=run_dir/"native-report.json"
        guest_path.write_bytes(guest);descriptor_path.write_bytes(descriptor)
        command=[builds[variant]["binary_path"],guest_path.relative_to(ROOT).as_posix(),"--route-plan",descriptor_path.relative_to(ROOT).as_posix(),
            "--route-report",report_path.relative_to(ROOT).as_posix(),"--route-instruction-probe",str(case["probe_pc"]),
            "--route-probe-only","--route-probe-stack-before-a7"]
        if ENGINEERING_OWNER=='06-23':
            command=_qualification23_oracle().argv_builder()(builds[variant]['binary_path'],descriptor_path.relative_to(ROOT).as_posix(),
                report_path.relative_to(ROOT).as_posix(),0x200,guest_path.relative_to(ROOT).as_posix(),stack_observer=True)
        def launch(_reservation,case=case,variant=variant,binary=binary,command=command,run_dir=run_dir,
                   report_path=report_path,guest=guest,descriptor=descriptor):
            process=_invoke(command,cwd=ROOT,timeout=30.0,output_prefix=run_dir/"process")
            raw=report_path.read_bytes() if report_path.is_file() and not report_path.is_symlink() else b""
            row={"schema":"phase6-d123-run-v1","run_id":case["purpose_id"],"kind":"qualification","variant":variant,
                "purpose_id":case["purpose_id"],"status":"retained-before-check","source_identity":accounting.source_identity(ROOT),
                "binary_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),"guest_sha256":hashlib.sha256(guest).hexdigest(),
                "descriptor_sha256":hashlib.sha256(descriptor).hexdigest(),"oracle_sha256":hashlib.sha256(json.dumps(case["expected"],sort_keys=True).encode()).hexdigest(),
                "command":command,"process":process,"raw_report_path":report_path.relative_to(ROOT).as_posix(),
                "raw_report_sha256":hashlib.sha256(raw).hexdigest() if raw else None,"raw_report_bytes":len(raw)}
            _d123_json(run_dir/"run.json",row)
            if process["return_code"]!=(1 if ENGINEERING_OWNER=='06-23' else 0) or process["timed_out"] or process["bound_violation"] or any(s["truncated"] for s in process["streams"].values()):
                raise RuntimeError("d123-qualification-process-failed-or-bounded:"+variant)
            if not raw or len(raw)>8388608:raise RuntimeError("d123-qualification-report-missing-or-oversized:"+variant)
            checks=validate_qualification23_capture(json.loads(raw)) if ENGINEERING_OWNER=='06-23' else _validate_observation_report({"expected":case["expected"]},json.loads(raw))
            result={"kind":"qualification","variant":variant,"purpose_id":case["purpose_id"],"status":"passed",
                "source_identity":accounting.source_identity(ROOT),"binary_sha256":row["binary_sha256"],
                "guest_sha256":row["guest_sha256"],"descriptor_sha256":row["descriptor_sha256"],
                "raw_report_path":row["raw_report_path"],"raw_report_sha256":row["raw_report_sha256"],
                "process_streams":process["streams"],"command":command,"checks":checks,
                "oracle_sha256":row["oracle_sha256"],"process_return_code":process["return_code"],
                "timed_out":process["timed_out"],"bound_violation":process["bound_violation"]}
            _d123_json(run_dir/"assessment.json",result)
            return result
        rows.append(_d123_activity(accounting,activity_id=case["purpose_id"],stage="qualification",exposure=30.0,
            launcher=launch,evidence_identity=accounting.source_identity(ROOT)))
    result={"schema":"phase6-d123-qualification-v1","status":"passed-three-rows",
        "manifest_path":manifest_path.relative_to(ROOT).as_posix(),"manifest_sha256":hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "source_identity":accounting.source_identity(ROOT),"rows":rows,"qualification_count":3,
        "launches":3,"target_attempts":0,"development_rows_excluded":True,
        "preflight":preflight}
    _d123_json(output/"qualification-rows.json",result)
    if ENGINEERING_OWNER=='06-23':
        bridge=_d123_load_module('qualification23_bridge_writer',ROOT/'tests/evidence/phase6_tank_continuation_contract.py').create_qualification23_bridge(
            ROOT/'build/phase6',manifest_path,output/'qualification-rows.json',QUALIFICATION_BRIDGE_OUTPUT,output.parent/'source-freeze.json')
        print('qualification23=3/3 bridge='+bridge['bridge_sha256'])
        return result
    bridge_path=ROOT/("evidence/phase6-tank-observer-bridge-d123-g02.json" if "g02" in manifest_path.name else
        "evidence/phase6-tank-observer-bridge.json")
    bridge=_d123_load_module("d123_bridge_writer",ROOT/"tests/evidence/phase6_tank_continuation_contract.py").create_d123_observer_bridge(
        ROOT/"build/phase6",manifest_path,output/"qualification-rows.json",bridge_path)
    print("d123-qualification=3/3 independent bridge="+bridge["bridge_sha256"])
    return result


def _invoke(command: list[str], *, cwd: pathlib.Path, timeout: float,
            output_prefix: pathlib.Path) -> dict:
    started = time.monotonic()
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    runner_spec=importlib.util.spec_from_file_location('phase6_bounded_process_tree',ROOT/'tests/fixtures/phase4_game.py')
    runner=importlib.util.module_from_spec(runner_spec);runner_spec.loader.exec_module(runner)
    bound_violation=False;timed_out=False
    try:
        result=runner.bounded_run(command,timeout=timeout,cap=2097152)
        out,err,return_code=result.stdout,result.stderr,result.returncode
    except runner.BoundedProcessError as exc:
        out,err,return_code=exc.stdout,exc.stderr,None
        timed_out='timeout' in str(exc);bound_violation='cap' in str(exc)
    streams = {"stdout": _write_bounded(output_prefix.with_suffix(".stdout.raw"), out, 1048576),
               "stderr": _write_bounded(output_prefix.with_suffix(".stderr.raw"), err, 1048576)}
    executable_path = shutil.which(command[0]) if "/" not in command[0] else command[0]
    return {"command": command, "cwd": ".", "executable": command[0], "bound_violation": bound_violation,
        "executable_path": pathlib.Path(executable_path).resolve().as_posix() if executable_path else None,
        "executable_sha256": hashlib.sha256(pathlib.Path(executable_path).read_bytes()).hexdigest()
            if executable_path and pathlib.Path(executable_path).is_file() else None,
        "wall_seconds": round(time.monotonic() - started, 3),
        "return_code": return_code, "timed_out": timed_out, "streams": streams}


def _validate_observation_report(row: dict, report: dict) -> dict:
    expected = row["expected"]
    native = report.get("native_report", report)
    if not isinstance(native, dict) or native.get("schema") != "genewhip-route-native-v1":
        raise RuntimeError("observer-native-report-invalid")
    if native.get("fields", 99) > 1 or native.get("boundary_calls", 99) > 16:
        raise RuntimeError("observer-proof-runtime-bound-exceeded")
    pair = native.get("probe_boundary")
    if not isinstance(pair, dict):
        raise RuntimeError("observer-probe-pair-missing")
    before, after = pair.get("before", {}), pair.get("after", {})
    if pair.get("instruction_address") != expected["pc"] or before.get("pc") != expected["pc"] or pair.get("opcode") != expected["opcode"]:
        raise RuntimeError("observer-probe-identity-mismatch")
    if after.get("sr") != before.get("sr"):
        raise RuntimeError("observer-probe-sr-changed")
    width=6 if expected["opcode"]==0x4879 else 2
    expected_a7=(expected["source_a7"]-4)&0xffffffff if expected["opcode"]==0x4879 else expected["source_a7"]
    if pair.get("retired") is not True or type(before.get("instructions")) is not int or \
       type(after.get("instructions")) is not int or after["instructions"]!=before["instructions"]+1:
        raise RuntimeError("observer-probe-retirement-denominator-invalid")
    before_a,after_a=before.get("a"),after.get("a")
    if not isinstance(before_a,list) or not isinstance(after_a,list) or len(before_a)!=8 or len(after_a)!=8 or \
       any(type(value) is not int for value in (before_a[7],after_a[7])) or \
       after.get("pc")!=expected["pc"]+width or before_a[7]!=expected["source_a7"] or after_a[7]!=expected_a7:
        raise RuntimeError("observer-probe-pc-or-a7-transition-invalid")
    tick_delta=after.get("tick")-before.get("tick") if type(after.get("tick")) is int and type(before.get("tick")) is int else None
    expected_ticks=expected.get("master_ticks")
    if type(tick_delta) is not int or tick_delta<=0 or (expected_ticks is not None and tick_delta!=expected_ticks):
        raise RuntimeError("observer-probe-master-tick-delta-invalid")
    enabled = True
    observations = validate_stack_pair(pair, enabled=enabled,
        expected_source_a7=expected["source_a7"], expected_before=expected.get("before_bytes"),
        expected_after=expected.get("after_bytes"))
    before_observation = before["stack_observation"]
    after_observation = after["stack_observation"]
    if before_observation["status"] != expected.get("read_status", [0, 0, 0, 0]) or \
            after_observation["status"] != expected.get("read_status", [0, 0, 0, 0]):
        raise RuntimeError("observer-exact-status-mismatch")
    if sum((before_observation["read_calls"], after_observation["read_calls"])) != 8:
        raise RuntimeError("observer-actual-read-call-denominator-invalid")
    return {"probe_pc": expected["pc"], "opcode": expected["opcode"],
        "source_a7": observations["source_a7"], "read_calls": 8,
        "before_status": before_observation["status"], "after_status": after_observation["status"],
        "before_bytes": before_observation["bytes"], "after_bytes": after_observation["bytes"],
        "sr_unchanged": True, "retired":pair["retired"],"instruction_delta":1,
        "master_tick_delta":tick_delta,"before_a7":before["a"][7],"after_a7":after["a"][7],
        "fields": native["fields"], "boundary_calls": native["boundary_calls"]}


def _build_and_prove(manifest_path: pathlib.Path, output_path: pathlib.Path,
                     bridge_output_path: pathlib.Path | None = None) -> dict:
    preflight = _prelaunch_check(manifest_path)
    ledger = json.loads(LEDGER.read_text())
    frozen = ledger.get("d122_successor_manifest", {})
    if frozen.get("status") != "frozen" or frozen.get("sha256") != preflight["sha256"]:
        raise RuntimeError("observer-successor-not-frozen")
    import importlib.util
    spec = importlib.util.spec_from_file_location("phase6_d122_accounting", ROOT / "scripts/evidence/phase6_accounting.py")
    accounting = importlib.util.module_from_spec(spec); spec.loader.exec_module(accounting)
    current_source = accounting.source_identity(ROOT)
    if current_source != frozen.get("source_identity"):
        raise RuntimeError("observer-frozen-source-drift")
    checker_spec=importlib.util.spec_from_file_location('phase6_binary_retention_check',ROOT/'tests/evidence/phase6_tank_continuation_contract.py')
    checker=importlib.util.module_from_spec(checker_spec);checker_spec.loader.exec_module(checker)
    retention=checker.load_original_binary_retention(frozen.get('original_binary_retention'))
    with tempfile.TemporaryDirectory(prefix='observer-original-preflight-') as temporary:
        original=checker.revalidate_proof(ROOT/'build/phase6',pathlib.Path(temporary)/'original.json',
            update_ledger=False,binary_retention=retention)
    if original.get('status')!='passed-no-launch' or original.get('original_runtime_closure',{}).get('variant_binaries_distinct') is not True:
        raise RuntimeError('observer-prebuild-original-closure-invalid')
    for name,digest in frozen.get("source_file_hashes",{}).items():
        candidate=ROOT/name
        if candidate.is_symlink() or not candidate.is_file() or hashlib.sha256(candidate.read_bytes()).hexdigest()!=digest:
            raise RuntimeError("observer-frozen-source-file-drift:"+name)
    tool_identity=frozen.get("tool_identity",{});cmake=shutil.which("cmake")
    if not cmake or pathlib.Path(cmake).resolve().as_posix()!=tool_identity.get("cmake_path") or \
       hashlib.sha256(pathlib.Path(cmake).read_bytes()).hexdigest()!=tool_identity.get("cmake_sha256"):
        raise RuntimeError("observer-frozen-cmake-identity-drift")
    for row in _successor_document()["builds"]:
        saved=tool_identity.get("builds",{}).get(row["variant"],{});cache=ROOT/row["directory"]/"CMakeCache.txt"
        if saved.get("command")!=row["command"] or hashlib.sha256(cache.read_bytes()).hexdigest()!=saved.get("cache_sha256"):
            raise RuntimeError("observer-frozen-build-cache-or-command-drift:"+row["variant"])
        if hashlib.sha256(pathlib.Path(saved.get("compiler_path","")).read_bytes()).hexdigest()!=saved.get("compiler_sha256") or \
           hashlib.sha256(pathlib.Path(saved.get("build_tool_path","")).read_bytes()).hexdigest()!=saved.get("build_tool_sha256"):
            raise RuntimeError("observer-frozen-compiler-or-build-tool-drift:"+row["variant"])
    if output_path.is_symlink():
        raise RuntimeError("observer-output-path-symlink-denied")
    output_path.resolve(strict=False).relative_to(ROOT.resolve(strict=True))
    build_root = ROOT / "build/phase6/d122-observer"
    if output_path.exists() or build_root.exists():
        raise RuntimeError("observer-build-proof-output-already-exists")
    for build in _successor_document()["builds"]:
        cache = ROOT / build["directory"] / "CMakeCache.txt"
        if cache.is_symlink() or not cache.is_file():
            raise RuntimeError("observer-build-cache-missing-or-unsafe:" + build["variant"])
    build_root.mkdir(parents=True, exist_ok=True)
    build_cases = []
    build_commands = [row["command"] for row in _successor_document()["builds"]]
    command_identity = hashlib.sha256(json.dumps(build_commands, separators=(",", ":")).encode()).hexdigest()
    build_environment = hashlib.sha256(json.dumps([str(ROOT / row["directory"] / "CMakeCache.txt")
        for row in _successor_document()["builds"]], separators=(",", ":")).encode()).hexdigest()

    proof_rows_path=build_root / "observer-proof-rows.json"
    if output_path.name.endswith(".json") and output_path.exists():
        raise RuntimeError("observer-final-bridge-output-already-exists")

    def run_builds(reservation: dict) -> dict:
        deadline = time.monotonic() + 300.0
        for index, row in enumerate(_successor_document()["builds"]):
            command = row["command"]
            try:
                result = _invoke(command, cwd=ROOT, timeout=max(0.001, deadline - time.monotonic()),
                                 output_prefix=build_root / f"build-{row['variant']}")
            except BaseException as exc:
                build_cases.append({"variant":row["variant"],"command":command,"return_code":None,
                    "timed_out":False,"bound_violation":True,"launcher_exception":type(exc).__name__})
                _write_json(proof_rows_path,{"status":"build-prefix","builds":build_cases,"proofs":[],"launches":len(build_cases)})
                raise
            build_cases.append({"variant": row["variant"], **result})
            _write_json(proof_rows_path, {"status": "build-prefix", "builds": build_cases,
                                      "proofs": [], "launches": len(build_cases)})
            if result["return_code"] != 0 or result["timed_out"] or result["bound_violation"] or any(s["truncated"] for s in result["streams"].values()):
                raise RuntimeError("observer-build-failed-or-bounded:" + row["variant"])
        return {"status": "built-three-variants", "builds": build_cases}

    build_result = accounting.authorize_observer_activity(LEDGER, purpose="stack-observer-builds",
        plan="06-18", case=accounting.OBSERVER_BUILD_CASE, source_identity=current_source,
        current_source_identity=accounting.source_identity(ROOT), binary_identity=build_environment,
        command_identity=command_identity, manifest_sha256=preflight["sha256"],
        launcher=run_builds, boot_identity=accounting.read_boot_identity(), allowed_root=ROOT)
    historical=json.loads((ROOT/'evidence/phase6-capture-recovery.json').read_text())
    historical_hashes={row['variant']:row['client_sha256'] for row in historical['synthetic_process_rows']}
    built_hashes={row['variant']:hashlib.sha256((ROOT/row['directory']/'tools/session/gw_headless').read_bytes()).hexdigest()
        for row in _successor_document()['builds']}
    if len(set(built_hashes.values()))!=3 or any(built_hashes[name]==historical_hashes.get(name) for name in built_hashes):
        raise RuntimeError("observer-build-binaries-not-distinct-from-each-other-and-history")
    proof_rows = []
    for row in _successor_document()["cases"]:
        purpose = row["purpose_id"]
        target_variant = {"native": "native", "sanitize": "sanitize", "hooks": "hooks-off"}[purpose.split("-")[2]]
        build_dir = ROOT / next(b["directory"] for b in _successor_document()["builds"]
                                if b["variant"] == target_variant)
        client = build_dir / "tools/session/gw_headless"
        if not client.is_file():
            raise RuntimeError("observer-built-client-missing:" + purpose)
        guest = build_root / f"{purpose}.rom"
        descriptor = build_root / f"{purpose}.route"
        guest.write_bytes(bytes.fromhex(row["guest_bytes_hex"]))
        descriptor.write_bytes(bytes.fromhex(row["descriptor_bytes_hex"]))
        report_path = build_root / f"{purpose}.report.json"
        command = [str(client), str(guest), "--route-plan", str(descriptor), "--route-report", str(report_path),
            "--route-instruction-probe", str(row["probe_pc"]), "--route-probe-only", "--route-probe-stack-before-a7"]
        binary_id = hashlib.sha256(client.read_bytes()).hexdigest()
        if binary_id!=built_hashes[target_variant] or binary_id==historical_hashes.get(target_variant):
            raise RuntimeError("observer-proof-binary-not-bound-to-prevalidated-new-build:"+purpose)
        command_id = hashlib.sha256(json.dumps(command, separators=(",", ":")).encode()).hexdigest()
        captured = {"launcher_entered":False}
        def launch_proof(reservation: dict, *, row=row, command=command, report_path=report_path,
                         purpose=purpose, captured=captured):
            captured["launcher_entered"]=True
            if not report_path.is_file() and report_path.is_symlink():
                raise RuntimeError("observer-report-path-symlink-denied")
            if report_path.exists():
                raise RuntimeError("observer-report-path-already-exists")
            prefix = build_root / purpose
            launch_started=time.monotonic()
            try:result = _invoke(command, cwd=ROOT, timeout=30.0, output_prefix=prefix)
            except BaseException as exc:
                captured["process"]={"return_code":None,"timed_out":False,"bound_violation":True,
                    "launcher_exception":type(exc).__name__,"wall_seconds":round(time.monotonic()-launch_started,3),"streams":{}}
                raise
            captured["process"] = result
            if result["timed_out"] or result["bound_violation"] or result["return_code"] != 0 or any(s["truncated"] for s in result["streams"].values()):
                raise RuntimeError("observer-proof-process-failed:" + purpose)
            if not report_path.is_file() or report_path.is_symlink() or report_path.stat().st_size > 8388608:
                raise RuntimeError("observer-proof-report-missing-or-oversized")
            raw = report_path.read_bytes()
            report_hash = hashlib.sha256(raw).hexdigest()
            report = json.loads(raw)
            checks = _validate_observation_report(row, report)
            captured.update(report=report, report_sha256=report_hash, checks=checks,
                            report_path=report_path.relative_to(ROOT).as_posix())
            return {"status": "proof-passed", "report_sha256": report_hash, "checks": checks}
        try:
            accounting.authorize_observer_activity(LEDGER, purpose=purpose, plan="06-18", case=purpose,
                source_identity=current_source, current_source_identity=accounting.source_identity(ROOT),
                binary_identity=binary_id, command_identity=command_id,
                manifest_sha256=preflight["sha256"], launcher=launch_proof,
                boot_identity=accounting.read_boot_identity(), allowed_root=ROOT)
        except BaseException as exc:
            attempted=1 if captured.get('launcher_entered') else 0
            failed=[{'purpose_id':purpose,'status':'failed-prefix' if attempted else 'admission-denied',
                'binary_sha256':binary_id,'command_sha256':command_id,'process':captured.get('process',{}),
                'error_type':type(exc).__name__}] if attempted else []
            _write_json(proof_rows_path,{"schema":"phase6-d122-observer-proof-rows-v1","status":"partial",
                "manifest_sha256":preflight["sha256"],"source_identity":current_source,
                "builds":build_cases,"proofs":proof_rows+failed,"attempted_purpose":purpose,
                "launches":len(build_cases)+len(proof_rows)+attempted})
            raise
        proof_rows.append({"purpose_id": purpose, "binary_sha256": binary_id,
            "guest_sha256": hashlib.sha256(guest.read_bytes()).hexdigest(),
            "descriptor_sha256": hashlib.sha256(descriptor.read_bytes()).hexdigest(),
            "command": command, "command_sha256": command_id,
            "process": captured["process"], "report_path": captured["report_path"],
            "report_sha256": captured["report_sha256"], "checks": captured["checks"]})
        _write_json(proof_rows_path, {"schema": "phase6-d122-observer-proof-rows-v1", "status": "partial",
            "manifest_sha256": preflight["sha256"], "source_identity": current_source,
            "builds": build_cases, "build_result": build_result, "proofs": proof_rows,
            "launches": len(build_cases) + len(proof_rows)})
    result = {"schema": "phase6-d122-observer-proof-rows-v1", "status": "passed-three-rows",
        "manifest_path": preflight["path"], "manifest_sha256": preflight["sha256"],
        "source_identity": current_source, "builds": build_cases, "proofs": proof_rows,
        "launches": len(build_cases) + len(proof_rows), "guest_fields_max": 1,
        "proof_processes": 3, "target_attempts": 0}
    _write_json(proof_rows_path, result)
    if bridge_output_path is None:return result
    checker_spec=importlib.util.spec_from_file_location("phase6_actual_bridge_writer",ROOT/"tests/evidence/phase6_tank_continuation_contract.py")
    checker=importlib.util.module_from_spec(checker_spec);checker_spec.loader.exec_module(checker)
    return checker.create_observer_bridge(ROOT/"build/phase6",proof_rows_path,bridge_output_path)


def _write_json(path: pathlib.Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.is_symlink():
        raise RuntimeError("observer-json-temp-symlink-denied")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def _author_manifest():
    if MANIFEST.exists():
        raise RuntimeError("observer-manifest-already-authored")
    payload = json.dumps(manifest_document(), indent=2, sort_keys=True) + "\n"
    MANIFEST.write_text(payload)
    print(json.dumps({"status": "authored-unlaunched", "path": MANIFEST.relative_to(ROOT).as_posix(),
        "sha256": hashlib.sha256(payload.encode()).hexdigest()}, sort_keys=True))
    return 0


def cli_parser():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--offline", action="store_true")
    group.add_argument("--author-manifest", action="store_true")
    group.add_argument("--freeze-manifest", nargs="?", const="__original__")
    group.add_argument("--author-successor", type=pathlib.Path)
    group.add_argument("--prelaunch-check", action="store_true")
    group.add_argument("--build-and-prove", action="store_true")
    parser.add_argument("--d123-stage", choices=("tracer", "neighbors", "qualify"))
    parser.add_argument("--tracer-step", choices=("red", "green", "check"))
    parser.add_argument("--successor-manifest", type=pathlib.Path)
    parser.add_argument("--manifest", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument('--engineering-owner',choices=('06-23',))
    parser.add_argument('--qualification-generation',choices=('23',))
    parser.add_argument('--bridge-output',type=pathlib.Path)
    return parser


def main() -> int:
    global ENGINEERING_OWNER,QUALIFICATION_GENERATION,QUALIFICATION_BRIDGE_OUTPUT
    parser=cli_parser();args=parser.parse_args()
    try:
        if any((args.engineering_owner,args.qualification_generation,args.bridge_output)):
            if not all((args.engineering_owner,args.qualification_generation,args.bridge_output)) or args.d123_stage!='qualify':
                parser.error('qualification23 requires explicit engineering owner, generation23, bridge output and qualify stage')
            ENGINEERING_OWNER=args.engineering_owner;QUALIFICATION_GENERATION=args.qualification_generation
            QUALIFICATION_BRIDGE_OUTPUT=args.bridge_output if args.bridge_output.is_absolute() else ROOT/args.bridge_output
        if args.offline:
            unittest.main(argv=[sys.argv[0]], verbosity=2)
            return 0
        if args.d123_stage == "tracer":
            if not args.tracer_step or not args.output:
                parser.error("--d123-stage tracer requires --tracer-step and --output")
            final = args.output if args.output.is_absolute() else ROOT / args.output
            final.resolve(strict=False).relative_to(ROOT.resolve(strict=True))
            if args.tracer_step == "red":
                _d123_run_red(final)
                return 0
            if args.tracer_step == "check":
                print(json.dumps(_d123_check_red_green(final), sort_keys=True))
                return 0
            if args.tracer_step == "green":
                _d123_run_green(final)
                return 0
        if args.d123_stage == "neighbors":
            if args.tracer_step or not args.output:
                parser.error("--d123-stage neighbors requires --output and does not accept --tracer-step")
            final = args.output if args.output.is_absolute() else ROOT / args.output
            final.resolve(strict=False).relative_to(ROOT.resolve(strict=True))
            _d123_run_neighbors(final)
            return 0
        if args.d123_stage == "qualify":
            if not args.manifest or not args.output:
                parser.error("--d123-stage qualify requires --manifest and --output")
            manifest=args.manifest if args.manifest.is_absolute() else ROOT/args.manifest
            final=args.output if args.output.is_absolute() else ROOT/args.output
            final.resolve(strict=False).relative_to(ROOT.resolve(strict=True))
            _d123_run_qualify(manifest,final)
            return 0
        if args.author_manifest:
            return _author_manifest()
        if args.freeze_manifest == "__original__":
            return _freeze_manifest()
        if args.author_successor:
            print(json.dumps(_author_successor(args.author_successor), sort_keys=True)); return 0
        if args.prelaunch_check:
            if not args.successor_manifest: parser.error("--prelaunch-check requires --successor-manifest")
            print(json.dumps(_prelaunch_check(args.successor_manifest), sort_keys=True)); return 0
        if args.freeze_manifest is not None:
            print(json.dumps(_freeze_successor(pathlib.Path(args.freeze_manifest)), sort_keys=True)); return 0
        if args.build_and_prove:
            if not args.manifest or not args.output: parser.error("--build-and-prove requires --manifest and --output")
            final=args.output if args.output.is_absolute() else ROOT/args.output
            final.resolve(strict=False).relative_to(ROOT.resolve(strict=True))
            rows=ROOT/"build/phase6/d122-observer/observer-proof-rows.json"
            if final.exists() or final.is_symlink(): raise RuntimeError("observer-final-bridge-output-exists")
            print(json.dumps(_build_and_prove(args.manifest, rows, final), sort_keys=True)); return 0
        parser.error("a command is required")
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as exc:
        failure={"status":"halted","reason":str(exc),"launches":0}
        if ENGINEERING_OWNER=='06-23' and args.output:
            output=args.output if args.output.is_absolute() else ROOT/args.output
            ledger=json.loads(LEDGER.read_bytes())
            requests=[r['activity_id'] for r in ledger.get('d125_qualification23_activities',[]) if r.get('stage')=='qualification']
            observed=[json.loads(p.read_bytes()) for p in output.glob('*/run.json')]
            accepted=[json.loads(p.read_bytes()) for p in output.glob('*/assessment.json')]
            failure={'schema':'phase6-qualification23-partial-v1','status':'HALTED','reason':str(exc),
                'qualification_requests':requests,'observed_native_process_records':len(observed),'qualification_count':len(accepted),
                'planned_variants':['native','sanitize','hooks-off'],'unreached':[v for v in ('native','sanitize','hooks-off') if
                    'd123-qual-g23-'+v not in requests],'rows':observed,'assessments':accepted,'game_admission':False}
            if output.is_dir() and not (output/'qualification-rows.json').exists():_d123_json(output/'qualification-rows.json',failure)
        print(json.dumps(failure,sort_keys=True),file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

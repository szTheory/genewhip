#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run cleanup/host diagnostics under sticky process, signal, and native denial."""
from __future__ import annotations

import ctypes
import importlib.util
import json
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[2]
NATIVE_EVENTS = []


def load_sticky_denial():
    path = ROOT / "tests/evidence/phase7_sticky_denial.py"
    spec = importlib.util.spec_from_file_location("gw_phase7_diagnostic_sticky", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("sticky-denial-import-unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def deny_native(event, args):
    if event in ("ctypes.dlopen", "ctypes.dlsym"):
        NATIVE_EVENTS.append(event)
        raise PermissionError("sticky-native-load-denial")


def native_self_test():
    before = len(NATIVE_EVENTS)
    try:
        ctypes.CDLL("/__gw_diagnostic_native_denial_probe__")
    except PermissionError as error:
        if str(error) != "sticky-native-load-denial" or NATIVE_EVENTS[before:] != ["ctypes.dlopen"]:
            raise AssertionError("native-denial-self-test-wrong-boundary") from error
    else:
        raise AssertionError("native-denial-self-test-not-reached")


def main():
    sticky = load_sticky_denial()
    sticky.install()
    # Both audit hooks precede production imports and remain installed when
    # the fake boundaries are restored after the regression checks.
    sys.addaudithook(deny_native)
    native_self_test()
    runpy.run_path(str(ROOT / "tests/evidence/phase7_cleanup_diagnostic_contract.py"),
                   run_name="__main__")
    runpy.run_path(str(ROOT / "tests/evidence/phase7_host_failure_diagnostic_contract.py"),
                   run_name="__main__")
    sticky.self_test("after-diagnostic-contracts")
    native_self_test()
    process_receipt = sticky.receipt()
    if (process_receipt["unexpected_denials"] != 0 or process_receipt["real_child_starts"] != 0
            or NATIVE_EVENTS != ["ctypes.dlopen", "ctypes.dlopen"]):
        raise AssertionError("diagnostic-denial-receipt-invalid")
    print("GENEWHIP_DIAGNOSTIC_AUDIT:" + json.dumps({
        "process": process_receipt,
        "native_denials": len(NATIVE_EVENTS),
        "unexpected_native_events": 0,
    }, sort_keys=True))


if __name__ == "__main__":
    main()

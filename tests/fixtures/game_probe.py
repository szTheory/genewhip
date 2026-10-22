#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture and verify the actual, pre-repair independent-game stop."""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / "fixtures/independent-game/scenario.json"
ROM = ROOT / "fixtures/independent-game/game.bin"
CAPACITY = 256
TIMEOUT = 120


class ProbeValidationError(ValueError):
    """A named rejection from the guest-instruction evidence contract."""


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha(path: Path) -> str:
    return sha(path.read_bytes())


def build_identity(build: Path) -> dict:
    cache = build / "CMakeCache.txt"
    if not cache.is_file():
        raise ValueError("CMake build cache missing")
    keys = ("CMAKE_BUILD_TYPE", "CMAKE_C_COMPILER_ID", "CMAKE_C_COMPILER_VERSION",
            "CMAKE_GENERATOR", "GENEWHIP_TEST_HOOKS", "GENEWHIP_BUILD_DESKTOP")
    settings = {}
    for line in cache.read_text(errors="replace").splitlines():
        for key in keys:
            if line.startswith(key + ":"):
                settings[key] = line.split("=", 1)[-1]
    return {"cmake_cache_sha256": file_sha(cache), "settings": settings,
            "host": {"system": platform.system(), "machine": platform.machine()}}


def input_log(scenario: dict, path: Path) -> None:
    buttons = {"Start": 128, "Right": 8, "Left": 4, "Up": 1, "Down": 2,
               "A": 64, "B": 16, "C": 32}
    held = [0, 0]
    lines = ["genewhip-input-log 1"]
    for entry in sorted(scenario["input_schedule"], key=lambda item: item["frame"]):
        port_name, _, button = entry["control"].partition(" ")
        if port_name not in ("P1", "P2") or button not in buttons:
            raise ValueError("scenario contains an unknown controller event")
        port = int(port_name[1]) - 1
        if entry["asserted"]:
            held[port] |= buttons[button]
        else:
            held[port] &= ~buttons[button]
        lines.append(f"{entry['frame'] * 896040} pad {port} {held[port]:x}")
    path.write_text("\n".join(lines) + "\n")


def decode_instruction_access(rom: bytes, trace_row: dict, terminal_state: dict) -> dict:
    """Decode the captured MOVE.L immediate into its ordered 68000 bus words."""
    pc, opcode = trace_row["pc"], trace_row["opcode"]
    if opcode != 0x22bc:
        raise ProbeValidationError("unexpected-terminal-opcode")
    if pc < 0 or pc + 6 > len(rom):
        raise ProbeValidationError("instruction-outside-rom")
    if int.from_bytes(rom[pc:pc + 2], "big") != opcode:
        raise ProbeValidationError("rom-opcode-disagrees-with-trace")
    immediate = int.from_bytes(rom[pc + 2:pc + 6], "big")
    address_register = (opcode >> 9) & 7
    address = terminal_state["a"][address_register] & 0xffffff
    transactions = [
        {"address": address, "value": (immediate >> 16) & 0xffff, "width_bits": 16},
        {"address": (address + 2) & 0xffffff, "value": immediate & 0xffff, "width_bits": 16},
    ]
    return {
        "instruction": "MOVE.L #$C0000010,(A1)", "instruction_pc": pc,
        "opcode": opcode, "effective_address": address, "width_bits": 32,
        "bus_transactions": transactions, "faulting_transaction": transactions[1],
        "prior_vdp_control_latch": (
            "latch_pending=true after first word $C000; failing second word $0010 "
            "clears the latch before unsupported command-code rejection"),
    }


def validate_decoded_access(access: dict) -> None:
    transactions = access.get("bus_transactions")
    if not isinstance(transactions, list) or len(transactions) != 2:
        raise ProbeValidationError("longword-transaction-count-mismatch")
    first, second = transactions
    if second.get("address") != ((first.get("address", -2) + 2) & 0xffffff):
        raise ProbeValidationError("second-word-address-mismatch")
    if any(row.get("width_bits") != 16 for row in transactions):
        raise ProbeValidationError("second-word-width-mismatch")
    if (first.get("address") != 0xc00004 or first.get("value") != 0xc000 or
            second.get("address") != 0xc00006 or second.get("value") != 0x10):
        raise ProbeValidationError("decoded-vdp-transaction-mismatch")
    if access.get("faulting_transaction") != second:
        raise ProbeValidationError("faulting-transaction-side-effect-mismatch")
    if access.get("prior_vdp_control_latch") != (
            "latch_pending=true after first word $C000; failing second word $0010 "
            "clears the latch before unsupported command-code rejection"):
        raise ProbeValidationError("vdp-control-latch-side-effect-mismatch")
    if (access.get("instruction") != "MOVE.L #$C0000010,(A1)" or
            access.get("width_bits") != 32 or access.get("effective_address") != 0xc00004):
        raise ProbeValidationError("decoded-instruction-contract-mismatch")


def validate_capture_readback(record: dict, actual: dict) -> None:
    captured_access, actual_access = record.get("decoded_access"), actual.get("decoded_access")
    if not isinstance(captured_access, dict) or not isinstance(actual_access, dict):
        raise ProbeValidationError("decoded-access-missing")
    validate_decoded_access(captured_access)
    validate_decoded_access(actual_access)
    for key in ("schema", "classification", "identities", "execution", "trace", "decoded_access"):
        if record.get(key) != actual.get(key):
            raise ProbeValidationError("capture-readback-mismatch:" + key)


def execute(build: Path) -> dict:
    runner = (build / "tools/session/gw_headless").resolve()
    if not runner.is_file():
        raise ValueError("built gw_headless executable missing")
    scenario = json.loads(SCENARIO.read_text())
    if file_sha(ROM) != scenario["rom"]["sha256"]:
        raise ValueError("historical v1 ROM digest changed")
    with tempfile.TemporaryDirectory(prefix="gw-game-probe-") as td:
        temp = Path(td)
        replay, trace = temp / "input.log", temp / "instructions.jsonl"
        input_log(scenario, replay)
        input_digest = file_sha(replay)
        command = [str(runner), str(ROM), "--fields", str(scenario["budget"]["frames"]),
                   "--replay", str(replay), "--port-device", "pad3", "pad3", "--peek",
                   scenario["oracle"]["address"], "2", "--dump-instruction-trace", str(trace)]
        result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=TIMEOUT, check=False)
        output = result.stdout.decode("utf-8", errors="strict")
        final_lines = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
        final = next((row for row in reversed(final_lines) if "unsupported" in row), None)
        if final is None or not trace.is_file():
            raise ValueError("runner output has no final stop record or instruction trace")
        records = [json.loads(line) for line in trace.read_text().splitlines()]
        if len(records) < 2 or "count" not in records[-1] or "state" not in records[-1]:
            raise ValueError("instruction trace is incomplete")
        trailer = records.pop()
        if trailer["count"] != len(records) or trailer["dropped"] != 0 or len(records) > CAPACITY:
            raise ValueError("instruction trace overflow or denominator mismatch")
        matching = [row for row in records if row["stop_reason"] == final["stop_reason"]]
        if len(matching) != 1:
            raise ValueError("instruction trace does not uniquely contain the terminal stop")
        stop = matching[0]
        pc, opcode = final["instruction_address"], final["opcode"]
        if stop["pc"] != pc or stop["opcode"] != opcode or stop["fault_address"] != final["fault_address"]:
            raise ValueError("final stop and instruction trace disagree")
        state = trailer["state"]
        decoded_access = decode_instruction_access(
            ROM.read_bytes(), stop, state)
        validate_decoded_access(decoded_access)
        ea = decoded_access["effective_address"]
        if result.returncode not in (0, 1):
            raise ValueError("runner exited with unexpected infrastructure status")
        if final["stop_reason"] != 3 or final["fault_address"] != 0xc00006 or ea != 0xc00004:
            raise ValueError("actual guest did not reproduce the classified VDP longword stop")
        return {
            "schema": "genewhip-game-probe-v1", "classification": "reproduced",
            "identities": {"source_base_revision": subprocess.check_output(
                ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
                "source_files_sha256": sha("".join(file_sha(ROOT / p) for p in
                    ("src/bus.c", "src/vdp.c", "src/cpu68000.c", "tools/headless/main.c")).encode()),
                "probe_script_sha256": file_sha(Path(__file__)), "runner_sha256": file_sha(runner),
                "configuration": build_identity(build), "rom_sha256": file_sha(ROM),
                "scenario_sha256": file_sha(SCENARIO), "profile": scenario["machine"]["profile"],
                "scenario_id": scenario["scenario_id"]},
            "execution": {"command": ["build/phase4/tools/session/gw_headless", "fixtures/independent-game/game.bin",
                "--fields", str(scenario["budget"]["frames"]), "--replay", "<temporary scenario input log>",
                "--port-device", "pad3", "pad3", "--peek", scenario["oracle"]["address"], "2",
                "--dump-instruction-trace", "<temporary JSONL>"], "exit_code": result.returncode,
                "stdout_sha256": sha(result.stdout), "stderr_sha256": sha(result.stderr),
                "scenario_input_sha256": input_digest,
                "stop": final},
            "trace": {"capacity": CAPACITY, "rows": records, "count": len(records),
                "dropped": trailer["dropped"], "terminal_state": state},
            "decoded_access": decoded_access}


def self_test() -> None:
    # Independent bytes and trace/register records exercise the same decoder and
    # readback validator that execute()/verify() use on real guest evidence.
    pc, opcode, immediate = 0x40, 0x22bc, 0xc0000010
    rom = bytes(pc) + opcode.to_bytes(2, "big") + immediate.to_bytes(4, "big") + bytes(32)
    trace = {"pc": pc, "opcode": opcode}
    terminal_state = {"a": [0, 0xc00004, 0, 0, 0, 0, 0, 0]}
    decoded = decode_instruction_access(rom, trace, terminal_state)
    actual = {"schema": "probe-test", "classification": "reproduced",
              "identities": {}, "execution": {}, "trace": {}, "decoded_access": decoded}
    validate_capture_readback(actual, actual)

    mutations = (
        ("second-word-address", lambda row: row["bus_transactions"][1].update(address=0xc00008),
         "second-word-address-mismatch"),
        ("second-word-width", lambda row: row["bus_transactions"][1].update(width_bits=8),
         "second-word-width-mismatch"),
        ("latch-side-effect", lambda row: row.update(prior_vdp_control_latch="unchanged"),
         "vdp-control-latch-side-effect-mismatch"),
    )
    for name, mutate, expected_error in mutations:
        captured = json.loads(json.dumps(actual))
        mutate(captured["decoded_access"])
        try:
            validate_capture_readback(captured, actual)
        except ProbeValidationError as exc:
            if str(exc) != expected_error:
                raise AssertionError(f"{name}: expected named rejection {expected_error}, got {exc}") from exc
        else:
            raise AssertionError(f"{name}: mutated capture passed production readback validation")
    print("game_probe self-test: PASS (production decoder/readback; address, width, and latch mutations rejected by named checks)")


def verify(record_path: Path, build: Path) -> None:
    record = json.loads(record_path.read_text())
    actual = execute(build)
    validate_capture_readback(record, actual)
    print("game_probe capture verification: PASS (current-source guest reproduced exact terminal transaction)")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--capture", action="store_true")
    parser.add_argument("--verify-capture")
    parser.add_argument("--build")
    parser.add_argument("--out")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            return 0
        if not args.build:
            raise ValueError("--build is required")
        if args.capture:
            if not args.out:
                raise ValueError("--out is required with --capture")
            output = Path(args.out)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(execute(Path(args.build).resolve()), indent=2, sort_keys=True) + "\n")
            print("game_probe capture written: " + output.as_posix())
            return 0
        if args.verify_capture:
            verify(Path(args.verify_capture), Path(args.build).resolve())
            return 0
        raise ValueError("select --self-test, --capture or --verify-capture")
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.TimeoutExpired,
            subprocess.CalledProcessError) as exc:
        print("BLOCKED: " + str(exc), file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

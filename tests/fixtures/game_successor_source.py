#!/usr/bin/env python3
"""Validate frozen successor scenarios against authored source, before capture."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures/independent-game-v2"
SOURCE = FIXTURE / "src/game.s"
SCENARIO = FIXTURE / "scenario.json"
ORACLE = FIXTURE / "oracle.json"
EXPECTED = ["title-no-start", "start-idle", "start-move", "action-sound", "action-no-trigger", "sustained-play"]
SOUND = [132, 2, 144]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(source: str, scenario: dict, oracle: dict) -> None:
    cases = scenario.get("cases")
    if not isinstance(cases, list) or [c.get("id") for c in cases] != EXPECTED:
        raise ValueError("scenario-roster")
    if scenario.get("fixture_id") != "genewhip-independent-game-v2" or scenario.get("profile") != "VA3-NTSC-U":
        raise ValueError("scenario-profile")
    if scenario.get("source", {}).get("sha256") != sha(SOURCE):
        raise ValueError("scenario-source-identity")
    if oracle.get("source_sha256") != sha(SOURCE) or oracle.get("case_ids") != EXPECTED:
        raise ValueError("oracle-source-identity")
    mode = oracle.get("observations", {}).get("video_mode", {})
    if (mode.get("register") != 1 or mode.get("mode5_bit") != 2
            or mode.get("display_enable_bit") != 6
            or mode.get("primary_source") != "SEGA Genesis Software Manual, Addendum 4, section 2, compiled PDF page 18"
            or mode.get("primary_claim") != "The Genesis mode is active when Register #1's bit 2=1."
            or mode.get("primary_source_url") != "https://device.report/m/55cc8ed622c4bb453d08032a76b03b32ee4e41a5f3c09382b5fecdd0afe6268d.pdf#page=18"):
        raise ValueError("mode5-primary-source")
    register_one_values = [int(value, 16) for value in re.findall(
        r"move\.w\s+#0x([0-9a-f]{4}),\s*\(%a1\)", source, re.IGNORECASE
    ) if int(value[:2], 16) == 0x81]
    if not register_one_values:
        raise ValueError("mode5-register-write")
    mode5_enabled = False
    display_enabled = False
    for value in register_one_values:
        if value & 0x04:
            mode5_enabled = True
        if value & 0x40:
            display_enabled = True
            if not mode5_enabled:
                raise ValueError("mode5-bit")
    if not display_enabled:
        raise ValueError("mode5-display-enable")
    ancestry = oracle.get("ancestry", "").lower()
    if "derived from genewhip output" in ancestry or "trace-derived" in ancestry:
        raise ValueError("oracle-ancestry")
    required = ("title_wait:", "btst    #5,%d0", "move.w  #1,0x00ff0000",
                "0x00ff0002", "btst    #3,%d0", "move.w  #2,(%a0)",
                "btst    #4,%d0", "move.b  #0x84,0x00c00011",
                "move.b  #0x02,0x00c00011", "move.b  #0x90,0x00c00011",
                "0x40200000", "0x40400000", "0x40000003", "0x42000003",
                "0xc0000000", "0xc0020000", "0xc0040000", "swap    %d1")
    if any(fragment not in source for fragment in required):
        raise ValueError("source-contract")
    if any(fragment in source for fragment in ("0x40030000", "0x40030200", "0x40000080", "0x400000c0", "0xc0000008", "0xc0000010")):
        raise ValueError("vdp-command-encoding")
    forbidden = re.compile(r"(?:0x)?(?:00200000|00a130f0|00a130f1)\b", re.I)
    if forbidden.search(source):
        raise ValueError("cartridge-storage-reference")
    if not (scenario.get("budget", {}).get("max_trace_bytes", 0) <= 2_250_000_000
            and scenario.get("budget", {}).get("max_trace_rows", 0) <= 36_000_000
            and scenario.get("budget", {}).get("hard_timeout_seconds", 0) <= 600):
        raise ValueError("budget")
    sustained = scenario.get("sustained_policy", {})
    if (sustained.get("warmup_fields") != 120 or sustained.get("measured_fields") != 600
            or sustained.get("minimum_total_fields_per_fresh_run") < 720
            or sustained.get("scenario_id") != "sustained-play"):
        raise ValueError("sustained-protocol")
    for case in cases:
        ident, frames = case["id"], case.get("frames", 0)
        events = case.get("input_schedule")
        expect = case.get("expect", {})
        if not 1 <= frames <= 720 or not isinstance(events, list):
            raise ValueError("case-budget:" + ident)
        previous = 0
        held = {}
        for event in events:
            if event.get("control") not in {"P1 Start", "P1 Left", "P1 Right", "P1 B"}:
                raise ValueError("input-control:" + ident)
            if not previous < event.get("frame", 0) <= frames or not isinstance(event.get("asserted"), bool):
                raise ValueError("input-order:" + ident)
            if held.get(event["control"]) == event["asserted"]:
                raise ValueError("input-no-edge:" + ident)
            held[event["control"]] = event["asserted"]
            previous = event["frame"]
        should_start = any(e["control"] == "P1 Start" and e["asserted"] for e in events)
        if expect.get("play_state") != int(should_start):
            raise ValueError("start-oracle:" + ident)
        sound_trigger = any(e["control"] == "P1 B" and e["asserted"] for e in events)
        if expect.get("psg_writes") != (SOUND if sound_trigger else []):
            raise ValueError("sound-oracle:" + ident)
        geometry = expect.get("geometry", {})
        if geometry.get("title_row", {}).get("start") != 0xC000 or geometry.get("title_row", {}).get("cells") != 10:
            raise ValueError("geometry-oracle:" + ident)
        marker = geometry.get("marker", {})
        if marker.get("address") != 0xC280:
            raise ValueError("geometry-oracle:" + ident)
        if ident == "title-no-start":
            if marker.get("present") is not False or geometry["title_row"].get("tile") != 1:
                raise ValueError("geometry-oracle:" + ident)
        elif marker.get("tile") != 2 or geometry["title_row"].get("tile") != 0:
            raise ValueError("geometry-oracle:" + ident)
    by_id = {c["id"]: c for c in cases}
    if by_id["title-no-start"]["expect"]["play_state"] != 0:
        raise ValueError("title-no-start-control")
    if any(by_id[i]["expect"]["psg_writes"] for i in ("title-no-start", "start-idle", "start-move", "action-no-trigger")):
        raise ValueError("no-trigger-contamination")
    if by_id["action-sound"]["expect"]["psg_writes"] != SOUND:
        raise ValueError("action-sound-control")
    if by_id["sustained-play"]["frames"] < 720:
        raise ValueError("sustained-fields")


def self_test(source: str, scenario: dict, oracle: dict) -> int:
    cases = [
        ("unrelated sound/nonzero baseline", lambda h: h["scenario"]["cases"][0]["expect"].update(psg_writes=[0]), "sound-oracle:title-no-start"),
        ("absent Start", lambda h: h.update(source=h["source"].replace("btst    #5,%d0", "btst    #6,%d0")), "source-contract"),
        ("missing movement", lambda h: h.update(source=h["source"].replace("btst    #3,%d0", "btst    #7,%d0")), "source-contract"),
        ("no-trigger contamination", lambda h: h["scenario"]["cases"][4]["expect"].update(psg_writes=SOUND), "sound-oracle:action-no-trigger"),
        ("changed input schedule", lambda h: h["scenario"]["cases"][1]["input_schedule"].reverse(), "input-order:start-idle"),
        ("incorrect VDP command-half offset", lambda h: h.update(source=h["source"].replace("swap    %d1", "nop")), "source-contract"),
        ("cleared Mode 5 bit", lambda h: h.update(source=h["source"].replace("0x8144", "0x8140")), "mode5-bit"),
    ]
    for name, mutate, expected in cases:
        changed_source, changed_scenario, changed_oracle = source, copy.deepcopy(scenario), copy.deepcopy(oracle)
        mutate_holder = {"source": changed_source, "scenario": changed_scenario, "oracle": changed_oracle}
        mutate(mutate_holder)
        try:
            validate(mutate_holder["source"], mutate_holder["scenario"], mutate_holder["oracle"])
        except ValueError as exc:
            if str(exc) != expected:
                raise ValueError(f"{name}: expected {expected}, got {exc}") from exc
        else:
            raise ValueError(f"{name}: mutation was accepted")
    print(f"PASS: {len(cases)} named source/oracle/schedule mutations rejected for their intended reasons")
    return 0


class Mode5SourceContractTests(unittest.TestCase):
    def test_rejects_display_enabled_without_mode5(self) -> None:
        source = SOURCE.read_text()
        scenario = json.loads(SCENARIO.read_text())
        oracle = json.loads(ORACLE.read_text())
        source = source.replace("0x8144", "0x8140")
        with self.assertRaisesRegex(ValueError, "mode5-bit"):
            validate(source, scenario, oracle)


def main() -> int:
    source = SOURCE.read_text()
    scenario = json.loads(SCENARIO.read_text())
    oracle = json.loads(ORACLE.read_text())
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test(source, scenario, oracle)
    validate(source, scenario, oracle)
    print(json.dumps({"status":"pass","source_sha256":sha(SOURCE),"scenario_sha256":sha(SCENARIO),"oracle_sha256":sha(ORACLE),"cases":len(EXPECTED),"sustained_fields":720,"outcomes":"source-derived oracle frozen; MAME reference measured separately; Genewhip compatibility remains unqualified"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        raise SystemExit(1)

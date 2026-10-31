#!/usr/bin/env python3
"""Compile frozen Phase 5 route identities and validate Phase 6 outcome reports."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import struct
import tarfile
import math
import array
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
READER_PROVENANCE_PATHS = ("scripts/evidence/phase6_routes.py", "tests/fixtures/phase6_game.py",
                          "tests/session/phase6_route_contract.py")
PINNED_BASELINE_SHA256 = "e044daa65a617d3a1e3cd32a877bf40c2f9b3fad21fef1241f6335e4d7516209"
PINNED_ROSTER_SHA256 = "4dc108e8c936eb0a4af9f8a8fdabbaab0a2be6e90397b10f4f1bbbcbf0f62a58"
PINNED_REFERENCE_SHA256 = "d1295806831a0d20586e83a75fd1f86ee52d543d27fe900cf6d79cf230e064bc"
SOURCES = {
    "tank-battle": ("fixtures/phase5-a/scenario.json", "fixtures/phase5-a/oracle.json", "fixtures/phase5-a/input-program.json", "fixtures/phase5-a/game.bin"),
    "recursion94": ("fixtures/phase5-b/scenario.json", "fixtures/phase5-b/oracle.json", "fixtures/phase5-b/input-program.json", "fixtures/phase5-b/game.bin"),
    "genewhip-independent-game-v2": ("fixtures/independent-game-v2/scenario.json", "fixtures/independent-game-v2/oracle.json", "fixtures/independent-game-v2/host-controls.json", "fixtures/independent-game-v2/game.bin"),
}
STATUSES = {"pass", "fail", "unsupported", "skipped", "unknown", "infrastructure-error"}
STAGES = ("load", "boot", "interaction", "sustained", "completion")
BUTTONS = {"Up": 1, "Down": 2, "Left": 4, "Right": 8, "B": 16, "C": 32, "A": 64, "Start": 128}
TEST_FIXTURE_BASELINE_AUTHORITY = None


class Invalid(ValueError):
    pass


def load(path: pathlib.Path):
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _expected_baseline() -> tuple[str, str, str]:
    """Fixture identities require explicit authority on a retained authored root.

    The normal compiler has exactly the original frozen identities. This seam
    changes expected bytes only; baseline/link/reference predicates remain real.
    It cannot be activated by fixture files or environment variables alone.
    """
    authority = TEST_FIXTURE_BASELINE_AUTHORITY
    if authority is None:
        return PINNED_BASELINE_SHA256, PINNED_ROSTER_SHA256, PINNED_REFERENCE_SHA256
    root = ROOT.resolve(strict=True)
    checkout = next((p for p in root.parents if (p / ".git").exists()), None)
    if (checkout is None or root == checkout or
            not root.is_relative_to(checkout / "build/phase6/d125-debug") or
            not root.name.startswith("synthetic-consumer-") or
            not isinstance(authority, dict) or set(authority) != {
                "schema", "test_fixture_only", "root", "baseline_sha256", "roster_sha256", "reference_sha256"} or
            authority.get("schema") != "d125-authored-baseline-v1" or
            authority.get("test_fixture_only") is not True or authority.get("root") != str(root)):
        raise Invalid("test-fixture-baseline-authority-denied")
    marker = root / "metadata/d125-authored-root.json"
    if marker.is_symlink() or load(marker) != {"schema": "d125-authored-root-v1", "test_fixture_only": True}:
        raise Invalid("test-fixture-root-marker-invalid")
    ledger = load(root / "evidence/phase6-repairs.json")
    terminal_fixture_policies = {
        "d124_recovery_policy": {"status": "halted-scope-breach", "test_fixture_only": True},
        "d125_recovery_policy": {"status": "terminal-halted-containment-acceptance-failure", "test_fixture_only": True}}
    if ledger.get("test_fixture_only") is not True or any(
            key in ledger and (not ledger.get("d125_owner_generations") or ledger[key] != terminal_fixture_policies.get(key))
            for key in ("d123_recovery_policy", "d124_recovery_policy", "d125_recovery_policy")):
        raise Invalid("test-fixture-production-policy-denied")
    owners = ledger.get("d125_owner_generations", [])
    if owners and any(g.get("test_fixture_only") is not True for g in owners):
        raise Invalid("test-fixture-production-owner-denied")
    values = tuple(authority[key] for key in ("baseline_sha256", "roster_sha256", "reference_sha256"))
    if any(not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value)
           for value in values):
        raise Invalid("test-fixture-baseline-digest-invalid")
    return values


def trusted_baseline() -> tuple[dict, dict]:
    baseline_sha, roster_sha, reference_sha = _expected_baseline()
    baseline = load(ROOT / "evidence/phase5-baseline.json")
    roster = load(ROOT / "evidence/phase5-baseline-roster.json")
    inventory = load(ROOT / "evidence/phase5-failure-inventory.json")
    current = load(ROOT / "evidence/phase5-current-reference.json")
    reference_path = ROOT / current["report"]["path"]
    if canonical_digest(baseline) != baseline_sha or canonical_digest(roster) != roster_sha:
        raise Invalid("production-baseline-identity")
    if baseline.get("roster_sha256") != roster_sha or inventory.get("baseline_sha256") != baseline_sha:
        raise Invalid("production-admission-link")
    if inventory.get("baseline_roster_sha256") != roster_sha:
        raise Invalid("production-roster-link")
    if (current.get("status") != "qualified-pair" or current.get("decision") != "D-118" or
            current.get("report", {}).get("sha256") != reference_sha or
            digest(reference_path) != reference_sha):
        raise Invalid("current-reference-identity")
    if inventory.get("reference_report_sha256") != reference_sha:
        raise Invalid("failure-inventory-reference-link")
    return roster, inventory


def validate_delivery_map(delivery_map: dict, route: dict | None = None, client: str = "public-core") -> dict:
    """Validate the explicitly selected source-consumed Recursion94 map."""
    if not isinstance(delivery_map, dict) or delivery_map.get("schema") != "genewhip-consumed-input-map-v1":
        raise Invalid("delivery-map-schema")
    if delivery_map.get("version") != 1:
        raise Invalid("delivery-map-version")
    if delivery_map.get("map_id") != "recursion94-genewhip-public-client-v1" or delivery_map.get("consumer") != "genewhip-public-core-and-sdl-route-v1":
        raise Invalid("delivery-map-client")
    if client not in ("public-core", "sdl"):
        raise Invalid("delivery-map-client")
    input_path = ROOT / "fixtures/phase5-b/input-program.json"
    if delivery_map.get("source", {}).get("input_program_sha256") != digest(input_path):
        raise Invalid("delivery-map-source-identity")
    source = delivery_map.get("source", {})
    for key, relative in (("scenario_sha256", "fixtures/phase5-b/scenario.json"),
                          ("rom_sha256", "fixtures/phase5-b/game.bin"),
                          ("oracle_sha256", "fixtures/phase5-b/oracle.json"),
                          ("d118_sha256", "evidence/phase5-reference-d118.json")):
        if source.get(key) != digest(ROOT / relative):
            raise Invalid("delivery-map-source-identity")
    program = load(input_path)
    rows = delivery_map.get("events")
    if not isinstance(rows, list) or len(rows) != 19:
        raise Invalid("delivery-map-event-count")
    expected = program.get("events", [])
    if len(expected) != 19:
        raise Invalid("delivery-map-source-event-count")
    effective_mask = 0
    for index, (row, event) in enumerate(zip(rows, expected), 1):
        if not isinstance(row, dict) or row.get("order") != index or row.get("original_event_index") != index or row.get("event_id") != f"input-event-{index:02d}":
            raise Invalid("delivery-map-order")
        for key in ("control", "asserted", "cases"):
            if row.get(key) != event.get(key):
                raise Invalid(f"delivery-map-source-row:{index}")
        target = row.get("source_target")
        if not isinstance(target, dict) or any(target.get(key) != event.get(key) for key in ("attempt", "tick", "field", "state")):
            raise Invalid(f"delivery-map-source-clock:{index}")
        dispatch, consumed = row.get("consumer_dispatch"), row.get("consumed")
        if event["control"] == "P1 C":
            expected_dispatch = {"clock":"paused-ui-state", "attempt":event["attempt"],
                "tick":event["tick"], "state":event["state"], "dispatch_boundary":"completed-field-or-source-marker"}
            expected_consumed = {"clock":"paused-ui-meta", "attempt":event["attempt"],
                "tick":event["tick"], "state":event["state"],
                "completed_source_steps":(event["attempt"] + int(event["state"] == "terminal")) * 720}
            if dispatch != expected_dispatch or consumed != expected_consumed:
                raise Invalid(f"delivery-map-paused-meta:{index}")
        else:
            expected_tick = 696 if index == 19 else event["tick"]
            expected_consumed = 697 if index == 19 else (2 if event["tick"] == 0 else event["tick"] + 1)
            if dispatch != {"clock": "source-step", "attempt": event["attempt"], "tick": expected_tick} or consumed != {"attempt": event["attempt"], "tick": expected_consumed}:
                raise Invalid(f"delivery-map-consumption:{index}")
        if row.get("clock_kind") != ("paused-ui-state" if event["control"] == "P1 C" else "gameplay-source-step"):
            raise Invalid(f"delivery-map-clock-kind:{index}")
        if row.get("source_locator", {}).get("sha256") != digest(input_path) or row.get("source_locator", {}).get("event_order") != index:
            raise Invalid(f"delivery-map-source-locator:{index}")
        if row.get("evidence_class") not in ("retained-observation", "independent-source-derivation", "new-client-observation"):
            raise Invalid(f"delivery-map-evidence-class:{index}")
        schedule = row.get("scheduled_client_point", {}).get(client)
        if schedule != dispatch or schedule.get("clock") != ("paused-ui-state" if event["control"] == "P1 C" else "source-step"):
            raise Invalid(f"delivery-map-client-schedule:{index}")
        bit = BUTTONS[event["control"].split(" ", 1)[1]]
        effective_mask = effective_mask | bit if event["asserted"] else effective_mask & ~bit
        if type(row.get("effective_mask")) is not int or row["effective_mask"] != effective_mask:
            raise Invalid(f"delivery-map-effective-mask:{index}")
        if row.get("expected_guest_poll") != consumed:
            raise Invalid(f"delivery-map-expected-poll:{index}")
        hold_end = {"attempt": 4, "tick": 720} if index == 19 else {"next_event_id": f"input-event-{index + 1:02d}"}
        release = {"cleanup": True} if index == 19 else {"at_next_declared_transition": True}
        if row.get("hold_end") != hold_end:
            raise Invalid(f"delivery-map-hold:{index}")
        if row.get("release_boundary") != release:
            raise Invalid(f"delivery-map-release:{index}")
        if not isinstance(row.get("unknowns"), list):
            raise Invalid(f"delivery-map-unknowns:{index}")
    if delivery_map.get("cleanup_release", {}).get("event_row") is not False:
        raise Invalid("delivery-map-cleanup-is-event")
    if route is not None:
        scenario_path=ROOT/SOURCES["recursion94"][0]
        scenario=load(scenario_path)
        admitted_case_ids={case.get("id") for case in scenario.get("cases",[]) if isinstance(case,dict)}
        if (route.get("fixture") != "recursion94" or
                route.get("case", {}).get("id") not in admitted_case_ids):
            raise Invalid("delivery-map-route")
    return delivery_map


def compile_routes(delivery_map: dict | None = None, client: str = "public-core") -> dict:
    routes = []
    seen = set()
    baseline_roster, failure_inventory = trusted_baseline()
    admitted_cases = {(row["fixture_id"], row["case_id"]): row for row in baseline_roster["cases"]}
    for fixture, paths in SOURCES.items():
        scenario_path, oracle_path, input_path, rom_path = map(lambda p: ROOT / p, paths)
        scenario, oracle, program = load(scenario_path), load(oracle_path), load(input_path)
        if fixture != "genewhip-independent-game-v2":
            identity = scenario.get("identities", {})
            reference = load(ROOT / f"{pathlib.Path(paths[0]).parent}/reference-build-record.json")
            fixture_id = f"genewhip-phase5-{'a' if fixture == 'tank-battle' else 'b'}"
            admitted = [row for row in failure_inventory["records"] if row.get("fixture_id") == fixture_id]
            if len(admitted) == 0 or any(
                row.get("title_id") != fixture or row.get("rom_sha256") != identity.get("rom_sha256") or
                row.get("scenario_sha256") != reference.get("scenario_sha256")
                for row in admitted
            ):
                raise Invalid(f"admission-identity:{fixture}")
            if digest(scenario_path) != reference.get("scenario_sha256"):
                raise Invalid(f"changed-digest:{fixture}:scenario")
            if digest(input_path) != reference.get("input_program_sha256"):
                raise Invalid(f"changed-digest:{fixture}:input")
            if digest(rom_path) != identity.get("rom_sha256"):
                raise Invalid(f"changed-digest:{fixture}:rom")
            cases = scenario.get("cases", [])
            if not isinstance(cases, list):
                raise Invalid(f"invalid-cases:{fixture}")
            active_clock = scenario.get("active_clock")
            render_when = scenario.get("render_when", scenario.get("render_field"))
            controls = scenario.get("controls", [])
            thresholds = oracle
            source = scenario
        else:
            cases = scenario.get("cases", [])
            active_clock = scenario.get("sustained_policy", {})
            render_when = None
            controls = load(ROOT / "fixtures/independent-game-v2/host-controls.json")
            thresholds = oracle
            source = scenario
        for case in cases:
            case_id = case.get("id")
            key = (fixture, case_id)
            if not case_id or key in seen:
                raise Invalid(f"duplicate-case:{fixture}:{case_id}")
            seen.add(key)
            admission_id = "genewhip-independent-game-v2" if fixture == "genewhip-independent-game-v2" else fixture_id
            admission = admitted_cases.get((admission_id, case_id))
            if admission is None:
                raise Invalid(f"unadmitted-case:{fixture}:{case_id}")
            if digest(scenario_path) != admission["scenario"]["sha256"] or \
                    digest(rom_path) != admission["rom"]["sha256"]:
                raise Invalid(f"admission-digest:{fixture}:{case_id}")
            if fixture != "genewhip-independent-game-v2" and digest(input_path) != admission["route_input_program"]["sha256"]:
                raise Invalid(f"admission-input-digest:{fixture}:{case_id}")
            expected_oracle = admission.get("expectation_ref", {}).get("oracle_sha256")
            if expected_oracle is None:
                expected_oracle = admission.get("oracle", {}).get("sha256")
            if expected_oracle and digest(oracle_path) != expected_oracle:
                raise Invalid(f"admission-oracle-digest:{fixture}:{case_id}")
            case_oracle = thresholds if fixture != "genewhip-independent-game-v2" else admission["expectations"]
            definitions = {"case": case, "source_scenario": source,
                           "input_program": program, "oracle": case_oracle,
                           "controls": controls, "active_clock": active_clock,
                           "render_when": render_when,
                           "addresses": source.get("addresses", []),
                           "predicates": case_oracle.get("predicates", []) if isinstance(case_oracle, dict) else []}
            execution_blockers = _validate_definitions(definitions)
            routes.append({"fixture": fixture, "case": case, "definitions": definitions,
                           "admission": admission,
                           "active_clock": active_clock,
                           "execution_blockers": execution_blockers,
                           "identity": {"scenario_sha256": admission["scenario"]["sha256"],
                                        "oracle_sha256": expected_oracle,
                                        "input_sha256": admission.get("input_sha256"),
                                        "input_program_sha256": admission.get("route_input_program", {}).get("sha256", digest(input_path)),
                                        "rom_sha256": admission["rom"]["sha256"]}})
    if len(routes) != 12:
        raise Invalid(f"unexpected-case-count:{len(routes)}")
    return {"schema": "genewhip-phase6-route-roster-v1", "source_clock": "scenario-defined",
            "admission_roster_sha256": _expected_baseline()[1], "routes": routes}


def _validate_definitions(definitions: dict) -> list[str]:
    addresses = definitions.get("addresses", [])
    address_map = {}
    blockers = []
    for item in addresses:
        if not isinstance(item, dict) or not {"name", "address"} <= set(item):
            raise Invalid("source-address-schema")
        name, address = item["name"], item["address"]
        try:
            start = int(address, 16) if isinstance(address, str) else int(address)
        except (TypeError, ValueError) as error:
            raise Invalid("source-address-value") from error
        width = item.get("width", 1)
        if width in ("u8", 1):
            width_bytes = 1
        elif width in ("u16", 2):
            width_bytes = 2
        else:
            raise Invalid("source-address-width")
        endian = item.get("endian", "big")
        if endian not in ("big", "little") or start < 0 or start > 0xFFFFFFFF or start + width_bytes > 0x100000000:
            raise Invalid("source-address-range")
        # Fixture addresses describe the 68000's effective address. The core's
        # documented bus contract masks CPU addresses to 24 bits; retain that
        # source value and lower only the private tool read address here.
        bus_address = start & 0xFFFFFF
        if bus_address + width_bytes > 0x1000000:
            blockers.append(f"public-peek-address-wrap:{name}:{start:08X}:{width_bytes}")
        if name in address_map:
            raise Invalid("duplicate-source-address")
        address_map[name] = {"address": start, "bus_address": bus_address,
                             "normalization": "m68k-24bit-mask", "width": width_bytes,
                             "endian": endian}
    clock = definitions.get("active_clock")
    clock_names = {clock.get("name")} if isinstance(clock, dict) and clock.get("name") else set()
    for predicate in definitions.get("predicates", []):
        if not isinstance(predicate, dict) or not isinstance(predicate.get("field_window"), list) or len(predicate["field_window"]) != 2:
            raise Invalid("source-predicate-schema")
        low, high = predicate["field_window"]
        if (not isinstance(low, int) or not isinstance(high, int) or low < 0 or high < low or
                not isinstance(predicate.get("equals"), int) or
                predicate.get("signal") not in address_map and predicate.get("signal") not in clock_names):
            raise Invalid("source-predicate-value")
    return blockers


def control(value: str) -> tuple[int, int]:
    try:
        player, label = value.split(" ")
        if player not in ("P1", "P2"):
            raise ValueError()
        return int(player[1]) - 1, BUTTONS[label]
    except (AttributeError, ValueError, KeyError) as error:
        raise Invalid("source-control") from error


def encode_controller(header: list[int], sections: list[list[list[int]]]) -> bytes:
    """Numeric GWRC v1 encoder shared by the frozen compiler and authored tests.

    Native parsing is the independent structural validation boundary. This
    encoder does not accept JSON or infer expectations from observed execution.
    """
    if len(header) != 32 or len(sections) != 8:
        raise Invalid("controller-shape")
    words = list(header)
    for index, records in enumerate(sections):
        words[6 + index] = len(records)
    for records, width in zip(sections, (4, 2, 5, 2, 4, 3, 6, 4)):
        for record in records:
            if len(record) != width:
                raise Invalid("controller-record")
            words.extend(record)
    if sum(map(len, sections)) > 4096 or len(words) * 4 > 1048576:
        raise Invalid("controller-capacity")
    if any(type(word) is not int or not 0 <= word <= 0xFFFFFFFF for word in words):
        raise Invalid("controller-u32")
    words[0] = int.from_bytes(b"GWRC", "little")
    return struct.pack("<" + "I" * len(words), *words)


def lower_route(route: dict, boundary_call_limit: int = 1_000_000, delivery_map: dict | None = None,
                client: str = "public-core") -> tuple[bytes, dict]:
    """Lower frozen source clocks/controllers; no candidate setup or execution."""
    if type(boundary_call_limit) is not int or not 1 <= boundary_call_limit <= 100_000_000:
        raise Invalid("boundary-call-limit")
    definitions = route["definitions"]
    scenario, program, case = definitions["source_scenario"], definitions["input_program"], route["case"]
    if route["execution_blockers"]:
        raise Invalid("route-unexecutable")
    sections: list[list[list[int]]] = [[] for _ in range(8)]
    signals, markers, actions, steps, targets, conditions, events, predicates = sections
    names: dict[str, int] = {}
    metadata = {"identity": route["identity"], "signals": [], "markers": []}

    def signal(name: str, address, width=1, endian="big") -> int:
        if name in names:
            return names[name]
        source = int(address, 16) if isinstance(address, str) else address
        width = 2 if width in (2, "u16") else 1
        if type(source) is not int or not 0 <= source <= 0xFFFFFFFF or (source & 0xFFFFFF) + width > 0x1000000:
            raise Invalid("source-address-range")
        index = len(signals); names[name] = index
        signals.append([source, source & 0xFFFFFF, width, int(endian == "little")])
        metadata["signals"].append({"name": name, "source_address": source,
                                    "bus_address": source & 0xFFFFFF, "width": width, "endian": endian})
        return index

    for item in definitions["addresses"]:
        signal(item["name"], item["address"], item.get("width", 1), item.get("endian", "big"))
    header = [0] * 32
    header[1] = 1
    header[30] = boundary_call_limit
    if route["fixture"] == "genewhip-independent-game-v2":
        header[2] = 3; header[3] = header[4] = case["frames"]
        observations = load(ROOT / "fixtures/independent-game-v2/oracle.json")["observations"]
        header[14] = signal("play_state", observations["play_state"]["address"], 2)
        signal("position", observations["position"]["address"], 2)
        for event in case["input_schedule"]:
            port, bit = control(event["control"])
            events.append([0, event["frame"], 0, port, bit, int(event["asserted"])])
    else:
        clock = scenario["active_clock"]
        header[3] = scenario["budget"]["total_fields"]
        header[4] = scenario["budget"]["active_fields"]
        header[5] = scenario["budget"]["boot_fields"]
        header[19] = clock["active_value"]
        if clock["kind"] == "state-count":
            header[2] = 1; header[14] = names["game_state"]
            launch = program["launch"]
            header[21], header[22] = launch["field"], launch["release_after_fields"]
            header[23], header[24] = control(launch["press"])
            header[25], header[26] = 1, scenario["render_field"]

            def add_conditions(values: dict) -> tuple[int, int]:
                first = len(conditions)
                for name, value in values.items():
                    index, comparison = names.get(name), 0
                    if name == "active_ticks_gte": index, comparison = 0xFFFFFFFF, 1
                    if name == "active_ticks_lt": index, comparison = 0xFFFFFFFF, 2
                    if index is None:
                        raise Invalid("source-condition-signal")
                    conditions.append([index, comparison, value])
                return first, len(conditions) - first

            by_id = {action["id"]: action for action in program["actions"]}
            for action_id in program["cases"][case["id"]]:
                action = by_id[action_id]
                first_condition, condition_count = add_conditions(action["when"])
                first_step = len(steps)
                for step in action["steps"]:
                    first_target = len(targets)
                    for target in step["targets"]:
                        port, bit = control(target["control"])
                        first, count = add_conditions(target["until"])
                        targets.append([port, bit, first, count])
                    steps.append([first_target, len(targets) - first_target])
                actions.append([first_condition, condition_count, first_step, len(steps) - first_step, action["max_fields"]])
        elif clock["kind"] == "observed-completed-source-steps":
            header[2] = 2
            header[14] = signal("engine_state_word", clock["state_address"], 2)
            header[15] = signal("engine_attempt_word", clock["attempt_address"], 2)
            header[16] = signal("engine_tick_word", clock["tick_address"], 2)
            header[17] = names["source_phase"]
            header[18] = clock["ticks_per_attempt"]
            header[20] = program["state_values"]["terminal"]
            header[25] = 2
            render = program["render_when"]
            header[27], header[28], header[29] = render["attempt"], render["tick"], program["state_values"][render["state"]]
            # Exact pinned source/ROM derivation; these are observer PCs, never
            # execution patches or symbol guesses from Genewhip output.
            source_path = "reviewed-export/src/gameplay/gameplay_core.asm"
            with tarfile.open(ROOT / "fixtures/phase5-b/source.tar") as archive:
                source_bytes = archive.extractfile(source_path).read()
            if hashlib.sha256(source_bytes).hexdigest() != "df9b9056d65c7bbb987d7a42f56f9fa84bc01ec67db1d1d1fe15a842f7058a49":
                raise Invalid("marker-source-identity")
            rom = (ROOT / "fixtures/phase5-b/game.bin").read_bytes()
            needle = bytes.fromhex("427900ff1516")
            all_offsets = [i for i in range(len(rom)) if rom.startswith(needle, i)]
            if all_offsets != [0x39B0, 0x3CE2, 0x3D26, 0x3D5E, 0x3D9E]:
                raise Invalid("marker-rom-identity")
            for pc, line, label in ((0x3CE2,387,"active_done"), (0x3D26,400,"program_stable"),
                                    (0x3D5E,411,"current_destroyed"), (0x3D9E,423,"timeout")):
                markers.append([pc, 0x4279])
                metadata["markers"].append({"pc": pc, "opcode": 0x4279, "source": source_path,
                                             "line": line, "label": label,
                                             "source_sha256": hashlib.sha256(source_bytes).hexdigest()})
            mapped_rows = None
            if delivery_map is not None and route["fixture"] == "recursion94":
                validate_delivery_map(delivery_map, client=client)
                mapped_rows = {row["order"]: row for row in delivery_map["events"]}
            for event_index, event in enumerate(program["events"], 1):
                if case["id"] in event["cases"]:
                    port, bit = control(event["control"])
                    tick = (mapped_rows[event_index]["scheduled_client_point"][client].get("tick", event["tick"])
                            if mapped_rows else event["tick"])
                    events.append([event["attempt"], tick, program["state_values"][event["state"]],
                                   port, bit, int(event["asserted"])])
        else:
            raise Invalid("source-clock-kind")
        for predicate in definitions["predicates"]:
            predicates.append([names[predicate["signal"]], predicate["equals"], *predicate["field_window"]])
    if delivery_map is not None and route["fixture"] == "recursion94":
        validate_delivery_map(delivery_map, route=route, client=client)
        metadata["delivery_map"] = {"map_id": delivery_map["map_id"],
                                    "sha256": canonical_digest(delivery_map),
                                    "schema": delivery_map["schema"],
                                    "client": client,
                                    "original_input_sha256": delivery_map["source"]["input_program_sha256"]}
    return encode_controller(header, sections), metadata


def write_compiled(directory: pathlib.Path, delivery_map: dict | None = None, fixture_id: str | None = None,
                   client: str = "public-core") -> dict:
    roster = compile_routes(delivery_map, client)
    compiled = []
    # Validate/lower the entire set before writing any output.
    for route in roster["routes"]:
        if fixture_id and route["fixture"] != fixture_id:
            continue
        binary, metadata = lower_route(route, delivery_map=delivery_map if route["fixture"] == "recursion94" else None,
                                       client=client)
        if delivery_map is not None and route["fixture"] == "recursion94":
            metadata["delivery_map"] = {"map_id": delivery_map["map_id"], "sha256": canonical_digest(delivery_map),
                                         "schema": delivery_map["schema"], "client": client,
                                         "original_input_sha256": delivery_map["source"]["input_program_sha256"]}
        name = route["fixture"] + "--" + route["case"]["id"] + ".gwrc"
        compiled.append((name, binary, metadata))
    directory.mkdir(parents=True, exist_ok=True)
    for name, binary, metadata in compiled:
        (directory / name).write_bytes(binary)
        (directory / (name + ".json")).write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
    roster["compiled"] = [{"file": name, "sha256": hashlib.sha256(binary).hexdigest()} for name, binary, _ in compiled]
    (directory / "roster.json").write_text(json.dumps(roster, sort_keys=True, indent=2) + "\n")
    return roster


def validate_report(report: dict) -> None:
    if set(report) != {"schema", "routes", "host"} or report.get("schema") != "genewhip-phase6-route-report-v1":
        raise Invalid("schema")
    expected = compile_routes()["routes"]
    rows = report["routes"]
    if not isinstance(rows, list) or len(rows) != len(expected):
        raise Invalid("missing-row")
    by_key = {}
    for row in rows:
        if set(row) != {"fixture", "case", "identity", "definitions", "stages", "reached", "clocks"}:
            raise Invalid("row-schema")
        key = (row["fixture"], row["case"])
        if key in by_key:
            raise Invalid("duplicate-case")
        by_key[key] = row
    for source in expected:
        key = (source["fixture"], source["case"]["id"])
        row = by_key.get(key)
        if row is None:
            raise Invalid("missing-row")
        if row["identity"] != source["identity"]:
            raise Invalid("identity-mismatch")
        if row["definitions"] != source["definitions"]:
            raise Invalid("source-definition-mismatch")
        if not isinstance(row["stages"], dict) or set(row["stages"]) != set(STAGES):
            raise Invalid("missing-stage")
        any_reached = False
        for stage in STAGES:
            item = row["stages"][stage]
            if not isinstance(item, dict) or set(item) != {"status", "reached", "detail", "evidence"}:
                raise Invalid("stage-schema")
            if item["status"] not in STATUSES or not isinstance(item["reached"], bool):
                raise Invalid("stage-status")
            if not item["reached"] and item["status"] == "pass":
                raise Invalid("unreached-pass")
            any_reached = any_reached or item["reached"]
            if item["status"] == "pass":
                _validate_pass_receipt(source, stage, item["evidence"])
        if row["reached"] is not False and not isinstance(row["reached"], bool):
            raise Invalid("reached")
        if row["reached"] != any_reached:
            raise Invalid("reached-stage-mismatch")
        active_clock = source["active_clock"]
        clock_names = {active_clock["name"]} if isinstance(active_clock, dict) and active_clock.get("name") else set()
        if not isinstance(row["clocks"], dict):
            raise Invalid("guessed-field-clock")
        if set(row["clocks"]) != clock_names:
            raise Invalid("guessed-field-clock")
        for name, value in row["clocks"].items():
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > 2**64 - 1):
                raise Invalid("clock-value")
    if not isinstance(report["host"], dict) or set(report["host"]) - {"status", "failure", "evidence"} or report["host"].get("status") not in STATUSES:
        raise Invalid("host-status")
    if report["host"]["status"] == "pass" and report["host"].get("failure"):
        raise Invalid("suppressed-host-failure")
    if report["host"]["status"] == "pass":
        _validate_host_receipt(report["host"].get("evidence"))


def validate_product_report(report: dict, candidate: dict) -> None:
    """Validate the complete repeated roster against source and exact raw runs."""
    if (report.get("schema") != "genewhip-phase6-product-report-v1" or
            report.get("candidate_sha256") != canonical_digest(candidate)):
        raise Invalid("product-candidate")
    manifest=_read_receipt(report.get("candidate_manifest"),"product-candidate-manifest",64*1024)
    if canonical_digest(manifest)!=canonical_digest(candidate):
        raise Invalid("product-candidate-manifest")
    readers=set(READER_PROVENANCE_PATHS)|{"fixtures/phase6/media-expectations-v1.json"}
    for relative, expected in candidate.get("source_files", {}).items():
        if relative in readers:continue
        if pathlib.PurePosixPath(relative).name=="CMakeLists.txt":
            # Build inputs are frozen provenance. Current executable bytes,
            # runtime C/header sources and cache remain strict below; adding
            # CTest registrations cannot change an identical native binary.
            client=(ROOT/candidate["client_identities"]["public-core"]["path"]).resolve()
            snapshot=client.parents[2]/"evidence"/"build-provenance"/(expected+".cmake")
            if (not snapshot.resolve().is_relative_to(ROOT) or snapshot.is_symlink() or
                    not snapshot.is_file() or snapshot.stat().st_size>131072 or digest(snapshot)!=expected):
                raise Invalid("product-stale-source")
            continue
        path = (ROOT / relative).resolve()
        if not path.is_relative_to(ROOT) or not path.is_file() or digest(path) != expected:
            raise Invalid("product-stale-source")
    for identity in candidate.get("client_identities", {}).values():
        path = (ROOT / identity.get("path", "")).resolve()
        if not path.is_relative_to(ROOT) or not path.is_file() or digest(path) != identity.get("sha256"):
            raise Invalid("product-stale-client")
    headless = ROOT / candidate["client_identities"]["public-core"]["path"]
    if digest(headless.parents[2]/"CMakeCache.txt") != candidate.get("build_identity",{}).get("cmake_cache_sha256"):
        raise Invalid("product-stale-build")
    if candidate.get("configuration_identity") != {"audio_rate_hz":48000,"profile":"VA3-NTSC-U","test_hooks":True}:
        raise Invalid("product-configuration")
    if candidate.get("compiler_identity") != {"path":"scripts/evidence/phase6_routes.py",
            "sha256":candidate.get("source_files",{}).get("scripts/evidence/phase6_routes.py")}:
        raise Invalid("product-compiler")
    current_readers={path:digest(ROOT/path) for path in READER_PROVENANCE_PATHS}
    current_expectations=digest(ROOT/"fixtures/phase6/media-expectations-v1.json")
    if report.get("validation_identities") != {"reader_provenance":current_readers,
            "media_expectations_sha256":current_expectations}:
        raise Invalid("product-validation-identities")
    mapping = load(ROOT / candidate["delivery_map_identity"]["path"])
    validate_delivery_map(mapping)
    if canonical_digest(mapping) != candidate["delivery_map_identity"]["sha256"]:
        raise Invalid("product-map")
    routes = compile_routes()["routes"]
    expected = {(r["fixture"],r["case"]["id"]):r for r in routes}
    if report.get("roster") != [{"fixture":r["fixture"],"case":r["case"],"identity":r["identity"]} for r in routes]:
        raise Invalid("product-roster")
    rows = report.get("runs", [])
    if len(rows) != 24:
        raise Invalid("product-run-count")
    controls = report.get("controls")
    if (not isinstance(controls, list) or len(controls) != 2 or
            any(not isinstance(ref, dict) or set(ref) != {"path", "sha256"} for ref in controls) or
            len({(ref["path"], ref["sha256"]) for ref in controls}) != 2):
        raise Invalid("product-control-repetitions")
    control_refs = {(ref["path"], ref["sha256"]) for ref in controls}
    keyed = {}
    for row in rows:
        key = (row.get("fixture"),row.get("case"),row.get("repetition"))
        if key in keyed:
            raise Invalid("product-duplicate-run")
        keyed[key] = row
    for key,route in expected.items():
        repetitions = []
        for rep in (1,2):
            row = keyed.get((*key,rep))
            if row is None or row.get("identity") != route["identity"]:
                raise Invalid("product-run-identity")
            if row.get("status") != "pass":
                raise Invalid("product-run-failed")
            process = row.get("process", {})
            if (process.get("return_code") != 0 or process.get("bound_violation") or process.get("process_group_cleanup") != "confirmed" or
                    type(process.get("pid")) is not int or process["pid"]<=0 or process.get("pgid")!=process["pid"] or
                    process.get("status")!="completed"):
                raise Invalid("product-process")
            receipt = _read_receipt(row.get("process_receipt"),"product-process-receipt",16*1024*1024)
            if (not isinstance(receipt.get("processes"), list) or len(receipt["processes"]) != 1 or
                    receipt["processes"][0] != process):
                raise Invalid("product-process-binding")
            if key[0] == "genewhip-independent-game-v2":
                control_ref = row.get("control_report", {})
                ref_key = (control_ref.get("path"), control_ref.get("sha256"))
                if ref_key not in control_refs or ref_key != (controls[row["repetition"] - 1]["path"],
                                                               controls[row["repetition"] - 1]["sha256"]):
                    raise Invalid("product-control-binding")
                control = _read_receipt(row["control_report"],"product-control",4*1024*1024)
                case = next((x for x in control.get("results",[]) if x.get("id") == key[1]),None)
                if (control.get("outcome") != "pass" or control.get("denominator") != 6 or
                        control.get("fields") != 840 or case is None or case.get("outcome") != "pass" or
                        case.get("fields") != route["case"]["frames"]):
                    raise Invalid("product-control-case")
                if row.get("pcm") != case.get("retained_pcm"):
                    raise Invalid("product-control-pcm-binding")
                pcm = _media_artifact(row["pcm"],16*1024*1024,"product-control-pcm")
                if (len(pcm) != case["pcm_frames"]*4 or
                        case["pcm_frames"] != route["case"]["frames"]*896040*48000//53693175):
                    raise Invalid("product-control-pcm-length")
                wanted=route["case"]["expect"]
                values=array.array("h");values.frombytes(pcm)
                if sys.byteorder!="little":values.byteswap()
                ac=max(values)-min(values) if values else 0
                if (case.get("psg") != wanted["psg_writes"] or case.get("play_state") != wanted["play_state"] or
                        not wanted["position_min"] <= case.get("position",-1) <= wanted["position_max"] or
                        case.get("ac_range") != ac or bool(ac) != bool(wanted["psg_writes"])):
                    raise Invalid("product-control-source-semantics")
                if control.get("client_sha256") != [candidate["client_identities"]["public-core"]["sha256"]]:
                    raise Invalid("product-control-client")
                stdout=_media_artifact(case.get("process_streams",{}).get("stdout",{}),1048576,"product-control-stdout")
                output=[json.loads(line) for line in stdout.splitlines() if line.startswith(b'{')]
                final=next((item for item in reversed(output) if "unsupported" in item),None)
                fields=[item["fnv1a64"] for item in output if "sequence" in item and "fnv1a64" in item]
                if (final is None or final.get("fields") != route["case"]["frames"] or final.get("unsupported") != 0 or
                        len(fields) != route["case"]["frames"] or
                        hashlib.sha256("\n".join(fields).encode()).hexdigest() != case.get("field_hashes_sha256")):
                    raise Invalid("product-control-raw-binding")
                state=bytes.fromhex(final["peek"])
                if int.from_bytes(state[:2],"big") != case["play_state"] or int.from_bytes(state[2:4],"big") != case["position"]:
                    raise Invalid("product-control-raw-state")
            else:
                if row.get("client")!="public-core" or row.get("delivery_map_sha256")!=(canonical_digest(mapping) if key[0]=="recursion94" else None):
                    raise Invalid("product-run-map-client")
                cap = 100_000_000 if key[0] == "recursion94" else 10_000_000
                binary,_ = lower_route(route,cap,mapping if key[0] == "recursion94" else None)
                native = _read_receipt(row["native_report"],"product-native",8*1024*1024)
                if row.get("compiled_sha256") != hashlib.sha256(binary).hexdigest():
                    raise Invalid("product-compiled")
                process_receipt_data = receipt
                receipt = {"compiled_sha256":row["compiled_sha256"],"native_report":row["native_report"],
                           "predicate_results":row.get("predicate_results",{})}
                _validate_native_facts(route,"sustained",receipt,mapping if key[0] == "recursion94" else None,cap)
                if (native.get("boundary_calls",cap+1) > cap or native.get("queue_high_water",65) > 64 or
                        native.get("fields",7201) > (7200 if key[0] == "recursion94" else 4500)):
                    raise Invalid("product-work-cap")
                streams=process_receipt_data.get("streams",{})
                stdout=streams.get("stdout",{})
                text=stdout.get("text")
                encoded=text.encode() if isinstance(text,str) else b""
                if (stdout.get("truncated") is not False or
                        stdout.get("observed_bytes")!=len(encoded) or
                        stdout.get("sha256")!=hashlib.sha256(encoded).hexdigest()):
                    raise Invalid("product-field-stream-binding")
                try:
                    output=[json.loads(line) for line in text.splitlines() if line.startswith("{")]
                except (TypeError,ValueError):
                    raise Invalid("product-field-stream-binding") from None
                field_rows=[item for item in output if "sequence" in item and "fnv1a64" in item]
                if (len(field_rows)!=native.get("fields") or
                        canonical_digest(field_rows)!=row.get("field_hashes_sha256")):
                    raise Invalid("product-field-stream-binding")
                pcm = _media_artifact(row.get("pcm",{}),16*1024*1024,"product-pcm")
                if len(pcm) != native.get("audio_frames",-1)*4 or len(pcm) < 3600*800*4:
                    raise Invalid("product-pcm-length")
                image = _media_artifact(row.get("image",{}),320*224*4,"product-image")
                if len(image) != 320*224*4:
                    raise Invalid("product-image-geometry")
            repetitions.append(row)
        left,right = repetitions
        if (left["process"].get("pid") == right["process"].get("pid") or
                (left["process_receipt"].get("path"), left["process_receipt"].get("sha256")) ==
                (right["process_receipt"].get("path"), right["process_receipt"].get("sha256"))):
            raise Invalid("product-repeat-execution")
        if key[0] == "genewhip-independent-game-v2":
            left_control = left["control_report"]
            right_control = right["control_report"]
            if ((left_control.get("path"), left_control.get("sha256")) ==
                    (right_control.get("path"), right_control.get("sha256"))):
                raise Invalid("product-control-repetitions")
        if left["pcm"]["sha256"] != right["pcm"]["sha256"]:
            raise Invalid("product-repeat-pcm")
        if key[0] != "genewhip-independent-game-v2":
            if (left["native_report"]["sha256"] != right["native_report"]["sha256"] or
                    left["image"]["sha256"] != right["image"]["sha256"] or
                    left["field_hashes_sha256"] != right["field_hashes_sha256"]):
                raise Invalid("product-repeat-state-video")
    # Every public-core case has its own launch. The six original-control rows
    # in each repetition share one outer launch and receipt. The aggregate list
    # must represent exactly those fourteen completed outer processes.
    process_by_pid = {}
    receipt_by_pid = {}
    for row in rows:
        process = row["process"]
        pid = process["pid"]
        receipt_ref = row["process_receipt"]
        receipt_key = (receipt_ref.get("path"), receipt_ref.get("sha256"))
        prior = process_by_pid.get(pid)
        if prior is not None and (prior != process or receipt_by_pid[pid] != receipt_key):
            raise Invalid("product-process-reuse")
        process_by_pid[pid] = process
        receipt_by_pid[pid] = receipt_key
    title_pids = [row["process"]["pid"] for row in rows
                  if row["fixture"] != "genewhip-independent-game-v2"]
    if len(title_pids) != 12 or len(set(title_pids)) != 12:
        raise Invalid("product-repeat-execution")
    control_groups = {}
    for row in rows:
        if row["fixture"] == "genewhip-independent-game-v2":
            group = row["repetition"]
            process_key = (row["process"]["pid"], row["process_receipt"].get("path"),
                           row["process_receipt"].get("sha256"), row["control_report"].get("path"),
                           row["control_report"].get("sha256"))
            control_groups.setdefault(group, set()).add(process_key)
    if (set(control_groups) != {1, 2} or any(len(group) != 1 for group in control_groups.values()) or
            control_groups[1] == control_groups[2]):
        raise Invalid("product-control-repetitions")
    unique_receipts = set(receipt_by_pid.values())
    if len(process_by_pid) != 14 or len(unique_receipts) != 14:
        raise Invalid("product-process-count")
    declared_processes = report.get("processes")
    if (not isinstance(declared_processes, list) or len(declared_processes) != 14 or
            len({item.get("pid") for item in declared_processes if isinstance(item, dict)}) != 14 or
            {item.get("pid"): item for item in declared_processes if isinstance(item, dict)} != process_by_pid):
        raise Invalid("product-process-roster")
    cells = report.get("stages", [])
    if len(cells) != 120:
        raise Invalid("product-stage-count")
    identities = {(c.get("fixture"),c.get("case"),c.get("repetition"),c.get("stage")) for c in cells}
    if identities != {(*key,rep,stage) for key in expected for rep in (1,2) for stage in STAGES}:
        raise Invalid("product-stage-roster")
    for cell in cells:
        if cell.get("status") not in STATUSES or type(cell.get("reached")) is not bool:
            raise Invalid("product-stage-status")
        if cell["status"] == "pass" and not cell["reached"]:
            raise Invalid("product-stage-false-pass")
        if cell["stage"] == "completion" and cell["status"] == "pass":
            raise Invalid("product-invented-completion")
        if cell["fixture"] != "genewhip-independent-game-v2" and cell["stage"] != "completion" and cell["status"] != "pass":
            raise Invalid("product-required-stage")
    if report.get("outcomes",{}).get("status") != "pass":
        raise Invalid("product-outcome")


def validate_media_report(report: dict, candidate: dict) -> None:
    """Recompute media features from bounded raw captures, never outer digests alone."""
    if (not isinstance(report, dict) or report.get("schema") != "genewhip-phase6-media-v1" or
            report.get("result") != "pass" or report.get("candidate_sha256") != canonical_digest(candidate)):
        raise Invalid("media-envelope")
    expectation_path = ROOT / "fixtures/phase6/media-expectations-v1.json"
    try:
        expectation_bytes = expectation_path.read_bytes()
        expectations = json.loads(expectation_bytes)
    except (OSError, json.JSONDecodeError) as error:
        raise Invalid("media-expectations-unavailable") from error
    expected_sha = hashlib.sha256(expectation_bytes).hexdigest()
    # Media interpretation is a current validation dependency; changing it
    # does not alter an immutable native execution identity.
    if report.get("media_expectations_sha256") != expected_sha:
        raise Invalid("media-expectations-identity")
    routes = _read_receipt(report.get("core_routes"),"media-route-receipt",16*1024*1024)
    if (report.get("core_routes_sha256") != report["core_routes"]["sha256"] or
            routes.get("candidate_sha256") != canonical_digest(candidate)):
        raise Invalid("media-route-receipt-identity")
    validate_product_report(routes,candidate)
    rows = report.get("captures")
    expected = {(item["fixture"], item["case"]) for item in expectations.get("captures", [])}
    if not isinstance(rows, list) or len(rows) != len(expected):
        raise Invalid("media-roster")
    found = set()
    for row in rows:
        if not isinstance(row, dict):
            raise Invalid("media-capture-schema")
        key = (row.get("fixture"), row.get("case"))
        if key not in expected or key in found:
            raise Invalid("media-capture-identity")
        found.add(key)
        source = next(item for item in expectations["captures"] if (item["fixture"], item["case"]) == key)
        actual_run = next((run for run in routes["runs"] if run["fixture"]==key[0] and run["case"]==key[1] and run["repetition"]==1),None)
        if actual_run is None or any(row.get(k)!=actual_run.get(k) for k in ("image","scene_metadata","audio_trace","native_report","completed_fields","field_sequence")):
            raise Invalid("media-current-run-binding")
        if any(row.get("audio",{}).get(k)!=actual_run.get("pcm",{}).get(k) for k in ("path","sha256")):
            raise Invalid("media-current-pcm-binding")
        if key[0] == "recursion94":
            if row.get("attempt") != source.get("attempt") or row.get("source_tick", 0) < source.get("minimum_source_tick", 0):
                raise Invalid("media-rec-scene-clock")
        elif row.get("field") != source.get("field"):
            raise Invalid("media-tank-scene-field")
        image = row.get("image")
        audio = row.get("audio")
        if not isinstance(image, dict) or not isinstance(audio, dict):
            raise Invalid("media-artifact-schema")
        image_bytes = _media_artifact(image, 320 * 224 * 4, "media-image")
        if len(image_bytes) != 320 * 224 * 4:
            raise Invalid("media-image-geometry")
        metadata_ref = row.get("scene_metadata")
        if not isinstance(metadata_ref, dict):
            raise Invalid("media-scene-metadata")
        metadata_bytes = _media_artifact(metadata_ref, 8192, "media-scene-metadata")
        try:
            scene = json.loads(metadata_bytes)
        except (ValueError, UnicodeError) as error:
            raise Invalid("media-scene-metadata") from error
        if (scene.get("schema") != "genewhip-phase6-route-capture-v1" or
                scene.get("field_sequence") != row.get("field_sequence") or
                scene.get("candidate_sha256") != canonical_digest(candidate)):
            raise Invalid("media-scene-metadata")
        _validate_media_image(key[0], row, source, scene, image_bytes)
        audio_bytes = _media_artifact(audio, 16 * 1024 * 1024, "media-audio")
        completed_fields = row.get("completed_fields")
        if not isinstance(completed_fields, int) or completed_fields < 2:
            raise Invalid("media-audio-duration-basis")
        minimum_frames = ((completed_fields - 1) * 896040 * 48000) // 53693175
        if len(audio_bytes) < minimum_frames * 4 or len(audio_bytes) % 4:
            raise Invalid("media-audio-truncated")
        if audio.get("sample_rate_hz") != expectations.get("sample_rate_hz") or audio.get("encoding") != "s16le-stereo":
            raise Invalid("media-audio-format")
        validate_source_audio(key[0], row, audio_bytes, expectations)


def validate_host_input_observations(host: dict, native: dict, expected_masks=None) -> None:
    """The same real SDL-to-guest input assertion serves routes and fault probes."""
    host_events, native_events = host.get("input_events"), native.get("inputs")
    if (not isinstance(host_events,list) or not isinstance(native_events,list) or
            not native_events or len(host_events)!=len(native_events) or
            (expected_masks is not None and len(native_events)!=len(expected_masks))):
        raise Invalid("host-input")
    for index,(guest,event) in enumerate(zip(native_events,host_events)):
        desired=guest.get("desired")
        values=(desired,guest.get("effective"),event.get("requested_mask"),event.get("effective_mask"),event.get("joystick_mask"))
        if (type(guest.get("port")) is not int or guest["port"] not in (0,1) or
                type(event.get("port")) is not int or
                any(type(value) is not int or not 0<=value<=255 for value in values) or
                event.get("joystick_mask")!=event.get("effective_mask") or
                guest.get("port")!=event.get("port") or
                desired!=guest.get("effective") or desired!=event.get("requested_mask") or
                desired!=event.get("effective_mask") or
                event.get("handler")!="SDL_Gamepad/sample_port" or
                (expected_masks is not None and (guest.get("port")!=0 or desired!=expected_masks[index]))):
            raise Invalid("host-input")


def _validate_host_process(process: dict, receipt_ref: dict, cap: int) -> None:
    if (not isinstance(process,dict) or process.get("return_code")!=0 or process.get("bound_violation") or
            process.get("status")!="completed" or process.get("process_group_cleanup")!="confirmed" or
            type(process.get("pid")) is not int or process["pid"]<=0 or process.get("pgid")!=process["pid"] or
            type(process.get("wall_seconds")) not in (int,float) or not math.isfinite(process["wall_seconds"]) or not 0<=process["wall_seconds"]<=cap or
            process.get("stdout_bytes",1048577)>1048576 or process.get("stderr_bytes",1048577)>1048576 or
            process.get("report_bytes",8388609)>8388608):
        raise Invalid("host-process")
    for key,limit in (("stdout_bytes",1048576),("stderr_bytes",1048576),("report_bytes",8388608)):
        if type(process.get(key)) is not int or not 0<=process[key]<=limit:
            raise Invalid("host-process")
    receipt=_read_receipt(receipt_ref,"host-process-binding",16*1024*1024)
    if receipt.get("processes")!=[process]:
        raise Invalid("host-process-binding")


def validate_host_report(report: dict, candidate: dict) -> None:
    """Validate actual SDL host observations against the immutable current core product."""
    if not isinstance(report, dict) or report.get("schema") != "genewhip-phase6-host-v1":
        raise Invalid("host-envelope")
    if report.get("backend") not in ("software", "native"):
        raise Invalid("host-backend")
    if report.get("backend") == "native" and report.get("status") == "blocked-capability":
        raise Invalid("host-native-capability")
    if report.get("candidate_sha256") != canonical_digest(candidate):
        raise Invalid("host-candidate-identity")
    identity = report.get("host_identity")
    if not isinstance(identity, dict) or report.get("host_identity_sha256") != canonical_digest(identity):
        raise Invalid("host-identity")
    if identity.get("core_candidate_sha256") != canonical_digest(candidate):
        raise Invalid("host-identity")
    source = ROOT / "tools/desktop/main_sdl.c"
    if identity.get("desktop_source_sha256") != digest(source):
        raise Invalid("host-identity")
    if identity.get("audio_source_sha256") != digest(ROOT / "tools/desktop/audio.c"):
        raise Invalid("host-identity")
    if identity.get("phase4_control_source_sha256") != digest(ROOT / "tests/desktop/phase4_sessions.py"):
        raise Invalid("host-identity")
    if identity.get("desktop_test_source_sha256") != digest(ROOT / "tests/desktop/phase6_routes.py"):
        raise Invalid("host-identity")
    desktop = identity.get("desktop_binary", {})
    desktop_path = (ROOT / desktop.get("path", "")).resolve()
    if (not desktop_path.is_relative_to(ROOT) or not desktop_path.is_file() or
            desktop.get("sha256") != digest(desktop_path)):
        raise Invalid("host-identity")
    cache_path = desktop_path.parents[2] / "CMakeCache.txt"
    if identity.get("cmake_cache_sha256") != digest(cache_path):
        raise Invalid("host-identity")
    input_ref = identity.get("input_contract", {})
    input_path = (ROOT / input_ref.get("path", "")).resolve()
    if not input_path.is_relative_to(ROOT) or not input_path.is_file() or digest(input_path) != input_ref.get("sha256"):
        raise Invalid("host-input")
    try:
        input_proof = json.loads(input_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as error:
        raise Invalid("host-input") from error
    if (input_proof.get("outcome") != "pass" or input_proof.get("requested_count") != 23 or
            input_proof.get("port_isolation_verified") is not True or
            input_proof.get("desktop_sha256") != desktop.get("sha256")):
        raise Invalid("host-input")
    map_ref = identity.get("delivery_map", {})
    map_path = (ROOT / map_ref.get("path", "")).resolve()
    if not map_path.is_relative_to(ROOT) or not map_path.is_file():
        raise Invalid("host-map")
    mapping = load(map_path)
    validate_delivery_map(mapping, client="sdl")
    if map_ref.get("sha256") != canonical_digest(mapping):
        raise Invalid("host-map")
    if identity.get("media_expectations_sha256") != digest(ROOT / "fixtures/phase6/media-expectations-v1.json"):
        raise Invalid("host-media-identity")
    core_ref = identity.get("core_report", {})
    core = _read_receipt(core_ref, "host-core-report", 16 * 1024 * 1024)
    if core_ref.get("sha256") != digest(ROOT / core_ref.get("path", "")):
        raise Invalid("host-core-identity")
    validate_product_report(core, candidate)
    expected = [(fixture, case) for fixture, cases in (
        ("recursion94", ("full-route", "withhold-first-plate", "withhold-final-b")),
        ("tank-battle", ("full-route", "withhold-early-hit", "withhold-late-hit"))) for case in cases]
    rows = report.get("runs")
    if not isinstance(rows, list) or len(rows) != 6 or [
            (row.get("fixture"), row.get("case")) for row in rows if isinstance(row, dict)] != expected:
        raise Invalid("host-roster")
    for row in rows:
        if row.get("status") != "pass" or row.get("backend") != report["backend"]:
            raise Invalid("host-run-status")
        native_ref, host_ref, renderer_ref, pcm_ref = (row.get("raw_outputs", {}).get(name)
            for name in ("native", "host", "renderer", "pcm"))
        if not all(isinstance(ref, dict) for ref in (native_ref, host_ref, renderer_ref, pcm_ref)):
            raise Invalid("host-raw-output")
        native_bytes = _media_artifact(native_ref, 8 * 1024 * 1024, "host-raw-output")
        host_bytes = _media_artifact(host_ref, 1024 * 1024, "host-raw-output")
        renderer_bytes = _media_artifact(renderer_ref, 16 * 1024 * 1024, "host-raw-output")
        pcm_bytes = _media_artifact(pcm_ref, 16 * 1024 * 1024, "host-raw-output")
        try:
            native = json.loads(native_bytes)
            host = json.loads(host_bytes)
        except (ValueError, UnicodeError) as error:
            raise Invalid("host-raw-output") from error
        fixture, case = row["fixture"], row["case"]
        _validate_host_process(row.get("process"),row.get("process_receipt"),600 if fixture=="recursion94" else 300)
        headless_row = next((item for item in core["runs"] if item.get("fixture") == fixture and
            item.get("case") == case and item.get("client") == "public-core" and item.get("repetition") == 1 and item.get("status") == "pass"), None)
        if headless_row is None:
            raise Invalid("host-core-identity")
        headless_native = _read_receipt(headless_row.get("native_report"), "host-core-native", 8 * 1024 * 1024)
        if (row.get("identity") != headless_row.get("identity") or native.get("status") != 0 or
                native.get("active_ticks") != 3600 or native.get("samples") != headless_native.get("samples") or
                row.get("observed_clocks", {}).get("active_ticks") != 3600 or
                native.get("fields", 7201) > (7200 if fixture == "recursion94" else 4500) or
                native.get("boundary_calls", 100_000_001) > (100_000_000 if fixture == "recursion94" else 10_000_000)):
            raise Invalid("host-core-observation")
        # The host callback label is the sole expected native-report difference.
        if ({k:v for k,v in native.items() if k!="handler"} !=
                {k:v for k,v in headless_native.items() if k!="handler"}):
            raise Invalid("host-core-observation")
        expected_masks=None
        if fixture == "recursion94":
            events=[event for event in mapping["events"] if case in event["cases"]]
            expected_masks=[event["effective_mask"] for event in events]
            if expected_masks and expected_masks[-1]:expected_masks.append(0)
        validate_host_input_observations(host,native,expected_masks)
        boundary = row.get("common_boundary", {})
        if row.get("core_outcome") != "pass" or row.get("host_outcome") != "pass-diagnostic" or boundary.get("source_samples_equal") is not True:
            raise Invalid("host-run-status")
        if (pcm_ref.get("sha256") != headless_row.get("pcm", {}).get("sha256") or
                hashlib.sha256(pcm_bytes).hexdigest() != headless_row.get("pcm", {}).get("sha256")):
            raise Invalid("host-audio")
        if (renderer_ref.get("sha256") != headless_row.get("image", {}).get("sha256") or
                hashlib.sha256(renderer_bytes).hexdigest() != headless_row.get("image", {}).get("sha256")):
            raise Invalid("host-renderer")
        audio = row.get("audio", {})
        renderer = row.get("renderer", {})
        if (boundary.get("full_pcm_equal") is not True or host.get("audio_device_activity") is not True or
                host.get("audio_submitted_frames", 0) <= 0 or host.get("audio_device_consumed_frames", 0) <= 0 or
                audio.get("audio_submitted_frames") != host.get("audio_submitted_frames") or
                audio.get("audio_device_consumed_frames") != host.get("audio_device_consumed_frames")):
            raise Invalid("host-audio")
        if (boundary.get("renderer_pixel_equal") is not True or host.get("renderer_readback_activity") is not True or
                host.get("renderer_capture_field") != headless_row.get("field_sequence") or
                row.get("renderer", {}).get("renderer_capture_field") != headless_row.get("field_sequence") or
                not renderer.get("renderer") or not renderer.get("video_driver")):
            raise Invalid("host-renderer")
        if report["backend"] == "native" and (host.get("video_driver") != "cocoa" or host.get("audio_driver") != "coreaudio"):
            raise Invalid("host-native-capability")
    selected_processes=[row["process"] for row in rows]
    if len({process["pid"] for process in selected_processes})!=6:
        raise Invalid("host-process-roster")
    declared=report.get("processes")
    if not isinstance(declared,list) or any(declared.count(process)!=1 for process in selected_processes):
        raise Invalid("host-process-roster")
    controls = report.get("controls")
    if not isinstance(controls, dict) or controls.get("outcome") != "pass":
        raise Invalid("host-controls")
    _validate_host_process(controls.get("process"),controls.get("process_receipt"),600)
    if controls["process"]["pid"] in {process["pid"] for process in selected_processes} or declared.count(controls["process"])!=1:
        raise Invalid("host-process-roster")
    control_report_ref = controls.get("report")
    control_report = _read_receipt(control_report_ref, "host-controls-report", 8 * 1024 * 1024)
    required = {"pause", "resume", "reset", "mute", "unmute", "replace", "drop", "reject-cartridge", "exit"}
    control_rows = control_report.get("runs", [])
    expected_controls = 8 if report["backend"] == "software" else 4
    if len(control_rows) != expected_controls or any(
            row.get("outcome") != "pass" and not
            (report["backend"] == "software" and row.get("id", "").endswith("missing-audio-negative") and row.get("outcome") == "skipped")
            for row in control_rows):
        raise Invalid("host-controls")
    sessions = ("independent-game-v2", "sounded-diagnostic")
    for session in sessions:
        session_rows = [row for row in control_rows if row.get("id", "").startswith(session)]
        exercised = set().union(*(set(row.get("controls_exercised", [])) for row in session_rows)) if session_rows else set()
        if not required.issubset(exercised) or not any("replace-drop" in row.get("id", "") for row in session_rows):
            raise Invalid("host-controls")
    if report.get("status") != "pass":
        raise Invalid("host-run-status")


def validate_host_capability_blocker(report: dict, candidate: dict) -> None:
    """Validate a native capability blocker without treating it as acceptance."""
    if (not isinstance(report, dict) or report.get("schema") != "genewhip-phase6-host-v1" or
            report.get("backend") != "native" or report.get("status") != "blocked-capability" or
            report.get("candidate_sha256") != canonical_digest(candidate)):
        raise Invalid("host-native-capability")
    identity = report.get("host_identity", {})
    if report.get("host_identity_sha256") != canonical_digest(identity):
        raise Invalid("host-identity")
    expected = [(fixture, case) for fixture, cases in (
        ("recursion94", ("full-route", "withhold-first-plate", "withhold-final-b")),
        ("tank-battle", ("full-route", "withhold-early-hit", "withhold-late-hit"))) for case in cases]
    rows = report.get("runs")
    if not isinstance(rows, list) or [(row.get("fixture"), row.get("case")) for row in rows] != expected:
        raise Invalid("host-roster")
    if any(row.get("status") != "skipped" or row.get("reason") != "native-capability-unavailable-before-title-launch" for row in rows):
        raise Invalid("host-native-capability")
    attempts = report.get("attempts", [])
    capable = [row for row in attempts if row.get("capability") in ("video-unavailable", "renderer-unavailable", "audio-unavailable")]
    if not capable or not any(row.get("process", {}).get("return_code") == 77 and
            row.get("process", {}).get("process_group_cleanup") == "confirmed" and
            row.get("raw_outputs", {}).get("host") for row in capable):
        raise Invalid("host-native-capability-evidence")
    if not isinstance(report.get("controls"), dict) or report["controls"].get("outcome") != "skipped" or report["controls"].get("return_code") != 77:
        raise Invalid("host-native-capability")


def _pcm_window(pcm: bytes, first: int, count: int) -> list[float]:
    if first < 0 or count < 64 or (first + count) * 4 > len(pcm):
        raise Invalid("media-audio-window")
    values = array.array("h")
    values.frombytes(pcm[first*4:(first+count)*4])
    if sys.byteorder != "little":
        values.byteswap()
    mono = [(values[i] + values[i+1]) / 2 for i in range(0, len(values), 2)]
    mean = sum(mono) / len(mono)
    return [value - mean for value in mono]


def tone_features(values: list[float], frequency: float) -> dict:
    """Scale/DC invariant checks against a source-programmed tone, not a golden PCM."""
    energy = sum(x*x for x in values)
    if energy <= 0 or not 30 <= frequency <= 6000:
        raise Invalid("media-audio-source-signal")
    windowed = [x*(0.5-0.5*math.cos(2*math.pi*i/(len(values)-1))) for i,x in enumerate(values)]
    def power(hz):
        coefficient = 2*math.cos(2*math.pi*hz/48000)
        a = b = 0.0
        for sample in windowed:
            current = sample + coefficient*a - b
            b,a = a,current
        return max(0.0, a*a+b*b-coefficient*a*b)
    target = max(power(frequency*ratio) for ratio in (.95,.975,1.0,1.025,1.05))
    adjacent = max(power(frequency*ratio) for ratio in (.7,.8,1.2,1.3))
    period = 48000/frequency
    correlation = -1.0
    for lag in range(max(1,int(period*.95)), int(period*1.05)+2):
        left,right = values[:-lag],values[lag:]
        denominator = math.sqrt(sum(x*x for x in left)*sum(x*x for x in right))
        if denominator:
            correlation = max(correlation,sum(x*y for x,y in zip(left,right))/denominator)
    return {"frequency_hz":round(frequency,4), "prominence_ratio":round(target/max(adjacent,1e-12),4),
            "periodicity":round(correlation,4)}


def validate_source_audio(fixture: str, row: dict, pcm: bytes, expectations: dict) -> dict:
    trace_data = _media_artifact(row.get("audio_trace", {}), 4*1024*1024, "media-audio-trace")
    try:
        trace = [json.loads(line) for line in trace_data.splitlines()]
    except (ValueError, UnicodeError) as error:
        raise Invalid("media-audio-trace-schema") from error
    if not trace or len(trace) > 4097 or "dropped" not in trace[-1]:
        raise Invalid("media-audio-trace-schema")
    if trace[-1]["dropped"] != 0:
        raise Invalid("media-audio-trace-loss")
    writes = trace[:-1]
    checks = expectations["audio_checks"][fixture]
    native = _read_receipt(row.get("native_report"), "media-native", 8*1024*1024)
    if fixture == "recursion94":
        lows = [item for item in writes if item.get("chip") == 1 and item.get("reg") == 0xA0]
        sequence = checks["fm0_low_sequence"]
        start = next((i for i in range(len(lows)-len(sequence)+1)
                      if [item["value"] for item in lows[i:i+len(sequence)]] == sequence), None)
        if start is None:
            raise Invalid("media-rec-score-pattern")
        notes = lows[start:start+len(sequence)]
        # Follow the actually included v1 driver, not its standalone v2 score.
        # Every note keys off, writes high then low, programs PSG, and keys on.
        for note,period in zip(notes,checks["psg_periods"]):
            index = writes.index(note)
            high = writes[index-1] if index else {}
            before = writes[index-2] if index > 1 else {}
            after = writes[index+1:index+5]
            if (high.get("chip") != 1 or high.get("reg") != 0xA4 or high.get("value") != checks["high_register"] or
                    before.get("chip") != 1 or before.get("reg") != 0x28 or before.get("value") != 0 or
                    [(w.get("chip"),w.get("reg"),w.get("value")) for w in after] !=
                    [(3,0,0x80|(period&15)),(3,0,period>>4),(1,0x28,0xF0),(3,1,0x90|checks["psg_volume"])]):
                raise Invalid("media-rec-score-frequency-registers")
        for a,b in zip(notes,notes[1:]):
            if abs((b["tick"]-a["tick"])/896040-checks["note_fields"]) > checks["timing_tolerance_fields"]:
                raise Invalid("media-rec-score-timing")
        features = []
        for index in checks["pcm_notes"]:
            note = notes[index]
            frequency = checks["fm0_fnums"][index]*(2**checks["block"])*53693175/(7*144*2097152)
            first = int(note["tick"]*48000/53693175 + checks["window_offset_seconds"]*48000)
            feature = tone_features(_pcm_window(pcm,first,int(checks["window_seconds"]*48000)),frequency)
            if feature["prominence_ratio"] < checks["minimum_prominence_ratio"] or feature["periodicity"] < checks["minimum_periodicity"]:
                raise Invalid("media-rec-score-pcm")
            features.append(feature)
        return {"score":"selected-v1-vblank-motif", "notes":features, "trace_dropped":trace[-1]["dropped"],
                "reference_waveform":"unknown; source/chip-contract checks only"}
    # Decode only the independently source-specified PSG tone/envelope packets.
    # This is a feature oracle, not a second mixer or a candidate PCM golden.
    shot = next((x for x in native.get("inputs",[]) if x.get("port") == 0 and x.get("effective",0)&16),None)
    route = next(r for r in compile_routes()["routes"] if r["fixture"] == fixture and r["case"]["id"] == "full-route")
    _,metadata = lower_route(route,10_000_000)
    score_index = next(i for i,s in enumerate(metadata["signals"]) if s["name"] == "p1_score")
    collision = next((s for s in native["samples"] if s["values"][score_index] == 1),None)
    if shot is None or collision is None:
        raise Invalid("media-tank-source-events")
    periods=[0,0,0];packets=[]
    for w in writes:
        reg,value=w.get("reg",-1),w.get("value",-1)
        if w.get("chip")!=3 or reg not in (0,2,4):continue
        channel=reg//2
        if value&128:periods[channel]=(periods[channel]&0x3F0)|(value&15)
        else:
            periods[channel]=(periods[channel]&15)|((value&63)<<4)
            packets.append({"channel":channel,"period":periods[channel],"tick":w["tick"]})
    def envelopes(channel,level,after,before):
        return [w for w in writes if w.get("chip")==3 and w.get("reg")==channel*2+1 and
                w.get("value",-1)&15==level and after<=w.get("tick",-1)<=before]
    def onset(tick):
        frame=round(tick*48000/53693175)
        _pcm_window(pcm,frame-128,96)  # bound-check the pre-event window
        # Compare to the actual pre-event DC level, rather than treating a
        # static YM ladder offset as sound. Preserve the original DC here.
        raw=array.array("h");raw.frombytes(pcm[(frame-128)*4:(frame+160)*4])
        if sys.byteorder!="little":raw.byteswap()
        mono=[(raw[i]+raw[i+1])/2 for i in range(0,len(raw),2)]
        baseline=sum(mono[:96])/96
        return max(abs(x-baseline) for x in mono[120:])
    def gate(packet,channel,level,maximum_tick):
        levels=envelopes(channel,level,packet["tick"],packet["tick"]+896040)
        if not levels:return None
        opened=levels[0]["tick"]
        closed=envelopes(channel,15,opened+1,min(maximum_tick,opened+checks["maximum_gate_fields"]*896040))
        if not closed:return None
        shut=closed[0]["tick"]
        if min(onset(opened),onset(shut))<checks["minimum_pcm_step"]:
            raise Invalid("media-tank-source-envelope-pcm")
        return opened,shut
    candidates=[w for w in packets if w["channel"]==0 and w["period"]==checks["shot_period"] and
                shot["machine_tick"]<=w["tick"]<=(collision["field"]+1)*896040]
    observed=[]
    for packet in candidates:
        span=gate(packet,0,checks["shot_level"],(collision["field"]+6)*896040)
        if span is None:continue
        first=math.ceil(span[0]*48000/53693175)+16
        count=int((span[1]-span[0])*48000/53693175)-32
        feature={"gate_samples":count+32,"onset_and_mute_pcm":True,"pitch":"unknown: source gate shorter than10ms"}
        if count>=checks["pitch_minimum_gate_samples"]:
            measured=tone_features(_pcm_window(pcm,first,min(count,4000)),3579545/(32*checks["shot_period"]))
            if measured["prominence_ratio"]<checks["minimum_prominence_ratio"] or measured["periodicity"]<checks["minimum_periodicity"]:
                raise Invalid("media-tank-shot-pcm")
            feature.update(measured,pitch="source-period corroborated")
        observed.append(feature)
        if feature["pitch"]=="source-period corroborated":break
    if not observed:raise Invalid("media-tank-shot-source-packet")
    low=(collision["field"]-2)*896040;high=(collision["field"]+1)*896040
    explosion=next((w for w in packets if w["channel"]==1 and w["period"] in checks["explosion_periods"] and low<=w["tick"]<=high),None)
    noise=next((w for w in writes if w.get("chip")==3 and w.get("reg")==6 and
                w.get("value",0)&7==checks["noise_control"] and low<=w.get("tick",-1)<=high),None)
    if explosion is None or noise is None or gate(explosion,1,checks["explosion_level"],high+5*896040) is None:
        raise Invalid("media-tank-explosion-source-packet")
    noise_open=envelopes(3,0,low,noise["tick"])
    if not noise_open or min(onset(noise_open[-1]["tick"]),onset(noise["tick"]))<checks["minimum_pcm_step"]:
        raise Invalid("media-tank-explosion-pcm")
    return {"shot":observed,"explosion_period":explosion["period"],"explosion_source_envelope_pcm":True,
            "noise":"WHITE/TONE3 programmed; no unsupported broadband pitch claim",
            "trace_dropped":trace[-1]["dropped"],"reference_waveform":"unknown; source packet/onset/mute checks only"}


def _media_artifact(reference: dict, maximum_bytes: int, reason: str) -> bytes:
    path = reference.get("path")
    expected_sha = reference.get("sha256")
    if not isinstance(path, str) or not isinstance(expected_sha, str):
        raise Invalid(reason + "-identity")
    relative = pathlib.PurePosixPath(path)
    if relative.is_absolute() or ".." in relative.parts:
        raise Invalid(reason + "-path")
    artifact = ROOT.joinpath(*relative.parts)
    try:
        if any(part.is_symlink() for part in (artifact, *artifact.parents) if part == ROOT or part.is_relative_to(ROOT)):
            raise Invalid(reason + "-symlink")
        resolved = artifact.resolve(strict=True)
        resolved.relative_to(ROOT)
        if resolved.is_symlink() or resolved.stat().st_size > maximum_bytes:
            raise Invalid(reason + "-bound")
        data = resolved.read_bytes()
    except (OSError, ValueError) as error:
        if isinstance(error, Invalid):
            raise
        raise Invalid(reason + "-unavailable") from error
    if hashlib.sha256(data).hexdigest() != expected_sha:
        raise Invalid(reason + "-digest")
    return data


def _validate_media_image(fixture: str, row: dict, source: dict, scene: dict, image_bytes: bytes) -> None:
    if fixture == "tank-battle":
        if scene.get("field") != row.get("field") or scene.get("field") != source.get("field"):
            raise Invalid("media-tank-scene-field")
        expected_cells = source["image"]["expected_tank_ram_cells"]
        if [[scene.get("p1_x"), scene.get("p1_y")], [scene.get("p2_x"), scene.get("p2_y")]] != expected_cells:
            raise Invalid("media-tank-source-ram-cells")
        # Source/SDK palette indices, not original color comments, select the
        # wall shade. The independent field120 capture contains arena geometry
        # but no tank pixels; preserve its actual observation and scene clock.
        x0,y0,width,height = source["image"]["reference_arena_roi_px"]
        rows = source["image"]["reference_arena_rows"]
        if len(rows) != height//8 or any(len(line) != width//8 or set(line)-set("#.") for line in rows):
            raise Invalid("media-tank-reference-arena")
        wall = bytes.fromhex(source["image"]["wall_pixel_xrgb_le_hex"])
        for ty,line in enumerate(rows):
            for tx,cell in enumerate(line):
                if cell != "#":continue
                expected = wall
                for y in range(y0+ty*8,y0+(ty+1)*8):
                    for x in range(x0+tx*8,x0+(tx+1)*8):
                        offset=(y*320+x)*4
                        if image_bytes[offset:offset+4] != expected:
                            raise Invalid("media-tank-source-tile")
        for cx,cy,cw,ch in source["image"]["source_empty_cell_rectangles"]:
            for y in range(y0+cy*8,y0+(cy+ch)*8):
                for x in range(x0+cx*8,x0+(cx+cw)*8):
                    offset=(y*320+x)*4
                    if image_bytes[offset:offset+4] != bytes(4):
                        raise Invalid("media-tank-source-empty-corridor")
        return
    if (scene.get("attempt") != row.get("attempt") or
            scene.get("source_tick") != row.get("source_tick")):
        raise Invalid("media-rec-scene-metadata-clock")
    actor_x, actor_y = scene.get("actor_x_px"), scene.get("actor_y_px")
    region = source["image"]["expected_actor_region_px"]
    if (not isinstance(actor_x, int) or not isinstance(actor_y, int) or
            not region["x"][0] <= actor_x <= region["x"][1] or
            not region["y"][0] <= actor_y <= region["y"][1]):
        raise Invalid("media-rec-source-actor-position")
    reference_mask = _reference_actor_mask(source)
    candidate_mask = [image_bytes[offset:offset+3] != b"\0\0\0"
                      for offset in range(0, len(image_bytes), 4)]
    expected_points = [(x, y) for y in range(region["y"][0], region["y"][1])
                       for x in range(region["x"][0], region["x"][1])
                       if reference_mask[y * 320 + x]]
    if len(expected_points) < 8:
        raise Invalid("media-rec-reference-actor-mask")
    overlap = sum(candidate_mask[y * 320 + x] for x, y in expected_points)
    background = [(x,y) for y in range(region["y"][0],region["y"][1])
                  for x in range(region["x"][0],region["x"][1]) if not reference_mask[y*320+x]]
    background_match = sum(not candidate_mask[y*320+x] for x,y in background)
    tolerance = source["image"]["occupancy_tolerance"]
    if (overlap < max(8,len(expected_points)*tolerance["minimum_foreground_fraction"]) or
            not background or background_match < len(background)*tolerance["minimum_background_fraction"]):
        raise Invalid("media-rec-source-actor-mask")


def _reference_actor_mask(source: dict) -> list[bool]:
    region=source["image"]["expected_actor_region_px"]
    rows=source["image"]["reference_occupancy_rows"]
    width=region["x"][1]-region["x"][0]
    if len(rows)!=region["y"][1]-region["y"][0] or any(len(row)!=width or set(row)-set("#.") for row in rows):
        raise Invalid("media-rec-reference-mask-format")
    mask=[False]*(320*224)
    for y,row in enumerate(rows,region["y"][0]):
        for x,char in enumerate(row,region["x"][0]):mask[y*320+x]=char=="#"
    return mask


def _png_occupancy_mask(data: bytes) -> list[bool]:
    """Decode the retained RGB8 reference mask without third-party codecs."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise Invalid("media-reference-png")
    offset = 8
    compressed = bytearray()
    dimensions = None
    while offset + 12 <= len(data):
        size = int.from_bytes(data[offset:offset+4], "big")
        kind = data[offset+4:offset+8]
        chunk = data[offset+8:offset+8+size]
        if len(chunk) != size:
            raise Invalid("media-reference-png")
        if kind == b"IHDR":
            width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", chunk)
            dimensions = (width, height, depth, color, interlace)
        elif kind == b"IDAT":
            compressed.extend(chunk)
        elif kind == b"IEND":
            break
        offset += size + 12
    if dimensions != (320, 224, 8, 2, 0):
        raise Invalid("media-reference-png-format")
    try:
        raw = zlib.decompress(compressed)
    except zlib.error as error:
        raise Invalid("media-reference-png-data") from error
    stride = 320 * 3
    if len(raw) != (stride + 1) * 224:
        raise Invalid("media-reference-png-data")
    rows: list[bytes] = []
    previous = bytearray(stride)
    cursor = 0
    for _ in range(224):
        filter_type = raw[cursor]
        scan = bytearray(raw[cursor+1:cursor+1+stride])
        cursor += stride + 1
        for i in range(stride):
            left = scan[i-3] if i >= 3 else 0
            up = previous[i]
            upper_left = previous[i-3] if i >= 3 else 0
            if filter_type == 1:
                scan[i] = (scan[i] + left) & 255
            elif filter_type == 2:
                scan[i] = (scan[i] + up) & 255
            elif filter_type == 3:
                scan[i] = (scan[i] + ((left + up) // 2)) & 255
            elif filter_type == 4:
                p = left + up - upper_left
                pa, pb, pc = abs(p-left), abs(p-up), abs(p-upper_left)
                predictor = left if pa <= pb and pa <= pc else up if pb <= pc else upper_left
                scan[i] = (scan[i] + predictor) & 255
            elif filter_type != 0:
                raise Invalid("media-reference-png-filter")
        rows.append(bytes(scan))
        previous = scan
    return [rows[y][x*3:x*3+3] != b"\0\0\0" for y in range(224) for x in range(320)]


def _validate_pass_receipt(route: dict, stage: str, reference: object) -> None:
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
        raise Invalid("missing-pass-evidence")
    relative = pathlib.PurePosixPath(reference["path"])
    if relative.is_absolute() or ".." in relative.parts:
        raise Invalid("unsafe-pass-evidence-path")
    receipt_path = ROOT.joinpath(*relative.parts)
    try:
        resolved = receipt_path.resolve(strict=True)
        resolved.relative_to(ROOT)
        if resolved.stat().st_size > 1024 * 1024 or digest(resolved) != reference["sha256"]:
            raise Invalid("pass-evidence-digest")
        receipt = load(resolved)
    except (OSError, ValueError) as error:
        if isinstance(error, Invalid):
            raise
        raise Invalid("pass-evidence-unavailable") from error
    if route["execution_blockers"]:
        raise Invalid("route-unexecutable")
    expected_keys = {"schema", "fixture", "case", "stage", "identity", "exit_code", "host_status",
                     "completion_observed", "predicate_results", "native_report", "compiled_sha256"}
    if not isinstance(receipt, dict) or set(receipt) != expected_keys:
        raise Invalid("pass-evidence-schema")
    if (receipt["schema"] != "genewhip-phase6-process-receipt-v1" or
            receipt["fixture"] != route["fixture"] or receipt["case"] != route["case"]["id"] or
            receipt["stage"] != stage or receipt["identity"] != route["identity"]):
        raise Invalid("pass-evidence-identity")
    if receipt["exit_code"] != 0 or receipt["host_status"] != "pass":
        raise Invalid("pass-with-process-failure")
    if stage == "completion" and receipt["completion_observed"] is not True:
        raise Invalid("completion-not-observed")
    if not isinstance(receipt["predicate_results"], dict):
        raise Invalid("pass-predicates-schema")
    predicates = {item["id"]: item for item in route["definitions"].get("predicates", []) if isinstance(item, dict) and "id" in item}
    case = route["case"]
    required = case.get("withheld_predicates", [])
    if case.get("kind") == "primary":
        required = list(predicates) if stage in ("interaction", "sustained", "completion") else []
        for predicate_id in required:
            result = receipt["predicate_results"].get(predicate_id)
            predicate = predicates[predicate_id]
            if (not isinstance(result, dict) or result.get("reached") is not True or
                    result.get("value") != predicate.get("equals") or
                    not isinstance(result.get("field"), int) or
                    not predicate.get("field_window", [0, 0])[0] <= result["field"] <= predicate.get("field_window", [0, 0])[1]):
                raise Invalid("pass-predicate-unproven")
    elif required:
        for predicate_id in required:
            result = receipt["predicate_results"].get(predicate_id)
            if not isinstance(result, dict) or result.get("reached") is not False:
                raise Invalid("causal-control-unproven")
    _validate_native_facts(route, stage, receipt)


def _validate_native_facts(route: dict, stage: str, receipt: dict, delivery_map=None,
                           boundary_call_limit=1_000_000, client="public-core") -> None:
    binary, metadata = lower_route(route, boundary_call_limit, delivery_map, client)
    if receipt["compiled_sha256"] != hashlib.sha256(binary).hexdigest():
        raise Invalid("pass-compiled-identity")
    native = _read_receipt(receipt["native_report"], "native-evidence", 8 * 1024 * 1024)
    if native.get("plan_fnv1a64") != plan_fingerprint(binary):
        raise Invalid("native-plan-identity")
    if native.get("termination") == "diagnostic-prefix":
        raise Invalid("native-diagnostic-prefix-is-not-route-evidence")
    if (native.get("schema") != "genewhip-route-native-v1" or native.get("status") != 0 or
            native.get("first_stop_tick") is not None or native.get("queue_high_water", 65) > 64 or
            native.get("audio_complete") is not True):
        raise Invalid("native-evidence-failed")
    samples = native.get("samples")
    if not isinstance(samples, list) or not samples:
        raise Invalid("native-samples-missing")
    names = {signal["name"]: i for i, signal in enumerate(metadata["signals"])}
    previous_clock, previous_field = 0, 0
    previous_attempt, previous_tick = 0, 0
    kind = route["definitions"]["active_clock"].get("kind")
    for sample in samples:
        if (not isinstance(sample, dict) or set(sample) != {"field", "active_ticks", "attempt", "tick", "state", "values"} or
                any(type(sample.get(key)) is not int or sample[key] < 0 for key in
                    ("field", "active_ticks", "attempt", "tick", "state")) or
                not isinstance(sample["values"], list) or len(sample["values"]) != len(names) or
                any(type(value) is not int or value < 0 or value > (255 if metadata["signals"][i]["width"] == 1 else 65535)
                    for i, value in enumerate(sample["values"]))):
            raise Invalid("native-sample-schema")
        clock, field = sample["active_ticks"], sample["field"]
        if field < previous_field or clock < previous_clock or clock > previous_clock + 1:
            raise Invalid("native-sample-clock")
        if kind == "observed-completed-source-steps":
            attempt, tick = sample["attempt"], sample["tick"]
            if clock != previous_clock + 1 or not (
                    attempt == previous_attempt and tick == previous_tick + 1 or
                    attempt == previous_attempt + 1 and previous_tick == 720 and tick == 1):
                raise Invalid("native-source-clock")
            if (sample["values"][names["engine_attempt_word"]] != attempt or
                    sample["values"][names["engine_tick_word"]] != tick or
                    sample["values"][names["engine_state_word"]] != sample["state"] or
                    sample["state"] not in (1, 2) or sample["values"][names["source_phase"]] != 0):
                raise Invalid("native-source-state")
            previous_attempt, previous_tick = attempt, tick
        elif kind == "state-count":
            if field != previous_field + 1 or clock != previous_clock + int(sample["values"][names["game_state"]] == 1):
                raise Invalid("native-state-clock")
        previous_clock, previous_field = clock, field
    if native.get("active_ticks") != previous_clock or native.get("fields") < previous_field:
        raise Invalid("native-final-clock")
    if stage in ("sustained", "completion") and kind and previous_clock != 3600:
        raise Invalid("native-incomplete-observation")
    # Absence claims require observing the complete declared interval too.
    withheld = route["case"].get("withheld_predicates", [])
    predicates = route["definitions"].get("predicates", [])
    if stage in ("interaction", "sustained", "completion"):
        for predicate in predicates:
            index = names[predicate["signal"]]
            low, high = predicate["field_window"]
            matching = [s for s in samples if low <= s["active_ticks"] <= high and s["values"][index] == predicate["equals"]]
            result = receipt["predicate_results"].get(predicate["id"])
            if predicate["id"] in withheld:
                if matching or previous_clock < high or not isinstance(result, dict) or result.get("reached") is not False:
                    raise Invalid("native-causal-control-unproven")
            elif (not matching or not isinstance(result, dict) or result.get("reached") is not True or
                  not any(s["active_ticks"] == result.get("field") and s["values"][index] == result.get("value") for s in matching)):
                raise Invalid("native-predicate-unproven")
    if stage == "completion":
        completion = next((p for p in predicates if p["signal"] == "gameplay_result" and p["equals"] == 1), None)
        if completion is None:
            raise Invalid("completion-not-defined")
        if completion["id"] in withheld:
            raise Invalid("completion-withheld")


def plan_fingerprint(binary: bytes) -> str:
    value = 14695981039346656037
    for byte in binary:
        value = ((value ^ byte) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return f"{value:016x}"


def _read_receipt(reference: object, error_prefix: str, max_bytes: int = 1024 * 1024) -> dict:
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
        raise Invalid(f"{error_prefix}-missing")
    relative = pathlib.PurePosixPath(reference["path"])
    if relative.is_absolute() or ".." in relative.parts:
        raise Invalid(f"{error_prefix}-path")
    try:
        resolved = ROOT.joinpath(*relative.parts).resolve(strict=True)
        resolved.relative_to(ROOT)
        if resolved.stat().st_size > max_bytes or digest(resolved) != reference["sha256"]:
            raise Invalid(f"{error_prefix}-digest")
        receipt = load(resolved)
    except (OSError, ValueError) as error:
        if isinstance(error, Invalid):
            raise
        raise Invalid(f"{error_prefix}-unavailable") from error
    return receipt


def _validate_host_receipt(reference: object) -> None:
    receipt = _read_receipt(reference, "host-evidence")
    required = {"schema", "renderer", "audio_open", "handler_receipt", "failure", "native_report"}
    if not isinstance(receipt, dict) or set(receipt) != required or receipt["schema"] != "genewhip-phase6-host-receipt-v1":
        raise Invalid("host-evidence-schema")
    if receipt["failure"] is not None or receipt["renderer"] != "sdl" or receipt["audio_open"] is not True or receipt["handler_receipt"] is not True:
        raise Invalid("host-evidence-failed")
    native = _read_receipt(receipt["native_report"], "host-native-evidence", 8 * 1024 * 1024)
    if native.get("termination") == "diagnostic-prefix":
        raise Invalid("native-diagnostic-prefix-is-not-route-evidence")
    if (native.get("schema") != "genewhip-route-native-v1" or native.get("status") != 0 or
            native.get("handler") != "host-script" or native.get("audio_open") is not True or
            native.get("audio_complete") is not True or
            type(native.get("fields")) is not int or native["fields"] < 1):
        raise Invalid("host-native-evidence-failed")


def self_test() -> None:
    roster = compile_routes()
    tank_game_state = next(item for row in roster["routes"] if row["fixture"] == "tank-battle"
                           for item in row["definitions"]["addresses"] if item["name"] == "game_state")
    if tank_game_state["address"] != "E0FF0059" or (int(tank_game_state["address"], 16) & 0xFFFFFF) != 0xFF0059:
        raise AssertionError("Tank source address was not retained and lowered by the documented bus mask")
    report = {"schema": "genewhip-phase6-route-report-v1", "host": {"status": "unknown"}, "routes": []}
    for route in roster["routes"]:
        clock = route["active_clock"]
        clock_values = {clock["name"]: None} if isinstance(clock, dict) and clock.get("name") else {}
        report["routes"].append({"fixture": route["fixture"], "case": route["case"]["id"],
            "identity": route["identity"], "definitions": route["definitions"], "reached": False,
            "clocks": clock_values,
            "stages": {stage: {"status": "unknown", "reached": False, "detail": "not-run", "evidence": None} for stage in STAGES}})
    validate_report(report)
    mutants = []
    missing = json.loads(json.dumps(report)); missing["routes"].pop(); mutants.append((missing, "missing-row"))
    identity = json.loads(json.dumps(report)); identity["routes"][0]["identity"]["rom_sha256"] = "0" * 64; mutants.append((identity, "identity-mismatch"))
    clock = json.loads(json.dumps(report)); clock["routes"][0]["clocks"]["active_ticks"] = "invented-clock-value"; mutants.append((clock, "clock-value"))
    definitions = json.loads(json.dumps(report)); definitions["routes"][0]["definitions"]["addresses"][0]["width"] = 8; mutants.append((definitions, "source-definition-mismatch"))
    passes = json.loads(json.dumps(report))
    for row in passes["routes"]:
        row["reached"] = True
        for item in row["stages"].values(): item.update(status="pass", reached=True, detail="fabricated; no process or observations")
    passes["host"] = {"status": "pass"}
    mutants.append((passes, "missing-pass-evidence"))
    host = json.loads(json.dumps(report)); host["host"] = {"status": "pass", "failure": "SDL unavailable"}; mutants.append((host, "suppressed-host-failure"))
    completion = json.loads(json.dumps(report)); completion["routes"][0]["reached"] = True
    completion["routes"][0]["stages"]["completion"].update(status="pass", reached=True)
    mutants.append((completion, "missing-pass-evidence"))
    for mutant, reason in mutants:
        try:
            validate_report(mutant)
        except Invalid as error:
            if str(error) != reason:
                raise AssertionError(f"mutant rejected as {error}, expected {reason}") from error
        else:
            raise AssertionError(f"accepted mutant: {reason}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--validate", type=pathlib.Path)
    parser.add_argument("--compile", type=pathlib.Path)
    parser.add_argument("--delivery-map", type=pathlib.Path)
    parser.add_argument("--fixture-id", choices=("tank-battle", "recursion94", "genewhip-independent-game-v2"))
    parser.add_argument("--client", choices=("public-core", "sdl"), default="public-core")
    args = parser.parse_args()
    try:
        selected_map = load(args.delivery_map) if args.delivery_map else None
        if selected_map is not None:
            validate_delivery_map(selected_map)
        if args.self_test:
            self_test()
        if args.validate:
            validate_report(load(args.validate))
        if args.compile:
            write_compiled(args.compile, selected_map, args.fixture_id, args.client)
        if not (args.self_test or args.validate or args.compile):
            parser.error("select --self-test, --validate REPORT, or --compile OUTPUT")
    except (Invalid, OSError, ValueError, KeyError, TypeError) as error:
        print(f"REJECT: {error}", file=sys.stderr)
        return 1
    print("phase6 route contracts: pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

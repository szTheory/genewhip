#!/usr/bin/env python3
"""Bounded, source-first Phase 5 MAME reference qualification."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import signal
import shutil
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import wave
import array
import contextlib
import uuid
import selectors

ROOT = Path(__file__).resolve().parents[2]
LOCAL = ROOT / "local-fixtures/phase5"
MAME = ROOT / "build/tool-cache/mame0289/source/genewhip"
LOCK = ROOT / "fixtures/independent-game-v2/toolchain.lock"
MAX_STDOUT = MAX_STDERR = 1_048_576
MAX_TRACE = 16 * 1024 * 1024
MAX_ROWS = 100_000
MAX_SUMMARY = 8 * 1024 * 1024
MAX_DISK = 6 * 1024 * 1024 * 1024
WATCHDOG = 600
HISTORY = Path(".route-history.json")
CORRECTION_AUTH = Path("evidence/phase5-reference-correction-authorization.json")
CORRECTION_FREEZE = Path("evidence/phase5-reference-correction-freeze.json")
CORRECTION_ATTEMPT = Path("evidence/phase5-reference-correction-attempt.json")
TITLES = ("tank-battle", "recursion94")
DECISION = "D-115"


def _observation_recovery():
    import importlib.util
    name = "phase5_observation_recovery"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def _select_decision(decision):
    """Recovery is explicit; default invocations retain the consumed D-115 gate."""
    global DECISION, CORRECTION_AUTH, CORRECTION_FREEZE, CORRECTION_ATTEMPT
    DECISION = decision
    if decision == "D-118":
        CORRECTION_AUTH = Path("evidence/phase5-reference-input-delivery-correction.json")
        CORRECTION_FREEZE = Path("evidence/phase5-reference-input-delivery-freeze.json")
        CORRECTION_ATTEMPT = Path("evidence/phase5-reference-input-delivery-attempt.json")
        return
    if decision == "D-117":
        CORRECTION_AUTH = Path("evidence/phase5-reference-observation-recovery-plan.json")
        CORRECTION_FREEZE = Path("evidence/phase5-reference-observation-freeze.json")
        CORRECTION_ATTEMPT = Path("evidence/phase5-reference-observation-attempt.json")
        return
    suffix = "recovery" if decision == "D-116" else "correction"
    CORRECTION_AUTH = Path(f"evidence/phase5-reference-{suffix}-authorization.json")
    CORRECTION_FREEZE = Path(f"evidence/phase5-reference-{suffix}-freeze.json")
    CORRECTION_ATTEMPT = Path(f"evidence/phase5-reference-{suffix}-attempt.json")


class CaptureFailure(ValueError):
    """A failed check with the observations retained before it failed."""

    def __init__(self, reason: str, observations: dict):
        super().__init__(reason)
        self.observations = observations


def _collect_process(argv, work, stdout, stderr):
    """Drain both pipes without allowing retained output beyond either cap."""
    started = time.monotonic()
    proc = subprocess.Popen(argv, cwd=work, env={"PATH": os.environ.get("PATH", ""),
        "HOME": os.path.expanduser("~"), "SDL_VIDEODRIVER": "dummy", "SDL_AUDIODRIVER": "dummy"},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
    counts = {"stdout": 0, "stderr": 0}
    caps = {"stdout": MAX_STDOUT, "stderr": MAX_STDERR}
    try:
        with stdout.open("wb") as out, stderr.open("wb") as err, selectors.DefaultSelector() as selector:
            streams = {"stdout": out, "stderr": err}
            selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
            selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map() or proc.poll() is None:
                if time.monotonic() - started > WATCHDOG:
                    raise TimeoutError("reference-mame-watchdog")
                capture_root = LOCAL / "reference-captures"
                if sum(p.stat().st_size for p in capture_root.rglob("*")
                       if p.is_file() and not p.is_symlink()) > MAX_DISK:
                    raise ValueError("reference-disk-budget")
                for key, _ in selector.select(timeout=.1):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    remaining = caps[key.data] - counts[key.data]
                    streams[key.data].write(block[:remaining])
                    counts[key.data] += min(len(block), remaining)
                    if len(block) > remaining:
                        raise ValueError("reference-" + key.data + "-byte-budget")
        proc.wait()
        return proc.returncode, time.monotonic() - started
    except BaseException:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        raise
    finally:
        proc.stdout.close()
        proc.stderr.close()


@contextlib.contextmanager
def _retained_capture(scenario, case, script, rom, reference):
    root = LOCAL / "reference-captures"
    root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="capture-", dir=root))
    receipt = work / "receipt.json"
    reference.update(run_id=work.name, receipt=receipt.relative_to(ROOT).as_posix())
    request = {"title_id": scenario["title_id"], "case": case["id"],
               "scenario_sha256": hashlib.sha256(json.dumps(scenario, sort_keys=True).encode()).hexdigest(),
               "rom_sha256": sha(rom), "mame_sha256": sha(MAME),
               "script_sha256": hashlib.sha256(script.encode()).hexdigest(),
               "producer_sha256": sha(Path(__file__))}
    write_json(work / "request.json", request)
    (work / "producer.py").write_bytes(Path(__file__).read_bytes())
    if DECISION in ("D-117", "D-118"):
        (work / "observation-producer.py").write_bytes(Path(__file__).with_name("phase5_observation_recovery.py").read_bytes())
    failure = None
    try:
        yield work
    except Exception as exc:
        failure = str(exc).splitlines()[0][:512]
        if isinstance(exc, CaptureFailure):
            exc.observations.setdefault("raw_capture", reference)
            raise
        raise CaptureFailure(failure, {"raw_capture": reference}) from exc
    finally:
        # A failed parser, predicate or process must never delete its inputs.
        files = {p.relative_to(work).as_posix(): {"bytes": p.stat().st_size, "sha256": sha(p)}
                 for p in work.rglob("*") if p.is_file() and not p.is_symlink()
                 and p != receipt and p.stat().st_size <= MAX_DISK}
        write_json(receipt, {"schema": "genewhip-phase5-capture-receipt-v1",
                            "run_id": work.name, "request": request,
                            "capture_status": "error" if failure else "complete",
                            "reason": failure, "files": files})
        reference["receipt_sha256"] = sha(receipt)


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    if len(data.encode()) > MAX_SUMMARY:
        raise ValueError("reference-summary-byte-budget")
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(data, encoding="utf-8")
    os.replace(tmp, path)


def _input_digest(scenario):
    inputs = scenario.get("input_schedule")
    if "input_program" in scenario:
        inputs = {"input_schedule": inputs, "input_program": scenario["input_program"]}
    return hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _historical_blob(revision, name):
    return subprocess.run(["git", "show", revision + ":" + name], cwd=ROOT,
                          capture_output=True, timeout=10, check=True).stdout


def _verify_correction_freeze(ledger: Path, eligibility: Path):
    """D-115 changes source identities once, while preserving consumed history."""
    auth = read_json(ROOT / CORRECTION_AUTH)
    frozen = read_json(ROOT / CORRECTION_FREEZE)
    if (auth.get("decision") != DECISION or auth.get("status") != "granted"
            or auth.get("scope", {}).get("titles") != list(TITLES)
            or auth["scope"].get("qualification_cycles") != 1
            or auth["scope"].get("repetitions_per_case") != 2
            or auth["scope"].get("active_fields") != 3600
            or auth["scope"].get("total_fields_ceiling") != 7200
            or auth["scope"].get("further_retry") is not False
            or frozen.get("status") != "source-frozen"
            or frozen.get("authorization_sha256") != sha(ROOT / CORRECTION_AUTH)
            or frozen.get("producer_sha256") != sha(Path(__file__))
            or set(frozen.get("routes", {})) != set(TITLES)):
        raise ValueError("reference-correction-authorization-or-freeze")
    if DECISION == "D-116":
        if any(auth["scope"].get(name) is not False for name in
               ("new_builds", "new_titles", "weaken_gameplay_predicates", "candidate_baseline_before_pair", "phase6")):
            raise ValueError("reference-recovery-scope")
        if (sha(ROOT / "evidence/phase5-reference.json") != auth["prior_reference_sha256"]
                or sha(ROOT / "evidence/phase5-reference-correction-attempt.json") != auth["prior_d115_attempt_sha256"]
                or frozen.get("decision") != DECISION):
            raise ValueError("reference-recovery-d115-history-changed")
        # Verify the immutable authorization anchors independently of current rows.
        for name, digest in (("fixtures/candidate-screening-v2.json", auth["prior_ledger_sha256"]),
                             ("evidence/phase5-eligibility-v2.json", auth["prior_eligibility_sha256"])):
            original = _historical_blob(auth["prior_revision"], name)
            if hashlib.sha256(original).hexdigest() != digest:
                raise ValueError("reference-recovery-prior-anchor")
    current = read_json(ledger)
    eligible = {r["title_id"]: r for r in read_json(eligibility)["candidates"]}
    for title in TITLES:
        prior = auth["prior_titles"][title]
        row = next(r for r in current["candidates"] if r["id"] == title)
        history = row["identity_history"]
        if not any(e["sha256"] == prior["last_event_sha256"] for e in history):
            raise ValueError("reference-correction-history-prefix")
        expected = dict(prior["counters"])
        if DECISION == "D-115":
            expected["route_authoring_corrections"] += 1
        if row["counters"] != expected or row["build_evidence"] != prior["build_evidence"]:
            raise ValueError("reference-correction-counter-or-build-change")
        for name, digest in prior["files"].items():
            if sha(ROOT / prior["package"] / name) != digest:
                raise ValueError("reference-correction-old-package-changed")
        entry = frozen["routes"][title]
        generation = "route-v3" if DECISION == "D-116" and title == "tank-battle" else "route-v2"
        if entry.get("package") != f"local-fixtures/phase5/{title}/{generation}":
            raise ValueError("reference-correction-package")
        if DECISION == "D-116":
            events = [e for e in history if e.get("event") == "identity_observed"
                      and e.get("details", {}).get("decision") == DECISION]
            if (len(events) != 1 or events[0]["details"].get("authorization_sha256") != sha(ROOT / CORRECTION_AUTH)
                    or events[0]["details"].get("frozen") != entry["frozen"]
                    or events[0]["details"].get("exception_cycle_charge") != 1):
                raise ValueError("reference-recovery-journal-charge")
            if (entry["files"].get("oracle.json") != prior["files"].get("oracle.json")
                    or (title == "recursion94" and entry["files"] != prior["files"])):
                raise ValueError("reference-recovery-changed-oracle-or-recursion")
        for name, digest in entry["files"].items():
            if name not in ("scenario.json", "oracle.json", "mame.lua", "SOURCE-REVIEW.md"):
                raise ValueError("reference-correction-package-file")
            if sha(ROOT / entry["package"] / name) != digest:
                raise ValueError("reference-correction-frozen-file-changed")
        if not {"scenario.json", "oracle.json", "mame.lua"}.issubset(entry["files"]):
            raise ValueError("reference-correction-package-files")
        scenario = read_json(ROOT / entry["package"] / "scenario.json")
        oracle = read_json(ROOT / entry["package"] / "oracle.json")
        original = read_json(ROOT / prior["package"] / "scenario.json")["identities"]
        for key in ("rom_sha256", "rom_path", "source_revision", "source_archive_sha256",
                    "build_sha256", "build_receipt_sha256", "mame_build_sha256"):
            if scenario["identities"].get(key) != original.get(key):
                raise ValueError("reference-correction-changed-source-rom-or-tool")
        if (freeze_route(scenario, oracle) != entry["frozen"]
                or eligible[title].get("reference_route", {}).get("frozen") != entry["frozen"]):
            raise ValueError("reference-correction-frozen-identity")
    return frozen


def _require_committed(paths):
    for path in paths:
        relative = path.resolve().relative_to(ROOT.resolve()).as_posix()
        result = subprocess.run(["git", "show", "HEAD:" + relative], cwd=ROOT,
                                capture_output=True, timeout=10, check=False)
        if result.returncode or result.stdout != path.read_bytes():
            raise ValueError("reference-correction-uncommitted:" + relative)


def _begin_correction_cycle(ledger: Path, eligibility: Path, title_id=None):
    if title_id is not None:
        raise ValueError("reference-correction-requires-single-whole-pair-cycle")
    _verify_correction_freeze(ledger, eligibility)
    paths = [ROOT / p for p in (CORRECTION_AUTH, CORRECTION_FREEZE)]
    paths += [Path(__file__), ledger, eligibility]
    _require_committed(paths)
    attempt = {"schema": "genewhip-phase5-reference-correction-attempt-v1",
               "decision": DECISION, "status": "started",
               "authorization_sha256": sha(ROOT / CORRECTION_AUTH),
               "freeze_sha256": sha(ROOT / CORRECTION_FREEZE),
               "producer_sha256": sha(Path(__file__)), "started_at_unix": time.time(),
               "titles": list(TITLES), "further_retry": False}
    path = ROOT / CORRECTION_ATTEMPT
    try:
        with path.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(attempt, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("reference-correction-cycle-already-consumed") from exc
    return attempt


def freeze_route(scenario: dict, oracle: dict) -> dict:
    """Validate and bind a source-authored route before any emulator run."""
    if scenario.get("schema") != "genewhip-phase5-route-v1":
        raise ValueError("route-schema")
    if oracle.get("schema") != "genewhip-phase5-oracle-v1":
        raise ValueError("oracle-schema")
    if scenario.get("title_id") != oracle.get("title_id"):
        raise ValueError("route-oracle-title-identity")
    policy = scenario.get("budget")
    if not isinstance(policy, dict):
        raise ValueError("route-budget-missing")
    boot, interaction = policy.get("boot_fields"), policy.get("interaction_fields")
    active, total = policy.get("active_fields"), policy.get("total_fields")
    if not all(type(x) is int for x in (boot, interaction, active, total)):
        raise ValueError("route-budget-type")
    if not (1 <= boot <= 120 and boot < interaction <= 600 and active == 3600
            and boot + active <= total <= 7200):
        raise ValueError("route-budget-ceiling")
    if scenario.get("profile") != "VA3-NTSC-U":
        raise ValueError("route-profile")
    observation = scenario.get("observation")
    if observation is not None and (observation.get("kind") != "completed-source-step-write-tap-v1"
            or observation.get("phase_address") != "FF1516"
            or observation.get("phase_idle_data") != 0
            or observation.get("tap_return") != "nil-preserves-guest-data"
            or observation.get("guest_writes") is not False):
        raise ValueError("route-unsafe-completed-step-observer")
    events = scenario.get("input_schedule")
    program = scenario.get("input_program")
    if (not isinstance(events, list) or (not events and not program)
            or (program is not None and (not isinstance(program, dict) or not program))):
        raise ValueError("route-input-schedule")
    last = (-1, -1)
    seen = {}
    for order, event in enumerate(events):
        if (not isinstance(event, dict) or type(event.get("field")) is not int
                or event["field"] < 1 or event["field"] > total
                or event.get("control") not in scenario.get("controls", [])
                or type(event.get("asserted")) is not bool):
            raise ValueError("route-input-event")
        key = (event["field"], order)
        if key < last:
            raise ValueError("route-input-order")
        last = key
        control_key = (event["field"], event["control"])
        if control_key in seen and seen[control_key] != event["asserted"]:
            raise ValueError("route-conflicting-same-control-event")
        seen[control_key] = event["asserted"]
    cases = scenario.get("cases")
    if not isinstance(cases, list) or len(cases) < 2:
        raise ValueError("route-cases")
    ids = [c.get("id") for c in cases if isinstance(c, dict)]
    if len(ids) != len(cases) or len(ids) != len(set(ids)):
        raise ValueError("route-case-identity")
    predicates = oracle.get("predicates")
    if not isinstance(predicates, list) or len(predicates) < 2:
        raise ValueError("oracle-progress-predicates")
    windows = []
    for p in predicates:
        w = p.get("field_window") if isinstance(p, dict) else None
        if (not isinstance(w, list) or len(w) != 2 or any(type(x) is not int for x in w)
                or not (1 <= w[0] < w[1] <= total)):
            raise ValueError("oracle-predicate-window")
        windows.append(w)
    if windows[0][1] >= windows[1][0]:
        raise ValueError("oracle-progress-predicates-not-separated")
    late_floor = boot + active * 3 // 4
    if not any(w[0] >= late_floor for w in windows):
        raise ValueError("oracle-late-milestone")
    required = {"source", "source_sha256", "build_sha256", "rom_sha256", "input_sha256"}
    identities = scenario.get("identities")
    if not isinstance(identities, dict) or not required.issubset(identities):
        raise ValueError("route-identities")
    for key in required - {"source"}:
        if not re.fullmatch(r"[0-9a-f]{64}", str(identities[key])):
            raise ValueError("route-identity-digest:" + key)
    if not isinstance(identities["source"], str) or not identities["source"].startswith("local-fixtures/phase5/"):
        raise ValueError("route-source-provenance")
    if scenario.get("reset") != "fresh-process; source-defined initial state; no RAM pokes":
        raise ValueError("route-reset-assumption")
    if not oracle.get("authority", "").startswith("Pinned source semantics"):
        raise ValueError("oracle-authority")
    return {"scenario_sha256": hashlib.sha256(json.dumps(scenario, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "oracle_sha256": hashlib.sha256(json.dumps(oracle, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "script_sha256": identities.get("mame_script_sha256"),
            "title_id": scenario["title_id"], "cases": ids}


def parse_capture(data: bytes, scenario: dict) -> list[dict]:
    if len(data) > MAX_TRACE:
        raise ValueError("reference-trace-byte-budget")
    rows = []
    previous = 0
    previous_field = 0
    previous_active = -1
    source_steps = scenario.get("observation", {}).get("kind") == "completed-source-step-write-tap-v1"
    allowed = {item["id"] for item in scenario["cases"]}
    for raw in data.splitlines():
        if not raw:
            continue
        try:
            parts = raw.decode("ascii").split(",")
            if len(parts) != 5 or parts[0] != "GWCAP":
                raise ValueError
            _, case_id, seq_text, field_text, values = parts
            row = {"case": case_id, "sequence": int(seq_text), "field": int(field_text), "signals": {}}
            for item in values.split(";"):
                name, value = item.split("=", 1)
                if not name or name in row["signals"]:
                    raise ValueError
                row["signals"][name] = int(value, 10)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("reference-capture-malformed-row") from exc
        if (row["case"] not in allowed or row["sequence"] <= previous
                or row["field"] < previous_field or row["field"] < 1
                or (row["field"] == previous_field and (not source_steps
                    or row["signals"].get("active_ticks", -1) <= previous_active))
                or row["field"] > scenario["budget"]["total_fields"] or not row["signals"]):
            raise ValueError("reference-capture-row-order-or-identity")
        if source_steps and (type(row["signals"].get("active_ticks")) is not int
                or not previous_active <= row["signals"]["active_ticks"] <= 3600):
            raise ValueError("reference-source-step-clock-order")
        previous = row["sequence"]
        previous_field = row["field"]
        previous_active = row["signals"].get("active_ticks", -1)
        rows.append(row)
        if len(rows) > MAX_ROWS:
            raise ValueError("reference-trace-row-budget")
    if not rows:
        raise ValueError("reference-trace-missing")
    return rows


def _parse_inputs(data: bytes, scenario: dict, case_id: str):
    inputs, previous, seen = [], 0, {}
    for line in data.splitlines():
        if not line.startswith(b"GWINPUT,"):
            continue
        try:
            tag, case, field, control, value = line.decode("ascii").split(",")
            field = int(field)
        except (ValueError, UnicodeError) as exc:
            raise ValueError("reference-input-capture-malformed") from exc
        if (case != case_id or not previous <= field <= scenario["budget"]["total_fields"]
                or field < 1 or control not in scenario["controls"] or value not in ("true", "false")):
            raise ValueError("reference-input-capture-identity-or-order")
        key = field, control
        if key in seen and seen[key] != value:
            raise ValueError("reference-input-capture-conflicting-transition")
        seen[key] = value
        previous = field
        inputs.append({"field": field, "control": control, "asserted": value == "true"})
        if len(inputs) > MAX_ROWS:
            raise ValueError("reference-input-capture-row-budget")
    # Same-field independent control transitions commute.
    return sorted(inputs, key=lambda event: (event["field"], event["control"]))


def _capture_complete(rows, scenario):
    if rows[-1]["field"] == scenario["budget"]["total_fields"]:
        return True
    stop = scenario.get("stop_rule", {})
    clock = scenario.get("progress_clock")
    return (stop.get("kind") == "active-fields-or-total" and stop.get("active_fields") == 3600
            and set(stop).issubset({"kind", "active_fields", "total_fields"})
            and stop.get("total_fields", scenario["budget"]["total_fields"]) == scenario["budget"]["total_fields"]
            and clock is not None and rows[-1]["signals"].get(clock, 0) >= 3600)


def check_predicates(scenario: dict, oracle: dict, captures: dict[str, list[dict]]) -> None:
    if set(captures) != {c["id"] for c in scenario["cases"]}:
        raise ValueError("reference-case-roster")
    predicates = oracle["predicates"]
    primary = captures[scenario["cases"][0]["id"]]
    clock = scenario.get("progress_clock")
    required_signals = {p["signal"] for p in predicates} | ({clock} if clock else set())
    for rows in captures.values():
        if any(not required_signals.issubset(row["signals"]) for row in rows):
            raise ValueError("reference-capture-missing-signal")
    def coordinate(row):
        return row["signals"][clock] if clock else row["field"]
    for predicate in predicates:
        field_key, field_value = predicate["signal"], predicate["equals"]
        lo, hi = predicate["field_window"]
        if not any(lo <= coordinate(r) <= hi and r["signals"].get(field_key) == field_value for r in primary):
            raise ValueError("reference-source-progress:" + predicate["id"])
        if any(coordinate(r) < lo and r["signals"].get(field_key) == field_value for r in primary):
            raise ValueError("reference-progress-before-window:" + predicate["id"])
    for control in scenario["cases"][1:]:
        withheld = control.get("withheld_predicates", [])
        if control.get("withheld_predicate"):
            withheld = [control["withheld_predicate"]]
        for withhold in withheld:
            predicate = next((p for p in predicates if p["id"] == withhold), None)
            if predicate is None:
                raise ValueError("reference-control-predicate-identity")
            rows = captures[control["id"]]
            lo, hi = predicate["field_window"]
            if any(lo <= coordinate(r) <= hi and r["signals"].get(predicate["signal"]) == predicate["equals"] for r in rows):
                raise ValueError("reference-causal-withheld:" + predicate["id"])


def _lua_script(scenario: dict, case: dict, template: str) -> str:
    # Values are literals from the frozen source-authored package; no candidate
    # code is executed on the host and the Lua driver has read-only guest access.
    events = [e for e in scenario["input_schedule"] if e.get("case", scenario["cases"][0]["id"]) == case["id"]]
    def literal(value):
        if isinstance(value, bool): return "true" if value else "false"
        if isinstance(value, int): return str(value)
        if isinstance(value, str): return json.dumps(value)
        if isinstance(value, list): return "{" + ",".join(literal(x) for x in value) + "}"
        if isinstance(value, dict): return "{" + ",".join("[" + literal(k) + "]=" + literal(v) for k, v in value.items()) + "}"
        raise TypeError(type(value).__name__)
    substitutions = {
        "@@CONTROLS@@": literal(scenario["controls"]),
        "@@EVENTS@@": literal(events),
        "@@ADDRESSES@@": literal(scenario["addresses"]),
        "@@CONTROLLER@@": literal(scenario.get("controller")) if scenario.get("controller") else "nil",
        "@@INPUT_PROGRAM@@": literal(scenario.get("input_program")) if scenario.get("input_program") else "nil",
        "@@STOP_RULE@@": literal(scenario.get("stop_rule")) if scenario.get("stop_rule") else "nil",
        "@@ACTIVE_CLOCK@@": literal(scenario.get("active_clock")) if scenario.get("active_clock") else "nil",
        "@@TOTAL_FIELDS@@": str(scenario["budget"]["total_fields"]),
        "@@CASE_ID@@": literal(case["id"]),
        "@@RENDER_FIELD@@": str(scenario.get("render_field", 0)),
        "@@RENDER_FILE@@": literal("render.png"),
        "@@RENDER_CHECK@@": literal(scenario.get("render_check")) if scenario.get("render_check") else "nil",
    }
    for key, value in substitutions.items():
        template = template.replace(key, value)
    if "@@" in template:
        raise ValueError("reference-script-template-placeholder")
    return template


def _run_case(scenario: dict, case: dict, rom: Path, script: str, media: bool = False,
              media_dir: Path | None = None) -> dict:
    lock = read_json(LOCK)
    expected = lock["mame"]["executable_build_sha256"]
    if not MAME.is_file() or sha(MAME) != expected:
        raise RuntimeError("reference-mame-identity")
    if not rom.is_file() or sha(rom) != scenario["identities"]["rom_sha256"]:
        raise RuntimeError("reference-rom-identity")
    retained = {}
    with _retained_capture(scenario, case, script, rom, retained) as work:
        lua = work / "route.lua"
        stdout, stderr = work / "stdout", work / "stderr"
        lua.write_text(script, encoding="utf-8")
        argv = [str(MAME), "genesis", "-cart", str(rom), "-noreadconfig", "-skip_gameinfo",
                "-snapshot_directory", str(work), "-seconds_to_run", "130",
                "-autoboot_script", str(lua), "-autoboot_delay", "0"]
        if DECISION in ("D-116", "D-117", "D-118"):
            argv.append("-nothrottle")
        if media:
            argv.extend(["-mngwrite", str(work / "capture.mng"), "-wavwrite", str(work / "capture.wav")])
        else:
            argv.extend(["-video", "none"])
            if scenario.get("audio"):
                argv.extend(["-wavwrite", str(work / "capture.wav")])
        returncode, elapsed = _collect_process(argv, work, stdout, stderr)
        out, err = stdout.read_bytes(), stderr.read_bytes()
        if returncode != 0:
            raise RuntimeError(f"reference-mame-exit:{returncode}")
        captures = [line for line in out.splitlines() if line.startswith(b"GWCAP,")]
        raw = b"\n".join(captures) + (b"\n" if captures else b"")
        (work / "capture.csv").write_bytes(raw)
        if any(line.startswith(b"GWERROR,") for line in out.splitlines()):
            raise ValueError("reference-input-program-error")
        parsed = parse_capture(raw, scenario)
        selected = [r for r in parsed if r["case"] == case["id"]]
        if len(selected) != len(parsed):
            raise ValueError("reference-capture-wrong-case")
        if not _capture_complete(selected, scenario):
            raise ValueError("reference-capture-incomplete-field-budget")
        result = {"case": case["id"], "elapsed_seconds": elapsed,
                "stdout_sha256": hashlib.sha256(out).hexdigest(), "stderr_sha256": hashlib.sha256(err).hexdigest(),
                "rows": selected, "status": "pass", "raw_capture": retained}
        if scenario.get("input_program"):
            result["inputs"] = _parse_inputs(out, scenario, case["id"])
            if not result["inputs"]:
                raise ValueError("reference-input-program-no-transitions")
        audio_line = next((line.decode("ascii", "ignore").strip() for line in out.splitlines()
                           if line.startswith(b"GWAUDIO,")), None)
        if audio_line:
            fields = audio_line.split(",")
            if len(fields) != 4 or fields[1] != case["id"]:
                raise ValueError("reference-audio-capture-malformed")
            result["audio"] = {"samples": int(fields[2]), "peak": float(fields[3])}
        pixel_line = next((line.decode("ascii", "ignore").strip() for line in out.splitlines()
                           if line.startswith(b"GWPIXEL,")), None)
        if pixel_line:
            fields = pixel_line.split(",")
            if len(fields) != 7 or fields[1] != case["id"]:
                raise ValueError("reference-render-pixel-malformed")
            result["render_pixel"] = {"field": int(fields[2]), "x": int(fields[3]), "y": int(fields[4]),
                "foreground": int(fields[5]), "background": int(fields[6])}
        if scenario.get("audio"):
            wav_path = work / "capture.wav"
            if not wav_path.is_file() or wav_path.stat().st_size <= 44:
                raise ValueError("reference-audio-file-missing")
            if wav_path.stat().st_size > MAX_DISK:
                raise ValueError("reference-audio-file-budget")
            with wave.open(str(wav_path), "rb") as wav_file:
                frames = wav_file.readframes(wav_file.getnframes())
                sample_width = wav_file.getsampwidth()
                if sample_width == 2:
                    samples = array.array("h"); samples.frombytes(frames)
                    peak = max((abs(s) for s in samples), default=0)
                elif sample_width == 1:
                    peak = max((abs(byte - 128) for byte in frames), default=0)
                else:
                    raise ValueError("reference-audio-sample-width")
                result["audio_file"] = {"bytes": wav_path.stat().st_size, "sha256": sha(wav_path),
                    "frames": wav_file.getnframes(), "sample_rate": wav_file.getframerate(), "peak": peak}
            if media_dir:
                media_dir.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(wav_path, media_dir / "audio.wav")
        if scenario.get("render_field") or scenario.get("render_when"):
            render_path = work / "render.png"
            if not render_path.is_file() or not render_path.stat().st_size:
                raise ValueError("reference-render-snapshot-missing")
            if render_path.stat().st_size > MAX_DISK:
                raise ValueError("reference-render-snapshot-budget")
            result["render"] = {"bytes": render_path.stat().st_size, "sha256": sha(render_path)}
            if media_dir:
                media_dir.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(render_path, media_dir / "render.png")
        if media:
            for label, filename in (("render", "capture.mng"), ("audio", "capture.wav")):
                path = work / filename
                if not path.is_file() or not path.stat().st_size:
                    raise ValueError("reference-media-missing:" + label)
                if path.stat().st_size > MAX_DISK:
                    raise ValueError("reference-media-byte-budget:" + label)
                result[label] = {"bytes": path.stat().st_size, "sha256": sha(path)}
                if media_dir:
                    media_dir.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, media_dir / f"{label}.{path.suffix.lstrip('.')}")
        return result


def qualify_retained_control() -> dict:
    """Exercise the new input/selected-memory/render/audio path on the fixed 720-field control."""
    source_scenario = read_json(ROOT / "fixtures/independent-game-v2/scenario.json")
    source_oracle = read_json(ROOT / "fixtures/independent-game-v2/oracle.json")
    case = next(c for c in source_scenario["cases"] if c["id"] == "sustained-play")
    events = [{"field": e["frame"], "control": e["control"], "asserted": e["asserted"]}
              for e in case["input_schedule"]]
    scenario = {"schema": "genewhip-phase5-route-v1", "title_id": "genewhip-independent-game-v2",
                "profile": source_scenario["profile"], "reset": "fresh-process; source-defined initial state; no RAM pokes",
                "budget": {"boot_fields": 120, "interaction_fields": 122, "active_fields": 600, "total_fields": 720},
                "controls": sorted({e["control"] for e in events}), "input_schedule": events,
                "cases": [{"id": case["id"]}], "render_field": 30,
                "render_check": {"address": "FF0003", "cell_width": 8, "x_offset": 4, "y": 44},
                "audio": {"expectation": "source emits non-silent PSG tone after B edge"}, "addresses": [
                    {"name": "state", "address": "FF0001"}, {"name": "position", "address": "FF0003"}],
                "identities": {"source": "fixtures/independent-game-v2/src/game.s",
                    "source_sha256": source_scenario["source"]["sha256"],
                    "build_sha256": read_json(ROOT / "fixtures/independent-game-v2/toolchain.lock")["mame"]["executable_build_sha256"],
                    "rom_sha256": source_scenario["rom"]["sha256"], "input_sha256":
                    hashlib.sha256(json.dumps(events, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}}
    route = LOCAL / "tank-battle/route-v1/mame.lua"
    script = _lua_script(scenario, scenario["cases"][0], route.read_text(encoding="utf-8"))
    rom = ROOT / source_scenario["rom"]["relative_path"]
    retained_media = ROOT / "build/phase5-reference-retained-control"
    result = _run_case(scenario, scenario["cases"][0], rom, script, media_dir=retained_media)
    result["render"]["path"] = "build/phase5-reference-retained-control/render.png"
    final = result["rows"][-1]
    if final["field"] != 720 or final["signals"].get("state") != 1 or not 39 <= final["signals"].get("position", -1) <= 39:
        raise ValueError("retained-control-source-observation")
    if result.get("audio_file", {}).get("peak", 0) <= 0:
        raise ValueError("retained-control-audio-observation")
    pixel = result.get("render_pixel")
    if not pixel or pixel["foreground"] == pixel["background"]:
        raise ValueError("retained-control-render-pixel-observation")
    result["control_identity"] = {"scenario_sha256": sha(ROOT / "fixtures/independent-game-v2/scenario.json"),
                                  "oracle_sha256": sha(ROOT / "fixtures/independent-game-v2/oracle.json"),
                                  "rom_sha256": sha(rom), "field_count": final["field"]}
    prior = read_json(ROOT / "build/phase4/game-successor-reference.json")
    visual_audio = next(c for c in prior["cases"] if c["id"] == case["id"])
    if visual_audio["status"] != "pass" or visual_audio["frames"] != 720:
        raise ValueError("retained-control-render-audio-evidence")
    result["existing_render_audio_observation"] = {
        "evidence_sha256": sha(ROOT / "build/phase4/game-successor-reference.json"),
        "geometry": visual_audio["observed"]["geometry"],
        "psg_writes": visual_audio["observed"]["psg_writes"],
        "trace_sha256": visual_audio["trace"]["sha256"]}
    result["status"] = "pass"
    return result


def qualify_candidate(scenario: dict, oracle: dict, rom: Path, script: str) -> dict:
    frozen = freeze_route(scenario, oracle)
    routes = []
    attempted = []
    for repetition in (1, 2):
        captured = {}
        summaries = []
        try:
            for case in scenario["cases"]:
                attempted.append({"repetition": repetition, "case": case["id"]})
                result = _run_case(scenario, case, rom, _lua_script(scenario, case, script))
                captured[case["id"]] = result["rows"]
                summaries.append(result)
            clock = scenario.get("progress_clock")
            maximum = (max((row["signals"].get(clock, 0) for row in
                            captured[scenario["cases"][0]["id"]]), default=0) if clock else None)
            if clock and maximum < scenario["budget"]["active_fields"]:
                raise CaptureFailure("reference-active-field-budget", {
                    "active_clock_observation": {"signal": clock, "maximum": maximum,
                                                 "required_minimum": scenario["budget"]["active_fields"]}})
            check_predicates(scenario, oracle, captured)
        except (ValueError, RuntimeError, OSError, TimeoutError) as exc:
            details = dict(getattr(exc, "observations", {}))
            details.update(runs=routes + [{"repetition": repetition, "cases": summaries}],
                           attempted_case_runs=attempted,
                           completed_case_runs=sum(len(r["cases"]) for r in routes) + len(summaries),
                           unattempted_cases=[c["id"] for c in scenario["cases"]
                                              if {"repetition": repetition, "case": c["id"]} not in attempted],
                           not_run_cases=[c["id"] for c in scenario["cases"] if c["id"] not in captured],
                           repetitions_not_run=list(range(repetition + 1, 3)))
            raise CaptureFailure(str(exc), details) from exc
        routes.append({"repetition": repetition, "status": "pass", "cases": summaries})
    if scenario.get("audio", {}).get("require_non_silent"):
        primary_audio = routes[-1]["cases"][0].get("audio_file", {})
        if primary_audio.get("peak", 0) <= 0:
            raise ValueError("reference-audio-non-silent-predicate")
    if routes[0] != routes[1]:
        # Timings and raw output digests are evidence, but semantic rows must agree.
        for a, b in zip(routes[0]["cases"], routes[1]["cases"]):
            if a["rows"] != b["rows"] or a.get("inputs") != b.get("inputs"):
                return {"title_id": scenario["title_id"], "status": "unknown", "reason": "fresh-runs-disagree",
                        "frozen": frozen, "runs": routes}
    return {"title_id": scenario["title_id"], "status": "pass", "frozen": frozen, "runs": routes}


def _contract_tests() -> int:
    import unittest
    import importlib.util
    contract_path = ROOT / "tests/evidence/phase5_reference_contract.py"
    spec = importlib.util.spec_from_file_location("phase5_reference_contract", contract_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("reference-contract-import")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    ReferenceContract = module.ReferenceContract
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReferenceContract)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def _route_package(title: str) -> Path:
    if DECISION == "D-118":
        return LOCAL / title / ("route-v3" if title == "tank-battle" else "route-v4")
    if DECISION == "D-117":
        return LOCAL / title / "route-v3"
    if DECISION == "D-116":
        return LOCAL / title / ("route-v3" if title == "tank-battle" else "route-v2")
    generation = "route-v2" if (ROOT / CORRECTION_FREEZE).is_file() else "route-v1"
    return LOCAL / title / generation


def _routes(title_id: str | None = None):
    routes = []
    for title in ("tank-battle", "recursion94"):
        if title_id and title != title_id:
            continue
        base = _route_package(title)
        scenario = read_json(base / "scenario.json")
        oracle = read_json(base / "oracle.json")
        frozen = freeze_route(scenario, oracle)
        routes.append((scenario, oracle, frozen))
    return routes


def _author_check(ledger: Path, eligibility: Path) -> int:
    if not ledger.is_file() or not eligibility.is_file():
        raise ValueError("reference-ledger-or-eligibility-missing")
    if read_json(ledger).get("schema") != "genewhip-phase5-screening-v2":
        raise ValueError("reference-ledger-schema")
    if DECISION in ("D-116", "D-117", "D-118"):
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools/evidence"))
        import phase5_records
        phase5_records.validate_screening(read_json(ledger))
    if DECISION in ("D-117", "D-118"):
        _observation_recovery().verify_freeze(sys.modules[__name__], ledger, eligibility)
    elif (ROOT / CORRECTION_FREEZE).is_file():
        _verify_correction_freeze(ledger, eligibility)
    elig = read_json(eligibility)
    eligible_rows = {row.get("title_id"): row for row in elig.get("candidates", [])
                     if row.get("decision") == "eligible"}
    lock = read_json(LOCK)["mame"]
    if not MAME.is_file() or sha(MAME) != lock.get("executable_build_sha256"):
        raise ValueError("reference-mame-executable-identity")
    for scenario, oracle, frozen in _routes():
        if scenario["title_id"] not in eligible_rows:
            raise ValueError("route-title-not-build-eligible:" + scenario["title_id"])
        identities = scenario["identities"]
        candidate = eligible_rows[scenario["title_id"]]
        if candidate.get("reference_route", {}).get("source_audit", {}).get("status") == "invalid":
            raise ValueError("route-source-contract-invalid:" + scenario["title_id"])
        if identities.get("source_archive_sha256") != candidate.get("source_archive_sha256"):
            raise ValueError("route-source-archive-identity:" + scenario["title_id"])
        for material in scenario["identities"].get("source_materials", []):
            path = ROOT / material["path"]
            if not path.is_file() or sha(path) != material["sha256"]:
                raise ValueError("route-source-identity:" + material["path"])
        input_digest = _input_digest(scenario)
        if input_digest != identities.get("input_sha256"):
            raise ValueError("route-input-identity:" + scenario["title_id"])
        if sha(ROOT / identities["build_summary_path"]) != identities.get("build_sha256"):
            raise ValueError("route-build-summary-identity:" + scenario["title_id"])
        if sha(ROOT / identities["build_receipt_path"]) != identities.get("build_receipt_sha256"):
            raise ValueError("route-build-receipt-identity:" + scenario["title_id"])
        summary = read_json(ROOT / identities["build_summary_path"])
        if summary.get("title_id") != scenario["title_id"] or summary.get("source_revision") != candidate.get("source_revision"):
            raise ValueError("route-build-lineage-identity:" + scenario["title_id"])
        pair = summary.get("build_pair", summary)
        if pair.get("comparison") not in ("byte-identical",) and pair.get("status") != "byte-identical":
            if pair.get("comparison", {}).get("status") != "byte-identical":
                raise ValueError("route-build-pair-not-identical:" + scenario["title_id"])
        locked_revision = lock.get("source_revision", "").split("commit ")[-1].split(";")[0]
        if (identities.get("mame_build_sha256") != lock.get("executable_build_sha256")
                or identities.get("mame_source_revision") != locked_revision
                or identities.get("mame_source_sha256") != lock.get("source_archive_sha256")
                or identities.get("mame_patch_sha256") != lock.get("patch_sha256")):
            raise ValueError("route-mame-locked-identity:" + scenario["title_id"])
        rom = ROOT / scenario["identities"]["rom_path"]
        if not rom.is_file() or sha(rom) != scenario["identities"]["rom_sha256"]:
            raise ValueError("route-rom-identity:" + scenario["title_id"])
        package = _route_package(scenario["title_id"])
        if sha(package / "mame.lua") != identities["mame_script_sha256"]:
            raise ValueError("route-script-identity:" + scenario["title_id"])
        print(f"SOURCE-FROZEN {frozen['title_id']} scenario={frozen['scenario_sha256']} oracle={frozen['oracle_sha256']}")
    return 0


def _qualify_next(ledger: Path, eligibility: Path, output: Path, title_id: str | None = None) -> int:
    if DECISION in ("D-117", "D-118"):
        return _observation_recovery().qualify(sys.modules[__name__], ledger, eligibility, output, title_id)
    ledger, eligibility, output = ledger.resolve(), eligibility.resolve(), output.resolve()
    if DECISION == "D-116" and output != (ROOT / "evidence/phase5-reference-d116.json").resolve():
        raise ValueError("reference-recovery-output-path")
    for row in read_json(eligibility).get("candidates", []):
        if (not title_id or row.get("title_id") == title_id) and row.get("reference_route", {}).get("reference_observation"):
            raise ValueError("reference-observed-route-requires-explicit-disposition:" + row["title_id"])
    if not (ROOT / CORRECTION_FREEZE).is_file():
        return _qualify_next_impl(ledger, eligibility, output, title_id)
    _author_check(ledger, eligibility)
    attempt = _begin_correction_cycle(ledger, eligibility, title_id)
    code, reason = 2, "qualification-interrupted"
    try:
        code = _qualify_next_impl(ledger, eligibility, output, title_id)
        reason = None if code == 0 else "qualification-did-not-establish-pair"
        return code
    except BaseException as exc:
        reason = type(exc).__name__ + ": " + str(exc).splitlines()[0][:512]
        raise
    finally:
        write_json(ROOT / CORRECTION_ATTEMPT, {**attempt,
                   "status": "pass" if code == 0 else "failed", "reason": reason,
                   "completed_at_unix": time.time(),
                   "result": output.relative_to(ROOT.resolve()).as_posix(),
                   "result_sha256": sha(output) if output.is_file() else None})


def _qualify_next_impl(ledger: Path, eligibility: Path, output: Path, title_id: str | None = None) -> int:
    _author_check(ledger, eligibility)
    current = read_json(ledger)
    eligible = read_json(eligibility)
    eligible_by_id = {row.get("title_id"): row for row in eligible.get("candidates", [])
                      if row.get("decision") == "eligible"}
    prior_reference = ROOT / "evidence/phase5-reference.json"
    retained_control = read_json(prior_reference).get("retained_control_capability") if prior_reference.is_file() else None
    previous = read_json(output) if output.is_file() else {}
    prior_routes = previous.get("routes", [])
    prior_failures = previous.get("prior_failures", [])
    if title_id is None and (ROOT / CORRECTION_FREEZE).is_file():
        prior_failures.extend(prior_routes)
        prior_routes = []
    if title_id:
        prior_failures.extend(r for r in prior_routes if r.get("title_id") == title_id and r.get("status") != "pass")
        prior_routes = [r for r in prior_routes if r.get("title_id") != title_id]
    result = {"schema": "genewhip-phase5-reference-v1", "status": "blocked",
              "authority": "Pinned MAME differential evidence; source remains intended-behavior authority",
              "routes": prior_routes, "prior_failures": prior_failures, "candidate_genewhip_baseline": "not-run",
              "retained_control_capability": retained_control}
    if DECISION == "D-116":
        result.update(decision=DECISION, freeze_sha256=sha(ROOT / CORRECTION_FREEZE),
                      authorization_sha256=sha(ROOT / CORRECTION_AUTH))
    errors = []
    for scenario, oracle, frozen in _routes(title_id):
        candidate = next(row for row in current["candidates"] if row["id"] == scenario["title_id"])
        elig = eligible_by_id[scenario["title_id"]]
        rom = ROOT / scenario["identities"]["rom_path"]
        try:
            package = _route_package(scenario["title_id"])
            script_path = package / "mame.lua"
            if sha(script_path) != scenario["identities"]["mame_script_sha256"]:
                raise ValueError("reference-script-identity")
            template = script_path.read_text(encoding="utf-8")
            observations = qualify_candidate(scenario, oracle, rom, template)
            observations["lineage_id"] = candidate["lineage_id"]
            observations["build_identity"] = elig.get("build_pair_identity")
            observations["source_revision"] = candidate["source_revision"]
            result["routes"].append(observations)
            if observations.get("status") != "pass":
                errors.append({"title_id": scenario["title_id"], "status": "unknown",
                               "reason": observations.get("reason", "unqualified")})
                break
        except (OSError, ValueError, RuntimeError, TimeoutError) as exc:
            errors.append({"title_id": scenario["title_id"], "status": "infrastructure_error"
                           if "watchdog" in str(exc) or "mame-" in str(exc) else "fail", "reason": str(exc)})
            result["routes"].append({"title_id": scenario["title_id"], "status": errors[-1]["status"],
                                     "lineage_id": candidate["lineage_id"], "reason": str(exc), "frozen": frozen,
                                     **getattr(exc, "observations", {})})
            break
    if title_id:
        result["errors"] = [e for e in previous.get("errors", []) if e.get("title_id") != title_id] + errors
    else:
        result["errors"] = errors
    passing = [r for r in result["routes"] if r.get("status") == "pass"]
    if len(passing) == 2 and len({r.get("lineage_id") for r in passing}) == 2:
        result["status"] = "pass"
        current["selected_pair"] = [r["title_id"] for r in passing]
        result["selected_pair"] = current["selected_pair"]
        write_json(ledger, current)
    write_json(output, result)
    return 0 if result["status"] == "pass" else 2


def _verify_pair(path: Path, *, inherited_title=None) -> int:
    evidence = read_json(path)
    if inherited_title not in (None, "tank-battle"):
        raise ValueError("reference-invalid-inherited-title")
    if DECISION in ("D-117", "D-118") and inherited_title is None:
        _observation_recovery().verify_pair_bindings(sys.modules[__name__], path)
    if DECISION == "D-116" and inherited_title is None:
        attempt = read_json(ROOT / CORRECTION_ATTEMPT)
        if (evidence.get("decision") != DECISION or attempt.get("decision") != DECISION
                or attempt.get("status") != "pass" or attempt.get("result_sha256") != sha(path)
                or evidence.get("freeze_sha256") != sha(ROOT / CORRECTION_FREEZE)):
            raise ValueError("reference-recovery-pair-binding")
    if evidence.get("schema") != "genewhip-phase5-reference-v1": raise ValueError("reference-schema")
    passing = [x for x in evidence.get("routes", []) if x.get("status") == "pass"]
    if inherited_title:
        passing = [x for x in passing if x.get("title_id") == inherited_title]
    titles = {x.get("title_id") for x in passing}
    required = 1 if inherited_title else 2
    if len(titles) < required: raise ValueError("reference-pair-requires-two-qualified-lineages")
    if (len(passing) != required or len(titles) != required
            or any(not x.get("lineage_id") for x in passing)
            or len({x["lineage_id"] for x in passing}) != required):
        raise ValueError("reference-pair-distinct-lineages")
    if inherited_title is None and (evidence.get("status") != "pass" or evidence.get("errors")):
        raise ValueError("reference-pair-status")
    if evidence.get("candidate_genewhip_baseline") != "not-run": raise ValueError("reference-baseline-order")
    _author_check(ROOT / "fixtures/candidate-screening-v2.json", ROOT / "evidence/phase5-eligibility-v2.json")
    packages = {s["title_id"]: (s, o, f) for s, o, f in _routes()}
    seen = set()
    for route in passing:
        if route["title_id"] not in packages:
            raise ValueError("reference-pair-route-identity")
        scenario, oracle, frozen = packages[route["title_id"]]
        if route.get("frozen") != frozen:
            raise ValueError("reference-pair-frozen-identity")
        runs = route.get("runs")
        if not isinstance(runs, list) or [r.get("repetition") for r in runs] != [1, 2]:
            raise ValueError("reference-pair-fresh-repetitions")
        previous = None
        previous_inputs = None
        for run in runs:
            cases = run.get("cases", [])
            if [c.get("case") for c in cases] != frozen["cases"]:
                raise ValueError("reference-pair-case-roster")
            captured = {}
            captured_inputs = {}
            for case in cases:
                raw = case.get("raw_capture", {})
                relative = raw.get("receipt")
                if not isinstance(relative, str):
                    raise ValueError("reference-pair-raw-receipt")
                receipt_path = (ROOT / relative).resolve()
                if not receipt_path.is_relative_to((LOCAL / "reference-captures").resolve()):
                    raise ValueError("reference-pair-raw-receipt")
                if not receipt_path.is_file() or sha(receipt_path) != raw.get("receipt_sha256"):
                    raise ValueError("reference-pair-raw-receipt")
                receipt = read_json(receipt_path)
                identity = receipt.get("run_id")
                if not identity or identity in seen or identity != raw.get("run_id"):
                    raise ValueError("reference-pair-reused-capture")
                seen.add(identity)
                if receipt.get("capture_status") != "complete" or case.get("status") != "pass":
                    raise ValueError("reference-pair-capture-status")
                request = receipt["request"]
                declared_case = next(c for c in scenario["cases"] if c["id"] == case["case"])
                template = (_route_package(route["title_id"]) / "mame.lua").read_text(encoding="utf-8")
                if (request.get("case") != case["case"] or request.get("title_id") != route["title_id"]
                        or request.get("rom_sha256") != scenario["identities"]["rom_sha256"]
                        or request.get("mame_sha256") != sha(MAME)
                        or request.get("script_sha256") != hashlib.sha256(_lua_script(scenario, declared_case, template).encode()).hexdigest()
                        or request.get("scenario_sha256") != hashlib.sha256(json.dumps(scenario, sort_keys=True).encode()).hexdigest()):
                    raise ValueError("reference-pair-capture-identity")
                trace = receipt_path.parent / "capture.csv"
                if not trace.is_file() or sha(trace) != receipt.get("files", {}).get("capture.csv", {}).get("sha256"):
                    raise ValueError("reference-pair-capture-trace")
                rows = parse_capture(trace.read_bytes(), scenario)
                if rows != case.get("rows") or any(r["case"] != case["case"] for r in rows):
                    raise ValueError("reference-pair-capture-trace")
                if not _capture_complete(rows, scenario):
                    raise ValueError("reference-pair-incomplete-field-budget")
                if scenario.get("input_program"):
                    stdout = receipt_path.parent / "stdout"
                    if not stdout.is_file() or sha(stdout) != receipt.get("files", {}).get("stdout", {}).get("sha256"):
                        raise ValueError("reference-pair-input-capture")
                    inputs = _parse_inputs(stdout.read_bytes(), scenario, case["case"])
                    if not inputs or inputs != case.get("inputs"):
                        raise ValueError("reference-pair-input-capture")
                    captured_inputs[case["case"]] = inputs
                captured[case["case"]] = rows
            clock = scenario.get("progress_clock")
            if clock and max(r["signals"].get(clock, 0) for r in captured[frozen["cases"][0]]) < scenario["budget"]["active_fields"]:
                raise ValueError("reference-active-field-budget")
            check_predicates(scenario, oracle, captured)
            if previous is not None and (captured != previous or captured_inputs != previous_inputs):
                raise ValueError("reference-pair-fresh-runs-disagree")
            previous = captured
            previous_inputs = captured_inputs
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--self-test", action="store_true")
    g.add_argument("--author-check", action="store_true")
    g.add_argument("--qualify-next", action="store_true")
    g.add_argument("--qualify-retained-control", action="store_true")
    g.add_argument("--verify-pair", type=Path)
    p.add_argument("--title-id", choices=("tank-battle", "recursion94"))
    p.add_argument("--ledger", type=Path)
    p.add_argument("--eligibility", type=Path)
    p.add_argument("--output", type=Path)
    p.add_argument("--decision", choices=("D-115", "D-116", "D-117", "D-118"), default="D-115")
    args = p.parse_args(argv)
    _select_decision(args.decision)
    if args.self_test: return _contract_tests()
    if args.qualify_retained_control:
        result = qualify_retained_control()
        reference_path = ROOT / "evidence/phase5-reference.json"
        reference = read_json(reference_path) if reference_path.is_file() else {
            "schema": "genewhip-phase5-reference-v1", "status": "blocked", "routes": [],
            "candidate_genewhip_baseline": "not-run",
            "authority": "Pinned MAME differential evidence; source remains intended-behavior authority"}
        reference["retained_control_capability"] = result
        write_json(reference_path, reference)
        print(f"RETAINED-CONTROL PASS fields={result['control_identity']['field_count']} selected_rows={len(result['rows'])} existing_geometry={result['existing_render_audio_observation']['geometry']['marker_position']}")
        return 0
    if args.verify_pair: return _verify_pair(args.verify_pair)
    if not args.ledger or not args.eligibility: p.error("--ledger and --eligibility are required")
    if args.author_check: return _author_check(args.ledger, args.eligibility)
    if args.qualify_next:
        if not args.output: p.error("--output is required")
        return _qualify_next(args.ledger, args.eligibility, args.output, args.title_id)
    return 2


if __name__ == "__main__":
    try: raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, TimeoutError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        raise SystemExit(2)

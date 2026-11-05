#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Produce and validate bounded evidence from the loaded Libretro module."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SCENARIO_PATH = ROOT / "fixtures/independent-game-v2/scenario.json"
ORACLE_PATH = ROOT / "fixtures/independent-game-v2/oracle.json"
SOURCE_PATH = ROOT / "fixtures/independent-game-v2/src/game.s"
ROM_PATH = ROOT / "fixtures/independent-game-v2/game.bin"
CONTROLS_PATH = ROOT / "fixtures/independent-game-v2/host-controls.json"
ADMISSION_PATH = ROOT / "evidence/independent-game-v2.json"
WORKFLOW_PATH = ROOT / ".github/workflows/ci.yml"
FIXTURE_ID = "genewhip-independent-game-v2"
CASE_IDS = ("title-no-start", "start-idle", "start-move")
MAX_REPORT_BYTES = 256 * 1024
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
ROOT_SHA256 = {
    "rom_sha256": "7bdffe43fc1b6e4ac623e16298e3bd0a775de6cb4db2758695dbef0e200f4adb",
    "fixture_source_sha256": "b74cd12ec371767e8fb338feca808e59e63f569eb93298bb2470d20f8e4e9cfe",
    "scenario_sha256": "c702dd10287a9363405fd9269e05989954eb447d0973246bb59a10f74920dbb2",
    "oracle_sha256": "1a9d99cb01496f26fe3dc33d0c1bcb0cf22bd9178088fa183e5bba37a8600f42",
    "host_controls_sha256": "3bece05f616f9b152f222b9f4d930c117d9f73ff228062e381e218058611c6fb",
}
TOP_KEYS = {
    "schema_version", "status", "route_status", "reason", "source_sha",
    "workflow_sha256", "run_id", "run_attempt", "event", "ref", "runner",
    "toolchain", "build_configuration_sha256", "working_tree_clean",
    "library_sha256", "fixture_id", "rom_sha256", "fixture_source_sha256",
    "scenario_sha256", "oracle_sha256", "host_controls_sha256",
    "admission_evidence_sha256", "profile",
    "input_schedule", "input_sha256", "cases", "outcome_counts", "callback_counts", "geometry",
    "pitch", "pixel_format", "pcm_frames", "marker_observations",
}
CASE_KEYS = {
    "id", "status", "outcome", "fields", "input_schedule", "input_sha256", "replays",
    "video_digest_sha256", "pcm_digest_sha256", "pcm_frames",
}
REPLAY_KEYS = {"video_digest_sha256", "pcm_digest_sha256", "video_bytes",
               "pcm_frames", "ordered_video_digest_sha256",
               "ordered_pcm_digest_sha256"}
CALLBACK_KEYS = {"video", "audio_batch", "input_poll", "input_state"}
MARKER_KEYS = {"title_to_play_pixel_changed", "title_pixel_rgb", "play_pixel_rgb",
               "idle_marker", "moved_marker", "idle_control_at_moved_rgb",
               "idle_position", "moved_position",
               "idle_to_moved_pixel_changed"}


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_file(path: Path) -> str:
    return sha_bytes(path.read_bytes())


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _input_contract(scenario: dict) -> list[dict]:
    by_id = {case["id"]: case for case in scenario["cases"]}
    result = []
    for case_id in CASE_IDS:
        case = by_id[case_id]
        events = []
        for event in case["input_schedule"]:
            _port, sep, button = event["control"].partition(" ")
            if not sep or _port != "P1" or button not in {"Start", "Right"}:
                raise ValueError("scenario-input-control")
            events.append({"field": event["frame"], "control": button,
                           "asserted": event["asserted"]})
        result.append({"id": case_id, "fields": case["frames"], "events": events})
    return result


def _canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _admission_status(root: Path) -> str:
    script = root / "tests/fixtures/libretro_admission.py"
    spec = importlib.util.spec_from_file_location("gw_route_admission", script)
    if spec is None or spec.loader is None:
        return "admission-verifier-unavailable"
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        manifest = read_json(root / "fixtures/manifest.json")
        evidence = read_json(root / "evidence/independent-game-v2.json")
        notice = (root / "fixtures/independent-game-v2/NOTICES.md").read_text(encoding="utf-8")
        build = (root / "fixtures/independent-game-v2/build.sh").read_text(encoding="utf-8")
        return module.validate_contract(manifest, evidence, notice, build)
    except (OSError, ImportError, ValueError, TypeError, KeyError):
        return "admission-data-invalid"


def _schedule_argument(events: list[dict]) -> str:
    ids = {"Start": 3, "Right": 7}
    if not events:
        return "-"
    return ",".join(f"{event['field']}:{ids[event['control']]}:{int(event['asserted'])}"
                     for event in events)


def _expected_masks(case: dict) -> list[int]:
    held = set()
    by_field = {event["field"]: event for event in case["events"]}
    masks = []
    for field in range(case["fields"]):
        event = by_field.get(field)
        if event:
            if event["asserted"]:
                held.add(event["control"])
            else:
                held.discard(event["control"])
        masks.append((128 if "Start" in held else 0) |
                     (8 if "Right" in held else 0))
    return masks


def _run_case(host: Path, library: Path, case: dict, scratch_parent: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="libretro-route-", dir=scratch_parent) as temp:
        scratch = Path(temp)
        video_path = scratch / "video.raw"
        audio_path = scratch / "audio.s16le"
        command = [str(host), "fixture-route", str(library), str(ROM_PATH),
                   str(case["fields"]), _schedule_argument(case["events"]), str(scratch)]
        try:
            result = subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("route-host-infrastructure") from exc
        if result.returncode != 0:
            raise ValueError("route-host-failed")
        stdout = result.stdout.decode("ascii", errors="strict")
        rows = [line for line in stdout.splitlines() if line.startswith("GWROUTE,")]
        if len(rows) != case["fields"]:
            raise ValueError("route-callback-denominator")
        metadata = []
        expected_masks = _expected_masks(case)
        pattern = re.compile(
            r"^GWROUTE,field=(\d+),width=(\d+),height=(\d+),pitch=(\d+),"
            r"pixel_format=(XRGB8888),video_bytes=(\d+),audio_frames=(\d+),"
            r"poll_calls=(\d+),input_queries=(\d+),input_mask=(\d+)$")
        for expected_field, line in enumerate(rows):
            match = pattern.fullmatch(line)
            if match is None:
                raise ValueError("route-callback-metadata")
            field, width, height, pitch, pixel_format, video_bytes, pcm_frames, polls, queries, mask = match.groups()
            record = {"field": int(field), "width": int(width), "height": int(height),
                      "pitch": int(pitch), "pixel_format": pixel_format,
                      "video_bytes": int(video_bytes), "pcm_frames": int(pcm_frames),
                      "poll_calls": int(polls), "input_queries": int(queries),
                      "input_mask": int(mask)}
            if record["field"] != expected_field or record["width"] not in (256, 320) or \
                    record["height"] != 224 or record["pitch"] < record["width"] * 4 or \
                    record["video_bytes"] != record["width"] * record["height"] * 4 or \
                    record["pcm_frames"] <= 0 or record["poll_calls"] != 1 or \
                    record["input_queries"] != 16 or record["pixel_format"] != "XRGB8888" or \
                    record["input_mask"] != expected_masks[expected_field]:
                raise ValueError("route-callback-geometry-or-denominator")
            metadata.append(record)
        video = video_path.read_bytes()
        pcm = audio_path.read_bytes()
        if len(video) > MAX_CAPTURE_BYTES or len(pcm) > MAX_CAPTURE_BYTES:
            raise ValueError("route-capture-budget")
        expected_video = sum(item["video_bytes"] for item in metadata)
        expected_pcm = sum(item["pcm_frames"] for item in metadata)
        if len(video) != expected_video or len(pcm) != expected_pcm * 4:
            raise ValueError("route-callback-byte-denominator")
        video_fields = []
        video_cursor = 0
        for item in metadata:
            end = video_cursor + item["video_bytes"]
            video_fields.append(video[video_cursor:end])
            video_cursor = end
        pcm_digests = []
        pcm_cursor = 0
        for item in metadata:
            byte_count = item["pcm_frames"] * 4
            pcm_digests.append(sha_bytes(pcm[pcm_cursor:pcm_cursor + byte_count]))
            pcm_cursor += byte_count
        video_digests = [sha_bytes(field) for field in video_fields]
        return {"metadata": metadata, "video_fields": video_fields,
                "pcm_frames": expected_pcm,
                "video_digest_sha256": sha_bytes("".join(video_digests).encode("ascii")),
                "pcm_digest_sha256": sha_bytes("".join(pcm_digests).encode("ascii")),
                "ordered_video_digest_sha256": sha_bytes("".join(video_digests).encode("ascii")),
                "ordered_pcm_digest_sha256": sha_bytes("".join(pcm_digests).encode("ascii")),
                "video_bytes": len(video)}


def _pixel_rgb(field: bytes, width: int, height: int, x: int, y: int) -> int:
    if not (0 <= x < width and 0 <= y < height):
        raise ValueError("marker-coordinate-bounds")
    return int.from_bytes(field[(y * width + x) * 4:(y * width + x) * 4 + 4],
                          "little") & 0x00ffffff


def _expected_position(case: dict) -> int:
    position = 0
    playing = False
    for mask in _expected_masks(case):
        if mask & 128:
            playing = True
        if playing and mask & 8:
            position = min(39, position + 1)
    return position


def _marker_observations(case_rows: list[dict], contracts: list[dict]) -> dict:
    by_id = {row["id"]: row for row in case_rows}
    contract_by_id = {row["id"]: row for row in contracts}
    title = by_id["title-no-start"]["_replays"][0]
    idle = by_id["start-idle"]["_replays"][0]
    moved = by_id["start-move"]["_replays"][0]
    # Match the source comparator's zero-based field indexes in phase4_game.py.
    title_field = title["video_fields"][10]
    idle_play_field = idle["video_fields"][10]
    idle_marker_field = idle["video_fields"][19]
    moved_field = moved["video_fields"][19]
    geometry = by_id["title-no-start"]["_geometry"]
    width, height = geometry["width"], geometry["height"]
    title_pixel = _pixel_rgb(title_field, width, height, 0, 0)
    play_pixel = _pixel_rgb(idle_play_field, width, height, 0, 0)
    idle_position = _expected_position(contract_by_id["start-idle"])
    moved_position = _expected_position(contract_by_id["start-move"])
    # Plane A entry 0xC280 is row 10 of the source's 32-cell name table.
    marker_y = 80 + 3
    idle_rgb = _pixel_rgb(idle_marker_field, width, height,
                          idle_position * 8 + 3, marker_y)
    moved_rgb = _pixel_rgb(moved_field, width, height, moved_position * 8 + 3, marker_y)
    idle_control_at_moved = _pixel_rgb(idle_marker_field, width, height,
                                       moved_position * 8 + 3, marker_y)
    # Palette entry 2 in the admitted source is green (CRAM value 0x00e0).
    if title_pixel != 0xffffff or play_pixel != 0xff0000 or title_pixel == play_pixel:
        raise ValueError("marker-title-control")
    if idle_rgb != 0x00ff00 or moved_rgb != 0x00ff00 or idle_control_at_moved == 0x00ff00:
        raise ValueError("marker-input-progress")
    return {"title_to_play_pixel_changed": True,
            "title_pixel_rgb": f"{title_pixel:06x}",
            "play_pixel_rgb": f"{play_pixel:06x}",
            "idle_marker": f"{idle_rgb:06x}",
            "moved_marker": f"{moved_rgb:06x}",
            "idle_control_at_moved_rgb": f"{idle_control_at_moved:06x}",
            "idle_position": idle_position, "moved_position": moved_position,
            "idle_to_moved_pixel_changed": True}


def _toolchain(build_dir: Path) -> tuple[dict, str]:
    cache = build_dir / "CMakeCache.txt"
    values = {}
    if cache.is_file():
        for line in cache.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("CMAKE_GENERATOR:INTERNAL="):
                values["generator"] = line.split("=", 1)[1]
            elif line.startswith("CMAKE_BUILD_TYPE:STRING="):
                values["build_type"] = line.split("=", 1)[1]
    compiler_configurations = sorted((build_dir / "CMakeFiles").glob("*/CMakeCCompiler.cmake"))
    for compiler_config in compiler_configurations:
        text = compiler_config.read_text(encoding="utf-8", errors="replace")
        for key, variable in (("compiler", "CMAKE_C_COMPILER_ID"),
                              ("compiler_version", "CMAKE_C_COMPILER_VERSION")):
            match = re.search(rf'^set\({variable} "([A-Za-z0-9_.+-]+)"\)$', text, re.MULTILINE)
            if match:
                values[key] = match.group(1)
        if "compiler" in values and "compiler_version" in values:
            break
    try:
        version = subprocess.run(["cmake", "--version"], check=True, text=True,
                                 capture_output=True, timeout=5).stdout.splitlines()[0]
        match = re.search(r"cmake version ([0-9][A-Za-z0-9.+-]*)", version)
        values["cmake"] = match.group(1) if match else "unknown"
    except (OSError, subprocess.SubprocessError, IndexError):
        values["cmake"] = "unknown"
    for key in ("compiler", "compiler_version", "generator", "build_type"):
        values.setdefault(key, "unknown")
    if values.get("build_type") == "":
        values["build_type"] = "unspecified"
    return values, sha_file(cache) if cache.is_file() else "0" * 64


def _git_state() -> tuple[str, bool]:
    try:
        source_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                   check=True, text=True, capture_output=True,
                                   timeout=5).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=normal"],
                               cwd=ROOT, check=True, text=True, capture_output=True,
                               timeout=5).stdout.strip() != ""
        if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
            raise ValueError("git-source-identity")
        return source_sha, not dirty
    except (OSError, subprocess.SubprocessError, ValueError):
        return "0" * 40, False


def _metadata(args, toolchain: dict, build_hash: str) -> dict:
    git_source_sha, clean = _git_state()
    source_sha = args.source_sha or os.environ.get("GITHUB_SHA") or git_source_sha
    run_id = args.run_id or os.environ.get("GITHUB_RUN_ID")
    run_attempt = args.run_attempt or os.environ.get("GITHUB_RUN_ATTEMPT")
    event = args.event or os.environ.get("GITHUB_EVENT_NAME")
    ref = args.ref or os.environ.get("GITHUB_REF")
    runner_os = os.environ.get("RUNNER_OS", platform.system()).lower()
    runner_arch = os.environ.get("RUNNER_ARCH", platform.machine()).lower()
    if runner_arch in {"x64", "amd64"}:
        runner_arch = "x86_64"
    if runner_os in {"macos", "darwin"}:
        runner_os = "macos"
    elif runner_os not in {"linux", "windows"}:
        runner_os = "unknown"
    image = os.environ.get("ImageOS", "").lower()
    if not re.fullmatch(r"[a-z0-9.-]{1,32}", image):
        image = ""
    runner = f"{runner_os}-{runner_arch}" + (f"-{image}" if image else "")
    linux_x64 = sys.platform.startswith("linux") and platform.machine().lower() in {"x86_64", "amd64"}
    run_fields_present = all((run_id, run_attempt, event, ref))
    hosted = clean and linux_x64 and run_fields_present and \
        bool(re.fullmatch(r"[0-9a-f]{40}", source_sha)) and source_sha == git_source_sha
    hosted = hosted and bool(re.fullmatch(r"[0-9]{1,20}", str(run_id or ""))) and \
        bool(str(run_attempt or "").isdigit()) and int(run_attempt or "0") > 0 and \
        event in {"pull_request", "merge_group", "push"} and \
        bool(re.fullmatch(r"[A-Za-z0-9_./@+-]{1,160}", str(ref or ""))) and \
        runner.startswith("linux-x86_64-") and build_hash != "0" * 64 and \
        all(value != "unknown" for value in toolchain.values())
    reason = None if hosted else (
        "host-platform-not-linux-x86_64" if not linux_x64 else
        "working-tree-not-clean" if not clean else
        "toolchain-identity-incomplete" if build_hash == "0" * 64 or
            any(value == "unknown" for value in toolchain.values()) else
        "host-run-identity-incomplete")
    return {"status": "pass" if hosted else "unknown", "route_status": "pass",
            "reason": reason, "source_sha": source_sha,
            "workflow_sha256": sha_file(WORKFLOW_PATH), "run_id": run_id,
            "run_attempt": int(run_attempt) if run_attempt and str(run_attempt).isdigit() else None,
            "event": event, "ref": ref, "runner": runner, "toolchain": toolchain,
            "build_configuration_sha256": build_hash, "working_tree_clean": clean}


def _build_report(host: Path, library: Path, output: Path, args) -> dict:
    scenario = read_json(SCENARIO_PATH)
    oracle = read_json(ORACLE_PATH)
    manifest = read_json(ROOT / "fixtures/manifest.json")
    admission = read_json(ADMISSION_PATH)
    if sha_file(ROM_PATH) != ROOT_SHA256["rom_sha256"] or \
            sha_file(SOURCE_PATH) != ROOT_SHA256["fixture_source_sha256"] or \
            sha_file(SCENARIO_PATH) != ROOT_SHA256["scenario_sha256"] or \
            sha_file(ORACLE_PATH) != ROOT_SHA256["oracle_sha256"] or \
            sha_file(CONTROLS_PATH) != ROOT_SHA256["host_controls_sha256"]:
        raise ValueError("fixture-identity")
    admission_row = next((row for row in manifest["fixtures"]
                          if row.get("id") == FIXTURE_ID), None)
    if not admission_row or admission_row.get("status") != "admitted" or \
            admission_row.get("outcome") != "pass" or admission.get("candidate_disposition") != "admitted":
        raise ValueError("fixture-admission")
    admission_check = subprocess.run([sys.executable, "-I",
        str(ROOT / "tests/fixtures/libretro_admission.py")], cwd=ROOT,
        stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=False)
    if admission_check.returncode != 0:
        raise ValueError("fixture-admission-contract")
    if admission_row.get("evidence_sha256") != sha_file(ADMISSION_PATH):
        raise ValueError("fixture-admission-identity")
    if not host.is_file() or not library.is_file():
        raise ValueError("route-binary-missing")
    if scenario.get("fixture_id") != FIXTURE_ID or \
            oracle.get("oracle_id") != "genewhip-independent-game-v2-source-oracle-v1" or \
            oracle.get("source_sha256") != ROOT_SHA256["fixture_source_sha256"]:
        raise ValueError("fixture-oracle-identity")
    git_source_sha, _clean = _git_state()
    if (args.source_sha and args.source_sha != git_source_sha) or \
            (os.environ.get("GITHUB_SHA") and os.environ["GITHUB_SHA"] != git_source_sha):
        raise ValueError("source-checkout-mismatch")
    contracts = _input_contract(scenario)
    scratch_parent = output.parent.resolve()
    scratch_parent.mkdir(parents=True, exist_ok=True)
    case_rows = []
    common_geometry = None
    callbacks = {"video": 0, "audio_batch": 0, "input_poll": 0, "input_state": 0}
    total_pcm_frames = 0
    for contract in contracts:
        runs = [_run_case(host, library, contract, scratch_parent) for _ in range(2)]
        first, second = runs
        comparable_keys = ("metadata", "video_digest_sha256", "pcm_digest_sha256",
                           "video_bytes", "pcm_frames")
        if any(first[key] != second[key] for key in comparable_keys):
            raise ValueError("route-replay-nondeterministic")
        metadata = first["metadata"]
        geometry = {"width": metadata[0]["width"], "height": metadata[0]["height"],
                    "pitch": metadata[0]["pitch"], "pixel_format": metadata[0]["pixel_format"]}
        if any({"width": item["width"], "height": item["height"], "pitch": item["pitch"],
                "pixel_format": item["pixel_format"]} != geometry for item in metadata):
            raise ValueError("route-geometry-drift")
        if common_geometry is None:
            common_geometry = geometry
        if geometry != common_geometry:
            raise ValueError("route-controls-geometry-drift")
        for run in runs:
            for item in run["metadata"]:
                callbacks["video"] += 1
                callbacks["audio_batch"] += 1
                callbacks["input_poll"] += item["poll_calls"]
                callbacks["input_state"] += item["input_queries"]
        fields_pcm = sum(item["pcm_frames"] for item in metadata)
        if fields_pcm <= 0 or any(not 600 <= item["pcm_frames"] <= 820 for item in metadata):
            raise ValueError("route-pcm-denominator")
        total_pcm_frames += fields_pcm * 2
        schedule = {"fields": contract["fields"], "events": contract["events"]}
        schedule_hash = sha_bytes(_canonical_json(schedule))
        case_rows.append({"id": contract["id"], "status": "pass", "outcome": "pass",
                          "fields": contract["fields"],
                          "input_schedule": contract["events"],
                          "input_sha256": schedule_hash,
                          "replays": [
                              {key: run[key] for key in REPLAY_KEYS}
                              for run in runs],
                          "video_digest_sha256": first["video_digest_sha256"],
                          "pcm_digest_sha256": first["pcm_digest_sha256"],
                          "pcm_frames": fields_pcm * 2,
                          "_replays": runs,
                          "_video_fields": first["video_fields"],
                          "_geometry": geometry})
    markers = _marker_observations(case_rows, contracts)
    for row in case_rows:
        row.pop("_video_fields")
        row.pop("_geometry")
        row.pop("_replays")
    schedule_digest = sha_bytes(_canonical_json(contracts))
    build_dir = host.resolve().parent
    toolchain, build_hash = _toolchain(build_dir)
    hosted = _metadata(args, toolchain, build_hash)
    if hosted["status"] == "pass" and not (sys.platform.startswith("linux") and
            platform.machine().lower() in {"x86_64", "amd64"}):
        raise ValueError("hosted-platform-policy")
    return {"schema_version": 1, **hosted,
            "library_sha256": sha_file(library), "fixture_id": FIXTURE_ID,
            "rom_sha256": ROOT_SHA256["rom_sha256"],
            "fixture_source_sha256": ROOT_SHA256["fixture_source_sha256"],
            "scenario_sha256": ROOT_SHA256["scenario_sha256"],
            "oracle_sha256": ROOT_SHA256["oracle_sha256"],
            "host_controls_sha256": ROOT_SHA256["host_controls_sha256"],
            "admission_evidence_sha256": sha_file(ADMISSION_PATH),
            "profile": scenario["profile"], "input_schedule": contracts,
            "input_sha256": schedule_digest, "cases": case_rows,
            "outcome_counts": {"pass": len(case_rows), "fail": 0,
                               "skipped": 0, "unknown": 0},
            "callback_counts": callbacks, "geometry": common_geometry,
            "pitch": common_geometry["pitch"], "pixel_format": "XRGB8888",
            "pcm_frames": total_pcm_frames, "marker_observations": markers}


def validate_report(report: dict, *, root: Path = ROOT,
                    library_path: Path | None = None,
                    require_source: str | None = None,
                    require_hosted: bool = False,
                    require_run_id: str | None = None,
                    require_run_attempt: str | None = None,
                    require_event: str | None = None,
                    require_ref: str | None = None) -> str:
    try:
        encoded = json.dumps(report, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError):
        return "report-json"
    if len(encoded) > MAX_REPORT_BYTES:
        return "report-size"
    if not isinstance(report, dict) or set(report) != TOP_KEYS:
        return "report-fields"
    # Reject private or malformed identity fields before classifying hosted status;
    # callers should get the privacy violation regardless of runner provenance.
    for key in ("event", "ref", "runner"):
        value = report.get(key)
        if value is not None and (not isinstance(value, str) or
                not re.fullmatch(r"[A-Za-z0-9_./@+-]{1,160}", value) or
                value.startswith("/") or ".." in value.split("/") or
                "\\" in value or "\n" in value):
            return "report-private-field"
    report_ref = report.get("ref")
    if report_ref is not None and not report_ref.startswith(
            ("refs/heads/", "refs/pull/", "refs/tags/")):
        return "report-private-field"
    if report.get("run_id") is not None and not re.fullmatch(
            r"[0-9]{1,20}", str(report["run_id"])):
        return "report-private-field"
    if require_source is not None:
        if not re.fullmatch(r"[0-9a-f]{40}", require_source):
            return "required-source-invalid"
        if report.get("source_sha") != require_source:
            return "required-source-mismatch"
    if require_hosted and report.get("status") != "pass":
        return "hosted-status-required"
    if require_run_id is not None and report.get("run_id") != str(require_run_id):
        return "required-run-id-mismatch"
    if require_run_attempt is not None:
        if not re.fullmatch(r"[0-9]{1,10}", str(require_run_attempt)) or \
                report.get("run_attempt") != int(require_run_attempt):
            return "required-run-attempt-mismatch"
    if require_event is not None and report.get("event") != require_event:
        return "required-event-mismatch"
    if require_ref is not None and report.get("ref") != require_ref:
        return "required-ref-mismatch"
    if type(report.get("schema_version")) is not int or report.get("schema_version") != 1 or \
            report.get("fixture_id") != FIXTURE_ID:
        return "fixture-identity"
    if report.get("route_status") != "pass" or report.get("status") not in {"pass", "unknown"}:
        return "route-status"
    if report.get("profile") != "VA3-NTSC-U":
        return "fixture-profile"
    for key, expected in ROOT_SHA256.items():
        field = key
        if report.get(field) != expected:
            return "fixture-identity"
    frozen_paths = {
        "rom_sha256": "fixtures/independent-game-v2/game.bin",
        "fixture_source_sha256": "fixtures/independent-game-v2/src/game.s",
        "scenario_sha256": "fixtures/independent-game-v2/scenario.json",
        "oracle_sha256": "fixtures/independent-game-v2/oracle.json",
        "host_controls_sha256": "fixtures/independent-game-v2/host-controls.json",
    }
    try:
        if any(sha_file(root / rel) != ROOT_SHA256[key]
               for key, rel in frozen_paths.items()):
            return "fixture-identity"
        admission_digest = sha_file(root / "evidence/independent-game-v2.json")
        manifest = read_json(root / "fixtures/manifest.json")
        admission_row = next((row for row in manifest["fixtures"]
                              if row.get("id") == FIXTURE_ID), None)
        if not admission_row or admission_row.get("evidence_sha256") != admission_digest or \
                report.get("admission_evidence_sha256") != admission_digest:
            return "admission-evidence-identity"
    except OSError:
        return "fixture-identity"
    if _admission_status(root) != "ok":
        return "fixture-admission"
    identities = ("source_sha", "workflow_sha256", "build_configuration_sha256",
                  "library_sha256", "scenario_sha256", "oracle_sha256",
                  "host_controls_sha256", "rom_sha256", "fixture_source_sha256")
    if any(not re.fullmatch(r"[0-9a-f]{40}" if key == "source_sha" else r"[0-9a-f]{64}",
                            str(report.get(key, ""))) for key in identities):
        return "identity-format"
    try:
        if sha_file(root / ".github/workflows/ci.yml") != report["workflow_sha256"]:
            return "workflow-identity"
    except OSError:
        return "workflow-identity"
    if library_path is not None:
        try:
            if sha_file(library_path) != report["library_sha256"]:
                return "library-identity"
        except OSError:
            return "library-identity"
    if not isinstance(report.get("working_tree_clean"), bool):
        return "source-cleanliness"
    if report.get("run_attempt") is not None and (
            type(report.get("run_attempt")) is not int or report["run_attempt"] < 1):
        return "hosted-identity"
    if report.get("status") == "pass":
        if report.get("reason") is not None or report.get("working_tree_clean") is not True:
            return "hosted-status"
        if report.get("build_configuration_sha256") == "0" * 64:
            return "toolchain-identity-incomplete"
        if not all(report.get(key) for key in ("run_id", "run_attempt", "event", "ref", "runner")):
            return "hosted-identity"
        if report.get("event") not in {"pull_request", "merge_group", "push"} or \
                not re.fullmatch(r"[0-9]{1,20}", str(report.get("run_id", ""))) or \
                not isinstance(report.get("run_attempt"), int) or report["run_attempt"] < 1:
            return "hosted-identity"
        if not str(report.get("runner", "")).startswith("linux-x86_64-"):
            return "hosted-platform-identity"
    elif report.get("reason") not in {"working-tree-not-clean", "host-platform-not-linux-x86_64",
                                      "host-run-identity-incomplete",
                                      "toolchain-identity-incomplete"}:
        return "unknown-reason"
    for key in ("event", "ref", "runner", "run_id"):
        value = report.get(key)
        if value is not None and (not isinstance(value, str) or len(value) > 160 or
                                  "/" in value and key == "runner" or
                                  "\\" in value or "\n" in value):
            return "report-private-field"
    toolchain = report.get("toolchain")
    expected_toolchain_keys = {"compiler", "compiler_version", "generator", "build_type", "cmake"}
    if not isinstance(toolchain, dict) or set(toolchain) != expected_toolchain_keys:
        return "toolchain-fields"
    if any(not isinstance(value, str) or len(value) > 80 or "/" in value or "\\" in value
           for value in toolchain.values()):
        return "report-private-field"
    if toolchain["compiler"] != "unknown" and not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_.+-]{0,39}", toolchain["compiler"]):
        return "toolchain-fields"
    for key in ("compiler_version", "cmake"):
        if toolchain[key] != "unknown" and not re.fullmatch(
                r"[0-9][A-Za-z0-9_.+-]{0,39}", toolchain[key]):
            return "toolchain-fields"
    if toolchain["generator"] not in {"unknown", "Unix Makefiles", "Ninja"} or \
            toolchain["build_type"] not in {
                "unknown", "unspecified", "Debug", "Release", "RelWithDebInfo", "MinSizeRel"}:
        return "toolchain-fields"
    if report.get("status") == "pass" and any(value == "unknown" for value in toolchain.values()):
        return "toolchain-identity-incomplete"
    expected_schedule = _input_contract(read_json(root / "fixtures/independent-game-v2/scenario.json"))
    if report.get("input_schedule") != expected_schedule or \
            report.get("input_sha256") != sha_bytes(_canonical_json(expected_schedule)):
        return "input-schedule"
    cases = report.get("cases")
    if not isinstance(cases, list) or len(cases) != len(CASE_IDS):
        return "route-controls"
    for row, contract in zip(cases, expected_schedule):
        if not isinstance(row, dict) or set(row) != CASE_KEYS or row.get("id") != contract["id"]:
            return "route-controls"
        if row.get("status") != "pass" or row.get("outcome") != "pass":
            return "route-case-outcome"
        schedule = {"fields": contract["fields"], "events": contract["events"]}
        if row.get("fields") != contract["fields"] or row.get("input_schedule") != contract["events"] or \
                row.get("input_sha256") != sha_bytes(_canonical_json(schedule)):
            return "input-schedule"
        replays = row.get("replays")
        if not isinstance(replays, list) or len(replays) != 2 or any(
                not isinstance(replay, dict) or set(replay) != REPLAY_KEYS for replay in replays):
            return "route-replays"
        for replay in replays:
            for key in ("video_digest_sha256", "pcm_digest_sha256",
                        "ordered_video_digest_sha256", "ordered_pcm_digest_sha256"):
                if not re.fullmatch(r"[0-9a-f]{64}", str(replay.get(key, ""))):
                    return "route-digest"
            if replay.get("video_bytes", 0) <= 0 or replay.get("pcm_frames", 0) <= 0:
                return "route-denominator"
            if replay.get("video_bytes") != contract["fields"] * 256 * 224 * 4:
                return "route-denominator"
        if any(replays[0][key] != replays[1][key] for key in (
                "video_digest_sha256", "pcm_digest_sha256", "video_bytes", "pcm_frames",
                "ordered_video_digest_sha256", "ordered_pcm_digest_sha256")):
            return "route-replay-nondeterministic"
        if any(replay["ordered_video_digest_sha256"] != replay["video_digest_sha256"] or
               replay["ordered_pcm_digest_sha256"] != replay["pcm_digest_sha256"]
               for replay in replays):
            return "route-digest"
        if row.get("video_digest_sha256") != replays[0]["video_digest_sha256"] or \
                row.get("pcm_digest_sha256") != replays[0]["pcm_digest_sha256"]:
            return "route-digest"
        if row.get("pcm_frames") != sum(replay["pcm_frames"] for replay in replays) or \
                any(replay["pcm_frames"] < contract["fields"] * 600 or
                    replay["pcm_frames"] > contract["fields"] * 820 for replay in replays):
            return "route-denominator"
    if report.get("geometry") != {"width": 256, "height": 224,
                                   "pitch": report.get("pitch"),
                                   "pixel_format": "XRGB8888"}:
        return "route-geometry"
    geometry = report["geometry"]
    if not isinstance(geometry.get("pitch"), int) or geometry["pitch"] < geometry["width"] * 4 or \
            report.get("pixel_format") != "XRGB8888":
        return "route-geometry"
    expected_fields = 2 * sum(case["fields"] for case in expected_schedule)
    callback = report.get("callback_counts")
    if not isinstance(callback, dict) or set(callback) != CALLBACK_KEYS or \
            callback != {"video": expected_fields, "audio_batch": expected_fields,
                         "input_poll": expected_fields, "input_state": expected_fields * 16}:
        return "route-callback-denominator"
    expected_total_pcm = sum(case["pcm_frames"] for case in cases)
    if report.get("pcm_frames") != expected_total_pcm:
        return "route-pcm-denominator"
    if report.get("outcome_counts") != {"pass": len(CASE_IDS), "fail": 0,
                                         "skipped": 0, "unknown": 0}:
        return "route-outcome-denominator"
    markers = report.get("marker_observations")
    if not isinstance(markers, dict) or set(markers) != MARKER_KEYS:
        return "route-marker-fields"
    if markers.get("title_to_play_pixel_changed") is not True or \
            markers.get("idle_to_moved_pixel_changed") is not True or \
            markers.get("idle_position") != 0 or markers.get("moved_position") != 10 or \
            markers.get("idle_marker") != "00ff00" or markers.get("moved_marker") != "00ff00" or \
            markers.get("title_pixel_rgb") != "ffffff" or markers.get("play_pixel_rgb") != "ff0000" or \
            markers.get("idle_control_at_moved_rgb") == "00ff00":
        return "route-marker-progress"
    return "ok"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", type=Path)
    parser.add_argument("--library", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--validate", type=Path)
    parser.add_argument("--source-sha")
    parser.add_argument("--require-hosted", action="store_true",
                        help="reject locally passing but hosted-unknown evidence")
    parser.add_argument("--run-id")
    parser.add_argument("--run-attempt")
    parser.add_argument("--event")
    parser.add_argument("--ref")
    args = parser.parse_args(argv)
    if args.validate:
        try:
            raw = args.validate.read_bytes()
            if len(raw) > MAX_REPORT_BYTES:
                print("REJECT: report-size")
                return 1
            report = json.loads(raw)
            result = validate_report(report, library_path=args.library,
                                     require_source=args.source_sha,
                                     require_hosted=args.require_hosted,
                                     require_run_id=args.run_id,
                                     require_run_attempt=args.run_attempt,
                                     require_event=args.event,
                                     require_ref=args.ref)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            result = "report-read"
        if result != "ok":
            print(f"REJECT: {result}")
            return 1
        print("PASS: bounded callback route evidence validates")
        return 0
    if not args.host or not args.library or not args.output:
        parser.error("--host, --library and --output are required for route production")
    try:
        output = args.output.resolve()
        report = _build_report(args.host.resolve(), args.library.resolve(), output, args)
        result = validate_report(report, library_path=args.library.resolve())
        if result != "ok":
            raise ValueError("route-report-validation:" + result)
        rendered = json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
        if len(rendered.encode("ascii")) > MAX_REPORT_BYTES:
            raise ValueError("route-report-size")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="ascii")
        if report["status"] == "pass":
            print("PASS: source-identified Linux x86_64 callback route; bounded report written")
        else:
            print("UNKNOWN: local callback route passed; hosted source/run identity is incomplete")
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError,
            json.JSONDecodeError, UnicodeDecodeError) as exc:
        reason = str(exc)
        if not re.fullmatch(r"[a-z0-9:-]{1,96}", reason):
            reason = "route-evidence-failed"
        print(f"BLOCKED: {reason}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

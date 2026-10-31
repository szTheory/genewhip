#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Collect and validate the versioned Phase 4 evidence roster."""
import argparse
import hashlib
import io
import importlib.util
import json
import math
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "genewhip-phase4-evidence"
VERSION = 1
TRACER_SCHEMA = "genewhip-phase4-tracer"
OUTCOMES = ("pass", "fail", "unknown", "unsupported", "skipped", "infrastructure-error")
ROSTER = (
    ("diagnostic_public_clients", True),
    ("independent_gameplay", True),
    ("safety_contracts", True),
    ("core_performance", True),
    ("desktop_pacing", True),
    ("exact_packages", True),
    ("hosted_delivery", True),
)
CONFIG_KEYS = ("CMAKE_BUILD_TYPE", "CMAKE_C_COMPILER_ID", "CMAKE_C_COMPILER_VERSION",
               "CMAKE_GENERATOR", "GENEWHIP_BUILD_DESKTOP", "GENEWHIP_TEST_HOOKS")
GAME_CASES = ("title-no-start", "start-idle", "start-move", "action-sound",
              "action-no-trigger", "sustained-play")
GAME_FIELDS = (12, 20, 40, 24, 24, 720)
GAME_EXPECTATIONS = ((0, 0, 0, [], 0, None), (1, 0, 0, [], 0, None),
                     (1, 1, 39, [], 0, None), (1, 0, 0, [132, 2, 144], 1, None),
                     (1, 1, 39, [], 0, 0), (1, 39, 39, [132, 2, 144], 1, None))
GAME_IDENTITIES = {"source_sha256": "b74cd12ec371767e8fb338feca808e59e63f569eb93298bb2470d20f8e4e9cfe",
                   "rom_sha256": "7bdffe43fc1b6e4ac623e16298e3bd0a775de6cb4db2758695dbef0e200f4adb",
                   "scenario_sha256": "c702dd10287a9363405fd9269e05989954eb447d0973246bb59a10f74920dbb2",
                   "oracle_sha256": "1a9d99cb01496f26fe3dc33d0c1bcb0cf22bd9178088fa183e5bba37a8600f42"}
SAFE_CTEST_DIAGNOSTIC_METHODS = frozenset({
    "NativeParserContract.test_phase7_launcher_keeps_shorter_caller_deadline",
    "NativeParserContract.test_darwin_group_liveness_distinguishes_zombies",
    "NativeParserContract.test_partial_json_cannot_erase_completed_process_receipt",
    "NativeParserContract.test_bounded_malformed_route_matrix_both_clients",
    "NativeParserContract.test_process_group_and_stream_caps_are_enforced",
    "NativeParserContract.test_process_group_is_killed_when_leader_exits_first",
    "NativeParserContract.test_monitored_symlink_is_rejected_before_process_start",
    "NativeParserContract.test_preimport_popen_denial_is_observed_and_sticky",
    "NativeParserContract.test_wrong_popen_mock_does_not_replace_the_launch_boundary",
    "NativeParserContract.test_sigterm_during_popen_is_deferred_until_the_group_is_owned",
    "NativeParserContract.test_sigterm_after_pid_registration_uses_owned_group_cleanup",
    "NativeParserContract.test_sigterm_and_launch_error_restore_previous_handler_without_owned_child",
    "NativeParserContract.test_runner_setup_error_restores_previous_handler_before_any_launch",
    "RepairLedgerContract.test_distinct_budget_includes_discovered_next_stops_once",
    "RepairLedgerContract.test_identical_duplicate_receipt_is_counted_once",
    "RepairLedgerContract.test_conflicting_duplicate_receipt_is_rejected",
    "RepairLedgerContract.test_forged_history_correction_does_not_count_as_execution",
    "MediaConsumerContract.test_source_clock_must_match_the_declared_media_scene",
    "MediaConsumerContract.test_source_tone_analysis_rejects_silence_and_wrong_pitch",
    "MediaConsumerContract.test_boot_score_consumer_checks_programmed_pcm_pitch",
    "MediaConsumerContract.test_source_image_features_and_tank_palette_reject_pixel_mutants",
    "BaselineRecordContract.test_tracer_diagnostic_rom_rejects_outside_symlink",
    "BaselineRecordContract.test_tracer_diagnostic_rom_is_selected_build_input",
    "BaselineRecordContract.test_control_admission_preserves_existing_file_and_symlink",
    "BaselineRecordContract.test_valid_record_round_trips",
    "BaselineRecordContract.test_status_only_pass_is_rejected",
    "BaselineRecordContract.test_wrong_identity_is_rejected_by_case_key",
    "BaselineRecordContract.test_reordered_stage_history_is_rejected",
    "BaselineRecordContract.test_empty_denominator_is_rejected",
    "BaselineRecordContract.test_duplicate_stage_identity_is_rejected",
    "BaselineRecordContract.test_identity_mutation_between_stages_is_rejected",
    "BaselineRecordContract.test_historical_infrastructure_spellings_convert_explicitly",
    "BaselineRecordContract.test_unknown_historical_pair_is_rejected",
    "BaselineRecordContract.test_historical_spelling_is_bound_to_its_source_schema",
    "BaselineRecordContract.test_tracer_output_is_confined_to_dedicated_build_path",
    "BaselineRecordContract.test_exact_full_denominator_and_two_720_field_control_passes",
    "BaselineRecordContract.test_report_binds_roster_and_production_admission_identity",
    "BaselineRecordContract.test_missing_and_duplicate_rows_fail_at_named_denominator_assertion",
    "BaselineRecordContract.test_unsupported_stage_cannot_be_laundered_as_a_pass",
    "BaselineRecordContract.test_unsupported_row_cannot_claim_reached_even_with_identity_intact",
    "BaselineRecordContract.test_row_identity_mutations_rejected",
    "BaselineRecordContract.test_actual_failed_load_cannot_become_verified_false_pass",
    "BaselineRecordContract.test_self_consistent_status_reason_observation_forgery_rejected",
    "BaselineRecordContract.test_every_control_case_requires_named_predicates",
    "BaselineRecordContract.test_collection_identities_bound",
    "BaselineRecordContract.test_selected_wrong_client_rejected_before_admission_or_execution",
    "BaselineRecordContract.test_collection_failure_diagnostics_expose_only_enum_fields",
    "BaselineRecordContract.test_skip_or_unsupported_cannot_be_laundered_with_coherent_pass",
    "BaselineRecordContract.test_observable_core_stop_is_failure_not_infrastructure_or_unsupported",
    "BaselineRecordContract.test_synthetic_context_cannot_claim_actual_process",
    "BaselineRecordContract.test_current_roster_cannot_be_substituted_with_self_claimed_hash",
    "BaselineRecordContract.test_private_evidence_rejected_without_echo",
    "BaselineRecordContract.test_real_process_output_cap_timeout_and_status",
    "BaselineRecordContract.test_dependent_process_terminated_even_after_parent_exits",
    "BaselineRecordContract.test_handoff_private_injection_has_named_rejection",
    "BaselineRecordContract.test_failure_handoff_keeps_every_candidate_fail_skip_and_unknown",
})
SAFE_CTEST_DIAGNOSTIC_PREFIX = "GENEWHIP_TEST_RESULT:"
PHASE5_PROCESS_DIAGNOSTIC_METHOD = "BaselineRecordContract.test_real_process_output_cap_timeout_and_status"
PHASE5_PROCESS_SUBCASES = ("success", "stdout-cap", "timeout-direct", "timeout-descendant",
                           "exact-1023", "exact-1024", "stderr-cap")
PROCESS_CLEANUP_ENUM = (r"group-inactive|group-observer-cleanup-unconfirmed|group-status-budget-exhausted|"
    r"group-cleanup-os-error|cleanup-permission-denied|group-leader-reap-unconfirmed|"
    r"group-leader-wait-unconfirmed|group-reported-active|group-signal-permission-denied|"
    r"group-signal-visible|group-status-unavailable|cleanup-unclassified|not-observed|missing|other")
PROCESS_OBSERVER_STAGE_ENUM = (r"spawn|pipe|setup|selector|select|read|deadline|byte-limit|wait|"
    r"nonzero-exit|parse|observer-cleanup|none|missing|other")
PROCESS_SIGNAL_PHASE_ENUM = r"status-probe|sigterm|sigkill|other|none|missing"
PROCESS_OBSERVER_RETURN_ENUM = r"zero|nonzero|signaled|missing|other"
PROCESS_OBSERVER_ERROR_ENUM = r"permission|not-found|interrupted|timeout|io|other|none|missing"
PROCESS_OBSERVER_RAW = (rf"(?::({PROCESS_OBSERVER_STAGE_ENUM}):({PROCESS_SIGNAL_PHASE_ENUM}):"
    rf"({PROCESS_OBSERVER_RETURN_ENUM}):({PROCESS_OBSERVER_ERROR_ENUM}))?")
PROCESS_OBSERVER_SAFE = (rf"(?:;observer_failure_stage=({PROCESS_OBSERVER_STAGE_ENUM});"
    rf"cleanup_signal_phase=({PROCESS_SIGNAL_PHASE_ENUM});"
    rf"observer_return_category=({PROCESS_OBSERVER_RETURN_ENUM});"
    rf"observer_error_category=({PROCESS_OBSERVER_ERROR_ENUM}))?")
PROCESS_CLEANUP_DIAGNOSTIC = (rf"(?:;cleanup_reason=({PROCESS_CLEANUP_ENUM});"
    rf"status_observation=({PROCESS_CLEANUP_ENUM});cleanup_queries=(0|[1-9]|1[0-6]|other)" +
    PROCESS_OBSERVER_SAFE + r")?")
PHASE5_PROCESS_DIAGNOSTIC = re.compile(
    r"^GENEWHIP_TEST_RESULT:BaselineRecordContract\.test_real_process_output_cap_timeout_and_status"
    r":(failure|error):process:([a-z0-9-]+):"
    r"(AssertionError|PermissionError|FileNotFoundError|TimeoutExpired|OSError|RuntimeError|ValueError|TypeError|KeyError|IndexError|other|missing):"
    r"(not-launched|started|completed|failed|missing):"
    r"(not-launched|pending|confirmed|unconfirmed|missing):"
    r"(AssertionError|PermissionError|FileNotFoundError|TimeoutExpired|OSError|RuntimeError|ValueError|TypeError|KeyError|IndexError|other|missing):"
    r"(zero|nonzero|signaled|missing):"
    r"(output-byte-cap|timeout|cleanup-unconfirmed|other|none)"
    rf"(?::({PROCESS_CLEANUP_ENUM}):({PROCESS_CLEANUP_ENUM}):(0|[1-9]|1[0-6]|other)" +
    PROCESS_OBSERVER_RAW + r")?$")
SAFE_CTEST_DIAGNOSTIC = re.compile(
    r"^GENEWHIP_TEST_RESULT:([A-Za-z][A-Za-z0-9_]*\.test_[A-Za-z0-9_]+):(failure|error)"
    r"(?::(AssertionError|PermissionError|FileNotFoundError|TimeoutExpired|OSError|RuntimeError|ValueError|TypeError|KeyError|IndexError|other)"
    r":(confirmed|unconfirmed|missing):(phase7-capture-byte-limit|phase7-json-byte-limit|phase7-retained-byte-limit|"
    r"phase7-rss-byte-limit|phase7-rss-observation-unavailable|phase7-scratch-byte-limit|phase7-scratch-root-invalid|"
    r"phase7-scratch-tree-unsafe|phase7-stdout-stderr-byte-limit|phase7-wall-timeout|none|other|unspecified-bound-violation)"
    r":(group-inactive|group-leader-reap-unconfirmed|group-leader-wait-unconfirmed|"
    r"group-observer-cleanup-unconfirmed|group-status-budget-exhausted|group-reported-active|"
    r"cleanup-permission-denied|group-cleanup-os-error|group-signal-permission-denied|"
    r"group-signal-visible|group-status-unavailable|"
    r"cleanup-unclassified|not-observed|missing|other)"
    r":(group-inactive|group-leader-reap-unconfirmed|group-leader-wait-unconfirmed|"
    r"group-observer-cleanup-unconfirmed|group-status-budget-exhausted|group-reported-active|"
    r"cleanup-permission-denied|group-cleanup-os-error|group-signal-permission-denied|"
    r"group-signal-visible|group-status-unavailable|"
    r"cleanup-unclassified|not-observed|missing|other)"
    r":(0|[1-9]|1[0-6]|other)" + PROCESS_OBSERVER_RAW + r")?$")
HOST_SCHEMA = "genewhip-phase4-host-sessions"
HOST_CONTROLS = ROOT / "fixtures/independent-game-v2/host-controls.json"
HOST_HEX = re.compile(r"^[0-9a-f]{64}$")
SAFETY_LANES = {"native": ("pr", True), "sanitizer": ("pr", True),
                "production": ("production", False)}
SAFETY_ALLOWED_SKIPS = {"independent_game_admission", "independent_game_consumer"}
SAFETY_RUN_SCHEMA = "genewhip-phase4-safety-run-v1"
SAFETY_COMPLETION_SCHEMA = "genewhip-phase4-safety-lane-completion-v1"
SAFETY_FINAL_SCHEMA = "genewhip-phase4-safety-complete-v1"
SAFETY_CONFIG_SCHEMA = "genewhip-phase4-safety-config-v1"
SAFETY_GENERATORS = {"Unix Makefiles", "Ninja"}
SAFETY_CONFIG_KEYS = ("CMAKE_BUILD_TYPE", "CMAKE_GENERATOR", "GENEWHIP_TEST_HOOKS",
                      "CMAKE_C_COMPILER_ID", "CMAKE_C_COMPILER_VERSION")
SAFETY_MIN_CASES = {"native": 131, "sanitizer": 131, "production": 95}
PERSONAL_HOME_PATH = re.compile(
    rb"(?i)(?:/(?:Users|home)/[^/\\\s\"']+|[A-Z]:\\Users\\[^\\\s\"']+)"
)
SAFETY_COMMON_TESTS = {
    "evidence_contract", "diagnostics_contract", "load_contract", "time_contract",
    "reset_contract", "bus_boundary_contract", "gameplay_bus_contract", "installed_consumer",
}
SAFETY_HOOK_TESTS = {"memory_accounting", "phase4_report_contract"}
SAFETY_PRODUCTION_TESTS = {"cpu_overlay_absent", "z80_overlay_absent"}


def safety_required_tests(lane):
    required = set(SAFETY_COMMON_TESTS) | SAFETY_ALLOWED_SKIPS
    required |= SAFETY_HOOK_TESTS if SAFETY_LANES[lane][1] else SAFETY_PRODUCTION_TESTS
    return required


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def count(rows):
    return {name: sum(row.get("outcome") == name for row in rows) for name in OUTCOMES}


def git_head():
    snapshot_revision = os.environ.get("GENEWHIP_SOURCE_REVISION")
    if snapshot_revision:
        return snapshot_revision
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                          text=True, stdout=subprocess.PIPE).stdout.strip()


def public_source_identity(root=ROOT):
    """Return the committed public-source identity only when its worktree is clean.

    Planning notes are excluded because they are private workflow state and may be
    locally dirty without changing the public source tree under qualification.
    """
    root = Path(root).resolve()
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                          text=True, stdout=subprocess.PIPE).stdout.strip()
    tree = subprocess.run(["git", "rev-parse", "HEAD^{tree}"], cwd=root, check=True,
                          text=True, stdout=subprocess.PIPE).stdout.strip()
    changed = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all",
                              "--", ".", ":(exclude).planning/**"], cwd=root, check=True,
                             text=True, stdout=subprocess.PIPE).stdout
    if changed:
        raise ValueError("safety-source-dirty")
    return {"source_revision": head, "source_tree_id": tree}


def _safety_ci_root(build):
    build = Path(build).resolve()
    ci = build / "ci"
    if ci.is_symlink():
        raise ValueError("safety-ci-directory-symlink")
    ci.mkdir(parents=True, exist_ok=True)
    return ci


def _write_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(_json_bytes(value))
    os.replace(temporary, path)


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def _read_json(path):
    return json.loads(Path(path).read_text())


def _read_safety_record(path, invalid_reason):
    record = _read_json(path)
    if not isinstance(record, dict):
        raise ValueError(invalid_reason)
    return record


def _safety_run(build):
    return _read_safety_record(_safety_ci_root(build) / "safety-run.json",
                               "safety-run-invalid")


def safety_start(build, root=ROOT):
    """Start a fresh safety run, invalidating every prior lane artifact first."""
    identity = public_source_identity(root)
    ci = _safety_ci_root(build)
    for lane in SAFETY_LANES:
        lane_dir = ci / lane
        if lane_dir.is_symlink():
            lane_dir.unlink()
        elif lane_dir.exists():
            shutil.rmtree(lane_dir)
    for name in ("safety-run.json", "safety-complete.json", "source-revision.txt"):
        path = ci / name
        if path.is_symlink():
            path.unlink()
        else:
            path.unlink(missing_ok=True)
    _remove_safety_export(Path(build) / "safety-export")
    _remove_safety_export(Path(build) / "safety-failure-export")
    run = {"schema": SAFETY_RUN_SCHEMA, "version": 1,
           "run_id": secrets.token_hex(16), **identity}
    _write_json(ci / "safety-run.json", run)
    (ci / "source-revision.txt").write_text(identity["source_revision"] + "\n")
    return run


def _remove_safety_export(path):
    if path.is_symlink():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


def sanitize_ctest_junit(source, destination):
    """Keep testcase outcomes and exact allowlisted method IDs; discard freeform output."""
    source, destination = Path(source), Path(destination)
    _remove_safety_export(destination)
    try:
        original = ET.parse(source).getroot()
    except (OSError, ET.ParseError) as exc:
        raise ValueError("safety-ctest-junit-invalid") from exc
    original_cases = original.findall(".//testcase")
    if not original_cases:
        raise ValueError("safety-ctest-empty")
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite")
    for case in original_cases:
        name = case.get("name", "")
        if not name or PERSONAL_HOME_PATH.search(name.encode("utf-8")):
            raise ValueError("safety-ctest-personal-path")
        safe_case = ET.SubElement(suite, "testcase", {"name": name})
        for marker in ("skipped", "failure", "error"):
            if case.find(marker) is not None:
                ET.SubElement(safe_case, marker)
        diagnostics = set()
        for stream in case.iter():
            if stream.tag not in {"system-out", "system-err"}:
                continue
            for line in (stream.text or "").splitlines():
                if not line.startswith(SAFE_CTEST_DIAGNOSTIC_PREFIX):
                    continue
                process_match = PHASE5_PROCESS_DIAGNOSTIC.fullmatch(line)
                if process_match:
                    if process_match.group(2) not in PHASE5_PROCESS_SUBCASES:
                        raise ValueError("safety-ctest-diagnostic-invalid")
                    diagnostics.add((PHASE5_PROCESS_DIAGNOSTIC_METHOD, *process_match.groups(), "process"))
                    continue
                match = SAFE_CTEST_DIAGNOSTIC.fullmatch(line)
                if not match or match.group(1) not in SAFE_CTEST_DIAGNOSTIC_METHODS:
                    raise ValueError("safety-ctest-diagnostic-invalid")
                diagnostics.add((*match.groups(), "legacy"))
        if diagnostics:
            safe_output = ET.SubElement(safe_case, "system-out")
            lines = []
            for row in sorted(diagnostics, key=lambda row: tuple(
                     (0, "") if value is None else (1, str(value)) for value in row)):
                method, kind, *fields = row
                flavor = fields.pop()
                if flavor == "process":
                    subcase, exception, status, cleanup, cleanup_error, return_category, failure, reason, observation, attempts, observer, signal_phase, observer_return, observer_error = fields
                    lines.append(f"GENEWHIP_SAFE_TEST_RESULT:{method}:{kind};process_subcase={subcase};"
                        f"process_exception={exception};process_status={status};process_cleanup={cleanup};"
                        f"process_cleanup_error={cleanup_error};process_return={return_category};process_failure={failure}" +
                        (f";cleanup_reason={reason};status_observation={observation};cleanup_queries={attempts}"
                         if reason is not None else "") +
                        (f";observer_failure_stage={observer};cleanup_signal_phase={signal_phase};"
                         f"observer_return_category={observer_return};observer_error_category={observer_error}"
                         if observer is not None else ""))
                else:
                    exception, cleanup, bound, reason, status, attempts, observer, signal_phase, observer_return, observer_error = fields
                    lines.append(f"GENEWHIP_SAFE_TEST_RESULT:{method}:{kind}" +
                        (f";exception={exception};cleanup={cleanup};bound={bound};"
                         f"cleanup_reason={reason};status_observation={status};cleanup_queries={attempts}" if exception else "") +
                        (f";observer_failure_stage={observer};cleanup_signal_phase={signal_phase};"
                         f"observer_return_category={observer_return};observer_error_category={observer_error}"
                         if observer is not None else ""))
            safe_output.text = "\n".join(lines)
    payload = ET.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n"
    if PERSONAL_HOME_PATH.search(payload):
        raise ValueError("safety-ctest-personal-path")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".ctest-junit-",
                                         delete=False) as stream:
            temp_name = stream.name
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, destination)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)
    return destination


def summarize_sanitized_ctest_failures(source):
    """Return fixed outcome enums and allowlisted method IDs, never testcase names."""
    try:
        root = ET.parse(source).getroot()
    except (OSError, ET.ParseError) as exc:
        raise ValueError("safety-ctest-junit-invalid") from exc
    cases = root.findall(".//testcase")
    if not cases:
        raise ValueError("safety-ctest-empty")
    output = []
    for case in cases:
        name = case.get("name", "")
        if not name or PERSONAL_HOME_PATH.search(name.encode("utf-8")):
            raise ValueError("safety-ctest-personal-path")
        for kind in ("failure", "error"):
            if case.find(kind) is not None:
                output.append(f"CTest failure [{kind}]")
        for stream in case.findall("system-out"):
            for line in (stream.text or "").splitlines():
                if not line.startswith("GENEWHIP_SAFE_TEST_RESULT:"):
                    continue
                process_match = re.fullmatch(
                    r"GENEWHIP_SAFE_TEST_RESULT:BaselineRecordContract\.test_real_process_output_cap_timeout_and_status:(failure|error);"
                    r"process_subcase=([a-z0-9-]+);process_exception=(AssertionError|PermissionError|FileNotFoundError|TimeoutExpired|OSError|RuntimeError|ValueError|TypeError|KeyError|IndexError|other|missing);"
                    r"process_status=(not-launched|started|completed|failed|missing);process_cleanup=(not-launched|pending|confirmed|unconfirmed|missing);"
                    r"process_cleanup_error=(AssertionError|PermissionError|FileNotFoundError|TimeoutExpired|OSError|RuntimeError|ValueError|TypeError|KeyError|IndexError|other|missing);"
                    r"process_return=(zero|nonzero|signaled|missing);"
                    r"process_failure=(output-byte-cap|timeout|cleanup-unconfirmed|other|none)" +
                    PROCESS_CLEANUP_DIAGNOSTIC, line)
                if process_match:
                    if process_match.group(2) not in PHASE5_PROCESS_SUBCASES:
                        raise ValueError("safety-ctest-diagnostic-invalid")
                    output.append(f"CTest process subcase: {PHASE5_PROCESS_DIAGNOSTIC_METHOD} "
                        f"[{process_match.group(2)}; {process_match.group(1)}; exception={process_match.group(3)}; "
                        f"status={process_match.group(4)}; cleanup={process_match.group(5)}; "
                        f"cleanup_error={process_match.group(6)}; return={process_match.group(7)}; "
                        f"result={process_match.group(8)}" +
                        (f"; cleanup_reason={process_match.group(9)}; status_observation={process_match.group(10)}; "
                         f"cleanup_queries={process_match.group(11)}" if process_match.group(9) is not None else "") +
                        (f"; observer_failure_stage={process_match.group(12)}; cleanup_signal_phase={process_match.group(13)}"
                         f"; observer_return_category={process_match.group(14)}; observer_error_category={process_match.group(15)}"
                         if process_match.group(12) is not None else "") + "]")
                    continue
                match = re.fullmatch(
                    r"GENEWHIP_SAFE_TEST_RESULT:([A-Za-z][A-Za-z0-9_]*\.test_[A-Za-z0-9_]+):(failure|error)"
                    r"(?:;exception=(AssertionError|PermissionError|FileNotFoundError|TimeoutExpired|OSError|RuntimeError|ValueError|TypeError|KeyError|IndexError|other)"
                    r";cleanup=(confirmed|unconfirmed|missing);bound=(phase7-capture-byte-limit|phase7-json-byte-limit|"
                    r"phase7-retained-byte-limit|phase7-rss-byte-limit|phase7-rss-observation-unavailable|"
                    r"phase7-scratch-byte-limit|phase7-scratch-root-invalid|phase7-scratch-tree-unsafe|"
                    r"phase7-stdout-stderr-byte-limit|phase7-wall-timeout|none|other|unspecified-bound-violation);cleanup_reason="
                    r"(group-inactive|group-observer-cleanup-unconfirmed|group-status-budget-exhausted|"
                    r"group-leader-reap-unconfirmed|group-leader-wait-unconfirmed|group-reported-active|"
                    r"cleanup-permission-denied|group-cleanup-os-error|group-signal-permission-denied|"
                    r"group-signal-visible|"
                    r"group-status-unavailable|cleanup-unclassified|not-observed|missing|other);status_observation="
                    r"(group-inactive|group-observer-cleanup-unconfirmed|group-status-budget-exhausted|"
                    r"group-leader-reap-unconfirmed|group-leader-wait-unconfirmed|group-reported-active|"
                    r"cleanup-permission-denied|group-cleanup-os-error|group-signal-permission-denied|"
                    r"group-signal-visible|"
                    r"group-status-unavailable|cleanup-unclassified|not-observed|missing|other);"
                    r"cleanup_queries=(0|[1-9]|1[0-6]|other)" + PROCESS_OBSERVER_SAFE + r")?",
                    line)
                if not match or match.group(1) not in SAFE_CTEST_DIAGNOSTIC_METHODS:
                    raise ValueError("safety-ctest-diagnostic-invalid")
                if match.group(3):
                    if (match.group(2) == "failure") != (match.group(3) == "AssertionError"):
                        raise ValueError("safety-ctest-diagnostic-invalid")
                    output.append(
                        f"CTest subtest failure: {match.group(1)} [{match.group(2)}; "
                        f"exception={match.group(3)}; cleanup={match.group(4)}; bound={match.group(5)}; "
                        f"cleanup_reason={match.group(6)}; status_observation={match.group(7)}; "
                        f"cleanup_queries={match.group(8)}" +
                        (f"; observer_failure_stage={match.group(9)}; cleanup_signal_phase={match.group(10)}"
                         f"; observer_return_category={match.group(11)}; observer_error_category={match.group(12)}"
                         if match.group(9) is not None else "") + "]")
                else:
                    output.append(f"CTest subtest failure: {match.group(1)} [{match.group(2)}]")
    return sorted(set(output))


def _safety_lane_files(ci, lane):
    lane_build = ci / lane
    junit_path = lane_build / "ctest-junit.xml"
    summary_path = lane_build / "safety-contract.json"
    cache_path = lane_build / "CMakeCache.txt"
    config_path = lane_build / "safety-config.json"
    root = ET.parse(junit_path).getroot()
    cases = root.findall(".//testcase")
    if not cases:
        raise ValueError("safety-ctest-empty")
    names = [case.get("name", "") for case in cases]
    skipped = [case.get("name", "") for case in cases if case.find("skipped") is not None]
    passed = sum(case.find("skipped") is None and case.find("failure") is None and
                 case.find("error") is None for case in cases)
    failed = sum(case.find("failure") is not None for case in cases)
    errors = sum(case.find("error") is not None for case in cases)
    ctest = {"denominator": len(cases), "pass": passed, "fail": failed,
             "error": errors, "skipped": skipped, "case_names": names,
             "test_inventory_sha256": digest(sorted(names)), "junit_sha256": sha(junit_path)}
    if (len(names) < SAFETY_MIN_CASES[lane] or len(names) != len(set(names)) or
            not safety_required_tests(lane) <= set(names)):
        raise ValueError("safety-ctest-roster")
    if failed or errors or passed + len(skipped) != len(cases):
        raise ValueError("safety-ctest-outcome")
    if any(not isinstance(name, str) or not name for name in skipped):
        raise ValueError("safety-unexpected-skip")
    if len(skipped) != len(set(skipped)):
        raise ValueError("safety-duplicate-skip")
    if not set(skipped) <= SAFETY_ALLOWED_SKIPS:
        raise ValueError("safety-unexpected-skip")
    summary_bytes = summary_path.read_bytes()
    summary = json.loads(summary_bytes)
    config_bytes = config_path.read_bytes()
    safety_config = json.loads(config_bytes)
    _validate_safety_configuration(safety_config, lane)
    if cache_path.is_file() and safety_config != _safety_configuration_from_cache(cache_path, lane):
        raise ValueError("safety-config-cache-mismatch")
    return {"ctest": ctest, "summary": summary,
            "summary_sha256": digest(summary),
            "summary_file_sha256": hashlib.sha256(summary_bytes).hexdigest(),
            "configuration": safety_config,
            "configuration_sha256": hashlib.sha256(config_bytes).hexdigest()}


def _safety_configuration_from_cache(cache_path, lane):
    """Read only safe lane settings from CMakeCache; never export cache contents."""
    cache_keys = {"CMAKE_BUILD_TYPE", "CMAKE_GENERATOR", "GENEWHIP_TEST_HOOKS"}
    values = {}
    for line in Path(cache_path).read_text(errors="replace").splitlines():
        match = re.match(r"^([^:]+):[^=]*=(.*)$", line)
        if match and match.group(1) in cache_keys | {"CMAKE_C_COMPILER_ID", "CMAKE_C_COMPILER_VERSION"}:
            key, value = match.groups()
            if key in values:
                raise ValueError("safety-config-invalid")
            values[key] = value
    if not cache_keys <= set(values):
        raise ValueError("safety-config-invalid")
    compiler_keys = {"CMAKE_C_COMPILER_ID", "CMAKE_C_COMPILER_VERSION"}
    present_compiler_keys = compiler_keys & set(values)
    if present_compiler_keys and present_compiler_keys != compiler_keys:
        raise ValueError("safety-config-invalid")
    if not present_compiler_keys:
        identities = set()
        for compiler_file in Path(cache_path).parent.glob("CMakeFiles/*/CMakeCCompiler.cmake"):
            text = compiler_file.read_text(errors="replace")
            compiler_id = re.search(r'^set\(CMAKE_C_COMPILER_ID "([^"]+)"\)$', text, re.MULTILINE)
            compiler_version = re.search(r'^set\(CMAKE_C_COMPILER_VERSION "([^"]+)"\)$', text, re.MULTILINE)
            if compiler_id and compiler_version:
                identities.add((compiler_id.group(1), compiler_version.group(1)))
        if len(identities) != 1:
            raise ValueError("safety-config-invalid")
        values["CMAKE_C_COMPILER_ID"], values["CMAKE_C_COMPILER_VERSION"] = identities.pop()
    config = {"schema": SAFETY_CONFIG_SCHEMA, "version": 1,
              "lane": lane, "values": values}
    _validate_safety_configuration(config, lane)
    return config


def _validate_safety_configuration(config, lane):
    if (not isinstance(config, dict) or set(config) != {"schema", "version", "lane", "values"} or
            config.get("schema") != SAFETY_CONFIG_SCHEMA or config.get("version") != 1 or
            config.get("lane") != lane or not isinstance(config.get("values"), dict) or
            set(config["values"]) != set(SAFETY_CONFIG_KEYS)):
        raise ValueError("safety-config-invalid")
    values = config["values"]
    safe_text = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _+.-]{0,63}$")
    for key in SAFETY_CONFIG_KEYS:
        value = values.get(key)
        if not isinstance(value, str) or not safe_text.fullmatch(value):
            raise ValueError("safety-config-invalid")
    if values["CMAKE_BUILD_TYPE"] != "Release":
        raise ValueError("safety-config-invalid")
    if values["CMAKE_GENERATOR"] not in SAFETY_GENERATORS:
        raise ValueError("safety-config-invalid")
    if values["GENEWHIP_TEST_HOOKS"] != ("ON" if SAFETY_LANES[lane][1] else "OFF"):
        raise ValueError("safety-config-invalid")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9+_.-]{0,63}", values["CMAKE_C_COMPILER_ID"]):
        raise ValueError("safety-config-invalid")
    if not re.fullmatch(r"[0-9][A-Za-z0-9.+_-]{0,63}", values["CMAKE_C_COMPILER_VERSION"]):
        raise ValueError("safety-config-invalid")
    return config


def _validate_lane_completion(ci, lane, run):
    path = ci / lane / "safety-completion.json"
    if not isinstance(run, dict):
        raise ValueError("safety-run-invalid")
    record = _read_safety_record(path, "safety-lane-record-invalid")
    if record.get("schema") != SAFETY_COMPLETION_SCHEMA or record.get("lane") != lane:
        raise ValueError("safety-lane-record-invalid")
    if record.get("run_id") != run.get("run_id"):
        raise ValueError("safety-lane-run-mismatch")
    for key in ("source_revision", "source_tree_id"):
        if record.get(key) != run.get(key):
            raise ValueError("safety-lane-source-mismatch")
    current = _safety_lane_files(ci, lane)
    for key in ("ctest", "summary", "summary_sha256", "summary_file_sha256",
                "configuration", "configuration_sha256"):
        if record.get(key) != current.get(key):
            raise ValueError("safety-lane-artifact-mismatch")
    return record


def safety_complete_lane(build, lane, root=ROOT):
    if lane not in SAFETY_LANES:
        raise ValueError("safety-lane-invalid")
    run = _safety_run(build)
    if public_source_identity(root) != {key: run.get(key) for key in
                                        ("source_revision", "source_tree_id")}:
        raise ValueError("safety-source-changed")
    ci = _safety_ci_root(build)
    lane_dir = ci / lane
    safety_config = _safety_configuration_from_cache(lane_dir / "CMakeCache.txt", lane)
    _write_json(lane_dir / "safety-config.json", safety_config)
    record = {"schema": SAFETY_COMPLETION_SCHEMA, "version": 1, "run_id": run["run_id"],
              "lane": lane, "source_revision": run["source_revision"],
              "source_tree_id": run["source_tree_id"],
              **_safety_lane_files(ci, lane)}
    _write_json(ci / lane / "safety-completion.json", record)
    return record


def safety_finish(build, root=ROOT):
    run = _safety_run(build)
    if public_source_identity(root) != {key: run.get(key) for key in
                                        ("source_revision", "source_tree_id")}:
        raise ValueError("safety-source-changed")
    ci = _safety_ci_root(build)
    records = {lane: _validate_lane_completion(ci, lane, run) for lane in SAFETY_LANES}
    final = {"schema": SAFETY_FINAL_SCHEMA, "version": 1, "run_id": run["run_id"],
             "source_revision": run["source_revision"],
             "source_tree_id": run["source_tree_id"],
             "lane_completion_sha256": {
                 lane: digest(records[lane]) for lane in SAFETY_LANES}}
    _write_json(ci / "safety-complete.json", final)
    return final


def safety_export(build, output, root=ROOT):
    """Atomically stage only complete, validated, path-free safety evidence."""
    build, output = Path(build), Path(output)
    _remove_safety_export(output)
    ci = _safety_ci_root(build)
    run = _safety_run(build)
    safety_finish(build, root)
    evidence, problems = collect_safety_contracts(build, run.get("source_revision"))
    if problems or evidence.get("source_revision") != run.get("source_revision"):
        reasons = sorted({name for name, _ in problems})
        suffix = ":" + ",".join(reasons) if reasons else ""
        raise ValueError("safety-export-validation" + suffix)
    files = [ci / "safety-run.json", ci / "safety-complete.json",
             ci / "source-revision.txt", ci / "toolchain.txt"]
    for lane in SAFETY_LANES:
        files.extend(ci / lane / name for name in
                     ("safety-config.json", "ctest-junit.xml", "safety-contract.json",
                      "safety-completion.json"))
    if any(not path.is_file() or path.is_symlink() for path in files):
        raise ValueError("safety-export-file-missing")
    payloads = [(path, path.read_bytes()) for path in files]
    if any(PERSONAL_HOME_PATH.search(payload) for _, payload in payloads):
        raise ValueError("safety-export-personal-path")
    output.parent.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(prefix=".safety-export-", dir=output.parent))
    try:
        for source, payload in payloads:
            target = temp_dir / source.relative_to(ci)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        os.replace(temp_dir, output)
    finally:
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
    return output


def safety_failure_export(build, output, root=ROOT):
    """Retain bounded failure diagnostics without producing safety completion evidence."""
    build, output = Path(build).resolve(), Path(output)
    if output.name != "safety-failure-export" or output.parent.resolve() != build:
        raise ValueError("safety-failure-export-destination")
    _remove_safety_export(output)
    ci = _safety_ci_root(build)
    run_path = ci / "safety-run.json"
    def read_owned(path, cap):
        info = path.lstat()
        if (path.is_symlink() or not path.is_file() or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_size > cap):
            raise ValueError("safety-failure-export-file-invalid")
        with path.open("rb") as stream:
            raw = stream.read(cap + 1)
        if len(raw) > cap:
            raise ValueError("safety-failure-export-file-invalid")
        return raw
    run = json.loads(read_owned(run_path, 4096))
    identity = public_source_identity(root)
    if (not isinstance(run, dict)
            or set(run) != {"schema", "version", "run_id", "source_revision", "source_tree_id"}
            or run.get("schema") != SAFETY_RUN_SCHEMA or type(run.get("version")) is not int
            or run.get("version") != 1
            or not re.fullmatch(r"[0-9a-f]{32}", str(run.get("run_id", "")))
            or any(not re.fullmatch(r"[0-9a-f]{40}", str(run.get(key, "")))
                   or run.get(key) != identity.get(key) for key in ("source_revision", "source_tree_id"))):
        raise ValueError("safety-failure-export-identity")
    payloads, lanes = [], []
    for lane in SAFETY_LANES:
        directory = ci / lane
        if directory.is_symlink():
            raise ValueError("safety-failure-export-file-invalid")
        source = directory / "ctest-junit.xml"
        if not source.exists() and not source.is_symlink():
            continue
        raw = read_owned(source, 2 * 1024 * 1024)
        failures = summarize_sanitized_ctest_failures(io.BytesIO(raw))
        original = ET.fromstring(raw)
        cases = original.findall(".//testcase")
        if len(cases) > 4096:
            raise ValueError("safety-failure-export-case-limit")
        safe = ET.Element("testsuites")
        suite = ET.SubElement(safe, "testsuite")
        for index, case in enumerate(cases):
            target = ET.SubElement(suite, "testcase", {"name": f"case-{index + 1}"})
            for marker in ("failure", "error", "skipped"):
                if case.find(marker) is not None:
                    ET.SubElement(target, marker)
            lines = [line for stream in case.findall("system-out")
                     for line in (stream.text or "").splitlines()
                     if line.startswith("GENEWHIP_SAFE_TEST_RESULT:")]
            if lines:
                ET.SubElement(target, "system-out").text = "\n".join(lines)
        payload = ET.tostring(safe, encoding="utf-8", xml_declaration=True) + b"\n"
        payloads.append((Path(lane) / "ctest-junit.xml", payload))
        lanes.append({"lane": lane, "source_junit_sha256": hashlib.sha256(raw).hexdigest(),
                      "exported_junit_sha256": hashlib.sha256(payload).hexdigest(), "failures": failures})
    if not any(row["failures"] for row in lanes):
        raise ValueError("safety-failure-export-no-failure")
    report = {"schema": "genewhip-safety-failure-diagnostics-v1", "status": "failed",
              "qualification_accepted": False, "run_id": run["run_id"], **identity, "lanes": lanes}
    payloads.append((Path("failure-diagnostics.json"), _json_bytes(report)))
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".safety-failure-export-", dir=output.parent))
    try:
        for relative, payload in payloads:
            target = temporary / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return output


def host_export(build, output, run_id, run_attempt, source_sha, root=ROOT):
    """Atomically stage the exact-source host reports without runner paths or binaries."""
    build, output, root = Path(build), Path(output), Path(root)
    build_resolved, output_resolved, root_resolved = (
        build.resolve(), output.resolve(), root.resolve())
    try:
        output_resolved.relative_to(build_resolved)
    except ValueError as exc:
        raise ValueError("host-export-output-outside-build") from exc
    if output_resolved == build_resolved or output_resolved == root_resolved:
        raise ValueError("host-export-output-overlaps-source")
    if not isinstance(run_id, str) or not run_id.isdecimal():
        raise ValueError("host-export-run-id-invalid")
    if type(run_attempt) is not int or run_attempt < 1:
        raise ValueError("host-export-run-attempt-invalid")
    if not isinstance(source_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("host-export-source-invalid")
    identity = public_source_identity(root)
    if identity["source_revision"] != source_sha:
        raise ValueError("host-export-source-mismatch")
    desktop = build / "tools/desktop/genewhip-desktop"
    headless = build / "tools/session/gw_headless"
    cache = build / "CMakeCache.txt"
    paths = {"software": build / "evidence/phase4-host-sessions.json",
             "live": build / "evidence/phase4-host-live.json"}
    protected = (root_resolved, build_resolved, *(path.resolve() for path in
                 (desktop, headless, cache, *paths.values())))
    if any(path == output_resolved or output_resolved in path.parents
           for path in protected):
        raise ValueError("host-export-output-overlaps-source")
    if any(not path.is_file() or path.is_symlink() for path in (desktop, headless, cache, *paths.values())):
        raise ValueError("host-export-input-missing")
    try:
        reports = {name: json.loads(path.read_text()) for name, path in paths.items()}
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("host-export-report-invalid") from exc
    if any(not isinstance(report, dict) for report in reports.values()):
        raise ValueError("host-export-report-invalid")
    if any(report.get("outcome") != "pass" for report in reports.values()):
        raise ValueError("host-export-report-not-pass")
    expected_identity = {"build_configuration_sha256": sha(cache),
                         "desktop_build_sha256": sha(desktop),
                         "headless_build_sha256": sha(headless)}
    problems = validate_host_sessions(reports, expected_revision=source_sha,
                                      expected_identity=expected_identity)
    if problems:
        reasons = sorted({reason for reason, _ in problems})
        message = "host-export-validation:" + ",".join(reasons)
        if "desktop-host-capability" in reasons:
            message += ";live-display-summary=" + json.dumps(
                _host_display_summary(reports["live"]), sort_keys=True, separators=(",", ":"))
        raise ValueError(message)

    hygiene_spec = importlib.util.spec_from_file_location(
        "gw_host_export_public_hygiene", root / "scripts/ci/public_hygiene.py")
    if hygiene_spec is None or hygiene_spec.loader is None:
        raise ValueError("host-export-hygiene-unavailable")
    hygiene = importlib.util.module_from_spec(hygiene_spec)
    hygiene_spec.loader.exec_module(hygiene)
    payloads = {"phase4-host-sessions.json": paths["software"].read_bytes(),
                "phase4-host-live.json": paths["live"].read_bytes()}
    if any(hygiene.PATTERNS[reason].search(payload)
           for payload in payloads.values() for reason in hygiene.PATTERNS):
        raise ValueError("host-export-private-content")
    receipt = {"schema": "genewhip-phase4-host-evidence-v1", "version": 1,
               "run_id": run_id, "run_attempt": run_attempt,
               "source_revision": identity["source_revision"],
               "source_tree_id": identity["source_tree_id"],
               "reports": {
                   "software": {"path": "phase4-host-sessions.json",
                                "sha256": hashlib.sha256(payloads["phase4-host-sessions.json"]).hexdigest()},
                   "live": {"path": "phase4-host-live.json",
                            "sha256": hashlib.sha256(payloads["phase4-host-live.json"]).hexdigest()}}}
    payloads["host-evidence.json"] = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    _remove_safety_export(output)
    temp_dir = Path(tempfile.mkdtemp(prefix=".host-export-", dir=output.parent))
    try:
        for name, payload in payloads.items():
            target = temp_dir / name
            target.write_bytes(payload)
            if hygiene.scan_file(target):
                raise ValueError("host-export-private-content")
        os.replace(temp_dir, output)
    finally:
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
    return output


def _host_display_summary(report):
    """Return only bounded, non-identifying display capability facts for failure logs."""
    summary = []
    rows = report.get("runs")
    if not isinstance(rows, list):
        return summary
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        settings = row.get("host_settings")
        settings = settings if isinstance(settings, dict) else {}
        display = settings.get("display_identity")
        display = display if isinstance(display, dict) else {}
        displays = display.get("displays")
        displays = displays if isinstance(displays, list) else []
        refresh_count = sum(
            isinstance(item, dict)
            and isinstance(item.get("refresh_hz"), (int, float))
            and not isinstance(item.get("refresh_hz"), bool)
            and math.isfinite(item.get("refresh_hz"))
            and item.get("refresh_hz") > 0
            for item in displays)
        summary.append({"case_index": index,
                        "cocoa_driver": settings.get("video_driver") == "cocoa",
                        "display_observed": display.get("status") == "observed",
                        "display_count": len(displays), "refresh_count": refresh_count})
    return summary


def _valid_host_display_identity(display):
    """Accept an observed display with explicit unknown refresh, or a named absence."""
    if not isinstance(display, dict):
        return False
    status = display.get("status")
    if status == "unavailable":
        return isinstance(display.get("reason"), str) and bool(display["reason"].strip()) and \
            not display.get("displays")
    if status != "observed":
        return False
    displays = display.get("displays")
    if not isinstance(displays, list) or not displays:
        return False
    for item in displays:
        if not isinstance(item, dict) or "refresh_hz" not in item:
            return False
        refresh = item["refresh_hz"]
        if refresh is not None and (not isinstance(refresh, (int, float)) or isinstance(refresh, bool)
                                    or not math.isfinite(refresh) or refresh <= 0):
            return False
    return True


def source_state():
    if os.environ.get("GENEWHIP_SOURCE_SNAPSHOT") == "1":
        return "clean"
    result = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT,
                            check=True, text=True, stdout=subprocess.PIPE)
    return "dirty" if result.stdout else "clean"


def configuration(build):
    cache = Path(build) / "CMakeCache.txt"
    if not cache.is_file():
        raise ValueError("CMakeCache.txt is missing from build directory")
    values = {}
    for line in cache.read_text(errors="replace").splitlines():
        match = re.match(r"^([^:]+):[^=]+=(.*)$", line)
        if match and match.group(1) in CONFIG_KEYS:
            values[match.group(1)] = match.group(2)
    return {"cmake": values, "host": {"system": platform.system(), "machine": platform.machine()}}


def expected_tracer_identity(build):
    scenario_path = ROOT / "fixtures/raster-toy/scenario.json"
    scenario = json.loads(scenario_path.read_text())
    source_path = ROOT / scenario["rom"]["source"]
    rom_path = ROOT / scenario["rom"]["path"]
    ticks = scenario["inputs"]["ticks_per_field"]
    input_bytes = ("genewhip-input-log 1\n" + "".join(
        "%d pad %d %x\n" % (int(entry["field"]) * ticks, int(entry["port"]), int(entry["mask"], 0))
        for entry in scenario["inputs"]["entries"])).encode()
    build = Path(build).resolve()
    headless, desktop = build / "tools/session/gw_headless", build / "tools/desktop/genewhip-desktop"
    identity = {
        "fixture": "fixtures/raster-toy",
        "profile": "VA3 NTSC-U",
        "source_sha256": sha(source_path),
        "scenario_sha256": sha(scenario_path),
        "rom_sha256": sha(rom_path),
        "input_sha256": hashlib.sha256(input_bytes).hexdigest(),
        "build_configuration_sha256": digest(configuration(build)),
        "headless_build_sha256": sha(headless) if headless.is_file() else None,
        "desktop_build_sha256": sha(desktop) if desktop.is_file() else None,
    }
    return identity


def validate_gameplay(evidence, qualification=False, expected_identity=None):
    problems = []
    if not isinstance(evidence, dict) or evidence.get("schema") != "genewhip-phase4-gameplay-v1" or evidence.get("version") != 1:
        return [("gameplay-schema", "invalid gameplay schema/version")]
    if evidence.get("outcome") != "pass":
        problems.append(("gameplay-outcome", str(evidence.get("outcome"))))
    if evidence.get("fixture_id") != "genewhip-independent-game-v2":
        problems.append(("gameplay-fixture", "unexpected fixture id"))
    for key, value in GAME_IDENTITIES.items():
        if evidence.get(key) != value:
            problems.append(("stale-game-" + key.removesuffix("_sha256"), key))
    if evidence.get("profile") != "VA3-NTSC-U":
        problems.append(("stale-game-profile", str(evidence.get("profile"))))
    visual = evidence.get("visual_observations")
    if not isinstance(visual, dict) or visual.get("title_to_play_field_10_changed") is not True or \
            visual.get("start_idle_to_moved_marker_field_19_changed") is not True:
        problems.append(("gameplay-visual-oracle", "title/movement rendered pixels did not satisfy source-derived comparisons"))
    for key in ("build_configuration_sha256",):
        if not isinstance(evidence.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", evidence[key]):
            problems.append(("gameplay-identity", key))
    clients = evidence.get("clients")
    if not isinstance(clients, list) or any(name not in ("headless", "desktop") for name in clients) or len(set(clients)) != len(clients):
        problems.append(("gameplay-clients", "invalid client roster"))
    if qualification and clients != ["headless", "desktop"]:
        problems.append(("gameplay-client-missing", "headless and desktop are both required"))
    client_digests = evidence.get("client_sha256")
    if not isinstance(client_digests, list) or len(client_digests) != (len(clients) if isinstance(clients, list) else -1) or any(
            not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in client_digests):
        problems.append(("gameplay-identity", "client_sha256"))
    if expected_identity:
        for key, reason in (("build_configuration_sha256", "gameplay-stale-configuration"),
                            ("client_sha256", "gameplay-stale-client")):
            if evidence.get(key) != expected_identity.get(key):
                problems.append((reason, key))
    rows = evidence.get("results")
    if not isinstance(rows, list):
        return problems + [("gameplay-roster", "results must be a list")]
    if evidence.get("denominator") != len(rows):
        problems.append(("gameplay-denominator", "case denominator differs"))
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            problems.append(("gameplay-row", "case must be an object")); continue
        case_id = row.get("id")
        if case_id not in GAME_CASES or case_id in seen:
            problems.append(("gameplay-case-roster", str(case_id))); continue
        seen.add(case_id)
        index = GAME_CASES.index(case_id)
        play, low, high, psg, minimum_ac, maximum_ac = GAME_EXPECTATIONS[index]
        if row.get("outcome") != "pass": problems.append(("gameplay-case-non-pass", case_id))
        if row.get("unsupported") != 0: problems.append(("gameplay-unsupported", case_id))
        if row.get("fields") != GAME_FIELDS[index]: problems.append(("gameplay-field-budget", case_id))
        if row.get("play_state") != play or not isinstance(row.get("position"), int) or not low <= row["position"] <= high:
            problems.append(("gameplay-source-state", case_id))
        if row.get("psg") != psg:
            problems.append(("gameplay-causal-psg", case_id))
        if not isinstance(row.get("ac_range"), int) or row["ac_range"] < minimum_ac or \
                (maximum_ac is not None and row["ac_range"] != maximum_ac):
            problems.append(("gameplay-waveform", case_id))
        if not isinstance(row.get("input_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", row["input_sha256"]):
            problems.append(("gameplay-identity", case_id + " input"))
        if not isinstance(row.get("machine_digest"), str) or not isinstance(row.get("field_hashes_sha256"), str):
            problems.append(("gameplay-observation", case_id))
        if clients == ["headless", "desktop"] and row.get("desktop_equal") is not True:
            problems.append(("gameplay-client-divergence", case_id))
    for case_id in set(GAME_CASES) - seen:
        problems.append(("gameplay-case-missing", case_id))
    if evidence.get("fields") != sum(GAME_FIELDS):
        problems.append(("gameplay-total-fields", "expected full frozen denominator"))
    return problems


def host_fixture_identities():
    document = json.loads(HOST_CONTROLS.read_text())
    result = {}
    for key, session in document["sessions"].items():
        scenario_path = ROOT / session["scenario"]
        scenario = json.loads(scenario_path.read_text())
        source_path = ROOT / (scenario["source"]["relative_path"] if session["scenario_case"]
                              else scenario["rom"]["source"])
        result[key] = {"fixture_id": session["fixture_id"],
                       "scenario_sha256": sha(scenario_path), "source_sha256": sha(source_path),
                       "rom_sha256": sha(ROOT / session["rom"])}
    return result


def validate_host_sessions(evidence, expected_revision=None, expected_identity=None):
    """Validate finite desktop observations and their exact build/fixture identities."""
    problems = []
    if not isinstance(evidence, dict) or not {"software", "live"} <= set(evidence):
        return [("desktop-host-schema", "software and live evidence are required")]
    expected_identity = expected_identity or {}
    fixture_identities = host_fixture_identities()
    control_sha = sha(HOST_CONTROLS)
    for mode in ("software", "live"):
        all_ids = set()
        report = evidence.get(mode)
        if not isinstance(report, dict) or report.get("schema") != HOST_SCHEMA or report.get("version") != 1:
            problems.append(("desktop-host-schema", mode)); continue
        if report.get("mode") != mode:
            problems.append(("desktop-host-schema", mode + " mode mismatch"))
        if expected_revision and report.get("source_revision") != expected_revision:
            problems.append(("desktop-host-stale-source", mode))
        if report.get("control_sha256") != control_sha:
            problems.append(("desktop-host-control-identity", mode))
        for field, reason in (("build_configuration_sha256", "desktop-host-stale-build"),
                              ("desktop_build_sha256", "desktop-host-stale-build"),
                              ("headless_build_sha256", "desktop-host-stale-build")):
            expected = expected_identity.get(field)
            if expected and report.get(field) != expected:
                problems.append((reason, mode + " " + field))
        if report.get("outcome") not in (("pass",) if mode == "software" else ("pass", "skipped")):
            problems.append(("desktop-host-outcome", mode))
        if mode == "live" and report.get("outcome") == "skipped" and not report.get("reason"):
            problems.append(("desktop-host-capability", "live skip requires a reason"))
        runs = report.get("runs")
        if not isinstance(runs, list) or report.get("denominator") != len(runs):
            problems.append(("desktop-host-denominator", mode)); continue
        counts = {name: sum(isinstance(row, dict) and row.get("outcome") == name for row in runs)
                  for name in ("pass", "skipped", "fail")}
        if report.get("counts") != counts:
            problems.append(("desktop-host-counts", mode))
        if mode == "live" and report.get("outcome") == "skipped" and not runs:
            continue
        expected_modes = (("live", "replace-drop") if mode == "live" else
                          ("software-dummy", "software-disk", "missing-audio-negative", "replace-drop"))
        expected_ids = {fixture + "-" + run_mode for fixture in fixture_identities for run_mode in expected_modes}
        actual_ids = {row.get("id") for row in runs if isinstance(row, dict)}
        if actual_ids != expected_ids:
            problems.append(("desktop-host-roster", mode))
        if report.get("outcome") == "pass" and any(row.get("outcome") == "fail" for row in runs):
            problems.append(("desktop-host-outcome", mode + " contains failed run"))
        if mode == "live" and report.get("outcome") == "pass" and any(
                isinstance(row, dict) and row.get("outcome") != "pass" for row in runs):
            problems.append(("desktop-host-outcome", "live pass requires every run to pass"))
        host = report.get("host")
        if not isinstance(host, dict) or not host.get("video_driver") or not host.get("audio_backend_requested") or \
                not isinstance(host.get("audio_rate_hz"), int) or not isinstance(host.get("audio_queue_policy"), dict):
            problems.append(("desktop-host-setup", mode))
        for row in runs:
            if not isinstance(row, dict):
                problems.append(("desktop-host-schema", mode + " row must be object")); continue
            row_id = row.get("id")
            if row_id in all_ids:
                problems.append(("desktop-host-roster", "duplicate " + str(row_id)))
            all_ids.add(row_id)
            if row.get("outcome") == "fail":
                problems.append(("desktop-host-outcome", str(row_id)))
            if mode == "live" and row.get("outcome") == "skipped" and row.get("reason"):
                continue
            if row_id and row_id.endswith("missing-audio-negative"):
                stats = row.get("stats", {})
                if row.get("outcome") != "skipped" or stats.get("audio_available") != 0 or stats.get("queue_samples") != 0:
                    problems.append(("desktop-host-audio-fallback", str(row_id)))
                continue
            fixture = next((key for key in fixture_identities if row_id and row_id.startswith(key + "-")), None)
            if fixture is None:
                problems.append(("desktop-host-roster", str(row_id))); continue
            if row_id.endswith("replace-drop"):
                replacement_key = "sounded-diagnostic" if fixture == "independent-game-v2" else "independent-game-v2"
                for label, key in (("primary", fixture), ("replacement", replacement_key)):
                    actual = row.get(label)
                    identity = fixture_identities[key]
                    if not isinstance(actual, dict) or any(actual.get(field) != value
                                                          for field, value in identity.items()):
                        problems.append(("desktop-host-source-identity", str(row_id) + " " + label))
                if row.get("outcome") != "pass":
                    problems.append(("desktop-host-outcome", str(row_id)))
                deterministic = {key: row.get(key) for key in ("fields_by_segment", "complete_pcm_frames",
                    "machine_digest", "field_hashes_sha256", "field_identity_sha256", "complete_pcm_sha256")}
                stats = row.get("stats", {})
                settings = row.get("host_settings")
                if row.get("controls_exercised") != ["drop", "replace"]:
                    problems.append(("desktop-host-controls", str(row_id)))
                if row.get("deterministic_segment_join") is not True or \
                        not all(isinstance(deterministic[key], (list, int, str)) for key in deterministic) or \
                        deterministic["machine_digest"] != row.get("headless_machine_digest") or \
                        row.get("field_hashes_sha256") != row.get("headless_field_hashes_sha256") or \
                        row.get("field_identity_sha256") != row.get("headless_field_identity_sha256") or \
                        row.get("complete_pcm_sha256") != row.get("headless_core_pcm_sha256"):
                    problems.append(("desktop-host-deterministic-identity", str(row_id)))
                if stats.get("stats_version") != 2:
                    problems.append(("desktop-host-stats-version", str(row_id)))
                if row.get("elapsed_exposure_ns", 0) <= 0 or not isinstance(settings, dict) or \
                        settings.get("video_driver") != ("cocoa" if mode == "live" else "dummy") or \
                        settings.get("audio_backend_requested") != ("coreaudio" if mode == "live" else "disk"):
                    problems.append(("desktop-host-setup", str(row_id)))
                if mode == "live" and not _valid_host_display_identity(
                        settings.get("display_identity") if isinstance(settings, dict) else None):
                    problems.append(("desktop-host-capability", str(row_id)))
                if "present_errors" not in stats or not isinstance(stats.get("present_errors"), int) or \
                        stats.get("present_errors") != 0 or stats.get("presentation_error") != 0 or \
                        stats.get("present_calls", 0) != stats.get("present_successes", 0) + stats.get("present_errors", 0) or \
                        stats.get("present_calls", 0) < 1:
                    problems.append(("desktop-host-presentation", str(row_id)))
                if stats.get("audio_available") != 1 or \
                        stats.get("queue_source_unit") != "SDL input bytes and stereo source frames" or \
                        stats.get("queue_exposure_ns", 0) <= 0 or \
                        row.get("host_audio_queue_kind") != "SDL queued source bytes/frames" or \
                        "unavailable" not in row.get("device_queue_observation", ""):
                    problems.append(("desktop-host-queue", str(row_id)))
                for field in ("input_log_sha256", "input_script_sha256", "control_sha256",
                              "build_configuration_sha256", "desktop_build_sha256", "headless_build_sha256"):
                    if not HOST_HEX.fullmatch(str(row.get(field, ""))):
                        problems.append(("desktop-host-stale-identity", str(row_id) + " " + field))
                    expected = expected_identity.get(field)
                    if expected and row.get(field) != expected:
                        problems.append(("desktop-host-stale-identity", str(row_id) + " " + field))
                if row.get("control_sha256") != control_sha:
                    problems.append(("desktop-host-control-identity", str(row_id)))
                continue
            for field, value in fixture_identities[fixture].items():
                if row.get(field) != value:
                    problems.append(("desktop-host-source-identity", str(row_id) + " " + field))
            if row.get("outcome") != "pass":
                problems.append(("desktop-host-outcome", str(row_id)))
            settings = row.get("host_settings")
            required_settings = ("os", "os_release", "os_version", "architecture", "video_driver",
                                 "display_identity", "vsync_requested", "vsync_actual", "audio_backend_requested",
                                 "audio_rate_hz", "audio_queue_policy", "renderer_readback", "physical_scanout")
            if not isinstance(settings, dict) or any(key not in settings for key in required_settings) or \
                    not row.get("elapsed_exposure_ns", 0) > 0:
                problems.append(("desktop-host-setup", str(row_id)))
            if mode == "live":
                display = settings.get("display_identity") if isinstance(settings, dict) else None
                if (not isinstance(settings, dict) or settings.get("video_driver") != "cocoa"
                        or not _valid_host_display_identity(display)):
                    problems.append(("desktop-host-capability", str(row_id)))
            stats = row.get("stats")
            if not isinstance(stats, dict) or row.get("stats_schema") != 2 or stats.get("stats_version") != 2:
                problems.append(("desktop-host-stats-version", str(row_id)))
                continue
            expected_controls = ["drop", "exit", "mute", "pause", "reject-cartridge", "replace", "reset", "resume", "unmute"]
            if row.get("controls_exercised") != expected_controls or row.get("rejected_cartridge_reason") != \
                    "REJECT: missing genewhip-phase4-missing-cartridge.bin" or row.get("paused_fields", 0) <= 0:
                problems.append(("desktop-host-controls", str(row_id)))
            if "present_errors" not in stats or not isinstance(stats.get("present_errors"), int) or \
                    stats.get("present_calls", 0) != stats.get("present_successes", 0) + stats.get("present_errors", 0) or \
                    stats.get("present_errors") != 0 or stats.get("presentation_error") != 0:
                problems.append(("desktop-host-presentation", str(row_id)))
            if stats.get("audio_available") != 1 or stats.get("queue_source_unit") != "SDL input bytes and stereo source frames" or \
                    stats.get("queue_exposure_ns", 0) <= 0 or row.get("host_audio_queue_kind") != "SDL queued source bytes/frames" or \
                    "unavailable" not in row.get("device_queue_observation", ""):
                problems.append(("desktop-host-queue", str(row_id)))
            deterministic = row.get("deterministic")
            if not isinstance(deterministic, dict) or deterministic.get("deterministic_join") is not True or \
                    not isinstance(deterministic.get("fields"), int) or deterministic["fields"] <= 0 or \
                    not isinstance(deterministic.get("machine_digest"), str) or \
                    not HOST_HEX.fullmatch(str(deterministic.get("field_hashes_sha256", ""))) or \
                    not HOST_HEX.fullmatch(str(deterministic.get("field_identity_sha256", ""))) or \
                    deterministic.get("field_hashes_sha256") == deterministic.get("field_identity_sha256") or \
                    not HOST_HEX.fullmatch(str(deterministic.get("core_pcm_sha256", ""))) or \
                    not isinstance(deterministic.get("core_pcm_frames"), int) or deterministic["core_pcm_frames"] <= 0 or \
                    deterministic.get("machine_digest") != deterministic.get("headless_machine_digest") or \
                    deterministic.get("field_hashes_sha256") != deterministic.get("headless_field_hashes_sha256") or \
                    deterministic.get("field_identity_sha256") != deterministic.get("headless_field_identity_sha256") or \
                    deterministic.get("core_pcm_sha256") != deterministic.get("headless_core_pcm_sha256") or \
                    row.get("deterministic_identity_sha256") != digest(deterministic):
                problems.append(("desktop-host-deterministic-identity", str(row_id)))
            for field in ("input_log_sha256", "input_script_sha256", "control_sha256",
                          "build_configuration_sha256", "desktop_build_sha256", "headless_build_sha256"):
                if not HOST_HEX.fullmatch(str(row.get(field, ""))):
                    problems.append(("desktop-host-stale-identity", str(row_id) + " " + field))
                expected = expected_identity.get(field)
                if expected and row.get(field) != expected:
                    problems.append(("desktop-host-stale-identity", str(row_id) + " " + field))
            if row.get("control_sha256") != control_sha:
                problems.append(("desktop-host-control-identity", str(row_id)))
    return problems


def validate_delivery_evidence(evidence):
    """Require actual protected run identities, complete release assets and adoption."""
    if not isinstance(evidence, dict) or evidence.get("schema") != "genewhip.hosted-delivery.v1":
        return ["delivery-schema-invalid"]
    problems = []
    sha_pattern = re.compile(r"^[0-9a-f]{40}$")
    for key in ("pull_request_head_sha", "pull_request_base_sha", "merged_source_sha",
                "publisher_source_sha"):
        if not isinstance(evidence.get(key), str) or not sha_pattern.fullmatch(evidence[key]):
            problems.append("delivery-identity-invalid")
    if evidence.get("repository") != "szTheory/genewhip":
        problems.append("delivery-repository-mismatch")
    if not isinstance(evidence.get("pull_request"), int) or evidence["pull_request"] < 1:
        problems.append("delivery-pr-identity-invalid")
    for key in ("qualification_run_id", "publisher_run_id"):
        if not isinstance(evidence.get(key), str) or not evidence[key].isdigit():
            problems.append("delivery-run-identity-invalid")
    for key in ("qualification_run_attempt", "publisher_run_attempt"):
        if not isinstance(evidence.get(key), int) or evidence[key] < 1:
            problems.append("delivery-run-attempt-invalid")
    hosted = evidence.get("hosted_evidence")
    if not isinstance(hosted, dict) or hosted.get("outcome") != "success" \
            or hosted.get("qualifies_rel_03") is not True:
        problems.append("delivery-hosted-qualification-not-passed")
    if evidence.get("downloaded_package_adoption") != "pass":
        problems.append("delivery-adoption-not-passed")
    requirements = evidence.get("requirements")
    if not isinstance(requirements, dict) or any(
            requirements.get(key) != "pass" for key in ("REL-03", "REL-02", "DOC-01")):
        problems.append("delivery-requirements-not-passed")
    release = evidence.get("release")
    source = evidence.get("merged_source_sha")
    if not isinstance(release, dict) or release.get("source_sha") != source:
        problems.append("delivery-release-source-mismatch")
    else:
        inventory = release.get("inventory")
        assets = release.get("assets")
        if not isinstance(inventory, dict) or inventory.get("source_revision") != source \
                or not isinstance(inventory.get("assets"), dict) or len(inventory["assets"]) != 6:
            problems.append("delivery-inventory-invalid")
        if not isinstance(assets, list) or len(assets) != 8:
            problems.append("delivery-asset-roster-invalid")
        else:
            names = set()
            prefix = "https://github.com/szTheory/genewhip/releases/download/v0.1.0/"
            for row in assets:
                if not isinstance(row, dict) or not isinstance(row.get("name"), str) \
                        or row["name"] in names or not re.fullmatch(r"[A-Za-z0-9._-]+", row["name"]) \
                        or not isinstance(row.get("sha256"), str) or not HOST_HEX.fullmatch(row["sha256"]) \
                        or not isinstance(row.get("url"), str) or not row["url"].startswith(prefix):
                    problems.append("delivery-asset-identity-invalid")
                    break
                names.add(row["name"])
            if isinstance(inventory, dict) and isinstance(inventory.get("assets"), dict):
                expected_names = set(inventory["assets"]) | {"inventory.json", "SHA256SUMS"}
                if names != expected_names:
                    problems.append("delivery-asset-inventory-mismatch")
                indexed = {row.get("name"): row for row in assets if isinstance(row, dict)}
                for name, record in inventory["assets"].items():
                    if not isinstance(record, dict) or indexed.get(name, {}).get("sha256") != record.get("sha256"):
                        problems.append("delivery-inventory-asset-digest-mismatch")
                        break
        release_url = release.get("release_url")
        if release_url != "https://github.com/szTheory/genewhip/releases/tag/v0.1.0":
            problems.append("delivery-release-url-invalid")
    return sorted(set(problems))


def validate_safety_contracts(evidence, expected_revision=None):
    """Validate exact-source CTest and API-safety evidence for all required gate lanes."""
    problems = []
    if not isinstance(evidence, dict) or evidence.get("schema") != "genewhip-phase4-safety-contracts-v1" or evidence.get("version") != 1:
        return [("safety-schema", "invalid safety-contract schema/version")]
    revision = evidence.get("source_revision")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        problems.append(("safety-source-identity", "invalid source revision"))
    if expected_revision and revision != expected_revision:
        problems.append(("safety-stale-source", "safety lanes do not match report source"))
    run_id = evidence.get("run_id")
    tree_id = evidence.get("source_tree_id")
    final_record = evidence.get("final_record")
    if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id):
        problems.append(("safety-run-identity", "invalid safety run identifier"))
    if not isinstance(tree_id, str) or not re.fullmatch(r"[0-9a-f]{40}", tree_id):
        problems.append(("safety-source-tree", "invalid committed source tree identity"))
    if not isinstance(final_record, dict):
        problems.append(("safety-final-record-invalid", "final completion record must be an object"))
    elif (evidence.get("final_record_sha256") != digest(final_record) or
            final_record.get("schema") != SAFETY_FINAL_SCHEMA or
            final_record.get("version") != 1 or final_record.get("run_id") != run_id or
            final_record.get("source_revision") != revision or
            final_record.get("source_tree_id") != tree_id or
            not isinstance(final_record.get("lane_completion_sha256"), dict) or
            set(final_record["lane_completion_sha256"]) != set(SAFETY_LANES)):
        problems.append(("safety-run-incomplete", "missing or invalid final complete-run record"))
    lanes = evidence.get("lanes")
    if not isinstance(lanes, dict) or set(lanes) != set(SAFETY_LANES):
        return problems + [("safety-lane-roster", "native, sanitizer, and production lanes are required")]
    for name, (mode, instrumented) in SAFETY_LANES.items():
        lane = lanes.get(name)
        if not isinstance(lane, dict):
            problems.append(("safety-lane-schema", name)); continue
        if lane.get("source_revision") != revision:
            problems.append(("safety-stale-source", name))
        if lane.get("run_id") != run_id or lane.get("source_tree_id") != tree_id:
            problems.append(("safety-lane-run-mismatch", name))
        lane_record = {key: value for key, value in lane.items()
                       if key != "completion_record_sha256"}
        if (lane.get("completion_record_sha256") != digest(lane_record) or
                lane_record.get("schema") != SAFETY_COMPLETION_SCHEMA or
                lane_record.get("version") != 1 or lane_record.get("lane") != name or
                lane_record.get("run_id") != run_id or
                lane_record.get("source_revision") != revision or
                lane_record.get("source_tree_id") != tree_id or
                not isinstance(lane_record.get("configuration_sha256"), str) or
                not HOST_HEX.fullmatch(lane_record["configuration_sha256"]) or
                not isinstance(lane_record.get("summary_file_sha256"), str) or
                not HOST_HEX.fullmatch(lane_record["summary_file_sha256"])):
            problems.append(("safety-lane-completion-identity", name))
        try:
            safe_config = _validate_safety_configuration(lane_record.get("configuration"), name)
            if lane_record.get("configuration_sha256") != hashlib.sha256(
                    _json_bytes(safe_config)).hexdigest():
                problems.append(("safety-config-identity", name))
        except ValueError:
            problems.append(("safety-config-invalid", name))
        if (not isinstance(final_record, dict) or
                not isinstance(final_record.get("lane_completion_sha256"), dict) or
                final_record["lane_completion_sha256"].get(name) != lane.get("completion_record_sha256")):
            problems.append(("safety-final-lane-identity", name))
        ctest = lane.get("ctest")
        if not isinstance(ctest, dict):
            problems.append(("safety-ctest-schema", name)); continue
        total, passed = ctest.get("denominator"), ctest.get("pass")
        case_names = ctest.get("case_names")
        skipped = ctest.get("skipped")
        if (not isinstance(total, int) or isinstance(total, bool) or total <= 0 or
                not isinstance(passed, int) or isinstance(passed, bool) or
                not isinstance(skipped, list) or ctest.get("fail") != 0 or ctest.get("error") != 0 or
                passed + len(skipped) != total):
            problems.append(("safety-ctest-outcome", name))
        if (not isinstance(case_names, list) or
                any(not isinstance(item, str) or not item for item in case_names) or
                len(case_names) != total or len(set(case_names)) != len(case_names) or
                total < SAFETY_MIN_CASES[name] or
                not safety_required_tests(name) <= set(case_names)):
            problems.append(("safety-ctest-roster", name))
        elif ctest.get("test_inventory_sha256") != digest(sorted(case_names)):
            problems.append(("safety-ctest-inventory-identity", name))
        if isinstance(skipped, list):
            if any(not isinstance(item, str) or not item for item in skipped):
                problems.append(("safety-unexpected-skip", name))
            elif len(skipped) != len(set(skipped)):
                problems.append(("safety-duplicate-skip", name))
            elif not set(skipped) <= SAFETY_ALLOWED_SKIPS:
                problems.append(("safety-unexpected-skip", name))
        if not isinstance(ctest.get("junit_sha256"), str) or not HOST_HEX.fullmatch(ctest["junit_sha256"]):
            problems.append(("safety-ctest-identity", name))
        summary = lane.get("summary")
        if not isinstance(summary, dict):
            problems.append(("safety-summary-contract", name)); continue
        expected_summary = {"mode": mode, "seed": "47573105", "cases": 16, "safety_pass": 16,
                            "audio_pass": 256, "negative_controls": 12,
                            "steps_per_case": 8, "tick_budget": 180000,
                            "output_cap_frames": 128,
                            "allocation_instrumented": instrumented,
                            "allocation_count_peak": 2 if instrumented else 0,
                            "steady_allocations": 0}
        if not isinstance(summary, dict) or any(summary.get(key) != value
                                                 for key, value in expected_summary.items()):
            problems.append(("safety-summary-contract", name))
        if lane.get("summary_sha256") != digest(summary):
            problems.append(("safety-summary-identity", name))
    return problems


def collect_safety_contracts(build, expected_revision):
    """Read the three required-gate lanes; absent or malformed evidence stays unknown."""
    build = Path(build).resolve()
    evidence = {"schema": "genewhip-phase4-safety-contracts-v1", "version": 1,
                "source_revision": None, "lanes": {}}
    ci = build / "ci"
    safety_inputs = [ci / "safety-run.json", ci / "safety-complete.json"]
    for name in SAFETY_LANES:
        lane = ci / name
        safety_inputs.extend(lane / filename for filename in
                             ("safety-config.json", "ctest-junit.xml", "safety-contract.json",
                              "safety-completion.json"))
    if not any(path.is_file() or path.is_symlink() for path in safety_inputs):
        return evidence, [("safety-evidence-missing",
                           "required gate safety artifacts are absent from this build")]
    try:
        root = ROOT
        identity = public_source_identity(root)
        run = _safety_run(build)
        final = _read_safety_record(ci / "safety-complete.json",
                                    "safety-final-record-invalid")
        evidence.update(identity)
        evidence["run_id"] = run.get("run_id")
        evidence["final_record"] = final
        evidence["final_record_sha256"] = digest(final)
        if run.get("schema") != SAFETY_RUN_SCHEMA or run.get("version") != 1:
            raise ValueError("safety-run-invalid")
        if {key: run.get(key) for key in identity} != identity:
            raise ValueError("safety-run-source-mismatch")
        if identity["source_revision"] != expected_revision:
            raise ValueError("safety-stale-source")
        for name, (mode, _) in SAFETY_LANES.items():
            record = _validate_lane_completion(ci, name, run)
            evidence["lanes"][name] = {**record,
                "completion_record_sha256": digest(record)}
    except (OSError, ET.ParseError, ValueError, json.JSONDecodeError, KeyError) as error:
        reason = str(error) if str(error).startswith("safety-") else "safety-evidence-incomplete"
        return evidence, [(reason, str(error))]
    problems = validate_safety_contracts(evidence, expected_revision=expected_revision)
    return evidence, problems


def expected_for(build=None, head=None):
    expected = {"source_revision": head or git_head(),
                "fixture_manifest_sha256": sha(ROOT / "fixtures/manifest.json")}
    if build is not None:
        expected["configuration_sha256"] = digest(configuration(build))
        expected["tracer_identity"] = expected_tracer_identity(build)
        build = Path(build).resolve()
        expected["gameplay_identity"] = {
            "build_configuration_sha256": sha(build / "CMakeCache.txt"),
            "client_sha256": [sha(build / "tools/session/gw_headless")] +
                ([sha(build / "tools/desktop/genewhip-desktop")]
                 if (build / "tools/desktop/genewhip-desktop").is_file() else []),
        }
        expected["host_identity"] = {
            "build_configuration_sha256": sha(build / "CMakeCache.txt"),
            "desktop_build_sha256": sha(build / "tools/desktop/genewhip-desktop"),
            "headless_build_sha256": sha(build / "tools/session/gw_headless"),
        }
        benchmark = build / "gw_core_benchmark"
        if benchmark.is_file() and (build / "phase4-performance.json").is_file():
            path = ROOT / "tools/evidence/core_benchmark.py"
            spec = importlib.util.spec_from_file_location("gw_core_benchmark_identity", path)
            benchmark_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(benchmark_module)
            expected["performance_identity"] = {
                "build_configuration_sha256": sha(build / "CMakeCache.txt"),
                "benchmark_binary_sha256": sha(benchmark),
                "source_identity_sha256": benchmark_module.source_identity(),
            }
    return expected


def build_report(build):
    build = Path(build).resolve()
    tracer_path = build / "evidence/phase4-tracer.json"
    if tracer_path.is_file():
        tracer = json.loads(tracer_path.read_text())
        outcome, observed = tracer.get("outcome", "infrastructure-error"), tracer
    else:
        outcome, observed = "unknown", {"reason": "phase4_tracer has not produced evidence in this build"}
    gameplay_path = build / "evidence/phase4-gameplay.json"
    gameplay = json.loads(gameplay_path.read_text()) if gameplay_path.is_file() else None
    host_software_path = build / "evidence/phase4-host-sessions.json"
    host_live_path = build / "evidence/phase4-host-live.json"
    host_evidence = None
    host_outcome = "unknown"
    if host_software_path.is_file() and host_live_path.is_file():
        host_evidence = {"software": json.loads(host_software_path.read_text()),
                         "live": json.loads(host_live_path.read_text())}
        host_problems = validate_host_sessions(host_evidence, expected_revision=git_head(),
                                               expected_identity=expected_for(build).get("host_identity"))
        live_outcome = host_evidence["live"].get("outcome")
        host_outcome = "infrastructure-error" if host_problems else ("pass" if live_outcome == "pass" else "skipped")
        if host_problems:
            host_evidence["validation_errors"] = [{"reason": reason, "detail": detail}
                                                  for reason, detail in host_problems]
    else:
        host_evidence = {"reason": "phase4 host software and live lanes have not both produced evidence"}
    rows = []
    safety_evidence, safety_problems = collect_safety_contracts(build, expected_revision=git_head())
    for row_id, required in ROSTER:
        if row_id == "diagnostic_public_clients":
            rows.append({"id": row_id, "required": required, "outcome": outcome, "observed": observed})
        elif row_id == "independent_gameplay":
            rows.append({"id": row_id, "required": required,
                         "outcome": gameplay.get("outcome", "infrastructure-error") if gameplay else "unknown",
                         "observed": gameplay if gameplay else {"reason": "phase4 gameplay clients have not produced evidence in this build"}})
        elif row_id == "safety_contracts":
            rows.append({"id": row_id, "required": required,
                         "outcome": "pass" if not safety_problems else "unknown",
                         "observed": safety_evidence,
                         **({"validation_errors": [{"reason": reason, "detail": detail}
                             for reason, detail in safety_problems]} if safety_problems else {})})
        elif row_id == "core_performance":
            performance_path = build / "phase4-performance.json"
            performance = json.loads(performance_path.read_text()) if performance_path.is_file() else None
            rows.append({"id": row_id, "required": required,
                         "outcome": performance.get("outcome", "infrastructure-error") if performance else "unknown",
                         "observed": performance if performance else {"reason": "qualified core benchmark has not produced evidence in this build"}})
        elif row_id == "desktop_pacing":
            rows.append({"id": row_id, "required": required, "outcome": host_outcome,
                         "observed": host_evidence})
        elif row_id in ("exact_packages", "hosted_delivery"):
            delivery_path = ROOT / "build/phase4/delivery-evidence.json"
            try:
                delivery = json.loads(delivery_path.read_text())
            except (OSError, json.JSONDecodeError):
                delivery = None
            problems = validate_delivery_evidence(delivery)
            if row_id == "exact_packages":
                passed = not problems and delivery.get("downloaded_package_adoption") == "pass"
            else:
                passed = not problems
            rows.append({"id": row_id, "required": required,
                         "outcome": "pass" if passed else "unknown",
                         "observed": delivery if delivery else {
                             "reason": "no verified hosted-delivery record is available"},
                         **({"validation_errors": problems} if problems else {})})
        else:
            rows.append({"id": row_id, "required": required, "outcome": "unknown",
                         "observed": {"reason": "capability is owned by a later Phase 4 plan"}})
    config = configuration(build)
    report = {"schema": SCHEMA, "version": VERSION, "source_revision": git_head(),
              "source_state": source_state(), "configuration": config,
              "configuration_sha256": digest(config),
              "fixture_manifest_sha256": sha(ROOT / "fixtures/manifest.json"),
              "tracer": {"path": "tests/fixtures/phase4_tracer.py",
                         "sha256": sha(ROOT / "tests/fixtures/phase4_tracer.py")},
              "rows": rows, "denominator": len(rows), "counts": count(rows)}
    return report


def validate(report, head=None, qualification=False, expected=None):
    expected = expected or expected_for(head=head)
    problems = []
    if not isinstance(report, dict) or report.get("schema") != SCHEMA or report.get("version") != VERSION:
        return [("schema", "invalid schema/version")]
    if report.get("source_revision") != expected.get("source_revision"):
        problems.append(("stale-revision", "source revision does not match expected revision"))
    if report.get("fixture_manifest_sha256") != expected.get("fixture_manifest_sha256"):
        problems.append(("stale-fixture-manifest", "fixture manifest digest differs"))
    config = report.get("configuration")
    if not isinstance(config, dict) or report.get("configuration_sha256") != digest(config):
        problems.append(("configuration-digest", "configuration digest does not match configuration"))
    elif expected.get("configuration_sha256") and report.get("configuration_sha256") != expected["configuration_sha256"]:
        problems.append(("stale-configuration", "build configuration differs from expected configuration"))

    rows = report.get("rows")
    if not isinstance(rows, list):
        return problems + [("schema", "rows must be a list")]
    required = dict(ROSTER)
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            problems.append(("schema", "row must be an object"))
            continue
        row_id = row.get("id")
        if row_id not in required:
            problems.append(("unexpected-row", str(row_id)))
            continue
        if row_id in seen:
            problems.append(("duplicate-row", row_id))
            continue
        seen.add(row_id)
        if row.get("required") is not required[row_id]:
            problems.append(("requiredness", row_id))
        outcome = row.get("outcome")
        if outcome not in OUTCOMES:
            problems.append(("invalid-outcome", row_id))
        if not isinstance(row.get("observed"), dict):
            problems.append(("observed", row_id))
        if qualification and required[row_id] and outcome != "pass":
            problems.append(("required-non-pass", row_id))
        identity = expected.get("tracer_identity")
        observed = row.get("observed")
        if row_id == "diagnostic_public_clients" and outcome == "pass" and identity:
            if not isinstance(observed, dict) or observed.get("schema") != TRACER_SCHEMA or observed.get("version") != 1:
                problems.append(("tracer-schema", row_id))
            else:
                reasons = {
                    "source_sha256": "stale-source", "scenario_sha256": "stale-scenario",
                    "rom_sha256": "stale-rom", "input_sha256": "stale-input",
                    "build_configuration_sha256": "stale-configuration",
                    "headless_build_sha256": "stale-build", "desktop_build_sha256": "stale-build",
                    "profile": "stale-profile", "fixture": "stale-fixture",
                }
                for field, reason in reasons.items():
                    if observed.get(field) != identity.get(field):
                        problems.append((reason, field))
        if row_id == "independent_gameplay" and outcome == "pass":
            problems.extend(validate_gameplay(observed, qualification=qualification,
                                               expected_identity=expected.get("gameplay_identity")))
        if row_id == "safety_contracts" and outcome == "pass":
            problems.extend(validate_safety_contracts(observed,
                                                       expected_revision=expected.get("source_revision")))
        if row_id == "core_performance" and outcome == "pass":
            benchmark_path = ROOT / "tools/evidence/core_benchmark.py"
            bench_spec = importlib.util.spec_from_file_location("gw_core_benchmark_validator", benchmark_path)
            benchmark = importlib.util.module_from_spec(bench_spec)
            bench_spec.loader.exec_module(benchmark)
            problems.extend(("performance-" + reason, reason)
                            for reason in benchmark.validate_report(observed, qualification=True,
                                expected={"build_configuration_sha256":
                                    (expected.get("performance_identity") or {}).get("build_configuration_sha256"),
                                    "benchmark_binary_sha256": (expected.get("performance_identity") or {}).get("benchmark_binary_sha256"),
                                    "source_identity_sha256": (expected.get("performance_identity") or {}).get("source_identity_sha256")}))
            identity = expected.get("performance_identity") or {}
            actual_build = observed.get("build_identity", {})
            if actual_build.get("build_configuration_sha256") != identity.get("build_configuration_sha256"):
                problems.append(("performance-stale-build", "benchmark CMake configuration differs"))
            if observed.get("benchmark_binary_sha256") != identity.get("benchmark_binary_sha256"):
                problems.append(("performance-stale-build", "benchmark executable differs"))
            if observed.get("source_identity_sha256") != identity.get("source_identity_sha256"):
                problems.append(("performance-stale-source", "benchmark source files differ"))
        if row_id == "desktop_pacing" and isinstance(observed, dict) and set(observed) >= {"software", "live"}:
            problems.extend(validate_host_sessions(observed, expected_revision=expected.get("source_revision"),
                                                   expected_identity=expected.get("host_identity")))
        if row_id in ("exact_packages", "hosted_delivery") and outcome == "pass":
            problems.extend(("delivery-" + reason, reason)
                            for reason in validate_delivery_evidence(observed))
    for row_id in required.keys() - seen:
        problems.append(("missing-row", row_id))
    if report.get("denominator") != len(rows):
        problems.append(("denominator", "row denominator differs from row list"))
    if report.get("counts") != count(rows):
        problems.append(("counts", "outcome counts differ from rows"))
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    build_cmd = sub.add_parser("build")
    build_cmd.add_argument("--build", type=Path, required=True)
    build_cmd.add_argument("--out", type=Path, required=True)
    check = sub.add_parser("validate")
    check.add_argument("--report", type=Path, required=True)
    check.add_argument("--build", type=Path, required=True)
    check.add_argument("--head", default=None)
    check.add_argument("--qualification", action="store_true")
    start = sub.add_parser("safety-start")
    start.add_argument("--build", type=Path, required=True)
    complete_lane = sub.add_parser("safety-lane-complete")
    complete_lane.add_argument("--build", type=Path, required=True)
    complete_lane.add_argument("--lane", choices=tuple(SAFETY_LANES), required=True)
    finish = sub.add_parser("safety-finish")
    finish.add_argument("--build", type=Path, required=True)
    sanitize = sub.add_parser("safety-sanitize-junit")
    sanitize.add_argument("--input", type=Path, required=True)
    sanitize.add_argument("--output", type=Path, required=True)
    failure_summary = sub.add_parser("safety-ctest-failure-summary")
    failure_summary.add_argument("--input", type=Path, required=True)
    export = sub.add_parser("safety-export")
    export.add_argument("--build", type=Path, required=True)
    export.add_argument("--out", type=Path, required=True)
    export.add_argument("--failure-only", action="store_true")
    host = sub.add_parser("host-export")
    host.add_argument("--build", type=Path, required=True)
    host.add_argument("--out", type=Path, required=True)
    host.add_argument("--run-id", required=True)
    host.add_argument("--run-attempt", type=int, required=True)
    host.add_argument("--source-sha", required=True)
    args = parser.parse_args(argv)
    if args.command == "safety-start":
        safety_start(args.build)
        return 0
    if args.command == "safety-lane-complete":
        safety_complete_lane(args.build, args.lane)
        return 0
    if args.command == "safety-finish":
        safety_finish(args.build)
        return 0
    if args.command == "safety-sanitize-junit":
        try:
            sanitize_ctest_junit(args.input, args.output)
        except (OSError, ValueError) as exc:
            reason = str(exc) if isinstance(exc, ValueError) else "safety-ctest-junit-io"
            print("REJECT: " + reason, file=sys.stderr)
            return 1
        return 0
    if args.command == "safety-ctest-failure-summary":
        try:
            for line in summarize_sanitized_ctest_failures(args.input):
                print(line)
        except (OSError, ValueError) as exc:
            reason = str(exc) if isinstance(exc, ValueError) else "safety-ctest-junit-io"
            print("REJECT: " + reason, file=sys.stderr)
            return 1
        return 0
    if args.command == "safety-export":
        try:
            if args.failure_only:
                safety_failure_export(args.build, args.out)
            else:
                safety_export(args.build, args.out)
        except (OSError, ValueError) as exc:
            reason = str(exc) if isinstance(exc, ValueError) else "safety-export-io"
            print("REJECT: " + reason, file=sys.stderr)
            return 1
        return 0
    if args.command == "host-export":
        try:
            host_export(args.build, args.out, args.run_id, args.run_attempt, args.source_sha)
        except (OSError, ValueError) as exc:
            reason = str(exc) if isinstance(exc, ValueError) else "host-export-io"
            print("REJECT: " + reason, file=sys.stderr)
            return 1
        print(json.dumps({"outcome": "pass", "run_id": args.run_id,
                          "run_attempt": args.run_attempt, "source_sha": args.source_sha,
                          "staged_reports": 2}, sort_keys=True))
        return 0
    if args.command == "build":
        report = build_report(args.build)
        problems = validate(report, expected=expected_for(args.build))
        if problems:
            print("invalid built report: %r" % problems, file=sys.stderr)
            return 1
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        print("phase4 report: %d rows; %s" % (report["denominator"], report["counts"]))
        return 0
    report = json.loads(args.report.read_text())
    problems = validate(report, args.head, args.qualification, expected_for(args.build, args.head))
    if problems:
        for reason, detail in problems:
            print("REJECT: %s %s" % (reason, detail), file=sys.stderr)
        return 1
    print("phase4 report valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

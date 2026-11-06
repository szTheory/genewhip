#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Two serial, source-bound ordinary-completion host checks for Phase 7 return."""
from __future__ import annotations

import argparse
import datetime
import fcntl
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
CAP = 65536
CHUNK = 8192
STATUS_TIMEOUT = 0.25
MAX_DIAGNOSTIC_SECONDS = 120
MAX_OBSERVER_QUERIES_PER_CASE = 8
MAX_OBSERVER_RSS_PER_CASE = 4
MAX_OWNER_RSS_PER_CASE = 508
MAX_RSS_SAMPLES_PER_CASE = 512
MAX_STARTS_PER_CASE = 42
MAX_STARTS_TOTAL = 84
MAX_STATUS_STARTS_PER_CASE = 40
LIMITS = {
    "case_roster": ["shared_launch", "bounded_command"],
    "controller_start_events_per_case": 25,
    "owner_start_events_per_case": 17,
    "total_start_events_per_case": MAX_STARTS_PER_CASE,
    "total_start_events": MAX_STARTS_TOTAL,
    "observer_queries_per_case": MAX_OBSERVER_QUERIES_PER_CASE,
    "observer_queries_total": 16,
    "observer_rss_samples_per_case": MAX_OBSERVER_RSS_PER_CASE,
    "owner_rss_samples_per_case": MAX_OWNER_RSS_PER_CASE,
    "rss_samples_per_case": MAX_RSS_SAMPLES_PER_CASE,
    "rss_samples_total": 1024,
    "native_rss_pids_per_observation": 4096,
    "native_rss_pid_queries_per_case": 2_097_152,
    "native_rss_pid_queries_total": 4_194_304,
    "status_child_starts_per_case": MAX_STATUS_STARTS_PER_CASE,
    "observer_argv": ["/bin/ps", "-axo", "pid=,pgid=,lstart=,stat="],
    "observer_environment": {"LC_ALL": "C"},
    "status_query_output_bytes": CAP,
    "status_query_output_total_bytes_per_case": 40 * CAP,
    "diagnostic_elapsed_seconds": MAX_DIAGNOSTIC_SECONDS,
    "controller_timeout_seconds": 45,
    "owner_timeout_seconds": 20,
    "leaf_timeout_seconds": 4,
    "observer_communication_timeout_seconds": STATUS_TIMEOUT,
    "case_retained_bytes": 4 * 1024 * 1024,
    "aggregate_retained_bytes": 8 * 1024 * 1024,
    "maximum_tree_entries": 64,
    "reserved_wrapper_entries_per_case": 16,
    "reserved_wrapper_bytes_per_case": 1024 * 1024,
    "stdout_stderr_cap_bytes": CAP,
    "scratch_bytes_per_case": 1024 * 1024,
    "rss_limit_bytes_per_process": 268435456,
}
PRIOR_CUMULATIVE_LIMITS = {
    "campaign_host_invocations": 3,
    "campaign_wrapper_calls": 3,
    "campaign_start_events": 126,
    "campaign_status_helper_starts": 120,
    "campaign_observer_queries": 24,
    "campaign_rss_samples": 1536,
    "campaign_native_rss_pid_queries": 6_291_456,
    "campaign_retained_bytes": 12 * 1024 * 1024,
    "campaign_status_output_bytes": 7_864_320,
    "campaign_elapsed_seconds": 240,
    "prior_host_invocations_used": 2,
    "future_host_invocations_reserved": 1,
    "prior_wrapper_calls_used": 1,
    "future_wrapper_calls_reserved": 2,
    "prior_controller_starts_measured": 6,
    "prior_owner_starts_unknown_reserved": 17,
    "prior_starts_reserved": 23,
    "future_starts_reserved": 84,
    "prior_status_helpers_measured": 5,
    "prior_owner_status_helpers_unknown_reserved": 17,
    "prior_status_helpers_reserved": 22,
    "future_status_helpers_reserved": 80,
    "prior_observer_queries_measured": 4,
    "future_observer_queries_reserved": 16,
    "prior_rss_samples_measured": 4,
    "prior_owner_rss_samples_unknown_reserved": 508,
    "prior_rss_samples_reserved": 512,
    "future_rss_samples_reserved": 1024,
    "prior_native_rss_queries_reserved": 2_097_152,
    "future_native_rss_queries_reserved": 4_194_304,
    "prior_retained_bytes_measured": 9665,
    "future_retained_bytes_reserved": 8 * 1024 * 1024,
    "prior_status_output_bytes_reserved": 2_621_440,
    "future_status_output_bytes_reserved": 5_242_880,
    "prior_elapsed_seconds_reserved": 120,
    "future_elapsed_seconds_reserved": 120,
}
CUMULATIVE_LIMITS = {
    **PRIOR_CUMULATIVE_LIMITS,
    "campaign_host_invocations": 4,
    "campaign_wrapper_calls": 4,
    "campaign_start_events": 130,
    "campaign_status_helper_starts": 124,
    "campaign_observer_queries": 24,
    "campaign_rss_samples": 2048,
    "campaign_native_rss_pid_queries": 8_388_608,
    "campaign_retained_bytes": 8_408_394,
    "campaign_control_bytes": 66_833,
    "campaign_status_output_bytes": 10_485_760,
    "campaign_elapsed_seconds": 360,
    "prior_control_bytes_measured": 1297,
    "future_control_bytes_reserved": 65_536,
    "prior_control_entries_measured": 2,
    "future_control_entries_reserved": 1,
    "campaign_control_entries": 3,
    "prior_host_invocations_used": 3,
    "future_host_invocations_reserved": 1,
    "prior_wrapper_calls_used": 2,
    "prior_starts_reserved": 46,
    "prior_status_helpers_reserved": 44,
    "prior_observer_queries_measured": 8,
    "prior_rss_samples_reserved": 1024,
    "prior_native_rss_queries_reserved": 4_194_304,
    "prior_retained_bytes_measured": 19_786,
    "prior_status_output_bytes_reserved": 5_242_880,
    "prior_elapsed_seconds_reserved": 240,
    "prior_controller_starts_measured": 12,
    "prior_owner_starts_unknown_reserved": 34,
    "prior_status_helpers_measured": 10,
    "prior_owner_status_helpers_unknown_reserved": 34,
    "prior_observer_queries_measured": 8,
    "prior_rss_samples_measured": 8,
    "prior_owner_rss_samples_unknown_reserved": 1016,
}
ATTEMPT4_CUMULATIVE_LIMITS = {
    **CUMULATIVE_LIMITS,
    "campaign_host_invocations": 5,
    "prior_host_invocations_used": 4,
    "campaign_elapsed_seconds": 480,
    "prior_elapsed_seconds_reserved": 360,
    "campaign_control_bytes": 69_222,
    "prior_control_bytes_measured": 3_686,
    "campaign_control_entries": 4,
    "prior_control_entries_measured": 3,
}
SCHEMA = "genewhip.phase7-wrapper-return.v1"
CAMPAIGN_SCHEMA = "genewhip.v02-recovery-campaign.v1"
SCOPE_ID = "phase7-serial-child-workloads"
SCOPE = {
    "schema": "genewhip-v02-execution-v1", "scope_id": SCOPE_ID,
    "qualification_batch": {"wall_seconds": 86400, "runtime_wall_seconds": 64800,
        "package_wall_seconds": 14400, "close_wall_seconds": 7200},
    "per_child_limits": {"wall_seconds": 20, "cleanup_grace_seconds": .25,
        "max_rss_bytes": 268435456, "max_stdout_stderr_bytes": CAP,
        "max_json_bytes": CAP, "max_binary_file_bytes": CAP,
        "max_capture_bytes": CAP, "max_scratch_bytes": 1048576,
        "max_retained_bytes": CAP, "max_fields": 1, "max_calls": 1},
}
PHASE_DIR = ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery"
PACKET15 = PHASE_DIR + "/07-15-ADMISSION.json"
PACKET16 = PHASE_DIR + "/07-16-ADMISSION.json"
SOURCES16 = (
    "evidence/v02-execution.json",
    "scripts/release/v02_qualification.py",
    "tests/evidence/phase7_wrapper_return.py",
    "tests/evidence/phase7_wrapper_return_contract.py",
    "tests/evidence/phase7_return_archive_contract.py",
    "tests/evidence/phase7_wrapper16_contract.py",
    "tests/evidence/phase7_sticky_denial.py",
    "tests/fixtures/phase6_game.py",
    "scripts/evidence/phase6_routes.py",
    "fixtures/phase6/media-expectations-v1.json",
    "tests/session/phase6_route_contract.py",
    "scripts/evidence/phase5_process.py",
    "tests/evidence/phase7_cleanup_transition_contract.py",
    "tests/evidence/phase7_cleanup_budget_contract.py",
    "tests/evidence/phase7_creation_receipts_contract.py",
    "tests/evidence/phase7_darwin_status_contract.py",
    "tests/evidence/phase7_rss_contract.py",
)
RUN_COUNTS = None
RUN_COUNT_LOCK = threading.Lock()


def install_start_counter(max_starts: int, max_status_starts: int):
    global RUN_COUNTS
    counters = {"starts": 0, "status_helper_starts": 0, "observer_queries": 0,
                "rss_samples": 0}
    original = subprocess.Popen
    def counted(command, *args, **kwargs):
        argv0 = str(command[0]) if isinstance(command, (list, tuple)) and command else ""
        with RUN_COUNT_LOCK:
            if counters["starts"] >= max_starts:
                raise ValueError("return-process-start-ceiling")
            if argv0 == "/bin/ps":
                if counters["status_helper_starts"] >= max_status_starts:
                    raise ValueError("return-status-helper-start-ceiling")
                counters["status_helper_starts"] += 1
            counters["starts"] += 1
        return original(command, *args, **kwargs)
    subprocess.Popen = counted
    RUN_COUNTS = counters
    return original, counters
SOURCES = (
    "tests/evidence/phase7_wrapper_return.py",
    "tests/evidence/phase7_wrapper_return_contract.py",
    "tests/evidence/phase7_sticky_denial.py",
    "tests/fixtures/phase6_game.py",
    "tests/session/phase6_route_contract.py",
    "scripts/evidence/phase5_process.py",
    "scripts/release/v02_qualification.py",
    "evidence/v02-execution.json",
    "tests/evidence/phase7_cleanup_transition_contract.py",
    "tests/evidence/phase7_cleanup_budget_contract.py",
    "tests/evidence/phase7_creation_receipts_contract.py",
    "tests/evidence/phase7_darwin_status_contract.py",
    "tests/evidence/phase7_rss_contract.py",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-SECURITY.md",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-RENEWED-WINDOW.md",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-PLAN.md",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-DENIED.md",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-RED.json",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-PRESTART-REVIEW.md",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-PRESTART-SECURITY.md",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-PRESTART-REJECTION.md",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-ATTEMPT1-FAILURE.json",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-ATTEMPT1-REVIEW.md",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-ATTEMPT1-SECURITY.md",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-ATTEMPT2-ADMISSION.json",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-ATTEMPT2-FAILURE.json",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-DENIED-FOLLOWUP.md",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-REASSESSMENT.md",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-PLAN-CHECK.md",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-ATTEMPT2-REVIEW.md",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-ATTEMPT2-SECURITY.md",
)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _accepted_review(text: str, *, packet_sha256: str, protocol_sha256: str,
                     reviewer_role: str, reviewer_model: str) -> bool:
    """Parse the unique YAML frontmatter fields used by independent review gates."""
    if not text.startswith("---\n"):
        return False
    end = text.find("\n---\n", 4)
    if end < 0:
        return False
    fields = {}
    for line in text[4:end].splitlines():
        if not line or line.startswith("#"):
            continue
        if line[0].isspace() or ":" not in line:
            return False
        key, value = line.split(":", 1)
        if (key != key.strip() or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _/-]*", key)):
            return False
        value = value.strip()
        if key in fields:
            return False
        fields[key] = value
    return (fields.get("status") == "accepted"
        and fields.get("reviewer_role") == reviewer_role
        and fields.get("reviewer_model") == reviewer_model
        and fields.get("author_role") == "gsd-executor"
        and fields.get("source-review") == "current-source-and-packet"
        and fields.get("unresolved high/critical") == "0"
        and fields.get("critical") == "0"
        and fields.get("high") == "0"
        and fields.get("packet_sha256") == packet_sha256
        and fields.get("protocol_sha256") == protocol_sha256)


def _accepted_security_report(text: str, required: dict[str, str]) -> bool:
    """Read only the exact machine-metadata preamble, never Markdown body/fences."""
    lines = text.splitlines()
    expected = [f"{key}: {value}" for key, value in required.items()]
    return (len(lines) >= len(expected) + 1
        and lines[:len(expected)] == expected
        and lines[len(expected)] == "---")


def validate_interpreter_pin(interpreter: dict):
    expected = {"executable": sys.executable,
        "sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
        "version": sys.version, "platform": {"system": platform.system(),
            "release": platform.release(), "machine": platform.machine()}}
    if interpreter != expected:
        raise ValueError("return-admission-interpreter-stale")


def require_clean_host_environment():
    conflicting = ("GENEWHIP_QUALIFICATION_STARTED_AT", "GENEWHIP_QUALIFICATION_PHASE",
        "GENEWHIP_QUALIFICATION_NONCE", "GENEWHIP_RECOVERY_CAMPAIGN_SHA256")
    if any(os.environ.get(name) is not None for name in conflicting):
        raise ValueError("return-host-environment-clock-not-clean")


def safe_json(path: Path, *, maximum: int = CAP):
    if path.is_symlink() or not path.is_file():
        raise ValueError("return-owned-file-missing-or-symlink")
    info = path.lstat()
    if info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size > maximum:
        raise ValueError("return-owned-file-invalid")
    return json.loads(path.read_bytes())


def ensure_owned_tree_path(path: Path, *, may_create_leaf=False):
    path = Path(os.path.abspath(path))
    try:
        relative = path.relative_to(ROOT)
    except ValueError:
        raise ValueError("return-path-outside-project") from None
    current = ROOT
    if current.is_symlink():
        raise ValueError("return-project-root-symlink")
    for index, part in enumerate(relative.parts):
        current = current / part
        if current.is_symlink():
            raise ValueError("return-path-symlink")
        if current.exists():
            info = current.lstat()
            if info.st_uid != os.getuid():
                raise ValueError("return-path-not-owned")
            if index < len(relative.parts) - 1 and not current.is_dir():
                raise ValueError("return-parent-not-directory")
        elif not (may_create_leaf and index == len(relative.parts) - 1):
            # Missing intermediate directories are allowed only where the caller
            # creates them one component at a time after validating this prefix.
            if index < len(relative.parts) - 1:
                continue
    return path


def check_owned_tree(root: Path, *, byte_cap=4 * 1024 * 1024, entry_cap=None):
    ensure_owned_tree_path(root)
    if entry_cap is None:
        entry_cap = LIMITS["maximum_tree_entries"]
    count = total = 0
    pending = [Path(root)]
    while pending:
        current = pending.pop()
        with os.scandir(current) as entries:
            for entry in entries:
                item = Path(entry.path)
                info = entry.stat(follow_symlinks=False)
                count += 1
                if entry.is_symlink() or info.st_uid != os.getuid():
                    raise ValueError("return-owned-tree-entry-invalid")
                if stat.S_ISREG(info.st_mode):
                    if info.st_nlink != 1 or info.st_size > CAP:
                        raise ValueError("return-owned-tree-file-invalid")
                    total += info.st_size
                elif stat.S_ISDIR(info.st_mode):
                    pending.append(item)
                else:
                    raise ValueError("return-owned-tree-type-invalid")
                if count > entry_cap or total > byte_cap:
                    raise ValueError("return-owned-tree-ceiling")
    return {"entries": count, "bytes": total}


def create_limits_lock(root: Path):
    path = root / ".limits.lock"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def create_case_root(index: int) -> Path:
    recovery = ROOT / "build/v02/recovery15"
    root = case_root(index)
    lock_path = recovery / ".limits.lock"
    lock_fd = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if root.exists() or root.is_symlink():
            raise ValueError("return-case-root-not-new")
        total = check_owned_tree(recovery, byte_cap=LIMITS["aggregate_retained_bytes"],
            entry_cap=LIMITS["maximum_tree_entries"] * 2 + 3)
        if total["entries"] + 2 > LIMITS["maximum_tree_entries"] * 2 + 3:
            raise ValueError("return-case-root-prospective-entry-ceiling")
        root.mkdir(mode=0o700)
        (root / "controller").mkdir(mode=0o700)
        check_owned_tree(root, byte_cap=LIMITS["case_retained_bytes"])
        check_owned_tree(recovery, byte_cap=LIMITS["aggregate_retained_bytes"],
            entry_cap=LIMITS["maximum_tree_entries"] * 2 + 3)
        reserve_case_capacity_locked(root)
        return root
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def reserve_case_capacity_locked(root: Path):
    case = check_owned_tree(root, byte_cap=LIMITS["case_retained_bytes"])
    total = check_owned_tree(ROOT / "build/v02/recovery15",
        byte_cap=LIMITS["aggregate_retained_bytes"],
        entry_cap=LIMITS["maximum_tree_entries"] * 2 + 3)
    if (case["entries"] + LIMITS["reserved_wrapper_entries_per_case"] > LIMITS["maximum_tree_entries"]
            or case["bytes"] + LIMITS["reserved_wrapper_bytes_per_case"] > LIMITS["case_retained_bytes"]
            or total["bytes"] + LIMITS["reserved_wrapper_bytes_per_case"] > LIMITS["aggregate_retained_bytes"]):
        raise ValueError("return-case-wrapper-capacity-reserve-unavailable")


def reserve_case_capacity(root: Path):
    lock_path = ROOT / "build/v02/recovery15/.limits.lock"
    lock_fd = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        reserve_case_capacity_locked(root)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def packet_and_review(packet_path: Path):
    supplied = packet_path if packet_path.is_absolute() else ROOT / packet_path
    expected15, expected16 = ROOT / PACKET15, ROOT / PACKET16
    if supplied not in (expected15, expected16):
        raise ValueError("return-admission-packet-path-invalid")
    attempt_number = 4 if supplied == expected16 else 3
    expected = supplied
    packet = safe_json(expected)
    if packet.get("schema") != "genewhip.phase7-wrapper-return-admission.v1" or packet.get("status") != "candidate":
        raise ValueError("return-admission-packet-invalid")
    packet_digest = sha(expected)
    packet["packet_sha256"] = packet_digest
    validate_cumulative_limits(packet.get("cumulative_limits"), attempt_number=attempt_number)
    protocol = ROOT / (PHASE_DIR + ("/07-16-PROTOCOL.md" if attempt_number == 4 else "/07-15-PROTOCOL.md"))
    expected_sources = {relative: sha(ROOT / relative) for relative in
        (SOURCES16 if attempt_number == 4 else SOURCES)}
    expected_limits = ATTEMPT4_CUMULATIVE_LIMITS if attempt_number == 4 else CUMULATIVE_LIMITS
    if (packet.get("scope") != SCOPE or packet.get("limits") != LIMITS
            or packet.get("cumulative_limits") != expected_limits
            or packet.get("case_roster") != LIMITS["case_roster"]
            or packet.get("sources") != expected_sources):
        raise ValueError("return-admission-source-or-scope-stale")
    if (protocol.is_symlink() or not protocol.is_file()
            or packet.get("protocol_sha256") != sha(protocol)):
        raise ValueError("return-protocol-pin-stale")
    validate_interpreter_pin(packet.get("interpreter"))
    review_path = ROOT / (PHASE_DIR + ("/07-16-REVIEW.md" if attempt_number == 4 else "/07-15-REVIEW.md"))
    security_path = ROOT / (PHASE_DIR + "/07-16-SECURITY.md")
    review = (review_path.read_text(encoding="utf-8") if review_path.is_file()
              and not review_path.is_symlink() and review_path.stat().st_size <= CAP else "")
    if not _accepted_review(review, packet_sha256=packet_digest,
            protocol_sha256=packet["protocol_sha256"],
            reviewer_role="gsd-code-reviewer", reviewer_model="gpt-6-luna"):
        raise ValueError("return-independent-review-stale-or-rejected")
    if attempt_number == 4:
        security = (security_path.read_text(encoding="utf-8") if security_path.is_file()
                    and not security_path.is_symlink() and security_path.stat().st_size <= CAP else "")
        source_pins_sha = hashlib.sha256(json.dumps(packet["sources"], sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        required = {
            "prospective diagnostic source eligibility": "accepted",
            "reviewer_role": "gsd-security-auditor",
            "reviewer_model": "gpt-6.1-sol",
            "unresolved current high/critical": "0",
            "packet_sha256": packet_digest,
            "protocol_sha256": packet["protocol_sha256"],
            "source_pins_sha256": source_pins_sha,
            "historical identity/liveness": "UNKNOWN",
            "T-07-07": "OPEN/high",
        }
        if not _accepted_security_report(security, required):
            raise ValueError("return-independent-security-stale-or-rejected")
    return packet, review_path


def validate_cumulative_limits(limits, *, attempt_number=3):
    expected = ATTEMPT4_CUMULATIVE_LIMITS if attempt_number == 4 else CUMULATIVE_LIMITS
    if (attempt_number not in (3, 4) or not isinstance(limits, dict) or limits != expected
            or any(type(value) is not int for value in limits.values())):
        raise ValueError("return-cumulative-attempt-budget-invalid")
    sums = (
        (limits["prior_starts_reserved"] + limits["future_starts_reserved"], limits["campaign_start_events"]),
        (limits["prior_status_helpers_reserved"] + limits["future_status_helpers_reserved"], limits["campaign_status_helper_starts"]),
        (limits["prior_observer_queries_measured"] + limits["future_observer_queries_reserved"], limits["campaign_observer_queries"]),
        (limits["prior_rss_samples_reserved"] + limits["future_rss_samples_reserved"], limits["campaign_rss_samples"]),
        (limits["prior_native_rss_queries_reserved"] + limits["future_native_rss_queries_reserved"], limits["campaign_native_rss_pid_queries"]),
        (limits["prior_retained_bytes_measured"] + limits["future_retained_bytes_reserved"], limits["campaign_retained_bytes"]),
        (limits["prior_status_output_bytes_reserved"] + limits["future_status_output_bytes_reserved"], limits["campaign_status_output_bytes"]),
        (limits["prior_elapsed_seconds_reserved"] + limits["future_elapsed_seconds_reserved"], limits["campaign_elapsed_seconds"]),
        (limits["prior_control_bytes_measured"] + limits["future_control_bytes_reserved"], limits["campaign_control_bytes"]),
        (limits["prior_control_entries_measured"] + limits["future_control_entries_reserved"], limits["campaign_control_entries"]),
        (limits["prior_host_invocations_used"] + limits["future_host_invocations_reserved"], limits["campaign_host_invocations"]),
        (limits["prior_wrapper_calls_used"] + limits["future_wrapper_calls_reserved"], limits["campaign_wrapper_calls"]),
    )
    if any(type(used) is not int or used > maximum for used, maximum in sums):
        raise ValueError("return-cumulative-attempt-reserve-exceeded")
    if (limits["prior_controller_starts_measured"] + limits["prior_owner_starts_unknown_reserved"]
            != limits["prior_starts_reserved"]
            or limits["prior_status_helpers_measured"] + limits["prior_owner_status_helpers_unknown_reserved"]
            != limits["prior_status_helpers_reserved"]
            or limits["prior_rss_samples_measured"] + limits["prior_owner_rss_samples_unknown_reserved"]
            != limits["prior_rss_samples_reserved"]
            or limits["prior_rss_samples_reserved"] * LIMITS["native_rss_pids_per_observation"]
            != limits["prior_native_rss_queries_reserved"]):
        raise ValueError("return-cumulative-prior-debit-invalid")


def read_record(path: Path, deadline: float):
    for _ in range(100):
        if time.monotonic() >= deadline:
            break
        if path.is_file() and not path.is_symlink():
            try:
                return safe_json(path)
            except (OSError, json.JSONDecodeError, ValueError):
                pass
        time.sleep(.02)
    raise TimeoutError("return-gate-record-deadline")


def write_record(path: Path, value: dict, *, exclusive=True):
    ensure_owned_tree_path(path.parent)
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(encoded) > CAP:
        raise ValueError("return-record-byte-cap")
    recovery = ROOT / "build/v02/recovery15"
    owned_recovery = path == recovery or path.is_relative_to(recovery)
    lock_fd = None
    locked = False
    case_root_path = None
    total_entry_cap = LIMITS["maximum_tree_entries"] * 2 + 3
    if owned_recovery:
        lock_path = recovery / ".limits.lock"
        if lock_path.is_symlink() or not lock_path.is_file():
            raise ValueError("return-output-limit-lock-missing")
        lock_info = lock_path.lstat()
        if lock_info.st_uid != os.getuid() or lock_info.st_nlink != 1:
            raise ValueError("return-output-limit-lock-invalid")
        lock_fd = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if lock_fd is not None:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            locked = True
        if owned_recovery:
            current_total = check_owned_tree(recovery, byte_cap=LIMITS["aggregate_retained_bytes"],
                entry_cap=total_entry_cap)
            case_root_path = next((parent for parent in (path.parent, *path.parents)
                if parent.parent == recovery and parent.name.startswith("case-")), None)
            current_case = check_owned_tree(case_root_path, byte_cap=LIMITS["case_retained_bytes"]) if case_root_path else {"entries": 0, "bytes": 0}
            if path.is_symlink():
                raise ValueError("return-record-symlink")
            existing_size = 0
            if path.exists():
                if exclusive or not path.is_file():
                    raise ValueError("return-record-already-exists")
                existing_info = path.lstat()
                if existing_info.st_uid != os.getuid() or existing_info.st_nlink != 1:
                    raise ValueError("return-record-existing-file-invalid")
                existing_size = existing_info.st_size
            added_entries = 0 if path.exists() else 1
            if (current_total["entries"] + added_entries > total_entry_cap
                    or current_total["bytes"] - existing_size + len(encoded) > LIMITS["aggregate_retained_bytes"]
                    or case_root_path is not None and (current_case["entries"] + added_entries > LIMITS["maximum_tree_entries"]
                        or current_case["bytes"] - existing_size + len(encoded) > LIMITS["case_retained_bytes"])):
                raise ValueError("return-output-prospective-ceiling")
        flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_EXCL if exclusive else os.O_TRUNC)
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        if owned_recovery:
            if case_root_path:
                check_owned_tree(case_root_path, byte_cap=LIMITS["case_retained_bytes"])
            check_owned_tree(recovery, byte_cap=LIMITS["aggregate_retained_bytes"],
                entry_cap=total_entry_cap)
    finally:
        if lock_fd is not None:
            if locked:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)


def create_owned_case_directory(path: Path):
    root = next((parent for parent in (path.parent, *path.parents)
        if parent.parent == ROOT / "build/v02/recovery15" and parent.name.startswith("case-")), None)
    if root is None:
        raise ValueError("return-case-directory-root-invalid")
    lock_fd = os.open(ROOT / "build/v02/recovery15/.limits.lock", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if path.exists() or path.is_symlink():
            raise ValueError("return-case-directory-not-new")
        case = check_owned_tree(root, byte_cap=LIMITS["case_retained_bytes"])
        total = check_owned_tree(ROOT / "build/v02/recovery15",
            byte_cap=LIMITS["aggregate_retained_bytes"],
            entry_cap=LIMITS["maximum_tree_entries"] * 2 + 3)
        if (case["entries"] + 1 + LIMITS["reserved_wrapper_entries_per_case"] > LIMITS["maximum_tree_entries"]
                or case["bytes"] + LIMITS["reserved_wrapper_bytes_per_case"] > LIMITS["case_retained_bytes"]
                or total["entries"] + 1 > LIMITS["maximum_tree_entries"] * 2 + 3
                or total["bytes"] + LIMITS["reserved_wrapper_bytes_per_case"] > LIMITS["aggregate_retained_bytes"]):
            raise ValueError("return-case-directory-prospective-ceiling")
        path.mkdir(mode=0o700)
        check_owned_tree(root, byte_cap=LIMITS["case_retained_bytes"])
        check_owned_tree(ROOT / "build/v02/recovery15",
            byte_cap=LIMITS["aggregate_retained_bytes"],
            entry_cap=LIMITS["maximum_tree_entries"] * 2 + 3)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def bounded_json_writer(root: Path, work: Path, writer):
    def bounded(path, value):
        target = Path(os.path.abspath(path))
        if not target.is_relative_to(work) or target == work or target.is_symlink():
            raise ValueError("return-wrapper-json-path-invalid")
        encoded = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
        if len(encoded) > CAP:
            raise ValueError("return-wrapper-json-byte-cap")
        reserve_case_capacity(root)
        writer(target, value)
        if target.is_symlink() or not target.is_file() or target.stat().st_nlink != 1 or target.stat().st_size > CAP:
            raise ValueError("return-wrapper-json-persistence-invalid")
        check_owned_tree(root, byte_cap=LIMITS["case_retained_bytes"])
    return bounded


def observer_snapshot(pid: int) -> dict:
    """One fixed raw-byte snapshot, bounded before decoding, with direct-child reap."""
    command = list(LIMITS["observer_argv"])
    if RUN_COUNTS is not None:
        with RUN_COUNT_LOCK:
            RUN_COUNTS["observer_queries"] += 1
            RUN_COUNTS["rss_samples"] += 1
            if (RUN_COUNTS["observer_queries"] > MAX_OBSERVER_QUERIES_PER_CASE
                    or RUN_COUNTS["rss_samples"] > MAX_OBSERVER_RSS_PER_CASE):
                raise ValueError("return-observation-count-ceiling")
    observer_env = {**os.environ, **LIMITS["observer_environment"]}
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, start_new_session=True, bufsize=0, env=observer_env)
    if process.stdout is None:
        try:
            process.kill()
            process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            raise ValueError("return-observer-child-unsettled") from None
        raise ValueError("return-observer-pipe-missing")
    import selectors
    selector = selectors.DefaultSelector()
    output = bytearray()
    overflow = False
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + STATUS_TIMEOUT
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("return-observer-communication-deadline")
            if not selector.select(remaining):
                raise TimeoutError("return-observer-communication-deadline")
            block = os.read(process.stdout.fileno(), min(CHUNK, CAP + 1 - len(output)))
            if not block:
                break
            output.extend(block)
            if len(output) > CAP:
                overflow = True
                output = output[:CAP + 1]
                raise ValueError("return-observer-output-overflow-sentinel")
        if process.wait(timeout=max(.001, deadline - time.monotonic())) != 0:
            raise ValueError("return-observer-command-failed")
    except BaseException:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                raise ValueError("return-observer-child-unsettled")
        raise
    finally:
        selector.close()
        process.stdout.close()
    if overflow or len(output) > CAP:
        raise ValueError("return-observer-output-byte-cap")
    rows = parse_observer_status(bytes(output))
    rss_spec = importlib.util.spec_from_file_location("return_rss_observer",
        ROOT / "tests/session/phase6_route_contract.py")
    rss_module = importlib.util.module_from_spec(rss_spec)
    rss_spec.loader.exec_module(rss_module)
    rss = rss_module._process_group_rss_bytes(pid)
    return {"pid": pid, "identity": rows.get(pid), "rss_bytes": rss,
            "group_members": [row for row in rows.values() if row["pgid"] == pid],
            "bytes": len(output), "status_sha256": hashlib.sha256(output).hexdigest(),
            "query": command}


def parse_observer_status(output: bytes) -> dict[int, dict]:
    rows = {}
    try:
        for line in output.decode("ascii", "strict").splitlines():
            fields = line.split()
            if len(fields) != 8 or not fields[0].isdigit() or not fields[1].isdigit():
                raise ValueError("return-observer-status-shape-invalid")
            row_pid, row_pgid = int(fields[0]), int(fields[1])
            if row_pid <= 0 or row_pgid <= 0:
                raise ValueError("return-observer-status-identity-invalid")
            if row_pid in rows:
                raise ValueError("return-observer-duplicate-pid")
            birth_fields = fields[2:7]
            if (re.fullmatch(r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)", birth_fields[0]) is None
                    or re.fullmatch(r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)", birth_fields[1]) is None
                    or re.fullmatch(r"(?:[1-9]|[12][0-9]|3[01])", birth_fields[2]) is None
                    or re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]", birth_fields[3]) is None
                    or re.fullmatch(r"[0-9]{4}", birth_fields[4]) is None):
                raise ValueError("return-observer-birth-shape-invalid")
            state = fields[7]
            if (not state or state[0] not in "IRSTUZ"
                    or any(char not in "+<>AELNSsVWX" for char in state[1:])
                    or len(set(state[1:])) != len(state[1:])):
                raise ValueError("return-observer-stat-invalid")
            rows[row_pid] = {"pid": row_pid, "pgid": row_pgid,
                "birth": " ".join(birth_fields), "state": state}
        if not rows:
            raise ValueError("return-observer-empty-status-table")
    except (UnicodeDecodeError, ValueError):
        raise ValueError("return-observer-status-decode-invalid") from None
    return rows


def require_bounded_count(value, maximum: int, label: str) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise ValueError("return-live-counter-invalid:" + label)
    return value


def validate_packet_for_entry(packet_path: Path):
    packet, review_path = packet_and_review(packet_path)
    attempt_number = packet.get("resume_campaign", {}).get("attempt_number", 1)
    packet_name = PACKET16 if attempt_number == 4 else PACKET15
    if packet.get("command") != [sys.executable, "-I", "tests/evidence/phase7_wrapper_return.py",
            "--run-selected", "--packet", packet_name,
            "--campaign", "build/v02/campaign15/campaign.json", "--out", "build/v02/recovery15/live.json"]:
        raise ValueError("return-admission-command-mismatch")
    if packet.get("owner_argv") != [sys.executable, "-I", "tests/evidence/phase7_wrapper_return.py",
            "--owner", "{case}", "{root}", "--controller-pid", "{controller_pid}",
            "--controller-nonce", "{controller_nonce}",
            "--packet", packet_name,
            "--campaign", "build/v02/campaign15/campaign.json", "--campaign-sha256", "{campaign_sha256}"]:
        raise ValueError("return-owner-command-template-mismatch")
    expected_leaf = {
        "shared_launch": [sys.executable, "-I", "../../../../../tests/evidence/phase7_wrapper_return.py",
            "--leaf", "{root}"],
        "bounded_command": [sys.executable, "-I", "tests/evidence/phase7_wrapper_return.py",
            "--leaf", "{root}"],
    }
    if packet.get("leaf_argv") != expected_leaf:
        raise ValueError("return-leaf-command-template-mismatch")
    return packet, review_path


def create_campaign(path: Path, packet: dict) -> tuple[dict, str]:
    expected = ROOT / "build/v02/campaign15/campaign.json"
    path = path if path.is_absolute() else ROOT / path
    if Path(os.path.abspath(path)) != Path(os.path.abspath(expected)) or path.exists() or path.is_symlink():
        raise ValueError("return-campaign-must-be-new-canonical-file")
    ensure_owned_tree_path(path.parent.parent)
    campaign_parent = ensure_owned_tree_path(path.parent, may_create_leaf=True)
    if not campaign_parent.exists():
        campaign_parent.mkdir(mode=0o700)
        parent_fd = os.open(campaign_parent.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(parent_fd)
        finally: os.close(parent_fd)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    start_dt = datetime.datetime.fromisoformat(started)
    value = {"schema": CAMPAIGN_SCHEMA, "campaign_id": "phase7-renewed-2026-10-30",
        "status": "started", "started_at": started,
        "runtime_cutoff": (start_dt + datetime.timedelta(seconds=64800)).isoformat(),
        "package_cutoff": (start_dt + datetime.timedelta(seconds=79200)).isoformat(),
        "global_cutoff": (start_dt + datetime.timedelta(seconds=86400)).isoformat(),
        "scope_path": "evidence/v02-execution.json", "scope_sha256": sha(ROOT / "evidence/v02-execution.json"),
        "admission_sha256": packet["packet_sha256"],
        "journal_path": "build/v02/campaign15/hosted-delivery-journal.json"}
    value["record_sha256"] = hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()
    write_record(path, value)
    return value, sha(path)


def validate_prechild_resume_state(campaign_path: Path, packet: dict | None = None) -> tuple[dict, str, bool]:
    """Reopen the exact campaign and validate the sole bounded retry state."""
    packet_path = ROOT / (PACKET16 if packet and packet.get("resume_campaign", {}).get("attempt_number") == 4 else PACKET15)
    selected_packet = packet if packet is not None else packet_and_review(packet_path)[0]
    attempt_number = selected_packet.get("resume_campaign", {}).get("attempt_number", 1)
    if attempt_number not in (1, 2, 3, 4):
        raise ValueError("return-corrected-attempt-selector-invalid")
    if attempt_number == 4:
        return validate_attempt4_prechild_resume_state(campaign_path, selected_packet)
    if attempt_number == 3:
        return validate_final_prechild_resume_state(campaign_path, selected_packet)
    recovery = ROOT / "build/v02/recovery15"
    archive = ROOT / "build/v02/recovery15-attempt1"
    started = safe_json(campaign_path)
    campaign_sha = sha(campaign_path)
    require_corrected_invocation_unconsumed()
    if archive.exists() or archive.is_symlink():
        raise ValueError("return-corrected-invocation-state-invalid")
    spec = importlib.util.spec_from_file_location("return_campaign_resume_coordinator",
        ROOT / "scripts/release/v02_qualification.py")
    coordinator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(coordinator)
    scope_path = ROOT / "evidence/v02-execution.json"
    coordinator._campaign_projection(campaign_path, scope_path,
        ROOT / started.get("journal_path", ""), phase="runtime",
        expected_sha256=campaign_sha, require_return=False)
    coordinator._require_hosted_budget(started["started_at"],
        datetime.datetime.now(datetime.timezone.utc).isoformat(),
        json.loads(scope_path.read_text(encoding="utf-8")), phase="runtime")
    if (ROOT / "build/v02/campaign15/hosted-delivery-journal.json").exists():
        raise ValueError("return-prechild-campaign-resume-state-invalid")
    resume = packet_and_review(ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-ADMISSION.json")[0].get("resume_campaign", {})
    if (resume.get("attempt_number") != 2
            or resume.get("attempt2_marker_path") != "build/v02/campaign15/attempt2-started.json"):
        raise ValueError("return-corrected-attempt-selector-invalid")
    failed = resume.get("failed_attempt")
    if not isinstance(failed, dict) or failed.get("schema") != "genewhip.phase7-wrapper-return-attempt.v1":
        raise ValueError("return-failed-attempt-binding-missing")
    manifest_path = ROOT / failed.get("path", "")
    if sha(manifest_path) != failed.get("sha256"):
        raise ValueError("return-failed-attempt-manifest-stale")
    manifest = safe_json(manifest_path)
    if (manifest.get("attempt") != 1 or manifest.get("live_status") != "failed"
            or manifest.get("failure") != "return-wrapper-result-missing"
            or manifest.get("case_roster") != ["shared_launch"]
            or manifest.get("campaign_sha256") != campaign_sha
            or manifest.get("campaign_started_at") != started.get("started_at")
            or manifest.get("packet_sha256") != failed.get("failed_packet_sha256")
            or manifest.get("owner_settled") is not True
            or manifest.get("leaf_settled") is not True
            or manifest.get("owner_final_group_absent") is not True
            or manifest.get("leaf_final_group_absent") is not True):
        raise ValueError("return-failed-attempt-binding-invalid")
    attempt_root = archive if archive.exists() else recovery
    tree = check_owned_tree(attempt_root, byte_cap=CUMULATIVE_LIMITS["campaign_retained_bytes"],
        entry_cap=LIMITS["maximum_tree_entries"])
    if (tree["bytes"] != manifest.get("tree_bytes")
            or tree["entries"] != manifest.get("tree_entries")):
        raise ValueError("return-attempt-tree-accounting-mismatch")
    if Path(manifest.get("live_path", "")) != Path("build/v02/recovery15/live.json"):
        raise ValueError("return-failed-live-path-invalid")
    live = safe_json(attempt_root / "live.json")
    if (sha(attempt_root / "live.json") != manifest.get("live_sha256")
            or live.get("status") != "failed" or live.get("packet_sha256") != manifest.get("packet_sha256")
            or live.get("campaign_sha256") != campaign_sha or len(live.get("cases", [])) != 1
            or live["cases"][0].get("status") != "failed"
            or live["cases"][0].get("error") != manifest.get("failure")):
        raise ValueError("return-failed-live-binding-invalid")
    if Path(os.path.abspath(ROOT / manifest.get("archive_root", ""))) != archive:
        raise ValueError("return-attempt-archive-invalid")
    review = ROOT / manifest.get("review_path", "")
    security = ROOT / manifest.get("security_path", "")
    if (sha(review) != manifest.get("review_sha256") or sha(security) != manifest.get("security_sha256")
            or manifest.get("review_sha256") != failed.get("review_sha256")
            or manifest.get("security_sha256") != failed.get("security_sha256")):
        raise ValueError("return-attempt-independent-review-stale")
    for relative, detail in manifest.get("files", {}).items():
        item = attempt_root / relative
        if (item.is_symlink() or not item.is_file() or item.stat().st_size != detail.get("bytes")
                or sha(item) != detail.get("sha256")):
            raise ValueError("return-attempt-file-hash-mismatch")
    if manifest.get("cumulative_reserve") != PRIOR_CUMULATIVE_LIMITS:
        raise ValueError("return-cumulative-attempt-budget-invalid")
    accounting = manifest.get("attempt_accounting", {})
    if (accounting.get("host_invocations") != 2 or accounting.get("actual_wrapper_calls") != 1
            or accounting.get("measured") != {"controller_starts": 6,
                "status_helper_starts": 5, "observer_queries": 4,
                "controller_rss_samples": 4, "elapsed_seconds": 0.2984199159545824,
                "retained_bytes": 9665}
            or accounting.get("unknown_reserves") != {"owner_starts": 17,
                "owner_status_helper_starts": 17, "owner_rss_samples": 508,
                "native_rss_pid_queries": 2097152}
            or accounting.get("not_measurements", {}).get("meaning") !=
                "fallback fields written when owner count receipt was missing; not observed zero"
            or accounting.get("not_measurements", {}).get("live_case_owner_starts") != 0
            or accounting.get("not_measurements", {}).get("live_case_owner_rss_samples") != 0):
        raise ValueError("return-failed-attempt-accounting-invalid")
    current = recovery.exists()
    if archive.exists():
        if archive.is_symlink() or not archive.is_dir():
            raise ValueError("return-attempt-archive-invalid")
        if current:
            if recovery.is_symlink() or not recovery.is_dir():
                raise ValueError("return-prechild-campaign-resume-state-invalid")
            names = list(os.listdir(recovery))
            lock_path = recovery / ".limits.lock"
            if (names != [".limits.lock"] or lock_path.is_symlink() or not lock_path.is_file()
                    or lock_path.stat().st_uid != os.getuid() or lock_path.stat().st_nlink != 1
                    or lock_path.stat().st_size != 0):
                raise ValueError("return-prechild-campaign-resume-state-invalid")
        return started, campaign_sha, not current
    if current:
        if recovery.is_symlink() or not recovery.is_dir():
            raise ValueError("return-prechild-campaign-resume-state-invalid")
        # The failed attempt must exactly match the pinned file roster before rename.
        expected = set(manifest.get("files", {}))
        actual = set()
        for base, dirs, files in os.walk(recovery, followlinks=False):
            for name in dirs:
                if (Path(base) / name).is_symlink(): raise ValueError("return-attempt-tree-symlink")
            for name in files:
                actual.add((Path(base) / name).relative_to(recovery).as_posix())
        if actual != expected:
            raise ValueError("return-attempt-file-roster-mismatch")
        return started, campaign_sha, True
    return started, campaign_sha, True


def validate_final_prechild_resume_state(campaign_path: Path, packet: dict) -> tuple[dict, str, bool]:
    """Validate both spent failures and the exact single remaining attempt, read-only."""
    resume = packet.get("resume_campaign", {})
    recovery = ROOT / "build/v02/recovery15"
    archive1 = ROOT / "build/v02/recovery15-attempt1"
    archive2 = ROOT / "build/v02/recovery15-attempt2"
    marker3 = ROOT / "build/v02/campaign15/attempt3-started.json"
    if marker3.exists() or marker3.is_symlink():
        raise ValueError("return-final-invocation-already-consumed")
    started = safe_json(campaign_path)
    campaign_sha = sha(campaign_path)
    coordinator_spec = importlib.util.spec_from_file_location("return_final_resume_coordinator",
        ROOT / "scripts/release/v02_qualification.py")
    coordinator = importlib.util.module_from_spec(coordinator_spec)
    coordinator_spec.loader.exec_module(coordinator)
    scope_path = ROOT / "evidence/v02-execution.json"
    coordinator._campaign_projection(campaign_path, scope_path,
        ROOT / started.get("journal_path", ""), phase="runtime",
        expected_sha256=campaign_sha, require_return=False)
    coordinator._require_hosted_budget(started["started_at"],
        datetime.datetime.now(datetime.timezone.utc).isoformat(),
        json.loads(scope_path.read_text(encoding="utf-8")), phase="runtime")
    if (resume.get("attempt_number") != 3
            or resume.get("attempt3_marker_path") != "build/v02/campaign15/attempt3-started.json"
            or resume.get("campaign_sha256") != campaign_sha
            or resume.get("campaign_started_at") != started.get("started_at")
            or started.get("started_at") != "2026-10-30T16:50:39.837827+00:00"
            or (ROOT / "build/v02/campaign15/hosted-delivery-journal.json").exists()):
        raise ValueError("return-final-campaign-binding-invalid")
    marker2 = ROOT / "build/v02/campaign15/attempt2-started.json"
    attempt2 = resume.get("attempt2_failure", {})
    manifest2_path = ROOT / attempt2.get("path", "")
    if (attempt2.get("path") != ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-ATTEMPT2-FAILURE.json"
            or manifest2_path.is_symlink() or not manifest2_path.is_file()
            or sha(manifest2_path) != attempt2.get("sha256")
            or marker2.is_symlink() or not marker2.is_file()
            or sha(marker2) != resume.get("attempt2_marker_sha256")):
        raise ValueError("return-final-attempt2-history-stale")
    manifest2 = safe_json(manifest2_path)
    marker2_doc = safe_json(marker2)
    marker2_digest = marker2_doc.pop("record_sha256", None)
    if (manifest2.get("attempt") != 2 or manifest2.get("live_status") != "failed"
            or manifest2.get("failure") != "return-wrapper-result-missing"
            or manifest2.get("campaign_sha256") != campaign_sha
            or manifest2.get("campaign_started_at") != started.get("started_at")
            or manifest2.get("case_roster") != ["shared_launch"]
            or manifest2.get("owner_settled") is not True
            or manifest2.get("leaf_settled") is not True
            or manifest2.get("owner_final_group_absent") is not True
            or manifest2.get("leaf_final_group_absent") is not True
            or manifest2.get("attempt_entry_sha256") != resume.get("attempt2_marker_sha256")
            or marker2_doc.get("attempt") != 2
            or marker2_doc.get("campaign_sha256") != campaign_sha
            or marker2_doc.get("packet_sha256") != manifest2.get("packet_sha256")
            or hashlib.sha256(json.dumps(marker2_doc, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest() != marker2_digest):
        raise ValueError("return-final-attempt2-history-invalid")
    if campaign_path.stat().st_size != 672 or marker2.stat().st_size != 625:
        raise ValueError("return-final-control-byte-reserve-invalid")
    admission_path = ROOT / resume.get("attempt2_admission_path", "")
    review_path = ROOT / resume.get("attempt2_review_path", "")
    security_path = ROOT / resume.get("attempt2_security_path", "")
    denied_path = ROOT / resume.get("attempt2_denied_path", "")
    phase = ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/"
    if (admission_path != ROOT / (phase + "07-15-ATTEMPT2-ADMISSION.json")
            or review_path != ROOT / (phase + "07-15-ATTEMPT2-REVIEW.md")
            or security_path != ROOT / (phase + "07-15-ATTEMPT2-SECURITY.md")
            or denied_path != ROOT / (phase + "07-15-DENIED-FOLLOWUP.md")
            or sha(admission_path) != resume.get("attempt2_admission_sha256")
            or sha(review_path) != resume.get("attempt2_review_sha256")
            or sha(security_path) != resume.get("attempt2_security_sha256")
            or sha(denied_path) != resume.get("attempt2_denied_sha256")):
        raise ValueError("return-final-attempt2-review-record-stale")
    if ("packet_sha256: " + resume["attempt2_packet_sha256"] not in review_path.read_text(encoding="utf-8")
            or "| Packet | `" + resume["attempt2_packet_sha256"] + "` |" not in security_path.read_text(encoding="utf-8")
            or sha(admission_path) != resume["attempt2_packet_sha256"]):
        raise ValueError("return-final-attempt2-review-binding-invalid")
    expected = manifest2.get("files")
    tree = check_owned_tree(recovery, byte_cap=4 * 1024 * 1024,
        entry_cap=LIMITS["maximum_tree_entries"])
    if (recovery.is_symlink() or archive2.exists() or archive2.is_symlink()
            or tree["bytes"] != manifest2.get("tree_bytes")
            or tree["entries"] != manifest2.get("tree_entries")
            or not isinstance(expected, dict)):
        raise ValueError("return-final-attempt2-tree-invalid")
    actual = {}
    for base, dirs, files in os.walk(recovery, followlinks=False):
        for name in dirs:
            if (Path(base) / name).is_symlink():
                raise ValueError("return-final-attempt2-tree-symlink")
        for name in files:
            item = Path(base) / name
            relative = item.relative_to(recovery).as_posix()
            actual[relative] = {"bytes": item.stat().st_size, "sha256": sha(item)}
    if actual != expected:
        raise ValueError("return-final-attempt2-file-hash-mismatch")
    live = safe_json(recovery / "live.json")
    if (sha(recovery / "live.json") != manifest2.get("live_sha256")
            or live.get("status") != "failed"
            or live.get("campaign_sha256") != campaign_sha
            or live.get("packet_sha256") != manifest2.get("packet_sha256")
            or live.get("started_at") != started.get("started_at")):
        raise ValueError("return-final-attempt2-live-invalid")
    if archive1.is_symlink() or not archive1.is_dir():
        raise ValueError("return-final-attempt1-archive-missing")
    old1 = resume.get("failed_attempt", {})
    old1_path = ROOT / old1.get("path", "")
    if old1_path.is_symlink() or not old1_path.is_file() or sha(old1_path) != old1.get("sha256"):
        raise ValueError("return-final-attempt1-manifest-stale")
    if (ROOT / "build/v02/campaign15/hosted-delivery-journal.json").exists():
        raise ValueError("return-final-hosted-journal-present")
    return started, campaign_sha, True


def validate_attempt4_prechild_resume_state(campaign_path: Path, packet: dict) -> tuple[dict, str, bool]:
    """Read-only admission of exact history and active state before debit4."""
    expected_campaign = ROOT / "build/v02/campaign15/campaign.json"
    marker = ROOT / "build/v02/campaign15/attempt4-started.json"
    if (Path(os.path.abspath(campaign_path)) != expected_campaign
            or campaign_path.is_symlink() or not campaign_path.is_file()
            or marker.exists() or marker.is_symlink()):
        raise ValueError("return-attempt4-prechild-state-invalid")
    started = safe_json(campaign_path)
    campaign_sha = sha(campaign_path)
    coordinator_spec = importlib.util.spec_from_file_location("return_attempt4_resume_coordinator",
        ROOT / "scripts/release/v02_qualification.py")
    coordinator = importlib.util.module_from_spec(coordinator_spec)
    coordinator_spec.loader.exec_module(coordinator)
    scope_path = ROOT / "evidence/v02-execution.json"
    coordinator._campaign_projection(campaign_path, scope_path,
        ROOT / started.get("journal_path", ""), phase="runtime",
        expected_sha256=campaign_sha, require_return=False, selection="16",
        allow_unconsumed_attempt4=True)
    coordinator._require_hosted_budget(started["started_at"],
        datetime.datetime.now(datetime.timezone.utc).isoformat(),
        json.loads(scope_path.read_text(encoding="utf-8")), phase="runtime")
    if (started.get("started_at") != "2026-10-30T16:50:39.837827+00:00"
            or campaign_path.stat().st_size != 672
            or (ROOT / "build/v02/campaign15/hosted-delivery-journal.json").exists()):
        raise ValueError("return-attempt4-campaign-binding-invalid")
    return started, campaign_sha, True


def require_corrected_invocation_unconsumed():
    marker = ROOT / "build/v02/campaign15/attempt2-started.json"
    if marker.exists() or marker.is_symlink():
        raise ValueError("return-corrected-invocation-already-consumed")


def archive_failed_attempt1_and_prepare_recovery():
    recovery = ROOT / "build/v02/recovery15"
    archive = ROOT / "build/v02/recovery15-attempt1"
    if archive.exists() or archive.is_symlink():
        raise ValueError("return-attempt1-already-archived")
    if recovery.is_symlink() or not recovery.is_dir():
        raise ValueError("return-attempt-archive-source-invalid")
    # The current source/packet gate has verified every retained attempt-1 byte.
    os.rename(recovery, archive)
    parent_fd = os.open(recovery.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    recovery.mkdir(mode=0o700)
    create_limits_lock(recovery)
    parent_fd = os.open(recovery.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def archive_failed_attempt2_and_prepare_recovery():
    recovery = ROOT / "build/v02/recovery15"
    archive = ROOT / "build/v02/recovery15-attempt2"
    marker = ROOT / "build/v02/campaign15/attempt3-started.json"
    marker_doc = safe_json(marker, maximum=65536)
    marker_digest = marker_doc.pop("record_sha256", None)
    if (marker_doc.get("attempt") != 3
            or marker_doc.get("cumulative_limits") != CUMULATIVE_LIMITS
            or hashlib.sha256(json.dumps(marker_doc, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest() != marker_digest):
        raise ValueError("return-final-debit-required-before-archive")
    if archive.exists() or archive.is_symlink():
        raise ValueError("return-final-attempt2-already-archived")
    if recovery.is_symlink() or not recovery.is_dir():
        raise ValueError("return-final-attempt2-archive-source-invalid")
    os.rename(recovery, archive)
    parent_fd = os.open(recovery.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    recovery.mkdir(mode=0o700)
    create_limits_lock(recovery)
    parent_fd = os.open(recovery.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def consume_corrected_invocation(packet: dict, campaign_sha: str, campaign_started_at: str):
    require_corrected_invocation_unconsumed()
    path = ROOT / "build/v02/campaign15/attempt2-started.json"
    value = {"schema": "genewhip.phase7-wrapper-return-attempt-entry.v1",
        "attempt": 2, "campaign_sha256": campaign_sha,
        "campaign_started_at": campaign_started_at,
        "packet_sha256": packet["packet_sha256"],
        "failed_attempt_manifest_sha256": packet["resume_campaign"]["failed_attempt"]["sha256"],
        "prior_host_invocations_used": 2, "prior_wrapper_calls_used": 1,
        "future_wrapper_calls_reserved": 2,
        "consumed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    value["record_sha256"] = hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()
    write_record(path, value)
    return sha(path)


def consume_final_invocation(packet: dict, campaign_sha: str, campaign_started_at: str) -> str:
    """Persist the sole third-attempt debit before archiving or creating runtime state."""
    resume = packet.get("resume_campaign", {})
    if resume.get("attempt_number") != 3:
        raise ValueError("return-final-attempt-selector-invalid")
    campaign = ROOT / "build/v02/campaign15/campaign.json"
    old_marker = ROOT / "build/v02/campaign15/attempt2-started.json"
    marker = ROOT / "build/v02/campaign15/attempt3-started.json"
    attempt2 = resume.get("attempt2_failure", {})
    campaign_doc = safe_json(campaign)
    old_marker_doc = safe_json(old_marker)
    old_marker_digest = old_marker_doc.pop("record_sha256", None)
    if (campaign.is_symlink() or not campaign.is_file() or sha(campaign) != campaign_sha
            or not old_marker.is_file() or old_marker.is_symlink()
            or sha(old_marker) != resume.get("attempt2_marker_sha256")
            or campaign.stat().st_size != 672 or old_marker.stat().st_size != 625
            or campaign_doc.get("started_at") != campaign_started_at
            or old_marker_doc.get("attempt") != 2
            or hashlib.sha256(json.dumps(old_marker_doc, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest() != old_marker_digest
            or attempt2.get("path") != ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-ATTEMPT2-FAILURE.json"
            or sha(ROOT / attempt2.get("path", "")) != attempt2.get("sha256")):
        raise ValueError("return-final-attempt-history-stale")
    if marker.exists() or marker.is_symlink():
        raise ValueError("return-final-invocation-already-consumed")
    value = {
        "schema": "genewhip.phase7-wrapper-return-attempt-entry.v1",
        "attempt": 3,
        "campaign_sha256": campaign_sha,
        "campaign_started_at": campaign_started_at,
        "packet_sha256": packet["packet_sha256"],
        "attempt1_failure_manifest_sha256": resume["failed_attempt"]["sha256"],
        "attempt2_failure_manifest_sha256": attempt2["sha256"],
        "attempt2_marker_sha256": resume["attempt2_marker_sha256"],
        "prior_host_invocations_used": 3,
        "future_host_invocations_reserved": 1,
        "prior_wrapper_calls_used": 2,
        "future_wrapper_calls_reserved": 2,
        "cumulative_limits": CUMULATIVE_LIMITS,
        "consumed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    value["record_sha256"] = hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()
    write_record(marker, value)
    return "build/v02/campaign15/attempt3-started.json"


def consume_attempt4_invocation(packet: dict, campaign_sha: str, campaign_started_at: str) -> str:
    """Durably debit the only user-authorized attempt4 before case setup."""
    resume = packet.get("resume_campaign", {})
    marker = ROOT / "build/v02/campaign15/attempt4-started.json"
    if (resume.get("attempt_number") != 4
            or resume.get("attempt4_marker_path") != "build/v02/campaign15/attempt4-started.json"
            or resume.get("campaign_sha256") != campaign_sha
            or resume.get("campaign_started_at") != campaign_started_at
            or packet.get("cumulative_limits") != ATTEMPT4_CUMULATIVE_LIMITS
            or marker.exists() or marker.is_symlink()):
        raise ValueError("return-attempt4-debit-precondition-invalid")
    value = {
        "schema": "genewhip.phase7-wrapper-return-attempt-entry.v1",
        "attempt": 4,
        "campaign_sha256": campaign_sha,
        "campaign_started_at": campaign_started_at,
        "packet_sha256": packet["packet_sha256"],
        "attempt1_failure_manifest_sha256": resume["attempt1_failure_manifest_sha256"],
        "attempt2_failure_manifest_sha256": resume["attempt2_failure_manifest_sha256"],
        "attempt3_marker_sha256": resume["attempt3_marker_sha256"],
        "authorization_sha256": resume["authorization_sha256"],
        "prior_host_invocations_used": 4,
        "future_host_invocations_reserved": 1,
        "prior_wrapper_calls_used": 2,
        "future_wrapper_calls_reserved": 2,
        "cumulative_limits": ATTEMPT4_CUMULATIVE_LIMITS,
        "consumed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    value["record_sha256"] = hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()
    write_record(marker, value)
    return "build/v02/campaign15/attempt4-started.json"


def validate_campaign_usage(cases, wrapper_calls: int, diagnostic_seconds: float,
                           archived_bytes: int, active_bytes_reserved: int,
                           *, attempt_number=3) -> dict:
    if attempt_number not in (3, 4):
        raise ValueError("return-cumulative-attempt-number-invalid")
    limit = ATTEMPT4_CUMULATIVE_LIMITS if attempt_number == 4 else CUMULATIVE_LIMITS
    starts = sum(require_bounded_count(row.get("starts"), MAX_STARTS_PER_CASE, "starts")
        for row in cases)
    status_helpers = sum(require_bounded_count(row.get("status_helper_starts"),
        MAX_STATUS_STARTS_PER_CASE, "status_helper_starts") for row in cases)
    observer_queries = sum(require_bounded_count(row.get("observer_queries"),
        MAX_OBSERVER_QUERIES_PER_CASE, "observer_queries") for row in cases)
    rss_samples = sum(require_bounded_count(row.get("rss_samples"),
        MAX_RSS_SAMPLES_PER_CASE, "rss_samples") for row in cases)
    if (type(wrapper_calls) is not int
            or (attempt_number == 3 and wrapper_calls != 2)
            or (attempt_number == 4 and (wrapper_calls < 0 or wrapper_calls > 2))
            or type(diagnostic_seconds) not in (int, float) or isinstance(diagnostic_seconds, bool)
            or not math.isfinite(diagnostic_seconds) or diagnostic_seconds < 0
            or diagnostic_seconds > MAX_DIAGNOSTIC_SECONDS
            or type(archived_bytes) is not int or archived_bytes != limit["prior_retained_bytes_measured"]
            or type(active_bytes_reserved) is not int
            or active_bytes_reserved < 0
            or active_bytes_reserved > limit["future_retained_bytes_reserved"]):
        raise ValueError("return-cumulative-campaign-counter-invalid")
    current_native = rss_samples * LIMITS["native_rss_pids_per_observation"]
    used = {
        "host_invocations": limit["prior_host_invocations_used"] + 1,
        "wrapper_calls": limit["prior_wrapper_calls_used"] + wrapper_calls,
        "start_events": limit["prior_starts_reserved"] + starts,
        "status_helper_starts": limit["prior_status_helpers_reserved"] + status_helpers,
        "observer_queries": limit["prior_observer_queries_measured"] + observer_queries,
        "rss_samples": limit["prior_rss_samples_reserved"] + rss_samples,
        "native_rss_pid_queries": limit["prior_native_rss_queries_reserved"] + current_native,
        "retained_bytes": archived_bytes + active_bytes_reserved,
        "status_output_bytes_reserved": limit["prior_status_output_bytes_reserved"]
            + limit["future_status_output_bytes_reserved"],
        "elapsed_seconds_reserved": limit["prior_elapsed_seconds_reserved"]
            + float(diagnostic_seconds),
        "control_bytes_reserved": limit["prior_control_bytes_measured"]
            + limit["future_control_bytes_reserved"],
        "control_entries_reserved": limit["prior_control_entries_measured"]
            + limit["future_control_entries_reserved"],
    }
    caps = {
        "host_invocations": limit["campaign_host_invocations"],
        "wrapper_calls": limit["campaign_wrapper_calls"],
        "start_events": limit["campaign_start_events"],
        "status_helper_starts": limit["campaign_status_helper_starts"],
        "observer_queries": limit["campaign_observer_queries"],
        "rss_samples": limit["campaign_rss_samples"],
        "native_rss_pid_queries": limit["campaign_native_rss_pid_queries"],
        "retained_bytes": limit["campaign_retained_bytes"],
        "status_output_bytes_reserved": limit["campaign_status_output_bytes"],
        "elapsed_seconds_reserved": limit["campaign_elapsed_seconds"],
        "control_bytes_reserved": limit["campaign_control_bytes"],
        "control_entries_reserved": limit["campaign_control_entries"],
    }
    if any(used[key] > maximum for key, maximum in caps.items()):
        raise ValueError("return-cumulative-campaign-ceiling")
    return {"prior_failed_attempts_usage_and_reserves": dict(limit),
        "current_attempt": {"wrapper_calls": wrapper_calls, "start_events": starts,
            "status_helper_starts": status_helpers, "observer_queries": observer_queries,
            "rss_samples": rss_samples, "native_rss_pid_queries": current_native,
            "retained_bytes_reserved": active_bytes_reserved,
            "status_output_bytes_reserved": limit["future_status_output_bytes_reserved"],
            "elapsed_seconds": float(diagnostic_seconds)},
        "campaign_used": used, "campaign_caps": caps}


def case_root(index: int) -> Path:
    return ROOT / "build/v02/recovery15" / f"case-{index}"


def owner(case: str, root: Path, *, controller_pid: int, controller_nonce: str, packet_path: Path,
          campaign_path: Path, campaign_sha256: str) -> int:
    owner_started = time.monotonic()
    if (os.getppid() != controller_pid or type(controller_pid) is not int
            or re.fullmatch(r"[0-9a-f]{64}", controller_nonce) is None):
        raise ValueError("return-owner-controller-parent-mismatch")
    packet, _review = validate_packet_for_entry(packet_path)
    packet_sha = packet["packet_sha256"]
    campaign_sha = campaign_sha256
    campaign_path = campaign_path if campaign_path.is_absolute() else ROOT / campaign_path
    attempt_number = packet.get("resume_campaign", {}).get("attempt_number", 1)
    expected_packet_path = ROOT / (PACKET16 if attempt_number == 4 else PACKET15)
    if (sha(campaign_path) != campaign_sha256
            or packet.get("packet_sha256") != sha(expected_packet_path)
            or Path(os.path.abspath(packet_path if packet_path.is_absolute() else ROOT / packet_path))
                != expected_packet_path):
        raise ValueError("return-owner-campaign-or-packet-pin-mismatch")
    module_spec = importlib.util.spec_from_file_location("return_owner_campaign_coordinator",
        ROOT / "scripts/release/v02_qualification.py")
    campaign_coordinator = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(campaign_coordinator)
    campaign_coordinator._campaign_projection(campaign_path, ROOT / "evidence/v02-execution.json",
        ROOT / "build/v02/campaign15/hosted-delivery-journal.json", phase="runtime",
        expected_sha256=campaign_sha256, require_return=False,
        selection="16" if attempt_number == 4 else "15")
    expected_case_root = {"shared_launch": case_root(1), "bounded_command": case_root(2)}[case]
    expected_root = expected_case_root
    if root != expected_root or root.is_symlink() or not root.is_dir():
        raise ValueError("return-owner-root-invalid")
    release = root / "release-A.json"
    gate = read_record(release, time.monotonic() + 2)
    if gate != {"pid": os.getpid(), "scope_id": SCOPE_ID, "case": case,
            "controller_pid": controller_pid, "controller_nonce": controller_nonce,
            "packet_sha256": packet["packet_sha256"], "campaign_sha256": campaign_sha256}:
        raise ValueError("return-owner-creation-gate-invalid")
    work = root / "owner-work"
    reserve_case_capacity(root)
    create_owned_case_directory(work)
    leaf_cmd = [arg.replace("{root}", str(root))
        for arg in packet["leaf_argv"][case]]
    original_popen, counters = install_start_counter(
        LIMITS["owner_start_events_per_case"], LIMITS["owner_start_events_per_case"])
    original_spec = importlib.util.spec_from_file_location
    rss_counts = {"observations": 0}
    restore_json_writers = []
    def spec_from_file_location(name, location, *args, **kwargs):
        spec = original_spec(name, location, *args, **kwargs)
        try:
            is_route = Path(location).resolve() == ROOT / "tests/session/phase6_route_contract.py"
        except (TypeError, OSError):
            is_route = False
        if is_route and spec is not None:
            delegate = spec.loader
            class RSSLoader:
                def __getattr__(self, key):
                    return getattr(delegate, key)
                def exec_module(self, module):
                    delegate.exec_module(module)
                    actual = module._process_group_rss_bytes
                    def counted_rss(group):
                        rss_counts["observations"] += 1
                        if rss_counts["observations"] > MAX_OWNER_RSS_PER_CASE:
                            raise ValueError("return-rss-observation-cap")
                        return actual(group)
                    module._process_group_rss_bytes = counted_rss
            spec.loader = RSSLoader()
        return spec
    importlib.util.spec_from_file_location = spec_from_file_location
    try:
        if case == "shared_launch":
            reserve_case_capacity(root)
            fixture_spec = importlib.util.spec_from_file_location("return_phase6_game", ROOT / "tests/fixtures/phase6_game.py")
            fixture = importlib.util.module_from_spec(fixture_spec)
            fixture_spec.loader.exec_module(fixture)
            original_json_writer = fixture.write_json
            fixture.write_json = bounded_json_writer(root, work, original_json_writer)
            restore_json_writers.append((fixture, original_json_writer))
            fixture.set_execution_scope(SCOPE)
            try:
                result, receipt, _streams = fixture.shared_launch(Path(sys.executable), leaf_cmd,
                    work, work / "report.json", LIMITS["leaf_timeout_seconds"],
                    plan_id="GW-07-16" if attempt_number == 4 else "GW-07-15", env=dict(os.environ))
            finally:
                fixture.set_execution_scope(None)
            if result.returncode != 0 or receipt.get("process_group_cleanup") != "confirmed":
                raise ValueError("return-shared-launch-not-qualified")
            write_record(work / "wrapper-result.json", {"wrapper": "shared_launch",
                "case": case, "campaign_sha256": campaign_sha, "packet_sha256": packet_sha,
                "returncode": result.returncode, "receipt": receipt, "streams": _streams})
        else:
            module_spec = importlib.util.spec_from_file_location("return_coordinator", ROOT / "scripts/release/v02_qualification.py")
            coordinator = importlib.util.module_from_spec(module_spec)
            module_spec.loader.exec_module(coordinator)
            original_json_writer = coordinator._write_json
            coordinator._write_json = bounded_json_writer(root, work, original_json_writer)
            restore_json_writers.append((coordinator, original_json_writer))
            reserve_case_capacity(root)
            limits = dict(SCOPE["per_child_limits"])
            limits["wall_seconds"] = LIMITS["leaf_timeout_seconds"]
            attempt = coordinator._bounded_command(leaf_cmd, limits=limits, scratch=work,
                timeout=LIMITS["leaf_timeout_seconds"], label="return-owner-leaf", env=dict(os.environ), cwd=ROOT,
                check=True, scratch_roots=(work,),
                ownership_callback=lambda entry: write_record(root / "owner-created.json", entry))
            if attempt["returncode"] != 0 or attempt["process_group_cleanup"] != "confirmed":
                raise ValueError("return-bounded-command-not-qualified")
            write_record(work / "wrapper-result.json", {"wrapper": "_bounded_command",
                "case": case, "campaign_sha256": campaign_sha, "packet_sha256": packet_sha,
                "returncode": attempt["returncode"], "receipt": attempt["processes"][0],
                "attempt": {key: attempt[key] for key in ("label", "process_group_cleanup", "streams")}})
        write_record(root / "owner-process-count.json", {"starts": counters["starts"],
            "status_helper_starts": counters["status_helper_starts"],
            "rss_observations": rss_counts["observations"], "wrapper_calls": 1,
            "case": case, "campaign_sha256": campaign_sha, "packet_sha256": packet_sha})
        if time.monotonic() - owner_started > LIMITS["owner_timeout_seconds"]:
            raise ValueError("return-owner-wall-limit")
        return 0
    finally:
        for module, writer in restore_json_writers:
            if hasattr(module, "write_json"):
                module.write_json = writer
            if hasattr(module, "_write_json"):
                module._write_json = writer
        importlib.util.spec_from_file_location = original_spec
        subprocess.Popen = original_popen


def leaf(root: Path) -> int:
    deadline = time.monotonic() + 2
    release = root / "release-B.json"
    while time.monotonic() < deadline:
        if release.is_file() and not release.is_symlink():
            gate = safe_json(release)
            if gate == {"pid": os.getpid(), "scope_id": SCOPE_ID}:
                time.sleep(.1)
                return 0
            return 2
        time.sleep(.02)
    return 3


def receipt_candidate(root: Path, before: set[str]) -> tuple[Path, dict] | None:
    for base in (root / "owner-work/process-receipts", root / "owner-work"):
        if not base.is_dir() or base.is_symlink():
            continue
        for path in base.iterdir():
            if path.name in before or path.is_symlink() or not path.is_file() or path.stat().st_size > CAP:
                continue
            try:
                value = safe_json(path)
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            rows = value.get("processes") if isinstance(value, dict) else None
            if isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict):
                row = rows[0]
                if type(row.get("pid")) is int and row.get("pgid") == row["pid"]:
                    return path, row
    return None


def watch_leaf(root: Path, before: set[str], result: dict, stop: threading.Event):
    deadline = time.monotonic() + 8
    try:
        candidate = None
        while time.monotonic() < deadline and not stop.is_set():
            candidate = receipt_candidate(root, before)
            if candidate is not None and candidate[1].get("status") not in ("launch-failed", "not-launched"):
                break
            time.sleep(.02)
        if candidate is None:
            raise TimeoutError("return-leaf-creation-receipt-missing")
        path, row = candidate
        pid = row["pid"]
        snapshot = observer_snapshot(pid)
        observed = snapshot.get("identity")
        if (observed is None or observed.get("pid") != pid or observed.get("pgid") != pid
                or not observed.get("birth") or observed.get("state", "").startswith("Z")):
            raise ValueError("return-leaf-creation-identity-uncertain")
        result.update(leaf_receipt=path.relative_to(ROOT).as_posix(),
                      leaf_birth={**observed, "rss_bytes": snapshot["rss_bytes"]},
                      observer_bytes=snapshot["bytes"])
        write_record(root / "release-B.json", {"pid": pid, "scope_id": SCOPE_ID})
    except BaseException as error:
        result["error"] = type(error).__name__ + ":" + str(error)
        stop.set()


def run_case(index: int, case: str, counters: dict, campaign_sha: str, packet_sha: str,
             *, packet_path: Path | None = None) -> dict:
    case_started = time.monotonic()
    root = create_case_root(index)
    before = set()
    result = {"case": case, "case_root": root.relative_to(ROOT).as_posix(),
        "controller_pid": os.getpid(), "status": "started", "starts": 0,
        "observer_queries": 0}
    watcher_result = {}
    stop = threading.Event()
    thread = threading.Thread(target=watch_leaf, args=(root, before, watcher_result, stop), daemon=True)
    controller_nonce = secrets.token_hex(32)
    selected_packet = packet_path or ROOT / PACKET15
    command = [sys.executable, "-I", "tests/evidence/phase7_wrapper_return.py", "--owner", case, str(root),
        "--controller-pid", str(os.getpid()), "--controller-nonce", controller_nonce, "--packet",
        str(selected_packet.relative_to(ROOT)),
        "--campaign", "build/v02/campaign15/campaign.json",
        "--campaign-sha256", campaign_sha]
    outer = importlib.util.spec_from_file_location("return_phase5", ROOT / "scripts/evidence/phase5_process.py")
    process_module = importlib.util.module_from_spec(outer)
    outer.loader.exec_module(process_module)
    receipts = []
    original_popen, run_counters = install_start_counter(
        LIMITS["controller_start_events_per_case"], LIMITS["observer_queries_per_case"])
    thread.start()
    try:
        with process_module.receipt_file(root, Path("controller/process.json")) as receipt_stream:
            def creation(receipt):
                pid = receipt.get("pid")
                if type(pid) is not int or receipt.get("pgid") != pid:
                    raise ValueError("return-owner-creation-receipt-invalid")
                snapshot = observer_snapshot(pid)
                observed = snapshot.get("identity")
                if (observed is None or observed.get("pid") != pid or observed.get("pgid") != pid
                        or not observed.get("birth") or observed.get("state", "").startswith("Z")
                        or type(snapshot.get("rss_bytes")) is not int):
                    raise ValueError("return-owner-not-active-at-creation")
                result["owner_birth"] = {**observed, "rss_bytes": snapshot["rss_bytes"]}
                write_record(root / "release-A.json", {"pid": pid, "scope_id": SCOPE_ID,
                    "case": case, "controller_pid": os.getpid(), "controller_nonce": controller_nonce,
                    "packet_sha256": packet_sha,
                    "campaign_sha256": campaign_sha})
            prior_context = os.environ.get("GENEWHIP_PROCESS_CONTEXT")
            try:
                os.environ["GENEWHIP_PROCESS_CONTEXT"] = "host-cleanup-v1"
                completed = process_module.run(command, cwd=ROOT,
                    timeout=LIMITS["owner_timeout_seconds"], cap=CAP,
                    runs=receipts, process_receipt_stream=receipt_stream,
                    ownership_callback=creation)
            except BaseException as error:
                stop.set()
                result.update(status="failed", error=type(error).__name__ + ":" + str(error),
                              owner_receipts=receipts)
            else:
                result.update(status="pass" if completed.returncode == 0 else "failed",
                    returncode=completed.returncode, owner_receipts=receipts)
            finally:
                if prior_context is None:
                    os.environ.pop("GENEWHIP_PROCESS_CONTEXT", None)
                else:
                    os.environ["GENEWHIP_PROCESS_CONTEXT"] = prior_context
        thread.join(timeout=2)
        if thread.is_alive():
            result.update(status="failed", error="return-observer-thread-unsettled")
            stop.set()
        result.update(watcher_result)
        owner_pid = result.get("owner_birth", {}).get("pid")
        if owner_pid is None and receipts:
            owner_pid = receipts[0].get("pid")
        leaf_pid = result.get("leaf_birth", {}).get("pid")
        candidate = receipt_candidate(root, before)
        if leaf_pid is None and candidate is not None:
            leaf_pid = candidate[1].get("pid")
        if type(owner_pid) is int:
            settled = observer_snapshot(owner_pid)
            result["owner_final_observation"] = settled
            if settled["identity"] is None and not settled["group_members"]:
                result["owner_settled"] = True
            else:
                result.update(status="failed", error=result.get("error", "return-owner-group-not-absent"))
        if type(leaf_pid) is int:
            leaf_settled = observer_snapshot(leaf_pid)
            result["leaf_final_observation"] = leaf_settled
            if leaf_settled["identity"] is None and not leaf_settled["group_members"]:
                result["leaf_settled"] = True
            else:
                result.update(status="failed", error=result.get("error", "return-leaf-group-not-absent"))
        controller_receipt_path = root / "controller/process.json"
        if controller_receipt_path.is_file() and not controller_receipt_path.is_symlink():
            controller_receipt = safe_json(controller_receipt_path)
            rows = controller_receipt.get("processes") if isinstance(controller_receipt, dict) else None
            if (not isinstance(rows, list) or len(rows) != 1
                    or rows[0].get("pid") != owner_pid or rows[0].get("pgid") != owner_pid
                    or rows[0].get("process_group_cleanup") != "confirmed"):
                result.update(status="failed", error=result.get("error", "return-controller-receipt-mismatch"))
            result.update(controller_receipt_path=controller_receipt_path.relative_to(ROOT).as_posix(),
                controller_receipt_sha256=sha(controller_receipt_path))
        else:
            result.update(status="failed", error=result.get("error", "return-controller-receipt-missing"))
        wrapper_result_path = root / "owner-work/wrapper-result.json"
        if wrapper_result_path.is_file() and not wrapper_result_path.is_symlink():
            wrapper_result = safe_json(wrapper_result_path)
            inner = wrapper_result.get("receipt") if isinstance(wrapper_result, dict) else None
            expected_wrapper = "shared_launch" if case == "shared_launch" else "_bounded_command"
            if (not isinstance(inner, dict) or inner.get("pid") != leaf_pid
                    or inner.get("pgid") != leaf_pid
                    or inner.get("process_group_cleanup") != "confirmed"
                    or wrapper_result.get("wrapper") != expected_wrapper
                    or wrapper_result.get("returncode") != 0):
                result.update(status="failed", error=result.get("error", "return-wrapper-receipt-mismatch"))
            result.update(wrapper_result_path=wrapper_result_path.relative_to(ROOT).as_posix(),
                wrapper_result_sha256=sha(wrapper_result_path))
        else:
            result.update(status="failed", error=result.get("error", "return-wrapper-result-missing"))
        leaf_receipt_path = (ROOT / watcher_result["leaf_receipt"]
            if watcher_result.get("leaf_receipt") else None)
        if leaf_receipt_path is not None and leaf_receipt_path.is_file() and not leaf_receipt_path.is_symlink():
            result["leaf_receipt_sha256"] = sha(leaf_receipt_path)
        else:
            result.update(status="failed", error=result.get("error", "return-leaf-receipt-missing"))
        for key in ("release-A.json", "release-B.json"):
            gate_path = root / key
            if gate_path.is_file() and not gate_path.is_symlink():
                result[key.replace(".json", "_sha256")] = sha(gate_path)
                result[key.replace(".json", "_path")] = gate_path.relative_to(ROOT).as_posix()
            else:
                result.update(status="failed", error=result.get("error", "return-case-gate-missing"))
        owner_gate = safe_json(root / "release-A.json") if (root / "release-A.json").is_file() and not (root / "release-A.json").is_symlink() else None
        leaf_gate = safe_json(root / "release-B.json") if (root / "release-B.json").is_file() and not (root / "release-B.json").is_symlink() else None
        if (owner_gate != {"pid": owner_pid, "scope_id": SCOPE_ID, "case": case,
                "controller_pid": os.getpid(), "controller_nonce": controller_nonce,
                "packet_sha256": packet_sha, "campaign_sha256": campaign_sha}
                or leaf_gate != {"pid": leaf_pid, "scope_id": SCOPE_ID}):
            result.update(status="failed", error=result.get("error", "return-case-gate-binding-invalid"))
        try:
            owner_count_path = root / "owner-process-count.json"
            owner_counts = safe_json(owner_count_path)
            result.update(owner_process_count_path=owner_count_path.relative_to(ROOT).as_posix(),
                owner_process_count_sha256=sha(owner_count_path))
        except (OSError, ValueError, json.JSONDecodeError):
            owner_counts = {"starts": 0, "status_helper_starts": 0,
                "rss_observations": 0, "wrapper_calls": 0}
            result.update(status="failed", error=result.get("error", "return-owner-process-count-missing-or-invalid"))
        total_starts = run_counters["starts"] + owner_counts["starts"]
        status_starts = run_counters["status_helper_starts"] + owner_counts["status_helper_starts"]
        rss_samples = owner_counts["rss_observations"] + run_counters["rss_samples"]
        owner_rss = result.get("owner_birth", {}).get("rss_bytes")
        leaf_rss = result.get("leaf_birth", {}).get("rss_bytes")
        if (total_starts > MAX_STARTS_PER_CASE
                or run_counters["observer_queries"] > MAX_OBSERVER_QUERIES_PER_CASE
                or rss_samples > MAX_RSS_SAMPLES_PER_CASE
                or status_starts > MAX_STATUS_STARTS_PER_CASE
                or owner_counts.get("wrapper_calls") != 1
                or owner_counts.get("starts", 0) <= 0):
            result.update(status="failed", error=result.get("error", "return-diagnostic-count-ceiling"))
        if (owner_rss is not None and (type(owner_rss) is not int or owner_rss > 268435456)
                or leaf_rss is not None and (type(leaf_rss) is not int or leaf_rss > 268435456)
                or type(owner_rss) is int and type(leaf_rss) is int
                   and owner_rss + leaf_rss > 536870912):
            result.update(status="failed", error=result.get("error", "return-rss-observation-invalid-or-over-limit"))
        if (watcher_result.get("error") or not result.get("owner_settled")
                or not result.get("leaf_settled") or not result.get("owner_birth")
                or not result.get("leaf_birth") or result.get("returncode") != 0
                or run_counters["starts"] <= 0
                or owner_counts.get("starts", 0) <= 0):
            result.update(status="failed", error=result.get("error", "return-case-incomplete-before-next-case"))
        result.update(starts=total_starts, status_helper_starts=status_starts,
            controller_starts=run_counters["starts"], owner_starts=owner_counts["starts"],
            observer_queries=run_counters["observer_queries"], rss_samples=rss_samples,
            owner_rss_samples=owner_counts["rss_observations"],
            observer_rss_samples=run_counters["rss_samples"],
            rss_bytes={"owner": owner_rss, "leaf": leaf_rss})
        result["case_elapsed_seconds"] = time.monotonic() - case_started
        if result["case_elapsed_seconds"] > LIMITS["controller_timeout_seconds"]:
            result.update(status="failed", error=result.get("error", "return-controller-wall-limit"))
        write_record(root / "case-result.json", result)
        return result
    finally:
        subprocess.Popen = original_popen
        if RUN_COUNTS is run_counters:
            globals()["RUN_COUNTS"] = None


def run_selected(packet_path: Path, campaign_path: Path, out: Path):
    packet, _review = validate_packet_for_entry(packet_path)
    attempt_number = packet.get("resume_campaign", {}).get("attempt_number", 1)
    if attempt_number not in (1, 2, 3, 4):
        raise ValueError("return-corrected-attempt-selector-invalid")
    out = out if out.is_absolute() else ROOT / out
    campaign_path = campaign_path if campaign_path.is_absolute() else ROOT / campaign_path
    if Path(os.path.abspath(out)) != Path(os.path.abspath(ROOT / "build/v02/recovery15/live.json")):
        raise ValueError("return-live-output-path-invalid")
    if Path(os.path.abspath(campaign_path)) != Path(os.path.abspath(ROOT / "build/v02/campaign15/campaign.json")):
        raise ValueError("return-campaign-path-invalid")
    require_clean_host_environment()
    root = ROOT / "build/v02/recovery15"
    ensure_owned_tree_path(root.parent)
    ensure_owned_tree_path(ROOT / "build/v02/campaign15", may_create_leaf=True)
    coordinator_spec = importlib.util.spec_from_file_location("return_campaign_coordinator",
        ROOT / "scripts/release/v02_qualification.py")
    coordinator = importlib.util.module_from_spec(coordinator_spec)
    coordinator_spec.loader.exec_module(coordinator)
    attempt_entry_sha = None
    if campaign_path.exists() or campaign_path.is_symlink():
        started, campaign_sha, needs_archive = validate_prechild_resume_state(campaign_path, packet)
        if needs_archive:
            if packet.get("resume_campaign", {}).get("attempt_number") == 4:
                attempt_entry_path = consume_attempt4_invocation(packet, campaign_sha, started["started_at"])
                attempt_entry_sha = sha(ROOT / attempt_entry_path)
            elif packet.get("resume_campaign", {}).get("attempt_number") == 3:
                attempt_entry_path = consume_final_invocation(packet, campaign_sha, started["started_at"])
                attempt_entry_sha = sha(ROOT / attempt_entry_path)
                archive_failed_attempt2_and_prepare_recovery()
            else:
                attempt_entry_sha = consume_corrected_invocation(packet, campaign_sha, started["started_at"])
                archive_failed_attempt1_and_prepare_recovery()
    else:
        if packet.get("resume_campaign", {}).get("attempt_number") in (2, 3, 4):
            raise ValueError("return-campaign-required-for-corrected-attempt")
        if root.exists():
            if root.is_symlink() or not root.is_dir() or any(root.iterdir()):
                raise ValueError("return-owned-root-not-empty")
        else:
            root.mkdir(parents=True, mode=0o700)
        create_limits_lock(root)
        started, campaign_sha = create_campaign(campaign_path, packet)
    scope_path = ROOT / "evidence/v02-execution.json"
    coordinator._campaign_projection(campaign_path, scope_path,
        ROOT / started["journal_path"], phase="runtime", expected_sha256=campaign_sha,
        require_return=False, selection="16" if attempt_number == 4 else "15")
    coordinator._require_hosted_budget(started["started_at"],
        datetime.datetime.now(datetime.timezone.utc).isoformat(),
        json.loads(scope_path.read_text(encoding="utf-8")), phase="runtime")
    results = []
    diagnostic_started = time.monotonic()
    # First actual child is attempted immediately after the exclusive, fsynced start.
    for index, case in enumerate(("shared_launch", "bounded_command"), start=1):
        if time.monotonic() - diagnostic_started >= MAX_DIAGNOSTIC_SECONDS:
            raise TimeoutError("return-diagnostic-total-deadline-before-case")
        if attempt_number == 4:
            result = run_case(index, case, {}, campaign_sha, packet["packet_sha256"],
                packet_path=ROOT / PACKET16)
        else:
            result = run_case(index, case, {}, campaign_sha, packet["packet_sha256"])
        results.append(result)
        if result.get("status") != "pass":
            break
        if time.monotonic() - diagnostic_started >= MAX_DIAGNOSTIC_SECONDS:
            result.update(status="failed", error="return-diagnostic-total-deadline-exhausted")
            break
        if index == 1:
            remaining = coordinator._require_hosted_budget(
                started["started_at"], datetime.datetime.now(datetime.timezone.utc).isoformat(),
                json.loads(scope_path.read_text()), phase="runtime")
            if remaining <= 7200:
                result.update(status="failed", error="return-runtime-reserve-exhausted")
                break
    value = {"schema": SCHEMA, "status": "pass" if len(results) == 2 and all(
        row.get("status") == "pass" and row.get("owner_settled") and row.get("leaf_settled")
        for row in results) else "failed", "campaign": "build/v02/campaign15/campaign.json",
        "campaign_sha256": campaign_sha, "started_at": started["started_at"],
        "cases": results, "source_pins": packet["sources"],
        "packet_sha256": packet["packet_sha256"], "review_sha256": sha(_review),
        "attempt_number": packet.get("resume_campaign", {}).get("attempt_number", 1),
        "attempt_entry_path": ("build/v02/campaign15/attempt4-started.json"
            if attempt_number == 4 else "build/v02/campaign15/attempt3-started.json"
            if attempt_number == 3
            else "build/v02/campaign15/attempt2-started.json"),
        "attempt_entry_sha256": attempt_entry_sha,
        "diagnostic_elapsed_seconds": time.monotonic() - diagnostic_started,
        "historical_identity_liveness": "UNKNOWN", "historical_T-07-07": "OPEN/high",
        "requirements_qualified": []}
    if (attempt_number == 4 or len(results) == 2 and all(row.get("status") == "pass" for row in results)):
        archived = check_owned_tree(ROOT / "build/v02/recovery15-attempt1",
            byte_cap=4 * 1024 * 1024, entry_cap=LIMITS["maximum_tree_entries"])
        if attempt_number in (3, 4):
            archived2 = check_owned_tree(ROOT / "build/v02/recovery15-attempt2",
                byte_cap=4 * 1024 * 1024, entry_cap=LIMITS["maximum_tree_entries"])
            archived_bytes = archived["bytes"] + archived2["bytes"]
        else:
            archived_bytes = archived["bytes"]
        active_before_live = check_owned_tree(root,
            byte_cap=LIMITS["aggregate_retained_bytes"],
            entry_cap=LIMITS["maximum_tree_entries"] * 2 + 3)
        wrapper_calls = 0
        for row in results:
            count_path = row.get("owner_process_count_path")
            if isinstance(count_path, str) and (ROOT / count_path).is_file():
                owner_count = safe_json(ROOT / count_path)
                wrapper_calls += require_bounded_count(owner_count.get("wrapper_calls"), 1,
                    "owner_receipt_wrapper_calls")
        value["cumulative_accounting"] = validate_campaign_usage(results,
            wrapper_calls, value["diagnostic_elapsed_seconds"], archived_bytes,
            active_before_live["bytes"] + CAP, attempt_number=attempt_number)
    write_record(out, value)
    print("phase7-wrapper-return: " + value["status"] + "; cases=" + str(len(results)))
    return 0 if value["status"] == "pass" else 1


def verify_live(evidence_path: Path):
    evidence = safe_json(evidence_path)
    if evidence.get("schema") != SCHEMA or evidence.get("status") != "pass":
        raise ValueError("return-live-evidence-invalid")
    cases = evidence.get("cases")
    if not isinstance(cases, list) or [row.get("case") for row in cases] != LIMITS["case_roster"]:
        raise ValueError("return-case-roster-invalid")
    if len(cases) != len(LIMITS["case_roster"]):
        raise ValueError("return-case-count-invalid")
    validate_live_case_roster(cases)
    observed_identities = set()
    for row in cases:
        if (row.get("status") != "pass" or row.get("returncode") != 0
                or not row.get("owner_settled") or not row.get("leaf_settled")
                or not row.get("owner_birth") or not row.get("leaf_birth")):
            raise ValueError("return-live-case-not-independently-settled")
        elapsed = row.get("case_elapsed_seconds")
        if (type(elapsed) not in (int, float) or isinstance(elapsed, bool)
                or not math.isfinite(elapsed) or elapsed < 0
                or elapsed > LIMITS["controller_timeout_seconds"]):
            raise ValueError("return-live-case-wall-limit-invalid")
        counts = {
            "starts": require_bounded_count(row.get("starts"), MAX_STARTS_PER_CASE, "starts"),
            "observer_queries": require_bounded_count(row.get("observer_queries"), MAX_OBSERVER_QUERIES_PER_CASE, "observer_queries"),
            "rss_samples": require_bounded_count(row.get("rss_samples"), MAX_RSS_SAMPLES_PER_CASE, "rss_samples"),
            "owner_rss_samples": require_bounded_count(row.get("owner_rss_samples"), MAX_OWNER_RSS_PER_CASE, "owner_rss_samples"),
            "observer_rss_samples": require_bounded_count(row.get("observer_rss_samples"), MAX_OBSERVER_RSS_PER_CASE, "observer_rss_samples"),
            "controller_starts": require_bounded_count(row.get("controller_starts"), LIMITS["controller_start_events_per_case"], "controller_starts"),
            "owner_starts": require_bounded_count(row.get("owner_starts"), LIMITS["owner_start_events_per_case"], "owner_starts"),
            "status_helper_starts": require_bounded_count(row.get("status_helper_starts"), MAX_STATUS_STARTS_PER_CASE, "status_helper_starts"),
        }
        rss = row.get("rss_bytes")
        if not isinstance(rss, dict):
            raise ValueError("return-live-rss-shape-invalid")
        require_bounded_count(rss.get("owner"), LIMITS["rss_limit_bytes_per_process"], "owner_rss_bytes")
        require_bounded_count(rss.get("leaf"), LIMITS["rss_limit_bytes_per_process"], "leaf_rss_bytes")
        owner = row["owner_birth"]
        leaf = row["leaf_birth"]
        if any(type(identity.get("pid")) is not int or identity.get("pgid") != identity.get("pid")
                or not identity.get("birth") or identity.get("state", "").startswith("Z")
                for identity in (owner, leaf)):
            raise ValueError("return-live-creation-identity-invalid")
        identities = [owner, leaf]
        if any(row["controller_pid"] == identity["pid"] for identity in identities):
            raise ValueError("return-live-controller-identity-collision")
        for identity in identities:
            key = (identity["pid"], identity["birth"])
            if key in observed_identities:
                raise ValueError("return-live-process-identity-reused")
            observed_identities.add(key)
        validate_final_observation(row.get("owner_final_observation"), owner["pid"])
        validate_final_observation(row.get("leaf_final_observation"), leaf["pid"])
        for path_key, digest_key in (("controller_receipt_path", "controller_receipt_sha256"),
                                     ("wrapper_result_path", "wrapper_result_sha256"),
                                     ("leaf_receipt", "leaf_receipt_sha256"),
                                     ("owner_process_count_path", "owner_process_count_sha256")):
            artifact = ROOT / row.get(path_key, "")
            if (not row.get(path_key) or artifact.is_symlink() or not artifact.is_file()
                    or sha(artifact) != row.get(digest_key)):
                raise ValueError("return-live-durable-receipt-invalid")
        controller_receipt = safe_json(ROOT / row["controller_receipt_path"])
        owner_counts = safe_json(ROOT / row["owner_process_count_path"])
        owner_count_starts = require_bounded_count(owner_counts.get("starts"),
            LIMITS["owner_start_events_per_case"], "owner_receipt_starts")
        owner_count_status = require_bounded_count(owner_counts.get("status_helper_starts"),
            LIMITS["owner_start_events_per_case"], "owner_receipt_status_helpers")
        owner_count_rss = require_bounded_count(owner_counts.get("rss_observations"),
            MAX_OWNER_RSS_PER_CASE, "owner_receipt_rss_samples")
        owner_wrapper_calls = require_bounded_count(owner_counts.get("wrapper_calls"), 1,
            "owner_receipt_wrapper_calls")
        controller_rows = controller_receipt.get("processes")
        wrapper_result = safe_json(ROOT / row["wrapper_result_path"])
        validate_wrapper_result_identity(row["case"], wrapper_result,
            evidence.get("campaign_sha256"), evidence.get("packet_sha256"))
        inner_receipt = wrapper_result.get("receipt")
        leaf_receipt = safe_json(ROOT / row["leaf_receipt"])
        leaf_rows = leaf_receipt.get("processes")
        if (not isinstance(controller_rows, list) or len(controller_rows) != 1
                or controller_rows[0].get("pid") != owner["pid"]
                or controller_rows[0].get("pgid") != owner["pid"]
                or owner.get("pgid") != controller_rows[0].get("pgid")
                or controller_rows[0].get("process_group_cleanup") != "confirmed"
                or owner_wrapper_calls != 1
                or owner_count_starts != row.get("owner_starts")
                or owner_count_status > row.get("status_helper_starts")
                or owner_count_rss != row.get("owner_rss_samples")
                or not isinstance(inner_receipt, dict) or inner_receipt.get("pid") != leaf["pid"]
                or inner_receipt.get("pgid") != leaf["pid"]
                or leaf.get("pgid") != inner_receipt.get("pgid")
                or inner_receipt.get("process_group_cleanup") != "confirmed"
                or not isinstance(leaf_rows, list) or len(leaf_rows) != 1
                or leaf_rows[0].get("pid") != leaf["pid"]
                or leaf_rows[0].get("pgid") != leaf["pid"]
                or leaf_rows[0].get("process_group_cleanup") != "confirmed"):
            raise ValueError("return-live-receipt-accounting-invalid")
        if (owner_counts.get("case") != row["case"]
                or owner_counts.get("campaign_sha256") != evidence.get("campaign_sha256")
                or owner_counts.get("packet_sha256") != evidence.get("packet_sha256")):
            raise ValueError("return-live-owner-count-binding-invalid")
        for key in ("release-A_sha256", "release-B_sha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", str(row.get(key, ""))):
                raise ValueError("return-live-gate-record-missing")
        release_a_path = ROOT / row["release-A_path"]
        release_b_path = ROOT / row["release-B_path"]
        release_a = safe_json(release_a_path)
        release_b = safe_json(release_b_path)
        if (sha(release_a_path) != row["release-A_sha256"]
                or sha(release_b_path) != row["release-B_sha256"]
                or release_a != {"pid": owner["pid"], "scope_id": SCOPE_ID,
                    "case": row["case"], "controller_pid": row["controller_pid"],
                    "controller_nonce": release_a.get("controller_nonce"),
                    "packet_sha256": evidence.get("packet_sha256"),
                    "campaign_sha256": evidence.get("campaign_sha256")}
                or not re.fullmatch(r"[0-9a-f]{64}", str(release_a.get("controller_nonce", "")))
                or release_b != {"pid": leaf["pid"], "scope_id": SCOPE_ID}):
            raise ValueError("return-live-case-gate-binding-invalid")
    if (sum(require_bounded_count(row.get("starts"), MAX_STARTS_PER_CASE, "starts") for row in cases) > MAX_STARTS_TOTAL
            or sum(require_bounded_count(row.get("observer_queries"), MAX_OBSERVER_QUERIES_PER_CASE, "observer_queries") for row in cases) > LIMITS["observer_queries_total"]
            or sum(require_bounded_count(row.get("rss_samples"), MAX_RSS_SAMPLES_PER_CASE, "rss_samples") for row in cases) > LIMITS["rss_samples_total"]):
        raise ValueError("return-live-aggregate-count-ceiling")
    attempt_number = evidence.get("attempt_number")
    if attempt_number not in (3, 4):
        raise ValueError("return-live-attempt-entry-missing")
    packet, review_path = validate_packet_for_entry(ROOT / (PACKET16 if attempt_number == 4 else PACKET15))
    campaign_path = ROOT / "build/v02/campaign15/campaign.json"
    campaign = safe_json(campaign_path)
    coordinator_spec = importlib.util.spec_from_file_location("return_verify_coordinator",
        ROOT / "scripts/release/v02_qualification.py")
    coordinator = importlib.util.module_from_spec(coordinator_spec)
    coordinator_spec.loader.exec_module(coordinator)
    campaign_sha = sha(campaign_path)
    coordinator._campaign_projection(campaign_path, ROOT / "evidence/v02-execution.json",
        ROOT / campaign.get("journal_path", ""), phase="runtime",
        expected_sha256=campaign_sha, require_return=False,
        selection="16" if attempt_number == 4 else "15",
        allow_live_evidence=attempt_number == 4)
    if (evidence.get("source_pins") != packet.get("sources")
            or evidence.get("packet_sha256") != packet["packet_sha256"]
            or evidence.get("review_sha256") != sha(review_path)
            or evidence.get("campaign_sha256") != campaign_sha
            or evidence.get("started_at") != campaign.get("started_at")
            or evidence.get("campaign") != "build/v02/campaign15/campaign.json"
            or evidence.get("historical_identity_liveness") != "UNKNOWN"
            or evidence.get("historical_T-07-07") != "OPEN/high"
            or evidence.get("requirements_qualified") != []):
        raise ValueError("return-live-current-pin-mismatch")
    marker_path = ("build/v02/campaign15/attempt4-started.json" if attempt_number == 4
                   else "build/v02/campaign15/attempt3-started.json")
    if (evidence.get("attempt_entry_path") != marker_path
            or not re.fullmatch(r"[0-9a-f]{64}", str(evidence.get("attempt_entry_sha256", "")))):
        raise ValueError("return-live-attempt-entry-missing")
    marker = ROOT / evidence["attempt_entry_path"]
    if marker.is_symlink() or not marker.is_file() or sha(marker) != evidence["attempt_entry_sha256"]:
        raise ValueError("return-live-attempt-entry-stale")
    marker_doc = safe_json(marker)
    marker_digest = marker_doc.pop("record_sha256", None)
    expected_cumulative = ATTEMPT4_CUMULATIVE_LIMITS if attempt_number == 4 else CUMULATIVE_LIMITS
    if (marker_doc.get("attempt") != attempt_number
            or marker_doc.get("campaign_sha256") != campaign_sha
            or marker_doc.get("campaign_started_at") != campaign.get("started_at")
            or marker_doc.get("packet_sha256") != packet["packet_sha256"]
            or marker_doc.get("cumulative_limits") != expected_cumulative
            or hashlib.sha256(json.dumps(marker_doc, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest() != marker_digest):
        raise ValueError("return-live-attempt-entry-binding-invalid")
    elapsed = evidence.get("diagnostic_elapsed_seconds")
    if type(elapsed) not in (int, float) or isinstance(elapsed, bool) or not math.isfinite(elapsed):
        raise ValueError("return-live-diagnostic-elapsed-invalid")
    archive1 = check_owned_tree(ROOT / "build/v02/recovery15-attempt1",
        byte_cap=4 * 1024 * 1024, entry_cap=LIMITS["maximum_tree_entries"])
    archive2 = check_owned_tree(ROOT / "build/v02/recovery15-attempt2",
        byte_cap=4 * 1024 * 1024, entry_cap=LIMITS["maximum_tree_entries"])
    active = check_owned_tree(ROOT / "build/v02/recovery15",
        byte_cap=LIMITS["aggregate_retained_bytes"],
        entry_cap=LIMITS["maximum_tree_entries"] * 2 + 3)
    accounting = evidence.get("cumulative_accounting")
    if not isinstance(accounting, dict):
        raise ValueError("return-live-cumulative-accounting-missing")
    current = accounting.get("current_attempt", {})
    active_reserve = current.get("retained_bytes_reserved")
    if type(active_reserve) is not int or active["bytes"] > active_reserve:
        raise ValueError("return-live-cumulative-retention-reserve-invalid")
    wrapper_calls = sum(require_bounded_count(safe_json(ROOT / row["owner_process_count_path"])
        .get("wrapper_calls"), 1, "owner_receipt_wrapper_calls") for row in cases)
    expected_accounting = validate_campaign_usage(cases, wrapper_calls, elapsed,
        archive1["bytes"] + archive2["bytes"], active_reserve,
        attempt_number=attempt_number)
    if accounting != expected_accounting:
        raise ValueError("return-live-cumulative-accounting-mismatch")
    print("phase7-wrapper-return: live evidence verified; historical UNKNOWN retained")
    return 0


def validate_live_case_roster(cases):
    if not isinstance(cases, list) or [row.get("case") for row in cases] != LIMITS["case_roster"]:
        raise ValueError("return-case-roster-invalid")
    roots = ["build/v02/recovery15/case-1", "build/v02/recovery15/case-2"]
    for index, row in enumerate(cases):
        root = roots[index]
        expected_paths = {
            "controller_receipt_path": root + "/controller/process.json",
            "wrapper_result_path": root + "/owner-work/wrapper-result.json",
            "owner_process_count_path": root + "/owner-process-count.json",
            "release-A_path": root + "/release-A.json",
            "release-B_path": root + "/release-B.json",
        }
        if row.get("case_root") != root or any(row.get(key) != value for key, value in expected_paths.items()):
            raise ValueError("return-live-case-path-binding-invalid")
        leaf_receipt = row.get("leaf_receipt")
        if (not isinstance(leaf_receipt, str) or Path(leaf_receipt).is_absolute()
                or ".." in Path(leaf_receipt).parts
                or not leaf_receipt.startswith(root + "/owner-work/")):
            raise ValueError("return-live-leaf-path-binding-invalid")
        if type(row.get("controller_pid")) is not int or row["controller_pid"] <= 0:
            raise ValueError("return-live-controller-identity-invalid")


def validate_wrapper_result_identity(case, wrapper_result, campaign_sha, packet_sha):
    expected = {"shared_launch": "shared_launch", "bounded_command": "_bounded_command"}.get(case)
    if (expected is None or not isinstance(wrapper_result, dict)
            or wrapper_result.get("wrapper") != expected
            or wrapper_result.get("case") != case
            or wrapper_result.get("campaign_sha256") != campaign_sha
            or wrapper_result.get("packet_sha256") != packet_sha
            or wrapper_result.get("returncode") != 0):
        raise ValueError("return-live-wrapper-identity-invalid")


def validate_final_observation(observation, expected_pid):
    if (not isinstance(observation, dict)
            or observation.get("pid") != expected_pid
            or observation.get("query") != LIMITS["observer_argv"]
            or observation.get("identity") is not None
            or observation.get("group_members") != []
            or type(observation.get("bytes")) is not int
            or observation["bytes"] < 0 or observation["bytes"] > LIMITS["status_query_output_bytes"]
            or not re.fullmatch(r"[0-9a-f]{64}", str(observation.get("status_sha256", "")))):
        raise ValueError("return-live-final-absence-observation-invalid")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--entry-check", action="store_true")
    parser.add_argument("--run-selected", action="store_true")
    parser.add_argument("--verify-live", action="store_true")
    parser.add_argument("--packet", type=Path)
    parser.add_argument("--campaign", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--owner", nargs=2, metavar=("CASE", "ROOT"))
    parser.add_argument("--controller-pid", type=int)
    parser.add_argument("--controller-nonce")
    parser.add_argument("--campaign-sha256")
    parser.add_argument("--leaf", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.entry_check:
            if args.packet is None:
                raise ValueError("return-packet-required")
            packet, _review = validate_packet_for_entry(args.packet)
            campaign = ROOT / "build/v02/campaign15/campaign.json"
            recovery = ROOT / "build/v02/recovery15"
            ensure_owned_tree_path(ROOT / "build/v02/campaign15", may_create_leaf=True)
            ensure_owned_tree_path(recovery, may_create_leaf=True)
            if campaign.exists() or campaign.is_symlink() or recovery.exists():
                if not campaign.is_file() or campaign.is_symlink():
                    raise ValueError("return-entry-output-already-present")
                validate_prechild_resume_state(campaign, packet)
                print("phase7-wrapper-return: preserved pre-child campaign verified; no child started")
                return 0
            print("phase7-wrapper-return: entry-check passed; no child started")
            return 0
        if args.run_selected:
            if args.packet is None or args.campaign is None or args.out is None:
                raise ValueError("return-live-arguments-required")
            return run_selected(args.packet, args.campaign, args.out)
        if args.verify_live:
            if args.evidence is None:
                raise ValueError("return-live-evidence-required")
            return verify_live(args.evidence)
        if args.owner:
            case, root = args.owner
            if (case not in ("shared_launch", "bounded_command") or args.controller_pid is None
                    or args.campaign is None or args.campaign_sha256 is None
                    or args.controller_nonce is None
                    or args.packet is None):
                raise ValueError("return-owner-authority-arguments-invalid")
            return owner(case, root=Path(root), controller_pid=args.controller_pid,
                controller_nonce=args.controller_nonce, packet_path=args.packet, campaign_path=args.campaign,
                campaign_sha256=args.campaign_sha256)
        if args.leaf is not None:
            return leaf(args.leaf)
        parser.error("select --entry-check, --run-selected, --verify-live, --owner, or --leaf")
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError,
            subprocess.SubprocessError, RuntimeError, TimeoutError) as error:
        print("REJECT: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

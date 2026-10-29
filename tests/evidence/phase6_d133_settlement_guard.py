"""D133 source-pinned capability guard; no project compile before denial probes.

An accidental-execution boundary, not a sandbox for hostile Python source.
"""
import argparse
import base64
import builtins
import contextlib
import copy
import collections
import datetime
import decimal
import fcntl
import gettext
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import re
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import types
import typing
import traceback
import textwrap
import _colorize
import __future__

# A bounded English error formatter needs no locale filesystem reads after
# denial. Argparse imported these aliases directly; replace the aliases too.
_ENGLISH = gettext.NullTranslations()
argparse._ = _ENGLISH.gettext
argparse.ngettext = _ENGLISH.ngettext

SOURCE_NAMES = ("scripts/evidence/phase6_accounting.py",
    "scripts/evidence/phase6_settlement.py", "tests/fixtures/phase6_repairs.py",
    "tests/evidence/test_phase6_policy_settlement.py",
    "tests/evidence/phase6_d133_settlement_guard.py")
PHASE = ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/"
APPROVAL_NAME = PHASE + "06-D133-APPROVAL.json"
ENTRY_NAME = PHASE + "06-D133-ENTRY.json"
ALLOWED_IMPORTS = frozenset(("__future__", "argparse", "datetime", "contextlib",
    "decimal", "fcntl", "hashlib", "importlib.util", "json", "math", "os",
    "pathlib", "re", "stat", "subprocess", "sys", "tempfile", "time", "typing",
    "io", "_io", "copy", "collections", "collections.abc", "shutil", "textwrap", "_colorize"))

class GuardDenied(RuntimeError):
    pass

class GuardDeadline(BaseException):
    pass

def digest(data):
    return hashlib.sha256(data).hexdigest()

def require(condition, reason):
    if not condition:
        raise AssertionError(reason)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("clone", "live", "retained"), required=True)
    parser.add_argument("--case", choices=("tracer", "fault-matrix",
        "oracle-negative-controls", "settle-once", "commit-settlement",
        "recover-settlement", "read-current", "remaining", "recompute-receipt",
        "final-package"), required=True)
    parser.add_argument("--review-pin", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--admission")
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[2]
    phase = project / PHASE
    pin_path = Path(args.review_pin).resolve(strict=True)
    require(pin_path.parent == phase, "exact-independent-review-directory")
    pin_bytes = pin_path.read_bytes()
    pin = json.loads(pin_bytes)
    require(pin.get("decision") == "accepted" and pin.get("reviewer_identity"),
        "independent-review-required")
    require(pin.get("bootstrap_before_compile") is True, "review-bootstrap-required")
    require(args.case in pin.get("allowed_lanes", []),
        "independent-lane-admission-required")
    stages = {"clone": ("bootstrap-red", "completed-static-source-review"),
        "live": ("completed-prelive-review",),
        "retained": ("completed-final-result-review",)}
    require(pin.get("stage") in stages[args.mode], "independent-stage-admission")
    approved = pin.get("source_sha256", {})
    require(set(approved) == set(SOURCE_NAMES), "exact-source-roster-required")
    approval_bytes = (project / APPROVAL_NAME).read_bytes()
    approval = json.loads(approval_bytes)
    entry_bytes = (project / ENTRY_NAME).read_bytes()
    entry = json.loads(entry_bytes)
    require(digest(approval_bytes) == pin.get("approval_sha256") ==
        entry.get("approval_sha256"), "approval-pin")
    require(digest(entry_bytes) == pin.get("entry_sha256"), "entry-pin")
    require(entry.get("stage") == "SOURCE_OWNER_DISPATCH" and
        entry.get("admitted") is True and entry.get("boot_uuid") == approval.get("boot_uuid"),
        "actual-source-dispatch-required")
    snapshot = Path(approval["snapshot_path"])
    require(not snapshot.is_absolute() and ".." not in snapshot.parts and
        snapshot.parent == Path("build/phase6/d133-30"), "parent-snapshot-path")
    baseline = (project / snapshot).read_bytes()
    require(digest(baseline) == approval.get("entry_ledger_sha256"),
        "clone-entry-byte-identity")
    expected = approval["entry_object_sha256"]
    require(len(expected) == 68 and len(json.loads(baseline)) == 68,
        "clone-original68-roster")
    data_blobs = {project / APPROVAL_NAME: approval_bytes,
        project / ENTRY_NAME: entry_bytes, project / snapshot: baseline,
        pin_path: pin_bytes}
    expectations_path = phase / "06-30-SEMANTIC-EXPECTATIONS.md"
    data_blobs[expectations_path] = expectations_path.read_bytes()
    require(digest(data_blobs[expectations_path]) == pin.get("semantic_expectations_sha256"),
        "independent-expectations-pin")
    for name, wanted in (("06-30-PLAN.md", approval["plan_sha256"]),
            ("06-D133-SETTLEMENT-AMENDMENT.md", approval["amendment_sha256"])):
        path = phase / name
        data_blobs[path] = path.read_bytes()
        require(digest(data_blobs[path]) == wanted, "approved-plan-amendment-pin")
    source_review_bytes = pin_bytes
    if args.mode != "clone":
        source_path = phase / "06-30-SOURCE-REVIEW.json"
        source_review_bytes = source_path.read_bytes()
        data_blobs[source_path] = source_review_bytes
        source_review = json.loads(source_review_bytes)
        require(digest(source_review_bytes) == pin.get("source_review_sha256") and
            source_review.get("decision") == "accepted" and
            source_review.get("stage") == "completed-static-source-review" and
            source_review.get("source_sha256") == approved and
            source_review.get("frozen_rosters") == pin.get("frozen_rosters") and
            source_review.get("approval_sha256") == digest(approval_bytes),
            "completed-exact-source-review-required")
    authority_pins = {"approval": digest(approval_bytes), "entry": digest(entry_bytes),
        "plan": approval["plan_sha256"], "amendment": approval["amendment_sha256"],
        "source_review": digest(source_review_bytes)}
    reader_pin = {"schema": "d133-reader-pin-v1", "authority_pins": authority_pins,
        "source_sha256": approved}
    observation = {"boot_uuid": entry["boot_uuid"], "elapsed_seconds": 1.0,
        "observed_monotonic_seconds": entry["start_monotonic"] + 1.0}
    retained = {}
    def retained_blob(binding):
        relative = Path(binding["path"])
        require(not relative.is_absolute() and ".." not in relative.parts and
            relative.parent == Path(PHASE), "exact-retained-report-path")
        path = project / relative
        require(not path.is_symlink(), "retained-report-symlink")
        data = path.read_bytes()
        limit = 16777216 if relative.name == "06-30-PRELIVE-ADMISSION.json" else 2097152
        require(len(data) <= limit and digest(data) == binding.get("sha256"),
            "retained-report-sha256")
        data_blobs[path] = data
        return json.loads(data)

    if args.mode != "clone":
        require(pin.get("completed_clone_results") is True, "completed-clone-review-required")
        bindings = pin.get("result_reports", {})
        require(set(bindings) == {"tracer", "fault-matrix", "oracle-negative-controls"},
            "completed-three-clone-lanes-required")
        for lane, binding in bindings.items():
            result = retained_blob(binding)
            roster = pin.get("frozen_rosters", {}).get(lane)
            require(isinstance(roster, list) and roster and
                result.get("status") == "pass" and result.get("mode") == "clone" and
                result.get("lane") == lane and result.get("pins") == approved and
                result.get("snapshot_sha256") == digest(baseline) and
                result.get("review_pin_sha256") == digest(source_review_bytes) and
                result.get("denominator") == len(roster) == binding.get("denominator") and
                result.get("case_ids") == roster and
                [row.get("case_id") for row in result.get("cases", [])] == roster and
                all(row.get("status") == "pass" for row in result["cases"]),
                "complete-reviewed-clone-roster:" + lane)
            require(result.get("bootstrap_denials") == 32 and
                result.get("unexpected_denial_count") == 0 and
                len(result.get("denials", [])) == 32 and
                all(row.get("expected") is True for row in result["denials"]) and
                [row.get("probe_case_id") for row in result["denials"]] ==
                pin["frozen_rosters"].get("denial_probes"), "complete-clone-denials:" + lane)
            retained[lane] = result

    admission = None
    admission_bytes = None
    expected_post = None
    expected_receipt = None
    reader_path = None
    correction_path = phase / "06-D133-LOCK-LOCATION-APPROVAL.json"
    if args.mode == "live":
        require(args.case in ("settle-once", "commit-settlement", "recover-settlement",
            "read-current", "remaining", "recompute-receipt"), "exact-live-lane")
        require(args.output_root == "live" and args.admission is not None,
            "explicit-live-admission-required")
        admission_path = Path(args.admission).resolve(strict=True)
        require(admission_path == phase / "06-30-PRELIVE-ADMISSION.json",
            "exact-parent-admission-path")
        admission_bytes = admission_path.read_bytes()
        admission = json.loads(admission_bytes)
        data_blobs[admission_path] = admission_bytes
        require(admission.get("schema") == "d133-prelive-admission-v1" and
            admission.get("decision") == "admitted" and admission.get("parent_identity") and
            admission.get("approval_sha256") == digest(approval_bytes) and
            admission.get("entry_sha256") == digest(entry_bytes) and
            admission.get("source_review_sha256") == digest(source_review_bytes) and
            admission.get("prelive_review_sha256") == digest(pin_bytes) and
            admission.get("source_sha256") == approved and
            admission.get("baseline_sha256") == digest(baseline) and
            admission.get("expected_objects") == expected and
            admission.get("boot_uuid") == entry["boot_uuid"],
            "complete-parent-admission-identity")
        require(pin.get("permitted_observation_fields") ==
            ["elapsed_seconds", "observed_monotonic_seconds"],
            "bounded-observation-variance-only")
        correction_bytes = correction_path.read_bytes()
        correction = json.loads(correction_bytes)
        proposal_path = phase / "06-D133-LOCK-LOCATION-CORRECTION.md"
        proposal_bytes = proposal_path.read_bytes()
        data_blobs[correction_path] = correction_bytes
        data_blobs[proposal_path] = proposal_bytes
        require(digest(correction_bytes) == admission.get("correction_approval_sha256") and
            correction.get("decision") == "approved" and
            correction.get("original_approval_sha256") == digest(approval_bytes) and
            correction.get("proposal_sha256") == digest(proposal_bytes) and
            correction.get("lock_root") == "evidence/.d133-30-locks" and
            correction.get("no_budget_changes") is True, "actual-lock-correction-approval")
        record = admission["record"]
        require(digest(json.dumps(record, sort_keys=True, separators=(",", ":"),
            allow_nan=False).encode()) == admission.get("record_sha256"),
            "frozen-record-sha256")
        observation = record["policy_settlement"]["own_observation"]
        require(observation["boot_uuid"] == admission["boot_uuid"] and
            observation["elapsed_seconds"] == admission.get("elapsed_seconds") and
            observation["observed_monotonic_seconds"] ==
            admission.get("observed_monotonic_seconds"), "admitted-own-observation")
        expected_post = base64.b64decode(admission["expected_post_ledger_base64"], validate=True)
        expected_receipt = base64.b64decode(admission["expected_receipt_base64"], validate=True)
        require(digest(expected_post) == admission.get("expected_post_ledger_sha256") and
            digest(expected_receipt) == admission.get("expected_receipt_sha256"),
            "complete-expected-byte-transition")
        reader_relative = Path(admission["reader_pin_path"])
        require(reader_relative == Path("build/phase6/d133-30/live-reader-pin.json"),
            "exact-live-reader-pin-path")
        reader_path = project / reader_relative
        reader_bytes = reader_path.read_bytes()
        require(digest(reader_bytes) == admission.get("reader_pin_sha256") and
            json.loads(reader_bytes) == reader_pin, "live-reader-pin-identity")
        data_blobs[reader_path] = reader_bytes
        root = project / "evidence"
        require(not root.is_symlink() and root.resolve(strict=True) == root and
            not (root / ".d133-30-locks").is_symlink() and
            (root / ".d133-30-locks").is_dir(), "parent-prepared-live-directories")
    else:
        require(args.output_root == "temporary", "fresh-direct-temporary-sentinel-required")
        if args.mode == "clone":
            require(args.case in ("tracer", "fault-matrix", "oracle-negative-controls"),
                "clone-lane-required")
        else:
            require(args.case == "final-package" and
                pin.get("result_review_completed") is True and
                pin.get("parent_integrity_checked") is True,
                "completed-independent-final-review-required")
            for name in ("live_report", "prelive_review", "prelive_admission",
                    "postlive_review", "parent_integrity"):
                retained[name] = retained_blob(pin[name])
            require(retained["live_report"].get("status") == "pass" and
                retained["live_report"].get("mode") == "live" and
                retained["live_report"].get("pins") == approved and
                retained["live_report"].get("unexpected_denial_count") == 0 and
                retained["postlive_review"].get("decision") == "accepted" and
                retained["prelive_review"].get("decision") == "accepted",
                "actual-accepted-live-closeout-required")
            live = retained["live_report"]
            admitted = retained["prelive_admission"]
            correction_bytes = correction_path.read_bytes()
            correction = json.loads(correction_bytes)
            proposal_path = phase / "06-D133-LOCK-LOCATION-CORRECTION.md"
            proposal_bytes = proposal_path.read_bytes()
            data_blobs[correction_path] = correction_bytes
            data_blobs[proposal_path] = proposal_bytes
            require(digest(correction_bytes) == admitted["correction_approval_sha256"] and
                correction.get("decision") == "approved" and
                correction.get("original_approval_sha256") == digest(approval_bytes) and
                correction.get("proposal_sha256") == digest(proposal_bytes) and
                correction.get("lock_root") == "evidence/.d133-30-locks" and
                correction.get("no_budget_changes") is True,
                "retained-actual-correction-authority")
            require(live.get("admission_sha256") == pin["prelive_admission"]["sha256"] and
                live.get("review_pin_sha256") == pin["prelive_review"]["sha256"] and
                live.get("source_review_sha256") == digest(source_review_bytes) and
                live.get("snapshot_sha256") == digest(baseline) and
                live.get("bootstrap_denials") == 32 and
                [row.get("probe_case_id") for row in live.get("denials", [])] ==
                pin["frozen_rosters"]["denial_probes"] and
                all(row.get("expected") is True for row in live["denials"]) and
                live.get("case_ids") == ["live-settlement-current-readers"] and
                live.get("denominator") == 1 and len(live.get("cases", [])) == 1 and
                live["cases"][0].get("status") == "pass",
                "retained-complete-live-result")
            expected_live = base64.b64decode(admitted["expected_post_ledger_base64"], validate=True)
            expected_output = base64.b64decode(admitted["expected_receipt_base64"], validate=True)
            live_row = live["cases"][0]
            require(digest(expected_live) == admitted["expected_post_ledger_sha256"] ==
                live_row.get("ledger_sha256") and digest(expected_output) ==
                admitted["expected_receipt_sha256"] == live_row.get("receipt_sha256"),
                "retained-complete-live-byte-identities")
            live_value = json.loads(expected_live)
            require(set(live_value) == set(expected) | {"ledger_transactions_v1"} and
                all(digest(json.dumps(live_value[key], sort_keys=True, separators=(",", ":"),
                    allow_nan=False).encode()) == wanted for key, wanted in expected.items()),
                "retained-original68-identities")
            transactions = live_value["ledger_transactions_v1"]["transactions"]
            require(set(transactions) == {"D133-settlement30"} and
                transactions["D133-settlement30"]["record"] == admitted["record"] and
                transactions["D133-settlement30"]["receipt_bytes"].encode() == expected_output,
                "retained-one-policy-intent")
            view = live_row["view"]
            require(view.get("actual_total_status") == "unknown" and
                view.get("publication_state") == "published" and
                view.get("capacity_allowed") is True and
                view.get("purpose_allocations") == approval["cumulative_allocations"] and
                view.get("authority_pins") == authority_pins and
                view.get("source_sha256") == approved and
                view.get("actual_evidence") == admitted["record"]["policy_settlement"]["actual_evidence"] and
                set(live_row.get("actual_callers", {})) ==
                    {"coordinator", "read-current", "remaining", "recompute-receipt"} and
                all(reported == view for reported in live_row["actual_callers"].values()),
                "retained-actual-current-callers")
            with decimal.localcontext() as arithmetic:
                arithmetic.prec = 512
                posted = decimal.Decimal(approval["posted_actual_closed_seconds"])
                liabilities = sum((decimal.Decimal(str(v)) for v in approval["cumulative_allocations"].values()))
                reserve = decimal.Decimal(approval["protected_process_reserve_seconds"])
                ceiling = decimal.Decimal(str(approval["selected_global_ceiling"]))
                wanted_numbers = {"posted_actual_closed_seconds": posted,
                    "policy_liability_seconds": liabilities,
                    "policy_settled_exposure_seconds": posted + liabilities,
                    "protected_process_reserve_seconds": reserve,
                    "policy_remaining_seconds": ceiling - posted - liabilities,
                    "admissible_policy_headroom_seconds": ceiling - posted - liabilities - reserve}
                require(all(type(view.get(key)) in (int, float, str) and
                    decimal.Decimal(str(view[key])).is_finite() and
                    decimal.Decimal(str(view[key])) == wanted for key, wanted in wanted_numbers.items()),
                    "retained-exact-financial-values")
        root = Path(tempfile.mkdtemp(prefix="genewhip-d133-", dir=tempfile.gettempdir())).resolve()
        root_stat = root.stat()
        require(root.parent == Path(tempfile.gettempdir()).resolve() and
            stat.S_ISDIR(root_stat.st_mode), "fresh-direct-temporary-root")
    events = []
    expected_probe = [False]
    fds = {}
    fd_paths = {}
    source_paths = {project / name for name in SOURCE_NAMES}
    data_paths = set(data_blobs)
    live_ledger = project / "evidence/phase6-repairs.json"
    live_receipt = project / "evidence/phase6-d133-settlement30-receipt.json"
    live_locks = project / "evidence/.d133-30-locks"
    live_lock = live_locks / ("genewhip-phase6-accounting-" + digest(str(live_ledger).encode()) + ".lock")
    helper_trace = []
    real_open = os.open
    real_close = os.close
    raw_lstat = os.lstat
    raw_readlink = os.readlink
    raw_fstat = os.fstat
    real_import = builtins.__import__
    owned_temps = set()

    def deny(event):
        events.append({"event": event, "expected": expected_probe[0]})
        raise GuardDenied("guard-denied:" + event)

    def inside(path):
        return path == root or root in path.parents

    def resolved(raw, strict=False):
        # Use captured primitives only: patched Path.resolve/os.lstat would
        # recursively re-enter classification. These reads only classify the
        # requested path; callers receive no outside-root metadata.
        pending = list(Path(os.path.abspath(os.fsdecode(raw))).parts[1:])
        current = Path(os.path.sep)
        links = 0
        while pending:
            part = pending.pop(0)
            if part == "..":
                current = current.parent
                continue
            candidate = current / part
            try:
                info = raw_lstat(candidate)
            except FileNotFoundError:
                if strict:
                    raise
                current = candidate
                continue
            if stat.S_ISLNK(info.st_mode):
                links += 1
                require(links <= 40, "path-symlink-loop")
                target = Path(raw_readlink(candidate))
                if target.is_absolute():
                    current = Path(os.path.sep)
                    pending = list(target.parts[1:]) + pending
                else:
                    pending = list(target.parts) + pending
            else:
                current = candidate
        return current

    def checked_fd(fd):
        if fd not in fds:
            deny("unknown-fd")
        try:
            info = raw_fstat(fd)
        except OSError:
            deny("closed-fd")
        if (info.st_dev, info.st_ino) != fds[fd]:
            deny("reused-fd")

    def live_path(path, *, writing, admitted_root, authority):
        # This policy is also exercised with disposable roots before compile.
        ledger = admitted_root / "phase6-repairs.json"
        receipt = admitted_root / "phase6-d133-settlement30-receipt.json"
        locks = admitted_root / ".d133-30-locks"
        lock = locks / ("genewhip-phase6-accounting-" + digest(str(ledger).encode()) + ".lock")
        if authority is None:
            deny("live-authority-absent")
        if path in (ledger, receipt, lock):
            return
        if path in (admitted_root, locks) and not writing:
            return
        if writing and path.parent == admitted_root:
            live_capability(authority=authority, temporary=path.name)
            return
        deny("outside-live-write" if writing else "outside-live-read")

    def live_open_policy(path, flags, *, admitted_root, authority):
        if authority is None:
            deny("live-authority-absent")
        ledger = admitted_root / "phase6-repairs.json"
        receipt = admitted_root / "phase6-d133-settlement30-receipt.json"
        locks = admitted_root / ".d133-30-locks"
        lock = locks / ("genewhip-phase6-accounting-" + digest(str(ledger).encode()) + ".lock")
        # CPython audit open events add the descriptor-safety CLOEXEC bit.
        flags &= ~getattr(os, "O_CLOEXEC", 0)
        writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
        if not writing:
            live_path(path, writing=False, admitted_root=admitted_root, authority=authority)
            return
        if path == lock:
            required = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW
            if flags != required:
                deny("unsafe-live-lock-flags")
            return
        if path in (ledger, receipt):
            deny("direct-live-output-open")
        if path.parent != admitted_root:
            deny("outside-live-write")
        live_capability(authority=authority, temporary=path.name)
        required = os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_RDWR
        if flags != required:
            deny("unsafe-live-temp-flags")

    def live_mutation_policy(event, values, *, admitted_root, authority, owned):
        if authority is None:
            deny("live-authority-absent")
        ledger = admitted_root / "phase6-repairs.json"
        receipt = admitted_root / "phase6-d133-settlement30-receipt.json"
        locks = admitted_root / ".d133-30-locks"
        if isinstance(values[0], int):
            checked_fd(values[0])
            if event == "os.chmod" and fd_paths.get(values[0]) in owned:
                return
            deny("unsafe-live-descriptor-mutation:" + event)
        source = Path(values[0])
        if event == "os.mkdir" and source == locks:
            if stat.S_ISDIR(raw_lstat(locks).st_mode):
                return
        if event == "os.remove" and source in owned:
            return
        if event in ("os.rename", "os.link"):
            destination = Path(values[1])
            if source in owned and source.parent == admitted_root and (
                    (event == "os.rename" and destination == ledger and
                        source.name.startswith(".phase6-repairs.json.")) or
                    (event == "os.link" and destination == receipt and
                        source.name.startswith(".phase6-d133-settlement30-receipt.json."))):
                if args.mode == "live" and authority is admission and admitted_root == root:
                    payload = expected_post if destination == ledger else expected_receipt
                    if source.read_bytes() != payload:
                        deny("unexpected-live-output-bytes")
                    if destination == ledger and ledger.read_bytes() != baseline:
                        deny("unexpected-live-ledger-transition")
                return
        deny("unsafe-live-mutation:" + event)

    def checked_path(raw, writing=False):
        if isinstance(raw, int):
            checked_fd(raw)
            return
        path = resolved(raw)
        if not writing and path in source_paths | data_paths:
            return
        if args.mode == "live":
            if not writing and path in owned_temps:
                return
            # Canonical _locked mkdir(exist_ok=True) must refer to the already
            # parent-prepared directory only, never grant arbitrary mkdir.
            if writing and path == live_locks and raw_lstat(path):
                return
            live_path(path, writing=writing, admitted_root=root, authority=admission)
            return
        if inside(path):
            return
        deny("outside-clone-write" if writing else "outside-clone-read")

    def audit(event, values):
        if event.startswith(("subprocess.", "socket.", "ctypes.", "os.exec",
                "os.spawn", "os.posix_spawn", "os.fork")) or event in ("os.system", "pty.spawn"):
            deny(event)
        if event == "import" and values[0].split(".")[0] not in ALLOWED_IMPORTS:
            deny("import:" + values[0].split(".")[0])
        if event == "open":
            checked_path(values[0], bool(values[2] & (os.O_WRONLY | os.O_RDWR |
                         os.O_CREAT | os.O_TRUNC | os.O_APPEND)))
            if args.mode == "live" and isinstance(values[0], int):
                checked_fd(values[0])
                if (values[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND) and
                        fd_paths.get(values[0]) not in owned_temps):
                    deny("live-writable-fdopen-not-owned-temp")
            if (args.mode == "live" and not isinstance(values[0], int) and
                    values[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)):
                live_open_policy(resolved(values[0]), values[2],
                    admitted_root=root, authority=admission)
        if event in ("os.listdir", "os.scandir"):
            checked_path(values[0])
        mutations = {"os.remove": (0,), "os.rmdir": (0,), "os.mkdir": (0,),
                     "os.rename": (0, 1), "os.link": (0, 1), "os.symlink": (1,),
                     "os.chmod": (0,), "os.truncate": (0,), "os.utime": (0,)}
        if args.mode == "live" and event in mutations:
            live_mutation_policy(event, values, admitted_root=root,
                authority=admission, owned=owned_temps)
        for index in mutations.get(event, ()):
            checked_path(values[index], True)

    def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
        if dir_fd is not None:
            deny("dir-fd")
        checked_path(path, bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT |
                                         os.O_TRUNC | os.O_APPEND)))
        if args.mode == "live":
            live_open_policy(resolved(path), flags, admitted_root=root, authority=admission)
        fd = real_open(path, flags, mode)
        if args.mode == "live" and flags & os.O_EXCL:
            owned_temps.add(Path(path))
        info = raw_fstat(fd)
        fds[fd] = (info.st_dev, info.st_ino)
        fd_paths[fd] = Path(path)
        return fd

    def guarded_close(fd):
        checked_fd(fd)
        real_close(fd)
        del fds[fd]
        fd_paths.pop(fd, None)

    def fd_wrapper(function):
        def call(fd, *positional, **kwargs):
            checked_fd(fd)
            if args.mode == "live":
                name = function.__name__
                if name in ("write", "fchmod", "ftruncate") and fd_paths.get(fd) not in owned_temps:
                    deny("live-descriptor-write-not-owned-temp")
                if name in ("flock", "lockf") and fd_paths.get(fd) != live_lock:
                    deny("live-flock-not-exact-lock")
            return function(fd, *positional, **kwargs)
        return call

    def path_wrapper(function, indices=(0,), writing=False):
        def call(*positional, **kwargs):
            if any(kwargs.get(key) is not None for key in
                   ("dir_fd", "src_dir_fd", "dst_dir_fd")):
                deny("dir-fd:" + function.__name__)
            for index in indices:
                checked_path(positional[index], writing)
            return function(*positional, **kwargs)
        return call

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level or name not in ALLOWED_IMPORTS:
            deny("import:" + name)
        return real_import(name, globals, locals, fromlist, level)

    sys.addaudithook(audit)
    builtins.__import__ = guarded_import
    os.open = guarded_open
    os.close = guarded_close
    # Prevent pathlib's own resolution from issuing intermediate metadata calls
    # through public wrappers; final canonical paths still require admission.
    def guarded_resolve(path, strict=False):
        checked_path(path)
        return resolved(path, strict)
    Path.resolve = guarded_resolve
    for name in ("read", "write", "fsync", "fstat", "fchmod", "ftruncate", "lseek", "fdopen", "fchown", "isatty"):
        setattr(os, name, fd_wrapper(getattr(os, name)))
    for name in ("stat", "lstat", "readlink", "access", "statvfs", "listdir", "scandir"):
        setattr(os, name, path_wrapper(getattr(os, name)))
    for name in ("unlink", "remove", "rmdir", "mkdir", "chmod", "chown", "truncate", "utime"):
        setattr(os, name, path_wrapper(getattr(os, name), writing=True))
    for name in ("rename", "replace", "link"):
        setattr(os, name, path_wrapper(getattr(os, name), (0, 1), True))
    os.symlink = path_wrapper(os.symlink, (1,), True)
    fcntl.flock = fd_wrapper(fcntl.flock)
    fcntl.lockf = fd_wrapper(fcntl.lockf)

    def unsupported(name):
        def call(*positional, **kwargs):
            deny("unsupported-primitive:" + name)
        return call
    # No clone operation needs descriptor duplication, raw ioctl/fcntl control,
    # cwd mutation, extended attributes or vectored/cross-descriptor transfers.
    for name in ("dup", "dup2", "chdir", "fchdir", "readv", "writev", "pread", "pwrite", "sendfile", "copy_file_range", "getxattr", "listxattr", "setxattr", "removexattr", "fwalk"):
        if hasattr(os, name):
            setattr(os, name, unsupported("os." + name))
    fcntl.fcntl = unsupported("fcntl.fcntl")
    fcntl.ioctl = unsupported("fcntl.ioctl")

    def probe(name, action):
        expected_probe[0] = True
        before = len(events)
        try:
            action()
        except GuardDenied:
            require(len(events) == before + 1, "probe-single-denial:" + name)
            events[-1]["probe_case_id"] = name
            events[-1]["probe_mode"] = ("audit-event-only" if name.endswith("audit-only") else
                "actual-api-entry" if name in ("outside-open", "outside-enumeration",
                    "unapproved-project-import", "process-call-entry", "unknown-fd", "dir-fd",
                    "unknown-fd-stat", "unknown-fd-flock", "outside-stat", "outside-lstat",
                    "outside-readlink", "outside-access") else "guard-policy-entry")
        else:
            raise AssertionError("probe-not-denied:" + name)
        finally:
            expected_probe[0] = False

    probe("outside-open", lambda: (project / "D133-must-not-open").read_bytes())
    probe("outside-enumeration", lambda: os.listdir(project))
    probe("unapproved-project-import", lambda: __import__("d128_seam"))
    probe("process-call-entry", lambda: os.system("D133-must-not-execute"))
    probe("unknown-fd", lambda: os.fchmod(987654, 0o600))
    probe("dir-fd", lambda: os.open("absent", os.O_RDONLY, dir_fd=987654))
    probe("unknown-fd-stat", lambda: os.stat(0))
    probe("unknown-fd-flock", lambda: fcntl.flock(0, fcntl.LOCK_EX | fcntl.LOCK_NB))
    probe("outside-stat", lambda: os.stat(project / "D133-metadata-probe"))
    probe("outside-lstat", lambda: os.lstat(project / "D133-metadata-probe"))
    probe("outside-readlink", lambda: os.readlink(project / "D133-metadata-probe"))
    probe("outside-access", lambda: os.access(project / "D133-metadata-probe", os.R_OK))
    probe("socket-audit-only", lambda: sys.audit("socket.__new__", None, 0, 0, 0))
    probe("native-audit-only", lambda: sys.audit("ctypes.dlopen", "D133-probe"))
    def live_capability(*, authority=None, transaction_id="D133-settlement30",
                        receipt="phase6-d133-settlement30-receipt.json",
                        temporary=".phase6-repairs.json.a1b2c3d4", lock=None,
                        caller="phase6_settlement"):
        # Capability validation is real guard policy, also used by live mode.
        # Checking adjacent fields first makes every denial discriminating.
        if transaction_id != "D133-settlement30":
            deny("unadmitted-live-transaction-id")
        if receipt != "phase6-d133-settlement30-receipt.json":
            deny("unadmitted-live-receipt")
        if not re.fullmatch(r"\.(?:phase6-repairs\.json|phase6-d133-settlement30-receipt\.json)\.[a-z0-9_]{8}", temporary):
            deny("unsafe-live-temporary")
        if lock is not None and not re.fullmatch(r"genewhip-phase6-accounting-[0-9a-f]{64}\.lock", lock):
            deny("unsafe-live-lock")
        if caller != "phase6_settlement":
            deny("forbidden-live-caller")
        if authority is None:
            deny("live-authority-absent")

    probe("live-without-authority", lambda: live_capability())
    probe("clone-live-root-confusion", lambda: live_path(project / "evidence/phase6-repairs.json", writing=True, admitted_root=root / "probe-live", authority={"probe": True}))
    probe("arbitrary-project-write", lambda: checked_path(project / "D133-write", True))
    probe("extra-receipt", lambda: live_capability(receipt="extra.json"))
    probe("extra-id", lambda: live_capability(transaction_id="extra"))
    probe("unsafe-temp", lambda: live_capability(temporary=".unsafe-temp"))
    probe("unsafe-lock", lambda: live_capability(lock="unsafe.lock"))
    probe("forbidden-caller", lambda: live_capability(caller="phase6_routes"))
    # Actual syscall policy functions, using only disposable path spellings.
    probe_root = root / "probe-live"
    probe_ledger = probe_root / "phase6-repairs.json"
    probe_receipt = probe_root / "phase6-d133-settlement30-receipt.json"
    probe_temp = probe_root / ".phase6-repairs.json.a1b2c3d4"
    probe_receipt_temp = probe_root / ".phase6-d133-settlement30-receipt.json.a1b2c3d4"
    probe_authority = {"probe": True}
    def open_probe(path, flags):
        return live_open_policy(path, flags, admitted_root=probe_root, authority=probe_authority)
    def mutation_probe(event, values):
        return live_mutation_policy(event, values, admitted_root=probe_root,
            authority=probe_authority, owned={probe_temp, probe_receipt_temp})
    probe("live-direct-ledger-open", lambda: open_probe(probe_ledger, os.O_WRONLY | os.O_TRUNC))
    probe("live-direct-receipt-open", lambda: open_probe(probe_receipt, os.O_WRONLY | os.O_TRUNC))
    probe("live-replace-receipt", lambda: mutation_probe("os.rename", (probe_temp, probe_receipt)))
    probe("live-rename-escape", lambda: mutation_probe("os.rename", (probe_temp, probe_root / "other.json")))
    probe("live-unlink-ledger", lambda: mutation_probe("os.remove", (probe_ledger,)))
    probe("live-chmod-ledger", lambda: mutation_probe("os.chmod", (probe_ledger, 0o600)))
    probe("live-nonexclusive-temp", lambda: open_probe(probe_temp, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW))
    probe("live-follow-temp", lambda: open_probe(probe_temp, os.O_RDWR | os.O_CREAT | os.O_EXCL))
    probe("live-alternate-lock", lambda: open_probe(probe_root / ".d133-30-locks" / ("genewhip-phase6-accounting-" + "0" * 64 + ".lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW))
    probe("live-wrong-receipt-link", lambda: mutation_probe("os.link", (probe_temp, probe_receipt)))
    open_probe(probe_temp, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW)
    mutation_probe("os.rename", (probe_temp, probe_ledger))
    mutation_probe("os.link", (probe_receipt_temp, probe_receipt))
    # The positive neighboring spelling is checked without writing anything.
    live_path(root / "probe-live/phase6-repairs.json", writing=True,
        admitted_root=root / "probe-live", authority={"probe": True})
    bootstrap_denials = len(events)
    blobs = {name: (project / name).read_bytes() for name in SOURCE_NAMES}
    require(all(digest(blobs[name]) == approved[name] for name in SOURCE_NAMES),
        "reviewed-source-sha256")

    def load(name, source, injected=None):
        module = types.ModuleType(name)
        module.__file__ = str(project / source)
        if injected:
            module.__dict__.update(injected)
        exec(compile(blobs[source], source, "exec"), module.__dict__)
        return module

    def live_before_intent(path, frozen, recover):
        # Synchronous callback under the unchanged canonical lock.
        require(admission is not None, "actual-live-admission")
        for source, wanted in approved.items():
            require(digest((project / source).read_bytes()) == wanted, "live-source-drift")
        for data_path, original in data_blobs.items():
            require(data_path.read_bytes() == original, "live-authority-data-drift")
        api = modules["settlement"]
        elapsed = time.monotonic() - entry["start_monotonic"]
        outcome = api.d133_admission(elapsed_seconds=elapsed,
            remaining_forecast_seconds=admission["remaining_forecast_seconds"],
            terminal_remaining_seconds=admission["terminal_remaining_seconds"],
            newly_known_unallocated_liabilities=str(api._known_liabilities(approval)))
        require(outcome["admitted"] is True and
            api._number(admission["terminal_remaining_seconds"], "terminal") >= 1200 and
            time.monotonic() <= entry["ordinary_latest_stop_monotonic"],
            "fresh-complete-forecast-terminal-admission")
        require(admission["newly_known_unallocated_liabilities"] ==
            approval["other_newly_known_liabilities"], "all-known-liabilities-accounted")
        actual = path.read_bytes()
        if recover:
            require(digest(actual) == admission["expected_post_ledger_sha256"],
                "same-intent-recovery-ledger")
        else:
            require(actual == baseline and frozen == admission["record"],
                "one-original-live-intent")
            age = time.monotonic() - observation["observed_monotonic_seconds"]
            require(0 <= age <= 60, "immediate-preintent-observation")
            require(not live_receipt.exists() and not live_receipt.is_symlink(),
                "first-live-receipt-absent")
        expected_value = json.loads(baseline)
        independent = {"schema": "ledger-transaction-intent-v1",
            "transaction_id": "D133-settlement30",
            "receipt_path": "phase6-d133-settlement30-receipt.json",
            "record": admission["record"], "expected_objects": expected}
        intent_bytes = json.dumps(independent, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode()
        receipt_bytes = oracle.expected_receipt_bytes(admission["record"], expected)
        row = dict(independent, intent_bytes=intent_bytes.decode(),
            intent_sha256=digest(intent_bytes), receipt_bytes=receipt_bytes.decode(),
            receipt_sha256=digest(receipt_bytes))
        expected_value["ledger_transactions_v1"] = {"schema": "ledger-transactions-v1",
            "transactions": {"D133-settlement30": row}}
        full = (json.dumps(expected_value, indent=2, sort_keys=False, allow_nan=False) + "\n").encode()
        require(full == expected_post and receipt_bytes == expected_receipt,
            "independent-full-live-transition")
        oracle.record_oracle(admission["record"], expected, context)

    def fresh_modules():
        accounting = load("d133_canonical", SOURCE_NAMES[0])
        settlement = load("d133_settlement", SOURCE_NAMES[1], {"ACCOUNTING": accounting,
            "_D133_CAPABILITY": {"mode": args.mode, "root": str(root)},
            "_D133_BEFORE_INTENT": live_before_intent if args.mode == "live" else None,
            "_D133_ENTRY": json.loads(json.dumps(entry)),
            "_D133_AUTHORITY": json.loads(json.dumps(approval)),
            "_D133_READER_PIN": json.loads(json.dumps(reader_pin))})
        coordinator = load("d133_coordinator", SOURCE_NAMES[2], {"D133_SETTLEMENT": settlement})
        return {"accounting": accounting, "settlement": settlement, "coordinator": coordinator}

    def actual_main(module, argv):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            status = module.main(argv)
        return status, stream.getvalue()

    def trace(frame, event, arg):
        if event == "call" and frame.f_code.co_filename == SOURCE_NAMES[0] and frame.f_code.co_name in (
                "_locked", "_load", "_write", "_receipt_payload", "_publish_receipt_once"):
            helper_trace.append(frame.f_code.co_name)
        return trace

    def timeout(signum, frame):
        raise GuardDeadline("internal55-second-deadline")
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(55)
    rows = []
    roster = []
    try:
        if args.mode == "retained":
            roster = []
            for lane in ("tracer", "fault-matrix", "oracle-negative-controls"):
                roster.extend(pin["frozen_rosters"][lane])
                rows.extend(retained[lane]["cases"])
            require(len(roster) == 74 and all(len(set(pin["frozen_rosters"][lane])) ==
                len(pin["frozen_rosters"][lane]) for lane in
                ("tracer", "fault-matrix", "oracle-negative-controls")),
                "frozen-retained-74-roster")
            require(retained["parent_integrity"].get("accepted") is True or
                retained["parent_integrity"].get("status") in ("pass", "passed"),
                "actual-parent-integrity")
            require(not helper_trace, "retained-zero-canonical-calls")
        else:
            modules = fresh_modules()
            oracle = load("d133_independent_oracle", SOURCE_NAMES[3])
            context = {"authority": approval, "reader_pin": reader_pin,
                "observation": observation,
                "coordinator_main": lambda argv: actual_main(modules["coordinator"], argv),
                "settlement_main": lambda argv: actual_main(modules["settlement"], argv)}
            sys.setprofile(trace)
            if args.mode == "live":
                api = modules["settlement"]
                common = dict(project_root=root, authority=approval, reader_pin=reader_pin,
                    expected_objects=expected, baseline_sha256=digest(baseline), lock_root=live_locks)
                oracle.record_oracle(admission["record"], expected, context)
                roster = ["live-settlement-current-readers"]
                if args.case in ("settle-once", "commit-settlement"):
                    result = api.commit_d133_settlement(live_ledger, record=admission["record"], **common)
                elif args.case == "recover-settlement":
                    result = api.recover_d133_settlement(live_ledger, **common)
                else:
                    result = {"read-current": api.d133_current_view,
                        "remaining": api.d133_remaining,
                        "recompute-receipt": api.d133_recompute_receipt}[args.case](live_ledger, **common)
                view = api.d133_current_view(live_ledger, **common)
                require(live_ledger.read_bytes() == expected_post and
                    live_receipt.read_bytes() == expected_receipt, "actual-full-live-transition")
                oracle.persisted_oracle(live_ledger, live_receipt, expected,
                    admission["record"], view, context)
                base_args = ["--ledger", str(live_ledger), "--project-root", str(root),
                    "--lock-root", str(live_locks), "--settlement-approval",
                    str(project / APPROVAL_NAME), "--reader-pin", str(reader_path)]
                callers = {}
                status, output = actual_main(modules["coordinator"],
                    ["--accounting-preflight", "--accounting-scope", "D133"] + base_args)
                require(status == 0, "actual-live-coordinator-exit")
                callers["coordinator"] = json.loads(output)
                for lane in ("read-current", "remaining", "recompute-receipt"):
                    status, output = actual_main(api, ["--case", lane] + base_args)
                    require(status == 0, "actual-live-cli-exit:" + lane)
                    callers[lane] = json.loads(output)
                for name, reported in callers.items():
                    oracle.view_oracle(reported, context)
                rows = [{"case_id": roster[0], "status": "pass", "result": result,
                    "view": view, "actual_callers": callers, "ledger_sha256": digest(expected_post),
                    "receipt_sha256": digest(expected_receipt),
                    "receipt_inode": live_receipt.stat().st_ino}]
            else:
                roster = list(oracle.ROSTERS[args.case])
                if args.case == "tracer":
                    rows = oracle.run_tracer(modules["settlement"], root, baseline,
                        expected, fresh_modules, context)
                elif args.case == "fault-matrix":
                    rows = oracle.run_fault_matrix(root, baseline, expected, fresh_modules, context)
                else:
                    rows = oracle.run_negative_controls(root, baseline, expected, fresh_modules, context)
                if isinstance(rows, dict):
                    rows = [row for partition in rows.values() for row in partition]
                require(roster == pin.get("frozen_rosters", {}).get(args.case),
                    "independent-frozen-roster")
            require([row["case_id"] for row in rows] == roster, "frozen-case-roster")
            if args.mode == "clone" and all(row["status"] == "pass" for row in rows):
                require(set(("_locked", "_load", "_write", "_receipt_payload", "_publish_receipt_once")) <=
                    set(helper_trace), "actual-canonical-helper-coverage")
    except (Exception, GuardDeadline) as exc:
        rows.append({"case_id": "bootstrap-or-lane", "status": "fail",
            "exception": type(exc).__name__, "assertion": str(exc)})
    finally:
        sys.setprofile(None)
        signal.alarm(0)
    unexpected = [row for row in events if not row["expected"]]
    success = bool(roster) and len(rows) == len(roster) and all(
        row["status"] == "pass" for row in rows) and not unexpected
    report = {"scope": "D133 exact clone only" if args.mode == "clone" else "D133 scoped policy settlement",
        "mode": args.mode, "lane": args.case,
        "status": "pass" if success else "fail", "case_ids": [row["case_id"] for row in rows],
        "denominator": len(roster), "cases": rows, "pins": approved,
        "snapshot_sha256": digest(baseline), "review_pin_sha256": digest(pin_bytes),
        "bootstrap_denials": bootstrap_denials, "denials": events,
        "unexpected_denial_count": len(unexpected), "canonical_helper_trace": helper_trace,
        "canonical_calls_this_run": len(helper_trace), "clone_basename": root.name,
        "source_review_sha256": digest(source_review_bytes),
        "admission_sha256": digest(admission_bytes) if admission_bytes else None}
    if pin.get("stage") == "bootstrap-red":
        print("TAP version 13")
        print("1.." + str(len(rows)))
        for number, row in enumerate(rows, 1):
            print(("ok " if row["status"] == "pass" else "not ok ") +
                str(number) + " - " + row["case_id"])
            if row["status"] != "pass":
                print("  ---")
                print("  message: " + json.dumps(row.get("assertion", "")))
                print("  type: " + row.get("exception", "AssertionError"))
                print("  ...")
        print("# JSON " + json.dumps(report, sort_keys=True))
    else:
        print(json.dumps(report, sort_keys=True))
    return 0 if success else 1

if __name__ == "__main__":
    raise SystemExit(main())


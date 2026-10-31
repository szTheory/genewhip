"""Prospective D133 policy liabilities over the unchanged neutral ledger API.

Pure record construction does not confer storage authority. Guarded callers own
exact source/approval capabilities; storage/recovery always use ACCOUNTING.
"""
from __future__ import annotations
import argparse
from decimal import Decimal, InvalidOperation, localcontext
import hashlib
import importlib.util
import json
import pathlib
import re
import sys

if "ACCOUNTING" not in globals():
    _spec = importlib.util.spec_from_file_location("phase6_accounting",
        pathlib.Path(__file__).with_name("phase6_accounting.py"))
    ACCOUNTING = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(ACCOUNTING)

ID = "D133-settlement30"
RECEIPT = "phase6-d133-settlement30-receipt.json"
PURPOSE = "D133-settlement30-current-readers"
ALLOCATIONS = {"D129-S": 1800, "D130-old-A": 5400, "D131-probe": 1200,
    "D132-engineering29": 4200, "D132-documentary-control": 1800,
    "D133-documentary-control": 2400, PURPOSE: 9000}
LOWER_BOUNDS = {"D129-S": "1508.589962375001",
    "D130-old-A": "2306.7324035839993", "D131-probe": "762.6347023750423",
    "D132-engineering29": "2522.823684834002",
    "D132-documentary-control": None, "D133-documentary-control": None}
POSTED = Decimal("45802.60140849992")
PROCESS = Decimal("1794.135")
LIABILITY = Decimal("25800")
CEILING = Decimal("73500")
MAXIMUM = POSTED + LIABILITY + PROCESS
SOURCE_NAMES = ("scripts/evidence/phase6_accounting.py",
    "scripts/evidence/phase6_settlement.py", "tests/fixtures/phase6_repairs.py",
    "tests/evidence/test_phase6_policy_settlement.py",
    "tests/evidence/phase6_d133_settlement_guard.py")


def _error(reason):
    raise ACCOUNTING.AccountingError(reason)


def _number(value, name):
    if type(value) not in (int, float, str):
        _error("d133-numeric-invalid:" + name)
    if type(value) is int and value.bit_length() > 40:
        _error("d133-numeric-invalid:" + name)
    if type(value) is str and len(value) > 256:
        _error("d133-numeric-invalid:" + name)
    try:
        result = Decimal(str(value))
    except (ValueError, InvalidOperation, OverflowError):
        _error("d133-numeric-invalid:" + name)
    if (not result.is_finite() or result < 0 or result > Decimal("1000000000000") or
            len(result.as_tuple().digits) > 128 or
            abs(result.as_tuple().exponent) > 128):
        _error("d133-numeric-invalid:" + name)
    return result


def d133_admission(*, elapsed_seconds, remaining_forecast_seconds,
                   terminal_remaining_seconds, newly_known_unallocated_liabilities):
    """Exact thresholds; terminal is a subset of remaining, full purpose once."""
    elapsed = _number(elapsed_seconds, "elapsed")
    remaining = _number(remaining_forecast_seconds, "remaining-forecast")
    terminal = _number(terminal_remaining_seconds, "terminal-remaining")
    other = _number(newly_known_unallocated_liabilities, "known-liabilities")
    if terminal > remaining:
        _error("d133-terminal-forecast-invalid")
    with localcontext() as arithmetic:
        arithmetic.prec = 512
        projected = elapsed + remaining
        maximum = MAXIMUM + other
        return {"admitted": projected <= 9000 and maximum <= CEILING,
            "purpose_projected_seconds": str(projected),
            "maximum_policy_exposure_seconds": str(maximum),
            "admissible_policy_headroom_seconds": str(CEILING - maximum),
            "actual_total_status": "unknown",
            "terminal_inside_remaining_seconds": str(terminal)}


def _sha_map(value, keys, name):
    if (not isinstance(value, dict) or set(value) != set(keys) or
            any(type(v) is not str or re.fullmatch("[0-9a-f]{64}", v) is None
                for v in value.values())):
        _error("d133-" + name + "-invalid")


def _known_liabilities(authority):
    rows = authority.get("other_newly_known_liabilities")
    if not isinstance(rows, list) or len(rows) > 128:
        _error("d133-known-liabilities-invalid")
    total = Decimal(0)
    seen = set()
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {"purpose", "seconds", "evidence_sha256"} or
                type(row["purpose"]) is not str or not row["purpose"] or
                row["purpose"] in seen or row["purpose"] in ALLOCATIONS or
                re.fullmatch("[0-9a-f]{64}", str(row["evidence_sha256"])) is None):
            _error("d133-known-liabilities-invalid")
        seen.add(row["purpose"])
        with localcontext() as arithmetic:
            arithmetic.prec = 512
            total += _number(row["seconds"], "other-liabilities")
    return total


def _authority(authority, reader_pin, expected_objects, baseline_sha256):
    if not isinstance(authority, dict) or not isinstance(reader_pin, dict):
        _error("d133-authority-invalid")
    if (authority.get("schema") != "d133-approval-v1" or
            authority.get("purpose") != PURPOSE or
            authority.get("cumulative_allocations") != ALLOCATIONS or
            authority.get("actual_total_status") != "unknown" or
            authority.get("selected_global_ceiling") != 73500 or
            authority.get("engineering_cap") != 9000 or
            authority.get("protected_terminal_inside_cap") != 1200 or
            authority.get("fact_only_terminal_subset_max") != 90 or
            authority.get("documentary_policy_allocation") != 2400 or
            authority.get("historical_live_ledger_ceiling_unchanged") != 57600):
        _error("d133-authority-invalid")
    if (_number(authority.get("posted_actual_closed_seconds"), "posted") != POSTED or
            _number(authority.get("protected_process_reserve_seconds"), "process") != PROCESS or
            _number(authority.get("maximum_policy_exposure"), "maximum") != MAXIMUM or
            _known_liabilities(authority) > CEILING - MAXIMUM):
        _error("d133-authority-financial-invalid")
    if (type(baseline_sha256) is not str or
            baseline_sha256 != authority.get("entry_ledger_sha256") or
            not isinstance(expected_objects, dict) or
            expected_objects != authority.get("entry_object_sha256") or
            len(expected_objects) != 68):
        _error("d133-baseline-identity")
    _sha_map(expected_objects, expected_objects, "baseline-map")
    if (set(reader_pin) != {"schema", "authority_pins", "source_sha256"} or
            reader_pin.get("schema") != "d133-reader-pin-v1"):
        _error("d133-reader-pin-invalid")
    pins = reader_pin["authority_pins"]
    _sha_map(pins, ("approval", "entry", "plan", "amendment", "source_review"),
        "authority-pins")
    _sha_map(reader_pin["source_sha256"], SOURCE_NAMES, "source-pins")
    if pins["plan"] != authority.get("plan_sha256") or pins["amendment"] != authority.get("amendment_sha256"):
        _error("d133-authority-identity")
    if "_D133_AUTHORITY" in globals() and authority != _D133_AUTHORITY:
        _error("d133-authority-identity")
    if "_D133_READER_PIN" in globals() and reader_pin != _D133_READER_PIN:
        _error("d133-reader-identity")


def _observation(observation, authority):
    if (not isinstance(observation, dict) or set(observation) !=
            {"boot_uuid", "elapsed_seconds", "observed_monotonic_seconds"} or
            observation.get("boot_uuid") != authority.get("boot_uuid")):
        _error("d133-observation-invalid")
    elapsed = _number(observation["elapsed_seconds"], "observation-elapsed")
    observed = _number(observation["observed_monotonic_seconds"], "observation-monotonic")
    if elapsed > 9000 or observed < elapsed:
        _error("d133-observation-invalid")
    entry = globals().get("_D133_ENTRY")
    if not isinstance(entry, dict) or entry.get("boot_uuid") != observation["boot_uuid"]:
        _error("d133-observation-origin")
    with localcontext() as arithmetic:
        arithmetic.prec = 512
        if abs(observed - elapsed - _number(entry.get("start_monotonic"), "entry-start")) > Decimal("0.0000001"):
            _error("d133-observation-origin")
    return json.loads(json.dumps(observation, allow_nan=False))


def make_d133_settlement_record(*, authority, reader_pin, observation,
                                expected_objects, baseline_sha256):
    """Construct one cumulative policy disposition, never a measured charge."""
    _authority(authority, reader_pin, expected_objects, baseline_sha256)
    own = _observation(observation, authority)
    evidence = {key: {"lower_bound_seconds": lower, "unknown_tail": True}
                for key, lower in LOWER_BOUNDS.items()}
    evidence[PURPOSE] = {"lower_bound_seconds": own["elapsed_seconds"], "unknown_tail": True}
    record = {"kind": "engineering-metadata", "policy_settlement": {
        "schema": "phase6-policy-settlement-v1", "settlement_id": ID,
        "receipt_path": RECEIPT, "baseline_sha256": baseline_sha256,
        "expected_objects": expected_objects, "authority_pins": reader_pin["authority_pins"],
        "source_sha256": reader_pin["source_sha256"], "operating_ceiling_seconds": 73500,
        "posted_actual_closed_seconds": str(POSTED),
        "protected_process_reserve_seconds": str(PROCESS), "allocations": ALLOCATIONS,
        "policy_liability_seconds": str(LIABILITY),
        "policy_settled_exposure_seconds": str(POSTED + LIABILITY),
        "maximum_policy_exposure_seconds": str(MAXIMUM),
        "actual_total_status": "unknown", "actual_evidence": evidence,
        "own_observation": own}}
    # No caller-owned mutable object is retained.
    return ACCOUNTING._transaction_record(record)


def validate_d133_settlement_record(record, *, authority, reader_pin, observation=None,
                                    expected_objects, baseline_sha256):
    _authority(authority, reader_pin, expected_objects, baseline_sha256)
    if (not isinstance(record, dict) or set(record) != {"kind", "policy_settlement"} or
            not isinstance(record.get("policy_settlement"), dict)):
        _error("d133-record-invalid")
    policy = record["policy_settlement"]
    own = policy.get("own_observation")
    if observation is not None and own != observation:
        _error("d133-observation-identity")
    wanted = make_d133_settlement_record(authority=authority, reader_pin=reader_pin,
        observation=own, expected_objects=expected_objects, baseline_sha256=baseline_sha256)
    if ACCOUNTING._transaction_record(record) != wanted:
        _error("d133-record-invalid")
    return wanted


def _arguments(ledger_path, project_root, expected_objects, lock_root):
    capability = globals().get("_D133_CAPABILITY")
    if not isinstance(capability, dict) or capability.get("mode") not in ("clone", "live"):
        _error("d133-guard-capability-required")
    args = ACCOUNTING._transaction_arguments(ledger_path, project_root, ID,
        pathlib.Path(project_root) / RECEIPT, expected_objects, lock_root)
    allowed = pathlib.Path(capability["root"])
    root, ledger, receipt, locks, _ = args
    if capability["mode"] == "clone":
        if root != allowed and allowed not in root.parents:
            _error("d133-clone-root-escape")
    elif (root != allowed or ledger != allowed / "phase6-repairs.json" or
            locks != allowed / ".d133-30-locks"):
        _error("d133-live-identity")
    return args


def _view_unlocked(path, root, expected, authority, reader_pin, baseline_sha256):
    _authority(authority, reader_pin, expected, baseline_sha256)
    value = ACCOUNTING._load(path, root)
    journal = ACCOUNTING._transaction_journal(value, expected)
    fixed_receipt = ACCOUNTING._transaction_path(RECEIPT, root, flat=True)
    orphan_exists = fixed_receipt.exists()
    if (not journal["transactions"] and not orphan_exists and
            hashlib.sha256(path.read_bytes()).hexdigest() != baseline_sha256):
        _error("d133-entry-byte-identity")
    posted = Decimal(str(ACCOUNTING._closed_seconds(value["phase6_accounting"])))
    if posted != POSTED:
        _error("d133-posted-base-mismatch")
    policies = []
    purposes = set()
    state = "pending-publication" if orphan_exists else "reserved"
    receipt_sha = None
    orphan_policy = None
    if not journal["transactions"] and fixed_receipt.is_file():
        # Receipt evidence can strengthen a lower bound, never recreate intent
        # or permit capacity when the canonical journal has disappeared.
        try:
            orphan_bytes = fixed_receipt.read_bytes()
            orphan_payload = json.loads(orphan_bytes)
            orphan_record = validate_d133_settlement_record(orphan_payload.get("record"),
                authority=authority, reader_pin=reader_pin, expected_objects=expected,
                baseline_sha256=baseline_sha256)
            wanted = ACCOUNTING._transaction_intent(ID, RECEIPT, orphan_record, expected)
            if orphan_bytes == wanted["receipt_bytes"].encode():
                orphan_policy = orphan_record["policy_settlement"]
        except (ValueError, TypeError, AttributeError, ACCOUNTING.AccountingError):
            pass  # Unknown orphan bytes never grant publication or capacity.
    for identifier, row in journal["transactions"].items():
        record = row["record"]
        if "policy_settlement" not in record:
            # Validated neutral metadata has no financial authority.
            continue
        policy = record.get("policy_settlement")
        if not isinstance(policy, dict):
            _error("d133-unrecognized-policy")
        allocations = policy.get("allocations")
        if not isinstance(allocations, dict):
            _error("d133-unrecognized-policy")
        if purposes.intersection(allocations):
            _error("d133-duplicate-purpose")
        purposes.update(allocations)
        validate_d133_settlement_record(record, authority=authority,
            reader_pin=reader_pin, expected_objects=expected,
            baseline_sha256=baseline_sha256)
        if identifier != ID or row["receipt_path"] != RECEIPT:
            _error("d133-settlement-identity")
        policies.append(policy)
        receipt = ACCOUNTING._transaction_path(row["receipt_path"], root, flat=True)
        state = "pending-publication"
        if receipt.is_file() and receipt.read_bytes() == row["receipt_bytes"].encode():
            state = "published"
            receipt_sha = hashlib.sha256(receipt.read_bytes()).hexdigest()
    # Both representations contain precisely the same full selected liabilities.
    if policies:
        evidence = policies[0]["actual_evidence"]
    elif orphan_policy is not None:
        evidence = orphan_policy["actual_evidence"]
    else:
        evidence = {key: {"lower_bound_seconds": lower, "unknown_tail": True}
                    for key, lower in LOWER_BOUNDS.items()}
        evidence[PURPOSE] = {"lower_bound_seconds": 0, "unknown_tail": True}
    with localcontext() as arithmetic:
        arithmetic.prec = 512
        liability = sum((Decimal(str(amount)) for amount in ALLOCATIONS.values()), Decimal(0))
        settled = posted + liability
        other = _known_liabilities(authority)
        headroom = CEILING - settled - PROCESS - other
        maximum = settled + PROCESS + other
        remaining = CEILING - settled
    view = {"posted_actual_closed_seconds": str(posted),
        "policy_liability_seconds": str(liability),
        "policy_settled_exposure_seconds": str(settled),
        "protected_process_reserve_seconds": str(PROCESS),
        "policy_remaining_seconds": str(remaining),
        "admissible_policy_headroom_seconds": str(headroom),
        "maximum_policy_exposure_seconds": str(maximum),
        "actual_total_status": "unknown", "publication_state": state,
        "capacity_allowed": state != "pending-publication" and headroom >= 0,
        "purpose_allocations": ALLOCATIONS, "actual_evidence": evidence,
        "authority_pins": reader_pin["authority_pins"],
        "source_sha256": reader_pin["source_sha256"],
        "receipt_sha256": receipt_sha,
        "policy_identity": ID}
    return json.loads(json.dumps(view, allow_nan=False))


def d133_current_view(ledger_path, *, project_root, authority, reader_pin,
                      expected_objects, baseline_sha256, lock_root):
    """Reload original objects, canonical journal and publication under one lock."""
    root, path, receipt, locks, expected = _arguments(ledger_path, project_root,
        expected_objects, lock_root)
    with ACCOUNTING._locked(path, lock_root=locks, timeout_seconds=2):
        _arguments(path, root, expected, locks)
        return _view_unlocked(path, root, expected, authority, reader_pin, baseline_sha256)


def d133_remaining(ledger_path, **kwargs):
    return d133_current_view(ledger_path, **kwargs)


def d133_recompute_receipt(ledger_path, **kwargs):
    return d133_current_view(ledger_path, **kwargs)


def _store(ledger_path, *, project_root, authority, reader_pin, expected_objects,
           baseline_sha256, lock_root, record=None, checkpoint=None, recover=False):
    root, path, receipt, locks, expected = _arguments(ledger_path, project_root,
        expected_objects, lock_root)
    if checkpoint is not None and not callable(checkpoint):
        _error("transaction-checkpoint-invalid")
    frozen = None if recover else validate_d133_settlement_record(record,
        authority=authority, reader_pin=reader_pin, expected_objects=expected,
        baseline_sha256=baseline_sha256)
    def boundary(name):
        if name == "before_intent":
            # Canonical commit already holds its lock. Never nest-lock here.
            view = _view_unlocked(path, root, expected, authority, reader_pin,
                baseline_sha256)
            if Decimal(view["admissible_policy_headroom_seconds"]) < 0:
                _error("d133-known-excess")
            if recover:
                value = ACCOUNTING._load(path, root)
                journal = ACCOUNTING._transaction_journal(value, expected)
                row = journal["transactions"].get(ID)
                if row is not None:
                    validate_d133_settlement_record(row["record"], authority=authority,
                        reader_pin=reader_pin, expected_objects=expected,
                        baseline_sha256=baseline_sha256)
            else:
                validate_d133_settlement_record(frozen, authority=authority,
                    reader_pin=reader_pin, expected_objects=expected,
                    baseline_sha256=baseline_sha256)
            callback = globals().get("_D133_BEFORE_INTENT")
            if callback is not None:
                callback(path, frozen, recover)
        if checkpoint is not None:
            checkpoint(name)
    kwargs = dict(project_root=root, transaction_id=ID, receipt_path=receipt,
        expected_objects=expected, lock_root=locks, checkpoint=boundary)
    if recover:
        storage = ACCOUNTING.recover_ledger_transaction(path, **kwargs)
    else:
        storage = ACCOUNTING.commit_ledger_transaction(path, record=frozen, **kwargs)
    view = d133_current_view(path, project_root=root, authority=authority,
        reader_pin=reader_pin, expected_objects=expected,
        baseline_sha256=baseline_sha256, lock_root=locks)
    view["storage_result"] = storage
    return view


def commit_d133_settlement(ledger_path, **kwargs):
    return _store(ledger_path, **kwargs)


def recover_d133_settlement(ledger_path, **kwargs):
    return _store(ledger_path, recover=True, **kwargs)


def cli_arguments(parser):
    parser.add_argument("--ledger", type=pathlib.Path, required=True)
    parser.add_argument("--project-root", type=pathlib.Path, required=True)
    parser.add_argument("--lock-root", type=pathlib.Path, required=True)
    parser.add_argument("--settlement-approval", type=pathlib.Path, required=True)
    parser.add_argument("--reader-pin", type=pathlib.Path, required=True)


def cli_context(args):
    authority = json.loads(args.settlement_approval.read_bytes())
    pin = json.loads(args.reader_pin.read_bytes())
    return dict(project_root=args.project_root, authority=authority, reader_pin=pin,
        expected_objects=authority["entry_object_sha256"],
        baseline_sha256=authority["entry_ledger_sha256"], lock_root=args.lock_root)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=("read-current", "remaining",
        "recompute-receipt", "commit-settlement", "recover-settlement"), required=True)
    cli_arguments(parser)
    parser.add_argument("--record", type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        common = cli_context(args)
        if args.case == "commit-settlement":
            if args.record is None:
                parser.error("--record required for commit-settlement")
            record = json.loads(args.record.read_bytes())
            result = commit_d133_settlement(args.ledger, record=record, **common)
        elif args.case == "recover-settlement":
            result = recover_d133_settlement(args.ledger, **common)
        else:
            reader = {"read-current": d133_current_view, "remaining": d133_remaining,
                "recompute-receipt": d133_recompute_receipt}[args.case]
            result = reader(args.ledger, **common)
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        return 0
    except (ACCOUNTING.AccountingError, OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "blocked", "reason": str(exc),
            "actual_total_status": "unknown"}, sort_keys=True))
        return 1

if __name__ == "__main__":
    raise SystemExit(main())


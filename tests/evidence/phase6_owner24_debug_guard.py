"""Independent, stdlib-only process boundary for bounded owner24 regressions."""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import signal
import subprocess
import sys
import unittest
import time

ENGINEERING25_FILES = (
    "scripts/evidence/phase6_accounting.py",
    "tests/evidence/phase6_d125_consumers_contract.py",
    "tests/evidence/phase6_d125_authored_fixture.py",
    "tests/evidence/test_engineering25_accounting.py",
    "tests/evidence/phase6_owner24_debug_guard.py",
)
ENGINEERING25_APPROVAL = ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-D127-APPROVAL.json"
ENGINEERING25_PLAN = ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-25-PLAN.md"
ENGINEERING25_AMENDMENT = ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-D127-ENGINEERING-AMENDMENT.md"
ENGINEERING25_CHECK = ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-25-PLAN-CHECK.md"
ENGINEERING25_CONTEXT = ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-CONTEXT.md"
ENGINEERING25_OPERATING = ".planning/context/OPERATING.md"
ENGINEERING25_APPROVAL_SHA = "570452c689bcf1585ce8c56335b5c6de3d577f6a6fc81d508425dc6d5feaf335"
ENGINEERING25_PLAN_SHA = "517522b38d6ac8d9def8c7d2bd35ab1fa929f49395a03d778f374b75d614b88e"
ENGINEERING25_AMENDMENT_SHA = "232e21fda7ffb0de345c9d7669cf4ca769d3b2227f0eb12d6f21b74ffa605000"
ENGINEERING25_CHECK_SHA = "26a6aaa3f45a7004f5a22cf5d8008697de0d1ede5c157635cfabc59efec9ffbd"


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _engineering25_preimport(args, root):
    """Validate parent-observed source review in stdlib before project imports."""
    if not all((args.approval, args.approval_sha256, args.parent_review_pin,
                args.parent_review_pin_sha256, args.expected_reviewer_identity, args.case)):
        raise RuntimeError("engineering25-explicit-approval-and-review-pin-required")
    approval_path = root / args.approval
    pin_path = root / args.parent_review_pin
    for candidate in (approval_path, pin_path):
        if candidate.is_symlink():
            raise RuntimeError("engineering25-authority-path-symlink-denied")
    approval_bytes = approval_path.read_bytes()
    if _sha(approval_bytes) != args.approval_sha256 or args.approval_sha256 != ENGINEERING25_APPROVAL_SHA:
        raise RuntimeError("engineering25-approval-digest-mismatch")
    approval = json.loads(approval_bytes)
    if (approval.get("decision") != "approved" or
            approval.get("plan_sha256") != ENGINEERING25_PLAN_SHA or
            approval.get("amendment_sha256") != ENGINEERING25_AMENDMENT_SHA or
            approval.get("baseline_ledger_sha256") != "9bee5d2dbdf8038ccff5cc4c430aafeaa864b96b64c36dc2817f610054918997" or
            approval.get("engineering_owner") != "06-25" or
            approval.get("game_admission") is not False or
            approval.get("builds_authorized") is not False or
            approval.get("native_guests_authorized") is not False or
            approval.get("scarce_reservations_authorized") is not False):
        raise RuntimeError("engineering25-approval-scope-invalid")

    input_hashes = {
        ENGINEERING25_PLAN: ENGINEERING25_PLAN_SHA,
        ENGINEERING25_AMENDMENT: ENGINEERING25_AMENDMENT_SHA,
        ENGINEERING25_CHECK: ENGINEERING25_CHECK_SHA,
        ENGINEERING25_CONTEXT: None,
        ENGINEERING25_OPERATING: None,
    }
    current_inputs = {}
    for relative, expected in input_hashes.items():
        target = root / relative
        if target.is_symlink() or not target.is_file():
            raise RuntimeError("engineering25-bound-input-missing-or-symlink:" + relative)
        actual = _sha(target.read_bytes())
        if expected is not None and actual != expected:
            raise RuntimeError("engineering25-approved-input-digest-mismatch:" + relative)
        current_inputs[relative] = actual

    ledger_path = root / "evidence/phase6-repairs.json"
    if ledger_path.is_symlink() or not ledger_path.is_file():
        raise RuntimeError("engineering25-ledger-missing-or-symlink")
    ledger = json.loads(ledger_path.read_bytes())
    policy = ledger.get("d127_engineering25_policy", {})
    if (policy.get("schema") != "phase6-d127-engineering25-v1" or
            policy.get("status") != "active" or policy.get("owner") != "06-25" or
            policy.get("purpose") != "D127-engineering25-retained-consumer-closure" or
            policy.get("approval_sha256") != ENGINEERING25_APPROVAL_SHA or
            policy.get("plan_sha256") != ENGINEERING25_PLAN_SHA or
            policy.get("amendment_sha256") != ENGINEERING25_AMENDMENT_SHA or
            policy.get("entry_ledger_sha256") != approval.get("baseline_ledger_sha256") or
            policy.get("game_admission") is not False or policy.get("scarce_reservations") is not False or
            policy.get("global_cap_seconds") != 57600 or policy.get("engineering_cap_seconds") != 12600 or
            policy.get("terminal_reserve_seconds") != 600 or policy.get("protected_process_seconds") != 1794.135):
        raise RuntimeError("engineering25-live-policy-invalid")

    pin_bytes = pin_path.read_bytes()
    if _sha(pin_bytes) != args.parent_review_pin_sha256:
        raise RuntimeError("engineering25-parent-review-pin-digest-mismatch")
    pin = json.loads(pin_bytes)
    review_candidate = root / pin.get("review_path", "")
    if review_candidate.is_symlink():
        raise RuntimeError("engineering25-independent-review-output-missing-or-symlink")
    try:
        review_path = review_candidate.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("engineering25-independent-review-output-missing-or-symlink") from exc
    if (not review_path.is_file() or
            (root != review_path and root not in review_path.parents)):
        raise RuntimeError("engineering25-independent-review-output-missing-or-symlink")
    review_bytes = review_path.read_bytes()
    inventory = pin.get("source_inventory")
    if (pin.get("schema") != "genewhip.plan25.preimport-parent-pin.v1" or
            pin.get("reviewer_identity") != args.expected_reviewer_identity or
            pin.get("reviewer_terminal_status") != "completed" or
            pin.get("decision") != "ACCEPT" or pin.get("blocking_findings") != 0 or
            pin.get("review_sha256") != _sha(review_bytes) or
            pin.get("approval_sha256") != ENGINEERING25_APPROVAL_SHA or
            pin.get("plan_sha256") != ENGINEERING25_PLAN_SHA or
            pin.get("amendment_sha256") != ENGINEERING25_AMENDMENT_SHA or
            pin.get("baseline_ledger_sha256") != policy.get("entry_ledger_sha256") or
            pin.get("bound_inputs") != current_inputs or
            not isinstance(inventory, dict) or set(inventory) != set(ENGINEERING25_FILES)):
        raise RuntimeError("engineering25-parent-review-pin-invalid")
    actual_inventory = {}
    for relative in ENGINEERING25_FILES:
        target = root / relative
        if target.is_symlink() or not target.is_file():
            raise RuntimeError("engineering25-source-inventory-missing-or-symlink:" + relative)
        actual_inventory[relative] = _sha(target.read_bytes())
    if inventory != actual_inventory:
        raise RuntimeError("engineering25-current-source-inventory-stale")
    for relative, digest in current_inputs.items():
        if _sha((root / relative).read_bytes()) != digest:
            raise RuntimeError("engineering25-approved-input-changed-before-import:" + relative)
    return {
        "approval_sha256": _sha(approval_bytes), "pin_sha256": _sha(pin_bytes),
        "reviewer_identity": pin["reviewer_identity"], "review_sha256": _sha(review_bytes),
        "source_inventory": actual_inventory, "ledger_entry_sha256": policy["entry_ledger_sha256"],
    }


def _engineering25_denial():
    """Install independent process denial and return separate attempt counters."""
    attempts = []
    def deny(event, args):
        if event in {"subprocess.Popen", "os.system", "os.exec", "os.fork", "os.forkpty", "os.posix_spawn", "os.spawn"}:
            attempts.append({"event": event, "argument_count": len(args)})
            raise RuntimeError("engineering25-process-denied:" + event)
    cached_popen, cached_system = subprocess.Popen, os.system
    sys.addaudithook(deny)
    for event in ("subprocess.Popen", "os.system", "os.exec", "os.fork", "os.forkpty", "os.posix_spawn", "os.spawn"):
        before = len(attempts)
        try:
            sys.audit(event, "engineering25-preimport-sentinel")
        except RuntimeError:
            pass
        if len(attempts) != before + 1:
            raise RuntimeError("engineering25-preimport-audit-denial-missing:" + event)
    for call in (lambda: cached_popen(["engineering25-forbidden"]),
                  lambda: cached_system("engineering25-forbidden")):
        before = len(attempts)
        try:
            call()
        except RuntimeError as exc:
            if "engineering25-process-denied" not in str(exc):
                raise
        if len(attempts) != before + 1:
            raise RuntimeError("engineering25-cached-process-alias-denial-missing")
    def blocked(*_args, **_kwargs):
        attempts.append({"event": "direct-api", "argument_count": len(_args)})
        raise RuntimeError("engineering25-process-denied:direct-api")
    for name in ("Popen", "run", "call", "check_call", "check_output"):
        setattr(subprocess, name, blocked)
    for name in dir(os):
        if name in {"system", "popen", "startfile"} or name.startswith(("fork", "spawn", "exec", "posix_spawn")):
            if callable(getattr(os, name)):
                setattr(os, name, blocked)
    return attempts


def _engineering25_run(args, root):
    source_pin = _engineering25_preimport(args, root)
    attempts = _engineering25_denial()
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError("engineering25-55-second-deadline")))
    signal.alarm(55)
    start = time.monotonic()
    spec = importlib.util.spec_from_file_location(
        "engineering25_accounting_tests", root / "tests/evidence/test_engineering25_accounting.py")
    module = importlib.util.module_from_spec(spec)
    module.SOURCE_ROOT = root
    module.CASE = args.case
    spec.loader.exec_module(module)
    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    selected = []
    names = {
        "test_numeric_string_forecast_is_normalized_before_exposure_comparison": "wr01-forecast-string",
    }
    def visit(node):
        if isinstance(node, unittest.TestSuite):
            for child in node:
                visit(child)
        elif names.get(node._testMethodName) == args.case:
            selected.append(node)
    visit(suite)
    if not selected:
        raise RuntimeError("engineering25-zero-or-unknown-case")
    result = unittest.TestResult()
    for test in selected:
        test(result)
    elapsed = time.monotonic() - start
    signal.alarm(0)
    report = {
        "schema": "phase6-d127-engineering25-guard-v1", "step": args.engineering25_step,
        "case": args.case, "approval_sha256": source_pin["approval_sha256"],
        "parent_review_pin_sha256": source_pin["pin_sha256"],
        "reviewer_identity": source_pin["reviewer_identity"], "review_sha256": source_pin["review_sha256"],
        "source_inventory": source_pin["source_inventory"],
        "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
        "failure_messages": [failure for _, failure in result.failures],
        "error_messages": [error for _, error in result.errors],
        "denied_api_attempts": attempts, "fake_leaf_calls": [], "observer_records": [],
        "retained_synthetic_roots": list(getattr(module, "RETAINED_ROOTS", [])),
        "unexpected_process_requests": len(attempts) - 9, "elapsed_seconds": elapsed,
    }
    output = pathlib.Path(args.output)
    if output.is_symlink() or output.exists():
        raise RuntimeError("engineering25-output-exists-or-symlink")
    output = output.resolve()
    if root != output and root not in output.parents:
        raise RuntimeError("engineering25-output-path-escape")
    payload = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
    if len(payload) > 8 * 1024 * 1024:
        raise RuntimeError("engineering25-report-size-exceeded")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(output.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    if not result.wasSuccessful() or len(attempts) != 9:
        return 1
    return 0

DENIED = []
SENTINEL_SOURCES = set()
def deny(event, args):
    # Pure sys.audit installation marker, never an OS invocation argument tuple.
    # The inner contract hook must observe and reject its own marker.
    if event in {'subprocess.Popen', 'os.system', 'os.exec', 'os.fork',
                 'os.forkpty', 'os.posix_spawn', 'os.spawn'}:
        if args == ('d125-deny-sentinel',):
            caller = sys._getframe(1)
            if caller.f_code.co_name == 'sentinel' and caller.f_code.co_filename in SENTINEL_SOURCES:
                return
        DENIED.append(event)
        raise RuntimeError('independent-debug-process-denied:' + event)

def blocked(*args, **kwargs):
    deny('subprocess.Popen', args)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[2])
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--probe-only', action='store_true')
    parser.add_argument('--engineering25-step', choices=('tracer', 'retained', 'publication', 'terminal'))
    parser.add_argument('--approval', type=pathlib.Path)
    parser.add_argument('--approval-sha256')
    parser.add_argument('--parent-review-pin', type=pathlib.Path)
    parser.add_argument('--parent-review-pin-sha256')
    parser.add_argument('--expected-reviewer-identity')
    parser.add_argument('--case')
    args = parser.parse_args()
    if args.engineering25_step:
        root = pathlib.Path(args.source_root).resolve(strict=True)
        if not args.case:
            raise SystemExit('engineering25-case-required')
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('55s engineering25 deadline')))
        signal.alarm(55)
        try:
            return _engineering25_run(args, root)
        finally:
            signal.alarm(0)
    SENTINEL_SOURCES.add(str(args.source_root.resolve() / 'tests/evidence/phase6_d125_consumers_contract.py'))
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('55s debug deadline')))
    signal.alarm(55)
    cached_popen = subprocess.Popen
    cached_system = os.system
    sys.addaudithook(deny)
    for event in ('subprocess.Popen', 'os.system', 'os.exec', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.spawn'):
        before = len(DENIED)
        try:
            sys.audit(event, 'independent-preimport-sentinel')
        except RuntimeError:
            pass
        assert len(DENIED) == before + 1, 'independent-preimport-denial-missing'
    for callback in (lambda: cached_popen(['/nonexistent-owner24-forbidden']),
                     lambda: cached_system('nonexistent-owner24-forbidden'),
                     lambda: cached_system('d125-deny-sentinel')):
        before = len(DENIED)
        try:
            callback()
        except RuntimeError as exc:
            assert 'independent-debug-process-denied' in str(exc)
        assert len(DENIED) == before + 1, 'cached-alias-denial-missing'
    for name in ('Popen', 'run', 'call', 'check_call', 'check_output'):
        setattr(subprocess, name, blocked)
    for name in dir(os):
        if name == 'system' or name.startswith(('fork', 'spawn', 'exec', 'posix_spawn')):
            if callable(getattr(os, name)):
                setattr(os, name, blocked)
    sentinel_count = len(DENIED)
    root = pathlib.Path(__file__).resolve().parents[2]
    paths = ['scripts/evidence/phase6_accounting.py',
             'tests/evidence/phase6_d125_consumers_contract.py',
             'tests/evidence/phase6_d125_authored_fixture.py',
             'tests/evidence/test_engineering24_accounting.py',
             'tests/evidence/phase6_owner24_debug_guard.py']
    inventory = {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in paths}
    inventory.update({'source:' + p: hashlib.sha256((args.source_root / p).read_bytes()).hexdigest()
                      for p in paths[:3]})
    result = None
    if not args.probe_only:
        spec = importlib.util.spec_from_file_location('owner24_debug_tests', root / paths[3])
        module = importlib.util.module_from_spec(spec)
        module.SOURCE_ROOT = args.source_root.resolve()
        spec.loader.exec_module(module)
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(module))
    report = {'inventory': inventory, 'preimport_denials': sentinel_count,
              'unexpected_process_requests': len(DENIED) - sentinel_count,
              'tests': result.testsRun if result else 0,
              'failures': len(result.failures) if result else 0,
              'errors': len(result.errors) if result else 0}
    if result is not None:
        report['retained_synthetic_roots'] = module.RETAINED_ROOTS
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    return 0 if (result is None or result.wasSuccessful()) and len(DENIED) == sentinel_count else 1

if __name__ == '__main__':
    sys.exit(main())

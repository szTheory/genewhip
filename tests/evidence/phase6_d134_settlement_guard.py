"""D134 clone/retained evidence runner.

This is an accidental-execution boundary for reviewed local Python, not a
sandbox against hostile source. It deliberately has no live mode. Denial
self-probes run before any project module is compiled or imported.
"""
import argparse
import builtins
import contextlib
import datetime
import decimal
import fcntl
import gettext
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types
import _colorize

_ENGLISH = gettext.NullTranslations()
argparse._ = _ENGLISH.gettext
argparse.ngettext = _ENGLISH.ngettext

PHASE = Path(".planning/phases/GW-06-shared-repairs-and-two-playable-routes")
APPROVAL = PHASE / "06-D134-APPROVAL.json"
ENTRY = PHASE / "06-D134-ENTRY.json"
PLAN = PHASE / "06-31-PLAN.md"
AMENDMENT = PHASE / "06-D134-SETTLEMENT-AMENDMENT.md"
EXPECTATIONS = PHASE / "06-31-SEMANTIC-EXPECTATIONS.md"
SOURCE_NAMES = (
    "scripts/evidence/phase6_accounting.py",
    "scripts/evidence/phase6_settlement.py",
    "tests/fixtures/phase6_repairs.py",
    "tests/evidence/phase6_d134_settlement_guard.py",
    "tests/evidence/test_phase6_d134_settlement.py",
)
LANES = ("tracer", "fault-matrix", "oracle-negative-controls",
         "live-capability-containment")
ORACLE_LANE_KEYS = {"tracer": "tracer", "fault-matrix": "matrix",
                    "oracle-negative-controls": "mutations",
                    "live-capability-containment": "denial_probes"}
DENIAL_PROBE_IDS = (
    "outside-open", "outside-enumeration", "unapproved-project-import",
    "process-call-entry", "unknown-fd", "dir-fd", "unknown-fd-stat",
    "unknown-fd-flock", "outside-stat", "outside-lstat", "outside-readlink",
    "outside-access", "socket-audit-only", "native-audit-only",
    "live-without-authority", "clone-live-root-confusion", "arbitrary-project-write",
    "extra-receipt", "extra-id", "unsafe-temp", "unsafe-lock", "forbidden-caller",
    "live-direct-ledger-open", "live-direct-receipt-open", "live-replace-receipt",
    "live-rename-escape", "live-unlink-ledger", "live-chmod-ledger",
    "live-nonexclusive-temp", "live-follow-temp", "live-alternate-lock",
    "live-wrong-receipt-link", "clone_has_no_live_mode",
    "d133_approval_cannot_authorize31", "outside_root_lock", "alternate31_receipt",
    "extra31_intent", "unreviewed_live_source", "stale_transition_binding",
    "unpinned_metadata_descriptor",
)
ALLOWED_IMPORTS = frozenset((
    "__future__", "argparse", "contextlib", "datetime", "decimal", "fcntl",
    "hashlib", "importlib", "importlib.util", "io", "json", "math", "os",
    "pathlib", "re", "stat", "subprocess", "sys", "tempfile", "time",
    "types", "typing", "_colorize",
))


class GuardDenied(RuntimeError):
    pass


class GuardDeadline(BaseException):
    pass


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def require(ok, reason):
    if not ok:
        raise AssertionError(reason)


def require_d134_surface(namespace):
    """Oracle RED seam: fail explicitly before exercising any producer path."""
    if "make_d134_settlement_record" not in namespace:
        raise AssertionError("missing-d134-constructor")
    if "d134_current_view" not in namespace:
        raise AssertionError("missing-d134-current-view")


def _read_exact(project, relative, data_blobs):
    path = project / relative
    require(not path.is_symlink(), "authority-source-symlink:" + str(relative))
    blob = path.read_bytes()
    data_blobs[path] = blob
    return blob


def _validate_bootstrap(project, pin_path, lane, mode):
    require(mode == "clone", "bootstrap-must-be-clone")
    require(pin_path.parent == project / PHASE, "exact-independent-review-directory")
    pin_bytes = pin_path.read_bytes()
    pin = json.loads(pin_bytes)
    require(pin.get("decision") == "accepted" and pin.get("reviewer_identity"),
            "independent-bootstrap-review-required")
    require(pin.get("bootstrap_before_compile") is True,
            "precompile-bootstrap-review-required")
    require(pin.get("stage") == "bootstrap-red", "bootstrap-red-stage-required")
    require(lane in pin.get("allowed_lanes", []), "independent-lane-admission-required")
    require(set(pin.get("source_sha256", {})) == set(SOURCE_NAMES),
            "exact-initial-source-roster-required")
    frozen = pin.get("frozen_rosters", {})
    require(set(frozen) == {"tracer", "matrix", "mutations", "semantic", "denial_probes"},
            "exact-independent-oracle-roster-keys")
    expected_sizes = {"tracer": 4, "matrix": 92, "mutations": 12,
                      "semantic": 108, "denial_probes": 40}
    require(all(isinstance(frozen[key], list) and len(frozen[key]) == size
                for key, size in expected_sizes.items()),
            "exact-independent-oracle-roster-sizes")
    oracle_lane = ORACLE_LANE_KEYS[lane]
    require(frozen.get(oracle_lane), "frozen-lane-roster-required")
    require(tuple(frozen.get("denial_probes", ())) == DENIAL_PROBE_IDS,
            "exact-frozen-denial-probe-roster")
    return pin_bytes, pin


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("clone", "retained"), required=True)
    parser.add_argument("--case", choices=LANES + ("final-package",), required=True)
    parser.add_argument("--review-pin", required=True)
    parser.add_argument("--output-root", required=True)
    args = parser.parse_args(argv)
    project = Path(__file__).resolve().parents[2]
    phase_root = (project / PHASE).resolve(strict=True)
    pin_path = Path(args.review_pin).resolve(strict=True)
    if args.mode == "clone":
        require(args.case == "tracer", "bootstrap-red-admits-tracer-only")
        pin_bytes, pin = _validate_bootstrap(project, pin_path, args.case, args.mode)
    else:
        require(args.case == "final-package", "retained-data-only-lane-required")
        pin_bytes = pin_path.read_bytes()
        pin = json.loads(pin_bytes)
        require(pin.get("decision") == "accepted" and
                pin.get("stage") == "completed-final-result-review",
                "completed-independent-final-review-required")

    data_blobs = {pin_path: pin_bytes}
    approval_bytes = _read_exact(project, APPROVAL, data_blobs)
    entry_bytes = _read_exact(project, ENTRY, data_blobs)
    plan_bytes = _read_exact(project, PLAN, data_blobs)
    amendment_bytes = _read_exact(project, AMENDMENT, data_blobs)
    expectation_bytes = _read_exact(project, EXPECTATIONS, data_blobs)
    approval = json.loads(approval_bytes)
    entry = json.loads(entry_bytes)
    retained_reports = {}
    if args.mode == "retained":
        bindings = pin.get("retained_reports", {})
        require(set(bindings) == set(LANES), "complete-retained-lane-report-roster")
        for lane, binding in bindings.items():
            relative = Path(binding.get("path", ""))
            require(not relative.is_absolute() and ".." not in relative.parts and
                    relative.parent == PHASE, "retained-report-path:" + lane)
            retained_path = project / relative
            require(not retained_path.is_symlink(), "retained-report-symlink:" + lane)
            retained_bytes = retained_path.read_bytes()
            require(len(retained_bytes) <= 16 * 1024 * 1024 and
                    digest(retained_bytes) == binding.get("sha256"),
                    "retained-report-hash:" + lane)
            retained_reports[lane] = json.loads(retained_bytes)
            data_blobs[retained_path] = retained_bytes
    if args.mode == "clone":
        require(digest(approval_bytes) == pin.get("approval_sha256") ==
                entry.get("approval_sha256"), "approval-pin")
        require(digest(entry_bytes) == pin.get("entry_sha256"), "entry-pin")
        require(digest(plan_bytes) == approval.get("plan_sha256"), "approved-plan-pin")
        require(digest(amendment_bytes) == approval.get("amendment_sha256"),
                "approved-amendment-pin")
        require(digest(expectation_bytes) == pin.get("semantic_expectations_sha256"),
                "independent-expectations-pin")
        require(entry.get("stage") == "SOURCE_OWNER_DISPATCH" and
                entry.get("admitted") is True and
                entry.get("boot_uuid") == approval.get("boot_uuid"),
                "actual-source-dispatch-required")
        snapshot = Path(approval["snapshot_path"])
        require(not snapshot.is_absolute() and ".." not in snapshot.parts and
                snapshot == Path("build/phase6/d134-31/entry-ledger.json"),
                "exact-parent-snapshot-path")
        baseline = (project / snapshot).read_bytes()
        require(digest(baseline) == approval.get("entry_ledger_sha256"),
                "clone-entry-byte-identity")
        originals = approval.get("entry_object_sha256", {})
        def unique_pairs(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate-json-key:" + key)
                result[key] = value
            return result
        original_values = json.loads(baseline, object_pairs_hook=unique_pairs)
        require(len(originals) == 68 and set(original_values) == set(originals),
                "exact-original68-roster")
        for key, value in original_values.items():
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                                 allow_nan=False).encode()
            require(digest(encoded) == originals[key], "original-object-digest:" + key)
        for source, wanted in pin["source_sha256"].items():
            blob = _read_exact(project, source, data_blobs)
            require(digest(blob) == wanted, "reviewed-source-sha256:" + source)
        out = Path(args.output_root)
        require(not out.is_absolute() and ".." not in out.parts and
                out == Path("build/phase6/d134-31/clone-runs"),
                "exact-clone-output-root")
        out_path = project / out
        require(not out_path.is_symlink() and out_path.is_dir() and
                out_path.resolve(strict=True) == out_path,
                "parent-prepared-direct-clone-output-root")
        root = Path(tempfile.mkdtemp(prefix="d134-31-", dir=out_path)).resolve(strict=True)
        clone_ledger = root / "phase6-repairs.json"
        clone_ledger.write_bytes(baseline)
    else:
        baseline = b""
        originals = {}
        root = None

    events = []
    expected_probe = [False]
    fds = {}
    fd_identity = {}
    source_paths = {project / item for item in SOURCE_NAMES} if args.mode == "clone" else set()
    authority_paths = set(data_blobs)
    real_open, real_close, real_import = os.open, os.close, builtins.__import__
    real_lstat, real_readlink, real_fstat = os.lstat, os.readlink, os.fstat
    helper_trace = []
    launch_attempts = {"subprocess": 0, "network": 0, "native": 0, "process": 0}
    injected_audit_events = {"socket": 0, "native": 0}

    def deny(name):
        events.append({"event": name, "expected": expected_probe[0]})
        raise GuardDenied("guard-denied:" + name)

    def in_clone(path):
        return root is not None and (path == root or root in path.parents)

    def resolved(raw, strict=False):
        # Outside-root names are rejected lexically, before metadata probing.
        # Within the fresh clone, resolve symlinks component by component and
        # reject any target that leaves the workspace.
        lexical = Path(os.path.abspath(os.fsdecode(raw)))
        if not in_clone(lexical):
            return lexical
        pending = list(lexical.relative_to(root).parts)
        current = root
        hops = 0
        while pending:
            part = pending.pop(0)
            if part == "..":
                if current == root:
                    deny("clone-traversal-escape")
                current = current.parent
                continue
            candidate = current / part
            try:
                info = real_lstat(candidate)
            except FileNotFoundError:
                if strict:
                    raise
                current = candidate
                continue
            if stat.S_ISLNK(info.st_mode):
                hops += 1
                require(hops <= 40, "symlink-loop")
                target = Path(real_readlink(candidate))
                if target.is_absolute():
                    target = Path(os.path.abspath(target))
                    if not in_clone(target):
                        deny("clone-symlink-escape")
                    current = root
                    pending = list(target.relative_to(root).parts) + pending
                else:
                    pending = list(target.parts) + pending
            else:
                current = candidate
            if not in_clone(current):
                deny("clone-symlink-escape")
        return current

    def check_fd(fd):
        if fd not in fds:
            deny("unknown-fd")
        try:
            info = real_fstat(fd)
        except OSError:
            deny("closed-fd")
        if (info.st_dev, info.st_ino) != fd_identity[fd]:
            deny("reused-fd")

    def check_path(raw, writing=False):
        if isinstance(raw, int):
            check_fd(raw)
            return
        path = resolved(raw)
        if not writing and (path in source_paths or path in authority_paths):
            return
        if in_clone(path):
            return
        deny("outside-clone-write" if writing else "outside-clone-read")

    def guarded_resolve(path, strict=False):
        check_path(path)
        return resolved(path, strict=strict)

    def audited(event, values):
        if event.startswith("subprocess."):
            launch_attempts["subprocess"] += 1
        elif event.startswith("socket."):
            if expected_probe[0]:
                injected_audit_events["socket"] += 1
            else:
                launch_attempts["network"] += 1
        elif event.startswith("ctypes."):
            if expected_probe[0]:
                injected_audit_events["native"] += 1
            else:
                launch_attempts["native"] += 1
        elif event in ("os.system", "pty.spawn", "os.exec", "os.spawn",
                       "os.posix_spawn", "os.fork"):
            launch_attempts["process"] += 1
        if event.startswith(("subprocess.", "socket.", "ctypes.", "os.exec",
                             "os.spawn", "os.posix_spawn", "os.fork")) or event in (
                "os.system", "pty.spawn"):
            deny("audit:" + event)
        if event == "import" and values[0].split(".")[0] not in ALLOWED_IMPORTS:
            deny("import:" + values[0].split(".")[0])
        if event == "open":
            writing = bool(values[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT |
                                        os.O_TRUNC | os.O_APPEND))
            check_path(values[0], writing)
        if event in ("os.listdir", "os.scandir"):
            check_path(values[0])
        mutation_indices = {"os.remove": (0,), "os.rmdir": (0,), "os.mkdir": (0,),
            "os.rename": (0, 1), "os.link": (0, 1), "os.symlink": (1,),
            "os.chmod": (0,), "os.truncate": (0,), "os.utime": (0,)}
        for index in mutation_indices.get(event, ()):
            check_path(values[index], True)

    def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
        if dir_fd is not None:
            deny("dir-fd")
        check_path(path, bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT |
                                      os.O_TRUNC | os.O_APPEND)))
        fd = real_open(path, flags, mode)
        info = real_fstat(fd)
        fds[fd] = True
        fd_identity[fd] = (info.st_dev, info.st_ino)
        return fd

    def guarded_close(fd):
        check_fd(fd)
        real_close(fd)
        fds.pop(fd, None)
        fd_identity.pop(fd, None)

    def fd_call(fn):
        def wrapped(fd, *args, **kwargs):
            check_fd(fd)
            return fn(fd, *args, **kwargs)
        return wrapped

    def path_call(fn, indices=(0,), writing=False):
        def wrapped(*args, **kwargs):
            if any(kwargs.get(key) is not None for key in ("dir_fd", "src_dir_fd", "dst_dir_fd")):
                deny("dir-fd:" + fn.__name__)
            for index in indices:
                check_path(args[index], writing)
            return fn(*args, **kwargs)
        return wrapped

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level or name.split(".")[0] not in ALLOWED_IMPORTS:
            deny("import:" + name)
        return real_import(name, globals, locals, fromlist, level)

    def live_capability(*, mode="clone", authority=None, lock=None,
                        lock_root="evidence/.d134-31-locks",
                        receipt="phase6-d134-settlement31-receipt.json",
                        transaction_id="D134-settlement31",
                        temporary=".phase6-repairs.json.a1b2c3d4",
                        caller="phase6_settlement", source_pin=None,
                        transition_pin=None, metadata_fd=None):
        if authority is None:
            deny("live-authority-absent")
        if authority.get("schema") != "d134-approval-v1":
            deny("unapproved-live-authority")
        if transaction_id != "D134-settlement31":
            deny("unadmitted-live-transaction-id")
        if receipt != "phase6-d134-settlement31-receipt.json":
            deny("unadmitted-live-receipt")
        if not temporary.startswith((".phase6-repairs.json.",
                                     ".phase6-d134-settlement31-receipt.json.")):
            deny("unsafe-live-temporary")
        if lock is not None:
            if not lock.startswith("genewhip-phase6-accounting-"):
                deny("unadmitted-live-lock")
            if lock_root != "evidence/.d134-31-locks":
                deny("outside-root-lock")
        if caller != "phase6_settlement":
            deny("forbidden-live-caller")
        if source_pin is not None and source_pin != "reviewed-d134-source-pin":
            deny("unreviewed-live-source")
        if transition_pin is not None and transition_pin != "admitted-d134-transition":
            deny("stale-transition-binding")
        if metadata_fd is not None:
            check_fd(metadata_fd)
        if mode not in ("clone", "retained"):
            deny("clone-has-no-live-mode")
        deny("live-capability-unavailable-in-clone-guard")

    live_root = project / "evidence"
    live_ledger = live_root / "phase6-repairs.json"
    live_receipt = live_root / "phase6-d134-settlement31-receipt.json"
    live_locks = live_root / ".d134-31-locks"
    live_lock = live_locks / ("genewhip-phase6-accounting-" +
                              digest(str(live_ledger).encode()) + ".lock")
    live_temp = live_root / ".phase6-repairs.json.a1b2c3d4"
    live_receipt_temp = live_root / ".phase6-d134-settlement31-receipt.json.a1b2c3d4"

    def live_path_policy(path, *, writing=False):
        if path in (live_ledger, live_receipt, live_lock, live_locks) or path == live_root:
            deny("clone-live-root-confusion")
        deny("unadmitted-live-path")

    def live_open_policy(path, flags):
        if path == live_ledger and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
            deny("direct-live-ledger-open")
        if path == live_receipt and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
            deny("direct-live-receipt-open")
        if path == live_lock:
            if flags != (os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)):
                deny("unsafe-live-lock-flags")
            deny("unadmitted-live-lock-open")
        if path in (live_temp, live_receipt_temp):
            required = os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_RDWR
            if flags != required:
                deny("unsafe-live-temp-flags")
            deny("unadmitted-live-temp-open")
        deny("unadmitted-live-open")

    def live_mutation_policy(event, source, destination=None):
        if event == "os.rename" and source == live_temp and destination == live_ledger:
            deny("unadmitted-ledger-replace")
        if event == "os.link" and source == live_receipt_temp and destination == live_receipt:
            deny("unadmitted-receipt-link")
        if event == "os.rename" and source == live_temp and destination != live_ledger:
            deny("live-rename-escape")
        if event == "os.remove" and source == live_ledger:
            deny("live-unlink-ledger")
        if event == "os.chmod" and source == live_ledger:
            deny("live-chmod-ledger")
        deny("unadmitted-live-mutation:" + event)

    def probe(name, action, mechanism):
        expected_probe[0] = True
        start = len(events)
        try:
            action()
        except GuardDenied:
            require(len(events) == start + 1, "probe-single-denial:" + name)
            events[-1].update(probe_case_id=name, mechanism=mechanism)
        else:
            raise AssertionError("probe-not-denied:" + name)
        finally:
            expected_probe[0] = False

    # Install path/descriptor wrappers before probes so each actual API probe is
    # stopped at the guard boundary. The audit hook is installed separately.
    for name in ("read", "write", "fsync", "fstat", "fchmod", "ftruncate", "lseek", "fdopen"):
        setattr(os, name, fd_call(getattr(os, name)))
    for name in ("stat", "lstat", "readlink", "access", "statvfs", "listdir", "scandir"):
        setattr(os, name, path_call(getattr(os, name)))
    for name in ("unlink", "remove", "rmdir", "mkdir", "chmod", "chown", "truncate", "utime"):
        setattr(os, name, path_call(getattr(os, name), writing=True))
    for name in ("rename", "replace", "link"):
        setattr(os, name, path_call(getattr(os, name), (0, 1), True))
    os.symlink = path_call(os.symlink, (1,), True)
    fcntl.flock = fd_call(fcntl.flock)
    fcntl.lockf = fd_call(fcntl.lockf)
    os.open, os.close = guarded_open, guarded_close
    Path.resolve = guarded_resolve
    builtins.__import__ = guarded_import
    sys.addaudithook(audited)

    # Actual API-entry denials, independent of Python audit-event-only probes.
    probe("outside-open", lambda: os.open(project / "D134-no-open", os.O_RDONLY), "api")
    probe("outside-enumeration", lambda: os.listdir(project), "api")
    probe("unapproved-project-import", lambda: __import__("d128_seam"), "api")
    probe("process-call-entry", lambda: os.system("D134-no-process"), "api")
    probe("unknown-fd", lambda: os.fchmod(987654, 0o600), "api")
    probe("dir-fd", lambda: os.open("absent", os.O_RDONLY, dir_fd=987654), "api")
    probe("unknown-fd-stat", lambda: os.stat(0), "api")
    probe("unknown-fd-flock", lambda: fcntl.flock(0, fcntl.LOCK_EX | fcntl.LOCK_NB), "api")
    probe("outside-stat", lambda: os.stat(project / "D134-metadata"), "api")
    probe("outside-lstat", lambda: os.lstat(project / "D134-metadata"), "api")
    probe("outside-readlink", lambda: os.readlink(project / "D134-metadata"), "api")
    probe("outside-access", lambda: os.access(project / "D134-metadata", os.R_OK), "api")
    # These are intentionally labelled audit-only: no socket/native call occurs.
    probe("socket-audit-only", lambda: sys.audit("socket.__new__", None, 0, 0, 0), "audit")
    probe("native-audit-only", lambda: sys.audit("ctypes.dlopen", "D134-probe"), "audit")
    def checked_probe(probe_id, action):
        expected_probe[0] = True
        start = len(events)
        try:
            action()
        except GuardDenied:
            require(len(events) == start + 1, "probe-single-denial:" + probe_id)
            events[-1].update(probe_case_id=probe_id, mechanism="guard-policy")
        else:
            raise AssertionError("probe-not-denied:" + probe_id)
        finally:
            expected_probe[0] = False
        require(len(events) == start + 1, "probe-single-denial:" + probe_id)

    # Keep the exact frozen legacy rejection identifiers and their distinct
    # policy entry points; every probe establishes one specific denial.
    checked_probe("live-without-authority", lambda: live_capability(authority=None))
    checked_probe("clone-live-root-confusion", lambda: live_path_policy(live_ledger))
    checked_probe("arbitrary-project-write", lambda: check_path(project / "D134-write", True))
    checked_probe("extra-receipt", lambda: live_capability(authority={"schema": "d134-approval-v1"}, receipt="extra.json"))
    checked_probe("extra-id", lambda: live_capability(authority={"schema": "d134-approval-v1"}, transaction_id="extra"))
    checked_probe("unsafe-temp", lambda: live_capability(authority={"schema": "d134-approval-v1"}, temporary=".unsafe"))
    checked_probe("unsafe-lock", lambda: live_capability(authority={"schema": "d134-approval-v1"}, lock="unsafe.lock"))
    checked_probe("forbidden-caller", lambda: live_capability(authority={"schema": "d134-approval-v1"}, caller="phase6_routes"))
    checked_probe("live-direct-ledger-open", lambda: live_open_policy(live_ledger, os.O_WRONLY))
    checked_probe("live-direct-receipt-open", lambda: live_open_policy(live_receipt, os.O_WRONLY))
    checked_probe("live-replace-receipt", lambda: live_mutation_policy("os.rename", live_temp, live_receipt))
    checked_probe("live-rename-escape", lambda: live_mutation_policy("os.rename", live_temp, live_root / "other.json"))
    checked_probe("live-unlink-ledger", lambda: live_mutation_policy("os.remove", live_ledger))
    checked_probe("live-chmod-ledger", lambda: live_mutation_policy("os.chmod", live_ledger))
    checked_probe("live-nonexclusive-temp", lambda: live_open_policy(live_temp, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW))
    checked_probe("live-follow-temp", lambda: live_open_policy(live_temp, os.O_RDWR | os.O_CREAT | os.O_EXCL))
    checked_probe("live-alternate-lock", lambda: live_open_policy(live_locks / "alternate.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW))
    checked_probe("live-wrong-receipt-link", lambda: live_mutation_policy("os.link", live_temp, live_receipt))

    # D134 adds eight separately named capability predicates.
    checked_probe("clone_has_no_live_mode", lambda: live_capability(mode="live", authority={"schema": "d134-approval-v1"}))
    checked_probe("d133_approval_cannot_authorize31", lambda: live_capability(authority={"schema": "d133-approval-v1"}))
    checked_probe("outside_root_lock", lambda: live_capability(authority={"schema": "d134-approval-v1"}, lock="genewhip-phase6-accounting-valid.lock", lock_root="elsewhere"))
    checked_probe("alternate31_receipt", lambda: live_capability(authority={"schema": "d134-approval-v1"}, receipt="alternate31.json"))
    checked_probe("extra31_intent", lambda: live_capability(authority={"schema": "d134-approval-v1"}, transaction_id="extra31"))
    checked_probe("unreviewed_live_source", lambda: live_capability(authority={"schema": "d134-approval-v1"}, source_pin="not-reviewed"))
    checked_probe("stale_transition_binding", lambda: live_capability(authority={"schema": "d134-approval-v1"}, transition_pin="stale"))
    checked_probe("unpinned_metadata_descriptor", lambda: live_capability(authority={"schema": "d134-approval-v1"}, metadata_fd=99931))

    bootstrap_denials = len(events)
    require(bootstrap_denials == 40, "bootstrap-denial-count")
    observed_probe_ids = tuple(row.get("probe_case_id") for row in events)
    require(observed_probe_ids == DENIAL_PROBE_IDS and len(set(observed_probe_ids)) == 40,
            "exact-unique-40-denial-probe-roster")
    require(observed_probe_ids == tuple(pin["frozen_rosters"]["denial_probes"]),
            "review-pinned-40-denial-probe-roster")

    # Install sticky restrictions only after the reviewed self-probes pass.
    def denied_primitive(*_args, **_kwargs):
        deny("unsupported-process-or-fd-primitive")
    for name in ("dup", "dup2", "chdir", "fchdir", "readv", "writev", "pread", "pwrite",
                 "sendfile", "copy_file_range", "fwalk"):
        if hasattr(os, name):
            setattr(os, name, denied_primitive)
    fcntl.fcntl = fcntl.ioctl = denied_primitive

    blobs = {name: data_blobs[project / name] for name in SOURCE_NAMES}
    require(all(digest(blobs[name]) == pin["source_sha256"][name] for name in SOURCE_NAMES),
            "reviewed-source-stable-after-probes")

    def load(name, source, injected=None):
        module = types.ModuleType(name)
        module.__file__ = str(project / source)
        if injected:
            module.__dict__.update(injected)
        exec(compile(blobs[source], source, "exec"), module.__dict__)
        return module

    rows = []
    roster = []
    retained_semantic_case_ids = None
    started = time.monotonic()

    def timeout(_signum, _frame):
        raise GuardDeadline("internal-55-second-deadline")

    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(55)
    try:
        if args.mode == "clone":
            accounting = load("d134_canonical", SOURCE_NAMES[0])
            settlement = load("d134_settlement", SOURCE_NAMES[1], {"ACCOUNTING": accounting,
                "_D134_CAPABILITY": {"mode": "clone", "root": str(root)}})
            oracle = load("d134_independent_oracle", SOURCE_NAMES[4])
            oracle_roster_key = ORACLE_LANE_KEYS[args.case]
            roster = list(pin["frozen_rosters"][oracle_roster_key])
            # Surface RED must be decided against the exact reviewed wrapper
            # before the legacy coordinator is compiled. This keeps an old
            # eager game/compiler import from masking the intended assertion.
            oracle.require_d134_surface(settlement.__dict__)
            original_argv = sys.argv
            try:
                sys.argv = [original_argv[0], "--accounting-scope", "D134"]
                coordinator = load("d134_coordinator", SOURCE_NAMES[2],
                                   {"D134_SETTLEMENT": settlement})
            finally:
                sys.argv = original_argv
            context = {"approval": approval, "entry": entry, "baseline": baseline,
                "expected_objects": originals, "workspace": root,
                "coordinator": coordinator, "settlement": settlement,
                "guard": sys.modules.get(__name__), "require_d134_surface": require_d134_surface}
            lane_rows = oracle.run_tracer(settlement.__dict__, context, root) if args.case == "tracer" else \
                oracle.run_lane(args.case, settlement.__dict__, context, root)
            rows = list(lane_rows)
            require([row.get("case_id") for row in rows] == roster,
                    "independent-frozen-roster")
        else:
            # Retained mode is added after final source/results reviews. It must
            # validate pinned JSON only and never compile source or call helpers.
            qualified_semantic_ids = []
            semantic_case_ids_by_lane = {}
            for lane in LANES:
                report = retained_reports[lane]
                require(report.get("status") == "pass" and report.get("lane") == lane,
                        "retained-lane-pass:" + lane)
                require(report.get("mode") == "clone" and
                        report.get("unexpected_denial_count") == 0 and
                        report.get("bootstrap_denials") == 40,
                        "retained-lane-denials:" + lane)
                denial_ids = tuple(row.get("probe_case_id")
                                   for row in report.get("denials", []))
                require(denial_ids == DENIAL_PROBE_IDS,
                        "retained-exact-denial-roster:" + lane)
                if lane != "live-capability-containment":
                    oracle_lane = ORACLE_LANE_KEYS[lane]
                    expected_ids = pin["frozen_rosters"][oracle_lane]
                    actual_ids = report.get("case_ids", [])
                    require(actual_ids == expected_ids and
                            [row.get("case_id") for row in report.get("cases", [])] == expected_ids,
                            "retained-exact-semantic-roster:" + lane)
                    rows.extend(report.get("cases", []))
                    semantic_case_ids_by_lane[oracle_lane] = actual_ids
                    qualified_semantic_ids.extend((oracle_lane, case_id)
                                                  for case_id in actual_ids)
            roster = qualified_semantic_ids
            require(len(roster) == 108 and len(set(roster)) == 108 and
                    all(row.get("status") == "pass" for row in rows),
                    "retained-108-semantic-rows")
            require(not helper_trace, "retained-zero-canonical-calls")
            retained_semantic_case_ids = semantic_case_ids_by_lane
        if args.mode == "clone":
            retained_semantic_case_ids = None
    except (Exception, GuardDeadline) as exc:
        assertion = str(exc)
        intended_red = (args.mode == "clone" and args.case == "tracer" and
                        type(exc) is AssertionError and assertion in
                        ("missing-d134-constructor", "missing-d134-current-view"))
        rows.append({"case_id": "bootstrap-red" if intended_red else "bootstrap-or-lane",
                     "status": "fail", "exception": type(exc).__name__,
                     "assertion": assertion,
                     "failure_classification": "INTENDED_MISSING_D134_SURFACE" if intended_red
                     else "INVALID_RED" if args.mode == "clone" and args.case == "tracer"
                     else "LANE_FAILURE"})
    finally:
        signal.alarm(0)

    unexpected = [row for row in events if not row.get("expected")]
    passed = (bool(roster) and len(rows) == len(roster) and
              all(row.get("status") == "pass" for row in rows) and not unexpected and
              time.monotonic() - started <= 60)
    report = {"schema": "d134-clone-guard-report-v1", "mode": args.mode,
        "lane": args.case, "status": "pass" if passed else "fail",
        "case_ids": [row.get("case_id") for row in rows], "denominator": len(roster),
        "cases": rows, "source_sha256": pin.get("source_sha256"),
        "baseline_sha256": digest(baseline) if baseline else None,
        "review_pin_sha256": digest(pin_bytes), "bootstrap_denials": bootstrap_denials,
        "denials": events, "unexpected_denial_count": len(unexpected),
        "launch_attempts": launch_attempts, "injected_audit_events": injected_audit_events,
        "canonical_helper_trace": helper_trace, "canonical_calls_this_run": len(helper_trace),
        "failure_classification": (rows[-1].get("failure_classification")
                                   if rows and rows[-1].get("status") == "fail" else None),
        "semantic_case_ids_by_lane": retained_semantic_case_ids,
        "workspace": root.name if root else None}
    print(json.dumps(report, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        status = main()
    except Exception as exc:
        # Keep bootstrap failures machine-readable and path-free even when they
        # happen before the per-lane reporting boundary.
        print(json.dumps({"schema": "d134-clone-guard-report-v1", "status": "fail",
                          "failure_classification": "BOOTSTRAP_FAILURE",
                          "exception": type(exc).__name__, "assertion": str(exc)},
                         sort_keys=True))
        status = 1
    raise SystemExit(status)

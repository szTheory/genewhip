#!/usr/bin/env python3
"""D125 guarded consumer contract entry.

The process-denial boundary is installed before any project module is loaded.
It is an accidental-execution guard, not an OS sandbox.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import platform
import re
import select
import shutil
import sys
import tempfile
import time
from typing import Any


class ProcessDenied(RuntimeError):
    pass


class ChildProcessMonitor:
    """Kernel kqueue observer for child creation and process replacement."""

    def __init__(self) -> None:
        required = ("kqueue", "kevent", "KQ_FILTER_PROC", "KQ_EV_ADD",
                    "KQ_EV_CLEAR", "KQ_NOTE_FORK", "KQ_NOTE_EXEC")
        if any(not hasattr(select, name) for name in required):
            raise RuntimeError("independent-process-monitor-unavailable")
        self.pid = os.getpid()
        self.queue = select.kqueue()
        self.events: list[dict[str, Any]] = []
        event = select.kevent(self.pid, filter=select.KQ_FILTER_PROC,
            flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
            fflags=select.KQ_NOTE_FORK | select.KQ_NOTE_EXEC)
        self.queue.control([event], 0, 0)

    def poll(self) -> list[dict[str, Any]]:
        found = self.queue.control(None, 64, 0.01)
        for event in found:
            self.events.append({"pid": event.ident, "filter": event.filter,
                                "flags": event.flags, "fflags": event.fflags,
                                "data": event.data})
        return self.events

    @property
    def process_events(self) -> int:
        self.poll()
        return len(self.events)


PROCESS_MONITOR = ChildProcessMonitor()


class DenyBoundary:
    """Sticky process denial with both audit-hook and direct API coverage."""

    def __init__(self) -> None:
        self._attempts: list[dict[str, Any]] = []
        self._installation_attempts: list[dict[str, Any]] = []
        self._decisions: list[dict[str, Any]] = []
        self._installing = True
        self._next_violation, self._current_violation = self._counter()
        self.installed = False
        self._originals: dict[tuple[int, str], Any] = {}

    @staticmethod
    def _counter():
        value = 0
        def increment():
            nonlocal value
            value += 1
            return value
        def read():
            return value
        return increment, read

    @property
    def attempts(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._attempts)

    @property
    def violation_count(self) -> int:
        return self._current_violation()

    @property
    def permitted(self) -> int:
        return PROCESS_MONITOR.process_events

    def _record(self, api: str, detail: Any = None) -> None:
        frame = sys._getframe(2)
        row = {"api": api, "detail": repr(detail)[:512],
               "caller": frame.f_code.co_name, "monotonic": time.monotonic()}
        if self._installing:
            self._installation_attempts.append(row)
        else:
            row["violation"] = self._next_violation()
            self._attempts.append(row)
            self._decisions.append({"api": api, "decision": "denied",
                                    "violation": row["violation"]})
        raise ProcessDenied(f"process-denied:{api}")

    def _audit(self, event: str, args: tuple[Any, ...]) -> None:
        if event in {"subprocess.Popen", "os.system", "os.exec", "os.fork",
                     "os.forkpty", "os.posix_spawn", "os.spawn"}:
            self._record(f"audit:{event}", args)

    def _wrap(self, owner: Any, name: str, label: str) -> None:
        value = getattr(owner, name, None)
        if not callable(value):
            return
        self._originals[(id(owner), name)] = value

        def denied(*args: Any, **kwargs: Any) -> Any:
            self._record(label, args[0] if args else kwargs)

        setattr(owner, name, denied)

    def install(self, *, register_hook=sys.addaudithook, sentinel_emitter=sys.audit) -> None:
        # Install the audit hook before importing or loading project code.
        register_hook(self._audit)
        self.installed = True
        for event in ("subprocess.Popen", "os.system", "os.exec", "os.fork",
                      "os.forkpty", "os.posix_spawn", "os.spawn"):
            self.sentinel(event, emitter=sentinel_emitter)
        self.begin_guarded_stage()
        import subprocess

        # Direct routes protect references imported after installation. The
        # audit hook also catches cached Popen and other existing aliases.
        for name in ("Popen", "call", "run", "check_call", "check_output"):
            self._wrap(subprocess, name, f"subprocess.{name}")
        for name in dir(os):
            if name == "system" or name.startswith(("posix_spawn", "fork", "exec", "spawn")):
                if callable(getattr(os, name, None)):
                    self._wrap(os, name, f"os.{name}")

    def sentinel(self, event: str, *, emitter=sys.audit) -> None:
        before = len(self._installation_attempts)
        try:
            emitter(event, "d125-deny-sentinel")
        except ProcessDenied:
            pass
        if (len(self._installation_attempts) != before + 1
                or self._installation_attempts[-1]["api"] != f"audit:{event}"):
            raise RuntimeError(f"audit-hook-not-observed:{event}")

    def begin_guarded_stage(self) -> None:
        self._installing = False

    def report(self) -> dict[str, Any]:
        return {"installed": self.installed, "attempted": len(self._attempts),
                "denied_api_attempts": len(self._attempts),
                "violation_count": self.violation_count,
                "permitted": self.permitted, "attempts": list(self._attempts),
                "observed_process_events": PROCESS_MONITOR.process_events,
                "permitted_field_semantics": "legacy alias for observer event records; not an exact launch census",
                "decisions": list(self._decisions),
                "installation_attempts": list(self._installation_attempts),
                "independent_process_monitor": {"kind": "kqueue-KQ_FILTER_PROC",
                    "pid": PROCESS_MONITOR.pid,
                    "events": list(PROCESS_MONITOR.events)}}


BOUNDARY = DenyBoundary()
BOUNDARY.install()
INSTALLATION_PROOF = BOUNDARY.report()


def _write_create_once(path: pathlib.Path, value: dict[str, Any]) -> None:
    root = pathlib.Path(__file__).resolve().parents[2]
    path = _resolve_under(root, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)


def _resolve_under(root: pathlib.Path, candidate: pathlib.Path) -> pathlib.Path:
    root = root.resolve(strict=True)
    resolved = candidate if candidate.is_absolute() else root / candidate
    if ".." in pathlib.PurePath(candidate).parts:
        raise ValueError("traversal-component-rejected")
    if resolved != root and not resolved.is_relative_to(root):
        raise ValueError("path-escapes-synthetic-root")
    cursor = root
    for part in resolved.relative_to(root).parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("symlink-in-synthetic-path")
    resolved = resolved.resolve(strict=False)
    if not resolved.is_relative_to(root):
        raise ValueError("path-escapes-synthetic-root")
    return resolved


def _create_synthetic_consumer_root(parent: pathlib.Path) -> dict[str, Any]:
    """Author a project-shaped, unusable data root; copy no production data."""
    root = pathlib.Path(tempfile.mkdtemp(prefix="synthetic-consumer-", dir=parent)).resolve()
    for directory in ("evidence", "receipts", "build/phase6", "build/phase6/pcm",
                      "metadata", "fixtures", "output"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    authored = {
        "evidence/phase6-repairs.json": b'{"schema":"d125-synthetic-ledger-v1","records":[]}\n',
        "receipts/input.json": b'{"schema":"synthetic-receipt-v1","status":"fixture"}\n',
        "build/phase6/client-metadata.json": b'{"executable":false,"source":"synthetic"}\n',
        "build/phase6/d125-global-anchor.json": b'{"purpose":"synthetic-only","boot_identity":"synthetic-boot","monotonic_started_at":1.0}\n',
        "build/phase6/pcm/control.pcm": b"\x00\x00\x00\x00",
        "metadata/client.json": b'{"executable":false}\n',
        "fixtures/unusable.rom": b"D125-NO-GUEST-IMAGE",
    }
    for relative, content in authored.items():
        target = _resolve_under(root, root / relative)
        target.write_bytes(content)
    roots = {
        "project": root,
        "ledger": root / "evidence/phase6-repairs.json",
        "receipt": root / "receipts/input.json",
        "build": root / "build/phase6",
        "anchor": root / "build/phase6/d125-global-anchor.json",
        "pcm": root / "build/phase6/pcm",
        "output": root / "output",
        "metadata": root / "metadata/client.json",
        "unusable_guest": root / "fixtures/unusable.rom",
    }
    checked = {}
    for name, path in roots.items():
        checked[name] = _resolve_under(root, path).relative_to(root).as_posix()
    (root / "escape").symlink_to(parent.resolve(strict=True))
    return {"root": root, "roots": roots, "relative_roots": checked,
            "authored_sha256": {name: hashlib.sha256(data).hexdigest()
                                for name, data in authored.items()},
            "production_tree_copied": False, "usable_guest_or_client": False}


def _verify_synthetic_roots(synthetic: dict[str, Any], root: pathlib.Path) -> bool:
    base = synthetic["root"].resolve(strict=True)
    if not base.is_relative_to(root.resolve(strict=True)):
        return False
    for path in synthetic["roots"].values():
        _resolve_under(base, path)
    if synthetic["production_tree_copied"] or synthetic["usable_guest_or_client"]:
        return False
    for candidate in (root, base / "escape" / "ledger.json", base / "evidence" / ".." / "ledger.json"):
        try:
            _resolve_under(base, candidate)
        except (ValueError, OSError):
            continue
        return False
    return True


def _source_sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _require_independent_containment_review(review_path: pathlib.Path,
                                            source_path: pathlib.Path,
                                            guard_path: pathlib.Path,
                                            parent_pin_path: pathlib.Path | None = None,
                                            parent_pin_sha256: str | None = None,
                                            expected_reviewer_identity: str | None = None,
                                            expected_reviewer_role: str | None = None) -> dict[str, Any]:
    """Consume the exact tuple supplied by the parent after separate review.

    The parent observes the actual reviewer completion and supplies the pin's
    digest through its launch context. This is an operational trust boundary;
    local JSON/Markdown alone cannot authenticate a reviewer or hostile caller.
    """
    project_root = pathlib.Path(__file__).resolve().parents[2]
    if source_path.resolve(strict=True) != pathlib.Path(__file__).resolve(strict=True):
        raise RuntimeError("parent-review-source-is-not-entry")
    if parent_pin_path is None or not parent_pin_sha256:
        raise RuntimeError("parent-observed-review-pin-required")
    parent_pin_path = _resolve_under(project_root, parent_pin_path)
    if _source_sha(parent_pin_path) != parent_pin_sha256:
        raise RuntimeError("parent-review-pin-digest-mismatch")
    pin = json.loads(parent_pin_path.read_bytes())
    if (not expected_reviewer_identity or expected_reviewer_role != "gsd-code-reviewer" or
            pin.get("reviewer_identity") != expected_reviewer_identity or
            pin.get("reviewer_role") != expected_reviewer_role or pin.get("test_fixture_only") is True):
        raise RuntimeError("parent-review-expected-identity-or-role-mismatch")
    if pin.get("dependent_source_sha256") != _dependent_source_identity():
        raise RuntimeError("parent-review-dependent-source-closure-stale")
    review_path = _resolve_under(project_root, review_path)
    guard_path = _resolve_under(project_root, guard_path)
    return _validate_review_tuple(pin, review_path, source_path, guard_path, project_root)


def _validate_review_tuple(pin: dict[str, Any], review_path: pathlib.Path,
                           source_path: pathlib.Path, guard_path: pathlib.Path,
                           project_root: pathlib.Path) -> dict[str, Any]:
    expected = {"source_sha256": _source_sha(source_path),
                "guard_output_sha256": _source_sha(guard_path),
                "review_sha256": _source_sha(review_path),
                "source_path": source_path.relative_to(project_root).as_posix(),
                "guard_output_path": guard_path.relative_to(project_root).as_posix(),
                "review_path": review_path.relative_to(project_root).as_posix()}
    if (pin.get("schema") != "d125-parent-observed-review-v1"
            or pin.get("origin") != "parent-observed-separate-reviewer-completion"
            or pin.get("tool_handoff_result") != "completed"
            or pin.get("decision") != "accepted"
            or pin.get("reviewer_role") != "gsd-code-reviewer"
            or not pin.get("reviewer_identity")
            or any(pin.get(key) != value for key, value in expected.items())):
        raise RuntimeError("parent-observed-review-tuple-missing-or-stale")
    raw = review_path.read_text()
    if not raw.startswith("---\n"):
        raise RuntimeError("containment-review-frontmatter-missing")
    frontmatter = raw.split("---\n", 2)[1]
    fields = {key: value.strip().strip('"') for key, value in
              re.findall(r"^([a-z_][a-z_0-9]*):[ \t]*(.*?)[ \t]*$", frontmatter, re.MULTILINE)}
    guard_payload = json.loads(guard_path.read_text())
    identity = fields.get("reviewer_identity", "")
    producer = fields.get("producer_identity", "")
    if (fields.get("decision") != "accepted" or fields.get("status") != "accepted" or
            fields.get("source_sha256") != _source_sha(source_path) or
            fields.get("guard_output_sha256") != _source_sha(guard_path) or
            guard_payload.get("status") != "passed" or
            fields.get("reviewer_role") != "gsd-code-reviewer" or len(identity) < 3 or
            not producer or identity == producer or identity != pin["reviewer_identity"] or
            fields.get("tool_handoff_result") != "completed" or
            fields.get("critical_findings") != "0" or fields.get("high_findings") != "0" or
            BOUNDARY.violation_count != 0 or PROCESS_MONITOR.process_events != 0):
        raise RuntimeError("independent-containment-review-missing-or-stale")
    return {"reviewer_identity": identity, "reviewer_role": fields["reviewer_role"],
            "review_sha256": _source_sha(review_path), "guard_sha256": _source_sha(guard_path),
            "source_sha256": _source_sha(source_path),
            "tool_handoff_result": fields["tool_handoff_result"],
            "origin": pin["origin"]}


def _load_guarded_consumer_sources(synthetic: dict[str, Any]) -> dict[str, Any]:
    """Load reviewed production modules only from the constrained synthetic root."""
    # Admission is set only after the parent tuple gate in the entry dispatch.
    if synthetic.get("review_admission") is not _IMPORT_ADMISSION:
        raise RuntimeError("consumer-import-parent-admission-required")
    if not BOUNDARY.installed or BOUNDARY.violation_count or PROCESS_MONITOR.process_events:
        raise RuntimeError("guard-invalid-before-project-import")
    project = pathlib.Path(__file__).resolve().parents[2]
    root = _resolve_under(project, synthetic["root"])
    if not _verify_synthetic_roots(synthetic, project):
        raise RuntimeError("synthetic-root-binding-invalid")
    copied = {}
    for relative in CONSUMER_SOURCE_PATHS:
        source = _resolve_under(project, pathlib.Path(relative))
        target = _resolve_under(root, pathlib.Path(relative))
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(source.read_bytes())
        copied[relative] = _source_sha(target)
    modules, bindings = [], []
    synthetic["loaded_module_records"] = modules
    synthetic["binding_records"] = bindings
    original_spec = importlib.util.spec_from_file_location

    def checked_spec(name, location, *args, **kwargs):
        path = _resolve_under(root, pathlib.Path(location))
        relative = path.relative_to(root).as_posix()
        if relative not in copied or _source_sha(path) != copied[relative]:
            raise RuntimeError("unknown-or-drifted-consumer-source:" + relative)
        if BOUNDARY.violation_count or PROCESS_MONITOR.process_events:
            raise RuntimeError("guard-invalid-before-nested-import")
        spec = original_spec(name, path, *args, **kwargs)
        loader = spec.loader

        class BoundLoader:
            def create_module(self, selected):
                return loader.create_module(selected)

            def exec_module(self, module):
                # Audited top-level effects are stdlib imports, definitions,
                # Path constants and the coordinator's three checked imports.
                loader.exec_module(module)
                if BOUNDARY.violation_count or PROCESS_MONITOR.process_events:
                    raise RuntimeError("sticky-project-import-violation")
                if pathlib.Path(module.__file__).resolve(strict=True) != path:
                    raise RuntimeError("consumer-loaded-file-drift")
                for key, value in vars(module).copy().items():
                    if isinstance(value, pathlib.Path) and value.is_absolute():
                        if relative == "tests/fixtures/phase6_repairs.py" and key == "ACCOUNTING_ANCHOR":
                            setattr(module, key, synthetic["roots"]["anchor"])
                        else:
                            _resolve_under(root, value)
                # Only environmental and exact execution-leaf seams belong in
                # this callback. It is supplied by the reviewed fixture helper.
                synthetic["bind_instance"](relative, module, bindings)
                synthetic["check_instance"](relative, module)
                modules.append((relative, module))

        spec.loader = BoundLoader()
        return spec

    importlib.util.spec_from_file_location = checked_spec
    try:
        spec = checked_spec("d125_coordinator", root / "tests/fixtures/phase6_repairs.py")
        coordinator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(coordinator)
        spec = checked_spec("d125_checker", root / "tests/evidence/phase6_tank_continuation_contract.py")
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
    except BaseException:
        importlib.util.spec_from_file_location = original_spec
        raise
    # Keep the wrapper through the transaction to bind all dynamic instances.
    return {"coordinator": coordinator, "checker": checker, "modules": modules,
            "bindings": bindings, "source_sha256": copied,
            "restore_loader": lambda: setattr(importlib.util, "spec_from_file_location", original_spec)}


CONSUMER_SOURCE_PATHS = (
    "tests/fixtures/phase6_repairs.py", "scripts/evidence/phase6_routes.py",
    "tests/session/phase6_route_contract.py", "scripts/evidence/phase6_accounting.py",
    "tests/evidence/phase6_tank_continuation_contract.py",
    "tests/evidence/phase6_stack_observation_contract.py", "tests/fixtures/phase4_game.py",
)
_IMPORT_ADMISSION = object()


def _dependent_source_identity():
    root = pathlib.Path(__file__).resolve().parents[2]
    return {name: _source_sha(root / name) for name in (*CONSUMER_SOURCE_PATHS,
        "tests/evidence/phase6_d125_authored_fixture.py")}


def consumer_tracer(args):
    project = pathlib.Path(__file__).resolve().parents[2]
    output = _resolve_under(project, args.output)
    if output.exists() or output.is_symlink():
        raise FileExistsError("consumer-report-already-exists")
    synthetic = None
    loaded = None
    fixture = None
    report = {"schema": "phase6-d125-consumer-tests-v1", "status": "failed",
              "project_imports": 0, "consumer_assertions": 0,
              "source_sha256": _source_sha(pathlib.Path(__file__)),
              "dependent_source_sha256": _dependent_source_identity()}
    import signal
    prior_alarm = signal.getsignal(signal.SIGALRM)
    def deadline(_signum, _frame):
        raise TimeoutError("consumer-55-second-deadline")
    try:
        if args.case in QUALIFICATION23_CASES:
            _qualification23_entry(args, project)
        if args.case in ENGINEERING24_CASES:
            _engineering24_entry(args, project)
        if not all((args.containment_review, args.guard_report, args.parent_review_pin, args.parent_review_pin_sha256)):
            raise RuntimeError("consumer-review-inputs-required")
        report["mode"] = "accounting" if args.accounting_self_test else args.consumer_stage
        report["case"] = args.case
        report["command"] = sys.argv[1:]
        report["review_admission"] = _require_independent_containment_review(
            args.containment_review, pathlib.Path(__file__).resolve(), args.guard_report,
            args.parent_review_pin, args.parent_review_pin_sha256,
            args.expected_reviewer_identity, args.expected_reviewer_role)
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(55)
        current_tuple = _qualification23_current_tuple(args, project) if args.case == "qualification23-final" else None
        workspace = _resolve_under(project, output.parent / (output.stem + "-workspace"))
        workspace.mkdir(parents=True, exist_ok=False)
        synthetic = _create_synthetic_consumer_root(workspace)
        report["workspace"] = synthetic["root"].relative_to(project).as_posix()
        helper_path = project / "tests/evidence/phase6_d125_authored_fixture.py"
        spec = importlib.util.spec_from_file_location("d125_authored_fixture", helper_path)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        fixture = helper.AuthoredFixture(synthetic)
        fixture.current_qualification23_tuple = current_tuple
        fixture.author_inputs()
        synthetic["bind_instance"] = fixture.bind
        synthetic["check_instance"] = fixture.check_instance
        synthetic["review_admission"] = _IMPORT_ADMISSION
        loaded = _load_guarded_consumer_sources(synthetic)
        report["project_imports"] = len(loaded["modules"])
        if args.case in ENGINEERING24_CASES:
            result = fixture.engineering24_chain(loaded, args, BOUNDARY, PROCESS_MONITOR)
        elif args.case in QUALIFICATION23_CASES:
            result = fixture.qualification23_chain(loaded, args, BOUNDARY, PROCESS_MONITOR)
        elif args.accounting_self_test:
            result = fixture.accounting_cases(loaded)
        elif args.consumer_stage == "expanded":
            result = fixture.expanded_case(loaded, args.case, BOUNDARY, PROCESS_MONITOR)
        else:
            bridge = fixture.prepare_transaction(loaded)
            result = fixture.finish_transaction(loaded, bridge)
        report.update(result)
        report["project_imports"] = len(loaded["modules"])
        report["bindings"] = loaded["bindings"]
        report["consumer_assertions"] = len(result["checks"])
        expected_denials = result.get("expected_denied_requests", 0)
        if BOUNDARY.violation_count != expected_denials or PROCESS_MONITOR.process_events:
            raise RuntimeError("positive-consumer-sticky-violation")
        if _dependent_source_identity() != report["dependent_source_sha256"]:
            raise RuntimeError("consumer-source-closure-drift")
        report["status"] = "passed"
    except Exception as exc:
        report["error"] = str(exc)
        report["exception"] = type(exc).__name__
        if fixture is not None:
            report["checks"] = fixture.progress_checks
            report["consumer_assertions"] = len(fixture.progress_checks)
            report["fake_leaf_calls"] = fixture.calls
        if loaded is not None:
            report["project_imports"] = len(loaded["modules"])
            report["bindings"] = loaded["bindings"]
        if synthetic is not None:
            report["project_imports"] = len(synthetic.get("loaded_module_records", []))
            report["bindings"] = synthetic.get("binding_records", [])
            ledger = synthetic["roots"]["ledger"]
            report["retained_ledger_sha256"] = _source_sha(ledger)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, prior_alarm)
        if loaded is not None:
            loaded["restore_loader"]()
    report["guard"] = BOUNDARY.report()
    if synthetic is not None:
        report["retained_files"] = {p.relative_to(project).as_posix(): _source_sha(p)
            for p in synthetic["root"].rglob("*") if p.is_file() and not p.is_symlink()}
    _write_create_once(output, report)
    return report


QUALIFICATION23_CASES = ("qualification23-chain", "qualification23-negatives", "qualification23-final")


def _qualification23_current_tuple(args, project):
    """Read-only actual checker, under independent OS denial and finite import inventory."""
    allowed = {name: _source_sha(project / name) for name in (
        "scripts/evidence/phase6_accounting.py", "tests/evidence/phase6_tank_continuation_contract.py",
        "tests/evidence/phase6_stack_observation_contract.py")}
    original = importlib.util.spec_from_file_location
    def checked(name, location, *extra, **kwargs):
        path = _resolve_under(project, pathlib.Path(location))
        relative = path.relative_to(project).as_posix()
        if relative not in allowed or _source_sha(path) != allowed[relative]:
            raise RuntimeError("qualification23-unknown-live-read-only-import:" + relative)
        if BOUNDARY.violation_count or PROCESS_MONITOR.process_events:
            raise RuntimeError("qualification23-live-checker-sticky-denial")
        return original(name, path, *extra, **kwargs)
    importlib.util.spec_from_file_location = checked
    try:
        spec=checked("qualification23_readonly_checker",project/"tests/evidence/phase6_tank_continuation_contract.py")
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        result=module.verify_qualification23_companion(args.bridge,args.proof_review,args.review_check,project/"build/phase6")
        if BOUNDARY.violation_count or PROCESS_MONITOR.process_events:
            raise RuntimeError("qualification23-live-checker-unexpected-process")
        return result
    finally:
        importlib.util.spec_from_file_location=original


def _qualification23_entry(args, project):
    """Stdlib pre-import gate; independent source review remains mandatory next."""
    if args.engineering_owner != "06-23":
        raise RuntimeError("qualification23-explicit-engineering-owner-required")
    value = json.loads((project / "evidence/phase6-repairs.json").read_bytes())
    policy = value.get("d125_qualification23_policy", {})
    anchor = value.get("phase6_accounting", {}).get("active_anchor")
    if (policy.get("plan") != "06-23" or policy.get("status") != "engineering-only" or
            policy.get("game_admission") is not False or policy.get("test_fixture_only") is not False or
            value.get("test_fixture_only") or not isinstance(anchor, dict) or
            anchor.get("id") != policy.get("anchor_id") or anchor.get("pea_charge") is not False or
            anchor.get("boot_identity") != policy.get("boot_identity")):
        raise RuntimeError("qualification23-live-engineering-policy-required")
    required = {".planning/phases/GW-06-shared-repairs-and-two-playable-routes/" + name
                for name in ("06-23-PLAN.md", "06-23-PLAN-CHECK.md", "06-CONTEXT.md")}
    required.add(".planning/context/OPERATING.md")
    bindings = policy.get("bindings", {})
    if set(bindings) != required or any(_source_sha(_resolve_under(project, pathlib.Path(p))) != h
                                      for p, h in bindings.items()):
        raise RuntimeError("qualification23-entry-plan-binding-stale")
    if args.case == "qualification23-final" and not all((args.bridge, args.proof_review, args.review_check)):
        raise RuntimeError("qualification23-final-explicit-current-tuple-required")


def _engineering24_entry(args, project):
    """Validate owner24 and bootstrap with stdlib before consumer imports."""
    if args.engineering_owner != "06-24":
        raise RuntimeError("engineering24-explicit-owner-required")
    ledger = json.loads((project / "evidence/phase6-repairs.json").read_bytes())
    policy = ledger.get("d125_engineering24_policy", {})
    entry_path = project / "build/phase6/d125-engineering24/entry.json"
    closeout_path = project / "evidence/phase6-d125-proof-receipt-debug-closeout.json"
    entry, closeout = json.loads(entry_path.read_bytes()), json.loads(closeout_path.read_bytes())
    if (policy.get("schema") != "phase6-d125-engineering24-v1" or policy.get("plan") != "06-24" or
            policy.get("status") != "engineering-only" or policy.get("game_admission") is not False or
            policy.get("test_fixture_only") is not False or policy.get("retained_count") != 3 or
            policy.get("fresh_count") != 0 or policy.get("entry_sha256") != _source_sha(entry_path) or
            policy.get("entry_ledger_sha256") != closeout.get("entry_ledger_sha256") or
            policy.get("debug_closeout_sha256") != _source_sha(closeout_path) or
            entry.get("status") != "active" or closeout.get("debug_anchor_closed") is not True or
            closeout.get("production_anchor") is not None or entry.get("pea_used_seconds") != 7098.193 or
            entry.get("process_used_seconds") != 5.865 or entry.get("attempts_used") != 2):
        raise RuntimeError("engineering24-live-policy-invalid")
    if args.case == "engineering24-final" and not all((args.bridge, args.proof_review, args.review_check)):
        raise RuntimeError("engineering24-final-explicit-current-tuple-required")


EXPANDED_CASES = ("historical-locked-swap", "binding-negative", "controlled-denial",
    "selected-authority", "replay-quarantine", "filesystem-publication", "denominator-numeric", "lock-serial", "prospective-chain")
EXPANDED_CASES += QUALIFICATION23_CASES
ENGINEERING24_CASES = ("engineering24-chain", "engineering24-negatives", "engineering24-final")
EXPANDED_CASES += ENGINEERING24_CASES


def consumer_expanded(args):
    return consumer_tracer(args)


def accounting_self_test(args):
    return consumer_tracer(args)


def check_retained_report(path, kind, output, expected_case=None):
    import signal
    previous_handler=signal.getsignal(signal.SIGALRM)
    previous_alarm=signal.alarm(0)
    started=time.monotonic()
    signal.signal(signal.SIGALRM,lambda *_: (_ for _ in ()).throw(TimeoutError("retained-check-55-second-deadline")))
    signal.alarm(55)
    try:return _check_retained_report(path,kind,output,expected_case)
    finally:
        signal.alarm(0);signal.signal(signal.SIGALRM,previous_handler)
        if previous_alarm:signal.alarm(max(1,previous_alarm-int(time.monotonic()-started)))


def _check_retained_report(path, kind, output, expected_case=None):
    """Stdlib retained-data oracle. Never import a project consumer or execute it."""
    root = pathlib.Path(__file__).resolve().parents[2]
    path = _resolve_under(root, path)
    value = json.loads(path.read_bytes())
    checks = []
    def check(name, passed):
        checks.append({"case": name, "passed": bool(passed)})
    if kind in ("case", "accounting"):
        check("requested-mode-and-case", (value.get("mode") == "accounting" and value.get("case") is None)
            if kind == "accounting" else (value.get("mode") == "expanded" and value.get("case") in EXPANDED_CASES and
                value.get("case") == (expected_case or path.stem)))
        check("passed-nonzero-semantic-denominator", value.get("status") == "passed" and
            type(value.get("consumer_assertions")) is int and value["consumer_assertions"] > 0 and
            value["consumer_assertions"] == len(value.get("checks", [])) and
            all(row.get("passed") is True for row in value.get("checks", [])))
        check("current-source-closure", value.get("source_sha256") == _source_sha(pathlib.Path(__file__)) and
            value.get("dependent_source_sha256") == _dependent_source_identity())
        check("exact-sticky-observations", _report_is_observed(value) and
            value.get("guard", {}).get("attempted") == value.get("expected_denied_requests", 0))
        files = value.get("retained_files", {})
        check("retained-hash-denominator", bool(files) and all(
            _source_sha(_resolve_under(root, pathlib.Path(p))) == h for p, h in files.items()))
        check("independent-review-consumed", value.get("review_admission", {}).get("origin") ==
            "parent-observed-separate-reviewer-completion")
    elif kind == "closure":
        check("current-closure-established", value.get("schema") == "phase6-d125-source-freeze-v1" and
            value.get("status") == "accepted-current-closure" and value.get("test_fixture_only") is not True)
        pins = value.get("file_sha256", {})
        check("full-current-freeze", bool(pins) and all(_source_sha(_resolve_under(root, pathlib.Path(p))) == h for p,h in pins.items()))
        check("complete-component-denominator", bool(value.get("components")) and all(
            item.get("decision") == "accepted" and item.get("old_sha256") and item.get("new_sha256")
            for item in value.get("components", [])))
        required={"owner_generation_id","owner_generation_sha256","source_identity","selected_tuple",
            "parent_preflight_pin","ledger_sha256","launch_forecast"}
        complete=required.issubset(value)
        check("selected-owner-review-tuple-required",complete)
        if complete:
            ledger_path=root/"evidence/phase6-repairs.json";ledger=json.loads(ledger_path.read_bytes())
            generations=ledger.get("d125_owner_generations",[]);owner=generations[-1] if generations else {}
            canonical=lambda data:hashlib.sha256(json.dumps(data,sort_keys=True,separators=(",",":"),allow_nan=False).encode()).hexdigest()
            binding=owner.get("runtime_binding",{})
            check("live-selected-generation",owner.get("generation_id")==value["owner_generation_id"] and
                canonical(owner)==value["owner_generation_sha256"] and owner.get("status")=="prospective-bound" and
                owner.get("test_fixture_only") is not True and binding==value["selected_tuple"] and
                binding.get("source_identity")==value["source_identity"] and _source_sha(ledger_path)==value["ledger_sha256"])
            tuple_keys=("bridge","proof_review","review_check","component_review","parent_pin")
            tuple_valid=all(isinstance(binding.get(name),dict) and binding[name].get("path") in pins and
                pins[binding[name]["path"]]==binding[name].get("sha256") for name in tuple_keys)
            check("complete-selected-file-tuple",tuple_valid and binding.get("parent_pin")==value["parent_preflight_pin"])
            if tuple_valid:
                read=lambda name:json.loads(_resolve_under(root,pathlib.Path(binding[name]["path"])).read_bytes())
                bridge=read("bridge");review_check=read("review_check");parent_pin=read("parent_pin")
                component_text=_resolve_under(root,pathlib.Path(binding["component_review"]["path"])).read_text()
                blocks=re.findall(r"```json\s*\n(.*?)\n```",component_text,re.S)
                component=json.loads(blocks[0]) if len(blocks)==1 else {}
                expected_components=[dict(row,decision="accepted") for row in bridge.get("d125_component_disposition",{}).get("components",[])]
                source_map=bridge.get("current_source_closure",{}).get("component_sha256",{})
                raw_map=bridge.get("d125_component_disposition",{}).get("raw_closure",{}).get("retained_file_sha256",{})
                check("full-independent-source-and-raw-denominator",bool(source_map) and bool(raw_map) and
                    set(CONSUMER_SOURCE_PATHS).issubset(source_map) and value["components"]==expected_components and
                    component.get("disposition")=="accepted" and component.get("components")==expected_components and
                    all(pins.get(path)==digest for path,digest in {**source_map,**raw_map}.items()))
                check("actual-parent-observed-prelaunch-review",parent_pin.get("origin")=="parent-observed-separate-reviewer-completion" and
                    parent_pin.get("tool_handoff_result")=="completed" and parent_pin.get("decision")=="accepted" and
                    parent_pin.get("reviewer_role")=="gsd-code-reviewer" and parent_pin.get("test_fixture_only") is not True and
                    parent_pin.get("source_identity")==value["source_identity"] and parent_pin.get("review_sha256")==binding["proof_review"]["sha256"] and
                    parent_pin.get("bridge_sha256")==bridge.get("bridge_sha256") and
                    parent_pin.get("launch_forecast")==owner.get("launch_forecast")==value["launch_forecast"])
                check("real-current-review-check",review_check.get("schema")=="phase6-d125-observer-review-check-v1" and
                    review_check.get("status")=="accepted" and review_check.get("launches")==0 and
                    review_check.get("check_sha256")==canonical({k:v for k,v in review_check.items() if k!="check_sha256"}) and
                    review_check.get("source_identity")==value["source_identity"] and review_check.get("bridge_sha256")==bridge.get("bridge_sha256") and
                    review_check.get("review_sha256")==binding["proof_review"]["sha256"])
                handoffs=[r for r in ledger.get("d125_trusted_review_handoffs",[]) if r.get("lane")=="observer-proof-review" and
                    r.get("status")=="completed" and r.get("parent_pin_path")==binding["parent_pin"]["path"] and
                    r.get("parent_pin_sha256")==binding["parent_pin"]["sha256"] and r.get("reviewer_identity")==parent_pin.get("reviewer_identity") and
                    r.get("review_sha256")==binding["proof_review"]["sha256"] and r.get("disposition")=="accepted" and r.get("test_fixture_only") is not True]
                check("real-trusted-handoff",len(handoffs)==1 and canonical(handoffs[0])==review_check.get("trusted_handoff_sha256"))
                state=ledger.get("phase6_accounting",{});anchor=state.get("active_anchor") or {}
                now=time.monotonic();started=anchor.get("monotonic_started_at",now+1)
                process_used=5.244+sum(r.get("process_active_seconds",0) for r in ledger.get("records",[]) if r.get("d125_owner")=="06-22")
                global_used=state.get("closed_baseline_seconds",43200)+sum(r.get("active_seconds",0) for r in state.get("closed_intervals",[]))+now-started
                forecast=owner.get("launch_forecast",{});admissions=ledger.get("d125_admissions",[]);admission=admissions[-1] if admissions else {}
                check("live-protected-complete-forecast",anchor.get("id")==owner.get("anchor_id") and anchor.get("pea_charge") is False and now>=started and
                    not any(r.get("event")=="terminal" for r in ledger.get("d125_owner_events",[])) and admission.get("status")=="admitted" and
                    admission.get("generation_id")==owner.get("generation_id") and admission.get("source_identity")==value["source_identity"] and
                    admission.get("process_seconds")==1800-process_used and admission.get("nonprocess_seconds",-1)>=forecast.get("nonprocess_seconds",43200) and
                    forecast.get("final_review_seconds",0)>0 and admission.get("closeout_seconds",0)>=120 and
                    43200-global_used>=admission.get("nonprocess_seconds",43200)+(1800-process_used)+admission.get("closeout_seconds",120))
    elif kind == "qualification23-terminal":
        ledger=json.loads((root/'evidence/phase6-repairs.json').read_bytes())
        policy=ledger.get('d125_qualification23_policy',{})
        accepted=value.get('status')=='accepted-affected-qualification-and-consumers'
        check('truthful-engineering-terminal-status',value.get('schema')=='phase6-d125-qualification23-terminal-v1' and
              value.get('status') in ('HALTED','accepted-affected-qualification-and-consumers') and value.get('game_admission') is False)
        check('null-live-and-receipt-anchor',value.get('anchor') is None and ledger['phase6_accounting'].get('active_anchor') is None)
        check('unchanged-game-counters',value.get('pea_used_seconds')==7098.193 and value.get('process_used_seconds')==5.865 and
              type(value.get('attempts_used')) is int and value['attempts_used']==2 and ledger['usage']['attempts_for_this_stop']==2)
        check('phase-and-game-authority-remain-denied',value.get('phase6_complete') is False and value.get('phase7_started') is False and
              value.get('auto_advance') is False and value.get('game_purpose_created') is False and policy.get('game_admission') is False)
        check('honest-partial-qualification-denominator',type(value.get('qualification_count')) is int and
              0<=value['qualification_count']<=3 and value.get('qualification_planned')==3 and
              (not accepted or value['qualification_count']==3))
        state=ledger['phase6_accounting']
        closed=state['closed_baseline_seconds']+sum(r['active_seconds'] for r in state['closed_intervals'])
        check('closed-global-accounting-not-overstated',closed>=value.get('global_used_seconds',43201) and closed<=43200 and
              value.get('global_remaining_seconds')==43200-value.get('global_used_seconds',0))
        files=value.get('accepted_file_sha256',{})
        check('accepted-current-tuple-required',not accepted or (bool(files) and all(
              _source_sha(_resolve_under(root,pathlib.Path(p)))==h for p,h in files.items())))
    elif kind == "terminal":
        ledger = json.loads((root / "evidence/phase6-repairs.json").read_bytes())
        check("terminal-status-honest", value.get("status") in ("HALTED", "accepted-original14-recovery"))
        check("closed-anchor", ledger.get("phase6_accounting", {}).get("active_anchor") is None and value.get("anchor") is None)
        check("ledger-hash", value.get("ledger_sha256") == _source_sha(root / "evidence/phase6-repairs.json"))
        check("downstream-stop", value.get("downstream_blocked") == ["06-12","06-09","06-05","06-06","06-07"] and
            value.get("phase6_complete") is False)
        if value.get("status") == "accepted-original14-recovery":
            check("accepted-full-denominator", value.get("actual_counts") == {"tank": 1, "controls": 2, "children": 12, "pcm": 12} and
                bool(value.get("checked_receipt_sha256")) and bool(value.get("final_review_sha256")))
    report = {"schema": "phase6-d125-retained-check-v1", "status": "passed" if checks and all(c["passed"] for c in checks) else "failed",
        "input_sha256": _source_sha(path), "report_kind": kind, "checks": checks, "project_imports": 0, "guard": BOUNDARY.report()}
    _write_create_once(output, report)
    return report


def _report_is_observed(report: dict[str, Any]) -> bool:
    guard = report.get("guard", {})
    checks = report.get("checks", [])
    return (guard.get("attempted") == len(guard.get("attempts", []))
            and guard.get("observed_process_events") == 0
            and guard.get("violation_count") == guard.get("attempted")
            and len(guard.get("decisions", [])) == guard.get("attempted")
            and all(event.get("decision") == "denied"
                    and event.get("violation") == guard["attempts"][i].get("violation")
                    for i, event in enumerate(guard.get("decisions", [])))
            and all(row.get("attempted") == row.get("attempt_delta")
                    and row.get("violation_count") == row.get("attempt_delta")
                    and row.get("permitted") == row.get("permitted_delta")
                    for row in checks))


def guard_self_test(output: pathlib.Path) -> dict[str, Any]:
    """Exercise guarded denial routes without creating any OS process."""
    available = {}
    import subprocess
    for name in ("Popen", "call", "run", "check_call", "check_output"):
        available[f"subprocess.{name}"] = callable(getattr(subprocess, name, None))
    for name in dir(os):
        if name == "system" or name.startswith(("posix_spawn", "fork", "exec", "spawn")):
            available[f"os.{name}"] = callable(getattr(os, name, None))

    checks = []
    root = pathlib.Path(__file__).resolve().parents[2]
    case_root = _resolve_under(root, output.parent / "guard-cases")
    case_root.mkdir(parents=True, exist_ok=True)
    # A captured alias must still trigger the independent audit hook.
    cached_popen = BOUNDARY._originals[(id(subprocess), "Popen")]
    cached_fork = BOUNDARY._originals.get((id(os), "fork"))
    cached_forkpty = BOUNDARY._originals.get((id(os), "forkpty"))
    cached_execve = BOUNDARY._originals.get((id(os), "execve"))
    cached_spawnv = BOUNDARY._originals.get((id(os), "spawnv"))
    cached_posix_spawn = BOUNDARY._originals.get((id(os), "posix_spawn"))
    scenarios = [
        ("direct-subprocess", lambda _workspace: subprocess.Popen(["unavailable-d125-probe"])),
        ("cached-popen-alias", lambda _workspace: cached_popen(["unavailable-d125-probe"])),
        # Simulate a patch on the wrong reference: the alias captured before
        # replacement still reaches the independent audit event.
        ("wrong-mock", lambda _workspace: cached_fork()),
        ("missing-mock", lambda _workspace: cached_posix_spawn("/unavailable", ["/unavailable"], {})),
        ("forkpty-alias", lambda _workspace: cached_forkpty()),
        ("execve-alias", lambda _workspace: cached_execve("/unavailable", ["unavailable"], {})),
        ("spawnv-alias", lambda _workspace: cached_spawnv(os.P_WAIT, "/unavailable", ["unavailable"])),
        ("swallowed-denial", lambda _workspace: _swallow_denial()),
        ("import-time-attempt", _import_time_request),
    ]
    tested_os_routes = {"fork", "forkpty", "execve", "spawnv", "posix_spawn", "system"}
    for qualified_name, present in available.items():
        if not present or not qualified_name.startswith("os."):
            continue
        route_name = qualified_name.removeprefix("os.")
        if route_name in tested_os_routes:
            continue
        scenarios.append((f"direct-{route_name}",
                          lambda _workspace, name=route_name: getattr(os, name)()))
    for label, action in scenarios:
        before = len(BOUNDARY.attempts)
        allowed_before = BOUNDARY.permitted
        workspace = pathlib.Path(tempfile.mkdtemp(prefix=f"{label}-", dir=case_root))
        violation_before = BOUNDARY.violation_count
        try:
            action(workspace)
            if len(BOUNDARY.attempts) > before:
                raise ProcessDenied("sticky-observed-denial-survived-action")
            result = "FAILED:permitted"
        except ProcessDenied:
            result = "FAILED:denied-before-launch"
        except Exception as exc:
            result = f"FAILED:{type(exc).__name__}"
        row = {"case": label, "status": result,
               "attempted": len(BOUNDARY.attempts) - before,
               "attempt_delta": len(BOUNDARY.attempts) - before,
               "permitted": BOUNDARY.permitted - allowed_before,
               "permitted_delta": BOUNDARY.permitted - allowed_before,
               "violation_count": BOUNDARY.violation_count - violation_before,
               "workspace": workspace.relative_to(root).as_posix(),
               "retained": True}
        (workspace / "case.json").write_text(json.dumps(row, sort_keys=True) + "\n")
        checks.append(row)

    escape = case_root / "escape"
    if not escape.exists() and not escape.is_symlink():
        try:
            escape.symlink_to(root.parent)
        except OSError:
            pass
    try:
        _resolve_under(root, escape / "ledger.json")
        escape_rejected = False
    except (ValueError, OSError):
        escape_rejected = True

    # Verify a suppressed hook installer is detected by the installation
    # sentinel. This injectable seam has no OS process and cannot affect the
    # already-installed production boundary.
    suppressed = DenyBoundary()
    try:
        suppressed.install(register_hook=lambda _hook: None,
                           sentinel_emitter=lambda *_args: None)
        suppression_detected = False
    except RuntimeError as exc:
        suppression_detected = str(exc) == "audit-hook-not-observed:subprocess.Popen"

    forged = {"guard": {"attempted": 1, "attempts": [{"violation": 1}],
                        "violation_count": 1, "permitted": 0, "decisions": []},
              "checks": [{"attempted": 1, "attempt_delta": 1,
                          "violation_count": 1,
                          "permitted": 0, "permitted_delta": 0}]}
    forged["guard"]["observed_process_events"] = 0
    forged_zero_rejected = not _report_is_observed(forged)
    observer_nonzero_rejected = not _report_is_observed({"guard": {
        "attempted": 0, "attempts": [], "decisions": [], "violation_count": 0,
        "observed_process_events": 1}, "checks": []})
    synthetic = _create_synthetic_consumer_root(case_root)
    roots_valid = _verify_synthetic_roots(synthetic, root)
    traversal_rejected = False
    try:
        _resolve_under(synthetic["root"], synthetic["root"] / "evidence" / ".." / "ledger.json")
    except ValueError as exc:
        traversal_rejected = str(exc) == "traversal-component-rejected"

    report = {"schema": "phase6-d125-guard-v1", "status": "passed" if (
        BOUNDARY.installed and all(row["status"] == "FAILED:denied-before-launch"
                                   and row["attempted"] > 0 and row["permitted"] == 0
                                   and pathlib.Path(root / row["workspace"]).exists()
                                   for row in checks) and escape_rejected and suppression_detected
        and forged_zero_rejected and observer_nonzero_rejected and roots_valid and traversal_rejected
        and _report_is_observed({"guard": BOUNDARY.report(),
                                                          "checks": checks})) else "failed",
        "guard": BOUNDARY.report(), "installation_proof": INSTALLATION_PROOF,
        "runtime": {"implementation": platform.python_implementation(),
                    "version": platform.python_version(), "platform": sys.platform},
        "source_sha256": _source_sha(pathlib.Path(__file__)),
        "legacy_entry_sha256": _source_sha(root / "tests/evidence/phase6_d124_consumers_contract.py"),
        "scope": "provisional stdlib guard and entry only; consumer imports denied",
        "available_routes": available,
        "checks": checks, "symlink_escape_rejected": escape_rejected,
        "negative_workspaces": "retained", "suppression_detected": suppression_detected,
        "forged_zero_rejected": forged_zero_rejected, "synthetic_roots": {
            "root": synthetic["root"].relative_to(root).as_posix(),
            "relative_roots": synthetic["relative_roots"],
            "authored_sha256": synthetic["authored_sha256"],
            "production_tree_copied": synthetic["production_tree_copied"],
            "usable_guest_or_client": synthetic["usable_guest_or_client"],
            "validation_passed": roots_valid, "traversal_rejected": traversal_rejected},
        "observer_nonzero_rejected": observer_nonzero_rejected,
        "claim": "accidental-execution-control; not an OS sandbox; observer records are not exact launches"}
    _write_create_once(output, report)
    return report


def _import_time_request(workspace: pathlib.Path) -> None:
    module_path = workspace / "synthetic_import_probe.py"
    module_path.write_text("import subprocess\nsubprocess.Popen(['unavailable-d125-probe'])\n")
    spec = importlib.util.spec_from_file_location("d125_synthetic_import_probe", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("synthetic-import-probe-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)


def _swallow_denial() -> None:
    before = BOUNDARY.violation_count
    try:
        os.system("unavailable-d125-probe")
    except ProcessDenied:
        pass
    if BOUNDARY.violation_count == before:
        raise RuntimeError("swallowed-denial-not-observed")


def engineering24_self_test(mode, output):
    """Run bounded synthetic owner/publication checks; no tuple qualification."""
    report = {'schema': 'phase6-d125-engineering24-self-test-v1',
        'status': 'unsupported', 'mode': mode, 'checks': [],
        'consumer_assertions': 0, 'game_admission': False,
        'reason': 'current-owner24-proof-final-tuple-self-test-not-implemented'}
    if mode in ('owner', 'publication'):
        import io
        import unittest
        root = pathlib.Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location('engineering24_selftest_regressions',
            root / 'tests/evidence/test_engineering24_accounting.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        names = (('test_owner_exact_floor_prefix_and_closeout',
                  'test_owner_rejects_missing_bound_plan_input', 'test_actual_bootstrap_ledger_digest',
                  'test_real_owner24_activity_chain') if mode == 'owner' else
                 ('test_accepted_close_is_fail_closed', 'test_receipt_recovery_existing_absent_conflict_symlink'))
        suite = unittest.TestSuite(module.Engineering24OwnerTests(name) for name in names)
        result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
        failed = {test._testMethodName for test, _ in (*result.errors, *result.failures)}
        report.update(status='passed' if result.wasSuccessful() else 'failed',
            checks=[{'case': name, 'passed': name not in failed} for name in names],
            consumer_assertions=result.testsRun, synthetic_only=True,
            reason='bounded-synthetic-api-checks-only-no-current-tuple-acceptance')
    _write_create_once(output, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--guard-self-test", action="store_true")
    modes.add_argument("--entry-self-test", action="store_true")
    modes.add_argument("--consumer-stage", choices=("tracer", "expanded"))
    modes.add_argument("--accounting-self-test", action="store_true")
    modes.add_argument("--check-report", type=pathlib.Path)
    modes.add_argument("--engineering24-self-test", choices=("owner", "retained", "publication"))
    parser.add_argument("--report-kind", choices=("case", "accounting", "closure", "terminal", "qualification23-terminal", "engineering24-terminal"))
    parser.add_argument("--case")
    parser.add_argument("--engineering-owner", choices=("06-23", "06-24"))
    parser.add_argument("--negative-family", choices=("historical-locked-swap", "binding-negative", "controlled-denial",
        "selected-authority", "replay-quarantine", "filesystem-publication", "denominator-numeric", "lock-serial",
        "owner", "source-review", "binding", "closure", "payload", "raw", "accounting", "publication"))
    parser.add_argument("--expected-reviewer-identity")
    parser.add_argument("--expected-reviewer-role")
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--bridge", type=pathlib.Path)
    parser.add_argument("--proof-review", type=pathlib.Path)
    parser.add_argument("--review-check", type=pathlib.Path)
    parser.add_argument("--containment-review", type=pathlib.Path)
    parser.add_argument("--guard-report", type=pathlib.Path)
    parser.add_argument("--parent-review-pin", type=pathlib.Path)
    parser.add_argument("--parent-review-pin-sha256")
    args = parser.parse_args(argv)
    if args.engineering24_self_test:
        report = engineering24_self_test(args.engineering24_self_test, args.output)
        print(json.dumps({"status": report["status"], "assertions": len(report["checks"])}, sort_keys=True))
        return 0 if report["status"] == "passed" else 1
    if args.check_report:
        if not args.report_kind:
            parser.error("--check-report requires --report-kind")
        report = check_retained_report(args.check_report, args.report_kind, args.output, args.case)
        print(json.dumps({"status": report["status"], "assertions": len(report["checks"])}))
        return 0 if report["status"] == "passed" else 1
    if args.entry_self_test:
        report = entry_self_test(args.output)
        print(json.dumps({"status": report["status"], "assertions": len(report["checks"])}, sort_keys=True))
        return 0 if report["status"] == "passed" else 1
    if args.guard_self_test:
        report = guard_self_test(args.output)
        print(json.dumps({"status": report["status"], "attempted": report["guard"]["attempted"],
                          "permitted": report["guard"]["permitted"]}, sort_keys=True))
        return 0 if report["status"] == "passed" else 1
    if args.consumer_stage == "expanded" and args.case not in EXPANDED_CASES:
        _write_create_once(args.output, {"schema": "phase6-d125-entry-v1", "status": "failed",
            "error": "unknown-or-missing-expanded-case", "project_imports": 0, "consumer_assertions": 0,
            "guard": BOUNDARY.report()})
        return 1
    if args.consumer_stage or args.accounting_self_test:
        report = consumer_tracer(args)
        print(json.dumps({"status": report["status"], "assertions": report["consumer_assertions"],
                          "error": report.get("error")}, sort_keys=True))
        return 0 if report["status"] == "passed" else 1
    # These lanes have no implemented transaction yet. Reject before review
    # consumption, workspace creation or project imports; loading is not success.
    reason = (f"unsupported-consumer-stage:{args.consumer_stage}" if args.consumer_stage
              else "unsupported-accounting-self-test")
    _write_create_once(args.output, {"schema": "phase6-d125-entry-v1", "status": "failed",
        "error": reason, "project_imports": 0, "consumer_assertions": 0,
        "guard": BOUNDARY.report(), "installation_proof": INSTALLATION_PROOF})
    print(reason, file=sys.stderr)
    return 1


def entry_self_test(output: pathlib.Path) -> dict[str, Any]:
    """Specified CLI oracles only; never import any project consumer."""
    import contextlib
    import io
    root = pathlib.Path(__file__).resolve().parents[2]
    output = _resolve_under(root, output)
    cases = _resolve_under(root, output.parent / (output.stem + "-entry-cases"))
    cases.mkdir(parents=True, exist_ok=False)
    checks = []
    for label, mode, error in (
        ("unsupported-tracer", ["--consumer-stage", "tracer"], "consumer-review-inputs-required"),
        ("unsupported-expanded", ["--consumer-stage", "expanded"], "unknown-or-missing-expanded-case"),
        ("unsupported-accounting", ["--accounting-self-test"], "consumer-review-inputs-required"),
    ):
        target = cases / (label + ".json")
        with contextlib.redirect_stderr(io.StringIO()):
            code = main([*mode, "--output", str(target)])
        value = json.loads(target.read_bytes())
        passed = (code == 1 and value["status"] == "failed" and value["error"] == error
                  and value["project_imports"] == value["consumer_assertions"] == 0)
        checks.append({"case": label, "passed": passed, "exit_status": code,
                       "error": value["error"]})
    for label, mode in (("missing-mode", []),
                        ("conflicting-modes", ["--guard-self-test", "--consumer-stage", "tracer"])):
        target = cases / (label + ".json")
        code = None
        with contextlib.redirect_stderr(io.StringIO()):
            try:
                main([*mode, "--output", str(target)])
            except SystemExit as exc:
                code = exc.code
        checks.append({"case": label, "passed": code == 2 and not target.exists(),
                       "exit_status": code})
    # A failed output is immutable even if a caller retries the same pathname.
    target = cases / "unsupported-tracer.json"
    before = target.read_bytes()
    collided = False
    try:
        main(["--consumer-stage", "tracer", "--output", str(target)])
    except FileExistsError:
        collided = True
    checks.append({"case": "failed-output-create-once", "passed": collided and target.read_bytes() == before})
    checks.extend(_review_tuple_self_test(cases, root))
    closure=cases/"forged-incomplete-closure.json"
    closure.write_text(json.dumps({"schema":"phase6-d125-source-freeze-v1","status":"accepted-current-closure","test_fixture_only":False,
        "file_sha256":{pathlib.Path(__file__).relative_to(root).as_posix():_source_sha(pathlib.Path(__file__))},
        "components":[{"decision":"accepted","old_sha256":"invented","new_sha256":"invented"}]}))
    rejected=check_retained_report(closure,"closure",cases/"forged-incomplete-closure-check.json")
    checks.append({"case":"incomplete-forged-closure-rejected","passed":rejected["status"]=="failed"})
    checks.append({"case": "positive-entry-sticky-zero",
                   "passed": BOUNDARY.violation_count == PROCESS_MONITOR.process_events == 0})
    report = {"schema": "phase6-d125-entry-tests-v1",
              "status": "passed" if checks and all(row["passed"] for row in checks) else "failed",
              "checks": checks, "project_imports": 0, "guard": BOUNDARY.report(),
              "source_sha256": _source_sha(pathlib.Path(__file__))}
    _write_create_once(output, report)
    return report


def _review_tuple_self_test(cases: pathlib.Path, root: pathlib.Path) -> list[dict[str, Any]]:
    """Mechanical tuple validation using authored files, never review authority."""
    source = cases / "tuple-fixture-source.txt"
    guard = cases / "tuple-fixture-guard.json"
    review = cases / "tuple-fixture-review.md"
    source.write_text("test_fixture_only source; no executable authority\n")
    guard.write_text('{"status":"passed","test_fixture_only":true}\n')
    fields = {"decision": "accepted", "status": "accepted",
        "source_sha256": _source_sha(source), "guard_output_sha256": _source_sha(guard),
        "reviewer_identity": "synthetic-separate-reviewer", "producer_identity": "synthetic-producer",
        "reviewer_role": "gsd-code-reviewer", "tool_handoff_result": "completed",
        "critical_findings": "0", "high_findings": "0"}
    review.write_text("---\n" + "".join(f"{key}: {value}\n" for key, value in fields.items()) + "---\nfixture only\n")
    pin = {"schema": "d125-parent-observed-review-v1",
        "origin": "parent-observed-separate-reviewer-completion", "tool_handoff_result": "completed",
        "decision": "accepted", "reviewer_identity": fields["reviewer_identity"],
        "reviewer_role": "gsd-code-reviewer", "test_fixture_only": True,
        "source_sha256": _source_sha(source), "guard_output_sha256": _source_sha(guard),
        "review_sha256": _source_sha(review), "source_path": source.relative_to(root).as_posix(),
        "guard_output_path": guard.relative_to(root).as_posix(), "review_path": review.relative_to(root).as_posix()}
    result = _validate_review_tuple(pin, review, source, guard, root)
    rows = [{"case": "authored-review-tuple-mechanical-positive",
             "passed": result["reviewer_identity"] == fields["reviewer_identity"], "test_fixture_only": True}]
    for key, bad in (("reviewer_identity", "wrong-reviewer"), ("reviewer_role", "producer"),
                     ("decision", "rejected"), ("tool_handoff_result", "running"),
                     ("source_sha256", "0" * 64), ("guard_output_sha256", "0" * 64),
                     ("review_sha256", "0" * 64), ("origin", "producer-asserted")):
        mutated = dict(pin, **{key: bad})
        try:
            _validate_review_tuple(mutated, review, source, guard, root)
            passed = False
        except RuntimeError as exc:
            passed = str(exc) in {"parent-observed-review-tuple-missing-or-stale",
                                  "independent-containment-review-missing-or-stale"}
        rows.append({"case": "reject-review-tuple-" + key, "passed": passed})
    try:
        _require_independent_containment_review(review, pathlib.Path(__file__), guard)
        rejected = False
    except RuntimeError as exc:
        rejected = str(exc) == "parent-observed-review-pin-required"
    rows.append({"case": "producer-markdown-without-parent-pin-rejected", "passed": rejected})
    # No mode or direct helper currently admits project imports.
    try:
        _load_guarded_consumer_sources({})
        rejected = False
    except RuntimeError as exc:
        rejected = str(exc) == "consumer-import-parent-admission-required"
    rows.append({"case": "unimplemented-direct-import-helper-rejected", "passed": rejected})
    return rows



if __name__ == "__main__":
    raise SystemExit(main())

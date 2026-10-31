#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent CPython audit backstop for zero-start synthetic exercises.

Install before production imports. Never remove/reset the hook or event ledger.
This covers audited Python APIs, not hostile native code or OS containment.
"""
import contextlib
import os
import re
import signal
import subprocess
import sys

EVENTS = []
SELF_TESTS = []
COUNTERFACTUALS = []
READONLY_GIT_STARTS = []
READONLY_GIT_CWD = None
READONLY_GIT_SOURCE_ROOT = None
INSTALLED = False
_GIT_CLEANUP = None


@contextlib.contextmanager
def owned_readonly_git_cleanup():
    """Permit only a fresh, unreaped Git handle's own Popen.kill cleanup.

    This is a single-invocation Python audit guard, not OS containment. Spawn,
    kill and reap scheduling can exceed subprocess.run's timeout; no universal
    hard wall bound is asserted. Output limits remain postcapture checks.
    """
    if READONLY_GIT_CWD is None:
        raise AssertionError("readonly-git-allowance-required")
    original_popen = subprocess.Popen
    owned = set()

    class OwnedGitPopen(original_popen):
        def __init__(self, command, *args, **kwargs):
            if not readonly_git_event_allowed(kwargs.get("executable"), command,
                    kwargs.get("cwd")):
                raise PermissionError("unapproved-owned-git-handle")
            super().__init__(command, *args, **kwargs)
            self._owned_git_pid = self.pid
            owned.add(self)

        def kill(self):
            global _GIT_CLEANUP
            if self not in owned or self.returncode is not None or self.pid != self._owned_git_pid:
                return super().kill()
            previous = _GIT_CLEANUP
            _GIT_CLEANUP = (self, self._owned_git_pid, owned)
            try:
                return super().kill()
            finally:
                _GIT_CLEANUP = previous

    subprocess.Popen = OwnedGitPopen
    try:
        yield
    finally:
        subprocess.Popen = original_popen
        owned.clear()


def readonly_git_argv_allowed(argv):
    if not isinstance(argv, (list, tuple)) or len(argv) < 2 or argv[0] != "git":
        return False
    args = tuple(argv[1:])
    exact = {
        ("rev-parse", "HEAD"), ("rev-parse", "HEAD^"), ("rev-parse", "HEAD^{tree}"),
        ("symbolic-ref", "--short", "HEAD"), ("remote", "get-url", "origin"),
        ("show", "-s", "--format=%P", "HEAD"), ("for-each-ref", "--format=%(refname)"),
        ("ls-files", "-z"), ("status", "--porcelain", "--untracked-files=all"),
        ("rev-list", "HEAD"), ("rev-list", "--objects", "HEAD"),
        ("cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"),
        ("cat-file", "--batch"),
        ("log", "HEAD", "--format=%an%x00%ae%x00%cn%x00%ce"),
        ("log", "--follow", "--format=%H", "-1", "--",
            "fixtures/independent-game-v2/src/game.s"),
        ("show", "HEAD^:fixtures/manifest.json"),
        ("show", "HEAD^:evidence/independent-game-v2.json"),
    }
    return (args in exact
        or (len(args) == 3 and args[:2] == ("rev-parse", "--verify")
            and re.fullmatch(r"refs/tags/genewhip-fixture-source-v2-[0-9a-f]{40}\^\{commit\}", args[2]) is not None)
        or (len(args) == 2 and args[0] == "show"
            and re.fullmatch(r"[0-9a-f]{40}:fixtures/independent-game-v2/src/game\.s", args[1]) is not None))


def normalized_readonly_git(command, cwd):
    """Recognize only exact roots; never resolve traversal or Git config options."""
    if (not isinstance(command, (list, tuple)) or len(command) < 2
            or any(not isinstance(arg, str) for arg in command) or command[0] != "git"):
        return None, ()
    actual_cwd = os.fsdecode(cwd) if cwd is not None else None
    if command[1] == "-C":
        if (len(command) < 4 or command[2] != READONLY_GIT_CWD
                or actual_cwd not in (None, READONLY_GIT_CWD)):
            return None, ()
        return READONLY_GIT_CWD, ("git", *command[3:])
    return actual_cwd, tuple(command)


def readonly_git_event_allowed(executable, command, cwd):
    if executable not in (None, "git"):
        return False
    actual_cwd, command = normalized_readonly_git(command, cwd)
    if READONLY_GIT_CWD is None or not command:
        return False
    if actual_cwd == READONLY_GIT_SOURCE_ROOT:
        return tuple(command) == ("git", "rev-parse", "HEAD")
    return actual_cwd == READONLY_GIT_CWD and readonly_git_argv_allowed(command)


def enable_readonly_git(cwd, source_root):
    global READONLY_GIT_CWD, READONLY_GIT_SOURCE_ROOT
    if READONLY_GIT_CWD is not None:
        raise AssertionError("readonly-git-allowance-already-active")
    READONLY_GIT_CWD = str(cwd)
    READONLY_GIT_SOURCE_ROOT = str(source_root)


def disable_readonly_git():
    global READONLY_GIT_CWD, READONLY_GIT_SOURCE_ROOT
    READONLY_GIT_CWD = None
    READONLY_GIT_SOURCE_ROOT = None


def deny(event, args):
    if event == "os.kill" and _GIT_CLEANUP is not None:
        handle, pid, owned = _GIT_CLEANUP
        if (handle in owned and handle.returncode is None and handle.pid == pid
                and args == (pid, signal.SIGKILL)):
            return
    if event == "subprocess.Popen" and READONLY_GIT_CWD is not None:
        executable, command, cwd, _env = args
        if readonly_git_event_allowed(executable, command, cwd):
            READONLY_GIT_STARTS.append(tuple(command))
            return
    if (event in ("subprocess.Popen", "os.system", "os.fork", "os.forkpty",
                  "pty.spawn", "os.kill", "os.killpg")
            or event.startswith(("os.exec", "os.spawn", "os.posix_spawn"))):
        EVENTS.append(event)
        raise PermissionError("sticky-process-and-signal-denial")


def self_test(label):
    before = len(EVENTS)
    probes = (("subprocess.Popen", lambda: subprocess.Popen(["/__gw_no_client__"])),
              ("os.system", lambda: os.system("/__gw_no_client__")),
              ("os.killpg", lambda: os.killpg(987654321, 0)))
    for event, probe in probes:
        try:
            probe()
        except PermissionError as error:
            if str(error) != "sticky-process-and-signal-denial" or EVENTS[-1] != event:
                raise AssertionError("denial-self-test-wrong-boundary") from error
        else:
            raise AssertionError("denial-self-test-not-reached")
    if EVENTS[before:] != [event for event, _ in probes]:
        raise AssertionError("unexpected-denial-during-self-test")
    SELF_TESTS.append({"label": label, "events": EVENTS[before:]})


def install():
    global INSTALLED
    if not INSTALLED:
        sys.addaudithook(deny)
        INSTALLED = True
    self_test("before-production-imports")


def receipt():
    self_events = sum(len(row["events"]) for row in SELF_TESTS)
    counter_events = sum(len(row["events"]) for row in COUNTERFACTUALS)
    return {"audit_events": len(EVENTS), "self_test_denials": self_events,
            "counterfactual_denials": counter_events,
            "unexpected_denials": len(EVENTS) - self_events - counter_events,
            "real_child_starts": len(READONLY_GIT_STARTS),
            "readonly_git_starts": len(READONLY_GIT_STARTS), "self_tests": SELF_TESTS}

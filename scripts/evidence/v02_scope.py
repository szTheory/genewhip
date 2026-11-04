#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Resolve one exact, repository-pinned v0.2 qualification scope."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat

LEGACY_SCOPE_SHA256 = "05eb7f5fa91d759fbef8fb86bbc9db402dc41812261235bcf5085a0e2aa9b1a5"
LEGACY_SCOPE_REL = Path("evidence/v02-execution.json")
PHASE7_CI_MEMORY_SCOPE_SHA256 = "0aa84e06d689fba4593c6d52b3819c8954b941c3433c7f0ee502db0feda9efea"
PHASE7_CI_MEMORY_SCOPE_REL = Path("evidence/v02-phase7-ci-memory-scope.json")
SCOPE_PROFILES = {
    LEGACY_SCOPE_SHA256: LEGACY_SCOPE_REL,
    "6deaf18aab75f45ac412a141caf9e089158f5c39d3971d49cb9bb7bb1be58df4":
        Path("evidence/v02-phase7-full-execution-scope.json"),
    "a72453ee43bceeb16f03a5b023c6f94def38196e5ff23f36c7f2e4a35a99136c":
        Path("evidence/v02-phase7-two-hour-execution-scope.json"),
    "bda5c36ded9c6e1389e43eb089fd8c804e193917850d5a014b625ff3bbb0757c":
        Path("evidence/v02-phase7-renewed-two-hour-execution-scope.json"),
    "c77556022454459deb731ea1d50f7f1a1ba0d20370c540a101e2144175c3986a":
        Path("evidence/v02-phase7-authorized-execution-scope.json"),
    PHASE7_CI_MEMORY_SCOPE_SHA256: PHASE7_CI_MEMORY_SCOPE_REL,
}
SCOPE_READ_LIMIT_BYTES = 1024 * 1024


class ScopeSelectionError(ValueError):
    """A selected scope path/hash pair is not an exact supported profile."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def read_scope(root: Path, explicit: Path | str | None = None, *,
               scope_path: str = "", scope_sha256: str = "") -> tuple[Path, bytes]:
    """Return the selected path and its exact bounded, digest-verified byte snapshot."""
    if not isinstance(scope_path, str) or not isinstance(scope_sha256, str):
        raise ScopeSelectionError("profile-invalid")
    try:
        root = Path(root).resolve(strict=True)
    except (OSError, RuntimeError):
        raise ScopeSelectionError("profile-invalid") from None

    if scope_sha256:
        relative = SCOPE_PROFILES.get(scope_sha256)
        if relative is None:
            raise ScopeSelectionError("profile-invalid")
        if scope_sha256 == LEGACY_SCOPE_SHA256:
            if scope_path not in ("", LEGACY_SCOPE_REL.as_posix()):
                raise ScopeSelectionError("profile-invalid")
        elif scope_path != relative.as_posix():
            raise ScopeSelectionError("profile-invalid")
    else:
        relative = LEGACY_SCOPE_REL
        if scope_path not in ("", LEGACY_SCOPE_REL.as_posix()):
            raise ScopeSelectionError("profile-invalid")
        scope_sha256 = LEGACY_SCOPE_SHA256

    expected = root / relative
    if explicit is not None:
        supplied = Path(explicit)
        requested = (Path(os.path.abspath(supplied)) if supplied.is_absolute()
            else root / supplied)
        if requested != expected:
            reason = "not-selected" if relative == LEGACY_SCOPE_REL else "profile-invalid"
            raise ScopeSelectionError(reason)

    current = root
    try:
        for part in relative.parts:
            current = current / part
            info = current.lstat()
            if (stat.S_ISLNK(info.st_mode) or
                    (current == expected and (not stat.S_ISREG(info.st_mode) or
                     info.st_nlink != 1 or info.st_size < 0 or
                     info.st_size > SCOPE_READ_LIMIT_BYTES))):
                raise ScopeSelectionError("profile-invalid")
        # O_NONBLOCK prevents a final-path swap to a FIFO from hanging before fstat.
        flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
        descriptor = os.open(expected, flags)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_size < 0 or info.st_size > SCOPE_READ_LIMIT_BYTES):
                raise ScopeSelectionError("profile-invalid")
            raw = stream.read(SCOPE_READ_LIMIT_BYTES + 1)
    except ScopeSelectionError:
        raise
    except OSError:
        raise ScopeSelectionError("profile-invalid") from None
    if (len(raw) > SCOPE_READ_LIMIT_BYTES
            or hashlib.sha256(raw).hexdigest() != scope_sha256):
        raise ScopeSelectionError("profile-invalid")
    return expected, raw


def resolve_scope(root: Path, explicit: Path | str | None = None, *,
                  scope_path: str = "", scope_sha256: str = "") -> Path:
    """Compatibility wrapper for callers that need only the selected path."""
    path, _raw = read_scope(root, explicit,
        scope_path=scope_path, scope_sha256=scope_sha256)
    return path

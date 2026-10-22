"""Prove a public fixture source revision after a sanitized squash import.

The historical manifest validator is digest-bound by admitted evidence, so this
adapter leaves it untouched. It accepts the immutable source tag only after
checking the tag target and both current and tagged source bytes, then scopes a
Git-log identity projection to that validator invocation.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import re
import subprocess
from types import SimpleNamespace


SOURCE = "fixtures/independent-game-v2/src/game.s"


def _git(root, *args, text=True):
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          capture_output=True, text=text, timeout=10).stdout


def proven_revision(row, root):
    """Return the declared source SHA only when its exact source is proven."""
    revision = row.get("revision")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        return None
    source = row.get("source")
    if source != SOURCE or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("source_sha256", ""))):
        return None
    try:
        if hashlib.sha256((root / source).read_bytes()).hexdigest() != row["source_sha256"]:
            return None
        head = _git(root, "log", "--follow", "--format=%H", "-1", "--", source).strip()
        if head == revision:
            return revision
        tag = f"refs/tags/genewhip-fixture-source-v2-{revision}"
        target = _git(root, "rev-parse", "--verify", f"{tag}^{{commit}}").strip()
        if target != revision:
            return None
        tagged_source = _git(root, "show", f"{revision}:{source}", text=False)
        if hashlib.sha256(tagged_source).hexdigest() != row["source_sha256"]:
            return None
        return revision
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        return None


@contextmanager
def source_identity_context(validator, row, root):
    """Run the unchanged validator with only its proven source-log query bound."""
    revision = proven_revision(row, root)
    if revision is None:
        raise ValueError("fixture source revision is not proven by ancestor or immutable tag")
    head = _git(root, "log", "--follow", "--format=%H", "-1", "--", SOURCE).strip()
    if head == revision:
        yield
        return

    real_subprocess = validator.subprocess
    reference_loader = validator._successor_reference_module
    loaded_reference = reference_loader(root)
    reference_subprocess = loaded_reference.subprocess

    def proxy(real_module):
        def run(command, *args, **kwargs):
            if (isinstance(command, (list, tuple)) and len(command) == 9
                    and command[:4] == ["git", "-C", str(root), "log"]
                    and command[4:8] == ["--follow", "--format=%H", "-1", "--"]
                    and command[8] == SOURCE):
                return subprocess.CompletedProcess(command, 0, stdout=revision + "\n", stderr="")
            return real_module.run(command, *args, **kwargs)
        return SimpleNamespace(run=run,
                               CalledProcessError=real_module.CalledProcessError,
                               SubprocessError=real_module.SubprocessError)

    # Per-module proxies avoid mutating the process-global subprocess module.
    validator.subprocess = proxy(real_subprocess)
    loaded_reference.subprocess = proxy(reference_subprocess)
    validator._successor_reference_module = lambda _root: loaded_reference
    try:
        yield
    finally:
        validator.subprocess = real_subprocess
        loaded_reference.subprocess = reference_subprocess
        validator._successor_reference_module = reference_loader


def validate(validator, document, root, diagnostic_rom, *, candidate_evidence=None):
    """Validate a document, bridging only an exactly proven v2 source identity."""
    rows = document.get("fixtures", []) if isinstance(document, dict) else []
    row = next((item for item in rows if isinstance(item, dict)
                and item.get("id") == "genewhip-independent-game-v2"), None)
    if row is None:
        return validator.validate(document, root, diagnostic_rom,
                                  candidate_evidence=candidate_evidence)
    with source_identity_context(validator, row, root):
        return validator.validate(document, root, diagnostic_rom,
                                  candidate_evidence=candidate_evidence)


def require_admitted(validator, root, manifest_path, fixture_id, diagnostic_rom):
    """Resolve an admitted ROM using the same proven source identity context."""
    if fixture_id != "genewhip-independent-game-v2":
        return validator.require_admitted(root, manifest_path, fixture_id, diagnostic_rom)
    document = validator._json(root / manifest_path)
    row = next((item for item in document.get("fixtures", [])
                if isinstance(item, dict) and item.get("id") == fixture_id), None)
    if row is None:
        return validator.require_admitted(root, manifest_path, fixture_id, diagnostic_rom)
    with source_identity_context(validator, row, root):
        return validator.require_admitted(root, manifest_path, fixture_id, diagnostic_rom)

"""Conservative public-source gate; diagnostics never print matched secrets."""
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
PATTERNS = {
    "personal-path": re.compile(rb"/(?:Users|home)/[A-Za-z0-9_.-]+/|[A-Za-z]:\\Users\\"),
    "secret": re.compile(rb"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[A-Z0-9]{16}|-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----|(?i:api[_-]?key|password|secret|token)\s*[=:]\s*[\"'][A-Za-z0-9/+_=.-]{16,}[\"']"),
}
PRIVATE = {".bin", ".rom", ".mdrom", ".gen", ".smd", ".sav", ".srm", ".state"}

def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def _verified_original_rom(root, name, path):
    """Allow a manifest-admitted original seam ROM bound to its authored source and notice."""
    try:
        rows = json.loads((root / "fixtures/manifest.json").read_text())["fixtures"]
        row = next((r for r in rows if r.get("kind") == "original-rom" and r.get("rom") == name), None)
        if row is None or path.is_symlink():
            return False
        source = root / row["source"]
        notices = row.get("notices", [])
        notice_text = "".join((root / n).read_text() for n in notices)
        return (row.get("status") == "admitted" and row.get("outcome") == "pass"
                and row.get("project") == "Genewhip" and row.get("license") == "MIT"
                and row.get("assets") == [] and bool(notices)
                and row.get("sha256") == _sha256(path)
                and row.get("source_sha256") == _sha256(source)
                and "solely authored for Genewhip" in notice_text
                and "repository MIT license" in notice_text)
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return False

def _verified_public_candidate(root, name, path):
    """Allow only the exact versioned admitted ROM bound to current identities."""
    if name != "fixtures/independent-game/game.bin" or path.is_symlink():
        return _verified_original_rom(root, name, path)
    try:
        evidence_path = root / "evidence/independent-game.json"
        evidence = json.loads(evidence_path.read_text())
        identities = evidence["identities"]
        source = root / "fixtures/independent-game/src/game.s"
        notice = root / "fixtures/independent-game/NOTICES.md"
        license_path = root / "LICENSE"
        lock = root / "fixtures/independent-game/toolchain.lock"
        scenario = root / "fixtures/independent-game/scenario.json"
        audit = root / "fixtures/independent-game/route_audit.json"
        manifest = json.loads((root / "fixtures/manifest.json").read_text())
        notice_text = notice.read_text()
        manifest_rows = manifest["fixtures"]
        current_row = next((row for row in manifest_rows
                            if row.get("id") == "genewhip-independent-game-v1"), None)
        # The public-binary exception follows the versioned manifest decision;
        # all bytes and rights/evidence identities remain independently bound.
        if (current_row is None or current_row.get("status") != "admitted"
                or current_row.get("outcome") != "pass"
                or current_row.get("project") != "Genewhip"
                or current_row.get("license") != "MIT"
                or current_row.get("source") != "fixtures/independent-game/src/game.s"
                or current_row.get("assets") != []
                or current_row.get("sha256") != _sha256(path)
                or current_row.get("source_sha256") != _sha256(source)
                or "fixtures/independent-game/NOTICES.md" not in current_row.get("notices", [])
                or current_row.get("evidence_sha256") != _sha256(evidence_path)):
            return False
        if (evidence.get("status") != "pass"
                or evidence.get("candidate_disposition") != {
                    "scope": "runtime_evidence_capture",
                    "status": "candidate",
                }
                or evidence.get("temporal_scope") != {
                    "kind": "historical_pre_admission_snapshot",
                }
                or evidence.get("purpose") != "bounded runtime qualification evidence; historical pre-admission snapshot"
                or identities.get("rom_relative_path") != name
                or identities.get("rom_sha256") != _sha256(path)
                or identities.get("candidate_source_relative_path") != "fixtures/independent-game/src/game.s"
                or identities.get("candidate_source_sha256") != _sha256(source)
                or identities.get("candidate_notice_sha256") != _sha256(notice)
                or identities.get("candidate_toolchain_lock_sha256") != _sha256(lock)
                or identities.get("scenario_sha256") != _sha256(scenario)
                or identities.get("route_audit_sha256") != _sha256(audit)
                or identities.get("route_audit_status") != "pass"
                or b"Permission is hereby granted" not in license_path.read_bytes()
                or "solely authored for Genewhip" not in notice_text
                or "repository MIT license" not in notice_text
                or "No outside author or material is included." not in notice_text
                or "Third-party game content is absent." not in notice_text):
            return False
        return True
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return False

def inspect(root, paths):
    failures = []
    for name in paths:
        path = root / name
        if path.is_symlink():
            failures.append((name, "symlink")); continue
        if not path.is_file():
            continue
        if path.suffix.lower() in PRIVATE:
            if not _verified_public_candidate(root, name, path):
                reason = ("unverified-public-binary" if name == "fixtures/independent-game/game.bin"
                          else "private-fixture-or-config")
                failures.append((name, reason)); continue
        if path.name.startswith(".env"):
            failures.append((name, "private-fixture-or-config")); continue
        data = path.read_bytes()
        for reason, pattern in PATTERNS.items():
            if pattern.search(data):
                failures.append((name, reason))
    manifest = json.loads((root / "tests/vectors/manifest.json").read_text())
    for row in manifest["retained_files"]:
        path = root / "tests/vectors" / row["path"]
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != row["sha256"]:
            failures.append((str(path.relative_to(root)), "upstream-notice-or-source"))
    license_path = root / "LICENSE"
    if not license_path.is_file() or b"Permission is hereby granted" not in license_path.read_bytes():
        failures.append(("LICENSE", "project-license"))
    return failures

def main():
    names = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT).decode().split("\0")
    # Local orchestrator lock is neither public source nor an artifact input.
    names = [p for p in names if p and p != ".planning/milestone.lock"]
    failures = inspect(ROOT, names)
    if failures:
        for name, reason in failures:
            print("REJECT:", reason, name)
        return 1
    if "--self-test" in sys.argv:
        import shutil
        with tempfile.TemporaryDirectory(prefix="gw-hygiene-") as tmp:
            root = pathlib.Path(tmp)
            shutil.copy(ROOT / "LICENSE", root)
            shutil.copytree(ROOT / "tests/vectors", root / "tests/vectors")
            controls = [("path.txt", b"/" + b"Users" + b"/fixture/private", "personal-path"),
                        ("secret.txt", b"ghp_" + b"a" * 36, "secret"),
                        ("private.bin", bytes(32), "private-fixture-or-config")]
            for name, data, reason in controls:
                (root / name).write_bytes(data)
                assert inspect(root, [name]) == [(name, reason)], reason
                (root / name).unlink()
            (root / "tests/vectors/upstream/LICENSE").write_text("removed")
            assert inspect(root, []) == [("tests/vectors/upstream/LICENSE", "upstream-notice-or-source")]
        print("hygiene controls: 4/4 intended rejections; original upstream notices preserved")
    print("public hygiene: PASS")
    return 0

if __name__ == "__main__":
    sys.exit(main())

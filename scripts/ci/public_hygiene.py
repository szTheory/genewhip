"""Conservative public-source gate; diagnostics never print matched secrets."""
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import tarfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
PATTERNS = {
    "personal-path": re.compile(rb"/(?:Users|home)/[A-Za-z0-9_.-]+/|[A-Za-z]:\\Users\\"),
    "secret": re.compile(rb"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[A-Z0-9]{16}|-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----|(?i:api[_-]?key|password|secret|token)\s*[=:]\s*[\"'][A-Za-z0-9/+_=.-]{16,}[\"']"),
}
PRIVATE = {".bin", ".rom", ".mdrom", ".gen", ".smd", ".sav", ".srm", ".state"}
PUBLIC_GAME_CANDIDATES = {
    "fixtures/independent-game/game.bin",
    "fixtures/independent-game-v2/game.bin",
}

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
    if path.is_symlink():
        return _verified_original_rom(root, name, path)
    if name == "fixtures/independent-game-v2/game.bin":
        try:
            manifest = json.loads((root / "fixtures/manifest.json").read_text())
            row = next((entry for entry in manifest["fixtures"]
                        if entry.get("id") == "genewhip-independent-game-v2"), None)
            if row is None or row.get("rom") != name:
                return False
            spec = __import__("importlib.util", fromlist=["spec_from_file_location"])
            module_spec = spec.spec_from_file_location(
                "gw_public_fixture_manifest", root / "tools/evidence/fixture_manifest.py")
            if module_spec is None or module_spec.loader is None:
                return False
            validator = spec.module_from_spec(module_spec)
            module_spec.loader.exec_module(validator)
            return validator._validate_successor(row, root) == "ok"
        except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError,
                AttributeError, ImportError):
            return False
    if name != "fixtures/independent-game/game.bin":
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
                reason = ("unverified-public-binary" if name in PUBLIC_GAME_CANDIDATES
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

def scan_git_history(root=ROOT, revision="HEAD"):
    """Scan reachable historical blobs without returning matched source bytes."""
    root = pathlib.Path(root)
    commits = subprocess.check_output(
        ["git", "rev-list", revision], cwd=root, text=True).splitlines()
    object_lines = subprocess.check_output(
        ["git", "rev-list", "--objects", revision], cwd=root, text=True).splitlines()
    paths_by_oid = {}
    for line in object_lines:
        oid, _, name = line.partition(" ")
        if re.fullmatch(r"[0-9a-f]{40,64}", oid):
            paths_by_oid.setdefault(oid, name)

    object_ids = list(paths_by_oid)
    checks = subprocess.run(
        ["git", "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        cwd=root, input="\n".join(object_ids) + "\n", text=True,
        check=True, capture_output=True)
    blobs = []
    for row in checks.stdout.splitlines():
        fields = row.split()
        if len(fields) == 3 and fields[1] == "blob":
            blobs.append((fields[0], paths_by_oid[fields[0]]))

    findings = {}
    historical_binaries = {}
    binary_validation = {}
    batch_size = 128
    for start in range(0, len(blobs), batch_size):
        batch = blobs[start:start + batch_size]
        result = subprocess.run(
            ["git", "cat-file", "--batch"], cwd=root,
            input=("\n".join(oid for oid, _ in batch) + "\n").encode("ascii"),
            text=False, check=True, capture_output=True)
        cursor = 0
        for oid, name in batch:
            newline = result.stdout.find(b"\n", cursor)
            if newline < 0:
                raise RuntimeError("git-history-scan-truncated-header")
            header = result.stdout[cursor:newline].split()
            if len(header) != 3 or header[1] != b"blob":
                raise RuntimeError("git-history-scan-invalid-object")
            size = int(header[2])
            data_start = newline + 1
            data_end = data_start + size
            if data_end >= len(result.stdout):
                raise RuntimeError("git-history-scan-truncated-blob")
            data = result.stdout[data_start:data_end]
            cursor = data_end + 1
            reasons = [reason for reason, pattern in PATTERNS.items()
                       if pattern.search(data)]
            suffix = pathlib.PurePosixPath(name).suffix.lower()
            if suffix in PRIVATE:
                if name not in binary_validation:
                    current = root / name
                    binary_validation[name] = bool(
                        current.is_file() and _verified_public_candidate(root, name, current))
                    historical_binaries[name] = 0
                if binary_validation[name]:
                    historical_binaries[name] += 1
                else:
                    reasons.append("historical-private-binary")
            if reasons:
                safe_name = name if (name and not name.startswith("/")
                                     and ".." not in pathlib.PurePosixPath(name).parts
                                     and re.fullmatch(r"[A-Za-z0-9._/-]+", name)) else "path-redacted"
                row = findings.setdefault(safe_name, {"reasons": set(), "blob_versions": 0})
                row["reasons"].update(reasons)
                row["blob_versions"] += 1

    output_findings = [
        {"path": name, "reasons": sorted(row["reasons"]),
         "blob_versions": row["blob_versions"]}
        for name, row in sorted(findings.items())
    ]
    counts = {}
    for row in output_findings:
        for reason in row["reasons"]:
            counts[reason] = counts.get(reason, 0) + row["blob_versions"]
    identity_rows = subprocess.check_output(
        ["git", "log", revision, "--format=%an%x00%ae%x00%cn%x00%ce"],
        cwd=root, text=True).splitlines()
    author_names = author_emails = committer_names = committer_emails = 0
    for row in identity_rows:
        fields = row.split("\x00")
        if len(fields) == 4:
            author_names += bool(fields[0])
            author_emails += bool(fields[1])
            committer_names += bool(fields[2])
            committer_emails += bool(fields[3])
    return {
        "revision": revision,
        "commits_scanned": len(commits),
        "unique_blobs_scanned": len(blobs),
        "finding_counts": dict(sorted(counts.items())),
        "findings": output_findings,
        "historical_binary_versions": [
            {"path": name, "blob_versions": versions,
             "current_fixture_provenance_verified": True}
            for name, versions in sorted(historical_binaries.items()) if versions
        ],
        "commit_identity": {
            "commits_with_author_name": author_names,
            "commits_with_author_email": author_emails,
            "commits_with_committer_name": committer_names,
            "commits_with_committer_email": committer_emails,
            "identity_values_included": False,
        },
    }

def scan_archive(path):
    """Inspect an archive's member paths and contents without printing matched bytes."""
    path = pathlib.Path(path)
    findings = []
    try:
        with tarfile.open(path, mode="r:*") as archive:
            for member in archive.getmembers():
                member_path = pathlib.PurePosixPath(member.name)
                if (member_path.is_absolute() or ".." in member_path.parts
                        or not (member.isfile() or member.isdir())):
                    findings.append({"member": "path-redacted", "reasons": ["unsafe-archive-member"]})
                    continue
                if not member.isfile():
                    continue
                if member.size > 64 * 1024 * 1024:
                    findings.append({"member": member.name, "reasons": ["archive-member-too-large"]})
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    findings.append({"member": member.name, "reasons": ["archive-member-unreadable"]})
                    continue
                data = stream.read(64 * 1024 * 1024 + 1)
                reasons = [reason for reason, pattern in PATTERNS.items() if pattern.search(data)]
                if reasons:
                    safe_name = (member.name if not member.name.startswith("/")
                                 and ".." not in member_path.parts
                                 and re.fullmatch(r"[A-Za-z0-9._/-]+", member.name)
                                 else "path-redacted")
                    findings.append({"member": safe_name, "reasons": sorted(reasons)})
    except (OSError, tarfile.TarError, EOFError):
        findings.append({"member": "archive-redacted", "reasons": ["archive-unreadable"]})
    return findings

def scan_file(path):
    """Return only finding categories for one local file."""
    try:
        data = pathlib.Path(path).read_bytes()
    except OSError:
        return ["file-unreadable"]
    return [reason for reason, pattern in PATTERNS.items() if pattern.search(data)]

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

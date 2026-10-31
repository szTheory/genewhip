"""Build only clean, identified sources in a fresh directory; smoke exact bytes."""
import gzip
import hashlib
import importlib.util
import argparse
import io
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
_ARCHIVE_SPEC = importlib.util.spec_from_file_location(
    "genewhip_package_archive", ROOT / "scripts/package_archive.py")
package_archive = importlib.util.module_from_spec(_ARCHIVE_SPEC)
_ARCHIVE_SPEC.loader.exec_module(package_archive)

SDK_LIMIT_ARCHIVE = 256 * 1024 * 1024

def run(*args, **kwargs):
    return subprocess.check_output(args, cwd=ROOT, text=True, **kwargs).strip()

def identity(ignore_planning_for_list=False):
    status = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"],
                                     cwd=ROOT, text=True)
    # Planning notes do not enter the SDK payload; all public source and fixture
    # inputs still have to be committed before package identity is assigned.
    changes = [line for line in status.splitlines()
               if not line[3:].startswith(".planning/")]
    if changes:
        raise ValueError("source-dirty: commit public inputs before packaging")
    return run("git", "rev-parse", "HEAD")


def _json(path):
    return json.loads(pathlib.Path(path).read_text())


def _validate_performance_evidence(path, revision):
    """Re-run the production benchmark policy against the package's exact scope/run."""
    scope_path = ROOT / "evidence/v02-execution.json"
    scope = _json(scope_path)
    spec = importlib.util.spec_from_file_location("gw_package_benchmark_policy",
        ROOT / "tools/evidence/core_benchmark.py")
    benchmark = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(benchmark)
    expected = {"source_sha": revision, "head_sha": os.environ.get("GITHUB_SHA", revision),
        "base_sha": os.environ.get("GITHUB_BASE_SHA", revision),
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1")}
    document = _json(path)
    reports, digests = {}, {}
    for workload in benchmark.WORKLOADS:
        report_path = ROOT / "build/v02/collected" / ("benchmark-" + workload) / ("benchmark-" + workload + ".json")
        reports[workload] = _json(report_path)
        digests[workload] = hashlib.sha256(report_path.read_bytes()).hexdigest()
    problems = benchmark.validate_public_performance_projection(document, identity=expected,
        source_identity_sha256=benchmark.source_identity(), scope_id=scope["scope_id"],
        scope_sha256=hashlib.sha256(scope_path.read_bytes()).hexdigest(),
        expected_reports=reports, raw_report_digests=digests)
    if problems:
        raise ValueError("public-performance-policy-rejected:" + ",".join(problems))
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def _api_and_input_versions():
    header = (ROOT / "include/genewhip/genewhip.h").read_text()
    api = re.search(r"#define GW_API_VERSION UINT32_C\((\d+)\)", header)
    desktop = (ROOT / "docs/desktop.md").read_text()
    input_log = re.search(r"genewhip-input-log (\d+)", desktop)
    if not api or not input_log:
        raise ValueError("package-contract-version-unavailable")
    return int(api.group(1)), int(input_log.group(1))


def _set_consumer_package_version(cmake_path, version):
    """Align the copied consumer's exact package request with this archive version."""
    path = pathlib.Path(cmake_path)
    text = path.read_text()
    pattern = r"find_package\(Genewhip\s+\d+\.\d+\.\d+\s+EXACT"
    updated, count = re.subn(pattern, f"find_package(Genewhip {version} EXACT", text)
    if count != 1:
        raise ValueError("sdk-consumer-version-contract-missing-or-ambiguous")
    path.write_text(updated)


def _stage_consumer(source, destination, version):
    """Copy the public C/C++ consumer and bind it to its selected SDK version."""
    destination = pathlib.Path(destination)
    shutil.copytree(source, destination)
    _set_consumer_package_version(destination / "CMakeLists.txt", version)


def _load_v02_roster(path=None):
    roster = _json(path or ROOT / "packaging/v02-members.json")
    if roster.get("schema") != "genewhip-v02-package-members-v1" or roster.get("release_version") != "0.2.0":
        raise ValueError("package-roster-version")
    rights = roster.get("rights")
    if not isinstance(rights, dict):
        raise ValueError("package-rights-missing")
    for kind in ("sdk", "desktop"):
        entries = roster.get(kind, {}).get("members")
        if not isinstance(entries, list) or not entries:
            raise ValueError("package-roster-members-missing")
        paths = [row.get("path") for row in entries]
        if len(paths) != len(set(paths)):
            raise ValueError("package-roster-duplicate-member")
        by_path = set(paths)
        for row in entries:
            member = pathlib.PurePosixPath(row.get("path", ""))
            if member.is_absolute() or ".." in member.parts or "\\" in row.get("path", "") or not member.parts:
                raise ValueError("package-roster-unsafe-path")
            if row.get("rights") not in rights or not row.get("role") or not row.get("source"):
                raise ValueError("package-roster-rights-incomplete")
            rights_row = rights[row["rights"]]
            if not rights_row.get("license") or not rights_row.get("source") or not rights_row.get("redistribution"):
                raise ValueError("package-rights-incomplete")
            notice_member = rights_row.get("notice_members", {}).get(kind, rights_row.get("notice_member"))
            if notice_member not in by_path:
                raise ValueError("package-required-notice-missing")
    return roster


def _unknown_public_closure(input_path, temp_root):
    """Use the checked-in public consumer to create an explicit unknown matrix when absent."""
    import importlib.util
    matrix_path = ROOT / "scripts/evidence/v02_matrix.py"
    spec = importlib.util.spec_from_file_location("gw_v02_package_matrix", matrix_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    roster = _json(ROOT / "evidence/v02-roster.json")
    candidate = pathlib.Path(input_path).resolve()
    if (candidate / "manifest.json").is_file():
        identity_path = candidate.parent / "runtime-identity.json"
        expected_identity = _json(identity_path) if identity_path.is_file() else None
        module.verify_public_closure(candidate, ROOT / "evidence/v02-roster.json", expected_identity)
        closure = candidate
    else:
        closure = pathlib.Path(temp_root) / "public-closure"
        rows = [dict(expected, outcome="unknown", reason="no current package-source qualification proof supplied",
                     reached=False, observation_dependencies={}, observations={})
                for expected in module.expected_matrix_rows(roster)]
        module.project_public_closure(roster, rows, closure)
    return module, closure


def _closure_members(closure):
    names = ["compatibility-matrix.md", "manifest.json", "observations.json", "roster.json", "schema.json", "verifier.py"]
    if (pathlib.Path(closure) / "execution-identity.json").is_file():
        names.append("execution-identity.json")
    return names


def _sandbox_run(command, *, cwd, env, timeout=600, capture=True):
    """Run extracted SDK checks with macOS network access denied and fresh caches."""
    sandbox = shutil.which("sandbox-exec")
    if platform.system() != "Darwin" or not sandbox:
        raise ValueError("required-network-denial-capability-unavailable")
    profile = "(version 1)(allow default)(deny network*)"
    args = [sandbox, "-p", profile, *map(str, command)]
    return subprocess.run(args, cwd=cwd, env=env, check=True, timeout=timeout,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.STDOUT if capture else None, text=True)


def _build_v02(args):
    roster = _load_v02_roster()
    if args.release_version != "0.2.0":
        raise ValueError("release-version-not-supported")
    revision = identity()
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha) or args.source_sha != revision:
        raise ValueError("source-sha-must-match-actual-clean-head")
    if not args.development_only:
        subprocess.run(["bash", "scripts/ci/public-hygiene.sh"], cwd=ROOT, check=True)
    api_version, input_version = _api_and_input_versions()
    output = pathlib.Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    name = f"genewhip-0.2.0-sdk-diagnostic-{platform.system().lower()}-{platform.machine()}-{revision[:12]}"
    members = {row["path"]: row for row in roster["sdk"]["members"]}
    with tempfile.TemporaryDirectory(prefix="gw-sdk-v02-") as temp:
        scratch = pathlib.Path(temp)
        build, stage = scratch / "build", scratch / name
        subprocess.run(["cmake", "-S", str(ROOT), "-B", str(build), "-DCMAKE_BUILD_TYPE=Release",
                        "-DBUILD_TESTING=OFF", "-DGENEWHIP_TEST_HOOKS=OFF", "-DGENEWHIP_BUILD_DESKTOP=OFF",
                        "-DGENEWHIP_INSTALL_PACKAGE_VERSION=0.2.0",
                        "-DCMAKE_FIND_USE_PACKAGE_REGISTRY=FALSE"], check=True)
        build_env = dict(os.environ, ZERO_AR_DATE="1")
        subprocess.run(["cmake", "--build", str(build), "--parallel", "2"], check=True, env=build_env,
                       timeout=600)
        install = scratch / "install"
        subprocess.run(["cmake", "--install", str(build), "--prefix", str(install)], check=True, timeout=120)
        if platform.system() == "Darwin":
            for library in install.rglob("*.a"):
                subprocess.run(["ranlib", "-D", str(library)], check=True, timeout=60)
        stage.mkdir(parents=True)
        for installed in install.rglob("*"):
            if installed.is_file():
                rel = installed.relative_to(install).as_posix()
                destination = stage / rel
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(installed, destination)
        share = stage / "share/genewhip"
        for source, target in (("LICENSE", "LICENSE"), ("docs/core.md", "core.md"),
                               ("docs/input.md", "input.md"), ("evidence/schema.json", "schema.json"),
                               ("evidence/input.json", "input.json"),
                               ("packaging/notices/THIRD-PARTY-ymfm.txt", "notices/THIRD-PARTY-ymfm.txt"),
                               ("tests/vectors/upstream/LICENSE", "SingleStepTests-LICENSE"),
                               ("packaging/v02-members.json", "v02-members.json")):
            destination = share / target
            destination.parent.mkdir(parents=True, exist_ok=True)
            if source == "docs/core.md":
                core_doc = (ROOT / source).read_text().replace("package version 0.1.0", "package version 0.2.0")
                destination.write_text(core_doc)
            else:
                shutil.copyfile(ROOT / source, destination)
        _stage_consumer(ROOT / "tests/consumer", share / "consumer", "0.2.0")
        consumer_main = share / "consumer/main.c"
        consumer_source = consumer_main.read_text()
        old_mulu = "variant[0x200] = 0xc0; variant[0x201] = 0xc0; /* legal MULU.W D0,D0, unsupported */"
        old_opcode = "result.opcode == 0xc0c0"
        if old_mulu not in consumer_source or old_opcode not in consumer_source:
            raise ValueError("sdk-consumer-obsolete-opcode-control-not-found")
        # Phase 6 added documented MULU.W behavior. Keep the public unsupported-opcode
        # contract exercised with an as-yet-unimplemented legal DIVU.W encoding.
        consumer_main.write_text(consumer_source.replace(old_mulu,
            "variant[0x200] = 0x4a; variant[0x201] = 0xc0; /* legal TAS D0, not in the selected CPU subset */")
            .replace(old_opcode, "result.opcode == 0x4ac0"))
        shutil.copyfile(build / "diagnostic.bin", share / "diagnostic.bin")
        report = subprocess.check_output([str(stage / "bin/gw_diagnostic_runner"), str(share / "diagnostic.bin")],
                                         cwd=scratch, text=True, timeout=30)
        (share / "diagnostic-evidence.json").write_text(report + "\n")
        subprocess.run([str(stage / "bin/gw_validate_evidence"), str(share / "diagnostic-evidence.json")],
                       cwd=scratch, check=True, timeout=30)
        module, closure = _unknown_public_closure(args.public_evidence, scratch)
        identity_path = pathlib.Path(args.public_evidence).resolve().parent / "runtime-identity.json"
        current_identity = _json(identity_path) if identity_path.is_file() else None
        verify = module.verify_public_closure(closure, ROOT / "evidence/v02-roster.json", current_identity)
        public_digest = _json(closure / "manifest.json")["closure_id"]
        matrix_rows = _json(closure / "observations.json")
        matrix_counts = {status: sum(row.get("outcome") == status for row in matrix_rows)
                         for status in ("pass", "fail", "unsupported", "skipped", "unknown", "infrastructure-error")}
        matrix_summary = ", ".join(f"{status} {count}" for status, count in matrix_counts.items() if count)
        evidence_dir = share / "evidence"
        evidence_dir.mkdir()
        for item in _closure_members(closure):
            shutil.copyfile(closure / item, evidence_dir / item)
        performance = pathlib.Path(args.public_evidence).resolve() / "performance.json"
        if not performance.is_file():
            raise ValueError("public-performance-evidence-missing")
        performance_digest = _validate_performance_evidence(performance, revision)
        shutil.copyfile(performance, evidence_dir / "performance.json")
        (share / "README.md").write_text(
            "# Genewhip v0.2.0 SDK package\n\n"
            f"Package version 0.2.0; C API {api_version}; input-log format {input_version}. "
            f"The included independently verified scoped matrix records {matrix_summary or 'no outcomes'}. "
            "The separate performance report names its own source identity. This archive is not a publication "
            "or authenticated downloaded-byte qualification claim.\n\n"
            "This SDL-free SDK contains the diagnostic, installed C API, C/C++ consumer example, "
            "and notices. It contains no admitted game corpus. See the included compatibility matrix "
            "for explicit scope and limitations.\n")
        binary_paths = ["lib/libgenewhip_core.a", "bin/gw_diagnostic_runner", "bin/gw_validate_evidence"]
        runtime_identity = hashlib.sha256("\n".join(
            f"{path}:{hashlib.sha256((stage/path).read_bytes()).hexdigest()}" for path in binary_paths).encode()).hexdigest()
        required = sorted(set(members) - {"metadata.json", "checksums.json"})
        rights = {path: members[path]["rights"] for path in required}
        metadata = {"schema_version": 2, "version": "0.2.0", "release_version": "0.2.0",
                    "api_version": api_version, "input_log_version": input_version, "kind": "SDL-free SDK/diagnostic",
                    "source_revision": revision, "source_state": "development-only" if args.development_only else "clean",
                    "configuration": json.loads(report)["configuration"], "system": platform.system(),
                    "architecture": platform.machine(), "os_version": platform.mac_ver()[0] or platform.release(),
                    "compiler": run(os.environ.get("CC", "cc"), "--version").splitlines()[0],
                    "cmake": run("cmake", "--version").splitlines()[0],
                    "build": "Release; C17; static; hooks off; SDL-free; offline core",
                    "runtime_content_identity": runtime_identity, "public_evidence_digest": public_digest,
                    "performance_evidence_digest": performance_digest,
                    "required_members": required, "member_rights": rights,
                    "limitations": "Scoped compatibility evidence is reported per roster row; no publication or authenticated downloaded-byte qualification claim"}
        (stage / "metadata.json").write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
        payload = sorted(p for p in stage.rglob("*") if p.is_file())
        personal_path = re.compile(rb"/(?:Users|home)/[A-Za-z0-9_.-]+/(?:projects|Desktop|Documents|Downloads|Library)/")
        home_path = str(pathlib.Path.home().resolve()).encode()
        for path in payload:
            body = path.read_bytes()
            if (str(ROOT).encode() in body or str(scratch).encode() in body or home_path in body or
                    personal_path.search(body)):
                raise ValueError("private-path-in-package: " + path.relative_to(stage).as_posix())
        checksum_map = {p.relative_to(stage).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in payload}
        (stage / "checksums.json").write_text(json.dumps(checksum_map, sort_keys=True, indent=2) + "\n")
        _validate_v02_members(stage, "sdk", roster)
        epoch = int(run("git", "show", "-s", "--format=%ct", revision))
        pending = scratch / "sdk.tar.gz"
        with pending.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                for path in sorted(p for p in stage.rglob("*") if p.is_file()):
                    data = path.read_bytes()
                    info = tarfile.TarInfo(name + "/" + path.relative_to(stage).as_posix())
                    info.size, info.mtime, info.mode = len(data), epoch, 0o755 if os.access(path, os.X_OK) else 0o644
                    tar.addfile(info, io.BytesIO(data))
        digest = hashlib.sha256(pending.read_bytes()).hexdigest()
        smoke = subprocess.run([sys.executable, str(ROOT / "tests/package/smoke.py"), "--v02", str(pending), digest,
                                revision, str(ROOT / "packaging/v02-members.json")],
                               cwd=ROOT, check=False, capture_output=True, text=True, timeout=1200)
        if smoke.returncode:
            sys.stderr.write(smoke.stdout + smoke.stderr)
            raise ValueError("sdk-package-smoke-failed")
        shutil.copyfile(pending, output / (name + ".tar.gz"))
        archive = output / (name + ".tar.gz")
        archive.with_suffix(archive.suffix + ".sha256").write_text(digest + "  " + archive.name + "\n")
        receipt = {"schema": "genewhip-local-package-qualification", "version": 2,
                   "release_version": "0.2.0", "kind": "SDL-free SDK/diagnostic archive", "outcome": "pass",
                   "source_revision": revision, "source_state": metadata["source_state"], "archive": archive.name,
                   "archive_sha256": digest, "runtime_content_identity": runtime_identity,
                   "public_evidence_digest": public_digest,
                   "performance_evidence_digest": performance_digest, "api_version": api_version,
                   "input_log_version": input_version, "smoke": json.loads(smoke.stdout.strip().splitlines()[-1]),
                   "publication": "not published; external local exact-byte development qualification"}
        receipt_path = output / (archive.name + ".qualification.json")
        receipt_path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
        print(json.dumps({"archive": str(archive), "sha256": digest, "receipt": str(receipt_path),
                          "source_revision": revision, "source_state": metadata["source_state"],
                          "public_evidence_digest": public_digest}))


def _validate_v02_members(stage, kind, roster):
    expected = {row["path"] for row in roster[kind]["members"]}
    actual = {p.relative_to(stage).as_posix() for p in stage.rglob("*") if p.is_file()} | {"checksums.json"}
    if expected != actual:
        raise ValueError("package-member-roster-mismatch")

def main():
    if "--release-version" in sys.argv[1:]:
        parser = argparse.ArgumentParser(description="Build explicitly versioned Genewhip SDK archives")
        parser.add_argument("--release-version", required=True, choices=("0.1.0", "0.2.0"))
        parser.add_argument("--source-sha", required=True)
        parser.add_argument("--public-evidence", required=True, type=pathlib.Path)
        parser.add_argument("--output-dir", required=True, type=pathlib.Path)
        parser.add_argument("--development-only", action="store_true")
        args = parser.parse_args()
        if args.release_version == "0.2.0":
            _build_v02(args)
            return
        # Legacy 0.1.0 builds retain the historical command/receipt contract.
        if args.public_evidence or args.output_dir:
            raise ValueError("legacy-version-explicit-arguments-unsupported")
    list_mode = sys.argv[1:] == ["--list"]
    if sys.argv[1:] and not list_mode:
        raise ValueError("usage: package_sdk.py [--list]")
    revision = identity(ignore_planning_for_list=list_mode)
    subprocess.run(["bash", "scripts/ci/public-hygiene.sh"], cwd=ROOT, check=True)
    output = ROOT / "artifacts"
    if not list_mode:
        output.mkdir(exist_ok=True)
    name = "genewhip-0.1.0-sdk-diagnostic-" + platform.system().lower() + "-" + platform.machine() + "-" + revision[:12]
    with tempfile.TemporaryDirectory(prefix="gw-package-") as tmp:
        scratch = pathlib.Path(tmp)
        build, stage = scratch / "build", scratch / name
        subprocess.run(["cmake", "-S", str(ROOT), "-B", str(build), "-DCMAKE_BUILD_TYPE=Release",
                        "-DBUILD_TESTING=OFF", "-DGENEWHIP_TEST_HOOKS=OFF", "-DGENEWHIP_INSTALL_PACKAGE_VERSION=0.1.0",
                        "-DCMAKE_C_FLAGS="], check=True)
        # Apple libtool archives otherwise embed wall-clock member timestamps.
        build_env = dict(os.environ, ZERO_AR_DATE="1")
        subprocess.run(["cmake", "--build", str(build), "--parallel", "2"], check=True, env=build_env)
        subprocess.run(["cmake", "--install", str(build), "--prefix", str(stage)], check=True)
        if platform.system() == "Darwin":
            # Xcode's ranlib table of contents needs its explicit deterministic
            # switch even when ar received ZERO_AR_DATE.
            for library in stage.rglob("*.a"):
                subprocess.run(["ranlib", "-D", str(library)], check=True)
        share = stage / "share/genewhip"
        for src in ["packaging/README.md", "docs/core.md", "evidence/schema.json", "evidence/input.json", "fixtures/manifest.json"]:
            shutil.copy(ROOT / src, share / pathlib.Path(src).name)
        shutil.copy(ROOT / "packaging/notices/THIRD-PARTY-ymfm.txt", share / "THIRD-PARTY-ymfm.txt")
        _stage_consumer(ROOT / "tests/consumer", share / "consumer", "0.1.0")
        # No upstream vectors/decoder are shipped. Their retained license is also
        # included for the source provenance cited by the diagnostic SDK docs.
        shutil.copy(ROOT / "tests/vectors/upstream/LICENSE", share / "SingleStepTests-LICENSE")
        report = run(str(stage / "bin/gw_diagnostic_runner"), str(share / "diagnostic.bin"))
        (share / "diagnostic-evidence.json").write_text(report + "\n")
        run(str(stage / "bin/gw_validate_evidence"), str(share / "diagnostic-evidence.json"))
        evidence = json.loads(report)
        if evidence["source_revision"] != revision or evidence["source_state"] != "clean":
            raise ValueError("evidence-source-identity")
        metadata = {"schema_version": 1, "version": "0.1.0", "api_version": 4,
                    "kind": "SDK/diagnostic preview", "source_revision": revision,
                    "source_state": "clean", "configuration": evidence["configuration"],
                    "system": platform.system(), "architecture": platform.machine(),
                    "os_version": platform.mac_ver()[0] or platform.release(),
                    "compiler": run(os.environ.get("CC", "cc"), "--version").splitlines()[0],
                    "cmake": run("cmake", "--version").splitlines()[0],
                    "build": "Release; C17; static; test hooks off; no SDL",
                    "limitations": "Native host only; unsigned/unnotarized; no game compatibility or performance claim; no publication"}
        (stage / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
        files = sorted(p for p in stage.rglob("*") if p.is_file())
        for path in files:
            data = path.read_bytes()
            if str(ROOT).encode() in data or str(scratch).encode() in data:
                raise ValueError("private-build-path-in-artifact")
        checksums = {str(p.relative_to(stage)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
        (stage / "checksums.json").write_text(json.dumps(checksums, indent=2) + "\n")
        if identity(ignore_planning_for_list=list_mode) != revision:
            raise ValueError("source-changed-during-build")
        if list_mode:
            archive_files = sorted(p for p in stage.rglob("*") if p.is_file())
            for path in archive_files:
                print("SDK_FILE\t" + str(path.relative_to(stage)).replace(os.sep, "/"))
            return
        epoch = int(run("git", "show", "-s", "--format=%ct", revision))
        archive = output / (name + ".tar.gz")
        pending = scratch / "package.tar.gz"
        with pending.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                for path in sorted(stage.rglob("*")):
                    if not path.is_file():
                        continue
                    data = path.read_bytes()
                    info = tarfile.TarInfo(name + "/" + str(path.relative_to(stage)))
                    info.size, info.mtime, info.mode = len(data), epoch, 0o755 if os.access(path, os.X_OK) else 0o644
                    tar.addfile(info, io.BytesIO(data))
        digest = hashlib.sha256(pending.read_bytes()).hexdigest()
        # No successful-looking final artifact until exact-byte smoke succeeds.
        smoke = subprocess.run([sys.executable, str(ROOT / "tests/package/smoke.py"), str(pending), digest, revision],
                               check=False, capture_output=True, text=True)
        if smoke.returncode:
            sys.stderr.write(smoke.stdout)
            sys.stderr.write(smoke.stderr)
            raise ValueError("sdk-package-smoke-failed")
        smoke_result = json.loads(smoke.stdout.strip().splitlines()[-1])
        if identity() != revision:
            raise ValueError("source-changed-during-smoke")
        shutil.copyfile(pending, archive)
        archive.with_suffix(archive.suffix + ".sha256").write_text(digest + "  " + archive.name + "\n")
        with tarfile.open(pending, "r:*") as tar:
            root_name = next(pathlib.PurePosixPath(row.name).parts[0] for row in tar.getmembers() if row.isfile())
            inventory_sha256 = hashlib.sha256(tar.extractfile(root_name + "/checksums.json").read()).hexdigest()
            metadata = json.loads(tar.extractfile(root_name + "/metadata.json").read())
        receipt = {"schema": "genewhip-local-package-qualification", "version": 1,
                   "kind": "SDL-free API 4 SDK archive", "outcome": "pass",
                   "source_revision": revision, "archive": archive.name, "archive_sha256": digest,
                   "inventory_sha256": inventory_sha256, "api_version": metadata["api_version"],
                   "host_system": metadata["system"], "host_architecture": metadata["architecture"],
                   "smoke": smoke_result,
                   "publication": "not published; this is a local exact-byte qualification receipt"}
        receipt_path = output / (archive.name + ".qualification.json")
        receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps({"archive": str(archive.relative_to(ROOT)), "sha256": digest,
                          "inventory_sha256": inventory_sha256, "receipt": str(receipt_path.relative_to(ROOT)),
                          "source_revision": revision}))

if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print("REJECT: " + str(error), file=sys.stderr)
        sys.exit(1)

"""Build and qualify the exact native arm64 playable-preview archive.

Usage: package_desktop.py [--repeatability]

The archive is smoked as exact bytes before it is copied to artifacts/. With
--repeatability the build runs twice in fresh directories and the archive digests
are compared (no smoke, no copy); differing members are listed on a mismatch.
"""
import gzip
import argparse
import hashlib
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
LABEL = "narrow playable preview"
PERSONAL_PATH = re.compile(rb"/(?:Users|home)/[A-Za-z0-9_.-]+/|[A-Za-z]:\\Users\\")


def run(*args, **kwargs):
    return subprocess.check_output(args, cwd=ROOT, text=True, **kwargs).strip()


def identity():
    status = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"],
                                     cwd=ROOT, text=True)
    # Planning artifacts do not enter the archive. Public source, build, fixture,
    # tests and packaging edits still have to be committed before packaging.
    changes = [p for p in status.splitlines() if not p[3:].startswith(".planning/")]
    if changes:
        raise ValueError("source-dirty: commit public inputs before packaging")
    return run("git", "rev-parse", "HEAD")


def toy_log(scenario):
    """The scenario's guest-independent inputs as a genewhip-input-log 1 file."""
    ticks = scenario["inputs"]["ticks_per_field"]
    lines = ["genewhip-input-log 1"] + ["%d pad %d %x" % (e["field"] * ticks, e["port"], int(e["mask"], 0))
                                       for e in scenario["inputs"]["entries"]]
    return "\n".join(lines) + "\n"


def game_input_log(case):
    buttons = {"Start": 128, "Right": 8, "Left": 4, "Up": 1, "Down": 2,
               "A": 64, "B": 16, "C": 32}
    held = [0, 0]
    lines = ["genewhip-input-log 1"]
    for event in sorted(case["input_schedule"], key=lambda row: row["frame"]):
        port_name, _, button = event["control"].partition(" ")
        if port_name not in ("P1", "P2") or button not in buttons:
            raise ValueError("game-input-log: unknown controller event")
        port = int(port_name[1]) - 1
        held[port] = held[port] | buttons[button] if event["asserted"] else held[port] & ~buttons[button]
        lines.append("%d pad %d %x" % (event["frame"] * 896040, port, held[port]))
    return ("\n".join(lines) + "\n").encode()


def sdl_route():
    archive = os.environ.get("GENEWHIP_SDL3_ARCHIVE", "")
    if archive:
        return ["-DGENEWHIP_SDL3_ARCHIVE=" + archive], "local archive (SHA-256 pin still enforced)"
    return [], "pinned release URL (URL_HASH enforced)"


def _v02_sdl_route():
    archive = pathlib.Path(os.environ.get("GENEWHIP_SDL3_ARCHIVE", ""))
    dependency = json.loads((ROOT / "packaging/dependencies/sdl3.json").read_text())
    if not archive.is_file() or hashlib.sha256(archive.read_bytes()).hexdigest() != dependency.get("sha256"):
        raise ValueError("pinned-sdl3-local-archive-unavailable-or-mismatched")
    return ["-DGENEWHIP_SDL3_ARCHIVE=" + str(archive.resolve())], "verified local SHA-256 archive; offline"


def _build_v02_archive(revision, scratch, name, development_only, public_evidence):
    """Build the reviewed v0.2 desktop member set from a committed source snapshot."""
    spec = __import__("importlib.util", fromlist=["spec_from_file_location"])
    loader = spec.spec_from_file_location("gw_v02_sdk_roster", ROOT / "scripts/package_sdk.py")
    package_sdk = spec.module_from_spec(loader)
    loader.loader.exec_module(package_sdk)
    roster = package_sdk._load_v02_roster()
    source, build, stage = scratch / "source", scratch / "source/.package-build", scratch / name
    source.mkdir()
    source_archive = subprocess.check_output(["git", "archive", revision], cwd=ROOT)
    with tarfile.open(fileobj=io.BytesIO(source_archive), mode="r:") as source_tar:
        source_tar.extractall(source)
    env = dict(os.environ, ZERO_AR_DATE="1")
    sdl_args, route = _v02_sdl_route()
    maps = " ".join("-ffile-prefix-map=%s=." % p for p in (build, source))
    configure_build(source, build, ["-DBUILD_TESTING=OFF", "-DGENEWHIP_TEST_HOOKS=OFF",
        "-DGENEWHIP_BUILD_DESKTOP=ON", "-DGENEWHIP_INSTALL_PACKAGE_VERSION=0.2.0",
        "-DCMAKE_C_FLAGS=" + maps, *sdl_args], env)
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("unsupported-build-host: native macOS arm64 required")
    (stage / "bin").mkdir(parents=True)
    (stage / "share/genewhip").mkdir(parents=True)
    shutil.copy2(build / "tools/desktop/genewhip-desktop", stage / "bin/genewhip-desktop")
    shutil.copy2(build / "tools/session/gw_headless", stage / "bin/gw_headless")

    module, closure = package_sdk._unknown_public_closure(public_evidence, scratch)
    identity_path = pathlib.Path(public_evidence).resolve().parent / "runtime-identity.json"
    current_identity = package_sdk._json(identity_path) if identity_path.is_file() else None
    module.verify_public_closure(closure, source / "evidence/v02-roster.json", current_identity)
    closure_map = {"share/genewhip/evidence/" + p: closure / p
        for p in package_sdk._closure_members(closure)}
    performance = pathlib.Path(public_evidence).resolve() / "performance.json"
    if not performance.is_file():
        raise ValueError("public-performance-evidence-missing")
    performance_digest = package_sdk._validate_performance_evidence(performance, revision)
    for row in roster["desktop"]["members"]:
        target_name = row["path"]
        source_name = row["source"]
        if target_name in ("bin/genewhip-desktop", "bin/gw_headless", "metadata.json", "checksums.json"):
            continue
        if target_name in closure_map:
            (stage / target_name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(closure_map[target_name], stage / target_name)
            continue
        if target_name == "share/genewhip/evidence/performance.json":
            shutil.copyfile(performance, stage / target_name)
            continue
        if target_name == "share/genewhip/v02-members.json":
            shutil.copyfile(source / "packaging/v02-members.json", stage / target_name)
            continue
        if target_name == "share/genewhip/README.md":
            readme = (source / "packaging/desktop/README.md").read_text()
            readme = readme.replace("0.1.0", "0.2.0")
            readme += ("\nThis exact local package was built from a development-only source snapshot. "
                       "Its compatibility matrix records unknown outcomes unless matching public proof is present. "
                       "Only the enumerated admitted examples and bounded routes are included.\n")
            (stage / target_name).write_text(readme)
            continue
        if source_name.startswith("fixtures/") or source_name.startswith("docs/") or source_name.startswith("packaging/") or source_name == "LICENSE":
            source_path = source / source_name
            if not source_path.is_file() or source_path.is_symlink():
                raise ValueError("package-source-member-unavailable: " + source_name)
            (stage / target_name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_path, stage / target_name)
            continue
        raise ValueError("package-member-source-not-explicit: " + source_name)

    api_version, input_version = package_sdk._api_and_input_versions()
    dependency = json.loads((source / "packaging/dependencies/sdl3.json").read_text())
    payload = sorted(p for p in stage.rglob("*") if p.is_file())
    home_path = str(pathlib.Path.home().resolve()).encode()
    for path in payload:
        body = path.read_bytes()
        if str(ROOT).encode() in body or str(scratch).encode() in body or home_path in body or PERSONAL_PATH.search(body):
            raise ValueError("private-path-in-package: " + path.relative_to(stage).as_posix())
    required = sorted(p.relative_to(stage).as_posix() for p in payload)
    rights = {row["path"]: row["rights"] for row in roster["desktop"]["members"] if row["path"] not in ("checksums.json", "metadata.json")}
    identity = hashlib.sha256("\n".join(f"{p}:{hashlib.sha256((stage/p).read_bytes()).hexdigest()}" for p in
        ("bin/genewhip-desktop", "bin/gw_headless")).encode()).hexdigest()
    matrix_digest = package_sdk._json(closure / "manifest.json")["closure_id"]
    metadata = {"schema_version": 2, "version": "0.2.0", "release_version": "0.2.0",
        "api_version": api_version, "input_log_version": input_version,
        "kind": "curated SDL3 desktop archive", "source_revision": revision,
        "source_state": "development-only" if development_only else "clean",
        "system": platform.system(), "architecture": platform.machine(), "architectures": [platform.machine()],
        "tested_os": platform.mac_ver()[0] or platform.release(),
        "deployment_target": os.environ.get("MACOSX_DEPLOYMENT_TARGET", "toolchain default (not explicitly set)"),
        "compiler": run(os.environ.get("CC", "cc"), "--version").splitlines()[0],
        "cmake": run("cmake", "--version").splitlines()[0],
        "build": "Release; C17; hooks off; SDL3 static from hash-verified local archive",
        "sdl3_route": route, "sdl3_version": dependency["version"], "sdl3_sha256": dependency["sha256"],
        "runtime_content_identity": identity, "public_evidence_digest": matrix_digest,
        "performance_evidence_digest": performance_digest,
        "required_members": required, "member_rights": rights,
        "limitations": "Development-only local snapshot; unknown matrix outcomes retained; native macOS arm64; unsigned/unnotarized; no publication"}
    (stage / "metadata.json").write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
    checksums = {p.relative_to(stage).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in
                 sorted(p for p in stage.rglob("*") if p.is_file())}
    (stage / "checksums.json").write_text(json.dumps(checksums, sort_keys=True, indent=2) + "\n")
    _validate_v02_desktop_members(stage, roster)
    epoch = int(run("git", "show", "-s", "--format=%ct", revision))
    pending = scratch / "desktop.tar.gz"
    with pending.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for path in sorted(p for p in stage.rglob("*") if p.is_file()):
                data = path.read_bytes()
                info = tarfile.TarInfo(name + "/" + path.relative_to(stage).as_posix())
                info.size, info.mtime, info.mode = len(data), epoch, 0o755 if os.access(path, os.X_OK) else 0o644
                tar.addfile(info, io.BytesIO(data))
    return pending, hashlib.sha256(pending.read_bytes()).hexdigest()


def _validate_v02_desktop_members(stage, roster):
    expected = {row["path"] for row in roster["desktop"]["members"]}
    actual = {p.relative_to(stage).as_posix() for p in stage.rglob("*") if p.is_file()} | {"checksums.json"}
    if expected != actual:
        raise ValueError("package-member-roster-mismatch missing=" + ",".join(sorted(expected - actual)) +
                         " extra=" + ",".join(sorted(actual - expected)))


def _v02_package(args):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("unsupported-build-host: native macOS arm64 required")
    if args.development_only:
        status = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"],
                                         cwd=ROOT, text=True)
        if status.strip():
            raise ValueError("development-snapshot-not-clean")
        revision = run("git", "rev-parse", "HEAD")
        state = "development-only"
    else:
        if identity() != args.source_sha:
            raise ValueError("source-sha-not-clean-head")
        subprocess.run(["bash", "scripts/ci/public-hygiene.sh"], cwd=ROOT, check=True)
        revision, state = args.source_sha, "clean"
    if revision != args.source_sha:
        raise ValueError("source-sha-mismatch")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    name = "genewhip-0.2.0-playable-preview-macos-arm64-" + revision[:12]
    with tempfile.TemporaryDirectory(prefix="gw-desktop-v02-") as tmp:
        pending, digest = _build_v02_archive(revision, pathlib.Path(tmp), name, state == "development-only",
                                             args.public_evidence)
        with tempfile.TemporaryDirectory(prefix="gw-desktop-v02-repeat-") as repeat_tmp:
            repeated, repeated_digest = _build_v02_archive(revision, pathlib.Path(repeat_tmp), name,
                                                            state == "development-only", args.public_evidence)
            if digest != repeated_digest or members(pending) != members(repeated):
                raise ValueError("desktop-v02-archive-not-repeatable")
        smoke = subprocess.run([sys.executable, str(ROOT / "tests/package/desktop_smoke.py"), "--v02",
                                str(pending), digest, revision, str(ROOT / "packaging/v02-members.json")],
                               cwd=ROOT, capture_output=True, text=True, timeout=1800)
        if smoke.returncode:
            sys.stderr.write(smoke.stdout + smoke.stderr)
            raise ValueError("desktop-v02-package-smoke-failed")
        smoke_result = json.loads(smoke.stdout.strip().splitlines()[-1])
        archive = output / (name + ".tar.gz")
        shutil.copyfile(pending, archive)
        archive.with_suffix(archive.suffix + ".sha256").write_text(digest + "  " + archive.name + "\n")
        with tarfile.open(pending, "r:*") as tar:
            root_name = next(pathlib.PurePosixPath(row.name).parts[0] for row in tar.getmembers() if row.isfile())
            inventory_digest = hashlib.sha256(tar.extractfile(root_name + "/checksums.json").read()).hexdigest()
            metadata = json.loads(tar.extractfile(root_name + "/metadata.json").read())
        receipt = {"schema": "genewhip-local-package-qualification", "version": 2,
            "release_version": "0.2.0", "kind": "curated SDL3 desktop archive", "outcome": "pass",
            "source_revision": revision, "source_state": state, "archive": archive.name,
            "archive_sha256": digest, "inventory_sha256": inventory_digest,
            "runtime_content_identity": metadata["runtime_content_identity"],
            "public_evidence_digest": metadata["public_evidence_digest"],
            "performance_evidence_digest": performance_digest, "api_version": metadata["api_version"],
            "input_log_version": metadata["input_log_version"], "smoke": smoke_result,
            "publication": "not published; external local exact-byte development qualification"}
        receipt_path = archive.with_suffix(archive.suffix + ".qualification.json")
        receipt_path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
        print(json.dumps({"archive": str(archive), "sha256": digest, "receipt": str(receipt_path),
            "source_revision": revision, "source_state": state,
            "public_evidence_digest": metadata["public_evidence_digest"]}, sort_keys=True))


def configure_build(src, build, extra, env):
    subprocess.run(["cmake", "-S", str(src), "-B", str(build), "-DCMAKE_BUILD_TYPE=Release", *extra],
                   check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["cmake", "--build", str(build), "--parallel", "2"], check=True, env=env,
                   stdout=subprocess.DEVNULL)


def build_archive(revision, scratch, name):
    """Return (pending archive path, sha256) for the revision, built inside scratch."""
    source, build, stage = scratch / "source", scratch / "source/.package-build", scratch / name
    source.mkdir()
    source_archive = subprocess.check_output(["git", "archive", revision], cwd=ROOT)
    with tarfile.open(fileobj=io.BytesIO(source_archive), mode="r:") as source_tar:
        source_tar.extractall(source)
    # Apple libtool/ld otherwise embed wall-clock or build-directory identity.
    env = dict(os.environ, ZERO_AR_DATE="1")
    sdl_args, route = sdl_route()
    maps = " ".join("-ffile-prefix-map=%s=." % p for p in (build, source))
    configure_build(source, build, ["-DBUILD_TESTING=OFF", "-DGENEWHIP_TEST_HOOKS=OFF", "-DGENEWHIP_BUILD_DESKTOP=ON",
                                    "-DCMAKE_C_FLAGS=" + maps, *sdl_args], env)
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("unsupported-build-host: native macOS arm64 required")
    phase4_game = source / "tests/fixtures/phase4_game.py"
    game_evidence = build / "evidence/phase4-gameplay.json"
    game_evidence.parent.mkdir(parents=True, exist_ok=True)
    game_run = subprocess.run([sys.executable, str(phase4_game), str(build / "tools/session/gw_headless"),
                               str(build / "tools/desktop/genewhip-desktop"), "--report", str(game_evidence)],
                              cwd=source, env=dict(os.environ, SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="dummy"),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=900)
    if game_run.returncode:
        raise ValueError("gameplay-qualification: " + game_run.stderr.strip())
    tracer = source / "tests/fixtures/phase4_tracer.py"
    tracer_out = build / "evidence/phase4-tracer.json"
    subprocess.run([sys.executable, str(tracer), "--headless", str(build / "tools/session/gw_headless"),
                    "--desktop", str(build / "tools/desktop/genewhip-desktop"), "--out", str(tracer_out)],
                   cwd=source, env=dict(os.environ, SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="dummy"),
                   check=True, timeout=600)
    phase4_report = source / "scripts/evidence/phase4_report.py"
    report_path = build / "evidence/phase4-evidence.json"
    report_env = dict(os.environ, GENEWHIP_SOURCE_SNAPSHOT="1", GENEWHIP_SOURCE_REVISION=revision)
    subprocess.run([sys.executable, str(phase4_report), "build", "--build", str(build), "--out", str(report_path)],
                   cwd=source, env=report_env, check=True, timeout=120)
    share = stage / "share/genewhip"
    (stage / "bin").mkdir(parents=True)
    share.mkdir(parents=True)
    shutil.copy(build / "tools/desktop/genewhip-desktop", stage / "bin/genewhip-desktop")
    shutil.copy(build / "tools/session/gw_headless", stage / "bin/gw_headless")
    for target, src in [("README.md", "packaging/desktop/README.md"), ("LICENSE", "LICENSE"),
                        ("SDL3-LICENSE.txt", "packaging/notices/SDL3-LICENSE.txt"),
                        ("THIRD-PARTY-ymfm.txt", "packaging/notices/THIRD-PARTY-ymfm.txt"),
                        ("sdl3.json", "packaging/dependencies/sdl3.json"),
                        ("manifest.json", "fixtures/manifest.json"),
                        ("independent-game-v2.bin", "fixtures/independent-game-v2/game.bin"),
                        ("independent-game-v2.s", "fixtures/independent-game-v2/src/game.s"),
                        ("independent-game-v2-NOTICES.md", "fixtures/independent-game-v2/NOTICES.md"),
                        ("independent-game-v2-scenario.json", "fixtures/independent-game-v2/scenario.json"),
                        ("independent-game-v2-oracle.json", "fixtures/independent-game-v2/oracle.json"),
                        ("independent-game-v2-host-controls.json", "fixtures/independent-game-v2/host-controls.json"),
                        ("raster-toy.bin", "fixtures/raster-toy/toy.bin"),
                        ("raster-toy.s", "fixtures/raster-toy/src/toy.s"),
                        ("raster-toy-z80-driver.s", "fixtures/raster-toy/z80/driver.s"),
                        ("raster-toy-z80-driver.inc", "fixtures/raster-toy/z80/driver.inc"),
                        ("raster-toy-NOTICES.md", "fixtures/raster-toy/NOTICES.md"),
                        ("raster-toy-scenario.json", "fixtures/raster-toy/scenario.json"),
                        ("video.md", "docs/video.md"), ("input.md", "docs/input.md"),
                        ("desktop.md", "docs/desktop.md")]:
        if src:
            shutil.copy(source / src, share / target)
    scenario = json.loads((source / "fixtures/raster-toy/scenario.json").read_text())
    (share / "raster-toy-demo.log").write_text(toy_log(scenario))
    game_scenario = json.loads((source / "fixtures/independent-game-v2/scenario.json").read_text())
    game_case = next(row for row in game_scenario["cases"] if row["id"] == "sustained-play")
    (share / "independent-game-v2-demo.log").write_bytes(game_input_log(game_case))
    shutil.copy(game_evidence, share / "phase4-gameplay.json")
    shutil.copy(tracer_out, share / "phase4-diagnostic.json")
    shutil.copy(report_path, share / "phase4-evidence.json")
    report = json.loads(report_path.read_text())
    if report["source_revision"] != revision or report["source_state"] != "clean":
        raise ValueError("evidence-source-identity")
    subprocess.run([sys.executable, str(phase4_report), "validate", "--report", str(report_path),
                    "--build", str(build), "--head", revision], cwd=source, env=report_env, check=True)
    manifest = json.loads((source / "fixtures/manifest.json").read_text())
    game = next((row for row in manifest["fixtures"] if row.get("id") == "genewhip-independent-game-v2"), None)
    if not game or game.get("status") != "admitted" or game.get("outcome") != "pass":
        raise ValueError("fixture-admission: independent-game-v2")
    dependency = json.loads((source / "packaging/dependencies/sdl3.json").read_text())
    if dependency.get("version") != "3.4.18" or dependency.get("sha256") != "9c75cf16330322c217dedd2e0609f1124f1b54b8633e763467b4684d0f4334a3":
        raise ValueError("dependency-identity: SDL3")
    signing_output = subprocess.run(["security", "find-identity", "-v", "-p", "codesigning"],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout
    signing_capability = "Developer ID identity detected; signing not used" if "Developer ID Application" in signing_output else "no Developer ID identity detected"
    macos_target = os.environ.get("MACOSX_DEPLOYMENT_TARGET", "toolchain default (not explicitly set)")
    metadata = {"schema_version": 1, "version": "0.1.0", "api_version": 4, "label": LABEL,
                "source_revision": revision, "source_state": "clean",
                "signing": "unsigned, unnotarized", "signing_capability": signing_capability,
                "architectures": ["arm64"], "system": "Darwin", "architecture": "arm64",
                "tested_os": platform.mac_ver()[0] or platform.release(), "deployment_target": macos_target,
                "compiler": run(os.environ.get("CC", "cc"), "--version").splitlines()[0],
                "cmake": run("cmake", "--version").splitlines()[0],
                "build": "Release; C17; test hooks off; SDL3 3.4.18 static",
                "sdl3_route": route, "sdl3_version": dependency["version"],
                "sdl3_sha256": dependency["sha256"], "fixture_manifest_sha256": hashlib.sha256(
                    (share / "manifest.json").read_bytes()).hexdigest(),
                "fixtures": {"independent_game_v2": {"id": game["id"], "source_sha256": game["source_sha256"],
                              "rom_sha256": game["sha256"], "scenario_sha256": hashlib.sha256(
                                  (share / "independent-game-v2-scenario.json").read_bytes()).hexdigest(),
                              "oracle_sha256": hashlib.sha256((share / "independent-game-v2-oracle.json").read_bytes()).hexdigest()},
                             "raster_toy": {"id": "genewhip-raster-toy-v1", "source_sha256": hashlib.sha256(
                                  (share / "raster-toy.s").read_bytes()).hexdigest(), "rom_sha256": hashlib.sha256(
                                  (share / "raster-toy.bin").read_bytes()).hexdigest(),
                                  "scenario_sha256": hashlib.sha256((share / "raster-toy-scenario.json").read_bytes()).hexdigest()}},
                "input_sha256": {"independent_game_v2": hashlib.sha256((share / "independent-game-v2-demo.log").read_bytes()).hexdigest(),
                                 "raster_toy": hashlib.sha256((share / "raster-toy-demo.log").read_bytes()).hexdigest()},
                "configuration_sha256": report["configuration_sha256"],
                "binary_sha256": {name: hashlib.sha256((stage / "bin" / name).read_bytes()).hexdigest()
                                  for name in ("genewhip-desktop", "gw_headless")},
                "evidence_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                    for p in (share / "phase4-gameplay.json", share / "phase4-diagnostic.json", share / "phase4-evidence.json")},
                "limitations": "One admitted Genewhip-authored playable scenario and one sounded diagnostic; native macOS arm64 only; "
                               "unsigned/unnotarized; no hosted release or broader compatibility claim"}
    (stage / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    files = sorted(p for p in stage.rglob("*") if p.is_file())
    for path in files:
        data = path.read_bytes()
        if str(ROOT).encode() in data or str(scratch).encode() in data or PERSONAL_PATH.search(data):
            raise ValueError("private-build-path-in-artifact: " + str(path.relative_to(stage)))
    checksums = {str(p.relative_to(stage)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    (stage / "checksums.json").write_text(json.dumps(checksums, indent=2) + "\n")
    check_staged_inventory(stage)
    if identity() != revision:
        raise ValueError("source-changed-during-build")
    epoch = int(run("git", "show", "-s", "--format=%ct", revision))
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
    return pending, hashlib.sha256(pending.read_bytes()).hexdigest()


def members(path):
    with tarfile.open(path) as tar:
        result = {}
        for member in tar.getmembers():
            if member.name in result:
                raise ValueError("archive-duplicate-member")
            if member.name.startswith("/") or ".." in pathlib.PurePosixPath(member.name).parts:
                raise ValueError("archive-path")
            if not member.isfile():
                raise ValueError("archive-member-type")
            stream = tar.extractfile(member)
            if stream is None:
                raise ValueError("archive-member-unreadable")
            result[member.name] = hashlib.sha256(stream.read()).hexdigest()
        if not result:
            raise ValueError("archive-empty")
        return result


def check_staged_inventory(root):
    root = pathlib.Path(root)
    inventory_path = root / "checksums.json"
    if not inventory_path.is_file():
        raise ValueError("package-content-checksum")
    expected = json.loads(inventory_path.read_text())
    actual_paths = sorted(p for p in root.rglob("*") if p.is_file() and p != inventory_path)
    actual = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in actual_paths}
    if not isinstance(expected, dict) or expected != actual:
        raise ValueError("package-content-checksum")
    return actual


def repeatability(revision, name):
    digests, trees = [], []
    for _ in range(2):
        with tempfile.TemporaryDirectory(prefix="gw-desktop-repeat-") as tmp:
            pending, digest = build_archive(revision, pathlib.Path(tmp), name)
            digests.append(digest)
            trees.append(members(pending))
    if digests[0] == digests[1]:
        print(json.dumps({"repeatable": True, "sha256": digests[0], "source_revision": revision}))
        return
    differing = sorted(n for n in set(trees[0]) | set(trees[1]) if trees[0].get(n) != trees[1].get(n))
    print(json.dumps({"repeatable": False, "sha256": digests, "differing_members": differing}))
    raise ValueError("not-repeatable: " + ", ".join(differing))


def main():
    legacy_output = None
    legacy_source_sha = None
    if "--release-version" in sys.argv[1:]:
        parser = argparse.ArgumentParser(description="Build explicitly versioned Genewhip desktop archives")
        parser.add_argument("--release-version", required=True, choices=("0.1.0", "0.2.0"))
        parser.add_argument("--source-sha", required=True)
        parser.add_argument("--public-evidence", required=True, type=pathlib.Path)
        parser.add_argument("--output-dir", required=True, type=pathlib.Path)
        parser.add_argument("--development-only", action="store_true")
        args = parser.parse_args()
        if args.release_version == "0.2.0":
            _v02_package(args)
            return
        legacy_output, legacy_source_sha = args.output_dir, args.source_sha
    revision = identity()
    if legacy_source_sha is not None and revision != legacy_source_sha:
        raise ValueError("source-sha-not-clean-head")
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("unsupported-build-host: native macOS arm64 required")
    subprocess.run(["bash", "scripts/ci/public-hygiene.sh"], cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    name = ("genewhip-0.1.0-playable-preview-macos-arm64-"
            + revision[:12])
    if "--repeatability" in sys.argv[1:]:
        repeatability(revision, name)
        return
    output = legacy_output.resolve() if legacy_output is not None else ROOT / "artifacts"
    output.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gw-desktop-package-") as tmp:
        scratch = pathlib.Path(tmp)
        pending, digest = build_archive(revision, scratch, name)
        # No successful-looking final artifact until exact-byte smoke succeeds.
        smoke = subprocess.run([sys.executable, str(ROOT / "tests/package/desktop_smoke.py"), str(pending), digest, revision],
                               check=False, capture_output=True, text=True)
        if smoke.returncode:
            sys.stderr.write(smoke.stdout)
            sys.stderr.write(smoke.stderr)
            raise ValueError("desktop-package-smoke-failed")
        smoke_result = json.loads(smoke.stdout.strip().splitlines()[-1])
        if identity() != revision:
            raise ValueError("source-changed-during-smoke")
        archive = output / (name + ".tar.gz")
        shutil.copyfile(pending, archive)
        archive.with_suffix(archive.suffix + ".sha256").write_text(digest + "  " + archive.name + "\n")
        with tarfile.open(pending, "r:*") as tar:
            root_name = next(pathlib.PurePosixPath(row.name).parts[0] for row in tar.getmembers() if row.isfile())
            inventory_sha256 = hashlib.sha256(tar.extractfile(root_name + "/checksums.json").read()).hexdigest()
            metadata = json.loads(tar.extractfile(root_name + "/metadata.json").read())
        receipt = {"schema": "genewhip-local-package-qualification", "version": 1,
                   "kind": "native macOS arm64 desktop archive", "outcome": "pass",
                   "source_revision": revision, "archive": archive.name, "archive_sha256": digest,
                   "inventory_sha256": inventory_sha256, "api_version": metadata["api_version"],
                   "tested_os": metadata["tested_os"], "deployment_target": metadata["deployment_target"],
                   "signing": metadata["signing"], "smoke": smoke_result,
                   "publication": "not published; this is a local exact-byte qualification receipt"}
        receipt_path = output / (archive.name + ".qualification.json")
        receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
        sys.stdout.write(smoke.stdout)
        print(json.dumps({"archive": str(archive.relative_to(ROOT)), "sha256": digest,
                          "inventory_sha256": inventory_sha256, "receipt": str(receipt_path.relative_to(ROOT)),
                          "source_revision": revision}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print("REJECT: " + str(error), file=sys.stderr)
        sys.exit(1)

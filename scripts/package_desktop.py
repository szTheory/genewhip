"""Build the audio-capable diagnostic macOS desktop preview from a clean revision.

Usage: package_desktop.py [--repeatability]

The archive is smoked as exact bytes before it is copied to artifacts/. With
--repeatability the build runs twice in fresh directories and the archive digests
are compared (no smoke, no copy); differing members are listed on a mismatch.
"""
import gzip
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
LABEL = "audio-capable diagnostic desktop preview"
PERSONAL_PATH = re.compile(rb"/(?:Users|home)/[A-Za-z0-9_.-]+/|[A-Za-z]:\\Users\\")


def run(*args, **kwargs):
    return subprocess.check_output(args, cwd=ROOT, text=True, **kwargs).strip()


def identity():
    changes = run("git", "status", "--porcelain", "--untracked-files=all")
    changes = [p for p in changes.splitlines() if p[3:] != ".planning/milestone.lock"]
    if changes:
        raise ValueError("source-dirty: commit public inputs before packaging")
    return run("git", "rev-parse", "HEAD")


def toy_log(scenario):
    """The scenario's guest-independent inputs as a genewhip-input-log 1 file."""
    ticks = scenario["inputs"]["ticks_per_field"]
    lines = ["genewhip-input-log 1"] + ["%d pad %d %x" % (e["field"] * ticks, e["port"], int(e["mask"], 0))
                                       for e in scenario["inputs"]["entries"]]
    return "\n".join(lines) + "\n"


def sdl_route():
    archive = os.environ.get("GENEWHIP_SDL3_ARCHIVE", "")
    if archive:
        return ["-DGENEWHIP_SDL3_ARCHIVE=" + archive], "local archive (SHA-256 pin still enforced)"
    return [], "pinned release URL (URL_HASH enforced)"


def configure_build(src, build, extra, env):
    subprocess.run(["cmake", "-S", str(src), "-B", str(build), "-DCMAKE_BUILD_TYPE=Release", *extra],
                   check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["cmake", "--build", str(build), "--parallel", "2"], check=True, env=env,
                   stdout=subprocess.DEVNULL)


def build_archive(revision, scratch, name):
    """Return (pending archive path, sha256) for the revision, built inside scratch."""
    build, stage = scratch / "build", scratch / name
    # Apple libtool/ld otherwise embed wall-clock or build-directory identity.
    env = dict(os.environ, ZERO_AR_DATE="1")
    sdl_args, route = sdl_route()
    maps = " ".join("-ffile-prefix-map=%s=." % p for p in (build, ROOT))
    configure_build(ROOT, build, ["-DBUILD_TESTING=OFF", "-DGENEWHIP_TEST_HOOKS=OFF", "-DGENEWHIP_BUILD_DESKTOP=ON",
                                  "-DCMAKE_C_FLAGS=" + maps, *sdl_args], env)
    # The evidence report needs the hooks-on test build of the same revision.
    evidence_build = scratch / "evidence-build"
    configure_build(ROOT, evidence_build, ["-DBUILD_TESTING=ON", "-DGENEWHIP_TEST_HOOKS=ON"], env)
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
                        ("raster-toy.bin", "fixtures/raster-toy/toy.bin"),
                        ("raster-toy-NOTICES.md", "fixtures/raster-toy/NOTICES.md"),
                        ("raster-toy-demo.log", ""),
                        ("video.md", "docs/video.md"), ("input.md", "docs/input.md"),
                        ("desktop.md", "docs/desktop.md")]:
        if src:
            shutil.copy(ROOT / src, share / target)
    scenario = json.loads((ROOT / "fixtures/raster-toy/scenario.json").read_text())
    (share / "raster-toy-demo.log").write_text(toy_log(scenario))
    report_path = share / "phase3-evidence.json"
    subprocess.run([sys.executable, str(ROOT / "scripts/evidence/phase3_report.py"), "--build", str(evidence_build),
                    "--out", str(report_path)], cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    report = json.loads(report_path.read_text())
    if report["source_revision"] != revision or report["source_state"] != "clean":
        raise ValueError("evidence-source-identity")
    subprocess.run([sys.executable, str(ROOT / "scripts/evidence/phase3_report.py"),
                    "--validate", str(report_path), "--expected-revision", revision], check=True)
    metadata = {"schema_version": 1, "version": "0.1.0", "api_version": 4, "label": LABEL,
                "source_revision": revision, "source_state": "clean",
                "signing": "unsigned, unnotarized", "architectures": ["arm64"],
                "system": platform.system(), "architecture": platform.machine(),
                "os_version": platform.mac_ver()[0] or platform.release(),
                "compiler": run(os.environ.get("CC", "cc"), "--version").splitlines()[0],
                "cmake": run("cmake", "--version").splitlines()[0],
                "build": "Release; C17; test hooks off; SDL3 3.4.18 static",
                "sdl3_route": route,
                "limitations": "Original fixture PSG/FM/DAC only; no game audio compatibility or performance claim; "
                               "native macOS arm64 as executed; unsigned/unnotarized; no publication"}
    (stage / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    files = sorted(p for p in stage.rglob("*") if p.is_file())
    for path in files:
        data = path.read_bytes()
        if str(ROOT).encode() in data or str(scratch).encode() in data or PERSONAL_PATH.search(data):
            raise ValueError("private-build-path-in-artifact: " + str(path.relative_to(stage)))
    checksums = {str(p.relative_to(stage)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    (stage / "checksums.json").write_text(json.dumps(checksums, indent=2) + "\n")
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
        return {m.name: hashlib.sha256(tar.extractfile(m).read()).hexdigest() for m in tar.getmembers() if m.isfile()}


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
    revision = identity()
    subprocess.run(["bash", "scripts/ci/public-hygiene.sh"], cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    name = ("genewhip-0.1.0-desktop-audio-preview-" + platform.system().lower() + "-" + platform.machine() + "-"
            + revision[:12])
    if "--repeatability" in sys.argv[1:]:
        repeatability(revision, name)
        return
    output = ROOT / "artifacts"
    output.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gw-desktop-package-") as tmp:
        scratch = pathlib.Path(tmp)
        pending, digest = build_archive(revision, scratch, name)
        # No successful-looking final artifact until exact-byte smoke succeeds.
        subprocess.run([sys.executable, str(ROOT / "tests/package/desktop_smoke.py"), str(pending), digest, revision],
                       check=True)
        if identity() != revision:
            raise ValueError("source-changed-during-smoke")
        archive = output / (name + ".tar.gz")
        shutil.copyfile(pending, archive)
        archive.with_suffix(archive.suffix + ".sha256").write_text(digest + "  " + archive.name + "\n")
        print(json.dumps({"archive": str(archive.relative_to(ROOT)), "sha256": digest, "source_revision": revision}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print("REJECT: " + str(error), file=sys.stderr)
        sys.exit(1)

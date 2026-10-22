"""Build only clean, identified sources in a fresh directory; smoke exact bytes."""
import gzip
import hashlib
import io
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]

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

def main():
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
                        "-DBUILD_TESTING=OFF", "-DGENEWHIP_TEST_HOOKS=OFF", "-DCMAKE_C_FLAGS="], check=True)
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
        shutil.copytree(ROOT / "tests/consumer", share / "consumer")
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

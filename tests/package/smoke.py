"""Check inventory/identity before executing only the exact extracted SDK bytes."""
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
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
_ARCHIVE_SPEC = __import__("importlib.util", fromlist=["spec_from_file_location"]).spec_from_file_location(
    "genewhip_package_archive", ROOT / "scripts/package_archive.py")
_ARCHIVE = __import__("importlib.util", fromlist=["module_from_spec"]).module_from_spec(_ARCHIVE_SPEC)
_ARCHIVE_SPEC.loader.exec_module(_ARCHIVE)

MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_MEMBERS = 128
EXPECTED_FILES = {
    "bin/gw_diagnostic_runner", "bin/gw_validate_evidence", "metadata.json",
    "include/genewhip/genewhip.h", "lib/libgenewhip_core.a",
    "lib/cmake/Genewhip/GenewhipConfig.cmake", "lib/cmake/Genewhip/GenewhipConfigVersion.cmake",
    "lib/cmake/Genewhip/GenewhipTargets.cmake", "lib/cmake/Genewhip/GenewhipTargets-release.cmake",
    "share/genewhip/LICENSE", "share/genewhip/README.md", "share/genewhip/core.md", "share/genewhip/schema.json",
    "share/genewhip/THIRD-PARTY-ymfm.txt",
    "share/genewhip/input.json", "share/genewhip/manifest.json", "share/genewhip/diagnostic.bin",
    "share/genewhip/diagnostic-evidence.json", "share/genewhip/notices/THIRD-PARTY-ymfm.txt",
    "share/genewhip/SingleStepTests-LICENSE", "share/genewhip/consumer/CMakeLists.txt",
    "share/genewhip/consumer/header.cpp", "share/genewhip/consumer/install_smoke.cmake",
    "share/genewhip/consumer/main.c", "share/genewhip/consumer/negative_oracle.cmake", "checksums.json",
}


class SDKArchiveContract(unittest.TestCase):
    def test_wrong_archive_checksum_has_named_rejection(self):
        with tempfile.TemporaryDirectory(prefix="gw-sdk-checksum-") as tmp:
            archive = pathlib.Path(tmp) / "archive.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                data = b"payload"
                info = tarfile.TarInfo("root/file")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            with self.assertRaisesRegex(ValueError, "^archive-checksum$"):
                inspect_archive(archive, "0" * 64, "0" * 40)

    def test_duplicate_member_is_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory(prefix="gw-sdk-duplicate-") as tmp:
            archive = pathlib.Path(tmp) / "duplicate.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                for payload in (b"same", b"same"):
                    info = tarfile.TarInfo("genewhip-sdk/README.md")
                    info.size = len(payload)
                    tar.addfile(info, io.BytesIO(payload))
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            result = subprocess.run([sys.executable, __file__, str(archive), digest, "0" * 40],
                                     capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("REJECT: archive-duplicate-member", result.stderr)

def check_files(root):
    expected = json.loads((root / "checksums.json").read_text())
    actual = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in root.rglob("*") if p.is_file() and p.name != "checksums.json"}
    if expected != actual:
        raise ValueError("package-content-checksum")


def inspect_archive(archive, digest, revision):
    archive = pathlib.Path(archive)
    if not archive.is_file() or archive.stat().st_size == 0:
        raise ValueError("archive-empty")
    if archive.stat().st_size > MAX_ARCHIVE_BYTES or hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
        raise ValueError("archive-checksum")
    _ARCHIVE.preflight_tar_gz(archive, max_members=MAX_MEMBERS,
                              max_expanded_bytes=MAX_ARCHIVE_BYTES)
    try:
        tar = tarfile.open(archive, "r:*")
    except (OSError, tarfile.TarError) as error:
        raise ValueError("archive-malformed") from error
    with tar:
        rows = tar.getmembers()
        if not rows:
            raise ValueError("archive-empty")
        if len(rows) > MAX_MEMBERS or sum(row.size for row in rows) > MAX_ARCHIVE_BYTES:
            raise ValueError("archive-size-limit")
        by_name = {}
        for row in rows:
            path = pathlib.PurePosixPath(row.name)
            if row.name in by_name:
                raise ValueError("archive-duplicate-member")
            if path.is_absolute() or ".." in path.parts or "\\" in row.name or any(part in ("", ".") for part in path.parts):
                raise ValueError("archive-path")
            if not row.isfile():
                raise ValueError("archive-member-type")
            by_name[row.name] = row
        expected_root = "genewhip-0.1.0-sdk-diagnostic-" + platform.system().lower() + "-" + platform.machine() + "-" + revision[:12]
        roots = {pathlib.PurePosixPath(name).parts[0] for name in by_name}
        if roots != {expected_root}:
            raise ValueError("archive-root")
        prefix = expected_root + "/"
        files = {name[len(prefix):]: row for name, row in by_name.items() if name.startswith(prefix)}
        if set(files) != EXPECTED_FILES:
            raise ValueError("archive-member-set")
        inventory_row = files["checksums.json"]
        inventory = json.loads(tar.extractfile(inventory_row).read())
        payload_files = EXPECTED_FILES - {"checksums.json"}
        if not isinstance(inventory, dict) or set(inventory) != payload_files:
            raise ValueError("archive-inventory-members")
        for name in sorted(payload_files):
            stream = tar.extractfile(files[name])
            if stream is None or hashlib.sha256(stream.read()).hexdigest() != inventory[name]:
                raise ValueError("archive-inventory-digest")
        metadata = json.loads(tar.extractfile(files["metadata.json"]).read())
        if metadata.get("source_revision") != revision or metadata.get("source_state") != "clean":
            raise ValueError("package-revision")
        if metadata.get("api_version") != 4 or metadata.get("version") != "0.1.0":
            raise ValueError("package-api-version")
        if "SDL3" in metadata.get("build", "") or metadata.get("kind") != "SDK/diagnostic preview":
            raise ValueError("package-sdk-kind")
        for name in files:
            stream = tar.extractfile(files[name])
            data = stream.read() if stream else b""
            if b"/Users/" in data or b"/home/" in data:
                raise ValueError("package-private-path")
        return files, expected_root


def extract_verified(archive, files, root, destination):
    dest = destination / root
    with tarfile.open(archive, "r:*") as tar:
        for relative in sorted(files):
            row = files[relative]
            target = dest / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            stream = tar.extractfile(root + "/" + relative)
            if stream is None:
                raise ValueError("archive-member-unreadable")
            target.write_bytes(stream.read())
            target.chmod(row.mode & 0o777)
    return dest


def incompatible_api_smoke(sdk, scratch, package_version="0.1.0", network_denied=False):
    project = scratch / "api-mismatch-project"
    project.mkdir()
    source = project / "api-mismatch.c"
    source.write_text("""#include <genewhip/genewhip.h>
int main(void) {
  gw_config config = {0}; gw_machine *machine = NULL;
  config.struct_size = sizeof(config); config.version = GW_API_VERSION - 1;
  config.profile = GW_PROFILE_VA3_NTSC_U; config.reset_policy = GW_RESET_DETERMINISTIC_ZERO;
  gw_status status = gw_create(&config, &machine);
  return status != GW_OK && machine == NULL ? 0 : 1;
}
""")
    (project / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.24)\nproject(ApiMismatch C)\n"
                                           f"find_package(Genewhip {package_version} EXACT CONFIG REQUIRED)\n"
                                           "add_executable(api_mismatch api-mismatch.c)\n"
                                           "target_link_libraries(api_mismatch PRIVATE Genewhip::core)\n")
    build = scratch / "api-mismatch-build"
    env = dict(os.environ, CMAKE_DISABLE_FIND_PACKAGE_SDL3="TRUE", CMAKE_FIND_USE_PACKAGE_REGISTRY="FALSE")
    def run_check(command, timeout):
        if network_denied:
            return _network_denied(command, cwd=scratch, env=env, timeout=timeout)
        return subprocess.run(command, check=True, env=env, cwd=scratch, timeout=timeout,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    run_check(["cmake", "-S", str(project), "-B", str(build),
                    "-DCMAKE_PREFIX_PATH=" + str(sdk), "-DCMAKE_DISABLE_FIND_PACKAGE_SDL3=TRUE",
                    "-DCMAKE_FIND_USE_PACKAGE_REGISTRY=FALSE"], 120)
    run_check(["cmake", "--build", str(build), "--parallel", "2"], 180)
    run_check([str(build / "api_mismatch")], 30)


def inspect_v02_archive(archive, digest, revision, roster_path):
    """Validate the v0.2 allowlist and its rights before extraction or execution."""
    archive = pathlib.Path(archive)
    roster = json.loads(pathlib.Path(roster_path).read_text())
    entries = roster["sdk"]["members"]
    expected = {item["path"] for item in entries}
    if roster.get("schema") != "genewhip-v02-package-members-v1" or roster.get("release_version") != "0.2.0":
        raise ValueError("package-roster-version")
    for row in entries:
        rights = roster["rights"].get(row.get("rights"), {})
        if not rights.get("license") or not rights.get("source") or not rights.get("redistribution"):
            raise ValueError("package-rights-incomplete")
    if not archive.is_file() or archive.stat().st_size == 0 or archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("archive-size-limit")
    if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
        raise ValueError("archive-checksum")
    _ARCHIVE.preflight_tar_gz(archive, max_members=MAX_MEMBERS,
                              max_expanded_bytes=MAX_ARCHIVE_BYTES)
    try:
        tar = tarfile.open(archive, "r:*")
    except (OSError, tarfile.TarError) as error:
        raise ValueError("archive-malformed") from error
    with tar:
        rows = tar.getmembers()
        if not rows or len(rows) > MAX_MEMBERS or sum(row.size for row in rows) > MAX_ARCHIVE_BYTES:
            raise ValueError("archive-size-limit")
        by_name = {}
        for row in rows:
            path = pathlib.PurePosixPath(row.name)
            if row.name in by_name:
                raise ValueError("archive-duplicate-member")
            if path.is_absolute() or ".." in path.parts or "\\" in row.name or any(p in ("", ".") for p in path.parts):
                raise ValueError("archive-path")
            if not row.isfile() or row.size < 0 or row.size > MAX_ARCHIVE_BYTES:
                raise ValueError("archive-member-type")
            by_name[row.name] = row
        roots = {pathlib.PurePosixPath(name).parts[0] for name in by_name}
        expected_root = f"genewhip-0.2.0-sdk-diagnostic-{platform.system().lower()}-{platform.machine()}-{revision[:12]}"
        if roots != {expected_root}:
            raise ValueError("archive-root")
        prefix = expected_root + "/"
        files = {name[len(prefix):]: row for name, row in by_name.items() if name.startswith(prefix)}
        if set(files) != expected | {"metadata.json", "checksums.json"}:
            raise ValueError("archive-member-set")
        manifest = json.loads(tar.extractfile(files["checksums.json"]).read())
        payload = set(files) - {"checksums.json"}
        if not isinstance(manifest, dict) or set(manifest) != payload:
            raise ValueError("archive-inventory-members")
        for name in sorted(payload):
            stream = tar.extractfile(files[name])
            data = stream.read() if stream else b""
            if hashlib.sha256(data).hexdigest() != manifest[name]:
                raise ValueError("archive-inventory-digest")
            personal_path = re.compile(rb"/(?:Users|home)/[A-Za-z0-9_.-]+/(?:projects|Desktop|Documents|Downloads|Library)/")
            if personal_path.search(data) or str(pathlib.Path.home().resolve()).encode() in data:
                raise ValueError("package-private-path")
        metadata = json.loads(tar.extractfile(files["metadata.json"]).read())
        if metadata.get("release_version") != "0.2.0" or metadata.get("source_revision") != revision:
            raise ValueError("package-source-identity")
        if metadata.get("api_version") != 4 or metadata.get("input_log_version") != 1:
            raise ValueError("package-contract-version")
        if metadata.get("source_state") not in {"development-only", "clean"}:
            raise ValueError("package-source-state")
        required = expected - {"metadata.json", "checksums.json"}
        if metadata.get("required_members") != sorted(required):
            raise ValueError("package-required-member-identity")
        trusted_rights = {row["path"]: row["rights"] for row in roster["sdk"]["members"]
                          if row["path"] not in ("metadata.json", "checksums.json")}
        if metadata.get("member_rights") != trusted_rights:
            raise ValueError("package-member-rights")
        for row in roster["sdk"]["members"]:
            rights_record = roster["rights"][row["rights"]]
            notice = rights_record.get("notice_members", {}).get("sdk", rights_record.get("notice_member"))
            if notice not in expected:
                raise ValueError("package-required-notice-missing")
            notice_row = next((item for item in roster["sdk"]["members"] if item["path"] == notice), None)
            if not notice_row or not notice_row.get("source"):
                raise ValueError("package-notice-source-missing")
            trusted_notice = (ROOT / notice_row["source"]).read_bytes()
            if tar.extractfile(files[notice]).read() != trusted_notice:
                raise ValueError("package-notice-content-identity")
        if any(path.startswith("SDL") or "fixtures/phase5" in path or path.endswith(".bin") and "diagnostic" not in path
               for path in expected):
            raise ValueError("sdk-game-corpus-or-sdl")
        closure = json.loads(tar.extractfile(files["share/genewhip/evidence/manifest.json"]).read())
        if metadata.get("public_evidence_digest") != closure.get("closure_id"):
            raise ValueError("package-public-evidence-identity")
        performance_data = tar.extractfile(files["share/genewhip/evidence/performance.json"]).read()
        if metadata.get("performance_evidence_digest") != hashlib.sha256(performance_data).hexdigest():
            raise ValueError("package-performance-evidence-identity")
        return files, expected_root, metadata


def _offline_env(scratch):
    home = scratch / "fresh-home"
    cache = scratch / "empty-cache"
    home.mkdir(exist_ok=True)
    cache.mkdir(exist_ok=True)
    return dict(os.environ, HOME=str(home), XDG_CACHE_HOME=str(cache),
                CMAKE_DISABLE_FIND_PACKAGE_SDL3="TRUE", CMAKE_FIND_USE_PACKAGE_REGISTRY="FALSE",
                CMAKE_USER_PACKAGE_REGISTRY="", CMAKE_PACKAGE_REGISTRY="")


def _network_denied(command, *, cwd, env, timeout=600):
    sandbox = shutil.which("sandbox-exec")
    if platform.system() != "Darwin" or not sandbox:
        raise ValueError("required-network-denial-capability-unavailable")
    return subprocess.run([sandbox, "-p", "(version 1)(allow default)(deny network*)", *map(str, command)],
                          cwd=cwd, env=env, check=True, timeout=timeout)


def smoke_v02(archive, digest, revision, roster_path):
    files, root, metadata = inspect_v02_archive(archive, digest, revision, roster_path)
    with tempfile.TemporaryDirectory(prefix="gw-sdk-v02-smoke-") as directory:
        scratch = pathlib.Path(directory)
        sdk = scratch / root
        with tarfile.open(archive, "r:*") as tar:
            for name, row in files.items():
                target = sdk / name
                target.parent.mkdir(parents=True, exist_ok=True)
                source = tar.extractfile(row)
                if source is None:
                    raise ValueError("archive-member-unreadable")
                target.write_bytes(source.read())
                target.chmod(row.mode & 0o777)
        check_files(sdk)
        moved = scratch / "relocated-sdk"
        sdk.rename(moved)
        env = _offline_env(scratch)
        _network_denied([str(moved / "bin/gw_diagnostic_runner"), str(moved / "share/genewhip/diagnostic.bin")],
                        cwd=scratch, env=env, timeout=30)
        _network_denied([str(moved / "bin/gw_validate_evidence"), str(moved / "share/genewhip/diagnostic-evidence.json")],
                        cwd=scratch, env=env, timeout=30)
        _network_denied(["cmake", "-S", str(moved / "share/genewhip/consumer"), "-B", str(scratch / "consumer-build"),
                         "-DCMAKE_PREFIX_PATH=" + str(moved), "-DGW_HOOKS=OFF",
                         "-DGW_ROM=" + str(moved / "share/genewhip/diagnostic.bin"),
                         "-DCMAKE_DISABLE_FIND_PACKAGE_SDL3=TRUE", "-DCMAKE_FIND_USE_PACKAGE_REGISTRY=FALSE"],
                        cwd=scratch, env=env, timeout=120)
        _network_denied(["cmake", "--build", str(scratch / "consumer-build"), "--parallel", "2"],
                        cwd=scratch, env=env, timeout=180)
        _network_denied(["ctest", "--test-dir", str(scratch / "consumer-build"), "--output-on-failure"],
                        cwd=scratch, env=env, timeout=120)
        incompatible_api_smoke(moved, scratch, "0.2.0", network_denied=True)
        return {"schema": "genewhip-sdk-package-smoke", "version": 2, "outcome": "pass",
                "source_revision": revision, "source_state": metadata["source_state"],
                "relocated": True, "inventory": "exact", "c_consumer": "pass", "cpp_header": "pass",
                "diagnostic": "pass", "offline": True, "network_denial": "sandbox-exec-deny-network",
                "cache": "fresh-empty-home", "package_digest": digest}

def main():
    if sys.argv[1:] == ["--contract"]:
        unittest.main(argv=[sys.argv[0]])
        return
    if len(sys.argv) == 6 and sys.argv[1] == "--v02":
        result = smoke_v02(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
        print(json.dumps(result, sort_keys=True))
        return
    archive, digest, revision = sys.argv[1:]
    files, root = inspect_archive(archive, digest, revision)
    with tempfile.TemporaryDirectory(prefix="gw-sdk-smoke-") as tmp:
        scratch = pathlib.Path(tmp)
        sdk = extract_verified(archive, files, root, scratch)
        check_files(sdk)
        metadata = json.loads((sdk / "metadata.json").read_text())
        if metadata["source_revision"] != revision or metadata["source_state"] != "clean":
            raise ValueError("package-revision")
        if metadata.get("api_version") != 4:
            raise ValueError("package-api-version")
        share = sdk / "share/genewhip"
        for name in ["LICENSE", "SingleStepTests-LICENSE", "THIRD-PARTY-ymfm.txt", "README.md", "core.md", "diagnostic-evidence.json"]:
            if not (share / name).is_file():
                raise ValueError("package-notice-or-evidence")
        source_notice = pathlib.Path(__file__).resolve().parents[2] / "packaging/notices/THIRD-PARTY-ymfm.txt"
        if (share / "THIRD-PARTY-ymfm.txt").read_bytes() != source_notice.read_bytes():
            raise ValueError("package-ymfm-notice-drift")
        # Named mutation must be detected before any client execution.
        license_path = share / "LICENSE"
        original = license_path.read_bytes()
        license_path.write_bytes(original + b"tampered")
        try:
            check_files(sdk)
        except ValueError as error:
            if str(error) != "package-content-checksum":
                raise
        else:
            raise ValueError("negative-control-not-detected")
        license_path.write_bytes(original)
        check_files(sdk)
        # Move the prefix again: exported targets cannot rely on extraction path.
        moved = scratch / "relocated"
        sdk.rename(moved)
        share = moved / "share/genewhip"
        report = subprocess.check_output([str(moved / "bin/gw_diagnostic_runner"), str(share / "diagnostic.bin")])
        if json.loads(report) != json.loads((share / "diagnostic-evidence.json").read_bytes()):
            raise ValueError("diagnostic-report-drift")
        subprocess.run([str(moved / "bin/gw_validate_evidence"), str(share / "diagnostic-evidence.json")], check=True)
        env = dict(os.environ, CMAKE_DISABLE_FIND_PACKAGE_SDL3="TRUE", CMAKE_FIND_USE_PACKAGE_REGISTRY="FALSE")
        subprocess.run(["cmake", "-S", str(share / "consumer"), "-B", str(scratch / "consumer-build"),
                        "-DCMAKE_PREFIX_PATH=" + str(moved), "-DGW_HOOKS=OFF", "-DGW_ROM=" + str(share / "diagnostic.bin"),
                        "-DCMAKE_DISABLE_FIND_PACKAGE_SDL3=TRUE", "-DCMAKE_FIND_USE_PACKAGE_REGISTRY=FALSE"], check=True, env=env)
        subprocess.run(["cmake", "--build", str(scratch / "consumer-build")], check=True, env=env)
        subprocess.run(["ctest", "--test-dir", str(scratch / "consumer-build"), "--output-on-failure"], check=True, env=env)
        incompatible_api_smoke(moved, scratch)
        print(json.dumps({"schema": "genewhip-sdk-package-smoke", "version": 1, "outcome": "pass",
                          "relocated": True, "inventory": "exact", "c_consumer": "pass", "cpp_header": "pass",
                          "offline": True, "incompatible_api": "rejected"}))

if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired,
            tarfile.TarError, json.JSONDecodeError) as error:
        print("REJECT: " + str(error), file=sys.stderr)
        sys.exit(1)

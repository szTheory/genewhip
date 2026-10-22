"""Check inventory/identity before executing only the exact extracted SDK bytes."""
import hashlib
import io
import json
import os
import pathlib
import platform
import subprocess
import sys
import tarfile
import tempfile
import unittest

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


def incompatible_api_smoke(sdk, scratch):
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
                                           "find_package(Genewhip 0.1.0 EXACT CONFIG REQUIRED)\n"
                                           "add_executable(api_mismatch api-mismatch.c)\n"
                                           "target_link_libraries(api_mismatch PRIVATE Genewhip::core)\n")
    build = scratch / "api-mismatch-build"
    env = dict(os.environ, CMAKE_DISABLE_FIND_PACKAGE_SDL3="TRUE", CMAKE_FIND_USE_PACKAGE_REGISTRY="FALSE")
    subprocess.run(["cmake", "-S", str(project), "-B", str(build),
                    "-DCMAKE_PREFIX_PATH=" + str(sdk), "-DCMAKE_DISABLE_FIND_PACKAGE_SDL3=TRUE",
                    "-DCMAKE_FIND_USE_PACKAGE_REGISTRY=FALSE"], check=True, env=env,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    subprocess.run(["cmake", "--build", str(build), "--parallel", "2"], check=True, env=env,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    subprocess.run([str(build / "api_mismatch")], check=True, env=env, timeout=30)

def main():
    if sys.argv[1:] == ["--contract"]:
        unittest.main(argv=[sys.argv[0]])
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

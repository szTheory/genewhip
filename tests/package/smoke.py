"""Check inventory/identity before executing only the exact extracted SDK bytes."""
import hashlib
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile

def check_files(root):
    expected = json.loads((root / "checksums.json").read_text())
    actual = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in root.rglob("*") if p.is_file() and p.name != "checksums.json"}
    if expected != actual:
        raise ValueError("package-content-checksum")

def main():
    archive, digest, revision = sys.argv[1:]
    if hashlib.sha256(pathlib.Path(archive).read_bytes()).hexdigest() != digest:
        raise ValueError("archive-checksum")
    with tempfile.TemporaryDirectory(prefix="gw-sdk-smoke-") as tmp:
        scratch = pathlib.Path(tmp)
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                path = pathlib.PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or not member.isfile():
                    raise ValueError("archive-member")
            tar.extractall(scratch)
        roots = list(scratch.iterdir())
        if len(roots) != 1 or not roots[0].is_dir():
            raise ValueError("archive-root")
        sdk = roots[0]
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
        subprocess.run(["cmake", "-S", str(share / "consumer"), "-B", str(scratch / "consumer-build"),
                        "-DCMAKE_PREFIX_PATH=" + str(moved), "-DGW_HOOKS=OFF", "-DGW_ROM=" + str(share / "diagnostic.bin")], check=True)
        subprocess.run(["cmake", "--build", str(scratch / "consumer-build")], check=True)
        subprocess.run(["ctest", "--test-dir", str(scratch / "consumer-build"), "--output-on-failure"], check=True)
        print("package smoke: PASS; archive checksum, inventory, tamper rejection, relocated runner and C/C++ consumer")

if __name__ == "__main__":
    main()

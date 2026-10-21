"""Fresh builds must reject reports from different effective target settings."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(sys.argv[1]).resolve()
cmake = sys.argv[2]

def run(*args):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout

with tempfile.TemporaryDirectory(prefix="gw-configuration-") as temporary:
    scratch = Path(temporary)
    toolchain = scratch / "target-options.cmake"
    toolchain.write_text('add_compile_options(-DGW_CONFIGURATION_CONTROL=1)\n'
                        'add_link_options(-g)\n')
    variants = {
        "baseline": [],
        "relocated": [],
        "ipo": ["-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON"],
        "ipo-release": ["-DCMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE=ON"],
        "pic": ["-DCMAKE_POSITION_INDEPENDENT_CODE=ON"],
        "driver": ["-DCMAKE_C_COMPILER_ARG1=-DGW_DRIVER_CONTROL=1"],
        "toolchain": [f"-DCMAKE_TOOLCHAIN_FILE={toolchain}"],
    }
    identities = {}
    for name, options in variants.items():
        build = scratch / name
        run(cmake, "-G", "Unix Makefiles", "-S", root, "-B", build,
            "-DBUILD_TESTING=OFF", "-DGENEWHIP_TEST_HOOKS=OFF", "-DCMAKE_BUILD_TYPE=Release",
            "-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF", *options)
        run(cmake, "--build", build, "--parallel", "2")
        report = run(build / "gw_diagnostic_runner", build / "diagnostic.bin")
        parsed = json.loads(report)
        identities[name] = parsed["configuration"]
        path = build / "report.json"
        path.write_text(report)
        assert "ACCEPT: ok" in run(build / "gw_validate_evidence", path, "--inspect")
        if parsed["source_state"] == "clean":
            assert "ACCEPT: ok" in run(build / "gw_validate_evidence", path)
        if name in ("baseline", "relocated"):
            continue
        assert identities[name] != identities["baseline"], f"{name}: configuration collision"
        for producer, validator in (("baseline", name), (name, "baseline")):
            rejected = subprocess.run(
                [str(scratch / validator / "gw_validate_evidence"),
                 str(scratch / producer / "report.json"), "--inspect"],
                capture_output=True, text=True, timeout=10)
            assert rejected.returncode == 1 and "REJECT: configuration " in rejected.stdout, (
                name, rejected.stdout, rejected.stderr)
    assert identities["baseline"] == identities["relocated"], "build path must not alter identity"
    assert identities["ipo"] == identities["ipo-release"], "equivalent effective IPO settings"
    rejected = subprocess.run([cmake, "-G", "Unix Makefiles", "-S", str(root),
                               "-B", str(scratch / "multi"), "-DCMAKE_CONFIGURATION_TYPES=Debug;Release"],
                              capture_output=True, text=True, timeout=30)
    assert rejected.returncode != 0 and "require single-config" in rejected.stderr, rejected.stderr
    rejected = subprocess.run([cmake, "-G", "Unix Makefiles", "-S", str(root),
                               "-B", str(scratch / "launcher"), "-DCMAKE_C_COMPILER_LAUNCHER=echo"],
                              capture_output=True, text=True, timeout=30)
    assert rejected.returncode != 0 and "does not support command launchers" in rejected.stderr, rejected.stderr
print("PASS: relocated identity; IPO/per-config/PIC/driver/toolchain cross-report rejection; multi-config rejection")

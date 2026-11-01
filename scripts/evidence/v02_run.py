#!/usr/bin/env python3
"""Bounded v0.2 control tracer and source-identity freezer."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import re
import sys
import tempfile
import shutil
import subprocess
import datetime
import time
from subprocess import CompletedProcess

ROOT = pathlib.Path(__file__).resolve().parents[2]
FACTS_POLICY_PATH = ROOT / "scripts/evidence/v02_safety_build_facts.py"
SCENARIO = ROOT / "fixtures/independent-game-v2/scenario.json"
ORACLE = ROOT / "fixtures/independent-game-v2/oracle.json"
ROM = ROOT / "fixtures/independent-game-v2/game.bin"
SOURCE = ROOT / "fixtures/independent-game-v2/src/game.s"
SCENARIO_SHA = "c702dd10287a9363405fd9269e05989954eb447d0973246bb59a10f74920dbb2"
ORACLE_SHA = "1a9d99cb01496f26fe3dc33d0c1bcb0cf22bd9178088fa183e5bba37a8600f42"
SOURCE_SHA = "b74cd12ec371767e8fb338feca808e59e63f569eb93298bb2470d20f8e4e9cfe"
ROM_SHA = "7bdffe43fc1b6e4ac623e16298e3bd0a775de6cb4db2758695dbef0e200f4adb"


def sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _format_chunk_inputs(inputs: list[dict]) -> bytes:
    """Serialize chunk input rows in the newline-terminated parser format."""
    return "".join(f"{event['machine_tick']},{event['port']},{event['effective']}\n"
                   for event in inputs).encode("utf-8")


def configuration_sha(path: pathlib.Path) -> str:
    lines = []
    for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
        if line.startswith(("CMAKE_BUILD_TYPE:", "CMAKE_C_COMPILER:", "CMAKE_C_FLAGS:",
                "GENEWHIP_", "SDL3_", "SDL_")):
            lines.append(line)
    return hashlib.sha256(("\n".join(sorted(lines)) + "\n").encode()).hexdigest()


def workflow_base_sha(head: str) -> str:
    value = os.environ.get("GITHUB_BASE_SHA")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not value and event_path:
        try:
            event = json.loads(pathlib.Path(event_path).read_text(encoding="utf-8"))
            value = event.get("before") or event.get("pull_request", {}).get("base", {}).get("sha")
        except (OSError, ValueError, TypeError):
            value = None
    return value or head


def available_memory_bytes() -> int | None:
    if sys.platform == "darwin":
        try:
            result = subprocess.run(["/usr/bin/vm_stat"], text=True, capture_output=True,
                                    timeout=5, check=True)
            values = {name: int(count.replace(".", "")) for name, count in
                      re.findall(r"^Pages ([a-z]+):\s+([0-9.]+)", result.stdout, re.MULTILINE)}
            reclaimable = sum(values.get(name, 0) for name in ("free", "inactive", "speculative", "purgeable"))
            return reclaimable * os.sysconf("SC_PAGE_SIZE")
        except (OSError, subprocess.SubprocessError, ValueError):
            return None
    if sys.platform.startswith("linux"):
        try:
            for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
            return None
        except (OSError, ValueError, IndexError):
            return None
    return None


def require_memory_reserve(available: int | None, required: int) -> int:
    if available is None:
        raise ValueError("phase7-memory-reserve-unobservable")
    if available < required:
        raise ValueError("phase7-memory-reserve-insufficient")
    return available


def freeze_identity(build: pathlib.Path) -> dict:
    cache = build / "CMakeCache.txt"
    client = build / "tools/session/gw_headless"
    if not cache.is_file() or not client.is_file():
        raise ValueError("identified-build-or-headless-client-missing")
    identities = {"scenario_sha256": sha(SCENARIO), "oracle_sha256": sha(ORACLE),
                  "rom_sha256": sha(ROM), "source_sha256": sha(SOURCE),
                  "cmake_cache_sha256": sha(cache), "executable_sha256": sha(client)}
    if (identities["scenario_sha256"] != SCENARIO_SHA or identities["oracle_sha256"] != ORACLE_SHA or
            identities["rom_sha256"] != ROM_SHA or identities["source_sha256"] != SOURCE_SHA):
        raise ValueError("phase7-fixture-identity-drift")
    return identities


def _module(path: pathlib.Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("phase7-contract-module-unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def resolve_owned_output_roots(scope: dict) -> tuple[pathlib.Path, ...]:
    """Validate repository-contained output roots, including roots not created yet."""
    roots = scope.get("owned_roots")
    if not isinstance(roots, list) or not roots:
        raise ValueError("phase7-owned-output-roots-missing")
    repo = ROOT.resolve()
    resolved_roots = []
    for item in roots:
        if (not isinstance(item, str) or not item or "\\" in item):
            raise ValueError("phase7-owned-output-root-invalid")
        relative = pathlib.PurePosixPath(item)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise ValueError("phase7-owned-output-root-invalid")
        candidate = repo
        for part in relative.parts:
            candidate = candidate / part
            if candidate.is_symlink() or (candidate.exists() and not candidate.is_dir()):
                raise ValueError("phase7-owned-output-root-invalid")
        resolved = candidate.resolve()
        if not resolved.is_relative_to(repo):
            raise ValueError("phase7-owned-output-root-invalid")
        resolved_roots.append(resolved)
    return tuple(resolved_roots)


def validate_execution_scope(scope_path: pathlib.Path, mode: str) -> tuple[dict, dict]:
    """Load finite Phase 7 limits and bind this invocation to current source/build bytes."""
    path = scope_path.resolve(strict=True)
    scope = json.loads(path.read_text(encoding="utf-8"))
    if scope.get("schema") != "genewhip-v02-execution-v1" or scope.get("scope_id") != "phase7-serial-child-workloads":
        raise ValueError("phase7-execution-scope-invalid")
    limits = scope.get("per_child_limits")
    required = {"wall_seconds", "cleanup_grace_seconds", "max_rss_bytes", "max_stdout_stderr_bytes",
        "max_json_bytes", "max_binary_file_bytes", "max_capture_bytes", "max_scratch_bytes",
        "max_retained_bytes", "max_fields", "max_calls"}
    if not isinstance(limits, dict) or not required <= limits.keys() or any(
            type(limits[key]) is not int or limits[key] <= 0 for key in required):
        raise ValueError("phase7-per-child-limits-invalid")
    if scope.get("cleanup_grace_seconds") != limits["cleanup_grace_seconds"]:
        raise ValueError("phase7-cleanup-grace-mismatch")
    if scope.get("workload", {}).get("serial_children") is not True:
        raise ValueError("phase7-child-serialization-required")
    if (type(scope.get("per_batch_wall_seconds")) is not int or scope["per_batch_wall_seconds"] <= 0 or
            type(scope.get("final_reserve_seconds")) is not int or scope["final_reserve_seconds"] <= 0 or
            scope["per_batch_wall_seconds"] + scope["final_reserve_seconds"] > scope.get("qualification_batch",{}).get("wall_seconds",0)):
        raise ValueError("phase7-batch-reserve-invalid")
    batch = scope["qualification_batch"]
    if (batch.get("runtime_wall_seconds") != 64800 or batch.get("package_wall_seconds") != 14400 or
            batch.get("close_wall_seconds") != 7200 or
            sum(batch[key] for key in ("runtime_wall_seconds", "package_wall_seconds", "close_wall_seconds")) != batch["wall_seconds"]):
        raise ValueError("phase7-common-cutoff-partition-invalid")
    resolve_owned_output_roots(scope)
    if not isinstance(scope.get("launch_identities"),dict) or not isinstance(scope.get("observed_exposure"),dict):
        raise ValueError("phase7-execution-facts-missing")
    if mode not in ("smoke", "full", "safety", "chunk"):
        raise ValueError("phase7-mode-not-owned:" + mode)
    return scope, limits


def source_identity(module) -> dict:
    """Hash exact core, fixture, route compiler, host collector, and delivery-map inputs."""
    names = {"CMakeLists.txt", "tools/session/CMakeLists.txt", "tests/fixtures/phase4_game.py",
        "tests/desktop/phase4_sessions.py", "tests/session/phase6_controller_contract.py",
        "tests/fixtures/phase6_game.py", "tests/session/phase6_route_contract.py",
        "tests/desktop/phase6_routes.py", "scripts/evidence/phase6_routes.py",
        "scripts/evidence/v02_matrix.py", "scripts/release/v02_qualification.py",
        "evidence/v02-roster.json", "evidence/v02-schema.json",
        "scripts/evidence/v02_run.py", "tests/evidence/v02_execution_contract.py",
        "tools/session/route_controller.c", "tools/session/session.c",
        "fixtures/phase6/recursion94-consumed-map-v1.json"}
    for directory in ("src", "include", "tools/session", "tools/headless"):
        for path in (ROOT/directory).rglob("*"):
            if path.is_file() and path.suffix in (".c", ".h", ".inc"):
                names.add(str(path.relative_to(ROOT)))
    for title in ("recursion94", "tank-battle", "genewhip-independent-game-v2"):
        names.update(module.SOURCES[title][:4])
    digests = {name:sha(ROOT/name) for name in sorted(names) if (ROOT/name).is_file()}
    canonical = json.dumps(digests,sort_keys=True,separators=(",",":")).encode()
    return {"source_sha256":hashlib.sha256(canonical).hexdigest(),"source_files":digests,
        "controller_sha256":sha(ROOT/"tools/session/route_controller.c"),
        "route_compiler_sha256":sha(ROOT/"scripts/evidence/phase6_routes.py"),
        "fixture_harness_sha256":sha(ROOT/"tests/fixtures/phase6_game.py"),
        "delivery_map_sha256":sha(ROOT/"fixtures/phase6/recursion94-consumed-map-v1.json")}


def current_git_head() -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
        capture_output=True, check=True).stdout.strip()


def retain_safety_build_evidence(build: pathlib.Path, runtime: pathlib.Path, report_path: pathlib.Path,
                                current_identity: dict) -> dict:
    """Retain exact build hashes and portable facts without exporting pathful caches/binaries."""
    report = json.loads(report_path.read_text(encoding="utf-8"))
    target = runtime / "safety-build-evidence"
    if target.exists() or target.is_symlink():
        raise ValueError("phase7-safety-evidence-output-collision")
    facts_dir = target
    facts_dir.mkdir()
    entries = []
    total = 0
    compiler_identity = None
    for variant in ("native", "sanitize", "hooks-off"):
        row = next((item for item in report.get("variants", []) if item.get("variant") == variant), None)
        if not isinstance(row, dict):
            raise ValueError("phase7-safety-evidence-variant-missing:" + variant)
        build_root = ROOT / row.get("build_directory", "")
        expected_root = (build if variant == "native" else ROOT / "build/v02/runtime/safety" /
            ("asan-ubsan" if variant == "sanitize" else "hooks-off"))
        if build_root.resolve() != expected_root.resolve():
            raise ValueError("phase7-safety-evidence-build-directory-invalid:" + variant)
        identity = row.get("build_identity", {})
        sources = {str((build_root / "CMakeCache.txt").relative_to(ROOT)): identity.get("cache_sha256"),
            str((build_root / "phase6_safety").relative_to(ROOT)): identity.get("phase6_safety_sha256")}
        binaries = identity.get("test_executables", {})
        if not isinstance(binaries, dict) or not binaries:
            raise ValueError("phase7-safety-evidence-binaries-missing:" + variant)
        sources.update(binaries)
        fact_entries = []
        for source_path, digest in sorted(sources.items()):
            source = ROOT / source_path
            if (not source.is_relative_to(build_root) or source.is_symlink() or not source.is_file() or
                    source.stat().st_size > 64 * 1024 * 1024 or sha(source) != digest):
                raise ValueError("phase7-safety-evidence-source-invalid:" + variant)
            total += source.stat().st_size
            if total > 256 * 1024 * 1024:
                raise ValueError("phase7-safety-evidence-byte-cap")
            fact_entries.append({"source_path": source_path, "sha256": digest, "size": source.stat().st_size})
        facts_spec = importlib.util.spec_from_file_location("gw_v02_safety_build_facts",
            FACTS_POLICY_PATH)
        facts_module = importlib.util.module_from_spec(facts_spec)
        facts_spec.loader.exec_module(facts_module)
        cache = facts_module.project_cache(build_root / "CMakeCache.txt")
        fact_problem = facts_module.validate_facts(variant, cache, sources)
        observed_compiler = (cache.get("CMAKE_C_COMPILER_ID"), cache.get("CMAKE_C_COMPILER_VERSION"))
        if fact_problem or (compiler_identity is not None and observed_compiler != compiler_identity):
            raise ValueError("phase7-safety-build-configuration-invalid:" + variant + ":" + str(fact_problem or "compiler-mismatch"))
        compiler_identity = observed_compiler
        fact = {"schema": "genewhip.v02-portable-build-facts.v1", "variant": variant,
            "build_facts": cache, "raw_build_artifact_identities": fact_entries,
            "raw_build_artifact_bytes_transferred": False,
            "evidence_basis": "producer-observed-source-identities-plus-portable-facts",
            "raw_build_artifact_digest_policy": "producer-observed source-byte SHA-256 and size; original bytes omitted and not independently reopened"}
        fact_path = facts_dir / (variant + ".json")
        fact_path.write_text(json.dumps(fact, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        fact_digest = sha(fact_path)
        for entry in fact_entries:
            entries.append({"source_path": entry["source_path"], "source_sha256": entry["sha256"],
                "source_size": entry["size"], "variant": variant,
                "path": fact_path.relative_to(ROOT).as_posix(), "sha256": fact_digest,
                "size": fact_path.stat().st_size})
    portable_total = sum((facts_dir / (variant + ".json")).stat().st_size
        for variant in ("native", "sanitize", "hooks-off"))
    manifest = {"schema": "genewhip.v02-safety-build-evidence.v2", "identity": current_identity,
        "entries": entries, "entry_count": len(entries), "source_bytes_total": total,
        "portable_fact_bytes_total": portable_total,
        "raw_build_artifact_bytes_transferred": False,
        "evidence_basis": "producer-observed-source-identities-plus-portable-facts",
        "portable_facts": "build/v02/runtime-observation/safety-build-evidence/"}
    manifest_path = runtime / "safety-build-evidence.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    report["build_evidence"] = {"path": manifest_path.relative_to(ROOT).as_posix(), "sha256": sha(manifest_path)}
    report_path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return {"path": manifest_path.relative_to(ROOT).as_posix(), "sha256": sha(manifest_path)}


def plan_mode(mode: str, build: pathlib.Path, scope_path: pathlib.Path, out: pathlib.Path) -> dict:
    """Resolve exact finite mode rosters and argv without launching children."""
    scope, limits = validate_execution_scope(scope_path, mode)
    build = build.resolve(strict=True)
    out = out.resolve()
    output_roots=resolve_owned_output_roots(scope)
    if not any(out.is_relative_to(root) for root in output_roots):
        raise ValueError("phase7-output-outside-owned-roots")
    headless, desktop = build / "tools/session/gw_headless", build / "tools/desktop/genewhip-desktop"
    if not (build / "CMakeCache.txt").is_file() or not headless.is_file():
        raise ValueError("identified-build-or-headless-client-missing")
    module = _module(ROOT / "scripts/evidence/phase6_routes.py", "gw_v02_plan_routes")
    mapping = json.loads((ROOT / "fixtures/phase6/recursion94-consumed-map-v1.json").read_text())
    routes = module.compile_routes(mapping, "sdl")["routes"]
    titles = {name: pathlib.Path(module.SOURCES[name][3]) for name in
              ("recursion94", "tank-battle", "genewhip-independent-game-v2")}
    routes = module.compile_routes(mapping, "public-core")["routes"]
    artifact_root = out.parent / out.stem
    source = source_identity(module)
    git_head = current_git_head()
    candidate_path = artifact_root / "candidate.json"
    candidate_sha = None
    if mode == "full":
        fixture = _module(ROOT / "tests/fixtures/phase6_game.py", "gw_v02_plan_fixture")
        candidate = fixture.freeze_candidate(build, ROOT / "fixtures/phase6/recursion94-consumed-map-v1.json", candidate_path)
        candidate_sha = fixture.canonical_sha(candidate)
    all_names = ("load_contract", "time_contract", "reset_contract", "bus_boundary_contract",
        "gameplay_bus_contract", "movem_contract", "phase6_repairs_contract", "session_contract",
        "input_log_contract", "phase6_chunk_contract", "phase6_safety", "phase6_delivery_map_contract")
    commands: list[dict] = []
    workloads: dict = {}
    expected_children = 0
    if mode == "smoke":
        selected = [(title, next(row for row in routes if row["fixture"] == title and row["case"]["id"] == "full-route"))
                    for title in ("recursion94", "tank-battle")]
        for title, route in selected:
            binary, _ = module.lower_route(route, 100_000_000 if title == "recursion94" else 10_000_000,
                mapping if title == "recursion94" else None)
            root = artifact_root / title
            plan_path, core_report = root / "controller.gwrc", root / "core.json"
            commands.append({"kind":"core", "title":title, "case":"full-route", "argv":[str(headless),
                "--route-plan",str(plan_path),"--route-report",str(core_report),str((ROOT/titles[title]).resolve())],
                "plan_sha256":hashlib.sha256(binary).hexdigest(),"output":str(core_report)})
            commands.append({"kind":"software-sdl", "title":title, "case":"full-route", "argv":[str(desktop),
                "--route-plan",str(plan_path),"--route-report",str(root/"host-native.json"),
                "--route-input-source","virtual-gamepad","--route-diagnostic",str(root/"host.json"),
                str((ROOT/titles[title]).resolve())], "output":str(root/"host.json")})
        expected_children = 4
        workloads = {"core_title_smokes":2,"software_sdl_title_smokes":2,"synthetic_controls":1}
    elif mode == "full":
        title_rows = [row for row in routes if row["fixture"] in ("recursion94","tank-battle")]
        control_rows = [row for row in routes if row["fixture"] == "genewhip-independent-game-v2"]
        for repetition in (1,2):
            for row in (*title_rows,*control_rows):
                title=row["fixture"]; rec=title=="recursion94"
                binary,_=module.lower_route(row,100_000_000 if rec else (10_000_000 if title=="tank-battle" else 1_000_000),mapping if rec else None)
                root=artifact_root/"core"/f"{title}-{row['case']['id']}-r{repetition}"
                plan_path,report=root/"route.gwrc",root/"native.json"
                commands.append({"kind":"core-route","title":title,"case":row["case"]["id"],"repetition":repetition,
                    "argv":[str(headless),"--route-plan",str(plan_path),"--route-report",str(report),
                        "--audio-rate","48000","--dump-audio",str(root/"audio.pcm"),
                        "--dump-audio-trace",str(root/"audio-trace.jsonl"),"--dump-fields",str(root/"fields"),
                        "--capture-identity",candidate_sha,str((ROOT/titles[title]).resolve())],
                    "plan_sha256":hashlib.sha256(binary).hexdigest(),"output":str(report)})
        for backend in ("software","native"):
            commands.append({"kind":"host-title-roster","backend":backend,"title_cases":[
                {"title":row["fixture"],"case":row["case"]["id"]} for row in title_rows],
                "argv":[sys.executable,"-I",str(ROOT/"tests/desktop/phase6_routes.py"),"--mode",backend,
                    "--build",str(build),"--core",str(artifact_root/"core-report.json"),
                    "--delivery-map",str(ROOT/"fixtures/phase6/recursion94-consumed-map-v1.json"),
                    "--output",str(artifact_root/f"host-{backend}.json"),"--execution-scope",str(scope_path.resolve())]})
            commands[-1]["original_control_roster"]="original-six-controls"
        safety_variants=(("native",build),("asan-ubsan",ROOT/"build/phase6-sanitize"),("hooks-off",ROOT/"build/phase6-hooks-off"))
        for label,directory in safety_variants:
            commands.append({"kind":"ctest-discovery","variant":label,
                "argv":["ctest","--test-dir",str(directory),"--show-only=json-v1"],"expected_names":list(all_names)})
            for name in all_names:
                commands.append({"kind":"safety-test","variant":label,"test":name,
                    "argv":["ctest","--test-dir",str(directory),"--no-tests=error","--output-on-failure","-R",f"^{name}$"]})
            commands.append({"kind":"malformed-load","variant":label,"cases":4096,
                "argv":[str(directory/"gw_bounded_fuzz")],"exit_cap_seconds":90})
            commands.append({"kind":"safety-api-contract","variant":label,
                "argv":[sys.executable,"-I",str(ROOT/"tests/api/safety_contract.py"),"--build",str(directory),
                    "--mode","production" if label=="hooks-off" else "pr","--out",
                    str(artifact_root/f"safety-{label}.json")]})
        commands.extend({"kind":"chunk-title","title":title,"independent_instances":2,
            "comparisons":["RAM","CPU-explicit-fields","video","PCM","terminal-state","instruction-events"],
            "dropped_instruction_events_allowed":0} for title in ("recursion94","tank-battle"))
        expected_children=24+12+2+3+2
        workloads={"core_title_executions":12,"core_original_control_executions":12,
            "software_sdl_title_cases":6,"native_sdl_title_cases":6,
            "separate_original_host_control_rosters":2}
    elif mode == "safety":
        for label,directory in (("native",build),("asan-ubsan",ROOT/"build/phase6-sanitize"),
                                ("hooks-off",ROOT/"build/phase6-hooks-off")):
            if not (directory/"CMakeCache.txt").is_file() or not (directory/"gw_bounded_fuzz").is_file():
                raise ValueError("phase7-safety-build-or-fuzz-binary-missing:"+label)
            discovery=subprocess.run(["ctest","--test-dir",str(directory),"--show-only=json-v1"],
                cwd=ROOT,text=True,capture_output=True,timeout=30)
            if discovery.returncode:
                raise ValueError("phase7-safety-roster-discovery-failed:"+label)
            found=[row.get("name") for row in json.loads(discovery.stdout).get("tests",[])]
            missing=sorted(set(all_names)-set(found))
            if missing:
                raise ValueError("phase7-safety-tests-missing:"+label+":"+",".join(missing))
            commands.append({"kind":"ctest-discovery","variant":label,
                "argv":["ctest","--test-dir",str(directory),"--show-only=json-v1"],"expected_names":list(all_names)})
            commands.extend({"kind":"safety-test","variant":label,"test":name,
                "argv":["ctest","--test-dir",str(directory),"--no-tests=error","--output-on-failure","-R",f"^{name}$"]}
                for name in all_names)
            commands.append({"kind":"malformed-load","variant":label,"cases":4096,
                "argv":[str(directory/"gw_bounded_fuzz")],"exit_cap_seconds":90})
        for label,directory in (("native",build),("asan-ubsan",ROOT/"build/phase6-sanitize"),
                                ("hooks-off",ROOT/"build/phase6-hooks-off")):
            commands.append({"kind":"safety-api-contract","variant":label,
                "argv":[sys.executable,"-I",str(ROOT/"tests/api/safety_contract.py"),"--build",str(directory),
                    "--mode","production" if label=="hooks-off" else "pr","--out",
                    str(artifact_root/f"safety-{label}.json")]})
        expected_children=3
        workloads={"named_tests_per_variant":12,"variants":3,"malformed_load_cases_per_variant":4096,
            "malformed_load_total":12288}
    else: # chunk
        executable=build/"tools/session/phase6_chunk_contract"
        if not executable.is_file():
            raise ValueError("phase7-chunk-executable-missing")
        commands.append({"kind":"ctest-discovery","argv":["ctest","--test-dir",str(build),"--show-only=json-v1"],
            "expected_names":["phase6_chunk_contract"]})
        commands.append({"kind":"ctest-contract","argv":["ctest","--test-dir",str(build),"--no-tests=error",
            "--output-on-failure","-R","^phase6_chunk_contract$"]})
        discovery=subprocess.run(["ctest","--test-dir",str(build),"--show-only=json-v1"],
            cwd=ROOT,text=True,capture_output=True,timeout=30)
        if discovery.returncode or sum(row.get("name")=="phase6_chunk_contract"
                for row in json.loads(discovery.stdout).get("tests",[]))!=1:
            raise ValueError("phase7-chunk-test-roster-invalid")
        smoke_path=ROOT/"build/v02/smoke-task2-current.json"
        smoke=(json.loads(smoke_path.read_text(encoding="utf-8"))
               if smoke_path.is_file() else {})
        if (smoke.get("status")!="pass" or smoke.get("source_identity")!=source["source_sha256"] or
                smoke.get("git_head")!=git_head or smoke.get("execution_scope_sha256")!=sha(scope_path.resolve(strict=True)) or
                smoke.get("build_identity")!={"cmake_cache_sha256":sha(build/"CMakeCache.txt"),
                    "headless_sha256":sha(headless),"desktop_sha256":sha(desktop)}):
            core_path=artifact_root/"core-report.json";chunk_report=artifact_root/"chunk-report.json"
            collector=[sys.executable,"-I",str(ROOT/"tests/fixtures/phase6_game.py"),"--mode","chunk",
                "--build",str(build),"--candidate",str(artifact_root/"candidate.json"),
                "--delivery-map",str(ROOT/"fixtures/phase6/recursion94-consumed-map-v1.json"),
                "--core-report",str(core_path),"--execution-scope",str(scope_path.resolve()),"--output",str(chunk_report)]
            commands.append({"kind":"chunk-roster-collector","titles":["recursion94","tank-battle"],
                "argv":collector,"output":str(chunk_report),"source_input":"fresh-core-report",
                "source_identity_dependencies":[str(core_path),str(artifact_root/"candidate.json"),str(build/"CMakeCache.txt"),
                    str(build/"tools/session/phase6_chunk_contract")],"independent_instances":2,
                "comparisons":["RAM","CPU-explicit-fields","video","PCM","terminal-state","instruction-events"],
                "dropped_instruction_events_allowed":0})
            expected_children=2
            workloads={"titles":2,"independent_instances_per_title":2,"full_boundary_comparisons":True,
                "instruction_events_required":True,"fresh_core_dependency":str(core_path)}
            return {"schema":"genewhip-v02-execution-plan-v1","mode":mode,"scope_id":scope["scope_id"],
                **source,"git_head":git_head,"build_identity":{"cmake_cache_sha256":sha(build/"CMakeCache.txt"),
                    "headless_sha256":sha(headless),"desktop_sha256":sha(desktop) if desktop.is_file() else None},
                "commands":commands,"workloads":workloads,"required_child_count":expected_children,
                "plan_only_child_starts":0,"plan_only_guest_starts":0,
                "execution_scope_sha256":sha(scope_path.resolve(strict=True)),"max_child_wall_seconds":limits["wall_seconds"],
                "cleanup_grace_seconds":limits["cleanup_grace_seconds"],"resource_limits":limits,
                "requires_fresh_two_title_smoke":True,
                "requires_fresh_full_core_report_before_execution":True,
                "requested_host_backends":[],"observed_exposure":{"child_starts":0,"guest_starts":0,
                    "core_guest_starts":0,"desktop_guest_starts":0,"plan_helper_process_starts":1},
                "safety":None,"chunk":{"titles":["recursion94","tank-battle"],"instruction_events_required":True},
                "launch_identities":{"headless_sha256":sha(headless),"desktop_sha256":sha(desktop) if desktop.is_file() else None}}
        for title in ("recursion94","tank-battle"):
            smoke_row=next((row for row in smoke.get("core",[]) if row.get("title")==title),None)
            native_path=ROOT/"build/v02/smoke-committed"/f"{title}-core"/"native.json"
            run_path=native_path.parent/"run.json"
            if (smoke_row is None or not native_path.is_file() or not run_path.is_file() or
                    sha(native_path)!=smoke_row.get("native_sha256")):
                raise ValueError("phase7-chunk-smoke-route-facts-missing:"+title)
            native=json.loads(native_path.read_text(encoding="utf-8"));route_run=json.loads(run_path.read_text(encoding="utf-8"))
            inputs=native.get("inputs")
            if (native.get("status")!=0 or native.get("active_ticks")!=3600 or
                    type(native.get("fields")) is not int or native["fields"]>limits["max_fields"] or
                    not isinstance(inputs,list) or not 1<=len(inputs)<=64 or type(native.get("final_tick")) is not int or
                    type(route_run.get("field_sequence")) is not int):
                raise ValueError("phase7-chunk-smoke-route-facts-invalid:"+title)
            for event in inputs:
                if (type(event.get("machine_tick")) is not int or event["machine_tick"]<112 or
                        event.get("port") not in (0,1) or type(event.get("effective")) is not int or
                        not 0<=event["effective"]<=255):
                    raise ValueError("phase7-chunk-smoke-input-invalid:"+title)
            input_path=artifact_root/"chunk"/f"{title}-inputs.csv"
            input_path.parent.mkdir(parents=True,exist_ok=True)
            input_data=_format_chunk_inputs(inputs)
            if len(input_data)>limits["max_binary_file_bytes"]:
                raise ValueError("phase7-chunk-input-log-byte-limit:"+title)
            if input_path.exists() and input_path.read_bytes()!=input_data:
                raise ValueError("phase7-chunk-input-log-collision:"+title)
            input_path.write_bytes(input_data)
            cap=100_000_000 if title=="recursion94" else 10_000_000
            chunk_report=artifact_root/"chunk"/f"{title}-chunk.json"
            commands.append({"kind":"chunk-title","title":title,"argv":[str(executable),"--title",
                str((ROOT/titles[title]).resolve()),str(input_path),str(native["fields"]),str(cap),
                str(route_run["field_sequence"]),str(native["final_tick"]),str(chunk_report)],
                "source_native_sha256":sha(native_path),"input_log_sha256":hashlib.sha256(input_data).hexdigest(),
                "independent_instances":2,"comparisons":["RAM","CPU-explicit-fields","video","PCM",
                    "terminal-state","instruction-events"],"dropped_instruction_events_allowed":0})
        expected_children=2
        workloads={"titles":2,"independent_instances_per_title":2,"full_boundary_comparisons":True,
            "instruction_events_required":True}
    return {"schema":"genewhip-v02-execution-plan-v1","mode":mode,"scope_id":scope["scope_id"],
        **source,
        "git_head":git_head,
        "build_identity":{"cmake_cache_sha256":sha(build/"CMakeCache.txt"),"headless_sha256":sha(headless),
            "desktop_sha256":sha(desktop) if desktop.is_file() else None},"commands":commands,
        "workloads":workloads,"required_child_count":expected_children,"plan_only_child_starts":0,
        "plan_only_guest_starts":0,"execution_scope_sha256":sha(scope_path.resolve(strict=True)),
        "max_child_wall_seconds":limits["wall_seconds"],"cleanup_grace_seconds":limits["cleanup_grace_seconds"],
        "resource_limits":limits,"requested_host_backends":["software","native"] if mode=="full" else (["software"] if mode=="smoke" else []),
        "observed_exposure":{"child_starts":0,"guest_starts":0,"core_guest_starts":0,
            "desktop_guest_starts":0,"plan_helper_process_starts":3 if mode=="safety" else (1 if mode=="chunk" else 0)},
        "safety":{"test_names":list(all_names),"variants":["native","asan-ubsan","hooks-off"],
            "malformed_load_cases_per_variant":4096} if mode in ("full","safety") else None,
        "chunk":{"titles":["recursion94","tank-battle"],"instruction_events_required":True} if mode in ("full","chunk") else None,
        "launch_identities":{"headless_sha256":sha(headless),"desktop_sha256":sha(desktop) if desktop.is_file() else None}}


def validate_execution_observation(record: dict, expected: dict) -> None:
    """Validate child-boundary facts before accepting any Phase 7 execution observation."""
    if not isinstance(record, dict) or record.get("schema") != "genewhip-v02-execution-observation-v1":
        raise RuntimeError("phase7-observation-schema")
    payload = {key:value for key,value in record.items() if key != "payload_sha256"}
    if record.get("payload_sha256") != hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":")).encode()).hexdigest():
        raise RuntimeError("phase7-observation-payload-digest")
    for key in ("scope_id","source_sha256","build_identity","launch_identities"):
        if record.get(key) != expected.get(key):
            raise RuntimeError("phase7-stale-launch-identity:"+key)
    if record.get("historical_window_access") is not False:
        raise RuntimeError("phase7-historical-window-access")
    process=record.get("process",{})
    if process.get("process_group_cleanup") != "confirmed" or process.get("bound_violation") is not False:
        raise RuntimeError("phase7-process-cleanup-or-bound")
    capabilities=record.get("capabilities",{})
    if expected.get("require_native") and capabilities.get("native") != "observed":
        raise RuntimeError("phase7-native-capability-missing")
    comparisons=record.get("comparisons",{})
    for name in ("ram","cpu_explicit_fields","video","pcm","terminal_state","instruction_events"):
        if comparisons.get(name) is not True:
            raise RuntimeError("phase7-comparison-missing:"+name)
    if record.get("dropped_instruction_events") != 0:
        raise RuntimeError("phase7-instruction-events-dropped")


def _isolation_preflight(route_contract, limits: dict) -> dict:
    """Exercise the real child boundary with an unusable synthetic client and sticky denial."""
    with tempfile.TemporaryDirectory(prefix="gw-v02-denial-") as directory:
        scratch = pathlib.Path(directory)
        fake_client = scratch / "unusable-production-client"
        runs: list[dict] = []
        reached = []
        original = route_contract.subprocess.Popen
        def deny(*args, **kwargs):
            reached.append(args[0])
            raise AssertionError("phase7 synthetic child denied")
        route_contract.subprocess.Popen = deny
        try:
            result = route_contract._run_client(fake_client, [str(fake_client)], runs,
                report=scratch / "synthetic.json", timeout=2, limits=limits, scratch_roots=(scratch,))
        finally:
            route_contract.subprocess.Popen = original
        if not reached or result.returncode != 127 or len(runs) != 1 or runs[0].get("status") != "launch-failed":
            raise ValueError("phase7-synthetic-denial-hook-not-reached")
        return {"denial_hook_reached": True, "synthetic_attempts": len(reached),
            "production_child_starts": 0, "production_client_usable": fake_client.is_file()}


def _smoke_failure_summary(runs: list[dict]) -> dict:
    """Keep failure logs useful without exposing child commands, paths or output."""
    row = runs[-1] if runs and isinstance(runs[-1], dict) else {}
    fields = {
        "status": {"completed", "failed", "exception", "launch-failed"},
        "process_group_cleanup": {"confirmed", "unconfirmed", "not-launched"},
        "bound_violation_reason": {"phase7-rss-observation-unavailable"},
        "rss_observation_reason": {"linux-proc-scan-unavailable", "darwin-libproc-unavailable",
            "pid-count-invalid", "pid-fill-invalid", "pid-fill-saturated", "duplicate-pid",
            "process-group-query-unavailable", "task-info-unavailable",
            "darwin-libproc-query-unavailable", "platform-unsupported", "observation-unclassified"},
        "rss_observation_errno": {"absent", "esrch", "permission", "other"},
        "rss_observation_result": {"missing", "short", "oversized", "invalid", "saturated"},
    }
    result = {"schema": "genewhip.v02-smoke-child-failure.v1"}
    for field, allowed in fields.items():
        value = row.get(field)
        result[field] = value if isinstance(value, str) and value in allowed else "unavailable"
    return result


def _run_smoke_child(route_contract, limits, command, *, report, timeout, cwd,
                     env=None, files=(), directories=()):
    runs: list[dict] = []
    streams: dict = {}
    capture = _module(ROOT / "scripts/evidence/phase5_process.py", "gw_smoke_receipt")
    with capture.receipt_file(cwd, pathlib.Path("process.json")) as receipt_stream:
        try:
            result = route_contract._run_client(pathlib.Path(command[0]), command, runs, report=report,
                timeout=timeout, cwd=cwd, env=env, retained_streams=streams,
                monitored_files=files, monitored_directories=directories,
                limits=limits, scratch_roots=(cwd,), process_receipt_stream=receipt_stream)
        finally:
            receipt_stream.seek(0)
            json.dump({"processes": runs, "streams": streams}, receipt_stream, sort_keys=True, indent=2)
            receipt_stream.write("\n"); receipt_stream.truncate(); receipt_stream.flush()
            os.fsync(receipt_stream.fileno())
            if not runs or runs[-1].get("status") != "completed" or runs[-1].get("bound_violation"):
                try:
                    print("SMOKE_CHILD_FAILURE " + json.dumps(_smoke_failure_summary(runs), sort_keys=True),
                          flush=True)
                except OSError:
                    # The durable receipt remains authoritative if the CI log
                    # closes; do not replace the child's original failure.
                    pass
    return result, runs[-1], streams


def run_smoke(build: pathlib.Path, scope_path: pathlib.Path, out: pathlib.Path) -> dict:
    """Run one source-declared full-route discriminator per title through core and software SDL."""
    scope, limits = validate_execution_scope(scope_path, "smoke")
    out = out.resolve()
    build = build.resolve(strict=True)
    plan = plan_mode("smoke", build, scope_path, out)
    route_contract = _module(ROOT / "tests/session/phase6_route_contract.py", "gw_v02_smoke_boundary")
    fixture = _module(ROOT / "tests/fixtures/phase6_game.py", "gw_v02_smoke_fixture")
    desktop = _module(ROOT / "tests/desktop/phase6_routes.py", "gw_v02_smoke_desktop")
    fixture.set_execution_scope(scope)
    desktop.set_execution_scope(scope)
    isolation = _isolation_preflight(route_contract, limits)
    artifact_root = out.parent / out.stem
    artifact_root.mkdir(parents=True, exist_ok=True)
    mapping_path = ROOT / "fixtures/phase6/recursion94-consumed-map-v1.json"
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    compiler = fixture.compiler
    candidate_path = artifact_root / "candidate.json"
    candidate = fixture.freeze_candidate(build, mapping_path, candidate_path)
    headless = build / "tools/session/gw_headless"
    desktop_bin = build / "tools/desktop/genewhip-desktop"
    core_rows, host_rows = [], []

    def bounded(command, *, report, timeout, cwd, env=None, files=(), directories=()):
        return _run_smoke_child(route_contract, limits, command, report=report, timeout=timeout,
            cwd=cwd, env=env, files=files, directories=directories)

    prior_shared_launch = fixture.shared_launch
    def scoped_shared_launch(client, command, work, report, timeout, *, files=(), directories=(), env=None, plan_id="07-03"):
        return bounded(command, report=report, timeout=min(timeout, limits["wall_seconds"]), cwd=work,
            env=env, files=files, directories=directories)
    fixture.shared_launch = scoped_shared_launch
    scoped_state = None
    try:
        routes = compiler.compile_routes(mapping)["routes"]
        for title in ("recursion94", "tank-battle"):
            route = next(row for row in routes if row["fixture"] == title and row["case"]["id"] == "full-route")
            core_work = artifact_root / f"{title}-core"
            if core_work.exists():
                raise ValueError("phase7-smoke-output-already-exists")
            core_row = fixture.collect_case(build, route, mapping, candidate, core_work, 1,
                remaining_seconds=limits["wall_seconds"])
            core_report = json.loads((core_work / "native.json").read_text(encoding="utf-8"))
            comparison_fields=("plan_fnv1a64","audio_open","samples","inputs","predicates","active_ticks","fields",
                "final_tick","stop_reason","instruction_address","opcode","audio_frames","audio_hash",
                "termination","boundary_calls")
            core_rows.append({"title": title, "case": route["case"]["id"], "status": core_row["status"],
                "fields": core_row["completed_fields"], "active_ticks": core_report.get("active_ticks"),
                "predicates": core_row["predicate_results"], "process": core_row["process"],
                "native_sha256": sha(core_work / "native.json"), "plan_sha256": core_row["compiled_sha256"],
                "comparison_fields":list(comparison_fields),
                "native_observations":{key:core_report.get(key) for key in comparison_fields},
                "controller_events":[{"port":row.get("port"),"mask":row.get("desired"),
                    "effective":row.get("effective")} for row in core_report.get("inputs",[])]})

            host_work = artifact_root / f"{title}-software-sdl"
            host_work.mkdir(mode=0o700)
            binary, _ = compiler.lower_route(route, 100_000_000 if title == "recursion94" else 10_000_000,
                mapping if title == "recursion94" else None, client="sdl")
            plan_path, native_path, host_path = host_work / "route.gwrc", host_work / "native.json", host_work / "host.json"
            plan_path.write_bytes(binary)
            rom = ROOT / compiler.SOURCES[title][3]
            command = [str(desktop_bin), "--route-plan", str(plan_path), "--route-report", str(native_path),
                "--route-input-source", "virtual-gamepad", "--route-diagnostic", str(host_path), str(rom)]
            env = dict(os.environ, SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="disk", SDL_RENDER_DRIVER="software")
            result, process, _ = bounded(command, report=native_path, timeout=limits["wall_seconds"],
                cwd=host_work, env=env, files=((host_work / "sdlaudio.raw", limits["max_binary_file_bytes"]),))
            host_native = json.loads(native_path.read_text(encoding="utf-8")) if native_path.is_file() else {}
            host = json.loads(host_path.read_text(encoding="utf-8")) if host_path.is_file() else {}
            native_matches=all(core_report.get(key)==host_native.get(key) for key in comparison_fields)
            input_events=host.get("input_events",[])
            host_events=[{"port":row.get("port"),"mask":row.get("requested_mask"),
                "effective":row.get("effective_mask")} for row in input_events]
            controller_events=core_rows[-1]["controller_events"]
            input_events_match=len(host_events)==len(controller_events) and host_events==controller_events
            host_rows.append({"title": title, "backend": "software", "return_code": result.returncode,
                "process": process, "native_status": host_native.get("status"),
                "fields": host_native.get("fields"), "active_ticks": host_native.get("active_ticks"),
                "host_outcome": host.get("host_outcome"), "input_events": host.get("input_events"),
                "native_observations_match":native_matches,"controller_events_match":input_events_match,
                "presented_frames": host.get("presented_frames"),
                "renderer_readback_samples": host.get("renderer_readback_samples"),
                "pcm_frames": host.get("pcm_frames"), "pcm_sha256": host.get("pcm_hash"),
                "native_sha256": sha(native_path) if native_path.is_file() else None,
                "host_sha256": sha(host_path) if host_path.is_file() else None})
    finally:
        fixture.shared_launch = prior_shared_launch
        fixture.set_execution_scope(None)
        desktop.set_execution_scope(None)
    core_ok = len(core_rows) == 2 and all(row["status"] == "pass" for row in core_rows)
    host_ok = len(host_rows) == 2 and all(row["return_code"] == 0 and row["native_status"] == 0 and
        row["host_outcome"] == "pass-diagnostic" and row["process"].get("process_group_cleanup") == "confirmed" and
        row["process"].get("bound_violation") is False and isinstance(row["pcm_frames"], int) and row["pcm_frames"] > 0 and
        isinstance(row["renderer_readback_samples"], int) and row["renderer_readback_samples"] > 0 for row in host_rows)
    observations_match = all(any(host["title"] == core["title"] and host["native_observations_match"] and
        host["controller_events_match"] for host in host_rows) for core in core_rows)
    all_processes=[row["process"] for row in (*core_rows,*host_rows)]
    receipt = {"schema": "genewhip-v02-smoke-v1", "status": "pass" if core_ok and host_ok and observations_match else "fail",
        "scope_id": scope["scope_id"], "execution_scope_sha256":plan["execution_scope_sha256"],
        "source_identity": plan["source_sha256"], "git_head": plan["git_head"],
        "controller_identity":{"sha256":plan["controller_sha256"],"route_compiler_sha256":plan["route_compiler_sha256"],
            "fixture_harness_sha256":plan["fixture_harness_sha256"]},
        "launch_identities":plan["launch_identities"], "build_identity":plan["build_identity"],
        "delivery_map_sha256": compiler.canonical_digest(mapping), "isolation_preflight": isolation,
        "core": core_rows, "software_sdl": host_rows, "observations_match": observations_match,
        "cross_client_comparison_fields":["plan_fnv1a64","audio_open","samples","inputs","predicates",
            "active_ticks","fields","final_tick","stop_reason","instruction_address","opcode",
            "audio_frames","audio_hash","termination","boundary_calls","ordered controller events"],
        "observed_exposure": {"synthetic_production_starts": 0,
            "actual_bounded_children": len(core_rows) + len(host_rows),
            "all_process_groups_cleaned":all(row.get("process_group_cleanup")=="confirmed" for row in all_processes),
            "max_child_wall_seconds":max(row.get("wall_seconds",0) for row in all_processes),
            "max_child_rss_bytes":max(row.get("rss_bytes_peak",0) for row in all_processes),
            "max_child_output_bytes":max(row.get("stdout_bytes",0)+row.get("stderr_bytes",0) for row in all_processes)},
        "required_host_capabilities": {"software_sdl": "observed" if host_ok else "failed-or-blocked"},
        "limitations": ["One full-route discriminator per title; not full repeated qualification.",
            "Software SDL does not qualify native SDL or physical output quality."]}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return receipt


_SAFE_HOST_BATCH_CASES = frozenset({
    ("recursion94", "full-route"), ("recursion94", "withhold-first-plate"),
    ("recursion94", "withhold-final-b"), ("tank-battle", "full-route"),
    ("tank-battle", "withhold-early-hit"), ("tank-battle", "withhold-late-hit"),
})
_SAFE_HOST_BATCH_INPUT_COUNTS = {
    ("recursion94", "full-route"): 20,
    ("recursion94", "withhold-first-plate"): 18,
    ("recursion94", "withhold-final-b"): 18,
    ("tank-battle", "full-route"): 22,
    ("tank-battle", "withhold-early-hit"): 2,
    ("tank-battle", "withhold-late-hit"): 12,
}
_SAFE_HOST_BATCH_CLEANUP = frozenset({"confirmed", "unconfirmed", "not-launched"})
_SAFE_HOST_BATCH_REASONS = frozenset({
    "group-inactive", "group-observer-cleanup-unconfirmed", "group-status-budget-exhausted",
    "cleanup-permission-denied", "group-cleanup-os-error",
    "group-leader-reap-unconfirmed", "group-leader-wait-unconfirmed",
    "group-reported-active", "group-signal-permission-denied", "group-signal-visible",
    "group-status-unavailable", "cleanup-unclassified", "not-observed",
})
_SAFE_HOST_BATCH_BOUNDS = frozenset({
    "phase7-wall-timeout", "phase7-stdout-stderr-byte-limit",
    "phase7-rss-observation-unavailable", "phase7-rss-byte-limit",
    "phase7-scratch-tree-unsafe", "phase7-scratch-byte-limit",
    "phase7-json-byte-limit", "phase7-capture-byte-limit",
    "phase7-retained-byte-limit", "phase7-binary-file-byte-limit",
})


def _safe_host_batch_failure(backend: str, return_code: object, host: object) -> str:
    backend_value = backend if isinstance(backend, str) and backend in {"software", "native"} else "other"
    code_value = str(return_code) if type(return_code) is int and return_code in {0, 1, 77} else "other"
    report = host if isinstance(host, dict) else {}
    report_status = report.get("status")
    report_status = (report_status if isinstance(report_status, str) and
                     report_status in {"pass", "fail", "in-progress"} else
                     ("missing" if report_status is None else "other"))
    rows = report.get("runs")
    failed = next((row for row in rows if isinstance(row, dict) and row.get("status") == "fail"),
                  None) if isinstance(rows, list) else None
    if failed is None:
        case_value, row_status = "missing", "missing"
        process = {}
    else:
        pair = (failed.get("fixture"), failed.get("case"))
        case_value = (f"{pair[0]}/{pair[1]}" if all(isinstance(item, str) for item in pair) and
                      pair in _SAFE_HOST_BATCH_CASES else "unrecognized")
        row_status = "fail"
        process = failed.get("process") if isinstance(failed.get("process"), dict) else {}
    def enum(value, allowed):
        if value is None:
            return "missing"
        return value if isinstance(value, str) and value in allowed else "other"

    def tri_bool(value):
        return "true" if value is True else "false" if value is False else "unavailable"

    def counter(value, maximum, *, expected=None, positive=False):
        if value is None:
            return "missing"
        if type(value) is not int:
            return "untyped"
        if value < 0:
            return "negative"
        if value > maximum:
            return "overrange"
        if expected is not None:
            return "expected" if value == expected else "mismatch"
        if positive:
            return "zero" if value == 0 else "positive"
        return "in-range"

    def bounded_integer(value, maximum, *, minimum=0):
        if value is None:
            return "missing"
        if type(value) is not int:
            return "untyped"
        if value < minimum:
            return "negative"
        if value > maximum:
            return "overrange"
        return value

    cleanup = enum(process.get("process_group_cleanup"), _SAFE_HOST_BATCH_CLEANUP)
    bound = enum(process.get("bound_violation_reason"), _SAFE_HOST_BATCH_BOUNDS)
    if bound == "missing":
        bound = "unspecified" if process.get("bound_violation") is True else "none"
    reason = enum(process.get("cleanup_reason"), _SAFE_HOST_BATCH_REASONS)
    observation = enum(process.get("cleanup_status_observation"), _SAFE_HOST_BATCH_REASONS)
    attempts = process.get("cleanup_observation_attempts")
    attempts_value = str(attempts) if type(attempts) is int and 0 <= attempts <= 16 else "other"
    # Keep the outer host-batch status separate from the child process result.
    child_return = process.get("return_code")
    if child_return is None:
        child_exit = "missing"
    elif type(child_return) is not int:
        child_exit = "untyped"
    elif child_return < 0:
        child_exit = "signaled"
    else:
        child_exit = "zero" if child_return == 0 else "nonzero"

    reason_value = enum(failed.get("reason") if failed is not None else None,
                        {"core-input-progress-or-common-boundary-mismatch",
                         "host-renderer-pcm-or-device-mismatch"})
    core_outcome = enum(failed.get("core_outcome") if failed is not None else None, {"pass", "fail"})
    host_outcome = enum(failed.get("host_outcome") if failed is not None else None,
                        {"pass-diagnostic", "fail-diagnostic"})
    diagnostics = failed.get("failure_diagnostic") if failed is not None else None
    diagnostics = diagnostics if isinstance(diagnostics, dict) else {}
    comparisons = failed.get("common_boundary") if failed is not None else None
    comparisons = comparisons if isinstance(comparisons, dict) else {}
    renderer = failed.get("renderer") if failed is not None else None
    renderer = renderer if isinstance(renderer, dict) else {}
    audio = failed.get("audio") if failed is not None else None
    audio = audio if isinstance(audio, dict) else {}
    clocks = failed.get("observed_clocks") if failed is not None else None
    clocks = clocks if isinstance(clocks, dict) else {}
    fixture = failed.get("fixture") if failed is not None else None
    case_pair = (failed.get("fixture"), failed.get("case")) if failed is not None else None
    input_row_limit = (_SAFE_HOST_BATCH_INPUT_COUNTS.get(case_pair, 0)
        if isinstance(case_pair, tuple) and all(isinstance(part, str) for part in case_pair) else 0)
    input_facts = comparisons.get("inputs")
    input_facts = input_facts if isinstance(input_facts, dict) else {}
    input_rows = input_facts.get("rows")
    first_mismatch = {"state": "unavailable", "index": "missing",
        "expected_mask": "missing", "retained_desired": "missing", "retained_effective": "missing"}
    if isinstance(input_rows, list) and 0 < input_row_limit and len(input_rows) <= input_row_limit:
        mismatch = next((item for item in input_rows if isinstance(item, dict) and item.get("equal") is False), None)
        if mismatch is None:
            # "none" means a complete, checked roster with no mismatch, not
            # merely a producer-level equal=True flag. Only this fixed case has
            # a retained expected-mask map; other cases cannot prove absence.
            complete_first_plate = (
                case_pair == ("recursion94", "withhold-first-plate")
                and len(input_rows) == input_row_limit
                and input_facts.get("equal") is True
                and type(input_facts.get("core_count")) is int
                and input_facts.get("core_count") == input_row_limit
                and type(input_facts.get("host_count")) is int
                and input_facts.get("host_count") == input_row_limit
            )
            route_masks = globals().get("_NATIVE_DIAGNOSTIC_ROUTE_MASKS", ())
            complete_first_plate = complete_first_plate and len(route_masks) == input_row_limit
            if complete_first_plate:
                for expected_index, row in enumerate(input_rows):
                    if (not isinstance(row, dict)
                            or type(row.get("index")) is not int
                            or row.get("index") != expected_index
                            or type(row.get("equal")) is not bool
                            or row.get("equal") is not True
                            or type(row.get("port")) is not int
                            or row.get("port") != 0
                            or type(row.get("desired")) is not int
                            or row.get("desired") != route_masks[expected_index]
                            or type(row.get("effective")) is not int
                            or row.get("effective") != route_masks[expected_index]):
                        complete_first_plate = False
                        break
            if complete_first_plate:
                first_mismatch["state"] = "none"
            elif any(not isinstance(item, dict) or type(item.get("equal")) is not bool
                     for item in input_rows):
                first_mismatch["state"] = "malformed"
            else:
                first_mismatch["state"] = "unavailable"
        else:
            first_mismatch["state"] = "found"
            mismatch_index = bounded_integer(mismatch.get("index"), input_row_limit - 1)
            first_mismatch["index"] = mismatch_index
            if (type(mismatch_index) is int and case_pair ==
                    ("recursion94", "withhold-first-plate")):
                route_masks = globals().get("_NATIVE_DIAGNOSTIC_ROUTE_MASKS", ())
                first_mismatch["expected_mask"] = (route_masks[mismatch_index]
                    if mismatch_index < len(route_masks) else "unavailable")
            elif type(mismatch_index) is int:
                first_mismatch["expected_mask"] = "unavailable"
            # _input_join currently retains the core row values, not the host's
            # raw requested/effective values. Label those honestly; do not infer
            # or reconstruct the missing host observation.
            first_mismatch["retained_desired"] = bounded_integer(mismatch.get("desired"), 255)
            first_mismatch["retained_effective"] = bounded_integer(mismatch.get("effective"), 255)
    elif input_rows is None:
        first_mismatch["state"] = "missing"
    else:
        first_mismatch["state"] = ("overrange" if isinstance(input_rows, list) else
            "untyped" if input_rows is not None else "missing")
    if fixture == "recursion94":
        field_max, call_max = 7200, 100_000_000
    elif fixture == "tank-battle":
        field_max, call_max = 4500, 10_000_000
    else:
        field_max, call_max = 7200, 100_000_000
    fields = {
        "schema": "genewhip.v02-host-batch-failure.v2",
        "backend": backend_value, "report": report_status, "case": case_value, "row": row_status,
        "batch_return": code_value, "child_exit": child_exit, "cleanup": cleanup, "bound": bound,
        "cleanup_reason": reason, "status_observation": observation, "cleanup_queries": attempts_value,
        "reason": reason_value, "core_outcome": core_outcome, "host_outcome": host_outcome,
        "source_samples_equal": tri_bool(comparisons.get("source_samples_equal")),
        "input_equal": tri_bool((comparisons.get("inputs") or {}).get("equal")
                                 if isinstance(comparisons.get("inputs"), dict) else None),
        "renderer_pixel_equal": tri_bool(comparisons.get("renderer_pixel_equal")),
        "pcm_equal": tri_bool(comparisons.get("full_pcm_equal")),
        "readback_activity": tri_bool(renderer.get("renderer_readback_activity")),
        "audio_activity": tri_bool(audio.get("audio_device_activity")),
        "capture_field_matches": tri_bool(diagnostics.get("capture_field_matches")),
        "renderer_named": tri_bool(diagnostics.get("renderer_named")),
        "video_driver_named": tri_bool(diagnostics.get("video_driver_named")),
        "audio_driver_named": tri_bool(diagnostics.get("audio_driver_named")),
        "native_status": ("missing" if clocks.get("status") is None else
                          "untyped" if type(clocks.get("status")) is not int else
                          "zero" if clocks.get("status") == 0 else "nonzero"),
        "native_status_value": bounded_integer(clocks.get("status"), 255),
        "active_ticks": counter(clocks.get("active_ticks"), 3600, expected=3600),
        # Active ticks are expected to be exactly 3600 for these fixed cases;
        # retain any smaller observed value, but do not export beyond that bound.
        "active_ticks_value": bounded_integer(clocks.get("active_ticks"), 3600),
        "fields": counter(clocks.get("fields"), field_max),
        "fields_value": bounded_integer(clocks.get("fields"), field_max),
        "boundary_calls": counter(clocks.get("boundary_calls"), call_max),
        "boundary_calls_value": bounded_integer(clocks.get("boundary_calls"), call_max),
        "child_return_value": bounded_integer(process.get("return_code"), 255, minimum=-255),
        "input_core_count": bounded_integer(input_facts.get("core_count"), input_row_limit),
        "input_host_count": bounded_integer(input_facts.get("host_count"), input_row_limit),
        "input_row_count": bounded_integer(len(input_rows) if isinstance(input_rows, list) else None,
            input_row_limit),
        "first_input_mismatch": first_mismatch,
        "audio_submitted_frames": counter(audio.get("audio_submitted_frames"), 28_800_000, positive=True),
        "audio_consumed_frames": counter(audio.get("audio_device_consumed_frames"), 28_800_000, positive=True),
    }
    rendered = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(rendered.encode("utf-8")) > 4096:
        rendered = json.dumps({"schema": fields["schema"], "diagnostic": "unavailable"},
                              sort_keys=True, separators=(",", ":"))
    return rendered


def _collect_checked_host_batch(desktop, compiler, backend: str, build: pathlib.Path,
                                core_path: pathlib.Path, mapping_path: pathlib.Path,
                                host_path: pathlib.Path, candidate_path: pathlib.Path,
                                candidate: dict) -> dict:
    return_code = desktop.host_batch(
        backend, build, core_path, mapping_path, host_path, candidate_path)
    try:
        host = json.loads(host_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        if return_code != 0:
            raise ValueError("phase7-host-batch-failed:" +
                             _safe_host_batch_failure(backend, return_code, None))
        raise
    if return_code != 0:
        raise ValueError("phase7-host-batch-failed:" +
                         _safe_host_batch_failure(backend, return_code, host))
    compiler.validate_host_report(host, candidate)
    return host


def run_execution(mode: str, build: pathlib.Path, scope_path: pathlib.Path, out: pathlib.Path) -> dict:
    """Dispatch the existing bounded collectors under a fresh explicit Phase 7 scope."""
    if mode not in ("full", "safety", "chunk"):
        raise ValueError("phase7-runtime-mode-not-owned:" + mode)
    scope, limits = validate_execution_scope(scope_path, mode)
    build = build.resolve(strict=True); out = out.resolve()
    plan = plan_mode(mode, build, scope_path, out)
    route_contract = _module(ROOT / "tests/session/phase6_route_contract.py", "gw_v02_runtime_boundary")
    fixture = _module(ROOT / "tests/fixtures/phase6_game.py", "gw_v02_runtime_fixture")
    desktop = _module(ROOT / "tests/desktop/phase6_routes.py", "gw_v02_runtime_host")
    isolation = _isolation_preflight(route_contract, limits)
    if isolation.get("production_child_starts") != 0:
        raise ValueError("phase7-synthetic-isolation-exposure")
    runtime = out.parent / out.stem
    runtime.mkdir(parents=True, exist_ok=True)
    if runtime.is_symlink() or not runtime.is_dir() or any(
            item.name not in {"candidate.json"} for item in runtime.iterdir()):
        raise ValueError("phase7-runtime-output-collision")
    # Freeze one batch cutoff before any production launch. Nested helper
    # processes read this ignored execution copy; they cannot renew the clock
    # by starting a new Python process.
    started_value = os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT")
    try:
        started = (datetime.datetime.fromisoformat(started_value.replace("Z", "+00:00"))
            if started_value else datetime.datetime.now(datetime.timezone.utc))
        if started.tzinfo is None:
            raise ValueError("timezone-required")
    except ValueError as error:
        raise ValueError("phase7-common-batch-start-invalid") from error
    now = datetime.datetime.now(datetime.timezone.utc)
    if (now - started).total_seconds() < 0:
        raise ValueError("phase7-common-batch-start-in-future")
    runtime_seconds = scope["qualification_batch"]["runtime_wall_seconds"]
    if (now - started).total_seconds() >= runtime_seconds:
        raise ValueError("phase7-runtime-partition-deadline-exhausted")
    runtime_scope = {**scope,
        "qualification_started_at": started.isoformat(),
        "qualification_deadline": (started + datetime.timedelta(seconds=runtime_seconds)).isoformat()}
    scope_copy = runtime / "execution-scope.json"
    if scope_copy.exists() or scope_copy.is_symlink():
        raise ValueError("phase7-runtime-scope-copy-collision")
    scope_copy.write_text(json.dumps(runtime_scope, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    scoped = {**runtime_scope, "_scope_path": str(scope_copy.resolve(strict=True))}
    fixture.set_execution_scope(scoped); desktop.set_execution_scope(scoped)
    mapping_path = ROOT / "fixtures/phase6/recursion94-consumed-map-v1.json"
    candidate_path = runtime / "candidate.json"
    candidate = fixture.freeze_candidate(build, mapping_path, candidate_path)
    current_identity = None
    if mode == "full":
        cache = build / "CMakeCache.txt"
        headless = build / "tools/session/gw_headless"
        desktop_bin = build / "tools/desktop/genewhip-desktop"
        if not desktop_bin.is_file():
            raise ValueError("phase7-current-desktop-client-missing")
        current_identity = {"schema": "genewhip-v02-runtime-identity-v1",
            "source_sha256": plan["source_sha256"], "git_head": plan["git_head"],
            "base_sha": workflow_base_sha(plan["git_head"]),
            "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
            "scope_sha256": sha(scope_path.resolve(strict=True)),
            "candidate_sha256": fixture.canonical_sha(candidate),
            "build_identity": {"cmake_cache_sha256": sha(cache),
                "configuration_sha256": configuration_sha(cache),
                "headless_sha256": sha(headless), "desktop_sha256": sha(desktop_bin)}}
        identity_module = _module(ROOT / "scripts/evidence/v02_matrix.py", "gw_v02_current_identity")
        identity_module.validate_current_execution_identity(current_identity)
        identity_path = out.parent / "runtime-identity.json"
        if identity_path.exists() or identity_path.is_symlink():
            raise ValueError("phase7-current-identity-output-collision")
        identity_path.write_text(json.dumps(current_identity, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    rows = {}
    runtime_inputs = {}
    try:
        if mode == "full":
            core_path = runtime / "core-report.json"
            scoped["_core_report_path"] = str(core_path)
            fixture.set_execution_scope(scoped); desktop.set_execution_scope(scoped)
            fixture.core(build, mapping_path, candidate_path, core_path)
            compiler = fixture.compiler
            current_core = json.loads(core_path.read_text())
            compiler.validate_product_report(current_core, candidate)
            runtime_inputs["core"] = current_core
            rows["core"] = {"path": str(core_path.relative_to(ROOT)), "sha256": sha(core_path)}
            media_path = runtime / "media-report.json"
            fixture.media(build, candidate_path, media_path, core_path)
            rows["media"] = {"path": str(media_path.relative_to(ROOT)), "sha256": sha(media_path)}
            input_root=ROOT/"build/v02/runtime/input-contract"
            input_root.mkdir(parents=True,exist_ok=True)
            for backend in ("software","native"):
                input_path=input_root/f"{backend}.json"
                if desktop.input_contract(build,mapping_path,input_path,candidate_path,backend) != 0:
                    raise ValueError("phase7-current-input-contract-failed:"+backend)
                rows["input-"+backend]={"path":str(input_path.relative_to(ROOT)),"sha256":sha(input_path),
                    "capability":"present" if backend=="native" else "observed"}
            for backend in ("software", "native"):
                host_path = runtime / f"host-{backend}.json"
                if backend == "native" and not limits.get("require_native", True):
                    raise ValueError("phase7-native-capability-requirement-missing")
                host = _collect_checked_host_batch(desktop, compiler, backend, build,
                    core_path, mapping_path, host_path, candidate_path, candidate)
                if host.get("outcome", host.get("status")) not in ("pass", "pass-diagnostic"):
                    raise ValueError("phase7-host-roster-failed:" + backend)
                rows["host-" + backend] = {"path": str(host_path.relative_to(ROOT)), "sha256": sha(host_path),
                    "capability": "present" if backend == "native" else "observed"}
                runtime_inputs["host-" + backend] = host
            safety_path = runtime / "safety.json"
            fixture.safety(build, candidate_path, safety_path)
            safety_build_ref = retain_safety_build_evidence(build, runtime, safety_path, current_identity)
            rows["safety"] = {"path": str(safety_path.relative_to(ROOT)), "sha256": sha(safety_path),
                "build_evidence": safety_build_ref}
            chunk_path = runtime / "chunk.json"
            fixture.chunk(build, candidate_path, mapping_path, chunk_path)
            rows["chunk"] = {"path": str(chunk_path.relative_to(ROOT)), "sha256": sha(chunk_path)}
            matrix = identity_module
            roster = json.loads((ROOT / "evidence/v02-roster.json").read_text(encoding="utf-8"))
            observations = matrix.project_current_observations(roster, runtime_inputs["core"],
                {"software-sdl": runtime_inputs["host-software"],
                 "native-sdl": runtime_inputs["host-native"]}, current_identity)
            public_path = out.parent / "public"
            if public_path.exists() and any(public_path.iterdir()):
                raise ValueError("phase7-public-projection-output-collision")
            public_manifest = matrix.project_public_closure(roster, observations, public_path,
                current_identity, current_identity)
            rows["public-matrix"] = {"path": str((public_path / "manifest.json").relative_to(ROOT)),
                "sha256": sha(public_path / "manifest.json"), "closure_id": public_manifest["closure_id"]}
        elif mode == "safety":
            safety_path = runtime / "safety.json"
            fixture.safety(build, candidate_path, safety_path)
            rows["safety"] = {"path": str(safety_path.relative_to(ROOT)), "sha256": sha(safety_path)}
        else:
            core_path = runtime / "core-report.json"
            if not core_path.is_file():
                raise ValueError("phase7-chunk-requires-fresh-full-core-report")
            scoped["_core_report_path"] = str(core_path)
            fixture.set_execution_scope(scoped)
            chunk_path=runtime/"chunk.json"
            fixture.chunk(build,candidate_path,mapping_path,chunk_path)
            rows["chunk"]={"path":str(chunk_path.relative_to(ROOT)),"sha256":sha(chunk_path)}
        scoped_state = fixture._read_window()
    except BaseException as error:
        failure = {"schema": "genewhip-v02-runtime-observation-v1", "status": "fail",
            "mode": mode, "scope_id": scope["scope_id"], "source_sha256": plan["source_sha256"],
            "git_head": plan["git_head"], "build_identity": plan["build_identity"],
            "launch_identities": plan["launch_identities"], "historical_window_access": False,
            "isolation_preflight": isolation, "observed": rows,
            "failure": f"{type(error).__name__}: {error}"}
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(failure, sort_keys=True, indent=2) + "\n")
        raise
    finally:
        desktop.set_execution_scope(None); fixture.set_execution_scope(None)
    receipt = {"schema": "genewhip-v02-runtime-observation-v1", "status": "pass", "mode": mode,
        "scope_id": scope["scope_id"], "source_sha256": plan["source_sha256"],
        "git_head": plan["git_head"], "build_identity": plan["build_identity"],
        "launch_identities": plan["launch_identities"], "historical_window_access": False,
        "current_execution_identity": current_identity,
        "isolation_preflight": isolation, "observed": rows,
        "process_records": (scoped_state or {}).get("process_records", []),
        "process_group_cleanup": "confirmed", "capabilities": {"native": "observed" if mode == "full" else "not-requested"}}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    return receipt


_NATIVE_DIAGNOSTIC_FIXTURE = "recursion94"
_NATIVE_DIAGNOSTIC_CASE = "withhold-first-plate"
_NATIVE_DIAGNOSTIC_SELECTOR = "recursion94-withhold-first-plate"
_NATIVE_DIAGNOSTIC_STAGES = ("input-contract", "headless-reference", "native-sdl-comparison")
_NATIVE_DIAGNOSTIC_INPUT_MASKS = (8, 0, 8, 0, 8, 0, 32, 0, 8, 0, 32, 0, 1, 0, 8, 0, 2, 0, 16,
    2, 0, 16, 0)
_NATIVE_DIAGNOSTIC_ROUTE_MASKS = (8, 0, 8, 0, 32, 0, 8, 0, 32, 0, 1, 0, 8, 0, 2, 0, 16, 0)
_NATIVE_PREFIX_CASES = ("full-route", "withhold-first-plate")
_NATIVE_PREFIX_STAGES = ("input-contract", "headless-reference", "native-comparison")
_NATIVE_PREFIX_ROUTE_MASKS = {
    "full-route": (8, 0, 8, 0, 8, 0, 32, 0, 8, 0, 32, 0, 1, 0, 8, 0, 2, 0, 16, 0),
    "withhold-first-plate": _NATIVE_DIAGNOSTIC_ROUTE_MASKS,
}
_NATIVE_PREFIX_INPUT_COUNTS = {"full-route": 20, "withhold-first-plate": 18}
_NATIVE_PREFIX_EXPECTED_PREDICATES = {
    "full-route": {"early_dependency_interaction": (True, 1, 17),
        "two_echoes_at_boot_cap": (True, 2, 1441), "crossed_generated_door": (True, 1, 3530),
        "late_program_stable": (True, 1, 3600)},
    "withhold-first-plate": {"early_dependency_interaction": (False, 0, 0),
        "two_echoes_at_boot_cap": (True, 2, 1441), "crossed_generated_door": (True, 1, 3530),
        "late_program_stable": (True, 1, 3600)},
}
_NATIVE_PREFIX_SELECTOR = "recursion94-native-prefix"


def _diagnostic_process_projection(process: object) -> dict:
    process = process if isinstance(process, dict) else {}
    rc = process.get("return_code")
    return {"return_code": "missing" if "return_code" not in process else
            "untyped" if type(rc) is not int else "zero" if rc == 0 else
            "signaled" if rc < 0 else "nonzero",
        "status": process.get("status") if process.get("status") in
            ("completed", "failed", "timeout", "unconfirmed") else "unavailable",
        "cleanup": process.get("process_group_cleanup") if process.get("process_group_cleanup") in
            ("confirmed", "unconfirmed") else "unavailable",
        "bound_violation": process.get("bound_violation") if type(process.get("bound_violation")) is bool else None}


def safe_native_diagnostic(record: object, outer_attempt: object = None) -> dict:
    """Return a fixed-schema diagnostic view; never copy raw paths or media metadata."""
    record = record if isinstance(record, dict) else {}
    stages_in = record.get("stages") if isinstance(record.get("stages"), list) else []
    stages = []
    for index, stage_name in enumerate(_NATIVE_DIAGNOSTIC_STAGES):
        row = stages_in[index] if index < len(stages_in) and isinstance(stages_in[index], dict) else {}
        status = row.get("status") if row.get("status") in ("pass", "fail", "not-run") else (
            "not-run" if not row else "unavailable")
        projection = {"name": stage_name, "status": status,
            "process": _diagnostic_process_projection(row.get("process"))}
        if stage_name == "input-contract":
            proof = row.get("proof") if isinstance(row.get("proof"), dict) else {}
            raw_masks = proof.get("masks")
            raw_observations = proof.get("observations")
            masks = raw_masks if isinstance(raw_masks, list) else []
            observations = raw_observations if isinstance(raw_observations, list) else []
            projection["input"] = {"requested_count": proof.get("requested_count") if
                    type(proof.get("requested_count")) is int and 0 <= proof["requested_count"] <= 23 else
                    "missing" if "requested_count" not in proof else "untyped-or-out-of-range",
                "outcome": proof.get("outcome") if proof.get("outcome") in ("pass", "fail") else "unavailable",
                "port_isolation_verified": proof.get("port_isolation_verified") if
                    type(proof.get("port_isolation_verified")) is bool else None,
                "masks": [value if type(value) is int and 0 <= value <= 255 else
                    "untyped" if type(value) is not int else "out-of-range" for value in masks[:23]],
                "mask_validity": [type(value) is int and 0 <= value <= 255 for value in masks[:23]],
                "mask_count": len(masks) if isinstance(raw_masks, list) and len(masks) <= 100000 else
                    "overrange" if isinstance(raw_masks, list) else "missing" if raw_masks is None else "untyped",
                "observations_count": len(observations) if isinstance(raw_observations, list) and len(observations) <= 100000 else
                    "overrange" if isinstance(raw_observations, list) else "missing" if raw_observations is None else "untyped",
                "observations_truncated": len(observations) > 23,
                "observations": [{key: item[key] if type(item.get(key)) is int and 0 <= item[key] <= 255 else
                    "missing" if item.get(key) is None else
                    "untyped" if type(item.get(key)) is not int else "out-of-range"
                    for key in ("requested_mask", "effective_mask", "joystick_mask") if key in item}
                    for item in observations[:23] if isinstance(item, dict)]}
        elif stage_name == "headless-reference":
            facts = row.get("facts") if isinstance(row.get("facts"), dict) else {}
            projection["route"] = _safe_route_facts(facts)
        else:
            facts = row.get("facts") if isinstance(row.get("facts"), dict) else {}
            projection["comparison"] = _safe_host_facts(facts)
        stages.append(projection)
    outer_process = None
    if isinstance(outer_attempt, dict):
        processes = outer_attempt.get("processes")
        if isinstance(processes, list) and len(processes) == 1 and isinstance(processes[0], dict):
            outer_process = processes[0]
    outer = _diagnostic_process_projection(outer_process)
    exact_stages = (len(stages_in) == 3 and len(stages) == 3 and all(
        isinstance(raw, dict) and raw.get("name") == expected
        for raw, expected in zip(stages_in, _NATIVE_DIAGNOSTIC_STAGES)))
    if exact_stages:
        for row in stages:
            process = row.get("process") if isinstance(row.get("process"), dict) else {}
            if not (row.get("status") == "pass" and process.get("status") == "completed" and
                    process.get("return_code") == "zero" and process.get("cleanup") == "confirmed" and
                    process.get("bound_violation") is False):
                exact_stages = False
    outer_return = outer_attempt.get("returncode") if isinstance(outer_attempt, dict) else None
    outer_ok = (outer.get("status") == "completed" and outer.get("return_code") == "zero" and
        type(outer_return) is int and outer_return == 0 and outer.get("cleanup") == "confirmed" and
        outer.get("bound_violation") is False and
        isinstance(outer_attempt, dict) and outer_attempt.get("launch_error") is None and
        outer_attempt.get("process_group_cleanup") == "confirmed")
    failure_value = record.get("failure_category")
    failure = failure_value if type(failure_value) is str and failure_value in {
        "input-or-evidence-invalid", "bounded-workload-failed", "bounded-workload-timeout",
        "bounded-workload-io-failed", "required-evidence-missing", "evidence-shape-invalid",
        "native-sdl-comparison-failed", "diagnostic-stage-failed"} else None
    return {"schema": "genewhip-phase7-one-case-diagnostic-v2", "status":
            "pass" if record.get("status") == "pass" and exact_stages and outer_ok else "fail",
        "diagnostic_only": True, "qualification_accepted": False,
        "fixture": _NATIVE_DIAGNOSTIC_FIXTURE, "case": _NATIVE_DIAGNOSTIC_CASE,
        "failure_category": failure, "stages": stages, "outer_process": outer,
        "collector_read_status": "valid"}


_NATIVE_HANDOFF_SCHEMA = "genewhip-phase7-one-case-diagnostic-handoff.v1"
_NATIVE_HANDOFF_READ_STATES = ("valid", "missing", "oversized", "unsafe", "invalid")


def native_diagnostic_handoff(record: object) -> dict:
    """Make a small private handoff while the full collector record is in memory."""
    projected = safe_native_diagnostic(record)
    original = record if isinstance(record, dict) else {}
    status = original.get("status") if original.get("status") in ("pass", "fail") else "fail"
    return {"schema": _NATIVE_HANDOFF_SCHEMA, "collector_status": status,
        "failure_category": projected["failure_category"], "stages": projected["stages"]}


def complete_native_diagnostic_handoff(handoff: object, outer_attempt: object,
                                       read_status: str = "valid", identity: object = None,
                                       outer_rejection: str | None = None) -> dict:
    """Combine safe collector facts with the actual outer receipt, without upgrading either."""
    valid_states = _NATIVE_HANDOFF_READ_STATES
    if read_status not in valid_states:
        read_status = "invalid"
    allowed_failures = {"input-or-evidence-invalid", "bounded-workload-failed",
        "bounded-workload-timeout", "bounded-workload-io-failed", "required-evidence-missing",
        "evidence-shape-invalid", "native-sdl-comparison-failed", "diagnostic-stage-failed"}
    structurally_valid = (read_status == "valid" and isinstance(handoff, dict)
        and set(handoff) == {"schema", "collector_status", "failure_category", "stages"}
        and handoff.get("schema") == _NATIVE_HANDOFF_SCHEMA
        and handoff.get("collector_status") in ("pass", "fail")
        and (handoff.get("failure_category") is None or
            (type(handoff.get("failure_category")) is str and handoff.get("failure_category") in allowed_failures))
        and isinstance(handoff.get("stages"), list) and len(handoff["stages"]) == 3)
    stages = handoff["stages"] if structurally_valid else []
    stages_valid = structurally_valid and all(
        isinstance(stage, dict) and stage.get("name") == expected and
        stage.get("status") in ("pass", "fail", "not-run") and
        isinstance(stage.get("process"), dict)
        for stage, expected in zip(stages, _NATIVE_DIAGNOSTIC_STAGES))
    if not stages_valid:
        read_status = "invalid" if read_status == "valid" else read_status
        stages = _unavailable_native_diagnostic_stages()
    outer_report = safe_native_diagnostic({"status": "fail", "stages": []}, outer_attempt)
    outer = outer_report["outer_process"]
    outer_return = outer_attempt.get("returncode") if isinstance(outer_attempt, dict) else None
    outer_ok = (outer.get("status") == "completed" and outer.get("return_code") == "zero"
        and type(outer_return) is int and outer_return == 0 and outer.get("cleanup") == "confirmed"
        and outer.get("bound_violation") is False and isinstance(outer_attempt, dict)
        and outer_attempt.get("launch_error") is None and outer_attempt.get("process_group_cleanup") == "confirmed")
    all_stages_pass = len(stages) == 3 and all(
        stage.get("status") == "pass" and stage["process"].get("status") == "completed"
        and stage["process"].get("return_code") == "zero" and
        stage["process"].get("cleanup") == "confirmed" and stage["process"].get("bound_violation") is False
        for stage in stages)
    category = handoff.get("failure_category") if structurally_valid else None
    if read_status != "valid":
        category = {"missing": "collector-handoff-missing", "oversized": "collector-handoff-oversized",
            "unsafe": "collector-handoff-unsafe", "invalid": "collector-handoff-invalid"}[read_status]
    elif handoff["collector_status"] == "fail" and category is None:
        category = "evidence-shape-invalid"
    identity_keys = {"source_sha", "head_sha", "base_sha", "run_id", "run_attempt"}
    result = {"schema": "genewhip-phase7-one-case-diagnostic-v2",
        "status": "pass" if read_status == "valid" and handoff["collector_status"] == "pass"
            and all_stages_pass and outer_ok and outer_rejection is None else "fail",
        "diagnostic_only": True, "qualification_accepted": False,
        "fixture": _NATIVE_DIAGNOSTIC_FIXTURE, "case": _NATIVE_DIAGNOSTIC_CASE,
        "failure_category": category, "stages": stages, "outer_process": outer,
        "outer_rejection": outer_rejection, "collector_read_status": read_status,
        "identity": identity}
    try:
        if not isinstance(identity, dict) or set(identity) != identity_keys:
            raise ValueError("identity")
        validate_native_diagnostic_public(result, identity)
    except (TypeError, ValueError, KeyError):
        # Do not copy any malformed failed-stage payload to the downloadable report.
        result.update({"status": "fail", "failure_category": "collector-handoff-invalid",
            "collector_read_status": "invalid", "outer_rejection": outer_rejection,
            "stages": _unavailable_native_diagnostic_stages()})
        validate_native_diagnostic_public(result, identity)
    return result


def _unavailable_native_diagnostic_stages() -> list[dict]:
    return [{"name": name, "status": "unavailable", "process": _diagnostic_process_projection(None),
        "input": {"requested_count": "missing", "outcome": "unavailable",
            "port_isolation_verified": None, "masks": [], "mask_validity": [],
            "mask_count": "missing", "observations_count": "missing",
            "observations_truncated": False, "observations": []}} if index == 0 else
        {"name": name, "status": "unavailable", "process": _diagnostic_process_projection(None),
            ("route" if index == 1 else "comparison"): (_safe_route_facts({}) if index == 1 else
                _safe_host_facts({}))}
        for index, name in enumerate(_NATIVE_DIAGNOSTIC_STAGES)]


def validate_native_diagnostic_public(report: object, expected_identity: object) -> bool:
    """Validate the fixed public diagnostic payload before accepting downloaded bytes.

    Raises one fixed ValueError on any schema, identity, or bound mismatch. This
    validates the report as emitted; it never sanitizes or upgrades untrusted data.
    """
    label = "phase7-native-diagnostic-public-report-invalid"
    top_keys = {"schema", "status", "diagnostic_only", "qualification_accepted", "fixture", "case",
        "failure_category", "stages", "outer_process", "identity", "outer_rejection", "collector_read_status"}
    identity_keys = {"source_sha", "head_sha", "base_sha", "run_id", "run_attempt"}
    if not isinstance(report, dict) or set(report) != top_keys:
        raise ValueError(label)
    if not isinstance(expected_identity, dict) or set(expected_identity) != identity_keys:
        raise ValueError(label)
    identity = report.get("identity")
    if (not isinstance(identity, dict) or set(identity) != identity_keys
            or identity != expected_identity
            or any(not isinstance(identity.get(key), str) or not identity[key] for key in identity_keys)
            or any(re.fullmatch(r"[0-9a-f]{40}", identity[key]) is None
                   for key in ("source_sha", "head_sha", "base_sha"))
            or re.fullmatch(r"[0-9]+", identity["run_id"]) is None
            or identity["run_attempt"] != "1"):
        raise ValueError(label)
    if (report.get("schema") != "genewhip-phase7-one-case-diagnostic-v2"
            or report.get("diagnostic_only") is not True
            or report.get("qualification_accepted") is not False
            or report.get("fixture") != _NATIVE_DIAGNOSTIC_FIXTURE
            or report.get("case") != _NATIVE_DIAGNOSTIC_CASE
            or report.get("status") not in ("pass", "fail")
            or report.get("collector_read_status") not in _NATIVE_HANDOFF_READ_STATES
            or report.get("outer_rejection") not in (None, "outer-boundary-rejected")
            or report.get("failure_category") not in (None,
                "input-or-evidence-invalid", "bounded-workload-failed", "bounded-workload-timeout",
                "bounded-workload-io-failed", "required-evidence-missing", "evidence-shape-invalid",
                "native-sdl-comparison-failed", "diagnostic-stage-failed", "collector-handoff-missing",
                "collector-handoff-oversized", "collector-handoff-unsafe", "collector-handoff-invalid")):
        raise ValueError(label)
    read_failure_categories = {"missing": "collector-handoff-missing", "oversized": "collector-handoff-oversized",
        "unsafe": "collector-handoff-unsafe", "invalid": "collector-handoff-invalid"}
    read_status = report["collector_read_status"]
    if ((read_status == "valid" and report["failure_category"] in read_failure_categories.values()) or
            (read_status != "valid" and report["failure_category"] != read_failure_categories[read_status])):
        raise ValueError(label)
    try:
        if len(json.dumps(report, ensure_ascii=True, separators=(",", ":")).encode("utf-8")) > 65536:
            raise ValueError(label)
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ValueError(label) from None

    def bounded(value: object, maximum: int = 100_000_000) -> bool:
        return type(value) is int and 0 <= value <= maximum

    def bounded_or(value: object, sentinels: tuple[str, ...], maximum: int = 100_000) -> bool:
        return bounded(value, maximum) or value in sentinels

    def process_ok_shape(value: object) -> bool:
        return (isinstance(value, dict) and set(value) ==
                {"return_code", "status", "cleanup", "bound_violation"}
                and type(value.get("return_code")) is str and value.get("return_code") in ("zero", "nonzero", "signaled", "missing", "untyped")
                and value.get("status") in ("completed", "failed", "timeout", "unconfirmed", "unavailable")
                and value.get("cleanup") in ("confirmed", "unconfirmed", "unavailable")
                and (type(value.get("bound_violation")) is bool or value.get("bound_violation") is None))

    def mask_event(value: object, client: str) -> bool:
        if not isinstance(value, dict):
            return False
        if set(value) == {"index", "port", "mask_status"}:
            return bounded(value.get("index"), 63) and value.get("port") == "untyped" and value.get("mask_status") == "untyped"
        keys = {"index", "port", "requested_mask", "requested_mask_valid", "effective_mask",
            "effective_mask_valid", "joystick_mask", "joystick_mask_valid", "handler"}
        if set(value) != keys:
            return False
        scalar = lambda item: (type(item) is int and 0 <= item <= 255) or item in (
            "missing", "untyped", "out-of-range", "not-reported")
        return (bounded(value.get("index"), 63)
            and ((type(value.get("port")) is int and value["port"] in (0, 1))
                or value.get("port") in ("missing", "untyped", "out-of-range"))
            and scalar(value.get("requested_mask")) and type(value.get("requested_mask_valid")) is bool
            and scalar(value.get("effective_mask")) and type(value.get("effective_mask_valid")) is bool
            and scalar(value.get("joystick_mask"))
            and (type(value.get("joystick_mask_valid")) is bool or value.get("joystick_mask_valid") is None)
            and value.get("handler") in (("not-reported",) if client != "host" else
                ("sdl-gamepad-sample-port", "other", "missing")))

    def event_list(value: object, client: str, cap: int) -> bool:
        return isinstance(value, list) and len(value) <= cap and all(mask_event(item, client) for item in value)

    def count_or_state(value: object) -> bool:
        return bounded_or(value, ("missing", "untyped", "overrange"))

    outer = report.get("outer_process")
    stages = report.get("stages")
    if not process_ok_shape(outer) or not isinstance(stages, list) or len(stages) != 3:
        raise ValueError(label)
    stage_passes = []
    for index, (stage, expected_name) in enumerate(zip(stages, _NATIVE_DIAGNOSTIC_STAGES)):
        if not isinstance(stage, dict) or stage.get("name") != expected_name:
            raise ValueError(label)
        expected_keys = {"name", "status", "process", "input"} if index == 0 else (
            {"name", "status", "process", "route"} if index == 1 else
            {"name", "status", "process", "comparison"})
        if (set(stage) != expected_keys or stage.get("status") not in ("pass", "fail", "not-run", "unavailable")
                or not process_ok_shape(stage.get("process"))):
            raise ValueError(label)
        stage_passes.append(stage["status"] == "pass")
        if index == 0:
            value = stage["input"]
            keys = {"requested_count", "outcome", "port_isolation_verified", "masks", "mask_validity",
                "mask_count", "observations_count", "observations_truncated", "observations"}
            if (not isinstance(value, dict) or set(value) != keys
                    or not (bounded(value["requested_count"], 23) or value["requested_count"] in
                        ("missing", "untyped-or-out-of-range"))
                    or value["outcome"] not in ("pass", "fail", "unavailable")
                    or (type(value["port_isolation_verified"]) is not bool
                        and value["port_isolation_verified"] is not None)
                    or not isinstance(value["masks"], list) or len(value["masks"]) > 23
                    or any(not ((type(item) is int and 0 <= item <= 255) or item in
                        ("untyped", "out-of-range")) for item in value["masks"])
                    or not isinstance(value["mask_validity"], list)
                    or len(value["mask_validity"]) != len(value["masks"])
                    or any(type(item) is not bool for item in value["mask_validity"])
                    or not count_or_state(value["mask_count"])
                    or not count_or_state(value["observations_count"])
                    or type(value["observations_truncated"]) is not bool
                    or not isinstance(value["observations"], list) or len(value["observations"]) > 23):
                raise ValueError(label)
            for observation in value["observations"]:
                if (not isinstance(observation, dict)
                        or not set(observation).issubset({"requested_mask", "effective_mask", "joystick_mask"})
                        or any(not ((type(item) is int and 0 <= item <= 255) or item in
                            ("missing", "untyped", "out-of-range")) for item in observation.values())):
                    raise ValueError(label)
        elif index == 1:
            value = stage["route"]
            keys = {"status", "active_ticks", "fields", "boundary_calls", "input_event_count",
                "input_events", "input_events_truncated", "predicate_count", "predicates"}
            if (not isinstance(value, dict) or set(value) != keys
                    or not ((type(value["status"]) is int and value["status"] in (0, 1))
                        or value["status"] == "unavailable")
                    or any(item is not None and not bounded(item) for item in
                        (value["active_ticks"], value["fields"], value["boundary_calls"]))
                    or not count_or_state(value["input_event_count"])
                    or not event_list(value["input_events"], "core", 64)
                    or type(value["input_events_truncated"]) is not bool
                    or not count_or_state(value["predicate_count"])
                    or not isinstance(value["predicates"], list) or len(value["predicates"]) != 4
                    or any(not isinstance(item, dict) or set(item) != {"id", "reached", "value", "field"}
                        or item["id"] not in ("early_dependency_interaction", "two_echoes_at_boot_cap",
                            "crossed_generated_door", "late_program_stable")
                        or (type(item["reached"]) is not bool and item["reached"] is not None)
                        or not bounded_or(item["value"], ("missing", "untyped", "overrange"))
                        or not bounded_or(item["field"], ("missing", "untyped", "overrange"))
                        for item in value["predicates"])
                    or {item["id"] for item in value["predicates"]} != {
                        "early_dependency_interaction", "two_echoes_at_boot_cap",
                        "crossed_generated_door", "late_program_stable"}):
                raise ValueError(label)
        else:
            value = stage["comparison"]
            keys = {"status", "core_outcome", "host_outcome", "input_equal", "input_rows",
                "native_status", "observed_clocks", "core_input_count", "host_input_count",
                "native_input_events", "native_input_events_truncated", "host_input_events",
                "host_input_events_truncated", "reason", "failure_presence", "source_samples_equal",
                "renderer_pixel_equal", "full_pcm_equal", "renderer_readback", "audio_device_activity",
                "audio_submitted_frames", "audio_consumed_frames"}
            bool_or_none = lambda item: type(item) is bool or item is None
            if (not isinstance(value, dict) or set(value) != keys
                    or value["status"] not in ("pass", "fail", "unavailable")
                    or value["core_outcome"] not in ("pass", "fail", "unavailable")
                    or value["host_outcome"] not in ("pass-diagnostic", "fail-diagnostic", "fail", "unavailable")
                    or not bool_or_none(value["input_equal"])
                    or not isinstance(value["input_rows"], list) or len(value["input_rows"]) > 64
                    or not ((type(value["native_status"]) is int and value["native_status"] in (0, 1))
                        or value["native_status"] == "unavailable")
                    or not isinstance(value["observed_clocks"], dict)
                    or set(value["observed_clocks"]) != {"active_ticks", "fields", "boundary_calls"}
                    or any(item is not None and not bounded(item) for item in value["observed_clocks"].values())
                    or not count_or_state(value["core_input_count"]) or not count_or_state(value["host_input_count"])
                    or not event_list(value["native_input_events"], "native-host", 64)
                    or type(value["native_input_events_truncated"]) is not bool
                    or not event_list(value["host_input_events"], "host", 64)
                    or type(value["host_input_events_truncated"]) is not bool
                    or value["reason"] not in (None, "core-input-progress-or-common-boundary-mismatch",
                        "host-renderer-pcm-or-device-mismatch", "other")
                    or not isinstance(value["failure_presence"], dict)
                    or set(value["failure_presence"]) != {"capture_field_matches", "renderer_named",
                        "video_driver_named", "audio_driver_named"}
                    or any(not bool_or_none(item) for item in value["failure_presence"].values())
                    or any(not bool_or_none(value[key]) for key in ("source_samples_equal", "renderer_pixel_equal",
                        "full_pcm_equal", "renderer_readback", "audio_device_activity"))
                    or any(item is not None and not bounded(item) for item in
                        (value["audio_submitted_frames"], value["audio_consumed_frames"]))):
                raise ValueError(label)
            for item in value["input_rows"]:
                if (not isinstance(item, dict) or not {"index", "equal"}.issubset(item)
                        or not set(item).issubset({"index", "equal", "port", "desired", "effective"})
                        or not bounded(item.get("index"), 63) or type(item.get("equal")) is not bool
                        or any(key in item and not bounded(item[key], 255)
                            for key in ("port", "desired", "effective"))):
                    raise ValueError(label)
    outer_pass = (outer["status"] == "completed" and outer["return_code"] == "zero"
        and outer["cleanup"] == "confirmed" and outer["bound_violation"] is False
        and report["outer_rejection"] is None)
    if report["status"] == "pass":
        input_facts = stages[0]["input"]
        route_facts = stages[1]["route"]
        comparison = stages[2]["comparison"]
        input_pass = (input_facts["outcome"] == "pass"
            and input_facts["requested_count"] == 23
            and len(input_facts["masks"]) == 23
            and all(input_facts["mask_validity"])
            and input_facts["port_isolation_verified"] is True
            and input_facts["observations_count"] == 23
            and not input_facts["observations_truncated"]
            and len(input_facts["observations"]) == 23
            and input_facts["masks"] == list(_NATIVE_DIAGNOSTIC_INPUT_MASKS)
            and input_facts["mask_validity"] == [True for _ in _NATIVE_DIAGNOSTIC_INPUT_MASKS]
            and all(type(observation.get("requested_mask")) is int
                and observation["requested_mask"] == mask
                and type(observation.get("effective_mask")) is int
                and observation["effective_mask"] == mask
                and type(observation.get("joystick_mask")) is int
                and observation["joystick_mask"] == mask
                for index, (observation, mask) in enumerate(zip(input_facts["observations"],
                    _NATIVE_DIAGNOSTIC_INPUT_MASKS))))
        predicate_map = {item["id"]: item for item in route_facts["predicates"]}
        expected_predicates = {
            "early_dependency_interaction": (False, 0, 0),
            "two_echoes_at_boot_cap": (True, 2, 1441),
            "crossed_generated_door": (True, 1, 3530),
            "late_program_stable": (True, 1, 3600),
        }
        route_pass = (type(route_facts["status"]) is int and route_facts["status"] == 0
            and route_facts["input_event_count"] == 18
            and len(route_facts["input_events"]) == 18
            and route_facts["input_events_truncated"] is False
            and [event["requested_mask"] for event in route_facts["input_events"]] ==
                list(_NATIVE_DIAGNOSTIC_ROUTE_MASKS)
            and [event["effective_mask"] for event in route_facts["input_events"]] ==
                list(_NATIVE_DIAGNOSTIC_ROUTE_MASKS)
            and all(type(event["port"]) is int and event["port"] == 0
                for event in route_facts["input_events"])
            and route_facts["predicate_count"] == 4
            and all((predicate_map[key]["reached"], predicate_map[key]["value"],
                predicate_map[key]["field"]) == expected for key, expected in expected_predicates.items())
            and route_facts["active_ticks"] == 3600
            and type(route_facts["fields"]) is int and 0 <= route_facts["fields"] <= 7200
            and type(route_facts["boundary_calls"]) is int
            and 0 <= route_facts["boundary_calls"] <= 100_000_000)
        rows = comparison["input_rows"]
        comparison_pass = (comparison["status"] == "pass"
            and comparison["core_outcome"] == "pass"
            and comparison["host_outcome"] == "pass-diagnostic"
            and comparison["input_equal"] is True
            and comparison["source_samples_equal"] is True
            and comparison["renderer_pixel_equal"] is True
            and comparison["full_pcm_equal"] is True
            and comparison["renderer_readback"] is True
            and comparison["audio_device_activity"] is True
            and type(comparison["audio_submitted_frames"]) is int
            and comparison["audio_submitted_frames"] > 0
            and type(comparison["audio_consumed_frames"]) is int
            and comparison["audio_consumed_frames"] > 0
            and type(comparison["native_status"]) is int and comparison["native_status"] == 0
            and comparison["observed_clocks"]["active_ticks"] == 3600
            and comparison["core_input_count"] == 18
            and comparison["host_input_count"] == 18
            and len(comparison["native_input_events"]) == 18
            and len(comparison["host_input_events"]) == 18
            and not comparison["native_input_events_truncated"]
            and not comparison["host_input_events_truncated"]
            and len(rows) == 18 and all(row["index"] == index and row["equal"] is True
                and type(row.get("port")) is int and row["port"] == 0
                and type(row.get("desired")) is int and type(row.get("effective")) is int
                for index, row in enumerate(rows))
            and [row["desired"] for row in rows] == list(_NATIVE_DIAGNOSTIC_ROUTE_MASKS)
            and [row["effective"] for row in rows] == list(_NATIVE_DIAGNOSTIC_ROUTE_MASKS)
            and all(event["port"] in (0, 1) and type(event["port"]) is int
                for event in comparison["native_input_events"] + comparison["host_input_events"])
            and all(row["port"] == native_event["port"] == host_event["port"]
                and row["desired"] == native_event["requested_mask"] == host_event["requested_mask"]
                and row["effective"] == native_event["effective_mask"] == host_event["effective_mask"]
                for row, native_event, host_event in zip(rows,
                    comparison["native_input_events"], comparison["host_input_events"])))
        comparison_pass = (comparison_pass
            and all(event["requested_mask_valid"] and event["effective_mask_valid"]
                and event["joystick_mask"] == "not-reported" and event["joystick_mask_valid"] is None
                for event in comparison["native_input_events"])
            and all(event["requested_mask_valid"] and event["effective_mask_valid"]
                and event["joystick_mask_valid"] and event["joystick_mask"] == event["requested_mask"]
                and event["handler"] == "sdl-gamepad-sample-port"
                for event in comparison["host_input_events"]))
        if (report["failure_category"] is not None or not all(stage_passes) or not outer_pass
                or not input_pass or not route_pass or not comparison_pass
                or any(stage["process"]["status"] != "completed"
                    or stage["process"]["return_code"] != "zero"
                    or stage["process"]["cleanup"] != "confirmed"
                    or stage["process"]["bound_violation"] is not False for stage in stages)):
            raise ValueError(label)
    elif all(stage_passes) and outer_pass and report["outer_rejection"] is None:
        raise ValueError(label)
    return True


def _safe_route_facts(facts: dict) -> dict:
    native = facts.get("native") if isinstance(facts.get("native"), dict) else {}
    events = native.get("inputs") if isinstance(native.get("inputs"), list) else []
    safe_events = _safe_mask_events(events, "core")
    row = facts.get("row") if isinstance(facts.get("row"), dict) else {}
    predicates = row.get("predicate_results") if isinstance(row.get("predicate_results"), dict) else {}
    predicate_rows = []
    for predicate_id in ("early_dependency_interaction", "two_echoes_at_boot_cap",
            "crossed_generated_door", "late_program_stable"):
        value = predicates.get(predicate_id)
        if not isinstance(value, dict):
            predicate_rows.append({"id": predicate_id, "reached": None, "value": "missing", "field": "missing"})
        else:
            predicate_rows.append({"id": predicate_id,
                "reached": value.get("reached") if type(value.get("reached")) is bool else None,
                "value": _bounded_counter(value.get("value")) if type(value.get("value")) is int else "untyped",
                "field": _bounded_counter(value.get("field")) if type(value.get("field")) is int else "untyped"})
    return {"status": _fixed_status(native.get("status")),
        "active_ticks": _bounded_counter(native.get("active_ticks")),
        "fields": _bounded_counter(native.get("fields")),
        "boundary_calls": _bounded_counter(native.get("boundary_calls")),
        "input_event_count": (len(events) if len(events) <= 100000 else "overrange") if isinstance(native.get("inputs"), list)
            else "missing" if "inputs" not in native else "untyped",
        "input_events": safe_events["events"], "input_events_truncated": safe_events["truncated"],
        "predicate_count": len(predicates) if len(predicates) <= 100000 else "overrange",
        "predicates": predicate_rows}


def _safe_host_facts(facts: dict) -> dict:
    row = facts.get("row") if isinstance(facts.get("row"), dict) else {}
    boundary = row.get("common_boundary") if isinstance(row.get("common_boundary"), dict) else {}
    inputs = boundary.get("inputs") if isinstance(boundary.get("inputs"), dict) else {}
    input_rows = inputs.get("rows") if isinstance(inputs.get("rows"), list) else []
    raw_outputs = row.get("raw_outputs") if isinstance(row.get("raw_outputs"), dict) else {}
    native_report = _read_native_diagnostic_json(raw_outputs.get("native"))
    host_report = _read_native_diagnostic_json(raw_outputs.get("host"))
    native_events = native_report.get("inputs") if isinstance(native_report.get("inputs"), list) else []
    host_events = host_report.get("input_events") if isinstance(host_report.get("input_events"), list) else []
    native_safe = _safe_mask_events(native_events, "native-host")
    host_safe = _safe_mask_events(host_events, "host")
    reason = row.get("reason")
    allowed_reasons = (None, "core-input-progress-or-common-boundary-mismatch",
        "host-renderer-pcm-or-device-mismatch")
    failure = row.get("failure_diagnostic") if isinstance(row.get("failure_diagnostic"), dict) else {}
    return {"status": row.get("status") if row.get("status") in ("pass", "fail") else "unavailable",
        "core_outcome": row.get("core_outcome") if row.get("core_outcome") in ("pass", "fail") else "unavailable",
        "host_outcome": row.get("host_outcome") if row.get("host_outcome") in
            ("pass-diagnostic", "fail-diagnostic", "fail", "unavailable") else "unavailable",
        "input_equal": inputs.get("equal") if type(inputs.get("equal")) is bool else None,
        "input_rows": [{"index": item["index"], "equal": item["equal"],
            **{key: item[key] for key in ("port", "desired", "effective")
               if type(item.get(key)) is int and 0 <= item[key] <= 255}}
            for item in input_rows[:64] if isinstance(item, dict) and
                type(item.get("index")) is int and 0 <= item["index"] < 64
                and type(item.get("equal")) is bool],
        "native_status": _fixed_status(native_report.get("status")),
        "observed_clocks": {key: _bounded_counter(native_report.get(key))
            for key in ("active_ticks", "fields", "boundary_calls")},
        "core_input_count": (len(native_events) if len(native_events) <= 100000 else "overrange")
            if isinstance(native_report.get("inputs"), list) else
            "missing" if "inputs" not in native_report else "untyped",
        "host_input_count": (len(host_events) if len(host_events) <= 100000 else "overrange")
            if isinstance(host_report.get("input_events"), list) else
            "missing" if "input_events" not in host_report else "untyped",
        "native_input_events": native_safe["events"],
        "native_input_events_truncated": native_safe["truncated"],
        "host_input_events": host_safe["events"],
        "host_input_events_truncated": host_safe["truncated"],
        "reason": reason if reason in allowed_reasons else "other",
        "failure_presence": {key: failure.get(key) if type(failure.get(key)) is bool else None
            for key in ("capture_field_matches", "renderer_named", "video_driver_named", "audio_driver_named")},
        "source_samples_equal": boundary.get("source_samples_equal") if type(boundary.get("source_samples_equal")) is bool else None,
        "renderer_pixel_equal": boundary.get("renderer_pixel_equal") if type(boundary.get("renderer_pixel_equal")) is bool else None,
        "full_pcm_equal": boundary.get("full_pcm_equal") if type(boundary.get("full_pcm_equal")) is bool else None,
        "renderer_readback": row.get("renderer", {}).get("renderer_readback_activity")
            if isinstance(row.get("renderer"), dict) and type(row["renderer"].get("renderer_readback_activity")) is bool else None,
        "audio_device_activity": row.get("audio", {}).get("audio_device_activity")
            if isinstance(row.get("audio"), dict) and type(row["audio"].get("audio_device_activity")) is bool else None,
        "audio_submitted_frames": _bounded_counter(row.get("audio", {}).get("audio_submitted_frames")
            if isinstance(row.get("audio"), dict) else None),
        "audio_consumed_frames": _bounded_counter(row.get("audio", {}).get("audio_device_consumed_frames")
            if isinstance(row.get("audio"), dict) else None)}


def _safe_prefix_input_stage(stage: object) -> dict:
    stage = stage if isinstance(stage, dict) else {}
    proof = stage.get("proof") if isinstance(stage.get("proof"), dict) else {}
    masks = proof.get("masks") if isinstance(proof.get("masks"), list) else []
    observations = proof.get("observations") if isinstance(proof.get("observations"), list) else []
    return {"name": "input-contract",
        "status": stage.get("status") if stage.get("name") == "input-contract"
            and stage.get("status") in ("pass", "fail") else "unavailable",
        "process": _diagnostic_process_projection(stage.get("process")),
        "input": {"requested_count": proof.get("requested_count") if
                type(proof.get("requested_count")) is int and 0 <= proof["requested_count"] <= 23 else
                "missing" if "requested_count" not in proof else "untyped-or-out-of-range",
            "outcome": proof.get("outcome") if proof.get("outcome") in ("pass", "fail") else "unavailable",
            "port_isolation_verified": proof.get("port_isolation_verified") if
                type(proof.get("port_isolation_verified")) is bool else None,
            "masks": [value if type(value) is int and 0 <= value <= 255 else
                "untyped" if type(value) is not int else "out-of-range" for value in masks[:23]],
            "mask_validity": [type(value) is int and 0 <= value <= 255 for value in masks[:23]],
            "mask_count": len(masks) if len(masks) <= 100000 else "overrange",
            "observations_count": len(observations) if len(observations) <= 100000 else "overrange",
            "observations_truncated": len(observations) > 23,
            "observations": [{key: item[key] if type(item.get(key)) is int and 0 <= item[key] <= 255 else
                "missing" if item.get(key) is None else
                "untyped" if type(item.get(key)) is not int else "out-of-range"
                for key in ("requested_mask", "effective_mask", "joystick_mask") if key in item}
                for item in observations[:23] if isinstance(item, dict)]}}


def safe_native_prefix_diagnostic(record: object, outer_attempt: object = None,
                                  identity: object = None, outer_rejection: str | None = None,
                                  collector_read_status: str = "valid") -> dict:
    """Project the fixed two-case prefix collector without exposing raw artifacts."""
    record = record if isinstance(record, dict) else {}
    raw_stages = record.get("stages") if isinstance(record.get("stages"), list) else []
    raw_shape_valid = len(raw_stages) == len(_NATIVE_PREFIX_STAGES)
    if raw_shape_valid:
        for index, expected_name in enumerate(_NATIVE_PREFIX_STAGES):
            raw = raw_stages[index]
            if not isinstance(raw, dict) or raw.get("name") != expected_name:
                raw_shape_valid = False
                break
            if index in (1, 2):
                cases = raw.get("cases")
                if (not isinstance(cases, list) or len(cases) != len(_NATIVE_PREFIX_CASES)
                        or any(not isinstance(item, dict) or item.get("case") != expected_case
                            for item, expected_case in zip(cases, _NATIVE_PREFIX_CASES))):
                    raw_shape_valid = False
                    break
    stages: list[dict] = []
    for index, name in enumerate(_NATIVE_PREFIX_STAGES):
        raw = raw_stages[index] if index < len(raw_stages) and isinstance(raw_stages[index], dict) else {}
        raw_status = raw.get("status")
        status = (raw_status if raw.get("name") == name and isinstance(raw_status, str) and raw_status in ("pass", "fail")
            else "unavailable")
        if index == 0:
            stages.append(_safe_prefix_input_stage(raw))
            continue
        member = "route" if index == 1 else "comparison"
        cases = raw.get("cases") if isinstance(raw.get("cases"), list) else []
        safe_cases = []
        for case_index, expected_case in enumerate(_NATIVE_PREFIX_CASES):
            item = cases[case_index] if case_index < len(cases) and isinstance(cases[case_index], dict) else {}
            raw_case = item.get("case")
            case_name = raw_case if isinstance(raw_case, str) and raw_case in _NATIVE_PREFIX_CASES else expected_case
            raw_item_status = item.get("status")
            item_status = raw_item_status if isinstance(raw_item_status, str) and raw_item_status in ("pass", "fail") else "unavailable"
            if case_name != expected_case:
                case_name = expected_case
            if not raw_shape_valid:
                item_status = "unavailable"
            facts = item.get("facts") if isinstance(item.get("facts"), dict) else {}
            safe_facts = _safe_route_facts(facts) if index == 1 else _safe_host_facts(facts)
            safe_cases.append({"case": case_name, "status": item_status,
                "process": _diagnostic_process_projection(item.get("process")), member: safe_facts})
        stages.append({"name": name, "status": status, "cases": safe_cases})
    processes = outer_attempt.get("processes") if isinstance(outer_attempt, dict) else None
    outer_raw = processes[0] if isinstance(processes, list) and len(processes) == 1 else None
    outer = _diagnostic_process_projection(outer_raw)
    report = {"schema": "genewhip-phase7-native-prefix-diagnostic-v1",
        "status": "fail", "diagnostic_only": True, "qualification_accepted": False,
        "fixture": "recursion94", "case_order": list(_NATIVE_PREFIX_CASES),
        "failure_category": ("evidence-shape-invalid" if not raw_shape_valid else
            record.get("failure_category") if isinstance(record.get("failure_category"), str) and record.get("failure_category") in {
            "input-or-evidence-invalid", "bounded-workload-failed", "bounded-workload-timeout",
            "bounded-workload-io-failed", "required-evidence-missing", "evidence-shape-invalid",
            "native-sdl-comparison-failed", "diagnostic-stage-failed"} else None),
        "stages": stages, "outer_process": outer, "outer_rejection": outer_rejection,
        "collector_read_status": collector_read_status, "identity": identity}
    if (raw_shape_valid and record.get("status") == "pass" and collector_read_status == "valid"
            and outer_rejection is None and _native_prefix_stages_pass(stages)
            and _native_prefix_outer_pass(outer_attempt, outer)):
        report["status"] = "pass"
    return report


def _native_prefix_outer_pass(outer_attempt: object, outer: dict) -> bool:
    return (outer.get("status") == "completed" and outer.get("return_code") == "zero"
        and outer.get("cleanup") == "confirmed" and outer.get("bound_violation") is False
        and isinstance(outer_attempt, dict) and type(outer_attempt.get("returncode")) is int
        and outer_attempt["returncode"] == 0 and outer_attempt.get("launch_error") is None
        and outer_attempt.get("process_group_cleanup") == "confirmed")


def _native_prefix_stages_pass(stages: object) -> bool:
    if not isinstance(stages, list) or len(stages) != 3:
        return False
    input_stage, headless, native = stages
    input_facts = input_stage.get("input", {}) if isinstance(input_stage, dict) else {}
    input_expected = list(_NATIVE_DIAGNOSTIC_INPUT_MASKS)
    observations = input_facts.get("observations") if isinstance(input_facts, dict) else None
    input_ok = (input_stage.get("status") == "pass"
        and input_stage["process"].get("status") == "completed"
        and input_stage["process"].get("return_code") == "zero"
        and input_stage["process"].get("cleanup") == "confirmed"
        and input_stage["process"].get("bound_violation") is False
        and input_facts.get("outcome") == "pass" and input_facts.get("requested_count") == 23
        and input_facts.get("port_isolation_verified") is True
        and input_facts.get("masks") == list(_NATIVE_DIAGNOSTIC_INPUT_MASKS)
        and input_facts.get("mask_validity") == [True] * 23
        and input_facts.get("mask_count") == 23 and input_facts.get("observations_count") == 23
        and input_facts.get("observations_truncated") is False
        and isinstance(observations, list) and len(observations) == 23
        and all(isinstance(row, dict)
            and type(row.get("requested_mask")) is int and row["requested_mask"] == input_expected[index]
            and type(row.get("effective_mask")) is int and row["effective_mask"] == input_expected[index]
            and type(row.get("joystick_mask")) is int and row["joystick_mask"] == input_expected[index]
            for index, row in enumerate(observations)))
    if not input_ok:
        return False
    for stage, kind in ((headless, "route"), (native, "comparison")):
        if (not isinstance(stage, dict) or stage.get("status") != "pass"
                or not isinstance(stage.get("cases"), list)
                or len(stage["cases"]) != len(_NATIVE_PREFIX_CASES)):
            return False
        for case_name, case_row in zip(_NATIVE_PREFIX_CASES, stage["cases"]):
            expected_count = _NATIVE_PREFIX_INPUT_COUNTS[case_name]
            expected_masks = _NATIVE_PREFIX_ROUTE_MASKS[case_name]
            if (not isinstance(case_row, dict) or case_row.get("case") != case_name
                    or case_row.get("status") != "pass"):
                return False
            process = case_row.get("process")
            if (not isinstance(process, dict) or process.get("status") != "completed"
                    or process.get("return_code") != "zero" or process.get("cleanup") != "confirmed"
                    or process.get("bound_violation") is not False):
                return False
            facts = case_row.get(kind)
            if not isinstance(facts, dict):
                return False
            if kind == "route":
                events = facts.get("input_events")
                expected_predicates = _NATIVE_PREFIX_EXPECTED_PREDICATES[case_name]
                predicates = facts.get("predicates")
                predicate_map = ({item.get("id"): item for item in predicates
                    if isinstance(item, dict)} if isinstance(predicates, list) else {})
                if (type(facts.get("status")) is not int or facts.get("status") != 0
                        or type(facts.get("active_ticks")) is not int or facts.get("active_ticks") != 3600
                        or type(facts.get("fields")) is not int or not 0 < facts["fields"] <= 7200
                        or type(facts.get("boundary_calls")) is not int
                            or not 0 < facts["boundary_calls"] <= 100_000_000
                        or facts.get("input_event_count") != expected_count
                        or facts.get("input_events_truncated") is not False
                        or not isinstance(events, list) or len(events) != expected_count
                        or [item.get("requested_mask") for item in events] != list(expected_masks)
                        or [item.get("effective_mask") for item in events] != list(expected_masks)
                        or any(type(item.get("index")) is not int or item["index"] != idx
                            or type(item.get("port")) is not int or item["port"] != 0
                            or item.get("requested_mask_valid") is not True
                            or item.get("effective_mask_valid") is not True
                            or item.get("joystick_mask_valid") is not None
                            for idx, item in enumerate(events))
                        or type(facts.get("predicate_count")) is not int or facts["predicate_count"] != 4
                        or set(predicate_map) != set(expected_predicates)
                        or any((predicate_map[key].get("reached"), predicate_map[key].get("value"),
                            predicate_map[key].get("field")) != expected for key, expected in expected_predicates.items())):
                    return False
            else:
                native_events = facts.get("native_input_events")
                host_events = facts.get("host_input_events")
                rows = facts.get("input_rows")
                if (facts.get("status") != "pass" or facts.get("core_outcome") != "pass"
                        or facts.get("host_outcome") != "pass-diagnostic"
                        or facts.get("input_equal") is not True
                        or facts.get("source_samples_equal") is not True
                        or facts.get("renderer_pixel_equal") is not True
                        or facts.get("full_pcm_equal") is not True
                        or facts.get("renderer_readback") is not True
                        or facts.get("audio_device_activity") is not True
                        or type(facts.get("audio_submitted_frames")) is not int or facts["audio_submitted_frames"] <= 0
                        or type(facts.get("audio_consumed_frames")) is not int or facts["audio_consumed_frames"] <= 0
                        or type(facts.get("native_status")) is not int or facts["native_status"] != 0
                        or not isinstance(facts.get("observed_clocks"), dict)
                        or type(facts["observed_clocks"].get("active_ticks")) is not int
                            or facts["observed_clocks"]["active_ticks"] != 3600
                        or type(facts["observed_clocks"].get("fields")) is not int
                            or not 0 < facts["observed_clocks"]["fields"] <= 7200
                        or type(facts["observed_clocks"].get("boundary_calls")) is not int
                            or not 0 < facts["observed_clocks"]["boundary_calls"] <= 100_000_000
                        or facts.get("core_input_count") != expected_count
                        or facts.get("host_input_count") != expected_count
                        or not isinstance(native_events, list) or len(native_events) != expected_count
                        or not isinstance(host_events, list) or len(host_events) != expected_count
                        or facts.get("native_input_events_truncated") is not False
                        or facts.get("host_input_events_truncated") is not False
                        or not isinstance(rows, list) or len(rows) != expected_count
                        or any(not isinstance(row, dict) or type(row.get("index")) is not int
                            or row.get("index") != idx or row.get("equal") is not True
                            or type(row.get("port")) is not int or row.get("port") != 0
                            or type(row.get("desired")) is not int or row.get("desired") != expected_masks[idx]
                            or type(row.get("effective")) is not int or row.get("effective") != expected_masks[idx]
                            for idx, row in enumerate(rows))
                        or any(type(event.get("index")) is not int or event["index"] != idx
                            or type(event.get("requested_mask")) is not int or event["requested_mask"] != expected_masks[idx]
                            or type(event.get("effective_mask")) is not int or event["effective_mask"] != expected_masks[idx]
                            or type(event.get("port")) is not int or event["port"] != 0
                            or event.get("requested_mask_valid") is not True
                            or event.get("effective_mask_valid") is not True
                            for idx, event in enumerate(native_events))
                        or any(type(event.get("index")) is not int or event["index"] != idx
                            or type(event.get("requested_mask")) is not int or event["requested_mask"] != expected_masks[idx]
                            or type(event.get("effective_mask")) is not int or event["effective_mask"] != expected_masks[idx]
                            or type(event.get("joystick_mask")) is not int or event["joystick_mask"] != expected_masks[idx]
                            or type(event.get("port")) is not int or event["port"] != 0
                            or event.get("requested_mask_valid") is not True
                            or event.get("effective_mask_valid") is not True
                            or event.get("joystick_mask_valid") is not True
                            or event.get("handler") != "sdl-gamepad-sample-port"
                            for idx, event in enumerate(host_events))):
                    return False
    return True


_NATIVE_PREFIX_HANDOFF_SCHEMA = "genewhip-phase7-native-prefix-diagnostic-handoff.v1"
_NATIVE_PREFIX_HANDOFF_STATES = ("valid", "missing", "oversized", "unsafe", "invalid")


def _unavailable_native_prefix_stages() -> list[dict]:
    return [{"name": "input-contract", "status": "unavailable",
        "process": _diagnostic_process_projection(None),
        "input": {"requested_count": "missing", "outcome": "unavailable",
            "port_isolation_verified": None, "masks": [], "mask_validity": [],
            "mask_count": "missing", "observations_count": "missing",
            "observations_truncated": False, "observations": []}},
        {"name": "headless-reference", "status": "unavailable", "cases": [
            {"case": case, "status": "unavailable", "process": _diagnostic_process_projection(None),
                "route": _safe_route_facts({})} for case in _NATIVE_PREFIX_CASES]},
        {"name": "native-comparison", "status": "unavailable", "cases": [
            {"case": case, "status": "unavailable", "process": _diagnostic_process_projection(None),
                "comparison": _safe_host_facts({})} for case in _NATIVE_PREFIX_CASES]}]


def native_prefix_diagnostic_handoff(record: object) -> dict:
    projected = safe_native_prefix_diagnostic(record)
    collector_pass = (isinstance(record, dict) and record.get("status") == "pass"
        and projected["failure_category"] is None
        and _native_prefix_stages_pass(projected["stages"]))
    return {"schema": _NATIVE_PREFIX_HANDOFF_SCHEMA,
        "collector_status": "pass" if collector_pass else "fail",
        "failure_category": projected["failure_category"], "stages": projected["stages"]}


def complete_native_prefix_diagnostic_handoff(handoff: object, outer_attempt: object,
        read_status: str = "valid", identity: object = None,
        outer_rejection: str | None = None) -> dict:
    if read_status not in _NATIVE_PREFIX_HANDOFF_STATES:
        read_status = "invalid"
    failure_categories = {"input-or-evidence-invalid", "bounded-workload-failed",
        "bounded-workload-timeout", "bounded-workload-io-failed", "required-evidence-missing",
        "evidence-shape-invalid", "native-sdl-comparison-failed", "diagnostic-stage-failed"}
    valid = (read_status == "valid" and isinstance(handoff, dict)
        and set(handoff) == {"schema", "collector_status", "failure_category", "stages"}
        and handoff.get("schema") == _NATIVE_PREFIX_HANDOFF_SCHEMA
        and handoff.get("collector_status") in ("pass", "fail")
        and (handoff.get("failure_category") is None or
            (type(handoff.get("failure_category")) is str and handoff["failure_category"] in failure_categories))
        and isinstance(handoff.get("stages"), list) and len(handoff["stages"]) == 3)
    stages = handoff["stages"] if valid else _unavailable_native_prefix_stages()
    outer_report = safe_native_diagnostic({"status": "fail", "stages": []}, outer_attempt)
    outer = outer_report["outer_process"]
    category = handoff.get("failure_category") if valid else None
    if read_status != "valid":
        category = {"missing": "collector-handoff-missing", "oversized": "collector-handoff-oversized",
            "unsafe": "collector-handoff-unsafe", "invalid": "collector-handoff-invalid"}[read_status]
    report = {"schema": "genewhip-phase7-native-prefix-diagnostic-v1", "status": "fail",
        "diagnostic_only": True, "qualification_accepted": False, "fixture": "recursion94",
        "case_order": list(_NATIVE_PREFIX_CASES), "failure_category": category,
        "stages": stages, "outer_process": outer, "outer_rejection": outer_rejection,
        "collector_read_status": read_status, "identity": identity}
    if (valid and read_status == "valid" and handoff["collector_status"] == "pass"
            and category is None and outer_rejection is None
            and _native_prefix_stages_pass(stages)
            and _native_prefix_outer_pass(outer_attempt, outer)):
        report["status"] = "pass"
    try:
        validate_native_prefix_diagnostic_public(report, identity)
    except (TypeError, ValueError, KeyError, RecursionError):
        report.update({"status": "fail", "failure_category": "collector-handoff-invalid",
            "collector_read_status": "invalid", "stages": _unavailable_native_prefix_stages()})
        validate_native_prefix_diagnostic_public(report, identity)
    return report


def validate_native_prefix_diagnostic_public(report: object, expected_identity: object) -> bool:
    """Strictly validate the fixed two-case prefix report; never sanitize downloaded data."""
    label = "phase7-native-prefix-diagnostic-public-report-invalid"
    identity_keys = {"source_sha", "head_sha", "base_sha", "run_id", "run_attempt"}
    top_keys = {"schema", "status", "diagnostic_only", "qualification_accepted", "fixture",
        "case_order", "failure_category", "stages", "outer_process", "outer_rejection",
        "collector_read_status", "identity"}
    if (not isinstance(report, dict) or set(report) != top_keys
            or not isinstance(expected_identity, dict) or set(expected_identity) != identity_keys
            or not isinstance(report.get("identity"), dict) or set(report["identity"]) != identity_keys
            or report["identity"] != expected_identity
            or any(not isinstance(expected_identity.get(key), str) or not expected_identity[key]
                for key in identity_keys)
            or any(re.fullmatch(r"[0-9a-f]{40}", expected_identity[key]) is None
                for key in ("source_sha", "head_sha", "base_sha"))
            or re.fullmatch(r"[0-9]+", expected_identity["run_id"]) is None
            or expected_identity["run_attempt"] != "1"):
        raise ValueError(label)
    if (report.get("schema") != "genewhip-phase7-native-prefix-diagnostic-v1"
            or report.get("status") not in ("pass", "fail")
            or report.get("diagnostic_only") is not True
            or report.get("qualification_accepted") is not False
            or report.get("fixture") != "recursion94"
            or report.get("case_order") != list(_NATIVE_PREFIX_CASES)
            or report.get("collector_read_status") not in _NATIVE_PREFIX_HANDOFF_STATES
            or report.get("outer_rejection") not in (None, "outer-boundary-rejected")
            or report.get("failure_category") not in (None, *{
                "input-or-evidence-invalid", "bounded-workload-failed", "bounded-workload-timeout",
                "bounded-workload-io-failed", "required-evidence-missing", "evidence-shape-invalid",
                "native-sdl-comparison-failed", "diagnostic-stage-failed", "collector-handoff-missing",
                "collector-handoff-oversized", "collector-handoff-unsafe", "collector-handoff-invalid"})):
        raise ValueError(label)
    try:
        if len(json.dumps(report, ensure_ascii=True, separators=(",", ":")).encode("utf-8")) > 65536:
            raise ValueError(label)
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ValueError(label) from None

    def count(value: object, maximum: int = 100_000_000) -> bool:
        return type(value) is int and 0 <= value <= maximum

    def process(value: object) -> bool:
        return (isinstance(value, dict) and set(value) == {"return_code", "status", "cleanup", "bound_violation"}
            and type(value.get("return_code")) is str and value["return_code"] in
                ("zero", "nonzero", "signaled", "missing", "untyped")
            and value.get("status") in ("completed", "failed", "timeout", "unconfirmed", "unavailable")
            and value.get("cleanup") in ("confirmed", "unconfirmed", "unavailable")
            and (type(value.get("bound_violation")) is bool or value.get("bound_violation") is None))

    outer = report.get("outer_process")
    stages = report.get("stages")
    if not process(outer) or not isinstance(stages, list) or len(stages) != 3:
        raise ValueError(label)
    first = stages[0]
    input_keys = {"requested_count", "outcome", "port_isolation_verified", "masks", "mask_validity",
        "mask_count", "observations_count", "observations_truncated", "observations"}
    if (not isinstance(first, dict) or set(first) != {"name", "status", "process", "input"}
            or first.get("name") != "input-contract"
            or first.get("status") not in ("pass", "fail", "unavailable")
            or not process(first.get("process"))):
        raise ValueError(label)
    value = first.get("input")
    sentinels = ("missing", "untyped-or-out-of-range")
    if (not isinstance(value, dict) or set(value) != input_keys
            or not (count(value.get("requested_count"), 23) or value.get("requested_count") in sentinels)
            or value.get("outcome") not in ("pass", "fail", "unavailable")
            or (type(value.get("port_isolation_verified")) is not bool and value.get("port_isolation_verified") is not None)
            or not isinstance(value.get("masks"), list) or len(value["masks"]) > 23
            or any(not ((type(item) is int and 0 <= item <= 255) or item in ("untyped", "out-of-range")) for item in value["masks"])
            or not isinstance(value.get("mask_validity"), list) or len(value["mask_validity"]) != len(value["masks"])
            or any(type(item) is not bool for item in value["mask_validity"])
            or not (count(value.get("mask_count"), 100_000) or value.get("mask_count") in ("missing", "untyped", "overrange"))
            or not (count(value.get("observations_count"), 100_000) or value.get("observations_count") in ("missing", "untyped", "overrange"))
            or type(value.get("observations_truncated")) is not bool
            or not isinstance(value.get("observations"), list) or len(value["observations"]) > 23):
        raise ValueError(label)
    for observation in value["observations"]:
        if (not isinstance(observation, dict)
                or not set(observation).issubset({"requested_mask", "effective_mask", "joystick_mask"})
                or any(not ((type(item) is int and 0 <= item <= 255) or item in
                    ("missing", "untyped", "out-of-range")) for item in observation.values())):
            raise ValueError(label)

    for stage_index, expected_name in ((1, "headless-reference"), (2, "native-comparison")):
        stage = stages[stage_index]
        member = "route" if stage_index == 1 else "comparison"
        if (not isinstance(stage, dict) or set(stage) != {"name", "status", "cases"}
                or stage.get("name") != expected_name
                or stage.get("status") not in ("pass", "fail", "unavailable")
                or not isinstance(stage.get("cases"), list) or len(stage["cases"]) != 2):
            raise ValueError(label)
        for case, row in zip(_NATIVE_PREFIX_CASES, stage["cases"]):
            if (not isinstance(row, dict) or set(row) != {"case", "status", "process", member}
                    or (row.get("case") != case and row.get("case") != "unrecognized")
                    or (row.get("case") == "unrecognized" and row.get("status") != "unavailable")
                    or row.get("status") not in ("pass", "fail", "unavailable")
                    or not process(row.get("process")) or not isinstance(row.get(member), dict)):
                raise ValueError(label)
            facts = row[member]
            if member == "route":
                route_keys = {"status", "active_ticks", "fields", "boundary_calls", "input_event_count",
                    "input_events", "input_events_truncated", "predicate_count", "predicates"}
                if (set(facts) != route_keys
                        or facts.get("status") not in (0, 1, "unavailable")
                        or any(item is not None and not count(item) for item in
                            (facts.get("active_ticks"), facts.get("fields"), facts.get("boundary_calls")))
                        or not (count(facts.get("input_event_count"), 100_000) or facts.get("input_event_count") in ("missing", "untyped", "overrange"))
                        or not isinstance(facts.get("input_events"), list) or len(facts["input_events"]) > 64
                        or type(facts.get("input_events_truncated")) is not bool
                        or not (count(facts.get("predicate_count"), 100_000) or facts.get("predicate_count") in ("missing", "untyped", "overrange"))
                        or not isinstance(facts.get("predicates"), list) or len(facts["predicates"]) != 4):
                    raise ValueError(label)
                for event in facts["input_events"]:
                    if (not isinstance(event, dict) or set(event) != {"index", "port", "requested_mask",
                            "requested_mask_valid", "effective_mask", "effective_mask_valid", "joystick_mask",
                            "joystick_mask_valid", "handler"}
                            or not count(event.get("index"), 63)
                            or not ((type(event.get("port")) is int and event["port"] in (0, 1)) or
                                event.get("port") in ("missing", "untyped", "out-of-range"))
                            or any(not ((type(event.get(key)) is int and 0 <= event[key] <= 255) or
                                event.get(key) in ("missing", "untyped", "out-of-range", "not-reported"))
                                for key in ("requested_mask", "effective_mask", "joystick_mask"))
                            or type(event.get("requested_mask_valid")) is not bool
                            or type(event.get("effective_mask_valid")) is not bool
                            or (type(event.get("joystick_mask_valid")) is not bool and event.get("joystick_mask_valid") is not None)
                            or event.get("handler") != "not-reported"):
                        raise ValueError(label)
                predicate_ids = {"early_dependency_interaction", "two_echoes_at_boot_cap",
                    "crossed_generated_door", "late_program_stable"}
                if (any(not isinstance(item, dict) or set(item) != {"id", "reached", "value", "field"}
                        or item.get("id") not in predicate_ids
                        or (type(item.get("reached")) is not bool and item.get("reached") is not None)
                        or not (count(item.get("value")) or item.get("value") in ("missing", "untyped", "overrange"))
                        or not (count(item.get("field")) or item.get("field") in ("missing", "untyped", "overrange"))
                        for item in facts["predicates"])
                        or {item["id"] for item in facts["predicates"] if isinstance(item, dict)} != predicate_ids):
                    raise ValueError(label)
            else:
                # The established one-case comparison projector defines this exact
                # bounded comparison schema; reuse its field-level validator shape.
                expected_comparison = {"status", "core_outcome", "host_outcome", "input_equal", "input_rows",
                    "native_status", "observed_clocks", "core_input_count", "host_input_count",
                    "native_input_events", "native_input_events_truncated", "host_input_events",
                    "host_input_events_truncated", "reason", "failure_presence", "source_samples_equal",
                    "renderer_pixel_equal", "full_pcm_equal", "renderer_readback", "audio_device_activity",
                    "audio_submitted_frames", "audio_consumed_frames"}
                if (set(facts) != expected_comparison
                        or facts.get("status") not in ("pass", "fail", "unavailable")
                        or facts.get("core_outcome") not in ("pass", "fail", "unavailable")
                        or facts.get("host_outcome") not in ("pass-diagnostic", "fail-diagnostic", "fail", "unavailable")
                        or (type(facts.get("input_equal")) is not bool and facts.get("input_equal") is not None)
                        or not isinstance(facts.get("input_rows"), list) or len(facts["input_rows"]) > 64
                        or facts.get("native_status") not in (0, 1, "unavailable")
                        or not isinstance(facts.get("observed_clocks"), dict)
                        or set(facts["observed_clocks"]) != {"active_ticks", "fields", "boundary_calls"}
                        or any(item is not None and not count(item) for item in facts["observed_clocks"].values())
                        or any(not (count(facts.get(key), 100_000) or facts.get(key) in ("missing", "untyped", "overrange"))
                            for key in ("core_input_count", "host_input_count"))
                        or not isinstance(facts.get("native_input_events"), list) or len(facts["native_input_events"]) > 64
                        or not isinstance(facts.get("host_input_events"), list) or len(facts["host_input_events"]) > 64
                        or type(facts.get("native_input_events_truncated")) is not bool
                        or type(facts.get("host_input_events_truncated")) is not bool
                        or facts.get("reason") not in (None, "core-input-progress-or-common-boundary-mismatch", "host-renderer-pcm-or-device-mismatch", "other")
                        or not isinstance(facts.get("failure_presence"), dict)
                        or set(facts["failure_presence"]) != {"capture_field_matches", "renderer_named", "video_driver_named", "audio_driver_named"}
                        or any(type(item) is not bool and item is not None for item in facts["failure_presence"].values())
                        or any(type(facts.get(key)) is not bool and facts.get(key) is not None for key in
                            ("source_samples_equal", "renderer_pixel_equal", "full_pcm_equal", "renderer_readback", "audio_device_activity"))
                        or any(item is not None and not count(item) for item in
                            (facts.get("audio_submitted_frames"), facts.get("audio_consumed_frames")))):
                    raise ValueError(label)
                for input_row in facts["input_rows"]:
                    if (not isinstance(input_row, dict) or not {"index", "equal"}.issubset(input_row)
                            or not set(input_row).issubset({"index", "equal", "port", "desired", "effective"})
                            or not count(input_row.get("index"), 63) or type(input_row.get("equal")) is not bool
                            or any(key in input_row and not count(input_row[key], 255)
                                for key in ("port", "desired", "effective"))):
                        raise ValueError(label)
                for client, key in (("native-host", "native_input_events"), ("host", "host_input_events")):
                    for event in facts[key]:
                        if (not isinstance(event, dict) or set(event) != {"index", "port", "requested_mask",
                                "requested_mask_valid", "effective_mask", "effective_mask_valid", "joystick_mask",
                                "joystick_mask_valid", "handler"}
                                or not count(event.get("index"), 63)
                                or not ((type(event.get("port")) is int and event["port"] in (0, 1)) or
                                    event.get("port") in ("missing", "untyped", "out-of-range"))
                                or any(not ((type(event.get(key2)) is int and 0 <= event[key2] <= 255) or
                                    event.get(key2) in ("missing", "untyped", "out-of-range", "not-reported"))
                                    for key2 in ("requested_mask", "effective_mask", "joystick_mask"))
                                or type(event.get("requested_mask_valid")) is not bool
                                or type(event.get("effective_mask_valid")) is not bool
                                or (type(event.get("joystick_mask_valid")) is not bool and event.get("joystick_mask_valid") is not None)
                                or (event.get("handler") != "not-reported" if client == "native-host"
                                    else event.get("handler") not in ("sdl-gamepad-sample-port", "other", "missing"))):
                            raise ValueError(label)

    if report["status"] == "pass":
        if (report["collector_read_status"] != "valid" or report["failure_category"] is not None
                or report["outer_rejection"] is not None or outer.get("status") != "completed"
                or outer.get("return_code") != "zero" or outer.get("cleanup") != "confirmed"
                or outer.get("bound_violation") is not False or not _native_prefix_stages_pass(stages)
                or any(stage.get("status") != "pass" for stage in stages)
                or any(row.get("status") != "pass" for stage in stages[1:] for row in stage["cases"])):
            raise ValueError(label)
    return True


def _safe_mask_events(events: list, client: str) -> dict:
    safe = []
    for index, item in enumerate(events[:64]):
        if not isinstance(item, dict):
            safe.append({"index": index, "port": "untyped", "mask_status": "untyped"})
            continue
        port = item.get("port")
        requested = item.get("requested_mask", item.get("desired"))
        effective = item.get("effective_mask", item.get("effective"))
        joystick = item.get("joystick_mask")
        def mask_state(value):
            safe_value = value if type(value) is int and 0 <= value <= 255 else (
                "missing" if value is None else "untyped" if type(value) is not int else "out-of-range")
            return safe_value, type(value) is int and 0 <= value <= 255
        requested_safe, requested_valid = mask_state(requested)
        effective_safe, effective_valid = mask_state(effective)
        joystick_safe, joystick_valid = mask_state(joystick)
        safe.append({"index": index, "port": port if type(port) is int and port in (0, 1) else
                "missing" if port is None else "untyped" if type(port) is not int else "out-of-range",
            "requested_mask": requested_safe, "requested_mask_valid": requested_valid,
            "effective_mask": effective_safe, "effective_mask_valid": effective_valid,
            "joystick_mask": joystick_safe if client == "host" else "not-reported",
            "joystick_mask_valid": joystick_valid if client == "host" else None,
            "handler": ("sdl-gamepad-sample-port" if item.get("handler") == "SDL_Gamepad/sample_port"
                else "other" if item.get("handler") is not None else "missing") if client == "host" else "not-reported"})
    return {"events": safe, "truncated": len(events) > 64}


def _read_native_diagnostic_json(reference: object) -> dict:
    if not isinstance(reference, dict) or not isinstance(reference.get("path"), str):
        return {}
    relative = pathlib.PurePosixPath(reference["path"])
    if (relative.is_absolute() or ".." in relative.parts or not relative.parts or
            relative.parts[:2] not in (("build", "v02"), ("artifacts", "v02"))):
        return {}
    path = ROOT.joinpath(*relative.parts)
    try:
        if not path.resolve(strict=True).is_relative_to(ROOT.resolve(strict=True)):
            return {}
        info = path.lstat()
        if path.is_symlink() or not path.is_file() or info.st_nlink != 1 or info.st_size > 4 * 1024 * 1024:
            return {}
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _read_owned_diagnostic_json(path: pathlib.Path, owner: pathlib.Path) -> dict:
    """Read a small regular diagnostic file inside an owned workload directory."""
    try:
        owner_real = owner.resolve(strict=True)
        path_real = path.resolve(strict=True)
        if not path_real.is_relative_to(owner_real):
            return {}
        info = path.lstat()
        if path.is_symlink() or not path.is_file() or info.st_nlink != 1 or info.st_size > 4 * 1024 * 1024:
            return {}
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _fixed_status(value: object) -> str:
    return value if type(value) is int and value in (0, 1) else "unavailable"


def _bounded_counter(value: object) -> int | None:
    return value if type(value) is int and 0 <= value <= 100_000_000 else None


def run_native_diagnostic(build: pathlib.Path, scope_path: pathlib.Path, out: pathlib.Path) -> dict:
    """Run exactly one Phase 7 input, headless, and native comparison diagnostic."""
    if (os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch" or
            os.environ.get("GENEWHIP_NATIVE_DIAGNOSTIC_CASE") != _NATIVE_DIAGNOSTIC_SELECTOR):
        raise ValueError("phase7-native-diagnostic-fixed-selector-required")
    scope, limits = validate_execution_scope(scope_path, "full")
    build = build.resolve(strict=True)
    out = pathlib.Path(out).absolute()
    if out.exists() or out.is_symlink():
        raise ValueError("phase7-native-diagnostic-output-collision")
    if out.resolve() != out:
        raise ValueError("phase7-native-diagnostic-output-symlink")
    roots = resolve_owned_output_roots(scope)
    runtime = out.parent / out.stem
    resolved_runtime = runtime.resolve()
    if not any(resolved_runtime.is_relative_to(root) for root in roots):
        raise ValueError("phase7-native-diagnostic-output-unowned")
    if runtime.exists() or runtime.is_symlink():
        raise ValueError("phase7-native-diagnostic-output-collision")
    started_value = os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT")
    if not isinstance(started_value, str) or not started_value:
        raise ValueError("phase7-native-diagnostic-start-required")
    try:
        started = datetime.datetime.fromisoformat(started_value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("phase7-common-batch-start-invalid") from error
    if started.tzinfo is None:
        raise ValueError("phase7-common-batch-start-invalid")
    deadline = started + datetime.timedelta(seconds=scope["qualification_batch"]["runtime_wall_seconds"])
    now = datetime.datetime.now(datetime.timezone.utc)
    if (now - started).total_seconds() < 0:
        raise ValueError("phase7-common-batch-start-in-future")
    def remaining_seconds() -> int:
        now = datetime.datetime.now(datetime.timezone.utc)
        remaining = (deadline - now).total_seconds()
        if remaining <= 0:
            raise ValueError("phase7-native-diagnostic-runtime-deadline-exhausted")
        whole_seconds = int(remaining)
        if whole_seconds <= 0:
            raise ValueError("phase7-native-diagnostic-runtime-deadline-exhausted")
        return whole_seconds
    remaining_seconds()
    runtime.mkdir(parents=True, mode=0o700)
    mapping_path = ROOT / "fixtures/phase6/recursion94-consumed-map-v1.json"
    fixture = desktop = None
    stages: list[dict] = []
    record = {"schema": "genewhip-phase7-one-case-diagnostic-collector-v1", "status": "fail",
        "diagnostic_only": True, "qualification_accepted": False, "stages": stages}
    private_path = runtime / "private-workload.json"
    handoff_path = out.with_name(out.stem + "-handoff.json")
    if handoff_path.exists() or handoff_path.is_symlink():
        raise ValueError("phase7-native-diagnostic-handoff-collision")
    try:
        fixture = _module(ROOT / "tests/fixtures/phase6_game.py", "gw_v02_one_case_fixture")
        desktop = _module(ROOT / "tests/desktop/phase6_routes.py", "gw_v02_one_case_desktop")
        route_contract = _module(ROOT / "tests/session/phase6_route_contract.py", "gw_v02_one_case_process")
        isolation = _isolation_preflight(route_contract, limits)
        if isolation.get("production_child_starts") != 0:
            raise ValueError("phase7-synthetic-isolation-exposure")
        runtime_scope = {**scope, "qualification_started_at": started.isoformat(),
            "qualification_deadline": deadline.isoformat()}
        scope_copy = runtime / "execution-scope.json"
        scope_copy.write_text(json.dumps(runtime_scope, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        scoped = {**runtime_scope, "_scope_path": str(scope_copy.resolve(strict=True))}
        fixture.set_execution_scope(scoped)
        desktop.set_execution_scope(scoped)
        candidate_path = runtime / "candidate.json"
        candidate = fixture.freeze_candidate(build, mapping_path, candidate_path)
        mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
        core_routes = fixture.compiler.compile_routes()["routes"]
        core_route = next((item for item in core_routes if item.get("fixture") == _NATIVE_DIAGNOSTIC_FIXTURE and
            item.get("case", {}).get("id") == _NATIVE_DIAGNOSTIC_CASE), None)
        host_routes = desktop.compiler.compile_routes(mapping, "sdl")["routes"]
        host_route = next((item for item in host_routes if item.get("fixture") == _NATIVE_DIAGNOSTIC_FIXTURE and
            item.get("case", {}).get("id") == _NATIVE_DIAGNOSTIC_CASE), None)
        if core_route is None or host_route is None:
            raise ValueError("phase7-native-diagnostic-fixed-route-missing")
        desktop_bin = build / "tools/desktop/genewhip-desktop"
        if not desktop_bin.is_file():
            raise ValueError("phase7-current-desktop-client-missing")

        # The existing host identity validator binds this exact Phase 7 path.
        # It is under the scope's owned build/v02 root, and must be fresh.
        input_root = ROOT / "build/v02/runtime/input-contract"
        for path_part in (ROOT / "build", ROOT / "build/v02", ROOT / "build/v02/runtime", input_root):
            if path_part.is_symlink() or (path_part.exists() and not path_part.is_dir()):
                raise ValueError("phase7-native-diagnostic-input-root-invalid")
        input_path = runtime / "input-contract" / "native.json"
        input_path.parent.mkdir(mode=0o700)
        if input_path.exists() or input_path.is_symlink():
            raise ValueError("phase7-native-diagnostic-input-output-collision")
        remaining_seconds()
        input_result = 1
        input_proof = {}
        try:
            input_result = desktop.input_contract(build, mapping_path, input_path, candidate_path, "native")
            input_proof = json.loads(input_path.read_text(encoding="utf-8")) if input_path.is_file() else {}
        except Exception:
            try:
                input_proof = json.loads(input_path.read_text(encoding="utf-8")) if input_path.is_file() else {}
            except (OSError, ValueError, json.JSONDecodeError):
                input_proof = {}
            input_process = input_proof.get("process") if isinstance(input_proof, dict) else None
            input_proof = input_proof if isinstance(input_proof, dict) else {}
            stages.append({"name": "input-contract", "status": "fail", "process": input_process,
                "proof": {"outcome": input_proof.get("outcome"),
                    "requested_count": input_proof.get("requested_count"),
                    "port_isolation_verified": input_proof.get("port_isolation_verified"),
                    "masks": input_proof.get("masks") if isinstance(input_proof.get("masks"), list) else [],
                    "observations": input_proof.get("observations") if isinstance(input_proof.get("observations"), list) else []}})
            raise
        input_process = input_proof.get("process")
        input_process_ok = (isinstance(input_process, dict) and input_process.get("status") == "completed" and
            input_process.get("return_code") == 0 and input_process.get("process_group_cleanup") == "confirmed" and
            input_process.get("bound_violation") is False)
        masks = [item.get("requested_mask") for item in input_proof.get("observations", [])
            if isinstance(item, dict)] if isinstance(input_proof.get("observations"), list) else []
        mapping_digest = fixture.compiler.canonical_digest(mapping)
        expected_masks = [(0, item["effective_mask"]) for item in mapping.get("events", [])]
        expected_masks.extend(((1, 2), (1, 0), (1, 16), (1, 0)))
        observations = input_proof.get("observations") if isinstance(input_proof.get("observations"), list) else []
        masks_match = (len(observations) == 23 and all(isinstance(item, dict) and
            item.get("requested_mask") == expected[1] and item.get("effective_mask") == expected[1] and
            item.get("port") == expected[0] and (expected[0] != 0 or item.get("joystick_mask") == expected[1])
            for item, expected in zip(observations, expected_masks)))
        input_valid = (input_proof.get("schema") == "genewhip-phase6-sdl-virtual-input-contract-v1" and
            input_proof.get("backend") == "native" and input_proof.get("video_driver") == "cocoa" and
            input_proof.get("rom_used") is False and input_proof.get("outcome") == "pass" and
            input_proof.get("requested_count") == 23 and input_proof.get("port_isolation_verified") is True and
            input_proof.get("delivery_map_sha256") == mapping_digest and
            input_proof.get("desktop_sha256") == sha(desktop_bin) and
            input_proof.get("desktop_source_sha256") == sha(ROOT / "tools/desktop/main_sdl.c") and masks_match)
        input_stage = {"name": "input-contract", "status": "pass" if type(input_result) is int and input_result == 0 and
            input_valid and input_process_ok else "fail",
            "process": input_process, "proof": {"outcome": input_proof.get("outcome"),
                "requested_count": input_proof.get("requested_count"),
                "port_isolation_verified": input_proof.get("port_isolation_verified"),
                "masks": masks, "observations": input_proof.get("observations", [])}}
        stages.append(input_stage)
        if input_stage["status"] != "pass":
            raise ValueError("phase7-native-diagnostic-input-contract-failed")

        remaining_seconds()
        core_work = runtime / "headless-reference"
        try:
            core_binary, _ = fixture.compiler.lower_route(core_route,
                boundary_call_limit=100_000_000, delivery_map=mapping, client="public-core")
            core_row = fixture.collect_case(build, core_route, mapping, candidate, core_work, 1,
                min(600, remaining_seconds()), compiled_binary=core_binary)
        except Exception:
            retained = _read_owned_diagnostic_json(core_work / "run.json", core_work)
            native_facts = _read_owned_diagnostic_json(core_work / "native.json", core_work)
            process_receipt = _read_owned_diagnostic_json(core_work / "process.json", core_work)
            process_rows = process_receipt.get("processes")
            receipt_process = (process_rows[-1] if isinstance(process_rows, list) and process_rows and
                isinstance(process_rows[-1], dict) else None)
            process = retained.get("process") if isinstance(retained.get("process"), dict) else receipt_process
            stages.append({"name": "headless-reference", "status": "fail", "process": process,
                "facts": {"native": native_facts,
                    "row": {"predicate_results": retained.get("predicate_results")}}})
            raise
        core_report_path = runtime / "headless-report.json"
        core = {"schema": "genewhip-phase6-product-report-v1", "candidate_sha256": fixture.canonical_sha(candidate),
            "runs": [core_row]}
        core_report_path.write_text(json.dumps(core, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        native_path = ROOT / core_row["native_report"]["path"]
        native_facts = json.loads(native_path.read_text(encoding="utf-8")) if native_path.is_file() else {}
        core_process = core_row.get("process") if isinstance(core_row.get("process"), dict) else {}
        core_row_valid = (core_row.get("fixture") == _NATIVE_DIAGNOSTIC_FIXTURE and
            core_row.get("case") == _NATIVE_DIAGNOSTIC_CASE and core_row.get("repetition") == 1 and
            core_row.get("client") == "public-core" and core_row.get("status") == "pass" and
            core_process.get("status") == "completed" and core_process.get("return_code") == 0 and
            core_process.get("process_group_cleanup") == "confirmed" and core_process.get("bound_violation") is False)
        stages.append({"name": "headless-reference", "status": "pass" if core_row_valid else "fail",
            "process": core_row.get("process"), "facts": {"native": native_facts,
                "row": {"predicate_results": core_row.get("predicate_results")}}})
        if not core_row_valid:
            raise ValueError("phase7-native-diagnostic-headless-reference-failed")

        remaining_seconds()
        host_work = runtime / "native-sdl-comparison"
        host_work.mkdir(mode=0o700)
        try:
            host_row = desktop._retained_host_case(build, desktop_bin, host_route, mapping, core,
                core_report_path, "native", host_work, candidate)
        except Exception:
            receipt_paths = sorted(host_work.glob("**/process.json"))
            receipt_path = receipt_paths[-1] if receipt_paths else None
            try:
                receipt = _read_owned_diagnostic_json(receipt_path, host_work) if receipt_path else {}
            except (OSError, ValueError, json.JSONDecodeError):
                receipt = {}
            processes = receipt.get("processes") if isinstance(receipt, dict) else None
            process = processes[-1] if isinstance(processes, list) and processes and isinstance(processes[-1], dict) else None
            attempt_dirs = sorted(path for path in host_work.glob(
                f"{_NATIVE_DIAGNOSTIC_FIXTURE}-{_NATIVE_DIAGNOSTIC_CASE}-attempt*")
                if path.is_dir() and not path.is_symlink())
            attempt = attempt_dirs[-1] if attempt_dirs else None
            raw_outputs = {}
            if attempt is not None:
                for output_name, filename in (("native", "native.json"), ("host", "host.json")):
                    output_path = attempt / filename
                    if not output_path.is_file() or output_path.is_symlink():
                        continue
                    try:
                        relative = output_path.resolve(strict=True).relative_to(ROOT.resolve(strict=True))
                    except (OSError, ValueError):
                        continue
                    if relative.parts[:2] in (("build", "v02"), ("artifacts", "v02")):
                        raw_outputs[output_name] = {"path": relative.as_posix()}
            stages.append({"name": "native-sdl-comparison", "status": "fail", "process": process,
                "facts": {"row": {"status": "fail", "process": process,
                    "raw_outputs": raw_outputs}}})
            raise
        host_process = host_row.get("process") if isinstance(host_row.get("process"), dict) else {}
        host_valid = (host_row.get("fixture") == _NATIVE_DIAGNOSTIC_FIXTURE and
            host_row.get("case") == _NATIVE_DIAGNOSTIC_CASE and host_row.get("backend") == "native" and
            host_row.get("status") == "pass" and host_process.get("status") == "completed" and
            host_process.get("return_code") == 0 and host_process.get("process_group_cleanup") == "confirmed" and
            host_process.get("bound_violation") is False)
        host_stage = {"name": "native-sdl-comparison", "status": "pass" if host_valid else "fail",
            "process": host_row.get("process"), "facts": {"row": host_row}}
        stages.append(host_stage)
        record["status"] = "pass" if host_valid else "fail"
        if record["status"] != "pass":
            record["failure_category"] = "native-sdl-comparison-failed"
        record["private_workload"] = {"input_proof": input_proof, "headless_row": core_row, "native_row": host_row,
            "scope": runtime_scope, "candidate": candidate, "isolation": isolation}
    except Exception as error:
        record["status"] = "fail"
        record["failure_category"] = _native_diagnostic_failure_category(error)
        # Never discard already-completed raw stages when a later stage fails.
    finally:
        if desktop is not None:
            desktop.set_execution_scope(None)
        if fixture is not None:
            fixture.set_execution_scope(None)
        for stage_name in _NATIVE_DIAGNOSTIC_STAGES[len(stages):]:
            stages.append({"name": stage_name, "status": "not-run", "process": None, "facts": {}})
        private_path.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        handoff = native_diagnostic_handoff(record)
        handoff_bytes = (json.dumps(handoff, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(handoff_bytes) > 65536:
            raise ValueError("phase7-native-diagnostic-handoff-byte-limit")
        descriptor = os.open(handoff_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(handoff_bytes)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return record


def _native_prefix_headless_consumer_row(core_row: dict) -> dict:
    """Retain the complete private collector row for the SDL consumer."""
    if not isinstance(core_row, dict):
        raise TypeError("phase7-native-prefix-headless-row-invalid")
    return dict(core_row)


def _native_prefix_claim_deadline(started_value: str, claim_started: str | None,
                                  claim_deadline: str | None) -> datetime.datetime | None:
    if not claim_started and not claim_deadline:
        return None
    if not claim_started or not claim_deadline or claim_started != started_value:
        raise ValueError("phase7-native-prefix-diagnostic-claim-clock-invalid")
    try:
        carried_start = datetime.datetime.fromisoformat(claim_started.replace("Z", "+00:00"))
        carried_deadline = datetime.datetime.fromisoformat(claim_deadline.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("phase7-native-prefix-diagnostic-claim-clock-invalid") from None
    if (carried_start.tzinfo is None or carried_deadline.tzinfo is None
            or carried_deadline != carried_start + datetime.timedelta(seconds=2700)):
        raise ValueError("phase7-native-prefix-diagnostic-claim-clock-invalid")
    return carried_deadline


def run_native_prefix_diagnostic(build: pathlib.Path, scope_path: pathlib.Path,
                                 out: pathlib.Path) -> dict:
    """Compare two fixed recursion94 routes under one shared budget per stage."""
    if (os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or os.environ.get("GENEWHIP_NATIVE_DIAGNOSTIC_CASE") != _NATIVE_PREFIX_SELECTOR
            or not re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GENEWHIP_NATIVE_DIAGNOSTIC_SOURCE_SHA", ""))
            or os.environ.get("GITHUB_SHA") != os.environ.get("GENEWHIP_NATIVE_DIAGNOSTIC_SOURCE_SHA")):
        raise ValueError("phase7-native-prefix-diagnostic-fixed-selector-required")
    scope, limits = validate_execution_scope(scope_path, "full")
    build = build.resolve(strict=True)
    out = pathlib.Path(out).absolute()
    if out.exists() or out.is_symlink() or out.resolve() != out:
        raise ValueError("phase7-native-prefix-diagnostic-output-collision")
    roots = resolve_owned_output_roots(scope)
    runtime = out.parent / out.stem
    resolved_runtime = runtime.resolve()
    if not any(resolved_runtime.is_relative_to(root) for root in roots):
        raise ValueError("phase7-native-prefix-diagnostic-output-unowned")
    if runtime.exists() or runtime.is_symlink():
        raise ValueError("phase7-native-prefix-diagnostic-output-collision")
    started_value = os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT")
    if not isinstance(started_value, str) or not started_value:
        raise ValueError("phase7-native-prefix-diagnostic-start-required")
    try:
        started = datetime.datetime.fromisoformat(started_value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("phase7-common-batch-start-invalid") from error
    if started.tzinfo is None:
        raise ValueError("phase7-common-batch-start-invalid")
    now = datetime.datetime.now(datetime.timezone.utc)
    if (now - started).total_seconds() < 0:
        raise ValueError("phase7-common-batch-start-in-future")
    claim_deadline = _native_prefix_claim_deadline(started_value,
        os.environ.get("GENEWHIP_NATIVE_DIAGNOSTIC_STARTED_AT"),
        os.environ.get("GENEWHIP_NATIVE_DIAGNOSTIC_DEADLINE"))
    deadline = claim_deadline or started + datetime.timedelta(
        seconds=scope["qualification_batch"]["runtime_wall_seconds"])

    def remaining_seconds() -> int:
        remaining = (deadline - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
        whole = int(remaining)
        if remaining <= 0 or whole <= 0:
            raise ValueError("phase7-native-prefix-diagnostic-runtime-deadline-exhausted")
        return whole

    remaining_seconds()
    runtime.mkdir(parents=True, mode=0o700)
    private_path = runtime / "private-workload.json"
    handoff_path = out.with_name(out.stem + "-handoff.json")
    if handoff_path.exists() or handoff_path.is_symlink():
        raise ValueError("phase7-native-prefix-diagnostic-handoff-collision")
    mapping_path = ROOT / "fixtures/phase6/recursion94-consumed-map-v1.json"
    fixture = desktop = host_boundary = None
    stages: list[dict] = []
    record = {"schema": "genewhip-phase7-native-prefix-collector.v1", "status": "fail",
        "diagnostic_only": True, "qualification_accepted": False,
        "fixture": "recursion94", "case_order": list(_NATIVE_PREFIX_CASES), "stages": stages}
    prior_deadline = None
    prior_deadline_present = False
    try:
        fixture = _module(ROOT / "tests/fixtures/phase6_game.py", "gw_v02_native_prefix_fixture")
        desktop = _module(ROOT / "tests/desktop/phase6_routes.py", "gw_v02_native_prefix_desktop")
        route_contract = _module(ROOT / "tests/session/phase6_route_contract.py", "gw_v02_native_prefix_process")
        isolation = _isolation_preflight(route_contract, limits)
        if isolation.get("production_child_starts") != 0:
            raise ValueError("phase7-synthetic-isolation-exposure")
        runtime_scope = {**scope, "qualification_started_at": started.isoformat(),
            "qualification_deadline": deadline.isoformat()}
        scope_copy = runtime / "execution-scope.json"
        scope_copy.write_text(json.dumps(runtime_scope, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        scoped = {**runtime_scope, "_scope_path": str(scope_copy.resolve(strict=True))}
        fixture.set_execution_scope(scoped)
        desktop.set_execution_scope(scoped)
        candidate_path = runtime / "candidate.json"
        candidate = fixture.freeze_candidate(build, mapping_path, candidate_path)
        mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
        core_routes = fixture.compiler.compile_routes()["routes"]
        host_routes = desktop.compiler.compile_routes(mapping, "sdl")["routes"]
        core_by_case = {item.get("case", {}).get("id"): item for item in core_routes
            if item.get("fixture") == "recursion94" and isinstance(item.get("case"), dict)}
        host_by_case = {item.get("case", {}).get("id"): item for item in host_routes
            if item.get("fixture") == "recursion94" and isinstance(item.get("case"), dict)}
        if any(case not in core_by_case or case not in host_by_case for case in _NATIVE_PREFIX_CASES):
            raise ValueError("phase7-native-prefix-diagnostic-fixed-routes-missing")
        desktop_bin = build / "tools/desktop/genewhip-desktop"
        if not desktop_bin.is_file():
            raise ValueError("phase7-current-desktop-client-missing")
        for path_part in (ROOT / "build", ROOT / "build/v02", ROOT / "build/v02/runtime",
                          ROOT / "build/v02/runtime/input-contract"):
            if path_part.is_symlink() or (path_part.exists() and not path_part.is_dir()):
                raise ValueError("phase7-native-prefix-diagnostic-input-root-invalid")
        input_path = runtime / "input-contract" / "native.json"
        input_path.parent.mkdir(mode=0o700)
        if input_path.exists() or input_path.is_symlink():
            raise ValueError("phase7-native-prefix-diagnostic-input-collision")
        input_stage = {"name": "input-contract", "status": "unavailable", "process": None,
            "proof": {}}
        stages.append(input_stage)
        remaining_seconds()
        try:
            input_result = desktop.input_contract(build, mapping_path, input_path, candidate_path, "native")
            input_proof = json.loads(input_path.read_text(encoding="utf-8")) if input_path.is_file() else {}
        except Exception:
            try:
                input_proof = json.loads(input_path.read_text(encoding="utf-8")) if input_path.is_file() else {}
            except (OSError, ValueError, json.JSONDecodeError):
                input_proof = {}
            input_process = input_proof.get("process") if isinstance(input_proof, dict) else None
            input_stage.update({"status": "fail", "process": input_process,
                "proof": {key: input_proof.get(key) for key in
                    ("outcome", "requested_count", "port_isolation_verified", "masks", "observations")}})
            raise
        input_process = input_proof.get("process") if isinstance(input_proof, dict) else None
        expected_input = [(0, item["effective_mask"]) for item in mapping.get("events", [])]
        expected_input.extend(((1, 2), (1, 0), (1, 16), (1, 0)))
        observations = input_proof.get("observations") if isinstance(input_proof, dict) else None
        masks_match = (isinstance(observations, list) and len(observations) == 23 and
            len(expected_input) == 23 and all(isinstance(item, dict)
                and item.get("port") == expected[0]
                and item.get("requested_mask") == expected[1]
                and item.get("effective_mask") == expected[1]
                and item.get("joystick_mask") == expected[1]
                for item, expected in zip(observations, expected_input)))
        input_valid = (isinstance(input_proof, dict)
            and input_proof.get("schema") == "genewhip-phase6-sdl-virtual-input-contract-v1"
            and input_proof.get("backend") == "native" and input_proof.get("video_driver") == "cocoa"
            and input_proof.get("rom_used") is False and input_proof.get("outcome") == "pass"
            and input_proof.get("requested_count") == 23 and input_proof.get("port_isolation_verified") is True
            and input_proof.get("delivery_map_sha256") == fixture.compiler.canonical_digest(mapping)
            and input_proof.get("desktop_sha256") == sha(desktop_bin)
            and input_proof.get("desktop_source_sha256") == sha(ROOT / "tools/desktop/main_sdl.c")
            and masks_match and isinstance(input_process, dict)
            and input_process.get("status") == "completed" and input_process.get("return_code") == 0
            and input_process.get("process_group_cleanup") == "confirmed"
            and input_process.get("bound_violation") is False)
        input_stage.update({"status": "pass" if type(input_result) is int and input_result == 0 and input_valid else "fail",
            "process": input_process, "proof": {"outcome": input_proof.get("outcome") if isinstance(input_proof, dict) else None,
                "requested_count": input_proof.get("requested_count") if isinstance(input_proof, dict) else None,
                "port_isolation_verified": input_proof.get("port_isolation_verified") if isinstance(input_proof, dict) else None,
                "masks": [row.get("requested_mask") for row in observations if isinstance(row, dict)]
                    if isinstance(observations, list) else [], "observations": observations if isinstance(observations, list) else []}})
        if input_stage["status"] != "pass":
            raise ValueError("phase7-native-prefix-diagnostic-input-contract-failed")

        headless_stage = {"name": "headless-reference", "status": "unavailable", "cases": []}
        stages.append(headless_stage)
        headless_deadline = time.monotonic() + 600
        core_rows: list[dict] = []
        headless_reports: dict[str, dict] = {}
        # collect_case creates each case directory itself with mkdir() (without
        # parents=True), so create only the shared stage parent here.
        (runtime / "headless-reference").mkdir(mode=0o700)
        for case in _NATIVE_PREFIX_CASES:
            case_work = runtime / "headless-reference" / case
            remaining = min(600, int(headless_deadline - time.monotonic()))
            if remaining <= 0:
                raise TimeoutError("phase7-native-prefix-headless-aggregate-deadline")
            core_binary, _ = fixture.compiler.lower_route(core_by_case[case],
                boundary_call_limit=100_000_000, delivery_map=mapping, client="public-core")
            try:
                core_row = fixture.collect_case(build, core_by_case[case], mapping, candidate,
                    case_work, 1, remaining, compiled_binary=core_binary)
            except Exception:
                retained = _read_owned_diagnostic_json(case_work / "run.json", case_work)
                native_facts = _read_owned_diagnostic_json(case_work / "native.json", case_work)
                process_receipt = _read_owned_diagnostic_json(case_work / "process.json", case_work)
                process_rows = process_receipt.get("processes")
                proc = (process_rows[-1] if isinstance(process_rows, list) and process_rows
                    and isinstance(process_rows[-1], dict) else retained.get("process"))
                headless_stage["cases"].append({"case": case, "status": "fail", "process": proc,
                    "facts": {"native": native_facts, "row": {"predicate_results": retained.get("predicate_results")}}})
                raise
            native_path = ROOT / core_row["native_report"]["path"]
            native_facts = json.loads(native_path.read_text(encoding="utf-8")) if native_path.is_file() else {}
            proc = core_row.get("process") if isinstance(core_row.get("process"), dict) else {}
            expected_count = _NATIVE_PREFIX_INPUT_COUNTS[case]
            expected_masks = _NATIVE_PREFIX_ROUTE_MASKS[case]
            events = native_facts.get("inputs") if isinstance(native_facts, dict) else None
            core_valid = (core_row.get("fixture") == "recursion94" and core_row.get("case") == case
                and core_row.get("repetition") == 1 and core_row.get("client") == "public-core"
                and core_row.get("status") == "pass" and proc.get("status") == "completed"
                and proc.get("return_code") == 0 and proc.get("process_group_cleanup") == "confirmed"
                and proc.get("bound_violation") is False and isinstance(events, list)
                and len(events) == expected_count and native_facts.get("status") == 0
                and native_facts.get("active_ticks") == 3600
                and [item.get("desired") for item in events] == list(expected_masks)
                and [item.get("effective") for item in events] == list(expected_masks)
                and all(item.get("port") == 0 for item in events))
            # This private report is the direct input to the real host comparison
            # consumer. Keep the collector's media and identity references intact;
            # the public diagnostic projection below still selects its own fields.
            headless_reports[case] = _native_prefix_headless_consumer_row(core_row)
            headless_stage["cases"].append({"case": case, "status": "pass" if core_valid else "fail",
                "process": proc, "facts": {"native": native_facts, "row": core_row}})
            core_rows.append(headless_reports[case])
            if not core_valid or time.monotonic() > headless_deadline:
                raise ValueError("phase7-native-prefix-diagnostic-headless-reference-failed")
        core_report_path = runtime / "headless-report.json"
        core_report = {"schema": "genewhip-phase6-product-report-v1",
            "candidate_sha256": fixture.canonical_sha(candidate), "runs": core_rows}
        core_report_path.write_text(json.dumps(core_report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        headless_stage["status"] = "pass"

        native_stage = {"name": "native-comparison", "status": "unavailable", "cases": []}
        stages.append(native_stage)
        native_deadline = time.monotonic() + 600
        host_boundary = getattr(desktop, "phase6_game", None)
        prior_deadline_present = host_boundary is not None and hasattr(host_boundary, "_V02_DEADLINE")
        prior_deadline = getattr(host_boundary, "_V02_DEADLINE", None)
        if host_boundary is not None:
            host_boundary._V02_DEADLINE = (min(prior_deadline, native_deadline)
                if prior_deadline is not None else native_deadline)
        for case in _NATIVE_PREFIX_CASES:
            remaining_seconds()
            if time.monotonic() >= native_deadline:
                raise TimeoutError("phase7-native-prefix-comparison-aggregate-deadline")
            case_work = runtime / "native-comparison" / case
            case_work.mkdir(parents=True, mode=0o700)
            try:
                host_row = desktop._retained_host_case(build, desktop_bin, host_by_case[case], mapping,
                    core_report, core_report_path, "native", case_work, candidate)
            except Exception:
                proc = None
                receipt_paths = sorted(case_work.glob("**/process.json"))
                if receipt_paths:
                    try:
                        receipt = _read_owned_diagnostic_json(receipt_paths[-1], case_work)
                        processes = receipt.get("processes")
                        proc = processes[-1] if isinstance(processes, list) and processes else None
                    except (OSError, ValueError, json.JSONDecodeError):
                        proc = None
                native_stage["cases"].append({"case": case, "status": "fail", "process": proc,
                    "facts": {"row": {"status": "fail", "process": proc}}})
                raise
            proc = host_row.get("process") if isinstance(host_row.get("process"), dict) else {}
            case_ok = (host_row.get("fixture") == "recursion94" and host_row.get("case") == case
                and host_row.get("backend") == "native" and host_row.get("status") == "pass"
                and proc.get("status") == "completed" and proc.get("return_code") == 0
                and proc.get("process_group_cleanup") == "confirmed" and proc.get("bound_violation") is False)
            native_stage["cases"].append({"case": case, "status": "pass" if case_ok else "fail",
                "process": proc, "facts": {"row": host_row}})
            if not case_ok or time.monotonic() > native_deadline:
                raise ValueError("phase7-native-prefix-diagnostic-comparison-failed")
        native_stage["status"] = "pass"
        record["status"] = "pass"
        record["private_workload"] = {"input_proof": input_proof,
            "headless_rows": core_rows, "native_rows": [item.get("facts", {}).get("row") for item in native_stage["cases"]],
            "scope": runtime_scope, "candidate": candidate, "isolation": isolation}
    except Exception as error:
        record["status"] = "fail"
        record["failure_category"] = _native_diagnostic_failure_category(error)
        for name in _NATIVE_PREFIX_STAGES[len(stages):]:
            if name == "headless-reference":
                stages.append({"name": name, "status": "unavailable", "cases": [
                    {"case": case, "status": "unavailable", "process": None, "facts": {}}
                    for case in _NATIVE_PREFIX_CASES]})
            elif name == "native-comparison":
                stages.append({"name": name, "status": "unavailable", "cases": [
                    {"case": case, "status": "unavailable", "process": None, "facts": {}}
                    for case in _NATIVE_PREFIX_CASES]})
    finally:
        if host_boundary is not None:
            if prior_deadline_present:
                host_boundary._V02_DEADLINE = prior_deadline
            elif hasattr(host_boundary, "_V02_DEADLINE"):
                delattr(host_boundary, "_V02_DEADLINE")
        if desktop is not None:
            desktop.set_execution_scope(None)
        if fixture is not None:
            fixture.set_execution_scope(None)
        for name in _NATIVE_PREFIX_STAGES[len(stages):]:
            if name in ("headless-reference", "native-comparison"):
                stages.append({"name": name, "status": "unavailable", "cases": [
                    {"case": case, "status": "unavailable", "process": None, "facts": {}}
                    for case in _NATIVE_PREFIX_CASES]})
        for stage in stages[1:]:
            if not isinstance(stage.get("cases"), list):
                stage["cases"] = []
            known = {row.get("case") for row in stage["cases"] if isinstance(row, dict)}
            for case in _NATIVE_PREFIX_CASES:
                if case not in known:
                    stage["cases"].append({"case": case, "status": "unavailable",
                        "process": None, "facts": {}})
        private_path.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        handoff = native_prefix_diagnostic_handoff(record)
        handoff_bytes = (json.dumps(handoff, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(handoff_bytes) > 65536:
            raise ValueError("phase7-native-prefix-diagnostic-handoff-byte-limit")
        descriptor = os.open(handoff_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(handoff_bytes)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return record


def _native_diagnostic_failure_category(error: BaseException) -> str:
    allowed = {"ValueError": "input-or-evidence-invalid", "RuntimeError": "bounded-workload-failed",
        "TimeoutError": "bounded-workload-timeout", "TimeoutExpired": "bounded-workload-timeout",
        "OSError": "bounded-workload-io-failed",
        "KeyError": "required-evidence-missing", "TypeError": "evidence-shape-invalid"}
    return allowed.get(type(error).__name__, "diagnostic-stage-failed")


def _public_roster(scenario: dict, identity: dict) -> dict:
    source_keys = ("scenario_sha256", "oracle_sha256", "rom_sha256", "source_sha256")
    return {"schema": "genewhip-v02-roster-v1", "fixture_id": scenario["fixture_id"],
            "profile": scenario["profile"], "machine": scenario["machine"],
            "source_identity": {name: identity[name] for name in source_keys},
            "case_ids": [case["id"] for case in scenario["cases"]],
            "stage_ids": ["load", "boot", "interaction", "sustained", "completion"],
            "completion_policy": "unknown-unless-separate-source-oracle-proves-completion"}


def launch(client: pathlib.Path, case: dict, scratch: pathlib.Path, limits: dict) -> dict:
    fixture = _module(ROOT / "tests/fixtures/phase4_game.py", "gw_v02_phase4_fixture")
    route = _module(ROOT / "tests/session/phase6_route_contract.py", "gw_v02_shared_process_boundary")
    runs: list[dict] = []
    report = scratch / "unused-child-report.json"
    fields = scratch / "fields"
    audio = scratch / "headless.pcm"

    def bounded_run(command, *, timeout, outer_process_group=False):
        result = route._run_client(client, command, runs, report=report,
            timeout=min(int(timeout), int(limits["wall_seconds"])),
            monitored_files=((audio, limits["max_binary_file_bytes"]),),
            monitored_directories=((fields, int(limits["max_fields"]), limits["max_binary_file_bytes"]),),
            limits=limits, scratch_roots=(scratch,))
        return CompletedProcess(command, result.returncode, result.stdout.encode(), result.stderr.encode())

    fixture.bounded_run = bounded_run
    try:
        result = fixture.execute(client, ROM, case, scratch)
    finally:
        fixture.bounded_run = _module(ROOT / "tests/fixtures/phase4_game.py", "gw_v02_phase4_fixture_restore").bounded_run
    if len(result["hashes"]) != case["frames"] or len(result["geometry"]) != case["frames"]:
        raise ValueError("phase7-tracer-field-denominator-invalid")
    if len(runs) != 1 or runs[0].get("process_group_cleanup") != "confirmed" or runs[0].get("bound_violation"):
        raise ValueError("phase7-tracer-child-bound-or-cleanup-failed")
    if not isinstance(runs[0].get("rss_bytes_peak"), int) or runs[0]["rss_bytes_peak"] <= 0:
        raise ValueError("phase7-rss-observation-invalid")
    scratch_bytes = route._safe_tree_bytes(scratch)
    if scratch_bytes is None or scratch_bytes > limits["max_scratch_bytes"]:
        raise ValueError("phase7-tracer-scratch-limit-or-unsafe-tree")
    observed_calls = sum(int(row.get("instructions", 0)) for row in runs[0].get("observations", []))
    if case["frames"] > limits["max_fields"] or observed_calls > limits["max_calls"]:
        raise ValueError("phase7-tracer-work-ceiling-exceeded")
    result["resource_receipt"] = dict(runs[0])
    result["resource_receipt"]["scratch_bytes_observed"] = scratch_bytes
    result["resource_receipt"]["capture_bytes_observed"] = int(runs[0].get("stdout_bytes", 0)) + int(runs[0].get("stderr_bytes", 0))
    return result


def run_control(build: pathlib.Path, scope_path: pathlib.Path, out: pathlib.Path) -> dict:
    build = build.resolve(strict=True)
    scope = json.loads(scope_path.read_text())
    if scope.get("schema") != "genewhip-v02-execution-v1" or scope.get("scope_id") != "phase7-serial-child-workloads":
        raise ValueError("phase7-execution-scope-invalid")
    limits = scope.get("per_child_limits")
    if not isinstance(limits, dict):
        raise ValueError("phase7-per-child-limits-missing")
    memory_available = require_memory_reserve(available_memory_bytes(), limits["max_rss_bytes"])
    scenario = json.loads(SCENARIO.read_text())
    identity = freeze_identity(build)
    identity.update({"fixture_id": scenario["fixture_id"], "profile": scenario["profile"],
                     "machine": scenario["machine"]})
    case = next((row for row in scenario["cases"] if row.get("id") == "start-move"), None)
    if not isinstance(case, dict):
        raise ValueError("phase7-start-move-case-missing")
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gw-v02-start-move-", dir=out) as temp:
        result = launch(build / "tools/session/gw_headless", case, pathlib.Path(temp), limits)
    expected = case["expect"]
    predicates = {"play_state": result["play_state"] == expected["play_state"],
                  "position_in_source_range": expected["position_min"] <= result["position"] <= expected["position_max"],
                  "causal_control": result["psg"] == expected["psg_writes"]}
    status = "pass" if all(predicates.values()) else "fail"
    observations = []
    for row in scenario["cases"]:
        input_digest = hashlib.sha256(_module(ROOT / "tests/fixtures/phase4_game.py", "gw_v02_input_fixture").input_log(row)).hexdigest()
        if row["id"] == "start-move":
            observations.append({"case_id": row["id"], "status": status, "fields": len(result["hashes"]),
                "play_state": result["play_state"], "position": result["position"], "psg_writes": result["psg"],
                "input_sha256": input_digest, "pcm_sha256": hashlib.sha256(result["audio"]).hexdigest(),
                "video_sha256": hashlib.sha256(json.dumps(result["geometry"], separators=(",", ":")).encode()).hexdigest(),
                "source_predicates": predicates})
        else:
            observations.append({"case_id": row["id"], "status": "unknown", "fields": 0,
                "play_state": 0, "position": 0, "psg_writes": [], "input_sha256": input_digest,
                "pcm_sha256": "", "video_sha256": "", "source_predicates": {}})
    source_roster = _public_roster(scenario, identity)
    checked_roster = json.loads((ROOT / "evidence/v02-roster.json").read_text())
    if checked_roster != source_roster:
        raise ValueError("phase7-independent-roster-source-drift")
    schema_path = ROOT / "evidence/v02-schema.json"
    schema_doc = json.loads(schema_path.read_text())
    bundle = {"schema": "genewhip-v02-evidence-v1", "scope": "control-tracer",
              "source_identity": identity, "roster": checked_roster["case_ids"],
              "observations": observations,
              "artifacts": {"headless_executable_sha256": identity["executable_sha256"],
                            "cmake_cache_sha256": identity["cmake_cache_sha256"],
                            "schema_sha256": hashlib.sha256(schema_path.read_bytes()).hexdigest()}}
    matrix = _module(ROOT / "scripts/evidence/v02_matrix.py", "gw_v02_matrix")
    matrix.validate_public_bundle(bundle, expected_keys=bundle["roster"], schema_doc=schema_doc)
    out.mkdir(parents=True, exist_ok=True)
    bundle_path = out / "control-bundle.json"
    bundle_path.write_text(json.dumps(bundle, sort_keys=True, indent=2) + "\n")
    roster_path = out / "roster.json"
    roster_path.write_text(json.dumps(checked_roster, sort_keys=True, indent=2) + "\n")
    matrix_path = out / "matrix.md"
    matrix_path.write_text(matrix.render_matrix(bundle))
    tracked_calls = len(result["hashes"]) + len(case["input_schedule"]) + 2
    if tracked_calls > limits["max_calls"]:
        raise ValueError("phase7-tracer-public-call-limit")
    external = out / "external"
    external.mkdir(exist_ok=True)
    for source in (ROOT / "scripts/evidence/v02_matrix.py", bundle_path, roster_path, schema_path):
        (external / source.name).write_bytes(source.read_bytes())
    command = [sys.executable, "-I", str(external / "v02_matrix.py"), "verify",
               "--bundle", str(external / bundle_path.name), "--roster", str(external / roster_path.name),
               "--schema", str(external / schema_path.name)]
    import subprocess
    checked = subprocess.run(command, cwd=external, env={"PATH": "/usr/bin:/bin"},
                             text=True, capture_output=True, timeout=30)
    if checked.returncode:
        raise ValueError("external-public-validation-failed:" + checked.stderr.strip())
    retained_paths = [bundle_path, matrix_path, roster_path, schema_path, *(external / name for name in
        ("v02_matrix.py", bundle_path.name, roster_path.name, schema_path.name))]
    retained_bytes = sum(path.stat().st_size for path in retained_paths)
    if retained_bytes > limits["max_retained_bytes"]:
        raise ValueError("phase7-retained-proof-byte-limit")
    receipt = {"schema": "genewhip-v02-control-receipt-v1", "status": status,
        "source_identity": identity, "case_id": case["id"], "fields": len(result["hashes"]),
        "tracked_calls": tracked_calls,
        "tracked_calls_basis": "field dispatches + source-declared replay events + process setup/teardown markers",
        "actual_child_rss_bytes_observed": result["resource_receipt"].get("rss_bytes_peak"),
        "memory_available_bytes_before_launch": memory_available,
        "child_wall_seconds": result["process"]["wall_seconds"],
        "child_capture_bytes_observed": result["resource_receipt"]["capture_bytes_observed"],
        "child_scratch_bytes_observed": result["resource_receipt"]["scratch_bytes_observed"],
        "retained_generated_proof_bytes_observed_excluding_this_receipt": retained_bytes,
        "process_group_cleanup": "confirmed", "per_child_limits": dict(limits)}
    receipt_path = out / "control-receipt.json"
    receipt_path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    return {"bundle": bundle, "matrix": matrix_path.read_text(), "receipt": receipt,
            "external_validation": checked.stdout.strip(),
            "tracer_cases": 1}


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("control-tracer", "smoke", "full", "safety", "chunk",
        "native-diagnostic", "native-prefix-diagnostic"), required=True)
    parser.add_argument("--build", type=pathlib.Path, required=True)
    parser.add_argument("--scope", type=pathlib.Path, required=True)
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.plan_only:
            if args.mode in ("control-tracer", "native-diagnostic", "native-prefix-diagnostic"):
                raise ValueError("selected-mode-does-not-support-plan-only")
            plan = plan_mode(args.mode, args.build, args.scope, args.out)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(plan, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            print(f"mode={args.mode}")
            print(f"resolved_commands={len(plan['commands'])}")
            print(f"plan_only_child_starts={plan['plan_only_child_starts']}")
            return 0
        if args.mode == "control-tracer":
            raise ValueError("control-tracer-is-owned-by-07-01")
        if args.mode == "native-diagnostic":
            result = run_native_diagnostic(args.build, args.scope, args.out)
            print(f"native_diagnostic_status={result['status']}")
            print("qualification_accepted=false")
            return 0 if result["status"] == "pass" else 1
        if args.mode == "native-prefix-diagnostic":
            result = run_native_prefix_diagnostic(args.build, args.scope, args.out)
            print(f"native_prefix_diagnostic_status={result['status']}")
            print("qualification_accepted=false")
            return 0 if result["status"] == "pass" else 1
        if args.mode == "smoke":
            result = run_smoke(args.build, args.scope, args.out)
            print(f"smoke_status={result['status']}")
            print(f"core_titles={len(result['core'])}")
            print(f"software_sdl_titles={len(result['software_sdl'])}")
            print(f"synthetic_production_starts={result['observed_exposure']['synthetic_production_starts']}")
            return 0 if result["status"] == "pass" else 1
        result = run_execution(args.mode, args.build, args.scope, args.out)
        print(f"runtime_status={result['status']}")
        print(f"observed_dimensions={len(result['observed'])}")
        return 0 if result["status"] == "pass" else 1
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        if args.mode in ("native-diagnostic", "native-prefix-diagnostic"):
            print("BLOCKED: native diagnostic validation or bounded stage failed", file=sys.stderr)
        else:
            print("BLOCKED: " + str(sys.exc_info()[1]), file=sys.stderr)
        return 1


if __name__ == "__main__":
    os.environ["GENEWHIP_PROCESS_CONTEXT"] = "host-cleanup-v1"
    raise SystemExit(main())

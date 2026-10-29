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
        runs: list[dict] = []
        streams: dict = {}
        result = route_contract._run_client(pathlib.Path(command[0]), command, runs, report=report,
            timeout=timeout, cwd=cwd, env=env, retained_streams=streams,
            monitored_files=files, monitored_directories=directories,
            limits=limits, scratch_roots=(cwd,))
        fixture.write_json(cwd / "process.json", {"processes": runs, "streams": streams})
        return result, runs[-1], streams

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
                desktop.host_batch(backend, build, core_path, mapping_path, host_path, candidate_path)
                host = json.loads(host_path.read_text())
                compiler.validate_host_report(host, candidate)
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
    parser.add_argument("--mode", choices=("control-tracer", "smoke", "full", "safety", "chunk"), required=True)
    parser.add_argument("--build", type=pathlib.Path, required=True)
    parser.add_argument("--scope", type=pathlib.Path, required=True)
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.plan_only:
            if args.mode == "control-tracer":
                raise ValueError("control-tracer-does-not-support-plan-only")
            plan = plan_mode(args.mode, args.build, args.scope, args.out)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(plan, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            print(f"mode={args.mode}")
            print(f"resolved_commands={len(plan['commands'])}")
            print(f"plan_only_child_starts={plan['plan_only_child_starts']}")
            return 0
        if args.mode == "control-tracer":
            raise ValueError("control-tracer-is-owned-by-07-01")
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
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print("BLOCKED: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    os.environ["GENEWHIP_PROCESS_CONTEXT"] = "host-cleanup-v1"
    raise SystemExit(main())

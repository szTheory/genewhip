#!/usr/bin/env python3
"""Plan47 no-process selector, guard-order, and semantic-boundary contract."""
from __future__ import annotations

import importlib.util
import copy
import hashlib
import contextlib
import io
import json
import os
import pathlib
import subprocess
import sys
import shutil
import types

ROOT = pathlib.Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/47-evidence"


def redact_text(value: str) -> str:
    text = value.replace(str(ROOT), "[workspace]")
    home = pathlib.Path.home().as_posix()
    if home and home != "/":
        text = text.replace(home, "[local-home]")
    return text


class DeniedProcessCall(RuntimeError):
    pass


def main() -> int:
    args = list(sys.argv[1:])
    if args != ["--self-test", "--output", ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/47-evidence/tests.json"]:
        print("usage: phase6_tank_checkpoint_contract.py --self-test --output .planning/.../tests.json", file=sys.stderr)
        return 2
    attempts = []
    sticky = {"denied": False}

    def deny(name):
        def blocked(*argv, **kwargs):
            attempts.append({"api": name, "argv": [str(v)[:160] for v in argv[:1]]})
            sticky["denied"] = True
            raise DeniedProcessCall("plan47-no-process-denial:" + name)
        return blocked

    # Install every supported process-creation denial before importing either changed module.
    subprocess.Popen = deny("subprocess.Popen")
    subprocess.run = deny("subprocess.run")
    subprocess.call = deny("subprocess.call")
    subprocess.check_call = deny("subprocess.check_call")
    subprocess.check_output = deny("subprocess.check_output")
    os.system = deny("os.system")
    for name in ("fork", "forkpty", "posix_spawn", "posix_spawnp", "execv", "execve", "execvp", "execvpe",
                 "spawnv", "spawnve", "spawnvp", "spawnvpe", "execl", "execle", "execlp",
                 "spawnl", "spawnle", "spawnlp", "spawnlpe"):
        if hasattr(os, name):
            setattr(os, name, deny("os." + name))

    # Audit events provide a second independent tripwire for the interpreter's
    # process APIs. Install it before any changed project module is imported.
    def audit(event, args):
        if event in {"subprocess.Popen", "os.system", "os.fork", "os.forkpty", "os.exec",
                     "os.spawn", "os.posix_spawn", "os.posix_spawnp"}:
            sticky["denied"] = True
            attempts.append({"api": "audit:" + event, "argv": []})
            raise DeniedProcessCall("plan47-audit-denial:" + event)
    sys.addaudithook(audit)
    # Prove that the installed boundary denies a direct attempt before any
    # changed project source is imported.
    preimport_blocked = False
    try:
        subprocess.Popen([sys.executable, "-c", "pass"])
    except DeniedProcessCall:
        preimport_blocked = True
    if not preimport_blocked or not sticky["denied"]:
        raise AssertionError("pre-import process-denial self-test failed")

    output = EVIDENCE / "tests.json"
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    synthetic = next((EVIDENCE / f".contract-synthetic-root-{index}"
                      for index in range(1,5)
                      if not (EVIDENCE / f".contract-synthetic-root-{index}").exists()), None)
    if synthetic is None:
        raise RuntimeError("four retained contract failure roots already exist; inspect before another run")
    succeeded = False
    try:
        coordinator_path = synthetic / "tests/fixtures/phase6_repairs.py"
        helper_path = synthetic / "scripts/evidence/phase6_tank_checkpoint.py"
        coordinator_path.parent.mkdir(parents=True)
        helper_path.parent.mkdir(parents=True)
        (synthetic / "tests/evidence").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "tests/fixtures/phase6_repairs.py", coordinator_path)
        shutil.copyfile(ROOT / "scripts/evidence/phase6_tank_checkpoint.py", helper_path)
        shutil.copyfile(ROOT / "tests/fixtures/phase4_game.py", synthetic / "tests/fixtures/phase4_game.py")
        shutil.copyfile(ROOT / "tests/evidence/phase6_tank_checkpoint_contract.py",
                        synthetic / "tests/evidence/phase6_tank_checkpoint_contract.py")
        # Data-only identity inputs are copied by relative path. The tracked game
        # payload is replaced by an invalid sentinel below.
        for rel in (
            ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-47-PLAN.md",
            ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/47-evidence/selection.json",
            ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/47-evidence/continuation.json",
            ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/47-evidence/guard-review.md",
            "evidence/phase6-repairs.json",
            "fixtures/independent-game-v2/scenario.json",
            "fixtures/independent-game-v2/oracle.json",
            "fixtures/independent-game-v2/src/game.s",
            "fixtures/independent-game-v2/host-controls.json",
            "fixtures/phase5-a/scenario.json","fixtures/phase5-a/oracle.json",
            "fixtures/phase5-a/input-program.json","fixtures/phase5-a/reference-build-record.json",
            "fixtures/phase5-b/scenario.json","fixtures/phase5-b/oracle.json",
            "fixtures/phase5-b/input-program.json","evidence/phase5-baseline.json",
            "evidence/phase5-baseline-roster.json","evidence/phase5-failure-inventory.json",
            "evidence/phase5-current-reference.json","evidence/phase5-reference-d118.json",
            "tests/session/phase6_route_contract.py","CMakeLists.txt",
            "scripts/evidence/phase6_routes.py",
            "tests/api/load_contract.c","tests/api/time_contract.c","tests/api/reset_contract.c",
            "tests/api/bus_boundary_contract.c","tests/api/gameplay_bus_contract.c",
            "tests/api/movem_contract.c","tests/api/phase6_repairs_contract.c",
        ):
            target = synthetic / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / rel, target)
        for folder in ("src","include","tools","cmake"):
            source=ROOT/folder
            if source.exists():
                shutil.copytree(source,synthetic/folder,dirs_exist_ok=True)
        # Game ROM files required only as identity paths are non-executable invalid
        # sentinels, never copied from the checkout.
        for rel in ("fixtures/phase5-a/game.bin","fixtures/phase5-b/game.bin"):
            target=synthetic/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(b"not-a-rom\0")
        game_fixture = synthetic / "fixtures/independent-game-v2/game.bin"
        game_fixture.parent.mkdir(parents=True, exist_ok=True)
        game_fixture.write_bytes(b"not-a-rom\0")
        # Sentinels are deliberately invalid, tiny bytes. No checkout path or usable
        # game/client payload is made available to subject code.
        invalid = synthetic / "synthetic-inputs"
        invalid.mkdir()
        (invalid / "client.invalid").write_bytes(b"not-an-executable\0")
        (invalid / "rom.invalid").write_bytes(b"not-a-rom\0")
        synthetic_output = synthetic / "tests.json"
        # Verify the independent source review against the exact four copied
        # files before importing either changed coordinator/helper module.
        source_review_path=synthetic/".planning/phases/GW-06-shared-repairs-and-two-playable-routes/47-evidence/guard-review.md"
        source_review=json.loads(source_review_path.read_bytes())
        reviewed_names=("tests/fixtures/phase6_repairs.py","tests/fixtures/phase4_game.py",
            "scripts/evidence/phase6_tank_checkpoint.py","tests/evidence/phase6_tank_checkpoint_contract.py")
        source_hashes={name:hashlib.sha256((synthetic/name).read_bytes()).hexdigest() for name in reviewed_names}
        findings=source_review.get("findings",[])
        high=sum(item.get("severity") in ("high","critical") for item in findings)
        critical=sum(item.get("blocking") is True for item in findings)
        if (source_review.get("schema")!="genewhip-plan47-source-review-v1" or
            source_review.get("reviewer_identity")!="/root/continuation47_review" or
            source_review.get("reviewer_role")!="independent source guard and expectation reviewer" or
            source_review.get("source_hashes")!=source_hashes or high!=0 or critical!=0 or
            source_review.get("high_count")!=high or source_review.get("critical_count")!=critical or
            source_review.get("verdict")!="APPROVE"):
            raise AssertionError("exact independent source review missing or does not approve copied sources")
        spec = importlib.util.spec_from_file_location("phase6_repairs_guarded47", coordinator_path)
        coordinator = importlib.util.module_from_spec(spec)
        original_argv = sys.argv
        try:
            sys.argv = [str(coordinator_path), "--tank-checkpoint47"]
            spec.loader.exec_module(coordinator)
        finally:
            sys.argv = original_argv
        with contextlib.redirect_stderr(io.StringIO()):
            mixed_result=coordinator.main(["--tank-checkpoint47","--self-test","--pea-regressions"])
        if mixed_result == 0:
            raise AssertionError("mixed Plan47 and retired flags were accepted")
        result = coordinator.main(["--tank-checkpoint47", "--self-test", "--output", str(synthetic_output)])
        if result != 0:
            raise AssertionError("actual coordinator early Plan47 self-test dispatch failed")
        if not sticky["denied"] or not any(item["api"] == "subprocess.Popen" for item in attempts):
            raise AssertionError("lowest OS callback was not reached under denial boundary")
        # Patch an irrelevant API, then hit the real lowest launch seam again. This
        # catches a harness that mocks a convenient wrapper instead of Popen itself.
        helper_spec = importlib.util.spec_from_file_location("phase6_checkpoint_guarded47", helper_path)
        helper = importlib.util.module_from_spec(helper_spec)
        helper_spec.loader.exec_module(helper)
        checks = ["source-review-verified-before-import"]
        checks.append("mixed-legacy-flags-rejected")
        rejection_reasons={
            **{name:"ValueError:pea-check-failed:" for name in ("bad-opcode","bad-a7","bad-stack-byte",
                "bad-stack-address","bad-stack-status","bad-pea-ticks","bad-next-terminal-metadata",
                "bad-probe-is-not-retired")},
            "descriptor-watch-bound":"ValueError:watch-count-bound",
            "spent-slot":"FileExistsError:","double-writer":"FileExistsError:",
            "stale-control-source":"ValueError:control-report-identity-or-status-invalid",
            "stale-control-build":"ValueError:control-report-identity-or-status-invalid",
            "stale-control-rom":"ValueError:control-report-identity-or-status-invalid",
            "stale-control-contract":"ValueError:control-report-identity-or-status-invalid",
            "stale-control-case":"ValueError:original-control-source-predicate-invalid:",
            "skipped-control-case":"ValueError:control-case-order-invalid",
            "wrong-control-case":"ValueError:control-case-order-invalid",
            "duplicate-control-case":"ValueError:control-case-order-invalid",
            "extra-control-case":"ValueError:control-case-order-invalid",
            "missing-control-pcm":"FileNotFoundError:",
            "changed-control-terminal":"ValueError:original-control-raw-observation-invalid:",
            "wrong-control-child-group":"ValueError:original-control-child-identity-or-group-invalid",
            "malformed-child-json":"JSONDecodeError:",
            "truncated-child-stream":"ValueError:original-control-child-stream-invalid:",
            "malformed-child-json":"JSONDecodeError:",
            "stale-source-identity":"ValueError:source-identity-drift-before-slot",
            "stale-rom-identity":"ValueError:source-identity-drift-before-slot",
            "stale-contract-identity":"ValueError:source-identity-drift-before-slot",
            "stale-case-identity":"ValueError:source-identity-drift-before-slot",
            "stale-build-identity":"ValueError:build-identity-drift-before-slot",
            "terminal-deadline-bound":"TimeoutError:engineering-terminal-reserve-reached",
            "workspace-disk-bound":"RuntimeError:workspace-disk-bound",
            "bounded-stream-output-limit":"RuntimeError:bounded-stream-cap",
            "stale-selection":"ValueError:plan47-continuation-mismatch",
            "historical-ledger-write-detected":"ValueError:historical-ledger-changed",
            "stale-plan-source":"ValueError:selected-plan-bytes-changed",
            "source-review-reject-record":"ValueError:source-review-record-invalid-or-not-approved",
            "duplicate-json-key":"ValueError:synthetic-record-not-strict-json",
            "ctest-missing-row":"ValueError:ctest-seven-contract-denominator-invalid",
            "ctest-duplicate-row":"ValueError:ctest-seven-contract-denominator-invalid",
            "ctest-wrong-test":"ValueError:ctest-seven-contract-denominator-invalid",
            "ctest-six-denominator":"ValueError:ctest-seven-contract-denominator-invalid",
        }

        def rejected(name, callback, expected=(ValueError, KeyError, TypeError, FileExistsError,
                                               FileNotFoundError, RuntimeError)):
            try:
                callback()
            except expected as exc:
                prefix=rejection_reasons.get(name)
                actual=type(exc).__name__+":"+str(exc)
                if prefix is None or not actual.startswith(prefix):
                    raise AssertionError("mutant failed for unrelated reason: "+name+" -> "+actual) from exc
                checks.append(name)
            else:
                raise AssertionError("mutant accepted: " + name)

        ctest_names=("load_contract","time_contract","reset_contract","bus_boundary_contract",
                     "gameplay_bus_contract","movem_contract","phase6_repairs_contract")
        ctest_rows="\n".join(f"{i}/7 Test #{i}: {name} ................................   Passed  0.01 sec"
                             for i,name in enumerate(ctest_names,1))
        ctest_old=(ctest_rows+"\n100% tests passed, 0 tests failed out of 7\n").encode()
        ctest_new=(ctest_rows+"\n100% tests passed out of 7\n").encode()
        helper.validate_ctest_seven(ctest_old,b"")
        checks.append("ctest-old-summary-form-accepted")
        helper.validate_ctest_seven(ctest_new,b"")
        checks.append("ctest-new-summary-form-accepted")
        rejected("ctest-missing-row",lambda:helper.validate_ctest_seven(
            ("\n".join(ctest_rows.splitlines()[:-1])+"\n100% tests passed out of 7\n").encode(),b""))
        rejected("ctest-duplicate-row",lambda:helper.validate_ctest_seven(
            (ctest_rows+"\n7/7 Test #7: phase6_repairs_contract ........ Passed 0.01 sec\n100% tests passed out of 7\n").encode(),b""))
        wrong_row=ctest_rows.replace("5/7 Test #5: gameplay_bus_contract","5/7 Test #5: wrong_contract")
        rejected("ctest-wrong-test",lambda:helper.validate_ctest_seven(
            (wrong_row+"\n100% tests passed out of 7\n").encode(),b""))
        six_rows=ctest_rows.replace("/7 Test #","/6 Test #").replace("/7 Test #", "/6 Test #")
        rejected("ctest-six-denominator",lambda:helper.validate_ctest_seven(
            (six_rows+"\n100% tests passed out of 6\n").encode(),b""))

        # Independently grounded positive PEA observation: fixed original opcode,
        # split instruction bytes, source A7 and next unsupported boundary.
        addresses = [0x0FFC, 0x0FFD, 0x0FFE, 0x0FFF]
        before = {"pc":0xEC32,"sr":0x2700,"tick":100,"instructions":9,"a":[0]*7+[0x1000],
                  "spans":[{"address":0xEC32,"bytes":"4879"},{"address":0xEC34,"bytes":"0006"},
                           {"address":0xEC36,"bytes":"923c"}],
                  "stack_observation":{"source_a7":0x1000,"base32":0x0FFC,"addresses24":addresses,
                    "bytes":[0,0,0,0],"status":[0,0,0,0],"read_calls":4,"disposition":"observed"}}
        after = {"pc":0xEC38,"sr":0x2700,"tick":240,"instructions":10,"a":[0]*7+[0x0FFC],
                 "stack_observation":{"source_a7":0x1000,"base32":0x0FFC,"addresses24":addresses,
                    "bytes":[0,6,0x92,0x3C],"status":[0,0,0,0],"read_calls":4,"disposition":"observed"}}
        observation = {"schema":"genewhip-route-native-v1","probe_boundary":{"instruction_address":0xEC32,
            "opcode":0x4879,"retired":True,"before":before,"after":after},"stop_reason":2,"fields":1,
            "active_ticks":140,"boundary_calls":1,"queue_high_water":1,"instruction_address":0xEC3A,
            "opcode":0x4E71,"first_stop_tick":280,"final_tick":280,
            "last_boundary":{"instruction_address":0xEC3A,"opcode":0x4E71,"stop_reason":2,
                             "after":{"tick":280,"instructions":11}}}
        if not all(helper.pea_predicates(observation)["assertions"].values()):
            raise AssertionError("independent positive PEA vector rejected")
        checks.append("positive-pea-split-instruction")
        for name, mutate in (
            ("bad-opcode", lambda x: x["probe_boundary"].update(opcode=0x4878)),
            ("bad-a7", lambda x: x["probe_boundary"]["after"]["a"].__setitem__(7,0x0FFB)),
            ("bad-stack-byte", lambda x: x["probe_boundary"]["after"]["stack_observation"]["bytes"].__setitem__(3,0)),
            ("bad-stack-address", lambda x: x["probe_boundary"]["after"]["stack_observation"]["addresses24"].__setitem__(0,0)),
            ("bad-stack-status", lambda x: x["probe_boundary"]["after"]["stack_observation"]["status"].__setitem__(0,9)),
            ("bad-pea-ticks", lambda x: x["probe_boundary"]["after"].update(tick=241)),
            ("bad-next-terminal-metadata", lambda x: x["last_boundary"]["after"].update(tick=281)),
            ("bad-probe-is-not-retired", lambda x: x["probe_boundary"].update(retired=False)),
        ):
            mutant = copy.deepcopy(observation); mutate(mutant)
            rejected(name, lambda mutant=mutant: helper.pea_predicates(mutant))

        # Descriptor offsets are independently inspected, including append with
        # existing watch rows and real rejection at the 64-row bound.
        import struct
        descriptor = bytearray(144)
        descriptor[:4] = b"GWRC"
        struct.pack_into("<I", descriptor, 24, 1)
        descriptor[128:144] = struct.pack("<IIII",0x00AA55,0x00AA55,2,0)
        appended = helper._append_watches(bytes(descriptor))
        words = struct.unpack("<" + "I"*(len(appended)//4), appended)
        if (words[6] != 4 or appended[128:144] != bytes(descriptor[128:144]) or
                struct.unpack_from("<IIII",appended,144)!=(0xEC32,0xEC32,2,0)):
            raise AssertionError("watch extension did not occupy independently expected byte offset")
        checks.append("descriptor-watch-byte-layout")
        rejected("descriptor-watch-bound", lambda: helper._append_watches(
            b"GWRC" + b"\0"*20 + struct.pack("<I",62) + b"\0"*(128-28)))

        # Create-once slot rejection uses a fresh synthetic directory only.
        slot_root = synthetic / "slot-test"
        helper._reserve("synthetic-spent-slot", "a"*64,"b"*64,"c"*64,["sentinel"],slot_root)
        rejected("spent-slot", lambda: helper._reserve("synthetic-spent-slot", "a"*64,"b"*64,
                                                         "c"*64,["sentinel"],slot_root))

        # Exercise both bounded runners at the lowest mocked OS seam. A fake
        # selector stays readable until the fake monotonic deadline expires.
        class FakeSelector:
            def register(self, *_a, **_k): pass
            def get_map(self): return {1: object()}
            def select(self, *_a, **_k): return []
            def close(self): pass
        class FakeProcess:
            pid = 4747
            stdout = types.SimpleNamespace(close=lambda: None, fileno=lambda: 1)
            stderr = types.SimpleNamespace(close=lambda: None, fileno=lambda: 2)
            returncode = None
            def wait(self, **_k): self.returncode = -9; return self.returncode
            def kill(self): self.killed = True
        fake_events = []
        def exercise_helper_group():
            fake = FakeProcess()
            clock_values = iter((100.0, 101.0, 102.0, 103.0))
            old = (helper.subprocess.Popen, helper.selectors.DefaultSelector, helper.time.monotonic,
                   helper.os.getpgid, helper.os.killpg)
            helper.subprocess.Popen = lambda *_a, **_k: fake
            helper.selectors.DefaultSelector = FakeSelector
            helper.time.monotonic = lambda: next(clock_values)
            helper.os.getpgid = lambda _pid: 4747
            def killpg(pid, sig):
                fake_events.append(("helper-killpg", pid, sig))
                raise ProcessLookupError()
            helper.os.killpg = killpg
            try:
                try: helper._run_bounded(["fake-child"], timeout=0.5, cwd=synthetic, cap=32)
                except TimeoutError: pass
                else: raise AssertionError("fake helper process did not time out")
            finally:
                (helper.subprocess.Popen, helper.selectors.DefaultSelector, helper.time.monotonic,
                 helper.os.getpgid, helper.os.killpg) = old
        exercise_helper_group()
        if not any(row[0] == "helper-killpg" and row[1] == 4747 for row in fake_events):
            raise AssertionError("inner helper did not attempt fake process-group cleanup")
        checks.append("helper-process-group-timeout-cleanup")

        phase4_path = synthetic / "tests/fixtures/phase4_game.py"
        p4_spec = importlib.util.spec_from_file_location("phase4_game_guarded47", phase4_path)
        phase4 = importlib.util.module_from_spec(p4_spec); p4_spec.loader.exec_module(phase4)
        fake_events.clear()
        fake = FakeProcess()
        old = (phase4.subprocess.Popen, phase4.selectors.DefaultSelector, phase4.time.monotonic,
               phase4.os.getpgid, phase4.os.getpgrp, phase4.os.killpg)
        phase4.subprocess.Popen = lambda *_a, **_k: fake
        phase4.selectors.DefaultSelector = FakeSelector
        clock_values = iter((200.0, 201.0, 202.0, 203.0))
        phase4.time.monotonic = lambda: next(clock_values)
        phase4.os.getpgid = lambda _pid: 4747
        phase4.os.getpgrp = lambda: 4747
        phase4.os.killpg = lambda *args: fake_events.append(("outer-killpg",) + args)
        try:
            try: phase4.bounded_run(["fake-child"], timeout=0.1, outer_process_group=True)
            except phase4.BoundedProcessError: pass
            else: raise AssertionError("fake phase4 process did not time out")
        finally:
            (phase4.subprocess.Popen, phase4.selectors.DefaultSelector, phase4.time.monotonic,
             phase4.os.getpgid, phase4.os.getpgrp, phase4.os.killpg) = old
        if not getattr(fake, "killed", False) or any(event[0] == "outer-killpg" for event in fake_events):
            raise AssertionError("outer-group wrapper failed to kill only its child")
        checks.append("phase4-outer-group-child-cleanup")

        # Build an explicitly synthetic (never gameplay evidence) complete control
        # report from the immutable scenario/oracle and fake child observations.
        # This exercises the real validator's positive path before rejection cases.
        scenario_path = synthetic / "fixtures/independent-game-v2/scenario.json"
        oracle_path = synthetic / "fixtures/independent-game-v2/oracle.json"
        scenario = json.loads(scenario_path.read_bytes()); oracle = json.loads(oracle_path.read_bytes())
        build = synthetic / "fake-build"
        binary = build / "tools/session/gw_headless"; binary.parent.mkdir(parents=True)
        binary.write_bytes(b"not-an-executable\0")
        cache = build / "CMakeCache.txt"; cache.write_bytes(b"synthetic cache\n")
        manifest = {"build":{"cache_sha256":helper.digest(cache),"binary_sha256":helper.digest(binary),
                              "binary_path":"fake-build/tools/session/gw_headless"}}
        raw_dir = synthetic / "synthetic-raw"; pcm_dir = synthetic / "synthetic-pcm"
        raw_dir.mkdir(); pcm_dir.mkdir()
        control_report = {"schema":"genewhip-phase4-gameplay-v1","outcome":"pass",
            "fixture_id":scenario["fixture_id"],"denominator":6,
            "scenario_sha256":helper.digest(scenario_path),"oracle_sha256":helper.digest(oracle_path),
            "source_sha256":scenario["source"]["sha256"],"rom_sha256":scenario["rom"]["sha256"],
            "build_configuration_sha256":manifest["build"]["cache_sha256"],
            "client_sha256":[manifest["build"]["binary_sha256"]],"clients":["headless"],
            "visual_observations":{"title_to_play_field_10_changed":True,
                                    "start_idle_to_moved_marker_field_19_changed":True},
            "results":[],"native_child_processes":[]}
        child_receipts = []
        for case in scenario["cases"]:
            case_id=case["id"]; frames=case["frames"]; expected=case["expect"]
            position=expected["position_min"]
            machine="0123456789abcdef"
            hashes=[f"{i:016x}" for i in range(frames)]
            final={"fields":frames,"unsupported":0,"stop_reason":0,"fault_address":0,
                   "ram_fnv1a64":machine,"peek":expected["play_state"].to_bytes(2,"big").hex()+position.to_bytes(2,"big").hex()}
            stdout=("\n".join(json.dumps({"sequence":i,"fnv1a64":value},sort_keys=True) for i,value in enumerate(hashes))+
                    "\n"+json.dumps(final,sort_keys=True)+"\n").encode()
            stderr=b""
            out_path=raw_dir/(case_id+".stdout.raw"); err_path=raw_dir/(case_id+".stderr.raw")
            out_path.write_bytes(stdout); err_path.write_bytes(stderr)
            stream_rows={}
            for stream_name,stream_path,stream_bytes in (("stdout",out_path,stdout),("stderr",err_path,stderr)):
                stream_rows[stream_name]={"path":stream_path.relative_to(synthetic).as_posix(),
                    "sha256":helper.digest_bytes(stream_bytes),"observed_bytes":len(stream_bytes),
                    "retained_bytes":len(stream_bytes),"truncated":False}
            pcm_frames=frames*helper.FIELD_TICKS*48000//helper.MASTER_HZ
            sound=case_id in ("action-sound","sustained-play")
            samples=bytearray()
            for _i in range(pcm_frames):
                value=12000 if sound and _i%2 else 0
                samples.extend(struct.pack("<hh",value,value))
            pcm_path=pcm_dir/(case_id+".pcm"); pcm_path.write_bytes(samples)
            all_samples=[sample[0] for sample in struct.iter_unpack("<h",samples)]
            ac_range=max(all_samples)-min(all_samples) if all_samples else 0
            control_report["results"].append({"id":case_id,"outcome":"pass","unsupported":0,
                "fields":frames,"play_state":expected["play_state"],"position":position,
                "psg":expected["psg_writes"],"retained_pcm":{"path":pcm_path.relative_to(synthetic).as_posix(),
                    "bytes":len(samples),"sha256":helper.digest_bytes(samples)},"ac_range":ac_range,
                "machine_digest":machine,"field_hashes_sha256":helper.digest_bytes("\n".join(hashes).encode())})
            control_report["native_child_processes"].append({"case":case_id,"return_code":0,
                "executable_path":manifest["build"]["binary_path"],"executable_sha256":manifest["build"]["binary_sha256"],
                "streams":stream_rows})
            child_receipts.append({"pid":4000+len(child_receipts),"pgid":3000,"driver_pgid":3000,
                "outer_process_group":True,"status":"finished","returncode":0})
        control_path=synthetic/"synthetic-control-report.json"
        receipt_path=synthetic/"synthetic-child-receipt.json"
        control_path.write_text(json.dumps(control_report,sort_keys=True))
        receipt_path.write_text(json.dumps({"processes":child_receipts},sort_keys=True))
        helper.validate_control_bundle(control_path,receipt_path,build,manifest)
        checks.append("positive-synthetic-control-bundle-six-complete-pcm")

        def control_reject(name, mutate_report=lambda _r:None, mutate_receipt=lambda _r:None):
            report_value=copy.deepcopy(control_report); receipt_value=copy.deepcopy(child_receipts)
            mutate_report(report_value); mutate_receipt(receipt_value)
            case_report=synthetic/(name+".json"); case_receipt=synthetic/(name+"-receipt.json")
            case_report.write_text(json.dumps(report_value,sort_keys=True))
            case_receipt.write_text(json.dumps({"processes":receipt_value},sort_keys=True))
            rejected(name,lambda:helper.validate_control_bundle(case_report,case_receipt,build,manifest))
        control_reject("stale-control-source",lambda r:r.update(source_sha256="0"*64))
        control_reject("stale-control-build",lambda r:r.update(build_configuration_sha256="0"*64))
        control_reject("stale-control-rom",lambda r:r.update(rom_sha256="0"*64))
        control_reject("stale-control-contract",lambda r:r.update(scenario_sha256="0"*64))
        control_reject("stale-control-case",lambda r:r["results"][0].update(fields=-1))
        control_reject("skipped-control-case",lambda r:r["results"].pop())
        control_reject("wrong-control-case",lambda r:r["results"][0].update(id="unknown-case"))
        control_reject("duplicate-control-case",lambda r:r["results"][1].update(id=r["results"][0]["id"]))
        control_reject("extra-control-case",lambda r:r["results"].append(copy.deepcopy(r["results"][-1])))
        def missing_pcm(report_value):
            report_value["results"][0]["retained_pcm"]["path"]="missing.pcm"
        control_reject("missing-control-pcm",missing_pcm)
        def change_terminal(report_value):
            stream=report_value["native_child_processes"][0]["streams"]["stdout"]
            original=(synthetic/stream["path"]).read_text().splitlines()
            final=json.loads(original[-1]);final["stop_reason"]=1;original[-1]=json.dumps(final,sort_keys=True)
            raw=("\n".join(original)+"\n").encode();path=raw_dir/"wrong-terminal.stdout.raw";path.write_bytes(raw)
            stream.update(path=path.relative_to(synthetic).as_posix(),sha256=helper.digest_bytes(raw),
                          observed_bytes=len(raw),retained_bytes=len(raw),truncated=False)
        control_reject("changed-control-terminal",change_terminal)
        control_reject("wrong-control-child-group",mutate_receipt=lambda rows:rows[0].update(pgid=9999))
        malformed_child = copy.deepcopy(control_report)
        malformed_bytes=b'{"fields":\n'
        malformed_path=raw_dir/"malformed.stdout.raw";malformed_path.write_bytes(malformed_bytes)
        stream=malformed_child["native_child_processes"][0]["streams"]["stdout"]
        stream.update(path=malformed_path.relative_to(synthetic).as_posix(),sha256=helper.digest_bytes(malformed_bytes),
                      observed_bytes=len(malformed_bytes),retained_bytes=len(malformed_bytes),truncated=False)
        malformed_report_path=synthetic/"malformed-child-json.json"
        malformed_report_path.write_text(json.dumps(malformed_child,sort_keys=True))
        rejected("malformed-child-json",lambda:helper.validate_control_bundle(
            malformed_report_path,receipt_path,build,manifest))
        truncated_child = copy.deepcopy(control_report)
        truncated_child["native_child_processes"][0]["streams"]["stdout"]["truncated"] = True
        truncated_report_path=synthetic/"truncated-child-stream.json"
        truncated_report_path.write_text(json.dumps(truncated_child,sort_keys=True))
        rejected("truncated-child-stream",lambda:helper.validate_control_bundle(
            truncated_report_path,receipt_path,build,manifest))

        # Retired history and selection are checked against copied immutable input
        # bytes. Mutants alter only the synthetic copy and restore it immediately.
        helper.check_identity(helper.SELECTION)
        checks.append("positive-selected-identity-and-ledger")
        source_record=helper.check_guard_review()
        current_sources=helper.source_identity()
        source_identity_sha=helper.digest_bytes(helper.canonical(current_sources))
        manifest.update(sources=current_sources,source_review=source_record)
        manifest_path=synthetic/"prepared-manifest.json"
        manifest_path.write_text(json.dumps(manifest,sort_keys=True))
        manifest_sha=helper.digest(manifest_path)
        helper.check_prepared_inputs(manifest,build)
        checks.append("positive-source-review-and-prelaunch-identity")
        for label,path,payload in (
            ("stale-source-identity",synthetic/"src/core.c",b"synthetic source drift\n"),
            ("stale-rom-identity",synthetic/"fixtures/phase5-a/game.bin",b"changed invalid ROM sentinel\0"),
            ("stale-contract-identity",synthetic/"fixtures/phase5-a/scenario.json",b"{}\n"),
            ("stale-case-identity",synthetic/"fixtures/independent-game-v2/scenario.json",b"{}\n"),
        ):
            original=path.read_bytes();path.write_bytes(payload)
            rejected(label,lambda:helper.check_prepared_inputs(manifest,build))
            path.write_bytes(original)
        original_cache=cache.read_bytes();cache.write_bytes(b"stale build cache\n")
        rejected("stale-build-identity",lambda:helper.check_prepared_inputs(manifest,build))
        cache.write_bytes(original_cache)
        prior_monotonic=helper.time.monotonic
        helper.time.monotonic=lambda:helper.DEADLINE-500
        try:
            rejected("terminal-deadline-bound",helper._remaining,expected=(TimeoutError,))
        finally: helper.time.monotonic=prior_monotonic
        prior_disk_limit=helper.WORKLOAD_LIMITS["disk_bytes"]
        helper.WORKLOAD_LIMITS["disk_bytes"]=0
        try:
            # Real bounded runner checks the workspace before polling; all OS
            # operations below are fake callbacks and no child is created.
            fake=FakeProcess(); clock_values=iter((300.0,301.0,302.0,303.0))
            old=(helper.subprocess.Popen,helper.selectors.DefaultSelector,helper.time.monotonic,
                 helper.os.getpgid,helper.os.killpg)
            helper.subprocess.Popen=lambda *_a,**_k:fake
            helper.selectors.DefaultSelector=FakeSelector
            helper.time.monotonic=lambda:next(clock_values)
            helper.os.getpgid=lambda _pid:4747
            helper.os.killpg=lambda *_a:None
            try:
                rejected("workspace-disk-bound",lambda:helper._run_bounded(["fake"],timeout=5,
                    cwd=synthetic,cap=32,build=build))
            finally:
                (helper.subprocess.Popen,helper.selectors.DefaultSelector,helper.time.monotonic,
                 helper.os.getpgid,helper.os.killpg)=old
        finally: helper.WORKLOAD_LIMITS["disk_bytes"]=prior_disk_limit

        class ReadableSelector(FakeSelector):
            def __init__(self): self.keys=[]
            def register(self,fileobj,_events,data):
                self.keys.append(types.SimpleNamespace(fileobj=fileobj,data=data))
            def get_map(self): return {i:key for i,key in enumerate(self.keys)}
            def select(self,*_a,**_k): return [(self.keys[0],None)] if self.keys else []
            def unregister(self,fileobj): self.keys=[key for key in self.keys if key.fileobj is not fileobj]
        fake=FakeProcess();clock_values=iter((400.0,401.0,402.0,403.0))
        old=(helper.subprocess.Popen,helper.selectors.DefaultSelector,helper.time.monotonic,
             helper.os.getpgid,helper.os.killpg,helper.os.read)
        helper.subprocess.Popen=lambda *_a,**_k:fake
        helper.selectors.DefaultSelector=ReadableSelector
        helper.time.monotonic=lambda:next(clock_values)
        helper.os.getpgid=lambda _pid:4747
        helper.os.killpg=lambda *_a:None
        helper.os.read=lambda _fd,_size:b"x"*33
        try:
            rejected("bounded-stream-output-limit",lambda:helper._run_bounded(["fake"],timeout=5,
                cwd=synthetic,cap=32))
        finally:
            (helper.subprocess.Popen,helper.selectors.DefaultSelector,helper.time.monotonic,
             helper.os.getpgid,helper.os.killpg,helper.os.read)=old

        writer_fd=helper.claim_writer()
        try: rejected("double-writer",helper.claim_writer)
        finally:
            os.close(writer_fd)
            (helper.EVIDENCE/"writer.lock").unlink()
        selection_bytes=helper.SELECTION.read_bytes()
        helper.SELECTION.write_bytes(selection_bytes+b" ")
        rejected("stale-selection",lambda:helper.check_identity(helper.SELECTION))
        helper.SELECTION.write_bytes(selection_bytes)
        ledger_bytes=helper.LEDGER.read_bytes()
        helper.LEDGER.write_bytes(ledger_bytes+b" ")
        rejected("historical-ledger-write-detected",lambda:helper.check_identity(helper.SELECTION))
        helper.LEDGER.write_bytes(ledger_bytes)
        plan_bytes=helper.PLAN.read_bytes()
        helper.PLAN.write_bytes(plan_bytes+b" ")
        rejected("stale-plan-source",lambda:helper.check_identity(helper.SELECTION))
        helper.PLAN.write_bytes(plan_bytes)

        # A failed prelaunch identity check returns failure before any receipt is
        # emitted; this catches failure paths that would falsely claim a report.
        missing_output=synthetic/"must-not-exist-receipt.json"
        with contextlib.redirect_stderr(io.StringIO()):
            failed_status=helper.main(["--execute-once","--selection","missing-selection.json",
                                       "--output",str(missing_output)])
        if failed_status == 0 or missing_output.exists():
            raise AssertionError("prelaunch failure emitted a success receipt")
        checks.append("failure-before-report")
        (synthetic/"duplicate-key.json").write_text('{"verdict":"ACCEPT","verdict":"REJECT"}')
        rejected("duplicate-json-key",lambda:helper._load_review_record(
            synthetic/"duplicate-key.json","synthetic"))

        # A recorded source-review REJECT must remain a rejection on the actual
        # review parser/validator path.
        reviewed_names=("tests/fixtures/phase6_repairs.py","tests/fixtures/phase4_game.py",
            "scripts/evidence/phase6_tank_checkpoint.py","tests/evidence/phase6_tank_checkpoint_contract.py")
        reject_review={"schema":"genewhip-plan47-source-review-v1",
            "reviewer_identity":"/root/continuation47_review",
            "reviewer_role":"independent source guard and expectation reviewer",
            "source_hashes":{name:helper.digest(synthetic/name) for name in reviewed_names},
            "findings":[{"finding":"synthetic rejection case","severity":"high","blocking":True}],
            "high_count":1,"critical_count":1,"verdict":"REJECT"}
        helper.EVIDENCE.mkdir(parents=True,exist_ok=True)
        review_path=helper.EVIDENCE/"guard-review.md"
        original_review=review_path.read_bytes() if review_path.exists() else None
        review_path.write_text(json.dumps(reject_review))
        rejected("source-review-reject-record",helper.check_guard_review)
        if original_review is not None: review_path.write_bytes(original_review)

        prior_os_system = helper.os.system
        helper.os.system = lambda *_a, **_k: None
        before = len(attempts)
        try:
            helper._run_bounded([sys.executable, "-c", "pass"], timeout=0.01,
                                cwd=synthetic, cap=1024)
        except (DeniedProcessCall, RuntimeError):
            pass
        finally:
            helper.os.system = prior_os_system
        if len(attempts) <= before or not sticky["denied"]:
            raise AssertionError("wrong-mock check failed to prove the true Popen denial")
        report = json.loads(synthetic_output.read_bytes())
        if report.get("os_process_creations") != 0:
            raise AssertionError("subject reported an OS process creation")
        inner_report=report
        tested_files=("tests/fixtures/phase6_repairs.py","tests/fixtures/phase4_game.py",
            "scripts/evidence/phase6_tank_checkpoint.py","tests/evidence/phase6_tank_checkpoint_contract.py")
        tested_sources={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in tested_files}
        safe_attempts=[{"api":row["api"],"argv":[redact_text(value) for value in row["argv"]]} for row in attempts]
        nested_checks=[{"name":"helper:"+name,"status":"passed"}
                       for name in inner_report.get("named_mutants",[])]
        named_checks=list(nested_checks)
        named_checks.extend(({"name":"helper-positive-pea-vector","status":"passed"},
                             {"name":"helper-watch-descriptor-extension","status":"passed"}))
        named_checks.extend({"name":name,"status":"passed"} for name in checks)
        named_checks.extend(({"name":"actual-coordinator-early-dispatch","status":"passed"},
                             {"name":"preimport-denial-self-test","status":"passed"},
                             {"name":"wrong-mock-still-denies-popen","status":"passed"}))
        required_names=["positive-pea-split-instruction","bad-a7","bad-opcode","spent-slot",
            "helper-process-group-timeout-cleanup","phase4-outer-group-child-cleanup",
            "positive-synthetic-control-bundle-six-complete-pcm","stale-control-source","stale-control-build",
            "stale-control-rom","stale-control-contract","stale-control-case","skipped-control-case",
            "wrong-control-case","duplicate-control-case","extra-control-case","missing-control-pcm",
            "changed-control-terminal","malformed-child-json","truncated-child-stream",
            "historical-ledger-write-detected","stale-selection","stale-plan-source","source-review-reject-record",
            "positive-source-review-and-prelaunch-identity","stale-source-identity","stale-rom-identity",
            "stale-contract-identity","stale-case-identity","stale-build-identity","terminal-deadline-bound",
            "workspace-disk-bound","double-writer","bounded-stream-output-limit","failure-before-report",
            "duplicate-json-key","mixed-legacy-flags-rejected","source-review-verified-before-import",
            "ctest-old-summary-form-accepted","ctest-new-summary-form-accepted","ctest-missing-row",
            "ctest-duplicate-row","ctest-wrong-test","ctest-six-denominator"]
        report={"schema":"genewhip-phase6-tank-checkpoint47-tests-v1","status":"passed",
            "coordinator_self_test":inner_report,
            "boundary": {"installed_before_changed_import": True,"self_tested_before_import":preimport_blocked,
            "attempted_calls": safe_attempts,
            "denied_sticky_even_if_caught": sticky["denied"], "actual_coordinator_selector_reached": True,
            "changed_project_modules_imported_before_deny": False,
            "source_review_verified_before_changed_import":True,
            "synthetic_root": synthetic.relative_to(ROOT).as_posix(),
            "usable_client_or_rom_present": False,"wrong_mock_test":"irrelevant os.system patched; Popen denial remained active"},
            "tested_sources":tested_sources,"checks":named_checks,
            "tests_executed":len(named_checks),
            "nested_helper_checks":nested_checks,
            "required_coverage":{name:any(item["name"]==name and item["status"]=="passed" for item in named_checks)
                                 for name in required_names},
            "guard_self_checks":named_checks,
            "named_mutants":inner_report.get("named_mutants",[])+checks,
            "os_process_creations":0,
            "observed_attempts":[{"api":item["api"],"denied":True} for item in attempts],
            "subject_denied_attempts":[{"api":item["api"],"denied":True} for item in attempts]}
        if not all(report["required_coverage"].values()):
            raise AssertionError("required contract coverage missing: "+repr([k for k,v in report["required_coverage"].items() if not v]))
        helper.EVIDENCE.mkdir(parents=True,exist_ok=True)
        synthetic_tests=helper.EVIDENCE/"tests.json"
        synthetic_tests.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
        helper.check_contract_tests()
        named_checks.append({"name":"contract-report-self-check","status":"passed"})
        report["tests_executed"]=len(named_checks)
        report["checks"]=named_checks
        report["guard_self_checks"]=named_checks
        report["required_coverage"]["contract-report-self-check"]=True
        synthetic_tests.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
        helper.check_contract_tests()
        output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        succeeded = True
        print("PLAN47 SELF-TEST PASS: coordinator dispatch and pre-import process denial; creations=0")
        return 0
    except BaseException as exc:
        # Preserve exact synthetic inputs and the available diagnostic prefix on failure.
        failure = {"status": "failed", "error": redact_text(type(exc).__name__ + ": " + str(exc)),
                   "tests_executed": None, "tests_completed_before_failure": "unknown",
                   "observed_attempts": attempts,
                   "os_process_creations": 0, "synthetic_root": synthetic.relative_to(ROOT).as_posix()}
        output.write_text(json.dumps(failure, sort_keys=True, indent=2) + "\n")
        raise
    finally:
        if succeeded and synthetic.exists():
            shutil.rmtree(synthetic)


if __name__ == "__main__":
    raise SystemExit(main())

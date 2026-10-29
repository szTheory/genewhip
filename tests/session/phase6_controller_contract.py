"""Original authored guests exercise the frozen-controller tool, not games."""
from __future__ import annotations
import argparse
import importlib.util
import json
import pathlib
import struct
import tempfile
import unittest
import hashlib

ROOT = pathlib.Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


compiler = module("phase6_compiler", ROOT / "scripts/evidence/phase6_routes.py")
contracts = module("phase6_contract", ROOT / "tests/session/phase6_route_contract.py")


class Guest:
    def __init__(self):
        self.data = bytearray(512)
        struct.pack_into(">II", self.data, 0, 0xFF8000, 0x200)
        self.labels, self.fixups = {}, []

    def emit(self, hex_bytes):
        self.data.extend(bytes.fromhex(hex_bytes))

    def word(self, address, value):
        self.data.extend(struct.pack(">HHI", 0x33FC, value, address))

    def label(self, name):
        self.labels[name] = len(self.data)

    def branch(self, opcode, label):
        self.fixups.append((len(self.data), label))
        self.data.extend(struct.pack(">HH", opcode, 0))

    def finish(self):
        for offset, label in self.fixups:
            struct.pack_into(">h", self.data, offset + 2, self.labels[label] - offset - 2)
        return bytes(self.data)


def source_guest(*, gap=False, ui=False):
    g = Guest()
    g.emit("13fc004000a10009 13fc004000a10003")
    g.word(0xFF0000, 1)
    g.emit("427900ff0010")  # Initialization clear deliberately not a marker.
    markers = []

    def step(tick, state=1, duplicate=False):
        g.word(0xFF0004, tick); g.word(0xFF0000, state)
        markers.append([len(g.data), 0x4279]); g.emit("427900ff0010")
        if duplicate:
            markers.append([len(g.data), 0x4279]); g.emit("427900ff0010")
        g.emit("103900a10003 13c000ff0020")

    step(1, duplicate=True)
    step(3 if gap else 2, 2 if ui else 1)
    if ui:
        g.word(0xFF0002, 1); g.word(0xFF0004, 0); g.word(0xFF0000, 1)
        g.emit("427900ff0010")  # Reset publication must not count.
        g.label("wait_release")
        g.emit("103900a10003 08000005")
        g.branch(0x6700, "wait_release")
        step(1)
        step(2)
    else:
        step(3)
    g.emit("4e722700")
    return g.finish(), markers


def descriptor(markers, *, ui=False, limit=3):
    h = [0] * 32
    h[1:6] = [1, 2, 4, limit, 2]
    h[14:21] = [0, 1, 2, 3, 2 if ui else 720, 1, 2]
    h[30] = 3000000
    signals = [[0xFF0000 + i * 2, 0xFF0000 + i * 2, 2, 0] for i in range(3)]
    signals += [[0xFF0010, 0xFF0010, 2, 0], [0xFF0020, 0xFF0020, 1, 0]]
    if ui:
        events = [[0, 2, 2, 0, 32, 1], [1, 0, 1, 0, 32, 0], [1, 0, 1, 0, 8, 1]]
    else:
        events = [[0, 0, 1, 0, 8, 1], [0, 2, 1, 0, 8, 0], [0, 2, 1, 0, 16, 1]]
    return h, [signals, markers, [], [], [], [], events, []]


class ControllerContract(unittest.TestCase):
    build: pathlib.Path
    runs = []
    parser_only = False
    client_modes = (False,)

    def test_consumed_map_is_explicit_and_rejects_semantic_mutants(self):
        mapping = contracts.json.loads((ROOT / "fixtures/phase6/recursion94-consumed-map-v1.json").read_text())
        self.assertEqual(len(mapping["events"]), 19)
        self.assertEqual(mapping["events"][18]["consumer_dispatch"]["tick"], 696)
        self.assertEqual(mapping["events"][18]["consumed"]["tick"], 697)
        self.assertFalse(mapping["cleanup_release"]["event_row"])
        compiler.validate_delivery_map(mapping)
        for mutate, reason in (
            (lambda m: m.update(schema="genewhip-consumed-input-map-v2"), "delivery-map-schema"),
            (lambda m: m.update(map_id="another-client-v1"), "delivery-map-client"),
            (lambda m: m["source"].update(input_program_sha256="0" * 64), "delivery-map-source-identity"),
            (lambda m: m["events"].pop(), "delivery-map-event-count"),
            (lambda m: m["events"].reverse(), "delivery-map-order"),
            (lambda m: m["events"][18].update(consumer_dispatch={"clock":"source-step","attempt":4,"tick":695}), "delivery-map-consumption:19"),
            (lambda m: m["events"][17].update(consumer_dispatch={"clock":"source-step","attempt":4,"tick":676}), "delivery-map-consumption:18"),
            (lambda m: m["events"][6].update(consumer_dispatch={"clock":"source-step","attempt":2,"tick":720}), "delivery-map-paused-meta:7"),
            (lambda m: m["cleanup_release"].update(event_row=True), "delivery-map-cleanup-is-event"),
        ):
            mutant = contracts.json.loads(contracts.json.dumps(mapping))
            mutate(mutant)
            with self.assertRaisesRegex(compiler.Invalid, reason):
                compiler.validate_delivery_map(mutant)
        with self.assertRaisesRegex(compiler.Invalid, "delivery-map-client"):
            compiler.validate_delivery_map(mapping, client="unrecognized-client")

    def execute(self, data, binary, desktop=False, expected=0, probe=None, horizon=None, prefix=False):
        with tempfile.TemporaryDirectory(prefix="gw-controller-") as directory:
            work = pathlib.Path(directory)
            rom, plan, report = work / "guest.bin", work / "route.gwrc", work / "report.json"
            rom.write_bytes(data); plan.write_bytes(binary)
            client = self.build / ("tools/desktop/genewhip-desktop" if desktop else "tools/session/gw_headless")
            extra = [] if probe is None else ["--route-instruction-probe",str(probe)]
            if horizon is not None:extra += ["--route-stop-horizon",str(horizon)]
            if prefix:extra += ["--route-probe-only"]
            if desktop:
                result = contracts._run_desktop(client, plan, report, rom, work, self.runs,extra)
            else:
                result = contracts._run_client(client, [str(client), "--route-plan", str(plan),
                    "--route-report", str(report), *extra, str(rom)], self.runs, report=report, timeout=30)
            self.assertEqual(result.returncode, expected, result.stderr)
            self.last_stderr=result.stderr
            return json.loads(report.read_text()) if report.exists() else None

    def test_instruction_probe_has_true_before_fault_and_field_equivalence(self):
        g=Guest();g.emit("7001 5280 4afc")
        h=[0]*32;h[1:6]=[1,3,2,2,0];h[30]=100000
        sections=[[[0xFF0000,0xFF0000,2,0]],[],[],[],[],[],[],[]]
        binary=compiler.encode_controller(h,sections)
        for desktop in self.client_modes:
            report=self.execute(g.finish(),binary,desktop,expected=1,probe=516)
            b=report["last_boundary"]
            self.assertEqual(b["before"]["pc"],516)
            self.assertEqual(b["before"]["d"][0],2,"reject field-start D0=0 snapshot")
            self.assertEqual(b["after"]["d"],b["before"]["d"])
            self.assertEqual(b["after"]["instructions"],b["before"]["instructions"])
            self.assertEqual(b["stop_reason"],2)
            self.assertEqual(b["fault_address"],0)
            self.assertEqual(b["opcode"],0x4afc)
            self.assertEqual(b["before"]["spans"],b["after"]["spans"])
            self.assertEqual(b["returned_overshoot"],27)
            self.assertEqual(report["probe_boundary"],b)
            missing=self.execute(g.finish(),binary,desktop,expected=1,probe=518,prefix=True)
            self.assertIsNone(missing["probe_boundary"])
            self.assertEqual(missing["termination"],"error")
            self.assertIsNone(self.execute(g.finish(),binary,desktop,expected=2,horizon=309))
            self.assertIsNone(self.execute(g.finish(),binary,desktop,expected=2,horizon=0))
            self.assertIsNone(self.execute(g.finish(),binary,desktop,expected=2,prefix=True))
        g=Guest();g.emit("13fc000100ff0000 60fe")
        for desktop in self.client_modes:
            field=self.execute(g.finish(),binary,desktop)
            instruction=self.execute(g.finish(),binary,desktop,probe=512)
            for key in ("samples","inputs","predicates","active_ticks","fields","final_tick",
                        "queue_high_water","audio_frames","audio_hash","audio_complete"):
                self.assertEqual(field[key],instruction[key],key)

    def test_stop_horizon_cannot_skip_irq_marker_or_fault(self):
        for fault in (False,True):
            g=Guest();g.word(0xFF0000,1)
            g.emit("13fc004000a10009 13fc004000a10003 33fc812000c00004")
            if fault:g.emit("2e7c00e00000")
            g.label("wait");g.emit("4e722000");g.branch(0x6000,"wait")
            handler=len(g.data);g.emit("527900ff0004")
            marker=len(g.data);g.emit("427900ff0010 103900a10003 13c000ff0020 4e73")
            data=bytearray(g.finish());struct.pack_into(">I",data,0x78,handler)
            h,sections=descriptor([[marker,0x4279]])
            h[30]=4000000
            binary=compiler.encode_controller(h,sections)
            for desktop in self.client_modes:
                reference=self.execute(data,binary,desktop,expected=1 if fault else 0,probe=marker,horizon=1)
                optimized=self.execute(data,binary,desktop,expected=1 if fault else 0,probe=marker,horizon=308)
                for key in ("samples","inputs","predicates","active_ticks","fields","final_tick","first_stop_tick",
                            "instruction_address","opcode","stop_reason","queue_high_water","audio_frames","audio_hash","audio_complete"):
                    self.assertEqual(reference[key],optimized[key],key)
                if not fault:
                    self.assertEqual(optimized["active_ticks"],3)
                    self.assertEqual([s["tick"] for s in optimized["samples"]],[1,2,3])
                    self.assertLess(optimized["boundary_calls"],reference["boundary_calls"]//100)
                else:
                    self.assertEqual(optimized["stop_reason"],3)
                    self.assertEqual(optimized["last_boundary"]["fault_address"],0xdffffc)

    def test_field_cap_cannot_pass_missing_active_duration(self):
        data,markers=source_guest();h,sections=descriptor(markers,limit=4)
        binary=compiler.encode_controller(h,sections)
        for desktop in self.client_modes:
            report=self.execute(data,binary,desktop,expected=1)
            self.assertEqual(report["fields"],4)
            self.assertEqual(report["active_ticks"],3)
            self.assertNotEqual(report["status"],0,"field limit is not source-duration success")
            self.assertEqual(report["termination"],"error")

    def test_source_clock_duplicates_order_gte_and_next_poll_both_clients(self):
        data, markers = source_guest()
        h, sections = descriptor(markers)
        for desktop in self.client_modes:
            with self.subTest(desktop=desktop):
                report = self.execute(data, compiler.encode_controller(h, sections), desktop)
                self.assertEqual(report["active_ticks"], 3)
                self.assertEqual([s["tick"] for s in report["samples"]], [1, 2, 3])
                # Marker2 sees the poll after marker1; marker3 sees marker2's
                # release. B is a different active-low TH-high pad lane.
                self.assertEqual(report["samples"][1]["values"][4] & 8, 0)
                self.assertEqual(report["samples"][2]["values"][4] & 8, 8)
                self.assertEqual([i["desired"] for i in report["inputs"]], [8, 0, 16, 0])
                self.assertEqual([i["active_ticks"] for i in report["inputs"][:3]], [1, 2, 2])
                if desktop:
                    self.assertEqual(report["handler"], "host-script")
                    self.assertTrue(report["audio_open"])

    def test_missing_source_step_is_not_inferred(self):
        data, markers = source_guest(gap=True)
        h, sections = descriptor(markers)
        report = self.execute(data, compiler.encode_controller(h, sections), expected=1)
        self.assertNotEqual(report["status"], 0)
        self.assertEqual(report["active_ticks"], 1)
        self.assertEqual(report["inputs"][-1]["desired"], 0)

    def test_ui_release_and_next_attempt_gaming_only_after_source_step(self):
        data, markers = source_guest(ui=True)
        h, sections = descriptor(markers, ui=True, limit=4)
        for desktop in self.client_modes:
            report = self.execute(data, compiler.encode_controller(h, sections), desktop)
            self.assertEqual([(s["attempt"], s["tick"]) for s in report["samples"]], [(0,1),(0,2),(1,1),(1,2)])
            self.assertEqual(report["active_ticks"], 4)
            press, release, right = report["inputs"][:3]
            self.assertEqual([press["desired"], release["desired"], right["desired"]], [32,0,8])
            self.assertEqual(release["active_ticks"], 2)
            self.assertEqual(right["active_ticks"], 3)
            self.assertGreaterEqual(release["field"], 1)

    def test_stop_wait_is_not_unsupported(self):
        g = Guest(); g.emit("4e722700")
        h = [0]*32; h[1:6] = [1,3,2,2,0]; h[30] = 10
        sections = [[[0xFF0000,0xFF0000,1,0]],[],[],[],[],[],[],[]]
        for desktop in self.client_modes:
            report = self.execute(g.finish(), compiler.encode_controller(h, sections), desktop)
            self.assertEqual(report["active_ticks"], 2)
            self.assertEqual(report["status"], 0)

    def test_field_timeout_boundary_and_release(self):
        g=Guest();g.word(0xFF0000,1);g.emit("4e722700")
        h=[0]*32;h[1:6]=[1,1,6,6,0];h[19]=1;h[30]=10
        sections=[[[0xFF0000,0xFF0000,2,0],[0xFF0002,0xFF0002,2,0]],[],
                  [[0,1,0,1,2]],[[0,1]],[[0,1,1,1]],[[0,0,1],[1,0,1]],[],[]]
        for desktop in self.client_modes:
            report=self.execute(g.finish(),compiler.encode_controller(h,sections),desktop,expected=1)
            self.assertEqual([s["field"] for s in report["samples"]],[1,2,3])
            self.assertEqual([(i["field"],i["desired"]) for i in report["inputs"]],[(1,1),(4,0)])

    def test_frozen_launch_field60_release61(self):
        route=next(r for r in compiler.compile_routes()["routes"] if
                   r["fixture"]=="tank-battle" and r["case"]["id"]=="withhold-early-hit")
        binary,_=compiler.lower_route(route)
        words=list(struct.unpack("<"+"I"*(len(binary)//4),binary));words[4]=62;words[13]=0;words=words[:-8]
        g=Guest();g.emit("13fc000100ff0059 4e722700")
        for desktop in self.client_modes:
            report=self.execute(g.finish(),struct.pack("<"+"I"*len(words),*words),desktop)
            self.assertEqual([(i["field"],i["desired"]) for i in report["inputs"]],[(60,64),(61,0)])

    def test_frozen_tank_parallel_targets_and_independent_release(self):
        route = next(r for r in compiler.compile_routes()["routes"]
                     if r["fixture"] == "tank-battle" and r["case"]["id"] == "withhold-late-hit")
        binary, metadata = compiler.lower_route(route)
        # Original guest supplies bounded abstract state trajectories, never
        # copied Tank gameplay. Only the test run bounds/predicate list change.
        words = list(struct.unpack("<"+"I"*(len(binary)//4), binary))
        words[3], words[4], words[5], words[13], words[21], words[22] = 4500,12,0,0,1,1
        words = words[:-8]  # Two predicate records are absent in this short guest.
        g = Guest()
        for address, value in ((0xFF042C,4),(0xFF042E,1),(0xFF0438,31),(0xFF043A,2)):
            g.word(address, value)
        g.emit("13fc000100ff0059 13fc004000a1000b 13fc004000a10005 "
               "13fc004000a10009 13fc004000a10003")
        g.label("poll")
        g.emit("103900a10005 08000000")
        g.branch(0x6600,"p1")
        g.word(0xFF043A,1)
        g.label("p1")
        g.emit("103900a10003 08000004")
        g.branch(0x6600,"poll")
        g.emit("13fc000100ff0433")
        g.branch(0x6000,"poll")
        for desktop in self.client_modes:
            report = self.execute(g.finish(), struct.pack("<"+"I"*len(words),*words), desktop)
            self.assertFalse(any(i["port"]==0 and i["desired"] & 1 for i in report["inputs"]))
            p2 = [i["desired"] for i in report["inputs"] if i["port"]==1]
            self.assertEqual(p2,[1,0])
            shot = next(i for i in report["inputs"] if i["port"]==0 and i["desired"]==16)
            self.assertGreater(shot["field"], next(i["field"] for i in report["inputs"] if i["port"]==1 and i["desired"]==0))
            self.assertEqual(metadata["signals"][0]["source_address"],0xE0FF0059)
            self.assertEqual(report["samples"][-1]["values"][3],1)

    def test_all_descriptors_both_clients_control_and_identified_instruction_prefixes(self):
        roster = compiler.compile_routes()
        for route in roster["routes"]:
            fixture,case=route["fixture"],route["case"]["id"]
            is_control=fixture=="genewhip-independent-game-v2"
            binary, metadata = compiler.lower_route(route)
            path = {"recursion94":"fixtures/phase5-b/game.bin","tank-battle":"fixtures/phase5-a/game.bin",
                    "genewhip-independent-game-v2":"fixtures/independent-game-v2/game.bin"}[fixture]
            for desktop in self.client_modes:
                report = self.execute((ROOT/path).read_bytes(), binary, desktop,
                    probe=None if is_control else 0x204 if fixture=="tank-battle" else 0x7f3c,
                    prefix=not is_control)
                self.assertEqual(report["plan_fnv1a64"],compiler.plan_fingerprint(binary))
                if fixture=="tank-battle":
                    self.assertIsNotNone(report,"admitted Tank must pass the public loader")
                    self.assertEqual(report["termination"],"diagnostic-prefix")
                    self.assertEqual(report["fields"],0)
                    self.assertEqual(report["final_tick"],196)
                    self.assertEqual(report["instruction_address"],0x0204)
                    self.assertEqual(report["opcode"],0x4E67)
                    self.assertTrue(report["probe_boundary"]["retired"])
                    self.assertEqual(report["probe_boundary"]["after"]["a"][7],0xe1000000)
                elif fixture=="recursion94":
                    self.assertEqual(report["termination"],"diagnostic-prefix")
                    self.assertEqual(report["instruction_address"],0x7f3c)
                    self.assertEqual(report["opcode"],0x80FC)
                    self.assertIsNone(report["first_stop_tick"])
                    self.assertEqual(report["final_tick"],20825728)
                    self.assertEqual(report["fields"],23)
                    self.assertEqual(report["active_ticks"],0)
                    self.assertEqual(report["probe_boundary"]["before"]["d"][0],1)
                    self.assertEqual(report["probe_boundary"]["after"]["d"][0],0x10000)
                else:
                    self.assertEqual(report["fields"],route["case"]["frames"])
                    if case in ("start-move","sustained-play"):
                        self.assertGreater(report["samples"][-1]["values"][1],0)

    def test_new_descriptor_corruptions_rejected_before_report(self):
        data, markers = source_guest()
        h, sections = descriptor(markers)
        base = compiler.encode_controller(h,sections)
        def change(word,value):
            b=bytearray(base);struct.pack_into("<I",b,word*4,value);return bytes(b)
        mutants={"version":change(1,2),"kind":change(2,99),"total":change(3,7201),
                 "active":change(4,3601),"signals":change(6,129),"reserved":change(31,1),
                 "truncated":base[:-1],"trailing":base+b"\0\0\0\0","source-mask":change(33,0x1000000),
                 "width":change(34,3),"endian":change(35,2),"oversized":base+b"\0"*1048576}
        marker_word=32+sum(len(record) for record in sections[0])
        event_word=marker_word+sum(len(record) for record in sections[1])
        mutants.update({"byte-source-clock":change(34,1),"empty-markers":change(7,0),
                        "bad-marker-opcode":change(marker_word+1,0x4E71),
                        "duplicate-marker":change(marker_word+2,sections[1][0][0]),
                        "event-order":change(event_word,2),
                        "event-port":change(event_word+3,2),
                        "event-button":change(event_word+4,3),
                        "event-state":change(event_word+2,3),
                        "event-asserted":change(event_word+5,2)})
        for name,binary in mutants.items():
            for desktop in self.client_modes:
                with self.subTest(mutant=name,desktop=desktop):
                    self.assertIsNone(self.execute(data,binary,desktop,expected=1))

    def test_digestchecked_process_receipt_cannot_invent_oracle_results(self):
        route=next(r for r in compiler.compile_routes()["routes"] if
                   r["fixture"]=="tank-battle" and r["case"]["id"]=="full-route")
        binary,metadata=compiler.lower_route(route)
        # Synthetic parser fixture only. It independently supplies raw signal
        # rows so the validator must derive facts instead of trusting summaries.
        samples=[]
        for clock in range(1,3601):
            values=[0]*len(metadata["signals"]);values[0]=1
            values[3]=0 if clock<120 else 1 if clock<2761 else 2
            samples.append({"field":clock,"active_ticks":clock,"attempt":0,"tick":0,"state":1,"values":values})
        native={"schema":"genewhip-route-native-v1","status":0,"first_stop_tick":None,
                "queue_high_water":1,"samples":samples,"active_ticks":3600,"fields":3600,
                "plan_fnv1a64":compiler.plan_fingerprint(binary),"audio_complete":True}
        with tempfile.TemporaryDirectory(dir=self.build,prefix="receipt-fixture-") as directory:
            work=pathlib.Path(directory);raw=work/"native.json";receipt_path=work/"receipt.json"
            def reference(path):
                return {"path":path.relative_to(ROOT).as_posix(),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
            receipt={"schema":"genewhip-phase6-process-receipt-v1","fixture":route["fixture"],
                "case":"full-route","stage":"interaction","identity":route["identity"],
                "exit_code":0,"host_status":"pass","completion_observed":False,
                "compiled_sha256":hashlib.sha256(binary).hexdigest(),
                "predicate_results":{"p1_score_one":{"reached":True,"value":1,"field":120},
                                     "p1_score_two":{"reached":True,"value":2,"field":2761}}}
            def validate():
                raw.write_text(json.dumps(native));receipt["native_report"]=reference(raw)
                receipt_path.write_text(json.dumps(receipt))
                compiler._validate_pass_receipt(route,"interaction",reference(receipt_path))
            validate()
            native["termination"]="diagnostic-prefix"
            with self.assertRaisesRegex(compiler.Invalid,"native-diagnostic-prefix-is-not-route-evidence"):
                validate()
            del native["termination"]
            for s in samples:s["values"][3]=0
            with self.assertRaisesRegex(compiler.Invalid,"native-predicate-unproven"):
                validate()


def main():
    parser=argparse.ArgumentParser();parser.add_argument("--build",type=pathlib.Path,required=True)
    parser.add_argument("--desktop",action="store_true",
        help="include the selected CMake tree's desktop client in this contract roster")
    parser.add_argument("--out",type=pathlib.Path,help="write parser contract receipt to caller-owned output")
    parser.add_argument("--parser-only",action="store_true",
        help="exercise only finite malformed route descriptors; creates no admitted-game route")
    args=parser.parse_args();ControllerContract.build=args.build.resolve()
    ControllerContract.parser_only=args.parser_only
    desktop=ControllerContract.build/"tools/desktop/genewhip-desktop"
    if args.desktop and not desktop.is_file():
        parser.error("--desktop selected but desktop client is missing from build")
    ControllerContract.client_modes=(False,True) if args.desktop else (False,)
    suite=unittest.TestSuite([ControllerContract("test_new_descriptor_corruptions_rejected_before_report")]) if args.parser_only else \
        unittest.defaultTestLoader.loadTestsFromTestCase(ControllerContract)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    path=args.out or args.build/"evidence/controller.json";path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps({"schema":"genewhip-phase6-controller-contract-v1",
        "status":"pass" if result.wasSuccessful() else "fail","tests":result.testsRun,
        "runs":ControllerContract.runs},indent=2)+"\n")
    return 0 if result.wasSuccessful() else 1


if __name__=="__main__":
    raise SystemExit(main())

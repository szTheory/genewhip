"""Original fakeMAME bus fixture, tooling only; no ROM/game implementation."""
from pathlib import Path
import importlib.util
import json
import subprocess
import tempfile
import unittest
import argparse

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ref", ROOT / "tests/fixtures/phase5_reference.py")
ref = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(ref)
LUAJIT = Path("/opt/homebrew/bin/luajit")
FIXTURE = r'''
local mem, held, tap, framehook, exited = {}, {}, nil, nil, false
local function byte(a,v) mem[a]=v end
local function word(a,v) byte(a,math.floor(v/256)); byte(a+1,v%256) end
local function read(a) return mem[a] or 0 end
local fields = {}
for _, label in ipairs({"Right","Up","Down","B","C"}) do
  local name="P1 "..label
  fields[name]={set_value=function(self,value) held[name]=value==1 end}
end
local space={read_u8=function(self,a) return read(a) end,
  write_u8=function() error("guest mutation forbidden") end,
  write_u16=function() error("guest mutation forbidden") end}
space.install_write_tap=function(self,first,last,name,fn)
  assert(first==0xFF1516 and last==0xFF1517); tap=fn; return {retained=true}
end
manager={machine={devices={[":maincpu"]={spaces={program=space}}},screens={[":megadriv"]={}},
 ioport={ports={[":ctrl1:mdpad:PAD"]={fields=fields}}},exit=function() exited=true end}}
emu={register_sound_update=function(fn) return fn end,register_frame_done=function(fn) return fn end,
 add_machine_frame_notifier=function(fn) framehook=fn;return fn end}
dofile(arg[1])
local function phase(v,mask)
  if tap then assert(tap(0xFF1516,v,mask or 65535)==nil,"tap replaced guest write") end
  word(0xFF1516,v)
end
local physical=0
local function field() physical=physical+1; framehook() end
local b_steps, cached_b=0, false
for attempt=0,4 do
  word(0xFF140E,attempt);word(0xFF1410,0);word(0xFF1408,1)
  byte(0xFF1519,1)
  -- Reset phase publication deliberately precedes epoch change in this fixture.
  phase(0)
  if attempt>=3 then
    assert(held["P1 C"],"C never requested replacement")
    field(); field()
    assert(not held["P1 C"],"WAIT_RELEASE deadlock")
  end
  for tick=1,720 do
    if exited then break end
    -- A video callback may see next actor motion but old tick and cleared event.
    byte(0xFF16F7,0);word(0xFF150A,0)
    byte(0xFF18C6,(32+tick)%256)
    field()
    local consumed_b=held["P1 B"]
    if arg[2]=="cached" then consumed_b=cached_b; cached_b=held["P1 B"] end
    if attempt==4 and consumed_b then b_steps=b_steps+1 end
    word(0xFF2644,b_steps)
    word(0xFF1410,tick);word(0xFF1522,tick)
    byte(0xFF13F0, math.min(attempt,2))
    word(0xFF1408,tick==720 and 2 or 1)
    byte(0xFF16F7,attempt==0 and tick==22 and held["P1 Right"] and 1 or 0)
    byte(0xFF18C5,attempt==4 and tick>=671 and 1 or 0)
    word(0xFF150A,attempt==4 and tick==720 and b_steps==24 and 1 or 0)
    phase(6)
    if arg[2]=="malformed" and tick==5 then phase(0,255) else phase(0) end
    -- Duplicate bus clears and duplicate UI/field samples must add zero.
    if tick%77==0 then phase(0) end
  end
  if exited then break end
  if attempt<2 then
    -- Old observer misses a completed timeout during reset; new tap already saw it.
    word(0xFF1408,0);word(0xFF1410,0);phase(0);field()
  elseif attempt<4 then
    field() -- old observer gets terminal720; meta C has a VBlank to reach the pad
    word(0xFF1410,0);phase(0)
  end
end
while not exited and physical<7200 do field() end
assert(exited,"bounded stop missing")
print("FIXTURE-B-STEPS,"..b_steps)
assert(not tap or GW_PHASE_TAP,"tap userdata not retained")
'''


def execute(generation="route-v3", mode="normal", mutant=False):
    package=ROOT / "local-fixtures/phase5/recursion94" / generation
    scenario=ref.read_json(package / "scenario.json")
    template=(package / "mame.lua").read_text()
    if mutant:
        template=template.replace("return nil", "return 0")
    script=ref._lua_script(scenario,scenario["cases"][0],template)
    with tempfile.TemporaryDirectory() as directory:
        work=Path(directory); (work/"route.lua").write_text(script);(work/"fixture.lua").write_text(FIXTURE)
        result=subprocess.run([str(LUAJIT),str(work/"fixture.lua"),str(work/"route.lua"),mode],
                              capture_output=True,timeout=10)
    return scenario,result


class CompletedStepContract(unittest.TestCase):
    def test_cached_pad_old696_is23_and_corrected695_is24_stable720(self):
        for generation,count,stable in (("route-v3",23,0),("route-v4",24,1)):
            with self.subTest(generation=generation):
                scenario,result=execute(generation,mode="cached")
                self.assertEqual(result.returncode,0,result.stderr.decode())
                self.assertNotIn(b"GWERROR",result.stdout)
                self.assertIn(f"FIXTURE-B-STEPS,{count}".encode(),result.stdout)
                rows=ref.parse_capture(b"\n".join(l for l in result.stdout.splitlines() if l.startswith(b"GWCAP,")),scenario)
                self.assertEqual(rows[-1]["signals"]["active_ticks"],3600)
                self.assertEqual(rows[-1]["signals"]["gameplay_result"],stable)
                self.assertEqual(rows[-1]["signals"]["device2_timer"],count)
                self.assertEqual(rows[-1]["signals"]["engine_tick_hi"]*256+rows[-1]["signals"]["engine_tick_lo"],720)
        old=ROOT/"local-fixtures/phase5/recursion94/route-v3"
        new=old.with_name("route-v4")
        self.assertEqual((old/"mame.lua").read_bytes(),(new/"mame.lua").read_bytes())
        self.assertEqual((old/"oracle.json").read_bytes(),(new/"oracle.json").read_bytes())

    def test_actual_lua_nil_tap_counts3600_and_delivers24_B_steps(self):
        scenario,result=execute()
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertNotIn(b"GWERROR",result.stdout)
        self.assertIn(b"FIXTURE-B-STEPS,24",result.stdout)
        raw=b"\n".join(l for l in result.stdout.splitlines() if l.startswith(b"GWCAP,"))
        rows=ref.parse_capture(raw,scenario)
        self.assertEqual(rows[-1]["signals"]["active_ticks"],3600)
        primary={**scenario,"cases":scenario["cases"][:1]}
        oracle=ref.read_json(ROOT / "local-fixtures/phase5/recursion94/route-v3/oracle.json")
        ref.check_predicates(primary,oracle,{"full-route":rows})

    def test_old_frame_observer_loses_boundary_ticks_and_transient_event(self):
        scenario,result=execute("route-v2")
        self.assertEqual(result.returncode,0,result.stderr.decode())
        raw=b"\n".join(l for l in result.stdout.splitlines() if l.startswith(b"GWCAP,"))
        rows=ref.parse_capture(raw,scenario)
        self.assertLess(rows[-1]["signals"]["active_ticks"],3600)
        self.assertEqual({r["signals"]["campaign_dependency_event"] for r in rows},{0})

    def test_replacement_data_mutant_is_rejected(self):
        _,result=execute(mutant=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b"tap replaced guest write",result.stderr)

    def test_partial_word_write_fails_closed(self):
        _,result=execute(mode="malformed")
        self.assertIn(b"GWERROR,full-route,malformed-phase-write",result.stdout)

    def test_same_field_source_steps_require_clock_and_sequence_order(self):
        scenario=ref.read_json(ROOT/"local-fixtures/phase5/recursion94/route-v3/scenario.json")
        good=b"GWCAP,full-route,1,30,active_ticks=1\nGWCAP,full-route,2,30,active_ticks=2\n"
        self.assertEqual(len(ref.parse_capture(good,scenario)),2)
        for bad in (good.replace(b"2,30",b"1,30"),good.replace(b"active_ticks=2",b"active_ticks=1"),
                    good.replace(b"2,30",b"2,29")):
            with self.assertRaisesRegex(ValueError,"row-order"):
                ref.parse_capture(bad,scenario)
        scenario["observation"]["guest_writes"]=True
        with self.assertRaisesRegex(ValueError,"unsafe-completed-step"):
            ref.freeze_route(scenario,ref.read_json(ROOT/"local-fixtures/phase5/recursion94/route-v3/oracle.json"))


if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--self-test",action="store_true",required=True);p.parse_args()
    if not LUAJIT.is_file() or not (ROOT/"local-fixtures/phase5/recursion94/route-v3/scenario.json").is_file():
        print("SKIP: local LuaJIT/source observer package needed; tooling only");raise SystemExit(77)
    unittest.main(argv=[__file__],verbosity=2)

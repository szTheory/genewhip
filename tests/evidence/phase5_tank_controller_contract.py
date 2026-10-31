"""Execute authored route Lua against an original fakeMAME state fixture.

Tooling tests only: no ROM, game implementation, emulator, dependencies or
qualification results. Scripted input-responsive trajectories vary read cadence.
"""
from pathlib import Path
import argparse
import importlib.util
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("reference", ROOT / "tests/fixtures/phase5_reference.py")
ref = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ref)
LUAJIT = Path("/opt/homebrew/bin/luajit")

FIXTURE = r'''
local pressed, notifier, exited = {}, nil, false
local state = { game_state=0, p1_x=3, p1_y=12, p1_score=0,
                p2_x=32, p2_y=12, p2_score=0, win_score=5 }
local map = @@MAP@@
local tick, active, pause, shot = 0, 0, 0, nil
local movement = {"P1 Up", "P1 Right", "P2 Up", "P2 Left"}
local ports = {}
for _, player in ipairs({"P1", "P2"}) do
  local fields = {}
  for _, label in ipairs({"A", "B", "Up", "Right", "Left"}) do
    local name = player .. " " .. label
    fields[name] = {set_value=function(self,v) pressed[name] = v == 1 end}
  end
  ports[":ctrl" .. (player == "P1" and "1" or "2") .. ":mdpad:PAD"] = {fields=fields}
end
local space = {read_u8=function(self,a) return assert(state[map[a]]) end}
space.read_u16 = space.read_u8
manager = { machine = {
  devices = {[":maincpu"]={spaces={program=space}}},
  screens = {[":megadriv"]={}}, ioport={ports=ports},
  exit=function(self) exited=true end
}}
emu = {
  register_sound_update=function(fn) return fn end,
  add_machine_frame_notifier=function(fn) notifier=fn; return fn end,
  register_frame_done=function(fn) return fn end
}
dofile(arg[1])
local cadence = tonumber(arg[2])
local stutter = tonumber(arg[3])
local next_move = {P1=61+cadence, P2=64+cadence}
while not exited and tick < 7200 do
  tick = tick + 1
  if state.game_state == 0 and pressed["P1 A"] then state.game_state=1 end
  if state.game_state == 1 then
    active=active+1
    -- This fixture supplies abstract cell trajectories, not candidate game code.
    for i, player in ipairs({"P1", "P2"}) do
      if tick >= next_move[player] then
        next_move[player] = tick + cadence + (stutter == 1 and ((tick+i)%3)*2 or 0)
        local p = player == "P1" and "p1_" or "p2_"
        if pressed[player.." Up"] then state[p.."y"] = math.max(1,state[p.."y"]-1) end
        if pressed[player.." Right"] then state[p.."x"] = state[p.."x"]+1 end
        if pressed[player.." Left"] then state[p.."x"] = state[p.."x"]-1 end
        if player == "P1" and pressed["P1 B"] and not shot then
          -- Independent arithmetic contract: exact speed2 cells from x+1.
          if (state.p2_x - (state.p1_x+1)) % 2 ~= 0 then
            print("FIXTURE-VIOLATION,shot-parity-mismatch"); os.exit(0)
          end
          for _, name in ipairs(movement) do
            if pressed[name] then print("FIXTURE-VIOLATION,fire-with-movement"); os.exit(0) end
          end
          if state.p1_x ~= 4 or state.p2_x ~= 31 or state.p1_y ~= 1 or state.p2_y ~= 1 then
            print("FIXTURE-VIOLATION,shot-geometry"); os.exit(0)
          end
          shot = tick+130
        end
      end
    end
    if shot and tick >= shot then
      state.p1_score=state.p1_score+1
      print("FIXTURE-SCORE," .. state.p1_score .. "," .. active)
      state.game_state=2; pause=90; shot=nil
    end
  elseif state.game_state == 2 then
    pause=pause-1
    if pause == 0 then
      state.p1_x=3; state.p1_y=12; state.p2_x=32; state.p2_y=12
      state.game_state=1
    end
  end
  notifier()
end
assert(exited, "controller failed to stop")
print("FIXTURE-END," .. state.p1_score .. "," .. active)
'''


def execute(generation, case_id, cadence=20, stutter=0, mutate=None):
    package = ROOT / "local-fixtures/phase5/tank-battle" / generation
    scenario = ref.read_json(package / "scenario.json")
    if mutate:
        mutate(scenario)
    case = next(c for c in scenario["cases"] if c["id"] == case_id)
    script = ref._lua_script(scenario, case, (package / "mame.lua").read_text())
    mapping = "{" + ",".join(f'[{int(a["address"],16)}]="{a["name"]}"' for a in scenario["addresses"]) + "}"
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        (work / "route.lua").write_text(script)
        (work / "fixture.lua").write_text(FIXTURE.replace("@@MAP@@", mapping))
        result = subprocess.run([str(LUAJIT), str(work / "fixture.lua"), str(work / "route.lua"),
                                 str(cadence), str(stutter)], capture_output=True, timeout=10, check=True)
    return scenario, result.stdout


class TankControllerContract(unittest.TestCase):
    def test_old_moving_fire_fails_exact_parity_contract(self):
        _, output = execute("route-v2", "full-route")
        self.assertIn(b"FIXTURE-VIOLATION,shot-parity-mismatch", output)

    def test_actual_lua_completes_unchanged_predicates_with_varied_cadences(self):
        oracle = ref.read_json(ROOT / "local-fixtures/phase5/tank-battle/route-v3/oracle.json")
        self.assertEqual([p["field_window"] for p in oracle["predicates"]], [[120,500],[2761,3600]])
        for cadence, stutter in ((16,0), (20,0), (24,0), (20,1)):
            with self.subTest(cadence=cadence, stutter=stutter):
                captures = {}
                for case in ("full-route", "withhold-early-hit", "withhold-late-hit"):
                    scenario, output = execute("route-v3", case, cadence, stutter)
                    self.assertNotIn(b"FIXTURE-VIOLATION", output)
                    self.assertNotIn(b"GWERROR", output)
                    raw = b"\n".join(row for row in output.splitlines() if row.startswith(b"GWCAP,"))
                    captures[case] = ref.parse_capture(raw, scenario)
                    self.assertTrue(ref._capture_complete(captures[case], scenario))
                    self.assertIn(b",3600\n", output[-50:])
                ref.check_predicates(scenario, oracle, captures)

    def test_wrong_target_parity_mutant_is_killed(self):
        def mutate(scenario):
            for action in scenario["input_program"]["actions"]:
                action["steps"][2]["targets"][0]["until"]["p2_x"] = 32
        _, output = execute("route-v3", "full-route", mutate=mutate)
        self.assertIn(b"FIXTURE-VIOLATION,shot-parity-mismatch", output)

    def test_nonresponsive_state_fails_bounded_action(self):
        _, output = execute("route-v3", "full-route", 1000)
        self.assertIn(b"GWERROR,full-route,input-program-timeout,align-early", output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true", required=True)
    parser.parse_args()
    if not LUAJIT.is_file() or not (ROOT / "local-fixtures/phase5/tank-battle/route-v3/scenario.json").is_file():
        print("SKIP: local authored Tank package and installed LuaJIT required (tooling lane only)")
        raise SystemExit(77)
    unittest.main(argv=[__file__], verbosity=2)

-- Read-only guest observer and bounded input program for route-v3.
-- Route program values are source-authored literals. Guest RAM is never written.
local machine = manager.machine
local cpu = assert(machine.devices[":maincpu"], "maincpu unavailable")
local space = assert(cpu.spaces.program, "program space unavailable")
local screen = assert(machine.screens[":megadriv"], "render screen unavailable")
local pads = {
  P1 = assert(machine.ioport.ports[":ctrl1:mdpad:PAD"], "P1 pad unavailable"),
  P2 = assert(machine.ioport.ports[":ctrl2:mdpad:PAD"], "P2 pad unavailable")
}
local controls = {}
for _, name in ipairs(@@CONTROLS@@) do
  local player, label = string.match(name, "^(P[12]) (.+)$")
  assert(player and label, "invalid declared control: " .. name)
  controls[name] = assert(pads[player].fields[name], "input field unavailable: " .. name)
end
local program = @@INPUT_PROGRAM@@
local stop_rule = @@STOP_RULE@@
local addresses = @@ADDRESSES@@
local total_fields = @@TOTAL_FIELDS@@
local case_id = @@CASE_ID@@
local render_field = @@RENDER_FIELD@@
local render_file = @@RENDER_FILE@@
local render_check = @@RENDER_CHECK@@
local frame, sequence, active_ticks = 0, 0, 0
local audio_samples, audio_peak = 0, 0
local asserted = {}
local input_rows = 0

local function set_control(name, value)
  assert(controls[name], "undeclared control: " .. name)
  if (asserted[name] or false) == value then return end
  controls[name]:set_value(value and 1 or 0)
  asserted[name] = value
  input_rows = input_rows + 1
  print("GWINPUT," .. case_id .. "," .. frame .. "," .. name .. "," .. tostring(value))
end
local function release_all()
  for name in pairs(asserted) do set_control(name, false) end
end
local function read_signal(signal)
  local address = tonumber(signal.address, 16)
  if signal.width == 2 then return space:read_u16(address) end
  return space:read_u8(address)
end
local function snapshot()
  local values = {}
  for _, signal in ipairs(addresses) do
    values[signal.name] = read_signal(signal)
  end
  values.active_ticks = active_ticks
  return values
end

GW_SOUND_SUBSCRIPTION = emu.register_sound_update(function(sounds)
  for _, speakers in pairs(sounds) do
    for _, channel in pairs(speakers) do
      for _, sample in ipairs(channel) do
        audio_samples = audio_samples + 1
        audio_peak = math.max(audio_peak, math.abs(sample))
      end
    end
  end
end)

local launch_pressed = false
local action_index = 1
local step_index = 1
local action_started_field = nil
local function matches(values, conditions)
  for name, expected in pairs(conditions or {}) do
    if name == "active_ticks_gte" then
      if values.active_ticks < expected then return false end
    elseif name == "active_ticks_lt" then
      if values.active_ticks >= expected then return false end
    elseif values[name] ~= expected then
      return false
    end
  end
  return true
end

GW_FRAME_SUBSCRIPTION = emu.add_machine_frame_notifier(function()
  frame = frame + 1
  local values = snapshot()
  if values.game_state == 1 then active_ticks = active_ticks + 1 end
  values.active_ticks = active_ticks

  if frame == program.launch.field then
    set_control(program.launch.press, true)
    launch_pressed = true
  elseif launch_pressed and frame == program.launch.field + program.launch.release_after_fields then
    set_control(program.launch.press, false)
    launch_pressed = false
  end

  local enabled = program.cases[case_id]
  if enabled and action_index <= #enabled then
    local id = enabled[action_index]
    local action = nil
    for _, candidate in ipairs(program.actions) do
      if candidate.id == id then action = candidate; break end
    end
    assert(action, "unknown action in input program: " .. tostring(id))
    if action_started_field or matches(values, action.when) then
      if not action_started_field then action_started_field = frame end
      if frame - action_started_field > action.max_fields then
        release_all()
        print("GWERROR," .. case_id .. ",input-program-timeout," .. id)
        machine:exit()
        return
      end
      local step = assert(action.steps[step_index], "missing declared step")
      local complete = true
      for _, target in ipairs(step.targets) do
        local reached = matches(values, target["until"])
        -- Each player releases independently as soon as its own target is read.
        set_control(target.control, not reached)
        if not reached then complete = false end
      end
      if complete then
        step_index = step_index + 1
        if step_index > #action.steps then
          action_index = action_index + 1
          step_index = 1
          action_started_field = nil
        end
      end
    end
  end

  local active_stop = stop_rule and active_ticks >= stop_rule.active_fields
  local total_stop = frame >= stop_rule.total_fields
  if frame % 30 == 0 or active_stop or total_stop then
    sequence = sequence + 1
    local fields = {}
    for _, signal in ipairs(addresses) do
      fields[#fields + 1] = signal.name .. "=" .. read_signal(signal)
    end
    fields[#fields + 1] = "active_ticks=" .. active_ticks
    print("GWCAP," .. case_id .. "," .. sequence .. "," .. frame .. "," .. table.concat(fields, ";"))
  end
  if active_stop or total_stop then
    release_all()
    if enabled and action_index <= #enabled then
      print("GWERROR," .. case_id .. ",input-program-total-field-exhausted," .. tostring(enabled[action_index]))
      print("GWAUDIO," .. case_id .. "," .. audio_samples .. "," .. string.format("%.9f", audio_peak))
      machine:exit()
      return
    end
    print("GWAUDIO," .. case_id .. "," .. audio_samples .. "," .. string.format("%.9f", audio_peak))
    machine:exit()
  end
end)

if render_field > 0 and render_field < total_fields then
  GW_RENDER_SUBSCRIPTION = emu.register_frame_done(function()
    if frame == render_field then
      local failure = screen:snapshot(render_file)
      if failure then error("render-snapshot-failed: " .. tostring(failure)) end
      if render_check then
        local position = read_signal(render_check)
        local x = position * render_check.cell_width + render_check.x_offset
        local y = render_check.y
        print("GWPIXEL," .. case_id .. "," .. frame .. "," .. x .. "," .. y .. "," ..
          screen:pixel(x, y) .. "," .. screen:pixel(0, y))
      end
    end
  end)
end

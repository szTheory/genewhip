-- Reviewed, read-only source-clocked capture driver for the pinned MAME build.
-- It sets declared controller fields and samples only the selected RAM bytes.
-- It never writes guest memory, registers, ROM or other machine state.
local machine = manager.machine
local cpu = assert(machine.devices[":maincpu"], "maincpu unavailable")
local space = assert(cpu.spaces.program, "program space unavailable")
local screen = assert(machine.screens[":megadriv"], "render screen unavailable")
local pad = assert(machine.ioport.ports[":ctrl1:mdpad:PAD"], "three-button pad unavailable")
local fields = pad.fields
local controls = {}
for _, name in ipairs(@@CONTROLS@@) do
  controls[name] = assert(fields[name], "input field unavailable: " .. name)
end
local program = @@INPUT_PROGRAM@@
local addresses = @@ADDRESSES@@
local total_fields = @@TOTAL_FIELDS@@
local active_limit = 3600 -- frozen by scenario.active_clock.limit
local ticks_per_attempt = program.ticks_per_attempt
local case_id = @@CASE_ID@@
local boot_limit = 120
local render_file = @@RENDER_FILE@@
local render_check = @@RENDER_CHECK@@
local render_when = program.render_when

local frame = 0
local event_cursor = 1
local audio_samples, audio_peak = 0, 0
local active_ticks = 0
local previous_state, previous_attempt, previous_tick = nil, nil, nil
local render_requested = false
local render_captured = false
local capture_sequence = 0
local previous_dependency_event = 0
local previous_timeline_ui_flags = nil

local function read_u8(hex_address)
  return space:read_u8(tonumber(hex_address, 16))
end

local function read_u16(hex_address)
  local address = tonumber(hex_address, 16)
  return space:read_u8(address) * 256 + space:read_u8(address + 1)
end

local function read_signal(signal)
  if signal.width == "u16" then return read_u16(signal.address) end
  return read_u8(signal.address)
end

local function state_name(value)
  if value == program.state_values.active then return "active" end
  if value == program.state_values.terminal then return "terminal" end
  return "other"
end

local function sample_engine()
  return read_u16(program.attempt_address), read_u16(program.tick_address), read_u16(program.state_address)
end

local function event_ready(event, attempt, tick, state)
  local expected_state = program.state_values[event.state]
  return event.attempt == attempt and expected_state == state and tick >= event.tick
end

local function apply_due_inputs(attempt, tick, state, meta_only)
  local transitioned = false
  while event_cursor <= #program.events do
    local event = program.events[event_cursor]
    local applies_to_case = false
    for _, selected_case in ipairs(event.cases or {event.case}) do
      if selected_case == case_id then applies_to_case = true end
    end
    if applies_to_case and event_ready(event, attempt, tick, state) then
      if meta_only and event.control ~= "P1 C" then break end
      controls[event.control]:set_value(event.asserted and 1 or 0)
      print("GWINPUT," .. case_id .. "," .. frame .. "," .. event.control .. "," ..
        (event.asserted and "true" or "false"))
      transitioned = true
      event_cursor = event_cursor + 1
    elseif not applies_to_case then
      event_cursor = event_cursor + 1
    else
      -- Events are ordered by attempt/tick. Later events cannot be due yet.
      break
    end
  end
  return transitioned
end

GW_SOUND_SUBSCRIPTION = emu.register_sound_update(function(sounds)
  for _, speakers in pairs(sounds) do
    for _, channel in pairs(speakers) do
      for _, sample in ipairs(channel) do
        audio_samples = audio_samples + 1
        local magnitude = math.abs(sample)
        if magnitude > audio_peak then audio_peak = magnitude end
      end
    end
  end
end)

local last_values = nil
local last_attempt, last_tick = 0, 0
local exited = false
local function emit(values)
  capture_sequence = capture_sequence + 1
  print("GWCAP," .. case_id .. "," .. capture_sequence .. "," .. math.max(frame,1) .. "," .. table.concat(values,";"))
end
local function finish()
  if exited then return end
  exited = true
  print("GWAUDIO," .. case_id .. "," .. audio_samples .. "," .. string.format("%.9f", audio_peak))
  machine:exit()
end
local function fail(reason)
  print("GWERROR," .. case_id .. "," .. reason)
  finish()
end

-- MAME invokes taps before forwarding the guest write. Returning nil leaves
-- the guest's data unchanged. Keep the userdata alive for the entire capture.
GW_PHASE_TAP = assert(space:install_write_tap(0xFF1516, 0xFF1517, "gw-completed-source-step",
  function(offset, data, mask)
    if exited or data ~= 0 then return nil end
    if offset ~= 0xFF1516 or mask ~= 0xFFFF then fail("malformed-phase-write"); return nil end
    local attempt, tick, state = sample_engine()
    -- Reset/initialization may clear phase at tick0 before reset owners finish.
    if tick == 0 then return nil end
    if attempt == last_attempt and tick == last_tick then return nil end
    if not ((attempt == last_attempt and tick == last_tick+1)
        or (attempt == last_attempt+1 and last_tick == ticks_per_attempt and tick == 1)) then
      fail("noncontiguous-completed-source-step"); return nil
    end
    if state ~= program.state_values.active and state ~= program.state_values.terminal then
      fail("invalid-completed-source-state"); return nil
    end
    last_attempt, last_tick = attempt, tick
    active_ticks = active_ticks + 1
    local values = {}
    for _, signal in ipairs(addresses) do values[#values+1] = signal.name .. "=" .. read_signal(signal) end
    values[#values+1] = "active_ticks=" .. active_ticks
    last_values = values
    local transitioned = apply_due_inputs(attempt,tick,state,false)
    local dependency = read_u8("FF16F7")
    local ui = read_u16("FF16FA")
    if active_ticks % 30 == 0 or transitioned or dependency ~= previous_dependency_event
        or state == program.state_values.terminal or (attempt == 4 and tick >= 690) then emit(values) end
    previous_dependency_event = dependency
    previous_timeline_ui_flags = ui
    if render_when and not render_requested and attempt == render_when.attempt
        and tick >= render_when.tick and state == program.state_values[render_when.state] then render_requested=true end
    if active_ticks >= active_limit then finish() end
    return nil
  end), "phase tap unavailable")

GW_FRAME_SUBSCRIPTION = emu.add_machine_frame_notifier(function()
  frame = frame + 1
  if exited then return end
  -- Only paused/meta C transitions use field snapshots. No world predicate,
  -- active tick or B timing is derived from this callback.
  local attempt,tick,state = sample_engine()
  apply_due_inputs(attempt,tick,state,true)
  if frame > boot_limit and active_ticks == 0 then fail("no-completed-source-step"); return end
  if frame >= total_fields then
    if last_values then emit(last_values) end
    finish()
  end
end)

GW_RENDER_SUBSCRIPTION = emu.register_frame_done(function()
  if render_requested and not render_captured then
    local failure = screen:snapshot(render_file)
    if failure then error("render-snapshot-failed: " .. tostring(failure)) end
    if render_check then
      local position = read_signal(render_check)
      local x = position * render_check.cell_width + render_check.x_offset
      local y = render_check.y
      print("GWPIXEL," .. case_id .. "," .. frame .. "," .. x .. "," .. y .. "," ..
        screen:pixel(x, y) .. "," .. screen:pixel(0, y))
    end
    render_captured = true
  end
end)

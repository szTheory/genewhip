-- Bounded MAME input driver for the frozen successor cases in scenario.json.
local machine = manager.machine
local maincpu = machine.devices[":maincpu"]
assert(maincpu and maincpu.spaces.program, "Genesis main CPU program space unavailable")
local ports = machine.ioport.ports
local pad = ports[":ctrl1:mdpad:PAD"]
assert(pad, "NTSC-U three-button controller unavailable")
local fields = pad.fields
local controls = {
    ["P1 Start"] = assert(fields["P1 Start"], "P1 Start unavailable"),
    ["P1 Right"] = assert(fields["P1 Right"], "P1 Right unavailable"),
    ["P1 Left"] = assert(fields["P1 Left"], "P1 Left unavailable"),
    ["P1 B"] = assert(fields["P1 B"], "P1 B unavailable"),
}

-- The Python evidence driver substitutes only this frozen, identity-bound table.
local scenario = assert(GW_SCENARIO, "scenario schedule was not supplied")
local frame = 0
local cursor = 1
-- Keep the subscription alive; MAME releases the callback when the returned
-- notifier handle is collected (which happened after roughly two seconds).
GW_FRAME_SUBSCRIPTION = emu.add_machine_frame_notifier(function()
    frame = frame + 1
    while cursor <= #scenario.input_schedule and scenario.input_schedule[cursor].frame == frame do
        local event = scenario.input_schedule[cursor]
        controls[event.control]:set_value(event.asserted and 1 or 0)
        print(string.format("GWINPUT,scenario=%s,frame=%d,control=%s,asserted=%s",
            scenario.id, frame, event.control, tostring(event.asserted)))
        cursor = cursor + 1
    end
    if frame % 120 == 0 then
        print(string.format("GWPROGRESS,scenario=%s,frame=%d", scenario.id, frame))
    end
    if frame == scenario.frames then
        local ram = maincpu.spaces.program
        local state = ram:read_u16(0x00ff0000)
        local position = ram:read_u16(0x00ff0002)
        print(string.format("GWOBS,scenario=%s,frame=%d,play_state=%d,position=%d",
            scenario.id, frame, state, position))
        machine:exit()
    end
end)

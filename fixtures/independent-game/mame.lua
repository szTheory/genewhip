-- Bounded deterministic input/oracle driver for scenario.json.
local machine = manager.machine
local maincpu = machine.devices[":maincpu"]
assert(maincpu and maincpu.spaces.program, "Genesis main CPU program space unavailable")

local ports = machine.ioport.ports
local pad = ports[":ctrl1:mdpad:PAD"]
assert(pad and pad.fields["P1 Start"] and pad.fields["P1 Right"], "expected NTSC-U controller fields unavailable")
local start = pad.fields["P1 Start"]
local right = pad.fields["P1 Right"]
local frame = 0

-- Positive sentinel for the configured 68000 interrupt-acknowledge address space.
local cpu_space = maincpu.spaces["cpu_space"]
assert(cpu_space, "Genesis 68000 CPU space unavailable")
cpu_space:read_u16(0x00fffff3)

emu.add_machine_frame_notifier(function()
    frame = frame + 1
    if frame == 1 then
        start:set_value(1)
        print(string.format("GWINPUT,frame=1,port=%04X,start_mask=%04X,start_default=%04X", pad:read(), start.mask, start.defvalue))
    end
    if frame == 20 then
        start:set_value(0)
        print(string.format("GWINPUT,frame=20,port=%04X", pad:read()))
    end
    if frame == 25 then
        right:set_value(1)
        print(string.format("GWINPUT,frame=25,port=%04X,right_mask=%04X", pad:read(), right.mask))
    end
    if frame == 50 then
        right:set_value(0)
        print(string.format("GWINPUT,frame=50,port=%04X", pad:read()))
    end
    if frame == 60 then
        local position = maincpu.spaces.program:read_u16(0x00ff0002)
        print(string.format("GWOBS,scenario=genewhip-independent-game-start-right-ntscu-v1,frame=%d,position=%d", frame, position))
        machine:exit()
    end
end)

-- Separate calibration run; guest 68000 code performs the seeded accesses.
local frames = 0
emu.add_machine_frame_notifier(function()
    frames = frames + 1
    if frames == 3 then
        local pc = manager.machine.devices[":maincpu"].state["PC"].value
        print(string.format("GWSENTINEL,guest-68000-accesses-complete,pc=%06X", pc))
        manager.machine:exit()
    end
end)

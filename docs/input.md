# Input contract (API 4)

This page is the contract for controller input as of plan GW-02-07: two
three-button pad ports, timestamped pad events and the I/O register protocol a
guest reads. Six-button pads and other peripherals are not covered; the TH seam
evidence ROM is described in "TH seam" below.

## Button mask

`gw_event.mask` carries the full logical state of one pad; a set bit means
pressed. A later event for the same port replaces the whole mask.

| Bit | Value | Button |
|---|---|---|
| 0 | `GW_BUTTON_UP` (1) | Up |
| 1 | `GW_BUTTON_DOWN` (2) | Down |
| 2 | `GW_BUTTON_LEFT` (4) | Left |
| 3 | `GW_BUTTON_RIGHT` (8) | Right |
| 4 | `GW_BUTTON_B` (16) | B |
| 5 | `GW_BUTTON_C` (32) | C |
| 6 | `GW_BUTTON_A` (64) | A |
| 7 | `GW_BUTTON_START` (128) | Start |

`GW_BUTTON_MASK_PAD3` (255) is the union. Mask bits above it are reserved.

## Pad events (`GW_EVENT_PAD_STATE`)

`gw_schedule_event` queues `{tick, port, mask}` in the same 64-entry
(`GW_EVENT_CAPACITY`) queue as console resets, sorted by tick and then insertion
order. Every rejection leaves the queue and the machine unchanged:

| Condition | Result |
|---|---|
| wrong `struct_size` or `version` | `GW_ERROR_VERSION` |
| no ROM loaded | `GW_ERROR_NOT_LOADED` |
| non-zero `reserved`, `port` > 1, mask bits above `GW_BUTTON_MASK_PAD3` | `GW_ERROR_ARGUMENT` |
| port configured `GW_DEVICE_NONE` | `GW_ERROR_UNSUPPORTED` |
| `tick` below the current machine tick (equal is accepted) or above `GW_MAX_TARGET_TICK` | `GW_ERROR_TIME` |
| queue already holds 64 events | `GW_ERROR_CAPACITY` |

An identical duplicate event at the same tick has the same effect as one event.
Submit events just in time: before running across their timestamp, and never more
than `GW_EVENT_CAPACITY` outstanding. Applied events free their slots.

## Bus-time application

Pad events are applied by the I/O device when the machine reaches their tick, not
when a run call returns. A guest read of an I/O register at bus tick `t` observes
every pad event with `tick <= t`, in `(tick, insertion)` order. The same events
are also applied at each instruction boundary so the queue drains while the guest
does not touch the ports. Because only I/O reads observe pad state, both points
give the same guest-visible result, and what the guest observes does not depend on
how the host split its `gw_run_until` calls (the property
`split_run_equivalence` checks). A queued console reset keeps its place in the
order: pad events behind a pending reset wait for it.

Console resets keep the Phase 1 rule: applied at the first instruction boundary at
or after their tick.

## Devices and register map

`gw_config.port_device[port]` selects `GW_DEVICE_NONE` or `GW_DEVICE_PAD3` per
port; any other value returns `GW_ERROR_UNSUPPORTED` at creation. The device is
fixed for the machine's lifetime.

Registers are byte-wide and decoded only at these odd addresses:

| Address | Register | Access |
|---|---|---|
| `0xA10001` | Version | read; writes are ignored |
| `0xA10003` | Port 0 data | read/write |
| `0xA10005` | Port 1 data | read/write |
| `0xA10009` | Port 0 control | read/write |
| `0xA1000B` | Port 1 control | read/write |

Word and longword access, even addresses and every other `0xA1xxxx` address stay
fail-closed with `GW_STOP_UNSUPPORTED_ADDRESS` (including `0xA10000`). There are no
mirrors.

A data read composes each bit from the data latch where the bit is an output and
from the pin level elsewhere: output bits are `control | 0x80` (bit 7 is always
latch-backed). The TH level is the data latch bit 6 when control bit 6 is an
output, otherwise high.

## Pad protocol (active low)

| TH | bit 5 | bit 4 | bit 3 | bit 2 | bit 1 | bit 0 |
|---|---|---|---|---|---|---|
| high | C | B | Right | Left | Down | Up |
| low | Start | A | 0 | 0 | Down | Up |

A pressed button reads 0; a released one reads 1. Bit 6 reads the TH level on an
input pin. A `GW_DEVICE_NONE` port presents pull-ups: pins read `0x7F`.

## TH seam

`tests/devices/roms/th.s` (`genewhip-seam-th-v1`, original ROM, oracle
`documented-hardware-behaviour`) configures both ports with TH as an output, reads each
TH phase of each port, then reads both ports with TH as an input and the version
register. `gw_seam_runner --events FILE` schedules a bounded list of pad events
(`TICK PORT MASK-HEX` lines, at most `GW_EVENT_CAPACITY`, strictly parsed; anything else
prints `REJECT: events` before the run) and `--port-device P1 P2` (`none` or `pad3`)
sets the port devices. `th.expect.json` carries two run configurations, `both-pad3`
(port 1 holds A|Start|Up = `c1`, port 2 holds B|C|Right = `38`) and `port2-none`, and
`seam_check.py` runs each case in its run. Events sit at tick 112, the first tick after
the reset vector fetch (earlier ticks are late events). Expectations are authored from
the cited documentation and never from Genewhip output; the report is
`build/phase2/tests/devices/th-seam.json` (13 cases, `--report` selects the path).
`pad_th_seam_negative_control` flips one documented byte and requires exactly that case
to fail with `mismatch`; `seam_events_reject` covers malformed and oversized schedules.

| Case | Class | Basis |
|---|---|---|
| `port1-th-high`, `port1-th-low` | documented | plutiedev controllers and io-ports, TH high/low layouts |
| `port2-th-high`, `port2-th-low` | documented | same tables; port 2 mask independent of port 1 |
| `th-low-bits-3-2-zero` | documented | plutiedev controllers: Left/Right pins read 0 with TH low |
| `th-follows-data-write` | documented | plutiedev io-ports: control bit 6 makes TH follow data bit 6 |
| `port1-unaffected-by-port2-none` | documented | port 1 protocol independent of port 2 |
| `completion-marker` | documented | ROM control flow reached the final store |
| `port1-th-input-reads-th-high-layout`, `port2-th-input-reads-th-high-layout` | REF-derived | reference emulator behaviour; plutiedev is silent |
| `port2-none-reads-pull-ups`, `port2-none-th-input-reads-pull-ups` | REF-derived | assumption A7, reference emulator |
| `version-register-a10001` | unknown | assumption A6: observed value reported, no independent fixture |

REF-derived passes are reported under their own class and are not documented hardware
evidence. The version register case stays `unknown` in the denominator: the layout is
described by plutiedev, but no independent source fixes the value for this profile, so A6
remains a documented choice. A7 (pull-ups on an empty port, TH input reads high) is
reference-derived only. Bit 7 of data reads is masked out of every judged case.

## Version register (assumption A6)

`0xA10001` returns `0xA0`: overseas (bit 7), NTSC (bit 6 clear), no expansion
unit (bit 5), hardware version 0. This follows the plutiedev I/O ports
description for the profile's overseas NTSC console; it is a documented choice,
not a measurement from a console.

## Reset policy (assumption A8, I/O part)

- Cold init (`gw_cold_init`, `gw_load_rom`): clears data and control latches, held
  buttons and the event queue.
- Console reset (`gw_console_reset` or a queued reset event): clears the data and
  control latches; held buttons and queued events stay.
- Guest `RESET` does not touch the I/O device yet.

## Assumptions and limitations

- A6: version register value as above.
- A7: a `GW_DEVICE_NONE` port reads pull-ups on every input pin; a TH line
  configured as input reads high.
- Only the three-button pad exists: no six-button protocol, no multitap, mouse,
  light gun, serial or other peripherals.
- No register mirrors, no word access, no data/control access on even addresses.
- TH does not raise an external interrupt; the control register interrupt bit is
  stored but has no effect.
- Timing is event-ordered on the master tick; there is no controller settling
  delay. Real-hardware read timing was not measured.
- The session layer and desktop runner that feed these events are described in `docs/desktop.md`.

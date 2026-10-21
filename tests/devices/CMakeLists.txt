# Device-level contracts and their original ROM sources (SPDX MIT, see root).
set(GW_BACKDROP_ROM ${CMAKE_CURRENT_BINARY_DIR}/backdrop.bin)
add_custom_command(OUTPUT ${GW_BACKDROP_ROM}
  COMMAND gw_build_rom ${CMAKE_CURRENT_SOURCE_DIR}/backdrop.S ${GW_BACKDROP_ROM}
  DEPENDS gw_build_rom ${CMAKE_CURRENT_SOURCE_DIR}/backdrop.S VERBATIM)
add_custom_target(gw_backdrop_rom ALL DEPENDS ${GW_BACKDROP_ROM})

set(GW_PSG_SWEEP_ROM ${CMAKE_CURRENT_BINARY_DIR}/psg_sweep.bin)
add_custom_command(OUTPUT ${GW_PSG_SWEEP_ROM}
  COMMAND gw_build_rom ${CMAKE_CURRENT_SOURCE_DIR}/psg_sweep.S ${GW_PSG_SWEEP_ROM}
  DEPENDS gw_build_rom ${CMAKE_CURRENT_SOURCE_DIR}/psg_sweep.S VERBATIM)
add_custom_target(gw_psg_sweep_rom ALL DEPENDS ${GW_PSG_SWEEP_ROM})

set(GW_Z80_ARB_TRACER_ROM ${CMAKE_CURRENT_BINARY_DIR}/z80_arb_tracer.bin)
add_custom_command(OUTPUT ${GW_Z80_ARB_TRACER_ROM}
  COMMAND gw_build_rom ${CMAKE_CURRENT_SOURCE_DIR}/z80_arb_tracer.S ${GW_Z80_ARB_TRACER_ROM}
  DEPENDS gw_build_rom ${CMAKE_CURRENT_SOURCE_DIR}/z80_arb_tracer.S VERBATIM)
add_custom_target(gw_z80_arb_tracer_rom ALL DEPENDS ${GW_Z80_ARB_TRACER_ROM})

foreach(contract backdrop_field video_contract vdp_modes_contract pad_event_contract split_run_equivalence cram_expansion)
  add_executable(${contract} ${contract}.c)
  target_include_directories(${contract} PRIVATE ${PROJECT_SOURCE_DIR}/tests/api ${PROJECT_SOURCE_DIR}/src)
  target_link_libraries(${contract} PRIVATE Genewhip::core)
  set_target_properties(${contract} PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(${contract} PRIVATE -Wall -Wextra -Wpedantic -Wshadow)
  endif()
endforeach()
add_dependencies(backdrop_field gw_backdrop_rom)
add_test(NAME backdrop_field COMMAND backdrop_field ${GW_BACKDROP_ROM})
add_test(NAME video_contract COMMAND video_contract)
add_test(NAME cram_expansion COMMAND cram_expansion)
set_tests_properties(cram_expansion PROPERTIES TIMEOUT 15)
add_test(NAME vdp_modes_contract COMMAND vdp_modes_contract)
set_tests_properties(backdrop_field video_contract vdp_modes_contract PROPERTIES TIMEOUT 15)
add_test(NAME pad_event_contract COMMAND pad_event_contract ${CMAKE_CURRENT_SOURCE_DIR}/roms/pad_echo.bin)
set_tests_properties(pad_event_contract PROPERTIES TIMEOUT 15)
add_test(NAME split_run_equivalence COMMAND split_run_equivalence ${CMAKE_CURRENT_SOURCE_DIR}/roms/pad_echo.bin)
set_tests_properties(split_run_equivalence PROPERTIES TIMEOUT 60)

add_executable(audio_chunk_equivalence audio_chunk_equivalence.c)
target_include_directories(audio_chunk_equivalence PRIVATE ${PROJECT_SOURCE_DIR}/tests/api ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(audio_chunk_equivalence PRIVATE Genewhip::core)
set_target_properties(audio_chunk_equivalence PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(audio_chunk_equivalence PRIVATE -Wall -Wextra -Wpedantic -Wshadow)
endif()
if(GENEWHIP_TEST_HOOKS)
  target_compile_definitions(split_run_equivalence PRIVATE GW_TEST_HOOKS)
  target_compile_definitions(audio_chunk_equivalence PRIVATE GW_TEST_HOOKS)
  add_test(NAME audio_chunk_equivalence COMMAND audio_chunk_equivalence chunk ${GW_PSG_SWEEP_ROM})
  add_test(NAME audio_disabled_equivalence COMMAND audio_chunk_equivalence disabled ${GW_PSG_SWEEP_ROM})
  add_test(NAME z80_bank_split_equivalence COMMAND audio_chunk_equivalence chunk ${CMAKE_CURRENT_SOURCE_DIR}/roms/z80_bank.bin)
  add_test(NAME bus_arb_midinstr_split_equivalence COMMAND audio_chunk_equivalence chunk ${CMAKE_CURRENT_SOURCE_DIR}/roms/bus_arb_midinstr.bin)
  set_tests_properties(audio_chunk_equivalence audio_disabled_equivalence PROPERTIES TIMEOUT 120)
  set_tests_properties(z80_bank_split_equivalence bus_arb_midinstr_split_equivalence PROPERTIES TIMEOUT 120)
else()
  add_test(NAME audio_chunk_equivalence COMMAND audio_chunk_equivalence chunk ${GW_PSG_SWEEP_ROM})
  add_test(NAME state_digest_symbols_absent COMMAND ${Python3_EXECUTABLE} -c
    "import sys; data = open(sys.argv[1], 'rb').read(); names = (b'gw_test_state_digest', b'gw_test_audio_frames_at'); found = [n.decode() for n in names if n in data]; sys.exit('test-only symbols present: ' + ', '.join(found) if found else 0)"
    $<TARGET_FILE:genewhip_core>)
  set_tests_properties(state_digest_symbols_absent PROPERTIES TIMEOUT 15)
  set_tests_properties(audio_chunk_equivalence PROPERTIES TIMEOUT 120)
endif()
add_dependencies(audio_chunk_equivalence gw_psg_sweep_rom)

add_executable(z80_arbitration_contract z80_arbitration_contract.c)
target_include_directories(z80_arbitration_contract PRIVATE ${PROJECT_SOURCE_DIR}/tests/api ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(z80_arbitration_contract PRIVATE Genewhip::core)
set_target_properties(z80_arbitration_contract PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(z80_arbitration_contract PRIVATE -Wall -Wextra -Wpedantic -Wshadow)
endif()
add_dependencies(z80_arbitration_contract gw_z80_arb_tracer_rom)
add_test(NAME z80_arb_tracer COMMAND z80_arbitration_contract tracer ${GW_Z80_ARB_TRACER_ROM})
add_test(NAME z80_poll_order_negative COMMAND z80_arbitration_contract poll-order-negative)
set_tests_properties(z80_arb_tracer z80_poll_order_negative PROPERTIES TIMEOUT 60)
if(GENEWHIP_TEST_HOOKS)
  target_compile_definitions(z80_arbitration_contract PRIVATE GW_TEST_HOOKS)
  add_test(NAME z80_arbitration_contract COMMAND z80_arbitration_contract grant)
  add_test(NAME z80_midinstr_contract COMMAND z80_arbitration_contract midinstr)
  add_test(NAME z80_map_contract COMMAND z80_arbitration_contract map)
  add_test(NAME z80_sync_limit COMMAND z80_arbitration_contract sync-limit)
  add_test(NAME z80_sync_idempotence COMMAND z80_arbitration_contract idempotence ${GW_Z80_ARB_TRACER_ROM})
  add_test(NAME z80_sync_idempotence_bus_arb COMMAND z80_arbitration_contract idempotence
    ${PROJECT_SOURCE_DIR}/tests/devices/roms/bus_arb.bin)
  add_test(NAME z80_arbitration_order_negative COMMAND z80_arbitration_contract arbitration-order-negative)
  set_tests_properties(z80_arbitration_contract z80_midinstr_contract z80_map_contract z80_sync_limit z80_sync_idempotence
    z80_sync_idempotence_bus_arb z80_arbitration_order_negative
    PROPERTIES TIMEOUT 60)
endif()

# VDP FIFO/DMA scheduling model conformance (plan GW-02-08): hooks-gated, observes work-RAM
# store ticks through the private gw_test_bus_write hook; not hardware evidence.
if(GENEWHIP_TEST_HOOKS)
  add_executable(vdp_timing_contract vdp_timing_contract.c)
  target_include_directories(vdp_timing_contract PRIVATE ${PROJECT_SOURCE_DIR}/tests/api)
  target_link_libraries(vdp_timing_contract PRIVATE Genewhip::core)
  target_compile_definitions(vdp_timing_contract PRIVATE GW_TEST_HOOKS)
  set_target_properties(vdp_timing_contract PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(vdp_timing_contract PRIVATE -Wall -Wextra -Wpedantic -Wshadow)
  endif()
  add_test(NAME vdp_timing_contract COMMAND vdp_timing_contract)
  set_tests_properties(vdp_timing_contract PROPERTIES TIMEOUT 30)
endif()

# Seam diagnostics (D-30): a generic public-API runner plus per-seam authored expectations.
add_test(NAME original_rom_bytes COMMAND ${Python3_EXECUTABLE} -I
  ${CMAKE_CURRENT_SOURCE_DIR}/original_rom_bytes.py ${PROJECT_SOURCE_DIR})
set_tests_properties(original_rom_bytes PROPERTIES TIMEOUT 15)
add_test(NAME original_rom_extract COMMAND ${Python3_EXECUTABLE} -I
  ${CMAKE_CURRENT_SOURCE_DIR}/original_rom_extract.py ${PROJECT_SOURCE_DIR})
set_tests_properties(original_rom_extract PROPERTIES TIMEOUT 15)
if(GENEWHIP_BUILD_TOOLS)
  add_executable(gw_seam_runner seam_runner.c)
  target_link_libraries(gw_seam_runner PRIVATE Genewhip::core)
  add_dependencies(gw_seam_runner gw_evidence_identity)
  target_include_directories(gw_seam_runner PRIVATE ${PROJECT_BINARY_DIR}/evidence-$<CONFIG>)
  set_target_properties(gw_seam_runner PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(gw_seam_runner PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
  endif()
  add_test(NAME vdp_ports_seam COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/ports.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/ports.expect.json
    --report ${CMAKE_CURRENT_BINARY_DIR}/ports-seam.json)
  add_test(NAME vdp_ports_seam_negative_control COMMAND ${Python3_EXECUTABLE} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/ports.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/ports.expect.json --negative-control)
  set_tests_properties(vdp_ports_seam vdp_ports_seam_negative_control PROPERTIES TIMEOUT 30)
  add_test(NAME pad_th_seam COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/th.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/th.expect.json
    --report ${CMAKE_CURRENT_BINARY_DIR}/th-seam.json)
  add_test(NAME pad_th_seam_negative_control COMMAND ${Python3_EXECUTABLE} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/th.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/th.expect.json --negative-control)
  add_test(NAME seam_events_reject COMMAND ${Python3_EXECUTABLE} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/events_reject.py $<TARGET_FILE:gw_seam_runner>
    ${CMAKE_CURRENT_SOURCE_DIR}/roms/th.bin)
  set_tests_properties(pad_th_seam pad_th_seam_negative_control seam_events_reject PROPERTIES TIMEOUT 30)
  add_test(NAME vdp_dma_seam COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/dma.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/dma.expect.json
    --report ${CMAKE_CURRENT_BINARY_DIR}/dma-seam.json)
  add_test(NAME vdp_dma_seam_negative_control COMMAND ${Python3_EXECUTABLE} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/dma.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/dma.expect.json --negative-control)
  set_tests_properties(vdp_dma_seam vdp_dma_seam_negative_control PROPERTIES TIMEOUT 60)
  add_test(NAME vdp_fifo_seam COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/fifo.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/fifo.expect.json
    --report ${CMAKE_CURRENT_BINARY_DIR}/fifo-seam.json)
  add_test(NAME vdp_fifo_seam_negative_control COMMAND ${Python3_EXECUTABLE} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/fifo.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/fifo.expect.json --negative-control)
  set_tests_properties(vdp_fifo_seam vdp_fifo_seam_negative_control PROPERTIES TIMEOUT 60)
  add_test(NAME vdp_irq_seam COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/irq.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/irq.expect.json
    --report ${CMAKE_CURRENT_BINARY_DIR}/irq-seam.json)
  add_test(NAME vdp_irq_seam_negative_control COMMAND ${Python3_EXECUTABLE} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/irq.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/irq.expect.json --negative-control)
  set_tests_properties(vdp_irq_seam vdp_irq_seam_negative_control PROPERTIES TIMEOUT 60)
  add_test(NAME psg_seam COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/psg.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/psg.expect.json
    --report ${CMAKE_CURRENT_BINARY_DIR}/psg-seam.json)
  add_test(NAME psg_seam_negative_control COMMAND ${Python3_EXECUTABLE} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py --runner $<TARGET_FILE:gw_seam_runner>
    --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/psg.bin --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/psg.expect.json
    --negative-control)
  set_tests_properties(psg_seam psg_seam_negative_control PROPERTIES TIMEOUT 60)
  add_test(NAME psg_seam_repeat COMMAND ${Python3_EXECUTABLE} -I -c
    "import pathlib,subprocess,sys,tempfile; checker,runner,rom,expect=sys.argv[1:]; t=tempfile.TemporaryDirectory(); a=pathlib.Path(t.name)/'a.json'; b=pathlib.Path(t.name)/'b.json'; base=[sys.executable,'-I',checker,'--runner',runner,'--rom',rom,'--expect',expect]; subprocess.run(base+['--report',str(a)],check=True); subprocess.run(base+['--report',str(b)],check=True); subprocess.run([sys.executable,'-I',checker,'--compare',str(a),str(b)],check=True)"
    ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py $<TARGET_FILE:gw_seam_runner>
    ${CMAKE_CURRENT_SOURCE_DIR}/roms/psg.bin ${CMAKE_CURRENT_SOURCE_DIR}/roms/psg.expect.json)
  set_tests_properties(psg_seam_repeat PROPERTIES TIMEOUT 120)

  if(GENEWHIP_TEST_HOOKS)
    add_executable(psg_contract psg_contract.c)
    target_include_directories(psg_contract PRIVATE ${PROJECT_SOURCE_DIR}/tests/api ${PROJECT_SOURCE_DIR}/src)
    target_link_libraries(psg_contract PRIVATE Genewhip::core)
    target_compile_definitions(psg_contract PRIVATE GW_TEST_HOOKS)
    set_target_properties(psg_contract PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
      target_compile_options(psg_contract PRIVATE -Wall -Wextra -Wpedantic -Wshadow)
    endif()
    add_test(NAME psg_contract_protocol COMMAND psg_contract protocol)
    add_test(NAME psg_contract_lfsr COMMAND psg_contract lfsr)
    add_test(NAME psg_chunk_equivalence COMMAND audio_chunk_equivalence chunk ${CMAKE_CURRENT_SOURCE_DIR}/roms/psg.bin)
    set_tests_properties(psg_contract_protocol psg_contract_lfsr psg_chunk_equivalence PROPERTIES TIMEOUT 120)
  endif()
  add_test(NAME vdp_sprites_seam COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/sprites.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/sprites.expect.json
    --report ${CMAKE_CURRENT_BINARY_DIR}/sprites-seam.json)
  add_test(NAME vdp_sprites_seam_negative_control COMMAND ${Python3_EXECUTABLE} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/sprites.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/sprites.expect.json --negative-control)
  set_tests_properties(vdp_sprites_seam vdp_sprites_seam_negative_control PROPERTIES TIMEOUT 60)

  add_test(NAME bus_arb_seam COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/bus_arb.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/bus_arb.expect.json
    --report ${CMAKE_CURRENT_BINARY_DIR}/bus-arb-seam.json)
  add_test(NAME bus_arb_seam_negative_control COMMAND ${Python3_EXECUTABLE} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/bus_arb.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/bus_arb.expect.json --negative-control)
  set_tests_properties(bus_arb_seam bus_arb_seam_negative_control PROPERTIES TIMEOUT 60)

  add_test(NAME z80_bank_seam COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/z80_bank.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/z80_bank.expect.json)
  add_test(NAME z80_bank_seam_negative_control COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/z80_bank.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/z80_bank.expect.json --negative-control)
  add_test(NAME z80_guest_checks COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/z80_guest.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/z80_guest.expect.json)
  add_test(NAME z80_guest_checks_negative_control COMMAND ${Python3_EXECUTABLE} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/z80_guest.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/z80_guest.expect.json --negative-control)
  add_test(NAME bus_arb_midinstr_seam COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/bus_arb_midinstr.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/bus_arb_midinstr.expect.json)
  add_test(NAME bus_arb_midinstr_seam_negative_control COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/bus_arb_midinstr.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/bus_arb_midinstr.expect.json --negative-control)
  add_test(NAME fm_script_seam COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/fm_script.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/fm_script.expect.json
    --trace-output ${CMAKE_CURRENT_BINARY_DIR}/fm_script.trace.jsonl
    --report ${CMAKE_CURRENT_BINARY_DIR}/fm_script-seam.json)
  add_test(NAME fm_script_seam_negative_control COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/fm_script.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/fm_script.expect.json --negative-control)
  add_test(NAME dac_seam COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/dac.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/dac.expect.json
    --trace-output ${CMAKE_CURRENT_BINARY_DIR}/dac.trace.jsonl
    --report ${CMAKE_CURRENT_BINARY_DIR}/dac-seam.json)
  add_test(NAME dac_seam_negative_control COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/seam_check.py
    --runner $<TARGET_FILE:gw_seam_runner> --rom ${CMAKE_CURRENT_SOURCE_DIR}/roms/dac.bin
    --expect ${CMAKE_CURRENT_SOURCE_DIR}/roms/dac.expect.json --negative-control)
  set_tests_properties(fm_script_seam fm_script_seam_negative_control PROPERTIES TIMEOUT 120)
  set_tests_properties(dac_seam dac_seam_negative_control PROPERTIES TIMEOUT 60)
  if(GENEWHIP_TEST_HOOKS)
    add_test(NAME fm_script_split_equivalence COMMAND audio_chunk_equivalence chunk
      ${CMAKE_CURRENT_SOURCE_DIR}/roms/fm_script.bin 64 62)
    add_test(NAME dac_split_equivalence COMMAND audio_chunk_equivalence chunk
      ${CMAKE_CURRENT_SOURCE_DIR}/roms/dac.bin 4 257)
    set_tests_properties(fm_script_split_equivalence dac_split_equivalence PROPERTIES TIMEOUT 180)
  endif()
  set_tests_properties(z80_bank_seam z80_bank_seam_negative_control z80_guest_checks
    z80_guest_checks_negative_control bus_arb_midinstr_seam
    bus_arb_midinstr_seam_negative_control PROPERTIES TIMEOUT 60)
endif()

# Raster toy (plan GW-02-11): independent pixel oracle driven through gw_headless --dump-fields.
add_test(NAME raster_toy_planes COMMAND ${Python3_EXECUTABLE} -I
  ${CMAKE_CURRENT_SOURCE_DIR}/raster_toy.py ${PROJECT_SOURCE_DIR} $<TARGET_FILE:gw_headless>)
add_test(NAME raster_toy_negative_control COMMAND ${Python3_EXECUTABLE} -I
  ${CMAKE_CURRENT_SOURCE_DIR}/raster_toy.py ${PROJECT_SOURCE_DIR} $<TARGET_FILE:gw_headless> --negative-control)
set_tests_properties(raster_toy_planes raster_toy_negative_control PROPERTIES TIMEOUT 60)
add_test(NAME raster_toy_scroll COMMAND ${Python3_EXECUTABLE} -I
  ${CMAKE_CURRENT_SOURCE_DIR}/raster_toy.py ${PROJECT_SOURCE_DIR} $<TARGET_FILE:gw_headless> --test scroll)
set_tests_properties(raster_toy_scroll PROPERTIES TIMEOUT 60)
add_test(NAME raster_toy_sprites COMMAND ${Python3_EXECUTABLE} -I
  ${CMAKE_CURRENT_SOURCE_DIR}/raster_toy.py ${PROJECT_SOURCE_DIR} $<TARGET_FILE:gw_headless> --test sprites)
add_test(NAME raster_toy_sprites_negative_control COMMAND ${Python3_EXECUTABLE} -I
  ${CMAKE_CURRENT_SOURCE_DIR}/raster_toy.py ${PROJECT_SOURCE_DIR} $<TARGET_FILE:gw_headless> --test sprites --negative-control)
set_tests_properties(raster_toy_sprites raster_toy_sprites_negative_control PROPERTIES TIMEOUT 60)
add_test(NAME raster_toy_sound COMMAND ${Python3_EXECUTABLE} -I
  ${CMAKE_CURRENT_SOURCE_DIR}/raster_toy_sound.py ${PROJECT_SOURCE_DIR} $<TARGET_FILE:gw_headless>)
add_test(NAME raster_toy_sound_negative_control COMMAND ${Python3_EXECUTABLE} -I
  ${CMAKE_CURRENT_SOURCE_DIR}/raster_toy_sound.py ${PROJECT_SOURCE_DIR} $<TARGET_FILE:gw_headless> --negative-control)
set_tests_properties(raster_toy_sound raster_toy_sound_negative_control PROPERTIES TIMEOUT 120)

# Independent game through the core (plan GW-02-13, D-31): non-gating smoke. The outcome is
# printed and recorded; the test fails only on infrastructure errors. Not a compatibility claim.
add_test(NAME independent_game_core_smoke COMMAND ${Python3_EXECUTABLE} -I
  ${PROJECT_SOURCE_DIR}/tests/fixtures/independent_game_core_smoke.py ${PROJECT_SOURCE_DIR} $<TARGET_FILE:gw_headless>)
add_test(NAME independent_game_core_smoke_digest COMMAND ${Python3_EXECUTABLE} -I
  ${PROJECT_SOURCE_DIR}/tests/fixtures/independent_game_core_smoke.py ${PROJECT_SOURCE_DIR} $<TARGET_FILE:gw_headless>
  --check-digest-rejection)
set_tests_properties(independent_game_core_smoke independent_game_core_smoke_digest PROPERTIES TIMEOUT 120 LABELS non-gating)

# Phase 2 evidence report contract (plan GW-02-13): builds the versioned report from this build
# directory and requires each named-reason negative control to be rejected for its own reason.
if(GENEWHIP_BUILD_TOOLS AND GENEWHIP_TEST_HOOKS)
  add_test(NAME phase2_report_contract COMMAND ${Python3_EXECUTABLE} -I
    ${PROJECT_SOURCE_DIR}/tests/evidence/phase2_report_contract.py ${PROJECT_SOURCE_DIR} ${PROJECT_BINARY_DIR})
  set_tests_properties(phase2_report_contract PROPERTIES TIMEOUT 300)
  add_test(NAME phase3_report_contract COMMAND ${Python3_EXECUTABLE} -I
    ${PROJECT_SOURCE_DIR}/tests/evidence/phase3_report_contract.py ${PROJECT_SOURCE_DIR} ${PROJECT_BINARY_DIR})
  set_tests_properties(phase3_report_contract PROPERTIES TIMEOUT 600)
endif()

add_test(NAME independent_game_audio_smoke COMMAND ${Python3_EXECUTABLE} -I
  ${PROJECT_SOURCE_DIR}/tests/fixtures/independent_game_audio_smoke.py ${PROJECT_SOURCE_DIR} $<TARGET_FILE:gw_headless>)
set_tests_properties(independent_game_audio_smoke PROPERTIES TIMEOUT 120 LABELS non-gating)

# Signed, digest-pinned Z80 assembler; unavailable hosts skip visibly (D-63).
add_test(NAME z80_toolchain COMMAND ${Python3_EXECUTABLE} -I
  ${CMAKE_CURRENT_SOURCE_DIR}/z80_toolchain.py)
add_test(NAME z80_toolchain_negative_control COMMAND ${Python3_EXECUTABLE} -I
  ${CMAKE_CURRENT_SOURCE_DIR}/z80_toolchain.py --negative-control)
set_tests_properties(z80_toolchain z80_toolchain_negative_control
  PROPERTIES TIMEOUT 120 SKIP_RETURN_CODE 77)

add_test(NAME independent_game_toolchain COMMAND ${Python3_EXECUTABLE} -I
  ${PROJECT_SOURCE_DIR}/tests/evidence/independent_game_toolchain.py --self-test-lock)
set_tests_properties(independent_game_toolchain PROPERTIES TIMEOUT 30)
add_test(NAME z80_original_rom_pipeline COMMAND ${Python3_EXECUTABLE} -I
  ${CMAKE_CURRENT_SOURCE_DIR}/z80_pipeline.py)
set_tests_properties(z80_original_rom_pipeline PROPERTIES TIMEOUT 120 SKIP_RETURN_CODE 77)

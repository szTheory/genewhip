# SPDX-License-Identifier: MIT
# Record and offline checks run in the default build (no SDL, no network).
add_test(NAME dependency_record COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/dependency_record.py
  record ${PROJECT_SOURCE_DIR}/packaging/dependencies/sdl3.json)
set_tests_properties(dependency_record PROPERTIES TIMEOUT 15)
add_test(NAME default_configure_offline COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/dependency_record.py
  offline-configure ${PROJECT_SOURCE_DIR})
set_tests_properties(default_configure_offline PROPERTIES TIMEOUT 120)

# Runner tests need the SDL option; the dummy video driver keeps them display-free.
if(GENEWHIP_BUILD_DESKTOP)
  add_test(NAME phase4_game_desktop COMMAND ${Python3_EXECUTABLE} -I
    ${PROJECT_SOURCE_DIR}/tests/fixtures/phase4_game.py
    $<TARGET_FILE:gw_headless> $<TARGET_FILE:genewhip_desktop>
    --report ${PROJECT_BINARY_DIR}/evidence/phase4-gameplay.json)
  add_test(NAME phase4_game_desktop_negative_control COMMAND ${Python3_EXECUTABLE} -I
    ${PROJECT_SOURCE_DIR}/tests/fixtures/phase4_game.py
    $<TARGET_FILE:gw_headless> $<TARGET_FILE:genewhip_desktop> --negative-control)
  set_tests_properties(phase4_game_desktop phase4_game_desktop_negative_control PROPERTIES TIMEOUT 1800
    ENVIRONMENT "SDL_VIDEODRIVER=dummy;SDL_AUDIODRIVER=disk;SDL_AUDIO_DISK_OUTPUT_FILE=${PROJECT_BINARY_DIR}/phase4-game-disk.raw")

  add_executable(audio_accounting_contract audio_accounting_contract.c
    ${PROJECT_SOURCE_DIR}/tools/desktop/audio.c
    ${PROJECT_SOURCE_DIR}/tools/session/rate_ctl.c
    ${PROJECT_SOURCE_DIR}/tools/session/rom_file.c)
  target_include_directories(audio_accounting_contract PRIVATE
    ${PROJECT_SOURCE_DIR}/tools/desktop ${PROJECT_SOURCE_DIR}/tools/session)
  target_link_libraries(audio_accounting_contract PRIVATE SDL3::SDL3-static)
  set_target_properties(audio_accounting_contract PROPERTIES
    C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  add_test(NAME audio_accounting_contract COMMAND audio_accounting_contract)

  add_test(NAME phase4_tracer COMMAND ${Python3_EXECUTABLE} -I
    ${PROJECT_SOURCE_DIR}/tests/fixtures/phase4_tracer.py
    --headless $<TARGET_FILE:gw_headless> --desktop $<TARGET_FILE:genewhip_desktop>
    --out ${PROJECT_BINARY_DIR}/evidence/phase4-tracer.json)
  set_tests_properties(phase4_tracer PROPERTIES TIMEOUT 300
    ENVIRONMENT "SDL_VIDEODRIVER=dummy;SDL_AUDIODRIVER=dummy")
  add_test(NAME phase4_host_sessions COMMAND ${Python3_EXECUTABLE} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/phase4_sessions.py software
    --headless $<TARGET_FILE:gw_headless> --desktop $<TARGET_FILE:genewhip_desktop>
    --build ${PROJECT_BINARY_DIR} --out ${PROJECT_BINARY_DIR}/evidence/phase4-host-sessions.json)
  set_tests_properties(phase4_host_sessions PROPERTIES TIMEOUT 3600)
  add_test(NAME phase4_host_live COMMAND ${Python3_EXECUTABLE} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/phase4_sessions.py live
    --headless $<TARGET_FILE:gw_headless> --desktop $<TARGET_FILE:genewhip_desktop>
    --build ${PROJECT_BINARY_DIR} --out ${PROJECT_BINARY_DIR}/evidence/phase4-host-live.json)
  set_tests_properties(phase4_host_live PROPERTIES TIMEOUT 3600 SKIP_RETURN_CODE 77
    LABELS "live-display;live-audio")
  add_test(NAME runner_audio_dump COMMAND ${Python3_EXECUTABLE} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/runner_smoke.py runner_audio_dump
    $<TARGET_FILE:genewhip_desktop> ${PROJECT_SOURCE_DIR}/fixtures/raster-toy/toy.bin
    "" $<TARGET_FILE:gw_headless>)
  set_tests_properties(runner_audio_dump PROPERTIES TIMEOUT 60
    ENVIRONMENT "SDL_VIDEODRIVER=dummy;SDL_AUDIODRIVER=dummy")
  foreach(case runner_fields runner_errors runner_host_controls)
    add_test(NAME ${case} COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/runner_smoke.py
      ${case} $<TARGET_FILE:genewhip_desktop> ${PROJECT_BINARY_DIR}/tests/devices/backdrop.bin)
    set_tests_properties(${case} PROPERTIES TIMEOUT 60 ENVIRONMENT "SDL_VIDEODRIVER=dummy;SDL_AUDIODRIVER=dummy")
  endforeach()
  foreach(case runner_audio_counters runner_audio_fallback)
    add_test(NAME ${case} COMMAND ${Python3_EXECUTABLE} -I
      ${CMAKE_CURRENT_SOURCE_DIR}/runner_smoke.py ${case}
      $<TARGET_FILE:genewhip_desktop> ${PROJECT_BINARY_DIR}/tests/audio/psg_tone.bin)
    set_tests_properties(${case} PROPERTIES TIMEOUT 60
      ENVIRONMENT "SDL_VIDEODRIVER=dummy;SDL_AUDIODRIVER=dummy")
  endforeach()
  add_test(NAME runner_audio_mute_hashes COMMAND ${Python3_EXECUTABLE} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/runner_smoke.py runner_audio_mute_hashes
    $<TARGET_FILE:genewhip_desktop> ${PROJECT_BINARY_DIR}/tests/audio/psg_tone.bin)
  set_tests_properties(runner_audio_mute_hashes PROPERTIES TIMEOUT 60
    ENVIRONMENT "SDL_VIDEODRIVER=dummy;SDL_AUDIODRIVER=dummy")
  add_test(NAME runner_audio_capture COMMAND ${Python3_EXECUTABLE} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/runner_smoke.py runner_audio_capture
    $<TARGET_FILE:genewhip_desktop> ${PROJECT_BINARY_DIR}/tests/audio/psg_tone.bin)
  set_tests_properties(runner_audio_capture PROPERTIES TIMEOUT 60
    ENVIRONMENT "SDL_VIDEODRIVER=dummy;SDL_AUDIODRIVER=disk;SDL_AUDIO_DISK_OUTPUT_FILE=unused")
  add_test(NAME runner_toy_sound COMMAND ${Python3_EXECUTABLE} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/runner_smoke.py runner_toy_sound
    $<TARGET_FILE:genewhip_desktop> ${PROJECT_SOURCE_DIR}/fixtures/raster-toy/toy.bin)
  set_tests_properties(runner_toy_sound PROPERTIES TIMEOUT 90
    ENVIRONMENT "SDL_VIDEODRIVER=dummy;SDL_AUDIODRIVER=disk;SDL_AUDIO_DISK_OUTPUT_FILE=unused")
  foreach(case runner_audio_pause runner_audio_reset)
    add_test(NAME ${case} COMMAND ${Python3_EXECUTABLE} -I
      ${CMAKE_CURRENT_SOURCE_DIR}/runner_smoke.py ${case}
      $<TARGET_FILE:genewhip_desktop> ${PROJECT_BINARY_DIR}/tests/audio/psg_tone.bin)
    set_tests_properties(${case} PROPERTIES TIMEOUT 60
      ENVIRONMENT "SDL_VIDEODRIVER=dummy;SDL_AUDIODRIVER=dummy")
  endforeach()
  add_test(NAME runner_stats COMMAND ${Python3_EXECUTABLE} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/runner_smoke.py runner_stats
    $<TARGET_FILE:genewhip_desktop> ${PROJECT_BINARY_DIR}/tests/audio/psg_tone.bin)
  set_tests_properties(runner_stats PROPERTIES TIMEOUT 60
    ENVIRONMENT "SDL_VIDEODRIVER=dummy;SDL_AUDIODRIVER=dummy")
  add_test(NAME runner_presentation_contract COMMAND ${Python3_EXECUTABLE} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/runner_smoke.py runner_presentation_contract
    $<TARGET_FILE:genewhip_desktop> ${PROJECT_BINARY_DIR}/tests/audio/psg_tone.bin)
  set_tests_properties(runner_presentation_contract PROPERTIES TIMEOUT 60
    ENVIRONMENT "SDL_VIDEODRIVER=dummy;SDL_AUDIODRIVER=dummy")
  add_test(NAME runner_audio_stats_contract COMMAND ${Python3_EXECUTABLE} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/runner_smoke.py runner_audio_stats_contract
    $<TARGET_FILE:genewhip_desktop> ${PROJECT_BINARY_DIR}/tests/audio/psg_tone.bin)
  set_tests_properties(runner_audio_stats_contract PROPERTIES TIMEOUT 60
    ENVIRONMENT "SDL_VIDEODRIVER=dummy;SDL_AUDIODRIVER=dummy")
  add_executable(runner_presentation_contract_accounting runner_presentation_contract.c)
  target_include_directories(runner_presentation_contract_accounting PRIVATE
    ${PROJECT_SOURCE_DIR}/tools/desktop)
  set_target_properties(runner_presentation_contract_accounting PROPERTIES
    C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  add_test(NAME runner_presentation_contract_accounting
    COMMAND runner_presentation_contract_accounting)
  add_test(NAME runner_audio_replay COMMAND ${Python3_EXECUTABLE} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/runner_smoke.py runner_audio_replay
    $<TARGET_FILE:genewhip_desktop> ${PROJECT_BINARY_DIR}/tests/audio/psg_tone.bin "" $<TARGET_FILE:gw_headless>)
  set_tests_properties(runner_audio_replay PROPERTIES TIMEOUT 60
    ENVIRONMENT "SDL_VIDEODRIVER=dummy;SDL_AUDIODRIVER=dummy")
  foreach(case runner_input_replay runner_drop)
    add_test(NAME ${case} COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/runner_smoke.py
      ${case} $<TARGET_FILE:genewhip_desktop> ${PROJECT_BINARY_DIR}/tests/devices/backdrop.bin
      ${PROJECT_SOURCE_DIR}/tests/devices/roms/pad_echo.bin $<TARGET_FILE:gw_headless>)
    set_tests_properties(${case} PROPERTIES TIMEOUT 60 ENVIRONMENT "SDL_VIDEODRIVER=dummy;SDL_AUDIODRIVER=dummy")
  endforeach()
  # Opt-in real-window lane (GENEWHIP_LIVE_DISPLAY=1); skips visibly without it or a window server.
  add_test(NAME runner_live_display COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/runner_smoke.py
    runner_live_display $<TARGET_FILE:genewhip_desktop> ${PROJECT_BINARY_DIR}/tests/devices/backdrop.bin
    ${PROJECT_SOURCE_DIR}/tests/devices/roms/pad_echo.bin)
  set_tests_properties(runner_live_display PROPERTIES TIMEOUT 60 SKIP_RETURN_CODE 77 LABELS live-display)
  add_test(NAME runner_live_audio COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/runner_smoke.py
    runner_live_audio $<TARGET_FILE:genewhip_desktop> ${PROJECT_BINARY_DIR}/tests/audio/psg_tone.bin)
  set_tests_properties(runner_live_audio PROPERTIES TIMEOUT 60 SKIP_RETURN_CODE 77 LABELS live-audio)
endif()

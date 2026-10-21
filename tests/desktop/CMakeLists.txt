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

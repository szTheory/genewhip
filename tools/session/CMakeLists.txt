# SPDX-License-Identifier: MIT
# SDL-free session module: field stepping, pause, reset and bounded ROM reading.
add_library(gw_session STATIC session.c route_controller.c rom_file.c input_log.c rate_ctl.c)
target_include_directories(gw_session PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(gw_session PUBLIC Genewhip::core)
set_target_properties(gw_session PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(gw_session PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

# Headless client: reproduces recorded sessions without SDL.
add_executable(gw_headless ${PROJECT_SOURCE_DIR}/tools/headless/main.c)
target_link_libraries(gw_headless PRIVATE gw_session)
if(TARGET gw_diagnostic)
  add_dependencies(gw_headless gw_diagnostic)
endif()
set_target_properties(gw_headless PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(gw_headless PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

if(BUILD_TESTING)
  find_package(Python3 3.8 REQUIRED COMPONENTS Interpreter)
  add_executable(session_contract ${PROJECT_SOURCE_DIR}/tests/session/session_contract.c)
  target_include_directories(session_contract PRIVATE ${PROJECT_SOURCE_DIR}/tests/api)
  target_link_libraries(session_contract PRIVATE gw_session)
  set_target_properties(session_contract PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(session_contract PRIVATE -Wall -Wextra -Wpedantic -Wshadow)
  endif()
  add_test(NAME session_contract COMMAND session_contract)
  set_tests_properties(session_contract PROPERTIES TIMEOUT 15)

  foreach(contract session_cadence input_log_contract)
    add_executable(${contract} ${PROJECT_SOURCE_DIR}/tests/session/${contract}.c)
    target_include_directories(${contract} PRIVATE ${PROJECT_SOURCE_DIR}/tests/api)
    target_link_libraries(${contract} PRIVATE gw_session)
    set_target_properties(${contract} PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
      target_compile_options(${contract} PRIVATE -Wall -Wextra -Wpedantic -Wshadow)
    endif()
  endforeach()
  add_test(NAME session_cadence COMMAND session_cadence
    ${PROJECT_SOURCE_DIR}/tests/devices/roms/pad_echo.bin)
  set_tests_properties(session_cadence PROPERTIES TIMEOUT 60)
  add_test(NAME input_log_contract COMMAND input_log_contract)
  set_tests_properties(input_log_contract PROPERTIES TIMEOUT 15)

  add_executable(rate_ctl_unit ${PROJECT_SOURCE_DIR}/tests/session/rate_ctl_unit.c)
  target_link_libraries(rate_ctl_unit PRIVATE gw_session)
  set_target_properties(rate_ctl_unit PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(rate_ctl_unit PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
  endif()
  add_test(NAME rate_ctl_unit COMMAND rate_ctl_unit)
  set_tests_properties(rate_ctl_unit PROPERTIES TIMEOUT 15)

  add_dependencies(gw_headless gw_psg_tone_rom)
  foreach(mode normal negative_control)
    if(mode STREQUAL "normal")
      add_test(NAME headless_audio_dump COMMAND ${Python3_EXECUTABLE} -I
        ${PROJECT_SOURCE_DIR}/tests/session/headless_audio.py
        $<TARGET_FILE:gw_headless> ${PROJECT_BINARY_DIR}/tests/audio/psg_tone.bin)
    else()
      add_test(NAME headless_audio_dump_negative_control COMMAND ${Python3_EXECUTABLE} -I
        ${PROJECT_SOURCE_DIR}/tests/session/headless_audio.py
        $<TARGET_FILE:gw_headless> ${PROJECT_BINARY_DIR}/tests/audio/psg_tone.bin --negative-control)
    endif()
  endforeach()
  set_tests_properties(headless_audio_dump headless_audio_dump_negative_control PROPERTIES TIMEOUT 60)

  set(PHASE6_DESKTOP_ROSTER_ARG)
  if(GENEWHIP_BUILD_DESKTOP)
    list(APPEND PHASE6_DESKTOP_ROSTER_ARG --desktop)
  endif()
  add_test(NAME phase6_route_contract COMMAND ${Python3_EXECUTABLE} -I
    ${PROJECT_SOURCE_DIR}/tests/session/phase6_route_contract.py --contract --build ${PROJECT_BINARY_DIR}
    ${PHASE6_DESKTOP_ROSTER_ARG})
  add_test(NAME phase6_media_contract COMMAND ${Python3_EXECUTABLE} -I
    ${PROJECT_SOURCE_DIR}/tests/session/phase6_route_contract.py --media-contract --build ${PROJECT_BINARY_DIR})
  set_tests_properties(phase6_media_contract PROPERTIES TIMEOUT 30)
  option(GENEWHIP_PHASE6_ENABLE_SUSTAINED "Register the bounded canonical Phase6 game/control batch" OFF)
  if(GENEWHIP_PHASE6_ENABLE_SUSTAINED)
    add_test(NAME phase6_core_report_contract COMMAND ${Python3_EXECUTABLE} -I
      ${PROJECT_SOURCE_DIR}/tests/fixtures/phase6_game.py --mode contract
      --negative-controls --build ${PROJECT_BINARY_DIR}
      --candidate ${PROJECT_SOURCE_DIR}/evidence/phase6-candidate.json
      --output ${PROJECT_BINARY_DIR}/evidence/phase6-core-check.json)
    set_tests_properties(phase6_core_report_contract PROPERTIES TIMEOUT 60 SKIP_RETURN_CODE 77)
  endif()
  add_test(NAME phase6_delivery_map_contract COMMAND ${Python3_EXECUTABLE} -I
    ${PROJECT_SOURCE_DIR}/tests/fixtures/phase6_game.py --mode delivery-map
    --build ${PROJECT_BINARY_DIR}
    --delivery-map ${PROJECT_SOURCE_DIR}/fixtures/phase6/recursion94-consumed-map-v1.json
    --candidate ${PROJECT_SOURCE_DIR}/evidence/phase6-candidate.json
    --output ${PROJECT_BINARY_DIR}/evidence/phase6-delivery-map-contract.json)
  set_tests_properties(phase6_delivery_map_contract PROPERTIES TIMEOUT 60)
  if(GENEWHIP_PHASE6_ENABLE_SUSTAINED)
    add_test(NAME phase6_core_routes COMMAND ${Python3_EXECUTABLE} -I
      ${PROJECT_SOURCE_DIR}/tests/fixtures/phase6_game.py --mode core
      --build ${PROJECT_BINARY_DIR}
      --delivery-map ${PROJECT_SOURCE_DIR}/fixtures/phase6/recursion94-consumed-map-v1.json
      --candidate ${PROJECT_SOURCE_DIR}/evidence/phase6-candidate.json
      --output ${PROJECT_SOURCE_DIR}/evidence/phase6-core-routes.json)
    set_tests_properties(phase6_core_routes PROPERTIES TIMEOUT 7800 RUN_SERIAL TRUE LABELS "phase6-sustained")
  endif()
  add_test(NAME phase6_report_contract COMMAND ${Python3_EXECUTABLE} -I
    ${PROJECT_SOURCE_DIR}/scripts/evidence/phase6_routes.py --self-test)
  add_test(NAME phase6_controller_contract COMMAND ${Python3_EXECUTABLE} -I
    ${PROJECT_SOURCE_DIR}/tests/session/phase6_controller_contract.py --build ${PROJECT_BINARY_DIR}
    ${PHASE6_DESKTOP_ROSTER_ARG})
  add_test(NAME phase6_capture_argv_contract COMMAND ${Python3_EXECUTABLE} -I
    ${PROJECT_SOURCE_DIR}/tests/session/phase6_capture_argv_contract.py
    --client $<TARGET_FILE:gw_headless> --output ${PROJECT_BINARY_DIR}/evidence/capture-argv.json)
  set_tests_properties(phase6_capture_argv_contract PROPERTIES TIMEOUT 90)
  # Test-only route-controller object forwards its real memory reads through a
  # recording wrapper while the wrapper still calls Genewhip's public API.
  add_library(phase6_stack_forward_controller OBJECT route_controller.c)
  target_include_directories(phase6_stack_forward_controller PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(phase6_stack_forward_controller PRIVATE Genewhip::core)
  target_compile_definitions(phase6_stack_forward_controller PRIVATE gw_peek_memory=gw_test_forward_peek)
  set_target_properties(phase6_stack_forward_controller PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(phase6_stack_forward_controller PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
  endif()
  add_library(phase6_stack_forward_session STATIC session.c rom_file.c input_log.c rate_ctl.c
    $<TARGET_OBJECTS:phase6_stack_forward_controller>)
  target_include_directories(phase6_stack_forward_session PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(phase6_stack_forward_session PUBLIC Genewhip::core)
  set_target_properties(phase6_stack_forward_session PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  add_executable(phase6_stack_forward_contract ${PROJECT_SOURCE_DIR}/tests/session/phase6_stack_forward_contract.c)
  target_link_libraries(phase6_stack_forward_contract PRIVATE phase6_stack_forward_session)
  set_target_properties(phase6_stack_forward_contract PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(phase6_stack_forward_contract PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
  endif()
  add_test(NAME phase6_stack_forward_contract COMMAND phase6_stack_forward_contract)
  set_tests_properties(phase6_stack_forward_contract PROPERTIES TIMEOUT 30)
  add_executable(phase6_chunk_contract ${PROJECT_SOURCE_DIR}/tests/session/phase6_chunk_contract.c)
  target_link_libraries(phase6_chunk_contract PRIVATE Genewhip::core)
  set_target_properties(phase6_chunk_contract PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(phase6_chunk_contract PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
  endif()
  add_test(NAME phase6_chunk_contract COMMAND phase6_chunk_contract)
  set_tests_properties(phase6_route_contract phase6_report_contract phase6_controller_contract PROPERTIES TIMEOUT 60)
  set_tests_properties(phase6_chunk_contract PROPERTIES TIMEOUT 15)
endif()

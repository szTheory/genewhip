# SPDX-License-Identifier: MIT
# SDL-free session module: field stepping, pause, reset and bounded ROM reading.
add_library(gw_session STATIC session.c rom_file.c input_log.c rate_ctl.c)
target_include_directories(gw_session PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(gw_session PUBLIC Genewhip::core)
set_target_properties(gw_session PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(gw_session PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

# Headless client: reproduces recorded sessions without SDL.
add_executable(gw_headless ${PROJECT_SOURCE_DIR}/tools/headless/main.c)
target_link_libraries(gw_headless PRIVATE gw_session)
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
endif()

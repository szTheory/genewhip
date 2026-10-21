# Offline adapters are only available in test-hook/tool builds and never enter install().
add_executable(gw_fm_port_replay port_replay.c)
target_include_directories(gw_fm_port_replay PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(gw_fm_port_replay PRIVATE Genewhip::core)
target_compile_definitions(gw_fm_port_replay PRIVATE GW_TEST_HOOKS)
set_target_properties(gw_fm_port_replay PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(gw_fm_port_replay PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

foreach(test_name ym_port_fidelity ym_nuked_compare ym_nuked_negative_control ym_compare_repeat)
  if(test_name STREQUAL "ym_port_fidelity")
    set(test_args --fidelity)
  elseif(test_name STREQUAL "ym_nuked_compare")
    set(test_args --model)
  elseif(test_name STREQUAL "ym_nuked_negative_control")
    set(test_args --negative-control)
  else()
    set(test_args --repeat)
  endif()
  add_test(NAME ${test_name} COMMAND ${Python3_EXECUTABLE} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/compare.py ${test_args}
    --seam-runner $<TARGET_FILE:gw_seam_runner>
    --port-runner $<TARGET_FILE:gw_fm_port_replay>)
  set_tests_properties(${test_name} PROPERTIES TIMEOUT 600 SKIP_RETURN_CODE 77 LABELS fm-compare)
endforeach()

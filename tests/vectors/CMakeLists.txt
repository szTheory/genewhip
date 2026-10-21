# Manifest hashes/denominators are checked at test execution, not just configure.
# The vector adapter needs the private sparse-memory overlay, which exists only in
# hooks builds. Hooks-off builds register no vector test and instead prove that the
# library carries no overlay symbol.
find_package(Python3 3.8 REQUIRED COMPONENTS Interpreter)
if(GENEWHIP_TEST_HOOKS)
  add_executable(cpu_vector_runner cpu_vectors.c)
  target_link_libraries(cpu_vector_runner PRIVATE Genewhip::core)
  set_target_properties(cpu_vector_runner PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  target_compile_definitions(cpu_vector_runner PRIVATE GW_TEST_HOOKS)
  add_test(NAME cpu_vectors COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/run_vectors.py --runner $<TARGET_FILE:cpu_vector_runner>)
  add_test(NAME cpu_vectors_negative_control COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/run_vectors.py --runner $<TARGET_FILE:cpu_vector_runner> --negative-control)
  add_test(NAME cpu_vectors_integrity COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/integrity_contract.py $<TARGET_FILE:cpu_vector_runner>)
  set_tests_properties(cpu_vectors cpu_vectors_negative_control cpu_vectors_integrity PROPERTIES TIMEOUT 30)
  # Authored MC68000UM-derived interrupt-entry tests (plan GW-02-10); hooks only.
  add_executable(cpu_interrupt cpu_interrupt.c)
  target_link_libraries(cpu_interrupt PRIVATE Genewhip::core)
  set_target_properties(cpu_interrupt PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  target_compile_definitions(cpu_interrupt PRIVATE GW_TEST_HOOKS)
  if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(cpu_interrupt PRIVATE -Wall -Wextra -Wpedantic -Wshadow)
  endif()
  add_test(NAME cpu_interrupt COMMAND cpu_interrupt)
  set_tests_properties(cpu_interrupt PROPERTIES TIMEOUT 15)
else()
  add_test(NAME cpu_overlay_absent COMMAND ${Python3_EXECUTABLE} -c
    "import sys; data = open(sys.argv[1], 'rb').read(); sys.exit('gw_test_memory symbol present' if b'gw_test_memory' in data else 0)"
    $<TARGET_FILE:genewhip_core>)
  set_tests_properties(cpu_overlay_absent PROPERTIES TIMEOUT 15)
endif()

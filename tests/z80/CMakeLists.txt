find_package(Python3 3.8 REQUIRED COMPONENTS Interpreter)
if(GENEWHIP_TEST_HOOKS)
  add_executable(z80_vector_runner z80_vectors.c)
  target_link_libraries(z80_vector_runner PRIVATE Genewhip::core)
  set_target_properties(z80_vector_runner PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  target_compile_definitions(z80_vector_runner PRIVATE GW_TEST_HOOKS)
  if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(z80_vector_runner PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
  endif()
  add_test(NAME z80_vectors COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/run_z80_vectors.py --runner $<TARGET_FILE:z80_vector_runner>)
  add_test(NAME z80_vectors_negative_control COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/run_z80_vectors.py --runner $<TARGET_FILE:z80_vector_runner> --negative-control)
  add_test(NAME z80_vectors_integrity COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/run_z80_vectors.py --integrity)
  add_test(NAME z80_cycle_resume COMMAND z80_vector_runner --cycle-contract)
  add_executable(z80_interrupt_contract z80_interrupt_contract.c)
  target_link_libraries(z80_interrupt_contract PRIVATE Genewhip::core)
  target_include_directories(z80_interrupt_contract PRIVATE ${CMAKE_SOURCE_DIR}/src)
  target_compile_definitions(z80_interrupt_contract PRIVATE GW_TEST_HOOKS)
  set_target_properties(z80_interrupt_contract PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  add_test(NAME z80_interrupt_contract COMMAND z80_interrupt_contract)
  set_tests_properties(z80_vectors z80_vectors_negative_control z80_vectors_integrity z80_cycle_resume z80_interrupt_contract PROPERTIES TIMEOUT 60)
else()
  add_test(NAME z80_overlay_absent COMMAND ${Python3_EXECUTABLE} -c
    "import sys; data=open(sys.argv[1],'rb').read(); sys.exit('gw_test_z80 symbol present' if b'gw_test_z80' in data else 0)"
    $<TARGET_FILE:genewhip_core>)
  set_tests_properties(z80_overlay_absent PROPERTIES TIMEOUT 15)
endif()

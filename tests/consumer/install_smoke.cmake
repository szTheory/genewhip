function(checked)
  execute_process(COMMAND ${ARGV} RESULT_VARIABLE status)
  if(NOT status EQUAL 0)
    message(FATAL_ERROR "Installed-consumer step failed: ${ARGV0} (${status})")
  endif()
endfunction()

if(GW_CONFIG)
  set(config_args --config "${GW_CONFIG}")
  set(ctest_config_args -C "${GW_CONFIG}")
endif()

# Use a moved temporary prefix and copied consumer sources, with no source-tree
# include path. All generated files stay inside this test's build directory.
set(scratch "${GW_BUILD}/consumer-smoke")
file(REMOVE_RECURSE "${scratch}")
file(MAKE_DIRECTORY "${scratch}/project")
checked("${CMAKE_COMMAND}" --install "${GW_BUILD}" --prefix "${scratch}/original" ${config_args})
file(RENAME "${scratch}/original" "${scratch}/relocated")
file(COPY "${GW_SOURCE}/tests/consumer/CMakeLists.txt" "${GW_SOURCE}/tests/consumer/main.c"
  "${GW_SOURCE}/tests/consumer/header.cpp" "${GW_SOURCE}/tests/consumer/negative_oracle.cmake"
  DESTINATION "${scratch}/project")
file(COPY "${GW_BUILD}/diagnostic.bin" DESTINATION "${scratch}")
checked("${CMAKE_COMMAND}" -S "${scratch}/project" -B "${scratch}/build"
  "-DCMAKE_PREFIX_PATH=${scratch}/relocated" "-DGW_ROM=${scratch}/diagnostic.bin"
  "-DGW_HOOKS=${GW_HOOKS}" "-DCMAKE_C_COMPILER=${GW_C_COMPILER}"
  "-DCMAKE_C_FLAGS=${GW_C_FLAGS}" "-DCMAKE_EXE_LINKER_FLAGS=${GW_LINK_FLAGS}"
  "-DCMAKE_BUILD_TYPE=${GW_CONFIG}")
checked("${CMAKE_COMMAND}" --build "${scratch}/build" ${config_args})
checked("${CMAKE_CTEST_COMMAND}" --test-dir "${scratch}/build" ${ctest_config_args} --output-on-failure)

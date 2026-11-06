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
string(RANDOM LENGTH 16 ALPHABET 0123456789abcdef invocation_id)
set(scratch "${GW_BUILD}/consumer-smoke-${invocation_id}")
file(MAKE_DIRECTORY "${scratch}/project")
checked("${CMAKE_COMMAND}" --install "${GW_BUILD}" --prefix "${scratch}/original" ${config_args})
file(RENAME "${scratch}/original" "${scratch}/relocated")
file(COPY "${GW_SOURCE}/tests/consumer/CMakeLists.txt" "${GW_SOURCE}/tests/consumer/main.c"
  "${GW_SOURCE}/tests/consumer/header.cpp" "${GW_SOURCE}/tests/consumer/negative_oracle.cmake"
  DESTINATION "${scratch}/project")
if(NOT DEFINED GW_INSTALL_PACKAGE_VERSION OR GW_INSTALL_PACKAGE_VERSION STREQUAL "")
  message(FATAL_ERROR "Installed package version was not supplied to the consumer smoke test")
endif()
set(consumer_cmake "${scratch}/project/CMakeLists.txt")
file(READ "${consumer_cmake}" consumer_cmake_contents)
string(REPLACE "find_package(Genewhip 0.2.0 EXACT CONFIG REQUIRED)"
  "find_package(Genewhip ${GW_INSTALL_PACKAGE_VERSION} EXACT CONFIG REQUIRED)"
  consumer_cmake_contents "${consumer_cmake_contents}")
if(consumer_cmake_contents STREQUAL "")
  message(FATAL_ERROR "Installed consumer CMake file was empty")
endif()
if(NOT consumer_cmake_contents MATCHES "find_package\\(Genewhip ${GW_INSTALL_PACKAGE_VERSION} EXACT CONFIG REQUIRED\\)")
  message(FATAL_ERROR "Installed consumer package version was not updated")
endif()
file(WRITE "${consumer_cmake}" "${consumer_cmake_contents}")
file(COPY "${GW_BUILD}/diagnostic.bin" DESTINATION "${scratch}")
checked("${CMAKE_COMMAND}" -S "${scratch}/project" -B "${scratch}/build"
  "-DCMAKE_PREFIX_PATH=${scratch}/relocated" "-DGW_ROM=${scratch}/diagnostic.bin"
  "-DGW_HOOKS=${GW_HOOKS}" "-DCMAKE_C_COMPILER=${GW_C_COMPILER}"
  "-DCMAKE_C_FLAGS=${GW_C_FLAGS}" "-DCMAKE_EXE_LINKER_FLAGS=${GW_LINK_FLAGS}"
  "-DCMAKE_BUILD_TYPE=${GW_CONFIG}")
checked("${CMAKE_COMMAND}" --build "${scratch}/build" ${config_args})
checked("${CMAKE_CTEST_COMMAND}" --test-dir "${scratch}/build" ${ctest_config_args} --output-on-failure)
file(REMOVE_RECURSE "${scratch}")

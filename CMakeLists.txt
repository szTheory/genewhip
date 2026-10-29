cmake_minimum_required(VERSION 3.24)
project(Genewhip VERSION 0.2.0 LANGUAGES C)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)
option(GENEWHIP_TEST_HOOKS "Compile private allocation test hook (not public API)" ${BUILD_TESTING})
option(GENEWHIP_BUILD_TOOLS "Build original diagnostic and evidence tools" ON)
option(GENEWHIP_BUILD_DESKTOP "Build the SDL3 desktop runner (fetches a pinned SDL3 source archive)" OFF)
set(GENEWHIP_INSTALL_PACKAGE_VERSION "${PROJECT_VERSION}" CACHE STRING
  "Version advertised by the installed Genewhip CMake package")

add_library(genewhip_core STATIC src/core.c src/cpu68000.c src/z80.c src/z80_bus.c src/bus.c src/vdp.c src/io.c src/psg.c src/ym2612.c src/state_digest.c src/render.c src/diagnostic.c src/diagnostics.c src/audio_out.c)
add_library(Genewhip::core ALIAS genewhip_core)
set_target_properties(genewhip_core PROPERTIES EXPORT_NAME core C_STANDARD 17
  C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
target_include_directories(genewhip_core PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(genewhip_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()
if(GENEWHIP_TEST_HOOKS)
  target_compile_definitions(genewhip_core PRIVATE GW_TEST_HOOKS)
endif()

install(TARGETS genewhip_core EXPORT GenewhipTargets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/genewhip DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DATADIR}/genewhip)
install(FILES packaging/notices/THIRD-PARTY-ymfm.txt DESTINATION ${CMAKE_INSTALL_DATADIR}/genewhip/notices)
install(EXPORT GenewhipTargets NAMESPACE Genewhip:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Genewhip)
configure_package_config_file(cmake/GenewhipConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/GenewhipConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Genewhip)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/GenewhipConfigVersion.cmake
  VERSION ${GENEWHIP_INSTALL_PACKAGE_VERSION} COMPATIBILITY ExactVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/GenewhipConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/GenewhipConfigVersion.cmake DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Genewhip)

if(BUILD_TESTING OR GENEWHIP_BUILD_TOOLS)
  add_executable(gw_build_rom tests/diagnostic/build_rom.c)
  set_target_properties(gw_build_rom PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/diagnostic.bin
    COMMAND gw_build_rom ${CMAKE_CURRENT_SOURCE_DIR}/tests/diagnostic/diagnostic.S
      ${CMAKE_CURRENT_BINARY_DIR}/diagnostic.bin
    DEPENDS gw_build_rom tests/diagnostic/diagnostic.S VERBATIM)
  add_custom_target(gw_diagnostic ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/diagnostic.bin)
endif()

if(GENEWHIP_BUILD_TOOLS)
  # Evidence consumes generated target settings, after generator expressions and
  # toolchain/target properties have been resolved. Keep unsupported modes closed.
  if(CMAKE_CONFIGURATION_TYPES OR NOT CMAKE_GENERATOR MATCHES "^(Unix Makefiles|Ninja)$")
    message(FATAL_ERROR "Evidence tools require single-config Unix Makefiles or Ninja; disable GENEWHIP_BUILD_TOOLS for other generators")
  endif()
  if(CMAKE_VERSION VERSION_LESS 3.27)
    message(FATAL_ERROR "Evidence tools require CMake 3.27+ for generated configuration identity; core-only builds support 3.24+")
  endif()
  cmake_file_api(QUERY API_VERSION 1 CODEMODEL 2)
  file(SHA256 "${CMAKE_C_COMPILER}" GW_COMPILER_HASH)
  string(SHA256 GW_CONFIGURATION_SEED
    "${GW_COMPILER_HASH}|${CMAKE_C_COMPILER_ID}|${CMAKE_C_COMPILER_VERSION}|${CMAKE_C_FLAGS}|${CMAKE_C_FLAGS_DEBUG}|${CMAKE_C_FLAGS_RELEASE}|${CMAKE_C_FLAGS_RELWITHDEBINFO}|${CMAKE_C_FLAGS_MINSIZEREL}|${CMAKE_EXE_LINKER_FLAGS}|${CMAKE_EXE_LINKER_FLAGS_DEBUG}|${CMAKE_EXE_LINKER_FLAGS_RELEASE}|${CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO}|${CMAKE_EXE_LINKER_FLAGS_MINSIZEREL}|${CMAKE_BUILD_TYPE}|${CMAKE_SYSTEM_NAME}|${CMAKE_SYSTEM_PROCESSOR}|${CMAKE_OSX_ARCHITECTURES}|${CMAKE_OSX_DEPLOYMENT_TARGET}|${CMAKE_OSX_SYSROOT}|${CMAKE_SYSROOT}|${GENEWHIP_TEST_HOOKS}|C17|api4")
  # The codemodel contains resolved flags/defines/includes and link fragments.
  # Driver arguments and toolchain command templates live outside that model.
  set(GW_DRIVER_CONFIGURATION "${CMAKE_VERSION}|${CMAKE_GENERATOR}")
  foreach(setting CMAKE_C_COMPILER_ARG1 CMAKE_C_COMPILER_TARGET
      CMAKE_C_COMPILER_EXTERNAL_TOOLCHAIN CMAKE_C_COMPILER_LAUNCHER
      CMAKE_C_LINKER_LAUNCHER CMAKE_C_COMPILE_OBJECT CMAKE_C_LINK_EXECUTABLE
      CMAKE_C_ARCHIVE_CREATE CMAKE_C_ARCHIVE_APPEND CMAKE_C_ARCHIVE_FINISH
      CMAKE_C_CREATE_STATIC_LIBRARY CMAKE_C_STANDARD_LIBRARIES)
    string(APPEND GW_DRIVER_CONFIGURATION "\n${setting}=${${setting}}")
  endforeach()
  foreach(program CMAKE_AR CMAKE_RANLIB CMAKE_LINKER CMAKE_C_COMPILER_AR CMAKE_C_COMPILER_RANLIB)
    if(EXISTS "${${program}}")
      file(SHA256 "${${program}}" program_hash)
      string(APPEND GW_DRIVER_CONFIGURATION "\n${program}=${program_hash}")
    endif()
  endforeach()
  # Private build file only; bracket quoting preserves literal toolchain text.
  configure_file(cmake/EvidenceDriver.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/EvidenceDriver.cmake @ONLY)
  configure_file(cmake/EvidenceIdentity.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/EvidenceIdentity.cmake @ONLY)
  add_custom_target(gw_evidence_identity
    COMMAND ${CMAKE_COMMAND} -DGW_ACTIVE_CONFIG=$<CONFIG> -P ${CMAKE_CURRENT_BINARY_DIR}/EvidenceIdentity.cmake
    BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/evidence-$<CONFIG>/identity.h
    DEPENDS gw_diagnostic VERBATIM)
  add_executable(gw_diagnostic_runner tools/diagnostic/main.c)
  target_link_libraries(gw_diagnostic_runner PRIVATE Genewhip::core)
  add_executable(gw_validate_evidence tools/evidence/main.c tools/evidence/validate.c)
  install(TARGETS gw_diagnostic_runner gw_validate_evidence RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/diagnostic.bin DESTINATION ${CMAKE_INSTALL_DATADIR}/genewhip)
  foreach(tool gw_diagnostic_runner gw_validate_evidence)
    add_dependencies(${tool} gw_evidence_identity)
    target_include_directories(${tool} PRIVATE tools/evidence ${CMAKE_CURRENT_BINARY_DIR}/evidence-$<CONFIG>)
    set_target_properties(${tool} PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
      target_compile_options(${tool} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()
  endforeach()
  if(APPLE)
    add_executable(gw_core_benchmark tools/evidence/core_benchmark.c)
    target_include_directories(gw_core_benchmark PRIVATE src)
    if(GENEWHIP_TEST_HOOKS)
      target_compile_definitions(gw_core_benchmark PRIVATE GW_TEST_HOOKS)
    endif()
    add_dependencies(gw_core_benchmark gw_evidence_identity)
    set_target_properties(gw_core_benchmark PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
      target_compile_options(gw_core_benchmark PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()
  endif()
  # Launchers can rewrite commands after the codemodel is generated. Their
  # behavior is not represented by compile/link fragments, so fail closed.
  function(gw_check_evidence_launchers)
    foreach(property RULE_LAUNCH_COMPILE RULE_LAUNCH_LINK)
      get_property(global_launcher GLOBAL PROPERTY ${property})
      get_property(directory_launcher DIRECTORY PROPERTY ${property})
      if(global_launcher OR directory_launcher)
        message(FATAL_ERROR "Evidence configuration does not support command launchers")
      endif()
    endforeach()
    foreach(target genewhip_core gw_build_rom gw_diagnostic_runner gw_validate_evidence)
      foreach(property C_COMPILER_LAUNCHER C_LINKER_LAUNCHER RULE_LAUNCH_COMPILE RULE_LAUNCH_LINK)
        get_target_property(launcher ${target} ${property})
        if(launcher)
          message(FATAL_ERROR "Evidence configuration does not support command launchers (${target}.${property})")
        endif()
      endforeach()
    endforeach()
  endfunction()
  cmake_language(DEFER CALL gw_check_evidence_launchers)
endif()

# SDL-free session module shared by the desktop runner and headless clients.
if(BUILD_TESTING OR GENEWHIP_BUILD_TOOLS OR GENEWHIP_BUILD_DESKTOP)
  add_subdirectory(tools/session)
endif()
if(APPLE AND GENEWHIP_BUILD_TOOLS)
  target_link_libraries(gw_core_benchmark PRIVATE gw_session)
endif()
if(GENEWHIP_BUILD_DESKTOP)
  # FetchContent is included only here, so a default configure never downloads code.
  include(cmake/GenewhipDesktop.cmake)
endif()

if(BUILD_TESTING)
  add_executable(gw_bounded_fuzz tests/api/bounded_fuzz.c)
  target_link_libraries(gw_bounded_fuzz PRIVATE Genewhip::core)
  set_target_properties(gw_bounded_fuzz PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  find_package(Python3 3.8 REQUIRED COMPONENTS Interpreter)
  if(APPLE AND GENEWHIP_BUILD_TOOLS)
    add_test(NAME benchmark_contract COMMAND ${Python3_EXECUTABLE} -I
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/evidence/benchmark_contract.py
      --build ${CMAKE_CURRENT_BINARY_DIR})
    set_tests_properties(benchmark_contract PROPERTIES TIMEOUT 180)
  endif()
  add_subdirectory(tests/vectors)
  add_subdirectory(tests/z80)
  add_subdirectory(tests/devices)
  add_subdirectory(tests/desktop)
  add_subdirectory(tests/audio)
  if(GENEWHIP_BUILD_TOOLS AND GENEWHIP_TEST_HOOKS)
    add_subdirectory(tools/evidence/fm_compare)
  endif()
  add_executable(evidence_contract tests/evidence/evidence_contract.c tools/evidence/validate.c)
  target_include_directories(evidence_contract PRIVATE tools/evidence)
  set_target_properties(evidence_contract PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  add_test(NAME evidence_contract COMMAND evidence_contract)
  set_tests_properties(evidence_contract PROPERTIES TIMEOUT 15)
  if(GENEWHIP_BUILD_TOOLS)
    add_test(NAME phase5_public_admission_contract COMMAND ${Python3_EXECUTABLE} -I
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/evidence/public_admission_contract.py)
    set_tests_properties(phase5_public_admission_contract PROPERTIES TIMEOUT 60)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.planning/phases/GW-05-candidate-admission-and-baseline/05-02-SUMMARY.md")
      add_test(NAME phase5_admission_contract COMMAND ${Python3_EXECUTABLE} -I
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/evidence/phase5_admission_contract.py --self-test --consumer-self-test)
      set_tests_properties(phase5_admission_contract PROPERTIES TIMEOUT 30 LABELS "private-historical-admission")
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.planning/phases/GW-05-candidate-admission-and-baseline/05-02-SUMMARY.md")
      add_test(NAME phase5_build_contract COMMAND ${Python3_EXECUTABLE} -I
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/evidence/phase5_build_contract.py --policy-self-test)
      set_tests_properties(phase5_build_contract PROPERTIES TIMEOUT 30
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} LABELS "private-historical-admission")
      add_test(NAME phase5_build_enforcement COMMAND ${Python3_EXECUTABLE} -I
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/evidence/phase5_build_contract.py --enforcement-self-test)
      set_tests_properties(phase5_build_enforcement PROPERTIES TIMEOUT 180 LABELS "phase5-capability;local-isolation;private-historical-admission")
      add_test(NAME phase5_reference_contract COMMAND ${Python3_EXECUTABLE} -I
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/phase5_reference.py --self-test --decision D-118)
      set_tests_properties(phase5_reference_contract PROPERTIES TIMEOUT 30 LABELS "private-historical-admission")
      add_test(NAME phase5_reference_pair COMMAND ${Python3_EXECUTABLE} -I
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/phase5_reference.py
        --verify-pair ${CMAKE_CURRENT_SOURCE_DIR}/evidence/phase5-reference-d118.json --decision D-118)
      set_tests_properties(phase5_reference_pair PROPERTIES TIMEOUT 1800
        SKIP_RETURN_CODE 77 LABELS "phase5-capability;local-reference-evidence;private-historical-admission")
      option(GENEWHIP_PHASE5_ENABLE_REFERENCE_QUALIFY
        "Enable the opt-in long-running Phase 5 MAME route qualification lane" OFF)
      if(GENEWHIP_PHASE5_ENABLE_REFERENCE_QUALIFY)
        add_test(NAME phase5_reference_qualify COMMAND ${Python3_EXECUTABLE} -I
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/phase5_reference.py --qualify-next --decision D-118
          --ledger ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/candidate-screening-v2.json
          --eligibility ${CMAKE_CURRENT_SOURCE_DIR}/evidence/phase5-eligibility-v2.json
          --output ${CMAKE_CURRENT_BINARY_DIR}/phase5-reference-qualification.json)
        set_tests_properties(phase5_reference_qualify PROPERTIES TIMEOUT 1800
          LABELS "phase5-capability;local-mame;opt-in;private-historical-admission")
      endif()
    endif()
    add_test(NAME phase5_baseline_contract COMMAND ${Python3_EXECUTABLE} -I
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/evidence/phase5_baseline_contract.py --self-test)
    set_tests_properties(phase5_baseline_contract PROPERTIES TIMEOUT 30)
    add_test(NAME phase5_game_contract COMMAND ${Python3_EXECUTABLE} -I
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/phase5_game.py --self-test)
    set_tests_properties(phase5_game_contract PROPERTIES TIMEOUT 30)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.planning/phases/GW-05-candidate-admission-and-baseline/05-02-SUMMARY.md")
      add_test(NAME phase5_admitted_pair COMMAND ${Python3_EXECUTABLE} -I
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/evidence/phase5_admission_contract.py --verify-admitted-pair)
      set_tests_properties(phase5_admitted_pair PROPERTIES TIMEOUT 60 LABELS "private-historical-admission")
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.planning/phases/GW-05-candidate-admission-and-baseline/05-02-SUMMARY.md")
      add_test(NAME phase5_baseline_evidence COMMAND ${Python3_EXECUTABLE} -I
        ${CMAKE_CURRENT_SOURCE_DIR}/scripts/evidence/phase5_baseline.py
        --validate-handoff ${CMAKE_CURRENT_SOURCE_DIR}/evidence/phase5-failure-inventory.json
        --baseline ${CMAKE_CURRENT_SOURCE_DIR}/evidence/phase5-baseline.json)
      set_tests_properties(phase5_baseline_evidence PROPERTIES TIMEOUT 30 LABELS "private-historical-admission")
    endif()
    option(GENEWHIP_PHASE5_ENABLE_BASELINE_COLLECTION
      "Enable the opt-in, bounded local Phase 5 Genewhip baseline collection" OFF)
    if(GENEWHIP_PHASE5_ENABLE_BASELINE_COLLECTION)
      add_test(NAME phase5_baseline_collect COMMAND ${Python3_EXECUTABLE} -I
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/phase5_game.py --collect $<TARGET_FILE:gw_headless>
        --roster ${CMAKE_CURRENT_SOURCE_DIR}/evidence/phase5-baseline-roster.json
        --output ${CMAKE_CURRENT_BINARY_DIR}/phase5-baseline.json)
      set_tests_properties(phase5_baseline_collect PROPERTIES TIMEOUT 1800
        LABELS "phase5-capability;local-baseline;opt-in")
    endif()
    add_test(NAME phase5_tracer COMMAND ${Python3_EXECUTABLE} -I
      ${CMAKE_CURRENT_SOURCE_DIR}/scripts/evidence/phase5_baseline.py
      --tracer $<TARGET_FILE:gw_headless> --output ${CMAKE_CURRENT_BINARY_DIR}/phase5-tracer.json)
    set_tests_properties(phase5_tracer PROPERTIES TIMEOUT 60)
    add_test(NAME evidence_integration COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/evidence/integration.py
      $<TARGET_FILE:gw_diagnostic_runner> $<TARGET_FILE:gw_validate_evidence>
      ${CMAKE_CURRENT_BINARY_DIR}/diagnostic.bin)
    set_tests_properties(evidence_integration PROPERTIES TIMEOUT 30)
    add_test(NAME evidence_configuration COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/evidence/configuration.py
      ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_COMMAND})
    set_tests_properties(evidence_configuration PROPERTIES TIMEOUT 120)
  endif()
  add_test(NAME fixture_manifest COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/evidence/fixture_manifest.py
    ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/diagnostic.bin repository)
  set_tests_properties(fixture_manifest PROPERTIES TIMEOUT 15)
  add_test(NAME independent_game_admission COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/evidence/independent_game_admission.py
    ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/diagnostic.bin)
  set_tests_properties(independent_game_admission PROPERTIES TIMEOUT 1800 SKIP_RETURN_CODE 77 LABELS mame)
  add_test(NAME independent_game_consumer COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/evidence/independent_game_admission.py
    ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/diagnostic.bin --consumer-gate)
  set_tests_properties(independent_game_consumer PROPERTIES TIMEOUT 1800 SKIP_RETURN_CODE 77 LABELS mame)
  add_executable(diagnostics_contract tests/diagnostics/diagnostics_contract.c)
  target_link_libraries(diagnostics_contract PRIVATE Genewhip::core)
  set_target_properties(diagnostics_contract PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  if(GENEWHIP_TEST_HOOKS)
    target_compile_definitions(diagnostics_contract PRIVATE GW_TEST_HOOKS)
  endif()
  add_test(NAME diagnostics_contract COMMAND diagnostics_contract ${CMAKE_CURRENT_BINARY_DIR}/diagnostic.bin)
  set_tests_properties(diagnostics_contract PROPERTIES TIMEOUT 15)
  foreach(contract load_contract time_contract reset_contract bus_boundary_contract gameplay_bus_contract movem_contract phase6_repairs_contract phase6_safety)
    add_executable(${contract} tests/api/${contract}.c)
    target_link_libraries(${contract} PRIVATE Genewhip::core)
    set_target_properties(${contract} PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
    add_test(NAME ${contract} COMMAND ${contract})
    set_tests_properties(${contract} PROPERTIES TIMEOUT 15)
  endforeach()
  set_tests_properties(movem_contract PROPERTIES TIMEOUT 30)
  if(GENEWHIP_TEST_HOOKS)
    target_compile_definitions(movem_contract PRIVATE GW_TEST_HOOKS)
    target_compile_definitions(phase6_repairs_contract PRIVATE GW_TEST_HOOKS)
    target_compile_definitions(phase6_safety PRIVATE GW_TEST_HOOKS)
  endif()
  if(GENEWHIP_TEST_HOOKS)
    target_include_directories(load_contract PRIVATE src)
    target_compile_definitions(load_contract PRIVATE GW_TEST_HOOKS)
  endif()
  target_compile_definitions(load_contract PRIVATE GW_FIXTURE_TANK=\"${CMAKE_CURRENT_SOURCE_DIR}/fixtures/phase5-a/game.bin\")
  if(GENEWHIP_TEST_HOOKS)
    add_executable(memory_accounting tests/api/memory_accounting.c)
    target_link_libraries(memory_accounting PRIVATE Genewhip::core)
    target_include_directories(memory_accounting PRIVATE src)
    target_compile_definitions(memory_accounting PRIVATE GW_TEST_HOOKS)
    set_target_properties(memory_accounting PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
    add_test(NAME memory_accounting COMMAND memory_accounting)
    set_tests_properties(memory_accounting PROPERTIES TIMEOUT 15)
  endif()
  if(GENEWHIP_TEST_HOOKS)
    target_compile_definitions(time_contract PRIVATE GW_TEST_HOOKS)
    target_compile_definitions(gw_bounded_fuzz PRIVATE GW_TEST_HOOKS)
  endif()
  add_test(NAME installed_consumer COMMAND ${CMAKE_COMMAND}
    -DGW_SOURCE=${CMAKE_CURRENT_SOURCE_DIR} -DGW_BUILD=${CMAKE_CURRENT_BINARY_DIR}
    -DGW_CONFIG=$<CONFIG> -DGW_HOOKS=${GENEWHIP_TEST_HOOKS}
    -DGW_C_COMPILER=${CMAKE_C_COMPILER} -DGW_C_FLAGS=${CMAKE_C_FLAGS}
    -DGW_LINK_FLAGS=${CMAKE_EXE_LINKER_FLAGS}
    -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/consumer/install_smoke.cmake)
  set_tests_properties(installed_consumer PROPERTIES TIMEOUT 120)
endif()

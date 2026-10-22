if(NOT PROJECT_SOURCE_DIR)
  message(FATAL_ERROR "PROJECT_SOURCE_DIR is required")
endif()
get_filename_component(PROJECT_SOURCE_DIR "${PROJECT_SOURCE_DIR}" REALPATH)
if(GENEWHIP_PACKAGE_LIVE)
  execute_process(COMMAND "${CMAKE_COMMAND}" -E env GENEWHIP_PACKAGE_LIVE=1
    bash scripts/package-desktop.sh WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}" RESULT_VARIABLE status)
else()
  execute_process(COMMAND bash scripts/package-desktop.sh WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
    RESULT_VARIABLE status)
endif()
if(NOT status EQUAL 0)
  message(FATAL_ERROR "desktop exact archive build/identity/relocation/gameplay/audio smoke failed (${status})")
endif()

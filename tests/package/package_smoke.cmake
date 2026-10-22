if(NOT PROJECT_SOURCE_DIR)
  message(FATAL_ERROR "PROJECT_SOURCE_DIR is required")
endif()
get_filename_component(PROJECT_SOURCE_DIR "${PROJECT_SOURCE_DIR}" REALPATH)
execute_process(COMMAND bash scripts/package-sdk.sh WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
  RESULT_VARIABLE status)
if(NOT status EQUAL 0)
  message(FATAL_ERROR "SDK exact archive identity/safe extraction/offline C/C++ consumer smoke failed (${status})")
endif()

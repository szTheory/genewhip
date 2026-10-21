if(NOT PROJECT_SOURCE_DIR)
  message(FATAL_ERROR "PROJECT_SOURCE_DIR is required")
endif()
execute_process(COMMAND bash scripts/package-sdk.sh WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
  RESULT_VARIABLE status)
if(NOT status EQUAL 0)
  message(FATAL_ERROR "SDK archive build/extract/consumer smoke failed (${status})")
endif()

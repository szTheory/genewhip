execute_process(COMMAND "${CONSUMER}" "${ROM}" --negative-oracle
  RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT status EQUAL 1 OR NOT error MATCHES "FAIL: RAM lanes")
  message(FATAL_ERROR "Corrupted expected word must fail the named RAM-lanes assertion: ${status} ${output} ${error}")
endif()

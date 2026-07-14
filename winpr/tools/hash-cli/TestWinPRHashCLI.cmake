execute_process(
  COMMAND "${CMAKE_COMMAND}" -E echo "Password"
  COMMAND "${WINPR_HASH}" -u alice --password-stdin
  RESULT_VARIABLE hash_result
  OUTPUT_VARIABLE hash_output
  ERROR_VARIABLE hash_error)
if(NOT hash_result EQUAL 0 OR NOT hash_output STREQUAL "a4f49c406510bdcab6824ee7c30fd852\n")
  message(FATAL_ERROR "stdin hash failed: ${hash_result}: ${hash_output}${hash_error}")
endif()

execute_process(
  COMMAND "${CMAKE_COMMAND}" -E echo "Password"
  COMMAND "${WINPR_HASH}" -u alice -d EXAMPLE --password-stdin -f sam
  RESULT_VARIABLE sam_result
  OUTPUT_VARIABLE sam_output
  ERROR_VARIABLE sam_error)
if(NOT sam_result EQUAL 0 OR
   NOT sam_output STREQUAL "alice:EXAMPLE::a4f49c406510bdcab6824ee7c30fd852:::\n")
  message(FATAL_ERROR "stdin SAM output failed: ${sam_result}: ${sam_output}${sam_error}")
endif()

execute_process(
  COMMAND "${WINPR_HASH}" -u alice -p visible --password-stdin
  RESULT_VARIABLE conflict_result
  OUTPUT_QUIET
  ERROR_QUIET)
if(conflict_result EQUAL 0)
  message(FATAL_ERROR "conflicting password sources were accepted")
endif()

set(test_dir "${CMAKE_CURRENT_BINARY_DIR}/TestWinPRHashCLI")
file(MAKE_DIRECTORY "${test_dir}")
string(REPEAT "x" 4096 max_password)
file(WRITE "${test_dir}/max-password" "${max_password}")
execute_process(
  COMMAND "${WINPR_HASH}" -u alice --password-stdin
  INPUT_FILE "${test_dir}/max-password"
  RESULT_VARIABLE max_result
  OUTPUT_QUIET
  ERROR_QUIET)
if(NOT max_result EQUAL 0)
  message(FATAL_ERROR "4096-byte stdin password was rejected")
endif()

file(APPEND "${test_dir}/max-password" "x")
execute_process(
  COMMAND "${WINPR_HASH}" -u alice --password-stdin
  INPUT_FILE "${test_dir}/max-password"
  RESULT_VARIABLE oversized_result
  OUTPUT_QUIET
  ERROR_QUIET)
if(oversized_result EQUAL 0)
  message(FATAL_ERROR "4097-byte stdin password was accepted")
endif()

file(WRITE "${test_dir}/multiline-password" "line1\nline2\n")
execute_process(
  COMMAND "${WINPR_HASH}" -u alice --password-stdin
  INPUT_FILE "${test_dir}/multiline-password"
  RESULT_VARIABLE multiline_result
  OUTPUT_QUIET
  ERROR_QUIET)
if(multiline_result EQUAL 0)
  message(FATAL_ERROR "multiline stdin password was accepted")
endif()

string(ASCII 26 ctrl_z)
file(WRITE "${test_dir}/control-password" "a${ctrl_z}b")
execute_process(
  COMMAND "${WINPR_HASH}" -u alice --password-stdin
  INPUT_FILE "${test_dir}/control-password"
  RESULT_VARIABLE control_result
  OUTPUT_VARIABLE control_output
  ERROR_VARIABLE control_error)
if(NOT control_result EQUAL 0 OR
   NOT control_output STREQUAL "27105b784b7170ab98a7e2e9397870fc\n")
  message(FATAL_ERROR
    "stdin control-byte hash failed: ${control_result}: ${control_output}${control_error}")
endif()
file(REMOVE_RECURSE "${test_dir}")

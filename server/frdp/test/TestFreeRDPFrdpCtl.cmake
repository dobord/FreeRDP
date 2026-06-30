if(NOT DEFINED FRDPCTL_BINARY)
  message(FATAL_ERROR "FRDPCTL_BINARY is not set")
endif()

execute_process(
  COMMAND "${FRDPCTL_BINARY}" reload --socket
  RESULT_VARIABLE reload_result
  OUTPUT_VARIABLE reload_stdout
  ERROR_VARIABLE reload_stderr)

if(NOT reload_result EQUAL 1)
  message(FATAL_ERROR "frdpctl reload --socket returned ${reload_result}, expected 1")
endif()
if(NOT reload_stdout STREQUAL "")
  message(FATAL_ERROR "frdpctl reload --socket wrote unexpected stdout: ${reload_stdout}")
endif()
set(expected_reload_stderr "Usage: ${FRDPCTL_BINARY} reload [--socket <path>]\n")
if(NOT reload_stderr STREQUAL expected_reload_stderr)
  message(FATAL_ERROR "frdpctl reload --socket stderr did not report usage: ${reload_stderr}")
endif()

execute_process(
  COMMAND "${FRDPCTL_BINARY}" reload extra
  RESULT_VARIABLE reload_extra_result
  OUTPUT_VARIABLE reload_extra_stdout
  ERROR_VARIABLE reload_extra_stderr)

if(NOT reload_extra_result EQUAL 1)
  message(FATAL_ERROR "frdpctl reload extra returned ${reload_extra_result}, expected 1")
endif()
if(NOT reload_extra_stdout STREQUAL "")
  message(FATAL_ERROR "frdpctl reload extra wrote unexpected stdout: ${reload_extra_stdout}")
endif()
set(expected_reload_extra_stderr "Usage: ${FRDPCTL_BINARY} reload [--socket <path>]\n")
if(NOT reload_extra_stderr STREQUAL expected_reload_extra_stderr)
  message(FATAL_ERROR "frdpctl reload extra stderr did not report usage: ${reload_extra_stderr}")
endif()

execute_process(
  COMMAND "${FRDPCTL_BINARY}" status --socket
  RESULT_VARIABLE status_result
  OUTPUT_VARIABLE status_stdout
  ERROR_VARIABLE status_stderr)

if(NOT status_result EQUAL 1)
  message(FATAL_ERROR "frdpctl status --socket returned ${status_result}, expected 1")
endif()
if(NOT status_stdout STREQUAL "")
  message(FATAL_ERROR "frdpctl status --socket wrote unexpected stdout: ${status_stdout}")
endif()
set(expected_status_stderr "Usage: ${FRDPCTL_BINARY} status [--socket <path>]\n")
if(NOT status_stderr STREQUAL expected_status_stderr)
  message(FATAL_ERROR "frdpctl status --socket stderr did not report usage: ${status_stderr}")
endif()

execute_process(
  COMMAND "${FRDPCTL_BINARY}" kill-session
  RESULT_VARIABLE kill_result
  OUTPUT_VARIABLE kill_stdout
  ERROR_VARIABLE kill_stderr)

if(NOT kill_result EQUAL 1)
  message(FATAL_ERROR "frdpctl kill-session returned ${kill_result}, expected 1")
endif()
if(NOT kill_stdout STREQUAL "")
  message(FATAL_ERROR "frdpctl kill-session wrote unexpected stdout: ${kill_stdout}")
endif()
set(expected_kill_stderr "Usage: ${FRDPCTL_BINARY} kill-session <id> [--socket <path>]\n")
if(NOT kill_stderr STREQUAL expected_kill_stderr)
  message(FATAL_ERROR "frdpctl kill-session stderr did not report usage: ${kill_stderr}")
endif()

if(NOT DEFINED FRDPD_IPC_DEMO_BINARY)
  message(FATAL_ERROR "FRDPD_IPC_DEMO_BINARY is not set")
endif()

set(expected_usage "Usage: ${FRDPD_IPC_DEMO_BINARY} <config.toml> <socket-path> <username> <password>\n")

function(expect_ipc_demo_usage label)
  execute_process(
    COMMAND "${FRDPD_IPC_DEMO_BINARY}" ${ARGN}
    RESULT_VARIABLE demo_result
    OUTPUT_VARIABLE demo_stdout
    ERROR_VARIABLE demo_stderr)

  if(NOT demo_result EQUAL 1)
    message(FATAL_ERROR "${label} returned ${demo_result}, expected 1")
  endif()
  if(NOT demo_stdout STREQUAL "")
    message(FATAL_ERROR "${label} wrote unexpected stdout: ${demo_stdout}")
  endif()
  if(NOT demo_stderr STREQUAL expected_usage)
    message(FATAL_ERROR "${label} stderr did not report usage: ${demo_stderr}")
  endif()
endfunction()

expect_ipc_demo_usage("frdpd-ipc-demo without arguments")
expect_ipc_demo_usage("frdpd-ipc-demo without password" "/tmp/missing-frdpd.toml"
                      "/tmp/missing-frdpd.sock" "user")

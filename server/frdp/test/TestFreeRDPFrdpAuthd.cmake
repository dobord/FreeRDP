if(NOT DEFINED FRDP_AUTHD_BINARY)
  message(FATAL_ERROR "FRDP_AUTHD_BINARY is not set")
endif()

set(expected_usage
    "Usage: ${FRDP_AUTHD_BINARY} [--pam-service <name> | --config <path>] --socket <absolute-socket-path>\n"
)

set(test_dir "${CMAKE_CURRENT_BINARY_DIR}/TestFreeRDPFrdpAuthd")
file(REMOVE_RECURSE "${test_dir}")
file(MAKE_DIRECTORY "${test_dir}")
set(missing_config "${test_dir}/missing.toml")
set(socket_path "${test_dir}/frdp-authd-test.sock")

function(expect_authd_result name expected_code expected_stderr)
  execute_process(
    COMMAND "${FRDP_AUTHD_BINARY}" ${ARGN}
    RESULT_VARIABLE result
    OUTPUT_VARIABLE stdout
    ERROR_VARIABLE stderr)

  if(NOT result EQUAL expected_code)
    message(FATAL_ERROR "${name} returned ${result}, expected ${expected_code}")
  endif()
  if(NOT stdout STREQUAL "")
    message(FATAL_ERROR "${name} wrote unexpected stdout: ${stdout}")
  endif()
  if(NOT stderr STREQUAL expected_stderr)
    message(FATAL_ERROR "${name} stderr mismatch:\n${stderr}")
  endif()
endfunction()

expect_authd_result("frdp-authd --config" 2 "${expected_usage}" --config)

expect_authd_result("frdp-authd --config without socket" 2 "${expected_usage}" --config
                    "${missing_config}")

expect_authd_result("frdp-authd --config with pam-service" 2 "${expected_usage}" --config
                    "${missing_config}" --pam-service frdpd --socket "${socket_path}")

expect_authd_result("frdp-authd missing config" 1 "failed to load frdp-authd config\n"
                    --config "${missing_config}" --socket "${socket_path}")

expect_authd_result("frdp-authd invalid pam-service" 1 "invalid PAM service name\n"
                    --pam-service bad/service --socket "${socket_path}")

if(NOT DEFINED FRDP_SESMAND_BINARY)
  message(FATAL_ERROR "FRDP_SESMAND_BINARY is not set")
endif()

set(expected_usage
    "Usage: ${FRDP_SESMAND_BINARY} [--pam-service <name> | --config <path>] --socket <absolute-socket-path>\n       ${FRDP_SESMAND_BINARY} [--pam-service <name>] --open-session <user>\nSet FRDP_SESMAND_ALLOW_STANDALONE=1 to enable this development path.\n"
)

function(expect_sesmand_result name expected_code expected_stderr)
  execute_process(
    COMMAND "${FRDP_SESMAND_BINARY}" ${ARGN}
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

expect_sesmand_result("frdp-sesmand --config" 2 "${expected_usage}" --config)

expect_sesmand_result("frdp-sesmand --config without socket" 2 "${expected_usage}" --config
                      /tmp/frdp-sesmand-missing.toml)

expect_sesmand_result("frdp-sesmand --config with standalone open" 2 "${expected_usage}" --config
                      /tmp/frdp-sesmand-missing.toml --open-session nobody)

expect_sesmand_result("frdp-sesmand --config with pam-service" 2 "${expected_usage}" --config
                      /tmp/frdp-sesmand-missing.toml --pam-service frdpd --socket
                      /tmp/frdp-sesmand-test.sock)

expect_sesmand_result("frdp-sesmand missing config" 1
                      "failed to load frdp-sesmand config\n" --config
                      /tmp/frdp-sesmand-missing.toml --socket /tmp/frdp-sesmand-test.sock)

expect_sesmand_result("frdp-sesmand invalid pam-service" 1 "invalid PAM service name\n"
                      --pam-service bad/service --socket /tmp/frdp-sesmand-test.sock)

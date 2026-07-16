if(NOT DEFINED FRDP_SESMAND_BINARY)
  message(FATAL_ERROR "FRDP_SESMAND_BINARY is not set")
endif()

set(expected_usage
    "Usage: ${FRDP_SESMAND_BINARY} [--pam-service <name> | --config <path>] --socket <absolute-socket-path>\n       ${FRDP_SESMAND_BINARY} [--pam-service <name>] --open-session <user>\nSet FRDP_SESMAND_ALLOW_STANDALONE=1 to enable this development path.\n"
)

set(test_dir "${CMAKE_CURRENT_BINARY_DIR}/TestFreeRDPFrdpSesmand")
file(REMOVE_RECURSE "${test_dir}")
file(MAKE_DIRECTORY "${test_dir}")
set(missing_config "${test_dir}/missing.toml")
set(socket_path "${test_dir}/frdp-sesmand-test.sock")
set(unusable_xorg_config "${test_dir}/unusable-xorg.toml")
file(WRITE "${unusable_xorg_config}"
     "[session]\ndisplay_backend = \"xorg-dummy\"\nxorg_path = \"/missing/Xorg\"\nxorg_config = \"/missing/xorg-dummy.conf\"\n")

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
                      "${missing_config}")

expect_sesmand_result("frdp-sesmand --config with standalone open" 2 "${expected_usage}" --config
                      "${missing_config}" --open-session nobody)

expect_sesmand_result("frdp-sesmand --config with pam-service" 2 "${expected_usage}" --config
                      "${missing_config}" --pam-service frdpd --socket "${socket_path}")

expect_sesmand_result("frdp-sesmand missing config" 1
                      "failed to load frdp-sesmand config\n" --config "${missing_config}" --socket
                      "${socket_path}")

expect_sesmand_result("frdp-sesmand unusable xorg backend" 1
                      "failed to load frdp-sesmand config\n" --config
                      "${unusable_xorg_config}" --socket "${socket_path}")

expect_sesmand_result("frdp-sesmand invalid pam-service" 1 "invalid PAM service name\n"
                      --pam-service bad/service --socket "${socket_path}")

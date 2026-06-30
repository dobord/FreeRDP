if(NOT DEFINED FRDPD_BINARY)
  message(FATAL_ERROR "FRDPD_BINARY is not set")
endif()

function(run_frdpd_case_with_result name expected_result expected_message)
  execute_process(
    COMMAND "${FRDPD_BINARY}" ${ARGN}
    RESULT_VARIABLE result
    OUTPUT_VARIABLE stdout
    ERROR_VARIABLE stderr)

  if(NOT result EQUAL expected_result)
    message(FATAL_ERROR "${name}: frdpd returned ${result}, expected ${expected_result}")
  endif()
  if(NOT stdout STREQUAL "")
    message(FATAL_ERROR "${name}: frdpd wrote unexpected stdout: ${stdout}")
  endif()
  string(FIND "${stderr}" "${expected_message}" message_index)
  if(message_index EQUAL -1)
    message(FATAL_ERROR "${name}: stderr did not contain '${expected_message}': ${stderr}")
  endif()
endfunction()

function(run_frdpd_case name expected_message)
  run_frdpd_case_with_result("${name}" 255 "${expected_message}" ${ARGN})
endfunction()

run_frdpd_case(
  "missing-helper-sockets"
  "frdpd normal startup requires --auth-socket and --session-socket"
  --cert=/missing
  --key=/missing)

run_frdpd_case(
  "single-helper-socket"
  "frdpd helper topology requires both auth_socket and session_socket"
  --auth-socket=/tmp/frdpd-test-auth.sock
  --cert=/missing
  --key=/missing)

if(FRDPD_IN_PROCESS_PAM)
  run_frdpd_case(
    "legacy-with-helper-sockets"
    "--allow-in-process-pam cannot be combined with helper sockets"
    --auth-socket=/tmp/frdpd-test-auth.sock
    --session-socket=/tmp/frdpd-test-session.sock
    --allow-in-process-pam
    --cert=/missing
    --key=/missing)
else()
  run_frdpd_case_with_result(
    "legacy-option-disabled"
    2
    "Usage:"
    --allow-in-process-pam
    --cert=/missing
    --key=/missing)
endif()

run_frdpd_case(
  "helper-sockets-before-cert-check"
  "Certificate or key file not found: cert=/missing key=/missing"
  --auth-socket=/tmp/frdpd-test-auth.sock
  --session-socket=/tmp/frdpd-test-session.sock
  --cert=/missing
  --key=/missing)

if(FRDPD_IN_PROCESS_PAM)
  run_frdpd_case(
    "legacy-opt-in-before-cert-check"
    "running legacy in-process PAM path"
    --allow-in-process-pam
    --cert=/missing
    --key=/missing)
endif()

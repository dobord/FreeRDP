if(NOT DEFINED FRDP_KRB_AUTHD_BINARY)
  message(FATAL_ERROR "FRDP_KRB_AUTHD_BINARY is not set")
endif()

function(expect_normalized principal expected)
  execute_process(
    COMMAND "${FRDP_KRB_AUTHD_BINARY}" --normalize-principal-test "${principal}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE stdout
    ERROR_VARIABLE stderr)

  if(NOT result EQUAL 0)
    message(FATAL_ERROR "principal '${principal}' returned ${result}, expected 0: ${stderr}")
  endif()
  if(NOT stdout STREQUAL "${expected}\n")
    message(FATAL_ERROR "principal '${principal}' stdout mismatch: ${stdout}")
  endif()
  if(NOT stderr STREQUAL "")
    message(FATAL_ERROR "principal '${principal}' wrote unexpected stderr: ${stderr}")
  endif()
endfunction()

function(expect_rejected principal)
  execute_process(
    COMMAND "${FRDP_KRB_AUTHD_BINARY}" --normalize-principal-test "${principal}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE stdout
    ERROR_VARIABLE stderr)

  if(NOT result EQUAL 2)
    message(FATAL_ERROR "principal '${principal}' returned ${result}, expected 2")
  endif()
  if(NOT stdout STREQUAL "")
    message(FATAL_ERROR "principal '${principal}' wrote unexpected stdout: ${stdout}")
  endif()
  if(NOT stderr MATCHES "invalid Kerberos user principal")
    message(FATAL_ERROR "principal '${principal}' stderr mismatch: ${stderr}")
  endif()
endfunction()

expect_normalized("alice@EXAMPLE.COM" "alice")
expect_normalized("alice.smith@EXAMPLE.COM" "alice.smith")
expect_normalized("alice_smith-1@EXAMPLE.COM" "alice_smith-1")

expect_rejected("host/server.example.com@EXAMPLE.COM")
expect_rejected("alice/admin@EXAMPLE.COM")
expect_rejected("@EXAMPLE.COM")
expect_rejected("alice@")
expect_rejected("alice@example.com@EXAMPLE.COM")
expect_rejected("alice smith@EXAMPLE.COM")
expect_rejected("alice:admin@EXAMPLE.COM")
expect_rejected("alice@BAD REALM")

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

function(expect_decoded token expected)
  execute_process(
    COMMAND "${FRDP_KRB_AUTHD_BINARY}" --decode-token-test "${token}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE stdout
    ERROR_VARIABLE stderr)

  if(NOT result EQUAL 0)
    message(FATAL_ERROR "token '${token}' returned ${result}, expected 0: ${stderr}")
  endif()
  if(NOT stdout STREQUAL "${expected}\n")
    message(FATAL_ERROR "token '${token}' stdout mismatch: ${stdout}")
  endif()
  if(NOT stderr STREQUAL "")
    message(FATAL_ERROR "token '${token}' wrote unexpected stderr: ${stderr}")
  endif()
endfunction()

function(expect_decode_rejected token)
  execute_process(
    COMMAND "${FRDP_KRB_AUTHD_BINARY}" --decode-token-test "${token}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE stdout
    ERROR_VARIABLE stderr)

  if(NOT result EQUAL 2)
    message(FATAL_ERROR "token '${token}' returned ${result}, expected 2")
  endif()
  if(NOT stdout STREQUAL "")
    message(FATAL_ERROR "token '${token}' wrote unexpected stdout: ${stdout}")
  endif()
  if(NOT stderr MATCHES "invalid base64 Kerberos token")
    message(FATAL_ERROR "token '${token}' stderr mismatch: ${stderr}")
  endif()
endfunction()

function(expect_keytab_env label expected)
  execute_process(
    COMMAND ${CMAKE_COMMAND} -E env ${ARGN} "${FRDP_KRB_AUTHD_BINARY}" --keytab-env-test
    RESULT_VARIABLE result
    OUTPUT_VARIABLE stdout
    ERROR_VARIABLE stderr)

  if(NOT result EQUAL 0)
    message(FATAL_ERROR "${label} returned ${result}, expected 0: ${stderr}")
  endif()
  if(NOT stdout STREQUAL "${expected}\n")
    message(FATAL_ERROR "${label} stdout mismatch: ${stdout}")
  endif()
  if(NOT stderr STREQUAL "")
    message(FATAL_ERROR "${label} wrote unexpected stderr: ${stderr}")
  endif()
endfunction()

function(expect_acceptor_env label expected)
  execute_process(
    COMMAND ${CMAKE_COMMAND} -E env ${ARGN} "${FRDP_KRB_AUTHD_BINARY}" --acceptor-env-test
    RESULT_VARIABLE result
    OUTPUT_VARIABLE stdout
    ERROR_VARIABLE stderr)

  if(NOT result EQUAL 0)
    message(FATAL_ERROR "${label} returned ${result}, expected 0: ${stderr}")
  endif()
  if(NOT stdout STREQUAL "${expected}\n")
    message(FATAL_ERROR "${label} stdout mismatch: ${stdout}")
  endif()
  if(NOT stderr STREQUAL "")
    message(FATAL_ERROR "${label} wrote unexpected stderr: ${stderr}")
  endif()
endfunction()

function(expect_acceptor_imported name)
  execute_process(
    COMMAND "${FRDP_KRB_AUTHD_BINARY}" --import-acceptor-name-test "${name}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE stdout
    ERROR_VARIABLE stderr)

  if(NOT result EQUAL 0)
    message(FATAL_ERROR "acceptor '${name}' returned ${result}, expected 0: ${stderr}")
  endif()
  if(NOT stdout STREQUAL "ok\n")
    message(FATAL_ERROR "acceptor '${name}' stdout mismatch: ${stdout}")
  endif()
  if(NOT stderr STREQUAL "")
    message(FATAL_ERROR "acceptor '${name}' wrote unexpected stderr: ${stderr}")
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

expect_decoded("AQIDBA==" "4 01020304")
expect_decoded("YQ==" "1 61")

expect_decode_rejected("")
expect_decode_rejected("000")
expect_decode_rejected("0=00")

expect_keytab_env("default keytab" "/etc/frdpd/frdpd.keytab"
                  --unset=KRB5_KTNAME --unset=FRDP_KRB_KEYTAB)
expect_keytab_env("FRDP_KRB_KEYTAB keytab" "FILE:/tmp/frdp-custom.keytab"
                  --unset=KRB5_KTNAME FRDP_KRB_KEYTAB=FILE:/tmp/frdp-custom.keytab)
expect_keytab_env("empty keytab env" "/etc/frdpd/frdpd.keytab"
                  KRB5_KTNAME= FRDP_KRB_KEYTAB=)
expect_keytab_env("existing KRB5_KTNAME keytab" "FILE:/tmp/existing.keytab"
                  KRB5_KTNAME=FILE:/tmp/existing.keytab
                  FRDP_KRB_KEYTAB=FILE:/tmp/frdp-custom.keytab)

expect_acceptor_env("default acceptor name" "(default)"
                    --unset=FRDP_KRB_ACCEPTOR_NAME)
expect_acceptor_env("empty acceptor name" "(default)"
                    FRDP_KRB_ACCEPTOR_NAME=)
expect_acceptor_env("custom acceptor name" "TERMSRV@host.example.com"
                    FRDP_KRB_ACCEPTOR_NAME=TERMSRV@host.example.com)
expect_acceptor_imported("TERMSRV@host.example.com")

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

function(expect_account_groups user)
  execute_process(
    COMMAND "${FRDP_KRB_AUTHD_BINARY}" --account-groups-test "${user}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE stdout
    ERROR_VARIABLE stderr)

  if(NOT result EQUAL 0)
    message(FATAL_ERROR "account groups for '${user}' returned ${result}, expected 0: ${stderr}")
  endif()
  if(NOT stdout MATCHES "^[^ ]+ uid=[0-9]+ gid=[0-9]+ group_count=[1-9][0-9]*\n$")
    message(FATAL_ERROR "account groups for '${user}' stdout mismatch: ${stdout}")
  endif()
  if(NOT stderr STREQUAL "")
    message(FATAL_ERROR "account groups for '${user}' wrote unexpected stderr: ${stderr}")
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

function(expect_context_flags label flags)
  execute_process(
    COMMAND "${FRDP_KRB_AUTHD_BINARY}" --context-flags-test "${flags}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE stdout
    ERROR_VARIABLE stderr)

  if(NOT result EQUAL 0)
    message(FATAL_ERROR "${label} flags '${flags}' returned ${result}, expected 0: ${stderr}")
  endif()
  if(NOT stdout STREQUAL "ok\n")
    message(FATAL_ERROR "${label} flags '${flags}' stdout mismatch: ${stdout}")
  endif()
  if(NOT stderr STREQUAL "")
    message(FATAL_ERROR "${label} flags '${flags}' wrote unexpected stderr: ${stderr}")
  endif()
endfunction()

function(expect_context_flags_rejected label flags expected_result)
  execute_process(
    COMMAND "${FRDP_KRB_AUTHD_BINARY}" --context-flags-test "${flags}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE stdout
    ERROR_VARIABLE stderr)

  if(NOT result EQUAL expected_result)
    message(FATAL_ERROR "${label} flags '${flags}' returned ${result}, expected ${expected_result}")
  endif()
  if(NOT stdout STREQUAL "")
    message(FATAL_ERROR "${label} flags '${flags}' wrote unexpected stdout: ${stdout}")
  endif()
  if(expected_result EQUAL 3 AND NOT stderr MATCHES "delegated Kerberos credentials")
    message(FATAL_ERROR "${label} flags '${flags}' stderr mismatch: ${stderr}")
  endif()
endfunction()

function(expect_no_core)
  execute_process(
    COMMAND "${FRDP_KRB_AUTHD_BINARY}" --no-core-test
    RESULT_VARIABLE result
    OUTPUT_VARIABLE stdout
    ERROR_VARIABLE stderr)

  if(NOT result EQUAL 0)
    message(FATAL_ERROR "no-core test returned ${result}, expected 0: ${stderr}")
  endif()
  if(NOT stdout STREQUAL "ok\n")
    message(FATAL_ERROR "no-core stdout mismatch: ${stdout}")
  endif()
  if(NOT stderr STREQUAL "")
    message(FATAL_ERROR "no-core wrote unexpected stderr: ${stderr}")
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

execute_process(
  COMMAND whoami
  RESULT_VARIABLE whoami_result
  OUTPUT_VARIABLE current_user
  ERROR_QUIET)
string(STRIP "${current_user}" current_user)
if(whoami_result EQUAL 0 AND NOT current_user STREQUAL "")
  expect_account_groups("${current_user}")
endif()

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

expect_context_flags("no context flags" "0")
expect_context_flags("mutual and replay context flags" "6")
expect_context_flags_rejected("delegation context flag" "1" 3)
expect_context_flags_rejected("delegation plus replay context flags" "5" 3)
expect_context_flags_rejected("invalid context flags" "not-a-number" 2)

expect_no_core()

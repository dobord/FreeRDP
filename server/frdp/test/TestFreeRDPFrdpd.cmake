if(NOT DEFINED FRDPD_BINARY)
  message(FATAL_ERROR "FRDPD_BINARY is not set")
endif()
if(NOT DEFINED FRDP_SAMPLE_CONFIG_PATH)
  message(FATAL_ERROR "FRDP_SAMPLE_CONFIG_PATH is not set")
endif()
if(NOT DEFINED FRDPD_NTLM_ENABLED)
  message(FATAL_ERROR "FRDPD_NTLM_ENABLED is not set")
endif()

set(test_dir "${CMAKE_CURRENT_BINARY_DIR}/TestFreeRDPFrdpd")
file(REMOVE_RECURSE "${test_dir}")
file(MAKE_DIRECTORY "${test_dir}")

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

set(relative_auth_config "${test_dir}/relative-auth-socket.toml")
file(WRITE "${relative_auth_config}"
     "[server]\n"
     "tls_cert = \"/missing\"\n"
     "tls_key = \"/missing\"\n"
     "[auth]\n"
     "auth_socket = \"relative/authd.sock\"\n"
     "[session]\n"
     "session_socket = \"/tmp/frdpd-test-session.sock\"\n")
run_frdpd_case_with_result(
  "relative-auth-socket-config"
  1
  "failed to load configuration from ${relative_auth_config}"
  --config "${relative_auth_config}")

set(relative_session_config "${test_dir}/relative-session-socket.toml")
file(WRITE "${relative_session_config}"
     "[server]\n"
     "tls_cert = \"/missing\"\n"
     "tls_key = \"/missing\"\n"
     "[auth]\n"
     "auth_socket = \"/tmp/frdpd-test-auth.sock\"\n"
     "[session]\n"
     "session_socket = \"relative/sesmand.sock\"\n")
run_frdpd_case_with_result(
  "relative-session-socket-config"
  1
  "failed to load configuration from ${relative_session_config}"
  --config "${relative_session_config}")

set(ntlm_fallback_config "${test_dir}/ntlm-fallback-disabled.toml")
file(WRITE "${ntlm_fallback_config}"
     "[server]\n"
     "tls_cert = \"/missing\"\n"
     "tls_key = \"/missing\"\n"
     "[auth]\n"
     "auth_socket = \"/tmp/frdpd-test-auth.sock\"\n"
     "ntlm_fallback = false\n"
     "[session]\n"
     "session_socket = \"/tmp/frdpd-test-session.sock\"\n")
run_frdpd_case_with_result(
  "ntlm-fallback-disabled-config"
  255
  "Certificate or key file not found: cert=/missing key=/missing"
  --config "${ntlm_fallback_config}")

set(ntlm_enabled_config "${test_dir}/ntlm-enabled.toml")
file(WRITE "${ntlm_enabled_config}"
     "[server]\n"
     "tls_cert = \"/missing\"\n"
     "tls_key = \"/missing\"\n"
     "[auth]\n"
     "auth_socket = \"/tmp/frdpd-test-auth.sock\"\n"
     "ntlm_fallback = true\n"
     "ntlm_sam_file = \"/missing.sam\"\n"
     "[session]\n"
     "session_socket = \"/tmp/frdpd-test-session.sock\"\n")
if(FRDPD_NTLM_ENABLED)
  run_frdpd_case_with_result(
    "ntlm-enabled-build"
    255
    "Certificate or key file not found: cert=/missing key=/missing"
    --config "${ntlm_enabled_config}")
else()
  run_frdpd_case_with_result(
    "ntlm-disabled-build"
    255
    "NTLM authentication was disabled at build time"
    --config "${ntlm_enabled_config}")
endif()

if(FRDPD_NTLM_ENABLED)
  set(dummy_cert "${test_dir}/tls.crt")
  set(dummy_key "${test_dir}/tls.key")
  file(WRITE "${dummy_cert}" "not-a-certificate\n")
  file(WRITE "${dummy_key}" "not-a-key\n")
  function(run_invalid_ntlm_sam_case case_name sam_path)
    set(case_config "${test_dir}/${case_name}.toml")
    file(WRITE "${case_config}"
         "[server]\n"
         "tls_cert = \"${dummy_cert}\"\n"
         "tls_key = \"${dummy_key}\"\n"
         "[auth]\n"
         "auth_socket = \"/tmp/frdpd-test-auth.sock\"\n"
         "ntlm_fallback = true\n"
         "ntlm_sam_file = \"${sam_path}\"\n"
         "[session]\n"
         "session_socket = \"/tmp/frdpd-test-session.sock\"\n")
    run_frdpd_case_with_result(
      "${case_name}"
      255
      "NTLM fallback requires a valid non-empty owner-only regular ntlm_sam_file owned by frdpd"
      --config "${case_config}")
  endfunction()

  run_invalid_ntlm_sam_case("ntlm-missing-sam" "${test_dir}/missing.sam")

  set(ntlm_bad_mode_sam "${test_dir}/bad-mode.sam")
  file(WRITE "${ntlm_bad_mode_sam}" "user:::8846f7eaee8fb117ad06bdd830b7586c:::\n")
  file(CHMOD "${ntlm_bad_mode_sam}" PERMISSIONS OWNER_READ GROUP_READ)
  run_invalid_ntlm_sam_case("ntlm-bad-mode-sam" "${ntlm_bad_mode_sam}")

  set(ntlm_link_target "${test_dir}/link-target.sam")
  set(ntlm_symlink_sam "${test_dir}/symlink.sam")
  file(WRITE "${ntlm_link_target}" "user:::8846f7eaee8fb117ad06bdd830b7586c:::\n")
  file(CHMOD "${ntlm_link_target}" PERMISSIONS OWNER_READ OWNER_WRITE)
  file(CREATE_LINK "${ntlm_link_target}" "${ntlm_symlink_sam}" SYMBOLIC)
  run_invalid_ntlm_sam_case("ntlm-symlink-sam" "${ntlm_symlink_sam}")

  set(ntlm_hardlink_sam "${test_dir}/hardlink.sam")
  file(CREATE_LINK "${ntlm_link_target}" "${ntlm_hardlink_sam}")
  run_invalid_ntlm_sam_case("ntlm-hardlink-sam" "${ntlm_hardlink_sam}")

  set(ntlm_empty_sam "${test_dir}/empty.sam")
  file(WRITE "${ntlm_empty_sam}" "")
  file(CHMOD "${ntlm_empty_sam}" PERMISSIONS OWNER_READ OWNER_WRITE)
  run_invalid_ntlm_sam_case("ntlm-empty-sam" "${ntlm_empty_sam}")

  set(ntlm_comments_sam "${test_dir}/comments.sam")
  file(WRITE "${ntlm_comments_sam}" "# no accounts\n# provision before startup\n")
  file(CHMOD "${ntlm_comments_sam}" PERMISSIONS OWNER_READ OWNER_WRITE)
  run_invalid_ntlm_sam_case("ntlm-comments-only-sam" "${ntlm_comments_sam}")

  set(ntlm_malformed_sam "${test_dir}/malformed.sam")
  file(WRITE "${ntlm_malformed_sam}" "user:::gggggggggggggggggggggggggggggggg:::\n")
  file(CHMOD "${ntlm_malformed_sam}" PERMISSIONS OWNER_READ OWNER_WRITE)
  run_invalid_ntlm_sam_case("ntlm-malformed-sam" "${ntlm_malformed_sam}")
endif()

if(FRDPD_NTLM_ENABLED)
  run_frdpd_case_with_result(
    "sample-config"
    255
    "Certificate or key file not found: cert=/etc/frdpd/tls.crt key=/etc/frdpd/tls.key"
    --config "${FRDP_SAMPLE_CONFIG_PATH}")
else()
  run_frdpd_case_with_result(
    "sample-config"
    255
    "Certificate or key file not found: cert=/etc/frdpd/tls.crt key=/etc/frdpd/tls.key"
    --config "${FRDP_SAMPLE_CONFIG_PATH}")
endif()

set(audit_disabled_config "${test_dir}/audit-disabled.toml")
file(WRITE "${audit_disabled_config}"
     "[server]\n"
     "tls_cert = \"/missing\"\n"
     "tls_key = \"/missing\"\n"
     "[auth]\n"
     "auth_socket = \"/tmp/frdpd-test-auth.sock\"\n"
     "[session]\n"
     "session_socket = \"/tmp/frdpd-test-session.sock\"\n"
     "[audit]\n"
     "enabled = false\n")
run_frdpd_case_with_result(
  "audit-disabled-config"
  255
  "Certificate or key file not found: cert=/missing key=/missing"
  --config "${audit_disabled_config}")

set(audit_enabled_config "${test_dir}/audit-enabled.toml")
file(WRITE "${audit_enabled_config}"
     "[server]\n"
     "tls_cert = \"/missing\"\n"
     "tls_key = \"/missing\"\n"
     "[auth]\n"
     "auth_socket = \"/tmp/frdpd-test-auth.sock\"\n"
     "[session]\n"
     "session_socket = \"/tmp/frdpd-test-session.sock\"\n"
     "[audit]\n"
     "enabled = true\n")
run_frdpd_case_with_result(
  "audit-enabled-config"
  1
  "failed to load configuration from ${audit_enabled_config}"
  --config "${audit_enabled_config}")

set(clipboard_text_config "${test_dir}/clipboard-text.toml")
file(WRITE "${clipboard_text_config}"
     "[server]\n"
     "tls_cert = \"/missing\"\n"
     "tls_key = \"/missing\"\n"
     "[auth]\n"
     "auth_socket = \"/tmp/frdpd-test-auth.sock\"\n"
     "[session]\n"
     "session_socket = \"/tmp/frdpd-test-session.sock\"\n"
     "[clipboard]\n"
     "mode = \"text\"\n"
     "direction = \"client-to-server\"\n")
run_frdpd_case_with_result(
  "clipboard-text-config"
  255
  "Certificate or key file not found: cert=/missing key=/missing"
  --config "${clipboard_text_config}")

set(kerberos_config "${test_dir}/kerberos-enabled.toml")
file(WRITE "${kerberos_config}"
     "[server]\n"
     "tls_cert = \"/missing\"\n"
     "tls_key = \"/missing\"\n"
     "[auth]\n"
     "auth_socket = \"/tmp/frdpd-test-auth.sock\"\n"
     "ntlm_fallback = false\n"
     "kerberos = true\n"
     "keytab = \"/etc/frdpd/frdpd.keytab\"\n"
     "accepted_spn = \"TERMSRV/rdp01.example.com\"\n"
     "[session]\n"
     "session_socket = \"/tmp/frdpd-test-session.sock\"\n")
run_frdpd_case_with_result(
  "kerberos-enabled-config"
  1
  "Kerberos acceptor configuration requires integrated CredSSP/SPNEGO support"
  --config "${kerberos_config}")

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

run_frdpd_case_with_result(
  "legacy-option-removed"
  2
  "Usage:"
  --allow-in-process-pam
  --cert=/missing
  --key=/missing)

run_frdpd_case(
  "helper-sockets-before-cert-check"
  "Certificate or key file not found: cert=/missing key=/missing"
  --auth-socket=/tmp/frdpd-test-auth.sock
  --session-socket=/tmp/frdpd-test-session.sock
  --cert=/missing
  --key=/missing)

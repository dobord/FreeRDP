if(NOT DEFINED BASH_EXECUTABLE)
  message(FATAL_ERROR "BASH_EXECUTABLE is not set")
endif()
if(NOT DEFINED FRDP_E2E_DIR)
  message(FATAL_ERROR "FRDP_E2E_DIR is not set")
endif()

function(expect_file path)
  if(NOT EXISTS "${path}")
    message(FATAL_ERROR "expected E2E fixture is missing: ${path}")
  endif()
endfunction()

function(expect_contains haystack needle label)
  string(FIND "${haystack}" "${needle}" found)
  if(found EQUAL -1)
    message(FATAL_ERROR "${label} is missing '${needle}':\n${haystack}")
  endif()
endfunction()

foreach(script
        run.sh
        scripts/frdpd-entrypoint.sh
        scripts/frdpd-healthcheck.sh
        scripts/freeipa-ready.sh
        scripts/rdp-load-probe.sh
        scripts/rdp-probe.sh
        scripts/rdp-protocol-regression.sh
        scripts/rdp-session-smoke.sh
        scripts/samba-entrypoint.sh)
  set(script_path "${FRDP_E2E_DIR}/${script}")
  expect_file("${script_path}")
  execute_process(
    COMMAND "${BASH_EXECUTABLE}" -n "${script_path}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE stdout
    ERROR_VARIABLE stderr)
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "bash syntax check failed for ${script}: ${stderr}\n${stdout}")
  endif()
endforeach()

foreach(fixture
        .env.example
        Dockerfile
        Dockerfile.freeipa
        Dockerfile.samba
        frdpd.toml
        pam/frdpd-local
        pam/frdpd-sssd)
  expect_file("${FRDP_E2E_DIR}/${fixture}")
endforeach()

set(compose_file "${FRDP_E2E_DIR}/compose.yaml")
expect_file("${compose_file}")
file(READ "${compose_file}" compose)

foreach(expected
        "component-tests:"
        "rdp-client-local:"
        "samba-dc:"
        "rdp-client-samba:"
        "freeipa:"
        "rdp-client-freeipa:"
        "profiles: [\"component\"]"
        "profiles: [\"local\"]"
        "profiles: [\"samba\"]"
        "profiles: [\"freeipa\"]"
        "FRDP_TEST_GROUP: \${FRDP_TEST_GROUP:-rdp-users}"
        "samba-tool group listmembers"
        "grep -Fxq")
  expect_contains("${compose}" "${expected}" "E2E compose file")
endforeach()

file(READ "${FRDP_E2E_DIR}/scripts/samba-entrypoint.sh" samba_entrypoint)
foreach(expected
        "FRDP_TEST_GROUP:-rdp-users"
        "samba-tool group add"
        "samba-tool group addmembers"
        "samba-tool group listmembers")
  expect_contains("${samba_entrypoint}" "${expected}" "Samba entrypoint")
endforeach()

file(READ "${FRDP_E2E_DIR}/scripts/frdpd-entrypoint.sh" frdpd_entrypoint)
foreach(expected
        "wait_supplementary_group"
        "getent group \"$group\""
        "id -G \"$user\""
        "SSSD resolved supplementary group"
        "SSSD did not resolve supplementary group")
  expect_contains("${frdpd_entrypoint}" "${expected}" "frdpd entrypoint")
endforeach()

file(READ "${FRDP_E2E_DIR}/run.sh" runner)
foreach(expected
        "component)"
        "local)"
        "samba)"
        "freeipa)"
        "all)"
        "FRDP_E2E_ARTIFACTS"
        "FRDP_E2E_PROFILE_TIMEOUT"
        "profile_timeout"
        "command -v git"
        "command -v tar"
        "command -v docker"
        "docker compose version"
        "command -v timeout"
        "timeout \"\${profile_timeout}s\""
        "snapshot_excluded_paths"
        "\${root#\"$repo_root/\"}/artifacts"
        "snapshot_excludes"
        "\${artifacts#\"$repo_root/\"}"
        "mktemp \"\${TMPDIR:-/tmp}/frdp-source."
        "source snapshot contains excluded path"
        "tar -tzf \"$source_archive\""
        "exceeded FRDP_E2E_PROFILE_TIMEOUT"
        "compose-config.yaml"
        "must be a dedicated non-root directory named artifacts"
        "rm -rf -- \"\${artifacts:?}/$profile\""
        "validate_rdp_auth_artifacts"
        "server-auth.log"
        "expected 3 PAM accepts and 2 PAM denials"
        "one NTLM proof rejection and two disabled-user PAM denials"
        "proof identity does not match the delegated credentials"
        "container-inspect")
  expect_contains("${runner}" "${expected}" "E2E runner")
endforeach()

file(READ "${FRDP_E2E_DIR}/scripts/rdp-probe.sh" rdp_probe)
foreach(expected
        "FRDP_E2E_TIMEOUT"
        "FRDP_AUTH_TIMEOUT"
        "positive_integer \"$FRDP_E2E_TIMEOUT\""
        "positive_integer \"$FRDP_AUTH_TIMEOUT\""
        "command -v timeout"
        "command -v xvfb-run"
        "command -v Xvfb"
        "command -v xwd"
        "command -v xclip"
        "command -v ps"
        "command -v nc"
        "command -v find"
        "command -v frdpctl"
        "timeout \"\${FRDP_AUTH_TIMEOUT}s\""
        "-auto-reconnect"
        "frdpctl list-sessions --socket"
        "assert_no_managed_sessions"
        "session-list-after-auth-\${label}.txt"
        "session-runtime-after-auth-\${label}.txt"
        "left managed session runtime artifacts"
        "cleanup_auth_only_session"
        "session-list-after-auth-valid-cleanup.txt"
        "valid auth-only managed session was cleaned"
        "rdp-reconnect.log"
        "session-list-reconnected.txt"
        "session-list-reconnected-held.txt"
        "session_identity_is_exclusively_active"
        "process_is_running"
        "managed RDP session reattached with stable id/display/PID"
        "client-to-server Unicode clipboard transfer passed"
        "server-to-client Unicode clipboard transfer passed"
        "session-list-after-reconnect.txt")
  expect_contains("${rdp_probe}" "${expected}" "E2E RDP probe script")
endforeach()

file(READ "${FRDP_E2E_DIR}/scripts/rdp-load-probe.sh" load_probe)
foreach(expected
        "FRDP_LOAD_CONCURRENCY"
        "FRDP_LOAD_ITERATIONS"
        "FRDP_LOAD_TIMEOUT"
        "command -v timeout"
        "command -v xvfb-run"
        "command -v nc"
        "timeout \"\${FRDP_LOAD_TIMEOUT}s\"")
  expect_contains("${load_probe}" "${expected}" "E2E load probe script")
endforeach()

file(READ "${FRDP_E2E_DIR}/scripts/rdp-protocol-regression.sh" protocol_probe)
foreach(expected
        "FRDP_PROTOCOL_TIMEOUT"
        "command -v timeout"
        "command -v xvfb-run"
        "command -v nc"
        "timeout \"\${FRDP_PROTOCOL_TIMEOUT}s\"")
  expect_contains("${protocol_probe}" "${expected}" "E2E protocol regression script")
endforeach()

file(READ "${FRDP_E2E_DIR}/scripts/rdp-session-smoke.sh" session_smoke)
foreach(expected
        "FRDP_SESSION_TIMEOUT"
        "FRDP_SESSION_HOLD_SECONDS"
        "command -v Xvfb"
        "command -v xdpyinfo"
        "command -v xwd"
        "command -v ps"
        "command -v nc"
        "command -v frdpctl"
        "allocate_display"
        "xdpyinfo -display \"$display_name\""
        "frdpctl status --socket"
        "frdpctl list-sessions --socket"
        "list_status=$?"
        "awk -v id=\"$session_id\""
        "xwd -display \"$display_name\" -root"
        "managed RDP session detached after client disconnect"
        "rdp-reconnect.log"
        "session-list-reconnected.txt"
        "session-list-reconnected-held.txt"
        "session_identity_is_exclusively_active"
        "process_is_running"
        "managed RDP session reattached with stable id/display/PID"
        "session-list-after-reconnect.txt"
        "frdpctl kill-session \"$session_id\" --socket"
        "managed RDP session was cleaned after explicit kill-session")
  expect_contains("${session_smoke}" "${expected}" "E2E session smoke script")
endforeach()

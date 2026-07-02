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
        "profiles: [\"freeipa\"]")
  expect_contains("${compose}" "${expected}" "E2E compose file")
endforeach()

file(READ "${FRDP_E2E_DIR}/run.sh" runner)
foreach(expected
        "component)"
        "local)"
        "samba)"
        "freeipa)"
        "all)"
        "FRDP_E2E_ARTIFACTS"
        "compose-config.yaml"
        "container-inspect")
  expect_contains("${runner}" "${expected}" "E2E runner")
endforeach()

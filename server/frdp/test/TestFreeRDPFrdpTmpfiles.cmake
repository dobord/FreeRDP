if(NOT DEFINED SYSTEMD_TMPFILES_EXECUTABLE)
  message(FATAL_ERROR "SYSTEMD_TMPFILES_EXECUTABLE is not set")
endif()
if(NOT DEFINED FRDP_TMPFILES_CONFIG)
  message(FATAL_ERROR "FRDP_TMPFILES_CONFIG is not set")
endif()

set(test_root "${CMAKE_CURRENT_BINARY_DIR}/TestFreeRDPFrdpTmpfiles")
set(tmpfiles_dir "${test_root}/usr/lib/tmpfiles.d")
set(installed_config "${tmpfiles_dir}/frdpd.conf")

file(REMOVE_RECURSE "${test_root}")
file(MAKE_DIRECTORY "${tmpfiles_dir}")
file(COPY_FILE "${FRDP_TMPFILES_CONFIG}" "${installed_config}")

execute_process(
  COMMAND "${SYSTEMD_TMPFILES_EXECUTABLE}" --cat-config "--root=${test_root}"
  RESULT_VARIABLE result
  OUTPUT_VARIABLE stdout
  ERROR_VARIABLE stderr)

if(NOT result EQUAL 0)
  message(FATAL_ERROR "systemd-tmpfiles syntax check failed: ${stderr}\n${stdout}")
endif()

if(NOT stdout MATCHES "d /run/frdp-auth-token 0700 root root -")
  message(FATAL_ERROR "systemd-tmpfiles output did not include the expected auth-token rule:\n${stdout}")
endif()

execute_process(COMMAND id -u OUTPUT_VARIABLE uid OUTPUT_STRIP_TRAILING_WHITESPACE)
if(uid STREQUAL "0")
  execute_process(
    COMMAND "${SYSTEMD_TMPFILES_EXECUTABLE}" --create "--root=${test_root}" "${installed_config}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE stdout
    ERROR_VARIABLE stderr)

  if(NOT result EQUAL 0)
    message(FATAL_ERROR "systemd-tmpfiles create failed: ${stderr}\n${stdout}")
  endif()

  if(NOT IS_DIRECTORY "${test_root}/run/frdp-auth-token")
    message(FATAL_ERROR "systemd-tmpfiles did not create /run/frdp-auth-token")
  endif()
endif()

if(NOT DEFINED FRDP_BUILD_DIR OR NOT DEFINED FRDP_INSTALL_BINDIR OR
   NOT DEFINED FRDP_NTLM_PROVISIONING_AVAILABLE)
  message(FATAL_ERROR "FRDP install test arguments are incomplete")
endif()

set(install_root "${FRDP_BUILD_DIR}/frdp-server-install-test")
set(install_prefix "/frdp-server-install-prefix")
if(IS_ABSOLUTE "${FRDP_INSTALL_BINDIR}")
  set(installed_hash "${install_root}${FRDP_INSTALL_BINDIR}/winpr-hash")
else()
  set(installed_hash
      "${install_root}${install_prefix}/${FRDP_INSTALL_BINDIR}/winpr-hash")
endif()
file(REMOVE_RECURSE "${install_root}")
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "DESTDIR=${install_root}"
          "${CMAKE_COMMAND}" --install "${FRDP_BUILD_DIR}"
          --prefix "${install_prefix}" --component server
  RESULT_VARIABLE install_result
  OUTPUT_VARIABLE install_output
  ERROR_VARIABLE install_error)
if(NOT install_result EQUAL 0)
  message(FATAL_ERROR "server component install failed: ${install_output}${install_error}")
endif()

if(FRDP_NTLM_PROVISIONING_AVAILABLE)
  if(NOT EXISTS "${installed_hash}")
    message(FATAL_ERROR "NTLM-enabled server component omitted winpr-hash")
  endif()
elseif(EXISTS "${installed_hash}")
  message(FATAL_ERROR "NTLM-disabled server component installed winpr-hash")
endif()

file(REMOVE_RECURSE "${install_root}")

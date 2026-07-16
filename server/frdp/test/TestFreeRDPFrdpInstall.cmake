if(NOT DEFINED FRDP_BUILD_DIR OR NOT DEFINED FRDP_INSTALL_BINDIR OR
   NOT DEFINED FRDP_INSTALL_DATADIR OR
   NOT DEFINED FRDP_INSTALL_MANDIR OR
   NOT DEFINED FRDP_VERSION_FULL OR
   NOT DEFINED FRDP_NTLM_PROVISIONING_AVAILABLE)
  message(FATAL_ERROR "FRDP install test arguments are incomplete")
endif()
set(install_root "${FRDP_BUILD_DIR}/frdp-server-install-test")
set(install_prefix "/frdp-server-install-prefix")
if(IS_ABSOLUTE "${FRDP_INSTALL_DATADIR}")
  set(installed_data_root "${install_root}${FRDP_INSTALL_DATADIR}")
else()
  set(installed_data_root
      "${install_root}${install_prefix}/${FRDP_INSTALL_DATADIR}")
endif()
if(IS_ABSOLUTE "${FRDP_INSTALL_BINDIR}")
  set(installed_hash "${install_root}${FRDP_INSTALL_BINDIR}/winpr-hash")
else()
  set(installed_hash
      "${install_root}${install_prefix}/${FRDP_INSTALL_BINDIR}/winpr-hash")
endif()
if(IS_ABSOLUTE "${FRDP_INSTALL_MANDIR}")
  set(installed_man_root "${install_root}${FRDP_INSTALL_MANDIR}")
else()
  set(installed_man_root
      "${install_root}${install_prefix}/${FRDP_INSTALL_MANDIR}")
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
  if(NOT EXISTS "${installed_man_root}/man1/winpr-hash.1")
    message(FATAL_ERROR "NTLM-enabled server component omitted winpr-hash(1)")
  endif()
  file(READ "${installed_man_root}/man1/winpr-hash.1" installed_hash_manpage)
  string(FIND "${installed_hash_manpage}" "\"${FRDP_VERSION_FULL}\"" hash_version_index)
  if(hash_version_index EQUAL -1)
    message(FATAL_ERROR "installed winpr-hash(1) omitted the build version")
  endif()
elseif(EXISTS "${installed_hash}")
  message(FATAL_ERROR "NTLM-disabled server component installed winpr-hash")
elseif(EXISTS "${installed_man_root}/man1/winpr-hash.1")
  message(FATAL_ERROR "NTLM-disabled server component installed winpr-hash(1)")
endif()

foreach(manpage
        man1/frdpctl.1
        man8/frdpd.8
        man8/frdp-authd.8
        man8/frdp-sesmand.8
        man8/frdp-session-agent.8)
  if(NOT EXISTS "${installed_man_root}/${manpage}")
    message(FATAL_ERROR "server component omitted ${manpage}")
  endif()
endforeach()

if(NOT DEFINED FRDP_XORG_DUMMY_CONFIG_DIR OR FRDP_XORG_DUMMY_CONFIG_DIR STREQUAL "")
  message(FATAL_ERROR "FRDP_XORG_DUMMY_CONFIG_DIR was not provided")
endif()
if(IS_ABSOLUTE "${FRDP_XORG_DUMMY_CONFIG_DIR}")
  set(installed_xorg_config
      "${install_root}${FRDP_XORG_DUMMY_CONFIG_DIR}/xorg-dummy.conf")
else()
  set(installed_xorg_config
      "${install_root}${install_prefix}/${FRDP_XORG_DUMMY_CONFIG_DIR}/xorg-dummy.conf")
endif()
if(NOT EXISTS "${installed_xorg_config}")
  message(FATAL_ERROR "server component omitted xorg-dummy.conf")
endif()

file(REMOVE_RECURSE "${install_root}")

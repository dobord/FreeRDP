set(MODULE_NAME "TestFreeRDPFrdp")
set(MODULE_PREFIX "TEST_FREERDP_FRDP")

disable_warnings_for_directory(${CMAKE_CURRENT_BINARY_DIR})

find_program(SYSTEMD_RUN_EXECUTABLE systemd-run)
find_program(SYSTEMCTL_EXECUTABLE systemctl)

set(${MODULE_PREFIX}_DRIVER ${MODULE_NAME}.c)
set(${MODULE_PREFIX}_TESTS TestFreeRDPFrdpConfig.c TestFreeRDPFrdpIpc.c TestFreeRDPFrdpCtlIpc.c
                         TestFreeRDPFrdpAudit.c
                         TestFreeRDPFrdpHelperStop.c TestFreeRDPFrdpServiceIpc.c
                         TestFreeRDPFrdpAuthdPam.c TestFreeRDPFrdpAuthFailureLimit.c
                         TestFreeRDPFrdpNtlmIdentity.c
                         TestFreeRDPFrdpFramePolicy.c TestFreeRDPFrdpInputPolicy.c
                         TestFreeRDPFrdpDisplayControl.c TestFreeRDPFrdpClipboard.c
                         TestFreeRDPFrdpDisplayPolicy.c TestFreeRDPFrdpProcessIdentity.c
                         TestFreeRDPFrdpTrustedPath.c
                         TestFreeRDPFrdpSessionState.c
                         TestFreeRDPFrdpSessionCleanup.c TestFreeRDPFrdpSessionDisconnect.c
                         TestFreeRDPFrdpSessionLimits.c
                         TestFreeRDPFrdpSessionIdentity.c TestFreeRDPFrdpSessionReconnect.c
                         TestFreeRDPFrdpSessionMetadata.c TestFreeRDPFrdpSessionResources.c
                         TestFreeRDPFrdpSessionRecovery.c TestFreeRDPFrdpSessionPamOwner.c
                         TestFreeRDPFrdpSesmandPam.c
                         TestFreeRDPFrdpPam.c)
if(SYSTEMD_RUN_EXECUTABLE AND SYSTEMCTL_EXECUTABLE)
  list(APPEND ${MODULE_PREFIX}_TESTS TestFreeRDPFrdpSystemdRecovery.c)
endif()
find_program(XVFB_EXECUTABLE Xvfb)
find_program(FRDP_XORG_SERVER_EXECUTABLE NAMES Xorg
             HINTS /usr/lib/xorg /usr/libexec NO_DEFAULT_PATH)
find_package(pam_wrapper CONFIG QUIET)
if(XVFB_EXECUTABLE)
  list(APPEND ${MODULE_PREFIX}_TESTS TestFreeRDPFrdpAgentStop.c)
  add_executable(frdp-session-agent-test EXCLUDE_FROM_ALL ${FRDP_SESSION_AGENT_SOURCES})
  target_compile_definitions(frdp-session-agent-test PRIVATE FRDP_AGENT_TESTING)
  target_include_directories(frdp-session-agent-test SYSTEM PRIVATE
      ${X11_INCLUDE_DIR} ${X11_XTest_INCLUDE_PATH} ${X11_Xdamage_INCLUDE_PATH}
      ${X11_Xrandr_INCLUDE_PATH})
  target_link_libraries(frdp-session-agent-test PRIVATE winpr Threads::Threads
      ${X11_LIBRARIES} ${X11_XTest_LIB} ${X11_Xdamage_LIB} ${X11_Xrandr_LIB}
      ${UUID_LIBRARY})
  frdp_apply_strict_warnings(frdp-session-agent-test)
  set_property(TARGET frdp-session-agent-test PROPERTY FOLDER "Server/frdp/Test")
endif()
create_test_sourcelist(${MODULE_PREFIX}_SRCS ${${MODULE_PREFIX}_DRIVER} ${${MODULE_PREFIX}_TESTS})

add_executable(frdp-authd-test-deny EXCLUDE_FROM_ALL
    ../frdp-authd/frdp-authd.c
    ../frdp-authd/auth_failure_limit.c
    ../frdp-authd/auth_failure_limit.h
    ../frdp-authd/authd_pam.c
    ../frdp-authd/authd_pam.h
    ../config/frdp-config.c
    ../config/frdp-config.h
    $<TARGET_OBJECTS:frdp-ipc>)
target_compile_definitions(frdp-authd-test-deny PRIVATE FRDP_AUTHD_TEST_DENY_ALL)
target_include_directories(frdp-authd-test-deny SYSTEM PRIVATE ${PAM_INCLUDE_DIR})
target_link_libraries(frdp-authd-test-deny PRIVATE winpr ${PAM_LIBRARIES} ${UUID_LIBRARY})
frdp_apply_strict_warnings(frdp-authd-test-deny)
set_property(TARGET frdp-authd-test-deny PROPERTY FOLDER "Server/frdp/Test")

add_executable(frdp-session-agent-blocking EXCLUDE_FROM_ALL TestFreeRDPFrdpBlockingAgent.c)
frdp_apply_strict_warnings(frdp-session-agent-blocking)
set_property(TARGET frdp-session-agent-blocking PROPERTY FOLDER "Server/frdp/Test")

add_executable(${MODULE_NAME}
    ${${MODULE_PREFIX}_SRCS}
    ../audit/frdp-audit.c
    ../audit/frdp-audit.h
    ../config/frdp-config.c
    ../config/frdp-config.h
    ../config/trusted-path.c
    ../config/trusted-path.h
    ../ipc/frdp-auth-token.c
    ../ipc/frdp-auth-token.h
    ../ipc/frdp-ipc.c
    ../ipc/frdp-ipc.h
    ../frdpd/channel_policy.c
    ../frdpd/channel_policy.h
    ../frdpd/clipboard.c
    ../frdpd/clipboard.h
    ../frdpd/display_control.c
    ../frdpd/display_control.h
    ../frdpd/frame_policy.c
    ../frdpd/frame_policy.h
    ../frdpd/frdpd_pam.c
    ../frdpd/frdpd_pam.h
    ../frdpd/frdpd_auth.c
    ../frdpd/frdpd_auth.h
    ../frdpd/frdpd_audit.c
    ../frdpd/frdpd_audit.h
    ../frdp-authd/authd_pam.c
    ../frdp-authd/authd_pam.h
    ../frdp-authd/auth_failure_limit.c
    ../frdp-authd/auth_failure_limit.h
    ../frdp-sesmand/sesmand_pam.c
    ../frdp-sesmand/sesmand_pam.h
    ../frdp-session-agent/input_policy.c
    ../frdp-session-agent/input_policy.h
    ../frdp-sesmand/display_policy.c
    ../frdp-sesmand/display_policy.h
    ../frdp-sesmand/process_identity.c
    ../frdp-sesmand/process_identity.h
    ../frdp-sesmand/session_cleanup.c
    ../frdp-sesmand/session_cleanup.h
    ../frdp-sesmand/session_disconnect.c
    ../frdp-sesmand/session_disconnect.h
    ../frdp-sesmand/session_identity.c
    ../frdp-sesmand/session_identity.h
    ../frdp-sesmand/session_logind.c
    ../frdp-sesmand/session_logind.h
    ../frdp-sesmand/session_limits.c
    ../frdp-sesmand/session_limits.h
    ../frdp-sesmand/session_metadata.c
    ../frdp-sesmand/session_metadata.h
    ../frdp-sesmand/session_pam_owner.c
    ../frdp-sesmand/session_pam_owner.h
    ../frdp-sesmand/session_reconnect.c
    ../frdp-sesmand/session_reconnect.h
    ../frdp-sesmand/session_recovery.c
    ../frdp-sesmand/session_recovery.h
    ../frdp-sesmand/session_resources.c
    ../frdp-sesmand/session_resources.h
    ../frdp-sesmand/session_scope.c
    ../frdp-sesmand/session_scope.h
    ../frdp-sesmand/session_state.c
    ../frdp-sesmand/session_state.h)
add_dependencies(${MODULE_NAME} frdpd frdpctl frdp-authd frdp-authd-test-deny frdp-sesmand
                 frdp-session-agent frdp-session-agent-blocking)
if(TARGET frdp-session-agent-test)
  add_dependencies(${MODULE_NAME} frdp-session-agent-test)
endif()
set(FRDP_NTLM_PROVISIONING_AVAILABLE FALSE)
if(WITH_FRDPD_NTLM AND TARGET winpr-hash)
  add_dependencies(${MODULE_NAME} winpr-hash)
  set(FRDP_NTLM_PROVISIONING_AVAILABLE TRUE)
endif()

target_include_directories(${MODULE_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_include_directories(${MODULE_NAME} SYSTEM PRIVATE ${PAM_INCLUDE_DIR} ${LIBSYSTEMD_INCLUDE_DIRS})
target_link_libraries(${MODULE_NAME} PRIVATE winpr ${PAM_LIBRARIES} ${UUID_LIBRARY}
                                             ${LIBSYSTEMD_LIBRARIES})
if(HAVE_PAM_PAM_APPL_H)
  target_compile_definitions(${MODULE_NAME} PRIVATE HAVE_PAM_PAM_APPL_H)
endif()
frdp_apply_strict_warnings(${MODULE_NAME})
target_compile_definitions(${MODULE_NAME} PRIVATE CMAKE_CURRENT_BINARY_DIR="${CMAKE_CURRENT_BINARY_DIR}"
                                                   FRDP_AUDIT_TESTING
                                                   FRDP_SAMPLE_CONFIG_PATH="${FRDP_CONFIG_FILE}"
                                                   FRDPD_NTLM_ENABLED=$<BOOL:${WITH_FRDPD_NTLM}>
                                                   FRDPD_PAM_TESTING
                                                   FRDPD_BINARY="$<TARGET_FILE:frdpd>"
                                                   FRDPCTL_BINARY="$<TARGET_FILE:frdpctl>"
                                                   FRDP_AUTHD_BINARY="$<TARGET_FILE:frdp-authd>"
                                                   FRDP_AUTHD_TEST_DENY_BINARY="$<TARGET_FILE:frdp-authd-test-deny>"
                                                   FRDP_SESMAND_BINARY="$<TARGET_FILE:frdp-sesmand>"
                                                   FRDP_SESSION_AGENT_BINARY="$<TARGET_FILE:frdp-session-agent>"
                                                   FRDP_SESSION_AGENT_BLOCKING_BINARY="$<TARGET_FILE:frdp-session-agent-blocking>")
if(TARGET frdp-session-agent-test)
  target_compile_definitions(${MODULE_NAME} PRIVATE
      FRDP_SESSION_AGENT_FAULT_BINARY="$<TARGET_FILE:frdp-session-agent-test>")
endif()
if(SYSTEMD_RUN_EXECUTABLE AND SYSTEMCTL_EXECUTABLE)
  target_compile_definitions(${MODULE_NAME} PRIVATE
      FRDP_SYSTEMD_RUN_BINARY="${SYSTEMD_RUN_EXECUTABLE}"
      FRDP_SYSTEMCTL_BINARY="${SYSTEMCTL_EXECUTABLE}")
endif()
if(PAM_WRAPPER_LIBRARY AND PAM_WRAPPER_MODULE_DIR AND NOT WITH_SANITIZE_ADDRESS)
  add_library(frdp-pam-session-test MODULE EXCLUDE_FROM_ALL TestFreeRDPFrdpPamModule.c)
  add_library(frdp-pam-session-allow-test MODULE EXCLUDE_FROM_ALL TestFreeRDPFrdpPamModule.c)
  add_library(frdp-pam-session-block-test MODULE EXCLUDE_FROM_ALL TestFreeRDPFrdpPamModule.c)
  add_library(frdp-pam-session-close-block-test MODULE EXCLUDE_FROM_ALL
              TestFreeRDPFrdpPamModule.c)
  add_library(frdp-pam-auth-canonical-deny-test MODULE EXCLUDE_FROM_ALL
              TestFreeRDPFrdpPamModule.c)
  target_include_directories(frdp-pam-session-test SYSTEM PRIVATE ${PAM_INCLUDE_DIR})
  target_include_directories(frdp-pam-session-allow-test SYSTEM PRIVATE ${PAM_INCLUDE_DIR})
  target_include_directories(frdp-pam-session-block-test SYSTEM PRIVATE ${PAM_INCLUDE_DIR})
  target_include_directories(frdp-pam-session-close-block-test SYSTEM PRIVATE ${PAM_INCLUDE_DIR})
  target_include_directories(frdp-pam-auth-canonical-deny-test SYSTEM PRIVATE ${PAM_INCLUDE_DIR})
  if(HAVE_PAM_PAM_APPL_H)
    target_compile_definitions(frdp-pam-session-test PRIVATE HAVE_PAM_PAM_APPL_H)
    target_compile_definitions(frdp-pam-session-allow-test PRIVATE HAVE_PAM_PAM_APPL_H)
    target_compile_definitions(frdp-pam-session-block-test PRIVATE HAVE_PAM_PAM_APPL_H)
    target_compile_definitions(frdp-pam-session-close-block-test PRIVATE HAVE_PAM_PAM_APPL_H)
    target_compile_definitions(frdp-pam-auth-canonical-deny-test PRIVATE HAVE_PAM_PAM_APPL_H)
  endif()
  target_compile_definitions(frdp-pam-session-block-test
      PRIVATE FRDP_PAM_TEST_ALWAYS_BLOCK_SESSION)
  target_compile_definitions(frdp-pam-session-allow-test PRIVATE FRDP_PAM_TEST_ALLOW_SESSION_OPEN)
  target_compile_definitions(frdp-pam-session-close-block-test PRIVATE
      FRDP_PAM_TEST_ALLOW_SESSION_OPEN FRDP_PAM_TEST_ALWAYS_BLOCK_SESSION_CLOSE)
  target_compile_definitions(frdp-pam-auth-canonical-deny-test PRIVATE
      FRDP_PAM_TEST_CANONICAL_DENY)
  set_target_properties(frdp-pam-session-test PROPERTIES
      C_VISIBILITY_PRESET default
      PREFIX "")
  set_target_properties(frdp-pam-session-allow-test PROPERTIES
      C_VISIBILITY_PRESET default
      PREFIX "")
  set_target_properties(frdp-pam-session-block-test PROPERTIES
      C_VISIBILITY_PRESET default
      PREFIX "")
  set_target_properties(frdp-pam-session-close-block-test PROPERTIES
      C_VISIBILITY_PRESET default
      PREFIX "")
  set_target_properties(frdp-pam-auth-canonical-deny-test PROPERTIES
      C_VISIBILITY_PRESET default
      PREFIX "")
  frdp_apply_strict_warnings(frdp-pam-session-test)
  frdp_apply_strict_warnings(frdp-pam-session-allow-test)
  frdp_apply_strict_warnings(frdp-pam-session-block-test)
  frdp_apply_strict_warnings(frdp-pam-session-close-block-test)
  frdp_apply_strict_warnings(frdp-pam-auth-canonical-deny-test)
  set_property(TARGET frdp-pam-session-test PROPERTY FOLDER "Server/frdp/Test")
  set_property(TARGET frdp-pam-session-allow-test PROPERTY FOLDER "Server/frdp/Test")
  set_property(TARGET frdp-pam-session-block-test PROPERTY FOLDER "Server/frdp/Test")
  set_property(TARGET frdp-pam-session-close-block-test PROPERTY FOLDER "Server/frdp/Test")
  set_property(TARGET frdp-pam-auth-canonical-deny-test PROPERTY FOLDER "Server/frdp/Test")
  add_dependencies(${MODULE_NAME} frdp-pam-session-test frdp-pam-session-allow-test
                   frdp-pam-session-block-test
                   frdp-pam-session-close-block-test frdp-pam-auth-canonical-deny-test)
  target_compile_definitions(${MODULE_NAME} PRIVATE
      FRDP_PAM_WRAPPER_LIBRARY="${PAM_WRAPPER_LIBRARY}"
      FRDP_PAM_WRAPPER_MODULE_DIR="${PAM_WRAPPER_MODULE_DIR}"
      FRDP_PAM_SESSION_TEST_MODULE="$<TARGET_FILE:frdp-pam-session-test>"
      FRDP_PAM_SESSION_ALLOW_TEST_MODULE="$<TARGET_FILE:frdp-pam-session-allow-test>"
      FRDP_PAM_SESSION_BLOCK_TEST_MODULE="$<TARGET_FILE:frdp-pam-session-block-test>"
      FRDP_PAM_SESSION_CLOSE_BLOCK_TEST_MODULE="$<TARGET_FILE:frdp-pam-session-close-block-test>"
      FRDP_PAM_AUTH_CANONICAL_DENY_TEST_MODULE="$<TARGET_FILE:frdp-pam-auth-canonical-deny-test>")
endif()
if(SYSTEMD_RUN_EXECUTABLE AND SYSTEMCTL_EXECUTABLE AND NOT WITH_SANITIZE_ADDRESS)
  add_executable(frdp-sesmand-login1-test-runner EXCLUDE_FROM_ALL
                 TestFreeRDPFrdpSesmandLogindRunner.c)
  target_compile_definitions(frdp-sesmand-login1-test-runner PRIVATE
      FRDP_SYSTEMD_RUN_BINARY="${SYSTEMD_RUN_EXECUTABLE}"
      FRDP_TEST_BINARY="$<TARGET_FILE:${MODULE_NAME}>")
  add_dependencies(${MODULE_NAME} frdp-sesmand-login1-test-runner)
  frdp_apply_strict_warnings(frdp-sesmand-login1-test-runner)
  set_property(TARGET frdp-sesmand-login1-test-runner PROPERTY FOLDER "Server/frdp/Test")
  if(PAM_WRAPPER_LIBRARY AND PAM_WRAPPER_MODULE_DIR)
    add_test(NAME TestFreeRDPFrdpSesmandLogindLifecycle
             COMMAND frdp-sesmand-login1-test-runner login1-owner-crash)
    set_tests_properties(TestFreeRDPFrdpSesmandLogindLifecycle
                         PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 180)
  endif()
  if(XVFB_EXECUTABLE)
    add_test(NAME TestFreeRDPFrdpSesmandScopeRuntimeLimits
             COMMAND frdp-sesmand-login1-test-runner scope-runtime-limits)
    set_tests_properties(TestFreeRDPFrdpSesmandScopeRuntimeLimits
                         PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 180)
  endif()
endif()
if(XVFB_EXECUTABLE)
  target_compile_definitions(${MODULE_NAME} PRIVATE FRDP_XVFB_EXECUTABLE="${XVFB_EXECUTABLE}")
  target_include_directories(${MODULE_NAME} SYSTEM PRIVATE ${X11_INCLUDE_DIR})
  target_link_libraries(${MODULE_NAME} PRIVATE ${X11_LIBRARIES})
endif()
if(FRDP_XORG_SERVER_EXECUTABLE)
  target_compile_definitions(${MODULE_NAME} PRIVATE
      FRDP_XORG_SERVER_EXECUTABLE="${FRDP_XORG_SERVER_EXECUTABLE}"
      FRDP_XORG_DUMMY_CONFIG="${CMAKE_CURRENT_SOURCE_DIR}/../config/xorg-dummy.conf")
endif()

set_target_properties(${MODULE_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${TESTING_OUTPUT_DIRECTORY}")

foreach(test ${${MODULE_PREFIX}_TESTS})
  get_filename_component(TestName ${test} NAME_WE)
  add_test(${TestName} ${TESTING_OUTPUT_DIRECTORY}/${MODULE_NAME} ${TestName})
endforeach()
if(SYSTEMD_RUN_EXECUTABLE AND SYSTEMCTL_EXECUTABLE)
  set_tests_properties(TestFreeRDPFrdpSystemdRecovery
                       PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 180)
endif()

add_test(NAME TestFreeRDPFrdpCtl
         COMMAND ${CMAKE_COMMAND} -DFRDPCTL_BINARY=$<TARGET_FILE:frdpctl>
                 -P ${CMAKE_CURRENT_SOURCE_DIR}/TestFreeRDPFrdpCtl.cmake)

add_test(NAME TestFreeRDPFrdpAuthd
         COMMAND ${CMAKE_COMMAND} -DFRDP_AUTHD_BINARY=$<TARGET_FILE:frdp-authd>
                 -P ${CMAKE_CURRENT_SOURCE_DIR}/TestFreeRDPFrdpAuthd.cmake)

add_test(NAME TestFreeRDPFrdpSesmand
         COMMAND ${CMAKE_COMMAND} -DFRDP_SESMAND_BINARY=$<TARGET_FILE:frdp-sesmand>
                 -P ${CMAKE_CURRENT_SOURCE_DIR}/TestFreeRDPFrdpSesmand.cmake)

add_test(NAME TestFreeRDPFrdpd
         COMMAND ${CMAKE_COMMAND} -DFRDPD_BINARY=$<TARGET_FILE:frdpd>
                 -DFRDPD_NTLM_ENABLED=$<BOOL:${WITH_FRDPD_NTLM}>
                 "-DFRDP_SAMPLE_CONFIG_PATH=${FRDP_CONFIG_FILE}"
                 -P ${CMAKE_CURRENT_SOURCE_DIR}/TestFreeRDPFrdpd.cmake)

add_test(NAME TestFreeRDPFrdpInstall
         COMMAND ${CMAKE_COMMAND}
                 -DFRDP_BUILD_DIR=${CMAKE_BINARY_DIR}
                 -DFRDP_INSTALL_BINDIR=${CMAKE_INSTALL_BINDIR}
                 -DFRDP_INSTALL_MANDIR=${CMAKE_INSTALL_MANDIR}
                 -DFRDP_INSTALL_DATADIR=${CMAKE_INSTALL_DATADIR}
                 -DFRDP_XORG_DUMMY_CONFIG_DIR=${FRDP_XORG_DUMMY_CONFIG_DIR}
                 -DFRDP_VERSION_FULL=${FREERDP_VERSION_FULL}
                 -DFRDP_NTLM_PROVISIONING_AVAILABLE=${FRDP_NTLM_PROVISIONING_AVAILABLE}
                 -P ${CMAKE_CURRENT_SOURCE_DIR}/TestFreeRDPFrdpInstall.cmake)

add_test(NAME TestFreeRDPFrdpIpcDemo
         COMMAND ${CMAKE_COMMAND} -DFRDPD_IPC_DEMO_BINARY=$<TARGET_FILE:frdpd-ipc-demo>
                 -P ${CMAKE_CURRENT_SOURCE_DIR}/TestFreeRDPFrdpIpcDemo.cmake)

if(TARGET frdp-krb-authd)
  add_test(NAME TestFreeRDPFrdpKrbAuthd
           COMMAND ${CMAKE_COMMAND} -DFRDP_KRB_AUTHD_BINARY=$<TARGET_FILE:frdp-krb-authd>
                   -P ${CMAKE_CURRENT_SOURCE_DIR}/TestFreeRDPFrdpKrbAuthd.cmake)
endif()

find_program(SYSTEMD_ANALYZE_EXECUTABLE systemd-analyze)
if(SYSTEMD_ANALYZE_EXECUTABLE)
  add_test(NAME TestFreeRDPFrdpSystemd
           COMMAND ${CMAKE_COMMAND}
                   -DSYSTEMD_ANALYZE_EXECUTABLE=${SYSTEMD_ANALYZE_EXECUTABLE}
                   -DFRDP_SYSTEMD_UNIT_DIR=${CMAKE_CURRENT_BINARY_DIR}/..
                   -DFRDP_MAN_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/../man
                   -DFRDP_INSTALL_FULL_BINDIR=${CMAKE_INSTALL_FULL_BINDIR}
                   -DFRDP_INSTALL_FULL_SYSCONFDIR=${CMAKE_INSTALL_FULL_SYSCONFDIR}
                   -P ${CMAKE_CURRENT_SOURCE_DIR}/TestFreeRDPFrdpSystemd.cmake)
endif()

find_program(APPARMOR_PARSER_EXECUTABLE apparmor_parser)
if(APPARMOR_PARSER_EXECUTABLE)
  add_test(NAME TestFreeRDPFrdpAppArmor
           COMMAND ${CMAKE_COMMAND}
                   -DAPPARMOR_PARSER_EXECUTABLE=${APPARMOR_PARSER_EXECUTABLE}
                   -DFRDP_APPARMOR_PROFILE=${CMAKE_SOURCE_DIR}/packaging/apparmor/frdpd
                   -P ${CMAKE_CURRENT_SOURCE_DIR}/TestFreeRDPFrdpAppArmor.cmake)
endif()

find_program(CHECKMODULE_EXECUTABLE checkmodule)
find_program(SEMODULE_PACKAGE_EXECUTABLE semodule_package)
if(CHECKMODULE_EXECUTABLE AND SEMODULE_PACKAGE_EXECUTABLE)
  add_test(NAME TestFreeRDPFrdpSELinux
           COMMAND ${CMAKE_COMMAND}
                   -DCHECKMODULE_EXECUTABLE=${CHECKMODULE_EXECUTABLE}
                   -DSEMODULE_PACKAGE_EXECUTABLE=${SEMODULE_PACKAGE_EXECUTABLE}
                   -DFRDP_SELINUX_POLICY=${CMAKE_SOURCE_DIR}/packaging/selinux/frdpd.te
                   -DFRDP_SELINUX_FILE_CONTEXTS=${CMAKE_SOURCE_DIR}/packaging/selinux/frdpd.fc
                   -DFRDP_SELINUX_WORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/selinux-policy-test
                   -P ${CMAKE_CURRENT_SOURCE_DIR}/TestFreeRDPFrdpSELinux.cmake)
endif()

find_program(SYSTEMD_TMPFILES_EXECUTABLE systemd-tmpfiles)
if(SYSTEMD_TMPFILES_EXECUTABLE)
  add_test(NAME TestFreeRDPFrdpTmpfiles
           COMMAND ${CMAKE_COMMAND}
                   -DSYSTEMD_TMPFILES_EXECUTABLE=${SYSTEMD_TMPFILES_EXECUTABLE}
                   -DFRDP_TMPFILES_CONFIG=${CMAKE_SOURCE_DIR}/packaging/tmpfiles/frdpd.conf
                   -P ${CMAKE_CURRENT_SOURCE_DIR}/TestFreeRDPFrdpTmpfiles.cmake)
endif()

find_program(BASH_EXECUTABLE bash)
if(BASH_EXECUTABLE)
  add_test(NAME TestFreeRDPFrdpMonitoring
           COMMAND ${CMAKE_COMMAND}
                   -DBASH_EXECUTABLE=${BASH_EXECUTABLE}
                   -DFRDP_MONITORING_SCRIPT=${CMAKE_SOURCE_DIR}/packaging/monitoring/frdpd-node-exporter-textfile.sh
                   -DFRDP_PROMETHEUS_ALERTS=${CMAKE_SOURCE_DIR}/packaging/monitoring/frdpd-prometheus-alerts.yml
                   -DFRDP_GRAFANA_DASHBOARD=${CMAKE_SOURCE_DIR}/packaging/monitoring/frdpd-grafana-dashboard.json
                   -P ${CMAKE_CURRENT_SOURCE_DIR}/TestFreeRDPFrdpMonitoring.cmake)
  add_test(NAME TestFreeRDPFrdpE2EScripts
           COMMAND ${CMAKE_COMMAND}
                   -DBASH_EXECUTABLE=${BASH_EXECUTABLE}
                   -DFRDP_E2E_DIR=${CMAKE_CURRENT_SOURCE_DIR}/e2e
                   -P ${CMAKE_CURRENT_SOURCE_DIR}/TestFreeRDPFrdpE2EScripts.cmake)
endif()

set_property(TARGET ${MODULE_NAME} PROPERTY FOLDER "FreeRDP/Test")

if(BUILD_FUZZERS)
  set(FRDP_CONFIG_FUZZER TestFuzzFreeRDPFrdpConfig)
  add_executable(${FRDP_CONFIG_FUZZER}
      TestFuzzFreeRDPFrdpConfig.c
      ../config/frdp-config.c
      ../config/frdp-config.h
      ../frdpd/channel_policy.c
      ../frdpd/channel_policy.h)
  target_include_directories(${FRDP_CONFIG_FUZZER} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
  target_link_libraries(${FRDP_CONFIG_FUZZER} PUBLIC fuzzer_config winpr)
  set_target_properties(${FRDP_CONFIG_FUZZER}
      PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${TESTING_OUTPUT_DIRECTORY}"
                 FOLDER "FreeRDP/Test/Fuzzers")
  add_dependencies(fuzzers ${FRDP_CONFIG_FUZZER})

  set(FRDP_AUTH_TOKEN_FUZZER TestFuzzFreeRDPFrdpAuthToken)
  add_executable(${FRDP_AUTH_TOKEN_FUZZER}
      TestFuzzFreeRDPFrdpAuthToken.c
      ../ipc/frdp-auth-token.c
      ../ipc/frdp-auth-token.h)
  target_include_directories(${FRDP_AUTH_TOKEN_FUZZER} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
  target_link_libraries(${FRDP_AUTH_TOKEN_FUZZER} PUBLIC fuzzer_config winpr ${UUID_LIBRARY})
  set_target_properties(${FRDP_AUTH_TOKEN_FUZZER}
      PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${TESTING_OUTPUT_DIRECTORY}"
                 FOLDER "FreeRDP/Test/Fuzzers")
  add_dependencies(fuzzers ${FRDP_AUTH_TOKEN_FUZZER})

  set(FRDP_AUTHD_PAM_FUZZER TestFuzzFreeRDPFrdpAuthdPam)
  add_executable(${FRDP_AUTHD_PAM_FUZZER}
      TestFuzzFreeRDPFrdpAuthdPam.c
      ../frdp-authd/authd_pam.c
      ../frdp-authd/authd_pam.h)
  target_include_directories(${FRDP_AUTHD_PAM_FUZZER} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
  target_include_directories(${FRDP_AUTHD_PAM_FUZZER} SYSTEM PRIVATE ${PAM_INCLUDE_DIR})
  target_link_libraries(${FRDP_AUTHD_PAM_FUZZER} PUBLIC fuzzer_config winpr ${PAM_LIBRARIES})
  set_target_properties(${FRDP_AUTHD_PAM_FUZZER}
      PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${TESTING_OUTPUT_DIRECTORY}"
                 FOLDER "FreeRDP/Test/Fuzzers")
  add_dependencies(fuzzers ${FRDP_AUTHD_PAM_FUZZER})

  set(FRDPD_PAM_FUZZER TestFuzzFreeRDPFrdpPam)
  add_executable(${FRDPD_PAM_FUZZER}
      TestFuzzFreeRDPFrdpPam.c
      ../frdpd/frdpd_pam.c
      ../frdpd/frdpd_pam.h)
  target_include_directories(${FRDPD_PAM_FUZZER} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
  target_include_directories(${FRDPD_PAM_FUZZER} SYSTEM PRIVATE ${PAM_INCLUDE_DIR})
  target_link_libraries(${FRDPD_PAM_FUZZER} PUBLIC fuzzer_config winpr ${PAM_LIBRARIES})
  if(HAVE_PAM_PAM_APPL_H)
    target_compile_definitions(${FRDPD_PAM_FUZZER} PRIVATE HAVE_PAM_PAM_APPL_H)
  endif()
  set_target_properties(${FRDPD_PAM_FUZZER}
      PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${TESTING_OUTPUT_DIRECTORY}"
                 FOLDER "FreeRDP/Test/Fuzzers")
  add_dependencies(fuzzers ${FRDPD_PAM_FUZZER})

  set(FRDP_NTLM_IDENTITY_FUZZER TestFuzzFreeRDPFrdpNtlmIdentity)
  add_executable(${FRDP_NTLM_IDENTITY_FUZZER}
      TestFuzzFreeRDPFrdpNtlmIdentity.c
      ../frdpd/frdpd_auth.c
      ../frdpd/frdpd_auth.h
      ../frdpd/frdpd_pam.c
      ../frdpd/frdpd_pam.h
      ../ipc/frdp-ipc.c
      ../ipc/frdp-ipc.h)
  target_include_directories(${FRDP_NTLM_IDENTITY_FUZZER}
      PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
  target_include_directories(${FRDP_NTLM_IDENTITY_FUZZER} SYSTEM PRIVATE ${PAM_INCLUDE_DIR})
  target_link_libraries(${FRDP_NTLM_IDENTITY_FUZZER}
      PUBLIC fuzzer_config winpr ${PAM_LIBRARIES})
  if(HAVE_PAM_PAM_APPL_H)
    target_compile_definitions(${FRDP_NTLM_IDENTITY_FUZZER} PRIVATE HAVE_PAM_PAM_APPL_H)
  endif()
  get_target_property(FRDP_NTLM_IDENTITY_COMPILE_OPTIONS
      ${FRDP_NTLM_IDENTITY_FUZZER} COMPILE_OPTIONS)
  if(FRDP_NTLM_IDENTITY_COMPILE_OPTIONS)
    list(REMOVE_ITEM FRDP_NTLM_IDENTITY_COMPILE_OPTIONS ${COMPILE_WARN_OPTS})
    set_property(TARGET ${FRDP_NTLM_IDENTITY_FUZZER}
        PROPERTY COMPILE_OPTIONS ${FRDP_NTLM_IDENTITY_COMPILE_OPTIONS})
  endif()
  frdp_apply_strict_warnings(${FRDP_NTLM_IDENTITY_FUZZER})
  set_target_properties(${FRDP_NTLM_IDENTITY_FUZZER}
      PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${TESTING_OUTPUT_DIRECTORY}"
                 FOLDER "FreeRDP/Test/Fuzzers")
  add_dependencies(fuzzers ${FRDP_NTLM_IDENTITY_FUZZER})

  set(FRDP_IPC_CODEC_FUZZER TestFuzzFreeRDPFrdpIpcCodec)
  add_executable(${FRDP_IPC_CODEC_FUZZER}
      TestFuzzFreeRDPFrdpIpcCodec.c
      ../ipc/frdp-ipc.c
      ../ipc/frdp-ipc.h)
  target_include_directories(${FRDP_IPC_CODEC_FUZZER} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
  target_link_libraries(${FRDP_IPC_CODEC_FUZZER} PUBLIC fuzzer_config winpr)
  set_target_properties(${FRDP_IPC_CODEC_FUZZER}
      PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${TESTING_OUTPUT_DIRECTORY}"
                 FOLDER "FreeRDP/Test/Fuzzers")
  add_dependencies(fuzzers ${FRDP_IPC_CODEC_FUZZER})

  set(FRDP_CLIPBOARD_FUZZER TestFuzzFreeRDPFrdpClipboard)
  add_executable(${FRDP_CLIPBOARD_FUZZER}
      TestFuzzFreeRDPFrdpClipboard.c
      ../frdpd/clipboard.c
      ../frdpd/clipboard.h)
  target_include_directories(${FRDP_CLIPBOARD_FUZZER} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
  target_link_libraries(${FRDP_CLIPBOARD_FUZZER} PUBLIC fuzzer_config winpr)
  set_target_properties(${FRDP_CLIPBOARD_FUZZER}
      PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${TESTING_OUTPUT_DIRECTORY}"
                 FOLDER "FreeRDP/Test/Fuzzers")
  add_dependencies(fuzzers ${FRDP_CLIPBOARD_FUZZER})

  set(FRDP_FRAME_POLICY_FUZZER TestFuzzFreeRDPFrdpFramePolicy)
  add_executable(${FRDP_FRAME_POLICY_FUZZER}
      TestFuzzFreeRDPFrdpFramePolicy.c
      ../frdpd/frame_policy.c
      ../frdpd/frame_policy.h)
  target_include_directories(${FRDP_FRAME_POLICY_FUZZER} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
  target_link_libraries(${FRDP_FRAME_POLICY_FUZZER} PUBLIC fuzzer_config winpr)
  set_target_properties(${FRDP_FRAME_POLICY_FUZZER}
      PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${TESTING_OUTPUT_DIRECTORY}"
                 FOLDER "FreeRDP/Test/Fuzzers")
  add_dependencies(fuzzers ${FRDP_FRAME_POLICY_FUZZER})

  set(FRDP_INPUT_POLICY_FUZZER TestFuzzFreeRDPFrdpInputPolicy)
  add_executable(${FRDP_INPUT_POLICY_FUZZER}
      TestFuzzFreeRDPFrdpInputPolicy.c
      ../frdp-session-agent/input_policy.c
      ../frdp-session-agent/input_policy.h)
  target_include_directories(${FRDP_INPUT_POLICY_FUZZER} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
  target_link_libraries(${FRDP_INPUT_POLICY_FUZZER} PUBLIC fuzzer_config winpr)
  set_target_properties(${FRDP_INPUT_POLICY_FUZZER}
      PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${TESTING_OUTPUT_DIRECTORY}"
                 FOLDER "FreeRDP/Test/Fuzzers")
  add_dependencies(fuzzers ${FRDP_INPUT_POLICY_FUZZER})

  set(FRDP_DISPLAY_POLICY_FUZZER TestFuzzFreeRDPFrdpDisplayPolicy)
  add_executable(${FRDP_DISPLAY_POLICY_FUZZER}
      TestFuzzFreeRDPFrdpDisplayPolicy.c
      ../frdp-sesmand/display_policy.c
      ../frdp-sesmand/display_policy.h
      ../frdp-sesmand/process_identity.c
      ../frdp-sesmand/process_identity.h)
  target_include_directories(${FRDP_DISPLAY_POLICY_FUZZER} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
  target_link_libraries(${FRDP_DISPLAY_POLICY_FUZZER} PUBLIC fuzzer_config winpr)
  set_target_properties(${FRDP_DISPLAY_POLICY_FUZZER}
      PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${TESTING_OUTPUT_DIRECTORY}"
                 FOLDER "FreeRDP/Test/Fuzzers")
  add_dependencies(fuzzers ${FRDP_DISPLAY_POLICY_FUZZER})

  set(FRDP_SESSION_LIFECYCLE_FUZZER TestFuzzFreeRDPFrdpSessionLifecycle)
  add_executable(${FRDP_SESSION_LIFECYCLE_FUZZER}
      TestFuzzFreeRDPFrdpSessionLifecycle.c
      ../frdp-sesmand/session_cleanup.c
      ../frdp-sesmand/session_cleanup.h
      ../frdp-sesmand/session_disconnect.c
      ../frdp-sesmand/session_disconnect.h
      ../frdp-sesmand/session_reconnect.c
      ../frdp-sesmand/session_reconnect.h
      ../frdp-sesmand/session_resources.c
      ../frdp-sesmand/session_resources.h
      ../frdp-sesmand/session_state.c
      ../frdp-sesmand/session_state.h)
  target_include_directories(${FRDP_SESSION_LIFECYCLE_FUZZER} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
  target_link_libraries(${FRDP_SESSION_LIFECYCLE_FUZZER} PUBLIC fuzzer_config winpr)
  set_target_properties(${FRDP_SESSION_LIFECYCLE_FUZZER}
      PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${TESTING_OUTPUT_DIRECTORY}"
                 FOLDER "FreeRDP/Test/Fuzzers")
  add_dependencies(fuzzers ${FRDP_SESSION_LIFECYCLE_FUZZER})
endif()

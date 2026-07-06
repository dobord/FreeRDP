set(MODULE_NAME "TestFreeRDPFrdp")
set(MODULE_PREFIX "TEST_FREERDP_FRDP")

disable_warnings_for_directory(${CMAKE_CURRENT_BINARY_DIR})

set(${MODULE_PREFIX}_DRIVER ${MODULE_NAME}.c)
set(${MODULE_PREFIX}_TESTS TestFreeRDPFrdpConfig.c TestFreeRDPFrdpIpc.c TestFreeRDPFrdpCtlIpc.c
                         TestFreeRDPFrdpHelperStop.c TestFreeRDPFrdpServiceIpc.c
                         TestFreeRDPFrdpAuthdPam.c
                         TestFreeRDPFrdpFramePolicy.c TestFreeRDPFrdpInputPolicy.c
                         TestFreeRDPFrdpDisplayPolicy.c TestFreeRDPFrdpSessionState.c
                         TestFreeRDPFrdpSessionCleanup.c TestFreeRDPFrdpSessionReconnect.c
                         TestFreeRDPFrdpPam.c)
find_program(XVFB_EXECUTABLE Xvfb)
if(XVFB_EXECUTABLE)
  list(APPEND ${MODULE_PREFIX}_TESTS TestFreeRDPFrdpAgentStop.c)
endif()

create_test_sourcelist(${MODULE_PREFIX}_SRCS ${${MODULE_PREFIX}_DRIVER} ${${MODULE_PREFIX}_TESTS})

add_executable(${MODULE_NAME}
    ${${MODULE_PREFIX}_SRCS}
    ../config/frdp-config.c
    ../config/frdp-config.h
    ../ipc/frdp-auth-token.c
    ../ipc/frdp-auth-token.h
    ../ipc/frdp-ipc.c
    ../ipc/frdp-ipc.h
    ../frdpd/channel_policy.c
    ../frdpd/channel_policy.h
    ../frdpd/frame_policy.c
    ../frdpd/frame_policy.h
    ../frdpd/frdpd_pam.c
    ../frdpd/frdpd_pam.h
    ../frdp-authd/authd_pam.c
    ../frdp-authd/authd_pam.h
    ../frdp-session-agent/input_policy.c
    ../frdp-session-agent/input_policy.h
    ../frdp-sesmand/display_policy.c
    ../frdp-sesmand/display_policy.h
    ../frdp-sesmand/session_cleanup.c
    ../frdp-sesmand/session_cleanup.h
    ../frdp-sesmand/session_reconnect.c
    ../frdp-sesmand/session_reconnect.h
    ../frdp-sesmand/session_state.c
    ../frdp-sesmand/session_state.h)
add_dependencies(${MODULE_NAME} frdpd frdpctl frdp-authd frdp-sesmand frdp-session-agent)

target_include_directories(${MODULE_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_include_directories(${MODULE_NAME} SYSTEM PRIVATE ${PAM_INCLUDE_DIR})
target_link_libraries(${MODULE_NAME} PRIVATE winpr ${PAM_LIBRARIES} ${UUID_LIBRARY})
if(HAVE_PAM_PAM_APPL_H)
  target_compile_definitions(${MODULE_NAME} PRIVATE HAVE_PAM_PAM_APPL_H)
endif()
frdp_apply_strict_warnings(${MODULE_NAME})
target_compile_definitions(${MODULE_NAME} PRIVATE CMAKE_CURRENT_BINARY_DIR="${CMAKE_CURRENT_BINARY_DIR}"
                                                   FRDP_SAMPLE_CONFIG_PATH="${CMAKE_CURRENT_SOURCE_DIR}/../config/frdpd.toml"
                                                   FRDPD_PAM_TESTING
                                                   FRDPD_BINARY="$<TARGET_FILE:frdpd>"
                                                   FRDPCTL_BINARY="$<TARGET_FILE:frdpctl>"
                                                   FRDP_AUTHD_BINARY="$<TARGET_FILE:frdp-authd>"
                                                   FRDP_SESMAND_BINARY="$<TARGET_FILE:frdp-sesmand>"
                                                   FRDP_SESSION_AGENT_BINARY="$<TARGET_FILE:frdp-session-agent>")

set_target_properties(${MODULE_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${TESTING_OUTPUT_DIRECTORY}")

foreach(test ${${MODULE_PREFIX}_TESTS})
  get_filename_component(TestName ${test} NAME_WE)
  add_test(${TestName} ${TESTING_OUTPUT_DIRECTORY}/${MODULE_NAME} ${TestName})
endforeach()

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
                 -DFRDP_SAMPLE_CONFIG_PATH=${CMAKE_CURRENT_SOURCE_DIR}/../config/frdpd.toml
                 -P ${CMAKE_CURRENT_SOURCE_DIR}/TestFreeRDPFrdpd.cmake)

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
                   -DFRDP_INSTALL_FULL_BINDIR=${CMAKE_INSTALL_FULL_BINDIR}
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
      ../frdp-sesmand/display_policy.h)
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
      ../frdp-sesmand/session_reconnect.c
      ../frdp-sesmand/session_reconnect.h
      ../frdp-sesmand/session_state.c
      ../frdp-sesmand/session_state.h)
  target_include_directories(${FRDP_SESSION_LIFECYCLE_FUZZER} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
  target_link_libraries(${FRDP_SESSION_LIFECYCLE_FUZZER} PUBLIC fuzzer_config winpr)
  set_target_properties(${FRDP_SESSION_LIFECYCLE_FUZZER}
      PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${TESTING_OUTPUT_DIRECTORY}"
                 FOLDER "FreeRDP/Test/Fuzzers")
  add_dependencies(fuzzers ${FRDP_SESSION_LIFECYCLE_FUZZER})
endif()

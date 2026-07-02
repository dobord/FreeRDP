set(MODULE_NAME "TestFreeRDPFrdp")
set(MODULE_PREFIX "TEST_FREERDP_FRDP")

disable_warnings_for_directory(${CMAKE_CURRENT_BINARY_DIR})

set(${MODULE_PREFIX}_DRIVER ${MODULE_NAME}.c)
set(${MODULE_PREFIX}_TESTS TestFreeRDPFrdpConfig.c TestFreeRDPFrdpIpc.c TestFreeRDPFrdpCtlIpc.c
                         TestFreeRDPFrdpHelperStop.c TestFreeRDPFrdpServiceIpc.c)
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
    ../frdpd/channel_policy.h)
add_dependencies(${MODULE_NAME} frdpd frdpctl frdp-authd frdp-sesmand frdp-session-agent)

target_include_directories(${MODULE_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(${MODULE_NAME} PRIVATE winpr ${UUID_LIBRARY})
frdp_apply_strict_warnings(${MODULE_NAME})
target_compile_definitions(${MODULE_NAME} PRIVATE CMAKE_CURRENT_BINARY_DIR="${CMAKE_CURRENT_BINARY_DIR}"
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
                 -DFRDPD_IN_PROCESS_PAM=$<BOOL:${WITH_FRDPD_IN_PROCESS_PAM}>
                 -P ${CMAKE_CURRENT_SOURCE_DIR}/TestFreeRDPFrdpd.cmake)

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
endif()

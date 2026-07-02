# FreeRDP: A Remote Desktop Protocol Implementation
# Experimental FreeRDP PAM/SSSD RDP server components

find_package(PAM REQUIRED)
find_package(X11 REQUIRED)

if(NOT X11_XTest_FOUND)
  message(FATAL_ERROR "XTest is required for frdp-session-agent input injection")
endif()
if(NOT X11_Xdamage_FOUND)
  message(FATAL_ERROR "XDamage is required for frdp-session-agent dirty framebuffer tracking")
endif()
if(NOT X11_Xrandr_FOUND)
  message(FATAL_ERROR "XRandR is required for frdp-session-agent display resize")
endif()

find_library(UUID_LIBRARY NAMES uuid)
if(NOT UUID_LIBRARY)
  message(FATAL_ERROR "libuuid is required for WITH_FRDPD helper components")
endif()

option(WITH_FRDPD_IN_PROCESS_PAM "Enable insecure legacy in-process frdpd PAM fallback for local development" OFF)
option(WITH_FRDPD_STRICT_WARNINGS "Build FRDP daemon targets with strict compiler warnings as errors" OFF)

function(frdp_apply_strict_warnings target)
  if(NOT WITH_FRDPD_STRICT_WARNINGS)
    return()
  endif()
  if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(${target} PRIVATE
      -Wall
      -Wextra
      -Wpedantic
      -Wconversion
      -Wsign-conversion
      -Wcast-qual
      -Wmissing-prototypes
      -Wstrict-prototypes
      -Werror
      -Wno-deprecated-declarations)
  endif()
endfunction()

add_subdirectory(frdpd)

add_library(frdp-ipc OBJECT
    ipc/frdp-auth-token.c
    ipc/frdp-auth-token.h
    ipc/frdp-ipc.c
    ipc/frdp-ipc.h)
frdp_apply_strict_warnings(frdp-ipc)
set_property(TARGET frdp-ipc PROPERTY FOLDER "Server/frdp")

add_executable(frdp-authd
    frdp-authd/frdp-authd.c
    config/frdp-config.c
    config/frdp-config.h
    $<TARGET_OBJECTS:frdp-ipc>)
target_include_directories(frdp-authd SYSTEM PRIVATE ${PAM_INCLUDE_DIR})
target_link_libraries(frdp-authd PRIVATE winpr ${PAM_LIBRARIES} ${UUID_LIBRARY})
frdp_apply_strict_warnings(frdp-authd)
installwithrpath(TARGETS frdp-authd DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT server)
set_property(TARGET frdp-authd PROPERTY FOLDER "Server/frdp")

add_executable(frdp-sesmand
    frdp-sesmand/frdp-sesmand.c
    frdp-sesmand/display_policy.c
    frdp-sesmand/display_policy.h
    frdp-sesmand/session_cleanup.c
    frdp-sesmand/session_cleanup.h
    frdp-sesmand/session_reconnect.c
    frdp-sesmand/session_reconnect.h
    frdp-sesmand/session_state.c
    frdp-sesmand/session_state.h
    config/frdp-config.c
    config/frdp-config.h
    $<TARGET_OBJECTS:frdp-ipc>)
target_include_directories(frdp-sesmand SYSTEM PRIVATE ${PAM_INCLUDE_DIR})
target_link_libraries(frdp-sesmand PRIVATE winpr ${PAM_LIBRARIES} ${UUID_LIBRARY})
frdp_apply_strict_warnings(frdp-sesmand)
installwithrpath(TARGETS frdp-sesmand DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT server)
set_property(TARGET frdp-sesmand PROPERTY FOLDER "Server/frdp")

add_executable(frdp-session-agent
    frdp-session-agent/input_policy.c
    frdp-session-agent/input_policy.h
    frdp-session-agent/frdp-session-agent.c
    $<TARGET_OBJECTS:frdp-ipc>)
target_include_directories(frdp-session-agent SYSTEM PRIVATE ${X11_INCLUDE_DIR} ${X11_XTest_INCLUDE_PATH} ${X11_Xdamage_INCLUDE_PATH} ${X11_Xrandr_INCLUDE_PATH})
target_link_libraries(frdp-session-agent PRIVATE winpr ${X11_LIBRARIES} ${X11_XTest_LIB} ${X11_Xdamage_LIB} ${X11_Xrandr_LIB} ${UUID_LIBRARY})
frdp_apply_strict_warnings(frdp-session-agent)
installwithrpath(TARGETS frdp-session-agent DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT server)
set_property(TARGET frdp-session-agent PROPERTY FOLDER "Server/frdp")

add_executable(frdpd-ipc-demo
    frdpd/frdpd-ipc-demo.c
    config/frdp-config.c
    config/frdp-config.h
    $<TARGET_OBJECTS:frdp-ipc>)
target_link_libraries(frdpd-ipc-demo PRIVATE winpr ${UUID_LIBRARY})
frdp_apply_strict_warnings(frdpd-ipc-demo)
set_property(TARGET frdpd-ipc-demo PROPERTY FOLDER "Server/frdp")

add_executable(frdpctl
    ${CMAKE_SOURCE_DIR}/tools/frdpctl/frdpctl.c
    $<TARGET_OBJECTS:frdp-ipc>)
target_include_directories(frdpctl PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(frdpctl PRIVATE winpr ${UUID_LIBRARY})
frdp_apply_strict_warnings(frdpctl)
installwithrpath(TARGETS frdpctl DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT server)
set_property(TARGET frdpctl PROPERTY FOLDER "Server/frdp")

find_library(GSSAPI_LIBRARY NAMES gssapi_krb5 gssapi)
if(GSSAPI_LIBRARY)
  add_executable(frdp-krb-authd frdp-krb-authd/frdp-krb-authd.c)
  target_link_libraries(frdp-krb-authd PRIVATE ${GSSAPI_LIBRARY})
  frdp_apply_strict_warnings(frdp-krb-authd)
  set_property(TARGET frdp-krb-authd PROPERTY FOLDER "Server/frdp")
else()
  message(WARNING "GSSAPI library not found; frdp-krb-authd target will not be built")
endif()

set(FRDP_SYSTEMD_SYSTEM_UNIT_DIR "lib/systemd/system" CACHE PATH "systemd system unit install directory")
set(FRDP_TMPFILES_DIR "lib/tmpfiles.d" CACHE PATH "systemd tmpfiles install directory")
set(FRDP_SECURITY_POLICY_DIR "${CMAKE_INSTALL_DATADIR}/frdpd/security" CACHE PATH "FRDP security policy example install directory")
set(FRDP_MONITORING_DIR "${CMAKE_INSTALL_DATADIR}/frdpd/monitoring" CACHE PATH "FRDP monitoring example install directory")
set(FRDP_SYSTEMD_UNITS
    frdpd.service
    frdp-authd.service
    frdp-sesmand.service)
set(FRDP_SYSTEMD_UNIT_FILES)
foreach(FRDP_SYSTEMD_UNIT IN LISTS FRDP_SYSTEMD_UNITS)
  configure_file(${CMAKE_SOURCE_DIR}/packaging/systemd/${FRDP_SYSTEMD_UNIT}.in
                 ${CMAKE_CURRENT_BINARY_DIR}/${FRDP_SYSTEMD_UNIT}
                 @ONLY)
  list(APPEND FRDP_SYSTEMD_UNIT_FILES ${CMAKE_CURRENT_BINARY_DIR}/${FRDP_SYSTEMD_UNIT})
endforeach()

install(FILES config/frdpd.toml DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/frdpd COMPONENT server)
install(FILES config/frdpd.env DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/frdpd COMPONENT server)
install(FILES pam/frdpd DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/pam.d COMPONENT server)
install(FILES ${FRDP_SYSTEMD_UNIT_FILES}
        DESTINATION ${FRDP_SYSTEMD_SYSTEM_UNIT_DIR}
        COMPONENT server)
install(FILES ${CMAKE_SOURCE_DIR}/packaging/tmpfiles/frdpd.conf
        DESTINATION ${FRDP_TMPFILES_DIR}
        COMPONENT server)
install(FILES
        ${CMAKE_SOURCE_DIR}/packaging/selinux/frdpd.te
        ${CMAKE_SOURCE_DIR}/packaging/selinux/frdpd.fc
        DESTINATION ${FRDP_SECURITY_POLICY_DIR}/selinux
        COMPONENT server)
install(FILES ${CMAKE_SOURCE_DIR}/packaging/apparmor/frdpd
        DESTINATION ${FRDP_SECURITY_POLICY_DIR}/apparmor
        COMPONENT server)
install(PROGRAMS ${CMAKE_SOURCE_DIR}/packaging/monitoring/frdpd-node-exporter-textfile.sh
        DESTINATION ${FRDP_MONITORING_DIR}
        COMPONENT server)
install(FILES ${CMAKE_SOURCE_DIR}/packaging/monitoring/frdpd-prometheus-alerts.yml
        DESTINATION ${FRDP_MONITORING_DIR}
        COMPONENT server)

if(BUILD_TESTING_INTERNAL OR BUILD_TESTING)
  add_subdirectory(test)
endif()

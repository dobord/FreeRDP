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

find_library(UUID_LIBRARY NAMES uuid)
if(NOT UUID_LIBRARY)
  message(FATAL_ERROR "libuuid is required for WITH_FRDPD helper components")
endif()

add_subdirectory(frdpd)

add_library(frdp-ipc OBJECT
    ipc/frdp-ipc.c
    ipc/frdp-ipc.h)
set_property(TARGET frdp-ipc PROPERTY FOLDER "Server/frdp")

add_executable(frdp-authd
    frdp-authd/frdp-authd.c
    $<TARGET_OBJECTS:frdp-ipc>)
target_include_directories(frdp-authd SYSTEM PRIVATE ${PAM_INCLUDE_DIR})
target_link_libraries(frdp-authd PRIVATE ${PAM_LIBRARIES} ${UUID_LIBRARY})
installwithrpath(TARGETS frdp-authd DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT server)
set_property(TARGET frdp-authd PROPERTY FOLDER "Server/frdp")

add_executable(frdp-sesmand
    frdp-sesmand/frdp-sesmand.c
    $<TARGET_OBJECTS:frdp-ipc>)
target_include_directories(frdp-sesmand SYSTEM PRIVATE ${PAM_INCLUDE_DIR})
target_link_libraries(frdp-sesmand PRIVATE ${PAM_LIBRARIES} ${UUID_LIBRARY})
installwithrpath(TARGETS frdp-sesmand DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT server)
set_property(TARGET frdp-sesmand PROPERTY FOLDER "Server/frdp")

add_executable(frdp-session-agent frdp-session-agent/frdp-session-agent.c)
target_include_directories(frdp-session-agent SYSTEM PRIVATE ${X11_INCLUDE_DIR} ${X11_XTest_INCLUDE_PATH} ${X11_Xdamage_INCLUDE_PATH})
target_link_libraries(frdp-session-agent PRIVATE winpr ${X11_LIBRARIES} ${X11_XTest_LIB} ${X11_Xdamage_LIB})
installwithrpath(TARGETS frdp-session-agent DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT server)
set_property(TARGET frdp-session-agent PROPERTY FOLDER "Server/frdp")

add_executable(frdpd-ipc-demo
    frdpd/frdpd-ipc-demo.c
    config/frdp-config.c
    config/frdp-config.h
    $<TARGET_OBJECTS:frdp-ipc>)
set_property(TARGET frdpd-ipc-demo PROPERTY FOLDER "Server/frdp")

add_executable(frdpctl ${CMAKE_SOURCE_DIR}/tools/frdpctl/frdpctl.c)
installwithrpath(TARGETS frdpctl DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT server)
set_property(TARGET frdpctl PROPERTY FOLDER "Server/frdp")

find_library(GSSAPI_LIBRARY NAMES gssapi_krb5 gssapi)
if(GSSAPI_LIBRARY)
  add_executable(frdp-krb-authd frdp-krb-authd/frdp-krb-authd.c)
  target_link_libraries(frdp-krb-authd PRIVATE ${GSSAPI_LIBRARY})
  set_property(TARGET frdp-krb-authd PROPERTY FOLDER "Server/frdp")
else()
  message(WARNING "GSSAPI library not found; frdp-krb-authd target will not be built")
endif()

set(FRDP_SYSTEMD_SYSTEM_UNIT_DIR "lib/systemd/system" CACHE PATH "systemd system unit install directory")
set(FRDP_SECURITY_POLICY_DIR "${CMAKE_INSTALL_DATADIR}/frdpd/security" CACHE PATH "FRDP security policy example install directory")
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
install(FILES ${CMAKE_SOURCE_DIR}/packaging/selinux/frdpd.te
        DESTINATION ${FRDP_SECURITY_POLICY_DIR}/selinux
        COMPONENT server)
install(FILES ${CMAKE_SOURCE_DIR}/packaging/apparmor/frdpd
        DESTINATION ${FRDP_SECURITY_POLICY_DIR}/apparmor
        COMPONENT server)

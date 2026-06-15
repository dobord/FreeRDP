# FreeRDP: A Remote Desktop Protocol Implementation
# Experimental FreeRDP PAM/SSSD RDP server components

find_package(PAM REQUIRED)

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

install(FILES config/frdpd.toml DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/frdpd COMPONENT server)

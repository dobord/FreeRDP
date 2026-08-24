# FreeRDP: A Remote Desktop Protocol Implementation
# Experimental FreeRDP PAM/SSSD RDP daemon prototype

set(MODULE_NAME "frdpd")
set(MODULE_PREFIX "FREERDP_SERVER_FRDPD")

find_package(PAM REQUIRED)

set(SRCS
    frdpd.c
    frdpd.h
    frdpd_auth.c
    frdpd_auth.h
    frdpd_audit.c
    frdpd_audit.h
    frdpd_peer.c
    frdpd_peer.h
    channel_policy.c
    channel_policy.h
    clipboard.c
    clipboard.h
    clipboard_runtime.c
    clipboard_runtime.h
    display_control.c
    display_control.h
    frame_policy.c
    frame_policy.h
    gfx_policy.c
    gfx_policy.h
    frdpd_pam.c
    frdpd_pam.h
    ../ipc/frdp-auth-token.c
    ../ipc/frdp-auth-token.h
    ../ipc/frdp-ipc.c
    ../ipc/frdp-ipc.h
    ../config/frdp-config.c
    ../config/frdp-config.h)
list(APPEND SRCS ../audit/frdp-audit.c ../audit/frdp-audit.h)

addtargetwithresourcefile(${MODULE_NAME} TRUE "${FREERDP_VERSION}" SRCS)

include_directories(SYSTEM ${PAM_INCLUDE_DIR})
if(HAVE_PAM_PAM_APPL_H)
  target_compile_definitions(${MODULE_NAME} PRIVATE HAVE_PAM_PAM_APPL_H)
endif()
if(WITH_FRDPD_NTLM)
  target_compile_definitions(${MODULE_NAME} PRIVATE WITH_FRDPD_NTLM=1)
endif()
target_include_directories(${MODULE_NAME} SYSTEM PRIVATE ${LIBSYSTEMD_INCLUDE_DIRS})
target_link_libraries(${MODULE_NAME} PRIVATE freerdp-server freerdp winpr ${PAM_LIBRARIES}
                                             ${UUID_LIBRARY} ${LIBSYSTEMD_LIBRARIES})
frdp_apply_strict_warnings(${MODULE_NAME})

installwithrpath(TARGETS ${MODULE_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT server)

set_property(TARGET ${MODULE_NAME} PROPERTY FOLDER "Server/frdp/frdpd")

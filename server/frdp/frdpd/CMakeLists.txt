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
    frdpd_pam.c
    frdpd_pam.h
    ../config/frdp-config.c
    ../config/frdp-config.h)

addtargetwithresourcefile(${MODULE_NAME} TRUE "${FREERDP_VERSION}" SRCS)

include_directories(SYSTEM ${PAM_INCLUDE_DIR})
if(HAVE_PAM_PAM_APPL_H)
  target_compile_definitions(${MODULE_NAME} PRIVATE HAVE_PAM_PAM_APPL_H)
endif()
target_link_libraries(${MODULE_NAME} PRIVATE freerdp-server freerdp winpr ${PAM_LIBRARIES})

installwithrpath(TARGETS ${MODULE_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT server)

set_property(TARGET ${MODULE_NAME} PROPERTY FOLDER "Server/frdp/frdpd")

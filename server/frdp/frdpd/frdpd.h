/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Experimental frdpd server internals
 *
 * Licensed under the Apache License, Version 2.0.
 */

#ifndef FREERDP_SERVER_FRDPD_H
#define FREERDP_SERVER_FRDPD_H

#include <freerdp/freerdp.h>
#include <freerdp/peer.h>

#include "frdpd_pam.h"

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct
	{
		const char* bind_address;
		const char* cert_path;
		const char* key_path;
		const char* pam_service;
		const char* auth_socket;
		UINT16 port;
		BOOL allow_tls_fallback;
		BOOL open_pam_session;
		frdpdDomainMode domain_mode;
	} frdpdServerConfig;

	typedef struct
	{
		rdpContext _p;
		char correlation_id[64];
		void* pam_handle;
		char* pam_user;
		BOOL pam_credentials_established;
		BOOL pam_session_open;
		frdpdPamAuthStatus auth_status;
		int pam_status;
	} frdpdPeerContext;

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_SERVER_FRDPD_H */

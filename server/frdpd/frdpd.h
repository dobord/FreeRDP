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
		UINT16 port;
		BOOL allow_tls_fallback;
		frdpdDomainMode domain_mode;
	} frdpdServerConfig;

	typedef struct
	{
		rdpContext _p;
		char* pam_user;
		frdpdPamAuthStatus auth_status;
		int pam_status;
	} frdpdPeerContext;

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_SERVER_FRDPD_H */

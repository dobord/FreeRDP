/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Experimental frdpd authentication adapter
 *
 * Licensed under the Apache License, Version 2.0.
 */

#ifndef FREERDP_SERVER_FRDPD_AUTH_H
#define FREERDP_SERVER_FRDPD_AUTH_H

#include <winpr/sspi.h>

#include "frdpd_pam.h"

typedef struct
{
	const char* pam_service;
	const char* rhost;
	frdpdDomainMode domain_mode;
	BOOL open_pam_session;
} frdpdAuthConfig;

typedef struct
{
	frdpdPamAuthStatus status;
	int pam_status;
	char* pam_user;
	void* pam_handle;
	BOOL pam_credentials_established;
	BOOL pam_session_open;
} frdpdAuthResult;

BOOL frdpd_authenticate_identity(const frdpdAuthConfig* config,
                                 const SEC_WINNT_AUTH_IDENTITY* identity, frdpdAuthResult* result);

#endif /* FREERDP_SERVER_FRDPD_AUTH_H */

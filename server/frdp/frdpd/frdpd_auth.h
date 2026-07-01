/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Experimental frdpd authentication adapter
 *
 * Licensed under the Apache License, Version 2.0.
 */

#ifndef FREERDP_SERVER_FRDPD_AUTH_H
#define FREERDP_SERVER_FRDPD_AUTH_H

#include <sys/types.h>

#include <winpr/sspi.h>

#include "../ipc/frdp-ipc.h"
#include "frdpd_pam.h"

typedef struct
{
	const char* pam_service;
	const char* auth_socket;
	const char* correlation_id;
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
	uid_t uid;
	gid_t gid;
	uint32_t group_count;
	uint64_t groups[FRDP_IPC_MAX_AUTH_GROUPS];
	BOOL has_posix_account;
	char authorization_id[192];
} frdpdAuthResult;

BOOL frdpd_authenticate_identity(const frdpdAuthConfig* config,
                                 const SEC_WINNT_AUTH_IDENTITY* identity, frdpdAuthResult* result);

#endif /* FREERDP_SERVER_FRDPD_AUTH_H */

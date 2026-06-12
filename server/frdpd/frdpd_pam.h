/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Experimental frdpd PAM authentication helper
 *
 * Licensed under the Apache License, Version 2.0.
 */

#ifndef FREERDP_SERVER_FRDPD_PAM_H
#define FREERDP_SERVER_FRDPD_PAM_H

#include <winpr/wtypes.h>

typedef enum
{
	FRDPD_PAM_AUTH_OK = 0,
	FRDPD_PAM_AUTH_DENIED,
	FRDPD_PAM_AUTH_ACCOUNT_DENIED,
	FRDPD_PAM_AUTH_ERROR
} frdpdPamAuthStatus;

typedef struct
{
	const char* service;
	const char* user;
	const char* domain;
	const char* password;
	const char* rhost;
	int pam_status;
} frdpdPamAuthRequest;

BOOL frdpd_pam_build_user(const char* user, const char* domain, char** normalized_user);
void frdpd_pam_clear_secret(char* secret);
frdpdPamAuthStatus frdpd_pam_authenticate(frdpdPamAuthRequest* request);
const char* frdpd_pam_auth_status_string(frdpdPamAuthStatus status);

#endif /* FREERDP_SERVER_FRDPD_PAM_H */

/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Experimental frdpd authentication adapter
 *
 * Licensed under the Apache License, Version 2.0.
 */

#include "frdpd_auth.h"

#include <stdlib.h>

#include <winpr/crt.h>

static void frdpd_auth_result_set(frdpdAuthResult* result, frdpdPamAuthStatus status,
                                  int pam_status)
{
	if (!result)
		return;

	result->status = status;
	result->pam_status = pam_status;
}

BOOL frdpd_authenticate_identity(const frdpdAuthConfig* config,
                                 const SEC_WINNT_AUTH_IDENTITY* identity,
                                 frdpdAuthResult* result)
{
	char* user = NULL;
	char* domain = NULL;
	char* password = NULL;
	BOOL ok = FALSE;
	frdpdPamAuthRequest request = { 0 };

	frdpd_auth_result_set(result, FRDPD_PAM_AUTH_ERROR, 0);

	if (!config || !identity || !config->pam_service)
		return FALSE;

	if (!sspi_CopyAuthIdentityFieldsA((const SEC_WINNT_AUTH_IDENTITY_INFO*)identity, &user,
	                                  &domain, &password))
		goto fail;

	request.service = config->pam_service;
	request.user = user;
	request.domain = domain;
	request.password = password;
	request.rhost = config->rhost;
	request.pam_status = 0;

	const frdpdPamAuthStatus status = frdpd_pam_authenticate(&request);
	frdpd_auth_result_set(result, status, request.pam_status);
	ok = (status == FRDPD_PAM_AUTH_OK);

fail:
	free(user);
	free(domain);
	frdpd_pam_clear_secret(password);
	free(password);

	return ok;
}

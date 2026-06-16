/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Experimental frdpd authentication adapter
 *
 * Licensed under the Apache License, Version 2.0.
 */

#include "frdpd_auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <winpr/crt.h>

#include "../ipc/frdp-ipc.h"

static void frdpd_auth_result_set(frdpdAuthResult* result, frdpdPamAuthStatus status,
                                  int pam_status)
{
	if (!result)
		return;

	result->status = status;
	result->pam_status = pam_status;
	result->pam_user = NULL;
	result->pam_handle = NULL;
	result->pam_credentials_established = FALSE;
	result->pam_session_open = FALSE;
}

static BOOL frdpd_auth_string_is_empty(const char* value)
{
	return !value || (value[0] == '\0');
}

static BOOL frdpd_auth_copy_ipc_string(char* dst, size_t dst_size, const char* src)
{
	int rc = 0;

	if (!dst || (dst_size == 0))
		return FALSE;
	if (!src)
		src = "";

	rc = snprintf(dst, dst_size, "%s", src);
	return (rc >= 0) && ((size_t)rc < dst_size);
}

typedef struct
{
	char* secret;
	size_t length;
	BOOL locked;
} frdpdLockedSecret;

static BOOL frdpd_auth_lock_secret(char* secret, size_t length, frdpdLockedSecret* locked)
{
	if (!secret || !locked || (length == 0))
		return FALSE;

	memset(locked, 0, sizeof(*locked));
	locked->secret = secret;
	locked->length = length;
	if (mlock(secret, length) != 0)
		return FALSE;
	locked->locked = TRUE;
	return TRUE;
}

static void frdpd_auth_clear_locked_secret(frdpdLockedSecret* locked)
{
	if (!locked || !locked->secret)
		return;

	SecureZeroMemory(locked->secret, locked->length);
	if (locked->locked)
		(void)munlock(locked->secret, locked->length);
	memset(locked, 0, sizeof(*locked));
}

static BOOL frdpd_authenticate_identity_ipc(const frdpdAuthConfig* config,
                                            const SEC_WINNT_AUTH_IDENTITY* identity,
                                            frdpdAuthResult* result)
{
	char* user = NULL;
	char* domain = NULL;
	char* password = NULL;
	char* pam_user = NULL;
	BOOL ok = FALSE;
	int fd = -1;
	frdpdLockedSecret password_secret = { 0 };
	frdpdLockedSecret request_password_secret = { 0 };
	frdpAuthRequest request = { 0 };
	frdpAuthResponse response = { 0 };
	frdpIpcHeader header = { 0 };
	frdpIpcHeader response_header = { 0 };

	if (!config || !identity || frdpd_auth_string_is_empty(config->auth_socket) ||
	    frdpd_auth_string_is_empty(config->pam_service))
		return FALSE;
	if (config->open_pam_session)
		return FALSE;

	if (!sspi_CopyAuthIdentityFieldsA((const SEC_WINNT_AUTH_IDENTITY_INFO*)identity, &user, &domain,
	                                  &password))
		goto fail;
	if (!password)
		goto fail;
	if (!frdpd_auth_lock_secret(password, strlen(password) + 1, &password_secret))
		goto fail;
	if (!frdpd_pam_build_user(user, domain, config->domain_mode, &pam_user))
		goto fail;

	if (!frdpd_auth_copy_ipc_string(request.user, sizeof(request.user), pam_user) ||
	    !frdpd_auth_copy_ipc_string(request.correlation_id, sizeof(request.correlation_id),
	                                config->correlation_id) ||
	    !frdpd_auth_copy_ipc_string(request.rhost, sizeof(request.rhost), config->rhost))
		goto fail;
	if (!frdpd_auth_lock_secret(request.password, sizeof(request.password),
	                           &request_password_secret))
		goto fail;
	if (!frdpd_auth_copy_ipc_string(request.password, sizeof(request.password), password))
		goto fail;

	fd = frdp_ipc_connect(config->auth_socket);
	if (fd < 0)
		goto fail;

	header.type = FRDP_IPC_AUTH_REQUEST_V2;
	header.payload_len = sizeof(request);
	if ((frdp_ipc_send(fd, &header, sizeof(header)) < 0) ||
	    (frdp_ipc_send(fd, &request, sizeof(request)) < 0))
		goto fail;
	frdpd_auth_clear_locked_secret(&request_password_secret);

	if (frdp_ipc_recv(fd, &response_header, sizeof(response_header)) !=
	    (int)sizeof(response_header))
		goto fail;
	if ((response_header.type != FRDP_IPC_AUTH_RESPONSE) ||
	    (response_header.payload_len != sizeof(response)))
		goto fail;
	if (frdp_ipc_recv(fd, &response, sizeof(response)) != (int)sizeof(response))
		goto fail;

	frdpd_auth_result_set(result,
	                      response.success ? FRDPD_PAM_AUTH_OK
	                                       : (response.error[0] ? FRDPD_PAM_AUTH_ERROR
	                                                            : FRDPD_PAM_AUTH_DENIED),
	                      0);
	ok = response.success ? TRUE : FALSE;
	if (ok && result)
	{
		result->pam_user = pam_user;
		pam_user = NULL;
	}

fail:
	if (fd >= 0)
		(void)frdp_ipc_close(fd);
	frdpd_auth_clear_locked_secret(&request_password_secret);
	free(user);
	free(domain);
	free(pam_user);
	frdpd_auth_clear_locked_secret(&password_secret);
	free(password);
	return ok;
}

BOOL frdpd_authenticate_identity(const frdpdAuthConfig* config,
                                 const SEC_WINNT_AUTH_IDENTITY* identity, frdpdAuthResult* result)
{
	char* user = NULL;
	char* domain = NULL;
	char* password = NULL;
	char* pam_user = NULL;
	BOOL ok = FALSE;
	frdpdLockedSecret password_secret = { 0 };
	frdpdPamAuthRequest request = { 0 };

	frdpd_auth_result_set(result, FRDPD_PAM_AUTH_ERROR, 0);

	if (!config || !identity || !config->pam_service)
		return FALSE;
	if (!frdpd_auth_string_is_empty(config->auth_socket))
		return frdpd_authenticate_identity_ipc(config, identity, result);

	if (!sspi_CopyAuthIdentityFieldsA((const SEC_WINNT_AUTH_IDENTITY_INFO*)identity, &user, &domain,
	                                  &password))
		goto fail;
	if (!password)
		goto fail;
	if (!frdpd_auth_lock_secret(password, strlen(password) + 1, &password_secret))
		goto fail;
	if (!frdpd_pam_build_user(user, domain, config->domain_mode, &pam_user))
		goto fail;

	request.service = config->pam_service;
	request.user = user;
	request.domain = domain;
	request.password = password;
	request.rhost = config->rhost;
	request.domain_mode = config->domain_mode;
	request.open_session = config->open_pam_session;
	request.pam_status = 0;

	const frdpdPamAuthStatus status = frdpd_pam_authenticate(&request);
	frdpd_auth_result_set(result, status, request.pam_status);
	ok = (status == FRDPD_PAM_AUTH_OK);
	if (ok && result)
	{
		result->pam_user = pam_user;
		result->pam_handle = request.pam_handle;
		result->pam_credentials_established = request.pam_credentials_established;
		result->pam_session_open = request.pam_session_open;
		pam_user = NULL;
		request.pam_handle = NULL;
	}

fail:
	free(user);
	free(domain);
	free(pam_user);
	frdpd_auth_clear_locked_secret(&password_secret);
	free(password);

	return ok;
}

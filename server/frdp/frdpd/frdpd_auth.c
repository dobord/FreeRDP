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
	result->uid = (uid_t)-1;
	result->gid = (gid_t)-1;
	result->group_count = 0;
	memset(result->groups, 0, sizeof(result->groups));
	result->has_posix_account = FALSE;
	memset(result->authorization_id, 0, sizeof(result->authorization_id));
}

static BOOL frdpd_auth_string_is_empty(const char* value)
{
	return !value || (value[0] == '\0');
}

static BOOL frdpd_auth_identity_has_empty_password(const SEC_WINNT_AUTH_IDENTITY* identity)
{
	const char* passwordA = NULL;
	const WCHAR* passwordW = NULL;
	UINT32 password_length = 0;
	const UINT32 flags = sspi_GetAuthIdentityFlags(identity);

	if (flags & SEC_WINNT_AUTH_IDENTITY_ANSI)
		return sspi_GetAuthIdentityPasswordA(identity, &passwordA, &password_length) && passwordA &&
		       (password_length == 0);

	return sspi_GetAuthIdentityPasswordW(identity, &passwordW, &password_length) && passwordW &&
	       (password_length == 0);
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

	if (!config || !identity || frdpd_auth_string_is_empty(config->auth_socket) ||
	    frdpd_auth_string_is_empty(config->pam_service))
		return FALSE;

	if (!sspi_CopyAuthIdentityFieldsA((const SEC_WINNT_AUTH_IDENTITY_INFO*)identity, &user, &domain,
	                                  &password))
		goto fail;
	if (!password && frdpd_auth_identity_has_empty_password(identity))
	{
		password = _strdup("");
		if (!password)
			goto fail;
	}
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

	if (frdp_ipc_send_auth_request_v2(fd, &request) != 0)
		goto fail;
	frdpd_auth_clear_locked_secret(&request_password_secret);

	if (frdp_ipc_recv_auth_response(fd, &response) != 0)
		goto fail;

	frdpd_auth_result_set(result,
	                      response.success ? FRDPD_PAM_AUTH_OK
	                                       : (response.error[0] ? FRDPD_PAM_AUTH_ERROR
	                                                            : FRDPD_PAM_AUTH_DENIED),
	                      0);
	ok = response.success ? TRUE : FALSE;
	if (ok)
	{
		if (!result || (response.authorization_id[0] == '\0') ||
		    !frdpd_auth_copy_ipc_string(result->authorization_id,
		                                sizeof(result->authorization_id),
		                                response.authorization_id) ||
		    !response.has_posix_account ||
		    ((uint64_t)(uid_t)response.uid != response.uid) ||
		    ((uint64_t)(gid_t)response.gid != response.gid) ||
		    (response.group_count > FRDP_IPC_MAX_AUTH_GROUPS))
		{
			if (result)
				result->status = response.has_posix_account ? FRDPD_PAM_AUTH_ERROR
				                                            : FRDPD_PAM_AUTH_ACCOUNT_DENIED;
			ok = FALSE;
			goto fail;
		}
		result->uid = (uid_t)response.uid;
		result->gid = (gid_t)response.gid;
		result->group_count = response.group_count;
		memcpy(result->groups, response.groups, response.group_count * sizeof(response.groups[0]));
		result->has_posix_account = TRUE;
	}
	if (ok && result)
	{
		result->pam_user = pam_user;
		pam_user = NULL;
	}

fail:
	if (fd >= 0)
		(void)frdp_ipc_close(fd);
	frdpd_auth_clear_locked_secret(&request_password_secret);
	SecureZeroMemory(&response, sizeof(response));
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
	frdpd_auth_result_set(result, FRDPD_PAM_AUTH_ERROR, 0);

	if (!config || !identity || !config->pam_service)
		return FALSE;
	if (!frdpd_auth_string_is_empty(config->auth_socket))
		return frdpd_authenticate_identity_ipc(config, identity, result);

	return FALSE;
}

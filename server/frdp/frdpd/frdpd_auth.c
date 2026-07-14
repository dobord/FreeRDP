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
	SecureZeroMemory(result->groups, sizeof(result->groups));
	result->has_posix_account = FALSE;
	SecureZeroMemory(result->authorization_id, sizeof(result->authorization_id));
	SecureZeroMemory(result->broker_error, sizeof(result->broker_error));
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

BOOL frdpd_auth_identity_matches_proof(const SEC_WINNT_AUTH_IDENTITY* identity,
                                       const SecPkgContext_AuthIdentity* proof)
{
	char* user = NULL;
	char* domain = NULL;
	char* password = NULL;
	BOOL match = FALSE;

	if (!identity || !proof || (proof->User[0] == '\0'))
		return FALSE;
	if (!sspi_CopyAuthIdentityFieldsA((const SEC_WINNT_AUTH_IDENTITY_INFO*)identity, &user,
	                                  &domain, &password))
		goto out;

	match = user && (_stricmp(user, proof->User) == 0) &&
	        ((!domain || (domain[0] == '\0')) ? (proof->Domain[0] == '\0')
	                                          : (_stricmp(domain, proof->Domain) == 0));

out:
	if (password)
		SecureZeroMemory(password, strlen(password));
	free(password);
	free(domain);
	free(user);
	return match;
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

static BOOL frdpd_auth_fixed_string_is_valid(const char* value, size_t value_size)
{
	const char* end = value && value_size > 0 ? memchr(value, '\0', value_size) : NULL;

	if (!end)
		return FALSE;
	for (const char* current = value; current < end; current++)
	{
		const unsigned char c = (unsigned char)*current;

		if ((c < 0x20U) || (c == 0x7fU))
			return FALSE;
	}
	return TRUE;
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
	char* broker_user = NULL;
	const char* local_error = "invalid authentication request";
	BOOL ok = FALSE;
	int fd = -1;
	frdpdLockedSecret password_secret = { 0 };
	frdpdLockedSecret request_password_secret = { 0 };
	frdpAuthRequest request = { 0 };
	frdpAuthResponse response = { 0 };

	if (!config || !identity || frdpd_auth_string_is_empty(config->auth_socket) ||
	    frdpd_auth_string_is_empty(config->pam_service))
		return FALSE;

	local_error = "unable to extract CredSSP identity";
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
	local_error = "unable to lock CredSSP password memory";
	if (!frdpd_auth_lock_secret(password, strlen(password) + 1, &password_secret))
		goto fail;
	local_error = "unable to normalize PAM user";
	if (!frdpd_pam_build_user(user, domain, config->domain_mode, &pam_user))
		goto fail;

	local_error = "unable to construct auth broker request";
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

	local_error = "unable to connect to auth broker";
	fd = frdp_ipc_connect(config->auth_socket);
	if (fd < 0)
		goto fail;

	local_error = "unable to send auth broker request";
	if (frdp_ipc_send_auth_request_v2(fd, &request) != 0)
		goto fail;
	frdpd_auth_clear_locked_secret(&request_password_secret);

	local_error = "unable to receive auth broker response";
	if (frdp_ipc_recv_auth_response_v2(fd, &response) != 0)
		goto fail;
	if (!frdpd_auth_fixed_string_is_valid(response.error, sizeof(response.error)) ||
	    !frdpd_auth_fixed_string_is_valid(response.user, sizeof(response.user)) ||
	    !frdpd_auth_fixed_string_is_valid(response.authorization_id,
	                                      sizeof(response.authorization_id)))
		goto fail;

	frdpd_auth_result_set(result,
	                      response.success ? FRDPD_PAM_AUTH_OK
	                                       : (response.error[0] ? FRDPD_PAM_AUTH_ERROR
	                                                            : FRDPD_PAM_AUTH_DENIED),
	                      0);
	if (result && response.error[0] &&
	    !frdpd_auth_copy_ipc_string(result->broker_error, sizeof(result->broker_error),
	                                response.error))
		goto fail;
	ok = response.success ? TRUE : FALSE;
	if (ok)
	{
		local_error = "invalid auth broker response";
		if (!result || (response.user[0] == '\0') || (response.authorization_id[0] == '\0') ||
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
		broker_user = _strdup(response.user);
		if (!broker_user)
		{
			result->status = FRDPD_PAM_AUTH_ERROR;
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
		result->pam_user = broker_user;
		broker_user = NULL;
	}

fail:
	if (result && (result->status == FRDPD_PAM_AUTH_ERROR) && !result->broker_error[0])
		(void)frdpd_auth_copy_ipc_string(result->broker_error, sizeof(result->broker_error),
		                                 local_error);
	if (fd >= 0)
		(void)frdp_ipc_close(fd);
	frdpd_auth_clear_locked_secret(&request_password_secret);
	SecureZeroMemory(&response, sizeof(response));
	free(user);
	free(domain);
	free(pam_user);
	free(broker_user);
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

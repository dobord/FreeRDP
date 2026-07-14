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
#include <winpr/string.h>

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

typedef struct
{
	const char* user;
	size_t user_length;
	const char* domain;
	size_t domain_length;
} frdpdAuthIdentityView;

static BOOL frdpd_auth_identity_fields_are_valid(const SEC_WINNT_AUTH_IDENTITY* identity)
{
	UINT32 user_length = 0;
	UINT32 domain_length = 0;
	UINT32 password_length = 0;

	if (sspi_GetAuthIdentityFlags(identity) & SEC_WINNT_AUTH_IDENTITY_ANSI)
	{
		const char* user = NULL;
		const char* domain = NULL;
		const char* password = NULL;

		if (!sspi_GetAuthIdentityUserDomainA(identity, &user, &user_length, &domain,
		                                     &domain_length) ||
		    !sspi_GetAuthIdentityPasswordA(identity, &password, &password_length) ||
		    !user || (user_length == 0) || memchr(user, '\0', user_length) ||
		    ((domain_length > 0) && (!domain || memchr(domain, '\0', domain_length))) ||
		    ((password_length > 0) && (!password || memchr(password, '\0', password_length))))
			return FALSE;
		return TRUE;
	}
	else
	{
		const WCHAR* user = NULL;
		const WCHAR* domain = NULL;
		const WCHAR* password = NULL;

		if (!sspi_GetAuthIdentityUserDomainW(identity, &user, &user_length, &domain,
		                                     &domain_length) ||
		    !sspi_GetAuthIdentityPasswordW(identity, &password, &password_length) || !user ||
		    (user_length == 0) || ((domain_length > 0) && !domain) ||
		    ((password_length > 0) && !password))
			return FALSE;
		for (UINT32 x = 0; x < user_length; x++)
		{
			if (user[x] == 0)
				return FALSE;
		}
		for (UINT32 x = 0; x < domain_length; x++)
		{
			if (domain[x] == 0)
				return FALSE;
		}
		for (UINT32 x = 0; x < password_length; x++)
		{
			if (password[x] == 0)
				return FALSE;
		}
		return TRUE;
	}
}

static char* frdpd_auth_copy_ansi_field(const char* field, UINT32 length)
{
	char* copy = NULL;

	if (!field || (length == 0))
		return NULL;
	copy = malloc((size_t)length + 1U);
	if (!copy)
		return NULL;
	memcpy(copy, field, length);
	copy[length] = '\0';
	return copy;
}

static BOOL frdpd_auth_copy_identity_user_domain(const SEC_WINNT_AUTH_IDENTITY* identity,
                                                 char** user, char** domain)
{
	BOOL success = FALSE;
	UINT32 user_length = 0;
	UINT32 domain_length = 0;

	if (!identity || !user || !domain)
		return FALSE;
	*user = NULL;
	*domain = NULL;
	if (sspi_GetAuthIdentityFlags(identity) & SEC_WINNT_AUTH_IDENTITY_ANSI)
	{
		const char* source_user = NULL;
		const char* source_domain = NULL;

		if (!sspi_GetAuthIdentityUserDomainA(identity, &source_user, &user_length, &source_domain,
		                                     &domain_length))
			goto out;
		if (user_length > 0)
		{
			*user = frdpd_auth_copy_ansi_field(source_user, user_length);
			if (!*user)
				goto out;
		}
		if (domain_length > 0)
		{
			*domain = frdpd_auth_copy_ansi_field(source_domain, domain_length);
			if (!*domain)
				goto out;
		}
	}
	else
	{
		const WCHAR* source_user = NULL;
		const WCHAR* source_domain = NULL;

		if (!sspi_GetAuthIdentityUserDomainW(identity, &source_user, &user_length, &source_domain,
		                                     &domain_length))
			goto out;
		if (((user_length > 0) && !source_user) || ((domain_length > 0) && !source_domain))
			goto out;
		if (user_length > 0)
		{
			*user = ConvertWCharNToUtf8Alloc(source_user, user_length, NULL);
			if (!*user)
				goto out;
		}
		if (domain_length > 0)
		{
			*domain = ConvertWCharNToUtf8Alloc(source_domain, domain_length, NULL);
			if (!*domain)
				goto out;
		}
	}
	success = TRUE;

out:
	if (!success)
	{
		free(*domain);
		free(*user);
		*user = NULL;
		*domain = NULL;
	}
	return success;
}

static BOOL frdpd_auth_copy_identity_fields(const SEC_WINNT_AUTH_IDENTITY* identity, char** user,
                                            char** domain, char** password)
{
	BOOL success = FALSE;

	if (!identity || !user || !domain || !password)
		return FALSE;
	*user = NULL;
	*domain = NULL;
	*password = NULL;
	if (!frdpd_auth_copy_identity_user_domain(identity, user, domain))
		goto out;
	if (sspi_GetAuthIdentityFlags(identity) & SEC_WINNT_AUTH_IDENTITY_ANSI)
	{
		const char* source_password = NULL;
		UINT32 password_length = 0;

		if (!sspi_GetAuthIdentityPasswordA(identity, &source_password, &password_length))
			goto out;
		if (password_length > 0)
		{
			*password = frdpd_auth_copy_ansi_field(source_password, password_length);
			if (!*password)
				goto out;
		}
		success = TRUE;
	}
	else
	{
		const WCHAR* source_password = NULL;
		UINT32 password_length = 0;

		if (!sspi_GetAuthIdentityPasswordW(identity, &source_password, &password_length) ||
		    ((password_length > 0) && !source_password))
			goto out;
		if (password_length > 0)
		{
			*password = ConvertWCharNToUtf8Alloc(source_password, password_length, NULL);
			if (!*password)
				goto out;
		}
		success = TRUE;
	}

out:
	if (!success)
	{
		free(*password);
		free(*domain);
		free(*user);
		*user = NULL;
		*domain = NULL;
		*password = NULL;
	}
	return success;
}

static BOOL frdpd_auth_fixed_field_length(const char* field, size_t field_size, BOOL allow_empty,
	                                      size_t* length)
{
	const char* end = NULL;

	if (!field || (field_size == 0) || !length)
		return FALSE;
	end = memchr(field, '\0', field_size);
	if (!end || (!allow_empty && (end == field)))
		return FALSE;
	for (const char* current = end + 1; current < &field[field_size]; current++)
	{
		if (*current != '\0')
			return FALSE;
	}
	*length = (size_t)(end - field);
	return TRUE;
}

static BOOL frdpd_auth_identity_view(const char* user, size_t user_length, const char* domain,
	                                 size_t domain_length, frdpdAuthIdentityView* view)
{
	const char* separator = NULL;
	const char* alternate = NULL;

	if (!user || (user_length == 0) || !view)
		return FALSE;
	view->user = user;
	view->user_length = user_length;
	view->domain = domain;
	view->domain_length = domain_length;
	if (domain_length > 0)
		return domain && !memchr(user, '\\', user_length) && !memchr(user, '@', user_length) &&
		       !memchr(domain, '\\', domain_length) && !memchr(domain, '@', domain_length);

	separator = memchr(user, '\\', user_length);
	alternate = memchr(user, '@', user_length);
	if (separator && alternate)
		return FALSE;
	if (!separator)
		separator = alternate;
	if (!separator)
		return TRUE;
	if ((separator == user) || (separator == &user[user_length - 1U]) ||
	    memchr(separator + 1, *separator, (size_t)(&user[user_length] - separator - 1)) != NULL)
		return FALSE;

	if (*separator == '\\')
	{
		view->domain = user;
		view->domain_length = (size_t)(separator - user);
		view->user = separator + 1;
		view->user_length = (size_t)(&user[user_length] - view->user);
	}
	else
	{
		view->user_length = (size_t)(separator - user);
		view->domain = separator + 1;
		view->domain_length = (size_t)(&user[user_length] - view->domain);
	}
	return TRUE;
}

static BOOL frdpd_auth_identity_component_equal(const char* left, size_t left_length,
	                                            const char* right, size_t right_length)
{
	if (!left || !right || (left_length != right_length))
		return FALSE;
	for (size_t x = 0; x < left_length; x++)
	{
		unsigned char l = (unsigned char)left[x];
		unsigned char r = (unsigned char)right[x];

		if ((l >= 'A') && (l <= 'Z'))
			l = (unsigned char)(l + ('a' - 'A'));
		if ((r >= 'A') && (r <= 'Z'))
			r = (unsigned char)(r + ('a' - 'A'));
		if (l != r)
			return FALSE;
	}
	return TRUE;
}

BOOL frdpd_auth_identity_matches_proof(const SEC_WINNT_AUTH_IDENTITY* identity,
                                       const SecPkgContext_AuthIdentity* proof,
                                       frdpdDomainMode domain_mode)
{
	char* user = NULL;
	char* domain = NULL;
	char* pam_user = NULL;
	frdpdAuthIdentityView raw_delegated = { 0 };
	frdpdAuthIdentityView delegated = { 0 };
	frdpdAuthIdentityView authenticated = { 0 };
	size_t proof_user_length = 0;
	size_t proof_domain_length = 0;
	BOOL match = FALSE;

	if (!identity || !proof)
		return FALSE;
	if (!frdpd_auth_fixed_field_length(proof->User, sizeof(proof->User), FALSE,
	                                    &proof_user_length) ||
	    !frdpd_auth_fixed_field_length(proof->Domain, sizeof(proof->Domain), TRUE,
	                                    &proof_domain_length) ||
	    !frdpd_auth_identity_fields_are_valid(identity))
		return FALSE;
	if (!frdpd_auth_copy_identity_user_domain(identity, &user, &domain))
		goto out;

	if (!frdpd_auth_identity_view(user, user ? strlen(user) : 0, domain,
	                              domain ? strlen(domain) : 0, &raw_delegated) ||
	    !frdpd_pam_build_user(user, domain, domain_mode, &pam_user) ||
	    !frdpd_auth_identity_view(pam_user, pam_user ? strlen(pam_user) : 0, NULL, 0,
	                              &delegated) ||
	    !frdpd_auth_identity_view(proof->User, proof_user_length, proof->Domain,
	                              proof_domain_length, &authenticated))
		goto out;
	match = frdpd_auth_identity_component_equal(delegated.user, delegated.user_length,
	                                            authenticated.user,
	                                            authenticated.user_length);
	if (match && (raw_delegated.domain_length != 0))
		match = frdpd_auth_identity_component_equal(
		    raw_delegated.domain, raw_delegated.domain_length, authenticated.domain,
		    authenticated.domain_length);

out:
	free(pam_user);
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
	if (!frdpd_auth_identity_fields_are_valid(identity) ||
	    !frdpd_auth_copy_identity_fields(identity, &user, &domain, &password))
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

/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Experimental frdpd PAM authentication helper
 *
 * Licensed under the Apache License, Version 2.0.
 */

#include "frdpd_pam.h"

#include <stdlib.h>
#include <string.h>

#include <winpr/crt.h>
#include <winpr/string.h>

#if defined(HAVE_PAM_PAM_APPL_H)
#include <pam/pam_appl.h>
#else
#include <security/pam_appl.h>
#endif

static BOOL frdpd_string_is_empty(const char* value)
{
	return !value || (value[0] == '\0');
}

void frdpd_pam_clear_secret(char* secret)
{
	if (secret)
		SecureZeroMemory(secret, strlen(secret));
}

static int frdpd_pam_conv(int num_msg, const struct pam_message** msg,
                          struct pam_response** resp, void* appdata_ptr)
{
	WINPR_UNUSED(appdata_ptr);

	if ((num_msg <= 0) || !msg || !resp)
		return PAM_CONV_ERR;

	struct pam_response* reply = calloc((size_t)num_msg, sizeof(struct pam_response));
	if (!reply)
		return PAM_BUF_ERR;

	for (int x = 0; x < num_msg; x++)
	{
		switch (msg[x]->msg_style)
		{
			case PAM_PROMPT_ECHO_OFF:
			case PAM_PROMPT_ECHO_ON:
				goto fail;

			case PAM_TEXT_INFO:
			case PAM_ERROR_MSG:
				break;

			default:
				goto fail;
		}
	}

	*resp = reply;
	return PAM_SUCCESS;

fail:
	free(reply);
	return PAM_CONV_ERR;
}

BOOL frdpd_pam_build_user(const char* user, const char* domain, char** normalized_user)
{
	if (!normalized_user)
		return FALSE;

	*normalized_user = NULL;
	if (frdpd_string_is_empty(user))
		return FALSE;

	if (strchr(user, '@') || strchr(user, '\\') || frdpd_string_is_empty(domain))
	{
		*normalized_user = _strdup(user);
		return *normalized_user != NULL;
	}

	const int rc = winpr_asprintf(normalized_user, NULL, "%s\\%s", domain, user);
	return rc >= 0;
}

frdpdPamAuthStatus frdpd_pam_authenticate(frdpdPamAuthRequest* request)
{
	pam_handle_t* pamh = NULL;
	char* normalized_user = NULL;

	if (request)
		request->pam_status = PAM_SYSTEM_ERR;

	if (!request || frdpd_string_is_empty(request->service) || frdpd_string_is_empty(request->user) ||
	    !request->password)
		return FRDPD_PAM_AUTH_ERROR;

	if (!frdpd_pam_build_user(request->user, request->domain, &normalized_user))
		return FRDPD_PAM_AUTH_ERROR;

	const struct pam_conv conv = { .conv = frdpd_pam_conv, .appdata_ptr = NULL };

	int pam_status = pam_start(request->service, normalized_user, &conv, &pamh);
	if (pam_status == PAM_SUCCESS)
	{
		if (!frdpd_string_is_empty(request->rhost))
			pam_status = pam_set_item(pamh, PAM_RHOST, request->rhost);
	}

	if (pam_status == PAM_SUCCESS)
		pam_status = pam_set_item(pamh, PAM_AUTHTOK, request->password);

	if (pam_status == PAM_SUCCESS)
		pam_status = pam_authenticate(pamh, 0);

	frdpdPamAuthStatus status = FRDPD_PAM_AUTH_ERROR;
	if (pam_status == PAM_SUCCESS)
	{
		pam_status = pam_acct_mgmt(pamh, 0);
		status = (pam_status == PAM_SUCCESS) ? FRDPD_PAM_AUTH_OK : FRDPD_PAM_AUTH_ACCOUNT_DENIED;
	}
	else if (pam_status == PAM_AUTH_ERR || pam_status == PAM_USER_UNKNOWN ||
	         pam_status == PAM_PERM_DENIED || pam_status == PAM_CRED_INSUFFICIENT)
	{
		status = FRDPD_PAM_AUTH_DENIED;
	}

	if (pamh)
	{
		(void)pam_set_item(pamh, PAM_AUTHTOK, "");
		const int end_status = pam_end(pamh, pam_status);
		if ((pam_status == PAM_SUCCESS) && (end_status != PAM_SUCCESS))
		{
			pam_status = end_status;
			status = FRDPD_PAM_AUTH_ERROR;
		}
	}

	request->pam_status = pam_status;
	free(normalized_user);
	return status;
}

const char* frdpd_pam_auth_status_string(frdpdPamAuthStatus status)
{
	switch (status)
	{
		case FRDPD_PAM_AUTH_OK:
			return "ok";
		case FRDPD_PAM_AUTH_DENIED:
			return "denied";
		case FRDPD_PAM_AUTH_ACCOUNT_DENIED:
			return "account-denied";
		case FRDPD_PAM_AUTH_ERROR:
		default:
			return "error";
	}
}

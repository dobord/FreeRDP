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

typedef struct
{
	const char* password;
} frdpdPamConvData;

static char* frdpd_pam_strdup_len(const char* data, size_t length)
{
	char* out = NULL;

	if (!data && (length > 0))
		return NULL;

	out = calloc(length + 1, 1);
	if (!out)
		return NULL;

	if (length > 0)
		memcpy(out, data, length);
	return out;
}

void frdpd_pam_clear_secret(char* secret)
{
	if (secret)
		SecureZeroMemory(secret, strlen(secret));
}

static int frdpd_pam_conv(int num_msg, const struct pam_message** msg, struct pam_response** resp,
                          void* appdata_ptr)
{
	frdpdPamConvData* data = (frdpdPamConvData*)appdata_ptr;

	if ((num_msg <= 0) || !msg || !resp)
		return PAM_CONV_ERR;

	struct pam_response* reply = calloc((size_t)num_msg, sizeof(struct pam_response));
	if (!reply)
		return PAM_BUF_ERR;

	for (int x = 0; x < num_msg; x++)
	{
		if (!msg[x])
			goto fail;

		switch (msg[x]->msg_style)
		{
			case PAM_PROMPT_ECHO_OFF:
				reply[x].resp =
				    frdpd_pam_strdup_len(data && data->password ? data->password : "",
				                         data && data->password ? strlen(data->password) : 0);
				if (!reply[x].resp)
					goto fail;
				break;

			case PAM_PROMPT_ECHO_ON:
				reply[x].resp = frdpd_pam_strdup_len("", 0);
				if (!reply[x].resp)
					goto fail;
				break;

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
	for (int x = 0; x < num_msg; x++)
	{
		frdpd_pam_clear_secret(reply[x].resp);
		free(reply[x].resp);
	}
	free(reply);
	return PAM_CONV_ERR;
}

BOOL frdpd_pam_build_user(const char* user, const char* domain, frdpdDomainMode mode,
                          char** normalized_user)
{
	if (!normalized_user)
		return FALSE;

	*normalized_user = NULL;
	if (frdpd_string_is_empty(user))
		return FALSE;

	if (strchr(user, '@') || strchr(user, '\\') || frdpd_string_is_empty(domain) ||
	    (mode == FRDPD_DOMAIN_PLAIN))
	{
		*normalized_user = _strdup(user);
		return *normalized_user != NULL;
	}

	if (mode == FRDPD_DOMAIN_AUTO)
		mode = strchr(domain, '.') ? FRDPD_DOMAIN_UPN : FRDPD_DOMAIN_DOWNLEVEL;

	const int rc = (mode == FRDPD_DOMAIN_UPN)
	                   ? winpr_asprintf(normalized_user, NULL, "%s@%s", user, domain)
	                   : winpr_asprintf(normalized_user, NULL, "%s\\%s", domain, user);
	return rc >= 0;
}

frdpdPamAuthStatus frdpd_pam_authenticate(frdpdPamAuthRequest* request)
{
	pam_handle_t* pamh = NULL;
	char* normalized_user = NULL;

	if (request)
	{
		request->pam_status = PAM_SYSTEM_ERR;
		request->pam_handle = NULL;
		request->pam_session_open = FALSE;
	}

	if (!request || frdpd_string_is_empty(request->service) ||
	    frdpd_string_is_empty(request->user) || !request->password)
		return FRDPD_PAM_AUTH_ERROR;

	if (!frdpd_pam_build_user(request->user, request->domain, request->domain_mode,
	                          &normalized_user))
		return FRDPD_PAM_AUTH_ERROR;

	frdpdPamConvData conv_data = { request->password };
	const struct pam_conv conv = { .conv = frdpd_pam_conv, .appdata_ptr = &conv_data };

	int pam_status = pam_start(request->service, normalized_user, &conv, &pamh);
	if (pam_status == PAM_SUCCESS)
	{
		if (!frdpd_string_is_empty(request->rhost))
			pam_status = pam_set_item(pamh, PAM_RHOST, request->rhost);
	}
	if (pam_status == PAM_SUCCESS)
		pam_status = pam_set_item(pamh, PAM_TTY, "rdp");
	if (pam_status == PAM_SUCCESS)
		pam_status = pam_set_item(pamh, PAM_RUSER, normalized_user);

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

	if ((status == FRDPD_PAM_AUTH_OK) && request->open_session)
	{
		pam_status = pam_open_session(pamh, 0);
		if (pam_status == PAM_SUCCESS)
		{
			(void)pam_set_item(pamh, PAM_AUTHTOK, "");
			request->pam_handle = pamh;
			request->pam_session_open = TRUE;
			pamh = NULL;
		}
		else
			status = FRDPD_PAM_AUTH_ERROR;
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

int frdpd_pam_close_session(void* pam_handle, const char* pam_user, BOOL pam_session_open)
{
	pam_handle_t* pamh = (pam_handle_t*)pam_handle;
	int status = PAM_SUCCESS;

	WINPR_UNUSED(pam_user);
	if (!pamh)
		return PAM_SUCCESS;

	(void)pam_set_item(pamh, PAM_AUTHTOK, "");
	if (pam_session_open)
		status = pam_close_session(pamh, 0);
	(void)pam_end(pamh, status);
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

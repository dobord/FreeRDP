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

static BOOL frdpd_string_is_empty(const char* value)
{
	return !value || (value[0] == '\0');
}

typedef struct
{
	const char* password;
} frdpdPamConvData;

#ifndef FRDPD_PAM_TESTING
typedef struct
{
	int (*start)(const char* service, const char* user, const struct pam_conv* conv,
	             pam_handle_t** pamh);
	int (*set_item)(pam_handle_t* pamh, int item_type, const void* item);
	int (*authenticate)(pam_handle_t* pamh, int flags);
	int (*acct_mgmt)(pam_handle_t* pamh, int flags);
	int (*setcred)(pam_handle_t* pamh, int flags);
	int (*open_session)(pam_handle_t* pamh, int flags);
	int (*end)(pam_handle_t* pamh, int pam_status);
} frdpdPamOps;
#endif

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

int frdpd_pam_answer_conversation(int num_msg, const struct pam_message** msg,
                                  struct pam_response** resp, const char* password)
{
	if (resp)
		*resp = NULL;
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
				    frdpd_pam_strdup_len(password ? password : "", password ? strlen(password) : 0);
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

static int frdpd_pam_conv(int num_msg, const struct pam_message** msg, struct pam_response** resp,
                          void* appdata_ptr)
{
	frdpdPamConvData* data = (frdpdPamConvData*)appdata_ptr;

	return frdpd_pam_answer_conversation(num_msg, msg, resp,
	                                     data && data->password ? data->password : "");
}

frdpdPamAuthStatus frdpd_pam_authenticate_status_from_pam(int pam_status)
{
	switch (pam_status)
	{
		case PAM_SUCCESS:
			return FRDPD_PAM_AUTH_OK;
		case PAM_AUTH_ERR:
		case PAM_USER_UNKNOWN:
		case PAM_PERM_DENIED:
		case PAM_CRED_INSUFFICIENT:
			return FRDPD_PAM_AUTH_DENIED;
		default:
			return FRDPD_PAM_AUTH_ERROR;
	}
}

frdpdPamAuthStatus frdpd_pam_account_status_from_pam(int pam_status)
{
	return (pam_status == PAM_SUCCESS) ? FRDPD_PAM_AUTH_OK : FRDPD_PAM_AUTH_ACCOUNT_DENIED;
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

	size_t normalized_len = 0;
	const int rc = (mode == FRDPD_DOMAIN_UPN)
	                   ? winpr_asprintf(normalized_user, &normalized_len, "%s@%s", user, domain)
	                   : winpr_asprintf(normalized_user, &normalized_len, "%s\\%s", domain, user);
	return rc >= 0;
}

static int frdpd_pam_default_start(const char* service, const char* user,
                                   const struct pam_conv* conv, pam_handle_t** pamh)
{
	return pam_start(service, user, conv, pamh);
}

static int frdpd_pam_default_set_item(pam_handle_t* pamh, int item_type, const void* item)
{
	return pam_set_item(pamh, item_type, item);
}

static int frdpd_pam_default_authenticate(pam_handle_t* pamh, int flags)
{
	return pam_authenticate(pamh, flags);
}

static int frdpd_pam_default_acct_mgmt(pam_handle_t* pamh, int flags)
{
	return pam_acct_mgmt(pamh, flags);
}

static int frdpd_pam_default_setcred(pam_handle_t* pamh, int flags)
{
	return pam_setcred(pamh, flags);
}

static int frdpd_pam_default_open_session(pam_handle_t* pamh, int flags)
{
	return pam_open_session(pamh, flags);
}

static int frdpd_pam_default_end(pam_handle_t* pamh, int pam_status)
{
	return pam_end(pamh, pam_status);
}

static const frdpdPamOps g_frdpd_pam_default_ops = { .start = frdpd_pam_default_start,
	                                                 .set_item = frdpd_pam_default_set_item,
	                                                 .authenticate = frdpd_pam_default_authenticate,
	                                                 .acct_mgmt = frdpd_pam_default_acct_mgmt,
	                                                 .setcred = frdpd_pam_default_setcred,
	                                                 .open_session = frdpd_pam_default_open_session,
	                                                 .end = frdpd_pam_default_end };

static BOOL frdpd_pam_ops_valid(const frdpdPamOps* ops)
{
	return ops && ops->start && ops->set_item && ops->authenticate && ops->acct_mgmt &&
	       ops->setcred && ops->open_session && ops->end;
}

static frdpdPamAuthStatus frdpd_pam_authenticate_internal(frdpdPamAuthRequest* request,
                                                          const frdpdPamOps* ops)
{
	pam_handle_t* pamh = NULL;
	char* normalized_user = NULL;
	BOOL credentials_established = FALSE;

	if (request)
	{
		request->pam_status = PAM_SYSTEM_ERR;
		request->pam_handle = NULL;
		request->pam_credentials_established = FALSE;
		request->pam_session_open = FALSE;
		request->normalized_user = NULL;
	}

	if (!request || !frdpd_pam_ops_valid(ops) || frdpd_string_is_empty(request->service) ||
	    frdpd_string_is_empty(request->user) || !request->password)
		return FRDPD_PAM_AUTH_ERROR;

	if (!frdpd_pam_build_user(request->user, request->domain, request->domain_mode,
	                          &normalized_user))
		return FRDPD_PAM_AUTH_ERROR;

	frdpdPamConvData conv_data = { request->password };
	const struct pam_conv conv = { .conv = frdpd_pam_conv, .appdata_ptr = &conv_data };

	int pam_status = ops->start(request->service, normalized_user, &conv, &pamh);
	if (pam_status == PAM_SUCCESS)
	{
		if (!frdpd_string_is_empty(request->rhost))
			pam_status = ops->set_item(pamh, PAM_RHOST, request->rhost);
	}
	if (pam_status == PAM_SUCCESS)
		pam_status = ops->set_item(pamh, PAM_TTY, "rdp");
	if (pam_status == PAM_SUCCESS)
		pam_status = ops->set_item(pamh, PAM_RUSER, normalized_user);

	if (pam_status == PAM_SUCCESS)
		pam_status = ops->set_item(pamh, PAM_AUTHTOK, request->password);

	if (pam_status == PAM_SUCCESS)
		pam_status = ops->authenticate(pamh, 0);

	frdpdPamAuthStatus status = frdpd_pam_authenticate_status_from_pam(pam_status);
	if (status == FRDPD_PAM_AUTH_OK)
	{
		pam_status = ops->acct_mgmt(pamh, 0);
		status = frdpd_pam_account_status_from_pam(pam_status);
		if (status == FRDPD_PAM_AUTH_OK)
		{
			pam_status = ops->setcred(pamh, PAM_ESTABLISH_CRED);
			if (pam_status == PAM_SUCCESS)
			{
				credentials_established = TRUE;
				status = FRDPD_PAM_AUTH_OK;
			}
			else
				status = FRDPD_PAM_AUTH_ERROR;
		}
	}

	if ((status == FRDPD_PAM_AUTH_OK) && request->open_session)
	{
		pam_status = ops->open_session(pamh, 0);
		if (pam_status == PAM_SUCCESS)
		{
			(void)ops->set_item(pamh, PAM_AUTHTOK, "");
			request->pam_handle = pamh;
			request->pam_credentials_established = credentials_established;
			request->pam_session_open = TRUE;
			credentials_established = FALSE;
			pamh = NULL;
		}
		else
			status = FRDPD_PAM_AUTH_ERROR;
	}

	if (pamh)
	{
		(void)ops->set_item(pamh, PAM_AUTHTOK, "");
		if (credentials_established)
		{
			const int cred_status = ops->setcred(pamh, PAM_DELETE_CRED);
			if ((status == FRDPD_PAM_AUTH_OK) && (cred_status != PAM_SUCCESS))
			{
				pam_status = cred_status;
				status = FRDPD_PAM_AUTH_ERROR;
			}
		}
		const int end_status = ops->end(pamh, pam_status);
		if ((pam_status == PAM_SUCCESS) && (end_status != PAM_SUCCESS))
		{
			pam_status = end_status;
			status = FRDPD_PAM_AUTH_ERROR;
		}
	}

	request->pam_status = pam_status;
	if (status == FRDPD_PAM_AUTH_OK)
	{
		request->normalized_user = normalized_user;
		normalized_user = NULL;
	}
	free(normalized_user);
	return status;
}

frdpdPamAuthStatus frdpd_pam_authenticate(frdpdPamAuthRequest* request)
{
	return frdpd_pam_authenticate_internal(request, &g_frdpd_pam_default_ops);
}

#ifdef FRDPD_PAM_TESTING
frdpdPamAuthStatus frdpd_pam_authenticate_with_ops(frdpdPamAuthRequest* request,
                                                   const frdpdPamOps* ops)
{
	return frdpd_pam_authenticate_internal(request, ops);
}
#endif

int frdpd_pam_close_session(void* pam_handle, const char* pam_user,
                            BOOL pam_credentials_established, BOOL pam_session_open)
{
	pam_handle_t* pamh = (pam_handle_t*)pam_handle;
	int status = PAM_SUCCESS;
	int cred_status = PAM_SUCCESS;
	int end_status = PAM_SUCCESS;

	WINPR_UNUSED(pam_user);
	if (!pamh)
		return PAM_SUCCESS;

	(void)pam_set_item(pamh, PAM_AUTHTOK, "");
	if (pam_session_open)
		status = pam_close_session(pamh, 0);
	if (pam_credentials_established)
	{
		cred_status = pam_setcred(pamh, PAM_DELETE_CRED);
		if ((status == PAM_SUCCESS) && (cred_status != PAM_SUCCESS))
			status = cred_status;
	}
	end_status = pam_end(pamh, status);
	if ((status == PAM_SUCCESS) && (end_status != PAM_SUCCESS))
		status = end_status;
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

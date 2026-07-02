/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Experimental frdpd PAM authentication helper
 *
 * Licensed under the Apache License, Version 2.0.
 */

#ifndef FREERDP_SERVER_FRDPD_PAM_H
#define FREERDP_SERVER_FRDPD_PAM_H

#include <winpr/wtypes.h>

#if defined(HAVE_PAM_PAM_APPL_H)
#include <pam/pam_appl.h>
#else
#include <security/pam_appl.h>
#endif

typedef enum
{
	FRDPD_PAM_AUTH_OK = 0,
	FRDPD_PAM_AUTH_DENIED,
	FRDPD_PAM_AUTH_ACCOUNT_DENIED,
	FRDPD_PAM_AUTH_ERROR
} frdpdPamAuthStatus;

typedef enum
{
	FRDPD_DOMAIN_PLAIN = 0,
	FRDPD_DOMAIN_DOWNLEVEL,
	FRDPD_DOMAIN_UPN,
	FRDPD_DOMAIN_AUTO
} frdpdDomainMode;

typedef struct
{
	const char* service;
	const char* user;
	const char* domain;
	const char* password;
	const char* rhost;
	frdpdDomainMode domain_mode;
	BOOL open_session;
	void* pam_handle;
	BOOL pam_credentials_established;
	BOOL pam_session_open;
	int pam_status;
	char* normalized_user;
} frdpdPamAuthRequest;

#ifdef FRDPD_PAM_TESTING
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

BOOL frdpd_pam_build_user(const char* user, const char* domain, frdpdDomainMode mode,
                          char** normalized_user);
void frdpd_pam_clear_secret(char* secret);
int frdpd_pam_answer_conversation(int num_msg, const struct pam_message** msg,
                                  struct pam_response** resp, const char* password);
frdpdPamAuthStatus frdpd_pam_authenticate_status_from_pam(int pam_status);
frdpdPamAuthStatus frdpd_pam_account_status_from_pam(int pam_status);
frdpdPamAuthStatus frdpd_pam_authenticate(frdpdPamAuthRequest* request);
#ifdef FRDPD_PAM_TESTING
frdpdPamAuthStatus frdpd_pam_authenticate_with_ops(frdpdPamAuthRequest* request,
                                                   const frdpdPamOps* ops);
#endif
int frdpd_pam_close_session(void* pam_handle, const char* pam_user,
                            BOOL pam_credentials_established, BOOL pam_session_open);
const char* frdpd_pam_auth_status_string(frdpdPamAuthStatus status);

#endif /* FREERDP_SERVER_FRDPD_PAM_H */

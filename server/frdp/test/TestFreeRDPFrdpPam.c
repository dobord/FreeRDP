#include "frdpd/frdpd_pam.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
	int authenticate_status;
	int account_status;
	int setcred_establish_status;
	int setcred_delete_status;
	int open_session_status;
	int end_status;
	int start_calls;
	int set_item_calls;
	int authenticate_calls;
	int account_calls;
	int setcred_establish_calls;
	int setcred_delete_calls;
	int open_session_calls;
	int end_calls;
	char service[64];
	char user[128];
	char rhost[128];
	char tty[32];
	char ruser[128];
	char authtok[128];
	int authtok_clears;
} fakePamState;

static fakePamState g_fake_pam;

static void free_pam_responses(struct pam_response* responses, int count)
{
	if (!responses)
		return;
	for (int x = 0; x < count; x++)
	{
		frdpd_pam_clear_secret(responses[x].resp);
		free(responses[x].resp);
	}
	free(responses);
}

static void fake_pam_reset(void)
{
	memset(&g_fake_pam, 0, sizeof(g_fake_pam));
	g_fake_pam.authenticate_status = PAM_SUCCESS;
	g_fake_pam.account_status = PAM_SUCCESS;
	g_fake_pam.setcred_establish_status = PAM_SUCCESS;
	g_fake_pam.setcred_delete_status = PAM_SUCCESS;
	g_fake_pam.open_session_status = PAM_SUCCESS;
	g_fake_pam.end_status = PAM_SUCCESS;
}

static void fake_copy(char* dst, size_t dst_size, const char* src)
{
	if (!dst || (dst_size == 0))
		return;
	(void)snprintf(dst, dst_size, "%s", src ? src : "");
}

static int fake_pam_start(const char* service, const char* user, const struct pam_conv* conv,
                          pam_handle_t** pamh)
{
	(void)conv;
	if (!pamh)
		return PAM_SYSTEM_ERR;
	g_fake_pam.start_calls++;
	fake_copy(g_fake_pam.service, sizeof(g_fake_pam.service), service);
	fake_copy(g_fake_pam.user, sizeof(g_fake_pam.user), user);
	*pamh = (pam_handle_t*)&g_fake_pam;
	return PAM_SUCCESS;
}

static int fake_pam_set_item(pam_handle_t* pamh, int item_type, const void* item)
{
	if (pamh != (pam_handle_t*)&g_fake_pam)
		return PAM_SYSTEM_ERR;

	g_fake_pam.set_item_calls++;
	switch (item_type)
	{
		case PAM_RHOST:
			fake_copy(g_fake_pam.rhost, sizeof(g_fake_pam.rhost), (const char*)item);
			break;
		case PAM_TTY:
			fake_copy(g_fake_pam.tty, sizeof(g_fake_pam.tty), (const char*)item);
			break;
		case PAM_RUSER:
			fake_copy(g_fake_pam.ruser, sizeof(g_fake_pam.ruser), (const char*)item);
			break;
		case PAM_AUTHTOK:
			fake_copy(g_fake_pam.authtok, sizeof(g_fake_pam.authtok), (const char*)item);
			if (!item || (((const char*)item)[0] == '\0'))
				g_fake_pam.authtok_clears++;
			break;
		default:
			break;
	}
	return PAM_SUCCESS;
}

static int fake_pam_authenticate(pam_handle_t* pamh, int flags)
{
	(void)flags;
	if (pamh != (pam_handle_t*)&g_fake_pam)
		return PAM_SYSTEM_ERR;
	g_fake_pam.authenticate_calls++;
	return g_fake_pam.authenticate_status;
}

static int fake_pam_acct_mgmt(pam_handle_t* pamh, int flags)
{
	(void)flags;
	if (pamh != (pam_handle_t*)&g_fake_pam)
		return PAM_SYSTEM_ERR;
	g_fake_pam.account_calls++;
	return g_fake_pam.account_status;
}

static int fake_pam_setcred(pam_handle_t* pamh, int flags)
{
	if (pamh != (pam_handle_t*)&g_fake_pam)
		return PAM_SYSTEM_ERR;
	if (flags == PAM_ESTABLISH_CRED)
	{
		g_fake_pam.setcred_establish_calls++;
		return g_fake_pam.setcred_establish_status;
	}
	if (flags == PAM_DELETE_CRED)
	{
		g_fake_pam.setcred_delete_calls++;
		return g_fake_pam.setcred_delete_status;
	}
	return PAM_SYSTEM_ERR;
}

static int fake_pam_open_session(pam_handle_t* pamh, int flags)
{
	(void)flags;
	if (pamh != (pam_handle_t*)&g_fake_pam)
		return PAM_SYSTEM_ERR;
	g_fake_pam.open_session_calls++;
	return g_fake_pam.open_session_status;
}

static int fake_pam_end(pam_handle_t* pamh, int pam_status)
{
	(void)pam_status;
	if (pamh != (pam_handle_t*)&g_fake_pam)
		return PAM_SYSTEM_ERR;
	g_fake_pam.end_calls++;
	return g_fake_pam.end_status;
}

static const frdpdPamOps g_fake_ops = { .start = fake_pam_start,
	                                    .set_item = fake_pam_set_item,
	                                    .authenticate = fake_pam_authenticate,
	                                    .acct_mgmt = fake_pam_acct_mgmt,
	                                    .setcred = fake_pam_setcred,
	                                    .open_session = fake_pam_open_session,
	                                    .end = fake_pam_end };

static int expect_user(const char* user, const char* domain, frdpdDomainMode mode,
                       const char* expected)
{
	char* normalized = NULL;
	const int ok = frdpd_pam_build_user(user, domain, mode, &normalized);
	const int match = ok && normalized && (strcmp(normalized, expected) == 0);

	free(normalized);
	return match ? 0 : -1;
}

static int test_pam_user_normalization(void)
{
	char* normalized = NULL;

	if (frdpd_pam_build_user(NULL, NULL, FRDPD_DOMAIN_PLAIN, &normalized) != FALSE)
		return -1;
	if (normalized)
		return -1;
	if (expect_user("alice", NULL, FRDPD_DOMAIN_PLAIN, "alice") != 0)
		return -1;
	if (expect_user("alice@example.test", "EXAMPLE", FRDPD_DOMAIN_DOWNLEVEL,
	                "alice@example.test") != 0)
		return -1;
	if (expect_user("EXAMPLE\\alice", "example.test", FRDPD_DOMAIN_UPN, "EXAMPLE\\alice") != 0)
		return -1;
	if (expect_user("alice", "EXAMPLE", FRDPD_DOMAIN_AUTO, "EXAMPLE\\alice") != 0)
		return -1;
	if (expect_user("alice", "example.test", FRDPD_DOMAIN_AUTO, "alice@example.test") != 0)
		return -1;
	if (expect_user("alice", "EXAMPLE", FRDPD_DOMAIN_DOWNLEVEL, "EXAMPLE\\alice") != 0)
		return -1;
	if (expect_user("alice", "example.test", FRDPD_DOMAIN_UPN, "alice@example.test") != 0)
		return -1;
	return 0;
}

static int test_pam_conversation_answers_supported_prompts(void)
{
	struct pam_response* responses = NULL;
	const struct pam_message messages[] = {
		{ .msg_style = PAM_PROMPT_ECHO_OFF, .msg = "Password:" },
		{ .msg_style = PAM_TEXT_INFO, .msg = "Info" },
		{ .msg_style = PAM_ERROR_MSG, .msg = "Error" },
	};
	const struct pam_message* message_ptrs[] = { &messages[0], &messages[1],
		                                         &messages[2] };

	if (frdpd_pam_answer_conversation(3, message_ptrs, &responses, "secret") != PAM_SUCCESS)
		return -1;
	if (!responses)
		return -1;
	if (!responses[0].resp || (strcmp(responses[0].resp, "secret") != 0))
		goto fail;
	if (responses[1].resp || responses[2].resp)
		goto fail;
	free_pam_responses(responses, 3);
	return 0;

fail:
	free_pam_responses(responses, 3);
	return -1;
}

static int test_pam_conversation_rejects_unsupported_prompt(void)
{
	struct pam_response* responses = NULL;
	const struct pam_message echo_on = { .msg_style = PAM_PROMPT_ECHO_ON, .msg = "Login:" };
	const struct pam_message unsupported = { .msg_style = 0x7fffffff, .msg = "unsupported" };
	const struct pam_message password_prompts[] = {
		{ .msg_style = PAM_PROMPT_ECHO_OFF, .msg = "Password:" },
		{ .msg_style = PAM_PROMPT_ECHO_OFF, .msg = "Second password:" },
	};
	const struct pam_message* password_prompt_ptrs[] = { &password_prompts[0],
		                                                 &password_prompts[1] };
	const struct pam_message* message_ptr = &echo_on;

	if (frdpd_pam_answer_conversation(1, &message_ptr, &responses, "secret") != PAM_CONV_ERR)
	{
		free_pam_responses(responses, 1);
		return -1;
	}
	if (responses)
	{
		free_pam_responses(responses, 1);
		return -1;
	}

	message_ptr = &unsupported;
	if (frdpd_pam_answer_conversation(1, &message_ptr, &responses, "secret") != PAM_CONV_ERR)
	{
		free_pam_responses(responses, 1);
		return -1;
	}
	if (responses)
	{
		free_pam_responses(responses, 1);
		return -1;
	}
	if (frdpd_pam_answer_conversation(2, password_prompt_ptrs, &responses, "secret") !=
	    PAM_CONV_ERR)
	{
		free_pam_responses(responses, 2);
		return -1;
	}
	if (responses)
	{
		free_pam_responses(responses, 2);
		return -1;
	}
	return 0;
}

static int test_pam_conversation_rejects_bad_arguments(void)
{
	struct pam_response* responses = NULL;
	const struct pam_message message = { .msg_style = PAM_TEXT_INFO, .msg = "info" };
	const struct pam_message* null_message = NULL;
	const struct pam_message* message_ptr = &message;

	if (frdpd_pam_answer_conversation(0, &message_ptr, &responses, "secret") != PAM_CONV_ERR)
		return -1;
	if (frdpd_pam_answer_conversation(1, NULL, &responses, "secret") != PAM_CONV_ERR)
		return -1;
	if (frdpd_pam_answer_conversation(1, &message_ptr, NULL, "secret") != PAM_CONV_ERR)
		return -1;
	if (frdpd_pam_answer_conversation(1, &null_message, &responses, "secret") != PAM_CONV_ERR)
		return -1;
	if (responses)
	{
		free_pam_responses(responses, 1);
		return -1;
	}
	if (frdpd_pam_answer_conversation(33, &message_ptr, &responses, "secret") != PAM_CONV_ERR)
		return -1;
	if (responses)
	{
		free_pam_responses(responses, 1);
		return -1;
	}
	return 0;
}

static int test_pam_status_mapping(void)
{
	if (frdpd_pam_authenticate_status_from_pam(PAM_SUCCESS) != FRDPD_PAM_AUTH_OK)
		return -1;
	if (frdpd_pam_authenticate_status_from_pam(PAM_AUTH_ERR) != FRDPD_PAM_AUTH_DENIED)
		return -1;
	if (frdpd_pam_authenticate_status_from_pam(PAM_USER_UNKNOWN) != FRDPD_PAM_AUTH_DENIED)
		return -1;
	if (frdpd_pam_authenticate_status_from_pam(PAM_PERM_DENIED) != FRDPD_PAM_AUTH_DENIED)
		return -1;
	if (frdpd_pam_authenticate_status_from_pam(PAM_CRED_INSUFFICIENT) != FRDPD_PAM_AUTH_DENIED)
		return -1;
	if (frdpd_pam_authenticate_status_from_pam(PAM_SYSTEM_ERR) != FRDPD_PAM_AUTH_ERROR)
		return -1;
	if (frdpd_pam_account_status_from_pam(PAM_SUCCESS) != FRDPD_PAM_AUTH_OK)
		return -1;
	if (frdpd_pam_account_status_from_pam(PAM_ACCT_EXPIRED) != FRDPD_PAM_AUTH_ACCOUNT_DENIED)
		return -1;
	if (frdpd_pam_account_status_from_pam(PAM_PERM_DENIED) != FRDPD_PAM_AUTH_ACCOUNT_DENIED)
		return -1;
	return 0;
}

static frdpdPamAuthRequest fake_pam_request(BOOL open_session)
{
	frdpdPamAuthRequest request = { .service = "frdpd-test",
		                            .user = "alice",
		                            .domain = "EXAMPLE",
		                            .password = "secret",
		                            .rhost = "client.example.test",
		                            .domain_mode = FRDPD_DOMAIN_DOWNLEVEL,
		                            .open_session = open_session };
	return request;
}

static int test_pam_fake_success_without_session(void)
{
	fake_pam_reset();
	frdpdPamAuthRequest request = fake_pam_request(FALSE);

	const frdpdPamAuthStatus status = frdpd_pam_authenticate_with_ops(&request, &g_fake_ops);
	if (status != FRDPD_PAM_AUTH_OK)
		goto fail;
	if (!request.normalized_user || (strcmp(request.normalized_user, "EXAMPLE\\alice") != 0))
		goto fail;
	if (request.pam_status != PAM_SUCCESS)
		goto fail;
	if (request.pam_handle || request.pam_credentials_established || request.pam_session_open)
		goto fail;
	if ((g_fake_pam.start_calls != 1) || (g_fake_pam.authenticate_calls != 1) ||
	    (g_fake_pam.account_calls != 1) || (g_fake_pam.setcred_establish_calls != 1) ||
	    (g_fake_pam.setcred_delete_calls != 1) || (g_fake_pam.open_session_calls != 0) ||
	    (g_fake_pam.end_calls != 1))
		goto fail;
	if ((strcmp(g_fake_pam.service, "frdpd-test") != 0) ||
	    (strcmp(g_fake_pam.user, "EXAMPLE\\alice") != 0) ||
	    (strcmp(g_fake_pam.rhost, "client.example.test") != 0) ||
	    (strcmp(g_fake_pam.tty, "rdp") != 0) || (strcmp(g_fake_pam.ruser, "EXAMPLE\\alice") != 0) ||
	    (g_fake_pam.authtok_clears != 1))
		goto fail;

	free(request.normalized_user);
	return 0;

fail:
	free(request.normalized_user);
	return -1;
}

static int test_pam_fake_account_denial(void)
{
	fake_pam_reset();
	g_fake_pam.account_status = PAM_ACCT_EXPIRED;
	frdpdPamAuthRequest request = fake_pam_request(FALSE);

	const frdpdPamAuthStatus status = frdpd_pam_authenticate_with_ops(&request, &g_fake_ops);
	if (status != FRDPD_PAM_AUTH_ACCOUNT_DENIED)
		goto fail;
	if (request.normalized_user || request.pam_handle || request.pam_credentials_established ||
	    request.pam_session_open)
		goto fail;
	if (request.pam_status != PAM_ACCT_EXPIRED)
		goto fail;
	if ((g_fake_pam.authenticate_calls != 1) || (g_fake_pam.account_calls != 1) ||
	    (g_fake_pam.setcred_establish_calls != 0) || (g_fake_pam.setcred_delete_calls != 0) ||
	    (g_fake_pam.open_session_calls != 0) || (g_fake_pam.end_calls != 1) ||
	    (g_fake_pam.authtok_clears != 1))
		goto fail;
	return 0;

fail:
	free(request.normalized_user);
	return -1;
}

static int test_pam_fake_session_failure_cleans_credentials(void)
{
	fake_pam_reset();
	g_fake_pam.open_session_status = PAM_SESSION_ERR;
	frdpdPamAuthRequest request = fake_pam_request(TRUE);

	const frdpdPamAuthStatus status = frdpd_pam_authenticate_with_ops(&request, &g_fake_ops);
	if (status != FRDPD_PAM_AUTH_ERROR)
		goto fail;
	if (request.normalized_user || request.pam_handle || request.pam_credentials_established ||
	    request.pam_session_open)
		goto fail;
	if (request.pam_status != PAM_SESSION_ERR)
		goto fail;
	if ((g_fake_pam.setcred_establish_calls != 1) || (g_fake_pam.open_session_calls != 1) ||
	    (g_fake_pam.setcred_delete_calls != 1) || (g_fake_pam.end_calls != 1) ||
	    (g_fake_pam.authtok_clears != 1))
		goto fail;
	return 0;

fail:
	free(request.normalized_user);
	return -1;
}

static int test_pam_fake_session_success_retains_handle(void)
{
	fake_pam_reset();
	frdpdPamAuthRequest request = fake_pam_request(TRUE);

	const frdpdPamAuthStatus status = frdpd_pam_authenticate_with_ops(&request, &g_fake_ops);
	if (status != FRDPD_PAM_AUTH_OK)
		goto fail;
	if (!request.normalized_user || (strcmp(request.normalized_user, "EXAMPLE\\alice") != 0))
		goto fail;
	if (request.pam_handle != (void*)&g_fake_pam)
		goto fail;
	if (!request.pam_credentials_established || !request.pam_session_open)
		goto fail;
	if ((g_fake_pam.setcred_establish_calls != 1) || (g_fake_pam.open_session_calls != 1) ||
	    (g_fake_pam.setcred_delete_calls != 0) || (g_fake_pam.end_calls != 0) ||
	    (g_fake_pam.authtok_clears != 1))
		goto fail;

	free(request.normalized_user);
	return 0;

fail:
	free(request.normalized_user);
	return -1;
}

int TestFreeRDPFrdpPam(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if (test_pam_user_normalization() != 0)
	{
		printf("PAM user normalization test failed\n");
		return -1;
	}
	if (test_pam_conversation_answers_supported_prompts() != 0)
	{
		printf("PAM supported conversation test failed\n");
		return -1;
	}
	if (test_pam_conversation_rejects_unsupported_prompt() != 0)
	{
		printf("PAM unsupported conversation test failed\n");
		return -1;
	}
	if (test_pam_conversation_rejects_bad_arguments() != 0)
	{
		printf("PAM bad argument conversation test failed\n");
		return -1;
	}
	if (test_pam_status_mapping() != 0)
	{
		printf("PAM status mapping test failed\n");
		return -1;
	}
	if (test_pam_fake_success_without_session() != 0)
	{
		printf("PAM fake success lifecycle test failed\n");
		return -1;
	}
	if (test_pam_fake_account_denial() != 0)
	{
		printf("PAM fake account denial test failed\n");
		return -1;
	}
	if (test_pam_fake_session_failure_cleans_credentials() != 0)
	{
		printf("PAM fake session failure cleanup test failed\n");
		return -1;
	}
	if (test_pam_fake_session_success_retains_handle() != 0)
	{
		printf("PAM fake session success test failed\n");
		return -1;
	}
	return 0;
}

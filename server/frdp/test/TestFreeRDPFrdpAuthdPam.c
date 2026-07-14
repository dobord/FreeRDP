#include "frdp-authd/authd_pam.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const void* fake_pam_item = NULL;
static int fake_pam_status = PAM_SUCCESS;
static int fake_pam_auth_status = PAM_SUCCESS;
static int fake_pam_item_type = 0;
static int fake_pam_steps[16] = { 0 };
static size_t fake_pam_step_count = 0;

enum
{
	FAKE_PAM_START = 1,
	FAKE_PAM_RHOST,
	FAKE_PAM_TTY,
	FAKE_PAM_RUSER,
	FAKE_PAM_AUTHENTICATE,
	FAKE_PAM_ACCOUNT,
	FAKE_PAM_GET_USER,
	FAKE_PAM_ESTABLISH,
	FAKE_PAM_DELETE,
	FAKE_PAM_END
};

static int fake_pam_record(int step)
{
	if (fake_pam_step_count >= (sizeof(fake_pam_steps) / sizeof(fake_pam_steps[0])))
		return -1;
	fake_pam_steps[fake_pam_step_count++] = step;
	return 0;
}

static int fake_pam_get_item(const pam_handle_t* pamh, int item_type, const void** item)
{
	if (!pamh || !item)
		return PAM_SYSTEM_ERR;
	if ((fake_pam_step_count > 0) && (fake_pam_record(FAKE_PAM_GET_USER) != 0))
		return PAM_SYSTEM_ERR;
	fake_pam_item_type = item_type;
	*item = fake_pam_item;
	return fake_pam_status;
}

static int fake_pam_start(const char* service, const char* user, const struct pam_conv* conv,
                          pam_handle_t** pamh)
{
	if (!service || strcmp(service, "frdpd") != 0 || !user || strcmp(user, "alias") != 0 ||
	    !conv || conv->conv != frdp_authd_pam_conversation || !conv->appdata_ptr ||
	    strcmp((const char*)conv->appdata_ptr, "secret") != 0 || !pamh ||
	    fake_pam_record(FAKE_PAM_START) != 0)
		return PAM_SYSTEM_ERR;
	*pamh = (pam_handle_t*)1;
	return PAM_SUCCESS;
}

static int fake_pam_set_item(pam_handle_t* pamh, int item_type, const void* item)
{
	int step = 0;

	if (!pamh || !item)
		return PAM_SYSTEM_ERR;
	switch (item_type)
	{
		case PAM_RHOST:
			step = (strcmp((const char*)item, "192.0.2.1") == 0) ? FAKE_PAM_RHOST : 0;
			break;
		case PAM_TTY:
			step = (strcmp((const char*)item, "rdp") == 0) ? FAKE_PAM_TTY : 0;
			break;
		case PAM_RUSER:
			step = (strcmp((const char*)item, "alias") == 0) ? FAKE_PAM_RUSER : 0;
			break;
		default:
			break;
	}
	return (step != 0 && fake_pam_record(step) == 0) ? PAM_SUCCESS : PAM_SYSTEM_ERR;
}

static int fake_pam_authenticate(pam_handle_t* pamh, int flags)
{
	return (pamh && flags == 0 && fake_pam_record(FAKE_PAM_AUTHENTICATE) == 0)
	           ? fake_pam_auth_status
	           : PAM_SYSTEM_ERR;
}

static int fake_pam_account(pam_handle_t* pamh, int flags)
{
	return (pamh && flags == 0 && fake_pam_record(FAKE_PAM_ACCOUNT) == 0) ? PAM_SUCCESS
	                                                                    : PAM_SYSTEM_ERR;
}

static int fake_pam_setcred(pam_handle_t* pamh, int flags)
{
	const int step = (flags == PAM_ESTABLISH_CRED) ? FAKE_PAM_ESTABLISH : FAKE_PAM_DELETE;

	return (pamh && ((flags == PAM_ESTABLISH_CRED) || (flags == PAM_DELETE_CRED)) &&
	        fake_pam_record(step) == 0)
	           ? PAM_SUCCESS
	           : PAM_SYSTEM_ERR;
}

static int fake_pam_end(pam_handle_t* pamh, int pam_status)
{
	return (pamh && pam_status == fake_pam_auth_status && fake_pam_record(FAKE_PAM_END) == 0)
	           ? PAM_SUCCESS
	           : PAM_SYSTEM_ERR;
}

static void free_authd_pam_responses(struct pam_response *responses, int count)
{
	if (!responses)
		return;
	frdp_authd_pam_clear_responses(responses, count);
	free(responses);
}

static int test_authd_pam_conversation_answers_password_prompt(void)
{
	struct pam_response *responses = NULL;
	const struct pam_message messages[] = {
		{ .msg_style = PAM_PROMPT_ECHO_OFF, .msg = "Password:" },
		{ .msg_style = PAM_TEXT_INFO, .msg = "Info" },
		{ .msg_style = PAM_ERROR_MSG, .msg = "Error" },
	};
	const struct pam_message *message_ptrs[] = { &messages[0], &messages[1], &messages[2] };

	if (frdp_authd_pam_conversation(3, message_ptrs, &responses, "secret") != PAM_SUCCESS)
		return -1;
	if (!responses)
		return -1;
	if (!responses[0].resp || strcmp(responses[0].resp, "secret") != 0)
		goto fail;
	if (responses[1].resp || responses[2].resp)
		goto fail;
	free_authd_pam_responses(responses, 3);
	return 0;

fail:
	free_authd_pam_responses(responses, 3);
	return -1;
}

static int expect_conversation_error(const struct pam_message *message)
{
	struct pam_response *responses = NULL;
	const struct pam_message *message_ptr = message;

	if (frdp_authd_pam_conversation(1, &message_ptr, &responses, "secret") != PAM_CONV_ERR)
	{
		free_authd_pam_responses(responses, 1);
		return -1;
	}
	if (responses)
	{
		free_authd_pam_responses(responses, 1);
		return -1;
	}
	return 0;
}

static int test_authd_pam_conversation_rejects_interactive_prompts(void)
{
	const struct pam_message echo_on = { .msg_style = PAM_PROMPT_ECHO_ON, .msg = "Login:" };
	const struct pam_message unsupported = { .msg_style = 0x7fffffff, .msg = "unsupported" };
	const struct pam_message password_prompts[] = {
		{ .msg_style = PAM_PROMPT_ECHO_OFF, .msg = "Password:" },
		{ .msg_style = PAM_PROMPT_ECHO_OFF, .msg = "Second password:" },
	};
	const struct pam_message* password_prompt_ptrs[] = { &password_prompts[0],
		                                                 &password_prompts[1] };
	struct pam_response* responses = NULL;

	if (expect_conversation_error(&echo_on) != 0)
		return -1;
	if (expect_conversation_error(&unsupported) != 0)
		return -1;
	if (frdp_authd_pam_conversation(2, password_prompt_ptrs, &responses, "secret") !=
	    PAM_CONV_ERR)
	{
		free_authd_pam_responses(responses, 2);
		return -1;
	}
	if (responses)
	{
		free_authd_pam_responses(responses, 2);
		return -1;
	}
	return 0;
}

static int test_authd_pam_conversation_rejects_bad_arguments(void)
{
	struct pam_response *responses = NULL;
	const struct pam_message message = { .msg_style = PAM_TEXT_INFO, .msg = "Info" };
	const struct pam_message *message_ptr = &message;
	const struct pam_message *null_message = NULL;

	if (frdp_authd_pam_conversation(0, &message_ptr, &responses, "secret") != PAM_CONV_ERR)
		return -1;
	if (responses)
		return -1;
	if (frdp_authd_pam_conversation(1, NULL, &responses, "secret") != PAM_CONV_ERR)
		return -1;
	if (responses)
		return -1;
	if (frdp_authd_pam_conversation(1, &message_ptr, NULL, "secret") != PAM_CONV_ERR)
		return -1;
	if (frdp_authd_pam_conversation(1, &null_message, &responses, "secret") != PAM_CONV_ERR)
		return -1;
	if (responses)
		return -1;
	if (frdp_authd_pam_conversation(33, &message_ptr, &responses, "secret") != PAM_CONV_ERR)
		return -1;
	if (responses)
		return -1;
	return 0;
}

static int test_authd_pam_status_classification(void)
{
	if ((frdp_authd_pam_auth_status(PAM_SUCCESS) != FRDP_AUTHD_PAM_OK) ||
	    (frdp_authd_pam_auth_status(PAM_AUTH_ERR) != FRDP_AUTHD_PAM_DENIED) ||
	    (frdp_authd_pam_auth_status(PAM_USER_UNKNOWN) != FRDP_AUTHD_PAM_DENIED) ||
	    (frdp_authd_pam_auth_status(PAM_CRED_INSUFFICIENT) != FRDP_AUTHD_PAM_ERROR) ||
	    (frdp_authd_pam_auth_status(PAM_AUTHINFO_UNAVAIL) != FRDP_AUTHD_PAM_ERROR) ||
	    (frdp_authd_pam_auth_status(PAM_SYSTEM_ERR) != FRDP_AUTHD_PAM_ERROR))
		return -1;
	if ((frdp_authd_pam_account_status(PAM_SUCCESS) != FRDP_AUTHD_PAM_OK) ||
	    (frdp_authd_pam_account_status(PAM_ACCT_EXPIRED) != FRDP_AUTHD_PAM_DENIED) ||
	    (frdp_authd_pam_account_status(PAM_AUTH_ERR) != FRDP_AUTHD_PAM_DENIED) ||
	    (frdp_authd_pam_account_status(PAM_NEW_AUTHTOK_REQD) != FRDP_AUTHD_PAM_DENIED) ||
	    (frdp_authd_pam_account_status(PAM_SYSTEM_ERR) != FRDP_AUTHD_PAM_ERROR))
		return -1;
	return 0;
}

static int expect_pam_user_failure(const void* item, int status, char* output,
                                   size_t output_size)
{
	fake_pam_item = item;
	fake_pam_status = status;
	memset(output, 0xa5, output_size);
	if (frdp_authd_pam_copy_user((const pam_handle_t*)1, fake_pam_get_item, output,
	                             output_size) == 0)
		return -1;
	for (size_t x = 0; x < output_size; x++)
	{
		if (output[x] != '\0')
			return -1;
	}
	return 0;
}

static int test_authd_pam_copies_canonical_user(void)
{
	char output[64] = { 0 };

	fake_pam_item = "alice@example.com";
	fake_pam_status = PAM_SUCCESS;
	fake_pam_item_type = 0;
	if (frdp_authd_pam_copy_user((const pam_handle_t*)1, fake_pam_get_item, output,
	                             sizeof(output)) != 0)
		return -1;
	if ((fake_pam_item_type != PAM_USER) || strcmp(output, "alice@example.com") != 0)
		return -1;
	return 0;
}

static int test_authd_pam_rejects_invalid_canonical_user(void)
{
	char output[64] = { 0 };
	char unterminated[sizeof(output)];

	memset(unterminated, 'a', sizeof(unterminated));
	if (expect_pam_user_failure(NULL, PAM_SUCCESS, output, sizeof(output)) != 0 ||
	    expect_pam_user_failure("", PAM_SUCCESS, output, sizeof(output)) != 0 ||
	    expect_pam_user_failure("alice\nadmin", PAM_SUCCESS, output, sizeof(output)) != 0 ||
	    expect_pam_user_failure(unterminated, PAM_SUCCESS, output, sizeof(output)) != 0 ||
	    expect_pam_user_failure("alice", PAM_SYSTEM_ERR, output, sizeof(output)) != 0)
		return -1;
	if (frdp_authd_pam_copy_user(NULL, fake_pam_get_item, output, sizeof(output)) == 0 ||
	    frdp_authd_pam_copy_user((const pam_handle_t*)1, NULL, output, sizeof(output)) == 0 ||
	    frdp_authd_pam_copy_user((const pam_handle_t*)1, fake_pam_get_item, NULL,
	                             sizeof(output)) == 0 ||
	    frdp_authd_pam_copy_user((const pam_handle_t*)1, fake_pam_get_item, output, 0) == 0)
		return -1;
	return 0;
}

static int test_authd_pam_canonical_user_lifecycle(void)
{
	static const int expected[] = {
		FAKE_PAM_START,        FAKE_PAM_RHOST,    FAKE_PAM_TTY,       FAKE_PAM_RUSER,
		FAKE_PAM_AUTHENTICATE, FAKE_PAM_ACCOUNT,  FAKE_PAM_GET_USER,  FAKE_PAM_ESTABLISH,
		FAKE_PAM_DELETE,       FAKE_PAM_END
	};
	const frdpAuthdPamOps ops = {
		fake_pam_start,       fake_pam_set_item, fake_pam_authenticate, fake_pam_account,
		fake_pam_get_item,    fake_pam_setcred,  fake_pam_end
	};
	char output[64] = { 0 };
	char password[] = "secret";

	memset(fake_pam_steps, 0, sizeof(fake_pam_steps));
	fake_pam_step_count = 0;
	fake_pam_item = "canonical-alice";
	fake_pam_status = PAM_SUCCESS;
	fake_pam_auth_status = PAM_SUCCESS;
	if (frdp_authd_pam_authenticate_with_ops(&ops, "frdpd", "192.0.2.1", "alias", password,
	                                         output, sizeof(output)) != FRDP_AUTHD_PAM_OK ||
	    strcmp(output, "canonical-alice") != 0 ||
	    fake_pam_step_count != (sizeof(expected) / sizeof(expected[0])) ||
	    memcmp(fake_pam_steps, expected, sizeof(expected)) != 0)
		return -1;
	return 0;
}

static int test_authd_pam_denied_canonical_user(void)
{
	static const int expected[] = { FAKE_PAM_START, FAKE_PAM_RHOST, FAKE_PAM_TTY,
		                              FAKE_PAM_RUSER, FAKE_PAM_AUTHENTICATE,
		                              FAKE_PAM_GET_USER, FAKE_PAM_END };
	const frdpAuthdPamOps ops = {
		fake_pam_start,       fake_pam_set_item, fake_pam_authenticate, fake_pam_account,
		fake_pam_get_item,    fake_pam_setcred,  fake_pam_end
	};
	char output[64] = { 0 };
	char password[] = "secret";
	int rc = -1;

	memset(fake_pam_steps, 0, sizeof(fake_pam_steps));
	fake_pam_step_count = 0;
	fake_pam_item = "canonical-alice";
	fake_pam_status = PAM_SUCCESS;
	fake_pam_auth_status = PAM_AUTH_ERR;
	if ((frdp_authd_pam_authenticate_with_ops(&ops, "frdpd", "192.0.2.1", "alias", password,
	                                          output, sizeof(output)) == FRDP_AUTHD_PAM_DENIED) &&
	    (strcmp(output, "canonical-alice") == 0) &&
	    (fake_pam_step_count == (sizeof(expected) / sizeof(expected[0]))) &&
	    (memcmp(fake_pam_steps, expected, sizeof(expected)) == 0))
		rc = 0;
	fake_pam_auth_status = PAM_SUCCESS;
	return rc;
}

int TestFreeRDPFrdpAuthdPam(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	if (test_authd_pam_conversation_answers_password_prompt() != 0)
	{
		printf("authd PAM password conversation test failed\n");
		return -1;
	}
	if (test_authd_pam_conversation_rejects_interactive_prompts() != 0)
	{
		printf("authd PAM interactive prompt rejection test failed\n");
		return -1;
	}
	if (test_authd_pam_conversation_rejects_bad_arguments() != 0)
	{
		printf("authd PAM bad argument test failed\n");
		return -1;
	}
	if (test_authd_pam_status_classification() != 0)
	{
		printf("authd PAM status classification test failed\n");
		return -1;
	}
	if (test_authd_pam_copies_canonical_user() != 0)
	{
		printf("authd PAM canonical user test failed\n");
		return -1;
	}
	if (test_authd_pam_rejects_invalid_canonical_user() != 0)
	{
		printf("authd PAM invalid canonical user rejection test failed\n");
		return -1;
	}
	if (test_authd_pam_canonical_user_lifecycle() != 0)
	{
		printf("authd PAM canonical user lifecycle test failed\n");
		return -1;
	}
	if (test_authd_pam_denied_canonical_user() != 0)
	{
		printf("authd PAM denied canonical user test failed\n");
		return -1;
	}
	return 0;
}

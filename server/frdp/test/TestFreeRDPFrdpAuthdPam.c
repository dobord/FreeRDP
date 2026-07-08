#include "frdp-authd/authd_pam.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
	return 0;
}

#include "frdp-sesmand/sesmand_pam.h"

#include <stdio.h>
#include <stdlib.h>

static void free_sesmand_pam_responses(struct pam_response *responses, int count)
{
	if (!responses)
		return;
	frdp_sesmand_pam_clear_responses(responses, count);
	free(responses);
}

static int test_sesmand_pam_conversation_accepts_informational_messages(void)
{
	struct pam_response *responses = NULL;
	const struct pam_message messages[] = {
		{ .msg_style = PAM_TEXT_INFO, .msg = "Info" },
		{ .msg_style = PAM_ERROR_MSG, .msg = "Error" },
	};
	const struct pam_message *message_ptrs[] = { &messages[0], &messages[1] };

	if (frdp_sesmand_pam_conversation(2, message_ptrs, &responses, NULL) != PAM_SUCCESS)
		return -1;
	if (!responses)
		return -1;
	if (responses[0].resp || responses[1].resp)
	{
		free_sesmand_pam_responses(responses, 2);
		return -1;
	}
	free_sesmand_pam_responses(responses, 2);
	return 0;
}

static int expect_conversation_error(const struct pam_message *message)
{
	struct pam_response *responses = NULL;
	const struct pam_message *message_ptr = message;

	if (frdp_sesmand_pam_conversation(1, &message_ptr, &responses, NULL) != PAM_CONV_ERR)
	{
		free_sesmand_pam_responses(responses, 1);
		return -1;
	}
	if (responses)
	{
		free_sesmand_pam_responses(responses, 1);
		return -1;
	}
	return 0;
}

static int test_sesmand_pam_conversation_rejects_prompts(void)
{
	const struct pam_message echo_off = { .msg_style = PAM_PROMPT_ECHO_OFF, .msg = "Password:" };
	const struct pam_message echo_on = { .msg_style = PAM_PROMPT_ECHO_ON, .msg = "Login:" };
	const struct pam_message unsupported = { .msg_style = 0x7fffffff, .msg = "Unsupported" };

	if (expect_conversation_error(&echo_off) != 0)
		return -1;
	if (expect_conversation_error(&echo_on) != 0)
		return -1;
	if (expect_conversation_error(&unsupported) != 0)
		return -1;
	return 0;
}

static int test_sesmand_pam_conversation_rejects_bad_arguments(void)
{
	struct pam_response *responses = NULL;
	const struct pam_message message = { .msg_style = PAM_TEXT_INFO, .msg = "Info" };
	const struct pam_message *message_ptr = &message;
	const struct pam_message *null_message = NULL;

	if (frdp_sesmand_pam_conversation(0, &message_ptr, &responses, NULL) != PAM_CONV_ERR)
		return -1;
	if (responses)
		return -1;
	if (frdp_sesmand_pam_conversation(1, NULL, &responses, NULL) != PAM_CONV_ERR)
		return -1;
	if (responses)
		return -1;
	if (frdp_sesmand_pam_conversation(1, &message_ptr, NULL, NULL) != PAM_CONV_ERR)
		return -1;
	if (frdp_sesmand_pam_conversation(1, &null_message, &responses, NULL) != PAM_CONV_ERR)
		return -1;
	if (responses)
		return -1;
	if (frdp_sesmand_pam_conversation(33, &message_ptr, &responses, NULL) != PAM_CONV_ERR)
		return -1;
	if (responses)
		return -1;
	return 0;
}

int TestFreeRDPFrdpSesmandPam(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	if (test_sesmand_pam_conversation_accepts_informational_messages() != 0)
	{
		printf("sesmand PAM informational conversation test failed\n");
		return -1;
	}
	if (test_sesmand_pam_conversation_rejects_prompts() != 0)
	{
		printf("sesmand PAM prompt rejection test failed\n");
		return -1;
	}
	if (test_sesmand_pam_conversation_rejects_bad_arguments() != 0)
	{
		printf("sesmand PAM bad argument test failed\n");
		return -1;
	}
	return 0;
}

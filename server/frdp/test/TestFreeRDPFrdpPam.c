#include "frdpd/frdpd_pam.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
		{ .msg_style = PAM_PROMPT_ECHO_ON, .msg = "Ignored:" },
		{ .msg_style = PAM_TEXT_INFO, .msg = "Info" },
		{ .msg_style = PAM_ERROR_MSG, .msg = "Error" },
	};
	const struct pam_message* message_ptrs[] = { &messages[0], &messages[1], &messages[2],
		                                         &messages[3] };

	if (frdpd_pam_answer_conversation(4, message_ptrs, &responses, "secret") != PAM_SUCCESS)
		return -1;
	if (!responses)
		return -1;
	if (!responses[0].resp || (strcmp(responses[0].resp, "secret") != 0))
		goto fail;
	if (!responses[1].resp || (responses[1].resp[0] != '\0'))
		goto fail;
	if (responses[2].resp || responses[3].resp)
		goto fail;
	free_pam_responses(responses, 4);
	return 0;

fail:
	free_pam_responses(responses, 4);
	return -1;
}

static int test_pam_conversation_rejects_unsupported_prompt(void)
{
	struct pam_response* responses = NULL;
	const struct pam_message message = { .msg_style = 0x7fffffff, .msg = "unsupported" };
	const struct pam_message* message_ptr = &message;

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
	return 0;
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
	return 0;
}

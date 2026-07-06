#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "frdpd/frdpd_pam.h"

#define FRDPD_PAM_FUZZ_MAX_SIZE 512U
#define FRDPD_PAM_FUZZ_MAX_MESSAGES 8U
#define FRDPD_PAM_FUZZ_MAX_TEXT 32U

static int fuzz_style(uint8_t selector)
{
	switch (selector % 5U)
	{
		case 0:
			return PAM_PROMPT_ECHO_OFF;
		case 1:
			return PAM_TEXT_INFO;
		case 2:
			return PAM_ERROR_MSG;
		case 3:
			return PAM_PROMPT_ECHO_ON;
		default:
			return 0x7fffffff;
	}
}

static void copy_fuzz_text(char* destination, size_t destination_size, const uint8_t* data,
                           size_t size, size_t offset)
{
	size_t copy_len = 0;

	if (!destination || (destination_size == 0))
		return;
	destination[0] = '\0';
	if (!data || (offset >= size))
		return;

	copy_len = size - offset;
	if (copy_len >= destination_size)
		copy_len = destination_size - 1U;
	memcpy(destination, data + offset, copy_len);
	destination[copy_len] = '\0';
}

static void free_frdpd_pam_responses(struct pam_response* responses, int count)
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

int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
	struct pam_message messages[FRDPD_PAM_FUZZ_MAX_MESSAGES] = { 0 };
	const struct pam_message* message_ptrs[FRDPD_PAM_FUZZ_MAX_MESSAGES] = { 0 };
	char message_text[FRDPD_PAM_FUZZ_MAX_MESSAGES][FRDPD_PAM_FUZZ_MAX_TEXT] = { 0 };
	char password[FRDPD_PAM_FUZZ_MAX_TEXT] = { 0 };
	struct pam_response* responses = NULL;
	size_t count = 1;
	size_t offset = 0;
	const char* password_arg = password;

	if (!Data || (Size > FRDPD_PAM_FUZZ_MAX_SIZE))
		return 0;

	if (Size > 0)
	{
		count = (Data[0] % FRDPD_PAM_FUZZ_MAX_MESSAGES) + 1U;
		offset = 1U;
	}
	copy_fuzz_text(password, sizeof(password), Data, Size, offset);
	if ((Size > 1U) && ((Data[1] & 0x80U) != 0))
		password_arg = NULL;

	for (size_t x = 0; x < count; x++)
	{
		const size_t selector_offset = offset + (x * 3U);
		const uint8_t style_selector = (selector_offset < Size) ? Data[selector_offset] : (uint8_t)x;
		const size_t text_offset = offset + (x * 5U);

		messages[x].msg_style = fuzz_style(style_selector);
		copy_fuzz_text(message_text[x], sizeof(message_text[x]), Data, Size, text_offset);
		messages[x].msg = message_text[x];
		message_ptrs[x] = &messages[x];

		if ((selector_offset + 1U < Size) && ((Data[selector_offset + 1U] & 0x40U) != 0))
			message_ptrs[x] = NULL;
	}

	(void)frdpd_pam_answer_conversation((int)count, message_ptrs, &responses, password_arg);
	free_frdpd_pam_responses(responses, (int)count);
	return 0;
}

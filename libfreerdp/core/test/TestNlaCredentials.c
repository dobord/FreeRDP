#include <string.h>

#include <winpr/sspi.h>

#include "../nla_credentials.h"

typedef struct
{
	BOOL source_result;
	BOOL transform_result;
	BOOL sink_result;
	BOOL source_called;
	BOOL transform_called;
	BOOL sink_called;
	const char* source_data;
	const char* transform_data;
} credential_steps;

static BOOL set_buffer(SecBuffer* buffer, const char* value)
{
	const size_t length = strlen(value);
	if (!sspi_SecBufferAlloc(buffer, (ULONG)length))
		return FALSE;
	memcpy(buffer->pvBuffer, value, length);
	return TRUE;
}

static BOOL source_step(void* context, SecBuffer* output)
{
	credential_steps* steps = context;
	steps->source_called = TRUE;
	return set_buffer(output, steps->source_data) && steps->source_result;
}

static BOOL transform_step(void* context, const SecBuffer* input, SecBuffer* output)
{
	credential_steps* steps = context;
	steps->transform_called = TRUE;
	if (!input->pvBuffer || (input->cbBuffer < 1))
		return FALSE;
	return set_buffer(output, steps->transform_data) && steps->transform_result;
}

static BOOL sink_step(void* context, SecBuffer* input)
{
	credential_steps* steps = context;
	steps->sink_called = TRUE;
	if (!input->pvBuffer || (input->cbBuffer < 1))
		return FALSE;
	return steps->sink_result;
}

static BOOL buffer_is_empty(const SecBuffer* buffer)
{
	return (buffer->pvBuffer == NULL) && (buffer->cbBuffer == 0);
}

static int test_encode_encrypt(BOOL source_result, BOOL transform_result, BOOL expected_result)
{
	credential_steps steps = {
		source_result,           transform_result,       TRUE, FALSE, FALSE, FALSE,
		"plaintext-credentials", "encrypted-credentials"
	};
	SecBuffer plaintext = { 0 };
	SecBuffer ciphertext = { 0 };
	int rc = -1;

	if (!set_buffer(&ciphertext, "stale-ciphertext"))
		goto cleanup;
	if (nla_credentials_encode_encrypt(&steps, &plaintext, &ciphertext, source_step,
	                                   transform_step) != expected_result)
		goto cleanup;
	if (!steps.source_called || (steps.transform_called != source_result))
		goto cleanup;
	if (!buffer_is_empty(&plaintext))
		goto cleanup;
	if (expected_result)
	{
		if (!ciphertext.pvBuffer || (ciphertext.cbBuffer < 1))
			goto cleanup;
	}
	else if (!buffer_is_empty(&ciphertext))
		goto cleanup;
	rc = 0;

cleanup:
	sspi_SecBufferFree(&ciphertext);
	sspi_SecBufferFree(&plaintext);
	return rc;
}

static int test_decrypt_decode(BOOL transform_result, BOOL sink_result, BOOL expected_result)
{
	credential_steps steps = { TRUE,     transform_result,       sink_result, FALSE, FALSE, FALSE,
		                       "unused", "decrypted-credentials" };
	SecBuffer ciphertext = { 0 };
	SecBuffer plaintext = { 0 };
	int rc = -1;

	if (!set_buffer(&ciphertext, "encrypted-credentials") ||
	    !set_buffer(&plaintext, "stale-plaintext"))
		goto cleanup;
	if (nla_credentials_decrypt_decode(&steps, &ciphertext, &plaintext, transform_step,
	                                   sink_step) != expected_result)
		goto cleanup;
	if (!steps.transform_called || (steps.sink_called != transform_result))
		goto cleanup;
	if (!buffer_is_empty(&plaintext) || !buffer_is_empty(&ciphertext))
		goto cleanup;
	rc = 0;

cleanup:
	sspi_SecBufferFree(&plaintext);
	sspi_SecBufferFree(&ciphertext);
	return rc;
}

static int test_missing_ciphertext_is_cleared(void)
{
	credential_steps steps = { TRUE, TRUE, TRUE, FALSE, FALSE, FALSE, "unused", "unused" };
	SecBuffer ciphertext = { 0 };
	SecBuffer plaintext = { 0 };
	int rc = -1;

	if (!set_buffer(&plaintext, "stale-plaintext"))
		goto cleanup;
	if (nla_credentials_decrypt_decode(&steps, &ciphertext, &plaintext, transform_step, sink_step))
		goto cleanup;
	if (steps.transform_called || steps.sink_called || !buffer_is_empty(&plaintext) ||
	    !buffer_is_empty(&ciphertext))
		goto cleanup;
	rc = 0;

cleanup:
	sspi_SecBufferFree(&plaintext);
	sspi_SecBufferFree(&ciphertext);
	return rc;
}

int TestNlaCredentials(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if ((test_encode_encrypt(FALSE, TRUE, FALSE) < 0) ||
	    (test_encode_encrypt(TRUE, FALSE, FALSE) < 0) ||
	    (test_encode_encrypt(TRUE, TRUE, TRUE) < 0) ||
	    (test_decrypt_decode(FALSE, TRUE, FALSE) < 0) ||
	    (test_decrypt_decode(TRUE, FALSE, FALSE) < 0) ||
	    (test_decrypt_decode(TRUE, TRUE, TRUE) < 0))
		return -1;
	return test_missing_ciphertext_is_cleared();
}

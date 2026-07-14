/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * CredSSP Credential Buffer Lifecycle
 *
 * Licensed under the Apache License, Version 2.0.
 */

#include <winpr/assert.h>

#include "nla_credentials.h"

BOOL nla_credentials_encode_encrypt(void* context, SecBuffer* plaintext, SecBuffer* ciphertext,
                                    nla_credentials_source_fn encode,
                                    nla_credentials_transform_fn encrypt)
{
	BOOL rc = FALSE;

	WINPR_ASSERT(plaintext);
	WINPR_ASSERT(ciphertext);
	WINPR_ASSERT(encode);
	WINPR_ASSERT(encrypt);

	sspi_SecBufferFree(ciphertext);
	if (!encode(context, plaintext))
		goto out;

	rc = encrypt(context, plaintext, ciphertext);
	if (!rc)
		sspi_SecBufferFree(ciphertext);

out:
	sspi_SecBufferFree(plaintext);
	return rc;
}

BOOL nla_credentials_decrypt_decode(void* context, SecBuffer* ciphertext, SecBuffer* plaintext,
                                    nla_credentials_transform_fn decrypt,
                                    nla_credentials_sink_fn decode)
{
	BOOL rc = FALSE;

	WINPR_ASSERT(ciphertext);
	WINPR_ASSERT(plaintext);
	WINPR_ASSERT(decrypt);
	WINPR_ASSERT(decode);

	if (ciphertext->cbBuffer < 1)
		goto out;

	sspi_SecBufferFree(plaintext);
	if (!decrypt(context, ciphertext, plaintext))
		goto out;

	rc = decode(context, plaintext);

out:
	sspi_SecBufferFree(plaintext);
	sspi_SecBufferFree(ciphertext);
	return rc;
}

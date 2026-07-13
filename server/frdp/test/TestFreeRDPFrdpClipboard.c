#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../frdpd/clipboard.h"

static int test_directions(void)
{
	frdpClipboardPolicy policy = { FRDP_CLIPBOARD_MODE_DISABLED,
		                           FRDP_CLIPBOARD_DIRECTION_BIDIRECTIONAL, 1024U };

	if (frdpd_clipboard_client_to_server_enabled(&policy) ||
	    frdpd_clipboard_server_to_client_enabled(&policy))
		return -1;
	policy.mode = FRDP_CLIPBOARD_MODE_TEXT;
	policy.direction = FRDP_CLIPBOARD_DIRECTION_CLIENT_TO_SERVER;
	if (!frdpd_clipboard_client_to_server_enabled(&policy) ||
	    frdpd_clipboard_server_to_client_enabled(&policy))
		return -1;
	policy.direction = FRDP_CLIPBOARD_DIRECTION_SERVER_TO_CLIENT;
	if (frdpd_clipboard_client_to_server_enabled(&policy) ||
	    !frdpd_clipboard_server_to_client_enabled(&policy))
		return -1;
	policy.direction = FRDP_CLIPBOARD_DIRECTION_BIDIRECTIONAL;
	return (!frdpd_clipboard_client_to_server_enabled(&policy) ||
	        !frdpd_clipboard_server_to_client_enabled(&policy))
	           ? -1
	           : 0;
}

static int test_roundtrip(void)
{
	static const BYTE text[] = { 'F', 'r', 'e', 'e', 'R', 'D', 'P', ' ', 0xe2, 0x82, 0xac };
	BYTE* wide = NULL;
	BYTE* decoded = NULL;
	UINT32 wide_length = 0;
	UINT32 decoded_length = 0;
	int rc = -1;

	if (!frdpd_clipboard_utf8_to_utf16le(text, sizeof(text), 128U, &wide, &wide_length) ||
	    !frdpd_clipboard_utf16le_to_utf8(wide, wide_length, 128U, &decoded, &decoded_length))
		goto out;
	if ((decoded_length != sizeof(text)) || (memcmp(decoded, text, sizeof(text)) != 0))
		goto out;
	if (frdpd_clipboard_hash(decoded, decoded_length) != frdpd_clipboard_hash(text, sizeof(text)))
		goto out;
	rc = 0;

out:
	free(decoded);
	free(wide);
	return rc;
}

static int test_invalid_inputs(void)
{
	static const BYTE odd[] = { 'x', 0, 0 };
	static const BYTE no_terminal[] = { 'x', 0 };
	static const BYTE embedded_nul[] = { 'x', 0, 0, 0, 'y', 0, 0, 0 };
	static const BYTE malformed_surrogate[] = { 0x00, 0xd8, 0, 0 };
	static const BYTE malformed_utf8[] = { 0xc0, 0xaf };
	BYTE* output = NULL;
	UINT32 output_length = 0;

	if (frdpd_clipboard_utf16le_to_utf8(odd, sizeof(odd), 32U, &output, &output_length) ||
	    frdpd_clipboard_utf16le_to_utf8(no_terminal, sizeof(no_terminal), 32U, &output,
	                                    &output_length) ||
	    frdpd_clipboard_utf16le_to_utf8(embedded_nul, sizeof(embedded_nul), 32U, &output,
	                                    &output_length) ||
	    frdpd_clipboard_utf16le_to_utf8(malformed_surrogate, sizeof(malformed_surrogate), 32U,
	                                    &output, &output_length) ||
	    frdpd_clipboard_utf8_to_utf16le(malformed_utf8, sizeof(malformed_utf8), 32U, &output,
	                                    &output_length) ||
	    frdpd_clipboard_utf8_to_utf16le((const BYTE*)"abcd", 4U, 3U, &output, &output_length))
	{
		free(output);
		return -1;
	}
	return 0;
}

static int test_logical_limit_is_encoding_independent(void)
{
	BYTE* wide = NULL;
	BYTE* decoded = NULL;
	UINT32 wide_length = 0;
	UINT32 decoded_length = 0;
	int rc = -1;

	if (!frdpd_clipboard_utf8_to_utf16le((const BYTE*)"abcd", 4U, 4U, &wide, &wide_length) ||
	    (wide_length != 10U) ||
	    !frdpd_clipboard_utf16le_to_utf8(wide, wide_length, 4U, &decoded, &decoded_length) ||
	    (decoded_length != 4U) || (memcmp(decoded, "abcd", 4U) != 0))
		goto out;
	rc = 0;
out:
	free(decoded);
	free(wide);
	return rc;
}

int TestFreeRDPFrdpClipboard(int argc, char* argv[])
{
	(void)argc;
	(void)argv;
	if ((test_directions() != 0) || (test_roundtrip() != 0) || (test_invalid_inputs() != 0) ||
	    (test_logical_limit_is_encoding_independent() != 0))
	{
		fprintf(stderr, "clipboard policy/conversion test failed\n");
		return 1;
	}
	return 0;
}

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "frdpd/clipboard.h"

#define FRDP_CLIPBOARD_FUZZ_MAX_SIZE 65536U

static uint32_t read_u32(const uint8_t* data, size_t size)
{
	uint32_t value = 0;

	for (size_t x = 0; (x < 4U) && (x < size); x++)
		value |= ((uint32_t)data[x]) << (x * 8U);
	return value;
}

static void fuzz_utf8(const uint8_t* data, size_t size, uint32_t max_text_bytes)
{
	BYTE* wide = NULL;
	BYTE* decoded = NULL;
	UINT32 wide_length = 0;
	UINT32 decoded_length = 0;

	if (size > UINT32_MAX)
		return;
	if (frdpd_clipboard_utf8_to_utf16le(data, (UINT32)size, max_text_bytes, &wide, &wide_length))
	{
		if (!frdpd_clipboard_utf16le_to_utf8(wide, wide_length, max_text_bytes, &decoded,
		                                     &decoded_length) ||
		    (decoded_length != size) || ((size > 0) && (memcmp(decoded, data, size) != 0)))
			abort();
	}
	free(decoded);
	free(wide);
}

static void fuzz_utf16(const uint8_t* data, size_t size, uint32_t max_text_bytes)
{
	BYTE* text = NULL;
	BYTE* encoded = NULL;
	UINT32 text_length = 0;
	UINT32 encoded_length = 0;

	if (size > UINT32_MAX)
		return;
	if (frdpd_clipboard_utf16le_to_utf8(data, (UINT32)size, max_text_bytes, &text, &text_length))
	{
		if (!frdpd_clipboard_utf8_to_utf16le(text, text_length, max_text_bytes, &encoded,
		                                     &encoded_length) ||
		    (encoded_length != size) || ((size > 0) && (memcmp(encoded, data, size) != 0)))
			abort();
	}
	free(encoded);
	free(text);
}

int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
	const uint8_t* payload = NULL;
	size_t payload_size = 0;
	uint32_t max_text_bytes = 0;

	if (!Data || (Size > FRDP_CLIPBOARD_FUZZ_MAX_SIZE))
		return 0;
	max_text_bytes = read_u32(Data, Size) % (FRDP_CLIPBOARD_FUZZ_MAX_SIZE + 1U);
	payload = (Size > 4U) ? &Data[4] : Data;
	payload_size = (Size > 4U) ? Size - 4U : 0U;
	fuzz_utf8(payload, payload_size, max_text_bytes);
	fuzz_utf16(payload, payload_size, max_text_bytes);
	return 0;
}

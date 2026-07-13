/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Experimental frdpd text clipboard helpers
 *
 * Licensed under the Apache License, Version 2.0.
 */

#include <stdlib.h>
#include <string.h>

#include <winpr/string.h>

#include "clipboard.h"

#define FRDPD_CLIPBOARD_HASH_OFFSET 1469598103934665603ULL
#define FRDPD_CLIPBOARD_HASH_PRIME 1099511628211ULL

static BOOL frdpd_clipboard_utf8_valid(const BYTE* text, UINT32 length)
{
	UINT32 offset = 0;

	while (offset < length)
	{
		const BYTE first = text[offset++];
		UINT32 continuation = 0;
		UINT32 codepoint = 0;

		if (first <= 0x7fU)
			continue;
		if ((first >= 0xc2U) && (first <= 0xdfU))
		{
			continuation = 1U;
			codepoint = first & 0x1fU;
		}
		else if ((first >= 0xe0U) && (first <= 0xefU))
		{
			continuation = 2U;
			codepoint = first & 0x0fU;
		}
		else if ((first >= 0xf0U) && (first <= 0xf4U))
		{
			continuation = 3U;
			codepoint = first & 0x07U;
		}
		else
			return FALSE;
		if (continuation > (length - offset))
			return FALSE;
		for (UINT32 i = 0; i < continuation; i++)
		{
			const BYTE next = text[offset++];
			if ((next & 0xc0U) != 0x80U)
				return FALSE;
			codepoint = (codepoint << 6U) | (next & 0x3fU);
		}
		if (((continuation == 2U) && (codepoint < 0x800U)) ||
		    ((continuation == 3U) && (codepoint < 0x10000U)) ||
		    ((codepoint >= 0xd800U) && (codepoint <= 0xdfffU)) || (codepoint > 0x10ffffU))
			return FALSE;
	}
	return TRUE;
}

static BOOL frdpd_clipboard_utf16_valid(const WCHAR* wide, size_t length)
{
	for (size_t i = 0; i < length; i++)
	{
		if ((wide[i] >= 0xd800U) && (wide[i] <= 0xdbffU))
		{
			if ((i + 1U >= length) || (wide[i + 1U] < 0xdc00U) || (wide[i + 1U] > 0xdfffU))
				return FALSE;
			i++;
		}
		else if ((wide[i] >= 0xdc00U) && (wide[i] <= 0xdfffU))
			return FALSE;
	}
	return TRUE;
}

BOOL frdpd_clipboard_client_to_server_enabled(const frdpClipboardPolicy* policy)
{
	if (!policy || (policy->mode != FRDP_CLIPBOARD_MODE_TEXT))
		return FALSE;
	return (policy->direction == FRDP_CLIPBOARD_DIRECTION_CLIENT_TO_SERVER) ||
	       (policy->direction == FRDP_CLIPBOARD_DIRECTION_BIDIRECTIONAL);
}

BOOL frdpd_clipboard_server_to_client_enabled(const frdpClipboardPolicy* policy)
{
	if (!policy || (policy->mode != FRDP_CLIPBOARD_MODE_TEXT))
		return FALSE;
	return (policy->direction == FRDP_CLIPBOARD_DIRECTION_SERVER_TO_CLIENT) ||
	       (policy->direction == FRDP_CLIPBOARD_DIRECTION_BIDIRECTIONAL);
}

BOOL frdpd_clipboard_utf16le_to_utf8(const BYTE* data, UINT32 data_length, UINT32 max_text_bytes,
                                     BYTE** text, UINT32* text_length)
{
	WCHAR* wide = NULL;
	char* converted = NULL;
	size_t wide_length = 0;
	size_t converted_length = 0;
	size_t wire_limit = 0;
	BOOL rc = FALSE;

	if (!text || !text_length)
		return FALSE;
	*text = NULL;
	*text_length = 0;
	if (max_text_bytes > ((UINT32_MAX - 2U) / 2U))
		return FALSE;
	wire_limit = ((size_t)max_text_bytes * 2U) + 2U;
	if (!data || (data_length < 2U) || ((data_length & 1U) != 0U) ||
	    ((size_t)data_length > wire_limit))
		return FALSE;
	wide_length = (size_t)data_length / 2U;
	if ((data[data_length - 2U] != 0U) || (data[data_length - 1U] != 0U))
		return FALSE;

	wide = calloc(wide_length, sizeof(*wide));
	if (!wide)
		return FALSE;
	for (size_t i = 0; i < wide_length; i++)
	{
		wide[i] = (WCHAR)((UINT16)data[i * 2U] | ((UINT16)data[(i * 2U) + 1U] << 8U));
		if ((i + 1U < wide_length) && (wide[i] == 0U))
			goto out;
	}
	if (!frdpd_clipboard_utf16_valid(wide, wide_length - 1U))
		goto out;

	converted = ConvertWCharNToUtf8Alloc(wide, wide_length - 1U, &converted_length);
	if (!converted || (converted_length > max_text_bytes) || (converted_length > UINT32_MAX) ||
	    (memchr(converted, '\0', converted_length) != NULL))
		goto out;

	*text = (BYTE*)converted;
	*text_length = (UINT32)converted_length;
	converted = NULL;
	rc = TRUE;

out:
	free(converted);
	free(wide);
	return rc;
}

BOOL frdpd_clipboard_utf8_to_utf16le(const BYTE* text, UINT32 text_length, UINT32 max_text_bytes,
                                     BYTE** data, UINT32* data_length)
{
	WCHAR* wide = NULL;
	BYTE* converted = NULL;
	size_t wide_length = 0;
	size_t converted_length = 0;
	size_t wire_limit = 0;
	BOOL rc = FALSE;

	if (!data || !data_length)
		return FALSE;
	*data = NULL;
	*data_length = 0;
	if ((!text && (text_length != 0U)) || (text_length > max_text_bytes) ||
	    (text && ((memchr(text, '\0', text_length) != NULL) ||
	              !frdpd_clipboard_utf8_valid(text, text_length))))
		return FALSE;
	if (max_text_bytes > ((UINT32_MAX - 2U) / 2U))
		return FALSE;
	wire_limit = ((size_t)max_text_bytes * 2U) + 2U;

	wide = ConvertUtf8NToWCharAlloc((const char*)(text ? text : (const BYTE*)""), text_length,
	                                &wide_length);
	if (!wide || (wide_length > ((SIZE_MAX / 2U) - 1U)))
		goto out;
	converted_length = (wide_length + 1U) * 2U;
	if ((converted_length > wire_limit) || (converted_length > UINT32_MAX))
		goto out;
	converted = calloc(converted_length, 1U);
	if (!converted)
		goto out;
	for (size_t i = 0; i < wide_length; i++)
	{
		converted[i * 2U] = (BYTE)(wide[i] & 0xffU);
		converted[(i * 2U) + 1U] = (BYTE)((wide[i] >> 8U) & 0xffU);
	}

	*data = converted;
	*data_length = (UINT32)converted_length;
	converted = NULL;
	rc = TRUE;

out:
	free(converted);
	free(wide);
	return rc;
}

UINT64 frdpd_clipboard_hash(const BYTE* text, UINT32 text_length)
{
	UINT64 hash = FRDPD_CLIPBOARD_HASH_OFFSET;

	if (!text && (text_length != 0U))
		return 0;
	for (UINT32 i = 0; i < text_length; i++)
	{
		hash ^= text[i];
		hash *= FRDPD_CLIPBOARD_HASH_PRIME;
	}
	return hash;
}

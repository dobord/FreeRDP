/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Experimental frdpd text clipboard helpers
 *
 * Licensed under the Apache License, Version 2.0.
 */

#ifndef FREERDP_SERVER_FRDPD_CLIPBOARD_H
#define FREERDP_SERVER_FRDPD_CLIPBOARD_H

#include <winpr/wtypes.h>

#include "../config/frdp-config.h"

#ifdef __cplusplus
extern "C"
{
#endif

	BOOL frdpd_clipboard_client_to_server_enabled(const frdpClipboardPolicy* policy);
	BOOL frdpd_clipboard_server_to_client_enabled(const frdpClipboardPolicy* policy);
	BOOL frdpd_clipboard_utf16le_to_utf8(const BYTE* data, UINT32 data_length,
	                                     UINT32 max_text_bytes, BYTE** text, UINT32* text_length);
	BOOL frdpd_clipboard_utf8_to_utf16le(const BYTE* text, UINT32 text_length,
	                                     UINT32 max_text_bytes, BYTE** data, UINT32* data_length);
	UINT64 frdpd_clipboard_hash(const BYTE* text, UINT32 text_length);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_SERVER_FRDPD_CLIPBOARD_H */

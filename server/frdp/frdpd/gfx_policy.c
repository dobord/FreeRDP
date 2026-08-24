/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FRDP graphics-pipeline policy helpers
 *
 * Licensed under the Apache License, Version 2.0.
 */

#include "gfx_policy.h"

#include <string.h>

#include <winpr/collections.h>

int frdpd_gfx_select_capability(const RDPGFX_CAPSET* offered, UINT16 offered_count,
                                RDPGFX_CAPSET* selected)
{
	static const UINT32 preferred_versions[] = {
		RDPGFX_CAPVERSION_107, RDPGFX_CAPVERSION_106, RDPGFX_CAPVERSION_106_ERR,
		RDPGFX_CAPVERSION_105, RDPGFX_CAPVERSION_104, RDPGFX_CAPVERSION_103,
		RDPGFX_CAPVERSION_102, RDPGFX_CAPVERSION_101, RDPGFX_CAPVERSION_10,
		RDPGFX_CAPVERSION_81,  RDPGFX_CAPVERSION_8
	};

	if (!offered || (offered_count == 0) || !selected)
		return -1;
	memset(selected, 0, sizeof(*selected));
	for (size_t preference = 0; preference < ARRAYSIZE(preferred_versions); preference++)
	{
		for (UINT16 index = 0; index < offered_count; index++)
		{
			const RDPGFX_CAPSET* candidate = &offered[index];
			if ((candidate->version != preferred_versions[preference]) ||
			    (candidate->length != sizeof(UINT32)))
				continue;
			*selected = *candidate;
			selected->flags &= ~RDPGFX_CAPS_FLAG_AVC420_ENABLED;
			if (selected->version >= RDPGFX_CAPVERSION_10)
				selected->flags |= RDPGFX_CAPS_FLAG_AVC_DISABLED;
			return 0;
		}
	}
	return -1;
}

BOOL frdpd_gfx_copy_bgrx_bottom_up_to_top_down(BYTE* destination, size_t destination_size,
                                               const BYTE* source, size_t source_size,
                                               UINT32 width, UINT32 height, UINT32 stride)
{
	size_t expected = 0;

	if (!destination || !source || (width == 0) || (height == 0) ||
	    (width > UINT32_MAX / 4U) || (stride != width * 4U) ||
	    (height > SIZE_MAX / stride))
		return FALSE;
	expected = (size_t)stride * height;
	if ((destination_size != expected) || (source_size != expected))
		return FALSE;
	for (UINT32 row = 0; row < height; row++)
	{
		const BYTE* src = source + ((size_t)(height - row - 1U) * stride);
		BYTE* dst = destination + ((size_t)row * stride);
		memcpy(dst, src, stride);
	}
	return TRUE;
}

/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FRDP graphics-pipeline policy helpers
 *
 * Licensed under the Apache License, Version 2.0.
 */

#ifndef FREERDP_SERVER_FRDPD_GFX_POLICY_H
#define FREERDP_SERVER_FRDPD_GFX_POLICY_H

#include <stddef.h>

#include <winpr/wtypes.h>

#include <freerdp/channels/rdpgfx.h>

#ifdef __cplusplus
extern "C"
{
#endif

	WINPR_ATTR_NODISCARD int frdpd_gfx_select_capability(const RDPGFX_CAPSET* offered,
	                                                      UINT16 offered_count,
	                                                      RDPGFX_CAPSET* selected);

	WINPR_ATTR_NODISCARD BOOL frdpd_gfx_copy_bgrx_bottom_up_to_top_down(
	    BYTE* destination, size_t destination_size, const BYTE* source, size_t source_size,
	    UINT32 width, UINT32 height, UINT32 stride);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_SERVER_FRDPD_GFX_POLICY_H */

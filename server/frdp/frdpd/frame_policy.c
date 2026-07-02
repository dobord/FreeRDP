/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Experimental frdpd framebuffer policy helpers
 *
 * Licensed under the Apache License, Version 2.0.
 */

#include "frame_policy.h"

#include <string.h>

int frdpd_frame_response_metadata_is_valid(const frdpAgentFrameResponse* response,
                                           const char* correlation_id, const char* session_id,
                                           uint32_t request_x, uint32_t request_y,
                                           uint32_t request_width, uint32_t request_height,
                                           uint32_t request_flags, uint32_t max_tile_size,
                                           uint32_t max_payload_len)
{
	if (!response || !correlation_id || !session_id || (request_width == 0) ||
	    (request_height == 0) || (max_tile_size == 0) || (max_payload_len == 0))
		return 0;
	if (!response->success)
		return 0;
	if ((strcmp(response->session_id, session_id) != 0) ||
	    (strcmp(response->correlation_id, correlation_id) != 0))
		return 0;
	if (request_flags & ~((uint32_t)FRDP_AGENT_FRAME_REQUEST_FORCE |
	                      (uint32_t)FRDP_AGENT_FRAME_REQUEST_DIRTY_ONLY))
		return 0;
	if ((request_flags & FRDP_AGENT_FRAME_REQUEST_FORCE) &&
	    (request_flags & FRDP_AGENT_FRAME_REQUEST_DIRTY_ONLY))
		return 0;
	if (response->flags & ~((uint32_t)FRDP_AGENT_FRAME_RESPONSE_UNCHANGED))
		return 0;
	if ((request_flags & FRDP_AGENT_FRAME_REQUEST_FORCE) &&
	    (response->flags & FRDP_AGENT_FRAME_RESPONSE_UNCHANGED))
		return 0;
	if (!(request_flags & FRDP_AGENT_FRAME_REQUEST_DIRTY_ONLY) &&
	    ((response->x != request_x) || (response->y != request_y) ||
	     (response->width > request_width) || (response->height > request_height)))
		return 0;
	if ((response->width == 0) || (response->height == 0) ||
	    (response->width > max_tile_size) || (response->height > max_tile_size) ||
	    (response->bpp != 32))
		return 0;
	if (response->flags & FRDP_AGENT_FRAME_RESPONSE_UNCHANGED)
	{
		if ((response->x != request_x) || (response->y != request_y) ||
		    (response->width > request_width) || (response->height > request_height))
			return 0;
		if ((response->stride != 0) || (response->data_length != 0))
			return 0;
		return 1;
	}
	if ((response->stride != response->width * 4U) ||
	    (response->data_length != response->stride * response->height) ||
	    (response->data_length == 0) || (response->data_length > max_payload_len))
		return 0;
	return 1;
}

int frdpd_frame_pump_budget_is_exhausted(uint64_t now_ms, uint64_t pump_started_ms,
                                         uint32_t completed_tiles, uint32_t max_tiles,
                                         uint64_t budget_ms)
{
	if (max_tiles == 0)
		return 1;
	if (completed_tiles >= max_tiles)
		return 1;
	if (now_ms < pump_started_ms)
		return 1;
	return (now_ms - pump_started_ms) >= budget_ms;
}

/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Experimental frdpd framebuffer policy helpers
 *
 * Licensed under the Apache License, Version 2.0.
 */

#ifndef FREERDP_SERVER_FRDPD_FRAME_POLICY_H
#define FREERDP_SERVER_FRDPD_FRAME_POLICY_H

#include <stdint.h>

#include "../ipc/frdp-ipc.h"

int frdpd_frame_response_metadata_is_valid(const frdpAgentFrameResponse* response,
                                           const char* correlation_id, const char* session_id,
                                           uint32_t request_x, uint32_t request_y,
                                           uint32_t request_width, uint32_t request_height,
                                           uint32_t request_flags, uint32_t max_tile_size,
                                           uint32_t max_payload_len);

#endif /* FREERDP_SERVER_FRDPD_FRAME_POLICY_H */

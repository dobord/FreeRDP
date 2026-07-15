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

int frdpd_frame_pump_budget_is_exhausted(uint64_t now_ms, uint64_t pump_started_ms,
                                         uint32_t completed_tiles, uint32_t max_tiles,
                                         uint64_t budget_ms);

int frdpd_frame_ipc_failure_is_terminal(uint32_t* consecutive_failures, uint32_t failure_limit);
int frdpd_frame_agent_should_probe(int managed_session_open, int framebuffer_active,
                                   int output_suppressed, int has_agent_socket);

#endif /* FREERDP_SERVER_FRDPD_FRAME_POLICY_H */

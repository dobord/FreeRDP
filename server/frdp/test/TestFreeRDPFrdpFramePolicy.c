#include "frdpd/frame_policy.h"

#include <stdio.h>
#include <string.h>

#define TEST_CORRELATION_ID "frame-policy-correlation"
#define TEST_SESSION_ID "frame-policy-session"
#define TEST_TILE_SIZE 120U
#define TEST_MAX_PAYLOAD 65535U

static void init_valid_frame(frdpAgentFrameResponse* response)
{
	memset(response, 0, sizeof(*response));
	snprintf(response->correlation_id, sizeof(response->correlation_id), "%s",
	         TEST_CORRELATION_ID);
	snprintf(response->session_id, sizeof(response->session_id), "%s", TEST_SESSION_ID);
	response->success = 1;
	response->x = 10;
	response->y = 20;
	response->width = 16;
	response->height = 8;
	response->stride = response->width * 4U;
	response->bpp = 32;
	response->data_length = response->stride * response->height;
}

static int frame_is_valid(const frdpAgentFrameResponse* response, uint32_t request_flags)
{
	return frdpd_frame_response_metadata_is_valid(response, TEST_CORRELATION_ID, TEST_SESSION_ID,
	                                             10, 20, TEST_TILE_SIZE, TEST_TILE_SIZE,
	                                             request_flags, TEST_TILE_SIZE,
	                                             TEST_MAX_PAYLOAD);
}

static int test_valid_raw_frame(void)
{
	frdpAgentFrameResponse response;

	init_valid_frame(&response);
	return frame_is_valid(&response, 0) ? 0 : -1;
}

static int test_valid_unchanged_frame(void)
{
	frdpAgentFrameResponse response;

	init_valid_frame(&response);
	response.flags = FRDP_AGENT_FRAME_RESPONSE_UNCHANGED;
	response.stride = 0;
	response.data_length = 0;
	return frame_is_valid(&response, FRDP_AGENT_FRAME_REQUEST_DIRTY_ONLY) ? 0 : -1;
}

static int test_valid_dirty_only_raw_subrectangle(void)
{
	frdpAgentFrameResponse response;

	init_valid_frame(&response);
	response.x = 30;
	response.y = 40;
	return frame_is_valid(&response, FRDP_AGENT_FRAME_REQUEST_DIRTY_ONLY) ? 0 : -1;
}

static int test_rejects_id_and_flag_mismatches(void)
{
	frdpAgentFrameResponse response;

	init_valid_frame(&response);
	snprintf(response.session_id, sizeof(response.session_id), "wrong-session");
	if (frame_is_valid(&response, 0))
		return -1;
	init_valid_frame(&response);
	response.flags = 0x80000000U;
	if (frame_is_valid(&response, 0))
		return -1;
	init_valid_frame(&response);
	response.flags = FRDP_AGENT_FRAME_RESPONSE_UNCHANGED;
	response.stride = 0;
	response.data_length = 0;
	if (frame_is_valid(&response, FRDP_AGENT_FRAME_REQUEST_FORCE))
		return -1;
	return 0;
}

static int test_rejects_rectangle_and_format_bounds(void)
{
	frdpAgentFrameResponse response;

	init_valid_frame(&response);
	response.x++;
	if (frame_is_valid(&response, 0))
		return -1;
	init_valid_frame(&response);
	response.width = TEST_TILE_SIZE + 1U;
	response.stride = response.width * 4U;
	response.data_length = response.stride * response.height;
	if (frame_is_valid(&response, 0))
		return -1;
	init_valid_frame(&response);
	response.bpp = 24;
	if (frame_is_valid(&response, 0))
		return -1;
	return 0;
}

static int test_rejects_stride_and_payload_bounds(void)
{
	frdpAgentFrameResponse response;

	init_valid_frame(&response);
	response.stride--;
	if (frame_is_valid(&response, 0))
		return -1;
	init_valid_frame(&response);
	response.data_length--;
	if (frame_is_valid(&response, 0))
		return -1;
	init_valid_frame(&response);
	response.height = TEST_TILE_SIZE;
	response.width = TEST_TILE_SIZE;
	response.stride = response.width * 4U;
	response.data_length = response.stride * response.height;
	if (frdpd_frame_response_metadata_is_valid(&response, TEST_CORRELATION_ID, TEST_SESSION_ID,
	                                           10, 20, TEST_TILE_SIZE, TEST_TILE_SIZE, 0,
	                                           TEST_TILE_SIZE, response.data_length - 1U))
		return -1;
	init_valid_frame(&response);
	response.flags = FRDP_AGENT_FRAME_RESPONSE_UNCHANGED;
	response.data_length = 1;
	if (frame_is_valid(&response, FRDP_AGENT_FRAME_REQUEST_DIRTY_ONLY))
		return -1;
	return 0;
}

int TestFreeRDPFrdpFramePolicy(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if (test_valid_raw_frame() != 0)
	{
		fprintf(stderr, "valid raw frame metadata rejected\n");
		return -1;
	}
	if (test_valid_unchanged_frame() != 0)
	{
		fprintf(stderr, "valid unchanged frame metadata rejected\n");
		return -1;
	}
	if (test_valid_dirty_only_raw_subrectangle() != 0)
	{
		fprintf(stderr, "valid dirty-only raw subrectangle metadata rejected\n");
		return -1;
	}
	if (test_rejects_id_and_flag_mismatches() != 0)
	{
		fprintf(stderr, "id/flag mismatch metadata accepted\n");
		return -1;
	}
	if (test_rejects_rectangle_and_format_bounds() != 0)
	{
		fprintf(stderr, "rectangle/format bounds metadata accepted\n");
		return -1;
	}
	if (test_rejects_stride_and_payload_bounds() != 0)
	{
		fprintf(stderr, "stride/payload bounds metadata accepted\n");
		return -1;
	}
	return 0;
}

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "frdpd/frame_policy.h"

#define FRDP_FRAME_POLICY_FUZZ_MAX_SIZE 512U

static uint32_t read_u32(const uint8_t* data, size_t size, size_t offset)
{
	uint32_t value = 0;

	for (size_t x = 0; x < 4U; x++)
	{
		if (offset + x < size)
			value |= ((uint32_t)data[offset + x]) << (x * 8U);
	}
	return value;
}

static uint64_t read_u64(const uint8_t* data, size_t size, size_t offset)
{
	uint64_t value = 0;

	for (size_t x = 0; x < 8U; x++)
	{
		if (offset + x < size)
			value |= ((uint64_t)data[offset + x]) << (x * 8U);
	}
	return value;
}

static uint32_t bounded_dimension(uint32_t value)
{
	return (value % 8192U) + 1U;
}

static void fuzz_frame_response_metadata(const uint8_t* data, size_t size)
{
	static const char correlation_id[] = "fuzz-correlation";
	static const char session_id[] = "fuzz-session";
	frdpAgentFrameResponse response = { 0 };
	const uint32_t request_x = read_u32(data, size, 0);
	const uint32_t request_y = read_u32(data, size, 4);
	const uint32_t request_width = bounded_dimension(read_u32(data, size, 8));
	const uint32_t request_height = bounded_dimension(read_u32(data, size, 12));
	const uint32_t request_flags = read_u32(data, size, 16);
	const uint32_t max_tile_size = bounded_dimension(read_u32(data, size, 20));
	const uint32_t max_payload_len = (read_u32(data, size, 24) % (16U * 1024U * 1024U)) + 1U;
	size_t copy_len = size;

	if (copy_len > sizeof(response))
		copy_len = sizeof(response);
	memcpy(&response, data, copy_len);
	response.correlation_id[sizeof(response.correlation_id) - 1U] = '\0';
	response.session_id[sizeof(response.session_id) - 1U] = '\0';
	response.error[sizeof(response.error) - 1U] = '\0';

	(void)frdpd_frame_response_metadata_is_valid(
	    &response, correlation_id, session_id, request_x, request_y, request_width, request_height,
	    request_flags, max_tile_size, max_payload_len);

	memset(&response, 0, sizeof(response));
	snprintf(response.correlation_id, sizeof(response.correlation_id), "%s", correlation_id);
	snprintf(response.session_id, sizeof(response.session_id), "%s", session_id);
	response.success = 1;
	response.x = request_x;
	response.y = request_y;
	response.width = request_width;
	response.height = request_height;
	response.stride = response.width * 4U;
	response.bpp = 32;
	response.flags = request_flags & FRDP_AGENT_FRAME_REQUEST_DIRTY_ONLY
	                     ? 0
	                     : (read_u32(data, size, 28) & FRDP_AGENT_FRAME_RESPONSE_UNCHANGED);
	response.data_length =
	    (response.flags & FRDP_AGENT_FRAME_RESPONSE_UNCHANGED) ? 0 : response.stride * response.height;
	(void)frdpd_frame_response_metadata_is_valid(
	    &response, correlation_id, session_id, request_x, request_y, request_width, request_height,
	    request_flags, max_tile_size, max_payload_len);
}

static void fuzz_frame_pump_budget(const uint8_t* data, size_t size)
{
	const uint64_t now_ms = read_u64(data, size, 32);
	const uint64_t started_ms = read_u64(data, size, 40);
	const uint32_t completed_tiles = read_u32(data, size, 48);
	const uint32_t max_tiles = read_u32(data, size, 52);
	const uint64_t budget_ms = read_u64(data, size, 56);

	(void)frdpd_frame_pump_budget_is_exhausted(now_ms, started_ms, completed_tiles, max_tiles,
	                                           budget_ms);
}

int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
	if (!Data || (Size > FRDP_FRAME_POLICY_FUZZ_MAX_SIZE))
		return 0;
	fuzz_frame_response_metadata(Data, Size);
	fuzz_frame_pump_budget(Data, Size);
	return 0;
}

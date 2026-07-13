#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <freerdp/input.h>

#include "frdp-session-agent/input_policy.h"

#define FRDP_INPUT_POLICY_FUZZ_MAX_SIZE 256U

static int32_t read_i32(const uint8_t *data, size_t size, size_t offset)
{
	uint32_t value = 0;

	for (size_t x = 0; x < 4U; x++)
	{
		if (offset + x < size)
			value |= ((uint32_t)data[offset + x]) << (x * 8U);
	}
	return (int32_t)value;
}

static uint32_t read_u32(const uint8_t *data, size_t size, size_t offset)
{
	return (uint32_t)read_i32(data, size, offset);
}

static void fuzz_raw_event(const uint8_t *data, size_t size)
{
	frdpAgentInputEvent event = { 0 };
	size_t copy_len = size;

	if (copy_len > sizeof(event))
		copy_len = sizeof(event);
	memcpy(&event, data, copy_len);
	event.correlation_id[sizeof(event.correlation_id) - 1U] = '\0';
	event.session_id[sizeof(event.session_id) - 1U] = '\0';
	(void)frdp_agent_input_event_payload_is_valid(&event);
}

static void fuzz_structured_event(const uint8_t *data, size_t size)
{
	frdpAgentInputEvent event = { 0 };

	event.event_type = (read_u32(data, size, 0) % FRDP_AGENT_INPUT_EXT_MOUSE) + 1U;
	event.flags = read_u32(data, size, 4);
	event.param1 = read_i32(data, size, 8);
	event.param2 = read_i32(data, size, 12);

	switch (event.event_type)
	{
		case FRDP_AGENT_INPUT_SYNC:
			event.flags &= KBD_SYNC_SCROLL_LOCK | KBD_SYNC_NUM_LOCK | KBD_SYNC_CAPS_LOCK |
			               KBD_SYNC_KANA_LOCK | read_u32(data, size, 16);
			break;
		case FRDP_AGENT_INPUT_KEYBOARD:
			event.flags &= KBD_FLAGS_EXTENDED | KBD_FLAGS_EXTENDED1 | KBD_FLAGS_DOWN |
			               KBD_FLAGS_RELEASE | read_u32(data, size, 16);
			event.param1 &= 0x1FF;
			event.param2 = (size > 20U) ? event.param2 : 0;
			break;
		case FRDP_AGENT_INPUT_UNICODE:
			event.flags &= KBD_FLAGS_DOWN | KBD_FLAGS_RELEASE | read_u32(data, size, 16);
			event.param1 &= 0x1FFFF;
			event.param2 = (size > 20U) ? event.param2 : 0;
			break;
		case FRDP_AGENT_INPUT_MOUSE:
			event.flags &= PTR_FLAGS_HWHEEL | PTR_FLAGS_WHEEL | PTR_FLAGS_WHEEL_NEGATIVE |
			               PTR_FLAGS_MOVE | PTR_FLAGS_DOWN | PTR_FLAGS_BUTTON1 |
			               PTR_FLAGS_BUTTON2 | PTR_FLAGS_BUTTON3 | WheelRotationMask |
			               read_u32(data, size, 16);
			break;
		case FRDP_AGENT_INPUT_REL_MOUSE:
			event.flags &= PTR_FLAGS_MOVE | PTR_FLAGS_DOWN | PTR_FLAGS_BUTTON1 |
			               PTR_FLAGS_BUTTON2 | PTR_FLAGS_BUTTON3 | PTR_XFLAGS_BUTTON1 |
			               PTR_XFLAGS_BUTTON2 | read_u32(data, size, 16);
			break;
		case FRDP_AGENT_INPUT_EXT_MOUSE:
			event.flags &= PTR_XFLAGS_DOWN | PTR_XFLAGS_BUTTON1 | PTR_XFLAGS_BUTTON2 |
			               read_u32(data, size, 16);
			break;
		default:
			break;
	}

	(void)frdp_agent_input_event_payload_is_valid(&event);
}

static void fuzz_unicode_sequence(const uint8_t *data, size_t size)
{
	frdpAgentUnicodeInputState state = { 0 };
	frdpAgentInputEvent event = { 0 };

	event.event_type = FRDP_AGENT_INPUT_UNICODE;
	for (size_t offset = 0; offset + 1U < size; offset += 3U)
	{
		uint32_t codepoint = UINT32_MAX;
		int decode_status = 0;

		event.flags = ((offset + 2U < size) && (data[offset + 2U] & 1U))
		                  ? KBD_FLAGS_RELEASE
		                  : 0;
		event.param1 = (int32_t)((uint32_t)data[offset] | ((uint32_t)data[offset + 1U] << 8U));
		decode_status = frdp_agent_unicode_input_decode(&state, &event, &codepoint);
		if ((decode_status < -1) || (decode_status > 1))
			abort();
		if ((decode_status <= 0) && (codepoint != 0))
			abort();
		if ((decode_status == 1) &&
		    ((codepoint > 0x10FFFFU) || ((codepoint >= 0xD800U) && (codepoint <= 0xDFFFU))))
			abort();
		if ((decode_status == 1) && (codepoint >= 0x20U) &&
		    (frdp_agent_unicode_scalar_to_keysym(codepoint) !=
		     ((codepoint <= 0xFFU) ? codepoint : (UINT32_C(0x01000000) | codepoint))))
			abort();
		if ((state.pending_high_surrogate != 0) &&
		    ((state.pending_high_surrogate < 0xD800U) ||
		     (state.pending_high_surrogate > 0xDBFFU)))
			abort();
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	if (!Data || (Size > FRDP_INPUT_POLICY_FUZZ_MAX_SIZE))
		return 0;
	fuzz_raw_event(Data, Size);
	fuzz_structured_event(Data, Size);
	fuzz_unicode_sequence(Data, Size);
	return 0;
}

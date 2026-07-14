#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ipc/frdp-ipc.h"

#define FRDP_IPC_CODEC_FUZZ_MAX_SIZE 16384U

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

static int feed_socket(const uint8_t* data, size_t size, int fds[2])
{
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		return -1;
	if (size > 0)
		(void)frdp_ipc_send(fds[0], data, size);
	(void)shutdown(fds[0], SHUT_WR);
	return 0;
}

static void close_pair(int fds[2])
{
	if (fds[0] >= 0)
		(void)frdp_ipc_close(fds[0]);
	if (fds[1] >= 0)
		(void)frdp_ipc_close(fds[1]);
}

static void fuzz_header_decode(const uint8_t* data, size_t size)
{
	int fds[2] = { -1, -1 };
	frdpIpcHeader header = { 0 };

	if (feed_socket(data, size, fds) != 0)
		return;
	(void)frdp_ipc_recv_header(fds[1], &header);
	close_pair(fds);
}

static int selector_uses_message_stream(uint32_t selector)
{
	switch (selector % 19U)
	{
		case 1:
		case 4:
		case 5:
		case 6:
		case 9:
		case 11:
		case 13:
		case 14:
		case 17:
		case 18:
			return 1;
		default:
			return 0;
	}
}

static void fuzz_payload_decode(const uint8_t* data, size_t size, const uint8_t* payload,
                                size_t payload_size, uint32_t declared_len, uint32_t selector)
{
	int fds[2] = { -1, -1 };
	const int use_message_stream = selector_uses_message_stream(selector);
	const uint8_t* feed = use_message_stream ? data : payload;
	const size_t feed_size = use_message_stream ? size : payload_size;

	if (feed_socket(feed, feed_size, fds) != 0)
		return;

	switch (selector % 20U)
	{
		case 0:
		{
			frdpAuthRequest request = { 0 };
			(void)frdp_ipc_recv_auth_request_v2_payload(fds[1], &request, declared_len);
			break;
		}
		case 1:
		{
			frdpAuthResponse response = { 0 };
			(void)frdp_ipc_recv_auth_response(fds[1], &response);
			break;
		}
		case 2:
		{
			frdpSessionRequestV3 request = { 0 };
			(void)frdp_ipc_recv_session_request_v3_payload(fds[1], &request, declared_len);
			break;
		}
		case 3:
		{
			frdpSessionRequest request = { 0 };
			(void)frdp_ipc_recv_session_close_request_payload(fds[1], &request, declared_len);
			break;
		}
		case 4:
		{
			frdpSessionResponse response = { 0 };
			(void)frdp_ipc_recv_session_response(fds[1], &response);
			break;
		}
		case 5:
		{
			frdpSessionListResponse response = { 0 };
			(void)frdp_ipc_recv_session_list_response(fds[1], &response);
			break;
		}
		case 6:
		{
			frdpControlResponse response = { 0 };
			(void)frdp_ipc_recv_session_reload_response(fds[1], &response);
			break;
		}
		case 7:
		{
			frdpAgentInputEvent event = { 0 };
			(void)frdp_ipc_recv_agent_input_event_payload(fds[1], &event, declared_len);
			break;
		}
		case 8:
		{
			frdpAgentFrameRequest request = { 0 };
			(void)frdp_ipc_recv_agent_frame_request_payload(fds[1], &request, declared_len);
			break;
		}
		case 9:
		{
			frdpAgentFrameResponse response = { 0 };
			(void)frdp_ipc_recv_agent_frame_response(fds[1], &response);
			break;
		}
		case 10:
		{
			frdpAgentResizeRequest request = { 0 };
			(void)frdp_ipc_recv_agent_resize_request_payload(fds[1], &request, declared_len);
			break;
		}
		case 11:
		{
			frdpAgentResizeResponse response = { 0 };
			(void)frdp_ipc_recv_agent_resize_response(fds[1], &response);
			break;
		}
		case 12:
		{
			frdpAgentHeartbeat heartbeat = { 0 };
			(void)frdp_ipc_recv_agent_heartbeat_request_payload(fds[1], &heartbeat, declared_len);
			break;
		}
		case 13:
		{
			frdpAgentHeartbeat heartbeat = { 0 };
			(void)frdp_ipc_recv_agent_heartbeat_response(fds[1], &heartbeat);
			break;
		}
		case 14:
		{
			frdpControlResponse response = { 0 };
			(void)frdp_ipc_recv_helper_health_response(fds[1], &response);
			break;
		}
		case 15:
		{
			frdpAgentClipboardRequest request = { 0 };
			uint8_t* text = NULL;
			(void)frdp_ipc_recv_agent_clipboard_set_request_payload(fds[1], &request, &text,
			                                                        declared_len);
			free(text);
			break;
		}
		case 16:
		{
			frdpAgentClipboardRequest request = { 0 };
			(void)frdp_ipc_recv_agent_clipboard_get_request_payload(fds[1], &request, declared_len);
			break;
		}
		case 17:
		{
			frdpAgentClipboardResponse response = { 0 };
			uint8_t* text = NULL;
			(void)frdp_ipc_recv_agent_clipboard_response(
			    fds[1], FRDP_IPC_AGENT_CLIPBOARD_SET_RESPONSE, &response, &text);
			free(text);
			break;
		}
		default:
		{
			frdpAgentClipboardResponse response = { 0 };
			uint8_t* text = NULL;
			(void)frdp_ipc_recv_agent_clipboard_response(
			    fds[1], FRDP_IPC_AGENT_CLIPBOARD_GET_RESPONSE, &response, &text);
			free(text);
			break;
		}
		case 19:
		{
			frdpAuthResponse response = { 0 };
			(void)frdp_ipc_recv_auth_response_v2(fds[1], &response);
			break;
		}
	}

	close_pair(fds);
}

int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
	uint32_t declared_len = 0;
	const uint8_t* payload = NULL;
	size_t payload_size = 0;

	if (!Data || (Size > FRDP_IPC_CODEC_FUZZ_MAX_SIZE))
		return 0;

	fuzz_header_decode(Data, Size);
	declared_len = read_u32(Data, Size, 0);
	payload = (Size > 4U) ? &Data[4] : Data;
	payload_size = (Size > 4U) ? Size - 4U : 0;
	for (uint32_t selector = 0; selector < 19U; selector++)
		fuzz_payload_decode(Data, Size, payload, payload_size, declared_len, selector);

	return 0;
}

/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Experimental frdpd entry point
 *
 * Licensed under the Apache License, Version 2.0.
 */

#include <freerdp/config.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <unistd.h>

#include <winpr/assert.h>
#include <winpr/crt.h>
#include <winpr/interlocked.h>
#include <winpr/path.h>
#include <winpr/rpc.h>
#include <winpr/sam.h>
#include <winpr/sspi.h>
#include <winpr/ssl.h>
#include <winpr/synch.h>
#include <winpr/sysinfo.h>
#include <winpr/winsock.h>
#include <winpr/wtsapi.h>

#include <freerdp/constants.h>
#include <freerdp/channels/channels.h>
#include <freerdp/channels/wtsvc.h>
#include <freerdp/codec/color.h>
#include <freerdp/freerdp.h>
#include <freerdp/listener.h>
#include <freerdp/log.h>
#include <freerdp/peer.h>
#include <freerdp/server/disp.h>
#include <freerdp/settings.h>
#include <freerdp/crypto/certificate.h>
#include <freerdp/crypto/privatekey.h>

#include "../config/frdp-config.h"
#include "../ipc/frdp-ipc.h"
#include "channel_policy.h"
#include "clipboard_runtime.h"
#include "display_control.h"
#include "frame_policy.h"
#include "frdpd.h"
#include "frdpd_auth.h"

#define TAG SERVER_TAG("frdpd")
#define FRDPD_FRAME_TILE_SIZE 120U
#define FRDPD_FRAME_TILES_PER_PUMP 2U
#define FRDPD_FRAME_INTERVAL_MS 50ULL
#define FRDPD_FRAME_PUMP_BUDGET_MS 30ULL
#define FRDPD_FRAME_IPC_TIMEOUT_US 100000
#define FRDPD_FRAME_IPC_FAILURE_LIMIT 3U
#define FRDPD_FRAME_HASH_OFFSET 1469598103934665603ULL
#define FRDPD_FRAME_HASH_PRIME 1099511628211ULL
#define FRDPD_NSC_COLOR_LOSS_LEVEL 1U
#define FRDPD_KERBEROS_ONLY_PACKAGE_LIST "kerberos,u2u,!ntlm"
#define FRDPD_PEER_ACTIVE_WAIT_TIMEOUT_MS 50
#define FRDPD_PEER_IDLE_WAIT_TIMEOUT_MS 250
#define FRDPD_LOG_STRING_SIZE 1024U
#define FRDPD_HELPER_READY_ATTEMPTS 50U
#define FRDPD_HELPER_READY_TIMEOUT_MS 100U
#define FRDPD_HELPER_READY_RETRY_MS 100U

typedef struct
{
	frdpdServerConfig server;
	frdpConfig file_config;
	char config_bind_address[64];
	const char* config_path;
	BOOL domain_mode_set;
	BOOL show_help;
	BOOL pam_auth_test;
	const char* test_user;
	const char* test_domain;
	const char* test_rhost;
} frdpdOptions;

static volatile sig_atomic_t g_frdpd_running = 1;
static volatile sig_atomic_t g_frdpd_reload_requested = 0;
/* Peer workers are detached, so this lock intentionally lives until process exit. */
static CRITICAL_SECTION g_frdpd_policy_lock;

static BOOL frdpd_peer_remote_monitors(rdpContext* context, UINT32 count,
                                       const MONITOR_DEF* monitors);
static BOOL frdpd_process_pending_display_control(frdpdPeerContext* context);
static BOOL frdpd_apply_file_config(frdpdOptions* options);

#ifdef WITH_FRDPD_NTLM
static BOOL frdpd_prepare_ntlm_sam_file(frdpdServerConfig* config)
{
	struct stat st = { 0 };
	struct stat path_st = { 0 };
	WINPR_SAM* sam = NULL;
	int fd = -1;
	int length = 0;

	WINPR_ASSERT(config);
	if (!config->ntlm_fallback)
		return TRUE;
	if (!config->ntlm_sam_file || (config->ntlm_sam_file[0] != '/'))
		return FALSE;

	fd = open(config->ntlm_sam_file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return FALSE;
	if ((fstat(fd, &st) != 0) || !S_ISREG(st.st_mode) || (st.st_uid != geteuid()) ||
	    ((st.st_mode & 0777) != 0600) || (st.st_nlink != 1))
		goto fail;

	length = snprintf(config->ntlm_sam_fd_path, sizeof(config->ntlm_sam_fd_path),
	                  "/proc/self/fd/%d", fd);
	if ((length <= 0) || ((size_t)length >= sizeof(config->ntlm_sam_fd_path)) ||
	    (stat(config->ntlm_sam_fd_path, &path_st) != 0) || (path_st.st_dev != st.st_dev) ||
	    (path_st.st_ino != st.st_ino))
		goto fail;
	sam = SamOpen(config->ntlm_sam_fd_path, TRUE);
	if (!sam || !SamValidate(sam))
		goto fail;
	SamClose(sam);
	sam = NULL;

	config->ntlm_sam_fd = fd;
	config->ntlm_sam_file = config->ntlm_sam_fd_path;
	return TRUE;

fail:
	SamClose(sam);
	(void)close(fd);
	return FALSE;
}
#endif

static BOOL frdpd_disable_core_dumps(void)
{
	const struct rlimit limit = { 0, 0 };

	if (setrlimit(RLIMIT_CORE, &limit) != 0)
	{
		WLog_WARN(TAG, "Unable to disable core dumps for frdpd");
		return FALSE;
	}
#ifdef __linux__
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
	{
		WLog_WARN(TAG, "Unable to mark frdpd non-dumpable");
		return FALSE;
	}
#endif
	return TRUE;
}

static void frdpd_signal_handler(int signum)
{
	if (signum == SIGHUP)
		g_frdpd_reload_requested = 1;
	else
		g_frdpd_running = 0;
}

static BOOL frdpd_install_signal_handlers(void)
{
	struct sigaction action = { 0 };

	action.sa_handler = frdpd_signal_handler;
	if (sigemptyset(&action.sa_mask) != 0)
		return FALSE;
	if (sigaction(SIGINT, &action, NULL) != 0)
		return FALSE;
	if (sigaction(SIGTERM, &action, NULL) != 0)
		return FALSE;
	if (sigaction(SIGHUP, &action, NULL) != 0)
		return FALSE;
	return TRUE;
}

static void frdpd_escape_log_string(char* dst, size_t dst_size, const char* src)
{
	size_t out = 0;

	if (!dst || (dst_size == 0))
		return;
	dst[0] = '\0';
	if (!src)
		return;

	for (size_t i = 0; (src[i] != '\0') && (out + 1U < dst_size); i++)
	{
		const unsigned char c = (unsigned char)src[i];

		if ((c >= 0x20U) && (c <= 0x7eU) && (c != '\\'))
			dst[out++] = (char)c;
		else if (out + 4U < dst_size)
		{
			(void)snprintf(&dst[out], dst_size - out, "\\x%02X", c);
			out += 4U;
		}
		else
			break;
	}
	dst[out] = '\0';
}

static const char* frdpd_log_value(const char* value, char* dst, size_t dst_size,
                                   const char* fallback)
{
	if (!fallback)
		fallback = "unknown";
	if (!dst || (dst_size == 0))
		return fallback;
	frdpd_escape_log_string(dst, dst_size, value ? value : fallback);
	return (dst[0] != '\0') ? dst : fallback;
}

static const char* frdpd_client_log_name(const freerdp_peer* client, char* dst, size_t dst_size)
{
	const char* name = "unknown";

	if (client && client->local)
		name = "(local)";
	else if (client && (client->hostname[0] != '\0'))
		name = client->hostname;
	return frdpd_log_value(name, dst, dst_size, "unknown");
}

static const char* frdpd_context_log_session_id(const frdpdPeerContext* context, char* dst,
                                                size_t dst_size)
{
	return frdpd_log_value((context && (context->session_id[0] != '\0')) ? context->session_id
	                                                                     : NULL,
	                       dst, dst_size, "unknown");
}

static BOOL frdpd_generate_correlation_id(char* buffer, size_t size)
{
	UUID uuid = { 0 };
	RPC_CSTR uuid_string = NULL;
	BOOL rc = FALSE;

	if (!buffer || (size == 0))
		return FALSE;
	buffer[0] = '\0';
	if (UuidCreate(&uuid) != RPC_S_OK)
		return FALSE;
	if (UuidToStringA(&uuid, &uuid_string) != RPC_S_OK)
		return FALSE;
	rc = sprintf_s(buffer, size, "%s", (const char*)uuid_string) > 0;
	RpcStringFreeA(&uuid_string);
	return rc;
}

static BOOL frdpd_copy_ipc_string(char* dst, size_t dst_size, const char* src)
{
	int rc = 0;

	if (!dst || (dst_size == 0))
		return FALSE;
	if (!src)
		src = "";
	rc = snprintf(dst, dst_size, "%s", src);
	return (rc >= 0) && ((size_t)rc < dst_size);
}

static BOOL frdpd_session_ipc_request(const char* socket_path, frdpIpcMessageType type,
                                      const void* request, size_t request_size,
                                      frdpSessionResponse* response)
{
	int fd = -1;
	BOOL ok = FALSE;

	if (!socket_path || (socket_path[0] == '\0') || !request || !response)
		return FALSE;

	fd = frdp_ipc_connect(socket_path);
	if (fd < 0)
		goto fail;

	if (type == FRDP_IPC_SESSION_REQUEST_V3)
	{
		if ((request_size != sizeof(frdpSessionRequestV3)) ||
		    (frdp_ipc_send_session_request_v3(fd, (const frdpSessionRequestV3*)request) != 0))
			goto fail;
	}
	else if (type == FRDP_IPC_SESSION_CLOSE_REQUEST)
	{
		if ((request_size != sizeof(frdpSessionRequest)) ||
		    (frdp_ipc_send_session_close_request(fd, (const frdpSessionRequest*)request) != 0))
			goto fail;
	}
	else if (type == FRDP_IPC_SESSION_DISCONNECT_REQUEST)
	{
		if ((request_size != sizeof(frdpSessionRequest)) ||
		    (frdp_ipc_send_session_disconnect_request(fd, (const frdpSessionRequest*)request) != 0))
			goto fail;
	}
	else if ((frdp_ipc_send_header(fd, type, (UINT32)request_size) < 0) ||
	         (frdp_ipc_send(fd, request, request_size) < 0))
	{
		goto fail;
	}

	if (frdp_ipc_recv_session_response(fd, response) != 0)
		goto fail;

	response->session_id[sizeof(response->session_id) - 1] = '\0';
	response->display[sizeof(response->display) - 1] = '\0';
	response->agent_socket[sizeof(response->agent_socket) - 1] = '\0';
	response->error[sizeof(response->error) - 1] = '\0';
	ok = response->success ? TRUE : FALSE;

fail:
	if (fd >= 0)
		(void)frdp_ipc_close(fd);
	return ok;
}

static BOOL frdpd_send_agent_input(frdpdPeerContext* context, frdpAgentInputType type, UINT32 flags,
                                   INT32 param1, INT32 param2)
{
	int fd = -1;
	frdpAgentInputEvent event = { 0 };
	BOOL ok = FALSE;
	char log_session_id[FRDPD_LOG_STRING_SIZE] = { 0 };

	if (!context || !context->managed_session_open || (context->agent_socket[0] == '\0'))
		return TRUE;

	(void)frdpd_copy_ipc_string(event.correlation_id, sizeof(event.correlation_id),
	                            context->correlation_id);
	(void)frdpd_copy_ipc_string(event.session_id, sizeof(event.session_id), context->session_id);
	event.event_type = type;
	event.flags = flags;
	event.param1 = param1;
	event.param2 = param2;

	fd = frdp_ipc_connect(context->agent_socket);
	if (fd < 0)
		goto fail;

	if (frdp_ipc_send_agent_input_event(fd, &event) != 0)
		goto fail;
	ok = TRUE;

fail:
	if (fd >= 0)
		(void)frdp_ipc_close(fd);
	if (!ok && !context->agent_input_warned)
	{
		WLog_WARN(TAG, "correlation_id=%s failed to forward input to managed session_id=%s",
		          context->correlation_id,
		          frdpd_context_log_session_id(context, log_session_id, sizeof(log_session_id)));
		context->agent_input_warned = TRUE;
	}
	return ok;
}

static UINT32 frdpd_min_u32(UINT32 a, UINT32 b)
{
	return (a < b) ? a : b;
}

static void frdpd_reset_frame_encoder(frdpdPeerContext* context)
{
	if (!context)
		return;
	nsc_context_free(context->framebuffer_nsc);
	context->framebuffer_nsc = NULL;
	Stream_Free(context->framebuffer_nsc_stream, TRUE);
	context->framebuffer_nsc_stream = NULL;
	context->framebuffer_nsc_warned = FALSE;
}

static void frdpd_invalidate_framebuffer_cache(frdpdPeerContext* context)
{
	if (!context)
		return;
	context->framebuffer_next_x = 0;
	context->framebuffer_next_y = 0;
	context->framebuffer_last_tick = 0;
	free(context->framebuffer_hashes);
	context->framebuffer_hashes = NULL;
	context->framebuffer_hash_cols = 0;
	context->framebuffer_hash_rows = 0;
}

static void frdpd_reset_framebuffer_state(frdpdPeerContext* context)
{
	if (!context)
		return;
	context->framebuffer_active = FALSE;
	context->framebuffer_output_suppressed = FALSE;
	context->agent_frame_failures = 0;
	frdpd_invalidate_framebuffer_cache(context);
	frdpd_reset_frame_encoder(context);
}

static UINT64 frdpd_hash_frame_tile(const BYTE* data, UINT32 length)
{
	UINT64 hash = FRDPD_FRAME_HASH_OFFSET;

	if (!data || (length == 0))
		return 0;
	for (UINT32 i = 0; i < length; i++)
	{
		hash ^= data[i];
		hash *= FRDPD_FRAME_HASH_PRIME;
	}
	return (hash != 0) ? hash : 1;
}

static BOOL frdpd_prepare_frame_hashes(frdpdPeerContext* context, UINT32 desktop_width,
                                       UINT32 desktop_height)
{
	UINT32 cols = 0;
	UINT32 rows = 0;
	size_t count = 0;
	UINT64* hashes = NULL;

	if (!context || (desktop_width == 0) || (desktop_height == 0))
		return FALSE;
	cols = (desktop_width + FRDPD_FRAME_TILE_SIZE - 1U) / FRDPD_FRAME_TILE_SIZE;
	rows = (desktop_height + FRDPD_FRAME_TILE_SIZE - 1U) / FRDPD_FRAME_TILE_SIZE;
	if ((cols == 0) || (rows == 0) || (cols > SIZE_MAX / rows))
		return FALSE;
	count = (size_t)cols * rows;
	if (count > SIZE_MAX / sizeof(UINT64))
		return FALSE;
	if (context->framebuffer_hashes && (context->framebuffer_hash_cols == cols) &&
	    (context->framebuffer_hash_rows == rows))
		return TRUE;

	hashes = (UINT64*)calloc(count, sizeof(UINT64));
	if (!hashes)
		return FALSE;
	free(context->framebuffer_hashes);
	context->framebuffer_hashes = hashes;
	context->framebuffer_hash_cols = cols;
	context->framebuffer_hash_rows = rows;
	return TRUE;
}

static UINT64* frdpd_frame_tile_hash_slot(frdpdPeerContext* context, UINT32 x, UINT32 y)
{
	UINT32 col = 0;
	UINT32 row = 0;

	if (!context || !context->framebuffer_hashes || (context->framebuffer_hash_cols == 0) ||
	    (context->framebuffer_hash_rows == 0))
		return NULL;
	col = x / FRDPD_FRAME_TILE_SIZE;
	row = y / FRDPD_FRAME_TILE_SIZE;
	if ((col >= context->framebuffer_hash_cols) || (row >= context->framebuffer_hash_rows))
		return NULL;
	return &context->framebuffer_hashes[((size_t)row * context->framebuffer_hash_cols) + col];
}

static BOOL frdpd_frame_pump_budget_exhausted(UINT64 pump_started, UINT32 completed_tiles)
{
	return frdpd_frame_pump_budget_is_exhausted(GetTickCount64(), pump_started, completed_tiles,
	                                            FRDPD_FRAME_TILES_PER_PUMP,
	                                            FRDPD_FRAME_PUMP_BUDGET_MS)
	           ? TRUE
	           : FALSE;
}

static DWORD frdpd_peer_wait_timeout_ms(const frdpdPeerContext* context)
{
	if (context && context->managed_session_open && context->framebuffer_active &&
	    !context->framebuffer_output_suppressed && (context->agent_socket[0] != '\0'))
		return FRDPD_PEER_ACTIVE_WAIT_TIMEOUT_MS;
	return FRDPD_PEER_IDLE_WAIT_TIMEOUT_MS;
}

static BOOL frdpd_set_frame_ipc_timeout(int fd)
{
	struct timeval timeout = { 0 };

	timeout.tv_sec = 0;
	timeout.tv_usec = FRDPD_FRAME_IPC_TIMEOUT_US;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
		return FALSE;
	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0)
		return FALSE;
	return TRUE;
}

static BOOL frdpd_set_resize_ipc_timeout(int fd)
{
	struct timeval timeout = { 0 };

	timeout.tv_sec = 2;
	timeout.tv_usec = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
		return FALSE;
	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0)
		return FALSE;
	return TRUE;
}

static BOOL frdpd_nsc_surface_bits_supported(const rdpUpdate* update, const rdpSettings* settings)
{
	const UINT32 supported =
	    settings ? freerdp_settings_get_uint32(settings, FreeRDP_SurfaceCommandsSupported) : 0;
	const UINT32 codec_id = settings ? freerdp_settings_get_uint32(settings, FreeRDP_NSCodecId) : 0;

	return update && update->SurfaceBits && settings &&
	       ((supported & SURFCMDS_SET_SURFACE_BITS) != 0) &&
	       freerdp_settings_get_bool(settings, FreeRDP_NSCodec) && (codec_id != 0) &&
	       (codec_id <= UINT16_MAX);
}

static BOOL frdpd_prepare_nsc_encoder(frdpdPeerContext* context, UINT32 width, UINT32 height)
{
	if (!context || (width == 0) || (height == 0) || (width > UINT16_MAX) || (height > UINT16_MAX))
		return FALSE;
	if (!context->framebuffer_nsc)
	{
		context->framebuffer_nsc = nsc_context_new();
		if (!context->framebuffer_nsc)
			return FALSE;
	}
	if (!context->framebuffer_nsc_stream)
	{
		context->framebuffer_nsc_stream =
		    Stream_New(NULL, 4ULL * FRDPD_FRAME_TILE_SIZE * FRDPD_FRAME_TILE_SIZE);
		if (!context->framebuffer_nsc_stream)
			return FALSE;
	}

	if (!nsc_context_reset(context->framebuffer_nsc, width, height))
		return FALSE;
	if (!nsc_context_set_parameters(context->framebuffer_nsc, NSC_COLOR_LOSS_LEVEL,
	                                FRDPD_NSC_COLOR_LOSS_LEVEL))
		return FALSE;
	if (!nsc_context_set_parameters(context->framebuffer_nsc, NSC_ALLOW_SUBSAMPLING, 0))
		return FALSE;
	if (!nsc_context_set_parameters(context->framebuffer_nsc, NSC_DYNAMIC_COLOR_FIDELITY, 0))
		return FALSE;
	return nsc_context_set_parameters(context->framebuffer_nsc, NSC_COLOR_FORMAT,
	                                  PIXEL_FORMAT_BGRX32);
}

static BOOL frdpd_send_agent_resize(frdpdPeerContext* context, UINT32 width, UINT32 height,
                                    UINT32 color_depth)
{
	int fd = -1;
	frdpAgentResizeRequest request = { 0 };
	frdpAgentResizeResponse response = { 0 };
	BOOL ok = FALSE;

	if (!context || !context->managed_session_open || (context->agent_socket[0] == '\0') ||
	    (width == 0) || (height == 0) || (width > FRDPD_DISPLAY_MAX_DESKTOP_SIZE) ||
	    (height > FRDPD_DISPLAY_MAX_DESKTOP_SIZE))
		return FALSE;

	(void)frdpd_copy_ipc_string(request.correlation_id, sizeof(request.correlation_id),
	                            context->correlation_id);
	(void)frdpd_copy_ipc_string(request.session_id, sizeof(request.session_id),
	                            context->session_id);
	request.width = width;
	request.height = height;
	request.color_depth = color_depth;

	fd = frdp_ipc_connect(context->agent_socket);
	if (fd < 0)
		goto fail;
	if (!frdpd_set_resize_ipc_timeout(fd))
		goto fail;

	if (frdp_ipc_send_agent_resize_request(fd, &request) != 0)
		goto fail;
	if (frdp_ipc_recv_agent_resize_response(fd, &response) != 0)
		goto fail;

	response.correlation_id[sizeof(response.correlation_id) - 1] = '\0';
	response.session_id[sizeof(response.session_id) - 1] = '\0';
	response.error[sizeof(response.error) - 1] = '\0';
	if (!response.success)
		goto fail;
	if ((strcmp(response.session_id, context->session_id) != 0) ||
	    (strcmp(response.correlation_id, context->correlation_id) != 0))
		goto fail;
	if ((response.width != width) || (response.height != height))
		goto fail;
	ok = TRUE;

fail:
	if (fd >= 0)
		(void)frdp_ipc_close(fd);
	return ok;
}

static BOOL frdpd_receive_agent_frame(frdpdPeerContext* context, UINT32 x, UINT32 y, UINT32 width,
                                      UINT32 height, UINT32 flags, frdpAgentFrameResponse* response,
                                      BYTE** data)
{
	int fd = -1;
	frdpAgentFrameRequest request = { 0 };
	BOOL ok = FALSE;

	if (!context || !response || !data || !context->managed_session_open ||
	    (context->agent_socket[0] == '\0'))
		return FALSE;
	if (flags &
	    ~((UINT32)FRDP_AGENT_FRAME_REQUEST_FORCE | (UINT32)FRDP_AGENT_FRAME_REQUEST_DIRTY_ONLY))
		return FALSE;
	if ((flags & FRDP_AGENT_FRAME_REQUEST_FORCE) && (flags & FRDP_AGENT_FRAME_REQUEST_DIRTY_ONLY))
		return FALSE;
	*data = NULL;
	memset(response, 0, sizeof(*response));

	(void)frdpd_copy_ipc_string(request.correlation_id, sizeof(request.correlation_id),
	                            context->correlation_id);
	(void)frdpd_copy_ipc_string(request.session_id, sizeof(request.session_id),
	                            context->session_id);
	request.x = x;
	request.y = y;
	request.width = width;
	request.height = height;
	request.flags = flags;

	fd = frdp_ipc_connect(context->agent_socket);
	if (fd < 0)
		goto fail;
	if (!frdpd_set_frame_ipc_timeout(fd))
		goto fail;

	if (frdp_ipc_send_agent_frame_request(fd, &request) != 0)
		goto fail;
	if (frdp_ipc_recv_agent_frame_response(fd, response) != 0)
		goto fail;

	response->correlation_id[sizeof(response->correlation_id) - 1] = '\0';
	response->session_id[sizeof(response->session_id) - 1] = '\0';
	response->error[sizeof(response->error) - 1] = '\0';
	if (!frdpd_frame_response_metadata_is_valid(response, context->correlation_id,
	                                            context->session_id, x, y, width, height, flags,
	                                            FRDPD_FRAME_TILE_SIZE, UINT16_MAX))
		goto fail;
	if (response->flags & FRDP_AGENT_FRAME_RESPONSE_UNCHANGED)
	{
		ok = TRUE;
		goto done;
	}

	*data = (BYTE*)malloc(response->data_length);
	if (!*data)
		goto fail;
	if (frdp_ipc_recv(fd, *data, response->data_length) != (int)response->data_length)
		goto fail;
	ok = TRUE;

fail:
	if (!ok)
	{
		free(*data);
		*data = NULL;
	}
done:
	if (fd >= 0)
		(void)frdp_ipc_close(fd);
	return ok;
}

static BOOL frdpd_send_bitmap_frame(freerdp_peer* client, const frdpAgentFrameResponse* frame,
                                    BYTE* data)
{
	BITMAP_DATA bitmap = { 0 };
	BITMAP_UPDATE update_cmd = { 0 };
	rdpUpdate* update = NULL;
	BOOL ok = FALSE;

	if (!client || !client->context || !frame || !data)
		return FALSE;
	if ((frame->x > UINT16_MAX) || (frame->y > UINT16_MAX) || (frame->width == 0) ||
	    (frame->height == 0) || (frame->x + frame->width - 1U > UINT16_MAX) ||
	    (frame->y + frame->height - 1U > UINT16_MAX) || (frame->data_length > UINT16_MAX))
		return FALSE;

	update = client->context->update;
	if (!update || !update->BitmapUpdate)
		return FALSE;

	bitmap.destLeft = frame->x;
	bitmap.destTop = frame->y;
	bitmap.destRight = frame->x + frame->width - 1U;
	bitmap.destBottom = frame->y + frame->height - 1U;
	bitmap.width = frame->width;
	bitmap.height = frame->height;
	bitmap.bitsPerPixel = 32;
	bitmap.bitmapLength = frame->data_length;
	bitmap.cbScanWidth = frame->stride;
	bitmap.cbUncompressedSize = frame->data_length;
	bitmap.bitmapDataStream = data;
	bitmap.compressed = FALSE;

	update_cmd.number = 1;
	update_cmd.rectangles = &bitmap;
	update_cmd.skipCompression = FALSE;

	rdp_update_lock(update);
	ok = update->BitmapUpdate(update->context, &update_cmd);
	rdp_update_unlock(update);
	return ok;
}

static BOOL frdpd_send_nsc_frame(freerdp_peer* client, frdpdPeerContext* context,
                                 const frdpAgentFrameResponse* frame, BYTE* data)
{
	SURFACE_BITS_COMMAND cmd = { 0 };
	rdpSettings* settings = NULL;
	rdpUpdate* update = NULL;
	wStream* stream = NULL;
	size_t encoded_length = 0;
	UINT32 codec_id = 0;
	BOOL ok = FALSE;
	char log_session_id[FRDPD_LOG_STRING_SIZE] = { 0 };

	if (!client || !client->context || !context || !frame || !data)
		return FALSE;
	settings = client->context->settings;
	update = client->context->update;
	if (!frdpd_nsc_surface_bits_supported(update, settings))
		return FALSE;
	if ((frame->x > UINT16_MAX) || (frame->y > UINT16_MAX) || (frame->width > UINT16_MAX) ||
	    (frame->height > UINT16_MAX) || (frame->width > UINT16_MAX - frame->x) ||
	    (frame->height > UINT16_MAX - frame->y))
		return FALSE;
	if (!frdpd_prepare_nsc_encoder(context, frame->width, frame->height))
		goto fail;

	stream = context->framebuffer_nsc_stream;
	Stream_ResetPosition(stream);
	if (!nsc_compose_message(context->framebuffer_nsc, stream, data, frame->width, frame->height,
	                         frame->stride))
		goto fail;
	encoded_length = Stream_GetPosition(stream);
	if ((encoded_length == 0) || (encoded_length > UINT32_MAX))
		goto fail;
	if (encoded_length >= frame->data_length)
		return FALSE;

	codec_id = freerdp_settings_get_uint32(settings, FreeRDP_NSCodecId);
	cmd.cmdType = CMDTYPE_SET_SURFACE_BITS;
	cmd.destLeft = frame->x;
	cmd.destTop = frame->y;
	cmd.destRight = frame->x + frame->width;
	cmd.destBottom = frame->y + frame->height;
	cmd.bmp.bpp = 32;
	cmd.bmp.codecID = (UINT16)codec_id;
	cmd.bmp.width = (UINT16)frame->width;
	cmd.bmp.height = (UINT16)frame->height;
	cmd.bmp.bitmapDataLength = (UINT32)encoded_length;
	cmd.bmp.bitmapData = Stream_Buffer(stream);

	rdp_update_lock(update);
	ok = update->SurfaceBits(update->context, &cmd);
	rdp_update_unlock(update);
	if (ok)
	{
		context->framebuffer_nsc_warned = FALSE;
		return TRUE;
	}

fail:
	if (!context->framebuffer_nsc_warned)
	{
		WLog_WARN(TAG,
		          "correlation_id=%s failed to send NSCodec framebuffer tile for session_id=%s; "
		          "falling back to raw bitmap updates",
		          context->correlation_id,
		          frdpd_context_log_session_id(context, log_session_id, sizeof(log_session_id)));
		context->framebuffer_nsc_warned = TRUE;
	}
	return FALSE;
}

static BOOL frdpd_send_frame(freerdp_peer* client, frdpdPeerContext* context,
                             const frdpAgentFrameResponse* frame, BYTE* data)
{
	if (frdpd_send_nsc_frame(client, context, frame, data))
		return TRUE;
	return frdpd_send_bitmap_frame(client, frame, data);
}

static void frdpd_advance_frame_cursor(frdpdPeerContext* context, UINT32 desktop_width,
                                       UINT32 desktop_height)
{
	if (!context || (desktop_width == 0) || (desktop_height == 0))
		return;

	context->framebuffer_next_x += FRDPD_FRAME_TILE_SIZE;
	if (context->framebuffer_next_x >= desktop_width)
	{
		context->framebuffer_next_x = 0;
		context->framebuffer_next_y += FRDPD_FRAME_TILE_SIZE;
		if (context->framebuffer_next_y >= desktop_height)
			context->framebuffer_next_y = 0;
	}
}

static BOOL frdpd_pump_agent_framebuffer(freerdp_peer* client, frdpdPeerContext* context)
{
	rdpSettings* settings = NULL;
	UINT32 desktop_width = 0;
	UINT32 desktop_height = 0;
	BOOL hash_cache_ready = FALSE;
	const UINT64 now = GetTickCount64();
	const UINT64 pump_started = now;
	char log_session_id[FRDPD_LOG_STRING_SIZE] = { 0 };

	if (!client || !client->context || !context ||
	    !frdpd_frame_agent_should_probe(context->managed_session_open, context->framebuffer_active,
	                                    context->framebuffer_output_suppressed,
	                                    context->agent_socket[0] != '\0'))
		return TRUE;
	if ((context->framebuffer_last_tick != 0) &&
	    (now - context->framebuffer_last_tick < FRDPD_FRAME_INTERVAL_MS))
		return TRUE;
	context->framebuffer_last_tick = now;

	settings = client->context->settings;
	if (!settings)
		return TRUE;
	desktop_width = freerdp_settings_get_uint32(settings, FreeRDP_DesktopWidth);
	desktop_height = freerdp_settings_get_uint32(settings, FreeRDP_DesktopHeight);
	if ((desktop_width == 0) || (desktop_height == 0))
		return TRUE;
	if ((context->framebuffer_next_x >= desktop_width) ||
	    (context->framebuffer_next_y >= desktop_height))
	{
		context->framebuffer_next_x = 0;
		context->framebuffer_next_y = 0;
	}
	hash_cache_ready = frdpd_prepare_frame_hashes(context, desktop_width, desktop_height);

	for (UINT32 i = 0; i < FRDPD_FRAME_TILES_PER_PUMP; i++)
	{
		BYTE* data = NULL;
		UINT64 tile_hash = 0;
		UINT64* request_hash_slot = NULL;
		UINT64* response_hash_slot = NULL;
		UINT32 request_flags = 0;
		frdpAgentFrameResponse frame = { 0 };
		const UINT32 x = context->framebuffer_next_x;
		const UINT32 y = context->framebuffer_next_y;
		const UINT32 width = frdpd_min_u32(FRDPD_FRAME_TILE_SIZE, desktop_width - x);
		const UINT32 height = frdpd_min_u32(FRDPD_FRAME_TILE_SIZE, desktop_height - y);

		if (hash_cache_ready)
			request_hash_slot = frdpd_frame_tile_hash_slot(context, x, y);
		if (!request_hash_slot || (*request_hash_slot == 0))
			request_flags |= FRDP_AGENT_FRAME_REQUEST_FORCE;
		else
			request_flags |= FRDP_AGENT_FRAME_REQUEST_DIRTY_ONLY;

		if (!frdpd_receive_agent_frame(context, x, y, width, height, request_flags, &frame, &data))
		{
			const BOOL terminal = frdpd_frame_ipc_failure_is_terminal(
			    &context->agent_frame_failures, FRDPD_FRAME_IPC_FAILURE_LIMIT);
			if (!context->agent_frame_warned)
			{
				WLog_WARN(
				    TAG, "correlation_id=%s failed to receive framebuffer from session_id=%s",
				    context->correlation_id,
				    frdpd_context_log_session_id(context, log_session_id, sizeof(log_session_id)));
				context->agent_frame_warned = TRUE;
			}
			if (terminal)
			{
				WLog_ERR(
				    TAG,
				    "correlation_id=%s closing session_id=%s after %" PRIu32
				    " consecutive agent framebuffer IPC failures",
				    context->correlation_id,
				    frdpd_context_log_session_id(context, log_session_id, sizeof(log_session_id)),
				    context->agent_frame_failures);
				return FALSE;
			}
			frdpd_advance_frame_cursor(context, desktop_width, desktop_height);
			return TRUE;
		}
		context->agent_frame_failures = 0;
		if (context->framebuffer_output_suppressed)
		{
			free(data);
			context->agent_frame_warned = FALSE;
			frdpd_advance_frame_cursor(context, desktop_width, desktop_height);
			return TRUE;
		}
		if (frame.flags & FRDP_AGENT_FRAME_RESPONSE_UNCHANGED)
		{
			context->agent_frame_warned = FALSE;
			frdpd_advance_frame_cursor(context, desktop_width, desktop_height);
			if ((i + 1U < FRDPD_FRAME_TILES_PER_PUMP) &&
			    frdpd_frame_pump_budget_exhausted(pump_started, i + 1U))
				break;
			continue;
		}
		if ((frame.x >= desktop_width) || (frame.y >= desktop_height) ||
		    (frame.width > desktop_width - frame.x) || (frame.height > desktop_height - frame.y))
		{
			free(data);
			if (!context->agent_frame_warned)
			{
				WLog_WARN(
				    TAG,
				    "correlation_id=%s received out-of-bounds framebuffer tile from session_id=%s",
				    context->correlation_id,
				    frdpd_context_log_session_id(context, log_session_id, sizeof(log_session_id)));
				context->agent_frame_warned = TRUE;
			}
			frdpd_advance_frame_cursor(context, desktop_width, desktop_height);
			return TRUE;
		}
		if (hash_cache_ready)
			response_hash_slot = frdpd_frame_tile_hash_slot(context, frame.x, frame.y);
		tile_hash = frdpd_hash_frame_tile(data, frame.data_length);
		if (response_hash_slot && (*response_hash_slot == tile_hash))
		{
			free(data);
			context->agent_frame_warned = FALSE;
			frdpd_advance_frame_cursor(context, desktop_width, desktop_height);
			if ((i + 1U < FRDPD_FRAME_TILES_PER_PUMP) &&
			    frdpd_frame_pump_budget_exhausted(pump_started, i + 1U))
				break;
			continue;
		}

		if (!frdpd_send_frame(client, context, &frame, data))
		{
			free(data);
			WLog_WARN(
			    TAG, "correlation_id=%s failed to send framebuffer tile for session_id=%s",
			    context->correlation_id,
			    frdpd_context_log_session_id(context, log_session_id, sizeof(log_session_id)));
			return FALSE;
		}
		if (response_hash_slot)
			*response_hash_slot = tile_hash;
		free(data);
		context->agent_frame_warned = FALSE;
		frdpd_advance_frame_cursor(context, desktop_width, desktop_height);
		if ((i + 1U < FRDPD_FRAME_TILES_PER_PUMP) &&
		    frdpd_frame_pump_budget_exhausted(pump_started, i + 1U))
			break;
	}

	return TRUE;
}

typedef struct
{
	char socket_path[108];
	char correlation_id[64];
	char session_id[64];
	char user[64];
} frdpdSessionCloseRetry;

static DWORD WINAPI frdpd_session_close_retry_thread(LPVOID arg)
{
	frdpdSessionCloseRetry* retry = (frdpdSessionCloseRetry*)arg;
	BOOL closed = FALSE;
	char log_session_id[FRDPD_LOG_STRING_SIZE] = { 0 };

	if (!retry)
		return 0;

	for (int attempt = 0; attempt < 30 && !closed; attempt++)
	{
		frdpSessionRequest request = { 0 };
		frdpSessionResponse response = { 0 };

		(void)frdpd_copy_ipc_string(request.correlation_id, sizeof(request.correlation_id),
		                            retry->correlation_id);
		(void)frdpd_copy_ipc_string(request.session_id, sizeof(request.session_id),
		                            retry->session_id);
		(void)frdpd_copy_ipc_string(request.user, sizeof(request.user), retry->user);
		closed = frdpd_session_ipc_request(retry->socket_path, FRDP_IPC_SESSION_CLOSE_REQUEST,
		                                   &request, sizeof(request), &response);
		SecureZeroMemory(&request, sizeof(request));
		SecureZeroMemory(&response, sizeof(response));
		if (!closed)
			Sleep(1000);
	}

	if (closed)
		WLog_INFO(
		    TAG, "correlation_id=%s closed managed session_id=%s after retry",
		    retry->correlation_id,
		    frdpd_log_value(retry->session_id, log_session_id, sizeof(log_session_id), "unknown"));
	else
		WLog_WARN(
		    TAG, "correlation_id=%s exhausted close retries for managed session_id=%s",
		    retry->correlation_id,
		    frdpd_log_value(retry->session_id, log_session_id, sizeof(log_session_id), "unknown"));

	SecureZeroMemory(retry, sizeof(*retry));
	free(retry);
	return 0;
}

static BOOL frdpd_schedule_session_close_retry(const frdpdServerConfig* config,
                                               const frdpdPeerContext* context)
{
	HANDLE thread = NULL;
	frdpdSessionCloseRetry* retry = NULL;

	if (!config || !context || !config->session_socket || (config->session_socket[0] == '\0') ||
	    (context->session_id[0] == '\0'))
		return FALSE;

	retry = calloc(1, sizeof(*retry));
	if (!retry)
		return FALSE;
	if (!frdpd_copy_ipc_string(retry->socket_path, sizeof(retry->socket_path),
	                           config->session_socket) ||
	    !frdpd_copy_ipc_string(retry->correlation_id, sizeof(retry->correlation_id),
	                           context->correlation_id) ||
	    !frdpd_copy_ipc_string(retry->session_id, sizeof(retry->session_id), context->session_id) ||
	    !frdpd_copy_ipc_string(retry->user, sizeof(retry->user), context->pam_user))
	{
		free(retry);
		return FALSE;
	}

	thread = CreateThread(NULL, 0, frdpd_session_close_retry_thread, retry, 0, NULL);
	if (!thread)
	{
		free(retry);
		return FALSE;
	}
	(void)CloseHandle(thread);
	return TRUE;
}

static BOOL frdpd_open_managed_session(freerdp_peer* client, const frdpdServerConfig* config,
                                       frdpdPeerContext* context)
{
	rdpSettings* settings = NULL;
	frdpSessionRequestV3 request = { 0 };
	frdpSessionResponse response = { 0 };
	char log_error[FRDPD_LOG_STRING_SIZE] = { 0 };
	char log_session_id[FRDPD_LOG_STRING_SIZE] = { 0 };
	char log_session_display[FRDPD_LOG_STRING_SIZE] = { 0 };
	char log_agent_socket[FRDPD_LOG_STRING_SIZE] = { 0 };
	char log_user[FRDPD_LOG_STRING_SIZE] = { 0 };
	BOOL ok = FALSE;

	if (!config || !context || !config->session_socket || (config->session_socket[0] == '\0'))
		return TRUE;
	if (context->managed_session_open)
		return TRUE;
	if (!client || !context->pam_user)
		return FALSE;
	if (!context->has_posix_account)
		return FALSE;
	if (context->authorization_id[0] == '\0')
		return FALSE;
	if (context->group_count > FRDP_IPC_MAX_AUTH_GROUPS)
		return FALSE;

	if (!frdpd_copy_ipc_string(request.correlation_id, sizeof(request.correlation_id),
	                           context->correlation_id) ||
	    !frdpd_copy_ipc_string(request.user, sizeof(request.user), context->pam_user) ||
	    !frdpd_copy_ipc_string(request.authorization_id, sizeof(request.authorization_id),
	                           context->authorization_id) ||
	    !frdpd_copy_ipc_string(request.rhost, sizeof(request.rhost),
	                           (client->hostname[0] != '\0') ? client->hostname : NULL))
		goto cleanup;

	request.uid = (UINT64)context->uid;
	request.gid = (UINT64)context->gid;
	request.group_count = context->group_count;
	memcpy(request.groups, context->groups, context->group_count * sizeof(request.groups[0]));
	request.has_posix_account = TRUE;

	settings = client->context ? client->context->settings : NULL;
	if (settings)
	{
		request.desktop_width = freerdp_settings_get_uint32(settings, FreeRDP_DesktopWidth);
		request.desktop_height = freerdp_settings_get_uint32(settings, FreeRDP_DesktopHeight);
		request.color_depth = freerdp_settings_get_uint32(settings, FreeRDP_ColorDepth);
	}

	if (!frdpd_session_ipc_request(config->session_socket, FRDP_IPC_SESSION_REQUEST_V3, &request,
	                               sizeof(request), &response))
	{
		WLog_WARN(TAG, "correlation_id=%s session manager rejected login for %s: %s",
		          context->correlation_id,
		          frdpd_log_value(context->pam_user, log_user, sizeof(log_user), "unknown"),
		          frdpd_log_value(response.error[0] ? response.error : NULL, log_error,
		                          sizeof(log_error), "IPC failure"));
		goto cleanup;
	}

	if (!frdpd_copy_ipc_string(context->session_id, sizeof(context->session_id),
	                           response.session_id) ||
	    !frdpd_copy_ipc_string(context->session_display, sizeof(context->session_display),
	                           response.display) ||
	    !frdpd_copy_ipc_string(context->agent_socket, sizeof(context->agent_socket),
	                           response.agent_socket) ||
	    (context->session_id[0] == '\0') || (context->agent_socket[0] == '\0'))
	{
		if (response.session_id[0] != '\0')
		{
			frdpSessionRequest close_request = { 0 };
			frdpSessionResponse close_response = { 0 };
			BOOL rollback_closed = FALSE;

			(void)frdpd_copy_ipc_string(close_request.correlation_id,
			                            sizeof(close_request.correlation_id),
			                            context->correlation_id);
			(void)frdpd_copy_ipc_string(close_request.session_id, sizeof(close_request.session_id),
			                            response.session_id);
			(void)frdpd_copy_ipc_string(close_request.user, sizeof(close_request.user),
			                            context->pam_user);
			rollback_closed =
			    frdpd_session_ipc_request(config->session_socket, FRDP_IPC_SESSION_CLOSE_REQUEST,
			                              &close_request, sizeof(close_request), &close_response);
			if (!rollback_closed && (context->session_id[0] != '\0'))
			{
				context->managed_session_open = TRUE;
				(void)frdpd_schedule_session_close_retry(config, context);
				context->managed_session_open = FALSE;
				context->session_id[0] = '\0';
				context->session_display[0] = '\0';
				context->agent_socket[0] = '\0';
			}
			SecureZeroMemory(&close_request, sizeof(close_request));
			SecureZeroMemory(&close_response, sizeof(close_response));
		}
		context->session_id[0] = '\0';
		context->session_display[0] = '\0';
		context->agent_socket[0] = '\0';
		goto cleanup;
	}

	context->managed_session_open = TRUE;
	SecureZeroMemory(context->authorization_id, sizeof(context->authorization_id));
	context->agent_input_warned = FALSE;
	context->agent_frame_warned = FALSE;
	frdpd_reset_framebuffer_state(context);
	WLog_INFO(TAG,
	          "correlation_id=%s opened managed session_id=%s display=%s agent_socket=%s user=%s",
	          context->correlation_id,
	          frdpd_context_log_session_id(context, log_session_id, sizeof(log_session_id)),
	          frdpd_log_value(context->session_display[0] ? context->session_display : NULL,
	                          log_session_display, sizeof(log_session_display), "unknown"),
	          frdpd_log_value(context->agent_socket, log_agent_socket, sizeof(log_agent_socket),
	                          "unknown"),
	          frdpd_log_value(context->pam_user, log_user, sizeof(log_user), "unknown"));
	ok = TRUE;

cleanup:
	SecureZeroMemory(&request, sizeof(request));
	SecureZeroMemory(&response, sizeof(response));
	return ok;
}

static void frdpd_auth_result_cleanup(frdpdAuthResult* result)
{
	if (!result)
		return;
	free(result->pam_user);
	result->pam_user = NULL;
	result->uid = (uid_t)-1;
	result->gid = (gid_t)-1;
	result->group_count = 0;
	SecureZeroMemory(result->groups, sizeof(result->groups));
	result->has_posix_account = FALSE;
	SecureZeroMemory(result->authorization_id, sizeof(result->authorization_id));
	SecureZeroMemory(result->broker_error, sizeof(result->broker_error));
}

static BOOL frdpd_close_managed_session(const frdpdServerConfig* config, frdpdPeerContext* context,
                                        BOOL async_only)
{
	frdpSessionRequest request = { 0 };
	frdpSessionResponse response = { 0 };
	BOOL closed = FALSE;
	BOOL ok = FALSE;
	char log_error[FRDPD_LOG_STRING_SIZE] = { 0 };
	char log_session_id[FRDPD_LOG_STRING_SIZE] = { 0 };

	if (!config || !context || !context->managed_session_open || !config->session_socket ||
	    (config->session_socket[0] == '\0'))
		return TRUE;

	if (!frdpd_copy_ipc_string(request.correlation_id, sizeof(request.correlation_id),
	                           context->correlation_id) ||
	    !frdpd_copy_ipc_string(request.session_id, sizeof(request.session_id),
	                           context->session_id) ||
	    !frdpd_copy_ipc_string(request.user, sizeof(request.user), context->pam_user))
	{
		WLog_WARN(TAG, "correlation_id=%s unable to build session close request",
		          context->correlation_id);
		goto cleanup;
	}

	if (async_only)
	{
		if (!frdpd_schedule_session_close_retry(config, context))
		{
			WLog_WARN(
			    TAG, "correlation_id=%s failed to schedule close retry for session_id=%s",
			    context->correlation_id,
			    frdpd_context_log_session_id(context, log_session_id, sizeof(log_session_id)));
			goto cleanup;
		}
		WLog_INFO(TAG, "correlation_id=%s scheduled close retry for managed session_id=%s",
		          context->correlation_id,
		          frdpd_context_log_session_id(context, log_session_id, sizeof(log_session_id)));
		context->managed_session_open = FALSE;
		frdpd_reset_framebuffer_state(context);
		context->session_id[0] = '\0';
		context->session_display[0] = '\0';
		context->agent_socket[0] = '\0';
		ok = TRUE;
		goto cleanup;
	}

	closed = frdpd_session_ipc_request(config->session_socket, FRDP_IPC_SESSION_CLOSE_REQUEST,
	                                   &request, sizeof(request), &response);

	if (!closed)
	{
		WLog_WARN(TAG, "correlation_id=%s failed to close managed session_id=%s: %s",
		          context->correlation_id,
		          frdpd_context_log_session_id(context, log_session_id, sizeof(log_session_id)),
		          frdpd_log_value(response.error[0] ? response.error : NULL, log_error,
		                          sizeof(log_error), "IPC failure"));
		goto cleanup;
	}

	WLog_INFO(TAG, "correlation_id=%s closed managed session_id=%s", context->correlation_id,
	          frdpd_context_log_session_id(context, log_session_id, sizeof(log_session_id)));

	context->managed_session_open = FALSE;
	frdpd_reset_framebuffer_state(context);
	context->session_id[0] = '\0';
	context->session_display[0] = '\0';
	context->agent_socket[0] = '\0';
	ok = TRUE;

cleanup:
	SecureZeroMemory(&request, sizeof(request));
	SecureZeroMemory(&response, sizeof(response));
	return ok;
}

static BOOL frdpd_disconnect_managed_session(const frdpdServerConfig* config,
                                             frdpdPeerContext* context)
{
	frdpSessionRequest request = { 0 };
	frdpSessionResponse response = { 0 };
	char log_error[FRDPD_LOG_STRING_SIZE] = { 0 };
	char log_session_id[FRDPD_LOG_STRING_SIZE] = { 0 };
	BOOL detached = FALSE;

	if (!config || !context || !context->managed_session_open || !config->session_socket ||
	    (config->session_socket[0] == '\0'))
		return TRUE;

	if (!frdpd_copy_ipc_string(request.correlation_id, sizeof(request.correlation_id),
	                           context->correlation_id) ||
	    !frdpd_copy_ipc_string(request.session_id, sizeof(request.session_id),
	                           context->session_id) ||
	    !frdpd_copy_ipc_string(request.user, sizeof(request.user), context->pam_user))
	{
		WLog_WARN(TAG, "correlation_id=%s unable to build session disconnect request",
		          context->correlation_id);
		goto cleanup;
	}

	detached =
	    frdpd_session_ipc_request(config->session_socket, FRDP_IPC_SESSION_DISCONNECT_REQUEST,
	                              &request, sizeof(request), &response);
	if (!detached)
	{
		WLog_WARN(TAG, "correlation_id=%s failed to detach managed session_id=%s: %s",
		          context->correlation_id,
		          frdpd_context_log_session_id(context, log_session_id, sizeof(log_session_id)),
		          frdpd_log_value(response.error[0] ? response.error : NULL, log_error,
		                          sizeof(log_error), "IPC failure"));
		goto cleanup;
	}

	WLog_INFO(TAG, "correlation_id=%s detached managed session_id=%s", context->correlation_id,
	          frdpd_context_log_session_id(context, log_session_id, sizeof(log_session_id)));
	context->managed_session_open = FALSE;
	frdpd_reset_framebuffer_state(context);
	context->session_id[0] = '\0';
	context->session_display[0] = '\0';
	context->agent_socket[0] = '\0';

cleanup:
	SecureZeroMemory(&request, sizeof(request));
	SecureZeroMemory(&response, sizeof(response));
	return detached;
}

static void frdpd_peer_context_free(freerdp_peer* client, rdpContext* ctx)
{
	frdpdPeerContext* context = (frdpdPeerContext*)ctx;
	const frdpdServerConfig* config =
	    client ? (const frdpdServerConfig*)client->ContextExtra : NULL;

	if (!context)
		return;

	frdpd_clipboard_runtime_stop(context);
	disp_server_context_free(context->display_control);
	context->display_control = NULL;
	if (context->vcm && (context->vcm != INVALID_HANDLE_VALUE))
	{
		WTSCloseServer(context->vcm);
		context->vcm = NULL;
	}

	if (!frdpd_disconnect_managed_session(config, context))
		(void)frdpd_close_managed_session(config, context, TRUE);
	frdpd_reset_framebuffer_state(context);
	context->uid = (uid_t)-1;
	context->gid = (gid_t)-1;
	context->group_count = 0;
	SecureZeroMemory(context->groups, sizeof(context->groups));
	context->has_posix_account = FALSE;
	SecureZeroMemory(context->authorization_id, sizeof(context->authorization_id));
	free(context->pam_user);
	context->pam_user = NULL;
	if (context->display_control_lock_initialized)
	{
		DeleteCriticalSection(&context->display_control_lock);
		context->display_control_lock_initialized = FALSE;
	}
	if (context->clipboard_lock_initialized)
	{
		DeleteCriticalSection(&context->clipboard_lock);
		context->clipboard_lock_initialized = FALSE;
	}
}

static BOOL frdpd_dvc_authorize(void* userdata, DWORD SessionId, const char* channelName,
                                DWORD flags)
{
	frdpdPeerContext* context = (frdpdPeerContext*)userdata;

	WINPR_UNUSED(SessionId);
	WINPR_UNUSED(flags);

	if (!context)
		return FALSE;
	return frdp_channel_policy_dynamic_allowed_for_runtime(&context->channels, channelName) ? TRUE
	                                                                                        : FALSE;
}

static BOOL frdpd_display_control_channel_id_assigned(DispServerContext* display_control,
                                                      UINT32 channel_id)
{
	frdpdPeerContext* context = NULL;

	if (!display_control || !display_control->custom)
		return FALSE;
	context = (frdpdPeerContext*)display_control->custom;
	context->display_control_channel_id = channel_id;
	return TRUE;
}

static BOOL frdpd_dvc_creation_status(void* userdata, UINT32 channel_id, INT32 creation_status)
{
	frdpdPeerContext* context = (frdpdPeerContext*)userdata;

	if (!context || (channel_id != context->display_control_channel_id))
		return TRUE;
	if (creation_status < 0)
		context->display_control_creation_failed = TRUE;
	else
		context->display_control_creation_ready = TRUE;
	return TRUE;
}

static UINT frdpd_display_control_monitor_layout(DispServerContext* display_control,
                                                 const DISPLAY_CONTROL_MONITOR_LAYOUT_PDU* pdu)
{
	frdpdPeerContext* context = NULL;
	MONITOR_DEF monitors[FRDPD_DISPLAY_MAX_MONITORS] = { 0 };
	UINT32 width = 0;
	UINT32 height = 0;

	if (!display_control || !display_control->custom || !pdu ||
	    !frdpd_display_control_to_monitors(pdu, monitors, ARRAYSIZE(monitors)) ||
	    !frdpd_display_monitor_bounds(pdu->NumMonitors, monitors, &width, &height))
		return ERROR_INVALID_DATA;

	context = (frdpdPeerContext*)display_control->custom;
	EnterCriticalSection(&context->display_control_lock);
	memcpy(context->display_control_monitors, monitors, pdu->NumMonitors * sizeof(monitors[0]));
	context->display_control_monitor_count = pdu->NumMonitors;
	context->display_control_layout_pending = TRUE;
	LeaveCriticalSection(&context->display_control_lock);
	return CHANNEL_RC_OK;
}

static BOOL frdpd_service_display_control(frdpdPeerContext* context)
{
	BYTE state = DRDYNVC_STATE_NONE;

	if (!context || !context->vcm || !context->drdynvc_joined)
		return TRUE;
	state = WTSVirtualChannelManagerGetDrdynvcState(context->vcm);
	if (state == DRDYNVC_STATE_FAILED)
	{
		WLog_WARN(TAG, "correlation_id=%s dynamic virtual channel negotiation failed",
		          context->correlation_id);
		context->drdynvc_joined = FALSE;
		return TRUE;
	}
	if (state != DRDYNVC_STATE_READY)
		return TRUE;

	if (!context->display_control)
	{
		context->display_control = disp_server_context_new(context->vcm);
		if (!context->display_control)
			return FALSE;
		context->display_control->custom = context;
		context->display_control->rdpcontext = &context->_p;
		context->display_control->MaxNumMonitors = FRDPD_DISPLAY_MAX_MONITORS;
		context->display_control->MaxMonitorAreaFactorA = FRDPD_DISPLAY_MAX_DESKTOP_SIZE;
		context->display_control->MaxMonitorAreaFactorB = FRDPD_DISPLAY_MAX_DESKTOP_SIZE;
		context->display_control->ChannelIdAssigned = frdpd_display_control_channel_id_assigned;
		context->display_control->DispMonitorLayout = frdpd_display_control_monitor_layout;
		if (context->display_control->Open(context->display_control) != CHANNEL_RC_OK)
		{
			WLog_WARN(TAG, "correlation_id=%s failed to open Display Control DVC",
			          context->correlation_id);
			disp_server_context_free(context->display_control);
			context->display_control = NULL;
			context->drdynvc_joined = FALSE;
			return TRUE;
		}
	}

	if (context->display_control_creation_failed)
	{
		WLog_WARN(TAG, "correlation_id=%s client rejected Display Control DVC",
		          context->correlation_id);
		context->drdynvc_joined = FALSE;
		return TRUE;
	}
	if (context->display_control_creation_ready && !context->display_control_caps_sent)
	{
		if (context->display_control->DisplayControlCaps(context->display_control) != CHANNEL_RC_OK)
			return FALSE;
		context->display_control_caps_sent = TRUE;
		WLog_INFO(TAG, "correlation_id=%s Display Control DVC ready", context->correlation_id);
	}
	return TRUE;
}

static BOOL frdpd_peer_context_new(freerdp_peer* client, rdpContext* ctx)
{
	frdpdPeerContext* context = (frdpdPeerContext*)ctx;

	WINPR_ASSERT(ctx);
	if (!InitializeCriticalSectionAndSpinCount(&context->display_control_lock, 4000))
		return FALSE;
	context->display_control_lock_initialized = TRUE;
	if (!InitializeCriticalSectionAndSpinCount(&context->clipboard_lock, 4000))
	{
		DeleteCriticalSection(&context->display_control_lock);
		context->display_control_lock_initialized = FALSE;
		return FALSE;
	}
	context->clipboard_lock_initialized = TRUE;
	if (!frdpd_generate_correlation_id(context->correlation_id, sizeof(context->correlation_id)))
	{
		WLog_ERR(TAG, "Failed to generate peer correlation id");
		DeleteCriticalSection(&context->display_control_lock);
		context->display_control_lock_initialized = FALSE;
		DeleteCriticalSection(&context->clipboard_lock);
		context->clipboard_lock_initialized = FALSE;
		return FALSE;
	}

	context->vcm = WTSOpenServerA((LPSTR)client->context);
	if (!context->vcm || (context->vcm == INVALID_HANDLE_VALUE))
	{
		context->vcm = NULL;
		WLog_ERR(TAG, "correlation_id=%s failed to open virtual channel manager",
		         context->correlation_id);
		DeleteCriticalSection(&context->display_control_lock);
		context->display_control_lock_initialized = FALSE;
		DeleteCriticalSection(&context->clipboard_lock);
		context->clipboard_lock_initialized = FALSE;
		return FALSE;
	}
	WTSVirtualChannelManagerSetDVCCreationCallback(context->vcm, frdpd_dvc_creation_status,
	                                               context);
	WTSVirtualChannelManagerSetDVCChannelAuthorizationCallback(context->vcm, frdpd_dvc_authorize,
	                                                           context);
	return TRUE;
}

static BOOL frdpd_peer_init(freerdp_peer* client)
{
	WINPR_ASSERT(client);

	client->ContextSize = sizeof(frdpdPeerContext);
	client->ContextNew = frdpd_peer_context_new;
	client->ContextFree = frdpd_peer_context_free;
	return freerdp_peer_context_new(client);
}

static BOOL frdpd_reserve_connection(frdpdServerConfig* config, const char* hostname)
{
	const LONG max_connections = config ? (LONG)config->max_connections : 0;
	char log_hostname[FRDPD_LOG_STRING_SIZE] = { 0 };

	if (!config || (max_connections <= 0))
		return TRUE;

	for (;;)
	{
		const LONG active = InterlockedCompareExchange(&config->active_connections, 0, 0);

		if (active >= max_connections)
		{
			WLog_WARN(TAG, "rejecting client %s: max_connections=%ld active=%ld",
			          frdpd_log_value(hostname, log_hostname, sizeof(log_hostname), "unknown"),
			          (long)max_connections, (long)active);
			return FALSE;
		}
		if (InterlockedCompareExchange(&config->active_connections, active + 1, active) == active)
			return TRUE;
	}
}

static void frdpd_release_connection(frdpdServerConfig* config)
{
	if (config && (config->max_connections > 0))
		(void)InterlockedDecrement(&config->active_connections);
}

static void frdpd_peer_clear_owned_auth_identity(freerdp_peer* client,
                                                 const SEC_WINNT_AUTH_IDENTITY* identity)
{
	if (!client || (identity != &client->identity))
		return;
	sspi_FreeAuthIdentity(&client->identity);
}

static BOOL frdpd_peer_query_nla_package(freerdp_peer* client, const char* correlation_id,
                                         const char* log_hostname, char* package_name,
                                         size_t package_name_size)
{
	SecPkgContext_PackageInfo package = { 0 };
	BOOL rc = FALSE;

	WINPR_ASSERT(client);
	WINPR_ASSERT(client->context);
	WINPR_ASSERT(correlation_id);
	WINPR_ASSERT(log_hostname);
	WINPR_ASSERT(package_name);
	WINPR_ASSERT(package_name_size > 0);

	if (freerdp_nla_QueryContextAttributes(client->context, SECPKG_ATTR_PACKAGE_INFO, &package) !=
	    SEC_E_OK)
		goto out;

	if (!package.PackageInfo || !package.PackageInfo->Name ||
	    (package.PackageInfo->Name[0] == '\0') ||
	    (snprintf(package_name, package_name_size, "%s", package.PackageInfo->Name) < 0) ||
	    (strlen(package.PackageInfo->Name) >= package_name_size))
		goto out;

	rc = TRUE;

out:
	if (package.PackageInfo)
	{
		const SECURITY_STATUS status =
		    freerdp_nla_FreeContextBuffer(client->context, package.PackageInfo);
		if (status != SEC_E_OK)
			WLog_WARN(TAG, "correlation_id=%s unable to release NLA SSPI package info for %s",
			          correlation_id, log_hostname);
	}
	return rc;
}

static void frdpd_peer_log_nla_package(const char* correlation_id, const char* log_hostname,
                                       const char* package_name)
{
	char log_package[FRDPD_LOG_STRING_SIZE] = { 0 };

	WINPR_ASSERT(correlation_id);
	WINPR_ASSERT(log_hostname);
	WINPR_ASSERT(package_name);
	WLog_INFO(TAG, "correlation_id=%s NLA SSPI package=%s for %s", correlation_id,
	          frdpd_log_value(package_name, log_package, sizeof(log_package), "unknown"),
	          log_hostname);
}

static BOOL frdpd_peer_logon(freerdp_peer* client, const SEC_WINNT_AUTH_IDENTITY* identity,
                             BOOL automatic)
{
	frdpdServerConfig* config = NULL;
	frdpdPeerContext* context = NULL;
	frdpdAuthResult result = { 0 };
	char log_hostname[FRDPD_LOG_STRING_SIZE] = { 0 };
	char nla_package[FRDPD_LOG_STRING_SIZE] = { 0 };
	char log_user[FRDPD_LOG_STRING_SIZE] = { 0 };
	char requested_user[FRDPD_LOG_STRING_SIZE] = { 0 };

	WINPR_ASSERT(client);
	if (!client->context)
		return FALSE;

	config = (frdpdServerConfig*)client->ContextExtra;
	context = (frdpdPeerContext*)client->context;
	if (!config)
		return FALSE;
	(void)frdpd_client_log_name(client, log_hostname, sizeof(log_hostname));

	if (!automatic && !config->allow_tls_fallback)
	{
		WLog_WARN(TAG, "correlation_id=%s rejecting non-NLA login from %s", context->correlation_id,
		          log_hostname);
		return FALSE;
	}

	if (!identity)
	{
		WLog_WARN(TAG, "correlation_id=%s rejecting login from %s without identity",
		          context->correlation_id, log_hostname);
		return FALSE;
	}

	if (automatic)
	{
		SecPkgContext_AuthIdentity proof = WINPR_C_ARRAY_INIT;
		const BOOL package_known = frdpd_peer_query_nla_package(
		    client, context->correlation_id, log_hostname, nla_package, sizeof(nla_package));
		if (package_known)
			frdpd_peer_log_nla_package(context->correlation_id, log_hostname, nla_package);
		else
			WLog_WARN(TAG, "correlation_id=%s unable to query NLA SSPI package for %s",
			          context->correlation_id, log_hostname);

		if (!config->ntlm_fallback && (!package_known || (_stricmp(nla_package, "Kerberos") != 0)))
		{
			WLog_WARN(TAG,
			          "correlation_id=%s rejecting NLA login from %s because selected SSPI "
			          "package is not Kerberos",
			          context->correlation_id, log_hostname);
			return FALSE;
		}

		if (config->ntlm_fallback)
		{
			const SECURITY_STATUS status = freerdp_nla_QueryContextAttributes(
			    client->context, SECPKG_ATTR_AUTH_IDENTITY, &proof);
			if ((status != SEC_E_OK) ||
			    !frdpd_auth_identity_matches_proof(identity, &proof, config->domain_mode))
			{
				WLog_WARN(TAG,
				          "correlation_id=%s rejecting NLA login from %s because the proof "
				          "identity does not match the delegated credentials",
				          context->correlation_id, log_hostname);
				return FALSE;
			}
		}
	}

	const frdpdAuthConfig auth = {
		.pam_service = config->pam_service,
		.auth_socket = config->auth_socket,
		.correlation_id = context->correlation_id,
		.rhost = (client->hostname[0] != '\0') ? client->hostname : NULL,
		.domain_mode = config->domain_mode,
	};

	(void)frdpd_auth_identity_user_utf8(identity, requested_user, sizeof(requested_user));
	const BOOL ok = frdpd_authenticate_identity(&auth, identity, &result);
	frdpd_peer_clear_owned_auth_identity(client, identity);
	context->auth_status = result.status;
	context->pam_status = result.pam_status;

	if (!ok)
	{
		char log_broker_error[FRDPD_LOG_STRING_SIZE] = { 0 };
		const char* broker_error =
		    frdpd_log_value(result.broker_error[0] ? result.broker_error : NULL, log_broker_error,
		                    sizeof(log_broker_error), "none");

		WLog_WARN(TAG,
		          "correlation_id=%s PAM rejected RDP login for %s from %s: %s (%d), "
		          "broker_error=%s",
		          context->correlation_id,
		          frdpd_log_value(requested_user, log_user, sizeof(log_user), "unknown"), log_hostname,
		          frdpd_pam_auth_status_string(context->auth_status), context->pam_status,
		          broker_error);
		frdpd_auth_result_cleanup(&result);
		return FALSE;
	}

	if (!frdpd_close_managed_session(config, context, FALSE))
	{
		frdpd_auth_result_cleanup(&result);
		return FALSE;
	}
	free(context->pam_user);
	context->pam_user = result.pam_user;
	context->uid = result.uid;
	context->gid = result.gid;
	context->group_count = result.group_count;
	memcpy(context->groups, result.groups, result.group_count * sizeof(result.groups[0]));
	context->has_posix_account = result.has_posix_account;
	memcpy(context->authorization_id, result.authorization_id, sizeof(context->authorization_id));
	result.pam_user = NULL;
	frdpd_auth_result_cleanup(&result);

	WLog_INFO(
	    TAG, "correlation_id=%s PAM accepted RDP login for %s from %s", context->correlation_id,
	    frdpd_log_value(context->pam_user, log_user, sizeof(log_user), "unknown"), log_hostname);
	return TRUE;
}

static BOOL
frdpd_peer_remote_credentials(freerdp_peer* client,
                              WINPR_ATTR_UNUSED KERB_TICKET_LOGON* logon_creds,
                              WINPR_ATTR_UNUSED MSV1_0_REMOTE_SUPPLEMENTAL_CREDENTIAL* supp_creds)
{
	frdpdPeerContext* context = NULL;
	char log_hostname[FRDPD_LOG_STRING_SIZE] = { 0 };

	WINPR_ASSERT(client);
	context = (frdpdPeerContext*)client->context;
	WLog_WARN(TAG, "correlation_id=%s rejecting unsupported Remote Credential Guard login from %s",
	          context ? context->correlation_id : "unknown",
	          frdpd_client_log_name(client, log_hostname, sizeof(log_hostname)));
	return FALSE;
}

static BOOL frdpd_peer_post_connect(freerdp_peer* client)
{
	rdpSettings* settings = NULL;
	frdpdPeerContext* context = NULL;
	char log_hostname[FRDPD_LOG_STRING_SIZE] = { 0 };
	char log_user[FRDPD_LOG_STRING_SIZE] = { 0 };

	WINPR_ASSERT(client);
	WINPR_ASSERT(client->context);

	settings = client->context->settings;
	context = (frdpdPeerContext*)client->context;
	WINPR_ASSERT(settings);
	WINPR_ASSERT(context);

	WLog_INFO(TAG,
	          "correlation_id=%s client %s logged in as %s; requested desktop %" PRIu32 "x%" PRIu32
	          "x%" PRIu32,
	          context->correlation_id,
	          frdpd_client_log_name(client, log_hostname, sizeof(log_hostname)),
	          frdpd_log_value(context->pam_user, log_user, sizeof(log_user), "unknown"),
	          freerdp_settings_get_uint32(settings, FreeRDP_DesktopWidth),
	          freerdp_settings_get_uint32(settings, FreeRDP_DesktopHeight),
	          freerdp_settings_get_uint32(settings, FreeRDP_ColorDepth));
	return TRUE;
}

static BOOL frdpd_peer_activate(freerdp_peer* client)
{
	frdpdPeerContext* context = NULL;
	char log_hostname[FRDPD_LOG_STRING_SIZE] = { 0 };

	WINPR_ASSERT(client);
	context = (frdpdPeerContext*)client->context;
	if (context)
	{
		frdpd_reset_framebuffer_state(context);
		context->framebuffer_active = TRUE;
	}
	WLog_INFO(TAG, "correlation_id=%s client %s activated",
	          context ? context->correlation_id : "unknown",
	          frdpd_client_log_name(client, log_hostname, sizeof(log_hostname)));
	return TRUE;
}

static BOOL frdpd_peer_client_capabilities(freerdp_peer* client)
{
	frdpdPeerContext* context = NULL;
	frdpdServerConfig* config = NULL;
	rdpSettings* settings = NULL;
	UINT32 channel_count = 0;
	char log_hostname[FRDPD_LOG_STRING_SIZE] = { 0 };

	if (!client || !client->context)
		return FALSE;
	context = (frdpdPeerContext*)client->context;
	config = (frdpdServerConfig*)client->ContextExtra;
	settings = client->context->settings;
	if (!config || !settings)
		return FALSE;
	(void)frdpd_client_log_name(client, log_hostname, sizeof(log_hostname));

	channel_count = freerdp_settings_get_uint32(settings, FreeRDP_ChannelCount);
	context->drdynvc_joined = FALSE;
	context->cliprdr_joined = FALSE;
	for (UINT32 i = 0; i < channel_count; i++)
	{
		char name[CHANNEL_NAME_LEN + 2] = { 0 };
		char log_name[((CHANNEL_NAME_LEN + 1) * 4) + 1] = { 0 };
		const CHANNEL_DEF* channel = (const CHANNEL_DEF*)freerdp_settings_get_pointer_array(
		    settings, FreeRDP_ChannelDefArray, i);

		int allowed = frdp_channel_policy_static_channel_allowed_for_runtime(
		    &context->channels, &context->clipboard, channel, name, sizeof(name));
		if (allowed && (strcmp(name, "drdynvc") == 0))
		{
			allowed = frdp_channel_policy_dynamic_allowed_for_runtime(&context->channels,
			                                                          DISP_DVC_CHANNEL_NAME);
			context->drdynvc_joined = allowed ? TRUE : FALSE;
		}
		else if (allowed && (strcmp(name, "cliprdr") == 0))
			context->cliprdr_joined = TRUE;
		frdpd_escape_log_string(log_name, sizeof(log_name), name);
		if (!allowed)
		{
			WLog_WARN(TAG, "correlation_id=%s rejected static virtual channel '%s' from client %s",
			          context ? context->correlation_id : "unknown",
			          (log_name[0] != '\0') ? log_name : "invalid", log_hostname);
			return FALSE;
		}
	}

	return frdpd_open_managed_session(client, config, context);
}

static BOOL frdpd_peer_synchronize_event(rdpInput* input, UINT32 flags)
{
	if (!input || !input->context)
		return FALSE;
	return frdpd_send_agent_input((frdpdPeerContext*)input->context, FRDP_AGENT_INPUT_SYNC, flags,
	                              0, 0);
}

static BOOL frdpd_peer_keyboard_event(rdpInput* input, UINT16 flags, UINT8 code)
{
	if (!input || !input->context)
		return FALSE;
	return frdpd_send_agent_input((frdpdPeerContext*)input->context, FRDP_AGENT_INPUT_KEYBOARD,
	                              flags, code, 0);
}

static BOOL frdpd_peer_unicode_keyboard_event(rdpInput* input, UINT16 flags, UINT16 code)
{
	if (!input || !input->context)
		return FALSE;
	return frdpd_send_agent_input((frdpdPeerContext*)input->context, FRDP_AGENT_INPUT_UNICODE,
	                              flags, code, 0);
}

static BOOL frdpd_peer_mouse_event(rdpInput* input, UINT16 flags, UINT16 x, UINT16 y)
{
	if (!input || !input->context)
		return FALSE;
	return frdpd_send_agent_input((frdpdPeerContext*)input->context, FRDP_AGENT_INPUT_MOUSE, flags,
	                              x, y);
}

static BOOL frdpd_peer_rel_mouse_event(rdpInput* input, UINT16 flags, INT16 xDelta, INT16 yDelta)
{
	if (!input || !input->context)
		return FALSE;
	return frdpd_send_agent_input((frdpdPeerContext*)input->context, FRDP_AGENT_INPUT_REL_MOUSE,
	                              flags, xDelta, yDelta);
}

static BOOL frdpd_peer_extended_mouse_event(rdpInput* input, UINT16 flags, UINT16 x, UINT16 y)
{
	if (!input || !input->context)
		return FALSE;
	return frdpd_send_agent_input((frdpdPeerContext*)input->context, FRDP_AGENT_INPUT_EXT_MOUSE,
	                              flags, x, y);
}

static BOOL frdpd_peer_remote_monitors(rdpContext* context, UINT32 count,
                                       const MONITOR_DEF* monitors)
{
	frdpdPeerContext* frdp_context = NULL;
	rdpSettings* settings = NULL;
	UINT32 width = 0;
	UINT32 height = 0;
	UINT32 old_width = 0;
	UINT32 old_height = 0;
	UINT32 color_depth = 0;
	char log_session_id[FRDPD_LOG_STRING_SIZE] = { 0 };

	if (!context || !monitors)
		return FALSE;
	settings = context->settings;
	if (!settings)
		return FALSE;
	if (!frdpd_display_monitor_bounds(count, monitors, &width, &height))
		return FALSE;

	old_width = freerdp_settings_get_uint32(settings, FreeRDP_DesktopWidth);
	old_height = freerdp_settings_get_uint32(settings, FreeRDP_DesktopHeight);
	if ((width == old_width) && (height == old_height))
		return TRUE;

	frdp_context = (frdpdPeerContext*)context;
	color_depth = freerdp_settings_get_uint32(settings, FreeRDP_ColorDepth);
	if (frdp_context->managed_session_open &&
	    !frdpd_send_agent_resize(frdp_context, width, height, color_depth))
	{
		WLog_WARN(
		    TAG,
		    "correlation_id=%s ignored display resize to %" PRIu32 "x%" PRIu32 " for session_id=%s",
		    frdp_context->correlation_id, width, height,
		    frdpd_context_log_session_id(frdp_context, log_session_id, sizeof(log_session_id)));
		return TRUE;
	}

	if (!freerdp_settings_set_uint32(settings, FreeRDP_DesktopWidth, width) ||
	    !freerdp_settings_set_uint32(settings, FreeRDP_DesktopHeight, height))
		return FALSE;
	frdpd_invalidate_framebuffer_cache(frdp_context);
	frdpd_reset_frame_encoder(frdp_context);
	WLog_INFO(TAG,
	          "correlation_id=%s accepted display resize %" PRIu32 "x%" PRIu32
	          " monitor_count=%" PRIu32,
	          frdp_context->correlation_id, width, height, count);
	return TRUE;
}

static BOOL frdpd_process_pending_display_control(frdpdPeerContext* context)
{
	MONITOR_DEF monitors[FRDPD_DISPLAY_MAX_MONITORS] = { 0 };
	UINT32 count = 0;

	if (!context || !context->display_control_lock_initialized)
		return FALSE;
	EnterCriticalSection(&context->display_control_lock);
	if (context->display_control_layout_pending)
	{
		count = context->display_control_monitor_count;
		memcpy(monitors, context->display_control_monitors, count * sizeof(monitors[0]));
		context->display_control_layout_pending = FALSE;
	}
	LeaveCriticalSection(&context->display_control_lock);

	if (count == 0)
		return TRUE;
	return frdpd_peer_remote_monitors(&context->_p, count, monitors);
}

static BOOL frdpd_peer_refresh_rect(rdpContext* context, BYTE count, const RECTANGLE_16* areas)
{
	WINPR_UNUSED(count);
	WINPR_UNUSED(areas);
	if (context)
		frdpd_invalidate_framebuffer_cache((frdpdPeerContext*)context);
	return TRUE;
}

static BOOL frdpd_peer_suppress_output(rdpContext* context, BYTE allow, const RECTANGLE_16* area)
{
	WINPR_UNUSED(area);
	if (context)
	{
		frdpdPeerContext* frdp_context = (frdpdPeerContext*)context;
		frdp_context->framebuffer_output_suppressed = allow ? FALSE : TRUE;
		if (allow)
			frdpd_invalidate_framebuffer_cache(frdp_context);
	}
	return TRUE;
}

static BOOL frdpd_configure_security(freerdp_peer* client, const frdpdServerConfig* config)
{
	rdpSettings* settings = NULL;
	rdpPrivateKey* key = NULL;
	rdpCertificate* cert = NULL;

	WINPR_ASSERT(client);
	WINPR_ASSERT(client->context);
	WINPR_ASSERT(config);

	settings = client->context->settings;
	WINPR_ASSERT(settings);

	key = freerdp_key_new_from_file_enc(config->key_path, NULL);
	if (!key)
	{
		WLog_ERR(TAG, "Unable to load RDP server private key %s", config->key_path);
		return FALSE;
	}
	if (!freerdp_settings_set_pointer_len(settings, FreeRDP_RdpServerRsaKey, key, 1))
		return FALSE;

	cert = freerdp_certificate_new_from_file(config->cert_path);
	if (!cert)
	{
		WLog_ERR(TAG, "Unable to load RDP server certificate %s", config->cert_path);
		return FALSE;
	}
	if (!freerdp_settings_set_pointer_len(settings, FreeRDP_RdpServerCertificate, cert, 1))
		return FALSE;

	if (!freerdp_settings_set_bool(settings, FreeRDP_RdpSecurity, FALSE))
		return FALSE;
	if (!freerdp_settings_set_bool(settings, FreeRDP_TlsSecurity, config->allow_tls_fallback))
		return FALSE;
	if (!freerdp_settings_set_bool(settings, FreeRDP_NlaSecurity, TRUE))
		return FALSE;
	if (!config->ntlm_fallback &&
	    !freerdp_settings_set_string(settings, FreeRDP_AuthenticationPackageList,
	                                 FRDPD_KERBEROS_ONLY_PACKAGE_LIST))
		return FALSE;
#ifdef WITH_FRDPD_NTLM
	if (config->ntlm_fallback &&
	    !freerdp_settings_set_string(settings, FreeRDP_NtlmSamFile, config->ntlm_sam_file))
		return FALSE;
#endif
	if (!freerdp_settings_set_uint32(settings, FreeRDP_EncryptionLevel,
	                                 ENCRYPTION_LEVEL_CLIENT_COMPATIBLE))
		return FALSE;
	if (!freerdp_settings_set_bool(settings, FreeRDP_RemoteFxCodec, TRUE))
		return FALSE;
	if (!freerdp_settings_set_bool(settings, FreeRDP_NSCodec, TRUE))
		return FALSE;
	if (!freerdp_settings_set_uint32(settings, FreeRDP_NSCodecColorLossLevel,
	                                 FRDPD_NSC_COLOR_LOSS_LEVEL))
		return FALSE;
	if (!freerdp_settings_set_bool(settings, FreeRDP_NSCodecAllowSubsampling, FALSE))
		return FALSE;
	if (!freerdp_settings_set_bool(settings, FreeRDP_NSCodecAllowDynamicColorFidelity, FALSE))
		return FALSE;
	if (!freerdp_settings_set_uint32(settings, FreeRDP_ColorDepth, 32))
		return FALSE;
	if (!freerdp_settings_set_bool(settings, FreeRDP_SuppressOutput, TRUE))
		return FALSE;
	if (!freerdp_settings_set_bool(settings, FreeRDP_RefreshRect, TRUE))
		return FALSE;
	if (!freerdp_settings_set_bool(settings, FreeRDP_DesktopResize, TRUE))
		return FALSE;
	if (!freerdp_settings_set_bool(settings, FreeRDP_SupportDisplayControl, TRUE))
		return FALSE;
	if (!freerdp_settings_set_bool(settings, FreeRDP_DynamicResolutionUpdate, TRUE))
		return FALSE;
	if (!freerdp_settings_set_bool(settings, FreeRDP_UseMultimon, TRUE))
		return FALSE;
	if (!freerdp_settings_set_bool(settings, FreeRDP_HasRelativeMouseEvent, TRUE))
		return FALSE;
	if (!freerdp_settings_set_uint32(settings, FreeRDP_MultifragMaxRequestSize, 0xFFFFFF))
		return FALSE;

	return TRUE;
}

static void frdpd_register_callbacks(freerdp_peer* client)
{
	rdpInput* input = NULL;
	rdpUpdate* update = NULL;

	WINPR_ASSERT(client);
	WINPR_ASSERT(client->context);

	client->Logon = frdpd_peer_logon;
	client->RemoteCredentials = frdpd_peer_remote_credentials;
	client->ClientCapabilities = frdpd_peer_client_capabilities;
	client->PostConnect = frdpd_peer_post_connect;
	client->Activate = frdpd_peer_activate;

	input = client->context->input;
	WINPR_ASSERT(input);
	input->SynchronizeEvent = frdpd_peer_synchronize_event;
	input->KeyboardEvent = frdpd_peer_keyboard_event;
	input->UnicodeKeyboardEvent = frdpd_peer_unicode_keyboard_event;
	input->MouseEvent = frdpd_peer_mouse_event;
	input->RelMouseEvent = frdpd_peer_rel_mouse_event;
	input->ExtendedMouseEvent = frdpd_peer_extended_mouse_event;

	update = client->context->update;
	WINPR_ASSERT(update);
	update->RefreshRect = frdpd_peer_refresh_rect;
	update->SuppressOutput = frdpd_peer_suppress_output;
	update->RemoteMonitors = frdpd_peer_remote_monitors;
}

static DWORD WINAPI frdpd_peer_mainloop(LPVOID arg)
{
	freerdp_peer* client = (freerdp_peer*)arg;
	frdpdServerConfig* config = NULL;
	frdpdPeerContext* context = NULL;
	char log_hostname[FRDPD_LOG_STRING_SIZE] = { 0 };

	WINPR_ASSERT(client);
	config = (frdpdServerConfig*)client->ContextExtra;
	WINPR_ASSERT(config);

	if (!frdpd_peer_init(client))
		goto fail;
	context = (frdpdPeerContext*)client->context;
	EnterCriticalSection(&g_frdpd_policy_lock);
	context->channels = config->channels;
	context->clipboard = config->clipboard;
	LeaveCriticalSection(&g_frdpd_policy_lock);
	if (!frdpd_configure_security(client, config))
		goto fail;

	frdpd_register_callbacks(client);

	WINPR_ASSERT(client->Initialize);
	if (!client->Initialize(client))
		goto fail;
	(void)frdpd_client_log_name(client, log_hostname, sizeof(log_hostname));

	WLog_INFO(TAG, "correlation_id=%s accepted client %s", context->correlation_id, log_hostname);

	while (g_frdpd_running)
	{
		HANDLE handles[MAXIMUM_WAIT_OBJECTS] = { 0 };
		HANDLE channel_event = NULL;
		DWORD count = 0;
		DWORD status = 0;

		WINPR_ASSERT(client->GetEventHandles);
		count = client->GetEventHandles(client, handles, ARRAYSIZE(handles));
		if (count == 0)
		{
			WLog_ERR(TAG, "Failed to get peer event handles");
			break;
		}
		if (context->vcm)
		{
			if (count >= ARRAYSIZE(handles))
			{
				WLog_ERR(TAG, "No wait handle slot for peer virtual channel manager");
				break;
			}
			channel_event = WTSVirtualChannelManagerGetEventHandle(context->vcm);
			if (!channel_event || (channel_event == INVALID_HANDLE_VALUE))
			{
				WLog_ERR(TAG, "Failed to get peer virtual channel manager event handle");
				break;
			}
			handles[count++] = channel_event;
		}

		status = WaitForMultipleObjects(count, handles, FALSE, frdpd_peer_wait_timeout_ms(context));
		if (status == WAIT_TIMEOUT)
		{
			if (!frdpd_service_display_control(context) ||
			    !frdpd_process_pending_display_control(context) ||
			    !frdpd_clipboard_runtime_service(context))
				break;
			if (!frdpd_pump_agent_framebuffer(client, context))
				break;
			continue;
		}
		if (status == WAIT_FAILED)
		{
			WLog_ERR(TAG, "WaitForMultipleObjects failed for peer %s", log_hostname);
			break;
		}

		WINPR_ASSERT(client->CheckFileDescriptor);
		if (!client->CheckFileDescriptor(client))
			break;
		if (!frdpd_clipboard_runtime_service(context))
			break;
		if (context->vcm &&
		    !WTSVirtualChannelManagerCheckFileDescriptorEx(context->vcm, context->drdynvc_joined))
		{
			WLog_ERR(TAG, "Virtual channel manager check failed for peer %s", log_hostname);
			break;
		}
		if (!frdpd_service_display_control(context) ||
		    !frdpd_process_pending_display_control(context))
			break;
		if (!frdpd_pump_agent_framebuffer(client, context))
			break;
	}

	WLog_INFO(TAG, "correlation_id=%s client %s disconnected", context->correlation_id,
	          log_hostname);
	WINPR_ASSERT(client->Disconnect);
	client->Disconnect(client);

fail:
	freerdp_peer_context_free(client);
	freerdp_peer_free(client);
	frdpd_release_connection(config);
	return 0;
}

static BOOL frdpd_peer_accepted(freerdp_listener* instance, freerdp_peer* client)
{
	HANDLE thread = NULL;
	frdpdServerConfig* config = NULL;

	WINPR_ASSERT(instance);
	WINPR_ASSERT(client);

	config = (frdpdServerConfig*)instance->info;
	WINPR_ASSERT(config);

	if (!frdpd_reserve_connection(config, client->hostname))
	{
		freerdp_peer_free(client);
		return TRUE;
	}

	client->ContextExtra = instance->info;
	thread = CreateThread(NULL, 0, frdpd_peer_mainloop, client, 0, NULL);
	if (!thread)
	{
		frdpd_release_connection(config);
		return FALSE;
	}

	(void)CloseHandle(thread);
	return TRUE;
}

static void frdpd_reload_peer_policy(frdpdOptions* options)
{
	frdpConfig config = { 0 };
	frdpdOptions candidate = { 0 };

	WINPR_ASSERT(options);
	g_frdpd_reload_requested = 0;
	if (!options->config_path)
	{
		WLog_WARN(TAG, "ignoring SIGHUP because frdpd was started without --config");
		return;
	}
	if (frdp_config_load(options->config_path, &config) != 0)
	{
		WLog_ERR(TAG,
		         "failed to reload channel and clipboard policy from %s; retaining previous "
		         "policy",
		         options->config_path);
		return;
	}
	candidate.file_config = config;
	if (!frdpd_apply_file_config(&candidate))
	{
		WLog_ERR(TAG,
		         "configuration from %s is not supported by frdpd; retaining previous channel "
		         "and clipboard policy",
		         options->config_path);
		return;
	}

	EnterCriticalSection(&g_frdpd_policy_lock);
	options->server.channels = config.channels;
	options->server.clipboard = config.clipboard;
	LeaveCriticalSection(&g_frdpd_policy_lock);
	WLog_INFO(TAG,
	          "reloaded channel and clipboard policy from %s for new connections; existing "
	          "connections retain their policy snapshot",
	          options->config_path);
}

static void frdpd_server_mainloop(freerdp_listener* instance, frdpdOptions* options)
{
	WINPR_ASSERT(instance);
	WINPR_ASSERT(options);

	while (g_frdpd_running)
	{
		HANDLE handles[MAXIMUM_WAIT_OBJECTS] = { 0 };
		DWORD count = 0;
		DWORD status = 0;

		if (g_frdpd_reload_requested)
			frdpd_reload_peer_policy(options);

		WINPR_ASSERT(instance->GetEventHandles);
		count = instance->GetEventHandles(instance, handles, ARRAYSIZE(handles));
		if (count == 0)
		{
			WLog_ERR(TAG, "Failed to get listener event handles");
			break;
		}

		status = WaitForMultipleObjects(count, handles, FALSE, 250);
		if (status == WAIT_TIMEOUT)
			continue;
		if (status == WAIT_FAILED)
		{
			WLog_ERR(TAG, "WaitForMultipleObjects failed for listener");
			break;
		}

		WINPR_ASSERT(instance->CheckFileDescriptor);
		if (!instance->CheckFileDescriptor(instance))
		{
			WLog_ERR(TAG, "Failed to check listener file descriptor");
			break;
		}
	}

	WINPR_ASSERT(instance->Close);
	instance->Close(instance);
}

static frdpdDomainMode frdpd_parse_domain_mode(const char* value, BOOL* ok)
{
	WINPR_ASSERT(ok);
	*ok = TRUE;

	if (!value || (_stricmp(value, "plain") == 0))
		return FRDPD_DOMAIN_PLAIN;
	if (_stricmp(value, "downlevel") == 0)
		return FRDPD_DOMAIN_DOWNLEVEL;
	if (_stricmp(value, "upn") == 0)
		return FRDPD_DOMAIN_UPN;
	if (_stricmp(value, "auto") == 0)
		return FRDPD_DOMAIN_AUTO;

	*ok = FALSE;
	return FRDPD_DOMAIN_PLAIN;
}

static void frdpd_print_usage(const char* app)
{
	(void)fprintf(stderr, "Usage:\n");
	(void)fprintf(stderr, "  %s [options]\n", app);
	(void)fprintf(
	    stderr, "  %s --pam-auth-test USER [--domain DOMAIN] [--service SERVICE] [--rhost HOST]\n",
	    app);
	(void)fprintf(stderr, "Options:\n");
	(void)fprintf(stderr, "  --bind=<address>              Bind address, default all interfaces\n");
	(void)fprintf(stderr, "  --port=<port>                 TCP port, default 3389\n");
	(void)fprintf(stderr,
	              "  --max-connections=<n>         Concurrent accepted peer cap, 0 disables\n");
	(void)fprintf(stderr, "  --cert=<path>                 TLS certificate, default server.crt\n");
	(void)fprintf(stderr, "  --key=<path>                  TLS private key, default server.key\n");
	(void)fprintf(stderr, "  --config=<path>               Load frdpd.toml before CLI overrides\n");
	(void)fprintf(stderr, "  --pam-service=<name>          PAM service name, default frdpd\n");
	(void)fprintf(stderr,
	              "  --auth-socket=<path>          Auth/account IPC for normal helper topology\n");
	(void)fprintf(
	    stderr, "  --session-socket=<path>       Session-manager IPC for normal helper topology\n");
	(void)fprintf(stderr, "  --service <name>              PAM service alias for auth test\n");
	(void)fprintf(stderr, "  --domain-mode=plain|downlevel|upn|auto\n");
	(void)fprintf(stderr,
	              "  --allow-tls-fallback          Also advertise TLS; NLA remains preferred\n");
}

static BOOL frdpd_parse_port(const char* value, UINT16* port)
{
	char* end = NULL;
	long tmp = 0;

	WINPR_ASSERT(port);
	if (!value || (value[0] == '\0'))
		return FALSE;

	errno = 0;
	tmp = strtol(value, &end, 10);
	if ((errno != 0) || !end || (end[0] != '\0') || (tmp < 1) || (tmp > UINT16_MAX))
		return FALSE;

	*port = (UINT16)tmp;
	return TRUE;
}

static BOOL frdpd_parse_max_connections(const char* value, UINT32* max_connections)
{
	char* end = NULL;
	unsigned long tmp = 0;

	WINPR_ASSERT(max_connections);
	if (!value || (value[0] == '\0') || (value[0] == '-'))
		return FALSE;

	errno = 0;
	tmp = strtoul(value, &end, 10);
	if ((errno != 0) || !end || (end[0] != '\0') || (tmp > INT_MAX))
		return FALSE;

	*max_connections = (UINT32)tmp;
	return TRUE;
}

static BOOL frdpd_string_is_empty(const char* value)
{
	return !value || (value[0] == '\0');
}

static BOOL frdpd_socket_path_is_valid(const char* value)
{
	return !frdpd_string_is_empty(value) && (value[0] == '/');
}

static BOOL frdpd_apply_listen_config(frdpdOptions* options, const char* listen)
{
	char buffer[sizeof(options->config_bind_address) + 8] = { 0 };
	char* colon = NULL;

	WINPR_ASSERT(options);
	if (frdpd_string_is_empty(listen))
		return TRUE;
	if (strlen(listen) >= sizeof(buffer))
		return FALSE;

	(void)strcpy(buffer, listen);
	colon = strrchr(buffer, ':');
	if (!colon)
	{
		(void)strcpy(options->config_bind_address, buffer);
		options->server.bind_address = options->config_bind_address;
		return TRUE;
	}

	*colon = '\0';
	if (!frdpd_parse_port(colon + 1, &options->server.port))
		return FALSE;

	if (buffer[0] != '\0')
	{
		if (strlen(buffer) >= sizeof(options->config_bind_address))
			return FALSE;
		(void)strcpy(options->config_bind_address, buffer);
		options->server.bind_address = options->config_bind_address;
	}
	return TRUE;
}

static BOOL frdpd_apply_file_config(frdpdOptions* options)
{
	const frdpConfig* config = NULL;

	WINPR_ASSERT(options);
	config = &options->file_config;

	if (!frdpd_apply_listen_config(options, config->listen))
		return FALSE;
	options->server.max_connections = config->max_connections;
	if (_stricmp(config->auth_mode, "pam-sssd") != 0)
		return FALSE;
	if (config->kerberos)
	{
		WLog_ERR(TAG, "Kerberos acceptor configuration requires integrated CredSSP/SPNEGO support");
		return FALSE;
	}
	if (!frdpd_string_is_empty(config->tls_cert))
		options->server.cert_path = config->tls_cert;
	if (!frdpd_string_is_empty(config->tls_key))
		options->server.key_path = config->tls_key;
	if (!frdpd_string_is_empty(config->pam_service))
		options->server.pam_service = config->pam_service;
	if (!frdpd_string_is_empty(config->auth_socket))
	{
		if (!frdpd_socket_path_is_valid(config->auth_socket))
			return FALSE;
		options->server.auth_socket = config->auth_socket;
	}
	options->server.ntlm_fallback = config->ntlm_fallback ? TRUE : FALSE;
	if (!frdpd_string_is_empty(config->ntlm_sam_file))
		options->server.ntlm_sam_file = config->ntlm_sam_file;
	if (!frdpd_string_is_empty(config->session_socket))
	{
		if (!frdpd_socket_path_is_valid(config->session_socket))
			return FALSE;
		options->server.session_socket = config->session_socket;
	}
	options->server.channels = config->channels;
	options->server.clipboard = config->clipboard;

	if (_stricmp(config->security, "nla") == 0)
		options->server.allow_tls_fallback = FALSE;
	else
		return FALSE;

	return TRUE;
}

static BOOL frdpd_args_have_help(int argc, char* argv[])
{
	WINPR_ASSERT(argv);

	for (int x = 1; x < argc; x++)
	{
		if ((strcmp(argv[x], "--help") == 0) || (strcmp(argv[x], "-h") == 0))
			return TRUE;
	}
	return FALSE;
}

static BOOL frdpd_find_config_arg(int argc, char* argv[], const char** config_path)
{
	WINPR_ASSERT(argv);
	WINPR_ASSERT(config_path);

	*config_path = NULL;
	for (int x = 1; x < argc; x++)
	{
		const char* arg = argv[x];
		if (strcmp(arg, "--config") == 0)
		{
			if (++x >= argc)
				return FALSE;
			*config_path = argv[x];
		}
		else if (strncmp(arg, "--config=", 9) == 0)
			*config_path = &arg[9];
	}
	return TRUE;
}

static const char* frdpd_arg_value(int argc, char** argv, int* index)
{
	if ((*index + 1) >= argc)
		return NULL;
	(*index)++;
	return argv[*index];
}

static BOOL frdpd_set_arg_value(const char** target, int argc, char** argv, int* index)
{
	*target = frdpd_arg_value(argc, argv, index);
	return *target != NULL;
}

static BOOL frdpd_parse_args(int argc, char* argv[], frdpdOptions* options)
{
	WINPR_ASSERT(argv);
	WINPR_ASSERT(options);

	for (int x = 1; x < argc; x++)
	{
		const char* arg = argv[x];
		if (strcmp(arg, "--pam-auth-test") == 0)
		{
			if (!frdpd_set_arg_value(&options->test_user, argc, argv, &x))
				return FALSE;
			options->pam_auth_test = TRUE;
		}
		else if (strcmp(arg, "--domain") == 0)
		{
			if (!frdpd_set_arg_value(&options->test_domain, argc, argv, &x))
				return FALSE;
		}
		else if (strcmp(arg, "--service") == 0)
		{
			if (!frdpd_set_arg_value(&options->server.pam_service, argc, argv, &x))
				return FALSE;
		}
		else if (strcmp(arg, "--rhost") == 0)
		{
			if (!frdpd_set_arg_value(&options->test_rhost, argc, argv, &x))
				return FALSE;
		}
		else if (strncmp(arg, "--bind=", 7) == 0)
			options->server.bind_address = &arg[7];
		else if (strncmp(arg, "--port=", 7) == 0)
		{
			if (!frdpd_parse_port(&arg[7], &options->server.port))
				return FALSE;
		}
		else if (strncmp(arg, "--max-connections=", 18) == 0)
		{
			if (!frdpd_parse_max_connections(&arg[18], &options->server.max_connections))
				return FALSE;
		}
		else if (strncmp(arg, "--cert=", 7) == 0)
			options->server.cert_path = &arg[7];
		else if (strncmp(arg, "--key=", 6) == 0)
			options->server.key_path = &arg[6];
		else if (strcmp(arg, "--config") == 0)
		{
			if (!frdpd_set_arg_value(&options->config_path, argc, argv, &x))
				return FALSE;
		}
		else if (strncmp(arg, "--config=", 9) == 0)
			options->config_path = &arg[9];
		else if (strncmp(arg, "--pam-service=", 14) == 0)
			options->server.pam_service = &arg[14];
		else if (strncmp(arg, "--auth-socket=", 14) == 0)
		{
			if (!frdpd_socket_path_is_valid(&arg[14]))
				return FALSE;
			options->server.auth_socket = &arg[14];
		}
		else if (strncmp(arg, "--session-socket=", 17) == 0)
		{
			if (!frdpd_socket_path_is_valid(&arg[17]))
				return FALSE;
			options->server.session_socket = &arg[17];
		}
		else if (strncmp(arg, "--domain-mode=", 14) == 0)
		{
			BOOL ok = FALSE;
			options->server.domain_mode = frdpd_parse_domain_mode(&arg[14], &ok);
			options->domain_mode_set = ok;
			if (!ok)
				return FALSE;
		}
		else if (strcmp(arg, "--allow-tls-fallback") == 0)
			options->server.allow_tls_fallback = TRUE;
		else if ((strcmp(arg, "--help") == 0) || (strcmp(arg, "-h") == 0))
			options->show_help = TRUE;
		else
			return FALSE;
	}

	return TRUE;
}

static int frdpd_run_pam_auth_test(const frdpdOptions* options)
{
	char* password = NULL;

	WINPR_ASSERT(options);

	if (!options->test_user)
		return 2;

	password = getpass("Password: ");
	if (!password)
	{
		(void)fprintf(stderr, "failed to read password\n");
		return 1;
	}

	frdpdPamAuthRequest request = {
		.service = options->server.pam_service,
		.user = options->test_user,
		.domain = options->test_domain,
		.password = password,
		.rhost = options->test_rhost,
		.domain_mode =
		    options->domain_mode_set ? options->server.domain_mode : FRDPD_DOMAIN_DOWNLEVEL,
		.pam_status = 0,
	};

	const frdpdPamAuthStatus status = frdpd_pam_authenticate(&request);
	(void)printf("pam-auth-test=%s pam-status=%d\n", frdpd_pam_auth_status_string(status),
	             request.pam_status);
	frdpd_pam_clear_secret(password);

	return (status == FRDPD_PAM_AUTH_OK) ? 0 : 1;
}

static BOOL frdpd_validate_runtime_topology(frdpdOptions* options)
{
	frdpdServerConfig* config = NULL;
	BOOL has_auth_socket = FALSE;
	BOOL has_session_socket = FALSE;

	WINPR_ASSERT(options);
	config = &options->server;
	has_auth_socket = config->auth_socket && (config->auth_socket[0] != '\0');
	has_session_socket = config->session_socket && (config->session_socket[0] != '\0');

	if (!has_auth_socket && !has_session_socket)
	{
		WLog_ERR(TAG, "frdpd normal startup requires --auth-socket and --session-socket");
		return FALSE;
	}
	if (!has_auth_socket || !has_session_socket)
	{
		WLog_ERR(TAG, "frdpd helper topology requires both auth_socket and session_socket");
		return FALSE;
	}
	return TRUE;
}

static BOOL frdpd_validate_ntlm_config(frdpdServerConfig* config)
{
	WINPR_ASSERT(config);

#ifdef WITH_FRDPD_NTLM
	if (!frdpd_prepare_ntlm_sam_file(config))
	{
		WLog_ERR(TAG, "NTLM fallback requires a valid non-empty owner-only regular "
		              "ntlm_sam_file owned by frdpd");
		return FALSE;
	}
#endif
	return TRUE;
}

static BOOL frdpd_validate_build_features(const frdpdServerConfig* config)
{
	WINPR_ASSERT(config);

#ifndef WITH_FRDPD_NTLM
	if (config->ntlm_fallback)
	{
		WLog_ERR(TAG, "NTLM authentication was disabled at build time; rebuild with "
		              "-DWITH_FRDPD_NTLM=ON or set ntlm_fallback=false");
		return FALSE;
	}
#endif
	return TRUE;
}

static BOOL frdpd_probe_helper(const char* socket_path, const char* expected_role)
{
	frdpControlResponse response = { 0 };
	int fd = -1;
	BOOL ready = FALSE;

	if (!socket_path || !expected_role)
		return FALSE;
	fd = frdp_ipc_connect_timeout(socket_path, FRDPD_HELPER_READY_TIMEOUT_MS);
	if (fd < 0)
		goto cleanup;
	if ((frdp_ipc_exchange_helper_health(fd, &response, FRDPD_HELPER_READY_TIMEOUT_MS) != 0) ||
	    !response.success || !memchr(response.message, '\0', sizeof(response.message)) ||
	    !memchr(response.error, '\0', sizeof(response.error)) || (response.error[0] != '\0') ||
	    (strcmp(response.message, expected_role) != 0))
		goto cleanup;
	ready = TRUE;

cleanup:
	if (fd >= 0)
		(void)frdp_ipc_close(fd);
	SecureZeroMemory(&response, sizeof(response));
	return ready;
}

static BOOL frdpd_wait_for_helper(const char* socket_path, const char* expected_role)
{
	for (UINT32 attempt = 0; attempt < FRDPD_HELPER_READY_ATTEMPTS; attempt++)
	{
		if (frdpd_probe_helper(socket_path, expected_role))
			return TRUE;
		Sleep(FRDPD_HELPER_READY_RETRY_MS);
	}
	WLog_ERR(TAG, "helper role '%s' did not become ready on %s", expected_role, socket_path);
	return FALSE;
}

static int frdpd_run_server(frdpdOptions* options)
{
	int rc = -1;
	BOOL started = FALSE;
	WSADATA wsaData = { 0 };
	freerdp_listener* listener = NULL;
	frdpdServerConfig* config = &options->server;

	if (!frdpd_validate_build_features(config))
		return -1;
	if (!frdpd_validate_runtime_topology(options))
		return -1;
	if (!winpr_PathFileExists(config->cert_path) || !winpr_PathFileExists(config->key_path))
	{
		WLog_ERR(TAG, "Certificate or key file not found: cert=%s key=%s", config->cert_path,
		         config->key_path);
		return -1;
	}
	if (!frdpd_validate_ntlm_config(config))
		return -1;
	if (!frdpd_wait_for_helper(config->auth_socket, "frdp-authd") ||
	    !frdpd_wait_for_helper(config->session_socket, "frdp-sesmand"))
		return -1;

	if (!frdpd_install_signal_handlers())
	{
		WLog_ERR(TAG, "Failed to install signal handlers");
		return -1;
	}
	if (!InitializeCriticalSectionAndSpinCount(&g_frdpd_policy_lock, 4000))
	{
		WLog_ERR(TAG, "Failed to initialize peer policy lock");
		return -1;
	}
	if (!WTSRegisterWtsApiFunctionTable(FreeRDP_InitWtsApi()))
	{
		WLog_ERR(TAG, "Failed to initialize the FreeRDP virtual channel manager");
		return -1;
	}

	if (!winpr_InitializeSSL(WINPR_SSL_INIT_DEFAULT))
		return -1;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		return -1;

	listener = freerdp_listener_new();
	if (!listener)
		goto fail;

	listener->info = config;
	listener->PeerAccepted = frdpd_peer_accepted;

	WINPR_ASSERT(listener->Open);
	started = listener->Open(listener, config->bind_address, config->port);
	if (!started)
	{
		WLog_ERR(TAG, "Failed to listen on %s:%" PRIu16,
		         config->bind_address ? config->bind_address : "0.0.0.0", config->port);
		goto fail;
	}

	WLog_INFO(
	    TAG, "frdpd listening on %s:%" PRIu16 " with PAM service '%s' and NLA/CredSSP enabled",
	    config->bind_address ? config->bind_address : "0.0.0.0", config->port, config->pam_service);
	frdpd_server_mainloop(listener, options);
	rc = 0;

fail:
	freerdp_listener_free(listener);
	WSACleanup();
	return rc;
}

int main(int argc, char* argv[])
{
	frdpdOptions options = { 0 };
	int rc = 0;

	if (!frdpd_disable_core_dumps())
		return 1;

	options.server.port = 3389;
	options.server.cert_path = "server.crt";
	options.server.key_path = "server.key";
	options.server.pam_service = "frdpd";
	options.server.allow_tls_fallback = FALSE;
	options.server.ntlm_fallback = FALSE;
	options.server.ntlm_sam_fd = -1;
	options.server.domain_mode = FRDPD_DOMAIN_PLAIN;
	if (frdpd_args_have_help(argc, argv))
	{
		frdpd_print_usage(argv[0]);
		return 0;
	}
	if (!frdpd_find_config_arg(argc, argv, &options.config_path))
	{
		frdpd_print_usage(argv[0]);
		return 2;
	}
	if (options.config_path)
	{
		if ((frdp_config_load(options.config_path, &options.file_config) != 0) ||
		    !frdpd_apply_file_config(&options))
		{
			(void)fprintf(stderr, "failed to load configuration from %s\n", options.config_path);
			return 1;
		}
	}

	if (!frdpd_parse_args(argc, argv, &options))
	{
		frdpd_print_usage(argv[0]);
		return 2;
	}
	if (options.show_help)
	{
		frdpd_print_usage(argv[0]);
		return 0;
	}

	if (options.pam_auth_test)
		return frdpd_run_pam_auth_test(&options);

	rc = frdpd_run_server(&options);
	if (options.server.ntlm_sam_fd >= 0)
		(void)close(options.server.ntlm_sam_fd);
	return rc;
}

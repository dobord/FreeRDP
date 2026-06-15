/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Experimental frdpd entry point
 *
 * Licensed under the Apache License, Version 2.0.
 */

#include <freerdp/config.h>

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <unistd.h>

#include <winpr/assert.h>
#include <winpr/crt.h>
#include <winpr/path.h>
#include <winpr/rpc.h>
#include <winpr/ssl.h>
#include <winpr/synch.h>
#include <winpr/winsock.h>

#include <freerdp/constants.h>
#include <freerdp/freerdp.h>
#include <freerdp/listener.h>
#include <freerdp/log.h>
#include <freerdp/peer.h>
#include <freerdp/settings.h>
#include <freerdp/crypto/certificate.h>
#include <freerdp/crypto/privatekey.h>

#include "../config/frdp-config.h"
#include "../ipc/frdp-ipc.h"
#include "frdpd.h"
#include "frdpd_auth.h"

#define TAG SERVER_TAG("frdpd")

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
	WINPR_UNUSED(signum);
	g_frdpd_running = 0;
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
                                      const frdpSessionRequest* request,
                                      frdpSessionResponse* response)
{
	int fd = -1;
	BOOL ok = FALSE;
	frdpIpcHeader header = { 0 };
	frdpIpcHeader response_header = { 0 };

	if (!socket_path || (socket_path[0] == '\0') || !request || !response)
		return FALSE;

	fd = frdp_ipc_connect(socket_path);
	if (fd < 0)
		goto fail;

	header.type = type;
	header.payload_len = sizeof(*request);
	if ((frdp_ipc_send(fd, &header, sizeof(header)) < 0) ||
	    (frdp_ipc_send(fd, request, sizeof(*request)) < 0))
		goto fail;

	if (frdp_ipc_recv(fd, &response_header, sizeof(response_header)) !=
	    (int)sizeof(response_header))
		goto fail;
	if ((response_header.type != FRDP_IPC_SESSION_RESPONSE) ||
	    (response_header.payload_len != sizeof(*response)))
		goto fail;
	if (frdp_ipc_recv(fd, response, sizeof(*response)) != (int)sizeof(*response))
		goto fail;

	response->session_id[sizeof(response->session_id) - 1] = '\0';
	response->display[sizeof(response->display) - 1] = '\0';
	response->error[sizeof(response->error) - 1] = '\0';
	ok = response->success ? TRUE : FALSE;

fail:
	if (fd >= 0)
		(void)frdp_ipc_close(fd);
	return ok;
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
		                                  &request, &response);
		if (!closed)
			Sleep(1000);
	}

	if (closed)
		WLog_INFO(TAG, "correlation_id=%s closed managed session_id=%s after retry",
		          retry->correlation_id, retry->session_id);
	else
		WLog_WARN(TAG, "correlation_id=%s exhausted close retries for managed session_id=%s",
		          retry->correlation_id, retry->session_id);

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
	frdpSessionRequest request = { 0 };
	frdpSessionResponse response = { 0 };

	if (!config || !context || !config->session_socket || (config->session_socket[0] == '\0'))
		return TRUE;
	if (!client || !context->pam_user)
		return FALSE;

	if (!frdpd_copy_ipc_string(request.correlation_id, sizeof(request.correlation_id),
	                          context->correlation_id) ||
	    !frdpd_copy_ipc_string(request.user, sizeof(request.user), context->pam_user) ||
	    !frdpd_copy_ipc_string(request.rhost, sizeof(request.rhost),
	                          (client->hostname[0] != '\0') ? client->hostname : NULL))
		return FALSE;

	settings = client->context ? client->context->settings : NULL;
	if (settings)
	{
		request.desktop_width = freerdp_settings_get_uint32(settings, FreeRDP_DesktopWidth);
		request.desktop_height = freerdp_settings_get_uint32(settings, FreeRDP_DesktopHeight);
		request.color_depth = freerdp_settings_get_uint32(settings, FreeRDP_ColorDepth);
	}

	if (!frdpd_session_ipc_request(config->session_socket, FRDP_IPC_SESSION_REQUEST, &request,
	                              &response))
	{
		WLog_WARN(TAG, "correlation_id=%s session manager rejected login for %s: %s",
		          context->correlation_id, context->pam_user,
		          response.error[0] ? response.error : "IPC failure");
		return FALSE;
	}

	if (!frdpd_copy_ipc_string(context->session_id, sizeof(context->session_id),
	                          response.session_id) ||
	    !frdpd_copy_ipc_string(context->session_display, sizeof(context->session_display),
	                          response.display) ||
	    (context->session_id[0] == '\0'))
	{
		if (response.session_id[0] != '\0')
		{
			frdpSessionRequest close_request = { 0 };
			frdpSessionResponse close_response = { 0 };
			BOOL rollback_closed = FALSE;

			(void)frdpd_copy_ipc_string(close_request.correlation_id,
			                            sizeof(close_request.correlation_id),
			                            context->correlation_id);
			(void)frdpd_copy_ipc_string(close_request.session_id,
			                            sizeof(close_request.session_id), response.session_id);
			(void)frdpd_copy_ipc_string(close_request.user, sizeof(close_request.user),
			                            context->pam_user);
			rollback_closed = frdpd_session_ipc_request(
			    config->session_socket, FRDP_IPC_SESSION_CLOSE_REQUEST, &close_request,
			    &close_response);
			if (!rollback_closed && (context->session_id[0] != '\0'))
			{
				context->managed_session_open = TRUE;
				(void)frdpd_schedule_session_close_retry(config, context);
				context->managed_session_open = FALSE;
				context->session_id[0] = '\0';
				context->session_display[0] = '\0';
			}
		}
		return FALSE;
	}

	context->managed_session_open = TRUE;
	WLog_INFO(TAG, "correlation_id=%s opened managed session_id=%s display=%s user=%s",
	          context->correlation_id, context->session_id,
	          context->session_display[0] ? context->session_display : "unknown", context->pam_user);
	return TRUE;
}

static void frdpd_auth_result_cleanup(frdpdAuthResult* result)
{
	if (!result)
		return;
	(void)frdpd_pam_close_session(result->pam_handle, result->pam_user,
	                              result->pam_credentials_established,
	                              result->pam_session_open);
	free(result->pam_user);
	result->pam_user = NULL;
	result->pam_handle = NULL;
	result->pam_credentials_established = FALSE;
	result->pam_session_open = FALSE;
}

static BOOL frdpd_close_managed_session(const frdpdServerConfig* config, frdpdPeerContext* context,
                                        BOOL async_only)
{
	frdpSessionRequest request = { 0 };
	frdpSessionResponse response = { 0 };
	BOOL closed = FALSE;

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
		return FALSE;
	}

	if (async_only)
	{
		if (!frdpd_schedule_session_close_retry(config, context))
		{
			WLog_WARN(TAG, "correlation_id=%s failed to schedule close retry for session_id=%s",
			          context->correlation_id, context->session_id);
			return FALSE;
		}
		WLog_INFO(TAG, "correlation_id=%s scheduled close retry for managed session_id=%s",
		          context->correlation_id, context->session_id);
		context->managed_session_open = FALSE;
		context->session_id[0] = '\0';
		context->session_display[0] = '\0';
		return TRUE;
	}

	closed = frdpd_session_ipc_request(config->session_socket, FRDP_IPC_SESSION_CLOSE_REQUEST,
	                                  &request, &response);

	if (!closed)
	{
		WLog_WARN(TAG, "correlation_id=%s failed to close managed session_id=%s: %s",
		          context->correlation_id, context->session_id,
		          response.error[0] ? response.error : "IPC failure");
		return FALSE;
	}

	WLog_INFO(TAG, "correlation_id=%s closed managed session_id=%s", context->correlation_id,
	          context->session_id);

	context->managed_session_open = FALSE;
	context->session_id[0] = '\0';
	context->session_display[0] = '\0';
	return TRUE;
}

static void frdpd_peer_context_free(freerdp_peer* client, rdpContext* ctx)
{
	frdpdPeerContext* context = (frdpdPeerContext*)ctx;
	const frdpdServerConfig* config = client ? (const frdpdServerConfig*)client->ContextExtra : NULL;

	if (!context)
		return;

	(void)frdpd_close_managed_session(config, context, TRUE);
	(void)frdpd_pam_close_session(context->pam_handle, context->pam_user,
	                              context->pam_credentials_established,
	                              context->pam_session_open);
	context->pam_handle = NULL;
	context->pam_credentials_established = FALSE;
	context->pam_session_open = FALSE;
	free(context->pam_user);
	context->pam_user = NULL;
}

static BOOL frdpd_peer_context_new(freerdp_peer* client, rdpContext* ctx)
{
	frdpdPeerContext* context = (frdpdPeerContext*)ctx;

	WINPR_UNUSED(client);
	WINPR_ASSERT(ctx);
	if (!frdpd_generate_correlation_id(context->correlation_id,
	                                  sizeof(context->correlation_id)))
	{
		WLog_ERR(TAG, "Failed to generate peer correlation id");
		return FALSE;
	}
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

static BOOL frdpd_peer_logon(freerdp_peer* client, const SEC_WINNT_AUTH_IDENTITY* identity,
                             BOOL automatic)
{
	frdpdServerConfig* config = NULL;
	frdpdPeerContext* context = NULL;
	frdpdAuthResult result = { 0 };

	WINPR_ASSERT(client);
	if (!client->context)
		return FALSE;

	config = (frdpdServerConfig*)client->ContextExtra;
	context = (frdpdPeerContext*)client->context;
	if (!config)
		return FALSE;

	if (!automatic && !config->allow_tls_fallback)
	{
		WLog_WARN(TAG, "correlation_id=%s rejecting non-NLA login from %s",
		          context->correlation_id, client->hostname);
		return FALSE;
	}

	if (!identity)
	{
		WLog_WARN(TAG, "correlation_id=%s rejecting login from %s without identity",
		          context->correlation_id, client->hostname);
		return FALSE;
	}

	const frdpdAuthConfig auth = {
		.pam_service = config->pam_service,
		.auth_socket = config->auth_socket,
		.correlation_id = context->correlation_id,
		.rhost = (client->hostname[0] != '\0') ? client->hostname : NULL,
		.domain_mode = config->domain_mode,
		.open_pam_session = config->open_pam_session,
	};

	const BOOL ok = frdpd_authenticate_identity(&auth, identity, &result);
	context->auth_status = result.status;
	context->pam_status = result.pam_status;

	if (!ok)
	{
		frdpd_auth_result_cleanup(&result);
		WLog_WARN(TAG, "correlation_id=%s PAM rejected RDP login from %s: %s (%d)",
		          context->correlation_id, client->hostname,
		          frdpd_pam_auth_status_string(context->auth_status), context->pam_status);
		return FALSE;
	}

	if (!frdpd_close_managed_session(config, context, FALSE))
	{
		frdpd_auth_result_cleanup(&result);
		return FALSE;
	}
	(void)frdpd_pam_close_session(context->pam_handle, context->pam_user,
	                              context->pam_credentials_established,
	                              context->pam_session_open);
	context->pam_handle = NULL;
	context->pam_credentials_established = FALSE;
	context->pam_session_open = FALSE;
	free(context->pam_user);
	context->pam_user = result.pam_user;
	context->pam_handle = result.pam_handle;
	context->pam_credentials_established = result.pam_credentials_established;
	context->pam_session_open = result.pam_session_open;
	result.pam_user = NULL;
	result.pam_handle = NULL;

	WLog_INFO(TAG, "correlation_id=%s PAM accepted RDP login for %s from %s",
	          context->correlation_id, context->pam_user ? context->pam_user : "unknown",
	          client->hostname[0] != '\0' ? client->hostname : "unknown");
	if (!frdpd_open_managed_session(client, config, context))
		return FALSE;
	return TRUE;
}

static BOOL frdpd_peer_post_connect(freerdp_peer* client)
{
	rdpSettings* settings = NULL;
	frdpdPeerContext* context = NULL;

	WINPR_ASSERT(client);
	WINPR_ASSERT(client->context);

	settings = client->context->settings;
	context = (frdpdPeerContext*)client->context;
	WINPR_ASSERT(settings);
	WINPR_ASSERT(context);

	WLog_INFO(TAG,
	          "correlation_id=%s client %s logged in as %s; requested desktop %" PRIu32
	          "x%" PRIu32 "x%" PRIu32,
	          context->correlation_id, client->hostname,
	          context->pam_user ? context->pam_user : "unknown",
	          freerdp_settings_get_uint32(settings, FreeRDP_DesktopWidth),
	          freerdp_settings_get_uint32(settings, FreeRDP_DesktopHeight),
	          freerdp_settings_get_uint32(settings, FreeRDP_ColorDepth));
	return TRUE;
}

static BOOL frdpd_peer_activate(freerdp_peer* client)
{
	frdpdPeerContext* context = NULL;

	WINPR_ASSERT(client);
	context = (frdpdPeerContext*)client->context;
	WLog_INFO(TAG, "correlation_id=%s client %s activated",
	          context ? context->correlation_id : "unknown", client->hostname);
	return TRUE;
}

static BOOL frdpd_peer_synchronize_event(rdpInput* input, UINT32 flags)
{
	WINPR_UNUSED(input);
	WINPR_UNUSED(flags);
	return TRUE;
}

static BOOL frdpd_peer_keyboard_event(rdpInput* input, UINT16 flags, UINT8 code)
{
	WINPR_UNUSED(input);
	WINPR_UNUSED(flags);
	WINPR_UNUSED(code);
	return TRUE;
}

static BOOL frdpd_peer_unicode_keyboard_event(rdpInput* input, UINT16 flags, UINT16 code)
{
	WINPR_UNUSED(input);
	WINPR_UNUSED(flags);
	WINPR_UNUSED(code);
	return TRUE;
}

static BOOL frdpd_peer_mouse_event(rdpInput* input, UINT16 flags, UINT16 x, UINT16 y)
{
	WINPR_UNUSED(input);
	WINPR_UNUSED(flags);
	WINPR_UNUSED(x);
	WINPR_UNUSED(y);
	return TRUE;
}

static BOOL frdpd_peer_rel_mouse_event(rdpInput* input, UINT16 flags, INT16 xDelta, INT16 yDelta)
{
	WINPR_UNUSED(input);
	WINPR_UNUSED(flags);
	WINPR_UNUSED(xDelta);
	WINPR_UNUSED(yDelta);
	return TRUE;
}

static BOOL frdpd_peer_extended_mouse_event(rdpInput* input, UINT16 flags, UINT16 x, UINT16 y)
{
	WINPR_UNUSED(input);
	WINPR_UNUSED(flags);
	WINPR_UNUSED(x);
	WINPR_UNUSED(y);
	return TRUE;
}

static BOOL frdpd_peer_refresh_rect(rdpContext* context, BYTE count, const RECTANGLE_16* areas)
{
	WINPR_UNUSED(context);
	WINPR_UNUSED(count);
	WINPR_UNUSED(areas);
	return TRUE;
}

static BOOL frdpd_peer_suppress_output(rdpContext* context, BYTE allow, const RECTANGLE_16* area)
{
	WINPR_UNUSED(context);
	WINPR_UNUSED(allow);
	WINPR_UNUSED(area);
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
	if (!freerdp_settings_set_uint32(settings, FreeRDP_EncryptionLevel,
	                                 ENCRYPTION_LEVEL_CLIENT_COMPATIBLE))
		return FALSE;
	if (!freerdp_settings_set_bool(settings, FreeRDP_RemoteFxCodec, TRUE))
		return FALSE;
	if (!freerdp_settings_set_bool(settings, FreeRDP_NSCodec, TRUE))
		return FALSE;
	if (!freerdp_settings_set_uint32(settings, FreeRDP_ColorDepth, 32))
		return FALSE;
	if (!freerdp_settings_set_bool(settings, FreeRDP_SuppressOutput, TRUE))
		return FALSE;
	if (!freerdp_settings_set_bool(settings, FreeRDP_RefreshRect, TRUE))
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
}

static DWORD WINAPI frdpd_peer_mainloop(LPVOID arg)
{
	freerdp_peer* client = (freerdp_peer*)arg;
	frdpdServerConfig* config = NULL;
	frdpdPeerContext* context = NULL;

	WINPR_ASSERT(client);
	config = (frdpdServerConfig*)client->ContextExtra;
	WINPR_ASSERT(config);

	if (!frdpd_peer_init(client))
		goto fail;
	context = (frdpdPeerContext*)client->context;
	if (!frdpd_configure_security(client, config))
		goto fail;

	frdpd_register_callbacks(client);

	WINPR_ASSERT(client->Initialize);
	if (!client->Initialize(client))
		goto fail;

	WLog_INFO(TAG, "correlation_id=%s accepted client %s", context->correlation_id,
	          client->local ? "(local)" : client->hostname);

	while (g_frdpd_running)
	{
		HANDLE handles[MAXIMUM_WAIT_OBJECTS] = { 0 };
		DWORD count = 0;
		DWORD status = 0;

		WINPR_ASSERT(client->GetEventHandles);
		count = client->GetEventHandles(client, handles, ARRAYSIZE(handles));
		if (count == 0)
		{
			WLog_ERR(TAG, "Failed to get peer event handles");
			break;
		}

		status = WaitForMultipleObjects(count, handles, FALSE, 250);
		if (status == WAIT_TIMEOUT)
			continue;
		if (status == WAIT_FAILED)
		{
			WLog_ERR(TAG, "WaitForMultipleObjects failed for peer %s", client->hostname);
			break;
		}

		WINPR_ASSERT(client->CheckFileDescriptor);
		if (!client->CheckFileDescriptor(client))
			break;
	}

	WLog_INFO(TAG, "correlation_id=%s client %s disconnected", context->correlation_id,
	          client->hostname);
	WINPR_ASSERT(client->Disconnect);
	client->Disconnect(client);

fail:
	freerdp_peer_context_free(client);
	freerdp_peer_free(client);
	return 0;
}

static BOOL frdpd_peer_accepted(freerdp_listener* instance, freerdp_peer* client)
{
	HANDLE thread = NULL;

	WINPR_ASSERT(instance);
	WINPR_ASSERT(client);

	client->ContextExtra = instance->info;
	thread = CreateThread(NULL, 0, frdpd_peer_mainloop, client, 0, NULL);
	if (!thread)
		return FALSE;

	(void)CloseHandle(thread);
	return TRUE;
}

static void frdpd_server_mainloop(freerdp_listener* instance)
{
	WINPR_ASSERT(instance);

	while (g_frdpd_running)
	{
		HANDLE handles[MAXIMUM_WAIT_OBJECTS] = { 0 };
		DWORD count = 0;
		DWORD status = 0;

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
	(void)fprintf(stderr, "  --cert=<path>                 TLS certificate, default server.crt\n");
	(void)fprintf(stderr, "  --key=<path>                  TLS private key, default server.key\n");
	(void)fprintf(stderr, "  --config=<path>               Load frdpd.toml before CLI overrides\n");
	(void)fprintf(stderr, "  --pam-service=<name>          PAM service name, default frdpd\n");
	(void)fprintf(stderr,
	              "  --auth-socket=<path>          Auth/account IPC; requires --no-pam-session\n");
	(void)fprintf(stderr,
	              "  --session-socket=<path>       Session-manager IPC; requires --no-pam-session\n");
	(void)fprintf(stderr, "  --service <name>              PAM service alias for auth test\n");
	(void)fprintf(stderr, "  --domain-mode=plain|downlevel|upn|auto\n");
	(void)fprintf(stderr,
	              "  --allow-tls-fallback          Also advertise TLS; NLA remains preferred\n");
	(void)fprintf(stderr, "  --no-pam-session             Run PAM auth/account only\n");
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
	if (_stricmp(config->auth_mode, "pam-sssd") != 0)
		return FALSE;
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
	if (!frdpd_string_is_empty(config->session_socket))
	{
		if (!frdpd_socket_path_is_valid(config->session_socket))
			return FALSE;
		options->server.session_socket = config->session_socket;
	}

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
		else if (strcmp(arg, "--no-pam-session") == 0)
			options->server.open_pam_session = FALSE;
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

static int frdpd_run_server(const frdpdOptions* options)
{
	int rc = -1;
	BOOL started = FALSE;
	WSADATA wsaData = { 0 };
	freerdp_listener* listener = NULL;
	const frdpdServerConfig* config = &options->server;

	if (config->open_pam_session && config->auth_socket && (config->auth_socket[0] != '\0'))
	{
		WLog_ERR(TAG, "Auth IPC requires --no-pam-session until session ownership is delegated");
		return -1;
	}
	if (config->open_pam_session && config->session_socket && (config->session_socket[0] != '\0'))
	{
		WLog_ERR(TAG, "Session IPC requires --no-pam-session");
		return -1;
	}

	if (!winpr_PathFileExists(config->cert_path) || !winpr_PathFileExists(config->key_path))
	{
		WLog_ERR(TAG, "Certificate or key file not found: cert=%s key=%s", config->cert_path,
		         config->key_path);
		return -1;
	}

	(void)signal(SIGINT, frdpd_signal_handler);
	(void)signal(SIGTERM, frdpd_signal_handler);

	if (!winpr_InitializeSSL(WINPR_SSL_INIT_DEFAULT))
		return -1;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		return -1;

	listener = freerdp_listener_new();
	if (!listener)
		goto fail;

	listener->info = (void*)config;
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
	frdpd_server_mainloop(listener);
	rc = 0;

fail:
	freerdp_listener_free(listener);
	WSACleanup();
	return rc;
}

int main(int argc, char* argv[])
{
	frdpdOptions options = { 0 };

	if (!frdpd_disable_core_dumps())
		return 1;

	options.server.port = 3389;
	options.server.cert_path = "server.crt";
	options.server.key_path = "server.key";
	options.server.pam_service = "frdpd";
	options.server.allow_tls_fallback = FALSE;
	options.server.open_pam_session = TRUE;
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

	return frdpd_run_server(&options);
}

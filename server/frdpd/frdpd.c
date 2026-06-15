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
#include <unistd.h>

#include <winpr/assert.h>
#include <winpr/crt.h>
#include <winpr/path.h>
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

#include "frdpd.h"
#include "frdpd_auth.h"

#define TAG SERVER_TAG("frdpd")

typedef struct
{
	frdpdServerConfig server;
	BOOL domain_mode_set;
	BOOL show_help;
	BOOL pam_auth_test;
	const char* test_user;
	const char* test_domain;
	const char* test_rhost;
} frdpdOptions;

static volatile sig_atomic_t g_frdpd_running = 1;

static void frdpd_signal_handler(int signum)
{
	WINPR_UNUSED(signum);
	g_frdpd_running = 0;
}

static void frdpd_peer_context_free(freerdp_peer* client, rdpContext* ctx)
{
	frdpdPeerContext* context = (frdpdPeerContext*)ctx;

	WINPR_UNUSED(client);
	if (!context)
		return;

	free(context->pam_user);
	context->pam_user = NULL;
}

static BOOL frdpd_peer_context_new(freerdp_peer* client, rdpContext* ctx)
{
	WINPR_UNUSED(client);
	WINPR_ASSERT(ctx);
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
		WLog_WARN(TAG, "Rejecting non-NLA login from %s", client->hostname);
		return FALSE;
	}

	if (!identity)
	{
		WLog_WARN(TAG, "Rejecting login from %s without identity", client->hostname);
		return FALSE;
	}

	const frdpdAuthConfig auth = {
		.pam_service = config->pam_service,
		.rhost = (client->hostname[0] != '\0') ? client->hostname : NULL,
		.domain_mode = config->domain_mode,
	};

	const BOOL ok = frdpd_authenticate_identity(&auth, identity, &result);
	context->auth_status = result.status;
	context->pam_status = result.pam_status;
	free(context->pam_user);
	context->pam_user = result.pam_user;
	result.pam_user = NULL;

	if (!ok)
	{
		WLog_WARN(TAG, "PAM rejected RDP login from %s: %s (%d)", client->hostname,
		          frdpd_pam_auth_status_string(context->auth_status), context->pam_status);
		return FALSE;
	}

	WLog_INFO(TAG, "PAM accepted RDP login for %s from %s",
	          context->pam_user ? context->pam_user : "unknown",
	          client->hostname[0] != '\0' ? client->hostname : "unknown");
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

	WLog_INFO(TAG, "Client %s logged in as %s; requested desktop %" PRIu32 "x%" PRIu32 "x%" PRIu32,
	          client->hostname, context->pam_user ? context->pam_user : "unknown",
	          freerdp_settings_get_uint32(settings, FreeRDP_DesktopWidth),
	          freerdp_settings_get_uint32(settings, FreeRDP_DesktopHeight),
	          freerdp_settings_get_uint32(settings, FreeRDP_ColorDepth));
	return TRUE;
}

static BOOL frdpd_peer_activate(freerdp_peer* client)
{
	WINPR_ASSERT(client);
	WLog_INFO(TAG, "Client %s activated", client->hostname);
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

	WINPR_ASSERT(client);
	config = (frdpdServerConfig*)client->ContextExtra;
	WINPR_ASSERT(config);

	if (!frdpd_peer_init(client))
		goto fail;
	if (!frdpd_configure_security(client, config))
		goto fail;

	frdpd_register_callbacks(client);

	WINPR_ASSERT(client->Initialize);
	if (!client->Initialize(client))
		goto fail;

	WLog_INFO(TAG, "Accepted client %s", client->local ? "(local)" : client->hostname);

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

	WLog_INFO(TAG, "Client %s disconnected", client->hostname);
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
	(void)fprintf(stderr, "  --pam-service=<name>          PAM service name, default frdpd\n");
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
		else if (strncmp(arg, "--pam-service=", 14) == 0)
			options->server.pam_service = &arg[14];
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

static int frdpd_run_server(const frdpdOptions* options)
{
	int rc = -1;
	BOOL started = FALSE;
	WSADATA wsaData = { 0 };
	freerdp_listener* listener = NULL;
	const frdpdServerConfig* config = &options->server;

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

	options.server.port = 3389;
	options.server.cert_path = "server.crt";
	options.server.key_path = "server.key";
	options.server.pam_service = "frdpd";
	options.server.allow_tls_fallback = FALSE;
	options.server.domain_mode = FRDPD_DOMAIN_PLAIN;

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

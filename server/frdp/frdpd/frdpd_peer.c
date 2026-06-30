/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Experimental frdpd peer hooks
 *
 * Licensed under the Apache License, Version 2.0.
 */

#include "frdpd_peer.h"

#include <freerdp/log.h>

#include "frdpd_auth.h"

#define TAG FREERDP_TAG("server.frdpd.peer")

BOOL frdpd_peer_configure(freerdp_peer* peer, const frdpdPeerConfig* config)
{
	if (!peer)
		return FALSE;

	peer->ContextExtra = (void*)config;
	peer->Logon = frdpd_peer_logon;
	return TRUE;
}

BOOL frdpd_peer_logon(freerdp_peer* peer, const SEC_WINNT_AUTH_IDENTITY* identity, BOOL automatic)
{
	if (!peer || !identity)
		return FALSE;

	if (!automatic)
	{
		WLog_WARN(TAG, "rejecting anonymous non-NLA logon attempt from %s", peer->hostname);
		return FALSE;
	}

	const frdpdPeerConfig* peer_config = peer->ContextExtra;
	const char* pam_service = "frdpd";
	if (peer_config && peer_config->pam_service)
		pam_service = peer_config->pam_service;

	const frdpdAuthConfig auth_config = { .pam_service = pam_service, .rhost = peer->hostname };
	frdpdAuthResult auth_result = { 0 };
	if (!frdpd_authenticate_identity(&auth_config, identity, &auth_result))
	{
		WLog_WARN(TAG, "PAM authentication failed for peer %s: %s (%d)", peer->hostname,
		          frdpd_pam_auth_status_string(auth_result.status), auth_result.pam_status);
		return FALSE;
	}

	WLog_INFO(TAG, "PAM authentication succeeded for peer %s", peer->hostname);
	return TRUE;
}

/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Experimental frdpd peer hooks
 *
 * Licensed under the Apache License, Version 2.0.
 */

#ifndef FREERDP_SERVER_FRDPD_PEER_H
#define FREERDP_SERVER_FRDPD_PEER_H

#include <freerdp/peer.h>

typedef struct
{
	const char* pam_service;
} frdpdPeerConfig;

BOOL frdpd_peer_configure(freerdp_peer* peer, frdpdPeerConfig* config);
BOOL frdpd_peer_logon(freerdp_peer* peer, const SEC_WINNT_AUTH_IDENTITY* identity,
                      BOOL automatic);

#endif /* FREERDP_SERVER_FRDPD_PEER_H */

/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * RDP Server Peer Credential Handoff
 *
 * Licensed under the Apache License, Version 2.0.
 */

#include <winpr/assert.h>
#include <winpr/crt.h>

#include <freerdp/settings.h>

#include "peer_credentials.h"

BOOL peer_copy_nla_logon_identity(SEC_WINNT_AUTH_IDENTITY* identity,
                                  const SEC_WINNT_AUTH_IDENTITY_INFO* nlaIdentity,
                                  rdpSettings* settings)
{
	const char* user = NULL;
	const char* domain = NULL;
	char* password = NULL;
	BOOL rc = FALSE;

	WINPR_ASSERT(identity);
	WINPR_ASSERT(settings);

	user = freerdp_settings_get_string(settings, FreeRDP_Username);
	domain = freerdp_settings_get_string(settings, FreeRDP_Domain);
	password = freerdp_settings_get_string_writable(settings, FreeRDP_Password);
	if (user && password)
		rc = sspi_SetAuthIdentity(identity, user, domain, password) > 0;
	else
		rc = sspi_CopyAuthIdentity(identity, nlaIdentity) >= 0;

	if (password)
		SecureZeroMemory(password, strlen(password));
	if (!freerdp_settings_set_string(settings, FreeRDP_Password, NULL))
		return FALSE;
	return rc;
}

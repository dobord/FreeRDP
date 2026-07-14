#include <stdlib.h>
#include <string.h>

#include <winpr/crt.h>
#include <winpr/sspi.h>

#include <freerdp/settings.h>

#include "../peer_credentials.h"

static int test_settings_password_is_cleared_after_identity_copy(void)
{
	static const char user[] = "peer-credential-user";
	static const char domain[] = "PEER-CREDENTIAL-DOMAIN";
	static const char password[] = "peer-credential-password";
	SEC_WINNT_AUTH_IDENTITY identity = { 0 };
	rdpSettings* settings = NULL;
	char* copied_user = NULL;
	char* copied_domain = NULL;
	char* copied_password = NULL;
	int rc = -1;

	settings = freerdp_settings_new(0);
	if (!settings)
		goto cleanup;
	if (!freerdp_settings_set_string(settings, FreeRDP_Username, user) ||
	    !freerdp_settings_set_string(settings, FreeRDP_Domain, domain) ||
	    !freerdp_settings_set_string(settings, FreeRDP_Password, password))
		goto cleanup;
	if (!peer_copy_nla_logon_identity(&identity, NULL, settings))
		goto cleanup;
	if (freerdp_settings_get_string(settings, FreeRDP_Password) != NULL)
		goto cleanup;
	if (!sspi_CopyAuthIdentityFieldsA((const SEC_WINNT_AUTH_IDENTITY_INFO*)&identity, &copied_user,
	                                  &copied_domain, &copied_password))
		goto cleanup;
	if (!copied_user || !copied_domain || !copied_password || (strcmp(copied_user, user) != 0) ||
	    (strcmp(copied_domain, domain) != 0) || (strcmp(copied_password, password) != 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (copied_password)
		SecureZeroMemory(copied_password, strlen(copied_password));
	free(copied_password);
	free(copied_domain);
	free(copied_user);
	sspi_FreeAuthIdentity(&identity);
	freerdp_settings_free(settings);
	return rc;
}

static int test_nla_identity_fallback_clears_settings_password(void)
{
	static const char user[] = "nla-credential-user";
	static const char domain[] = "NLA-CREDENTIAL-DOMAIN";
	static const char password[] = "nla-credential-password";
	SEC_WINNT_AUTH_IDENTITY source = { 0 };
	SEC_WINNT_AUTH_IDENTITY identity = { 0 };
	rdpSettings* settings = NULL;
	char* copied_user = NULL;
	char* copied_domain = NULL;
	char* copied_password = NULL;
	int rc = -1;

	settings = freerdp_settings_new(0);
	if (!settings || (sspi_SetAuthIdentity(&source, user, domain, password) <= 0))
		goto cleanup;
	if (!freerdp_settings_set_string(settings, FreeRDP_Password, "settings-password"))
		goto cleanup;
	if (!peer_copy_nla_logon_identity(&identity, (const SEC_WINNT_AUTH_IDENTITY_INFO*)&source,
	                                  settings))
		goto cleanup;
	if (freerdp_settings_get_string(settings, FreeRDP_Password) != NULL)
		goto cleanup;
	if (!sspi_CopyAuthIdentityFieldsA((const SEC_WINNT_AUTH_IDENTITY_INFO*)&identity, &copied_user,
	                                  &copied_domain, &copied_password))
		goto cleanup;
	if (!copied_user || !copied_domain || !copied_password || (strcmp(copied_user, user) != 0) ||
	    (strcmp(copied_domain, domain) != 0) || (strcmp(copied_password, password) != 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (copied_password)
		SecureZeroMemory(copied_password, strlen(copied_password));
	free(copied_password);
	free(copied_domain);
	free(copied_user);
	sspi_FreeAuthIdentity(&identity);
	sspi_FreeAuthIdentity(&source);
	freerdp_settings_free(settings);
	return rc;
}

static int test_failed_identity_copy_clears_settings_password(void)
{
	rdpSettings* settings = freerdp_settings_new(0);
	SEC_WINNT_AUTH_IDENTITY identity = { 0 };
	int rc = -1;

	if (!settings)
		goto cleanup;
	if (!freerdp_settings_set_string(settings, FreeRDP_Password, "settings-password"))
		goto cleanup;
	if (peer_copy_nla_logon_identity(&identity, NULL, settings))
		goto cleanup;
	if (freerdp_settings_get_string(settings, FreeRDP_Password) != NULL)
		goto cleanup;
	rc = 0;

cleanup:
	sspi_FreeAuthIdentity(&identity);
	freerdp_settings_free(settings);
	return rc;
}

int TestPeerCredentials(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if (test_settings_password_is_cleared_after_identity_copy() < 0)
		return -1;
	if (test_nla_identity_fallback_clears_settings_password() < 0)
		return -1;
	return test_failed_identity_copy_clears_settings_password();
}

#include <string.h>

#include <winpr/crt.h>

#include "../frdpd/frdpd_auth.h"

static int identity_matches(const char* user, const char* domain,
                            const SecPkgContext_AuthIdentity* proof)
{
	SEC_WINNT_AUTH_IDENTITY identity = WINPR_C_ARRAY_INIT;
	int rc = -1;

	if (sspi_SetAuthIdentity(&identity, user, domain, "delegated-password") < 0)
		return -1;
	rc = frdpd_auth_identity_matches_proof(&identity, proof) ? 1 : 0;
	sspi_FreeAuthIdentity(&identity);
	return rc;
}

int TestFreeRDPFrdpNtlmIdentity(int argc, char* argv[])
{
	SecPkgContext_AuthIdentity proof = WINPR_C_ARRAY_INIT;

	WINPR_UNUSED(argc);
	WINPR_UNUSED(argv);
	memcpy(proof.User, "Alice", sizeof("Alice"));
	memcpy(proof.Domain, "EXAMPLE", sizeof("EXAMPLE"));
	if (identity_matches("alice", "example", &proof) != 1)
		return -1;
	if (identity_matches("bob", "EXAMPLE", &proof) != 0)
		return -1;
	if (identity_matches("Alice", "OTHER", &proof) != 0)
		return -1;
	if (identity_matches("Alice", NULL, &proof) != 0)
		return -1;
	if (frdpd_auth_identity_matches_proof(NULL, &proof))
		return -1;
	proof.User[0] = '\0';
	if (identity_matches("Alice", "EXAMPLE", &proof) != 0)
		return -1;
	return 0;
}

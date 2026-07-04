
#include <stdio.h>
#include <winpr/crt.h>
#include <winpr/sspi.h>
#include <winpr/winpr.h>

static const char* test_User = "User";
static const char* test_Domain = "Domain";
static const char* test_Password = "Password";

static int test_ntlm_credentials(void)
{
	int rc = -1;
	SECURITY_STATUS status = 0;
	CredHandle credentials = WINPR_C_ARRAY_INIT;
	TimeStamp expiration;
	SEC_WINNT_AUTH_IDENTITY identity = WINPR_C_ARRAY_INIT;
	SecurityFunctionTable* table = nullptr;
	SecPkgCredentials_Names credential_names;

	sspi_GlobalInit();
	table = InitSecurityInterfaceEx(0);
	identity.User = (UINT16*)_strdup(test_User);
	identity.Domain = (UINT16*)_strdup(test_Domain);
	identity.Password = (UINT16*)_strdup(test_Password);

	if (!identity.User || !identity.Domain || !identity.Password)
		goto fail;

	identity.UserLength = strlen(test_User);
	identity.DomainLength = strlen(test_Domain);
	identity.PasswordLength = strlen(test_Password);
	identity.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
	status =
	    table->AcquireCredentialsHandle(nullptr, NTLM_SSP_NAME, SECPKG_CRED_OUTBOUND, nullptr,
	                                    &identity, nullptr, nullptr, &credentials, &expiration);

	if (status != SEC_E_OK)
		goto fail;

	status =
	    table->QueryCredentialsAttributes(&credentials, SECPKG_CRED_ATTR_NAMES, &credential_names);

	if (status != SEC_E_OK)
		goto fail;

	rc = 0;
fail:

	if (SecIsValidHandle(&credentials))
		table->FreeCredentialsHandle(&credentials);

	free(identity.User);
	free(identity.Domain);
	free(identity.Password);
	sspi_GlobalFinish();
	return rc;
}

static int test_negotiate_package_list_disables_ntlm(void)
{
	int rc = -1;
	SECURITY_STATUS status = 0;
	CredHandle credentials = WINPR_C_ARRAY_INIT;
	CtxtHandle context = WINPR_C_ARRAY_INIT;
	TimeStamp expiration;
	ULONG context_attr = 0;
	BYTE output[1024] = { 0 };
	SecBuffer output_buffer = { sizeof(output), SECBUFFER_TOKEN, output };
	SecBufferDesc output_desc = { SECBUFFER_VERSION, 1, &output_buffer };
	SEC_WINNT_AUTH_IDENTITY_EXA identity = WINPR_C_ARRAY_INIT;
	SecurityFunctionTable* table = nullptr;

	sspi_GlobalInit();
	table = InitSecurityInterfaceEx(0);
	if (!table)
		goto fail;

	identity.Version = SEC_WINNT_AUTH_IDENTITY_VERSION;
	identity.Length = sizeof(identity);
	identity.User = (BYTE*)test_User;
	identity.UserLength = strlen(test_User);
	identity.Domain = (BYTE*)test_Domain;
	identity.DomainLength = strlen(test_Domain);
	identity.Password = (BYTE*)test_Password;
	identity.PasswordLength = strlen(test_Password);
	identity.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI | SEC_WINNT_AUTH_IDENTITY_EXTENDED;
	identity.PackageList = (BYTE*)"none";
	identity.PackageListLength = strlen((const char*)identity.PackageList);

	status =
	    table->AcquireCredentialsHandle(nullptr, NEGO_SSP_NAME, SECPKG_CRED_OUTBOUND, nullptr,
	                                    &identity, nullptr, nullptr, &credentials, &expiration);
	if (status != SEC_E_OK)
		goto fail;

	status = table->InitializeSecurityContext(&credentials, nullptr, nullptr, ISC_REQ_CONFIDENTIALITY,
	                                          0, SECURITY_NATIVE_DREP, nullptr, 0, &context,
	                                          &output_desc, &context_attr, &expiration);
	if (status == SEC_I_CONTINUE_NEEDED)
		goto fail;

	rc = 0;
fail:
	if (SecIsValidHandle(&context))
		table->DeleteSecurityContext(&context);
	if (SecIsValidHandle(&credentials))
		table->FreeCredentialsHandle(&credentials);
	sspi_GlobalFinish();
	return rc;
}

int TestAcquireCredentialsHandle(int argc, char* argv[])
{
	WINPR_UNUSED(argc);
	WINPR_UNUSED(argv);

	if (test_ntlm_credentials() != 0)
		return -1;

	return test_negotiate_package_list_disables_ntlm();
}

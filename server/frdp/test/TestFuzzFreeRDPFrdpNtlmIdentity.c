#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <winpr/crt.h>

#include "frdpd/frdpd_auth.h"

#define FRDP_NTLM_IDENTITY_FUZZ_MAX_SIZE 1024U
#define FRDP_NTLM_IDENTITY_FIELD_SIZE 64U
#define FRDP_NTLM_IDENTITY_HEADER_SIZE 8U

int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size);

static uint8_t fuzz_byte(const uint8_t* data, size_t size, size_t offset)
{
	return (data && (offset < size)) ? data[offset] : 0;
}

static void fuzz_copy_slot(void* destination, size_t destination_size, const uint8_t* data,
                           size_t size, size_t offset)
{
	size_t length = 0;

	if (!destination || (destination_size == 0) || !data || (offset >= size))
		return;
	length = size - offset;
	if (length > destination_size)
		length = destination_size;
	memcpy(destination, &data[offset], length);
}

static void fuzz_copy_wchar_slot(WCHAR* destination, size_t destination_count, const uint8_t* data,
                                 size_t size, size_t offset)
{
	if (!destination || !data)
		return;
	for (size_t x = 0; x < destination_count; x++)
	{
		const size_t byte_offset = offset + (x * 2U);

		if ((byte_offset >= size) || ((size - byte_offset) < 2U))
			break;
		destination[x] =
		    (WCHAR)((uint16_t)data[byte_offset] | ((uint16_t)data[byte_offset + 1U] << 8U));
	}
}

static void fuzz_correlate_proof(SecPkgContext_AuthIdentity* proof, const uint8_t* data,
                                 size_t size)
{
	const size_t user_offset = FRDP_NTLM_IDENTITY_HEADER_SIZE;
	const size_t domain_offset = user_offset + FRDP_NTLM_IDENTITY_FIELD_SIZE;
	size_t user_length = fuzz_byte(data, size, 2U) % (FRDP_NTLM_IDENTITY_FIELD_SIZE + 1U);
	size_t domain_length = fuzz_byte(data, size, 3U) % (FRDP_NTLM_IDENTITY_FIELD_SIZE + 1U);

	if (!proof)
		return;
	if (user_length >= sizeof(proof->User))
		user_length = sizeof(proof->User) - 1U;
	if (domain_length >= sizeof(proof->Domain))
		domain_length = sizeof(proof->Domain) - 1U;
	fuzz_copy_slot(proof->User, user_length, data, size, user_offset);
	fuzz_copy_slot(proof->Domain, domain_length, data, size, domain_offset);
	proof->User[user_length] = '\0';
	proof->Domain[domain_length] = '\0';
}

static void fuzz_ansi_identity(const uint8_t* data, size_t size,
                               const SecPkgContext_AuthIdentity* proof, frdpdDomainMode domain_mode)
{
	BYTE user[FRDP_NTLM_IDENTITY_FIELD_SIZE] = { 0 };
	BYTE domain[FRDP_NTLM_IDENTITY_FIELD_SIZE] = { 0 };
	BYTE password[FRDP_NTLM_IDENTITY_FIELD_SIZE] = { 0 };
	SEC_WINNT_AUTH_IDENTITY_A identity = WINPR_C_ARRAY_INIT;
	const size_t user_offset = FRDP_NTLM_IDENTITY_HEADER_SIZE;
	const size_t domain_offset = user_offset + FRDP_NTLM_IDENTITY_FIELD_SIZE;
	const size_t password_offset = domain_offset + FRDP_NTLM_IDENTITY_FIELD_SIZE;

	fuzz_copy_slot(user, sizeof(user), data, size, user_offset);
	fuzz_copy_slot(domain, sizeof(domain), data, size, domain_offset);
	fuzz_copy_slot(password, sizeof(password), data, size, password_offset);
	identity.User = user;
	identity.UserLength = fuzz_byte(data, size, 2U) % (ARRAYSIZE(user) + 1U);
	identity.Domain = domain;
	identity.DomainLength = fuzz_byte(data, size, 3U) % (ARRAYSIZE(domain) + 1U);
	identity.Password = password;
	identity.PasswordLength = fuzz_byte(data, size, 4U) % (ARRAYSIZE(password) + 1U);
	identity.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
	(void)frdpd_auth_identity_matches_proof((const SEC_WINNT_AUTH_IDENTITY*)&identity, proof,
	                                        domain_mode);
}

static void fuzz_unicode_identity(const uint8_t* data, size_t size,
                                  const SecPkgContext_AuthIdentity* proof,
                                  frdpdDomainMode domain_mode)
{
	WCHAR user[FRDP_NTLM_IDENTITY_FIELD_SIZE / 2U] = { 0 };
	WCHAR domain[FRDP_NTLM_IDENTITY_FIELD_SIZE / 2U] = { 0 };
	WCHAR password[FRDP_NTLM_IDENTITY_FIELD_SIZE / 2U] = { 0 };
	SEC_WINNT_AUTH_IDENTITY_W identity = WINPR_C_ARRAY_INIT;
	const size_t user_offset = FRDP_NTLM_IDENTITY_HEADER_SIZE;
	const size_t domain_offset = user_offset + FRDP_NTLM_IDENTITY_FIELD_SIZE;
	const size_t password_offset = domain_offset + FRDP_NTLM_IDENTITY_FIELD_SIZE;

	fuzz_copy_wchar_slot(user, ARRAYSIZE(user), data, size, user_offset);
	fuzz_copy_wchar_slot(domain, ARRAYSIZE(domain), data, size, domain_offset);
	fuzz_copy_wchar_slot(password, ARRAYSIZE(password), data, size, password_offset);
	identity.User = user;
	identity.UserLength = fuzz_byte(data, size, 2U) % (ARRAYSIZE(user) + 1U);
	identity.Domain = domain;
	identity.DomainLength = fuzz_byte(data, size, 3U) % (ARRAYSIZE(domain) + 1U);
	identity.Password = password;
	identity.PasswordLength = fuzz_byte(data, size, 4U) % (ARRAYSIZE(password) + 1U);
	identity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
	(void)frdpd_auth_identity_matches_proof((const SEC_WINNT_AUTH_IDENTITY*)&identity, proof,
	                                        domain_mode);
}

static void fuzz_valid_identity_paths(void)
{
	BYTE user[] = "Alice";
	BYTE domain[] = "EXAMPLE";
	BYTE dns_domain[] = "example.test";
	BYTE password[] = "pass";
	SEC_WINNT_AUTH_IDENTITY_A identity = WINPR_C_ARRAY_INIT;

	identity.User = user;
	identity.UserLength = ARRAYSIZE(user) - 1U;
	identity.Domain = domain;
	identity.DomainLength = ARRAYSIZE(domain) - 1U;
	identity.Password = password;
	identity.PasswordLength = ARRAYSIZE(password) - 1U;
	identity.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
	for (frdpdDomainMode mode = FRDPD_DOMAIN_PLAIN; mode <= FRDPD_DOMAIN_AUTO; mode++)
	{
		SecPkgContext_AuthIdentity proof = WINPR_C_ARRAY_INIT;

		memcpy(proof.User, "alice", sizeof("alice"));
		if (mode != FRDPD_DOMAIN_PLAIN)
			memcpy(proof.Domain, "example", sizeof("example"));
		if (!frdpd_auth_identity_matches_proof((const SEC_WINNT_AUTH_IDENTITY*)&identity, &proof,
		                                       mode))
			abort();
	}
	identity.Domain = dns_domain;
	identity.DomainLength = ARRAYSIZE(dns_domain) - 1U;
	{
		SecPkgContext_AuthIdentity proof = WINPR_C_ARRAY_INIT;

		memcpy(proof.User, "alice", sizeof("alice"));
		memcpy(proof.Domain, "EXAMPLE.TEST", sizeof("EXAMPLE.TEST"));
		if (!frdpd_auth_identity_matches_proof((const SEC_WINNT_AUTH_IDENTITY*)&identity, &proof,
		                                       FRDPD_DOMAIN_AUTO))
			abort();
	}
}

int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
	SecPkgContext_AuthIdentity proof = WINPR_C_ARRAY_INIT;
	const size_t proof_user_offset =
	    FRDP_NTLM_IDENTITY_HEADER_SIZE + (3U * FRDP_NTLM_IDENTITY_FIELD_SIZE);
	const size_t proof_domain_offset = proof_user_offset + sizeof(proof.User);
	const frdpdDomainMode domain_mode =
	    (frdpdDomainMode)(fuzz_byte(Data, Size, 1U) % (FRDPD_DOMAIN_AUTO + 1U));

	if (!Data || (Size > FRDP_NTLM_IDENTITY_FUZZ_MAX_SIZE))
		return 0;
	fuzz_valid_identity_paths();
	if ((fuzz_byte(Data, Size, 5U) & 1U) == 0)
		fuzz_correlate_proof(&proof, Data, Size);
	else
	{
		fuzz_copy_slot(proof.User, sizeof(proof.User), Data, Size, proof_user_offset);
		fuzz_copy_slot(proof.Domain, sizeof(proof.Domain), Data, Size, proof_domain_offset);
	}
	if ((fuzz_byte(Data, Size, 0U) & 1U) != 0)
		fuzz_ansi_identity(Data, Size, &proof, domain_mode);
	else
		fuzz_unicode_identity(Data, Size, &proof, domain_mode);
	return 0;
}

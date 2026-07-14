/**
 * WinPR: Windows Portable Runtime
 * NTLM Hashing Tool
 *
 * Copyright 2012 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

#include <winpr/ntlm.h>
#include <winpr/crt.h>
#include <winpr/ssl.h>
#include <winpr/assert.h>

#define WINPR_HASH_MAX_STDIN_PASSWORD 4096U

/**
 * Define NTOWFv1(Password, User, Domain) as
 * 	MD4(UNICODE(Password))
 * EndDefine
 *
 * Define LMOWFv1(Password, User, Domain) as
 * 	ConcatenationOf(DES(UpperCase(Password)[0..6], "KGS!@#$%"),
 * 		DES(UpperCase(Password)[7..13], "KGS!@#$%"))
 * EndDefine
 *
 * Define NTOWFv2(Password, User, Domain) as
 * 	HMAC_MD5(MD4(UNICODE(Password)),
 * 		UNICODE(ConcatenationOf(UpperCase(User), Domain)))
 * EndDefine
 *
 * Define LMOWFv2(Password, User, Domain) as
 * 	NTOWFv2(Password, User, Domain)
 * EndDefine
 *
 */

static int usage_and_exit(void)
{
	printf("winpr-hash: NTLM hashing tool\n");
	printf("Usage: winpr-hash -u <username> (-p <password> | --password-stdin) [-d <domain>] "
	       "[-f <_default_,sam>] [-v <_1_,2>]\n");
	return 1;
}

static char* read_password_stdin(void)
{
	char* password = calloc(WINPR_HASH_MAX_STDIN_PASSWORD + 2U, 1U);
	size_t length = 0;

	if (!password)
		return nullptr;
#if defined(_WIN32)
	if (_setmode(_fileno(stdin), _O_BINARY) == -1)
		goto fail;
#endif
	if (setvbuf(stdin, nullptr, _IONBF, 0) != 0)
		goto fail;

	length = fread(password, 1U, WINPR_HASH_MAX_STDIN_PASSWORD + 1U, stdin);
	if (ferror(stdin) || (length > WINPR_HASH_MAX_STDIN_PASSWORD))
		goto fail;
	if ((length > 0) && (password[length - 1U] == '\n'))
	{
		length--;
		if ((length > 0) && (password[length - 1U] == '\r'))
			length--;
	}
	if (memchr(password, '\0', length) || memchr(password, '\n', length) ||
	    memchr(password, '\r', length))
		goto fail;
	password[length] = '\0';
	return password;

fail:
	SecureZeroMemory(password, WINPR_HASH_MAX_STDIN_PASSWORD + 2U);
	free(password);
	return nullptr;
}

int main(int argc, char* argv[])
{
	int index = 1;
	int format = 0;
	unsigned long version = 1;
	BYTE NtHash[16] = WINPR_C_ARRAY_INIT;
	char* User = nullptr;
	size_t UserLength = 0;
	char* Domain = nullptr;
	size_t DomainLength = 0;
	char* Password = nullptr;
	char* OwnedPassword = nullptr;
	size_t PasswordLength = 0;
	BOOL passwordStdin = FALSE;
	BOOL sslInitialized = FALSE;
	int rc = 1;
	errno = 0;

	while (index < argc)
	{
		if (strcmp("-d", argv[index]) == 0)
		{
			index++;

			if (index == argc)
			{
				printf("missing domain\n\n");
				return usage_and_exit();
			}

			Domain = argv[index];
		}
		else if (strcmp("-u", argv[index]) == 0)
		{
			index++;

			if (index == argc)
			{
				printf("missing username\n\n");
				return usage_and_exit();
			}

			User = argv[index];
		}
		else if (strcmp("-p", argv[index]) == 0)
		{
			index++;

			if (index == argc)
			{
				printf("missing password\n\n");
				return usage_and_exit();
			}

			Password = argv[index];
		}
		else if (strcmp("--password-stdin", argv[index]) == 0)
		{
			passwordStdin = TRUE;
		}
		else if (strcmp("-v", argv[index]) == 0)
		{
			index++;

			if (index == argc)
			{
				printf("missing version parameter\n\n");
				return usage_and_exit();
			}

			version = strtoul(argv[index], nullptr, 0);

			if (((version != 1) && (version != 2)) || (errno != 0))
			{
				printf("unknown version %lu \n\n", version);
				return usage_and_exit();
			}
		}
		else if (strcmp("-f", argv[index]) == 0)
		{
			index++;

			if (index == argc)
			{
				printf("missing format\n\n");
				return usage_and_exit();
			}

			if (strcmp("default", argv[index]) == 0)
				format = 0;
			else if (strcmp("sam", argv[index]) == 0)
				format = 1;
		}
		else if (strcmp("-h", argv[index]) == 0)
		{
			return usage_and_exit();
		}

		index++;
	}

	if (Password && passwordStdin)
	{
		printf("password must be supplied by exactly one source\n\n");
		return usage_and_exit();
	}
	if (passwordStdin)
	{
		OwnedPassword = read_password_stdin();
		if (!OwnedPassword)
		{
			(void)fprintf(stderr, "failed to read password from standard input\n");
			goto out;
		}
		Password = OwnedPassword;
	}
	if ((!User) || (!Password))
	{
		printf("missing username or password\n\n");
		(void)usage_and_exit();
		goto out;
	}
	if (!winpr_InitializeSSL(WINPR_SSL_INIT_DEFAULT))
	{
		printf("winpr_InitializeSSL failed\n\n");
		goto out;
	}
	sslInitialized = TRUE;

	UserLength = strlen(User);
	PasswordLength = strlen(Password);
	DomainLength = (Domain) ? strlen(Domain) : 0;

	WINPR_ASSERT(UserLength <= UINT32_MAX);
	WINPR_ASSERT(PasswordLength <= UINT32_MAX);
	WINPR_ASSERT(DomainLength <= UINT32_MAX);

	if (version == 2)
	{
		if (!Domain)
		{
			printf("missing domain (version 2 requires a domain to specified)\n\n");
			(void)usage_and_exit();
			goto out;
		}

		if (!NTOWFv2A(Password, (UINT32)PasswordLength, User, (UINT32)UserLength, Domain,
		              (UINT32)DomainLength, NtHash))
		{
			(void)fprintf(stderr, "Hash creation failed\n");
			goto out;
		}
	}
	else
	{
		if (!NTOWFv1A(Password, (UINT32)PasswordLength, NtHash))
		{
			(void)fprintf(stderr, "Hash creation failed\n");
			goto out;
		}
	}

	if (format == 0)
	{
		for (int idx = 0; idx < 16; idx++)
			printf("%02" PRIx8 "", NtHash[idx]);

		printf("\n");
	}
	else if (format == 1)
	{
		printf("%s:", User);

		if (DomainLength > 0)
			printf("%s:", Domain);
		else
			printf(":");

		printf(":");

		for (int idx = 0; idx < 16; idx++)
			printf("%02" PRIx8 "", NtHash[idx]);

		printf(":::");
		printf("\n");
	}

	rc = 0;

out:
	SecureZeroMemory(NtHash, sizeof(NtHash));
	if (sslInitialized)
		(void)winpr_CleanupSSL(WINPR_SSL_INIT_DEFAULT);
	if (OwnedPassword)
	{
		SecureZeroMemory(OwnedPassword, WINPR_HASH_MAX_STDIN_PASSWORD + 2U);
		free(OwnedPassword);
	}
	return rc;
}

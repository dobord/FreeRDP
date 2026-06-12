/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Experimental frdpd entry point
 *
 * Licensed under the Apache License, Version 2.0.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "frdpd_pam.h"

static void frdpd_print_usage(const char* name)
{
	fprintf(stderr,
	        "Usage:\n"
	        "  %s --pam-auth-test USER [--domain DOMAIN] [--service SERVICE] [--rhost HOST]\n",
	        name);
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

int main(int argc, char** argv)
{
	const char* user = NULL;
	const char* domain = NULL;
	const char* service = "frdpd";
	const char* rhost = NULL;
	BOOL pam_auth_test = FALSE;

	for (int x = 1; x < argc; x++)
	{
		if (strcmp(argv[x], "--pam-auth-test") == 0)
		{
			if (!frdpd_set_arg_value(&user, argc, argv, &x))
			{
				frdpd_print_usage(argv[0]);
				return 2;
			}
			pam_auth_test = TRUE;
		}
		else if (strcmp(argv[x], "--domain") == 0)
		{
			if (!frdpd_set_arg_value(&domain, argc, argv, &x))
			{
				frdpd_print_usage(argv[0]);
				return 2;
			}
		}
		else if (strcmp(argv[x], "--service") == 0)
		{
			if (!frdpd_set_arg_value(&service, argc, argv, &x))
			{
				frdpd_print_usage(argv[0]);
				return 2;
			}
		}
		else if (strcmp(argv[x], "--rhost") == 0)
		{
			if (!frdpd_set_arg_value(&rhost, argc, argv, &x))
			{
				frdpd_print_usage(argv[0]);
				return 2;
			}
		}
		else if ((strcmp(argv[x], "-h") == 0) || (strcmp(argv[x], "--help") == 0))
		{
			frdpd_print_usage(argv[0]);
			return 0;
		}
		else
		{
			frdpd_print_usage(argv[0]);
			return 2;
		}

	}

	if (!pam_auth_test || !user)
	{
		frdpd_print_usage(argv[0]);
		return 2;
	}

	char* password = getpass("Password: ");
	if (!password)
	{
		fprintf(stderr, "failed to read password\n");
		return 1;
	}

	frdpdPamAuthRequest request = {
		.service = service,
		.user = user,
		.domain = domain,
		.password = password,
		.rhost = rhost,
		.pam_status = 0,
	};

	const frdpdPamAuthStatus status = frdpd_pam_authenticate(&request);
	printf("pam-auth-test=%s pam-status=%d\n", frdpd_pam_auth_status_string(status),
	       request.pam_status);
	frdpd_pam_clear_secret(password);

	return (status == FRDPD_PAM_AUTH_OK) ? 0 : 1;
}

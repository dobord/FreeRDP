#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <winpr/crt.h>

#include "../frdpd/frdpd_auth.h"

static int make_auth_broker_socket(char* dir, size_t dir_size, char* socket_path,
                                   size_t socket_path_size)
{
	struct sockaddr_un addr = { 0 };
	int rc = -1;
	int fd = -1;

	rc = snprintf(dir, dir_size, "/tmp/frdp-auth-identity-XXXXXX");
	if ((rc < 0) || ((size_t)rc >= dir_size) || !mkdtemp(dir))
		return -1;
	if (chmod(dir, 0700) != 0)
		goto fail;
	rc = snprintf(socket_path, socket_path_size, "%s/auth.sock", dir);
	if ((rc < 0) || ((size_t)rc >= socket_path_size))
		goto fail;
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		goto fail;
	addr.sun_family = AF_UNIX;
	rc = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);
	if ((rc < 0) || ((size_t)rc >= sizeof(addr.sun_path)) ||
	    bind(fd, (const struct sockaddr*)&addr, sizeof(addr)) != 0 ||
	    chmod(socket_path, 0600) != 0 || listen(fd, 1) != 0)
		goto fail;
	return fd;

fail:
	if (fd >= 0)
		close(fd);
	unlink(socket_path);
	rmdir(dir);
	dir[0] = '\0';
	socket_path[0] = '\0';
	return -1;
}

static int serve_auth_response(int listener, const char* user, const char* password)
{
	frdpIpcHeader header = { 0 };
	frdpAuthRequest request = { 0 };
	frdpAuthResponse response = { 0 };
	int fd = accept(listener, NULL, NULL);
	int rc = -1;

	if (fd < 0 || frdp_ipc_recv_header(fd, &header) != (int)sizeof(header) ||
	    (header.type != FRDP_IPC_AUTH_REQUEST_V2) ||
	    frdp_ipc_recv_auth_request_v2_payload(fd, &request, header.payload_len) != 0 ||
	    strcmp(request.user, "alice@EXAMPLE") != 0 || strcmp(request.password, password) != 0)
		goto cleanup;
	response.success = 1;
	snprintf(response.user, sizeof(response.user), "%s", user);
	snprintf(response.authorization_id, sizeof(response.authorization_id), "test-authorization");
	response.uid = 1000;
	response.gid = 1001;
	response.groups[0] = 1001;
	response.groups[1] = 2000;
	response.group_count = 2;
	response.has_posix_account = 1;
	rc = frdp_ipc_send_auth_response_v2(fd, &response);

cleanup:
	if (fd >= 0)
		close(fd);
	SecureZeroMemory(&request, sizeof(request));
	SecureZeroMemory(&response, sizeof(response));
	return rc;
}

static int test_auth_adapter_identity(const SEC_WINNT_AUTH_IDENTITY* identity,
	                                  const char* broker_user, const char* password,
	                                  int expect_success)
{
	char dir[128] = { 0 };
	char socket_path[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	frdpdAuthConfig config = { 0 };
	frdpdAuthResult result = { 0 };
	pid_t child = -1;
	int listener = -1;
	int status = 0;
	int rc = -1;

	listener = make_auth_broker_socket(dir, sizeof(dir), socket_path, sizeof(socket_path));
	if (listener < 0)
		goto cleanup;
	child = fork();
	if (child < 0)
		goto cleanup;
	if (child == 0)
		_exit(serve_auth_response(listener, broker_user, password) == 0 ? 0 : 1);
	config.pam_service = "frdpd";
	config.auth_socket = socket_path;
	config.correlation_id = "canonical-test";
	config.rhost = "192.0.2.1";
	config.domain_mode = FRDPD_DOMAIN_UPN;
	const BOOL authenticated = frdpd_authenticate_identity(&config, identity, &result);
	if (expect_success)
	{
		if (!authenticated || (result.status != FRDPD_PAM_AUTH_OK) || !result.pam_user ||
		    strcmp(result.pam_user, broker_user) != 0 || result.uid != 1000 || result.gid != 1001 ||
		    result.group_count != 2 || result.groups[0] != 1001 || result.groups[1] != 2000 ||
		    strcmp(result.authorization_id, "test-authorization") != 0)
			goto cleanup;
	}
	else if (authenticated || result.pam_user || (result.status != FRDPD_PAM_AUTH_ERROR))
		goto cleanup;
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		goto cleanup;
	child = -1;
	rc = 0;

cleanup:
	if (child > 0)
	{
		(void)kill(child, SIGKILL);
		(void)waitpid(child, NULL, 0);
	}
	if (listener >= 0)
		close(listener);
	free(result.pam_user);
	SecureZeroMemory(&result, sizeof(result));
	unlink(socket_path);
	rmdir(dir);
	return rc;
}

static int test_auth_adapter_broker_user(const char* broker_user, int expect_success)
{
	SEC_WINNT_AUTH_IDENTITY identity = WINPR_C_ARRAY_INIT;
	int rc = -1;

	if (sspi_SetAuthIdentity(&identity, "alice", "EXAMPLE", "password") < 0)
		return -1;
	rc = test_auth_adapter_identity(&identity, broker_user, "password", expect_success);
	sspi_FreeAuthIdentity(&identity);
	return rc;
}

static int test_invalid_auth_identity_without_ipc(const SEC_WINNT_AUTH_IDENTITY* identity)
{
	char dir[128] = { 0 };
	char socket_path[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	frdpdAuthConfig config = { 0 };
	frdpdAuthResult result = { 0 };
	struct pollfd event = { 0 };
	int listener = -1;
	int rc = -1;

	listener = make_auth_broker_socket(dir, sizeof(dir), socket_path, sizeof(socket_path));
	if (listener < 0)
		goto cleanup;
	config.pam_service = "frdpd";
	config.auth_socket = socket_path;
	config.domain_mode = FRDPD_DOMAIN_UPN;
	event.fd = listener;
	event.events = POLLIN;
	if (frdpd_authenticate_identity(&config, identity, &result) ||
	    (result.status != FRDPD_PAM_AUTH_ERROR) || (poll(&event, 1, 0) != 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (listener >= 0)
		close(listener);
	free(result.pam_user);
	SecureZeroMemory(&result, sizeof(result));
	unlink(socket_path);
	rmdir(dir);
	return rc;
}

static int identity_matches_mode(const char* user, const char* domain,
	                             const SecPkgContext_AuthIdentity* proof,
	                             frdpdDomainMode domain_mode)
{
	SEC_WINNT_AUTH_IDENTITY identity = WINPR_C_ARRAY_INIT;
	int rc = -1;

	if (sspi_SetAuthIdentity(&identity, user, domain, "delegated-password") < 0)
		return -1;
	rc = frdpd_auth_identity_matches_proof(&identity, proof, domain_mode) ? 1 : 0;
	sspi_FreeAuthIdentity(&identity);
	return rc;
}

static int identity_matches(const char* user, const char* domain,
	                        const SecPkgContext_AuthIdentity* proof)
{
	return identity_matches_mode(user, domain, proof, FRDPD_DOMAIN_DOWNLEVEL);
}

static int embedded_identity_fields_are_rejected(const SecPkgContext_AuthIdentity* proof)
{
	static const WCHAR embedded_user[] = { 'A', 'l', 0, 'i', 'c', 'e' };
	static const WCHAR embedded_domain[] = { 'E', 'X', 0, 'A', 'M', 'P', 'L', 'E' };
	static const WCHAR user[] = { 'A', 'l', 'i', 'c', 'e' };
	static const WCHAR domain[] = { 'E', 'X', 'A', 'M', 'P', 'L', 'E' };
	static const WCHAR password[] = { 'p', 'a', 's', 's' };
	SEC_WINNT_AUTH_IDENTITY identity = WINPR_C_ARRAY_INIT;
	int rc = -1;

	if (sspi_SetAuthIdentityWithLengthW(&identity, embedded_user, ARRAYSIZE(embedded_user), domain,
	                                    ARRAYSIZE(domain), password, ARRAYSIZE(password)) < 0)
		return -1;
	if (frdpd_auth_identity_matches_proof(&identity, proof, FRDPD_DOMAIN_DOWNLEVEL))
		goto out;
	sspi_FreeAuthIdentity(&identity);
	if (sspi_SetAuthIdentityWithLengthW(&identity, user, ARRAYSIZE(user), embedded_domain,
	                                    ARRAYSIZE(embedded_domain), password,
	                                    ARRAYSIZE(password)) < 0)
		return -1;
	if (!frdpd_auth_identity_matches_proof(&identity, proof, FRDPD_DOMAIN_DOWNLEVEL))
		rc = 0;

out:
	sspi_FreeAuthIdentity(&identity);
	return rc;
}

static int counted_ansi_identity_fields_are_bounded(const SecPkgContext_AuthIdentity* proof)
{
	static unsigned char user[] = { 'a', 'l', 'i', 'c', 'e' };
	static unsigned char domain[] = { 'E', 'X', 'A', 'M', 'P', 'L', 'E' };
	static unsigned char password[] = { 'p', 'a', 's', 's' };
	static unsigned char embedded_user[] = { 'a', 'l', 0, 'i', 'c', 'e' };
	static unsigned char embedded_password[] = { 'p', 0, 'a', 's', 's' };
	SEC_WINNT_AUTH_IDENTITY_A identity = WINPR_C_ARRAY_INIT;

	identity.User = user;
	identity.UserLength = ARRAYSIZE(user);
	identity.Domain = domain;
	identity.DomainLength = ARRAYSIZE(domain);
	identity.Password = password;
	identity.PasswordLength = ARRAYSIZE(password);
	identity.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
	if (!frdpd_auth_identity_matches_proof((const SEC_WINNT_AUTH_IDENTITY*)&identity, proof,
	                                       FRDPD_DOMAIN_DOWNLEVEL))
		return -1;
	if (test_auth_adapter_identity((const SEC_WINNT_AUTH_IDENTITY*)&identity, "canonical-alice",
	                               "pass", 1) != 0)
		return -1;
	identity.PasswordLength = 0;
	if (test_auth_adapter_identity((const SEC_WINNT_AUTH_IDENTITY*)&identity, "canonical-alice", "",
	                               1) != 0)
		return -1;
	identity.PasswordLength = ARRAYSIZE(password);
	identity.User = embedded_user;
	identity.UserLength = ARRAYSIZE(embedded_user);
	if (frdpd_auth_identity_matches_proof((const SEC_WINNT_AUTH_IDENTITY*)&identity, proof,
	                                      FRDPD_DOMAIN_DOWNLEVEL))
		return -1;
	if (test_invalid_auth_identity_without_ipc((const SEC_WINNT_AUTH_IDENTITY*)&identity) != 0)
		return -1;
	identity.User = user;
	identity.UserLength = ARRAYSIZE(user);
	identity.Password = embedded_password;
	identity.PasswordLength = ARRAYSIZE(embedded_password);
	if (frdpd_auth_identity_matches_proof((const SEC_WINNT_AUTH_IDENTITY*)&identity, proof,
	                                      FRDPD_DOMAIN_DOWNLEVEL))
		return -1;
	return test_invalid_auth_identity_without_ipc((const SEC_WINNT_AUTH_IDENTITY*)&identity);
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
	if (identity_matches("Alice", NULL, &proof) != 1)
		return -1;
	if (embedded_identity_fields_are_rejected(&proof) != 0)
		return -1;
	if (counted_ansi_identity_fields_are_bounded(&proof) != 0)
		return -1;
	if (identity_matches_mode("alice", "EXAMPLE", &proof, FRDPD_DOMAIN_PLAIN) != 1)
		return -1;
	if (identity_matches("alice@example", NULL, &proof) != 1)
		return -1;
	if (identity_matches("example\\alice", NULL, &proof) != 1)
		return -1;
	if (identity_matches("@example", NULL, &proof) != 0)
		return -1;
	if (identity_matches("alice@", NULL, &proof) != 0)
		return -1;
	if (identity_matches("\\alice", NULL, &proof) != 0)
		return -1;
	if (identity_matches("example\\", NULL, &proof) != 0)
		return -1;
	if (identity_matches("example\\\\alice", NULL, &proof) != 0)
		return -1;
	memset(&proof, 0, sizeof(proof));
	memcpy(proof.User, "Alice@Example", sizeof("Alice@Example"));
	if (identity_matches("alice", "example", &proof) != 1)
		return -1;
	memcpy(proof.Domain, "OTHER", sizeof("OTHER"));
	if (identity_matches("Alice@Example", "OTHER", &proof) != 0)
		return -1;
	memset(&proof, 0, sizeof(proof));
	memcpy(proof.User, "Example\\Alice", sizeof("Example\\Alice"));
	if (identity_matches("alice", "example", &proof) != 1)
		return -1;
	if (identity_matches("example\\alice", "example", &proof) != 0)
		return -1;
	memset(&proof, 0, sizeof(proof));
	memcpy(proof.User, "Alice", sizeof("Alice"));
	if (identity_matches("alice", NULL, &proof) != 1)
		return -1;
	if (identity_matches("alice", "EXAMPLE", &proof) != 0)
		return -1;
	if (identity_matches_mode("alice", "EXAMPLE", &proof, FRDPD_DOMAIN_PLAIN) != 0)
		return -1;
	if (identity_matches_mode("alice", "EXAMPLE", &proof, FRDPD_DOMAIN_UPN) != 0)
		return -1;
	memcpy(proof.Domain, "OTHER", sizeof("OTHER"));
	if (identity_matches("alice", "EXAMPLE", &proof) != 0)
		return -1;
	if (identity_matches_mode("alice", "EXAMPLE", &proof, FRDPD_DOMAIN_PLAIN) != 0)
		return -1;
	if (identity_matches_mode("alice", "EXAMPLE", &proof, FRDPD_DOMAIN_UPN) != 0)
		return -1;
	if (identity_matches("alice", "EXAMPLE@OTHER", &proof) != 0)
		return -1;
	memcpy(proof.Domain, "EXAMPLE\\OTHER", sizeof("EXAMPLE\\OTHER"));
	if (identity_matches("alice", "EXAMPLE\\OTHER", &proof) != 0)
		return -1;
	memset(&proof, 0, sizeof(proof));
	memcpy(proof.User, "Example\\Alice@Example", sizeof("Example\\Alice@Example"));
	if (identity_matches("alice", "example", &proof) != 0)
		return -1;
	memset(&proof, 0, sizeof(proof));
	memcpy(proof.User, "Alice@@Example", sizeof("Alice@@Example"));
	if (identity_matches("alice", "example", &proof) != 0)
		return -1;
	memset(&proof, 'a', sizeof(proof));
	if (identity_matches("alice", NULL, &proof) != 0)
		return -1;
	memset(&proof, 0, sizeof(proof));
	memcpy(proof.User, "Alice", sizeof("Alice"));
	memset(proof.Domain, 'a', sizeof(proof.Domain));
	if (identity_matches("alice", NULL, &proof) != 0)
		return -1;
	memset(&proof, 0, sizeof(proof));
	memcpy(proof.User, "Alice", sizeof("Alice"));
	proof.User[sizeof("Alice")] = 'x';
	if (identity_matches("alice", NULL, &proof) != 0)
		return -1;
	memset(&proof, 0, sizeof(proof));
	memcpy(proof.User, "Alice", sizeof("Alice"));
	memcpy(proof.Domain, "EXAMPLE", sizeof("EXAMPLE"));
	proof.Domain[sizeof("EXAMPLE")] = 'x';
	if (identity_matches("alice", "example", &proof) != 0)
		return -1;
	memset(&proof, 0, sizeof(proof));
	{
		static const char exact_user[] = { 'A', 'l', (char)0xc3, (char)0xaf, 'c', 'e', 0 };
		static const char proof_user[] = { 'a', 'l', (char)0xc3, (char)0xaf, 'c', 'e', 0 };
		static const char different_user[] = { 'A', 'l', (char)0xc3, (char)0x8f, 'c', 'e', 0 };

		memcpy(proof.User, proof_user, sizeof(proof_user));
		if (identity_matches(exact_user, NULL, &proof) != 1)
			return -1;
		if (identity_matches(different_user, NULL, &proof) != 0)
			return -1;
	}
	memset(&proof, 0, sizeof(proof));
	if (frdpd_auth_identity_matches_proof(NULL, &proof, FRDPD_DOMAIN_DOWNLEVEL))
		return -1;
	if (identity_matches("Alice", "EXAMPLE", &proof) != 0)
		return -1;
	if (test_auth_adapter_broker_user("canonical-alice", 1) != 0)
		return -1;
	if (test_auth_adapter_broker_user("canonical\nalice", 0) != 0)
		return -1;
	return 0;
}

#include "ipc/frdp-auth-token.h"
#include "ipc/frdp-ipc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int make_runtime_dir(char* dir, size_t dir_size)
{
	const int rc = snprintf(dir, dir_size, "/tmp/frdp-ipc-XXXXXX");

	if ((rc < 0) || ((size_t)rc >= dir_size))
		return -1;
	if (!mkdtemp(dir))
		return -1;
	if (chmod(dir, 0700) != 0)
	{
		rmdir(dir);
		return -1;
	}
	return 0;
}

static int make_secure_socket(const char* dir, char* socket_path, size_t socket_path_size)
{
	int fd = -1;
	struct sockaddr_un addr;
	const int rc = snprintf(socket_path, socket_path_size, "%s/ipc.sock", dir);

	if ((rc < 0) || ((size_t)rc >= socket_path_size))
		return -1;
	if (strlen(socket_path) >= sizeof(addr.sun_path))
		return -1;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);
	if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
		goto fail;
	if (chmod(socket_path, 0600) != 0)
		goto fail;
	if (listen(fd, 1) != 0)
		goto fail;
	return fd;

fail:
	close(fd);
	unlink(socket_path);
	return -1;
}

static int test_connect_rejects_relative_path(void)
{
	errno = 0;
	if (frdp_ipc_connect("relative.sock") >= 0)
		return -1;
	return errno == EACCES ? 0 : -1;
}

static int test_connect_secure_socket(void)
{
	char dir[1024] = { 0 };
	char socket_path[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	int server_fd = -1;
	int client_fd = -1;
	int accepted_fd = -1;
	int rc = -1;

	if (make_runtime_dir(dir, sizeof(dir)) != 0)
		return -1;
	server_fd = make_secure_socket(dir, socket_path, sizeof(socket_path));
	if (server_fd < 0)
		goto cleanup;
	client_fd = frdp_ipc_connect(socket_path);
	if (client_fd < 0)
		goto cleanup;
	const int flags = fcntl(client_fd, F_GETFD);
	if (flags < 0 || (flags & FD_CLOEXEC) == 0)
		goto cleanup;
	accepted_fd = accept(server_fd, NULL, NULL);
	if (accepted_fd < 0)
		goto cleanup;
	rc = 0;

cleanup:
	if (accepted_fd >= 0)
		close(accepted_fd);
	if (client_fd >= 0)
		frdp_ipc_close(client_fd);
	if (server_fd >= 0)
		close(server_fd);
	unlink(socket_path);
	rmdir(dir);
	return rc;
}

static int test_connect_rejects_insecure_parent(void)
{
	char dir[1024] = { 0 };
	char socket_path[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	int server_fd = -1;
	int rc = -1;

	if (make_runtime_dir(dir, sizeof(dir)) != 0)
		return -1;
	server_fd = make_secure_socket(dir, socket_path, sizeof(socket_path));
	if (server_fd < 0)
		goto cleanup;
	if (chmod(dir, 0770) != 0)
		goto cleanup;
	errno = 0;
	if (frdp_ipc_connect(socket_path) < 0 && errno == EACCES)
		rc = 0;

cleanup:
	if (server_fd >= 0)
		close(server_fd);
	chmod(dir, 0700);
	unlink(socket_path);
	rmdir(dir);
	return rc;
}

static int test_connect_rejects_insecure_socket(void)
{
	char dir[1024] = { 0 };
	char socket_path[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	int server_fd = -1;
	int rc = -1;

	if (make_runtime_dir(dir, sizeof(dir)) != 0)
		return -1;
	server_fd = make_secure_socket(dir, socket_path, sizeof(socket_path));
	if (server_fd < 0)
		goto cleanup;
	if (chmod(socket_path, 0660) != 0)
		goto cleanup;
	errno = 0;
	if (frdp_ipc_connect(socket_path) < 0 && errno == EACCES)
		rc = 0;

cleanup:
	if (server_fd >= 0)
		close(server_fd);
	unlink(socket_path);
	rmdir(dir);
	return rc;
}

static int test_recv_rejects_short_read(void)
{
	int fds[2] = { -1, -1 };
	char buf[4] = { 0 };
	const char partial[2] = { 'O', 'K' };
	int rc = -1;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		return -1;
	if (frdp_ipc_send(fds[1], partial, sizeof(partial)) != 0)
		goto cleanup;
	close(fds[1]);
	fds[1] = -1;
	if (frdp_ipc_recv(fds[0], buf, sizeof(buf)) < 0)
		rc = 0;

cleanup:
	if (fds[0] >= 0)
		close(fds[0]);
	if (fds[1] >= 0)
		close(fds[1]);
	return rc;
}

static int test_send_recv_reject_null_buffers(void)
{
	int fds[2] = { -1, -1 };
	int rc = -1;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		return -1;
	errno = 0;
	if (frdp_ipc_send(fds[0], NULL, 1) != -1 || errno != EINVAL)
		goto cleanup;
	errno = 0;
	if (frdp_ipc_recv(fds[0], NULL, 1) != -1 || errno != EINVAL)
		goto cleanup;
	if (frdp_ipc_send(fds[0], NULL, 0) != 0)
		goto cleanup;
	if (frdp_ipc_recv(fds[0], NULL, 0) != 0)
		goto cleanup;
	rc = 0;

cleanup:
	if (fds[0] >= 0)
		close(fds[0]);
	if (fds[1] >= 0)
		close(fds[1]);
	return rc;
}

static int test_header_uses_little_endian_wire_format(void)
{
	int fds[2] = { -1, -1 };
	const uint8_t expected[] = { 0x17, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12 };
	const uint8_t incoming[] = { 0x05, 0x00, 0x00, 0x00, 0xef, 0xcd, 0xab, 0x90 };
	uint8_t raw[8] = { 0 };
	frdpIpcHeader header = { 0 };
	int rc = -1;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		return -1;
	if (frdp_ipc_send_header(fds[0], (frdpIpcMessageType)0x17, 0x12345678U) != 0)
		goto cleanup;
	if (frdp_ipc_recv(fds[1], raw, sizeof(raw)) != (int)sizeof(raw))
		goto cleanup;
	if (memcmp(raw, expected, sizeof(expected)) != 0)
		goto cleanup;
	if (frdp_ipc_send(fds[1], incoming, sizeof(incoming)) != 0)
		goto cleanup;
	if (frdp_ipc_recv_header(fds[0], &header) != (int)sizeof(header))
		goto cleanup;
	if ((header.type != FRDP_IPC_AUTH_REQUEST_V2) || (header.payload_len != 0x90abcdefU))
		goto cleanup;
	errno = 0;
	if ((frdp_ipc_recv_header(fds[0], NULL) != -1) || (errno != EINVAL))
		goto cleanup;
	rc = 0;

cleanup:
	if (fds[0] >= 0)
		close(fds[0]);
	if (fds[1] >= 0)
		close(fds[1]);
	return rc;
}

static int test_auth_response_uses_explicit_wire_format(void)
{
	int fds[2] = { -1, -1 };
	frdpAuthResponse response = { 0 };
	frdpAuthResponse decoded = { 0 };
	frdpIpcHeader header = { 0 };
	uint8_t raw[FRDP_IPC_AUTH_RESPONSE_WIRE_SIZE] = { 0 };
	const size_t uid_offset = 4U + sizeof(response.error) + sizeof(response.authorization_id);
	const size_t gid_offset = uid_offset + 8U;
	const size_t group_count_offset = gid_offset + 8U;
	const size_t groups_offset = group_count_offset + 4U;
	const size_t unused_group_offset = groups_offset + 16U;
	int rc = -1;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		return -1;
	response.success = 1;
	snprintf(response.error, sizeof(response.error), "ignored");
	snprintf(response.authorization_id, sizeof(response.authorization_id), "authz");
	response.uid = UINT64_C(0x0102030405060708);
	response.gid = UINT64_C(0x1112131415161718);
	response.group_count = 2;
	response.groups[0] = UINT64_C(0x2122232425262728);
	response.groups[1] = UINT64_C(0x3132333435363738);
	response.groups[2] = UINT64_C(0xf1f2f3f4f5f6f7f8);
	response.has_posix_account = 1;

	if (frdp_ipc_send_auth_response(fds[0], &response) != 0)
		goto cleanup;
	if (frdp_ipc_recv_header(fds[1], &header) != (int)sizeof(header))
		goto cleanup;
	if ((header.type != FRDP_IPC_AUTH_RESPONSE) ||
	    (header.payload_len != FRDP_IPC_AUTH_RESPONSE_WIRE_SIZE))
		goto cleanup;
	if (frdp_ipc_recv(fds[1], raw, sizeof(raw)) != (int)sizeof(raw))
		goto cleanup;
	if ((raw[0] != 1U) || (raw[1] != 0U) || (raw[2] != 0U) || (raw[3] != 0U))
		goto cleanup;
	if ((raw[uid_offset] != 0x08U) || (raw[uid_offset + 7U] != 0x01U))
		goto cleanup;
	if ((raw[gid_offset] != 0x18U) || (raw[gid_offset + 7U] != 0x11U))
		goto cleanup;
	if ((raw[group_count_offset] != 2U) || (raw[group_count_offset + 1U] != 0U))
		goto cleanup;
	if ((raw[groups_offset] != 0x28U) || (raw[groups_offset + 7U] != 0x21U) ||
	    (raw[groups_offset + 8U] != 0x38U) || (raw[groups_offset + 15U] != 0x31U))
		goto cleanup;
	for (size_t x = 0; x < 8U; x++) {
		if (raw[unused_group_offset + x] != 0U)
			goto cleanup;
		raw[unused_group_offset + x] = (uint8_t)(0xa0U + x);
	}
	if (frdp_ipc_send_header(fds[1], FRDP_IPC_AUTH_RESPONSE, sizeof(raw)) != 0 ||
	    frdp_ipc_send(fds[1], raw, sizeof(raw)) != 0)
		goto cleanup;
	if (frdp_ipc_recv_auth_response(fds[0], &decoded) != 0)
		goto cleanup;
	if ((decoded.success != response.success) || (decoded.uid != response.uid) ||
	    (decoded.gid != response.gid) || (decoded.group_count != response.group_count) ||
	    (decoded.groups[0] != response.groups[0]) || (decoded.groups[1] != response.groups[1]) ||
	    (decoded.groups[2] != 0) ||
	    (decoded.has_posix_account != response.has_posix_account))
		goto cleanup;
	rc = 0;

cleanup:
	if (fds[0] >= 0)
		close(fds[0]);
	if (fds[1] >= 0)
		close(fds[1]);
	return rc;
}

static int test_auth_request_uses_explicit_wire_format(void)
{
	int fds[2] = { -1, -1 };
	frdpAuthRequest request = { 0 };
	frdpAuthRequest decoded = { 0 };
	frdpIpcHeader header = { 0 };
	uint8_t raw[FRDP_IPC_AUTH_REQUEST_V2_WIRE_SIZE] = { 0 };
	const size_t user_offset = sizeof(request.correlation_id);
	const size_t rhost_offset = user_offset + sizeof(request.user);
	const size_t password_offset = rhost_offset + sizeof(request.rhost);
	int rc = -1;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		return -1;
	snprintf(request.correlation_id, sizeof(request.correlation_id), "corr");
	snprintf(request.user, sizeof(request.user), "alice");
	snprintf(request.rhost, sizeof(request.rhost), "203.0.113.8");
	snprintf(request.password, sizeof(request.password), "secret");
	if (frdp_ipc_send_auth_request_v2(fds[0], &request) != 0)
		goto cleanup;
	if (frdp_ipc_recv_header(fds[1], &header) != (int)sizeof(header))
		goto cleanup;
	if ((header.type != FRDP_IPC_AUTH_REQUEST_V2) ||
	    (header.payload_len != FRDP_IPC_AUTH_REQUEST_V2_WIRE_SIZE))
		goto cleanup;
	if (frdp_ipc_recv(fds[1], raw, sizeof(raw)) != (int)sizeof(raw))
		goto cleanup;
	if ((memcmp(&raw[0], "corr", 4) != 0) || (memcmp(&raw[user_offset], "alice", 5) != 0) ||
	    (memcmp(&raw[rhost_offset], "203.0.113.8", 11) != 0) ||
	    (memcmp(&raw[password_offset], "secret", 6) != 0))
		goto cleanup;
	if (frdp_ipc_send(fds[1], raw, sizeof(raw)) != 0)
		goto cleanup;
	if (frdp_ipc_recv_auth_request_v2_payload(fds[0], &decoded, sizeof(raw)) != 0)
		goto cleanup;
	if ((strcmp(decoded.correlation_id, request.correlation_id) != 0) ||
	    (strcmp(decoded.user, request.user) != 0) || (strcmp(decoded.rhost, request.rhost) != 0) ||
	    (strcmp(decoded.password, request.password) != 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (fds[0] >= 0)
		close(fds[0]);
	if (fds[1] >= 0)
		close(fds[1]);
	return rc;
}

static int test_auth_token_binds_posix_account(void)
{
	char dir[1024] = { 0 };
	char key_path[1024] = { 0 };
	char token[192] = { 0 };
	char nonce[37] = { 0 };
	const uint64_t groups[] = { 1001, 2000 };
	const uint64_t changed_groups[] = { 1001, 2001 };
	unsigned long long expires_at = 0;
	const char* previous_key_path = getenv(FRDP_AUTH_TOKEN_KEY_ENV);
	char* saved_key_path = previous_key_path ? strdup(previous_key_path) : NULL;
	int rc = -1;

	if (previous_key_path && !saved_key_path)
		return -1;
	if (make_runtime_dir(dir, sizeof(dir)) != 0)
	{
		free(saved_key_path);
		return -1;
	}
	const int key_path_len = snprintf(key_path, sizeof(key_path), "%s/auth-token.key", dir);
	if ((key_path_len < 0) || ((size_t)key_path_len >= sizeof(key_path)))
		goto cleanup;
	if (setenv(FRDP_AUTH_TOKEN_KEY_ENV, key_path, 1) != 0)
		goto cleanup;
	if (frdp_auth_token_create("alice", "198.51.100.8", "corr-1", 1000, 1001, groups, 2, 1,
	                           token, sizeof(token)) != 0)
		goto cleanup;
	if (frdp_auth_token_verify(token, "alice", "198.51.100.8", "corr-1", 1000, 1001, groups,
	                           2, 1, nonce, sizeof(nonce), &expires_at) != 0)
		goto cleanup;
	if (nonce[0] == '\0' || expires_at == 0)
		goto cleanup;
	if (frdp_auth_token_verify(token, "alice", "198.51.100.8", "corr-1", 1002, 1001, groups,
	                           2, 1, nonce, sizeof(nonce), &expires_at) == 0)
		goto cleanup;
	if (frdp_auth_token_verify(token, "alice", "198.51.100.8", "corr-1", 1000, 1002, groups,
	                           2, 1, nonce, sizeof(nonce), &expires_at) == 0)
		goto cleanup;
	if (frdp_auth_token_verify(token, "alice", "198.51.100.8", "corr-1", 1000, 1001, groups,
	                           2, 0, nonce, sizeof(nonce), &expires_at) == 0)
		goto cleanup;
	if (frdp_auth_token_verify(token, "alice", "198.51.100.8", "corr-1", 1000, 1001,
	                           changed_groups, 2, 1, nonce, sizeof(nonce), &expires_at) == 0)
		goto cleanup;
	memset(token, 0, sizeof(token));
	if (frdp_auth_token_create("alice", "h|c", "x", 1000, 1001, groups, 2, 1, token,
	                           sizeof(token)) != 0)
		goto cleanup;
	if (frdp_auth_token_verify(token, "alice|h", "c", "x", 1000, 1001, groups, 2, 1, nonce,
	                           sizeof(nonce), &expires_at) == 0)
		goto cleanup;
	rc = 0;

cleanup:
	if (saved_key_path)
	{
		setenv(FRDP_AUTH_TOKEN_KEY_ENV, saved_key_path, 1);
		free(saved_key_path);
	}
	else
		unsetenv(FRDP_AUTH_TOKEN_KEY_ENV);
	unlink(key_path);
	rmdir(dir);
	return rc;
}

int TestFreeRDPFrdpIpc(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if (test_connect_rejects_relative_path() != 0)
		return -1;
	if (test_connect_secure_socket() != 0)
		return -1;
	if (test_connect_rejects_insecure_parent() != 0)
		return -1;
	if (test_connect_rejects_insecure_socket() != 0)
		return -1;
	if (test_recv_rejects_short_read() != 0)
		return -1;
	if (test_send_recv_reject_null_buffers() != 0)
		return -1;
	if (test_header_uses_little_endian_wire_format() != 0)
		return -1;
	if (test_auth_request_uses_explicit_wire_format() != 0)
		return -1;
	if (test_auth_response_uses_explicit_wire_format() != 0)
		return -1;
	if (test_auth_token_binds_posix_account() != 0)
		return -1;
	return 0;
}

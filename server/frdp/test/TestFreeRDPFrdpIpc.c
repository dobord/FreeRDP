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

static int test_get_peer_uid_validates_arguments_and_reads_peer(void)
{
	int fds[2] = { -1, -1 };
	uint64_t uid = UINT64_MAX;
	int rc = -1;

	errno = 0;
	if ((frdp_ipc_get_peer_uid(-1, NULL) != -1) || (errno != EINVAL))
		return -1;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		return -1;
	if (frdp_ipc_get_peer_uid(fds[0], &uid) != 0)
		goto cleanup;
	if (uid != (uint64_t)geteuid())
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

static int expect_einval(int rc)
{
	return (rc == -1) && (errno == EINVAL) ? 0 : -1;
}

static int test_payload_decoders_reject_invalid_arguments(void)
{
	frdpAuthRequest auth_request = { 0 };
	frdpSessionRequestV3 session_request_v3 = { 0 };
	frdpSessionRequest session_close_request = { 0 };
	frdpAgentInputEvent input = { 0 };
	frdpAgentFrameRequest frame_request = { 0 };
	frdpAgentResizeRequest resize_request = { 0 };

	errno = 0;
	if (expect_einval(frdp_ipc_recv_auth_request_v2_payload(
	        -1, &auth_request, FRDP_IPC_AUTH_REQUEST_V2_WIRE_SIZE - 1U)) != 0)
		return -1;
	errno = 0;
	if (expect_einval(frdp_ipc_recv_auth_request_v2_payload(
	        -1, &auth_request, FRDP_IPC_AUTH_REQUEST_V2_WIRE_SIZE + 1U)) != 0)
		return -1;
	errno = 0;
	if (expect_einval(frdp_ipc_recv_auth_request_v2_payload(
	        -1, NULL, FRDP_IPC_AUTH_REQUEST_V2_WIRE_SIZE)) != 0)
		return -1;
	errno = 0;
	if (expect_einval(frdp_ipc_recv_session_request_v3_payload(
	        -1, &session_request_v3, FRDP_IPC_SESSION_REQUEST_V3_WIRE_SIZE - 1U)) != 0)
		return -1;
	errno = 0;
	if (expect_einval(frdp_ipc_recv_session_request_v3_payload(
	        -1, &session_request_v3, FRDP_IPC_SESSION_REQUEST_V3_WIRE_SIZE + 1U)) != 0)
		return -1;
	errno = 0;
	if (expect_einval(frdp_ipc_recv_session_request_v3_payload(
	        -1, NULL, FRDP_IPC_SESSION_REQUEST_V3_WIRE_SIZE)) != 0)
		return -1;
	errno = 0;
	if (expect_einval(frdp_ipc_recv_session_close_request_payload(
	        -1, &session_close_request, FRDP_IPC_SESSION_CLOSE_REQUEST_WIRE_SIZE - 1U)) != 0)
		return -1;
	errno = 0;
	if (expect_einval(frdp_ipc_recv_session_close_request_payload(
	        -1, &session_close_request, FRDP_IPC_SESSION_CLOSE_REQUEST_WIRE_SIZE + 1U)) != 0)
		return -1;
	errno = 0;
	if (expect_einval(frdp_ipc_recv_session_close_request_payload(
	        -1, NULL, FRDP_IPC_SESSION_CLOSE_REQUEST_WIRE_SIZE)) != 0)
		return -1;
	errno = 0;
	if (expect_einval(frdp_ipc_recv_agent_input_event_payload(
	        -1, &input, FRDP_IPC_AGENT_INPUT_WIRE_SIZE - 1U)) != 0)
		return -1;
	errno = 0;
	if (expect_einval(frdp_ipc_recv_agent_input_event_payload(
	        -1, &input, FRDP_IPC_AGENT_INPUT_WIRE_SIZE + 1U)) != 0)
		return -1;
	errno = 0;
	if (expect_einval(
	        frdp_ipc_recv_agent_input_event_payload(-1, NULL, FRDP_IPC_AGENT_INPUT_WIRE_SIZE)) !=
	    0)
		return -1;
	errno = 0;
	if (expect_einval(frdp_ipc_recv_agent_frame_request_payload(
	        -1, &frame_request, FRDP_IPC_AGENT_FRAME_REQUEST_WIRE_SIZE - 1U)) != 0)
		return -1;
	errno = 0;
	if (expect_einval(frdp_ipc_recv_agent_frame_request_payload(
	        -1, &frame_request, FRDP_IPC_AGENT_FRAME_REQUEST_WIRE_SIZE + 1U)) != 0)
		return -1;
	errno = 0;
	if (expect_einval(frdp_ipc_recv_agent_frame_request_payload(
	        -1, NULL, FRDP_IPC_AGENT_FRAME_REQUEST_WIRE_SIZE)) != 0)
		return -1;
	errno = 0;
	if (expect_einval(frdp_ipc_recv_agent_resize_request_payload(
	        -1, &resize_request, FRDP_IPC_AGENT_RESIZE_REQUEST_WIRE_SIZE - 1U)) != 0)
		return -1;
	errno = 0;
	if (expect_einval(frdp_ipc_recv_agent_resize_request_payload(
	        -1, &resize_request, FRDP_IPC_AGENT_RESIZE_REQUEST_WIRE_SIZE + 1U)) != 0)
		return -1;
	errno = 0;
	if (expect_einval(frdp_ipc_recv_agent_resize_request_payload(
	        -1, NULL, FRDP_IPC_AGENT_RESIZE_REQUEST_WIRE_SIZE)) != 0)
		return -1;
	return 0;
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

static int test_session_request_v3_uses_explicit_wire_format(void)
{
	int fds[2] = { -1, -1 };
	frdpSessionRequestV3 request = { 0 };
	frdpSessionRequestV3 decoded = { 0 };
	frdpIpcHeader header = { 0 };
	uint8_t raw[FRDP_IPC_SESSION_REQUEST_V3_WIRE_SIZE] = { 0 };
	const size_t session_id_offset = sizeof(request.correlation_id);
	const size_t user_offset = session_id_offset + sizeof(request.session_id);
	const size_t rhost_offset = user_offset + sizeof(request.user);
	const size_t authorization_id_offset = rhost_offset + sizeof(request.rhost);
	const size_t uid_offset = authorization_id_offset + sizeof(request.authorization_id);
	const size_t gid_offset = uid_offset + 8U;
	const size_t group_count_offset = gid_offset + 8U;
	const size_t groups_offset = group_count_offset + 4U;
	const size_t unused_group_offset = groups_offset + 16U;
	const size_t has_posix_account_offset = groups_offset + (FRDP_IPC_MAX_AUTH_GROUPS * 8U);
	const size_t desktop_width_offset = has_posix_account_offset + 4U;
	const size_t desktop_height_offset = desktop_width_offset + 4U;
	const size_t color_depth_offset = desktop_height_offset + 4U;
	int rc = -1;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		return -1;
	snprintf(request.correlation_id, sizeof(request.correlation_id), "corr");
	snprintf(request.session_id, sizeof(request.session_id), "session");
	snprintf(request.user, sizeof(request.user), "alice");
	snprintf(request.rhost, sizeof(request.rhost), "203.0.113.9");
	snprintf(request.authorization_id, sizeof(request.authorization_id), "authz");
	request.uid = UINT64_C(0x0102030405060708);
	request.gid = UINT64_C(0x1112131415161718);
	request.group_count = 2;
	request.groups[0] = UINT64_C(0x2122232425262728);
	request.groups[1] = UINT64_C(0x3132333435363738);
	request.groups[2] = UINT64_C(0xf1f2f3f4f5f6f7f8);
	request.has_posix_account = 1;
	request.desktop_width = 0x44332211U;
	request.desktop_height = 0x88776655U;
	request.color_depth = 0xccbbaa99U;
	if (frdp_ipc_send_session_request_v3(fds[0], &request) != 0)
		goto cleanup;
	if (frdp_ipc_recv_header(fds[1], &header) != (int)sizeof(header))
		goto cleanup;
	if ((header.type != FRDP_IPC_SESSION_REQUEST_V3) ||
	    (header.payload_len != FRDP_IPC_SESSION_REQUEST_V3_WIRE_SIZE))
		goto cleanup;
	if (frdp_ipc_recv(fds[1], raw, sizeof(raw)) != (int)sizeof(raw))
		goto cleanup;
	if ((memcmp(&raw[0], "corr", 4) != 0) ||
	    (memcmp(&raw[session_id_offset], "session", 7) != 0) ||
	    (memcmp(&raw[user_offset], "alice", 5) != 0) ||
	    (memcmp(&raw[rhost_offset], "203.0.113.9", 11) != 0) ||
	    (memcmp(&raw[authorization_id_offset], "authz", 5) != 0))
		goto cleanup;
	if ((raw[uid_offset] != 0x08U) || (raw[uid_offset + 7U] != 0x01U) ||
	    (raw[gid_offset] != 0x18U) || (raw[gid_offset + 7U] != 0x11U))
		goto cleanup;
	if ((raw[group_count_offset] != 2U) || (raw[group_count_offset + 1U] != 0U))
		goto cleanup;
	if ((raw[groups_offset] != 0x28U) || (raw[groups_offset + 7U] != 0x21U) ||
	    (raw[groups_offset + 8U] != 0x38U) || (raw[groups_offset + 15U] != 0x31U))
		goto cleanup;
	for (size_t x = 0; x < 8U; x++) {
		if (raw[unused_group_offset + x] != 0U)
			goto cleanup;
		raw[unused_group_offset + x] = (uint8_t)(0xb0U + x);
	}
	if ((raw[has_posix_account_offset] != 1U) || (raw[desktop_width_offset] != 0x11U) ||
	    (raw[desktop_width_offset + 3U] != 0x44U) || (raw[desktop_height_offset] != 0x55U) ||
	    (raw[desktop_height_offset + 3U] != 0x88U) || (raw[color_depth_offset] != 0x99U) ||
	    (raw[color_depth_offset + 3U] != 0xccU))
		goto cleanup;
	if (frdp_ipc_send(fds[1], raw, sizeof(raw)) != 0)
		goto cleanup;
	if (frdp_ipc_recv_session_request_v3_payload(fds[0], &decoded, sizeof(raw)) != 0)
		goto cleanup;
	if ((strcmp(decoded.correlation_id, request.correlation_id) != 0) ||
	    (strcmp(decoded.session_id, request.session_id) != 0) ||
	    (strcmp(decoded.user, request.user) != 0) ||
	    (strcmp(decoded.rhost, request.rhost) != 0) ||
	    (strcmp(decoded.authorization_id, request.authorization_id) != 0) ||
	    (decoded.uid != request.uid) || (decoded.gid != request.gid) ||
	    (decoded.group_count != request.group_count) ||
	    (decoded.groups[0] != request.groups[0]) || (decoded.groups[1] != request.groups[1]) ||
	    (decoded.groups[2] != 0) || (decoded.has_posix_account != request.has_posix_account) ||
	    (decoded.desktop_width != request.desktop_width) ||
	    (decoded.desktop_height != request.desktop_height) ||
	    (decoded.color_depth != request.color_depth))
		goto cleanup;
	rc = 0;

cleanup:
	if (fds[0] >= 0)
		close(fds[0]);
	if (fds[1] >= 0)
		close(fds[1]);
	return rc;
}

static int test_session_response_uses_explicit_wire_format(void)
{
	int fds[2] = { -1, -1 };
	frdpSessionResponse response = { 0 };
	frdpSessionResponse decoded = { 0 };
	frdpIpcHeader header = { 0 };
	uint8_t raw[FRDP_IPC_SESSION_RESPONSE_WIRE_SIZE] = { 0 };
	const size_t session_id_offset = 4U;
	const size_t display_offset = session_id_offset + sizeof(response.session_id);
	const size_t agent_socket_offset = display_offset + sizeof(response.display);
	const size_t error_offset = agent_socket_offset + sizeof(response.agent_socket);
	int rc = -1;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		return -1;
	response.success = 1;
	snprintf(response.session_id, sizeof(response.session_id), "session");
	snprintf(response.display, sizeof(response.display), ":10");
	snprintf(response.agent_socket, sizeof(response.agent_socket), "/run/frdp/session.sock");
	snprintf(response.error, sizeof(response.error), "ignored");
	if (frdp_ipc_send_session_response(fds[0], &response) != 0)
		goto cleanup;
	if (frdp_ipc_recv_header(fds[1], &header) != (int)sizeof(header))
		goto cleanup;
	if ((header.type != FRDP_IPC_SESSION_RESPONSE) ||
	    (header.payload_len != FRDP_IPC_SESSION_RESPONSE_WIRE_SIZE))
		goto cleanup;
	if (frdp_ipc_recv(fds[1], raw, sizeof(raw)) != (int)sizeof(raw))
		goto cleanup;
	if ((raw[0] != 1U) || (raw[1] != 0U) || (raw[2] != 0U) || (raw[3] != 0U))
		goto cleanup;
	if ((memcmp(&raw[session_id_offset], "session", 7) != 0) ||
	    (memcmp(&raw[display_offset], ":10", 3) != 0) ||
	    (memcmp(&raw[agent_socket_offset], "/run/frdp/session.sock", 22) != 0) ||
	    (memcmp(&raw[error_offset], "ignored", 7) != 0))
		goto cleanup;
	if (frdp_ipc_send_header(fds[1], FRDP_IPC_SESSION_RESPONSE, sizeof(raw)) != 0 ||
	    frdp_ipc_send(fds[1], raw, sizeof(raw)) != 0)
		goto cleanup;
	if (frdp_ipc_recv_session_response(fds[0], &decoded) != 0)
		goto cleanup;
	if ((decoded.success != response.success) ||
	    (strcmp(decoded.session_id, response.session_id) != 0) ||
	    (strcmp(decoded.display, response.display) != 0) ||
	    (strcmp(decoded.agent_socket, response.agent_socket) != 0) ||
	    (strcmp(decoded.error, response.error) != 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (fds[0] >= 0)
		close(fds[0]);
	if (fds[1] >= 0)
		close(fds[1]);
	return rc;
}

static int test_session_close_request_uses_explicit_wire_format(void)
{
	int fds[2] = { -1, -1 };
	frdpSessionRequest request = { 0 };
	frdpSessionRequest decoded = { 0 };
	frdpIpcHeader header = { 0 };
	uint8_t raw[FRDP_IPC_SESSION_CLOSE_REQUEST_WIRE_SIZE] = { 0 };
	const size_t session_id_offset = sizeof(request.correlation_id);
	const size_t user_offset = session_id_offset + sizeof(request.session_id);
	const size_t rhost_offset = user_offset + sizeof(request.user);
	const size_t desktop_width_offset = rhost_offset + sizeof(request.rhost);
	const size_t desktop_height_offset = desktop_width_offset + 4U;
	const size_t color_depth_offset = desktop_height_offset + 4U;
	int rc = -1;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		return -1;
	snprintf(request.correlation_id, sizeof(request.correlation_id), "corr");
	snprintf(request.session_id, sizeof(request.session_id), "session");
	snprintf(request.user, sizeof(request.user), "alice");
	snprintf(request.rhost, sizeof(request.rhost), "203.0.113.11");
	request.desktop_width = 0x44332211U;
	request.desktop_height = 0x88776655U;
	request.color_depth = 0xccbbaa99U;
	if (frdp_ipc_send_session_close_request(fds[0], &request) != 0)
		goto cleanup;
	if (frdp_ipc_recv_header(fds[1], &header) != (int)sizeof(header))
		goto cleanup;
	if ((header.type != FRDP_IPC_SESSION_CLOSE_REQUEST) ||
	    (header.payload_len != FRDP_IPC_SESSION_CLOSE_REQUEST_WIRE_SIZE))
		goto cleanup;
	if (frdp_ipc_recv(fds[1], raw, sizeof(raw)) != (int)sizeof(raw))
		goto cleanup;
	if ((memcmp(&raw[0], "corr", 4) != 0) ||
	    (memcmp(&raw[session_id_offset], "session", 7) != 0) ||
	    (memcmp(&raw[user_offset], "alice", 5) != 0) ||
	    (memcmp(&raw[rhost_offset], "203.0.113.11", 12) != 0))
		goto cleanup;
	if ((raw[desktop_width_offset] != 0x11U) || (raw[desktop_width_offset + 3U] != 0x44U) ||
	    (raw[desktop_height_offset] != 0x55U) ||
	    (raw[desktop_height_offset + 3U] != 0x88U) ||
	    (raw[color_depth_offset] != 0x99U) || (raw[color_depth_offset + 3U] != 0xccU))
		goto cleanup;
	if (frdp_ipc_send(fds[1], raw, sizeof(raw)) != 0)
		goto cleanup;
	if (frdp_ipc_recv_session_close_request_payload(fds[0], &decoded, sizeof(raw)) != 0)
		goto cleanup;
	if ((strcmp(decoded.correlation_id, request.correlation_id) != 0) ||
	    (strcmp(decoded.session_id, request.session_id) != 0) ||
	    (strcmp(decoded.user, request.user) != 0) ||
	    (strcmp(decoded.rhost, request.rhost) != 0) ||
	    (decoded.desktop_width != request.desktop_width) ||
	    (decoded.desktop_height != request.desktop_height) ||
	    (decoded.color_depth != request.color_depth))
		goto cleanup;
	rc = 0;

cleanup:
	if (fds[0] >= 0)
		close(fds[0]);
	if (fds[1] >= 0)
		close(fds[1]);
	return rc;
}

static int test_session_list_response_uses_explicit_wire_format(void)
{
	int fds[2] = { -1, -1 };
	frdpSessionListResponse response = { 0 };
	frdpSessionListResponse decoded = { 0 };
	frdpIpcHeader header = { 0 };
	uint8_t raw[FRDP_IPC_SESSION_LIST_RESPONSE_WIRE_SIZE] = { 0 };
	const size_t count_offset = 4U;
	const size_t entries_offset = count_offset + 4U;
	const size_t entry1_offset = entries_offset + FRDP_IPC_SESSION_LIST_ENTRY_WIRE_SIZE;
	const size_t pid_offset = entries_offset + 64U + 64U + 32U;
	int rc = -1;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		return -1;
	response.success = 1;
	response.count = 1;
	snprintf(response.entries[0].session_id, sizeof(response.entries[0].session_id), "session");
	snprintf(response.entries[0].user, sizeof(response.entries[0].user), "alice");
	snprintf(response.entries[0].display, sizeof(response.entries[0].display), ":10");
	response.entries[0].agent_pid = 0x01020304;
	snprintf(response.entries[1].session_id, sizeof(response.entries[1].session_id), "unused");
	response.entries[1].agent_pid = 0x11121314;
	snprintf(response.error, sizeof(response.error), "ignored");
	if (frdp_ipc_send_session_list_response(fds[0], &response) != 0)
		goto cleanup;
	if (frdp_ipc_recv_header(fds[1], &header) != (int)sizeof(header))
		goto cleanup;
	if ((header.type != FRDP_IPC_SESSION_LIST_RESPONSE) ||
	    (header.payload_len != FRDP_IPC_SESSION_LIST_RESPONSE_WIRE_SIZE))
		goto cleanup;
	if (frdp_ipc_recv(fds[1], raw, sizeof(raw)) != (int)sizeof(raw))
		goto cleanup;
	if ((raw[0] != 1U) || (raw[count_offset] != 1U) ||
	    (memcmp(&raw[entries_offset], "session", 7) != 0) ||
	    (memcmp(&raw[entries_offset + 64U], "alice", 5) != 0) ||
	    (memcmp(&raw[entries_offset + 128U], ":10", 3) != 0) || (raw[pid_offset] != 0x04U) ||
	    (raw[pid_offset + 3U] != 0x01U))
		goto cleanup;
	for (size_t x = 0; x < FRDP_IPC_SESSION_LIST_ENTRY_WIRE_SIZE; x++) {
		if (raw[entry1_offset + x] != 0U)
			goto cleanup;
		raw[entry1_offset + x] = (uint8_t)(0xc0U + (x & 0x0fU));
	}
	if (frdp_ipc_send_header(fds[1], FRDP_IPC_SESSION_LIST_RESPONSE, sizeof(raw)) != 0 ||
	    frdp_ipc_send(fds[1], raw, sizeof(raw)) != 0)
		goto cleanup;
	if (frdp_ipc_recv_session_list_response(fds[0], &decoded) != 0)
		goto cleanup;
	if ((decoded.success != response.success) || (decoded.count != response.count) ||
	    (strcmp(decoded.entries[0].session_id, response.entries[0].session_id) != 0) ||
	    (strcmp(decoded.entries[0].user, response.entries[0].user) != 0) ||
	    (strcmp(decoded.entries[0].display, response.entries[0].display) != 0) ||
	    (decoded.entries[0].agent_pid != response.entries[0].agent_pid) ||
	    (decoded.entries[1].session_id[0] != '\0') || (decoded.entries[1].agent_pid != 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (fds[0] >= 0)
		close(fds[0]);
	if (fds[1] >= 0)
		close(fds[1]);
	return rc;
}

static int test_session_reload_response_uses_explicit_wire_format(void)
{
	int fds[2] = { -1, -1 };
	frdpControlResponse response = { 0 };
	frdpControlResponse decoded = { 0 };
	frdpIpcHeader header = { 0 };
	uint8_t raw[FRDP_IPC_SESSION_RELOAD_RESPONSE_WIRE_SIZE] = { 0 };
	const size_t message_offset = 4U;
	const size_t error_offset = message_offset + sizeof(response.message);
	int rc = -1;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		return -1;
	response.success = 1;
	snprintf(response.message, sizeof(response.message), "accepted");
	snprintf(response.error, sizeof(response.error), "ignored");
	if (frdp_ipc_send_session_reload_response(fds[0], &response) != 0)
		goto cleanup;
	if (frdp_ipc_recv_header(fds[1], &header) != (int)sizeof(header))
		goto cleanup;
	if ((header.type != FRDP_IPC_SESSION_RELOAD_RESPONSE) ||
	    (header.payload_len != FRDP_IPC_SESSION_RELOAD_RESPONSE_WIRE_SIZE))
		goto cleanup;
	if (frdp_ipc_recv(fds[1], raw, sizeof(raw)) != (int)sizeof(raw))
		goto cleanup;
	if ((raw[0] != 1U) || (raw[1] != 0U) ||
	    (memcmp(&raw[message_offset], "accepted", 8) != 0) ||
	    (memcmp(&raw[error_offset], "ignored", 7) != 0))
		goto cleanup;
	if (frdp_ipc_send_header(fds[1], FRDP_IPC_SESSION_RELOAD_RESPONSE, sizeof(raw)) != 0 ||
	    frdp_ipc_send(fds[1], raw, sizeof(raw)) != 0)
		goto cleanup;
	if (frdp_ipc_recv_session_reload_response(fds[0], &decoded) != 0)
		goto cleanup;
	if ((decoded.success != response.success) ||
	    (strcmp(decoded.message, response.message) != 0) ||
	    (strcmp(decoded.error, response.error) != 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (fds[0] >= 0)
		close(fds[0]);
	if (fds[1] >= 0)
		close(fds[1]);
	return rc;
}

static int test_agent_messages_use_explicit_wire_format(void)
{
	int fds[2] = { -1, -1 };
	frdpIpcHeader header = { 0 };
	frdpAgentInputEvent input = { 0 };
	frdpAgentInputEvent decoded_input = { 0 };
	frdpAgentFrameRequest frame_request = { 0 };
	frdpAgentFrameRequest decoded_frame_request = { 0 };
	frdpAgentFrameResponse frame_response = { 0 };
	frdpAgentFrameResponse decoded_frame_response = { 0 };
	frdpAgentResizeRequest resize_request = { 0 };
	frdpAgentResizeRequest decoded_resize_request = { 0 };
	frdpAgentResizeResponse resize_response = { 0 };
	frdpAgentResizeResponse decoded_resize_response = { 0 };
	uint8_t input_raw[FRDP_IPC_AGENT_INPUT_WIRE_SIZE] = { 0 };
	uint8_t frame_request_raw[FRDP_IPC_AGENT_FRAME_REQUEST_WIRE_SIZE] = { 0 };
	uint8_t frame_response_raw[FRDP_IPC_AGENT_FRAME_RESPONSE_WIRE_SIZE] = { 0 };
	uint8_t resize_request_raw[FRDP_IPC_AGENT_RESIZE_REQUEST_WIRE_SIZE] = { 0 };
	uint8_t resize_response_raw[FRDP_IPC_AGENT_RESIZE_RESPONSE_WIRE_SIZE] = { 0 };
	const size_t input_session_offset = sizeof(input.correlation_id);
	const size_t input_type_offset = input_session_offset + sizeof(input.session_id);
	const size_t input_flags_offset = input_type_offset + 4U;
	const size_t input_param1_offset = input_flags_offset + 4U;
	const size_t input_param2_offset = input_param1_offset + 4U;
	const size_t frame_request_session_offset = sizeof(frame_request.correlation_id);
	const size_t frame_request_x_offset =
	    frame_request_session_offset + sizeof(frame_request.session_id);
	const size_t frame_request_y_offset = frame_request_x_offset + 4U;
	const size_t frame_request_width_offset = frame_request_y_offset + 4U;
	const size_t frame_request_height_offset = frame_request_width_offset + 4U;
	const size_t frame_request_flags_offset = frame_request_height_offset + 4U;
	const size_t frame_response_session_offset = sizeof(frame_response.correlation_id);
	const size_t frame_response_success_offset =
	    frame_response_session_offset + sizeof(frame_response.session_id);
	const size_t frame_response_x_offset = frame_response_success_offset + 4U;
	const size_t frame_response_y_offset = frame_response_x_offset + 4U;
	const size_t frame_response_width_offset = frame_response_y_offset + 4U;
	const size_t frame_response_height_offset = frame_response_width_offset + 4U;
	const size_t frame_response_stride_offset = frame_response_height_offset + 4U;
	const size_t frame_response_bpp_offset = frame_response_stride_offset + 4U;
	const size_t frame_response_flags_offset = frame_response_bpp_offset + 4U;
	const size_t frame_response_data_length_offset = frame_response_flags_offset + 4U;
	const size_t frame_response_error_offset = frame_response_data_length_offset + 4U;
	const size_t resize_request_session_offset = sizeof(resize_request.correlation_id);
	const size_t resize_request_width_offset =
	    resize_request_session_offset + sizeof(resize_request.session_id);
	const size_t resize_request_height_offset = resize_request_width_offset + 4U;
	const size_t resize_request_color_depth_offset = resize_request_height_offset + 4U;
	const size_t resize_response_session_offset = sizeof(resize_response.correlation_id);
	const size_t resize_response_success_offset =
	    resize_response_session_offset + sizeof(resize_response.session_id);
	const size_t resize_response_width_offset = resize_response_success_offset + 4U;
	const size_t resize_response_height_offset = resize_response_width_offset + 4U;
	const size_t resize_response_error_offset = resize_response_height_offset + 4U;
	int rc = -1;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		return -1;

	snprintf(input.correlation_id, sizeof(input.correlation_id), "corr");
	snprintf(input.session_id, sizeof(input.session_id), "session");
	input.event_type = FRDP_AGENT_INPUT_KEYBOARD;
	input.flags = 0x11223344U;
	input.param1 = (int32_t)0x88776655U;
	input.param2 = -2;
	if (frdp_ipc_send_agent_input_event(fds[0], &input) != 0)
		goto cleanup;
	if (frdp_ipc_recv_header(fds[1], &header) != (int)sizeof(header))
		goto cleanup;
	if ((header.type != FRDP_IPC_AGENT_INPUT) ||
	    (header.payload_len != FRDP_IPC_AGENT_INPUT_WIRE_SIZE))
		goto cleanup;
	if (frdp_ipc_recv(fds[1], input_raw, sizeof(input_raw)) != (int)sizeof(input_raw))
		goto cleanup;
	if ((memcmp(&input_raw[0], "corr", 4) != 0) ||
	    (memcmp(&input_raw[input_session_offset], "session", 7) != 0) ||
	    (input_raw[input_type_offset] != FRDP_AGENT_INPUT_KEYBOARD) ||
	    (input_raw[input_flags_offset] != 0x44U) || (input_raw[input_flags_offset + 3U] != 0x11U) ||
	    (input_raw[input_param1_offset] != 0x55U) ||
	    (input_raw[input_param1_offset + 3U] != 0x88U) ||
	    (input_raw[input_param2_offset] != 0xfeU) ||
	    (input_raw[input_param2_offset + 3U] != 0xffU))
		goto cleanup;
	if (frdp_ipc_send(fds[1], input_raw, sizeof(input_raw)) != 0)
		goto cleanup;
	if (frdp_ipc_recv_agent_input_event_payload(fds[0], &decoded_input,
	                                            sizeof(input_raw)) != 0)
		goto cleanup;
	if ((strcmp(decoded_input.correlation_id, input.correlation_id) != 0) ||
	    (strcmp(decoded_input.session_id, input.session_id) != 0) ||
	    (decoded_input.event_type != input.event_type) || (decoded_input.flags != input.flags) ||
	    (decoded_input.param1 != input.param1) || (decoded_input.param2 != input.param2))
		goto cleanup;

	snprintf(frame_request.correlation_id, sizeof(frame_request.correlation_id), "corr");
	snprintf(frame_request.session_id, sizeof(frame_request.session_id), "session");
	frame_request.x = 0x01020304U;
	frame_request.y = 0x11121314U;
	frame_request.width = 0x21222324U;
	frame_request.height = 0x31323334U;
	frame_request.flags = FRDP_AGENT_FRAME_REQUEST_DIRTY_ONLY;
	if (frdp_ipc_send_agent_frame_request(fds[0], &frame_request) != 0)
		goto cleanup;
	if (frdp_ipc_recv_header(fds[1], &header) != (int)sizeof(header))
		goto cleanup;
	if ((header.type != FRDP_IPC_AGENT_FRAME_REQUEST) ||
	    (header.payload_len != FRDP_IPC_AGENT_FRAME_REQUEST_WIRE_SIZE))
		goto cleanup;
	if (frdp_ipc_recv(fds[1], frame_request_raw, sizeof(frame_request_raw)) !=
	    (int)sizeof(frame_request_raw))
		goto cleanup;
	if ((memcmp(&frame_request_raw[0], "corr", 4) != 0) ||
	    (memcmp(&frame_request_raw[frame_request_session_offset], "session", 7) != 0) ||
	    (frame_request_raw[frame_request_x_offset] != 0x04U) ||
	    (frame_request_raw[frame_request_x_offset + 3U] != 0x01U) ||
	    (frame_request_raw[frame_request_y_offset] != 0x14U) ||
	    (frame_request_raw[frame_request_y_offset + 3U] != 0x11U) ||
	    (frame_request_raw[frame_request_width_offset] != 0x24U) ||
	    (frame_request_raw[frame_request_width_offset + 3U] != 0x21U) ||
	    (frame_request_raw[frame_request_height_offset] != 0x34U) ||
	    (frame_request_raw[frame_request_height_offset + 3U] != 0x31U) ||
	    (frame_request_raw[frame_request_flags_offset] != FRDP_AGENT_FRAME_REQUEST_DIRTY_ONLY))
		goto cleanup;
	if (frdp_ipc_send(fds[1], frame_request_raw, sizeof(frame_request_raw)) != 0)
		goto cleanup;
	if (frdp_ipc_recv_agent_frame_request_payload(fds[0], &decoded_frame_request,
	                                             sizeof(frame_request_raw)) != 0)
		goto cleanup;
	if ((strcmp(decoded_frame_request.correlation_id, frame_request.correlation_id) != 0) ||
	    (strcmp(decoded_frame_request.session_id, frame_request.session_id) != 0) ||
	    (decoded_frame_request.x != frame_request.x) ||
	    (decoded_frame_request.y != frame_request.y) ||
	    (decoded_frame_request.width != frame_request.width) ||
	    (decoded_frame_request.height != frame_request.height) ||
	    (decoded_frame_request.flags != frame_request.flags))
		goto cleanup;

	snprintf(frame_response.correlation_id, sizeof(frame_response.correlation_id), "corr");
	snprintf(frame_response.session_id, sizeof(frame_response.session_id), "session");
	frame_response.success = 1;
	frame_response.x = 0x01020304U;
	frame_response.y = 0x11121314U;
	frame_response.width = 0x21222324U;
	frame_response.height = 0x31323334U;
	frame_response.stride = 0x41424344U;
	frame_response.bpp = 32;
	frame_response.flags = FRDP_AGENT_FRAME_RESPONSE_UNCHANGED;
	frame_response.data_length = 0x51525354U;
	snprintf(frame_response.error, sizeof(frame_response.error), "ignored");
	if (frdp_ipc_send_agent_frame_response(fds[0], &frame_response) != 0)
		goto cleanup;
	if (frdp_ipc_recv_header(fds[1], &header) != (int)sizeof(header))
		goto cleanup;
	if ((header.type != FRDP_IPC_AGENT_FRAME_RESPONSE) ||
	    (header.payload_len != FRDP_IPC_AGENT_FRAME_RESPONSE_WIRE_SIZE))
		goto cleanup;
	if (frdp_ipc_recv(fds[1], frame_response_raw, sizeof(frame_response_raw)) !=
	    (int)sizeof(frame_response_raw))
		goto cleanup;
	if ((memcmp(&frame_response_raw[0], "corr", 4) != 0) ||
	    (memcmp(&frame_response_raw[frame_response_session_offset], "session", 7) != 0) ||
	    (frame_response_raw[frame_response_success_offset] != 1U) ||
	    (frame_response_raw[frame_response_x_offset] != 0x04U) ||
	    (frame_response_raw[frame_response_x_offset + 3U] != 0x01U) ||
	    (frame_response_raw[frame_response_y_offset] != 0x14U) ||
	    (frame_response_raw[frame_response_y_offset + 3U] != 0x11U) ||
	    (frame_response_raw[frame_response_width_offset] != 0x24U) ||
	    (frame_response_raw[frame_response_width_offset + 3U] != 0x21U) ||
	    (frame_response_raw[frame_response_height_offset] != 0x34U) ||
	    (frame_response_raw[frame_response_height_offset + 3U] != 0x31U) ||
	    (frame_response_raw[frame_response_stride_offset] != 0x44U) ||
	    (frame_response_raw[frame_response_stride_offset + 3U] != 0x41U) ||
	    (frame_response_raw[frame_response_bpp_offset] != 32U) ||
	    (frame_response_raw[frame_response_flags_offset] != FRDP_AGENT_FRAME_RESPONSE_UNCHANGED) ||
	    (frame_response_raw[frame_response_data_length_offset] != 0x54U) ||
	    (frame_response_raw[frame_response_data_length_offset + 3U] != 0x51U) ||
	    (memcmp(&frame_response_raw[frame_response_error_offset], "ignored", 7) != 0))
		goto cleanup;
	if (frdp_ipc_send_header(fds[1], FRDP_IPC_AGENT_FRAME_RESPONSE,
	                         sizeof(frame_response_raw)) != 0 ||
	    frdp_ipc_send(fds[1], frame_response_raw, sizeof(frame_response_raw)) != 0)
		goto cleanup;
	if (frdp_ipc_recv_agent_frame_response(fds[0], &decoded_frame_response) != 0)
		goto cleanup;
	if ((strcmp(decoded_frame_response.correlation_id, frame_response.correlation_id) != 0) ||
	    (strcmp(decoded_frame_response.session_id, frame_response.session_id) != 0) ||
	    (decoded_frame_response.success != frame_response.success) ||
	    (decoded_frame_response.x != frame_response.x) ||
	    (decoded_frame_response.y != frame_response.y) ||
	    (decoded_frame_response.width != frame_response.width) ||
	    (decoded_frame_response.height != frame_response.height) ||
	    (decoded_frame_response.stride != frame_response.stride) ||
	    (decoded_frame_response.bpp != frame_response.bpp) ||
	    (decoded_frame_response.flags != frame_response.flags) ||
	    (decoded_frame_response.data_length != frame_response.data_length) ||
	    (strcmp(decoded_frame_response.error, frame_response.error) != 0))
		goto cleanup;

	snprintf(resize_request.correlation_id, sizeof(resize_request.correlation_id), "corr");
	snprintf(resize_request.session_id, sizeof(resize_request.session_id), "session");
	resize_request.width = 0x01020304U;
	resize_request.height = 0x11121314U;
	resize_request.color_depth = 0x21222324U;
	if (frdp_ipc_send_agent_resize_request(fds[0], &resize_request) != 0)
		goto cleanup;
	if (frdp_ipc_recv_header(fds[1], &header) != (int)sizeof(header))
		goto cleanup;
	if ((header.type != FRDP_IPC_AGENT_RESIZE_REQUEST) ||
	    (header.payload_len != FRDP_IPC_AGENT_RESIZE_REQUEST_WIRE_SIZE))
		goto cleanup;
	if (frdp_ipc_recv(fds[1], resize_request_raw, sizeof(resize_request_raw)) !=
	    (int)sizeof(resize_request_raw))
		goto cleanup;
	if ((memcmp(&resize_request_raw[0], "corr", 4) != 0) ||
	    (memcmp(&resize_request_raw[resize_request_session_offset], "session", 7) != 0) ||
	    (resize_request_raw[resize_request_width_offset] != 0x04U) ||
	    (resize_request_raw[resize_request_width_offset + 3U] != 0x01U) ||
	    (resize_request_raw[resize_request_height_offset] != 0x14U) ||
	    (resize_request_raw[resize_request_height_offset + 3U] != 0x11U) ||
	    (resize_request_raw[resize_request_color_depth_offset] != 0x24U) ||
	    (resize_request_raw[resize_request_color_depth_offset + 3U] != 0x21U))
		goto cleanup;
	if (frdp_ipc_send(fds[1], resize_request_raw, sizeof(resize_request_raw)) != 0)
		goto cleanup;
	if (frdp_ipc_recv_agent_resize_request_payload(fds[0], &decoded_resize_request,
	                                              sizeof(resize_request_raw)) != 0)
		goto cleanup;
	if ((strcmp(decoded_resize_request.correlation_id, resize_request.correlation_id) != 0) ||
	    (strcmp(decoded_resize_request.session_id, resize_request.session_id) != 0) ||
	    (decoded_resize_request.width != resize_request.width) ||
	    (decoded_resize_request.height != resize_request.height) ||
	    (decoded_resize_request.color_depth != resize_request.color_depth))
		goto cleanup;

	snprintf(resize_response.correlation_id, sizeof(resize_response.correlation_id), "corr");
	snprintf(resize_response.session_id, sizeof(resize_response.session_id), "session");
	resize_response.success = 1;
	resize_response.width = 0x01020304U;
	resize_response.height = 0x11121314U;
	snprintf(resize_response.error, sizeof(resize_response.error), "ignored");
	if (frdp_ipc_send_agent_resize_response(fds[0], &resize_response) != 0)
		goto cleanup;
	if (frdp_ipc_recv_header(fds[1], &header) != (int)sizeof(header))
		goto cleanup;
	if ((header.type != FRDP_IPC_AGENT_RESIZE_RESPONSE) ||
	    (header.payload_len != FRDP_IPC_AGENT_RESIZE_RESPONSE_WIRE_SIZE))
		goto cleanup;
	if (frdp_ipc_recv(fds[1], resize_response_raw, sizeof(resize_response_raw)) !=
	    (int)sizeof(resize_response_raw))
		goto cleanup;
	if ((memcmp(&resize_response_raw[0], "corr", 4) != 0) ||
	    (memcmp(&resize_response_raw[resize_response_session_offset], "session", 7) != 0) ||
	    (resize_response_raw[resize_response_success_offset] != 1U) ||
	    (resize_response_raw[resize_response_width_offset] != 0x04U) ||
	    (resize_response_raw[resize_response_width_offset + 3U] != 0x01U) ||
	    (resize_response_raw[resize_response_height_offset] != 0x14U) ||
	    (resize_response_raw[resize_response_height_offset + 3U] != 0x11U) ||
	    (memcmp(&resize_response_raw[resize_response_error_offset], "ignored", 7) != 0))
		goto cleanup;
	if (frdp_ipc_send_header(fds[1], FRDP_IPC_AGENT_RESIZE_RESPONSE,
	                         sizeof(resize_response_raw)) != 0 ||
	    frdp_ipc_send(fds[1], resize_response_raw, sizeof(resize_response_raw)) != 0)
		goto cleanup;
	if (frdp_ipc_recv_agent_resize_response(fds[0], &decoded_resize_response) != 0)
		goto cleanup;
	if ((strcmp(decoded_resize_response.correlation_id, resize_response.correlation_id) != 0) ||
	    (strcmp(decoded_resize_response.session_id, resize_response.session_id) != 0) ||
	    (decoded_resize_response.success != resize_response.success) ||
	    (decoded_resize_response.width != resize_response.width) ||
	    (decoded_resize_response.height != resize_response.height) ||
	    (strcmp(decoded_resize_response.error, resize_response.error) != 0))
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
	if (test_get_peer_uid_validates_arguments_and_reads_peer() != 0)
		return -1;
	if (test_header_uses_little_endian_wire_format() != 0)
		return -1;
	if (test_payload_decoders_reject_invalid_arguments() != 0)
		return -1;
	if (test_auth_request_uses_explicit_wire_format() != 0)
		return -1;
	if (test_auth_response_uses_explicit_wire_format() != 0)
		return -1;
	if (test_session_request_v3_uses_explicit_wire_format() != 0)
		return -1;
	if (test_session_response_uses_explicit_wire_format() != 0)
		return -1;
	if (test_session_close_request_uses_explicit_wire_format() != 0)
		return -1;
	if (test_session_list_response_uses_explicit_wire_format() != 0)
		return -1;
	if (test_session_reload_response_uses_explicit_wire_format() != 0)
		return -1;
	if (test_agent_messages_use_explicit_wire_format() != 0)
		return -1;
	if (test_auth_token_binds_posix_account() != 0)
		return -1;
	return 0;
}

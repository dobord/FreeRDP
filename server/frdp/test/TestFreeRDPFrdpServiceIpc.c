#include "ipc/frdp-auth-token.h"
#include "ipc/frdp-ipc.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef FRDPD_BINARY
#error "FRDPD_BINARY is not defined"
#endif
#ifndef FRDP_AUTHD_BINARY
#error "FRDP_AUTHD_BINARY is not defined"
#endif
#ifndef FRDP_SESMAND_BINARY
#error "FRDP_SESMAND_BINARY is not defined"
#endif

typedef struct
{
	pid_t pid;
	char dir[1024];
	char socket_path[sizeof(((struct sockaddr_un*)0)->sun_path)];
} frdpTestHelper;

static int make_runtime_dir(char* dir, size_t dir_size, const char* name)
{
	const int rc = snprintf(dir, dir_size, "/tmp/frdp-%s-XXXXXX", name);

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

static int wait_for_socket(const char* path)
{
	for (int attempt = 0; attempt < 50; attempt++)
	{
		struct stat st;

		if (lstat(path, &st) == 0)
		{
			if (!S_ISSOCK(st.st_mode) || ((st.st_mode & 0777) != 0600))
				return -1;
			return 0;
		}
		if (errno != ENOENT)
			return -1;
		usleep(100000);
	}
	return -1;
}

static int wait_for_exit(pid_t pid, int* status)
{
	for (int attempt = 0; attempt < 50; attempt++)
	{
		const pid_t rc = waitpid(pid, status, WNOHANG);

		if (rc == pid)
			return 0;
		if (rc < 0)
		{
			if (errno == EINTR)
				continue;
			return -1;
		}
		usleep(100000);
	}
	return -1;
}

static int start_helper_with_config(const char* binary, const char* name, const char* config_path,
                                    frdpTestHelper* helper)
{
	if (!binary || !name || !helper)
		return -1;
	memset(helper, 0, sizeof(*helper));
	helper->pid = -1;
	if (make_runtime_dir(helper->dir, sizeof(helper->dir), name) != 0)
		return -1;
	if (snprintf(helper->socket_path, sizeof(helper->socket_path), "%s/%s.sock", helper->dir,
	             name) >= (int)sizeof(helper->socket_path))
		goto fail;

	helper->pid = fork();
	if (helper->pid < 0)
		goto fail;
	if (helper->pid == 0)
	{
		if (config_path)
			execl(binary, binary, "--config", config_path, "--socket", helper->socket_path,
			      (char*)NULL);
		else
			execl(binary, binary, "--socket", helper->socket_path, (char*)NULL);
		_exit(127);
	}
	if (wait_for_socket(helper->socket_path) != 0)
		goto fail;
	return 0;

fail:
	if (helper->pid > 0)
	{
		int status = 0;
		kill(helper->pid, SIGTERM);
		if (wait_for_exit(helper->pid, &status) != 0)
		{
			kill(helper->pid, SIGKILL);
			(void)waitpid(helper->pid, NULL, 0);
		}
	}
	unlink(helper->socket_path);
	rmdir(helper->dir);
	memset(helper, 0, sizeof(*helper));
	helper->pid = -1;
	return -1;
}

static int start_helper(const char* binary, const char* name, frdpTestHelper* helper)
{
	return start_helper_with_config(binary, name, NULL, helper);
}

static int stop_helper(frdpTestHelper* helper)
{
	int status = 0;
	int rc = -1;

	if (!helper || helper->pid <= 0)
		return -1;
	if (kill(helper->pid, SIGTERM) != 0)
		goto cleanup;
	if (wait_for_exit(helper->pid, &status) != 0)
		goto cleanup;
	helper->pid = -1;
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0))
		goto cleanup;
	if (access(helper->socket_path, F_OK) == 0 || errno != ENOENT)
		goto cleanup;
	rc = 0;

cleanup:
	if (helper->pid > 0)
	{
		kill(helper->pid, SIGTERM);
		if (wait_for_exit(helper->pid, &status) != 0)
		{
			kill(helper->pid, SIGKILL);
			(void)waitpid(helper->pid, NULL, 0);
		}
		helper->pid = -1;
	}
	unlink(helper->socket_path);
	rmdir(helper->dir);
	return rc;
}

static int send_header(int fd, frdpIpcMessageType type, uint32_t payload_len)
{
	return frdp_ipc_send_header(fd, type, payload_len);
}

static int send_partial_header_then_close(const char* socket_path, frdpIpcMessageType type,
                                          uint32_t payload_len)
{
	frdpIpcHeader header = { 0 };
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	header.type = type;
	header.payload_len = payload_len;
	rc = frdp_ipc_send(fd, &header, sizeof(header) / 2U);
	frdp_ipc_close(fd);
	return rc;
}

static int send_partial_body_then_close(const char* socket_path, frdpIpcMessageType type,
                                        const void* payload, size_t payload_len)
{
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	if (send_header(fd, type, payload_len) == 0)
		rc = frdp_ipc_send(fd, payload, payload_len / 2U);
	frdp_ipc_close(fd);
	return rc;
}

static int receive_auth_failure(int fd, const char* expected_error)
{
	frdpAuthResponse response = { 0 };

	if (frdp_ipc_recv_auth_response(fd, &response) != 0)
		return -1;
	if (response.success != 0)
		return -1;
	if (!memchr(response.error, '\0', sizeof(response.error)))
		return -1;
	if (expected_error && strcmp(response.error, expected_error) != 0)
		return -1;
	return 0;
}

static int receive_session_response(int fd, int expected_success, const char* expected_error)
{
	frdpSessionResponse response = { 0 };

	if (frdp_ipc_recv_session_response(fd, &response) != 0)
		return -1;
	if (!!response.success != !!expected_success)
	{
		fprintf(stderr, "unexpected session success: got=%u expected=%d error=%s\n",
		        response.success, expected_success, response.error);
		return -1;
	}
	if (!memchr(response.error, '\0', sizeof(response.error)))
		return -1;
	if (expected_error && strcmp(response.error, expected_error) != 0)
	{
		fprintf(stderr, "unexpected session error: got=%s expected=%s\n", response.error,
		        expected_error);
		return -1;
	}
	return 0;
}

static int receive_reload_response(int fd, int expected_success, const char* expected_message,
                                   const char* expected_error)
{
	frdpIpcHeader header = { 0 };
	frdpControlResponse response = { 0 };

	if (frdp_ipc_recv_header(fd, &header) != (int)sizeof(header))
		return -1;
	if ((header.type != FRDP_IPC_SESSION_RELOAD_RESPONSE) ||
	    (header.payload_len != sizeof(response)))
		return -1;
	if (frdp_ipc_recv(fd, &response, sizeof(response)) != (int)sizeof(response))
		return -1;
	if (!!response.success != !!expected_success)
		return -1;
	if (!memchr(response.message, '\0', sizeof(response.message)) ||
	    !memchr(response.error, '\0', sizeof(response.error)))
		return -1;
	if (expected_message && strcmp(response.message, expected_message) != 0)
		return -1;
	if (expected_error && strcmp(response.error, expected_error) != 0)
		return -1;
	return 0;
}

static int compare_uint64(const void* lhs, const void* rhs)
{
	const uint64_t a = *(const uint64_t*)lhs;
	const uint64_t b = *(const uint64_t*)rhs;

	if (a < b)
		return -1;
	if (a > b)
		return 1;
	return 0;
}

static int group_list_contains(const uint64_t* groups, uint32_t group_count, uint64_t gid)
{
	for (uint32_t x = 0; x < group_count; x++)
	{
		if (groups[x] == gid)
			return 1;
	}
	return 0;
}

static int lookup_current_user(char* user, size_t user_size, uint64_t* uid, uint64_t* gid,
                               uint64_t* groups, uint32_t* group_count)
{
	gid_t native_groups[FRDP_IPC_MAX_AUTH_GROUPS] = { 0 };
	int native_group_count = (int)FRDP_IPC_MAX_AUTH_GROUPS;
	struct passwd* pwd = NULL;

	if (!user || !uid || !gid || !groups || !group_count)
		return -1;
	pwd = getpwuid(geteuid());
	if (!pwd || !pwd->pw_name)
		return -1;
	if (snprintf(user, user_size, "%s", pwd->pw_name) >= (int)user_size)
		return -1;
	if (getgrouplist(pwd->pw_name, pwd->pw_gid, native_groups, &native_group_count) < 0)
		return -1;
	if ((native_group_count <= 0) ||
	    ((uint32_t)native_group_count > FRDP_IPC_MAX_AUTH_GROUPS))
		return -1;
	*uid = (uint64_t)pwd->pw_uid;
	*gid = (uint64_t)pwd->pw_gid;
	*group_count = (uint32_t)native_group_count;
	for (uint32_t x = 0; x < *group_count; x++)
		groups[x] = (uint64_t)native_groups[x];
	qsort(groups, *group_count, sizeof(groups[0]), compare_uint64);
	return 0;
}

static int make_wrong_groups(const uint64_t* groups, uint32_t group_count, uint64_t* wrong_groups)
{
	uint64_t candidate = 0;

	if (!groups || !wrong_groups || (group_count == 0))
		return -1;
	memcpy(wrong_groups, groups, group_count * sizeof(groups[0]));
	candidate = groups[0] + 1U;
	while (group_list_contains(groups, group_count, candidate))
		candidate++;
	wrong_groups[0] = candidate;
	qsort(wrong_groups, group_count, sizeof(wrong_groups[0]), compare_uint64);
	if ((group_count == 1) && (wrong_groups[0] == groups[0]))
		return -1;
	if ((group_count > 1) &&
	    (memcmp(groups, wrong_groups, group_count * sizeof(groups[0])) == 0))
		return -1;
	return 0;
}

static int test_authd_rejects_bad_length(const char* socket_path)
{
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	if (send_header(fd, FRDP_IPC_AUTH_REQUEST_V2, sizeof(frdpAuthRequest) - 1U) != 0)
		goto cleanup;
	rc = receive_auth_failure(fd, "unsupported IPC request");

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int test_authd_rejects_unknown_type(const char* socket_path)
{
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	if (send_header(fd, (frdpIpcMessageType)0x7fffffff, 0) != 0)
		goto cleanup;
	rc = receive_auth_failure(fd, "unsupported IPC request");

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int test_authd_rejects_oversized_payload(const char* socket_path)
{
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	if (send_header(fd, FRDP_IPC_AUTH_REQUEST_V2, FRDP_IPC_MAX_REQUEST_PAYLOAD_LEN + 1U) != 0)
		goto cleanup;
	rc = receive_auth_failure(fd, "IPC payload too large");

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int test_authd_rejects_unterminated_request(const char* socket_path)
{
	frdpAuthRequest request = { 0 };
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	memset(request.user, 'A', sizeof(request.user));
	snprintf(request.correlation_id, sizeof(request.correlation_id),
	         "11111111-1111-4111-8111-111111111111");
	if (send_header(fd, FRDP_IPC_AUTH_REQUEST_V2, sizeof(request)) != 0 ||
	    frdp_ipc_send(fd, &request, sizeof(request)) != 0)
		goto cleanup;
	rc = receive_auth_failure(fd, "invalid auth request");

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int test_authd_survives_truncated_clients(const char* socket_path)
{
	frdpAuthRequest request = { 0 };

	snprintf(request.correlation_id, sizeof(request.correlation_id),
	         "12121212-1212-4212-8212-121212121212");
	if (send_partial_header_then_close(socket_path, FRDP_IPC_AUTH_REQUEST_V2,
	                                   sizeof(request)) != 0)
		return -1;
	if (send_partial_body_then_close(socket_path, FRDP_IPC_AUTH_REQUEST_V2, &request,
	                                 sizeof(request)) != 0)
		return -1;
	return test_authd_rejects_bad_length(socket_path);
}

static int test_authd_component(void)
{
	frdpTestHelper helper;
	int rc = -1;

	if (start_helper(FRDP_AUTHD_BINARY, "frdp-authd-component", &helper) != 0)
		return -1;
	if (test_authd_rejects_bad_length(helper.socket_path) != 0)
		goto cleanup;
	if (test_authd_rejects_unknown_type(helper.socket_path) != 0)
		goto cleanup;
	if (test_authd_rejects_oversized_payload(helper.socket_path) != 0)
		goto cleanup;
	if (test_authd_rejects_unterminated_request(helper.socket_path) != 0)
		goto cleanup;
	if (test_authd_survives_truncated_clients(helper.socket_path) != 0)
		goto cleanup;
	/* A final request proves that malformed clients did not stop the service loop. */
	if (test_authd_rejects_bad_length(helper.socket_path) != 0)
		goto cleanup;
	rc = 0;

cleanup:
	if (stop_helper(&helper) != 0)
		rc = -1;
	return rc;
}

static int test_authd_rate_limit(void)
{
	frdpTestHelper helper;
	int rc = -1;

	if (start_helper(FRDP_AUTHD_BINARY, "frdp-authd-rate-limit", &helper) != 0)
		return -1;
	for (uint32_t x = 0; x < FRDP_IPC_RATE_LIMIT_MAX_REQUESTS; x++)
	{
		if (test_authd_rejects_bad_length(helper.socket_path) != 0)
			goto cleanup;
	}
	{
		int fd = frdp_ipc_connect(helper.socket_path);

		if (fd < 0)
			goto cleanup;
		if (send_header(fd, FRDP_IPC_AUTH_REQUEST_V2, sizeof(frdpAuthRequest) - 1U) == 0)
			rc = receive_auth_failure(fd, "IPC rate limit exceeded");
		frdp_ipc_close(fd);
	}

cleanup:
	if (stop_helper(&helper) != 0)
		rc = -1;
	return rc;
}

static int test_sesmand_list_empty(const char* socket_path)
{
	frdpIpcHeader header = { 0 };
	frdpSessionListResponse response = { 0 };
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	if (send_header(fd, FRDP_IPC_SESSION_LIST_REQUEST, 0) != 0)
		goto cleanup;
	if (frdp_ipc_recv_header(fd, &header) != (int)sizeof(header))
		goto cleanup;
	if ((header.type != FRDP_IPC_SESSION_LIST_RESPONSE) ||
	    (header.payload_len != sizeof(response)))
		goto cleanup;
	if (frdp_ipc_recv(fd, &response, sizeof(response)) != (int)sizeof(response))
		goto cleanup;
	if ((response.success != 1) || (response.count != 0))
		goto cleanup;
	rc = 0;

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int test_sesmand_rejects_unknown_session(const char* socket_path)
{
	frdpSessionRequest request = { 0 };
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	snprintf(request.correlation_id, sizeof(request.correlation_id),
	         "22222222-2222-4222-8222-222222222222");
	snprintf(request.session_id, sizeof(request.session_id),
	         "33333333-3333-4333-8333-333333333333");
	if (frdp_ipc_send_session_close_request(fd, &request) != 0)
		goto cleanup;
	rc = receive_session_response(fd, 0, "unknown session");

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int test_sesmand_rejects_unterminated_request(const char* socket_path)
{
	frdpSessionRequest request = { 0 };
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	memset(request.session_id, 'S', sizeof(request.session_id));
	snprintf(request.correlation_id, sizeof(request.correlation_id),
	         "44444444-4444-4444-8444-444444444444");
	if (frdp_ipc_send_session_close_request(fd, &request) != 0)
		goto cleanup;
	rc = receive_session_response(fd, 0, "invalid session request");

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int test_sesmand_rejects_missing_posix_account(const char* socket_path)
{
	frdpSessionRequestV2 request = { 0 };
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	snprintf(request.correlation_id, sizeof(request.correlation_id),
	         "55555555-5555-4555-8555-555555555555");
	snprintf(request.session_id, sizeof(request.session_id),
	         "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
	snprintf(request.user, sizeof(request.user), "nobody");
	if (send_header(fd, FRDP_IPC_SESSION_REQUEST_V2, sizeof(request)) != 0 ||
	    frdp_ipc_send(fd, &request, sizeof(request)) != 0)
		goto cleanup;
	rc = receive_session_response(fd, 0, "missing authorization");

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int test_sesmand_rejects_posix_account_mismatch(const char* socket_path)
{
	frdpSessionRequestV2 request = { 0 };
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	snprintf(request.correlation_id, sizeof(request.correlation_id),
	         "66666666-6666-4666-8666-666666666666");
	snprintf(request.session_id, sizeof(request.session_id),
	         "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
	snprintf(request.user, sizeof(request.user), "nobody");
	request.has_posix_account = 1;
	request.uid = 0;
	request.gid = 0;
	if (send_header(fd, FRDP_IPC_SESSION_REQUEST_V2, sizeof(request)) != 0 ||
	    frdp_ipc_send(fd, &request, sizeof(request)) != 0)
		goto cleanup;
	rc = receive_session_response(fd, 0, "missing authorization");

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int test_sesmand_rejects_missing_authorization(const char* socket_path)
{
	frdpSessionRequestV3 request = { 0 };
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	snprintf(request.correlation_id, sizeof(request.correlation_id),
	         "88888888-8888-4888-8888-888888888888");
	snprintf(request.user, sizeof(request.user), "nobody");
	request.has_posix_account = 1;
	request.uid = 0;
	request.gid = 0;
	if (frdp_ipc_send_session_request_v3(fd, &request) != 0)
		goto cleanup;
	rc = receive_session_response(fd, 0, "missing authorization");

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int test_sesmand_rejects_invalid_authorization(const char* socket_path)
{
	frdpSessionRequestV3 request = { 0 };
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	snprintf(request.correlation_id, sizeof(request.correlation_id),
	         "99999999-9999-4999-8999-999999999999");
	snprintf(request.user, sizeof(request.user), "nobody");
	snprintf(request.authorization_id, sizeof(request.authorization_id),
	         "11111111-1111-4111-8111-111111111111:9999999999:%064u", 0U);
	request.has_posix_account = 1;
	request.uid = 0;
	request.gid = 0;
	if (frdp_ipc_send_session_request_v3(fd, &request) != 0)
		goto cleanup;
	rc = receive_session_response(fd, 0, "invalid authorization");

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int test_sesmand_rejects_posix_groups_mismatch(void)
{
	frdpTestHelper helper;
	char dir[1024] = { 0 };
	char key_path[1024] = { 0 };
	char user[64] = { 0 };
	char token[192] = { 0 };
	uint64_t uid = 0;
	uint64_t gid = 0;
	uint64_t groups[FRDP_IPC_MAX_AUTH_GROUPS] = { 0 };
	uint64_t wrong_groups[FRDP_IPC_MAX_AUTH_GROUPS] = { 0 };
	uint32_t group_count = 0;
	const char* previous_key_path = getenv(FRDP_AUTH_TOKEN_KEY_ENV);
	char* saved_key_path = previous_key_path ? strdup(previous_key_path) : NULL;
	int fd = -1;
	int rc = -1;
	const char* stage = "init";
	frdpSessionRequestV3 request = { 0 };

	memset(&helper, 0, sizeof(helper));
	helper.pid = -1;
	if (previous_key_path && !saved_key_path)
		return -1;
	stage = "make_runtime_dir";
	if (make_runtime_dir(dir, sizeof(dir), "frdp-sesmand-groups") != 0)
		goto cleanup;
	stage = "key_path";
	if (snprintf(key_path, sizeof(key_path), "%s/auth-token.key", dir) >=
	    (int)sizeof(key_path))
		goto cleanup;
	stage = "setenv";
	if (setenv(FRDP_AUTH_TOKEN_KEY_ENV, key_path, 1) != 0)
		goto cleanup;
	stage = "lookup_current_user";
	if (lookup_current_user(user, sizeof(user), &uid, &gid, groups, &group_count) != 0)
		goto cleanup;
	stage = "make_wrong_groups";
	if (make_wrong_groups(groups, group_count, wrong_groups) != 0)
		goto cleanup;
	stage = "create_token";
	if (frdp_auth_token_create(user, "203.0.113.10", "groups-mismatch", uid, gid,
	                           wrong_groups, group_count, 1, token, sizeof(token)) != 0)
		goto cleanup;
	stage = "start_helper";
	if (start_helper(FRDP_SESMAND_BINARY, "frdp-sesmand-groups", &helper) != 0)
		goto cleanup;
	stage = "connect";
	fd = frdp_ipc_connect(helper.socket_path);
	if (fd < 0)
		goto cleanup;
	snprintf(request.correlation_id, sizeof(request.correlation_id), "groups-mismatch");
	snprintf(request.user, sizeof(request.user), "%s", user);
	snprintf(request.rhost, sizeof(request.rhost), "203.0.113.10");
	snprintf(request.authorization_id, sizeof(request.authorization_id), "%s", token);
	request.has_posix_account = 1;
	request.uid = uid;
	request.gid = gid;
	request.group_count = group_count;
	memcpy(request.groups, wrong_groups, group_count * sizeof(wrong_groups[0]));
	if (frdp_ipc_send_session_request_v3(fd, &request) != 0)
		goto cleanup;
	stage = "receive";
	rc = receive_session_response(fd, 0, "POSIX groups mismatch");

cleanup:
	if (rc != 0)
		fprintf(stderr, "POSIX groups mismatch test failed at stage: %s\n", stage);
	if (fd >= 0)
		frdp_ipc_close(fd);
	if ((helper.pid > 0) && (stop_helper(&helper) != 0))
		rc = -1;
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

static int test_sesmand_rejects_bad_length(const char* socket_path)
{
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	if (send_header(fd, FRDP_IPC_SESSION_REQUEST, sizeof(frdpSessionRequest) - 1U) != 0)
		goto cleanup;
	rc = receive_session_response(fd, 0, "unsupported IPC request");

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int test_sesmand_rejects_oversized_payload(const char* socket_path)
{
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	if (send_header(fd, FRDP_IPC_SESSION_REQUEST, FRDP_IPC_MAX_REQUEST_PAYLOAD_LEN + 1U) != 0)
		goto cleanup;
	rc = receive_session_response(fd, 0, "IPC payload too large");

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int test_sesmand_survives_truncated_clients(const char* socket_path)
{
	frdpSessionRequest request = { 0 };

	snprintf(request.correlation_id, sizeof(request.correlation_id),
	         "77777777-7777-4777-8777-777777777777");
	if (send_partial_header_then_close(socket_path, FRDP_IPC_SESSION_REQUEST,
	                                   sizeof(request)) != 0)
		return -1;
	if (send_partial_body_then_close(socket_path, FRDP_IPC_SESSION_REQUEST, &request,
	                                 sizeof(request)) != 0)
		return -1;
	return test_sesmand_list_empty(socket_path);
}

static int test_sesmand_reload(const char* socket_path, int expected_success,
                               const char* expected_message, const char* expected_error)
{
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	if (send_header(fd, FRDP_IPC_SESSION_RELOAD_REQUEST, 0) != 0)
		goto cleanup;
	rc = receive_reload_response(fd, expected_success, expected_message, expected_error);

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int write_sesmand_config(const char* path, const char* pam_service)
{
	FILE* fp = NULL;

	if (!path || !pam_service)
		return -1;
	fp = fopen(path, "wb");
	if (!fp)
		return -1;
	if (fprintf(fp, "[auth]\npam_service = \"%s\"\n", pam_service) < 0)
	{
		fclose(fp);
		return -1;
	}
	return fclose(fp);
}

static int test_sesmand_reload_config(void)
{
	frdpTestHelper helper;
	char config_dir[1024] = { 0 };
	char config_path[1024] = { 0 };
	int rc = -1;

	memset(&helper, 0, sizeof(helper));
	helper.pid = -1;
	if (make_runtime_dir(config_dir, sizeof(config_dir), "frdp-sesmand-reload-config") != 0)
		return -1;
	if (snprintf(config_path, sizeof(config_path), "%s/frdpd.toml", config_dir) >=
	    (int)sizeof(config_path))
		goto cleanup_dir;
	if (write_sesmand_config(config_path, "frdpd") != 0)
		goto cleanup_dir;
	if (start_helper_with_config(FRDP_SESMAND_BINARY, "frdp-sesmand-reload", config_path,
	                             &helper) != 0)
		goto cleanup_dir;
	if (test_sesmand_reload(helper.socket_path, 1, "applied", NULL) != 0)
		goto cleanup;
	if (write_sesmand_config(config_path, "frdpd_reload") != 0)
		goto cleanup;
	if (test_sesmand_reload(helper.socket_path, 1, "applied", NULL) != 0)
		goto cleanup;
	if (write_sesmand_config(config_path, "bad/service") != 0)
		goto cleanup;
	if (test_sesmand_reload(helper.socket_path, 0, NULL, "config reload failed") != 0)
		goto cleanup;
	if (test_sesmand_list_empty(helper.socket_path) != 0)
		goto cleanup;
	rc = 0;

cleanup:
	if (stop_helper(&helper) != 0)
		rc = -1;
cleanup_dir:
	unlink(config_path);
	rmdir(config_dir);
	return rc;
}

static int test_sesmand_component(void)
{
	frdpTestHelper helper;
	int rc = -1;

	if (start_helper(FRDP_SESMAND_BINARY, "frdp-sesmand-component", &helper) != 0)
		return -1;
	if (test_sesmand_list_empty(helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_rejects_unknown_session(helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_rejects_unterminated_request(helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_rejects_missing_posix_account(helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_rejects_posix_account_mismatch(helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_rejects_missing_authorization(helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_rejects_invalid_authorization(helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_rejects_bad_length(helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_rejects_oversized_payload(helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_survives_truncated_clients(helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_reload(helper.socket_path, 1, "accepted", NULL) != 0)
		goto cleanup;
	/* A final list request proves the registry and service loop remained healthy. */
	if (test_sesmand_list_empty(helper.socket_path) != 0)
		goto cleanup;
	rc = 0;

cleanup:
	if (stop_helper(&helper) != 0)
		rc = -1;
	return rc;
}

static int test_sesmand_rate_limit(void)
{
	frdpTestHelper helper;
	int rc = -1;

	if (start_helper(FRDP_SESMAND_BINARY, "frdp-sesmand-rate-limit", &helper) != 0)
		return -1;
	for (uint32_t x = 0; x < FRDP_IPC_RATE_LIMIT_MAX_REQUESTS; x++)
	{
		if (test_sesmand_list_empty(helper.socket_path) != 0)
			goto cleanup;
	}
	{
		int fd = frdp_ipc_connect(helper.socket_path);

		if (fd < 0)
			goto cleanup;
		if (send_header(fd, FRDP_IPC_SESSION_LIST_REQUEST, 0) == 0)
			rc = receive_session_response(fd, 0, "IPC rate limit exceeded");
		frdp_ipc_close(fd);
	}

cleanup:
	if (stop_helper(&helper) != 0)
		rc = -1;
	return rc;
}

static int file_contains(const char* path, const char* needle)
{
	char buffer[4096] = { 0 };
	FILE* fp = NULL;
	size_t needle_len = 0;
	size_t used = 0;
	int found = 0;

	if (!path || !needle)
		return 0;
	needle_len = strlen(needle);
	if ((needle_len == 0) || (needle_len >= sizeof(buffer)))
		return 0;
	fp = fopen(path, "rb");
	if (!fp)
		return 0;
	while (!found)
	{
		const size_t available = sizeof(buffer) - used - 1U;
		const size_t read = fread(&buffer[used], 1, available, fp);

		used += read;
		buffer[used] = '\0';
		if (strstr(buffer, needle))
			found = 1;
		if (read < available)
			break;
		if (used > needle_len)
		{
			memmove(buffer, &buffer[used - needle_len], needle_len);
			used = needle_len;
		}
		else
			used = 0;
	}
	fclose(fp);
	return found;
}

static int run_frdpd_with_live_helpers(const char* auth_socket, const char* session_socket)
{
	char dir[1024] = { 0 };
	char stderr_path[1024] = { 0 };
	char auth_arg[sizeof(((struct sockaddr_un*)0)->sun_path) + 32] = { 0 };
	char session_arg[sizeof(((struct sockaddr_un*)0)->sun_path) + 32] = { 0 };
	pid_t pid = -1;
	int status = 0;
	int rc = -1;

	if (!auth_socket || !session_socket)
		return -1;
	if (make_runtime_dir(dir, sizeof(dir), "frdpd-topology") != 0)
		return -1;
	if (snprintf(stderr_path, sizeof(stderr_path), "%s/stderr.log", dir) >=
	    (int)sizeof(stderr_path))
		goto cleanup;
	if (snprintf(auth_arg, sizeof(auth_arg), "--auth-socket=%s", auth_socket) >=
	    (int)sizeof(auth_arg))
		goto cleanup;
	if (snprintf(session_arg, sizeof(session_arg), "--session-socket=%s", session_socket) >=
	    (int)sizeof(session_arg))
		goto cleanup;

	pid = fork();
	if (pid < 0)
		goto cleanup;
	if (pid == 0)
	{
		const int err = open(stderr_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
		const int devnull = open("/dev/null", O_WRONLY);

		if (err < 0)
			_exit(127);
		(void)dup2(err, STDERR_FILENO);
		if (devnull >= 0)
			(void)dup2(devnull, STDOUT_FILENO);
		if (err > STDERR_FILENO)
			close(err);
		if (devnull > STDOUT_FILENO)
			close(devnull);
		execl(FRDPD_BINARY, FRDPD_BINARY, auth_arg, session_arg, "--cert=/missing",
		      "--key=/missing", (char*)NULL);
		_exit(127);
	}
	if (wait_for_exit(pid, &status) != 0)
	{
		kill(pid, SIGKILL);
		(void)waitpid(pid, NULL, 0);
		pid = -1;
		goto cleanup;
	}
	pid = -1;
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != 255))
		goto cleanup;
	if (!file_contains(stderr_path, "Certificate or key file not found: cert=/missing key=/missing"))
		goto cleanup;
	rc = 0;

cleanup:
	if (pid > 0)
	{
		kill(pid, SIGKILL);
		(void)waitpid(pid, NULL, 0);
	}
	unlink(stderr_path);
	rmdir(dir);
	return rc;
}

static int test_frdpd_live_helper_topology(void)
{
	frdpTestHelper auth_helper;
	frdpTestHelper session_helper;
	int auth_started = 0;
	int session_started = 0;
	int rc = -1;

	if (start_helper(FRDP_AUTHD_BINARY, "frdp-authd-topology", &auth_helper) != 0)
		return -1;
	auth_started = 1;
	if (start_helper(FRDP_SESMAND_BINARY, "frdp-sesmand-topology", &session_helper) != 0)
		goto cleanup;
	session_started = 1;
	if (run_frdpd_with_live_helpers(auth_helper.socket_path, session_helper.socket_path) != 0)
		goto cleanup;
	if (test_authd_rejects_bad_length(auth_helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_list_empty(session_helper.socket_path) != 0)
		goto cleanup;
	rc = 0;

cleanup:
	if (session_started && (stop_helper(&session_helper) != 0))
		rc = -1;
	if (auth_started && (stop_helper(&auth_helper) != 0))
		rc = -1;
	return rc;
}

int TestFreeRDPFrdpServiceIpc(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if (test_authd_component() != 0)
	{
		printf("frdp-authd IPC component test failed\n");
		return -1;
	}
	if (test_sesmand_component() != 0)
	{
		printf("frdp-sesmand IPC component test failed\n");
		return -1;
	}
	if (test_authd_rate_limit() != 0)
	{
		printf("frdp-authd IPC rate-limit test failed\n");
		return -1;
	}
	if (test_sesmand_rate_limit() != 0)
	{
		printf("frdp-sesmand IPC rate-limit test failed\n");
		return -1;
	}
	if (test_sesmand_rejects_posix_groups_mismatch() != 0)
	{
		printf("frdp-sesmand POSIX groups mismatch test failed\n");
		return -1;
	}
	if (test_sesmand_reload_config() != 0)
	{
		printf("frdp-sesmand reload config test failed\n");
		return -1;
	}
	if (test_frdpd_live_helper_topology() != 0)
	{
		printf("frdpd live helper topology test failed\n");
		return -1;
	}
	return 0;
}

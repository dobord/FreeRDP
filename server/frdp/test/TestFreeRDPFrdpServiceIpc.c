#include "ipc/frdp-auth-token.h"
#include "ipc/frdp-ipc.h"
#include "frdp-sesmand/display_policy.h"
#include "frdp-sesmand/session_metadata.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <winpr/crt.h>

#ifndef FRDPD_BINARY
#error "FRDPD_BINARY is not defined"
#endif
#ifndef FRDP_AUTHD_BINARY
#error "FRDP_AUTHD_BINARY is not defined"
#endif
#ifndef FRDP_SESMAND_BINARY
#error "FRDP_SESMAND_BINARY is not defined"
#endif

#define FRDP_IPC_SLOW_SEND_DELAY_US 1000U
#define FRDP_IPC_CONCURRENT_CLIENTS 8U
#define FRDP_TEST_HELPER_TIMEOUT_MS "200"

typedef struct
{
	pid_t pid;
	char dir[1024];
	char socket_path[sizeof(((struct sockaddr_un*)0)->sun_path)];
} frdpTestHelper;

typedef int (*frdpTestRequestFn)(const char* socket_path);

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

static int restart_helper_with_config(const char* binary, const char* config_path,
                                      frdpTestHelper* helper)
{
	struct stat previous = { 0 };

	if (!binary || !config_path || !helper || (helper->pid > 0) ||
	    (lstat(helper->socket_path, &previous) != 0))
		return -1;
	helper->pid = fork();
	if (helper->pid < 0)
		return -1;
	if (helper->pid == 0)
	{
		execl(binary, binary, "--config", config_path, "--socket", helper->socket_path,
		      (char*)NULL);
		_exit(127);
	}
	for (int attempt = 0; attempt < 100; attempt++)
	{
		struct stat current = { 0 };
		const int stat_status = lstat(helper->socket_path, &current);

		if ((stat_status == 0) && S_ISSOCK(current.st_mode) &&
		    ((current.st_dev != previous.st_dev) || (current.st_ino != previous.st_ino)))
			return 0;
		if ((stat_status != 0) && (errno != ENOENT))
			break;
		usleep(100000);
	}
	kill(helper->pid, SIGKILL);
	(void)waitpid(helper->pid, NULL, 0);
	helper->pid = -1;
	return -1;
}

static int wait_for_process_gone(pid_t pid)
{
	for (int attempt = 0; attempt < 50; attempt++)
	{
		if ((kill(pid, 0) != 0) && (errno == ESRCH))
			return 0;
		usleep(100000);
	}
	return -1;
}

static int open_process_pidfd(pid_t pid)
{
#if defined(__linux__) && defined(SYS_pidfd_open)
	return (int)syscall(SYS_pidfd_open, pid, 0U);
#else
	(void)pid;
	errno = ENOTSUP;
	return -1;
#endif
}

static int signal_process_pidfd(int pidfd, int signal_number)
{
#if defined(__linux__) && defined(SYS_pidfd_send_signal)
	return (int)syscall(SYS_pidfd_send_signal, pidfd, signal_number, NULL, 0U);
#else
	(void)pidfd;
	(void)signal_number;
	errno = ENOTSUP;
	return -1;
#endif
}

static int prepend_binary_dirs_to_path(const char* first_binary, const char* second_binary,
                                       char** saved_path)
{
	char first_dir[1024] = { 0 };
	char second_dir[1024] = { 0 };
	char updated_path[4096] = { 0 };
	char* first_slash = NULL;
	char* second_slash = NULL;
	const char* current_path = getenv("PATH");

	if (!first_binary || !second_binary || !saved_path || !current_path ||
	    (snprintf(first_dir, sizeof(first_dir), "%s", first_binary) >= (int)sizeof(first_dir)) ||
	    (snprintf(second_dir, sizeof(second_dir), "%s", second_binary) >= (int)sizeof(second_dir)))
		return -1;
	*saved_path = strdup(current_path);
	if (!*saved_path)
		return -1;
	first_slash = strrchr(first_dir, '/');
	second_slash = strrchr(second_dir, '/');
	if (!first_slash || (first_slash == first_dir) || !second_slash || (second_slash == second_dir))
		goto fail;
	*first_slash = '\0';
	*second_slash = '\0';
	if (snprintf(updated_path, sizeof(updated_path), "%s:%s:%s", first_dir, second_dir,
	             current_path) >= (int)sizeof(updated_path))
		goto fail;
	if (setenv("PATH", updated_path, 1) != 0)
		goto fail;
	return 0;

fail:
	free(*saved_path);
	*saved_path = NULL;
	return -1;
}

static void restore_path(char* saved_path)
{
	if (!saved_path)
		return;
	(void)setenv("PATH", saved_path, 1);
	free(saved_path);
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

static int run_concurrent_requests(const char* socket_path, frdpTestRequestFn request_fn,
                                   uint32_t client_count)
{
	pid_t pids[FRDP_IPC_CONCURRENT_CLIENTS] = { 0 };
	int rc = -1;

	if (!socket_path || !request_fn || (client_count == 0) ||
	    (client_count > FRDP_IPC_CONCURRENT_CLIENTS))
		return -1;

	for (uint32_t x = 0; x < client_count; x++)
	{
		pids[x] = fork();
		if (pids[x] < 0)
			goto cleanup;
		if (pids[x] == 0)
			_exit(request_fn(socket_path) == 0 ? 0 : 1);
	}

	for (uint32_t x = 0; x < client_count; x++)
	{
		int status = 0;

		if (pids[x] <= 0)
			continue;
		if (waitpid(pids[x], &status, 0) != pids[x])
			goto cleanup;
		pids[x] = 0;
		if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0))
			goto cleanup;
	}
	rc = 0;

cleanup:
	for (uint32_t x = 0; x < client_count; x++)
	{
		if (pids[x] > 0)
		{
			kill(pids[x], SIGKILL);
			(void)waitpid(pids[x], NULL, 0);
		}
	}
	return rc;
}

static int send_header(int fd, frdpIpcMessageType type, uint32_t payload_len)
{
	return frdp_ipc_send_header(fd, type, payload_len);
}

static int send_partial_header_then_close(const char* socket_path, frdpIpcMessageType type,
                                          uint32_t payload_len, size_t sent_len)
{
	frdpIpcHeader header = { 0 };
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	if (sent_len >= sizeof(header))
		goto cleanup;
	header.type = type;
	header.payload_len = payload_len;
	rc = frdp_ipc_send(fd, &header, sent_len);
cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int send_partial_body_then_close(const char* socket_path, frdpIpcMessageType type,
                                        const void* payload, size_t payload_len, size_t sent_len)
{
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (!payload || (sent_len >= payload_len))
		return -1;
	if (fd < 0)
		return -1;
	if (send_header(fd, type, payload_len) == 0)
		rc = frdp_ipc_send(fd, payload, sent_len);
	frdp_ipc_close(fd);
	return rc;
}

static int send_truncated_boundaries(const char* socket_path, frdpIpcMessageType type,
                                     const void* payload, size_t payload_len)
{
	const size_t header_lengths[] = { 1U, sizeof(frdpIpcHeader) / 2U,
		                              sizeof(frdpIpcHeader) - 1U };
	const size_t header_length_count = sizeof(header_lengths) / sizeof(header_lengths[0]);
	size_t body_lengths[3] = { 0 };

	if (!socket_path || (!payload && (payload_len > 0)))
		return -1;
	for (size_t x = 0; x < header_length_count; x++)
	{
		if (send_partial_header_then_close(socket_path, type, (uint32_t)payload_len,
		                                   header_lengths[x]) != 0)
			return -1;
	}
	if (payload_len == 0)
		return 0;
	body_lengths[0] = 1U;
	body_lengths[1] = payload_len / 2U;
	body_lengths[2] = payload_len - 1U;
	for (size_t x = 0; x < (sizeof(body_lengths) / sizeof(body_lengths[0])); x++)
	{
		if ((body_lengths[x] == 0) || (body_lengths[x] >= payload_len))
			continue;
		if (send_partial_body_then_close(socket_path, type, payload, payload_len,
		                                 body_lengths[x]) != 0)
			return -1;
	}
	return 0;
}

static int send_slow_payload(int fd, const uint8_t* payload, size_t payload_len,
                             useconds_t delay_us)
{
	if (!payload && (payload_len > 0))
		return -1;
	for (size_t x = 0; x < payload_len; x++)
	{
		if (frdp_ipc_send(fd, &payload[x], 1U) != 0)
			return -1;
		if (delay_us > 0)
			usleep(delay_us);
	}
	return 0;
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

static int receive_session_success(int fd, frdpSessionResponse* response)
{
	if (!response || (frdp_ipc_recv_session_response(fd, response) != 0) ||
	    (response->success != 1) ||
	    !memchr(response->session_id, '\0', sizeof(response->session_id)) ||
	    !memchr(response->display, '\0', sizeof(response->display)) ||
	    !memchr(response->agent_socket, '\0', sizeof(response->agent_socket)) ||
	    !memchr(response->error, '\0', sizeof(response->error)) || (response->error[0] != '\0'))
		return -1;
	return 0;
}

static int receive_reload_response(int fd, int expected_success, const char* expected_message,
                                   const char* expected_error)
{
	frdpControlResponse response = { 0 };

	if (frdp_ipc_recv_session_reload_response(fd, &response) != 0)
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

static int test_authd_bad_length_or_rate_limited(const char* socket_path, int* limited)
{
	frdpAuthResponse response = { 0 };
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (limited)
		*limited = 0;
	if (fd < 0 || !limited)
		return -1;
	if (send_header(fd, FRDP_IPC_AUTH_REQUEST_V2, sizeof(frdpAuthRequest) - 1U) != 0)
		goto cleanup;
	if (frdp_ipc_recv_auth_response(fd, &response) != 0)
		goto cleanup;
	if (response.success != 0 || !memchr(response.error, '\0', sizeof(response.error)))
		goto cleanup;
	if (strcmp(response.error, "IPC rate limit exceeded") == 0)
	{
		*limited = 1;
		rc = 0;
	}
	else if (strcmp(response.error, "unsupported IPC request") == 0)
		rc = 0;

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

static int test_authd_handles_slow_complete_client(const char* socket_path)
{
	uint8_t payload[FRDP_IPC_AUTH_REQUEST_V2_WIRE_SIZE] = { 0 };
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	memset(payload, 'A', sizeof(((frdpAuthRequest*)0)->user));
	if (send_header(fd, FRDP_IPC_AUTH_REQUEST_V2, sizeof(payload)) != 0)
		goto cleanup;
	if (send_slow_payload(fd, payload, sizeof(payload), FRDP_IPC_SLOW_SEND_DELAY_US) != 0)
		goto cleanup;
	rc = receive_auth_failure(fd, "invalid auth request");

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int test_authd_times_out_incomplete_client(const char* socket_path)
{
	uint8_t payload[FRDP_IPC_AUTH_REQUEST_V2_WIRE_SIZE] = { 0 };
	frdpIpcHeader response = { 0 };
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	if (send_header(fd, FRDP_IPC_AUTH_REQUEST_V2, sizeof(payload)) != 0)
		goto cleanup;
	if (frdp_ipc_recv_header(fd, &response) >= 0)
		goto cleanup;
	if (test_authd_rejects_bad_length(socket_path) != 0)
		goto cleanup;
	rc = 0;

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int test_authd_survives_truncated_clients(const char* socket_path)
{
	uint8_t request[FRDP_IPC_AUTH_REQUEST_V2_WIRE_SIZE] = { 0 };

	if (send_truncated_boundaries(socket_path, FRDP_IPC_AUTH_REQUEST_V2, request,
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
	if (test_authd_handles_slow_complete_client(helper.socket_path) != 0)
		goto cleanup;
	if (run_concurrent_requests(helper.socket_path, test_authd_rejects_bad_length,
	                            FRDP_IPC_CONCURRENT_CLIENTS) != 0)
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
	int limited = 0;

	if (start_helper(FRDP_AUTHD_BINARY, "frdp-authd-rate-limit", &helper) != 0)
		return -1;
	for (uint32_t x = 0; x < FRDP_IPC_RATE_LIMIT_MAX_REQUESTS + 2U; x++)
	{
		if (test_authd_bad_length_or_rate_limited(helper.socket_path, &limited) != 0)
			goto cleanup;
		if (limited)
		{
			rc = 0;
			goto cleanup;
		}
	}

cleanup:
	if (stop_helper(&helper) != 0)
		rc = -1;
	return rc;
}

static int test_authd_slowloris_timeout(void)
{
	frdpTestHelper helper;
	const char* previous = getenv("FRDP_HELPER_IPC_TIMEOUT_MS");
	char* saved = previous ? strdup(previous) : NULL;
	int rc = -1;

	if (previous && !saved)
		return -1;
	memset(&helper, 0, sizeof(helper));
	helper.pid = -1;
	if (setenv("FRDP_HELPER_IPC_TIMEOUT_MS", FRDP_TEST_HELPER_TIMEOUT_MS, 1) != 0)
		goto cleanup_env;
	if (start_helper(FRDP_AUTHD_BINARY, "frdp-authd-slowloris", &helper) != 0)
		goto cleanup_env;
	rc = test_authd_times_out_incomplete_client(helper.socket_path);
	if (stop_helper(&helper) != 0)
		rc = -1;

cleanup_env:
	if (saved)
	{
		setenv("FRDP_HELPER_IPC_TIMEOUT_MS", saved, 1);
		free(saved);
	}
	else
		unsetenv("FRDP_HELPER_IPC_TIMEOUT_MS");
	return rc;
}

static int test_sesmand_list_empty(const char* socket_path)
{
	frdpSessionListResponse response = { 0 };
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	if (send_header(fd, FRDP_IPC_SESSION_LIST_REQUEST, 0) != 0)
		goto cleanup;
	if (frdp_ipc_recv_session_list_response(fd, &response) != 0)
		goto cleanup;
	if ((response.success != 1) || (response.count != 0))
		goto cleanup;
	rc = 0;

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int receive_sesmand_list(const char* socket_path, frdpSessionListResponse* response)
{
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if ((fd < 0) || !response)
		return -1;
	memset(response, 0, sizeof(*response));
	if (send_header(fd, FRDP_IPC_SESSION_LIST_REQUEST, 0) != 0)
		goto cleanup;
	if ((frdp_ipc_recv_session_list_response(fd, response) != 0) || (response->success != 1) ||
	    (response->count > FRDP_IPC_MAX_SESSION_LIST_ENTRIES) ||
	    !memchr(response->error, '\0', sizeof(response->error)) || (response->error[0] != '\0'))
		goto cleanup;
	for (uint32_t x = 0; x < response->count; x++)
	{
		const frdpSessionListEntry* entry = &response->entries[x];

		if (!memchr(entry->session_id, '\0', sizeof(entry->session_id)) ||
		    !memchr(entry->user, '\0', sizeof(entry->user)) ||
		    !memchr(entry->display, '\0', sizeof(entry->display)) ||
		    !memchr(entry->state, '\0', sizeof(entry->state)))
			goto cleanup;
	}
	rc = 0;

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int test_sesmand_list_empty_or_rate_limited(const char* socket_path, int* limited)
{
	frdpIpcHeader header = { .type = FRDP_IPC_INVALID, .payload_len = 0 };
	uint8_t list_wire[FRDP_IPC_SESSION_LIST_RESPONSE_WIRE_SIZE] = { 0 };
	uint8_t response_wire[FRDP_IPC_SESSION_RESPONSE_WIRE_SIZE] = { 0 };
	char error[sizeof(((frdpSessionResponse*)0)->error)] = { 0 };
	const size_t error_offset = 4U + sizeof(((frdpSessionResponse*)0)->session_id) +
	                            sizeof(((frdpSessionResponse*)0)->display) +
	                            sizeof(((frdpSessionResponse*)0)->agent_socket);
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (limited)
		*limited = 0;
	if (fd < 0 || !limited)
		return -1;
	if (send_header(fd, FRDP_IPC_SESSION_LIST_REQUEST, 0) != 0)
		goto cleanup;
	if (frdp_ipc_recv_header(fd, &header) != (int)sizeof(header))
		goto cleanup;
	if ((header.type == FRDP_IPC_SESSION_LIST_RESPONSE) &&
	    (header.payload_len == sizeof(list_wire)))
	{
		if (frdp_ipc_recv(fd, list_wire, sizeof(list_wire)) != (int)sizeof(list_wire))
			goto cleanup;
		if ((list_wire[0] != 1U) || (list_wire[1] != 0U) || (list_wire[2] != 0U) ||
		    (list_wire[3] != 0U) || (list_wire[4] != 0U) || (list_wire[5] != 0U) ||
		    (list_wire[6] != 0U) || (list_wire[7] != 0U))
			goto cleanup;
		rc = 0;
	}
	else if ((header.type == FRDP_IPC_SESSION_RESPONSE) &&
	         (header.payload_len == sizeof(response_wire)))
	{
		if (frdp_ipc_recv(fd, response_wire, sizeof(response_wire)) !=
		    (int)sizeof(response_wire))
			goto cleanup;
		memcpy(error, &response_wire[error_offset], sizeof(error));
		if (!memchr(error, '\0', sizeof(error)) ||
		    (strcmp(error, "IPC rate limit exceeded") != 0))
			goto cleanup;
		*limited = 1;
		rc = 0;
	}

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

static int test_sesmand_rejects_unknown_disconnect_session(const char* socket_path)
{
	frdpSessionRequest request = { 0 };
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	snprintf(request.correlation_id, sizeof(request.correlation_id),
	         "22222222-2222-4222-8222-222222222222");
	snprintf(request.session_id, sizeof(request.session_id),
	         "44444444-4444-4444-8444-444444444444");
	if (frdp_ipc_send_session_disconnect_request(fd, &request) != 0)
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

static int test_sesmand_rejects_legacy_v1_open_request(const char* socket_path)
{
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	if (send_header(fd, FRDP_IPC_SESSION_REQUEST, sizeof(frdpSessionRequest)) != 0)
		goto cleanup;
	rc = receive_session_response(fd, 0, "unsupported IPC request");

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int test_sesmand_rejects_legacy_v2_missing_posix_account(const char* socket_path)
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
	if (send_header(fd, FRDP_IPC_SESSION_REQUEST_V2, sizeof(request)) != 0)
		goto cleanup;
	rc = receive_session_response(fd, 0, "unsupported IPC request");

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int test_sesmand_rejects_legacy_v2_posix_account_mismatch(const char* socket_path)
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
	if (send_header(fd, FRDP_IPC_SESSION_REQUEST_V2, sizeof(request)) != 0)
		goto cleanup;
	rc = receive_session_response(fd, 0, "unsupported IPC request");

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

static int test_sesmand_requires_authorization_for_explicit_reconnect(const char* socket_path)
{
	frdpSessionRequestV3 request = { 0 };
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	snprintf(request.correlation_id, sizeof(request.correlation_id),
	         "77777777-7777-4777-8777-777777777777");
	snprintf(request.session_id, sizeof(request.session_id),
	         "aaaaaaaa-7777-4777-8777-aaaaaaaaaaaa");
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

static int test_sesmand_handles_slow_complete_client(const char* socket_path)
{
	uint8_t payload[FRDP_IPC_SESSION_CLOSE_REQUEST_WIRE_SIZE] = { 0 };
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	if (send_header(fd, FRDP_IPC_SESSION_CLOSE_REQUEST, sizeof(payload)) != 0)
		goto cleanup;
	if (send_slow_payload(fd, payload, sizeof(payload), FRDP_IPC_SLOW_SEND_DELAY_US) != 0)
		goto cleanup;
	rc = receive_session_response(fd, 0, "unknown session");

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int test_sesmand_times_out_incomplete_client(const char* socket_path)
{
	uint8_t payload[FRDP_IPC_SESSION_CLOSE_REQUEST_WIRE_SIZE] = { 0 };
	frdpIpcHeader response = { 0 };
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	if (send_header(fd, FRDP_IPC_SESSION_CLOSE_REQUEST, sizeof(payload)) != 0)
		goto cleanup;
	if (frdp_ipc_recv_header(fd, &response) >= 0)
		goto cleanup;
	if (test_sesmand_list_empty(socket_path) != 0)
		goto cleanup;
	rc = 0;

cleanup:
	frdp_ipc_close(fd);
	return rc;
}

static int test_sesmand_survives_truncated_clients(const char* socket_path)
{
	uint8_t open_request[FRDP_IPC_SESSION_REQUEST_V3_WIRE_SIZE] = { 0 };
	uint8_t close_request[FRDP_IPC_SESSION_CLOSE_REQUEST_WIRE_SIZE] = { 0 };

	if (send_truncated_boundaries(socket_path, FRDP_IPC_SESSION_REQUEST_V3, open_request,
	                              sizeof(open_request)) != 0)
		return -1;
	if (send_truncated_boundaries(socket_path, FRDP_IPC_SESSION_CLOSE_REQUEST, close_request,
	                              sizeof(close_request)) != 0)
		return -1;
	if (send_truncated_boundaries(socket_path, FRDP_IPC_SESSION_LIST_REQUEST, NULL, 0) != 0)
		return -1;
	if (send_truncated_boundaries(socket_path, FRDP_IPC_SESSION_RELOAD_REQUEST, NULL, 0) != 0)
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

static int test_sesmand_rejects_reload_payload(const char* socket_path)
{
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if (fd < 0)
		return -1;
	if (send_header(fd, FRDP_IPC_SESSION_RELOAD_REQUEST, 1) != 0)
		goto cleanup;
	rc = receive_session_response(fd, 0, "unsupported IPC request");

cleanup:
	frdp_ipc_close(fd);
	if (rc != 0)
		return rc;
	return test_sesmand_list_empty(socket_path);
}

static int write_sesmand_config(const char* path, const char* pam_service, uint32_t max_processes,
                                uint32_t memory_max_mb)
{
	FILE* fp = NULL;

	if (!path || !pam_service)
		return -1;
	fp = fopen(path, "wb");
	if (!fp)
		return -1;
	if (fprintf(fp, "[auth]\npam_service = \"%s\"\n"
	                "[session]\nmax_processes = %" PRIu32 "\nmemory_max_mb = %" PRIu32 "\n",
	            pam_service, max_processes, memory_max_mb) < 0)
	{
		fclose(fp);
		return -1;
	}
	return fclose(fp);
}

static int write_sesmand_heartbeat_config(const char* path, const char* pam_service,
                                          uint32_t interval_ms, uint32_t timeout_ms,
                                          uint32_t failures)
{
	FILE* fp = NULL;

	if (!path || !pam_service)
		return -1;
	fp = fopen(path, "wb");
	if (!fp)
		return -1;
	if (fprintf(fp, "[auth]\npam_service = \"%s\"\n"
	                "[session]\nagent_heartbeat_interval_ms = %" PRIu32 "\n"
	                "agent_heartbeat_timeout_ms = %" PRIu32 "\n"
	                "agent_heartbeat_failures = %" PRIu32 "\n",
	            pam_service, interval_ms, timeout_ms, failures) < 0)
	{
		fclose(fp);
		return -1;
	}
	return fclose(fp);
}

static int write_sesmand_config_body(const char* path, const char* body)
{
	FILE* fp = NULL;

	if (!path || !body)
		return -1;
	fp = fopen(path, "wb");
	if (!fp)
		return -1;
	if (fputs(body, fp) < 0)
	{
		fclose(fp);
		return -1;
	}
	return fclose(fp);
}

static int request_live_session(const char* socket_path, const char* user, const char* rhost,
                                const char* correlation_id, const char* requested_session_id,
                                uint64_t uid, uint64_t gid, const uint64_t* groups,
                                uint32_t group_count, frdpSessionResponse* response)
{
	frdpSessionRequestV3 request = { 0 };
	char token[192] = { 0 };
	int fd = -1;
	int rc = -1;

	if (!socket_path || !user || !rhost || !correlation_id || !groups || (group_count == 0) ||
	    !response)
		return -1;
	if (frdp_auth_token_create(user, rhost, correlation_id, uid, gid, groups, group_count, 1, token,
	                           sizeof(token)) != 0)
		goto cleanup;
	if ((snprintf(request.correlation_id, sizeof(request.correlation_id), "%s", correlation_id) >=
	     (int)sizeof(request.correlation_id)) ||
	    (snprintf(request.user, sizeof(request.user), "%s", user) >= (int)sizeof(request.user)) ||
	    (snprintf(request.rhost, sizeof(request.rhost), "%s", rhost) >=
	     (int)sizeof(request.rhost)) ||
	    (snprintf(request.authorization_id, sizeof(request.authorization_id), "%s", token) >=
	     (int)sizeof(request.authorization_id)))
		goto cleanup;
	if (requested_session_id && (snprintf(request.session_id, sizeof(request.session_id), "%s",
	                                      requested_session_id) >= (int)sizeof(request.session_id)))
		goto cleanup;
	request.uid = uid;
	request.gid = gid;
	request.group_count = group_count;
	memcpy(request.groups, groups, group_count * sizeof(groups[0]));
	request.has_posix_account = 1;
	request.desktop_width = 800;
	request.desktop_height = 600;
	request.color_depth = 24;
	fd = frdp_ipc_connect(socket_path);
	if ((fd < 0) || (frdp_ipc_send_session_request_v3(fd, &request) != 0))
		goto cleanup;
	rc = receive_session_success(fd, response);

cleanup:
	if (fd >= 0)
		frdp_ipc_close(fd);
	SecureZeroMemory(&request, sizeof(request));
	SecureZeroMemory(token, sizeof(token));
	return rc;
}

static int request_session_control(const char* socket_path, frdpIpcMessageType type,
                                   const char* correlation_id, const char* session_id,
                                   const char* user, frdpSessionResponse* response)
{
	frdpSessionRequest request = { 0 };
	int fd = -1;
	int rc = -1;

	if (!socket_path || !correlation_id || !session_id || !user || !response)
		return -1;
	if ((snprintf(request.correlation_id, sizeof(request.correlation_id), "%s", correlation_id) >=
	     (int)sizeof(request.correlation_id)) ||
	    (snprintf(request.session_id, sizeof(request.session_id), "%s", session_id) >=
	     (int)sizeof(request.session_id)) ||
	    (snprintf(request.user, sizeof(request.user), "%s", user) >= (int)sizeof(request.user)))
		return -1;
	fd = frdp_ipc_connect(socket_path);
	if (fd < 0)
		goto cleanup;
	if (type == FRDP_IPC_SESSION_DISCONNECT_REQUEST)
		rc = frdp_ipc_send_session_disconnect_request(fd, &request);
	else if (type == FRDP_IPC_SESSION_CLOSE_REQUEST)
		rc = frdp_ipc_send_session_close_request(fd, &request);
	else
		goto cleanup;
	if (rc != 0)
		goto cleanup;
	rc = receive_session_success(fd, response);

cleanup:
	if (fd >= 0)
		frdp_ipc_close(fd);
	SecureZeroMemory(&request, sizeof(request));
	return rc;
}

static int list_single_session(const char* socket_path, const frdpSessionResponse* expected,
                               const char* user, const char* state, int32_t expected_agent_pid,
                               int32_t* agent_pid)
{
	frdpSessionListResponse list = { 0 };
	const frdpSessionListEntry* entry = &list.entries[0];

	if (!expected || !user || !state || (receive_sesmand_list(socket_path, &list) != 0) ||
	    (list.count != 1) || (strcmp(entry->session_id, expected->session_id) != 0) ||
	    (strcmp(entry->user, user) != 0) || (strcmp(entry->display, expected->display) != 0) ||
	    (strcmp(entry->state, state) != 0) || (entry->agent_pid <= 0) ||
	    ((expected_agent_pid > 0) && (entry->agent_pid != expected_agent_pid)))
		return -1;
	if (agent_pid)
		*agent_pid = entry->agent_pid;
	return 0;
}

static int test_sesmand_live_reconnect_lifecycle(void)
{
#ifndef FRDP_XVFB_EXECUTABLE
	printf("frdp-sesmand live reconnect lifecycle skipped: Xvfb unavailable\n");
	return 0;
#else
	static const char pam_service[] = "common-session-noninteractive";
	static const char rhost[] = "127.0.0.1";
	frdpTestHelper helper = { .pid = -1 };
	frdpSessionResponse opened = { 0 };
	frdpSessionResponse detached = { 0 };
	frdpSessionResponse reconnected = { 0 };
	frdpSessionResponse closed = { 0 };
	frdpSessionListResponse final_list = { 0 };
	char dir[1024] = { 0 };
	char config_path[1024] = { 0 };
	char key_path[1024] = { 0 };
	char user[64] = { 0 };
	uint64_t uid = 0;
	uint64_t gid = 0;
	uint64_t groups[FRDP_IPC_MAX_AUTH_GROUPS] = { 0 };
	uint32_t group_count = 0;
	int32_t agent_pid = -1;
	struct stat socket_st = { 0 };
	const char* previous_key_path = getenv(FRDP_AUTH_TOKEN_KEY_ENV);
	char* saved_key_path = previous_key_path ? strdup(previous_key_path) : NULL;
	char* saved_path = NULL;
	int helper_started = 0;
	int rc = -1;
	const char* stage = "prerequisites";

	if (previous_key_path && !saved_key_path)
		return -1;
	if ((access("/etc/pam.d/common-session-noninteractive", R_OK) != 0) ||
	    (access(FRDP_XVFB_EXECUTABLE, X_OK) != 0))
	{
		printf(
		    "frdp-sesmand live reconnect lifecycle skipped: PAM/Xvfb prerequisite unavailable\n");
		rc = 0;
		goto cleanup;
	}
	if (make_runtime_dir(dir, sizeof(dir), "frdp-sesmand-live-lifecycle") != 0)
		goto cleanup;
	if ((snprintf(config_path, sizeof(config_path), "%s/frdpd.toml", dir) >=
	     (int)sizeof(config_path)) ||
	    (snprintf(key_path, sizeof(key_path), "%s/auth-token.key", dir) >= (int)sizeof(key_path)))
		goto cleanup;
	stage = "environment";
	if ((setenv(FRDP_AUTH_TOKEN_KEY_ENV, key_path, 1) != 0) ||
	    (prepend_binary_dirs_to_path(FRDP_SESSION_AGENT_BINARY, FRDP_XVFB_EXECUTABLE,
	                                 &saved_path) != 0))
		goto cleanup;
	stage = "config";
	if (write_sesmand_config(config_path, pam_service, 0, 0) != 0)
		goto cleanup;
	stage = "identity";
	if (lookup_current_user(user, sizeof(user), &uid, &gid, groups, &group_count) != 0)
		goto cleanup;
	stage = "helper-start";
	if (start_helper_with_config(FRDP_SESMAND_BINARY, "frdp-sesmand-live-lifecycle", config_path,
	                             &helper) != 0)
		goto cleanup;
	helper_started = 1;
	restore_path(saved_path);
	saved_path = NULL;

	stage = "open";
	if (request_live_session(helper.socket_path, user, rhost, "live-open", NULL, uid, gid, groups,
	                         group_count, &opened) != 0 ||
	    (opened.session_id[0] == '\0') || (opened.display[0] == '\0') ||
	    (opened.agent_socket[0] == '\0') || (lstat(opened.agent_socket, &socket_st) != 0) ||
	    !S_ISSOCK(socket_st.st_mode))
		goto cleanup;
	stage = "list-active";
	if (list_single_session(helper.socket_path, &opened, user, "active", -1, &agent_pid) != 0)
		goto cleanup;
	stage = "detach";
	if (request_session_control(helper.socket_path, FRDP_IPC_SESSION_DISCONNECT_REQUEST,
	                            "live-detach", opened.session_id, user, &detached) != 0 ||
	    (strcmp(detached.session_id, opened.session_id) != 0) ||
	    (strcmp(detached.agent_socket, opened.agent_socket) != 0))
		goto cleanup;
	stage = "list-disconnected";
	if (list_single_session(helper.socket_path, &opened, user, "disconnected", agent_pid, NULL) !=
	    0)
		goto cleanup;
	stage = "implicit-reconnect";
	if (request_live_session(helper.socket_path, user, rhost, "live-reconnect", NULL, uid, gid,
	                         groups, group_count, &reconnected) != 0 ||
	    (strcmp(reconnected.session_id, opened.session_id) != 0) ||
	    (strcmp(reconnected.display, opened.display) != 0) ||
	    (strcmp(reconnected.agent_socket, opened.agent_socket) != 0))
		goto cleanup;
	stage = "list-reactivated";
	if (list_single_session(helper.socket_path, &opened, user, "active", agent_pid, NULL) != 0)
		goto cleanup;
	stage = "hard-close";
	if (request_session_control(helper.socket_path, FRDP_IPC_SESSION_CLOSE_REQUEST, "live-close",
	                            opened.session_id, user, &closed) != 0 ||
	    (strcmp(closed.session_id, opened.session_id) != 0))
		goto cleanup;
	stage = "cleanup";
	if ((receive_sesmand_list(helper.socket_path, &final_list) != 0) || (final_list.count != 0) ||
	    (lstat(opened.agent_socket, &socket_st) == 0) || (errno != ENOENT) ||
	    (kill((pid_t)agent_pid, 0) == 0) || (errno != ESRCH))
		goto cleanup;
	rc = 0;

cleanup:
	if (rc != 0)
		fprintf(stderr, "live reconnect lifecycle failed at stage: %s\n", stage);
	if (saved_path)
		restore_path(saved_path);
	if (helper_started && (stop_helper(&helper) != 0))
		rc = -1;
	if (saved_key_path)
	{
		(void)setenv(FRDP_AUTH_TOKEN_KEY_ENV, saved_key_path, 1);
		free(saved_key_path);
	}
	else
		unsetenv(FRDP_AUTH_TOKEN_KEY_ENV);
	unlink(key_path);
	unlink(config_path);
	if (dir[0] != '\0')
		rmdir(dir);
	SecureZeroMemory(&opened, sizeof(opened));
	SecureZeroMemory(&detached, sizeof(detached));
	SecureZeroMemory(&reconnected, sizeof(reconnected));
	SecureZeroMemory(&closed, sizeof(closed));
	return rc;
#endif
}

static int test_sesmand_crash_restart_reconciliation(void)
{
#ifndef FRDP_XVFB_EXECUTABLE
	printf("frdp-sesmand crash reconciliation skipped: Xvfb unavailable\n");
	return 0;
#else
	static const char pam_service[] = "common-session-noninteractive";
	static const char rhost[] = "127.0.0.1";
	frdpTestHelper helper = { .pid = -1 };
	frdpSessionResponse opened = { 0 };
	frdpSessionListResponse final_list = { 0 };
	char dir[1024] = { 0 };
	char config_path[1024] = { 0 };
	char key_path[1024] = { 0 };
	char metadata_name[96] = { 0 };
	char metadata_path[1024] = { 0 };
	char reservation_path[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	char user[64] = { 0 };
	uint64_t uid = 0;
	uint64_t gid = 0;
	uint64_t groups[FRDP_IPC_MAX_AUTH_GROUPS] = { 0 };
	uint32_t group_count = 0;
	int32_t agent_pid = -1;
	int display_number = 0;
	const char* previous_key_path = getenv(FRDP_AUTH_TOKEN_KEY_ENV);
	char* saved_key_path = previous_key_path ? strdup(previous_key_path) : NULL;
	char* saved_path = NULL;
	int helper_started = 0;
	int rc = -1;
	const char* stage = "prerequisites";

	if (previous_key_path && !saved_key_path)
		return -1;
	if ((access("/etc/pam.d/common-session-noninteractive", R_OK) != 0) ||
	    (access(FRDP_XVFB_EXECUTABLE, X_OK) != 0))
	{
		printf("frdp-sesmand crash reconciliation skipped: PAM/Xvfb prerequisite unavailable\n");
		rc = 0;
		goto cleanup;
	}
	if (make_runtime_dir(dir, sizeof(dir), "frdp-sesmand-crash-reconcile") != 0)
		goto cleanup;
	if ((snprintf(config_path, sizeof(config_path), "%s/frdpd.toml", dir) >=
	     (int)sizeof(config_path)) ||
	    (snprintf(key_path, sizeof(key_path), "%s/auth-token.key", dir) >= (int)sizeof(key_path)))
		goto cleanup;
	stage = "environment";
	if ((setenv(FRDP_AUTH_TOKEN_KEY_ENV, key_path, 1) != 0) ||
	    (prepend_binary_dirs_to_path(FRDP_SESSION_AGENT_BINARY, FRDP_XVFB_EXECUTABLE,
	                                 &saved_path) != 0))
		goto cleanup;
	stage = "config";
	if (write_sesmand_config(config_path, pam_service, 0, 0) != 0)
		goto cleanup;
	stage = "identity";
	if (lookup_current_user(user, sizeof(user), &uid, &gid, groups, &group_count) != 0)
		goto cleanup;
	stage = "helper-start";
	if (start_helper_with_config(FRDP_SESMAND_BINARY, "frdp-sesmand-crash-reconcile",
	                             config_path, &helper) != 0)
		goto cleanup;
	helper_started = 1;
	restore_path(saved_path);
	saved_path = NULL;
	stage = "open";
	if (request_live_session(helper.socket_path, user, rhost, "crash-open", NULL, uid, gid, groups,
	                         group_count, &opened) != 0 ||
	    list_single_session(helper.socket_path, &opened, user, "active", -1, &agent_pid) != 0)
		goto cleanup;
	if ((sscanf(opened.display, ":%d", &display_number) != 1) ||
	    (frdp_sesmand_session_metadata_filename(metadata_name, sizeof(metadata_name),
	                                             opened.session_id) != 0) ||
	    (snprintf(metadata_path, sizeof(metadata_path), "%s/%s", helper.dir, metadata_name) >=
	     (int)sizeof(metadata_path)) ||
	    (frdp_sesmand_display_reservation_path(reservation_path, sizeof(reservation_path),
	                                           helper.dir, display_number) != 0) ||
	    (access(metadata_path, F_OK) != 0) || (access(opened.agent_socket, F_OK) != 0) ||
	    (access(reservation_path, F_OK) != 0))
		goto cleanup;
	stage = "manager-sigkill";
	if ((kill(helper.pid, SIGKILL) != 0) || (waitpid(helper.pid, NULL, 0) != helper.pid))
		goto cleanup;
	helper.pid = -1;
	helper_started = 0;
	if (kill((pid_t)agent_pid, 0) != 0)
		goto cleanup;
	stage = "manager-restart";
	if (restart_helper_with_config(FRDP_SESMAND_BINARY, config_path, &helper) != 0)
		goto cleanup;
	helper_started = 1;
	stage = "reconciled-list";
	if ((receive_sesmand_list(helper.socket_path, &final_list) != 0) || (final_list.count != 0))
		goto cleanup;
	stage = "reconciled-artifacts";
	if ((wait_for_process_gone((pid_t)agent_pid) != 0) || (access(metadata_path, F_OK) == 0) ||
	    (errno != ENOENT) || (access(opened.agent_socket, F_OK) == 0) || (errno != ENOENT) ||
	    (access(reservation_path, F_OK) == 0) || (errno != ENOENT))
		goto cleanup;
	rc = 0;

cleanup:
	if (rc != 0)
		fprintf(stderr, "crash restart reconciliation failed at stage: %s\n", stage);
	if (saved_path)
		restore_path(saved_path);
	if (helper_started && (stop_helper(&helper) != 0))
		rc = -1;
	if ((agent_pid > 1) && (kill((pid_t)agent_pid, 0) == 0))
	{
		kill(-(pid_t)agent_pid, SIGKILL);
		(void)wait_for_process_gone((pid_t)agent_pid);
	}
	if (saved_key_path)
	{
		(void)setenv(FRDP_AUTH_TOKEN_KEY_ENV, saved_key_path, 1);
		free(saved_key_path);
	}
	else
		unsetenv(FRDP_AUTH_TOKEN_KEY_ENV);
	unlink(metadata_path);
	unlink(opened.agent_socket);
	unlink(reservation_path);
	unlink(helper.socket_path);
	if (helper.dir[0] != '\0')
		rmdir(helper.dir);
	unlink(key_path);
	unlink(config_path);
	if (dir[0] != '\0')
		rmdir(dir);
	SecureZeroMemory(&opened, sizeof(opened));
	return rc;
#endif
}

static int test_sesmand_agent_heartbeat_cleanup(void)
{
#ifndef FRDP_XVFB_EXECUTABLE
	printf("frdp-sesmand heartbeat cleanup skipped: Xvfb unavailable\n");
	return 0;
#else
	static const char pam_service[] = "common-session-noninteractive";
	static const char rhost[] = "127.0.0.1";
	frdpTestHelper helper = { .pid = -1 };
	frdpSessionResponse opened = { 0 };
	frdpSessionListResponse list = { 0 };
	char dir[1024] = { 0 };
	char config_path[1024] = { 0 };
	char key_path[1024] = { 0 };
	char metadata_name[96] = { 0 };
	char metadata_path[1024] = { 0 };
	char reservation_path[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	char user[64] = { 0 };
	uint64_t uid = 0;
	uint64_t gid = 0;
	uint64_t groups[FRDP_IPC_MAX_AUTH_GROUPS] = { 0 };
	uint32_t group_count = 0;
	int32_t agent_pid = -1;
	int agent_pidfd = -1;
	int blocked_fd = -1;
	int display_number = 0;
	const char* previous_key_path = getenv(FRDP_AUTH_TOKEN_KEY_ENV);
	char* saved_key_path = previous_key_path ? strdup(previous_key_path) : NULL;
	char* saved_path = NULL;
	int helper_started = 0;
	int rc = -1;
	const char* stage = "prerequisites";

	if (previous_key_path && !saved_key_path)
		return -1;
	if ((access("/etc/pam.d/common-session-noninteractive", R_OK) != 0) ||
	    (access(FRDP_XVFB_EXECUTABLE, X_OK) != 0))
	{
		printf("frdp-sesmand heartbeat cleanup skipped: PAM/Xvfb prerequisite unavailable\n");
		rc = 0;
		goto cleanup;
	}
	if (make_runtime_dir(dir, sizeof(dir), "frdp-sesmand-heartbeat") != 0)
		goto cleanup;
	if ((snprintf(config_path, sizeof(config_path), "%s/frdpd.toml", dir) >=
	     (int)sizeof(config_path)) ||
	    (snprintf(key_path, sizeof(key_path), "%s/auth-token.key", dir) >= (int)sizeof(key_path)))
		goto cleanup;
	stage = "environment";
	if ((setenv(FRDP_AUTH_TOKEN_KEY_ENV, key_path, 1) != 0) ||
	    (prepend_binary_dirs_to_path(FRDP_SESSION_AGENT_BINARY, FRDP_XVFB_EXECUTABLE,
	                                 &saved_path) != 0))
		goto cleanup;
	stage = "config";
	if (write_sesmand_heartbeat_config(config_path, pam_service, 1000, 500, 3) != 0)
		goto cleanup;
	stage = "identity";
	if (lookup_current_user(user, sizeof(user), &uid, &gid, groups, &group_count) != 0)
		goto cleanup;
	stage = "helper-start";
	if (start_helper_with_config(FRDP_SESMAND_BINARY, "frdp-sesmand-heartbeat", config_path,
	                             &helper) != 0)
		goto cleanup;
	helper_started = 1;
	restore_path(saved_path);
	saved_path = NULL;
	stage = "open";
	if (request_live_session(helper.socket_path, user, rhost, "heartbeat-open", NULL, uid, gid,
	                         groups, group_count, &opened) != 0 ||
	    list_single_session(helper.socket_path, &opened, user, "active", -1, &agent_pid) != 0)
		goto cleanup;
	agent_pidfd = open_process_pidfd((pid_t)agent_pid);
	if ((agent_pidfd < 0) && ((errno == ENOSYS) || (errno == ENOTSUP)))
	{
		printf("frdp-sesmand heartbeat cleanup skipped: pidfd unavailable\n");
		rc = 0;
		goto cleanup;
	}
	if (agent_pidfd < 0)
		goto cleanup;
	if ((sscanf(opened.display, ":%d", &display_number) != 1) ||
	    (frdp_sesmand_session_metadata_filename(metadata_name, sizeof(metadata_name),
	                                             opened.session_id) != 0) ||
	    (snprintf(metadata_path, sizeof(metadata_path), "%s/%s", helper.dir, metadata_name) >=
	     (int)sizeof(metadata_path)) ||
	    (frdp_sesmand_display_reservation_path(reservation_path, sizeof(reservation_path),
	                                           helper.dir, display_number) != 0) ||
	    (access(metadata_path, F_OK) != 0) || (access(opened.agent_socket, F_OK) != 0) ||
	    (access(reservation_path, F_OK) != 0))
		goto cleanup;
	stage = "control-contention";
	blocked_fd = frdp_ipc_connect(opened.agent_socket);
	if ((blocked_fd < 0) ||
	    (frdp_ipc_send_header(blocked_fd, FRDP_IPC_AGENT_FRAME_REQUEST,
	                          FRDP_IPC_AGENT_FRAME_REQUEST_WIRE_SIZE) != 0))
		goto cleanup;
	usleep(3000000);
	frdp_ipc_close(blocked_fd);
	blocked_fd = -1;
	if (list_single_session(helper.socket_path, &opened, user, "active", agent_pid, NULL) != 0)
		goto cleanup;
	stage = "agent-sigstop";
	if (signal_process_pidfd(agent_pidfd, SIGSTOP) != 0)
		goto cleanup;
	stage = "heartbeat-cleanup";
	for (int attempt = 0; attempt < 50; attempt++)
	{
		if ((receive_sesmand_list(helper.socket_path, &list) == 0) && (list.count == 0))
			break;
		usleep(100000);
	}
	if ((list.count != 0) || (wait_for_process_gone((pid_t)agent_pid) != 0) ||
	    (access(metadata_path, F_OK) == 0) || (errno != ENOENT) ||
	    (access(opened.agent_socket, F_OK) == 0) || (errno != ENOENT) ||
	    (access(reservation_path, F_OK) == 0) || (errno != ENOENT))
		goto cleanup;
	rc = 0;

cleanup:
	if (rc != 0)
		fprintf(stderr, "agent heartbeat cleanup failed at stage: %s\n", stage);
	if (saved_path)
		restore_path(saved_path);
	if (blocked_fd >= 0)
		frdp_ipc_close(blocked_fd);
	if (agent_pidfd >= 0)
		(void)signal_process_pidfd(agent_pidfd, SIGCONT);
	if (helper_started && (stop_helper(&helper) != 0))
		rc = -1;
	if (agent_pidfd >= 0)
	{
		(void)signal_process_pidfd(agent_pidfd, SIGKILL);
		close(agent_pidfd);
	}
	if (saved_key_path)
	{
		(void)setenv(FRDP_AUTH_TOKEN_KEY_ENV, saved_key_path, 1);
		free(saved_key_path);
	}
	else
		unsetenv(FRDP_AUTH_TOKEN_KEY_ENV);
	unlink(metadata_path);
	unlink(opened.agent_socket);
	unlink(reservation_path);
	unlink(key_path);
	unlink(config_path);
	if (dir[0] != '\0')
		rmdir(dir);
	SecureZeroMemory(&opened, sizeof(opened));
	return rc;
#endif
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
	if (write_sesmand_config(config_path, "frdpd", 0, 0) != 0)
		goto cleanup_dir;
	if (start_helper_with_config(FRDP_SESMAND_BINARY, "frdp-sesmand-reload", config_path,
	                             &helper) != 0)
		goto cleanup_dir;
	if (test_sesmand_reload(helper.socket_path, 1,
	                        "pam_service=frdpd;max_processes=0;memory_max_mb=0", NULL) != 0)
		goto cleanup;
	if (write_sesmand_config(config_path,
	                         "frdpd_reload_abcdefghijklmnopqrstuvwxyz_0123456789_ABCDEFGHIJKL",
	                         77, 1536) != 0)
		goto cleanup;
	if (test_sesmand_reload(helper.socket_path, 1,
	                        "pam_service=frdpd_reload_abcdefghijklmnopqrstuvwxyz_"
	                        "0123456789_ABCDEFGHIJKL;max_processes=77;memory_max_mb=1536",
	                        NULL) != 0)
		goto cleanup;
	if (write_sesmand_config(config_path, "bad/service", 1, 1) != 0)
		goto cleanup;
	if (test_sesmand_reload(helper.socket_path, 0, NULL, "config reload failed") != 0)
		goto cleanup;
	if (write_sesmand_config_body(config_path,
	                              "[auth]\npam_service = \"frdpd\"\n"
	                              "[clipboard]\nmode = \"text\"\n"
	                              "direction = \"bidirectional\"\n") != 0)
		goto cleanup;
	if (test_sesmand_reload(helper.socket_path, 0, NULL, "config reload failed") != 0)
		goto cleanup;
	if (write_sesmand_config_body(config_path,
	                              "[auth]\npam_service = \"frdpd\"\n"
	                              "ntlm_fallback = false\n"
	                              "kerberos = true\n"
	                              "keytab = \"/etc/frdpd/frdpd.keytab\"\n"
	                              "accepted_spn = \"TERMSRV/host.example.com\"\n") != 0)
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
	if (test_sesmand_rejects_unknown_disconnect_session(helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_rejects_unterminated_request(helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_rejects_legacy_v1_open_request(helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_rejects_legacy_v2_missing_posix_account(helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_rejects_legacy_v2_posix_account_mismatch(helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_rejects_missing_authorization(helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_requires_authorization_for_explicit_reconnect(helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_rejects_invalid_authorization(helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_rejects_bad_length(helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_rejects_oversized_payload(helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_survives_truncated_clients(helper.socket_path) != 0)
		goto cleanup;
	if (test_sesmand_handles_slow_complete_client(helper.socket_path) != 0)
		goto cleanup;
	if (run_concurrent_requests(helper.socket_path, test_sesmand_list_empty,
	                            FRDP_IPC_CONCURRENT_CLIENTS) != 0)
		goto cleanup;
	if (test_sesmand_rejects_reload_payload(helper.socket_path) != 0)
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
	int limited = 0;

	if (start_helper(FRDP_SESMAND_BINARY, "frdp-sesmand-rate-limit", &helper) != 0)
		return -1;
	for (uint32_t x = 0; x < FRDP_IPC_RATE_LIMIT_MAX_REQUESTS + 2U; x++)
	{
		if (test_sesmand_list_empty_or_rate_limited(helper.socket_path, &limited) != 0)
			goto cleanup;
		if (limited)
		{
			rc = 0;
			goto cleanup;
		}
	}

cleanup:
	if (stop_helper(&helper) != 0)
		rc = -1;
	return rc;
}

static int test_sesmand_slowloris_timeout(void)
{
	frdpTestHelper helper;
	const char* previous = getenv("FRDP_HELPER_IPC_TIMEOUT_MS");
	char* saved = previous ? strdup(previous) : NULL;
	int rc = -1;

	if (previous && !saved)
		return -1;
	memset(&helper, 0, sizeof(helper));
	helper.pid = -1;
	if (setenv("FRDP_HELPER_IPC_TIMEOUT_MS", FRDP_TEST_HELPER_TIMEOUT_MS, 1) != 0)
		goto cleanup_env;
	if (start_helper(FRDP_SESMAND_BINARY, "frdp-sesmand-slowloris", &helper) != 0)
		goto cleanup_env;
	rc = test_sesmand_times_out_incomplete_client(helper.socket_path);
	if (stop_helper(&helper) != 0)
		rc = -1;

cleanup_env:
	if (saved)
	{
		setenv("FRDP_HELPER_IPC_TIMEOUT_MS", saved, 1);
		free(saved);
	}
	else
		unsetenv("FRDP_HELPER_IPC_TIMEOUT_MS");
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
	if (test_authd_slowloris_timeout() != 0)
	{
		printf("frdp-authd slowloris timeout test failed\n");
		return -1;
	}
	if (test_sesmand_slowloris_timeout() != 0)
	{
		printf("frdp-sesmand slowloris timeout test failed\n");
		return -1;
	}
	if (test_sesmand_rejects_posix_groups_mismatch() != 0)
	{
		printf("frdp-sesmand POSIX groups mismatch test failed\n");
		return -1;
	}
	if (test_sesmand_live_reconnect_lifecycle() != 0)
	{
		printf("frdp-sesmand live reconnect lifecycle test failed\n");
		return -1;
	}
	if (test_sesmand_crash_restart_reconciliation() != 0)
	{
		printf("frdp-sesmand crash restart reconciliation test failed\n");
		return -1;
	}
	if (test_sesmand_agent_heartbeat_cleanup() != 0)
	{
		printf("frdp-sesmand agent heartbeat cleanup test failed\n");
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

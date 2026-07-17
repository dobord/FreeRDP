#define _GNU_SOURCE

#include "ipc/frdp-auth-token.h"
#include "ipc/frdp-ipc.h"
#include "frdp-authd/auth_failure_limit.h"
#include "frdp-sesmand/display_policy.h"
#include "frdp-sesmand/process_identity.h"
#include "frdp-sesmand/session_metadata.h"
#include "frdp-sesmand/session_pam_owner.h"

#include <errno.h>
#include <dirent.h>
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
#include <time.h>
#include <unistd.h>

#include <systemd/sd-bus.h>
#include <winpr/crt.h>

#ifndef FRDPD_BINARY
#error "FRDPD_BINARY is not defined"
#endif
#ifndef FRDP_AUTHD_BINARY
#error "FRDP_AUTHD_BINARY is not defined"
#endif
#ifndef FRDP_AUTHD_TEST_DENY_BINARY
#error "FRDP_AUTHD_TEST_DENY_BINARY is not defined"
#endif
#ifndef FRDP_SESMAND_BINARY
#error "FRDP_SESMAND_BINARY is not defined"
#endif
#ifndef FRDP_SESSION_AGENT_BLOCKING_BINARY
#error "FRDP_SESSION_AGENT_BLOCKING_BINARY is not defined"
#endif

#define FRDP_IPC_SLOW_SEND_DELAY_US 1000U
#define FRDP_IPC_CONCURRENT_CLIENTS 8U
#define FRDP_TEST_HELPER_TIMEOUT_MS "200"
#define FRDP_TEST_SKIP 77

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
		int fd = -1;

		if (lstat(path, &st) == 0)
		{
			if (!S_ISSOCK(st.st_mode) || ((st.st_mode & 0777) != 0600))
				return -1;
			fd = frdp_ipc_connect(path);
			if (fd >= 0)
			{
				frdp_ipc_close(fd);
				return 0;
			}
			if ((errno != ECONNREFUSED) && (errno != ENOENT))
				return -1;
		}
		else if (errno != ENOENT)
			return -1;
		usleep(100000);
	}
	return -1;
}

static int wait_for_exit_attempts(pid_t pid, int* status, int attempts)
{
	for (int attempt = 0; attempt < attempts; attempt++)
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

static int wait_for_exit(pid_t pid, int* status)
{
	return wait_for_exit_attempts(pid, status, 50);
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

static int restart_helper_internal(const char* binary, const char* config_path,
                                   frdpTestHelper* helper)
{
	struct stat previous = { 0 };

	if (!binary || !helper || (helper->pid > 0) ||
	    (lstat(helper->socket_path, &previous) != 0))
		return -1;
	helper->pid = fork();
	if (helper->pid < 0)
		return -1;
	if (helper->pid == 0)
	{
		if (config_path)
			execl(binary, binary, "--config", config_path, "--socket", helper->socket_path,
			      (char*)NULL);
		else
			execl(binary, binary, "--socket", helper->socket_path, (char*)NULL);
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

static int restart_helper_with_config(const char* binary, const char* config_path,
                                      frdpTestHelper* helper)
{
	if (!config_path)
		return -1;
	return restart_helper_internal(binary, config_path, helper);
}

static int restart_helper(const char* binary, frdpTestHelper* helper)
{
	return restart_helper_internal(binary, NULL, helper);
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

static int wait_for_process_group_gone(pid_t pgid)
{
	if (pgid <= 1)
		return -1;
	for (int attempt = 0; attempt < 50; attempt++)
	{
		if ((kill(-pgid, 0) != 0) && (errno == ESRCH))
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

static int pidfd_runtime_supported(void)
{
	const int pidfd = open_process_pidfd(getpid());
	int rc = -1;

	if (pidfd < 0)
		return 0;
	rc = signal_process_pidfd(pidfd, 0);
	close(pidfd);
	return rc == 0;
}

static int read_single_child_pid(pid_t parent_pid, pid_t* child_pid)
{
#if defined(__linux__)
	char path[128] = { 0 };
	FILE* fp = NULL;
	long child = 0;
	char trailing = '\0';
	int rc = -1;

	if ((parent_pid <= 1) || !child_pid ||
	    (snprintf(path, sizeof(path), "/proc/%ld/task/%ld/children", (long)parent_pid,
	              (long)parent_pid) >= (int)sizeof(path)))
		return -1;
	fp = fopen(path, "r");
	if (!fp)
		return -1;
	if ((fscanf(fp, "%ld", &child) == 1) && (child > 1) && (child <= INT32_MAX) &&
	    (fscanf(fp, " %c", &trailing) != 1))
	{
		*child_pid = (pid_t)child;
		rc = 0;
	}
	fclose(fp);
	return rc;
#else
	(void)parent_pid;
	(void)child_pid;
	return -1;
#endif
}

static int pin_process_identity(pid_t pid, uid_t expected_uid, pid_t expected_pgid, int* pidfd,
	                            unsigned long long* start_ticks)
{
	unsigned long long before_ticks = 0;
	unsigned long long after_ticks = 0;
	uid_t before_uid = (uid_t)-1;
	uid_t after_uid = (uid_t)-1;
	pid_t before_pgid = -1;
	pid_t after_pgid = -1;
	int fd = -1;

	if ((pid <= 1) || (expected_pgid <= 1) || !pidfd || !start_ticks ||
	    (frdp_sesmand_process_identity_read(pid, &before_ticks, &before_uid) !=
	     FRDP_SESMAND_PROCESS_IDENTITY_OK) ||
	    ((before_pgid = getpgid(pid)) != expected_pgid) || (before_uid != expected_uid))
		return -1;
	fd = open_process_pidfd(pid);
	if (fd < 0)
		return -1;
	if ((frdp_sesmand_process_identity_read(pid, &after_ticks, &after_uid) !=
	     FRDP_SESMAND_PROCESS_IDENTITY_OK) ||
	    ((after_pgid = getpgid(pid)) != expected_pgid) || (after_uid != expected_uid) ||
	    (after_ticks != before_ticks))
	{
		close(fd);
		return -1;
	}
	*pidfd = fd;
	*start_ticks = after_ticks;
	return 0;
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

	if (frdp_ipc_recv_auth_response_v2(fd, &response) != 0)
		return -1;
	if (response.success != 0)
		return -1;
	if (!memchr(response.error, '\0', sizeof(response.error)))
		return -1;
	if (expected_error && strcmp(response.error, expected_error) != 0)
		return -1;
	return 0;
}

static int test_helper_health(const char* socket_path, const char* expected_role)
{
	frdpControlResponse response = { 0 };
	int fd = frdp_ipc_connect(socket_path);
	int rc = -1;

	if ((fd < 0) || !expected_role)
		goto cleanup;
	if ((frdp_ipc_send_helper_health_request(fd) != 0) ||
	    (frdp_ipc_recv_helper_health_response(fd, &response) != 0) || !response.success ||
	    !memchr(response.message, '\0', sizeof(response.message)) ||
	    !memchr(response.error, '\0', sizeof(response.error)) || (response.error[0] != '\0') ||
	    (strcmp(response.message, expected_role) != 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (fd >= 0)
		frdp_ipc_close(fd);
	SecureZeroMemory(&response, sizeof(response));
	return rc;
}

static int test_helper_health_rate_limit(const char* socket_path, const char* expected_role)
{
	int limited = 0;

	for (uint32_t x = 0; x < FRDP_IPC_RATE_LIMIT_MAX_REQUESTS + 2U; x++)
	{
		frdpControlResponse response = { 0 };
		int fd = frdp_ipc_connect(socket_path);

		if (fd < 0)
			return -1;
		if ((frdp_ipc_send_helper_health_request(fd) != 0) ||
		    (frdp_ipc_recv_helper_health_response(fd, &response) != 0))
		{
			frdp_ipc_close(fd);
			return -1;
		}
		frdp_ipc_close(fd);
		if (!response.success)
		{
			if (strcmp(response.error, "IPC health rate limit exceeded") != 0)
				return -1;
			limited = 1;
			break;
		}
		if (strcmp(response.message, expected_role) != 0)
			return -1;
	}
	return limited ? 0 : -1;
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

static int lookup_user(const char* requested_user, char* user, size_t user_size, uint64_t* uid,
                       uint64_t* gid, uint64_t* groups, uint32_t* group_count)
{
	gid_t native_groups[FRDP_IPC_MAX_AUTH_GROUPS] = { 0 };
	int native_group_count = (int)FRDP_IPC_MAX_AUTH_GROUPS;
	struct passwd* pwd = NULL;

	if (!user || !uid || !gid || !groups || !group_count)
		return -1;
	pwd = requested_user ? getpwnam(requested_user) : getpwuid(geteuid());
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

static int lookup_current_user(char* user, size_t user_size, uint64_t* uid, uint64_t* gid,
                               uint64_t* groups, uint32_t* group_count)
{
	return lookup_user(NULL, user, user_size, uid, gid, groups, group_count);
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
	if (frdp_ipc_recv_auth_response_v2(fd, &response) != 0)
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
	const char* stage = "start";

	if (start_helper(FRDP_AUTHD_BINARY, "frdp-authd-component", &helper) != 0)
		return -1;
	stage = "health";
	if (test_helper_health(helper.socket_path, "frdp-authd") != 0)
		goto cleanup;
	stage = "bad-length";
	if (test_authd_rejects_bad_length(helper.socket_path) != 0)
		goto cleanup;
	stage = "unknown-type";
	if (test_authd_rejects_unknown_type(helper.socket_path) != 0)
		goto cleanup;
	stage = "oversized";
	if (test_authd_rejects_oversized_payload(helper.socket_path) != 0)
		goto cleanup;
	stage = "unterminated";
	if (test_authd_rejects_unterminated_request(helper.socket_path) != 0)
		goto cleanup;
	stage = "truncated";
	if (test_authd_survives_truncated_clients(helper.socket_path) != 0)
		goto cleanup;
	stage = "slow-complete";
	if (test_authd_handles_slow_complete_client(helper.socket_path) != 0)
		goto cleanup;
	stage = "concurrent";
	if (run_concurrent_requests(helper.socket_path, test_authd_rejects_bad_length,
	                            FRDP_IPC_CONCURRENT_CLIENTS) != 0)
		goto cleanup;
	/* A final request proves that malformed clients did not stop the service loop. */
	stage = "final-request";
	if (test_authd_rejects_bad_length(helper.socket_path) != 0)
		goto cleanup;
	stage = "health-limit";
	if ((test_helper_health_rate_limit(helper.socket_path, "frdp-authd") != 0) ||
	    (test_authd_rejects_bad_length(helper.socket_path) != 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (rc != 0)
		fprintf(stderr, "authd component test failed at stage: %s\n", stage);
	if (stop_helper(&helper) != 0)
		rc = -1;
	return rc;
}

static int test_authd_crash_restart_health(void)
{
	frdpTestHelper helper = { .pid = -1 };
	int started = 0;
	int rc = -1;

	if (start_helper(FRDP_AUTHD_BINARY, "frdp-authd-crash-restart", &helper) != 0)
		return -1;
	started = 1;
	if (test_helper_health(helper.socket_path, "frdp-authd") != 0)
		goto cleanup;
	if ((kill(helper.pid, SIGKILL) != 0) || (waitpid(helper.pid, NULL, 0) != helper.pid))
		goto cleanup;
	helper.pid = -1;
	started = 0;
	if (test_helper_health(helper.socket_path, "frdp-authd") == 0)
		goto cleanup;
	if (restart_helper(FRDP_AUTHD_BINARY, &helper) != 0)
		goto cleanup;
	started = 1;
	if ((test_helper_health(helper.socket_path, "frdp-authd") != 0) ||
	    (test_authd_rejects_bad_length(helper.socket_path) != 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (started && (stop_helper(&helper) != 0))
		rc = -1;
	else if (!started)
	{
		unlink(helper.socket_path);
		rmdir(helper.dir);
	}
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

static int send_authd_failed_login(const char* socket_path, const char* user, const char* rhost,
                                   int expect_limited)
{
	frdpAuthRequest request = { 0 };
	frdpAuthResponse response = { 0 };
	int fd = -1;
	int rc = -1;

	if (!socket_path || !user || !rhost)
		return -1;
	fd = frdp_ipc_connect(socket_path);
	if (fd < 0)
		return -1;
	snprintf(request.correlation_id, sizeof(request.correlation_id), "%s",
	         "22222222-2222-4222-8222-222222222222");
	if ((snprintf(request.user, sizeof(request.user), "%s", user) >=
	     (int)sizeof(request.user)) ||
	    (snprintf(request.rhost, sizeof(request.rhost), "%s", rhost) >=
	     (int)sizeof(request.rhost)))
		goto cleanup;
	snprintf(request.password, sizeof(request.password), "%s", "invalid-password");
	if ((frdp_ipc_send_auth_request_v2(fd, &request) != 0) ||
	    (frdp_ipc_recv_auth_response_v2(fd, &response) != 0) || response.success ||
	    !memchr(response.error, '\0', sizeof(response.error)))
		goto cleanup;
	if (expect_limited)
		rc = strcmp(response.error, "authentication temporarily unavailable") == 0 ? 0 : -1;
	else
		rc = response.error[0] == '\0' ? 0 : -1;

cleanup:
	SecureZeroMemory(&request, sizeof(request));
	SecureZeroMemory(&response, sizeof(response));
	frdp_ipc_close(fd);
	return rc;
}

#if defined(FRDP_PAM_WRAPPER_LIBRARY) && defined(FRDP_PAM_WRAPPER_MODULE_DIR)
static int file_contents_equal(const char* path, const char* expected);
static int wait_for_file_contents(const char* path, const char* expected);

static int write_pam_fixture_file(const char* path, const char* contents)
{
	FILE* fp = NULL;
	int write_rc = -1;

	if (!path || !contents)
		return -1;
	fp = fopen(path, "wx");
	if (!fp)
		return -1;
	write_rc = fputs(contents, fp);
	if (fclose(fp) != 0)
		write_rc = -1;
	if (write_rc >= 0)
		return 0;
	unlink(path);
	return -1;
}

static int copy_test_executable(const char* source, const char* destination)
{
	char buffer[16384] = { 0 };
	int source_fd = -1;
	int destination_fd = -1;
	int rc = -1;

	if (!source || !destination)
		return -1;
	source_fd = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (source_fd < 0)
		goto cleanup;
	destination_fd = open(destination, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0755);
	if (destination_fd < 0)
		goto cleanup;
	for (;;)
	{
		ssize_t count = read(source_fd, buffer, sizeof(buffer));

		if (count == 0)
			break;
		if (count < 0)
		{
			if (errno == EINTR)
				continue;
			goto cleanup;
		}
		for (ssize_t offset = 0; offset < count;)
		{
			const ssize_t written =
			    write(destination_fd, &buffer[offset], (size_t)(count - offset));

			if (written < 0)
			{
				if (errno == EINTR)
					continue;
				goto cleanup;
			}
			offset += written;
		}
	}
	if (fsync(destination_fd) != 0)
		goto cleanup;
	rc = 0;

cleanup:
	if (destination_fd >= 0)
		close(destination_fd);
	if (source_fd >= 0)
		close(source_fd);
	if (rc != 0)
		unlink(destination);
	return rc;
}

static int start_helper_with_pam_wrapper_config(const char* binary, const char* name,
                                                const char* service_dir, const char* service,
                                                const char* config_path, const char* key_path,
                                                const char* pam_user, const char* audit_path,
                                                int block_auth, frdpTestHelper* helper)
{
	if (!binary || !name || !service_dir || !service || !key_path || !helper)
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
		if ((setenv("LD_PRELOAD", FRDP_PAM_WRAPPER_LIBRARY, 1) != 0) ||
		    (setenv("PAM_WRAPPER", "1", 1) != 0) ||
		    (setenv("PAM_WRAPPER_SERVICE_DIR", service_dir, 1) != 0) ||
		    (setenv(FRDP_AUTH_TOKEN_KEY_ENV, key_path, 1) != 0) ||
		    (pam_user && (setenv("PAM_USER", pam_user, 1) != 0)) ||
		    (audit_path && (setenv("FRDP_PAM_TEST_AUDIT_FILE", audit_path, 1) != 0)) ||
		    (block_auth && (setenv("FRDP_PAM_TEST_BLOCK_AUTH", "1", 1) != 0)))
			_exit(127);
		if (config_path)
			execl(binary, binary, "--config", config_path, "--socket", helper->socket_path,
			      (char*)NULL);
		else
			execl(binary, binary, "--pam-service", service, "--socket", helper->socket_path,
			      (char*)NULL);
		_exit(127);
	}
	if (wait_for_socket(helper->socket_path) != 0)
		goto fail;
	return 0;

fail:
	if (helper->pid > 0)
	{
		kill(helper->pid, SIGKILL);
		(void)waitpid(helper->pid, NULL, 0);
	}
	unlink(helper->socket_path);
	rmdir(helper->dir);
	memset(helper, 0, sizeof(*helper));
	helper->pid = -1;
	return -1;
}

static int start_helper_with_pam_wrapper(const char* binary, const char* name,
                                         const char* service_dir, const char* service,
                                         const char* key_path, const char* pam_user,
                                         const char* audit_path, int block_auth,
                                         frdpTestHelper* helper)
{
	return start_helper_with_pam_wrapper_config(binary, name, service_dir, service, NULL, key_path,
	                                            pam_user, audit_path, block_auth, helper);
}

static int exchange_authd_login_from(const char* socket_path, const char* user,
	                                 const char* password, const char* rhost,
	                                 frdpAuthResponse* response)
{
	frdpAuthRequest request = { 0 };
	int fd = -1;
	int rc = -1;

	if (!socket_path || !user || !password || !rhost || !response)
		return -1;
	fd = frdp_ipc_connect(socket_path);
	if (fd < 0)
		return -1;
	if ((snprintf(request.correlation_id, sizeof(request.correlation_id), "%s",
	              "33333333-3333-4333-8333-333333333333") >=
	     (int)sizeof(request.correlation_id)) ||
	    (snprintf(request.user, sizeof(request.user), "%s", user) >=
	     (int)sizeof(request.user)) ||
	    (snprintf(request.rhost, sizeof(request.rhost), "%s", rhost) >=
	     (int)sizeof(request.rhost)) ||
	    (snprintf(request.password, sizeof(request.password), "%s", password) >=
	     (int)sizeof(request.password)))
		goto cleanup;
	if ((frdp_ipc_send_auth_request_v2(fd, &request) != 0) ||
	    (frdp_ipc_recv_auth_response_v2(fd, response) != 0))
		goto cleanup;
	rc = 0;

cleanup:
	SecureZeroMemory(&request, sizeof(request));
	frdp_ipc_close(fd);
	return rc;
}

static int exchange_authd_login(const char* socket_path, const char* user, const char* password,
	                            frdpAuthResponse* response)
{
	return exchange_authd_login_from(socket_path, user, password, "203.0.113.30", response);
}

static int run_pam_wrapper_auth_case(const char* name, const char* service_dir,
	                                 const char* service, const char* canonical_user,
	                                 const char* key_path, frdpAuthResponse* response)
{
	frdpTestHelper helper = { .pid = -1 };
	int rc = -1;

	if (start_helper_with_pam_wrapper(FRDP_AUTHD_BINARY, name, service_dir, service, key_path,
	                                  canonical_user, NULL, 0, &helper) != 0)
		return -1;
	if (exchange_authd_login(helper.socket_path, "frdp-pam-alias", "test-password", response) ==
	    0)
		rc = 0;
	if (stop_helper(&helper) != 0)
		rc = -1;
	return rc;
}

static int run_pam_wrapper_error_limit_case(const char* service_dir, const char* service,
	                                        const char* canonical_user, const char* key_path)
{
	frdpTestHelper helper = { .pid = -1 };
	frdpAuthResponse response = { 0 };
	int rc = -1;

	if (start_helper_with_pam_wrapper(FRDP_AUTHD_BINARY, "pam-error", service_dir, service,
	                                  key_path, canonical_user, NULL, 0, &helper) != 0)
		return -1;
	for (uint32_t x = 0; x <= FRDP_AUTH_FAILURE_LIMIT_DEFAULT_MAX_FAILURES; x++)
	{
		SecureZeroMemory(&response, sizeof(response));
		if ((exchange_authd_login(helper.socket_path, "frdp-pam-alias", "test-password",
		                          &response) != 0) ||
		    response.success || (strcmp(response.error, "authentication service error") != 0))
			goto cleanup;
	}
	rc = 0;

cleanup:
	SecureZeroMemory(&response, sizeof(response));
	if (stop_helper(&helper) != 0)
		rc = -1;
	return rc;
}

static int test_authd_pam_canonical_alias_failure_limit(const char* canonical_user,
	                                                    const char* key_path)
{
	static const char service[] = "frdp-pam-canonical-deny";
	static const char expected_audit[] =
	    "authenticate-start\nauthenticate-start\nauthenticate-start\nauthenticate-start\n"
	    "authenticate-start\nauthenticate-start\nauthenticate-start\nauthenticate-start\n"
	    "authenticate-start\nauthenticate-start\nauthenticate-start\naccount\n"
	    "setcred-establish\nsetcred-delete\nauthenticate-start\n";
	frdpTestHelper helper = { .pid = -1 };
	frdpAuthResponse response = { 0 };
	char dir[1024] = { 0 };
	char service_path[1024] = { 0 };
	char audit_path[1024] = { 0 };
	char contents[2048] = { 0 };
	char rhost[64] = { 0 };
	int rc = -1;

	if (!canonical_user || !canonical_user[0] || !key_path ||
	    (make_runtime_dir(dir, sizeof(dir), "pam-canonical-limit") != 0))
		return -1;
	if ((snprintf(service_path, sizeof(service_path), "%s/%s", dir, service) >=
	     (int)sizeof(service_path)) ||
	    (snprintf(audit_path, sizeof(audit_path), "%s/audit.log", dir) >=
	     (int)sizeof(audit_path)) ||
	    (snprintf(contents, sizeof(contents), "auth required %s\naccount required %s\n",
	              FRDP_PAM_AUTH_CANONICAL_DENY_TEST_MODULE,
	              FRDP_PAM_AUTH_CANONICAL_DENY_TEST_MODULE) >= (int)sizeof(contents)) ||
	    (write_pam_fixture_file(service_path, contents) != 0) ||
	    (write_pam_fixture_file(audit_path, "") != 0) ||
	    (start_helper_with_pam_wrapper(FRDP_AUTHD_BINARY, "pam-canonical-limit", dir, service,
	                                   key_path, canonical_user, audit_path, 0, &helper) != 0))
		goto cleanup;

	for (uint32_t x = 0; x < FRDP_AUTH_FAILURE_LIMIT_DEFAULT_MAX_FAILURES; x++)
	{
		const char* alias = (x % 2U) == 0 ? "canonical-alias-one" : "canonical-alias-two";

		if ((snprintf(rhost, sizeof(rhost), "203.0.113.%" PRIu32, x + 1U) >=
		     (int)sizeof(rhost)) ||
		    (exchange_authd_login_from(helper.socket_path, alias, "test-password", rhost,
		                               &response) != 0) ||
		    response.success || response.error[0])
			goto cleanup;
		SecureZeroMemory(&response, sizeof(response));
	}
	if ((exchange_authd_login_from(helper.socket_path, "canonical-alias-one", "test-password",
	                              "203.0.113.11", &response) != 0) ||
	    response.success ||
	    (strcmp(response.error, "authentication temporarily unavailable") != 0) ||
	    (wait_for_file_contents(audit_path,
	                            "authenticate-start\nauthenticate-start\nauthenticate-start\n"
	                            "authenticate-start\nauthenticate-start\nauthenticate-start\n"
	                            "authenticate-start\nauthenticate-start\nauthenticate-start\n"
	                            "authenticate-start\n") != 0))
		goto cleanup;
	SecureZeroMemory(&response, sizeof(response));
	if ((exchange_authd_login_from(helper.socket_path, "canonical-success-alias",
	                              "test-password", "203.0.113.12", &response) != 0) ||
	    !response.success || (strcmp(response.user, canonical_user) != 0))
		goto cleanup;
	SecureZeroMemory(&response, sizeof(response));
	if ((exchange_authd_login_from(helper.socket_path, "canonical-alias-one", "test-password",
	                              "203.0.113.13", &response) != 0) ||
	    response.success || response.error[0] ||
	    (wait_for_file_contents(audit_path, expected_audit) != 0))
		goto cleanup;
	rc = 0;

cleanup:
	SecureZeroMemory(&response, sizeof(response));
	if ((helper.pid > 0) && (stop_helper(&helper) != 0))
		rc = -1;
	unlink(audit_path);
	unlink(service_path);
	if (dir[0])
		rmdir(dir);
	return rc;
}

static int test_authd_real_pam_provider(void)
{
	static const char success_service[] = "frdp-pam-success";
	static const char denied_service[] = "frdp-pam-denied";
	static const char error_service[] = "frdp-pam-error";
	frdpAuthResponse response = { 0 };
	struct passwd* pwd = getpwuid(geteuid());
	char dir[1024] = { 0 };
	char success_path[1024] = { 0 };
	char denied_path[1024] = { 0 };
	char error_path[1024] = { 0 };
	char passdb_path[1024] = { 0 };
	char denied_passdb_path[1024] = { 0 };
	char missing_passdb_path[1024] = { 0 };
	char key_path[1024] = { 0 };
	char contents[4096] = { 0 };
	int rc = -1;

	if (!pwd || !pwd->pw_name || !pwd->pw_name[0] ||
	    (make_runtime_dir(dir, sizeof(dir), "pam-provider") != 0))
		return -1;
	if ((snprintf(success_path, sizeof(success_path), "%s/%s", dir, success_service) >=
	     (int)sizeof(success_path)) ||
	    (snprintf(denied_path, sizeof(denied_path), "%s/%s", dir, denied_service) >=
	     (int)sizeof(denied_path)) ||
	    (snprintf(error_path, sizeof(error_path), "%s/%s", dir, error_service) >=
	     (int)sizeof(error_path)) ||
	    (snprintf(passdb_path, sizeof(passdb_path), "%s/success.passdb", dir) >=
	     (int)sizeof(passdb_path)) ||
	    (snprintf(denied_passdb_path, sizeof(denied_passdb_path), "%s/denied.passdb", dir) >=
	     (int)sizeof(denied_passdb_path)) ||
	    (snprintf(missing_passdb_path, sizeof(missing_passdb_path), "%s/missing.passdb", dir) >=
	     (int)sizeof(missing_passdb_path)) ||
	    (snprintf(key_path, sizeof(key_path), "%s/auth-token.key", dir) >=
	     (int)sizeof(key_path)))
		goto cleanup;

	if ((snprintf(contents, sizeof(contents), "%s:test-password:%s\n", pwd->pw_name,
	              success_service) >= (int)sizeof(contents)) ||
	    (write_pam_fixture_file(passdb_path, contents) != 0) ||
	    (snprintf(contents, sizeof(contents), "%s:test-password:some-other-service\n",
	              pwd->pw_name) >= (int)sizeof(contents)) ||
	    (write_pam_fixture_file(denied_passdb_path, contents) != 0))
		goto cleanup;

	if ((snprintf(contents, sizeof(contents),
	              "auth required %s/pam_set_items.so\n"
	              "auth required %s/pam_matrix.so passdb=%s\n"
	              "account required %s/pam_matrix.so passdb=%s\n",
	              FRDP_PAM_WRAPPER_MODULE_DIR, FRDP_PAM_WRAPPER_MODULE_DIR, passdb_path,
	              FRDP_PAM_WRAPPER_MODULE_DIR, passdb_path) >= (int)sizeof(contents)) ||
	    (write_pam_fixture_file(success_path, contents) != 0) ||
	    (snprintf(contents, sizeof(contents),
	              "auth required %s/pam_set_items.so\n"
	              "auth required %s/pam_matrix.so passdb=%s\n"
	              "account required %s/pam_matrix.so passdb=%s\n",
	              FRDP_PAM_WRAPPER_MODULE_DIR, FRDP_PAM_WRAPPER_MODULE_DIR, denied_passdb_path,
	              FRDP_PAM_WRAPPER_MODULE_DIR, denied_passdb_path) >= (int)sizeof(contents)) ||
	    (write_pam_fixture_file(denied_path, contents) != 0) ||
	    (snprintf(contents, sizeof(contents), "auth required %s/pam_matrix.so passdb=%s\n",
	              FRDP_PAM_WRAPPER_MODULE_DIR, missing_passdb_path) >= (int)sizeof(contents)) ||
	    (write_pam_fixture_file(error_path, contents) != 0))
		goto cleanup;

	if ((run_pam_wrapper_auth_case("pam-success", dir, success_service, pwd->pw_name, key_path,
	                               &response) != 0) ||
	    !response.success || (strcmp(response.user, pwd->pw_name) != 0) ||
	    (response.uid != (uint64_t)pwd->pw_uid) || (response.gid != (uint64_t)pwd->pw_gid) ||
	    !response.has_posix_account || !response.authorization_id[0] ||
	    (response.group_count == 0) || (response.group_count > FRDP_IPC_MAX_AUTH_GROUPS))
		goto cleanup;
	SecureZeroMemory(&response, sizeof(response));

	if ((run_pam_wrapper_auth_case("pam-denied", dir, denied_service, pwd->pw_name, key_path,
	                               &response) != 0) ||
	    response.success || response.error[0])
		goto cleanup;
	SecureZeroMemory(&response, sizeof(response));

	if (run_pam_wrapper_error_limit_case(dir, error_service, pwd->pw_name, key_path) != 0)
		goto cleanup;
	if (test_authd_pam_canonical_alias_failure_limit(pwd->pw_name, key_path) != 0)
		goto cleanup;
	rc = 0;

cleanup:
	SecureZeroMemory(&response, sizeof(response));
	unlink(key_path);
	unlink(error_path);
	unlink(denied_path);
	unlink(success_path);
	unlink(denied_passdb_path);
	unlink(passdb_path);
	rmdir(dir);
	return rc;
}
#else
static int test_authd_real_pam_provider(void)
{
	return 0;
}
#endif

static int test_monotonic_seconds(uint64_t* seconds)
{
	struct timespec now = { 0 };

	if (!seconds || (clock_gettime(CLOCK_MONOTONIC, &now) != 0) || (now.tv_sec < 0))
		return -1;
	*seconds = (uint64_t)now.tv_sec;
	return 0;
}

static int test_authd_account_and_source_failure_limit(void)
{
	frdpTestHelper helper;
	char user[sizeof(((frdpAuthRequest*)0)->user)] = { 0 };
	uint64_t started = 0;
	uint64_t finished = 0;
	int rc = -1;

	if (start_helper(FRDP_AUTHD_TEST_DENY_BINARY, "frdp-authd-auth-failure-limit", &helper) != 0)
		return -1;
	if (test_monotonic_seconds(&started) != 0)
		goto cleanup;
	for (uint32_t x = 0; x < FRDP_AUTH_FAILURE_LIMIT_DEFAULT_MAX_FAILURES; x++)
	{
		if (send_authd_failed_login(helper.socket_path, "frdp-no-such-limited-account",
		                            "192.0.2.44", 0) != 0)
			goto cleanup;
	}
	if ((test_monotonic_seconds(&finished) != 0) ||
	    ((finished - started) >= FRDP_AUTH_FAILURE_LIMIT_DEFAULT_WINDOW_SECONDS))
		goto cleanup;
	if (send_authd_failed_login(helper.socket_path, "FRDP-NO-SUCH-LIMITED-ACCOUNT",
	                            "192.0.2.45", 1) != 0)
		goto cleanup;
	if (test_monotonic_seconds(&started) != 0)
		goto cleanup;
	for (uint32_t x = 0; x < FRDP_AUTH_FAILURE_LIMIT_DEFAULT_MAX_FAILURES; x++)
	{
		if (snprintf(user, sizeof(user), "frdp-no-such-source-user-%" PRIu32, x) >=
		    (int)sizeof(user))
			goto cleanup;
		if (send_authd_failed_login(helper.socket_path, user, "198.51.100.9", 0) != 0)
			goto cleanup;
	}
	if ((test_monotonic_seconds(&finished) != 0) ||
	    ((finished - started) >= FRDP_AUTH_FAILURE_LIMIT_DEFAULT_WINDOW_SECONDS))
		goto cleanup;
	if (send_authd_failed_login(helper.socket_path, "frdp-no-such-source-user-final",
	                            "198.51.100.9", 1) != 0)
		goto cleanup;
	rc = 0;

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

static int write_sesmand_config(const char* path, const char* pam_service, uint32_t max_sessions,
                                uint32_t max_processes, uint32_t memory_max_mb)
{
	FILE* fp = NULL;

	if (!path || !pam_service)
		return -1;
	fp = fopen(path, "wb");
	if (!fp)
		return -1;
	if (fprintf(fp, "[auth]\npam_service = \"%s\"\n"
	                "[session]\nmax_sessions = %" PRIu32 "\nmax_processes = %" PRIu32
	                "\nmemory_max_mb = %" PRIu32 "\n",
	            pam_service, max_sessions, max_processes, memory_max_mb) < 0)
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
                                uint32_t group_count, frdpSessionResponse* response,
                                const char* expected_error)
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
	if (expected_error)
		rc = receive_session_response(fd, 0, expected_error);
	else
		rc = receive_session_success(fd, response);

cleanup:
	if (fd >= 0)
		frdp_ipc_close(fd);
	SecureZeroMemory(&request, sizeof(request));
	SecureZeroMemory(token, sizeof(token));
	return rc;
}

#if defined(FRDP_PAM_SESSION_TEST_MODULE) && defined(FRDP_PAM_WRAPPER_LIBRARY) && \
    defined(FRDP_PAM_WRAPPER_MODULE_DIR)
static int request_session_control(const char* socket_path, frdpIpcMessageType type,
                                   const char* correlation_id, const char* session_id,
                                   const char* user, frdpSessionResponse* response);
static int list_single_session(const char* socket_path, const frdpSessionResponse* expected,
                               const char* user, const char* state, int32_t expected_agent_pid,
                               int32_t* agent_pid);

typedef struct
{
	const char* session_id;
	uid_t uid;
	pid_t agent_pid;
	pid_t pgid;
	unsigned long long agent_start_ticks;
	int display_number;
	uint64_t agent_socket_dev;
	uint64_t agent_socket_ino;
	uint64_t display_reservation_dev;
	uint64_t display_reservation_ino;
	int count;
} frdpStoppingMetadataExpectation;

static int verify_stopping_metadata(const frdpSesmandSessionMetadata* metadata,
	                                uint64_t file_dev, uint64_t file_ino, void* context)
{
	frdpStoppingMetadataExpectation* expected = (frdpStoppingMetadataExpectation*)context;

	if (!metadata || !expected || !expected->session_id || (file_dev == 0) || (file_ino == 0) ||
	    (strcmp(metadata->session_id, expected->session_id) != 0) ||
	    (metadata->uid != expected->uid) || (metadata->agent_pid != expected->agent_pid) ||
	    (metadata->pgid != expected->pgid) ||
	    (metadata->agent_start_ticks != expected->agent_start_ticks) ||
	    (metadata->state != FRDP_SESMAND_SESSION_STOPPING) ||
	    (metadata->display_number != expected->display_number) ||
	    (metadata->agent_socket_dev != expected->agent_socket_dev) ||
	    (metadata->agent_socket_ino != expected->agent_socket_ino) ||
	    (metadata->display_reservation_dev != expected->display_reservation_dev) ||
	    (metadata->display_reservation_ino != expected->display_reservation_ino) ||
	    (metadata->pam_owner != 1))
		return -1;
	expected->count++;
	return 0;
}

static int file_contents_equal(const char* path, const char* expected)
{
	char contents[512] = { 0 };
	FILE* fp = NULL;
	size_t length = 0;
	int rc = -1;

	if (!path || !expected)
		return -1;
	fp = fopen(path, "rb");
	if (!fp)
		return -1;
	length = fread(contents, 1, sizeof(contents) - 1, fp);
	if (!ferror(fp) && feof(fp) && (strcmp(contents, expected) == 0))
		rc = 0;
	fclose(fp);
	return rc;
}

static int wait_for_file_contents_attempts(const char* path, const char* expected, int attempts)
{
	for (int attempt = 0; attempt < attempts; attempt++)
	{
		if (file_contents_equal(path, expected) == 0)
			return 0;
		usleep(50000);
	}
	return -1;
}

static int wait_for_file_contents(const char* path, const char* expected)
{
	return wait_for_file_contents_attempts(path, expected, 100);
}

static int wait_for_pid_file(const char* path, pid_t* pid)
{
	for (int attempt = 0; attempt < 100; attempt++)
	{
		FILE* fp = fopen(path, "r");

		if (fp)
		{
			long value = 0;
			char trailing = 0;
			const int valid = (fscanf(fp, "%ld", &value) == 1) && (value > 1) &&
			                  (value <= INT32_MAX) && (fscanf(fp, " %c", &trailing) != 1);

			fclose(fp);
			if (valid)
			{
				*pid = (pid_t)value;
				return 0;
			}
		}
		else if (errno != ENOENT)
			return -1;
		usleep(100000);
	}
	return -1;
}

static int test_authd_crash_during_pam(void)
{
	static const char service[] = "frdp-auth-crash";
	static const char expected_audit[] = "authenticate-start\n";
	frdpTestHelper helper = { .pid = -1 };
	struct passwd* pwd = getpwuid(geteuid());
	pid_t requester = -1;
	char dir[1024] = { 0 };
	char service_path[1024] = { 0 };
	char audit_path[1024] = { 0 };
	char key_path[1024] = { 0 };
	char contents[2048] = { 0 };
	int helper_started = 0;
	int status = 0;
	int rc = -1;

	if (!pwd || !pwd->pw_name || !pwd->pw_name[0] ||
	    (make_runtime_dir(dir, sizeof(dir), "pam-auth-crash") != 0))
		return -1;
	if ((snprintf(service_path, sizeof(service_path), "%s/%s", dir, service) >=
	     (int)sizeof(service_path)) ||
	    (snprintf(audit_path, sizeof(audit_path), "%s/audit.log", dir) >=
	     (int)sizeof(audit_path)) ||
	    (snprintf(key_path, sizeof(key_path), "%s/auth-token.key", dir) >=
	     (int)sizeof(key_path)) ||
	    (snprintf(contents, sizeof(contents), "auth required %s\n",
	              FRDP_PAM_SESSION_TEST_MODULE) >= (int)sizeof(contents)) ||
	    (write_pam_fixture_file(service_path, contents) != 0) ||
	    (write_pam_fixture_file(audit_path, "") != 0))
		goto cleanup;
	if (start_helper_with_pam_wrapper(FRDP_AUTHD_BINARY, "pam-auth-crash", dir, service,
	                                  key_path, pwd->pw_name, audit_path, 1, &helper) != 0)
		goto cleanup;
	helper_started = 1;
	requester = fork();
	if (requester < 0)
		goto cleanup;
	if (requester == 0)
	{
		frdpAuthResponse response = { 0 };
		const int exchange_rc =
		    exchange_authd_login(helper.socket_path, pwd->pw_name, "test-password", &response);

		SecureZeroMemory(&response, sizeof(response));
		_exit(exchange_rc != 0 ? 0 : 1);
	}
	if (wait_for_file_contents(audit_path, expected_audit) != 0)
		goto cleanup;
	if ((kill(helper.pid, SIGKILL) != 0) || (wait_for_exit(helper.pid, &status) != 0))
		goto cleanup;
	helper.pid = -1;
	if (!WIFSIGNALED(status) || (WTERMSIG(status) != SIGKILL))
		goto cleanup;
	if (wait_for_exit(requester, &status) != 0)
		goto cleanup;
	requester = -1;
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0))
		goto cleanup;
	if (test_helper_health(helper.socket_path, "frdp-authd") == 0)
		goto cleanup;
	rc = 0;

cleanup:
	if (requester > 0)
	{
		kill(requester, SIGKILL);
		(void)waitpid(requester, NULL, 0);
	}
	if (helper_started)
	{
		if (helper.pid > 0)
		{
			kill(helper.pid, SIGKILL);
			(void)waitpid(helper.pid, NULL, 0);
		}
		unlink(helper.socket_path);
		rmdir(helper.dir);
	}
	unlink(key_path);
	unlink(audit_path);
	unlink(service_path);
	if (dir[0])
		rmdir(dir);
	return rc;
}

static int helper_dir_contains_only_listener(const frdpTestHelper* helper)
{
	const char* listener_name = NULL;
	DIR* dir = NULL;
	struct dirent* entry = NULL;
	struct stat st = { 0 };
	int found = 0;
	int rc = -1;

	if (!helper)
		return -1;
	listener_name = strrchr(helper->socket_path, '/');
	if (!listener_name || !listener_name[1])
		return -1;
	listener_name++;
	dir = opendir(helper->dir);
	if (!dir)
		return -1;
	errno = 0;
	while ((entry = readdir(dir)) != NULL)
	{
		if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0))
			continue;
		if (found || (strcmp(entry->d_name, listener_name) != 0))
			goto cleanup;
		found = 1;
	}
	if ((errno == 0) && found && (lstat(helper->socket_path, &st) == 0) && S_ISSOCK(st.st_mode))
		rc = 0;

cleanup:
	closedir(dir);
	return rc;
}

static int helper_dir_contains_listener_and_pam_endpoint(const frdpTestHelper* helper)
{
	const char* listener_name = NULL;
	DIR* dir = NULL;
	struct dirent* entry = NULL;
	int found_listener = 0;
	int found_pam = 0;
	int rc = -1;

	if (!helper)
		return -1;
	listener_name = strrchr(helper->socket_path, '/');
	if (!listener_name || !listener_name[1] || !(dir = opendir(helper->dir)))
		return -1;
	listener_name++;
	errno = 0;
	while ((entry = readdir(dir)) != NULL)
	{
		const size_t length = strlen(entry->d_name);

		if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0))
			continue;
		if (strcmp(entry->d_name, listener_name) == 0)
		{
			if (found_listener)
				goto cleanup;
			found_listener = 1;
		}
		else if ((length == 45U) && (memcmp(entry->d_name, "pam-", 4U) == 0) &&
		         (memcmp(&entry->d_name[length - 5U], ".sock", 5U) == 0))
		{
			char path[1024] = { 0 };
			struct stat st = { 0 };

			if (found_pam ||
			    (snprintf(path, sizeof(path), "%s/%s", helper->dir, entry->d_name) >=
			     (int)sizeof(path)) ||
			    (lstat(path, &st) != 0) || !S_ISSOCK(st.st_mode) || ((st.st_mode & 0777) != 0600))
				goto cleanup;
			found_pam = 1;
		}
		else
			goto cleanup;
	}
	if ((errno == 0) && found_listener && found_pam)
		rc = 0;

cleanup:
	closedir(dir);
	return rc;
}

static int find_pam_endpoint(const frdpTestHelper* helper, char* path, size_t path_size)
{
	DIR* directory = NULL;
	struct dirent* entry = NULL;
	int found = 0;

	if (!helper || !path || (path_size == 0) || !(directory = opendir(helper->dir)))
		return -1;
	while ((entry = readdir(directory)) != NULL)
	{
		const size_t length = strlen(entry->d_name);

		if ((length != 45U) || (memcmp(entry->d_name, "pam-", 4U) != 0) ||
		    (memcmp(&entry->d_name[length - 5U], ".sock", 5U) != 0))
			continue;
		if (found ||
		    (snprintf(path, path_size, "%s/%s", helper->dir, entry->d_name) >= (int)path_size))
		{
			closedir(directory);
			return -1;
		}
		found = 1;
	}
	closedir(directory);
	return found ? 0 : -1;
}

static int pam_owner_peer_pid(const char* endpoint, pid_t* pid)
{
#if defined(__linux__) && defined(SO_PEERCRED)
	struct sockaddr_un address = { 0 };
	struct ucred credentials = { 0 };
	socklen_t size = sizeof(credentials);
	int fd = -1;
	int rc = -1;

	if (!endpoint || !pid || (strlen(endpoint) >= sizeof(address.sun_path)))
		return -1;
	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, sizeof(address.sun_path), "%s", endpoint);
	if ((connect(fd, (struct sockaddr*)&address, sizeof(address)) == 0) &&
	    (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &size) == 0) &&
	    (size == sizeof(credentials)) && (credentials.pid > 1))
	{
		*pid = credentials.pid;
		rc = 0;
	}
	close(fd);
	return rc;
#else
	(void)endpoint;
	(void)pid;
	return -1;
#endif
}

static int test_sesmand_pam_session_open_failure(void)
{
	static const char service[] = "frdp-session-deny";
	static const char expected_audit[] =
	    "account\nsetcred-establish\nopen-session-start\nopen-session-denied\nsetcred-delete\n";
	frdpTestHelper helper = { .pid = -1 };
	frdpSessionResponse response = { 0 };
	frdpSessionListResponse list = { 0 };
	char dir[1024] = { 0 };
	char service_path[1024] = { 0 };
	char audit_path[1024] = { 0 };
	char key_path[1024] = { 0 };
	char contents[4096] = { 0 };
	char user[64] = { 0 };
	uint64_t uid = 0;
	uint64_t gid = 0;
	uint64_t groups[FRDP_IPC_MAX_AUTH_GROUPS] = { 0 };
	uint32_t group_count = 0;
	const char* previous_key_path = getenv(FRDP_AUTH_TOKEN_KEY_ENV);
	char* saved_key_path = previous_key_path ? strdup(previous_key_path) : NULL;
	int helper_started = 0;
	int rc = -1;

	if (previous_key_path && !saved_key_path)
		return -1;
	if ((make_runtime_dir(dir, sizeof(dir), "pam-session-failure") != 0) ||
	    (snprintf(service_path, sizeof(service_path), "%s/%s", dir, service) >=
	     (int)sizeof(service_path)) ||
	    (snprintf(audit_path, sizeof(audit_path), "%s/pam-audit.log", dir) >=
	     (int)sizeof(audit_path)) ||
	    (snprintf(key_path, sizeof(key_path), "%s/auth-token.key", dir) >=
	     (int)sizeof(key_path)))
		goto cleanup;
	if ((snprintf(contents, sizeof(contents),
	              "auth required %s\naccount required %s\nsession required %s\n",
	              FRDP_PAM_SESSION_TEST_MODULE, FRDP_PAM_SESSION_TEST_MODULE,
	              FRDP_PAM_SESSION_TEST_MODULE) >= (int)sizeof(contents)) ||
	    (write_pam_fixture_file(service_path, contents) != 0) ||
	    (write_pam_fixture_file(audit_path, "") != 0) ||
	    (setenv(FRDP_AUTH_TOKEN_KEY_ENV, key_path, 1) != 0) ||
	    (lookup_current_user(user, sizeof(user), &uid, &gid, groups, &group_count) != 0))
		goto cleanup;
	if (start_helper_with_pam_wrapper(FRDP_SESMAND_BINARY, "pam-session-failure", dir, service,
	                                  key_path, NULL, audit_path, 0, &helper) != 0)
		goto cleanup;
	helper_started = 1;
	if ((request_live_session(helper.socket_path, user, "127.0.0.1", "pam-session-denied", NULL,
	                          uid, gid, groups, group_count, &response, "session open failed") !=
	     0) ||
	    (file_contents_equal(audit_path, expected_audit) != 0) ||
	    (receive_sesmand_list(helper.socket_path, &list) != 0) || (list.count != 0) ||
	    (helper_dir_contains_only_listener(&helper) != 0))
		goto cleanup;
	rc = 0;

cleanup:
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
	unlink(audit_path);
	unlink(service_path);
	if (dir[0])
		rmdir(dir);
	SecureZeroMemory(&response, sizeof(response));
	SecureZeroMemory(&list, sizeof(list));
	return rc;
}

static int test_sesmand_crash_during_pam_open(void)
{
	static const char service[] = "frdp-session-crash";
	static const char expected_audit[] =
	    "account\nsetcred-establish\nopen-session-start\n";
	frdpTestHelper helper = { .pid = -1 };
	pid_t requester = -1;
	char dir[1024] = { 0 };
	char service_path[1024] = { 0 };
	char audit_path[1024] = { 0 };
	char key_path[1024] = { 0 };
	char pam_endpoint[1024] = { 0 };
	char contents[4096] = { 0 };
	char user[64] = { 0 };
	uint64_t uid = 0;
	uint64_t gid = 0;
	uint64_t groups[FRDP_IPC_MAX_AUTH_GROUPS] = { 0 };
	uint32_t group_count = 0;
	const char* previous_key_path = getenv(FRDP_AUTH_TOKEN_KEY_ENV);
	char* saved_key_path = previous_key_path ? strdup(previous_key_path) : NULL;
	int helper_started = 0;
	int status = 0;
	int rc = -1;

	if (previous_key_path && !saved_key_path)
		return -1;
	if ((make_runtime_dir(dir, sizeof(dir), "pam-session-crash") != 0) ||
	    (snprintf(service_path, sizeof(service_path), "%s/%s", dir, service) >=
	     (int)sizeof(service_path)) ||
	    (snprintf(audit_path, sizeof(audit_path), "%s/pam-audit.log", dir) >=
	     (int)sizeof(audit_path)) ||
	    (snprintf(key_path, sizeof(key_path), "%s/auth-token.key", dir) >=
	     (int)sizeof(key_path)) ||
	    (snprintf(contents, sizeof(contents),
	              "auth required %s\naccount required %s\nsession required %s\n",
	              FRDP_PAM_SESSION_TEST_MODULE, FRDP_PAM_SESSION_TEST_MODULE,
	              FRDP_PAM_SESSION_BLOCK_TEST_MODULE) >=
	     (int)sizeof(contents)) ||
	    (write_pam_fixture_file(service_path, contents) != 0) ||
	    (write_pam_fixture_file(audit_path, "") != 0) ||
	    (setenv(FRDP_AUTH_TOKEN_KEY_ENV, key_path, 1) != 0) ||
	    (lookup_current_user(user, sizeof(user), &uid, &gid, groups, &group_count) != 0))
		goto cleanup;
	if (start_helper_with_pam_wrapper(FRDP_SESMAND_BINARY, "pam-session-crash", dir, service,
	                                  key_path, NULL, audit_path, 0, &helper) != 0)
		goto cleanup;
	helper_started = 1;
	requester = fork();
	if (requester < 0)
		goto cleanup;
	if (requester == 0)
	{
		frdpSessionResponse response = { 0 };
		const int request_rc = request_live_session(
		    helper.socket_path, user, "198.51.100.77", "pam-session-crash", NULL, uid, gid, groups,
		    group_count, &response, "unused after manager crash");

		SecureZeroMemory(&response, sizeof(response));
		_exit(request_rc != 0 ? 0 : 1);
	}
	if ((wait_for_file_contents(audit_path, expected_audit) != 0) ||
	    (helper_dir_contains_listener_and_pam_endpoint(&helper) != 0) ||
	    (find_pam_endpoint(&helper, pam_endpoint, sizeof(pam_endpoint)) != 0))
		goto cleanup;
	if ((kill(helper.pid, SIGKILL) != 0) || (wait_for_exit(helper.pid, &status) != 0))
		goto cleanup;
	helper.pid = -1;
	if (!WIFSIGNALED(status) || (WTERMSIG(status) != SIGKILL))
		goto cleanup;
	if (wait_for_exit(requester, &status) != 0)
		goto cleanup;
	requester = -1;
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0) ||
	    (test_helper_health(helper.socket_path, "frdp-sesmand") == 0) ||
	    (restart_helper(FRDP_SESMAND_BINARY, &helper) == 0))
		goto cleanup;
	if ((helper.pid > 0) || (access(pam_endpoint, F_OK) != 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (requester > 0)
	{
		kill(requester, SIGKILL);
		(void)waitpid(requester, NULL, 0);
	}
	if (helper_started)
	{
		if (helper.pid > 0)
		{
			kill(helper.pid, SIGKILL);
			(void)waitpid(helper.pid, NULL, 0);
		}
		unlink(helper.socket_path);
		unlink(pam_endpoint);
		rmdir(helper.dir);
	}
	if (saved_key_path)
	{
		(void)setenv(FRDP_AUTH_TOKEN_KEY_ENV, saved_key_path, 1);
		free(saved_key_path);
	}
	else
		unsetenv(FRDP_AUTH_TOKEN_KEY_ENV);
	unlink(key_path);
	unlink(audit_path);
	unlink(service_path);
	if (dir[0])
		rmdir(dir);
	SecureZeroMemory(groups, sizeof(groups));
	return rc;
}

static int test_sesmand_crash_after_agent_launch(void)
{
	static const char service[] = "frdp-session-launch-crash";
	static const char expected_audit[] = "account\nsetcred-establish\nopen-session-start\n"
	                                     "close-session-start\nclose-session\nsetcred-delete\n";
	frdpTestHelper helper = { .pid = -1 };
	pid_t requester = -1;
	pid_t agent_pid = -1;
	char dir[1024] = { 0 };
	char service_path[1024] = { 0 };
	char audit_path[1024] = { 0 };
	char key_path[1024] = { 0 };
	char marker_path[1024] = { 0 };
	char agent_dir[1024] = { 0 };
	char agent_path[1024] = { 0 };
	char updated_path[4096] = { 0 };
	char contents[4096] = { 0 };
	char user[64] = { 0 };
	uint64_t uid = 0;
	uint64_t gid = 0;
	uint64_t groups[FRDP_IPC_MAX_AUTH_GROUPS] = { 0 };
	uint32_t group_count = 0;
	const char* previous_key_path = getenv(FRDP_AUTH_TOKEN_KEY_ENV);
	const char* current_path = getenv("PATH");
	const char* previous_marker = getenv("FRDP_AGENT_TEST_MARKER");
	char* saved_key_path = previous_key_path ? strdup(previous_key_path) : NULL;
	char* saved_path = current_path ? strdup(current_path) : NULL;
	char* saved_marker = previous_marker ? strdup(previous_marker) : NULL;
	int helper_started = 0;
	int status = 0;
	int rc = -1;
	const char* stage = "prerequisites";

	if (!saved_path || (previous_key_path && !saved_key_path) || (previous_marker && !saved_marker))
		goto cleanup;
	if ((make_runtime_dir(dir, sizeof(dir), "pam-session-launch-crash") != 0) ||
	    (make_runtime_dir(agent_dir, sizeof(agent_dir), "blocking-agent") != 0) ||
	    (snprintf(service_path, sizeof(service_path), "%s/%s", dir, service) >=
	     (int)sizeof(service_path)) ||
	    (snprintf(audit_path, sizeof(audit_path), "%s/pam-audit.log", dir) >=
	     (int)sizeof(audit_path)) ||
	    (snprintf(key_path, sizeof(key_path), "%s/auth-token.key", dir) >=
	     (int)sizeof(key_path)) ||
	    (snprintf(marker_path, sizeof(marker_path), "%s/agent.pid", agent_dir) >=
	     (int)sizeof(marker_path)) ||
	    (snprintf(agent_path, sizeof(agent_path), "%s/frdp-session-agent", agent_dir) >=
	     (int)sizeof(agent_path)) ||
	    (snprintf(contents, sizeof(contents),
	              "auth required %s\naccount required %s\nsession required %s\n",
	              FRDP_PAM_SESSION_ALLOW_TEST_MODULE, FRDP_PAM_SESSION_ALLOW_TEST_MODULE,
	              FRDP_PAM_SESSION_ALLOW_TEST_MODULE) >= (int)sizeof(contents)) ||
	    (write_pam_fixture_file(service_path, contents) != 0) ||
	    (write_pam_fixture_file(audit_path, "") != 0) ||
	    (symlink(FRDP_SESSION_AGENT_BLOCKING_BINARY, agent_path) != 0) ||
	    (snprintf(updated_path, sizeof(updated_path), "%s:%s", agent_dir, saved_path) >=
	     (int)sizeof(updated_path)) ||
	    (setenv(FRDP_AUTH_TOKEN_KEY_ENV, key_path, 1) != 0) ||
	    (setenv("PATH", updated_path, 1) != 0) ||
	    (setenv("FRDP_AGENT_TEST_MARKER", marker_path, 1) != 0) ||
	    (lookup_current_user(user, sizeof(user), &uid, &gid, groups, &group_count) != 0))
		goto cleanup;
	stage = "helper-start";
	if (start_helper_with_pam_wrapper(FRDP_SESMAND_BINARY, "pam-session-launch-crash", dir,
	                                  service, key_path, NULL, audit_path, 0, &helper) != 0)
		goto cleanup;
	helper_started = 1;
	(void)setenv("PATH", saved_path, 1);
	if (saved_marker)
		(void)setenv("FRDP_AGENT_TEST_MARKER", saved_marker, 1);
	else
		unsetenv("FRDP_AGENT_TEST_MARKER");
	stage = "request";
	requester = fork();
	if (requester < 0)
		goto cleanup;
	if (requester == 0)
	{
		frdpSessionResponse response = { 0 };
		const int request_rc = request_live_session(
		    helper.socket_path, user, "198.51.100.78", "pam-session-launch-crash", NULL, uid, gid,
		    groups, group_count, &response, "unused after manager crash");

		SecureZeroMemory(&response, sizeof(response));
		_exit(request_rc != 0 ? 0 : 1);
	}
	stage = "agent-marker";
	if ((wait_for_pid_file(marker_path, &agent_pid) != 0) || (getpgid(agent_pid) != agent_pid) ||
	    (kill(helper.pid, SIGKILL) != 0) || (wait_for_exit(helper.pid, &status) != 0))
		goto cleanup;
	helper.pid = -1;
	stage = "manager-killed";
	if (!WIFSIGNALED(status) || (WTERMSIG(status) != SIGKILL) ||
	    (wait_for_exit(requester, &status) != 0))
		goto cleanup;
	requester = -1;
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0))
		goto cleanup;
	stage = "agent-gone";
	if (wait_for_process_gone(agent_pid) != 0)
		goto cleanup;
	stage = "pam-closed";
	if (wait_for_file_contents_attempts(audit_path, expected_audit, 200) != 0)
		goto cleanup;
	stage = "manager-restart";
	if (restart_helper(FRDP_SESMAND_BINARY, &helper) != 0)
		goto cleanup;
	stage = "stale-cleanup";
	if ((helper_dir_contains_only_listener(&helper) != 0) ||
	    (test_helper_health(helper.socket_path, "frdp-sesmand") != 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (rc != 0)
		fprintf(stderr, "post-launch crash failed at stage: %s\n", stage);
	if (agent_pid > 1)
		(void)kill(-agent_pid, SIGKILL);
	if (requester > 0)
	{
		kill(requester, SIGKILL);
		(void)waitpid(requester, NULL, 0);
	}
	if (helper_started)
	{
		if (helper.pid > 0)
		{
			kill(helper.pid, SIGKILL);
			(void)waitpid(helper.pid, NULL, 0);
		}
		unlink(helper.socket_path);
		rmdir(helper.dir);
	}
	if (saved_path)
	{
		(void)setenv("PATH", saved_path, 1);
		free(saved_path);
	}
	if (saved_marker)
	{
		(void)setenv("FRDP_AGENT_TEST_MARKER", saved_marker, 1);
		free(saved_marker);
	}
	else
		unsetenv("FRDP_AGENT_TEST_MARKER");
	if (saved_key_path)
	{
		(void)setenv(FRDP_AUTH_TOKEN_KEY_ENV, saved_key_path, 1);
		free(saved_key_path);
	}
	else
		unsetenv(FRDP_AUTH_TOKEN_KEY_ENV);
	unlink(marker_path);
	unlink(agent_path);
	rmdir(agent_dir);
	unlink(key_path);
	unlink(audit_path);
	unlink(service_path);
	if (dir[0])
		rmdir(dir);
	SecureZeroMemory(groups, sizeof(groups));
	return rc;
}

static int test_sesmand_crash_during_pam_close(void)
{
#ifndef FRDP_XVFB_EXECUTABLE
	printf("frdp-sesmand in-flight PAM close crash skipped: Xvfb unavailable\n");
	return 0;
#else
	if (!pidfd_runtime_supported())
	{
		printf("frdp-sesmand in-flight PAM close crash skipped: Linux pidfd support unavailable\n");
		return 0;
	}
	static const char service[] = "frdp-session-close-crash";
	static const char expected_audit[] =
	    "account\nsetcred-establish\nopen-session-start\nclose-session-start\n";
	frdpTestHelper helper = { .pid = -1 };
	frdpSessionResponse opened = { 0 };
	frdpStoppingMetadataExpectation metadata_expected = { 0 };
	struct stat agent_socket_st = { 0 };
	struct stat reservation_st = { 0 };
	pid_t requester = -1;
	pid_t agent_pgid = -1;
	pid_t backend_pid = -1;
	pid_t pam_owner_pid = -1;
	char dir[1024] = { 0 };
	char service_path[1024] = { 0 };
	char audit_path[1024] = { 0 };
	char key_path[1024] = { 0 };
	char metadata_name[96] = { 0 };
	char metadata_path[1024] = { 0 };
	char pam_owner_endpoint[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	char reservation_path[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	char contents[4096] = { 0 };
	char user[64] = { 0 };
	uint64_t uid = 0;
	uint64_t gid = 0;
	uint64_t groups[FRDP_IPC_MAX_AUTH_GROUPS] = { 0 };
	uint32_t group_count = 0;
	int32_t agent_pid = -1;
	int agent_pidfd = -1;
	int backend_pidfd = -1;
	int display_number = 0;
	unsigned long long agent_start_ticks = 0;
	unsigned long long backend_start_ticks = 0;
	const char* previous_key_path = getenv(FRDP_AUTH_TOKEN_KEY_ENV);
	char* saved_key_path = previous_key_path ? strdup(previous_key_path) : NULL;
	char* saved_path = NULL;
	int helper_started = 0;
	int status = 0;
	int rc = -1;
	const char* stage = "prerequisites";

	if (previous_key_path && !saved_key_path)
		return -1;
	if (access(FRDP_XVFB_EXECUTABLE, X_OK) != 0)
	{
		printf("frdp-sesmand in-flight PAM close crash skipped: Xvfb unavailable\n");
		rc = 0;
		goto cleanup;
	}
	if ((make_runtime_dir(dir, sizeof(dir), "pam-session-close-crash") != 0) ||
	    (snprintf(service_path, sizeof(service_path), "%s/%s", dir, service) >=
	     (int)sizeof(service_path)) ||
	    (snprintf(audit_path, sizeof(audit_path), "%s/pam-audit.log", dir) >=
	     (int)sizeof(audit_path)) ||
	    (snprintf(key_path, sizeof(key_path), "%s/auth-token.key", dir) >=
	     (int)sizeof(key_path)) ||
	    (snprintf(contents, sizeof(contents),
	              "auth required %s\naccount required %s\nsession required %s\n",
	              FRDP_PAM_SESSION_CLOSE_BLOCK_TEST_MODULE,
	              FRDP_PAM_SESSION_CLOSE_BLOCK_TEST_MODULE,
	              FRDP_PAM_SESSION_CLOSE_BLOCK_TEST_MODULE) >= (int)sizeof(contents)) ||
	    (write_pam_fixture_file(service_path, contents) != 0) ||
	    (write_pam_fixture_file(audit_path, "") != 0))
		goto cleanup;
	stage = "environment";
	if ((setenv(FRDP_AUTH_TOKEN_KEY_ENV, key_path, 1) != 0) ||
	    (prepend_binary_dirs_to_path(FRDP_SESSION_AGENT_BINARY, FRDP_XVFB_EXECUTABLE,
	                                 &saved_path) != 0) ||
	    (lookup_current_user(user, sizeof(user), &uid, &gid, groups, &group_count) != 0))
		goto cleanup;
	stage = "helper-start";
	if (start_helper_with_pam_wrapper(FRDP_SESMAND_BINARY, "pam-session-close-crash", dir,
	                                  service, key_path, NULL, audit_path, 0, &helper) != 0)
		goto cleanup;
	helper_started = 1;
	restore_path(saved_path);
	saved_path = NULL;
	stage = "open";
	if ((request_live_session(helper.socket_path, user, "127.0.0.1", "pam-close-crash-open", NULL,
	                          uid, gid, groups, group_count, &opened, NULL) != 0) ||
	    (list_single_session(helper.socket_path, &opened, user, "active", -1, &agent_pid) != 0) ||
	    (sscanf(opened.display, ":%d", &display_number) != 1) ||
	    (frdp_sesmand_session_metadata_filename(metadata_name, sizeof(metadata_name),
	                                            opened.session_id) != 0) ||
	    (snprintf(metadata_path, sizeof(metadata_path), "%s/%s", helper.dir, metadata_name) >=
	     (int)sizeof(metadata_path)) ||
	    (frdp_sesmand_display_reservation_path(reservation_path, sizeof(reservation_path),
	                                           helper.dir, display_number) != 0) ||
	    (frdp_sesmand_pam_owner_endpoint(pam_owner_endpoint, sizeof(pam_owner_endpoint), helper.dir,
	                                     opened.session_id) != 0) ||
	    (pam_owner_peer_pid(pam_owner_endpoint, &pam_owner_pid) != 0) ||
	    (lstat(opened.agent_socket, &agent_socket_st) != 0) ||
	    (lstat(reservation_path, &reservation_st) != 0) || (access(metadata_path, F_OK) != 0) ||
	    ((agent_pgid = getpgid((pid_t)agent_pid)) <= 1) ||
	    (pin_process_identity((pid_t)agent_pid, (uid_t)uid, agent_pgid, &agent_pidfd,
	                          &agent_start_ticks) != 0) ||
	    (read_single_child_pid((pid_t)agent_pid, &backend_pid) != 0) ||
	    (pin_process_identity(backend_pid, (uid_t)uid, agent_pgid, &backend_pidfd,
	                          &backend_start_ticks) != 0))
		goto cleanup;
	metadata_expected.session_id = opened.session_id;
	metadata_expected.uid = (uid_t)uid;
	metadata_expected.agent_pid = (pid_t)agent_pid;
	metadata_expected.pgid = agent_pgid;
	metadata_expected.agent_start_ticks = agent_start_ticks;
	metadata_expected.display_number = display_number;
	metadata_expected.agent_socket_dev = (uint64_t)agent_socket_st.st_dev;
	metadata_expected.agent_socket_ino = (uint64_t)agent_socket_st.st_ino;
	metadata_expected.display_reservation_dev = (uint64_t)reservation_st.st_dev;
	metadata_expected.display_reservation_ino = (uint64_t)reservation_st.st_ino;
	stage = "close-request";
	requester = fork();
	if (requester < 0)
		goto cleanup;
	if (requester == 0)
	{
		frdpSessionResponse response = { 0 };
		const int request_rc = request_session_control(
		    helper.socket_path, FRDP_IPC_SESSION_CLOSE_REQUEST, "pam-close-crash",
		    opened.session_id, user, &response);

		SecureZeroMemory(&response, sizeof(response));
		_exit(request_rc != 0 ? 0 : 1);
	}
	stage = "close-blocked";
	if ((wait_for_file_contents(audit_path, expected_audit) != 0) ||
	    (wait_for_process_gone((pid_t)agent_pid) != 0) ||
	    (wait_for_process_group_gone(agent_pgid) != 0) ||
	    (frdp_sesmand_session_metadata_visit(helper.dir, verify_stopping_metadata,
	                                         &metadata_expected) != 0) ||
	    (metadata_expected.count != 1) || (access(metadata_path, F_OK) != 0) ||
	    (access(opened.agent_socket, F_OK) != 0) || (access(reservation_path, F_OK) != 0))
		goto cleanup;
	stage = "manager-sigkill";
	if ((kill(helper.pid, SIGKILL) != 0) || (wait_for_exit(helper.pid, &status) != 0))
		goto cleanup;
	helper.pid = -1;
	helper_started = 0;
	if (!WIFSIGNALED(status) || (WTERMSIG(status) != SIGKILL) ||
	    (wait_for_exit(requester, &status) != 0))
		goto cleanup;
	requester = -1;
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0))
		goto cleanup;
	stage = "manager-restart";
	if ((restart_helper(FRDP_SESMAND_BINARY, &helper) != 0) ||
	    (wait_for_exit_attempts(helper.pid, &status, 150) != 0))
		goto cleanup;
	helper.pid = -1;
	if (!WIFEXITED(status) || (WEXITSTATUS(status) == 0))
		goto cleanup;
	stage = "preserved";
	if ((access(metadata_path, F_OK) != 0) || (access(opened.agent_socket, F_OK) != 0) ||
	    (access(reservation_path, F_OK) != 0) || (access(pam_owner_endpoint, F_OK) != 0) ||
	    (kill(pam_owner_pid, 0) != 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (rc != 0)
		fprintf(stderr, "in-flight PAM close crash failed at stage: %s\n", stage);
	if (saved_path)
		restore_path(saved_path);
	if (requester > 0)
	{
		kill(requester, SIGKILL);
		(void)waitpid(requester, NULL, 0);
	}
	if (helper.pid > 0)
	{
		kill(helper.pid, SIGKILL);
		(void)waitpid(helper.pid, NULL, 0);
		helper.pid = -1;
		helper_started = 0;
	}
	if (pam_owner_pid > 1)
	{
		(void)kill(pam_owner_pid, SIGKILL);
		(void)wait_for_process_gone(pam_owner_pid);
	}
	if ((agent_pidfd >= 0) && (backend_pidfd >= 0))
	{
		(void)signal_process_pidfd(backend_pidfd, SIGKILL);
		(void)signal_process_pidfd(agent_pidfd, SIGKILL);
	}
	if (helper_started && (stop_helper(&helper) != 0))
		rc = -1;
	else if (helper.pid > 0)
	{
		kill(helper.pid, SIGKILL);
		(void)waitpid(helper.pid, NULL, 0);
	}
	if (agent_pidfd >= 0)
	{
		close(agent_pidfd);
	}
	if (backend_pidfd >= 0)
		close(backend_pidfd);
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
	unlink(pam_owner_endpoint);
	unlink(helper.socket_path);
	if (helper.dir[0])
		rmdir(helper.dir);
	unlink(key_path);
	unlink(audit_path);
	unlink(service_path);
	if (dir[0])
		rmdir(dir);
	SecureZeroMemory(groups, sizeof(groups));
	SecureZeroMemory(&opened, sizeof(opened));
	return rc;
#endif
}

static int login1_session_for_pid(sd_bus* bus, pid_t pid, char* session_id, size_t session_id_size)
{
	if (!bus || (pid <= 1) || !session_id || (session_id_size == 0) || ((uint64_t)pid > UINT32_MAX))
		return -1;
	for (int attempt = 0; attempt < 50; attempt++)
	{
		sd_bus_error error = SD_BUS_ERROR_NULL;
		sd_bus_message* reply = NULL;
		const char* object_path = NULL;
		char* value = NULL;
		int rc = sd_bus_call_method(bus, "org.freedesktop.login1", "/org/freedesktop/login1",
		                            "org.freedesktop.login1.Manager", "GetSessionByPID", &error,
		                            &reply, "u", (uint32_t)pid);

		if ((rc >= 0) && (sd_bus_message_read(reply, "o", &object_path) >= 0) && object_path &&
		    (sd_bus_get_property_string(bus, "org.freedesktop.login1", object_path,
		                                "org.freedesktop.login1.Session", "Id", &error,
		                                &value) >= 0) &&
		    (snprintf(session_id, session_id_size, "%s", value) < (int)session_id_size))
		{
			free(value);
			sd_bus_message_unref(reply);
			sd_bus_error_free(&error);
			return 0;
		}
		free(value);
		sd_bus_message_unref(reply);
		sd_bus_error_free(&error);
		usleep(100000);
	}
	return -1;
}

static int wait_for_login1_session_gone(sd_bus* bus, const char* session_id)
{
	if (!bus || !session_id || (session_id[0] == '\0'))
		return -1;
	for (int attempt = 0; attempt < 50; attempt++)
	{
		sd_bus_error error = SD_BUS_ERROR_NULL;
		sd_bus_message* reply = NULL;
		const int rc = sd_bus_call_method(bus, "org.freedesktop.login1", "/org/freedesktop/login1",
		                                  "org.freedesktop.login1.Manager", "GetSession", &error,
		                                  &reply, "s", session_id);
		const int gone =
		    (rc < 0) && sd_bus_error_has_name(&error, "org.freedesktop.login1.NoSuchSession");

		sd_bus_message_unref(reply);
		sd_bus_error_free(&error);
		if (gone)
			return 0;
		usleep(100000);
	}
	return -1;
}

static int process_environment_has(pid_t pid, const char* expected)
{
	char path[64] = { 0 };
	char contents[16384] = { 0 };
	const size_t expected_length = expected ? strlen(expected) : 0;
	ssize_t count = 0;
	int fd = -1;

	if ((pid <= 1) || (expected_length == 0) ||
	    (snprintf(path, sizeof(path), "/proc/%ld/environ", (long)pid) >= (int)sizeof(path)))
		return -1;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	do
	{
		count = read(fd, contents, sizeof(contents) - 1U);
	} while ((count < 0) && (errno == EINTR));
	close(fd);
	if (count <= 0)
		return -1;
	for (size_t offset = 0; offset < (size_t)count;)
	{
		const size_t available = (size_t)count - offset;
		const size_t length = strnlen(&contents[offset], available);

		if ((length == expected_length) && (memcmp(&contents[offset], expected, length) == 0))
			return 0;
		if (length == available)
			break;
		offset += length + 1U;
	}
	return -1;
}

static int process_is_in_user_slice(void)
{
	char contents[4096] = { 0 };
	FILE* fp = fopen("/proc/self/cgroup", "r");

	if (!fp)
		return 0;
	const size_t length = fread(contents, 1, sizeof(contents) - 1U, fp);
	const int read_ok = !ferror(fp) && feof(fp);
	fclose(fp);
	return read_ok && (length > 0) && (strstr(contents, "/user.slice/") != NULL);
}

static int test_sesmand_logind_owner_crash_cleanup(void)
{
	static const char service[] = "frdp-logind-owner-crash";
	static const char expected_audit[] = "account\nsetcred-establish\nopen-session-start\n"
	                                     "close-session-start\nclose-session\nsetcred-delete\n";
	frdpTestHelper helper = { .pid = -1 };
	sd_bus_error bus_error = SD_BUS_ERROR_NULL;
	sd_bus* bus = NULL;
	pid_t requester = -1;
	pid_t agent_pid = -1;
	pid_t backend_pid = -1;
	pid_t agent_pgid = -1;
	char dir[1024] = { 0 };
	char agent_dir[1024] = { 0 };
	char service_path[1024] = { 0 };
	char audit_path[1024] = { 0 };
	char key_path[1024] = { 0 };
	char config_path[1024] = { 0 };
	char marker_path[1024] = { 0 };
	char agent_path[1024] = { 0 };
	char config[512] = { 0 };
	char contents[4096] = { 0 };
	char updated_path[4096] = { 0 };
	char session_id[64] = { 0 };
	char expected_session_env[96] = { 0 };
	char user[64] = { 0 };
	uint64_t uid = 0;
	uint64_t gid = 0;
	uint64_t groups[FRDP_IPC_MAX_AUTH_GROUPS] = { 0 };
	uint32_t group_count = 0;
	unsigned long long agent_start_ticks = 0;
	unsigned long long backend_start_ticks = 0;
	const char* previous_key_path = getenv(FRDP_AUTH_TOKEN_KEY_ENV);
	const char* current_path = getenv("PATH");
	const char* previous_marker = getenv("FRDP_AGENT_TEST_MARKER");
	char* saved_key_path = previous_key_path ? strdup(previous_key_path) : NULL;
	char* saved_path = current_path ? strdup(current_path) : NULL;
	char* saved_marker = previous_marker ? strdup(previous_marker) : NULL;
	int helper_started = 0;
	int agent_pidfd = -1;
	int backend_pidfd = -1;
	int status = 0;
	int rc = -1;
	const char* stage = "prerequisites";

	if (geteuid() != 0)
	{
		printf("frdp-sesmand login1 owner crash cleanup skipped: root required\n");
		return FRDP_TEST_SKIP;
	}
	if ((sd_bus_open_system(&bus) < 0) ||
	    (sd_bus_call_method(bus, "org.freedesktop.login1", "/org/freedesktop/login1",
	                        "org.freedesktop.DBus.Peer", "Ping", &bus_error, NULL, NULL) < 0))
	{
		printf("frdp-sesmand login1 owner crash cleanup skipped: login1 unavailable\n");
		rc = FRDP_TEST_SKIP;
		goto cleanup;
	}
	if (process_is_in_user_slice())
	{
		printf("frdp-sesmand login1 owner crash cleanup skipped: system service required\n");
		rc = FRDP_TEST_SKIP;
		goto cleanup;
	}
	if (!saved_path || (previous_key_path && !saved_key_path) || (previous_marker && !saved_marker))
		goto cleanup;
	if ((lookup_user("nobody", user, sizeof(user), &uid, &gid, groups, &group_count) != 0) ||
	    (uid == 0))
	{
		printf("frdp-sesmand login1 owner crash cleanup skipped: test account unavailable\n");
		rc = FRDP_TEST_SKIP;
		goto cleanup;
	}
	if ((make_runtime_dir(dir, sizeof(dir), "logind-owner-crash") != 0) ||
	    (make_runtime_dir(agent_dir, sizeof(agent_dir), "logind-blocking-agent") != 0) ||
	    (chown(agent_dir, (uid_t)uid, (gid_t)gid) != 0) ||
	    (snprintf(service_path, sizeof(service_path), "%s/%s", dir, service) >=
	     (int)sizeof(service_path)) ||
	    (snprintf(audit_path, sizeof(audit_path), "%s/pam-audit.log", dir) >=
	     (int)sizeof(audit_path)) ||
	    (snprintf(key_path, sizeof(key_path), "%s/auth-token.key", dir) >= (int)sizeof(key_path)) ||
	    (snprintf(config_path, sizeof(config_path), "%s/frdpd.toml", dir) >=
	     (int)sizeof(config_path)) ||
	    (snprintf(marker_path, sizeof(marker_path), "%s/agent.pid", agent_dir) >=
	     (int)sizeof(marker_path)) ||
	    (snprintf(agent_path, sizeof(agent_path), "%s/frdp-session-agent", agent_dir) >=
	     (int)sizeof(agent_path)) ||
	    (snprintf(contents, sizeof(contents),
	              "auth required %s\naccount required %s\nsession required %s\n",
	              FRDP_PAM_SESSION_ALLOW_TEST_MODULE, FRDP_PAM_SESSION_ALLOW_TEST_MODULE,
	              FRDP_PAM_SESSION_ALLOW_TEST_MODULE) >= (int)sizeof(contents)) ||
	    (snprintf(config, sizeof(config),
	              "[auth]\npam_service = \"%s\"\n[session]\nlogind_session = true\n",
	              service) >= (int)sizeof(config)) ||
	    (write_pam_fixture_file(service_path, contents) != 0) ||
	    (write_pam_fixture_file(audit_path, "") != 0) ||
	    (write_sesmand_config_body(config_path, config) != 0) ||
	    (copy_test_executable(FRDP_SESSION_AGENT_BLOCKING_BINARY, agent_path) != 0) ||
	    (snprintf(updated_path, sizeof(updated_path), "%s:%s", agent_dir, saved_path) >=
	     (int)sizeof(updated_path)) ||
	    (setenv(FRDP_AUTH_TOKEN_KEY_ENV, key_path, 1) != 0) ||
	    (setenv("PATH", updated_path, 1) != 0) ||
	    (setenv("FRDP_AGENT_TEST_MARKER", marker_path, 1) != 0))
		goto cleanup;
	stage = "helper-start";
	if (start_helper_with_pam_wrapper_config(FRDP_SESMAND_BINARY, "logind-owner-crash", dir,
	                                         service, config_path, key_path, NULL, audit_path, 0,
	                                         &helper) != 0)
		goto cleanup;
	helper_started = 1;
	(void)setenv("PATH", saved_path, 1);
	if (saved_marker)
		(void)setenv("FRDP_AGENT_TEST_MARKER", saved_marker, 1);
	else
		unsetenv("FRDP_AGENT_TEST_MARKER");
	stage = "request";
	requester = fork();
	if (requester < 0)
		goto cleanup;
	if (requester == 0)
	{
		frdpSessionResponse response = { 0 };
		const int request_rc = request_live_session(
		    helper.socket_path, user, "198.51.100.79", "logind-owner-crash", NULL, uid, gid, groups,
		    group_count, &response, "unused after manager crash");

		SecureZeroMemory(&response, sizeof(response));
		_exit(request_rc != 0 ? 0 : 1);
	}
	stage = "login1-session";
	if ((wait_for_pid_file(marker_path, &agent_pid) != 0) ||
	    ((agent_pgid = getpgid(agent_pid)) <= 1) ||
	    (pin_process_identity(agent_pid, (uid_t)uid, agent_pgid, &agent_pidfd,
	                          &agent_start_ticks) != 0) ||
	    (read_single_child_pid(agent_pid, &backend_pid) != 0) ||
	    (pin_process_identity(backend_pid, (uid_t)uid, agent_pgid, &backend_pidfd,
	                          &backend_start_ticks) != 0) ||
	    (login1_session_for_pid(bus, agent_pid, session_id, sizeof(session_id)) != 0) ||
	    (snprintf(expected_session_env, sizeof(expected_session_env), "XDG_SESSION_ID=%s",
	              session_id) >= (int)sizeof(expected_session_env)) ||
	    (process_environment_has(agent_pid, expected_session_env) != 0))
		goto cleanup;
	stage = "manager-killed";
	if ((kill(helper.pid, SIGKILL) != 0) || (wait_for_exit(helper.pid, &status) != 0))
		goto cleanup;
	helper.pid = -1;
	helper_started = 0;
	if (!WIFSIGNALED(status) || (WTERMSIG(status) != SIGKILL) ||
	    (wait_for_exit(requester, &status) != 0))
		goto cleanup;
	requester = -1;
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0))
		goto cleanup;
	stage = "owner-cleanup";
	if ((wait_for_process_gone(agent_pid) != 0) ||
	    (wait_for_file_contents_attempts(audit_path, expected_audit, 200) != 0) ||
	    (wait_for_login1_session_gone(bus, session_id) != 0))
		goto cleanup;
	stage = "manager-restart";
	if ((restart_helper_with_config(FRDP_SESMAND_BINARY, config_path, &helper) != 0) ||
	    (test_sesmand_list_empty(helper.socket_path) != 0) ||
	    (helper_dir_contains_only_listener(&helper) != 0))
		goto cleanup;
	helper_started = 1;
	rc = 0;

cleanup:
	if (rc != 0)
		fprintf(stderr, "login1 owner crash cleanup failed at stage: %s\n", stage);
	if (requester > 0)
	{
		kill(requester, SIGKILL);
		(void)waitpid(requester, NULL, 0);
	}
	if (backend_pidfd >= 0)
		(void)signal_process_pidfd(backend_pidfd, SIGKILL);
	if (agent_pidfd >= 0)
		(void)signal_process_pidfd(agent_pidfd, SIGKILL);
	if (helper_started && (stop_helper(&helper) != 0))
		rc = -1;
	else if (helper.pid > 0)
	{
		kill(helper.pid, SIGKILL);
		(void)waitpid(helper.pid, NULL, 0);
	}
	if (backend_pidfd >= 0)
		close(backend_pidfd);
	if (agent_pidfd >= 0)
		close(agent_pidfd);
	if (saved_key_path)
	{
		(void)setenv(FRDP_AUTH_TOKEN_KEY_ENV, saved_key_path, 1);
		free(saved_key_path);
	}
	else
		unsetenv(FRDP_AUTH_TOKEN_KEY_ENV);
	if (saved_path)
	{
		(void)setenv("PATH", saved_path, 1);
		free(saved_path);
	}
	if (saved_marker)
	{
		(void)setenv("FRDP_AGENT_TEST_MARKER", saved_marker, 1);
		free(saved_marker);
	}
	else
		unsetenv("FRDP_AGENT_TEST_MARKER");
	sd_bus_error_free(&bus_error);
	sd_bus_unref(bus);
	unlink(helper.socket_path);
	if (helper.dir[0])
		rmdir(helper.dir);
	unlink(agent_path);
	unlink(marker_path);
	if (agent_dir[0])
		rmdir(agent_dir);
	unlink(config_path);
	unlink(key_path);
	unlink(audit_path);
	unlink(service_path);
	if (dir[0])
		rmdir(dir);
	SecureZeroMemory(groups, sizeof(groups));
	return rc;
}
#else
static int test_authd_crash_during_pam(void)
{
	return 0;
}

static int test_sesmand_pam_session_open_failure(void)
{
	return 0;
}

static int test_sesmand_crash_during_pam_open(void)
{
	return 0;
}

static int test_sesmand_crash_during_pam_close(void)
{
	return 0;
}

static int test_sesmand_crash_after_agent_launch(void)
{
	return 0;
}

static int test_sesmand_logind_owner_crash_cleanup(void)
{
	return 0;
}
#endif

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
	if (write_sesmand_config(config_path, pam_service, 0, 0, 0) != 0)
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
	                         group_count, &opened, NULL) != 0 ||
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
	                         groups, group_count, &reconnected, NULL) != 0 ||
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
	if (write_sesmand_config(config_path, pam_service, 0, 0, 0) != 0)
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
	                         group_count, &opened, NULL) != 0 ||
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
	                         groups, group_count, &opened, NULL) != 0 ||
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
	if (write_sesmand_config(config_path, "frdpd", 0, 0, 0) != 0)
		goto cleanup_dir;
	if (start_helper_with_config(FRDP_SESMAND_BINARY, "frdp-sesmand-reload", config_path,
	                             &helper) != 0)
		goto cleanup_dir;
	if (test_sesmand_reload(
	        helper.socket_path, 1,
		        "pam_service=frdpd;max_sessions=0;max_processes=0;memory_max_mb=0;"
		        "display_backend=xvfb", NULL) != 0)
		goto cleanup;
	if (write_sesmand_config(config_path,
	                         "frdpd_reload_abcdefghijklmnopqrstuvwxyz_0123456789_ABCDEFGHIJKL",
		                         23, 77, 1536) != 0)
		goto cleanup;
	if (test_sesmand_reload(helper.socket_path, 1,
	                        "pam_service=frdpd_reload_abcdefghijklmnopqrstuvwxyz_"
		                        "0123456789_ABCDEFGHIJKL;max_sessions=23;max_processes=77;"
		                        "memory_max_mb=1536",
	                        NULL) != 0)
		goto cleanup;
	if (write_sesmand_config(config_path, "bad/service", 1, 1, 1) != 0)
		goto cleanup;
	if (test_sesmand_reload(helper.socket_path, 0, NULL, "config reload failed") != 0)
		goto cleanup;
	if (write_sesmand_config_body(config_path,
	                              "[auth]\npam_service = \"frdpd\"\n"
	                              "[clipboard]\nmode = \"text\"\n"
	                              "direction = \"bidirectional\"\n") != 0)
		goto cleanup;
	if (test_sesmand_reload(
	        helper.socket_path, 1,
		        "pam_service=frdpd;max_sessions=0;max_processes=0;memory_max_mb=0;"
		        "display_backend=xvfb", NULL) != 0)
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

static int test_sesmand_reload_session_limit(void)
{
#ifndef FRDP_XVFB_EXECUTABLE
	printf("frdp-sesmand reload session-limit test skipped: Xvfb unavailable\n");
	return 0;
#else
	static const char pam_service[] = "common-session-noninteractive";
	static const char rhost[] = "127.0.0.1";
	frdpTestHelper helper = { .pid = -1 };
	frdpSessionResponse first = { 0 };
	frdpSessionResponse second = { 0 };
	frdpSessionResponse rejected = { 0 };
	frdpSessionResponse replacement = { 0 };
	frdpSessionResponse closed = { 0 };
	frdpSessionListResponse list = { 0 };
	char dir[1024] = { 0 };
	char config_path[1024] = { 0 };
	char key_path[1024] = { 0 };
	char user[64] = { 0 };
	uint64_t uid = 0;
	uint64_t gid = 0;
	uint64_t groups[FRDP_IPC_MAX_AUTH_GROUPS] = { 0 };
	uint32_t group_count = 0;
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
		printf("frdp-sesmand reload session-limit test skipped: PAM/Xvfb prerequisite unavailable\n");
		rc = 0;
		goto cleanup;
	}
	if (make_runtime_dir(dir, sizeof(dir), "frdp-sesmand-reload-limit") != 0)
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
	if (write_sesmand_config(config_path, pam_service, 2, 0, 0) != 0)
		goto cleanup;
	stage = "identity";
	if (lookup_current_user(user, sizeof(user), &uid, &gid, groups, &group_count) != 0)
		goto cleanup;
	stage = "helper-start";
	if (start_helper_with_config(FRDP_SESMAND_BINARY, "frdp-sesmand-reload-limit", config_path,
	                             &helper) != 0)
		goto cleanup;
	helper_started = 1;
	restore_path(saved_path);
	saved_path = NULL;
	stage = "open-at-initial-limit";
	if ((request_live_session(helper.socket_path, user, rhost, "reload-limit-first", NULL, uid,
	                          gid, groups, group_count, &first, NULL) != 0) ||
	    (request_live_session(helper.socket_path, user, rhost, "reload-limit-second", NULL, uid,
	                          gid, groups, group_count, &second, NULL) != 0) ||
	    (strcmp(first.session_id, second.session_id) == 0) ||
	    (receive_sesmand_list(helper.socket_path, &list) != 0) || (list.count != 2))
		goto cleanup;
	stage = "lower-limit";
	if ((write_sesmand_config(config_path, pam_service, 1, 0, 0) != 0) ||
	    (test_sesmand_reload(helper.socket_path, 1,
	                         "pam_service=common-session-noninteractive;max_sessions=1;"
	                         "max_processes=0;memory_max_mb=0;display_backend=xvfb",
	                         NULL) != 0) ||
	    (receive_sesmand_list(helper.socket_path, &list) != 0) || (list.count != 2))
		goto cleanup;
	stage = "reject-above-lowered-limit";
	if ((request_live_session(helper.socket_path, user, rhost, "reload-limit-reject-two", NULL,
	                          uid, gid, groups, group_count, &rejected,
	                          "session limit reached") != 0) ||
	    (receive_sesmand_list(helper.socket_path, &list) != 0) || (list.count != 2))
		goto cleanup;
	stage = "close-first";
	if ((request_session_control(helper.socket_path, FRDP_IPC_SESSION_CLOSE_REQUEST,
	                             "reload-limit-close-first", first.session_id, user, &closed) != 0) ||
	    (receive_sesmand_list(helper.socket_path, &list) != 0) || (list.count != 1))
		goto cleanup;
	stage = "reject-at-lowered-limit";
	if ((request_live_session(helper.socket_path, user, rhost, "reload-limit-reject-one", NULL,
	                          uid, gid, groups, group_count, &rejected,
	                          "session limit reached") != 0) ||
	    (receive_sesmand_list(helper.socket_path, &list) != 0) || (list.count != 1))
		goto cleanup;
	stage = "below-lowered-limit";
	if ((request_session_control(helper.socket_path, FRDP_IPC_SESSION_CLOSE_REQUEST,
	                             "reload-limit-close-second", second.session_id, user, &closed) !=
	     0) ||
	    (receive_sesmand_list(helper.socket_path, &list) != 0) || (list.count != 0) ||
	    (request_live_session(helper.socket_path, user, rhost, "reload-limit-replacement", NULL,
	                          uid, gid, groups, group_count, &replacement, NULL) != 0) ||
	    (receive_sesmand_list(helper.socket_path, &list) != 0) || (list.count != 1))
		goto cleanup;
	stage = "final-cleanup";
	if ((request_session_control(helper.socket_path, FRDP_IPC_SESSION_CLOSE_REQUEST,
	                             "reload-limit-close-replacement", replacement.session_id, user,
	                             &closed) != 0) ||
	    (receive_sesmand_list(helper.socket_path, &list) != 0) || (list.count != 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (rc != 0)
		fprintf(stderr, "reload session-limit test failed at stage: %s\n", stage);
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
	SecureZeroMemory(&first, sizeof(first));
	SecureZeroMemory(&second, sizeof(second));
	SecureZeroMemory(&rejected, sizeof(rejected));
	SecureZeroMemory(&replacement, sizeof(replacement));
	SecureZeroMemory(&closed, sizeof(closed));
	return rc;
#endif
}

static int test_sesmand_component(void)
{
	frdpTestHelper helper;
	const char* stage = "start";
	int rc = -1;

	if (start_helper(FRDP_SESMAND_BINARY, "frdp-sesmand-component", &helper) != 0)
		return -1;
	stage = "health";
	if (test_helper_health(helper.socket_path, "frdp-sesmand") != 0)
		goto cleanup;
	stage = "empty list";
	if (test_sesmand_list_empty(helper.socket_path) != 0)
		goto cleanup;
	stage = "unknown session";
	if (test_sesmand_rejects_unknown_session(helper.socket_path) != 0)
		goto cleanup;
	stage = "unknown disconnect session";
	if (test_sesmand_rejects_unknown_disconnect_session(helper.socket_path) != 0)
		goto cleanup;
	stage = "unterminated request";
	if (test_sesmand_rejects_unterminated_request(helper.socket_path) != 0)
		goto cleanup;
	stage = "legacy v1 open";
	if (test_sesmand_rejects_legacy_v1_open_request(helper.socket_path) != 0)
		goto cleanup;
	stage = "legacy v2 missing account";
	if (test_sesmand_rejects_legacy_v2_missing_posix_account(helper.socket_path) != 0)
		goto cleanup;
	stage = "legacy v2 account mismatch";
	if (test_sesmand_rejects_legacy_v2_posix_account_mismatch(helper.socket_path) != 0)
		goto cleanup;
	stage = "missing authorization";
	if (test_sesmand_rejects_missing_authorization(helper.socket_path) != 0)
		goto cleanup;
	stage = "explicit reconnect authorization";
	if (test_sesmand_requires_authorization_for_explicit_reconnect(helper.socket_path) != 0)
		goto cleanup;
	stage = "invalid authorization";
	if (test_sesmand_rejects_invalid_authorization(helper.socket_path) != 0)
		goto cleanup;
	stage = "bad length";
	if (test_sesmand_rejects_bad_length(helper.socket_path) != 0)
		goto cleanup;
	stage = "oversized payload";
	if (test_sesmand_rejects_oversized_payload(helper.socket_path) != 0)
		goto cleanup;
	stage = "truncated clients";
	if (test_sesmand_survives_truncated_clients(helper.socket_path) != 0)
		goto cleanup;
	stage = "slow complete client";
	if (test_sesmand_handles_slow_complete_client(helper.socket_path) != 0)
		goto cleanup;
	stage = "concurrent requests";
	if (run_concurrent_requests(helper.socket_path, test_sesmand_list_empty,
	                            FRDP_IPC_CONCURRENT_CLIENTS) != 0)
		goto cleanup;
	stage = "reload payload";
	if (test_sesmand_rejects_reload_payload(helper.socket_path) != 0)
		goto cleanup;
	stage = "reload";
	if (test_sesmand_reload(helper.socket_path, 1, "accepted", NULL) != 0)
		goto cleanup;
	/* A final list request proves the registry and service loop remained healthy. */
	stage = "post-reload list";
	if (test_sesmand_list_empty(helper.socket_path) != 0)
		goto cleanup;
	stage = "health rate limit";
	if ((test_helper_health_rate_limit(helper.socket_path, "frdp-sesmand") != 0) ||
	    (test_sesmand_list_empty(helper.socket_path) != 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (rc != 0)
		fprintf(stderr, "sesmand component test failed at stage: %s\n", stage);
	if (stop_helper(&helper) != 0)
		rc = -1;
	return rc;
}

#if defined(__linux__)
static int connect_unvalidated_socket(const char* socket_path)
{
	struct sockaddr_un addr = { 0 };
	struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
	int fd = -1;

	if (!socket_path || (strlen(socket_path) >= sizeof(addr.sun_path)))
		return -1;
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);
	if ((setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) ||
	    (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) ||
	    (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0))
	{
		close(fd);
		return -1;
	}
	return fd;
}

static int run_cross_uid_request(const char* socket_path, int auth_helper, uid_t uid, gid_t gid)
{
	int fd = -1;
	int rc = -1;

	if ((setgroups(0, NULL) != 0) || (setgid(gid) != 0) || (setuid(uid) != 0) ||
	    (geteuid() != uid))
		return -1;
	fd = connect_unvalidated_socket(socket_path);
	if (fd < 0)
		return -1;
	if (auth_helper)
	{
		frdpAuthResponse response = { 0 };

		if ((frdp_ipc_recv_auth_response_v2(fd, &response) == 0) && !response.success &&
		    (strcmp(response.error, "unauthorized IPC peer") == 0))
			rc = 0;
		SecureZeroMemory(&response, sizeof(response));
	}
	else
		rc = receive_session_response(fd, 0, "unauthorized IPC peer");
	frdp_ipc_close(fd);
	return rc;
}

static int test_helper_rejects_different_uid(const char* binary, const char* name,
	                                         int auth_helper, uid_t uid, gid_t gid)
{
	frdpTestHelper helper = { .pid = -1 };
	pid_t child = -1;
	int status = 0;
	int permissions_changed = 0;
	int rc = -1;

	if (start_helper(binary, name, &helper) != 0)
		return -1;
	if (chmod(helper.dir, 0711) != 0)
		goto cleanup;
	permissions_changed = 1;
	if (chmod(helper.socket_path, 0666) != 0)
		goto cleanup;
	child = fork();
	if (child < 0)
		goto cleanup;
	if (child == 0)
		_exit(run_cross_uid_request(helper.socket_path, auth_helper, uid, gid) == 0 ? 0 : 1);
	{
		pid_t waited = -1;

		do
			waited = waitpid(child, &status, 0);
		while ((waited < 0) && (errno == EINTR));

		if (waited == child)
			child = -1;
		if ((waited < 0) || !WIFEXITED(status) || (WEXITSTATUS(status) != 0))
			goto cleanup;
	}
	if ((chmod(helper.socket_path, 0600) != 0) || (chmod(helper.dir, 0700) != 0))
		goto cleanup;
	permissions_changed = 0;
	if ((test_helper_health(helper.socket_path, auth_helper ? "frdp-authd" : "frdp-sesmand") !=
	     0) ||
	    (auth_helper ? (test_authd_rejects_bad_length(helper.socket_path) != 0)
	                 : (test_sesmand_list_empty(helper.socket_path) != 0)))
		goto cleanup;
	rc = 0;

cleanup:
	if (child > 0)
	{
		kill(child, SIGKILL);
		(void)waitpid(child, NULL, 0);
	}
	if (permissions_changed)
	{
		(void)chmod(helper.socket_path, 0600);
		(void)chmod(helper.dir, 0700);
	}
	if (stop_helper(&helper) != 0)
		rc = -1;
	return rc;
}
#endif

static int test_helpers_reject_different_uid(void)
{
#if !defined(__linux__)
	printf("helper cross-UID rejection skipped: Linux peer credentials unavailable\n");
	return 0;
#else
	struct passwd* pwd = NULL;
	uid_t peer_uid = (uid_t)65534;
	gid_t peer_gid = (gid_t)65534;

	if (geteuid() != 0)
	{
		printf("helper cross-UID rejection skipped: root required for UID drop\n");
		return 0;
	}
	pwd = getpwnam("nobody");
	if (pwd && (pwd->pw_uid != 0))
	{
		peer_uid = pwd->pw_uid;
		peer_gid = pwd->pw_gid;
	}
	if ((peer_uid == 0) ||
	    (test_helper_rejects_different_uid(FRDP_AUTHD_BINARY, "frdp-authd-cross-uid", 1,
	                                       peer_uid, peer_gid) != 0) ||
	    (test_helper_rejects_different_uid(FRDP_SESMAND_BINARY, "frdp-sesmand-cross-uid", 0,
	                                       peer_uid, peer_gid) != 0))
		return -1;
	return 0;
#endif
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
	if ((argc > 1) && (strcmp(argv[1], "login1-owner-crash") == 0))
		return test_sesmand_logind_owner_crash_cleanup();

	if (test_authd_component() != 0)
	{
		printf("frdp-authd IPC component test failed\n");
		return -1;
	}
	if (test_authd_crash_restart_health() != 0)
	{
		printf("frdp-authd crash/restart health test failed\n");
		return -1;
	}
	if (test_sesmand_component() != 0)
	{
		printf("frdp-sesmand IPC component test failed\n");
		return -1;
	}
	if (test_helpers_reject_different_uid() != 0)
	{
		printf("helper cross-UID rejection test failed\n");
		return -1;
	}
	if (test_authd_rate_limit() != 0)
	{
		printf("frdp-authd IPC rate-limit test failed\n");
		return -1;
	}
	if (test_authd_account_and_source_failure_limit() != 0)
	{
		printf("frdp-authd account/source failure-limit test failed\n");
		return -1;
	}
	if (test_authd_real_pam_provider() != 0)
	{
		printf("frdp-authd real PAM provider test failed\n");
		return -1;
	}
	if (test_authd_crash_during_pam() != 0)
	{
		printf("frdp-authd in-flight PAM crash test failed\n");
		return -1;
	}
	if (test_sesmand_pam_session_open_failure() != 0)
	{
		printf("frdp-sesmand PAM session-open failure test failed\n");
		return -1;
	}
	if (test_sesmand_crash_during_pam_open() != 0)
	{
		printf("frdp-sesmand in-flight PAM open crash test failed\n");
		return -1;
	}
	if (test_sesmand_crash_after_agent_launch() != 0)
	{
		printf("frdp-sesmand post-launch crash test failed\n");
		return -1;
	}
	if (test_sesmand_crash_during_pam_close() != 0)
	{
		printf("frdp-sesmand in-flight PAM close crash test failed\n");
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
	if (test_sesmand_reload_session_limit() != 0)
	{
		printf("frdp-sesmand reload session-limit test failed\n");
		return -1;
	}
	if (test_frdpd_live_helper_topology() != 0)
	{
		printf("frdpd live helper topology test failed\n");
		return -1;
	}
	return 0;
}

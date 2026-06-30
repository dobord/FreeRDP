#include "ipc/frdp-ipc.h"

#include <errno.h>
#include <fcntl.h>
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
	frdpIpcHeader header = { 0 };

	header.type = type;
	header.payload_len = payload_len;
	return frdp_ipc_send(fd, &header, sizeof(header));
}

static int receive_auth_failure(int fd, const char* expected_error)
{
	frdpIpcHeader header = { 0 };
	frdpAuthResponse response = { 0 };

	if (frdp_ipc_recv(fd, &header, sizeof(header)) != (int)sizeof(header))
		return -1;
	if ((header.type != FRDP_IPC_AUTH_RESPONSE) ||
	    (header.payload_len != sizeof(response)))
		return -1;
	if (frdp_ipc_recv(fd, &response, sizeof(response)) != (int)sizeof(response))
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
	frdpIpcHeader header = { 0 };
	frdpSessionResponse response = { 0 };

	if (frdp_ipc_recv(fd, &header, sizeof(header)) != (int)sizeof(header))
		return -1;
	if ((header.type != FRDP_IPC_SESSION_RESPONSE) ||
	    (header.payload_len != sizeof(response)))
		return -1;
	if (frdp_ipc_recv(fd, &response, sizeof(response)) != (int)sizeof(response))
		return -1;
	if (!!response.success != !!expected_success)
		return -1;
	if (!memchr(response.error, '\0', sizeof(response.error)))
		return -1;
	if (expected_error && strcmp(response.error, expected_error) != 0)
		return -1;
	return 0;
}

static int receive_reload_response(int fd, int expected_success, const char* expected_message,
                                   const char* expected_error)
{
	frdpIpcHeader header = { 0 };
	frdpControlResponse response = { 0 };

	if (frdp_ipc_recv(fd, &header, sizeof(header)) != (int)sizeof(header))
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
	if (test_authd_rejects_unterminated_request(helper.socket_path) != 0)
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
	if (frdp_ipc_recv(fd, &header, sizeof(header)) != (int)sizeof(header))
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
	if (send_header(fd, FRDP_IPC_SESSION_CLOSE_REQUEST, sizeof(request)) != 0 ||
	    frdp_ipc_send(fd, &request, sizeof(request)) != 0)
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
	if (send_header(fd, FRDP_IPC_SESSION_CLOSE_REQUEST, sizeof(request)) != 0 ||
	    frdp_ipc_send(fd, &request, sizeof(request)) != 0)
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
	snprintf(request.user, sizeof(request.user), "nobody");
	if (send_header(fd, FRDP_IPC_SESSION_REQUEST_V2, sizeof(request)) != 0 ||
	    frdp_ipc_send(fd, &request, sizeof(request)) != 0)
		goto cleanup;
	rc = receive_session_response(fd, 0, "missing POSIX account");

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
	snprintf(request.user, sizeof(request.user), "nobody");
	request.has_posix_account = 1;
	request.uid = 0;
	request.gid = 0;
	if (send_header(fd, FRDP_IPC_SESSION_REQUEST_V2, sizeof(request)) != 0 ||
	    frdp_ipc_send(fd, &request, sizeof(request)) != 0)
		goto cleanup;
	rc = receive_session_response(fd, 0, "POSIX account mismatch");

cleanup:
	frdp_ipc_close(fd);
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
	if (test_sesmand_rejects_bad_length(helper.socket_path) != 0)
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

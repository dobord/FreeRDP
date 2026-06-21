#include "ipc/frdp-ipc.h"

#include <errno.h>
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

#ifndef CMAKE_CURRENT_BINARY_DIR
#error "CMAKE_CURRENT_BINARY_DIR is not defined"
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
	const int rc = snprintf(dir, dir_size, "%s/%s-XXXXXX", CMAKE_CURRENT_BINARY_DIR, name);

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

static int start_helper(const char* binary, const char* name, frdpTestHelper* helper)
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
	if (test_sesmand_rejects_bad_length(helper.socket_path) != 0)
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
	return 0;
}

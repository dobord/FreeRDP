#include "ipc/frdp-ipc.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef FRDPCTL_BINARY
#error "FRDPCTL_BINARY is not defined"
#endif

typedef int (*frdpctlIpcHandler)(int fd);

typedef struct
{
	int status;
	char stdout_data[4096];
	char stderr_data[4096];
} frdpctlRunResult;

static int write_all(int fd, const void* data, size_t len)
{
	const char* p = data;
	size_t offset = 0;

	while (offset < len)
	{
		const ssize_t rc = write(fd, p + offset, len - offset);
		if (rc <= 0)
			return -1;
		offset += (size_t)rc;
	}
	return 0;
}

static int read_exact(int fd, void* data, size_t len)
{
	char* p = data;
	size_t offset = 0;

	while (offset < len)
	{
		const ssize_t rc = read(fd, p + offset, len - offset);
		if (rc <= 0)
			return -1;
		offset += (size_t)rc;
	}
	return 0;
}

static int read_file_to_string(const char* path, char* dst, size_t size)
{
	int fd = -1;
	size_t offset = 0;

	if (!path || !dst || (size == 0))
		return -1;
	dst[0] = '\0';
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	while (offset + 1 < size)
	{
		const ssize_t rc = read(fd, dst + offset, size - offset - 1);
		if (rc == 0)
			break;
		if (rc < 0)
		{
			if (errno == EINTR)
				continue;
			close(fd);
			return -1;
		}
		offset += (size_t)rc;
	}
	close(fd);
	dst[offset] = '\0';
	return 0;
}

static int send_list_response(int fd)
{
	frdpSessionListResponse response = { 0 };

	response.success = 1;
	response.count = 2;
	snprintf(response.entries[0].session_id, sizeof(response.entries[0].session_id), "session-1");
	snprintf(response.entries[0].user, sizeof(response.entries[0].user), "alice");
	snprintf(response.entries[0].display, sizeof(response.entries[0].display), ":20");
	response.entries[0].agent_pid = 1001;
	snprintf(response.entries[1].session_id, sizeof(response.entries[1].session_id), "session-2");
	snprintf(response.entries[1].user, sizeof(response.entries[1].user), "bob");
	snprintf(response.entries[1].display, sizeof(response.entries[1].display), ":21");
	response.entries[1].agent_pid = 1002;

	if (frdp_ipc_send_header(fd, FRDP_IPC_SESSION_LIST_RESPONSE, sizeof(response)) != 0)
		return -1;
	return write_all(fd, &response, sizeof(response));
}

static int send_control_list_response(int fd)
{
	frdpSessionListResponse response = { 0 };

	response.success = 1;
	response.count = 1;
	snprintf(response.entries[0].session_id, sizeof(response.entries[0].session_id), "session\n1");
	snprintf(response.entries[0].user, sizeof(response.entries[0].user), "al\tice");
	snprintf(response.entries[0].display, sizeof(response.entries[0].display), ":\\20");
	response.entries[0].agent_pid = 1003;

	if (frdp_ipc_send_header(fd, FRDP_IPC_SESSION_LIST_RESPONSE, sizeof(response)) != 0)
		return -1;
	return write_all(fd, &response, sizeof(response));
}

static int handle_list_request(int fd)
{
	frdpIpcHeader header = { 0 };

	if (frdp_ipc_recv_header(fd, &header) != (int)sizeof(header))
		return -1;
	if (header.type != FRDP_IPC_SESSION_LIST_REQUEST)
		return -1;
	if (header.payload_len != 0)
		return -1;
	return send_list_response(fd);
}

static int handle_control_list_request(int fd)
{
	frdpIpcHeader header = { 0 };

	if (frdp_ipc_recv_header(fd, &header) != (int)sizeof(header))
		return -1;
	if (header.type != FRDP_IPC_SESSION_LIST_REQUEST)
		return -1;
	if (header.payload_len != 0)
		return -1;
	return send_control_list_response(fd);
}

static int handle_close_request(int fd)
{
	frdpIpcHeader header = { 0 };
	frdpSessionRequest request = { 0 };
	frdpSessionResponse response = { 0 };

	if (frdp_ipc_recv_header(fd, &header) != (int)sizeof(header))
		return -1;
	if (header.type != FRDP_IPC_SESSION_CLOSE_REQUEST)
		return -1;
	if (header.payload_len != FRDP_IPC_SESSION_CLOSE_REQUEST_WIRE_SIZE)
		return -1;
	if (frdp_ipc_recv_session_close_request_payload(fd, &request, header.payload_len) != 0)
		return -1;
	request.session_id[sizeof(request.session_id) - 1] = '\0';
	request.correlation_id[sizeof(request.correlation_id) - 1] = '\0';
	if (strcmp(request.session_id, "session-1") != 0)
		return -1;
	if (strncmp(request.correlation_id, "frdpctl-", strlen("frdpctl-")) != 0)
		return -1;

	response.success = 1;
	snprintf(response.session_id, sizeof(response.session_id), "%s", request.session_id);
	return frdp_ipc_send_session_response(fd, &response);
}

static int handle_close_control_success_request(int fd)
{
	frdpIpcHeader header = { 0 };
	frdpSessionRequest request = { 0 };
	frdpSessionResponse response = { 0 };

	if (frdp_ipc_recv_header(fd, &header) != (int)sizeof(header))
		return -1;
	if (header.type != FRDP_IPC_SESSION_CLOSE_REQUEST)
		return -1;
	if (header.payload_len != FRDP_IPC_SESSION_CLOSE_REQUEST_WIRE_SIZE)
		return -1;
	if (frdp_ipc_recv_session_close_request_payload(fd, &request, header.payload_len) != 0)
		return -1;

	response.success = 1;
	snprintf(response.session_id, sizeof(response.session_id), "session\n1");
	return frdp_ipc_send_session_response(fd, &response);
}

static int handle_close_failure_request(int fd)
{
	frdpIpcHeader header = { 0 };
	frdpSessionRequest request = { 0 };
	frdpSessionResponse response = { 0 };

	if (frdp_ipc_recv_header(fd, &header) != (int)sizeof(header))
		return -1;
	if (header.type != FRDP_IPC_SESSION_CLOSE_REQUEST)
		return -1;
	if (header.payload_len != FRDP_IPC_SESSION_CLOSE_REQUEST_WIRE_SIZE)
		return -1;
	if (frdp_ipc_recv_session_close_request_payload(fd, &request, header.payload_len) != 0)
		return -1;

	response.success = 0;
	snprintf(response.error, sizeof(response.error), "denied\nbad\\path");
	return frdp_ipc_send_session_response(fd, &response);
}

static int handle_reload_request(int fd)
{
	frdpIpcHeader header = { 0 };
	frdpControlResponse response = { 0 };

	if (frdp_ipc_recv_header(fd, &header) != (int)sizeof(header))
		return -1;
	if (header.type != FRDP_IPC_SESSION_RELOAD_REQUEST)
		return -1;
	if (header.payload_len != 0)
		return -1;

	response.success = 1;
	snprintf(response.message, sizeof(response.message), "accepted");
	if (frdp_ipc_send_header(fd, FRDP_IPC_SESSION_RELOAD_RESPONSE, sizeof(response)) != 0)
		return -1;
	return write_all(fd, &response, sizeof(response));
}

static int handle_reload_failure_request(int fd)
{
	frdpIpcHeader header = { 0 };
	frdpControlResponse response = { 0 };

	if (frdp_ipc_recv_header(fd, &header) != (int)sizeof(header))
		return -1;
	if (header.type != FRDP_IPC_SESSION_RELOAD_REQUEST)
		return -1;
	if (header.payload_len != 0)
		return -1;

	response.success = 0;
	snprintf(response.error, sizeof(response.error), "busy\ntry later");
	if (frdp_ipc_send_header(fd, FRDP_IPC_SESSION_RELOAD_RESPONSE, sizeof(response)) != 0)
		return -1;
	return write_all(fd, &response, sizeof(response));
}

static int make_socket(char* dir, size_t dir_size, char* path, size_t path_size)
{
	int fd = -1;
	struct sockaddr_un addr = { 0 };

	const int dir_rc = snprintf(dir, dir_size, "%s/frdpctl-ipc-XXXXXX", CMAKE_CURRENT_BINARY_DIR);
	if ((dir_rc < 0) || ((size_t)dir_rc >= dir_size))
		return -1;
	if (!mkdtemp(dir))
		return -1;
	if (chmod(dir, 0700) != 0)
		goto fail;
	const int path_rc = snprintf(path, path_size, "%s/sesmand.sock", dir);
	if ((path_rc < 0) || ((size_t)path_rc >= path_size))
		goto fail;
	if (strlen(path) >= sizeof(addr.sun_path))
		goto fail;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		goto fail;
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
	if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
		goto fail;
	if (chmod(path, 0600) != 0)
		goto fail;
	if (listen(fd, 1) != 0)
		goto fail;
	return fd;

fail:
	if (fd >= 0)
		close(fd);
	if (path[0] != '\0')
		unlink(path);
	if (dir[0] != '\0')
		rmdir(dir);
	return -1;
}

static int run_with_server(char** argv, size_t socket_arg_index, frdpctlIpcHandler handler,
                           frdpctlRunResult* result)
{
	int server_fd = -1;
	int client_fd = -1;
	int stdout_fd = -1;
	int stderr_fd = -1;
	pid_t pid = -1;
	int status = 0;
	int rc = -1;
	char dir[1024] = { 0 };
	char socket_path[108] = { 0 };
	char stdout_path[1024] = { 0 };
	char stderr_path[1024] = { 0 };
	struct pollfd pfd = { 0 };

	if (!result)
		return -1;
	memset(result, 0, sizeof(*result));

	server_fd = make_socket(dir, sizeof(dir), socket_path, sizeof(socket_path));
	if (server_fd < 0)
		goto cleanup;
	argv[socket_arg_index] = socket_path;

	const int stdout_rc = snprintf(stdout_path, sizeof(stdout_path), "%s/stdout", dir);
	const int stderr_rc = snprintf(stderr_path, sizeof(stderr_path), "%s/stderr", dir);
	if ((stdout_rc < 0) || ((size_t)stdout_rc >= sizeof(stdout_path)) || (stderr_rc < 0) ||
	    ((size_t)stderr_rc >= sizeof(stderr_path)))
		goto cleanup;
	stdout_fd = open(stdout_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	stderr_fd = open(stderr_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	if ((stdout_fd < 0) || (stderr_fd < 0))
		goto cleanup;

	pid = fork();
	if (pid < 0)
		goto cleanup;
	if (pid == 0)
	{
		close(server_fd);
		dup2(stdout_fd, STDOUT_FILENO);
		dup2(stderr_fd, STDERR_FILENO);
		close(stdout_fd);
		close(stderr_fd);
		execv(FRDPCTL_BINARY, argv);
		_exit(127);
	}

	close(stdout_fd);
	stdout_fd = -1;
	close(stderr_fd);
	stderr_fd = -1;

	pfd.fd = server_fd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 5000) <= 0)
		goto cleanup;
	client_fd = accept(server_fd, NULL, NULL);
	if (client_fd < 0)
		goto cleanup;
	if (handler(client_fd) != 0)
		goto cleanup;
	close(client_fd);
	client_fd = -1;
	close(server_fd);
	server_fd = -1;

	if (waitpid(pid, &status, 0) != pid)
		goto cleanup;
	pid = -1;
	if (!WIFEXITED(status))
		goto cleanup;
	result->status = WEXITSTATUS(status);
	if (read_file_to_string(stdout_path, result->stdout_data, sizeof(result->stdout_data)) != 0)
		goto cleanup;
	if (read_file_to_string(stderr_path, result->stderr_data, sizeof(result->stderr_data)) != 0)
		goto cleanup;
	rc = 0;

cleanup:
	if (pid > 0)
	{
		kill(pid, SIGTERM);
		waitpid(pid, NULL, 0);
	}
	if (client_fd >= 0)
		close(client_fd);
	if (server_fd >= 0)
		close(server_fd);
	if (stdout_fd >= 0)
		close(stdout_fd);
	if (stderr_fd >= 0)
		close(stderr_fd);
	if (stdout_path[0] != '\0')
		unlink(stdout_path);
	if (stderr_path[0] != '\0')
		unlink(stderr_path);
	if (socket_path[0] != '\0')
		unlink(socket_path);
	if (dir[0] != '\0')
		rmdir(dir);
	return rc;
}

static int test_status(void)
{
	frdpctlRunResult result = { 0 };
	char* argv[] = { FRDPCTL_BINARY, "status", "--socket", NULL, NULL };

	if (run_with_server(argv, 3, handle_list_request, &result) != 0)
		return -1;
	if (result.status != 0)
		return -1;
	if (strcmp(result.stdout_data, "Session manager: reachable\nActive sessions: 2\n") != 0)
		return -1;
	if (strcmp(result.stderr_data, "") != 0)
		return -1;
	return 0;
}

static int test_list_sessions(void)
{
	frdpctlRunResult result = { 0 };
	char expected[1024] = { 0 };
	char* argv[] = { FRDPCTL_BINARY, "list-sessions", "--socket", NULL, NULL };

	if (run_with_server(argv, 3, handle_list_request, &result) != 0)
		return -1;
	if (result.status != 0)
		return -1;
	snprintf(expected, sizeof(expected), "%-36s  %-20s  %-8s  %-8s\n", "SESSION", "USER",
	         "DISPLAY", "PID");
	snprintf(expected + strlen(expected), sizeof(expected) - strlen(expected),
	         "%-36s  %-20s  %-8s  %-8d\n", "session-1", "alice", ":20", 1001);
	snprintf(expected + strlen(expected), sizeof(expected) - strlen(expected),
	         "%-36s  %-20s  %-8s  %-8d\n", "session-2", "bob", ":21", 1002);
	if (strcmp(result.stdout_data, expected) != 0)
		return -1;
	if (strcmp(result.stderr_data, "") != 0)
		return -1;
	return 0;
}

static int test_list_sessions_escapes_fields(void)
{
	frdpctlRunResult result = { 0 };
	char expected[1024] = { 0 };
	char* argv[] = { FRDPCTL_BINARY, "list-sessions", "--socket", NULL, NULL };

	if (run_with_server(argv, 3, handle_control_list_request, &result) != 0)
		return -1;
	if (result.status != 0)
		return -1;
	snprintf(expected, sizeof(expected), "%-36s  %-20s  %-8s  %-8s\n", "SESSION", "USER",
	         "DISPLAY", "PID");
	snprintf(expected + strlen(expected), sizeof(expected) - strlen(expected),
	         "%-36s  %-20s  %-8s  %-8d\n", "session\\x0a1", "al\\x09ice", ":\\\\20", 1003);
	if (strcmp(result.stdout_data, expected) != 0)
		return -1;
	if (strcmp(result.stderr_data, "") != 0)
		return -1;
	return 0;
}

static int test_kill_session(void)
{
	frdpctlRunResult result = { 0 };
	char* argv[] = { FRDPCTL_BINARY, "kill-session", "session-1", "--socket", NULL, NULL };

	if (run_with_server(argv, 4, handle_close_request, &result) != 0)
		return -1;
	if (result.status != 0)
		return -1;
	if (strcmp(result.stdout_data, "Closed session session-1\n") != 0)
		return -1;
	if (strcmp(result.stderr_data, "") != 0)
		return -1;
	return 0;
}

static int test_kill_session_escapes_success(void)
{
	frdpctlRunResult result = { 0 };
	char* argv[] = { FRDPCTL_BINARY, "kill-session", "session-1", "--socket", NULL, NULL };

	if (run_with_server(argv, 4, handle_close_control_success_request, &result) != 0)
		return -1;
	if (result.status != 0)
		return -1;
	if (strcmp(result.stdout_data, "Closed session session\\x0a1\n") != 0)
		return -1;
	if (strcmp(result.stderr_data, "") != 0)
		return -1;
	return 0;
}

static int test_kill_session_escapes_error(void)
{
	frdpctlRunResult result = { 0 };
	char* argv[] = { FRDPCTL_BINARY, "kill-session", "session-1", "--socket", NULL, NULL };

	if (run_with_server(argv, 4, handle_close_failure_request, &result) != 0)
		return -1;
	if (result.status != 4)
		return -1;
	if (strcmp(result.stdout_data, "") != 0)
		return -1;
	if (strcmp(result.stderr_data, "session close failed: denied\\x0abad\\\\path\n") != 0)
		return -1;
	return 0;
}

static int test_reload(void)
{
	frdpctlRunResult result = { 0 };
	char* argv[] = { FRDPCTL_BINARY, "reload", "--socket", NULL, NULL };

	if (run_with_server(argv, 3, handle_reload_request, &result) != 0)
		return -1;
	if (result.status != 0)
		return -1;
	if (strcmp(result.stdout_data, "Reload accepted\n") != 0)
		return -1;
	if (strcmp(result.stderr_data, "") != 0)
		return -1;
	return 0;
}

static int test_reload_escapes_error(void)
{
	frdpctlRunResult result = { 0 };
	char* argv[] = { FRDPCTL_BINARY, "reload", "--socket", NULL, NULL };

	if (run_with_server(argv, 3, handle_reload_failure_request, &result) != 0)
		return -1;
	if (result.status != 4)
		return -1;
	if (strcmp(result.stdout_data, "") != 0)
		return -1;
	if (strcmp(result.stderr_data, "reload failed: busy\\x0atry later\n") != 0)
		return -1;
	return 0;
}

int TestFreeRDPFrdpCtlIpc(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if (test_status() != 0)
		return -1;
	if (test_list_sessions() != 0)
		return -1;
	if (test_list_sessions_escapes_fields() != 0)
		return -1;
	if (test_kill_session() != 0)
		return -1;
	if (test_kill_session_escapes_success() != 0)
		return -1;
	if (test_kill_session_escapes_error() != 0)
		return -1;
	if (test_reload() != 0)
		return -1;
	if (test_reload_escapes_error() != 0)
		return -1;
	return 0;
}

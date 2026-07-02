#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ipc/frdp-ipc.h"

#ifndef FRDP_SESSION_AGENT_BINARY
#error "FRDP_SESSION_AGENT_BINARY is not defined"
#endif

#define TEST_CORRELATION_ID "agent-stop-test"
#define TEST_SESSION_ID "agent-stop-session"

static int wait_for_ready(int fd)
{
	struct pollfd pfd;
	char marker = 0;

	for (int attempt = 0; attempt < 100; attempt++)
	{
		memset(&pfd, 0, sizeof(pfd));
		pfd.fd = fd;
		pfd.events = POLLIN | POLLHUP;
		const int rc = poll(&pfd, 1, 100);

		if (rc < 0)
		{
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (rc == 0)
			continue;
		if ((pfd.revents & POLLIN) == 0)
			return -1;
		if (read(fd, &marker, sizeof(marker)) != (ssize_t)sizeof(marker))
			return -1;
		return marker == 'R' ? 0 : -1;
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

static int display_number_is_free(long display_number)
{
	char path[128] = { 0 };
	struct stat st;

	snprintf(path, sizeof(path), "/tmp/.X%ld-lock", display_number);
	if (lstat(path, &st) == 0 || errno != ENOENT)
		return 0;
	snprintf(path, sizeof(path), "/tmp/.X11-unix/X%ld", display_number);
	if (lstat(path, &st) == 0 || errno != ENOENT)
		return 0;
	return 1;
}

static int choose_display(char* display, size_t display_size)
{
	const long base = 18000L + ((long)getpid() % 1000L) * 10L;

	for (long offset = 0; offset < 200; offset++)
	{
		const long display_number = base + offset;

		if (!display_number_is_free(display_number))
			continue;
		if (snprintf(display, display_size, ":%ld", display_number) >= (int)display_size)
			return -1;
		return 0;
	}
	return -1;
}

static int create_control_socket(char* socket_dir, size_t socket_dir_size, char* socket_path,
                                 size_t socket_path_size)
{
	int fd = -1;
	mode_t old_umask;
	struct sockaddr_un addr;

	if (snprintf(socket_dir, socket_dir_size, "/tmp/frdp-agent-XXXXXX") >= (int)socket_dir_size)
		return -1;
	if (!mkdtemp(socket_dir))
		return -1;
	if (chmod(socket_dir, 0700) != 0)
		return -1;
	if (snprintf(socket_path, socket_path_size, "%s/control.sock", socket_dir) >=
	    (int)socket_path_size)
		return -1;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

	old_umask = umask(0177);
	if (bind(fd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
	{
		umask(old_umask);
		close(fd);
		return -1;
	}
	umask(old_umask);

	if (chmod(socket_path, 0600) != 0 || listen(fd, 8) != 0)
	{
		close(fd);
		unlink(socket_path);
		return -1;
	}
	return fd;
}

static int send_agent_resize(const char* socket_path, uint32_t width, uint32_t height,
                             int expect_response)
{
	int fd = -1;
	frdpAgentResizeRequest request;
	frdpAgentResizeResponse response;

	memset(&request, 0, sizeof(request));
	memset(&response, 0, sizeof(response));

	fd = frdp_ipc_connect(socket_path);
	if (fd < 0)
		return -1;

	snprintf(request.correlation_id, sizeof(request.correlation_id), "%s", TEST_CORRELATION_ID);
	snprintf(request.session_id, sizeof(request.session_id), "%s", TEST_SESSION_ID);
	request.width = width;
	request.height = height;
	request.color_depth = 24;

	if (frdp_ipc_send_agent_resize_request(fd, &request) != 0)
	{
		frdp_ipc_close(fd);
		return expect_response ? -1 : 0;
	}
	if (frdp_ipc_recv_agent_resize_response(fd, &response) != 0)
	{
		frdp_ipc_close(fd);
		return expect_response ? -1 : 0;
	}
	if (!expect_response)
	{
		frdp_ipc_close(fd);
		return -1;
	}
	frdp_ipc_close(fd);

	if (!response.success || response.width != width || response.height != height)
		return -1;
	if (strcmp(response.correlation_id, TEST_CORRELATION_ID) != 0 ||
	    strcmp(response.session_id, TEST_SESSION_ID) != 0)
		return -1;
	return 0;
}

int TestFreeRDPFrdpAgentStop(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	char socket_dir[64] = { 0 };
	char socket_path[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	int control_fd = -1;
	int ready_pipe[2] = { -1, -1 };
	pid_t pid = -1;
	int status = 0;
	int rc = -1;
	int resize_checked = 0;

	if (pipe(ready_pipe) != 0)
		return -1;
	control_fd = create_control_socket(socket_dir, sizeof(socket_dir), socket_path, sizeof(socket_path));
	if (control_fd < 0)
		goto cleanup;

	pid = fork();
	if (pid < 0)
		goto cleanup;
	if (pid == 0)
	{
		char control_fd_str[32] = { 0 };
		char ready_fd[32] = { 0 };
		char display[32] = { 0 };

		setpgid(0, 0);
		close(ready_pipe[0]);
		snprintf(ready_fd, sizeof(ready_fd), "%d", ready_pipe[1]);
		if (choose_display(display, sizeof(display)) != 0)
			_exit(126);
		snprintf(control_fd_str, sizeof(control_fd_str), "%d", control_fd);
		setenv("FRDP_AGENT_READY_FD", ready_fd, 1);
		setenv("FRDP_AGENT_CONTROL_FD", control_fd_str, 1);
		setenv("DISPLAY", display, 1);
		setenv("FRDP_DISPLAY", display, 1);
		setenv("FRDP_GEOMETRY", "64x64x24", 1);
		setenv("FRDP_CORRELATION_ID", TEST_CORRELATION_ID, 1);
		setenv("FRDP_SESSION_ID", TEST_SESSION_ID, 1);
		execl(FRDP_SESSION_AGENT_BINARY, FRDP_SESSION_AGENT_BINARY, (char*)NULL);
		_exit(127);
	}

	close(ready_pipe[1]);
	ready_pipe[1] = -1;
	close(control_fd);
	control_fd = -1;
	if (wait_for_ready(ready_pipe[0]) != 0)
		goto cleanup;
	if (send_agent_resize(socket_path, 64, 64, geteuid() == 0) != 0)
		goto cleanup;
	resize_checked = 1;
	if (kill(-pid, SIGTERM) != 0)
		goto cleanup;
	if (wait_for_exit(pid, &status) != 0)
		goto cleanup;
	pid = -1;
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (control_fd >= 0)
		close(control_fd);
	if (ready_pipe[0] >= 0)
		close(ready_pipe[0]);
	if (ready_pipe[1] >= 0)
		close(ready_pipe[1]);
	if (pid > 0)
	{
		kill(-pid, SIGTERM);
		if (wait_for_exit(pid, &status) != 0)
		{
			kill(-pid, SIGKILL);
			(void)waitpid(pid, NULL, 0);
		}
	}
	if (socket_path[0] != '\0')
		unlink(socket_path);
	if (socket_dir[0] != '\0')
		rmdir(socket_dir);
	if (rc != 0)
		printf("frdp-session-agent stop cleanup failed\n");
	else if (resize_checked && geteuid() != 0)
		printf("frdp-session-agent control peer rejection verified for non-root test uid\n");
	return rc;
}

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
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

#include <X11/Xlib.h>

#include <freerdp/input.h>

#include "ipc/frdp-ipc.h"

#ifndef FRDP_SESSION_AGENT_BINARY
#error "FRDP_SESSION_AGENT_BINARY is not defined"
#endif

#define TEST_CORRELATION_ID "agent-stop-test"
#define TEST_RECONNECT_CORRELATION_ID "agent-stop-reconnect-test"
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

static int prepare_trusted_xorg_config(char* directory, size_t directory_size, char* path,
	                                   size_t path_size)
{
#if defined(FRDP_XORG_DUMMY_CONFIG)
	char buffer[4096] = { 0 };
	int source = -1;
	int destination = -1;
	ssize_t length = 0;

	if (snprintf(directory, directory_size, "/run/frdp-xorg-test-XXXXXX") >=
	    (int)directory_size || !mkdtemp(directory) || chmod(directory, 0700) != 0 ||
	    snprintf(path, path_size, "%s/xorg-dummy.conf", directory) >= (int)path_size)
		return -1;
	source = open(FRDP_XORG_DUMMY_CONFIG, O_RDONLY | O_CLOEXEC);
	destination = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (source < 0 || destination < 0)
		goto fail;
	while ((length = read(source, buffer, sizeof(buffer))) > 0)
	{
		ssize_t offset = 0;

		while (offset < length)
		{
			const ssize_t written = write(destination, buffer + offset, (size_t)(length - offset));

			if (written < 0 && errno == EINTR)
				continue;
			if (written <= 0)
				goto fail;
			offset += written;
		}
	}
	if (length < 0)
		goto fail;
	if (close(source) != 0)
		goto fail;
	source = -1;
	if (close(destination) != 0)
		goto fail;
	destination = -1;
	return 0;

fail:
	if (source >= 0)
		close(source);
	if (destination >= 0)
		close(destination);
	if (path[0] != '\0')
		unlink(path);
	if (directory[0] != '\0')
		rmdir(directory);
	return -1;
#else
	(void)directory;
	(void)directory_size;
	(void)path;
	(void)path_size;
	return -1;
#endif
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

	snprintf(request.correlation_id, sizeof(request.correlation_id), "%s",
	         TEST_RECONNECT_CORRELATION_ID);
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
	if (strcmp(response.correlation_id, TEST_RECONNECT_CORRELATION_ID) != 0 ||
	    strcmp(response.session_id, TEST_SESSION_ID) != 0)
		return -1;
	return 0;
}

static int send_agent_resize_failure(const char* socket_path, uint32_t width, uint32_t height)
{
	int fd = -1;
	frdpAgentResizeRequest request = { 0 };
	frdpAgentResizeResponse response = { 0 };

	fd = frdp_ipc_connect(socket_path);
	if (fd < 0)
		return -1;
	snprintf(request.correlation_id, sizeof(request.correlation_id), "%s",
	         TEST_RECONNECT_CORRELATION_ID);
	snprintf(request.session_id, sizeof(request.session_id), "%s", TEST_SESSION_ID);
	request.width = width;
	request.height = height;
	request.color_depth = 24;
	if (frdp_ipc_send_agent_resize_request(fd, &request) != 0 ||
	    frdp_ipc_recv_agent_resize_response(fd, &response) != 0)
	{
		frdp_ipc_close(fd);
		return -1;
	}
	frdp_ipc_close(fd);
	if (response.success || response.width != 0 || response.height != 0 || response.error[0] == '\0' ||
	    strcmp(response.correlation_id, TEST_RECONNECT_CORRELATION_ID) != 0 ||
	    strcmp(response.session_id, TEST_SESSION_ID) != 0)
		return -1;
	return 0;
}

static int find_agent_xauthority(pid_t agent_pid, char* path, size_t path_size)
{
	char fd_directory[64] = { 0 };
	DIR* directory = NULL;
	struct dirent* entry = NULL;
	int found = 0;

	snprintf(fd_directory, sizeof(fd_directory), "/proc/%ld/fd", (long)agent_pid);
	directory = opendir(fd_directory);
	if (!directory)
		return -1;
	while ((entry = readdir(directory)) != NULL)
	{
		char fd_path[PATH_MAX] = { 0 };
		char target[PATH_MAX] = { 0 };
		ssize_t length = 0;

		if (entry->d_name[0] == '.')
			continue;
		snprintf(fd_path, sizeof(fd_path), "%s/%s", fd_directory, entry->d_name);
		length = readlink(fd_path, target, sizeof(target) - 1U);
		if (length <= 0)
			continue;
		target[length] = '\0';
		if (strstr(target, "/.frdp-xauthority-") == NULL || strstr(target, " (deleted)") == NULL)
			continue;
		if (snprintf(path, path_size, "%s", fd_path) < 0 || strlen(fd_path) >= path_size)
			break;
		found = 1;
		break;
	}
	closedir(directory);
	return found ? 0 : -1;
}

static Display* open_agent_display(pid_t agent_pid, const char* display_name)
{
	char authority[PATH_MAX] = { 0 };
	char* previous = getenv("XAUTHORITY");
	char* saved = previous ? strdup(previous) : NULL;
	Display* display = NULL;

	if ((previous && !saved) || find_agent_xauthority(agent_pid, authority, sizeof(authority)) != 0)
		goto cleanup;
	if (setenv("XAUTHORITY", authority, 1) != 0)
		goto cleanup;
	display = XOpenDisplay(display_name);
	if (saved)
		(void)setenv("XAUTHORITY", saved, 1);
	else
		(void)unsetenv("XAUTHORITY");

cleanup:
	free(saved);
	return display;
}

static int display_dimensions_match(pid_t agent_pid, const char* display_name, int width,
	                                int height)
{
	Display* display = open_agent_display(agent_pid, display_name);
	int matches = 0;

	if (!display)
		return 0;
	matches = (DisplayWidth(display, DefaultScreen(display)) == width) &&
	          (DisplayHeight(display, DefaultScreen(display)) == height);
	XCloseDisplay(display);
	return matches;
}

static int unauthenticated_uid_is_denied(const char* display_name)
{
	struct passwd* nobody = getpwnam("nobody");
	pid_t pid = -1;
	int status = 0;

	if (!nobody || nobody->pw_uid == 0 || nobody->pw_gid == 0)
		return -1;
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0)
	{
		Display* display = NULL;

		if (setgroups(0, NULL) != 0 || setgid(nobody->pw_gid) != 0 || setuid(nobody->pw_uid) != 0 ||
		    unsetenv("XAUTHORITY") != 0)
			_exit(2);
		display = XOpenDisplay(display_name);
		if (display)
			XCloseDisplay(display);
		_exit(display ? 1 : 0);
	}
	if (waitpid(pid, &status, 0) != pid)
		return -1;
	return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int send_agent_heartbeat(int fd)
{
	frdpAgentHeartbeat request = { 0 };
	frdpAgentHeartbeat response = { 0 };
	snprintf(request.session_id, sizeof(request.session_id), "%s", TEST_SESSION_ID);
	request.nonce = UINT64_C(0x0102030405060708);
	if (frdp_ipc_exchange_agent_heartbeat(fd, &request, &response, 1000) != 0)
		return -1;
	if ((response.nonce != request.nonce) || (strcmp(response.session_id, request.session_id) != 0))
		return -1;
	return 0;
}

static int send_agent_frame_request(const char* socket_path, uint32_t width, uint32_t height)
{
	uint8_t* pixels = NULL;
	size_t pixel_capacity = 0;
	const size_t requested_width = width;
	const size_t requested_height = height;
	int fd = -1;
	frdpAgentFrameRequest request;
	frdpAgentFrameResponse response;

	if ((requested_width == 0) || (requested_height == 0) ||
	    (requested_width > SIZE_MAX / requested_height) ||
	    (requested_width * requested_height > SIZE_MAX / 4U))
		return -1;
	pixel_capacity = requested_width * requested_height * 4U;
	pixels = (uint8_t*)calloc(1, pixel_capacity);
	if (!pixels)
		return -1;

	memset(&request, 0, sizeof(request));
	memset(&response, 0, sizeof(response));

	fd = frdp_ipc_connect(socket_path);
	if (fd < 0)
		goto fail;

	snprintf(request.correlation_id, sizeof(request.correlation_id), "%s",
	         TEST_RECONNECT_CORRELATION_ID);
	snprintf(request.session_id, sizeof(request.session_id), "%s", TEST_SESSION_ID);
	request.x = 0;
	request.y = 0;
	request.width = width;
	request.height = height;
	request.flags = FRDP_AGENT_FRAME_REQUEST_FORCE;

	if (frdp_ipc_send_agent_frame_request(fd, &request) != 0)
		goto fail;
	if (frdp_ipc_recv_agent_frame_response(fd, &response) != 0)
		goto fail;
	if (!response.success || (response.flags & FRDP_AGENT_FRAME_RESPONSE_UNCHANGED))
		goto fail;
	if (strcmp(response.correlation_id, TEST_RECONNECT_CORRELATION_ID) != 0 ||
	    strcmp(response.session_id, TEST_SESSION_ID) != 0)
		goto fail;
	if ((response.x != 0) || (response.y != 0) || (response.width != width) ||
	    (response.height != height) || (response.bpp != 32) || (response.stride != width * 4U))
		goto fail;
	if (response.data_length != response.stride * response.height ||
	    response.data_length > pixel_capacity)
		goto fail;
	if (frdp_ipc_recv(fd, pixels, response.data_length) != (int)response.data_length)
		goto fail;

	frdp_ipc_close(fd);
	free(pixels);
	return 0;

fail:
	if (fd >= 0)
		frdp_ipc_close(fd);
	free(pixels);
	return -1;
}

static int send_agent_unicode_event(const char* socket_path, uint32_t flags, uint16_t code_unit)
{
	frdpAgentInputEvent event = { 0 };
	int fd = frdp_ipc_connect(socket_path);

	if (fd < 0)
		return -1;
	snprintf(event.correlation_id, sizeof(event.correlation_id), "%s",
	         TEST_RECONNECT_CORRELATION_ID);
	snprintf(event.session_id, sizeof(event.session_id), "%s", TEST_SESSION_ID);
	event.event_type = FRDP_AGENT_INPUT_UNICODE;
	event.flags = flags;
	event.param1 = code_unit;
	if (frdp_ipc_send_agent_input_event(fd, &event) != 0)
	{
		frdp_ipc_close(fd);
		return -1;
	}
	frdp_ipc_close(fd);
	return 0;
}

static int wait_for_agent_key_pair(Display* display)
{
	KeyCode keycode = 0;
	int saw_press = 0;
	int saw_release = 0;
	struct pollfd pfd = { 0 };

	pfd.fd = ConnectionNumber(display);
	pfd.events = POLLIN;
	for (int attempt = 0; attempt < 20; attempt++)
	{
		if (XPending(display) == 0)
		{
			const int status = poll(&pfd, 1, 50);

			if (status < 0)
			{
				if (errno == EINTR)
					continue;
				return -1;
			}
			if (status == 0)
				continue;
		}
		while (XPending(display) > 0)
		{
			XEvent event;

			XNextEvent(display, &event);
			if (event.type == KeyPress)
			{
				keycode = event.xkey.keycode;
				saw_press = keycode != 0;
			}
			else if ((event.type == KeyRelease) && saw_press &&
			         (event.xkey.keycode == keycode))
			{
				saw_release = 1;
			}
		}
		if (saw_press && saw_release)
			return 0;
	}
	return -1;
}

static int send_agent_supplementary_unicode(const char* socket_path, pid_t agent_pid,
	                                        const char* display_name)
{
	Display* display = open_agent_display(agent_pid, display_name);
	Window window = None;
	int rc = -1;

	if (!display)
		return -1;
	window = XCreateSimpleWindow(display, DefaultRootWindow(display), 0, 0, 16, 16, 0, 0, 0);
	if (window == None)
		goto cleanup;
	XSelectInput(display, window, KeyPressMask | KeyReleaseMask);
	XMapWindow(display, window);
	XSetInputFocus(display, window, RevertToPointerRoot, CurrentTime);
	XSync(display, False);

	if ((send_agent_unicode_event(socket_path, 0, 0xD83C) != 0) ||
	    (send_agent_unicode_event(socket_path, KBD_FLAGS_RELEASE, 0xD83C) != 0) ||
	    (send_agent_unicode_event(socket_path, 0, 0xDF0D) != 0) ||
	    (send_agent_unicode_event(socket_path, KBD_FLAGS_RELEASE, 0xDF0D) != 0) ||
	    (wait_for_agent_key_pair(display) != 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (window != None)
		XDestroyWindow(display, window);
	XCloseDisplay(display);
	return rc;
}

static int send_agent_clipboard_roundtrip(const char* socket_path)
{
	static const uint8_t expected[] = "agent clipboard text";
	frdpAgentClipboardRequest request = { 0 };
	frdpAgentClipboardResponse response = { 0 };
	uint8_t* text = NULL;
	uint8_t* oversized = NULL;
	int fd = -1;
	int rc = -1;

	snprintf(request.correlation_id, sizeof(request.correlation_id), "%s",
	         TEST_RECONNECT_CORRELATION_ID);
	snprintf(request.session_id, sizeof(request.session_id), "%s", TEST_SESSION_ID);
	request.max_text_bytes = 1024;
	request.text_length = (uint32_t)(sizeof(expected) - 1U);
	fd = frdp_ipc_connect(socket_path);
	if ((fd < 0) || (frdp_ipc_send_agent_clipboard_set_request(fd, &request, expected) != 0) ||
	    (frdp_ipc_recv_agent_clipboard_response(fd, FRDP_IPC_AGENT_CLIPBOARD_SET_RESPONSE,
	                                            &response, &text) != 0) ||
	    !response.success || (response.text_length != 0) ||
	    (strcmp(response.correlation_id, TEST_RECONNECT_CORRELATION_ID) != 0) ||
	    (strcmp(response.session_id, TEST_SESSION_ID) != 0))
		goto cleanup;
	free(text);
	text = NULL;
	frdp_ipc_close(fd);
	fd = -1;

	request.text_length = 0;
	memset(&response, 0, sizeof(response));
	fd = frdp_ipc_connect(socket_path);
	if ((fd < 0) || (frdp_ipc_send_agent_clipboard_get_request(fd, &request) != 0) ||
	    (frdp_ipc_recv_agent_clipboard_response(fd, FRDP_IPC_AGENT_CLIPBOARD_GET_RESPONSE,
	                                            &response, &text) != 0) ||
	    !response.success || (response.text_length != sizeof(expected) - 1U) || !text ||
	    (memcmp(text, expected, sizeof(expected)) != 0))
		goto cleanup;
	free(text);
	text = NULL;
	frdp_ipc_close(fd);
	fd = -1;

	oversized = (uint8_t*)malloc(FRDP_IPC_AGENT_CLIPBOARD_MAX_TEXT_BYTES);
	if (!oversized)
		goto cleanup;
	memset(oversized, 'a', FRDP_IPC_AGENT_CLIPBOARD_MAX_TEXT_BYTES);
	request.max_text_bytes = FRDP_IPC_AGENT_CLIPBOARD_MAX_TEXT_BYTES;
	request.text_length = FRDP_IPC_AGENT_CLIPBOARD_MAX_TEXT_BYTES;
	memset(&response, 0, sizeof(response));
	fd = frdp_ipc_connect(socket_path);
	if ((fd < 0) || (frdp_ipc_send_agent_clipboard_set_request(fd, &request, oversized) != 0) ||
	    (frdp_ipc_recv_agent_clipboard_response(fd, FRDP_IPC_AGENT_CLIPBOARD_SET_RESPONSE,
	                                            &response, &text) != 0) ||
	    response.success || (response.text_length != 0))
		goto cleanup;
	rc = 0;

cleanup:
	if (fd >= 0)
		frdp_ipc_close(fd);
	free(text);
	free(oversized);
	return rc;
}

static int run_xorg_resize_fault_case(const char* fault, int expect_fatal)
{
#if defined(FRDP_SESSION_AGENT_FAULT_BINARY) && defined(FRDP_XORG_SERVER_EXECUTABLE) && \
    defined(FRDP_XORG_DUMMY_CONFIG)
	char socket_dir[64] = { 0 };
	char socket_path[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	char display[32] = { 0 };
	char xorg_config_dir[64] = { 0 };
	char xorg_config_path[128] = { 0 };
	int control_fd = -1;
	int ready_pipe[2] = { -1, -1 };
	int heartbeat_fds[2] = { -1, -1 };
	pid_t pid = -1;
	int status = 0;
	int rc = -1;

	if (geteuid() != 0)
		return 0;
	if (choose_display(display, sizeof(display)) != 0 ||
	    prepare_trusted_xorg_config(xorg_config_dir, sizeof(xorg_config_dir), xorg_config_path,
	                                sizeof(xorg_config_path)) != 0 ||
	    pipe(ready_pipe) != 0 || socketpair(AF_UNIX, SOCK_SEQPACKET, 0, heartbeat_fds) != 0)
		goto cleanup;
	control_fd =
	    create_control_socket(socket_dir, sizeof(socket_dir), socket_path, sizeof(socket_path));
	if (control_fd < 0)
		goto cleanup;
	pid = fork();
	if (pid < 0)
		goto cleanup;
	if (pid == 0)
	{
		char control_fd_str[32] = { 0 };
		char ready_fd[32] = { 0 };
		char heartbeat_fd[32] = { 0 };

		setpgid(0, 0);
		close(ready_pipe[0]);
		close(heartbeat_fds[0]);
		snprintf(ready_fd, sizeof(ready_fd), "%d", ready_pipe[1]);
		snprintf(control_fd_str, sizeof(control_fd_str), "%d", control_fd);
		snprintf(heartbeat_fd, sizeof(heartbeat_fd), "%d", heartbeat_fds[1]);
		setenv("FRDP_AGENT_READY_FD", ready_fd, 1);
		setenv("FRDP_AGENT_CONTROL_FD", control_fd_str, 1);
		setenv("FRDP_AGENT_HEARTBEAT_FD", heartbeat_fd, 1);
		setenv("DISPLAY", display, 1);
		setenv("FRDP_DISPLAY", display, 1);
		setenv("FRDP_DISPLAY_BACKEND", "xorg-dummy", 1);
		setenv("FRDP_XORG_PATH", FRDP_XORG_SERVER_EXECUTABLE, 1);
		setenv("FRDP_XORG_CONFIG", xorg_config_path, 1);
		setenv("FRDP_GEOMETRY", "1024x768x24", 1);
		setenv("FRDP_CORRELATION_ID", TEST_CORRELATION_ID, 1);
		setenv("FRDP_SESSION_ID", TEST_SESSION_ID, 1);
		setenv("FRDP_AGENT_TEST_RESIZE_FAULT", fault, 1);
		execl(FRDP_SESSION_AGENT_FAULT_BINARY, FRDP_SESSION_AGENT_FAULT_BINARY, (char*)NULL);
		_exit(127);
	}
	close(ready_pipe[1]);
	ready_pipe[1] = -1;
	close(heartbeat_fds[1]);
	heartbeat_fds[1] = -1;
	close(control_fd);
	control_fd = -1;
	if (wait_for_ready(ready_pipe[0]) != 0 || send_agent_heartbeat(heartbeat_fds[0]) != 0 ||
	    send_agent_resize_failure(socket_path, 800, 600) != 0)
		goto cleanup;
	if (!expect_fatal)
	{
		if (!display_dimensions_match(pid, display, 1024, 768) ||
		    send_agent_heartbeat(heartbeat_fds[0]) != 0 || kill(pid, SIGTERM) != 0 ||
		    wait_for_exit(pid, &status) != 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
			goto cleanup;
		pid = -1;
	}
	else
	{
		if (wait_for_exit(pid, &status) != 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
			goto cleanup;
		pid = -1;
	}
	rc = 0;

cleanup:
	if (control_fd >= 0)
		close(control_fd);
	if (ready_pipe[0] >= 0)
		close(ready_pipe[0]);
	if (ready_pipe[1] >= 0)
		close(ready_pipe[1]);
	if (heartbeat_fds[0] >= 0)
		close(heartbeat_fds[0]);
	if (heartbeat_fds[1] >= 0)
		close(heartbeat_fds[1]);
	if (pid > 0)
	{
		kill(pid, SIGTERM);
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
	if (xorg_config_path[0] != '\0')
		unlink(xorg_config_path);
	if (xorg_config_dir[0] != '\0')
		rmdir(xorg_config_dir);
	if (rc != 0)
		printf("frdp-session-agent Xorg resize fault case failed: %s\n", fault);
	return rc;
#else
	(void)fault;
	(void)expect_fatal;
	return 0;
#endif
}

int TestFreeRDPFrdpAgentStop(int argc, char* argv[])
{
	(void)argc;
	(void)argv;
	if (run_xorg_resize_fault_case("after-crtc", 0) != 0 ||
	    run_xorg_resize_fault_case("refresh", 0) != 0 ||
	    run_xorg_resize_fault_case("rollback", 1) != 0)
		return -1;

	char socket_dir[64] = { 0 };
	char socket_path[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	char display[32] = { 0 };
	char xorg_config_dir[64] = { 0 };
	char xorg_config_path[128] = { 0 };
	int control_fd = -1;
	int ready_pipe[2] = { -1, -1 };
	int heartbeat_fds[2] = { -1, -1 };
	pid_t pid = -1;
	int status = 0;
	int rc = -1;
	int resize_checked = 0;
	int frame_checked = 0;
	int clipboard_checked = 0;
	int unicode_checked = 0;
	int xorg_resize_checked = 0;
	int xauthority_checked = 0;

	if (choose_display(display, sizeof(display)) != 0)
		return -1;
#if defined(FRDP_XORG_SERVER_EXECUTABLE) && defined(FRDP_XORG_DUMMY_CONFIG)
	if (geteuid() == 0 &&
	    prepare_trusted_xorg_config(xorg_config_dir, sizeof(xorg_config_dir), xorg_config_path,
	                                sizeof(xorg_config_path)) != 0)
		return -1;
#endif
	if (pipe(ready_pipe) != 0)
		return -1;
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, heartbeat_fds) != 0)
		goto cleanup;
	control_fd =
	    create_control_socket(socket_dir, sizeof(socket_dir), socket_path, sizeof(socket_path));
	if (control_fd < 0)
		goto cleanup;

	pid = fork();
	if (pid < 0)
		goto cleanup;
	if (pid == 0)
	{
		char control_fd_str[32] = { 0 };
		char ready_fd[32] = { 0 };
		char heartbeat_fd[32] = { 0 };

		setpgid(0, 0);
		close(ready_pipe[0]);
		close(heartbeat_fds[0]);
		snprintf(ready_fd, sizeof(ready_fd), "%d", ready_pipe[1]);
		snprintf(control_fd_str, sizeof(control_fd_str), "%d", control_fd);
		setenv("FRDP_AGENT_READY_FD", ready_fd, 1);
		setenv("FRDP_AGENT_CONTROL_FD", control_fd_str, 1);
		snprintf(heartbeat_fd, sizeof(heartbeat_fd), "%d", heartbeat_fds[1]);
		setenv("FRDP_AGENT_HEARTBEAT_FD", heartbeat_fd, 1);
		setenv("DISPLAY", display, 1);
		setenv("FRDP_DISPLAY", display, 1);
		if (geteuid() == 0)
		{
#if defined(FRDP_XORG_SERVER_EXECUTABLE) && defined(FRDP_XORG_DUMMY_CONFIG)
			setenv("FRDP_DISPLAY_BACKEND", "xorg-dummy", 1);
			setenv("FRDP_XORG_PATH", FRDP_XORG_SERVER_EXECUTABLE, 1);
			setenv("FRDP_XORG_CONFIG", xorg_config_path, 1);
			setenv("FRDP_GEOMETRY", "1024x768x24", 1);
#else
			setenv("FRDP_DISPLAY_BACKEND", "xvfb", 1);
			setenv("FRDP_GEOMETRY", "64x64x24", 1);
#endif
		}
		else
		{
			setenv("FRDP_DISPLAY_BACKEND", "xvfb", 1);
			setenv("FRDP_GEOMETRY", "64x64x24", 1);
		}
		setenv("FRDP_CORRELATION_ID", TEST_CORRELATION_ID, 1);
		setenv("FRDP_SESSION_ID", TEST_SESSION_ID, 1);
		execl(FRDP_SESSION_AGENT_BINARY, FRDP_SESSION_AGENT_BINARY, (char*)NULL);
		_exit(127);
	}

	close(ready_pipe[1]);
	ready_pipe[1] = -1;
	close(heartbeat_fds[1]);
	heartbeat_fds[1] = -1;
	close(control_fd);
	control_fd = -1;
	if (wait_for_ready(ready_pipe[0]) != 0)
		goto cleanup;
	if (send_agent_heartbeat(heartbeat_fds[0]) != 0)
		goto cleanup;
	if (send_agent_resize(socket_path, geteuid() == 0 ? 800U : 64U, geteuid() == 0 ? 600U : 64U,
	                      geteuid() == 0) != 0)
		goto cleanup;
	resize_checked = 1;
	if (geteuid() == 0)
	{
#if defined(FRDP_XORG_SERVER_EXECUTABLE) && defined(FRDP_XORG_DUMMY_CONFIG)
		if (unauthenticated_uid_is_denied(display) != 0 ||
		    !display_dimensions_match(pid, display, 800, 600) ||
		    send_agent_resize(socket_path, 1280, 720, 1) != 0 ||
		    !display_dimensions_match(pid, display, 1280, 720))
			goto cleanup;
		xorg_resize_checked = 1;
		xauthority_checked = 1;
#endif
		if (send_agent_frame_request(socket_path, 16, 16) != 0)
			goto cleanup;
		frame_checked = 1;
		if (send_agent_clipboard_roundtrip(socket_path) != 0)
			goto cleanup;
		clipboard_checked = 1;
		if (send_agent_supplementary_unicode(socket_path, pid, display) != 0)
			goto cleanup;
		unicode_checked = 1;
	}
	if (kill(pid, SIGTERM) != 0)
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
	if (heartbeat_fds[0] >= 0)
		close(heartbeat_fds[0]);
	if (heartbeat_fds[1] >= 0)
		close(heartbeat_fds[1]);
	if (pid > 0)
	{
		kill(pid, SIGTERM);
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
	if (xorg_config_path[0] != '\0')
		unlink(xorg_config_path);
	if (xorg_config_dir[0] != '\0')
		rmdir(xorg_config_dir);
	if (rc != 0)
		printf("frdp-session-agent stop cleanup failed (resize=%d xorg=%d xauthority=%d frame=%d "
		       "clipboard=%d unicode=%d)\n",
		       resize_checked, xorg_resize_checked, xauthority_checked, frame_checked,
		       clipboard_checked,
		       unicode_checked);
	else if (resize_checked && geteuid() != 0)
		printf("frdp-session-agent control peer rejection verified for non-root test uid\n");
	else if (resize_checked && frame_checked && clipboard_checked && unicode_checked)
		printf("frdp-session-agent root resize, Xauthority isolation, frame, clipboard, and Unicode "
		       "IPC verified (xorg=%d xauthority=%d)\n",
		       xorg_resize_checked, xauthority_checked);
	return rc;
}

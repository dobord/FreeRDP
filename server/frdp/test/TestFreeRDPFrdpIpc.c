#include "ipc/frdp-ipc.h"

#include <errno.h>
#include <fcntl.h>
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
	return 0;
}

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
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
#ifndef FRDP_SAMPLE_CONFIG_PATH
#error "FRDP_SAMPLE_CONFIG_PATH is not defined"
#endif

static int make_runtime_dir(char* dir, size_t dir_size)
{
	const int rc = snprintf(dir, dir_size, "/tmp/frdp-helper-stop-XXXXXX");

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

		if ((lstat(path, &st) == 0) && S_ISSOCK(st.st_mode))
			return 0;
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

static int create_live_socket(const char* socket_path, int backlog)
{
	int fd = -1;
	struct sockaddr_un addr;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
	if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
	{
		close(fd);
		return -1;
	}
	if (chmod(socket_path, 0600) != 0 || listen(fd, backlog) != 0)
	{
		close(fd);
		unlink(socket_path);
		return -1;
	}
	return fd;
}

static int connect_socket(const char* socket_path)
{
	int fd = -1;
	struct sockaddr_un addr;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
	{
		close(fd);
		return -1;
	}
	return fd;
}

static int set_nonblock(int fd)
{
	const int flags = fcntl(fd, F_GETFL, 0);

	if (flags < 0)
		return -1;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int accept_pending_connections(int fd)
{
	for (;;)
	{
		const int accepted = accept(fd, NULL, NULL);

		if (accepted >= 0)
		{
			close(accepted);
			continue;
		}
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
			return 0;
		if (errno == EINTR)
			continue;
		return -1;
	}
}

static int run_config_stop_test(const char* binary, const char* name, const char* config_path);

static int run_stop_test(const char* binary, const char* name)
{
	return run_config_stop_test(binary, name, NULL);
}

static int run_config_stop_test(const char* binary, const char* name, const char* config_path)
{
	char dir[1024] = { 0 };
	char socket_path[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	pid_t pid = -1;
	int status = 0;
	int rc = -1;

	if (make_runtime_dir(dir, sizeof(dir)) != 0)
		return -1;
	if (snprintf(socket_path, sizeof(socket_path), "%s/%s.sock", dir, name) >=
	    (int)sizeof(socket_path))
		goto cleanup;

	pid = fork();
	if (pid < 0)
		goto cleanup;
	if (pid == 0)
	{
		if (config_path)
			execl(binary, binary, "--config", config_path, "--socket", socket_path, (char*)NULL);
		else
			execl(binary, binary, "--socket", socket_path, (char*)NULL);
		_exit(127);
	}

	if (wait_for_socket(socket_path) != 0)
		goto cleanup;
	if (kill(pid, SIGTERM) != 0)
		goto cleanup;
	if (wait_for_exit(pid, &status) != 0)
		goto cleanup;
	pid = -1;
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0))
		goto cleanup;
	if (access(socket_path, F_OK) == 0)
		goto cleanup;
	if (errno != ENOENT)
		goto cleanup;
	rc = 0;

cleanup:
	if (pid > 0)
	{
		kill(pid, SIGTERM);
		if (wait_for_exit(pid, &status) != 0)
		{
			kill(pid, SIGKILL);
			(void)waitpid(pid, NULL, 0);
		}
	}
	unlink(socket_path);
	rmdir(dir);
	return rc;
}

static int run_live_socket_protection_test(const char* binary, const char* name, int backlog,
                                           int prefill_backlog)
{
	char dir[1024] = { 0 };
	char socket_path[sizeof(((struct sockaddr_un*)0)->sun_path)] = { 0 };
	int live_fd = -1;
	int prefill_fd = -1;
	int client_fd = -1;
	int accepted_fd = -1;
	pid_t pid = -1;
	int status = 0;
	int rc = -1;

	if (make_runtime_dir(dir, sizeof(dir)) != 0)
		return -1;
	if (snprintf(socket_path, sizeof(socket_path), "%s/%s-live.sock", dir, name) >=
	    (int)sizeof(socket_path))
		goto cleanup;
	live_fd = create_live_socket(socket_path, backlog);
	if (live_fd < 0)
		goto cleanup;
	if (prefill_backlog)
	{
		prefill_fd = connect_socket(socket_path);
		if (prefill_fd < 0)
			goto cleanup;
	}

	pid = fork();
	if (pid < 0)
		goto cleanup;
	if (pid == 0)
	{
		execl(binary, binary, "--socket", socket_path, (char*)NULL);
		_exit(127);
	}

	if (wait_for_exit(pid, &status) != 0)
		goto cleanup;
	pid = -1;
	if (!WIFEXITED(status) || (WEXITSTATUS(status) == 0))
		goto cleanup;

	if (set_nonblock(live_fd) != 0)
		goto cleanup;
	if (accept_pending_connections(live_fd) != 0)
		goto cleanup;
	client_fd = connect_socket(socket_path);
	if (client_fd < 0)
		goto cleanup;
	accepted_fd = accept(live_fd, NULL, NULL);
	if (accepted_fd < 0)
		goto cleanup;
	rc = 0;

cleanup:
	if (pid > 0)
	{
		kill(pid, SIGTERM);
		if (wait_for_exit(pid, &status) != 0)
		{
			kill(pid, SIGKILL);
			(void)waitpid(pid, NULL, 0);
		}
	}
	if (accepted_fd >= 0)
		close(accepted_fd);
	if (client_fd >= 0)
		close(client_fd);
	if (prefill_fd >= 0)
		close(prefill_fd);
	if (live_fd >= 0)
		close(live_fd);
	unlink(socket_path);
	rmdir(dir);
	return rc;
}

int TestFreeRDPFrdpHelperStop(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if (run_stop_test(FRDP_AUTHD_BINARY, "authd") != 0)
	{
		printf("frdp-authd stop cleanup failed\n");
		return -1;
	}
	if (run_stop_test(FRDP_SESMAND_BINARY, "sesmand") != 0)
	{
		printf("frdp-sesmand stop cleanup failed\n");
		return -1;
	}
	if (run_config_stop_test(FRDP_AUTHD_BINARY, "authd-config", FRDP_SAMPLE_CONFIG_PATH) != 0)
	{
		printf("frdp-authd sample config startup cleanup failed\n");
		return -1;
	}
	if (run_config_stop_test(FRDP_SESMAND_BINARY, "sesmand-config", FRDP_SAMPLE_CONFIG_PATH) != 0)
	{
		printf("frdp-sesmand sample config startup cleanup failed\n");
		return -1;
	}
	if (run_live_socket_protection_test(FRDP_AUTHD_BINARY, "authd", 8, 0) != 0)
	{
		printf("frdp-authd live socket protection failed\n");
		return -1;
	}
	if (run_live_socket_protection_test(FRDP_SESMAND_BINARY, "sesmand", 8, 0) != 0)
	{
		printf("frdp-sesmand live socket protection failed\n");
		return -1;
	}
	if (run_live_socket_protection_test(FRDP_AUTHD_BINARY, "authd-busy", 0, 1) != 0)
	{
		printf("frdp-authd busy live socket protection failed\n");
		return -1;
	}
	if (run_live_socket_protection_test(FRDP_SESMAND_BINARY, "sesmand-busy", 0, 1) != 0)
	{
		printf("frdp-sesmand busy live socket protection failed\n");
		return -1;
	}
	return 0;
}

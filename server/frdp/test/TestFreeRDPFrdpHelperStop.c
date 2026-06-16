#include <errno.h>
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

static int make_runtime_dir(char* dir, size_t dir_size)
{
	const int rc = snprintf(dir, dir_size, "%s/frdp-helper-stop-XXXXXX", CMAKE_CURRENT_BINARY_DIR);

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

static int run_stop_test(const char* binary, const char* name)
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
	return 0;
}

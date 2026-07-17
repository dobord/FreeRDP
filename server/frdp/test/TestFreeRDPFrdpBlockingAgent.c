#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t g_parent_pid = -1;

static void terminate_parent(int signal_number)
{
	(void)signal_number;
	if (g_parent_pid > 1)
		(void)kill((pid_t)g_parent_pid, SIGKILL);
}

int main(int argc, char* argv[])
{
	const char* marker = getenv("FRDP_AGENT_TEST_MARKER");
	char pid[32] = { 0 };
	int fd = -1;
	int length = 0;
	int ready[2] = { -1, -1 };
	pid_t child = -1;

	(void)argc;
	(void)argv;
	if (!marker || !marker[0])
		return 1;
	if ((signal(SIGCHLD, SIG_IGN) == SIG_ERR) || (signal(SIGTERM, SIG_IGN) == SIG_ERR))
		return 1;
	if (pipe(ready) != 0)
		return 1;
	child = fork();
	if (child < 0)
		goto fail;
	if (child == 0)
	{
		char ready_marker = 'R';

		close(ready[0]);
		g_parent_pid = (sig_atomic_t)getppid();
		if ((signal(SIGTERM, terminate_parent) == SIG_ERR) ||
		    (write(ready[1], &ready_marker, 1U) != 1))
			_exit(1);
		close(ready[1]);
		for (;;)
			pause();
	}
	close(ready[1]);
	ready[1] = -1;
	char ready_marker = 0;

	if ((read(ready[0], &ready_marker, 1U) != 1) || (ready_marker != 'R') ||
	    (signal(SIGTERM, SIG_DFL) == SIG_ERR))
		goto fail;
	close(ready[0]);
	ready[0] = -1;
	fd = open(marker, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0)
		goto fail;
	length = snprintf(pid, sizeof(pid), "%ld\n", (long)getpid());
	if ((length <= 0) || ((size_t)length >= sizeof(pid)) ||
	    (write(fd, pid, (size_t)length) != (ssize_t)length) || (fsync(fd) != 0) || (close(fd) != 0))
		goto fail;
	fd = -1;
	for (;;)
		pause();

fail:
	if (ready[0] >= 0)
		close(ready[0]);
	if (ready[1] >= 0)
		close(ready[1]);
	if (fd >= 0)
		close(fd);
	(void)kill(child, SIGKILL);
	(void)waitpid(child, NULL, 0);
	return 1;
}

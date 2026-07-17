#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef FRDP_SYSTEMD_RUN_BINARY
#error "FRDP_SYSTEMD_RUN_BINARY is not defined"
#endif
#ifndef FRDP_TEST_BINARY
#error "FRDP_TEST_BINARY is not defined"
#endif

#define FRDP_SYSTEMD_SKIP 77

int main(void)
{
	char unit[96] = { 0 };
	pid_t child = -1;
	int status = 0;

	if (geteuid() != 0)
	{
		printf("frdp-sesmand login1 lifecycle skipped: root required\n");
		return FRDP_SYSTEMD_SKIP;
	}
	if (snprintf(unit, sizeof(unit), "--unit=frdp-sesmand-login1-test-%ld", (long)getpid()) >=
	    (int)sizeof(unit))
		return 1;
	child = fork();
	if (child < 0)
		return 1;
	if (child == 0)
	{
		execl(FRDP_SYSTEMD_RUN_BINARY, FRDP_SYSTEMD_RUN_BINARY, "--quiet", "--wait", "--pipe",
		      "--collect", "--service-type=exec", unit, FRDP_TEST_BINARY,
		      "TestFreeRDPFrdpServiceIpc", "login1-owner-crash", (char*)NULL);
		_exit(127);
	}
	do
	{
		child = waitpid(child, &status, 0);
	} while ((child < 0) && (errno == EINTR));
	if ((child < 0) || !WIFEXITED(status))
		return 1;
	return WEXITSTATUS(status);
}

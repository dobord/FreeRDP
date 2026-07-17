#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef FRDP_SYSTEMD_RUN_BINARY
#error "FRDP_SYSTEMD_RUN_BINARY is not defined"
#endif
#ifndef FRDP_TEST_BINARY
#error "FRDP_TEST_BINARY is not defined"
#endif

#define FRDP_SYSTEMD_SKIP 77

int main(int argc, char* argv[])
{
	char unit[96] = { 0 };
	const char* subcase = NULL;
	pid_t child = -1;
	int status = 0;

	if ((argc != 2) || ((strcmp(argv[1], "login1-owner-crash") != 0) &&
	                    (strcmp(argv[1], "scope-runtime-limits") != 0)))
		return 2;
	subcase = argv[1];
	if (geteuid() != 0)
	{
		printf("frdp-sesmand system lifecycle skipped: root required\n");
		return FRDP_SYSTEMD_SKIP;
	}
	if (snprintf(unit, sizeof(unit), "--unit=frdp-sesmand-system-test-%ld", (long)getpid()) >=
	    (int)sizeof(unit))
		return 1;
	child = fork();
	if (child < 0)
		return 1;
	if (child == 0)
	{
		execl(FRDP_SYSTEMD_RUN_BINARY, FRDP_SYSTEMD_RUN_BINARY, "--quiet", "--wait", "--pipe",
		      "--collect", "--service-type=exec", unit, FRDP_TEST_BINARY,
		      "TestFreeRDPFrdpServiceIpc", subcase, (char*)NULL);
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

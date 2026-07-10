#include "frdp-sesmand/process_identity.h"

#include <limits.h>
#include <stdio.h>
#include <unistd.h>

int TestFreeRDPFrdpProcessIdentity(int argc, char* argv[])
{
	unsigned long long start_ticks = 0;
	uid_t effective_uid = (uid_t)-1;

	(void)argc;
	(void)argv;

	if (frdp_sesmand_process_identity_read(0, &start_ticks, &effective_uid) !=
	    FRDP_SESMAND_PROCESS_IDENTITY_ERROR)
	{
		fprintf(stderr, "zero PID process identity was accepted\n");
		return -1;
	}
#ifdef __linux__
	if (frdp_sesmand_process_identity_read(getpid(), &start_ticks, &effective_uid) !=
	        FRDP_SESMAND_PROCESS_IDENTITY_OK ||
	    (start_ticks == 0) || (effective_uid != geteuid()))
	{
		fprintf(stderr, "current process identity could not be read\n");
		return -1;
	}
	if (frdp_sesmand_process_identity_read((pid_t)INT_MAX, &start_ticks, &effective_uid) !=
	    FRDP_SESMAND_PROCESS_IDENTITY_MISSING)
	{
		fprintf(stderr, "missing process identity was not reported\n");
		return -1;
	}
#else
	if (frdp_sesmand_process_identity_read(getpid(), &start_ticks, &effective_uid) !=
	    FRDP_SESMAND_PROCESS_IDENTITY_ERROR)
	{
		fprintf(stderr, "unsupported process identity platform was accepted\n");
		return -1;
	}
#endif
	return 0;
}

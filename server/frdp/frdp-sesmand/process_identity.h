#ifndef FRDP_SESMAND_PROCESS_IDENTITY_H
#define FRDP_SESMAND_PROCESS_IDENTITY_H

#include <sys/types.h>

typedef enum
{
	FRDP_SESMAND_PROCESS_IDENTITY_ERROR = -1,
	FRDP_SESMAND_PROCESS_IDENTITY_OK = 0,
	FRDP_SESMAND_PROCESS_IDENTITY_MISSING = 1
} frdpSesmandProcessIdentityResult;

frdpSesmandProcessIdentityResult frdp_sesmand_process_identity_read(
    pid_t pid, unsigned long long* start_ticks, uid_t* owner_uid);

#endif

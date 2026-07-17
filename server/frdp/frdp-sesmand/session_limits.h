#ifndef FRDP_SESMAND_SESSION_LIMITS_H
#define FRDP_SESMAND_SESSION_LIMITS_H

#include <signal.h>
#include <stddef.h>

#include "../config/frdp-config.h"

typedef struct
{
	const char* scope_name;
	frdpSessionResourcePolicy previous;
} frdpSesmandSessionLimitsTarget;

typedef int (*frdpSesmandSessionLimitsApply)(void* context, const char* scope_name,
                                             const frdpSessionResourcePolicy* policy);

typedef enum
{
	FRDP_SESMAND_SESSION_LIMITS_APPLIED = 0,
	FRDP_SESMAND_SESSION_LIMITS_UPDATE_FAILED = 1,
	FRDP_SESMAND_SESSION_LIMITS_ROLLBACK_FAILED = 2
} frdpSesmandSessionLimitsResult;

frdpSesmandSessionLimitsResult frdp_sesmand_session_limits_transaction(
    const frdpSesmandSessionLimitsTarget* targets, size_t count,
    const frdpSessionResourcePolicy* updated, frdpSesmandSessionLimitsApply apply, void* context,
    volatile sig_atomic_t* stop_requested);

#endif

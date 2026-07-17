#include "session_limits.h"

frdpSesmandSessionLimitsResult frdp_sesmand_session_limits_transaction(
    const frdpSesmandSessionLimitsTarget* targets, size_t count,
    const frdpSessionResourcePolicy* updated, frdpSesmandSessionLimitsApply apply, void* context,
    volatile sig_atomic_t* stop_requested)
{
	if ((!targets && (count > 0U)) || !updated || !apply || !stop_requested)
		return FRDP_SESMAND_SESSION_LIMITS_UPDATE_FAILED;
	for (size_t index = 0; index < count; index++)
	{
		if (!targets[index].scope_name || (targets[index].scope_name[0] == '\0'))
			return FRDP_SESMAND_SESSION_LIMITS_UPDATE_FAILED;
	}
	for (size_t index = 0; index < count; index++)
	{
		if (apply(context, targets[index].scope_name, updated) != 0)
		{
			int rollback_failed = 0;

			for (size_t rollback = 0; rollback <= index; rollback++)
			{
				if (apply(context, targets[rollback].scope_name,
				          &targets[rollback].previous) != 0)
					rollback_failed = 1;
			}
			if (rollback_failed)
			{
				*stop_requested = 1;
				return FRDP_SESMAND_SESSION_LIMITS_ROLLBACK_FAILED;
			}
			return FRDP_SESMAND_SESSION_LIMITS_UPDATE_FAILED;
		}
	}
	return FRDP_SESMAND_SESSION_LIMITS_APPLIED;
}

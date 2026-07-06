#include "session_resources.h"

#include <string.h>

static int default_setrlimit(int resource, const struct rlimit* limit, void* context)
{
	(void)context;
	return setrlimit(resource, limit);
}

static int apply_session_rlimit(frdpSesmandSetRlimitFn setrlimit_fn, void* context, int resource,
                                rlim_t value)
{
	struct rlimit limit;

	if (!setrlimit_fn)
		return -1;

	memset(&limit, 0, sizeof(limit));
	limit.rlim_cur = value;
	limit.rlim_max = value;
	return setrlimit_fn(resource, &limit, context);
}

int frdp_sesmand_apply_session_resource_policy_ex(const frdpSessionResourcePolicy* policy,
                                                  frdpSesmandSetRlimitFn setrlimit_fn,
                                                  void* context)
{
	if (!policy || !setrlimit_fn)
		return -1;

	if ((policy->max_processes > 0) &&
	    (apply_session_rlimit(setrlimit_fn, context, RLIMIT_NPROC,
	                          (rlim_t)policy->max_processes) != 0))
		return -1;

	if (policy->memory_max_mb > 0)
	{
		const rlim_t mb = (rlim_t)1024U * (rlim_t)1024U;
		const rlim_t memory_limit = (rlim_t)policy->memory_max_mb * mb;

		if ((memory_limit / mb) != (rlim_t)policy->memory_max_mb)
			return -1;
		if (apply_session_rlimit(setrlimit_fn, context, RLIMIT_AS, memory_limit) != 0)
			return -1;
	}
	return 0;
}

int frdp_sesmand_apply_session_resource_policy(const frdpSessionResourcePolicy* policy)
{
	return frdp_sesmand_apply_session_resource_policy_ex(policy, default_setrlimit, NULL);
}

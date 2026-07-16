#include "frdp-sesmand/session_resources.h"

#include <errno.h>
#include <stdio.h>
#include <stdint.h>

typedef struct
{
	int resource[4];
	struct rlimit limit[4];
	size_t count;
	int fail_resource;
} ResourcePolicyProbe;

static int probe_setrlimit(int resource, const struct rlimit* limit, void* context)
{
	ResourcePolicyProbe* probe = (ResourcePolicyProbe*)context;

	if (!probe || !limit || (probe->count >= 4U))
		return -1;
	if (resource == probe->fail_resource)
	{
		errno = EPERM;
		return -1;
	}
	probe->resource[probe->count] = resource;
	probe->limit[probe->count] = *limit;
	probe->count++;
	return 0;
}

static int test_disabled_resource_policy(void)
{
	ResourcePolicyProbe probe = { .fail_resource = -1 };
	const frdpSessionResourcePolicy policy = { 0 };

	if (frdp_sesmand_apply_session_resource_policy_ex(&policy, probe_setrlimit, &probe) != 0)
		return -1;
	if (probe.count != 0)
	{
		fprintf(stderr, "disabled policy unexpectedly called setrlimit %zu times\n", probe.count);
		return -1;
	}
	return 0;
}

static int test_process_and_memory_limits(void)
{
	ResourcePolicyProbe probe = { .fail_resource = -1 };
	const frdpSessionResourcePolicy policy = { .max_processes = 77, .memory_max_mb = 1536 };
	const rlim_t memory_limit = (rlim_t)1536U * (rlim_t)1024U * (rlim_t)1024U;

	if (frdp_sesmand_apply_session_resource_policy_ex(&policy, probe_setrlimit, &probe) != 0)
		return -1;
	if ((probe.count != 2U) || (probe.resource[0] != RLIMIT_NPROC) ||
	    (probe.limit[0].rlim_cur != 77U) || (probe.limit[0].rlim_max != 77U) ||
	    (probe.resource[1] != RLIMIT_AS) || (probe.limit[1].rlim_cur != memory_limit) ||
	    (probe.limit[1].rlim_max != memory_limit))
	{
		fprintf(stderr, "unexpected resource policy calls: count=%zu first=%d second=%d\n",
		        probe.count, probe.resource[0], probe.resource[1]);
		return -1;
	}
	return 0;
}

static int test_setrlimit_failure_stops_policy(void)
{
	ResourcePolicyProbe probe = { .fail_resource = RLIMIT_NPROC };
	const frdpSessionResourcePolicy policy = { .max_processes = 77, .memory_max_mb = 1536 };

	if (frdp_sesmand_apply_session_resource_policy_ex(&policy, probe_setrlimit, &probe) == 0)
		return -1;
	if (probe.count != 0)
	{
		fprintf(stderr, "failing process limit should stop before memory limit\n");
		return -1;
	}
	return 0;
}

static int test_memory_setrlimit_failure_reports_error(void)
{
	ResourcePolicyProbe probe = { .fail_resource = RLIMIT_AS };
	const frdpSessionResourcePolicy policy = { .max_processes = 77, .memory_max_mb = 1536 };

	if (frdp_sesmand_apply_session_resource_policy_ex(&policy, probe_setrlimit, &probe) == 0)
		return -1;
	if ((probe.count != 1U) || (probe.resource[0] != RLIMIT_NPROC))
	{
		fprintf(stderr, "failing memory limit should preserve only the earlier process limit call\n");
		return -1;
	}
	return 0;
}

static int test_memory_overflow_rejected(void)
{
	ResourcePolicyProbe probe = { .fail_resource = -1 };
	frdpSessionResourcePolicy policy = { .memory_max_mb = 1 };

	if ((rlim_t)-1 == (rlim_t)0)
		return 0;
	policy.memory_max_mb = (uint32_t)(((rlim_t)-1 / ((rlim_t)1024U * (rlim_t)1024U)) + 1U);
	if (policy.memory_max_mb == 0)
		return 0;
	if (frdp_sesmand_apply_session_resource_policy_ex(&policy, probe_setrlimit, &probe) == 0)
		return -1;
	if (probe.count != 0)
	{
		fprintf(stderr, "overflowing memory policy should not call setrlimit\n");
		return -1;
	}
	return 0;
}

static int test_invalid_resource_policy_arguments(void)
{
	const frdpSessionResourcePolicy policy = { 0 };
	ResourcePolicyProbe probe = { .fail_resource = -1 };

	if (frdp_sesmand_apply_session_resource_policy_ex(NULL, probe_setrlimit, &probe) == 0)
		return -1;
	if (frdp_sesmand_apply_session_resource_policy_ex(&policy, NULL, &probe) == 0)
		return -1;
	if (frdp_sesmand_apply_session_resource_policy(NULL) == 0)
		return -1;
	return 0;
}

static int test_session_capacity_policy(void)
{
	frdpSessionResourcePolicy policy = { 0 };

	if (!frdp_sesmand_session_capacity_available(&policy, 0) ||
	    !frdp_sesmand_session_capacity_available(&policy, FRDP_CONFIG_MAX_SESSIONS - 1U) ||
	    frdp_sesmand_session_capacity_available(&policy, FRDP_CONFIG_MAX_SESSIONS) ||
	    frdp_sesmand_session_capacity_available(&policy, UINT32_MAX))
		return -1;
	policy.max_sessions = 2;
	if (!frdp_sesmand_session_capacity_available(&policy, 0) ||
	    !frdp_sesmand_session_capacity_available(&policy, 1) ||
	    frdp_sesmand_session_capacity_available(&policy, 2) ||
	    frdp_sesmand_session_capacity_available(&policy, 3) ||
	    frdp_sesmand_session_capacity_available(NULL, 0))
		return -1;
	return 0;
}

int TestFreeRDPFrdpSessionResources(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if (test_disabled_resource_policy() != 0)
	{
		fprintf(stderr, "disabled resource policy test failed\n");
		return -1;
	}
	if (test_process_and_memory_limits() != 0)
	{
		fprintf(stderr, "process and memory limit test failed\n");
		return -1;
	}
	if (test_setrlimit_failure_stops_policy() != 0)
	{
		fprintf(stderr, "setrlimit failure test failed\n");
		return -1;
	}
	if (test_memory_setrlimit_failure_reports_error() != 0)
	{
		fprintf(stderr, "memory setrlimit failure test failed\n");
		return -1;
	}
	if (test_memory_overflow_rejected() != 0)
	{
		fprintf(stderr, "memory overflow test failed\n");
		return -1;
	}
	if (test_invalid_resource_policy_arguments() != 0)
	{
		fprintf(stderr, "invalid resource policy argument test failed\n");
		return -1;
	}
	if (test_session_capacity_policy() != 0)
	{
		fprintf(stderr, "session capacity policy test failed\n");
		return -1;
	}
	return 0;
}

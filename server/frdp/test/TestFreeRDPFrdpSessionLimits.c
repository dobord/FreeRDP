#include "frdp-sesmand/session_limits.h"

#include <stdio.h>
#include <string.h>

typedef struct
{
	unsigned int call_count;
	unsigned int fail_first;
	unsigned int fail_second;
	char names[8][32];
	frdpSessionResourcePolicy policies[8];
} mockLimitsApply;

static int mock_apply(void* context, const char* scope_name,
                      const frdpSessionResourcePolicy* policy)
{
	mockLimitsApply* mock = (mockLimitsApply*)context;
	const unsigned int call = ++mock->call_count;

	if ((call <= 8U) && scope_name && policy)
	{
		snprintf(mock->names[call - 1U], sizeof(mock->names[call - 1U]), "%s", scope_name);
		mock->policies[call - 1U] = *policy;
	}
	return ((call == mock->fail_first) || (call == mock->fail_second)) ? -1 : 0;
}

static int policy_matches(const frdpSessionResourcePolicy* policy, uint32_t processes,
                          uint32_t memory, uint32_t cpu)
{
	return policy && (policy->max_processes == processes) && (policy->memory_max_mb == memory) &&
	       (policy->cpu_quota_percent == cpu);
}

static int test_successful_batch(void)
{
	const frdpSesmandSessionLimitsTarget targets[] = {
		{ .scope_name = "first.scope", .previous = { .max_processes = 1 } },
		{ .scope_name = "second.scope", .previous = { .max_processes = 2 } },
	};
	const frdpSessionResourcePolicy updated = {
		.max_processes = 20,
		.memory_max_mb = 30,
		.cpu_quota_percent = 40,
	};
	mockLimitsApply mock = { 0 };
	volatile sig_atomic_t stop_requested = 0;

	if ((frdp_sesmand_session_limits_transaction(targets, 2U, &updated, mock_apply, &mock,
	                                                &stop_requested) !=
	     FRDP_SESMAND_SESSION_LIMITS_APPLIED) ||
	    (mock.call_count != 2U) || stop_requested ||
	    (strcmp(mock.names[0], "first.scope") != 0) ||
	    (strcmp(mock.names[1], "second.scope") != 0) ||
	    !policy_matches(&mock.policies[0], 20U, 30U, 40U) ||
	    !policy_matches(&mock.policies[1], 20U, 30U, 40U))
		return -1;
	return 0;
}

static int test_partial_batch_rolls_back_each_previous_tuple(void)
{
	const frdpSesmandSessionLimitsTarget targets[] = {
		{ .scope_name = "first.scope",
		  .previous = { .max_processes = 1, .memory_max_mb = 2, .cpu_quota_percent = 3 } },
		{ .scope_name = "second.scope",
		  .previous = { .max_processes = 4, .memory_max_mb = 5, .cpu_quota_percent = 6 } },
	};
	const frdpSessionResourcePolicy updated = {
		.max_processes = 20,
		.memory_max_mb = 30,
		.cpu_quota_percent = 40,
	};
	mockLimitsApply mock = { .fail_first = 2U };
	volatile sig_atomic_t stop_requested = 0;

	if ((frdp_sesmand_session_limits_transaction(targets, 2U, &updated, mock_apply, &mock,
	                                                &stop_requested) !=
	     FRDP_SESMAND_SESSION_LIMITS_UPDATE_FAILED) ||
	    (mock.call_count != 4U) || stop_requested ||
	    (strcmp(mock.names[2], "first.scope") != 0) ||
	    (strcmp(mock.names[3], "second.scope") != 0) ||
	    !policy_matches(&mock.policies[2], 1U, 2U, 3U) ||
	    !policy_matches(&mock.policies[3], 4U, 5U, 6U))
		return -1;
	return 0;
}

static int test_rollback_failure_requests_manager_stop(void)
{
	const frdpSesmandSessionLimitsTarget targets[] = {
		{ .scope_name = "first.scope", .previous = { .max_processes = 1 } },
		{ .scope_name = "second.scope", .previous = { .max_processes = 2 } },
	};
	const frdpSessionResourcePolicy updated = { .max_processes = 20 };
	mockLimitsApply mock = { .fail_first = 2U, .fail_second = 3U };
	volatile sig_atomic_t stop_requested = 0;

	if ((frdp_sesmand_session_limits_transaction(targets, 2U, &updated, mock_apply, &mock,
	                                                &stop_requested) !=
	     FRDP_SESMAND_SESSION_LIMITS_ROLLBACK_FAILED) ||
	    (mock.call_count != 4U) || !stop_requested ||
	    (strcmp(mock.names[3], "second.scope") != 0) ||
	    !policy_matches(&mock.policies[3], 2U, 0U, 0U))
		return -1;
	return 0;
}

static int test_single_update_failure_is_rolled_back(void)
{
	const frdpSesmandSessionLimitsTarget target = {
		.scope_name = "only.scope",
		.previous = { .max_processes = 7, .memory_max_mb = 8, .cpu_quota_percent = 9 },
	};
	const frdpSessionResourcePolicy updated = { .max_processes = 20 };
	mockLimitsApply mock = { .fail_first = 1U };
	volatile sig_atomic_t stop_requested = 0;

	if ((frdp_sesmand_session_limits_transaction(&target, 1U, &updated, mock_apply, &mock,
	                                                &stop_requested) !=
	     FRDP_SESMAND_SESSION_LIMITS_UPDATE_FAILED) ||
	    (mock.call_count != 2U) || stop_requested ||
	    !policy_matches(&mock.policies[1], 7U, 8U, 9U))
		return -1;
	return 0;
}

static int test_invalid_batch_is_rejected_before_apply(void)
{
	const frdpSesmandSessionLimitsTarget targets[] = {
		{ .scope_name = "first.scope", .previous = { .max_processes = 1 } },
		{ .scope_name = "", .previous = { .max_processes = 2 } },
	};
	const frdpSessionResourcePolicy updated = { .max_processes = 20 };
	mockLimitsApply mock = { 0 };
	volatile sig_atomic_t stop_requested = 0;

	if ((frdp_sesmand_session_limits_transaction(targets, 2U, &updated, mock_apply, &mock,
	                                                &stop_requested) !=
	     FRDP_SESMAND_SESSION_LIMITS_UPDATE_FAILED) ||
	    (mock.call_count != 0U) || stop_requested)
		return -1;
	return 0;
}

int TestFreeRDPFrdpSessionLimits(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if (test_successful_batch() != 0)
		return -1;
	if (test_partial_batch_rolls_back_each_previous_tuple() != 0)
		return -1;
	if (test_rollback_failure_requests_manager_stop() != 0)
		return -1;
	if (test_single_update_failure_is_rolled_back() != 0)
		return -1;
	if (test_invalid_batch_is_rejected_before_apply() != 0)
		return -1;
	return 0;
}

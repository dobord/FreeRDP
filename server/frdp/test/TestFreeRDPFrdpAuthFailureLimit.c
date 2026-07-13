#include "frdp-authd/auth_failure_limit.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static int test_blocks_at_threshold_and_clears(void)
{
	frdpAuthFailureLimiter limiter;

	frdp_auth_failure_limiter_init(&limiter, 3, 60);
	for (uint32_t x = 0; x < 3; x++)
	{
		if (!frdp_auth_failure_limiter_allow(&limiter, "alice@example.test", 100))
			return -1;
		if (frdp_auth_failure_limiter_record(&limiter, "alice@example.test", 100) != 0)
			return -1;
	}
	if (frdp_auth_failure_limiter_allow(&limiter, "alice@example.test", 100))
		return -1;
	if (!frdp_auth_failure_limiter_allow(&limiter, "bob@example.test", 100))
		return -1;
	frdp_auth_failure_limiter_clear(&limiter, "alice@example.test");
	return frdp_auth_failure_limiter_allow(&limiter, "alice@example.test", 100) ? 0 : -1;
}

static int test_account_keys_fold_ascii_case(void)
{
	frdpAuthFailureLimiter limiter;
	char lower[FRDP_AUTH_FAILURE_LIMIT_KEY_SIZE] = { 0 };
	char mixed[FRDP_AUTH_FAILURE_LIMIT_KEY_SIZE] = { 0 };

	if ((frdp_auth_failure_limiter_account_key("alice@example.test", sizeof("alice@example.test"),
	                                           NULL, lower, sizeof(lower)) != 0) ||
	    (frdp_auth_failure_limiter_account_key("Alice@Example.Test", sizeof("Alice@Example.Test"),
	                                           NULL, mixed, sizeof(mixed)) != 0) ||
	    (strcmp(lower, mixed) != 0))
		return -1;
	frdp_auth_failure_limiter_init(&limiter, 1, 60);
	if ((frdp_auth_failure_limiter_record(&limiter, lower, 100) != 0) ||
	    frdp_auth_failure_limiter_allow(&limiter, mixed, 100))
		return -1;
	errno = 0;
	if ((frdp_auth_failure_limiter_account_key("alice", sizeof("alice"), NULL, mixed, 5) != -1) ||
	    (errno != ENAMETOOLONG))
		return -1;
	if ((frdp_auth_failure_limiter_account_key("ALICE", sizeof("ALICE"), "Alice", mixed,
	                                           sizeof(mixed)) != 0) ||
	    (strcmp(mixed, "Alice") != 0))
		return -1;
	return 0;
}

static int test_expires_windows_and_handles_clock_regression(void)
{
	frdpAuthFailureLimiter limiter;

	frdp_auth_failure_limiter_init(&limiter, 1, 60);
	if ((frdp_auth_failure_limiter_record(&limiter, "192.0.2.10", 100) != 0) ||
	    frdp_auth_failure_limiter_allow(&limiter, "192.0.2.10", 159) ||
	    !frdp_auth_failure_limiter_allow(&limiter, "192.0.2.10", 160))
		return -1;
	if ((frdp_auth_failure_limiter_record(&limiter, "192.0.2.10", 200) != 0) ||
	    !frdp_auth_failure_limiter_allow(&limiter, "192.0.2.10", 199))
		return -1;
	return 0;
}

static int test_capacity_is_bounded_and_fail_closed(void)
{
	frdpAuthFailureLimiter limiter;
	char key[FRDP_AUTH_FAILURE_LIMIT_KEY_SIZE] = { 0 };

	frdp_auth_failure_limiter_init(&limiter, 2, 60);
	for (uint32_t x = 0; x < FRDP_AUTH_FAILURE_LIMIT_MAX_ENTRIES; x++)
	{
		if (snprintf(key, sizeof(key), "user-%" PRIu32, x) >= (int)sizeof(key))
			return -1;
		if (frdp_auth_failure_limiter_record(&limiter, key, 100) != 0)
			return -1;
	}
	errno = 0;
	if (frdp_auth_failure_limiter_allow(&limiter, "overflow", 100) || (errno != ENOSPC))
		return -1;
	if ((frdp_auth_failure_limiter_record(&limiter, "overflow", 100) != -1) ||
	    (errno != ENOSPC))
		return -1;
	if (!frdp_auth_failure_limiter_allow(&limiter, "overflow", 160))
		return -1;
	return 0;
}

static int test_rejects_invalid_policy_and_keys(void)
{
	frdpAuthFailureLimiter limiter;
	char oversized[FRDP_AUTH_FAILURE_LIMIT_KEY_SIZE] = { 0 };

	memset(oversized, 'x', sizeof(oversized));
	frdp_auth_failure_limiter_init(&limiter, 0, 60);
	errno = 0;
	if (frdp_auth_failure_limiter_allow(&limiter, "alice", 1) || (errno != EINVAL))
		return -1;
	frdp_auth_failure_limiter_init(&limiter, 1, 60);
	errno = 0;
	if (frdp_auth_failure_limiter_allow(&limiter, oversized, 1) || (errno != EINVAL))
		return -1;
	if ((frdp_auth_failure_limiter_record(NULL, "alice", 1) != -1) || (errno != EINVAL))
		return -1;
	return 0;
}

int TestFreeRDPFrdpAuthFailureLimit(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if (test_blocks_at_threshold_and_clears() != 0)
		return -1;
	if (test_account_keys_fold_ascii_case() != 0)
		return -1;
	if (test_expires_windows_and_handles_clock_regression() != 0)
		return -1;
	if (test_capacity_is_bounded_and_fail_closed() != 0)
		return -1;
	if (test_rejects_invalid_policy_and_keys() != 0)
		return -1;
	return 0;
}

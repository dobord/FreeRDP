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

static int test_canonical_aliases_share_budget(void)
{
	frdpAuthFailureLimiter limiter;

	frdp_auth_failure_limiter_init(&limiter, 3, 60);
	if ((frdp_auth_failure_limiter_record(&limiter, "alias-one", 100) != 0) ||
	    (frdp_auth_failure_limiter_bind_alias(&limiter, "alias-one", "canonical", 100) != 0) ||
	    (frdp_auth_failure_limiter_record(&limiter, "alias-one", 100) != 0) ||
	    (frdp_auth_failure_limiter_bind_alias(&limiter, "alias-two", "canonical", 100) != 0) ||
	    (frdp_auth_failure_limiter_record(&limiter, "alias-two", 100) != 0) ||
	    frdp_auth_failure_limiter_allow(&limiter, "alias-one", 100) ||
	    frdp_auth_failure_limiter_allow(&limiter, "alias-two", 100) ||
	    frdp_auth_failure_limiter_allow(&limiter, "canonical", 100))
		return -1;
	frdp_auth_failure_limiter_clear(&limiter, "alias-two");
	if (!frdp_auth_failure_limiter_allow(&limiter, "alias-one", 100) ||
	    !frdp_auth_failure_limiter_allow(&limiter, "canonical", 100))
		return -1;
	return 0;
}

static int test_alias_rebinding_compresses_chains(void)
{
	frdpAuthFailureLimiter limiter;

	frdp_auth_failure_limiter_init(&limiter, 1, 60);
	if ((frdp_auth_failure_limiter_bind_alias(&limiter, "first", "second", 100) != 0) ||
	    (frdp_auth_failure_limiter_bind_alias(&limiter, "second", "canonical", 100) != 0) ||
	    (frdp_auth_failure_limiter_record(&limiter, "first", 100) != 0) ||
	    frdp_auth_failure_limiter_allow(&limiter, "second", 100) ||
	    frdp_auth_failure_limiter_allow(&limiter, "canonical", 100) ||
	    !frdp_auth_failure_limiter_allow(&limiter, "first", 160))
		return -1;
	return 0;
}

static int test_alias_binding_merges_existing_budgets(void)
{
	frdpAuthFailureLimiter limiter;

	frdp_auth_failure_limiter_init(&limiter, 3, 60);
	if ((frdp_auth_failure_limiter_record(&limiter, "alias", 100) != 0) ||
	    (frdp_auth_failure_limiter_record(&limiter, "canonical", 100) != 0) ||
	    (frdp_auth_failure_limiter_bind_alias(&limiter, "alias", "canonical", 100) != 0) ||
	    !frdp_auth_failure_limiter_allow(&limiter, "alias", 100) ||
	    (frdp_auth_failure_limiter_record(&limiter, "alias", 100) != 0) ||
	    frdp_auth_failure_limiter_allow(&limiter, "canonical", 100))
		return -1;
	return 0;
}

static int test_conflicting_alias_rebinding_fails_closed(void)
{
	frdpAuthFailureLimiter limiter;

	frdp_auth_failure_limiter_init(&limiter, 1, 60);
	if ((frdp_auth_failure_limiter_bind_alias(&limiter, "alias", "canonical-one", 100) != 0) ||
	    (frdp_auth_failure_limiter_record(&limiter, "alias", 100) != 0))
		return -1;
	errno = 0;
	if ((frdp_auth_failure_limiter_bind_alias(&limiter, "alias", "canonical-two", 100) != -1) ||
	    (errno != EEXIST) || frdp_auth_failure_limiter_allow(&limiter, "alias", 100) ||
	    frdp_auth_failure_limiter_allow(&limiter, "canonical-one", 100) ||
	    !frdp_auth_failure_limiter_allow(&limiter, "canonical-two", 100))
		return -1;
	return 0;
}

static int test_alias_capacity_is_bounded_and_expires(void)
{
	frdpAuthFailureLimiter limiter;
	char alias[FRDP_AUTH_FAILURE_LIMIT_KEY_SIZE] = { 0 };

	frdp_auth_failure_limiter_init(&limiter, 2, 60);
	for (uint32_t x = 0; x < FRDP_AUTH_FAILURE_LIMIT_MAX_ENTRIES; x++)
	{
		if ((snprintf(alias, sizeof(alias), "alias-%" PRIu32, x) >= (int)sizeof(alias)) ||
		    (frdp_auth_failure_limiter_bind_alias(&limiter, alias, "canonical", 100) != 0))
			return -1;
	}
	errno = 0;
	if ((frdp_auth_failure_limiter_bind_alias(&limiter, "overflow", "canonical", 100) != -1) ||
	    (errno != ENOSPC) ||
	    (frdp_auth_failure_limiter_bind_alias(&limiter, "overflow", "canonical", 160) != 0))
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
	if (test_canonical_aliases_share_budget() != 0)
		return -1;
	if (test_alias_rebinding_compresses_chains() != 0)
		return -1;
	if (test_alias_binding_merges_existing_budgets() != 0)
		return -1;
	if (test_conflicting_alias_rebinding_fails_closed() != 0)
		return -1;
	if (test_alias_capacity_is_bounded_and_expires() != 0)
		return -1;
	if (test_capacity_is_bounded_and_fail_closed() != 0)
		return -1;
	if (test_rejects_invalid_policy_and_keys() != 0)
		return -1;
	return 0;
}

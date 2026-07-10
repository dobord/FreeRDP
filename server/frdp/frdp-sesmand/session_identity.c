#include "session_identity.h"

#include <grp.h>
#include <unistd.h>

#define FRDP_SESMAND_IDENTITY_MAX_GROUPS 32U

static int group_sets_match(const gid_t* expected, const gid_t* current, size_t count)
{
	for (size_t x = 0; x < count; x++)
	{
		int found = 0;

		for (size_t y = 0; y < count; y++)
		{
			if (expected[x] == current[y])
			{
				found = 1;
				break;
			}
		}
		if (!found)
			return 0;
		for (size_t y = x + 1U; y < count; y++)
		{
			if (expected[x] == expected[y])
				return 0;
		}
	}
	return 1;
}

int frdp_sesmand_apply_session_identity_with_ops(
    uid_t uid, gid_t gid, const gid_t* groups, size_t group_count,
    const frdpSesmandSessionIdentityOps* ops)
{
	gid_t current[FRDP_SESMAND_IDENTITY_MAX_GROUPS] = { 0 };
	int current_count = 0;

	if (!groups || (group_count == 0U) ||
	    (group_count > FRDP_SESMAND_IDENTITY_MAX_GROUPS) || !ops || !ops->getuid_fn ||
	    !ops->geteuid_fn || !ops->getgid_fn || !ops->getegid_fn || !ops->getgroups_fn ||
	    !ops->setgroups_fn || !ops->setgid_fn || !ops->setuid_fn)
		return -1;

	if (ops->geteuid_fn() == 0)
	{
		if (ops->setgroups_fn(group_count, groups) != 0 || ops->setgid_fn(gid) != 0 ||
		    ops->setuid_fn(uid) != 0)
			return -1;
		return 0;
	}

	if ((ops->getuid_fn() != uid) || (ops->geteuid_fn() != uid) ||
	    (ops->getgid_fn() != gid) || (ops->getegid_fn() != gid))
		return -1;
	current_count = ops->getgroups_fn(0, NULL);
	if ((current_count < 0) || ((size_t)current_count != group_count))
		return -1;
	if (ops->getgroups_fn(current_count, current) != current_count)
		return -1;
	return group_sets_match(groups, current, group_count) ? 0 : -1;
}

int frdp_sesmand_apply_session_identity(uid_t uid, gid_t gid, const gid_t* groups,
                                        size_t group_count)
{
	const frdpSesmandSessionIdentityOps ops = { .getuid_fn = getuid,
		                                         .geteuid_fn = geteuid,
		                                         .getgid_fn = getgid,
		                                         .getegid_fn = getegid,
		                                         .getgroups_fn = getgroups,
		                                         .setgroups_fn = setgroups,
		                                         .setgid_fn = setgid,
		                                         .setuid_fn = setuid };

	return frdp_sesmand_apply_session_identity_with_ops(uid, gid, groups, group_count, &ops);
}

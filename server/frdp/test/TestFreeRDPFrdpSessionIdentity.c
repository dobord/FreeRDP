#include "frdp-sesmand/session_identity.h"

#include <stdio.h>
#include <string.h>

typedef struct
{
	uid_t uid;
	uid_t euid;
	gid_t gid;
	gid_t egid;
	gid_t groups[4];
	int group_count;
	unsigned fail_mask;
	unsigned getgroups_calls;
	unsigned sequence;
	unsigned setgroups_order;
	unsigned setgid_order;
	unsigned setuid_order;
} IdentityProbe;

static IdentityProbe* g_probe = NULL;

static uid_t probe_getuid(void)
{
	return g_probe->uid;
}

static uid_t probe_geteuid(void)
{
	return g_probe->euid;
}

static gid_t probe_getgid(void)
{
	return g_probe->gid;
}

static gid_t probe_getegid(void)
{
	return g_probe->egid;
}

static int probe_getgroups(int size, gid_t list[])
{
	g_probe->getgroups_calls++;
	if ((g_probe->fail_mask & 0x01U) != 0U)
		return -1;
	if (((g_probe->fail_mask & 0x10U) != 0U) && (size != 0))
		return -1;
	if (size == 0)
		return g_probe->group_count;
	if (!list || (size != g_probe->group_count))
		return -1;
	memcpy(list, g_probe->groups, (size_t)size * sizeof(list[0]));
	return size;
}

static int probe_setgroups(size_t size, const gid_t* list)
{
	g_probe->setgroups_order = ++g_probe->sequence;
	if ((g_probe->fail_mask & 0x02U) != 0U || !list || (size != 2U) ||
	    (list[0] != 1000) || (list[1] != 27))
		return -1;
	return 0;
}

static int probe_setgid(gid_t gid)
{
	g_probe->setgid_order = ++g_probe->sequence;
	return ((g_probe->fail_mask & 0x04U) == 0U && gid == 1000) ? 0 : -1;
}

static int probe_setuid(uid_t uid)
{
	g_probe->setuid_order = ++g_probe->sequence;
	return ((g_probe->fail_mask & 0x08U) == 0U && uid == 1000) ? 0 : -1;
}

static const frdpSesmandSessionIdentityOps TEST_OPS = { .getuid_fn = probe_getuid,
	                                                    .geteuid_fn = probe_geteuid,
	                                                    .getgid_fn = probe_getgid,
	                                                    .getegid_fn = probe_getegid,
	                                                    .getgroups_fn = probe_getgroups,
	                                                    .setgroups_fn = probe_setgroups,
	                                                    .setgid_fn = probe_setgid,
	                                                    .setuid_fn = probe_setuid };

static int test_root_drop_order(void)
{
	const gid_t groups[] = { 1000, 27 };
	IdentityProbe probe = { .uid = 0, .euid = 0, .gid = 0, .egid = 0 };

	g_probe = &probe;
	if (frdp_sesmand_apply_session_identity_with_ops(1000, 1000, groups, 2, &TEST_OPS) != 0)
		return -1;
	if ((probe.setgroups_order != 1U) || (probe.setgid_order != 2U) ||
	    (probe.setuid_order != 3U))
		return -1;
	for (unsigned mask = 0x02U; mask <= 0x08U; mask <<= 1U)
	{
		memset(&probe, 0, sizeof(probe));
		probe.fail_mask = mask;
		g_probe = &probe;
		if (frdp_sesmand_apply_session_identity_with_ops(1000, 1000, groups, 2, &TEST_OPS) ==
		    0)
			return -1;
	}
	return 0;
}

static int test_same_user_identity(void)
{
	const gid_t groups[] = { 1000, 27 };
	IdentityProbe probe = { .uid = 1000,
		                    .euid = 1000,
		                    .gid = 1000,
		                    .egid = 1000,
		                    .groups = { 27, 1000 },
		                    .group_count = 2 };

	g_probe = &probe;
	if (frdp_sesmand_apply_session_identity_with_ops(1000, 1000, groups, 2, &TEST_OPS) != 0)
		return -1;
	return (probe.sequence == 0U) ? 0 : -1;
}

static int test_same_user_mismatch_rejected(void)
{
	const gid_t groups[] = { 1000, 27 };
	const gid_t duplicate_groups[] = { 1000, 1000 };
	IdentityProbe probe = { .uid = 1000,
		                    .euid = 1000,
		                    .gid = 1000,
		                    .egid = 1000,
		                    .groups = { 1000, 27 },
		                    .group_count = 2 };

	g_probe = &probe;
	probe.uid = 1001;
	if (frdp_sesmand_apply_session_identity_with_ops(1000, 1000, groups, 2, &TEST_OPS) == 0)
		return -1;
	probe.uid = 1000;
	probe.euid = 1001;
	if (frdp_sesmand_apply_session_identity_with_ops(1000, 1000, groups, 2, &TEST_OPS) == 0)
		return -1;
	probe.euid = 1000;
	probe.gid = 1001;
	if (frdp_sesmand_apply_session_identity_with_ops(1000, 1000, groups, 2, &TEST_OPS) == 0)
		return -1;
	probe.gid = 1000;
	probe.egid = 1001;
	if (frdp_sesmand_apply_session_identity_with_ops(1000, 1000, groups, 2, &TEST_OPS) == 0)
		return -1;
	probe.egid = 1000;
	probe.groups[1] = 46;
	if (frdp_sesmand_apply_session_identity_with_ops(1000, 1000, groups, 2, &TEST_OPS) == 0)
		return -1;
	probe.groups[1] = 27;
	probe.group_count = 1;
	if (frdp_sesmand_apply_session_identity_with_ops(1000, 1000, groups, 2, &TEST_OPS) == 0)
		return -1;
	probe.group_count = 2;
	probe.fail_mask = 0x01U;
	if (frdp_sesmand_apply_session_identity_with_ops(1000, 1000, groups, 2, &TEST_OPS) == 0)
		return -1;
	probe.fail_mask = 0x10U;
	if (frdp_sesmand_apply_session_identity_with_ops(1000, 1000, groups, 2, &TEST_OPS) == 0)
		return -1;
	probe.fail_mask = 0;
	probe.groups[0] = 1000;
	probe.groups[1] = 1000;
	return frdp_sesmand_apply_session_identity_with_ops(1000, 1000, duplicate_groups, 2,
	                                                    &TEST_OPS) == 0
	           ? -1
	           : 0;
}

static int test_invalid_arguments(void)
{
	const gid_t groups[] = { 1000 };
	frdpSesmandSessionIdentityOps incomplete = TEST_OPS;
	IdentityProbe probe = { .uid = 1000, .euid = 1000, .gid = 1000, .egid = 1000 };

	g_probe = &probe;
	incomplete.setuid_fn = NULL;
	if (frdp_sesmand_apply_session_identity_with_ops(1000, 1000, NULL, 1, &TEST_OPS) == 0)
		return -1;
	if (frdp_sesmand_apply_session_identity_with_ops(1000, 1000, groups, 0, &TEST_OPS) == 0)
		return -1;
	if (frdp_sesmand_apply_session_identity_with_ops(1000, 1000, groups, 33, &TEST_OPS) == 0)
		return -1;
	return frdp_sesmand_apply_session_identity_with_ops(1000, 1000, groups, 1, &incomplete) ==
	               0
	           ? -1
	           : 0;
}

int TestFreeRDPFrdpSessionIdentity(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if (test_root_drop_order() != 0)
	{
		fprintf(stderr, "root session identity drop failed\n");
		return -1;
	}
	if (test_same_user_identity() != 0)
	{
		fprintf(stderr, "same-user session identity failed\n");
		return -1;
	}
	if (test_same_user_mismatch_rejected() != 0)
	{
		fprintf(stderr, "same-user identity mismatch rejection failed\n");
		return -1;
	}
	if (test_invalid_arguments() != 0)
	{
		fprintf(stderr, "session identity invalid-argument rejection failed\n");
		return -1;
	}
	return 0;
}

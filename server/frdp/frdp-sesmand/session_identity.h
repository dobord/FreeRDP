#ifndef FRDP_SESMAND_SESSION_IDENTITY_H
#define FRDP_SESMAND_SESSION_IDENTITY_H

#include <stddef.h>
#include <sys/types.h>

typedef struct
{
	uid_t (*getuid_fn)(void);
	uid_t (*geteuid_fn)(void);
	gid_t (*getgid_fn)(void);
	gid_t (*getegid_fn)(void);
	int (*getgroups_fn)(int size, gid_t list[]);
	int (*setgroups_fn)(size_t size, const gid_t* list);
	int (*setgid_fn)(gid_t gid);
	int (*setuid_fn)(uid_t uid);
} frdpSesmandSessionIdentityOps;

int frdp_sesmand_apply_session_identity_with_ops(
    uid_t uid, gid_t gid, const gid_t* groups, size_t group_count,
    const frdpSesmandSessionIdentityOps* ops);
int frdp_sesmand_apply_session_identity(uid_t uid, gid_t gid, const gid_t* groups,
                                        size_t group_count);

#endif

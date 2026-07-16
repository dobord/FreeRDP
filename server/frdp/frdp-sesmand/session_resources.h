#ifndef FRDP_SESMAND_SESSION_RESOURCES_H
#define FRDP_SESMAND_SESSION_RESOURCES_H

#include <sys/resource.h>

#include "../config/frdp-config.h"

typedef int (*frdpSesmandSetRlimitFn)(int resource, const struct rlimit* limit, void* context);

int frdp_sesmand_session_capacity_available(const frdpSessionResourcePolicy* policy,
                                            uint32_t current_sessions);
int frdp_sesmand_apply_session_resource_policy(const frdpSessionResourcePolicy* policy);
int frdp_sesmand_apply_session_resource_policy_ex(const frdpSessionResourcePolicy* policy,
                                                  frdpSesmandSetRlimitFn setrlimit_fn,
                                                  void* context);

#endif

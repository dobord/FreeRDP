#ifndef FRDP_SESMAND_SESSION_SCOPE_H
#define FRDP_SESMAND_SESSION_SCOPE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "../config/frdp-config.h"

#define FRDP_SESMAND_SCOPE_NAME_SIZE 128U

typedef struct frdp_sesmand_scope_manager
{
	void* bus;
} frdpSesmandScopeManager;

int frdp_sesmand_scope_manager_init(frdpSesmandScopeManager* manager);
void frdp_sesmand_scope_manager_uninit(frdpSesmandScopeManager* manager);
int frdp_sesmand_scope_name(const char* session_id, char* name, size_t name_size);
int frdp_sesmand_scope_limits(const frdpSessionResourcePolicy* policy, uint64_t* tasks_max,
                              uint64_t* memory_max, uint64_t* cpu_quota_per_sec_usec);
int frdp_sesmand_scope_start(frdpSesmandScopeManager* manager, const char* session_id, pid_t pid,
                             const frdpSessionResourcePolicy* policy, char* name, size_t name_size);
int frdp_sesmand_scope_update(frdpSesmandScopeManager* manager, const char* name,
                              const frdpSessionResourcePolicy* policy);
int frdp_sesmand_scope_stop(frdpSesmandScopeManager* manager, const char* name);

#endif

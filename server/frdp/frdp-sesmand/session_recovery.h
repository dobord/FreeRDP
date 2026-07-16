#ifndef FRDP_SESMAND_SESSION_RECOVERY_H
#define FRDP_SESMAND_SESSION_RECOVERY_H

#include <stdint.h>
#include <sys/types.h>

typedef struct frdp_sesmand_scope_manager frdpSesmandScopeManager;

int frdp_sesmand_session_reconcile_all(const char* dir, frdpSesmandScopeManager* scope_manager);
int frdp_sesmand_session_recovery_supported(void);
int frdp_sesmand_session_unlink_artifact(const char* path, uint64_t expected_dev,
                                         uint64_t expected_ino, mode_t expected_type);

#endif

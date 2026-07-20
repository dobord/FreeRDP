#ifndef FRDP_SESMAND_SESSION_RECOVERY_H
#define FRDP_SESMAND_SESSION_RECOVERY_H

#include <stdint.h>
#include <sys/types.h>

typedef struct frdp_sesmand_scope_manager frdpSesmandScopeManager;
typedef struct frdp_sesmand_session_metadata frdpSesmandSessionMetadata;

typedef enum
{
	FRDP_SESMAND_SESSION_RESTORE_ERROR = -1,
	FRDP_SESMAND_SESSION_RESTORE_CLEANUP = 0,
	FRDP_SESMAND_SESSION_RESTORE_IMPORTED = 1
} frdpSesmandSessionRestoreResult;

typedef frdpSesmandSessionRestoreResult (*frdpSesmandSessionRestoreCallback)(
    const frdpSesmandSessionMetadata* metadata, uint64_t file_dev, uint64_t file_ino,
    void* context);

int frdp_sesmand_session_reconcile_all(const char* dir, frdpSesmandScopeManager* scope_manager);
int frdp_sesmand_session_restore_or_reconcile_all(
    const char* dir, frdpSesmandScopeManager* scope_manager,
    frdpSesmandSessionRestoreCallback restore, void* restore_context);
int frdp_sesmand_session_recovery_supported(void);
int frdp_sesmand_session_unlink_artifact(const char* path, uint64_t expected_dev,
                                         uint64_t expected_ino, mode_t expected_type);

#endif

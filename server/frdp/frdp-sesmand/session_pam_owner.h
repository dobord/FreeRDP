#ifndef FRDP_SESMAND_SESSION_PAM_OWNER_H
#define FRDP_SESMAND_SESSION_PAM_OWNER_H

#include <stddef.h>
#include <sys/types.h>

typedef struct
{
	pid_t pid;
	int active;
} frdpSesmandPamOwner;

int frdp_sesmand_pam_owner_endpoint(char* dst, size_t dst_size, const char* runtime_dir,
                                    const char* session_id);
int frdp_sesmand_pam_owner_start(const char* runtime_dir, const char* session_id,
                                 const char* pam_service, const char* user, const char* rhost,
                                 frdpSesmandPamOwner* owner);
int frdp_sesmand_pam_owner_bind_agent(const char* runtime_dir, const char* session_id,
                                      frdpSesmandPamOwner* owner, pid_t agent_pid, pid_t pgid);
int frdp_sesmand_pam_owner_bind_logind(const char* runtime_dir, const char* session_id,
                                       frdpSesmandPamOwner* owner, int fifo_fd);
int frdp_sesmand_pam_owner_close(const char* runtime_dir, const char* session_id,
                                 frdpSesmandPamOwner* owner);
int frdp_sesmand_pam_owner_prepare_close(const char* runtime_dir, const char* session_id,
                                         frdpSesmandPamOwner* owner);
int frdp_sesmand_pam_owner_recover(const char* runtime_dir, const char* session_id);
int frdp_sesmand_pam_owner_finalize(const char* runtime_dir, const char* session_id);
int frdp_sesmand_pam_owner_reconcile_stale(const char* runtime_dir);

#endif

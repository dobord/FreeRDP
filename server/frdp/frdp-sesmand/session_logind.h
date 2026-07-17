#ifndef FRDP_SESMAND_SESSION_LOGIND_H
#define FRDP_SESMAND_SESSION_LOGIND_H

#include <stddef.h>
#include <sys/types.h>

#define FRDP_SESMAND_LOGIND_ID_SIZE 128U
#define FRDP_SESMAND_LOGIND_RUNTIME_SIZE 256U

typedef struct frdp_sesmand_logind_manager
{
	void* bus;
} frdpSesmandLogindManager;

typedef struct frdp_sesmand_logind_session
{
	char id[FRDP_SESMAND_LOGIND_ID_SIZE];
	char runtime_path[FRDP_SESMAND_LOGIND_RUNTIME_SIZE];
	int fifo_fd;
} frdpSesmandLogindSession;

int frdp_sesmand_logind_manager_init(frdpSesmandLogindManager* manager);
void frdp_sesmand_logind_manager_uninit(frdpSesmandLogindManager* manager);
int frdp_sesmand_logind_create(frdpSesmandLogindManager* manager, uid_t uid, pid_t pid,
                               const char* service, const char* user, const char* remote_host,
                               const char* display, frdpSesmandLogindSession* session);
int frdp_sesmand_logind_release(frdpSesmandLogindManager* manager,
                                frdpSesmandLogindSession* session);
void frdp_sesmand_logind_session_close(frdpSesmandLogindSession* session);

#endif

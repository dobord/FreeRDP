#ifndef FRDP_SESMAND_SESSION_CLEANUP_H
#define FRDP_SESMAND_SESSION_CLEANUP_H

#include "session_state.h"

typedef struct
{
	frdpSesmandSessionState state;
	int has_process_group;
	int has_pam_handle;
	int credentials_established;
	int has_agent_socket;
	int has_display_reservation;
} frdpSesmandSessionCleanupContext;

typedef struct
{
	int mark_stopping;
	int terminate_process_group;
	int close_pam_session;
	int delete_pam_credentials;
	int unlink_agent_socket;
	int release_display_reservation;
	int mark_dead;
} frdpSesmandSessionCleanupPlan;

int frdp_sesmand_session_cleanup_plan(const frdpSesmandSessionCleanupContext* context,
                                      frdpSesmandSessionCleanupPlan* plan);

#endif

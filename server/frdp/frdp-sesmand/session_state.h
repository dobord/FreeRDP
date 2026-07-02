#ifndef FRDP_SESMAND_SESSION_STATE_H
#define FRDP_SESMAND_SESSION_STATE_H

typedef enum
{
	FRDP_SESMAND_SESSION_AUTHENTICATED = 0,
	FRDP_SESMAND_SESSION_STARTING,
	FRDP_SESMAND_SESSION_ACTIVE,
	FRDP_SESMAND_SESSION_DISCONNECTED,
	FRDP_SESMAND_SESSION_STOPPING,
	FRDP_SESMAND_SESSION_DEAD
} frdpSesmandSessionState;

int frdp_sesmand_session_state_is_valid(frdpSesmandSessionState state);
int frdp_sesmand_session_state_can_transition(frdpSesmandSessionState from,
                                              frdpSesmandSessionState to);
const char* frdp_sesmand_session_state_string(frdpSesmandSessionState state);

#endif

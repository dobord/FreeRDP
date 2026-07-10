#include "session_disconnect.h"

int frdp_sesmand_session_disconnect_begin(frdpSesmandSessionState* state, int has_agent_socket)
{
	if (!state || !has_agent_socket || (*state != FRDP_SESMAND_SESSION_ACTIVE) ||
	    !frdp_sesmand_session_state_can_transition(*state, FRDP_SESMAND_SESSION_DISCONNECTED))
		return -1;

	*state = FRDP_SESMAND_SESSION_DISCONNECTED;
	return 0;
}

int frdp_sesmand_session_disconnect_rollback(frdpSesmandSessionState* state)
{
	if (!state || (*state != FRDP_SESMAND_SESSION_DISCONNECTED) ||
	    !frdp_sesmand_session_state_can_transition(*state, FRDP_SESMAND_SESSION_ACTIVE))
		return -1;

	*state = FRDP_SESMAND_SESSION_ACTIVE;
	return 0;
}

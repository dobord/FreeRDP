#include "session_state.h"

int frdp_sesmand_session_state_is_valid(frdpSesmandSessionState state)
{
	return (state >= FRDP_SESMAND_SESSION_AUTHENTICATED) && (state <= FRDP_SESMAND_SESSION_DEAD);
}

int frdp_sesmand_session_state_can_transition(frdpSesmandSessionState from,
                                              frdpSesmandSessionState to)
{
	if (!frdp_sesmand_session_state_is_valid(from) || !frdp_sesmand_session_state_is_valid(to))
		return 0;
	if (from == to)
		return 1;

	switch (from)
	{
		case FRDP_SESMAND_SESSION_AUTHENTICATED:
			return (to == FRDP_SESMAND_SESSION_STARTING) || (to == FRDP_SESMAND_SESSION_DEAD);
		case FRDP_SESMAND_SESSION_STARTING:
			return (to == FRDP_SESMAND_SESSION_ACTIVE) || (to == FRDP_SESMAND_SESSION_DEAD);
		case FRDP_SESMAND_SESSION_ACTIVE:
			return (to == FRDP_SESMAND_SESSION_DISCONNECTED) ||
			       (to == FRDP_SESMAND_SESSION_STOPPING);
		case FRDP_SESMAND_SESSION_DISCONNECTED:
			return (to == FRDP_SESMAND_SESSION_ACTIVE) || (to == FRDP_SESMAND_SESSION_STOPPING);
		case FRDP_SESMAND_SESSION_STOPPING:
			return to == FRDP_SESMAND_SESSION_DEAD;
		case FRDP_SESMAND_SESSION_DEAD:
		default:
			return 0;
	}
}

const char* frdp_sesmand_session_state_string(frdpSesmandSessionState state)
{
	switch (state)
	{
		case FRDP_SESMAND_SESSION_AUTHENTICATED:
			return "authenticated";
		case FRDP_SESMAND_SESSION_STARTING:
			return "starting";
		case FRDP_SESMAND_SESSION_ACTIVE:
			return "active";
		case FRDP_SESMAND_SESSION_DISCONNECTED:
			return "disconnected";
		case FRDP_SESMAND_SESSION_STOPPING:
			return "stopping";
		case FRDP_SESMAND_SESSION_DEAD:
			return "dead";
		default:
			return "unknown";
	}
}

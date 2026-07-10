#ifndef FRDP_SESMAND_SESSION_DISCONNECT_H
#define FRDP_SESMAND_SESSION_DISCONNECT_H

#include "session_state.h"

int frdp_sesmand_session_disconnect_begin(frdpSesmandSessionState* state, int has_agent_socket);
int frdp_sesmand_session_disconnect_rollback(frdpSesmandSessionState* state);

#endif

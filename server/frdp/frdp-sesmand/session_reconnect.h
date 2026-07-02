#ifndef FRDP_SESMAND_SESSION_RECONNECT_H
#define FRDP_SESMAND_SESSION_RECONNECT_H

#include <stddef.h>

#include "session_state.h"

typedef struct
{
	const char* session_id;
	const char* user;
	frdpSesmandSessionState state;
	unsigned long long start_time;
} frdpSesmandReconnectCandidate;

int frdp_sesmand_reconnect_select(const frdpSesmandReconnectCandidate* candidates,
                                  size_t candidate_count, const char* requested_session_id,
                                  const char* user, size_t* selected_index);

#endif

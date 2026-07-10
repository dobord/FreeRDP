#ifndef FRDP_SESMAND_SESSION_RECONNECT_H
#define FRDP_SESMAND_SESSION_RECONNECT_H

#include <stddef.h>
#include <stdint.h>

#include "session_state.h"

typedef struct
{
	const char* session_id;
	const char* user;
	uint64_t uid;
	frdpSesmandSessionState state;
	unsigned long long start_time;
} frdpSesmandReconnectCandidate;

typedef enum
{
	FRDP_SESMAND_RECONNECT_ERROR = -1,
	FRDP_SESMAND_RECONNECT_SELECTED = 0,
	FRDP_SESMAND_RECONNECT_NOT_FOUND = 1
} frdpSesmandReconnectResult;

frdpSesmandReconnectResult frdp_sesmand_reconnect_select(
    const frdpSesmandReconnectCandidate* candidates, size_t candidate_count,
    const char* requested_session_id, const char* user, uint64_t uid, size_t* selected_index);

#endif

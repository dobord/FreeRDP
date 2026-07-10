#include "session_reconnect.h"

#include <string.h>

static int string_is_empty(const char* value)
{
	return !value || (value[0] == '\0');
}

static int string_matches(const char* left, const char* right)
{
	return !string_is_empty(left) && !string_is_empty(right) && (strcmp(left, right) == 0);
}

static int reconnectable_state(frdpSesmandSessionState state)
{
	return (state == FRDP_SESMAND_SESSION_ACTIVE) || (state == FRDP_SESMAND_SESSION_DISCONNECTED);
}

static int candidate_is_valid(const frdpSesmandReconnectCandidate* candidate)
{
	return candidate && !string_is_empty(candidate->session_id) &&
	       !string_is_empty(candidate->user) &&
	       frdp_sesmand_session_state_is_valid(candidate->state);
}

frdpSesmandReconnectResult frdp_sesmand_reconnect_select(
    const frdpSesmandReconnectCandidate* candidates, size_t candidate_count,
    const char* requested_session_id, const char* user, uint64_t uid, size_t* selected_index)
{
	size_t selected = 0;
	int found = 0;
	int ambiguous = 0;
	const int has_session_id = !string_is_empty(requested_session_id);

	if (!selected_index || !candidates || (candidate_count == 0) || string_is_empty(user))
		return FRDP_SESMAND_RECONNECT_ERROR;

	*selected_index = 0;
	for (size_t x = 0; x < candidate_count; x++)
	{
		const frdpSesmandReconnectCandidate* candidate = &candidates[x];

		if (!candidate_is_valid(candidate) || !reconnectable_state(candidate->state) ||
		    !string_matches(candidate->user, user) || (candidate->uid != uid))
			continue;
		if (has_session_id)
		{
			if (!string_matches(candidate->session_id, requested_session_id))
				continue;
			if (found)
				return FRDP_SESMAND_RECONNECT_ERROR;
			selected = x;
			found = 1;
			continue;
		}
		if (candidate->state != FRDP_SESMAND_SESSION_DISCONNECTED)
			continue;
		if (!found || (candidate->start_time > candidates[selected].start_time))
		{
			selected = x;
			found = 1;
			ambiguous = 0;
		}
		else if (candidate->start_time == candidates[selected].start_time)
		{
			ambiguous = 1;
		}
	}

	if (ambiguous)
		return FRDP_SESMAND_RECONNECT_ERROR;
	if (!found)
		return FRDP_SESMAND_RECONNECT_NOT_FOUND;
	*selected_index = selected;
	return FRDP_SESMAND_RECONNECT_SELECTED;
}

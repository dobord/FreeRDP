#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "frdp-sesmand/session_cleanup.h"
#include "frdp-sesmand/session_reconnect.h"
#include "frdp-sesmand/session_state.h"

#define FRDP_SESSION_LIFECYCLE_FUZZ_MAX_SIZE 256U
#define FRDP_SESSION_LIFECYCLE_FUZZ_CANDIDATES 4U

static uint32_t read_u32(const uint8_t* data, size_t size, size_t offset)
{
	uint32_t value = 0;

	for (size_t x = 0; x < 4U; x++)
	{
		if (offset + x < size)
			value |= ((uint32_t)data[offset + x]) << (x * 8U);
	}
	return value;
}

static unsigned long long read_u64(const uint8_t* data, size_t size, size_t offset)
{
	unsigned long long value = 0;

	for (size_t x = 0; x < 8U; x++)
	{
		if (offset + x < size)
			value |= ((unsigned long long)data[offset + x]) << (x * 8U);
	}
	return value;
}

static frdpSesmandSessionState fuzz_state(const uint8_t* data, size_t size, size_t offset)
{
	return (frdpSesmandSessionState)(int)(read_u32(data, size, offset) % 8U);
}

static void fuzz_session_state_policy(const uint8_t* data, size_t size)
{
	const frdpSesmandSessionState from = fuzz_state(data, size, 0);
	const frdpSesmandSessionState to = fuzz_state(data, size, 4);

	(void)frdp_sesmand_session_state_is_valid(from);
	(void)frdp_sesmand_session_state_can_transition(from, to);
	(void)frdp_sesmand_session_state_string(from);
}

static void fuzz_session_cleanup_policy(const uint8_t* data, size_t size)
{
	frdpSesmandSessionCleanupPlan plan = { 0 };
	const uint32_t flags = read_u32(data, size, 8);
	const frdpSesmandSessionCleanupContext context = { .state = fuzz_state(data, size, 12),
		                                               .has_process_group = (flags & 0x01U) != 0,
		                                               .has_pam_handle = (flags & 0x02U) != 0,
		                                               .credentials_established =
		                                                   (flags & 0x04U) != 0,
		                                               .has_agent_socket = (flags & 0x08U) != 0,
		                                               .has_display_reservation =
		                                                   (flags & 0x10U) != 0 };

	(void)frdp_sesmand_session_cleanup_plan(&context, &plan);
}

static void fill_candidate(frdpSesmandReconnectCandidate* candidate, char session_ids[][16],
                           char users[][16], size_t index, const uint8_t* data, size_t size)
{
	const size_t offset = 16U + (index * 32U);
	const uint32_t selector = read_u32(data, size, offset);

	snprintf(session_ids[index], sizeof(session_ids[index]), "session-%u",
	         selector % (FRDP_SESSION_LIFECYCLE_FUZZ_CANDIDATES - 1U));
	snprintf(users[index], sizeof(users[index]), "user-%u", read_u32(data, size, offset + 4U) % 3U);
	candidate->session_id = (selector & 0x80U) ? "" : session_ids[index];
	candidate->user = (selector & 0x40U) ? "" : users[index];
	candidate->state = fuzz_state(data, size, offset + 8U);
	candidate->start_time = read_u64(data, size, offset + 12U);
}

static void fuzz_session_reconnect_policy(const uint8_t* data, size_t size)
{
	frdpSesmandReconnectCandidate candidates[FRDP_SESSION_LIFECYCLE_FUZZ_CANDIDATES];
	char session_ids[FRDP_SESSION_LIFECYCLE_FUZZ_CANDIDATES][16] = { 0 };
	char users[FRDP_SESSION_LIFECYCLE_FUZZ_CANDIDATES][16] = { 0 };
	char requested_session_id[16] = { 0 };
	char requested_user[16] = { 0 };
	size_t selected = 0;
	const uint32_t selector = read_u32(data, size, 144U);

	for (size_t x = 0; x < FRDP_SESSION_LIFECYCLE_FUZZ_CANDIDATES; x++)
		fill_candidate(&candidates[x], session_ids, users, x, data, size);

	snprintf(requested_session_id, sizeof(requested_session_id), "session-%u",
	         read_u32(data, size, 148U) % (FRDP_SESSION_LIFECYCLE_FUZZ_CANDIDATES - 1U));
	snprintf(requested_user, sizeof(requested_user), "user-%u", read_u32(data, size, 152U) % 3U);

	(void)frdp_sesmand_reconnect_select(candidates, FRDP_SESSION_LIFECYCLE_FUZZ_CANDIDATES,
	                                    (selector & 0x01U) ? requested_session_id : NULL,
	                                    (selector & 0x02U) ? "" : requested_user, &selected);
}

int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
	if (!Data || (Size > FRDP_SESSION_LIFECYCLE_FUZZ_MAX_SIZE))
		return 0;
	fuzz_session_state_policy(Data, Size);
	fuzz_session_cleanup_policy(Data, Size);
	fuzz_session_reconnect_policy(Data, Size);
	return 0;
}

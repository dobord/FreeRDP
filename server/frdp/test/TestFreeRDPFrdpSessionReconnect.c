#include "frdp-sesmand/session_reconnect.h"

#include <stdio.h>

static int expect_selected(const frdpSesmandReconnectCandidate* candidates, size_t candidate_count,
                           const char* requested_session_id, const char* user,
                           size_t expected_index)
{
	size_t selected = 99;

	if (frdp_sesmand_reconnect_select(candidates, candidate_count, requested_session_id, user,
	                                  &selected) != 0)
		return -1;
	if (selected != expected_index)
	{
		fprintf(stderr, "expected reconnect index %zu, got %zu\n", expected_index, selected);
		return -1;
	}
	return 0;
}

static int expect_no_selection(const frdpSesmandReconnectCandidate* candidates,
                               size_t candidate_count, const char* requested_session_id,
                               const char* user)
{
	size_t selected = 99;

	return frdp_sesmand_reconnect_select(candidates, candidate_count, requested_session_id, user,
	                                     &selected) != 0
	           ? 0
	           : -1;
}

static int test_session_id_selection(void)
{
	const frdpSesmandReconnectCandidate candidates[] = {
		{ "session-a", "alice", FRDP_SESMAND_SESSION_DISCONNECTED, 10 },
		{ "session-b", "bob", FRDP_SESMAND_SESSION_DISCONNECTED, 20 },
		{ "session-c", "alice", FRDP_SESMAND_SESSION_ACTIVE, 30 }
	};

	if (expect_selected(candidates, 3, "session-c", "alice", 2) != 0)
		return -1;
	if (expect_no_selection(candidates, 3, "session-b", "alice") != 0)
		return -1;
	return expect_no_selection(candidates, 3, "missing", "alice");
}

static int test_user_selection_prefers_newest_disconnected(void)
{
	const frdpSesmandReconnectCandidate candidates[] = {
		{ "old", "alice", FRDP_SESMAND_SESSION_DISCONNECTED, 10 },
		{ "active", "alice", FRDP_SESMAND_SESSION_ACTIVE, 40 },
		{ "new", "alice", FRDP_SESMAND_SESSION_DISCONNECTED, 30 },
		{ "other", "bob", FRDP_SESMAND_SESSION_DISCONNECTED, 50 }
	};

	return expect_selected(candidates, 4, NULL, "alice", 2);
}

static int test_non_reconnectable_states_are_ignored(void)
{
	const frdpSesmandReconnectCandidate candidates[] = {
		{ "starting", "alice", FRDP_SESMAND_SESSION_STARTING, 10 },
		{ "stopping", "alice", FRDP_SESMAND_SESSION_STOPPING, 20 },
		{ "dead", "alice", FRDP_SESMAND_SESSION_DEAD, 30 }
	};

	if (expect_no_selection(candidates, 3, NULL, "alice") != 0)
		return -1;
	if (expect_no_selection(candidates, 3, "stopping", "alice") != 0)
		return -1;
	return expect_no_selection(candidates, 3, "dead", "alice");
}

static int test_ambiguous_selection_fails_closed(void)
{
	const frdpSesmandReconnectCandidate duplicate_ids[] = {
		{ "duplicate", "alice", FRDP_SESMAND_SESSION_ACTIVE, 10 },
		{ "duplicate", "alice", FRDP_SESMAND_SESSION_DISCONNECTED, 20 }
	};
	const frdpSesmandReconnectCandidate duplicate_newest[] = {
		{ "session-a", "alice", FRDP_SESMAND_SESSION_DISCONNECTED, 30 },
		{ "session-b", "alice", FRDP_SESMAND_SESSION_DISCONNECTED, 30 }
	};

	if (expect_no_selection(duplicate_ids, 2, "duplicate", "alice") != 0)
		return -1;
	return expect_no_selection(duplicate_newest, 2, NULL, "alice");
}

static int test_invalid_reconnect_arguments(void)
{
	size_t selected = 99;
	const frdpSesmandReconnectCandidate candidate = { "session", "alice",
		                                              FRDP_SESMAND_SESSION_DISCONNECTED, 10 };

	if (frdp_sesmand_reconnect_select(NULL, 1, NULL, "alice", &selected) == 0)
		return -1;
	if (frdp_sesmand_reconnect_select(&candidate, 0, NULL, "alice", &selected) == 0)
		return -1;
	if (frdp_sesmand_reconnect_select(&candidate, 1, NULL, NULL, &selected) == 0)
		return -1;
	if (frdp_sesmand_reconnect_select(&candidate, 1, NULL, "alice", NULL) == 0)
		return -1;
	return 0;
}

int TestFreeRDPFrdpSessionReconnect(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if (test_session_id_selection() != 0)
	{
		fprintf(stderr, "session-id reconnect selection failed\n");
		return -1;
	}
	if (test_user_selection_prefers_newest_disconnected() != 0)
	{
		fprintf(stderr, "user reconnect selection failed\n");
		return -1;
	}
	if (test_non_reconnectable_states_are_ignored() != 0)
	{
		fprintf(stderr, "non-reconnectable state selection failed\n");
		return -1;
	}
	if (test_ambiguous_selection_fails_closed() != 0)
	{
		fprintf(stderr, "ambiguous reconnect selection failed\n");
		return -1;
	}
	if (test_invalid_reconnect_arguments() != 0)
	{
		fprintf(stderr, "invalid reconnect arguments failed\n");
		return -1;
	}
	return 0;
}

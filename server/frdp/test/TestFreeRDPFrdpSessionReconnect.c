#include "frdp-sesmand/session_reconnect.h"

#include <stdio.h>

static int expect_selected(const frdpSesmandReconnectCandidate* candidates, size_t candidate_count,
                           const char* requested_session_id, const char* user, uint64_t uid,
                           size_t expected_index)
{
	size_t selected = 99;

	if (frdp_sesmand_reconnect_select(candidates, candidate_count, requested_session_id, user, uid,
	                                  &selected) != FRDP_SESMAND_RECONNECT_SELECTED)
		return -1;
	if (selected != expected_index)
	{
		fprintf(stderr, "expected reconnect index %zu, got %zu\n", expected_index, selected);
		return -1;
	}
	return 0;
}

static int expect_selection_result(const frdpSesmandReconnectCandidate* candidates,
                                   size_t candidate_count, const char* requested_session_id,
                                   const char* user, uint64_t uid,
                                   frdpSesmandReconnectResult expected)
{
	size_t selected = 99;

	return frdp_sesmand_reconnect_select(candidates, candidate_count, requested_session_id, user,
	                                     uid, &selected) == expected
	           ? 0
	           : -1;
}

static int test_session_id_selection(void)
{
	const frdpSesmandReconnectCandidate candidates[] = {
		{ "session-a", "alice", 1000, FRDP_SESMAND_SESSION_DISCONNECTED, 10 },
		{ "session-b", "bob", 1001, FRDP_SESMAND_SESSION_DISCONNECTED, 20 },
		{ "session-c", "alice", 1000, FRDP_SESMAND_SESSION_ACTIVE, 30 }
	};

	if (expect_selected(candidates, 3, "session-c", "alice", 1000, 2) != 0)
		return -1;
	if (expect_selection_result(candidates, 3, "session-b", "alice", 1000,
	                            FRDP_SESMAND_RECONNECT_NOT_FOUND) != 0)
		return -1;
	if (expect_selection_result(candidates, 3, "session-a", "alice", 2000,
	                            FRDP_SESMAND_RECONNECT_NOT_FOUND) != 0)
		return -1;
	return expect_selection_result(candidates, 3, "missing", "alice", 1000,
	                               FRDP_SESMAND_RECONNECT_NOT_FOUND);
}

static int test_user_selection_prefers_newest_disconnected(void)
{
	const frdpSesmandReconnectCandidate candidates[] = {
		{ "old", "alice", 1000, FRDP_SESMAND_SESSION_DISCONNECTED, 10 },
		{ "active", "alice", 1000, FRDP_SESMAND_SESSION_ACTIVE, 40 },
		{ "wrong-uid", "alice", 2000, FRDP_SESMAND_SESSION_DISCONNECTED, 50 },
		{ "new", "alice", 1000, FRDP_SESMAND_SESSION_DISCONNECTED, 30 },
		{ "other", "bob", 1001, FRDP_SESMAND_SESSION_DISCONNECTED, 60 }
	};

	return expect_selected(candidates, 5, NULL, "alice", 1000, 3);
}

static int test_non_reconnectable_states_are_ignored(void)
{
	const frdpSesmandReconnectCandidate candidates[] = {
		{ "starting", "alice", 1000, FRDP_SESMAND_SESSION_STARTING, 10 },
		{ "stopping", "alice", 1000, FRDP_SESMAND_SESSION_STOPPING, 20 },
		{ "dead", "alice", 1000, FRDP_SESMAND_SESSION_DEAD, 30 }
	};

	if (expect_selection_result(candidates, 3, NULL, "alice", 1000,
	                            FRDP_SESMAND_RECONNECT_NOT_FOUND) != 0)
		return -1;
	if (expect_selection_result(candidates, 3, "stopping", "alice", 1000,
	                            FRDP_SESMAND_RECONNECT_NOT_FOUND) != 0)
		return -1;
	return expect_selection_result(candidates, 3, "dead", "alice", 1000,
	                               FRDP_SESMAND_RECONNECT_NOT_FOUND);
}

static int test_ambiguous_selection_fails_closed(void)
{
	const frdpSesmandReconnectCandidate duplicate_ids[] = {
		{ "duplicate", "alice", 1000, FRDP_SESMAND_SESSION_ACTIVE, 10 },
		{ "duplicate", "alice", 1000, FRDP_SESMAND_SESSION_DISCONNECTED, 20 }
	};
	const frdpSesmandReconnectCandidate duplicate_newest[] = {
		{ "session-a", "alice", 1000, FRDP_SESMAND_SESSION_DISCONNECTED, 30 },
		{ "session-b", "alice", 1000, FRDP_SESMAND_SESSION_DISCONNECTED, 30 }
	};

	if (expect_selection_result(duplicate_ids, 2, "duplicate", "alice", 1000,
	                            FRDP_SESMAND_RECONNECT_ERROR) != 0)
		return -1;
	return expect_selection_result(duplicate_newest, 2, NULL, "alice", 1000,
	                               FRDP_SESMAND_RECONNECT_ERROR);
}

static int test_invalid_reconnect_arguments(void)
{
	size_t selected = 99;
	const frdpSesmandReconnectCandidate candidate = { "session", "alice", 1000,
		                                              FRDP_SESMAND_SESSION_DISCONNECTED, 10 };

	if (frdp_sesmand_reconnect_select(NULL, 1, NULL, "alice", 1000, &selected) !=
	    FRDP_SESMAND_RECONNECT_ERROR)
		return -1;
	if (frdp_sesmand_reconnect_select(&candidate, 0, NULL, "alice", 1000, &selected) !=
	    FRDP_SESMAND_RECONNECT_ERROR)
		return -1;
	if (frdp_sesmand_reconnect_select(&candidate, 1, NULL, NULL, 1000, &selected) !=
	    FRDP_SESMAND_RECONNECT_ERROR)
		return -1;
	if (frdp_sesmand_reconnect_select(&candidate, 1, NULL, "alice", 1000, NULL) !=
	    FRDP_SESMAND_RECONNECT_ERROR)
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

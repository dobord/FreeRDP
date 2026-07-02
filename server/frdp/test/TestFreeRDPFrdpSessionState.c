#include "frdp-sesmand/session_state.h"

#include <stdio.h>
#include <string.h>

static int expect_transition(frdpSesmandSessionState from, frdpSesmandSessionState to, int allowed)
{
	return (frdp_sesmand_session_state_can_transition(from, to) == allowed) ? 0 : -1;
}

static int test_session_state_names(void)
{
	if (strcmp(frdp_sesmand_session_state_string(FRDP_SESMAND_SESSION_AUTHENTICATED),
	           "authenticated") != 0)
		return -1;
	if (strcmp(frdp_sesmand_session_state_string(FRDP_SESMAND_SESSION_STARTING), "starting") != 0)
		return -1;
	if (strcmp(frdp_sesmand_session_state_string(FRDP_SESMAND_SESSION_ACTIVE), "active") != 0)
		return -1;
	if (strcmp(frdp_sesmand_session_state_string(FRDP_SESMAND_SESSION_DISCONNECTED),
	           "disconnected") != 0)
		return -1;
	if (strcmp(frdp_sesmand_session_state_string(FRDP_SESMAND_SESSION_STOPPING), "stopping") != 0)
		return -1;
	if (strcmp(frdp_sesmand_session_state_string(FRDP_SESMAND_SESSION_DEAD), "dead") != 0)
		return -1;
	return strcmp(frdp_sesmand_session_state_string((frdpSesmandSessionState)-1), "unknown") == 0
	           ? 0
	           : -1;
}

static int test_session_state_transitions(void)
{
	if (expect_transition(FRDP_SESMAND_SESSION_AUTHENTICATED, FRDP_SESMAND_SESSION_STARTING, 1) !=
	    0)
		return -1;
	if (expect_transition(FRDP_SESMAND_SESSION_AUTHENTICATED, FRDP_SESMAND_SESSION_DEAD, 1) != 0)
		return -1;
	if (expect_transition(FRDP_SESMAND_SESSION_STARTING, FRDP_SESMAND_SESSION_ACTIVE, 1) != 0)
		return -1;
	if (expect_transition(FRDP_SESMAND_SESSION_STARTING, FRDP_SESMAND_SESSION_DEAD, 1) != 0)
		return -1;
	if (expect_transition(FRDP_SESMAND_SESSION_ACTIVE, FRDP_SESMAND_SESSION_DISCONNECTED, 1) != 0)
		return -1;
	if (expect_transition(FRDP_SESMAND_SESSION_ACTIVE, FRDP_SESMAND_SESSION_STOPPING, 1) != 0)
		return -1;
	if (expect_transition(FRDP_SESMAND_SESSION_DISCONNECTED, FRDP_SESMAND_SESSION_ACTIVE, 1) != 0)
		return -1;
	if (expect_transition(FRDP_SESMAND_SESSION_DISCONNECTED, FRDP_SESMAND_SESSION_STOPPING, 1) != 0)
		return -1;
	if (expect_transition(FRDP_SESMAND_SESSION_STOPPING, FRDP_SESMAND_SESSION_DEAD, 1) != 0)
		return -1;
	if (expect_transition(FRDP_SESMAND_SESSION_DEAD, FRDP_SESMAND_SESSION_ACTIVE, 0) != 0)
		return -1;
	if (expect_transition(FRDP_SESMAND_SESSION_ACTIVE, FRDP_SESMAND_SESSION_STARTING, 0) != 0)
		return -1;
	if (expect_transition((frdpSesmandSessionState)-1, FRDP_SESMAND_SESSION_ACTIVE, 0) != 0)
		return -1;
	return expect_transition(FRDP_SESMAND_SESSION_ACTIVE, (frdpSesmandSessionState)99, 0);
}

int TestFreeRDPFrdpSessionState(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if (test_session_state_names() != 0)
	{
		fprintf(stderr, "session state names failed\n");
		return -1;
	}
	if (test_session_state_transitions() != 0)
	{
		fprintf(stderr, "session state transitions failed\n");
		return -1;
	}
	return 0;
}

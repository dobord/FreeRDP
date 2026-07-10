#include "frdp-sesmand/session_disconnect.h"

#include <stdio.h>

static int test_disconnect_begin_and_rollback(void)
{
	frdpSesmandSessionState state = FRDP_SESMAND_SESSION_ACTIVE;

	if (frdp_sesmand_session_disconnect_begin(&state, 1) != 0)
		return -1;
	if (state != FRDP_SESMAND_SESSION_DISCONNECTED)
		return -1;
	if (frdp_sesmand_session_disconnect_rollback(&state) != 0)
		return -1;
	return (state == FRDP_SESMAND_SESSION_ACTIVE) ? 0 : -1;
}

static int test_disconnect_rejects_invalid_states(void)
{
	frdpSesmandSessionState disconnected = FRDP_SESMAND_SESSION_DISCONNECTED;
	frdpSesmandSessionState stopping = FRDP_SESMAND_SESSION_STOPPING;
	frdpSesmandSessionState active_without_socket = FRDP_SESMAND_SESSION_ACTIVE;

	if (frdp_sesmand_session_disconnect_begin(NULL, 1) == 0)
		return -1;
	if (frdp_sesmand_session_disconnect_begin(&active_without_socket, 0) == 0)
		return -1;
	if (active_without_socket != FRDP_SESMAND_SESSION_ACTIVE)
		return -1;
	if (frdp_sesmand_session_disconnect_begin(&disconnected, 1) == 0)
		return -1;
	if (disconnected != FRDP_SESMAND_SESSION_DISCONNECTED)
		return -1;
	if (frdp_sesmand_session_disconnect_begin(&stopping, 1) == 0)
		return -1;
	return (stopping == FRDP_SESMAND_SESSION_STOPPING) ? 0 : -1;
}

static int test_disconnect_rollback_rejects_invalid_states(void)
{
	frdpSesmandSessionState active = FRDP_SESMAND_SESSION_ACTIVE;
	frdpSesmandSessionState dead = FRDP_SESMAND_SESSION_DEAD;

	if (frdp_sesmand_session_disconnect_rollback(NULL) == 0)
		return -1;
	if (frdp_sesmand_session_disconnect_rollback(&active) == 0)
		return -1;
	if (active != FRDP_SESMAND_SESSION_ACTIVE)
		return -1;
	if (frdp_sesmand_session_disconnect_rollback(&dead) == 0)
		return -1;
	return (dead == FRDP_SESMAND_SESSION_DEAD) ? 0 : -1;
}

int TestFreeRDPFrdpSessionDisconnect(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if (test_disconnect_begin_and_rollback() != 0)
	{
		fprintf(stderr, "disconnect begin/rollback failed\n");
		return -1;
	}
	if (test_disconnect_rejects_invalid_states() != 0)
	{
		fprintf(stderr, "disconnect invalid-state rejection failed\n");
		return -1;
	}
	if (test_disconnect_rollback_rejects_invalid_states() != 0)
	{
		fprintf(stderr, "disconnect rollback invalid-state rejection failed\n");
		return -1;
	}
	return 0;
}

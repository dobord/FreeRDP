#include "frdp-sesmand/session_cleanup.h"

#include <stdio.h>

static int expect_plan(const frdpSesmandSessionCleanupContext* context,
                       const frdpSesmandSessionCleanupPlan* expected)
{
	frdpSesmandSessionCleanupPlan actual;

	if (frdp_sesmand_session_cleanup_plan(context, &actual) != 0)
		return -1;
	if ((actual.mark_stopping == expected->mark_stopping) &&
	    (actual.terminate_process_group == expected->terminate_process_group) &&
	    (actual.close_pam_session == expected->close_pam_session) &&
	    (actual.delete_pam_credentials == expected->delete_pam_credentials) &&
	    (actual.unlink_agent_socket == expected->unlink_agent_socket) &&
	    (actual.release_display_reservation == expected->release_display_reservation) &&
	    (actual.mark_dead == expected->mark_dead))
		return 0;
	fprintf(stderr, "expected cleanup plan %d/%d/%d/%d/%d/%d/%d, got %d/%d/%d/%d/%d/%d/%d\n",
	        expected->mark_stopping, expected->terminate_process_group, expected->close_pam_session,
	        expected->delete_pam_credentials, expected->unlink_agent_socket,
	        expected->release_display_reservation, expected->mark_dead, actual.mark_stopping,
	        actual.terminate_process_group, actual.close_pam_session, actual.delete_pam_credentials,
	        actual.unlink_agent_socket, actual.release_display_reservation, actual.mark_dead);
	return -1;
}

static int test_active_session_cleanup_plan(void)
{
	const frdpSesmandSessionCleanupContext context = { .state = FRDP_SESMAND_SESSION_ACTIVE,
		                                               .has_process_group = 1,
		                                               .has_pam_handle = 1,
		                                               .credentials_established = 1,
		                                               .has_agent_socket = 1,
		                                               .has_display_reservation = 1 };
	const frdpSesmandSessionCleanupPlan expected = { .mark_stopping = 1,
		                                             .terminate_process_group = 1,
		                                             .close_pam_session = 1,
		                                             .delete_pam_credentials = 1,
		                                             .unlink_agent_socket = 1,
		                                             .release_display_reservation = 1,
		                                             .mark_dead = 1 };

	return expect_plan(&context, &expected);
}

static int test_partial_session_cleanup_plan(void)
{
	const frdpSesmandSessionCleanupContext context = { .state = FRDP_SESMAND_SESSION_STOPPING,
		                                               .has_process_group = 0,
		                                               .has_pam_handle = 1,
		                                               .credentials_established = 0,
		                                               .has_agent_socket = 0,
		                                               .has_display_reservation = 1 };
	const frdpSesmandSessionCleanupPlan expected = { .mark_stopping = 0,
		                                             .terminate_process_group = 0,
		                                             .close_pam_session = 1,
		                                             .delete_pam_credentials = 0,
		                                             .unlink_agent_socket = 0,
		                                             .release_display_reservation = 1,
		                                             .mark_dead = 1 };

	return expect_plan(&context, &expected);
}

static int test_auth_failure_cleanup_plan(void)
{
	const frdpSesmandSessionCleanupContext context = { .state = FRDP_SESMAND_SESSION_AUTHENTICATED,
		                                               .has_process_group = 0,
		                                               .has_pam_handle = 0,
		                                               .credentials_established = 1,
		                                               .has_agent_socket = 0,
		                                               .has_display_reservation = 0 };
	const frdpSesmandSessionCleanupPlan expected = { .mark_stopping = 0,
		                                             .terminate_process_group = 0,
		                                             .close_pam_session = 0,
		                                             .delete_pam_credentials = 0,
		                                             .unlink_agent_socket = 0,
		                                             .release_display_reservation = 0,
		                                             .mark_dead = 1 };

	return expect_plan(&context, &expected);
}

static int test_dead_session_cleanup_plan(void)
{
	const frdpSesmandSessionCleanupContext context = { .state = FRDP_SESMAND_SESSION_DEAD,
		                                               .has_process_group = 1,
		                                               .has_pam_handle = 0,
		                                               .credentials_established = 0,
		                                               .has_agent_socket = 1,
		                                               .has_display_reservation = 0 };
	const frdpSesmandSessionCleanupPlan expected = { .mark_stopping = 0,
		                                             .terminate_process_group = 1,
		                                             .close_pam_session = 0,
		                                             .delete_pam_credentials = 0,
		                                             .unlink_agent_socket = 1,
		                                             .release_display_reservation = 0,
		                                             .mark_dead = 0 };

	return expect_plan(&context, &expected);
}

static int test_invalid_cleanup_arguments(void)
{
	frdpSesmandSessionCleanupPlan plan;
	const frdpSesmandSessionCleanupContext invalid_state = { .state = (frdpSesmandSessionState)-1 };

	if (frdp_sesmand_session_cleanup_plan(NULL, &plan) == 0)
		return -1;
	if (frdp_sesmand_session_cleanup_plan(&invalid_state, &plan) == 0)
		return -1;
	if (frdp_sesmand_session_cleanup_plan(&invalid_state, NULL) == 0)
		return -1;
	return 0;
}

int TestFreeRDPFrdpSessionCleanup(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if (test_active_session_cleanup_plan() != 0)
	{
		fprintf(stderr, "active session cleanup plan failed\n");
		return -1;
	}
	if (test_partial_session_cleanup_plan() != 0)
	{
		fprintf(stderr, "partial session cleanup plan failed\n");
		return -1;
	}
	if (test_auth_failure_cleanup_plan() != 0)
	{
		fprintf(stderr, "auth failure cleanup plan failed\n");
		return -1;
	}
	if (test_dead_session_cleanup_plan() != 0)
	{
		fprintf(stderr, "dead session cleanup plan failed\n");
		return -1;
	}
	if (test_invalid_cleanup_arguments() != 0)
	{
		fprintf(stderr, "invalid cleanup arguments failed\n");
		return -1;
	}
	return 0;
}

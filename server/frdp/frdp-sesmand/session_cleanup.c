#include "session_cleanup.h"

#include <string.h>

int frdp_sesmand_session_cleanup_plan(const frdpSesmandSessionCleanupContext* context,
                                      frdpSesmandSessionCleanupPlan* plan)
{
	frdpSesmandSessionState final_state;

	if (!context || !plan || !frdp_sesmand_session_state_is_valid(context->state))
		return -1;

	memset(plan, 0, sizeof(*plan));
	final_state = context->state;

	if ((final_state != FRDP_SESMAND_SESSION_STOPPING) &&
	    frdp_sesmand_session_state_can_transition(final_state, FRDP_SESMAND_SESSION_STOPPING))
	{
		plan->mark_stopping = 1;
		final_state = FRDP_SESMAND_SESSION_STOPPING;
	}

	plan->terminate_process_group = context->has_process_group;
	plan->close_pam_session = context->has_pam_handle;
	plan->delete_pam_credentials = context->has_pam_handle && context->credentials_established;
	plan->unlink_agent_socket = context->has_agent_socket;
	plan->release_display_reservation = context->has_display_reservation;
	plan->mark_dead =
	    (final_state != FRDP_SESMAND_SESSION_DEAD) &&
	    frdp_sesmand_session_state_can_transition(final_state, FRDP_SESMAND_SESSION_DEAD);

	return 0;
}

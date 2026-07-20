#include "frdpd_audit.h"

#include <syslog.h>

#include <winpr/wlog.h>

#include "../audit/frdp-audit.h"

#define TAG SERVER_TAG("frdpd.audit")

void frdpd_audit_peer_event(const frdpdPeerContext* context, int priority, const char* event,
                            const char* result, const char* channel, const char* detail)
{
	frdpAuditEvent audit = { 0 };

	if (!context || !context->audit_enabled)
		return;
	audit.priority = priority;
	audit.identifier = "frdpd";
	audit.event = event;
	audit.correlation_id = context->correlation_id;
	audit.result = result;
	audit.user = (context->pam_user && (context->pam_user[0] != '\0')) ? context->pam_user : NULL;
	audit.session_id = (context->managed_session_open && (context->session_id[0] != '\0'))
	                       ? context->session_id
	                       : NULL;
	audit.channel = (channel && (channel[0] != '\0')) ? channel : NULL;
	audit.detail = (detail && (detail[0] != '\0')) ? detail : NULL;
	if (frdp_audit_emit_journald(&audit) < 0)
		WLog_WARN(TAG, "correlation_id=%s failed to emit structured audit event=%s",
		          context->correlation_id, event ? event : "invalid");
}

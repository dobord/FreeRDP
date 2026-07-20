#include <errno.h>
#include <string.h>
#include <sys/uio.h>
#include <syslog.h>

#include "../audit/frdp-audit.h"
#include "../frdpd/frdpd_audit.h"

static char g_fields[10][512];
static int g_field_count = 0;
static int g_sender_calls = 0;
static int g_sender_result = 0;

static int capture_sender(const struct iovec* fields, int count)
{
	if (!fields || (count < 0) || (count > 10))
		return -1;
	g_sender_calls++;
	g_field_count = count;
	for (int i = 0; i < count; i++)
	{
		if (!fields[i].iov_base || (fields[i].iov_len >= sizeof(g_fields[i])))
			return -1;
		memcpy(g_fields[i], fields[i].iov_base, fields[i].iov_len);
		g_fields[i][fields[i].iov_len] = '\0';
	}
	return g_sender_result;
}

static int field_count(const char* expected)
{
	int matches = 0;

	for (int i = 0; i < g_field_count; i++)
	{
		if (strcmp(g_fields[i], expected) == 0)
			matches++;
	}
	return matches;
}

int TestFreeRDPFrdpAudit(int argc, char* argv[])
{
	frdpAuditEvent event = { LOG_INFO,     "frdpd",   "channel.authorization",
		                     "peer-id",    "allowed", "alice",
		                     "session-id", "cliprdr", "static" };
	frdpdPeerContext context = { 0 };
	char oversized[512] = { 0 };

	(void)argc;
	(void)argv;
	frdp_audit_set_journal_sender(capture_sender);
	if ((frdp_audit_emit_journald(&event) != 0) || (g_sender_calls != 1) || (g_field_count != 10) ||
	    (field_count("MESSAGE=FRDP audit event") != 1) || (field_count("PRIORITY=6") != 1) ||
	    (field_count("SYSLOG_IDENTIFIER=frdpd") != 1) ||
	    (field_count("FRDP_EVENT=channel.authorization") != 1) ||
	    (field_count("FRDP_CORRELATION_ID=peer-id") != 1) ||
	    (field_count("FRDP_RESULT=allowed") != 1) || (field_count("FRDP_USER=alice") != 1) ||
	    (field_count("FRDP_SESSION_ID=session-id") != 1) ||
	    (field_count("FRDP_CHANNEL=cliprdr") != 1) || (field_count("FRDP_DETAIL=static") != 1))
		return -1;

	event.user = "";
	event.session_id = NULL;
	event.channel = NULL;
	event.detail = NULL;
	if ((frdp_audit_emit_journald(&event) != 0) || (g_sender_calls != 2) || (g_field_count != 6))
		return -1;

	event.event = NULL;
	errno = 0;
	if ((frdp_audit_emit_journald(&event) == 0) || (errno != EINVAL) || (g_sender_calls != 2))
		return -1;
	event.event = "channel.authorization";
	event.priority = 8;
	errno = 0;
	if ((frdp_audit_emit_journald(&event) == 0) || (errno != EINVAL) || (g_sender_calls != 2))
		return -1;

	memset(oversized, 'a', sizeof(oversized) - 1);
	event.priority = LOG_INFO;
	event.correlation_id = oversized;
	if ((frdp_audit_emit_journald(&event) == 0) || (g_sender_calls != 2))
		return -1;

	strcpy(context.correlation_id, "peer-context-id");
	context.pam_user = "bob";
	context.managed_session_open = TRUE;
	strcpy(context.session_id, "managed-session-id");
	frdpd_audit_peer_event(&context, LOG_INFO, "channel.activation", "ready", "cliprdr",
	                       "text-clipboard");
	if (g_sender_calls != 2)
		return -1;
	context.audit_enabled = TRUE;
	frdpd_audit_peer_event(&context, LOG_INFO, "channel.activation", "ready", "cliprdr",
	                       "text-clipboard");
	if ((g_sender_calls != 3) || (g_field_count != 10) ||
	    (field_count("FRDP_CORRELATION_ID=peer-context-id") != 1) ||
	    (field_count("FRDP_USER=bob") != 1) ||
	    (field_count("FRDP_SESSION_ID=managed-session-id") != 1))
		return -1;

	g_sender_result = -EIO;
	event.correlation_id = "peer-id";
	if ((frdp_audit_emit_journald(&event) != -EIO) || (g_sender_calls != 4))
		return -1;
	frdpd_audit_peer_event(&context, LOG_WARNING, "channel.activation", "failed", "cliprdr",
	                       "start");
	if (g_sender_calls != 5)
		return -1;

	frdp_audit_set_journal_sender(NULL);
	return 0;
}

#include "frdp-audit.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>

#include <systemd/sd-journal.h>

#define FRDP_AUDIT_MAX_FIELDS 10
#define FRDP_AUDIT_FIELD_SIZE 512

typedef int (*frdpAuditSender)(const struct iovec* fields, int count);

static frdpAuditSender g_journal_sender = sd_journal_sendv;

static int append_field(struct iovec* fields, int* count,
                        char storage[FRDP_AUDIT_MAX_FIELDS][FRDP_AUDIT_FIELD_SIZE],
                        const char* name, const char* value)
{
	int length = 0;

	if (!fields || !count || !storage || !name || !value || (value[0] == '\0') || (*count < 0) ||
	    (*count >= FRDP_AUDIT_MAX_FIELDS))
		return -1;
	length = snprintf(storage[*count], FRDP_AUDIT_FIELD_SIZE, "%s=%s", name, value);
	if ((length < 0) || (length >= FRDP_AUDIT_FIELD_SIZE))
		return -1;
	fields[*count].iov_base = storage[*count];
	fields[*count].iov_len = (size_t)length;
	(*count)++;
	return 0;
}

int frdp_audit_emit_journald(const frdpAuditEvent* event)
{
	struct iovec fields[FRDP_AUDIT_MAX_FIELDS] = { 0 };
	char storage[FRDP_AUDIT_MAX_FIELDS][FRDP_AUDIT_FIELD_SIZE] = { 0 };
	char priority[16] = { 0 };
	int count = 0;

	if (!event || !event->identifier || !event->event || !event->correlation_id || !event->result ||
	    (event->identifier[0] == '\0') || (event->event[0] == '\0') ||
	    (event->correlation_id[0] == '\0') || (event->result[0] == '\0') || (event->priority < 0) ||
	    (event->priority > 7))
	{
		errno = EINVAL;
		return -1;
	}
	if (snprintf(priority, sizeof(priority), "%d", event->priority) < 0)
		return -1;
	if ((append_field(fields, &count, storage, "MESSAGE", "FRDP audit event") != 0) ||
	    (append_field(fields, &count, storage, "PRIORITY", priority) != 0) ||
	    (append_field(fields, &count, storage, "SYSLOG_IDENTIFIER", event->identifier) != 0) ||
	    (append_field(fields, &count, storage, "FRDP_EVENT", event->event) != 0) ||
	    (append_field(fields, &count, storage, "FRDP_CORRELATION_ID", event->correlation_id) !=
	     0) ||
	    (append_field(fields, &count, storage, "FRDP_RESULT", event->result) != 0))
		return -1;
	if (event->user && (event->user[0] != '\0') &&
	    (append_field(fields, &count, storage, "FRDP_USER", event->user) != 0))
		return -1;
	if (event->session_id && (event->session_id[0] != '\0') &&
	    (append_field(fields, &count, storage, "FRDP_SESSION_ID", event->session_id) != 0))
		return -1;
	if (event->channel && (event->channel[0] != '\0') &&
	    (append_field(fields, &count, storage, "FRDP_CHANNEL", event->channel) != 0))
		return -1;
	if (event->detail && (event->detail[0] != '\0') &&
	    (append_field(fields, &count, storage, "FRDP_DETAIL", event->detail) != 0))
		return -1;
	return g_journal_sender(fields, count);
}

#ifdef FRDP_AUDIT_TESTING
void frdp_audit_set_journal_sender(frdpAuditJournalSender sender)
{
	g_journal_sender = sender ? sender : sd_journal_sendv;
}
#endif

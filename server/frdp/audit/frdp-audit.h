#ifndef FRDP_AUDIT_H
#define FRDP_AUDIT_H

#include <stddef.h>

typedef struct
{
	int priority;
	const char* identifier;
	const char* event;
	const char* correlation_id;
	const char* result;
	const char* user;
	const char* session_id;
	const char* channel;
	const char* detail;
} frdpAuditEvent;

int frdp_audit_emit_journald(const frdpAuditEvent* event);

#ifdef FRDP_AUDIT_TESTING
struct iovec;
typedef int (*frdpAuditJournalSender)(const struct iovec* fields, int count);
void frdp_audit_set_journal_sender(frdpAuditJournalSender sender);
#endif

#endif

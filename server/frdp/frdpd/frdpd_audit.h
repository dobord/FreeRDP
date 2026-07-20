#ifndef FRDPD_AUDIT_H
#define FRDPD_AUDIT_H

#include <winpr/wtypes.h>

#include "frdpd.h"

void frdpd_audit_peer_event(const frdpdPeerContext* context, int priority, const char* event,
                            const char* result, const char* channel, const char* detail);

#endif

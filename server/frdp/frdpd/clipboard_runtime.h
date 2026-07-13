/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Experimental frdpd cliprdr runtime
 *
 * Licensed under the Apache License, Version 2.0.
 */

#ifndef FREERDP_SERVER_FRDPD_CLIPBOARD_RUNTIME_H
#define FREERDP_SERVER_FRDPD_CLIPBOARD_RUNTIME_H

#include "frdpd.h"

#ifdef __cplusplus
extern "C"
{
#endif

	BOOL frdpd_clipboard_runtime_service(frdpdPeerContext* context);
	void frdpd_clipboard_runtime_stop(frdpdPeerContext* context);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_SERVER_FRDPD_CLIPBOARD_RUNTIME_H */

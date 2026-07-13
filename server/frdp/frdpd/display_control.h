#ifndef FREERDP_SERVER_FRDPD_DISPLAY_CONTROL_H
#define FREERDP_SERVER_FRDPD_DISPLAY_CONTROL_H

#include <stddef.h>

#include <freerdp/channels/disp.h>
#include <freerdp/settings_types.h>

#define FRDPD_DISPLAY_MAX_DESKTOP_SIZE 8192U
#define FRDPD_DISPLAY_MAX_MONITORS 16U

#ifdef __cplusplus
extern "C"
{
#endif

	BOOL frdpd_display_control_to_monitors(const DISPLAY_CONTROL_MONITOR_LAYOUT_PDU* pdu,
	                                       MONITOR_DEF* monitors, size_t capacity);
	BOOL frdpd_display_monitor_bounds(UINT32 count, const MONITOR_DEF* monitors, UINT32* width,
	                                  UINT32* height);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_SERVER_FRDPD_DISPLAY_CONTROL_H */

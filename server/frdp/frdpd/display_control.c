#include "display_control.h"

#include <limits.h>

BOOL frdpd_display_control_to_monitors(const DISPLAY_CONTROL_MONITOR_LAYOUT_PDU* pdu,
                                       MONITOR_DEF* monitors, size_t capacity)
{
	if (!pdu || !pdu->Monitors || !monitors ||
	    (pdu->MonitorLayoutSize != DISPLAY_CONTROL_MONITOR_LAYOUT_SIZE) ||
	    (pdu->NumMonitors == 0) || (pdu->NumMonitors > FRDPD_DISPLAY_MAX_MONITORS) ||
	    (pdu->NumMonitors > capacity))
		return FALSE;

	for (UINT32 i = 0; i < pdu->NumMonitors; i++)
	{
		const DISPLAY_CONTROL_MONITOR_LAYOUT* src = &pdu->Monitors[i];
		MONITOR_DEF* dst = &monitors[i];
		const INT64 right = (INT64)src->Left + (INT64)src->Width - 1;
		const INT64 bottom = (INT64)src->Top + (INT64)src->Height - 1;

		if ((src->Width < DISPLAY_CONTROL_MIN_MONITOR_WIDTH) ||
		    (src->Width > DISPLAY_CONTROL_MAX_MONITOR_WIDTH) ||
		    (src->Height < DISPLAY_CONTROL_MIN_MONITOR_HEIGHT) ||
		    (src->Height > DISPLAY_CONTROL_MAX_MONITOR_HEIGHT) || (right < INT32_MIN) ||
		    (right > INT32_MAX) || (bottom < INT32_MIN) || (bottom > INT32_MAX))
			return FALSE;

		dst->left = src->Left;
		dst->top = src->Top;
		dst->right = (INT32)right;
		dst->bottom = (INT32)bottom;
		dst->flags = src->Flags & DISPLAY_CONTROL_MONITOR_PRIMARY;
	}

	return TRUE;
}

BOOL frdpd_display_monitor_bounds(UINT32 count, const MONITOR_DEF* monitors, UINT32* width,
                                  UINT32* height)
{
	INT64 left = 0;
	INT64 top = 0;
	INT64 right = 0;
	INT64 bottom = 0;

	if (!monitors || !width || !height || (count == 0) || (count > FRDPD_DISPLAY_MAX_MONITORS))
		return FALSE;

	left = monitors[0].left;
	top = monitors[0].top;
	right = monitors[0].right;
	bottom = monitors[0].bottom;
	for (UINT32 i = 0; i < count; i++)
	{
		if ((monitors[i].right < monitors[i].left) || (monitors[i].bottom < monitors[i].top))
			return FALSE;
		if (monitors[i].left < left)
			left = monitors[i].left;
		if (monitors[i].top < top)
			top = monitors[i].top;
		if (monitors[i].right > right)
			right = monitors[i].right;
		if (monitors[i].bottom > bottom)
			bottom = monitors[i].bottom;
	}

	if ((right < left) || (bottom < top) || ((right - left + 1) > FRDPD_DISPLAY_MAX_DESKTOP_SIZE) ||
	    ((bottom - top + 1) > FRDPD_DISPLAY_MAX_DESKTOP_SIZE))
		return FALSE;

	*width = (UINT32)(right - left + 1);
	*height = (UINT32)(bottom - top + 1);
	return (*width > 0) && (*height > 0);
}

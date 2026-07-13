#include "frdpd/display_control.h"

#include <limits.h>
#include <string.h>

static int test_single_monitor(void)
{
	DISPLAY_CONTROL_MONITOR_LAYOUT layout = {
		.Flags = DISPLAY_CONTROL_MONITOR_PRIMARY, .Left = 0, .Top = 0, .Width = 1024, .Height = 768
	};
	DISPLAY_CONTROL_MONITOR_LAYOUT_PDU pdu = { .MonitorLayoutSize =
		                                           DISPLAY_CONTROL_MONITOR_LAYOUT_SIZE,
		                                       .NumMonitors = 1,
		                                       .Monitors = &layout };
	MONITOR_DEF monitor = { 0 };
	UINT32 width = 0;
	UINT32 height = 0;

	if (!frdpd_display_control_to_monitors(&pdu, &monitor, 1))
		return -1;
	if ((monitor.left != 0) || (monitor.top != 0) || (monitor.right != 1023) ||
	    (monitor.bottom != 767) || (monitor.flags != MONITOR_PRIMARY))
		return -1;
	if (!frdpd_display_monitor_bounds(1, &monitor, &width, &height))
		return -1;
	return ((width == 1024) && (height == 768)) ? 0 : -1;
}

static int test_multi_monitor_bounds(void)
{
	DISPLAY_CONTROL_MONITOR_LAYOUT layouts[2] = {
		{ .Left = -800, .Top = 0, .Width = 800, .Height = 600 },
		{ .Flags = DISPLAY_CONTROL_MONITOR_PRIMARY,
		  .Left = 0,
		  .Top = -168,
		  .Width = 1024,
		  .Height = 768 }
	};
	DISPLAY_CONTROL_MONITOR_LAYOUT_PDU pdu = { .MonitorLayoutSize =
		                                           DISPLAY_CONTROL_MONITOR_LAYOUT_SIZE,
		                                       .NumMonitors = 2,
		                                       .Monitors = layouts };
	MONITOR_DEF monitors[2] = { 0 };
	UINT32 width = 0;
	UINT32 height = 0;

	if (!frdpd_display_control_to_monitors(&pdu, monitors, ARRAYSIZE(monitors)))
		return -1;
	if (!frdpd_display_monitor_bounds(2, monitors, &width, &height))
		return -1;
	return ((width == 1824) && (height == 768)) ? 0 : -1;
}

static int test_invalid_layouts(void)
{
	DISPLAY_CONTROL_MONITOR_LAYOUT layout = { .Left = 0, .Top = 0, .Width = 1024, .Height = 768 };
	DISPLAY_CONTROL_MONITOR_LAYOUT_PDU pdu = { .MonitorLayoutSize =
		                                           DISPLAY_CONTROL_MONITOR_LAYOUT_SIZE,
		                                       .NumMonitors = 1,
		                                       .Monitors = &layout };
	MONITOR_DEF monitor = { 0 };
	UINT32 width = 0;
	UINT32 height = 0;

	if (frdpd_display_control_to_monitors(NULL, &monitor, 1) ||
	    frdpd_display_control_to_monitors(&pdu, NULL, 1) ||
	    frdpd_display_control_to_monitors(&pdu, &monitor, 0))
		return -1;
	pdu.MonitorLayoutSize = 0;
	if (frdpd_display_control_to_monitors(&pdu, &monitor, 1))
		return -1;
	pdu.MonitorLayoutSize = DISPLAY_CONTROL_MONITOR_LAYOUT_SIZE;
	layout.Width = DISPLAY_CONTROL_MIN_MONITOR_WIDTH - 1;
	if (frdpd_display_control_to_monitors(&pdu, &monitor, 1))
		return -1;
	layout.Width = 1024;
	layout.Left = INT32_MAX - 100;
	if (frdpd_display_control_to_monitors(&pdu, &monitor, 1))
		return -1;
	layout.Left = 0;
	monitor.left = 0;
	monitor.top = 0;
	monitor.right = (INT32)FRDPD_DISPLAY_MAX_DESKTOP_SIZE;
	monitor.bottom = 767;
	if (frdpd_display_monitor_bounds(1, &monitor, &width, &height))
		return -1;
	return 0;
}

int TestFreeRDPFrdpDisplayControl(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if (test_single_monitor() != 0)
		return -1;
	if (test_multi_monitor_bounds() != 0)
		return -1;
	return test_invalid_layouts();
}

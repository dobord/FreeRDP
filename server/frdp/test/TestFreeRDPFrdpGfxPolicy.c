#include "frdpd/gfx_policy.h"

#include <stdio.h>
#include <string.h>

#include <winpr/collections.h>

static int test_capability_selection(void)
{
	RDPGFX_CAPSET selected = { 0 };
	RDPGFX_CAPSET offered[] = {
		{ .version = RDPGFX_CAPVERSION_8,
		  .length = sizeof(UINT32),
		  .flags = RDPGFX_CAPS_FLAG_THINCLIENT },
		{ .version = RDPGFX_CAPVERSION_107,
		  .length = sizeof(UINT32),
		  .flags = RDPGFX_CAPS_FLAG_AVC420_ENABLED }
	};

	if (frdpd_gfx_select_capability(offered, ARRAYSIZE(offered), &selected) != 0)
		return -1;
	if ((selected.version != RDPGFX_CAPVERSION_107) ||
	    (selected.flags & RDPGFX_CAPS_FLAG_AVC420_ENABLED) ||
	    !(selected.flags & RDPGFX_CAPS_FLAG_AVC_DISABLED))
		return -1;
	return 0;
}

static int test_capability_validation_and_legacy_flags(void)
{
	RDPGFX_CAPSET selected = { 0 };
	RDPGFX_CAPSET offered[] = {
		{ .version = RDPGFX_CAPVERSION_107, .length = 1024, .flags = UINT32_MAX },
		{ .version = 0xFFFFFFFFU, .length = sizeof(UINT32), .flags = UINT32_MAX },
		{ .version = RDPGFX_CAPVERSION_81,
		  .length = sizeof(UINT32),
		  .flags = RDPGFX_CAPS_FLAG_AVC420_ENABLED }
	};

	if (frdpd_gfx_select_capability(offered, ARRAYSIZE(offered), &selected) != 0)
		return -1;
	if ((selected.version != RDPGFX_CAPVERSION_81) ||
	    (selected.flags & RDPGFX_CAPS_FLAG_AVC420_ENABLED) ||
	    (selected.flags & RDPGFX_CAPS_FLAG_AVC_DISABLED))
		return -1;
	if (frdpd_gfx_select_capability(NULL, 0, &selected) == 0)
		return -1;
	offered[2].length = 0;
	if (frdpd_gfx_select_capability(offered, ARRAYSIZE(offered), &selected) == 0)
		return -1;
	return 0;
}

static int test_bottom_up_to_top_down_copy(void)
{
	const BYTE source[] = {
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
	};
	const BYTE expected[] = {
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28
	};
	BYTE destination[sizeof(source)] = { 0 };

	if (!frdpd_gfx_copy_bgrx_bottom_up_to_top_down(
	        destination, sizeof(destination), source, sizeof(source), 2, 2, 8))
		return -1;
	if (memcmp(destination, expected, sizeof(expected)) != 0)
		return -1;
	if (frdpd_gfx_copy_bgrx_bottom_up_to_top_down(
	        destination, sizeof(destination) - 1U, source, sizeof(source), 2, 2, 8))
		return -1;
	if (frdpd_gfx_copy_bgrx_bottom_up_to_top_down(
	        destination, sizeof(destination), source, sizeof(source), 2, 2, 7))
		return -1;
	return 0;
}

int TestFreeRDPFrdpGfxPolicy(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	if (test_capability_selection() != 0)
	{
		fprintf(stderr, "RDPGFX capability preference/flag selection failed\n");
		return -1;
	}
	if (test_capability_validation_and_legacy_flags() != 0)
	{
		fprintf(stderr, "RDPGFX capability validation failed\n");
		return -1;
	}
	if (test_bottom_up_to_top_down_copy() != 0)
	{
		fprintf(stderr, "RDPGFX framebuffer row conversion failed\n");
		return -1;
	}
	return 0;
}

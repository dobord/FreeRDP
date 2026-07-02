#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "frdp-sesmand/display_policy.h"

#define FRDP_DISPLAY_POLICY_FUZZ_MAX_SIZE 256U

static uint32_t read_u32(const uint8_t* data, size_t size, size_t offset)
{
	uint32_t value = 0;

	for (size_t x = 0; x < 4U; x++)
	{
		if (offset + x < size)
			value |= ((uint32_t)data[offset + x]) << (x * 8U);
	}
	return value;
}

static int fuzz_display_number(uint32_t selector)
{
	switch (selector % 8U)
	{
		case 0:
			return FRDP_SESMAND_DISPLAY_MIN - 1;
		case 1:
			return FRDP_SESMAND_DISPLAY_MIN;
		case 2:
			return FRDP_SESMAND_DISPLAY_MIN + (int)(selector % 32U);
		case 3:
			return FRDP_SESMAND_DISPLAY_MAX;
		case 4:
			return FRDP_SESMAND_DISPLAY_MAX + 1;
		case 5:
			return -1;
		case 6:
			return 0;
		default:
			return (int)(selector & 0x7FFFFFFFU);
	}
}

static void fill_dir(char* dir, size_t dir_size, const uint8_t* data, size_t size)
{
	const uint32_t selector = read_u32(data, size, 4U);

	if (!dir || dir_size == 0)
		return;

	switch (selector % 6U)
	{
		case 0:
			snprintf(dir, dir_size, "/tmp");
			break;
		case 1:
			snprintf(dir, dir_size, "relative");
			break;
		case 2:
			snprintf(dir, dir_size, "/");
			break;
		case 3:
			snprintf(dir, dir_size, "");
			break;
		case 4:
			snprintf(dir, dir_size, "/tmp/frdp-display-policy-%u", selector);
			break;
		default:
			snprintf(dir, dir_size, "/tmp/frdp-display-policy-long-%08x-%08x-%08x-%08x-%08x",
			         selector, read_u32(data, size, 8U), read_u32(data, size, 12U),
			         read_u32(data, size, 16U), read_u32(data, size, 20U));
			break;
	}
}

int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
	char dir[128] = { 0 };
	char path[128] = { 0 };
	char tiny_path[8] = { 0 };
	int display = 0;

	if (!Data || (Size > FRDP_DISPLAY_POLICY_FUZZ_MAX_SIZE))
		return 0;

	display = fuzz_display_number(read_u32(Data, Size, 0));
	fill_dir(dir, sizeof(dir), Data, Size);

	(void)frdp_sesmand_display_number_is_valid(display);
	(void)frdp_sesmand_display_reservation_path(path, sizeof(path), dir, display);
	(void)frdp_sesmand_display_reservation_path(tiny_path, sizeof(tiny_path), dir, display);
	(void)frdp_sesmand_display_reservation_path(NULL, sizeof(path), dir, display);
	(void)frdp_sesmand_display_reservation_path(path, 0, dir, display);
	(void)frdp_sesmand_display_reservation_path(path, sizeof(path), NULL, display);

	return 0;
}

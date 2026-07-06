#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <winpr/wtsapi.h>

#include "config/frdp-config.h"
#include "frdpd/channel_policy.h"

#define FRDP_FUZZ_MAX_CONFIG_SIZE 65536U

static int write_all(int fd, const uint8_t* data, size_t size)
{
	size_t offset = 0;

	while (offset < size)
	{
		const ssize_t rc = write(fd, data + offset, size - offset);
		if (rc < 0)
			return -1;
		if (rc == 0)
			return -1;
		offset += (size_t)rc;
	}
	return 0;
}

static void fuzz_policy_helpers(const frdpChannelPolicy* policy, const frdpClipboardPolicy* clipboard,
                                const uint8_t* data, size_t size)
{
	char channel_name[FRDP_CONFIG_CHANNEL_NAME_SIZE] = { 0 };
	char extracted_name[FRDP_CONFIG_CHANNEL_NAME_SIZE] = { 0 };
	CHANNEL_DEF channel = { 0 };
	size_t name_len = size;

	if (!policy || !data || (size == 0))
		return;

	if (name_len >= sizeof(channel_name))
		name_len = sizeof(channel_name) - 1;
	memcpy(channel_name, data, name_len);
	channel_name[name_len] = '\0';

	if (name_len > sizeof(channel.name))
		name_len = sizeof(channel.name);
	memcpy(channel.name, data, name_len);

	(void)frdp_channel_policy_static_allowed(policy, channel_name);
	(void)frdp_channel_policy_static_allowed_for_runtime(policy, clipboard, channel_name);
	(void)frdp_channel_policy_dynamic_allowed(policy, channel_name);
	(void)frdp_channel_policy_static_channel_allowed(policy, &channel, extracted_name,
	                                                 sizeof(extracted_name));
	(void)frdp_channel_policy_static_channel_allowed_for_runtime(policy, clipboard, &channel,
	                                                             extracted_name,
	                                                             sizeof(extracted_name));
	(void)frdp_channel_policy_static_allowed(policy, "cliprdr");
	(void)frdp_channel_policy_static_allowed_for_runtime(policy, clipboard, "cliprdr");
	(void)frdp_channel_policy_static_allowed_for_runtime(policy, clipboard, "rdpsnd");
	(void)frdp_channel_policy_static_allowed_for_runtime(policy, clipboard, "rdpdr");
	(void)frdp_channel_policy_static_allowed_for_runtime(policy, clipboard, "rail");
	(void)frdp_channel_policy_static_allowed(policy, "drdynvc");
	(void)frdp_channel_policy_static_allowed_for_runtime(policy, clipboard, "drdynvc");
	(void)frdp_channel_policy_dynamic_allowed(policy, "rdpgfx");
	(void)frdp_channel_policy_dynamic_allowed(policy, "drdynvc");
}

static frdpClipboardPolicy fuzz_clipboard_policy(const frdpClipboardPolicy* loaded,
                                                 const uint8_t* data, size_t size)
{
	frdpClipboardPolicy clipboard = { 0 };

	if (loaded)
		clipboard = *loaded;
	if (data && (size > 0))
		clipboard.mode = (frdpClipboardMode)(data[0] & 3U);
	if (data && (size > 1))
		clipboard.direction = (frdpClipboardDirection)(data[1] & 3U);
	if (data && (size > 5))
	{
		clipboard.max_text_bytes = ((uint32_t)data[2]) | ((uint32_t)data[3] << 8U) |
		                           ((uint32_t)data[4] << 16U) | ((uint32_t)data[5] << 24U);
	}
	return clipboard;
}

int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
	char path[] = "/tmp/frdp-config-fuzz.XXXXXX";
	frdpConfig config = { 0 };
	int fd = -1;

	if (!Data || (Size > FRDP_FUZZ_MAX_CONFIG_SIZE))
		return 0;

	fd = mkstemp(path);
	if (fd < 0)
		return 0;

	if (write_all(fd, Data, Size) == 0)
	{
		(void)close(fd);
		fd = -1;
		if (frdp_config_load(path, &config) == 0)
		{
			const frdpClipboardPolicy clipboard =
			    fuzz_clipboard_policy(&config.clipboard, Data, Size);
			fuzz_policy_helpers(&config.channels, &clipboard, Data, Size);
		}
	}

	if (fd >= 0)
		(void)close(fd);
	(void)unlink(path);
	return 0;
}

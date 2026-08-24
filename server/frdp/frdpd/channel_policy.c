#include "channel_policy.h"

#include <ctype.h>
#include <string.h>

#include <freerdp/channels/disp.h>
#include <freerdp/channels/geometry.h>
#include <freerdp/channels/rdpgfx.h>

static void frdp_channel_policy_channel_name(char* dst, size_t dst_size, const CHANNEL_DEF* channel)
{
	size_t len = 0;

	if (!dst || (dst_size == 0))
		return;
	dst[0] = '\0';
	if (!channel)
		return;
	len = strnlen(channel->name, sizeof(channel->name));
	if (len >= dst_size)
		len = dst_size - 1;
	memcpy(dst, channel->name, len);
	dst[len] = '\0';
}

static int frdp_channel_policy_list_contains(
    const char channels[FRDP_CONFIG_MAX_CHANNELS][FRDP_CONFIG_CHANNEL_NAME_SIZE], uint32_t count,
    const char* channel)
{
	for (uint32_t i = 0; i < count; i++)
	{
		if (strcmp(channels[i], channel) == 0)
			return 1;
	}
	return 0;
}

static int frdp_channel_policy_name_valid(const char* channel)
{
	size_t len = 0;

	if (!channel)
		return 0;
	len = strlen(channel);
	if ((len == 0) || (len >= FRDP_CONFIG_CHANNEL_NAME_SIZE))
		return 0;
	for (size_t i = 0; i < len; i++)
	{
		const unsigned char c = (unsigned char)channel[i];

		if (!isalnum(c) && (c != '_'))
			return 0;
	}
	return 1;
}

static int frdp_channel_policy_runtime_name_valid(const char* channel)
{
	size_t length = 0;

	if (!channel)
		return 0;
	length = strnlen(channel, 256);
	if ((length == 0) || (length >= 256))
		return 0;
	for (size_t i = 0; i < length; i++)
	{
		const unsigned char c = (unsigned char)channel[i];
		if ((c < 0x20) || (c == 0x7F))
			return 0;
	}
	return 1;
}

int frdp_channel_policy_static_allowed(const frdpChannelPolicy* policy, const char* channel)
{
	if (!policy || !frdp_channel_policy_name_valid(channel))
		return 0;

	if (policy->static_mode == FRDP_CHANNEL_FILTER_ALLOWLIST)
		return frdp_channel_policy_list_contains(policy->static_allow, policy->static_allow_count,
		                                         channel);
	if (policy->static_mode == FRDP_CHANNEL_FILTER_BLOCKLIST)
	{
		return !frdp_channel_policy_list_contains(policy->static_deny, policy->static_deny_count,
		                                          channel);
	}
	return 0;
}

int frdp_channel_policy_static_allowed_for_runtime(const frdpChannelPolicy* policy,
                                                   const frdpClipboardPolicy* clipboard,
                                                   const char* channel)
{
	if (!policy || !clipboard || !frdp_channel_policy_name_valid(channel))
		return 0;
	return frdp_channel_policy_static_allowed(policy, channel);
}

int frdp_channel_policy_dynamic_allowed(const frdpChannelPolicy* policy, const char* channel)
{
	if (!policy || !frdp_channel_policy_name_valid(channel))
		return 0;
	if (strcmp(channel, "drdynvc") == 0)
		return 0;

	if (policy->dynamic_mode == FRDP_CHANNEL_FILTER_ALLOWLIST)
		return frdp_channel_policy_list_contains(policy->dynamic_allow, policy->dynamic_allow_count,
		                                         channel);
	if (policy->dynamic_mode == FRDP_CHANNEL_FILTER_BLOCKLIST)
	{
		return !frdp_channel_policy_list_contains(policy->dynamic_deny, policy->dynamic_deny_count,
		                                          channel);
	}
	return 0;
}

int frdp_channel_policy_dynamic_allowed_for_runtime(const frdpChannelPolicy* policy,
                                                    const char* channel)
{
	if (!policy || !channel)
		return 0;
	if (strcmp(channel, DISP_DVC_CHANNEL_NAME) == 0)
		return frdp_channel_policy_dynamic_allowed(policy, "disp");
	if (strcmp(channel, RDPGFX_DVC_CHANNEL_NAME) == 0)
		return frdp_channel_policy_dynamic_allowed(policy, RDPGFX_CHANNEL_NAME);
	if (strcmp(channel, GEOMETRY_DVC_CHANNEL_NAME) == 0)
		return frdp_channel_policy_dynamic_allowed(policy, GEOMETRY_CHANNEL_NAME);
	if (frdp_channel_policy_name_valid(channel))
		return frdp_channel_policy_dynamic_allowed(policy, channel);
	if (!frdp_channel_policy_runtime_name_valid(channel))
		return 0;
	return policy->dynamic_mode == FRDP_CHANNEL_FILTER_BLOCKLIST;
}

int frdp_channel_policy_static_channel_allowed(const frdpChannelPolicy* policy,
                                               const CHANNEL_DEF* channel, char* name,
                                               size_t name_size)
{
	char local_name[CHANNEL_NAME_LEN + 2] = { 0 };

	frdp_channel_policy_channel_name(local_name, sizeof(local_name), channel);
	frdp_channel_policy_channel_name(name, name_size, channel);
	return frdp_channel_policy_static_allowed(policy, local_name);
}

int frdp_channel_policy_static_channel_allowed_for_runtime(const frdpChannelPolicy* policy,
                                                           const frdpClipboardPolicy* clipboard,
                                                           const CHANNEL_DEF* channel, char* name,
                                                           size_t name_size)
{
	char local_name[CHANNEL_NAME_LEN + 2] = { 0 };

	frdp_channel_policy_channel_name(local_name, sizeof(local_name), channel);
	frdp_channel_policy_channel_name(name, name_size, channel);
	return frdp_channel_policy_static_allowed_for_runtime(policy, clipboard, local_name);
}

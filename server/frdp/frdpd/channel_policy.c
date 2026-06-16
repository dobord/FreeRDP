#include "channel_policy.h"

#include <string.h>

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

int frdp_channel_policy_static_allowed(const frdpChannelPolicy *policy, const char *channel)
{
	if (!policy || !channel || channel[0] == '\0')
		return 0;
	if (strcmp(channel, "drdynvc") == 0)
		return 0;

	for (uint32_t i = 0; i < policy->static_allow_count; i++)
	{
		if (strcmp(policy->static_allow[i], channel) == 0)
			return 1;
	}
	return 0;
}

int frdp_channel_policy_dynamic_allowed(const frdpChannelPolicy *policy, const char *channel)
{
	if (!policy || !channel || channel[0] == '\0')
		return 0;
	if (strcmp(channel, "drdynvc") == 0)
		return 0;

	for (uint32_t i = 0; i < policy->dynamic_allow_count; i++)
	{
		if (strcmp(policy->dynamic_allow[i], channel) == 0)
			return 1;
	}
	return 0;
}

int frdp_channel_policy_static_channel_allowed(const frdpChannelPolicy *policy,
                                               const CHANNEL_DEF *channel, char *name,
                                               size_t name_size)
{
	char local_name[CHANNEL_NAME_LEN + 2] = { 0 };

	frdp_channel_policy_channel_name(local_name, sizeof(local_name), channel);
	frdp_channel_policy_channel_name(name, name_size, channel);
	return frdp_channel_policy_static_allowed(policy, local_name);
}

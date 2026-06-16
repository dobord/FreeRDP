#include "channel_policy.h"

#include <string.h>

int frdp_channel_policy_static_allowed(const frdpChannelPolicy *policy, const char *channel)
{
    if (!policy || !channel || channel[0] == '\0')
        return 0;

    for (uint32_t i = 0; i < policy->static_allow_count; i++) {
        if (strcmp(policy->static_allow[i], channel) == 0)
            return 1;
    }
    return 0;
}

#ifndef FREERDP_SERVER_FRDPD_CHANNEL_POLICY_H
#define FREERDP_SERVER_FRDPD_CHANNEL_POLICY_H

#include <stddef.h>

#include <winpr/wtsapi.h>

#include "../config/frdp-config.h"

#ifdef __cplusplus
extern "C"
{
#endif

int frdp_channel_policy_static_allowed(const frdpChannelPolicy *policy, const char *channel);
int frdp_channel_policy_static_channel_allowed(const frdpChannelPolicy *policy,
                                               const CHANNEL_DEF *channel, char *name,
                                               size_t name_size);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_SERVER_FRDPD_CHANNEL_POLICY_H */

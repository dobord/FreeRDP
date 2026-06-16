#ifndef FREERDP_SERVER_FRDPD_CHANNEL_POLICY_H
#define FREERDP_SERVER_FRDPD_CHANNEL_POLICY_H

#include "../config/frdp-config.h"

#ifdef __cplusplus
extern "C"
{
#endif

int frdp_channel_policy_static_allowed(const frdpChannelPolicy *policy, const char *channel);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_SERVER_FRDPD_CHANNEL_POLICY_H */

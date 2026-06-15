/*
 * Simple channel policy engine stub.
 *
 * This module provides a placeholder for enforcing allow/deny rules for RDP
 * virtual channels. For the prototype implementation, unknown channels are
 * denied by default and only clipboard_text and audio_output are allowed.
 */

#include <string.h>
#include <stdio.h>

/* Return 1 if the channel is allowed, 0 if denied */
int frdp_channel_allowed(const char *channel)
{
    if (!channel)
        return 0;
    /* Deny everything by default */
    if (strcmp(channel, "clipboard_text") == 0)
        return 1;
    if (strcmp(channel, "audio_output") == 0)
        return 1;
    return 0;
}

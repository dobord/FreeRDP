/*
 * frdp-sesmand - Session manager for FreeRDP-based RDP server
 *
 * This skeleton manages user sessions: tracking login state, opening and closing
 * PAM sessions, integrating with systemd-logind and cgroup slices. A real implementation
 * would maintain a registry of active sessions and support reconnect.
 */

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    printf("frdp-sesmand: skeleton session manager starting\n");

    // TODO: implement session registry and PAM session lifecycle.
    // TODO: integrate with systemd-logind to create user sessions and cgroups.
    // TODO: handle reconnect, idle timeouts and cleanup.

    return 0;
}

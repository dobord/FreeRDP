/*
 * frdp-session-agent - Per-user agent for FreeRDP-based RDP server
 *
 * This skeleton runs as the authenticated user and is responsible for launching the
 * desktop backend (Xorg/Xvfb/Wayland), handling input and output channels and enforcing
 * policy. A complete implementation would interact with the FreeRDP peer to send
 * frame updates, clipboard data and audio.
 */

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    printf("frdp-session-agent: skeleton agent starting\n");

    // TODO: start headless Xorg/Xvfb or Wayland backend.
    // TODO: set up graphics capture, input handlers, clipboard and audio.
    // TODO: enforce allowed channel list from session manager.

    return 0;
}

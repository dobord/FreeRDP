/*
 * frdpd - FreeRDP RDP daemon listener
 *
 * This is a skeleton implementation for the FreeRDP-based RDP server. It creates
 * a TCP listener, sets up TLS, enables mandatory NLA and dispatches per-peer workers.
 * TODO: integrate with FreeRDP server API.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

// TODO: include FreeRDP server headers when available.

static volatile int running = 1;

static void signal_handler(int sig)
{
    running = 0;
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // TODO: initialize TLS context, load certificates from configuration.
    // TODO: create a FreeRDP listener on 0.0.0.0:3389 with NLA security.
    // TODO: drop unnecessary capabilities after binding the port.

    printf("frdpd: skeleton listener starting\n");

    while (running) {
        // TODO: accept incoming connections and dispatch to worker threads.
        // For now, sleep to simulate work.
        sleep(1);
    }

    printf("frdpd: shutting down\n");
    return 0;
}

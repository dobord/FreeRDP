/*
 * frdpctl - administration CLI for FreeRDP-based RDP server
 *
 * This stub provides basic operations: status, list-sessions, kill-session
 * and reload. In a full implementation it would communicate with the session
 * manager via IPC (e.g. unix domain sockets or D-Bus).
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void usage(const char *argv0)
{
    printf("Usage: %s <command> [options]\n", argv0);
    printf("Commands:\n");
    printf("  status                 Show server status\n");
    printf("  list-sessions          List active sessions\n");
    printf("  kill-session <id>      Terminate session by id\n");
    printf("  reload                 Reload configuration\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    const char *cmd = argv[1];
    if (strcmp(cmd, "status") == 0) {
        printf("Server status: stub implementation\n");
        return 0;
    } else if (strcmp(cmd, "list-sessions") == 0) {
        printf("Listing sessions: stub implementation\n");
        return 0;
    } else if (strcmp(cmd, "kill-session") == 0) {
        if (argc < 3) {
            fprintf(stderr, "kill-session requires an id\n");
            return 1;
        }
        const char *id = argv[2];
        printf("Killing session %s: stub implementation\n", id);
        return 0;
    } else if (strcmp(cmd, "reload") == 0) {
        printf("Reloading configuration: stub implementation\n");
        return 0;
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage(argv[0]);
        return 1;
    }
}

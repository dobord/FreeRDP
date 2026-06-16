/*
 * frdpctl - administration CLI for FreeRDP-based RDP server
 *
 * This tool provides basic operations for the FreeRDP-based RDP server.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "ipc/frdp-ipc.h"

#define FRDPCTL_DEFAULT_SESSION_SOCKET "/run/frdp-sesmand/sesmand.sock"

typedef struct
{
    const char *socket_path;
    const char *session_id;
} frdpctlKillSessionOptions;

typedef struct
{
    const char *socket_path;
} frdpctlListSessionsOptions;

static void usage(const char *argv0)
{
    printf("Usage: %s <command> [options]\n", argv0);
    printf("Commands:\n");
    printf("  status [--socket <path>]\n");
    printf("  list-sessions [--socket <path>]\n");
    printf("  kill-session <id> [--socket <path>]\n");
    printf("  reload                 Reload configuration\n");
}

static int copy_field(char *dst, size_t dst_size, const char *value)
{
    if (!dst || (dst_size == 0) || !value || (value[0] == '\0'))
        return -1;
    if (strlen(value) >= dst_size)
        return -1;
    memcpy(dst, value, strlen(value) + 1);
    return 0;
}

static int parse_kill_session_options(int argc, char **argv, frdpctlKillSessionOptions *options)
{
    if (!options)
        return -1;
    memset(options, 0, sizeof(*options));
    options->socket_path = FRDPCTL_DEFAULT_SESSION_SOCKET;

    if (argc < 3)
        return -1;
    options->session_id = argv[2];

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--socket") == 0) {
            if ((i + 1) >= argc)
                return -1;
            options->socket_path = argv[++i];
            continue;
        }
        return -1;
    }
    return 0;
}

static int parse_list_sessions_options(int argc, char **argv, frdpctlListSessionsOptions *options)
{
    if (!options)
        return -1;
    memset(options, 0, sizeof(*options));
    options->socket_path = FRDPCTL_DEFAULT_SESSION_SOCKET;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--socket") == 0) {
            if ((i + 1) >= argc)
                return -1;
            options->socket_path = argv[++i];
            continue;
        }
        return -1;
    }
    return 0;
}

static void terminate_session_list_response_strings(frdpSessionListResponse *response)
{
    if (!response)
        return;
    response->error[sizeof(response->error) - 1] = '\0';
    for (uint32_t i = 0; i < FRDP_IPC_MAX_SESSION_LIST_ENTRIES; i++) {
        response->entries[i].session_id[sizeof(response->entries[i].session_id) - 1] = '\0';
        response->entries[i].user[sizeof(response->entries[i].user) - 1] = '\0';
        response->entries[i].display[sizeof(response->entries[i].display) - 1] = '\0';
    }
}

static int send_session_list_request(const char *socket_path, int status_only)
{
    int fd = -1;
    frdpIpcHeader header;
    frdpIpcHeader response_header;
    frdpSessionListResponse response;

    memset(&header, 0, sizeof(header));
    memset(&response_header, 0, sizeof(response_header));
    memset(&response, 0, sizeof(response));

    fd = frdp_ipc_connect(socket_path);
    if (fd < 0) {
        fprintf(stderr, "unable to connect to session manager socket %s: %s\n", socket_path,
                strerror(errno));
        return 3;
    }

    header.type = FRDP_IPC_SESSION_LIST_REQUEST;
    header.payload_len = 0;
    if ((frdp_ipc_send(fd, &header, sizeof(header)) != 0) ||
        (frdp_ipc_recv(fd, &response_header, sizeof(response_header)) !=
         (int)sizeof(response_header)) ||
        (response_header.type != FRDP_IPC_SESSION_LIST_RESPONSE) ||
        (response_header.payload_len != sizeof(response)) ||
        (frdp_ipc_recv(fd, &response, sizeof(response)) != (int)sizeof(response))) {
        fprintf(stderr, "session list IPC failed\n");
        frdp_ipc_close(fd);
        return 3;
    }

    frdp_ipc_close(fd);
    terminate_session_list_response_strings(&response);
    if (!response.success) {
        fprintf(stderr, "session list failed: %s\n", response.error[0] ? response.error : "unknown");
        return 4;
    }
    if (response.count > FRDP_IPC_MAX_SESSION_LIST_ENTRIES) {
        fprintf(stderr, "session list response is invalid\n");
        return 3;
    }

    if (status_only) {
        printf("Session manager: reachable\n");
        printf("Active sessions: %" PRIu32 "\n", response.count);
        return 0;
    }

    if (response.count == 0) {
        printf("No active sessions\n");
        return 0;
    }

    printf("%-36s  %-20s  %-8s  %-8s\n", "SESSION", "USER", "DISPLAY", "PID");
    for (uint32_t i = 0; i < response.count; i++) {
        printf("%-36s  %-20s  %-8s  %-8d\n", response.entries[i].session_id,
               response.entries[i].user, response.entries[i].display,
               (int)response.entries[i].agent_pid);
    }
    return 0;
}

static int send_session_close_request(const char *socket_path, const char *session_id)
{
    int fd = -1;
    frdpIpcHeader header;
    frdpIpcHeader response_header;
    frdpSessionRequest request;
    frdpSessionResponse response;

    memset(&header, 0, sizeof(header));
    memset(&response_header, 0, sizeof(response_header));
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));

    if (copy_field(request.session_id, sizeof(request.session_id), session_id) != 0) {
        fprintf(stderr, "invalid session id\n");
        return 2;
    }
    snprintf(request.correlation_id, sizeof(request.correlation_id), "frdpctl-%ld", (long)getpid());

    fd = frdp_ipc_connect(socket_path);
    if (fd < 0) {
        fprintf(stderr, "unable to connect to session manager socket %s: %s\n", socket_path,
                strerror(errno));
        return 3;
    }

    header.type = FRDP_IPC_SESSION_CLOSE_REQUEST;
    header.payload_len = sizeof(request);
    if ((frdp_ipc_send(fd, &header, sizeof(header)) != 0) ||
        (frdp_ipc_send(fd, &request, sizeof(request)) != 0) ||
        (frdp_ipc_recv(fd, &response_header, sizeof(response_header)) !=
         (int)sizeof(response_header)) ||
        (response_header.type != FRDP_IPC_SESSION_RESPONSE) ||
        (response_header.payload_len != sizeof(response)) ||
        (frdp_ipc_recv(fd, &response, sizeof(response)) != (int)sizeof(response))) {
        fprintf(stderr, "session close IPC failed\n");
        frdp_ipc_close(fd);
        return 3;
    }

    response.session_id[sizeof(response.session_id) - 1] = '\0';
    response.display[sizeof(response.display) - 1] = '\0';
    response.agent_socket[sizeof(response.agent_socket) - 1] = '\0';
    response.error[sizeof(response.error) - 1] = '\0';

    frdp_ipc_close(fd);
    if (!response.success) {
        fprintf(stderr, "session close failed: %s\n", response.error[0] ? response.error : "unknown");
        return 4;
    }

    printf("Closed session %s\n", response.session_id[0] ? response.session_id : session_id);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    const char *cmd = argv[1];
    if (strcmp(cmd, "status") == 0) {
        frdpctlListSessionsOptions options;

        if (parse_list_sessions_options(argc, argv, &options) != 0) {
            fprintf(stderr, "Usage: %s status [--socket <path>]\n", argv[0]);
            return 1;
        }
        return send_session_list_request(options.socket_path, 1);
    } else if (strcmp(cmd, "list-sessions") == 0) {
        frdpctlListSessionsOptions options;

        if (parse_list_sessions_options(argc, argv, &options) != 0) {
            fprintf(stderr, "Usage: %s list-sessions [--socket <path>]\n", argv[0]);
            return 1;
        }
        return send_session_list_request(options.socket_path, 0);
    } else if (strcmp(cmd, "kill-session") == 0) {
        frdpctlKillSessionOptions options;

        if (parse_kill_session_options(argc, argv, &options) != 0) {
            fprintf(stderr, "Usage: %s kill-session <id> [--socket <path>]\n", argv[0]);
            return 1;
        }
        return send_session_close_request(options.socket_path, options.session_id);
    } else if (strcmp(cmd, "reload") == 0) {
        printf("Reloading configuration: stub implementation\n");
        return 0;
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage(argv[0]);
        return 1;
    }
}

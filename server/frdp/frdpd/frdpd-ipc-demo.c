/*
 * frdpd IPC demo client
 *
 * This simple program demonstrates how the RDP daemon could authenticate a user
 * via the frdp-authd broker using the IPC protocol defined in frdp-ipc.h.
 * It loads the daemon configuration to obtain defaults and sends an
 * FRDP_IPC_AUTH_REQUEST_V2 to the auth daemon.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../config/frdp-config.h"
#include "../ipc/frdp-ipc.h"

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <config.toml> <socket-path> <username> <password>\n", argv[0]);
        return 1;
    }
    const char *cfg_path = argv[1];
    const char *sock = argv[2];
    const char *user = argv[3];
    const char *pass = (argc >= 5) ? argv[4] : "";

    frdpConfig cfg;
    if (frdp_config_load(cfg_path, &cfg) != 0) {
        fprintf(stderr, "Failed to load configuration from %s\n", cfg_path);
        return 1;
    }
    int fd = frdp_ipc_connect(sock);
    if (fd < 0) {
        perror("frdp_ipc_connect");
        return 1;
    }
    frdpAuthRequest req;
    memset(&req, 0, sizeof(req));
    strncpy(req.correlation_id, "11111111-1111-4111-8111-111111111111",
            sizeof(req.correlation_id) - 1);
    strncpy(req.user, user, sizeof(req.user) - 1);
    strncpy(req.password, pass, sizeof(req.password) - 1);
    if (frdp_ipc_send_auth_request_v2(fd, &req) != 0) {
        perror("frdp_ipc_send");
        frdp_ipc_close(fd);
        return 1;
    }
    frdpAuthResponse resp;
    if (frdp_ipc_recv_auth_response(fd, &resp) != 0) {
        fprintf(stderr, "Failed to read response\n");
        frdp_ipc_close(fd);
        return 1;
    }
    printf("Authentication result: %s\n", resp.success ? "success" : "failure");
    if (!resp.success && resp.error[0] != '\0') {
        printf("Error: %s\n", resp.error);
    }
    frdp_ipc_close(fd);
    return resp.success ? 0 : 1;
}
